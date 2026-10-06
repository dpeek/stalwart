/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Read-only Gmail thread resources backed by Stalwart's stored messages.

use super::{error, labels::mailbox_label_id};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{MessageCache, MessageStoreCache, Server, auth::AccessToken};
use email::{
    cache::MessageCacheFetch,
    message::metadata::{MESSAGE_RECEIVED_MASK, MessageMetadata},
};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse, form_urlencoded};
use hyper::StatusCode;
use mail_parser::{
    Encoding, Message, MessageParser, MimeHeaders, PartType,
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
};
use serde::Serialize;
use std::str::FromStr;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::EmailField,
    id::Id,
    keyword::{FLAGGED, IMPORTANT, SEEN},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Full,
    Minimal,
}

impl Format {
    fn parse(query: Option<&str>) -> Option<Self> {
        let mut format = None;
        for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            if key == "format" && format.is_none() {
                format = Some(match value.as_ref() {
                    "full" => Self::Full,
                    "minimal" => Self::Minimal,
                    _ => return None,
                });
            } else {
                return None;
            }
        }
        Some(format.unwrap_or(Self::Full))
    }
}

#[derive(Serialize)]
struct ThreadResource<T: Serialize> {
    id: String,
    messages: Vec<T>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MinimalMessage {
    id: String,
    thread_id: String,
    label_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FullMessage {
    id: String,
    thread_id: String,
    label_ids: Vec<String>,
    snippet: String,
    size_estimate: u32,
    history_id: String,
    #[serde(rename = "internalDate")]
    internal_date: String,
    payload: MimePart,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MimePart {
    part_id: String,
    mime_type: String,
    filename: String,
    headers: Vec<MimeHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<MimeBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<Vec<MimePart>>,
}

#[derive(Serialize)]
struct MimeHeader {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MimeBody {
    size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_id: Option<String>,
}

#[derive(Serialize)]
struct AttachmentBody {
    size: usize,
    data: String,
}

fn selected<'a>(cache: &'a MessageStoreCache, thread_id: u32) -> Vec<&'a MessageCache> {
    cache
        .emails
        .items
        .iter()
        .filter(|item| item.thread_id == thread_id)
        .collect()
}

fn message_by_id(cache: &MessageStoreCache, document_id: u32) -> Option<&MessageCache> {
    cache
        .emails
        .items
        .iter()
        .find(|item| item.document_id == document_id)
}

pub(super) fn parse_thread_id(raw: &str) -> Option<u32> {
    let id = Id::from_str(raw).ok()?;
    let document_id = id.document_id();
    (u64::from(id) <= u32::MAX as u64 && Id::from(document_id).to_string() == raw)
        .then_some(document_id)
}

pub(super) fn parse_message_id(raw: &str) -> Option<u32> {
    parse_thread_id(raw)
}

fn parse_attachment_path(message_id: &str, attachment_id: &str) -> Option<Vec<usize>> {
    let path = attachment_id.strip_prefix(message_id)?.strip_prefix('.')?;
    let indices: Vec<usize> = path
        .split('.')
        .map(|segment| {
            let index: usize = segment.parse().ok()?;
            (index.to_string() == segment).then_some(index)
        })
        .collect::<Option<_>>()?;
    (indices.first() == Some(&0)).then_some(indices)
}

fn attachment_bytes(message: &Message<'_>, index: usize, remaining: &[usize]) -> Option<Vec<u8>> {
    let part = message.parts.get(index)?;
    if let Some((&next, rest)) = remaining.split_first() {
        return match &part.body {
            PartType::Multipart(children)
                if children
                    .iter()
                    .any(|child| usize::try_from(*child).ok() == Some(next)) =>
            {
                attachment_bytes(message, next, rest)
            }
            PartType::Message(nested) if next == 0 => attachment_bytes(nested, 0, rest),
            _ => None,
        };
    }
    let is_attachment = part.attachment_name().is_some_and(|name| !name.is_empty())
        || part
            .content_disposition()
            .is_some_and(|disposition| disposition.c_type.eq_ignore_ascii_case("attachment"));
    if !is_attachment && !matches!(part.body, PartType::Binary(_) | PartType::InlineBinary(_)) {
        return None;
    }
    let raw = message
        .raw_message
        .get(part.offset_body as usize..part.offset_end as usize)?;
    match part.encoding {
        Encoding::None => Some(raw.to_vec()),
        Encoding::Base64 => base64_decode(raw).or_else(|| Some(part.contents().to_vec())),
        Encoding::QuotedPrintable => {
            quoted_printable_decode(raw).or_else(|| Some(part.contents().to_vec()))
        }
    }
}

pub(super) fn labels(cache: &MessageStoreCache, item: &MessageCache) -> Vec<String> {
    let mut labels = Vec::new();
    for mailbox in &item.mailboxes {
        let label = cache
            .mailboxes
            .items
            .iter()
            .find(|entry| entry.document_id == mailbox.mailbox_id)
            .and_then(mailbox_label_id);
        if let Some(label) = label
            && !labels.contains(&label)
        {
            labels.push(label);
        }
    }
    for (flag, label) in [(FLAGGED, "STARRED"), (IMPORTANT, "IMPORTANT")] {
        if item.keywords & (1u128 << flag) != 0 {
            labels.push(label.to_string());
        }
    }
    if item.keywords & (1u128 << SEEN) == 0 {
        labels.push("UNREAD".into());
    }
    labels
}

fn mime_part(message: &Message<'_>, index: usize, message_id: &str, path: String) -> MimePart {
    let part = &message.parts[index];
    let mime_type = part
        .content_type()
        .map(|ct| {
            format!(
                "{}/{}",
                ct.c_type,
                ct.c_subtype.as_deref().unwrap_or("plain")
            )
        })
        .unwrap_or_else(|| match &part.body {
            PartType::Text(_) => "text/plain".into(),
            PartType::Html(_) => "text/html".into(),
            PartType::Multipart(_) => "multipart/mixed".into(),
            PartType::Message(_) => "message/rfc822".into(),
            _ => "application/octet-stream".into(),
        });
    let headers = part
        .headers
        .iter()
        .filter_map(|header| {
            let value = message
                .raw_message
                .get(header.offset_start as usize..header.offset_end as usize)?;
            Some(MimeHeader {
                name: header.name.as_str().to_string(),
                value: String::from_utf8_lossy(value).trim().to_string(),
            })
        })
        .collect();
    let filename = part.attachment_name().unwrap_or_default().to_string();
    let attachment_id = || format!("{message_id}.{path}");
    let is_attachment = !filename.is_empty()
        || part
            .content_disposition()
            .is_some_and(|disposition| disposition.c_type.eq_ignore_ascii_case("attachment"));
    let (body, parts) = match &part.body {
        PartType::Text(text) | PartType::Html(text) => {
            let bytes = text.as_bytes();
            (
                Some(MimeBody {
                    size: if is_attachment {
                        attachment_bytes(message, index, &[])
                            .map_or(bytes.len(), |decoded| decoded.len())
                    } else {
                        bytes.len()
                    },
                    data: (!is_attachment).then(|| URL_SAFE_NO_PAD.encode(bytes)),
                    attachment_id: is_attachment.then(attachment_id),
                }),
                None,
            )
        }
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => (
            Some(MimeBody {
                size: bytes.len(),
                data: None,
                attachment_id: Some(attachment_id()),
            }),
            None,
        ),
        PartType::Multipart(children) => (
            None,
            Some(
                children
                    .iter()
                    .filter_map(|child| {
                        let index = *child as usize;
                        (index < message.parts.len()).then(|| {
                            mime_part(message, index, message_id, format!("{path}.{index}"))
                        })
                    })
                    .collect(),
            ),
        ),
        PartType::Message(nested) => (
            None,
            (!nested.parts.is_empty())
                .then(|| vec![mime_part(nested, 0, message_id, format!("{path}.0"))]),
        ),
    };
    MimePart {
        part_id: path,
        mime_type,
        filename,
        headers,
        body,
        parts,
    }
}

fn minimal_message(cache: &MessageStoreCache, item: &MessageCache) -> MinimalMessage {
    MinimalMessage {
        id: Id::from(item.document_id).to_string(),
        thread_id: Id::from(item.thread_id).to_string(),
        label_ids: labels(cache, item),
    }
}

async fn full_message(
    server: &Server,
    account_id: u32,
    cache: &MessageStoreCache,
    item: &MessageCache,
) -> trc::Result<Result<(u64, FullMessage), HttpResponse>> {
    let Some(archive) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            item.document_id,
            EmailField::Metadata,
        ))
        .await?
    else {
        return Ok(Err(error(
            StatusCode::CONFLICT,
            "Message changed; retry retrieval",
        )));
    };
    let metadata = archive.unarchive::<MessageMetadata>()?;
    let blob_hash = BlobHash::from(&metadata.blob_hash);
    let Some(blob) = server
        .blob_store()
        .get_blob(blob_hash.as_slice(), 0..usize::MAX)
        .await?
    else {
        return Ok(Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored message blob is missing",
        )));
    };
    let mut raw = Vec::with_capacity(metadata.raw_headers.len() + blob.len());
    raw.extend_from_slice(&metadata.raw_headers);
    raw.extend_from_slice(
        blob.get(metadata.blob_body_offset.to_native() as usize..)
            .unwrap_or_default(),
    );
    let Some(parsed) = MessageParser::new().parse(&raw) else {
        return Ok(Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored message could not be parsed",
        )));
    };
    let id = Id::from(item.document_id).to_string();
    let received_at = metadata.rcvd_attach.to_native() & MESSAGE_RECEIVED_MASK;
    let payload = mime_part(&parsed, 0, &id, "0".into());
    Ok(Ok((
        received_at,
        FullMessage {
            id,
            thread_id: Id::from(item.thread_id).to_string(),
            label_ids: labels(cache, item),
            snippet: metadata.preview.to_string(),
            size_estimate: item.size,
            history_id: item.change_id.to_string(),
            internal_date: received_at.saturating_mul(1000).to_string(),
            payload,
        },
    )))
}

pub(crate) async fn get_thread(
    server: &Server,
    access_token: &AccessToken,
    raw_id: &str,
    query: Option<&str>,
) -> trc::Result<HttpResponse> {
    let Some(format) = Format::parse(query) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid thread format"));
    };
    let Some(thread_id) = parse_thread_id(raw_id) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid thread ID"));
    };
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let selected = selected(&cache, thread_id);
    if selected.is_empty() {
        return Ok(error(StatusCode::NOT_FOUND, "Thread not found"));
    }
    let thread_id_string = Id::from(thread_id).to_string();
    if format == Format::Minimal {
        return Ok(JsonResponse::new(ThreadResource {
            id: thread_id_string.clone(),
            messages: selected
                .iter()
                .map(|item| minimal_message(&cache, item))
                .collect(),
        })
        .no_cache()
        .into_http_response());
    }

    let mut messages = Vec::with_capacity(selected.len());
    for item in selected {
        match full_message(server, account_id, &cache, item).await? {
            Ok(message) => messages.push(message),
            Err(response) => return Ok(response),
        }
    }
    messages.sort_by_key(|(date, _)| *date);
    Ok(JsonResponse::new(ThreadResource {
        id: thread_id_string,
        messages: messages.into_iter().map(|(_, message)| message).collect(),
    })
    .no_cache()
    .into_http_response())
}

pub(crate) async fn get_message(
    server: &Server,
    access_token: &AccessToken,
    raw_id: &str,
    query: Option<&str>,
) -> trc::Result<HttpResponse> {
    let Some(format) = Format::parse(query) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid message format"));
    };
    let Some(document_id) = parse_message_id(raw_id) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid message ID"));
    };
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let Some(item) = message_by_id(&cache, document_id) else {
        return Ok(error(StatusCode::NOT_FOUND, "Message not found"));
    };
    if format == Format::Minimal {
        return Ok(JsonResponse::new(minimal_message(&cache, item))
            .no_cache()
            .into_http_response());
    }
    match full_message(server, account_id, &cache, item).await? {
        Ok((_, message)) => Ok(JsonResponse::new(message).no_cache().into_http_response()),
        Err(response) => Ok(response),
    }
}

pub(crate) async fn get_attachment(
    server: &Server,
    access_token: &AccessToken,
    raw_message_id: &str,
    raw_attachment_id: &str,
    query: Option<&str>,
) -> trc::Result<HttpResponse> {
    if query.is_some() {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid attachment query"));
    }
    let Some(document_id) = parse_message_id(raw_message_id) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid message ID"));
    };
    let Some(path) = parse_attachment_path(raw_message_id, raw_attachment_id) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid attachment ID"));
    };
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let Some(item) = message_by_id(&cache, document_id) else {
        return Ok(error(StatusCode::NOT_FOUND, "Message not found"));
    };
    let Some(archive) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            item.document_id,
            EmailField::Metadata,
        ))
        .await?
    else {
        return Ok(error(
            StatusCode::CONFLICT,
            "Message changed; retry retrieval",
        ));
    };
    let metadata = archive.unarchive::<MessageMetadata>()?;
    let blob_hash = BlobHash::from(&metadata.blob_hash);
    let Some(blob) = server
        .blob_store()
        .get_blob(blob_hash.as_slice(), 0..usize::MAX)
        .await?
    else {
        return Ok(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored message blob is missing",
        ));
    };
    let mut raw = Vec::with_capacity(metadata.raw_headers.len() + blob.len());
    raw.extend_from_slice(&metadata.raw_headers);
    raw.extend_from_slice(
        blob.get(metadata.blob_body_offset.to_native() as usize..)
            .unwrap_or_default(),
    );
    let Some(parsed) = MessageParser::new().parse(&raw) else {
        return Ok(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored message could not be parsed",
        ));
    };
    let Some(bytes) = attachment_bytes(&parsed, 0, &path[1..]) else {
        return Ok(error(StatusCode::NOT_FOUND, "Attachment not found"));
    };
    Ok(JsonResponse::new(AttachmentBody {
        size: bytes.len(),
        data: URL_SAFE_NO_PAD.encode(bytes),
    })
    .no_cache()
    .into_http_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn cache_with_message(document_id: u32, thread_id: u32) -> MessageStoreCache {
        MessageStoreCache {
            emails: Arc::new(common::MessagesCache {
                change_id: 1,
                items: vec![MessageCache {
                    document_id,
                    thread_id,
                    mailboxes: Default::default(),
                    keywords: 0,
                    change_id: 1,
                    size: 0,
                }]
                .into_boxed_slice(),
                index: Default::default(),
                keywords: Default::default(),
                size: 0,
            }),
            mailboxes: Arc::new(common::MailboxesCache {
                change_id: 1,
                items: Default::default(),
                index: Default::default(),
                size: 0,
            }),
            update_lock: Arc::new(common::UpdateLock::new()),
            last_change_id: 1,
            size: 0,
        }
    }

    #[test]
    fn message_lookup_stays_within_owners_cache() {
        let alice = cache_with_message(7, 3);
        let bob = cache_with_message(8, 4);
        assert!(message_by_id(&alice, 7).is_some());
        assert!(message_by_id(&bob, 7).is_none());
        assert_eq!(selected(&alice, 3).len(), 1);
        assert!(selected(&bob, 3).is_empty());
        let minimal = minimal_message(&alice, message_by_id(&alice, 7).unwrap());
        assert_eq!(minimal.id, Id::from(7u32).to_string());
        assert_eq!(minimal.thread_id, Id::from(3u32).to_string());
    }

    #[test]
    fn parses_formats_and_mime_payload_for_macro() {
        assert_eq!(Format::parse(None), Some(Format::Full));
        assert_eq!(Format::parse(Some("format=minimal")), Some(Format::Minimal));
        assert_eq!(Format::parse(Some("format=raw")), None);
        assert_eq!(parse_thread_id(&Id::from(42u32).to_string()), Some(42));
        assert_eq!(parse_thread_id(""), None);
        assert_eq!(parse_thread_id(&Id::from_parts(2, 42).to_string()), None);
        assert_eq!(parse_message_id(&Id::from(42u32).to_string()), Some(42));
        assert_eq!(parse_message_id(&Id::from_parts(2, 42).to_string()), None);
        let raw = b"From: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: Test\r\nMessage-ID: <one@example.test>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Bob";
        let parsed = MessageParser::new().parse(raw).unwrap();
        let payload = serde_json::to_value(mime_part(&parsed, 0, "a", "0".into())).unwrap();
        assert_eq!(payload["mimeType"], "text/plain");
        assert_eq!(
            payload["headers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|header| header["name"] == "Subject")
                .unwrap()["value"],
            "Test"
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(payload["body"]["data"].as_str().unwrap())
                .unwrap(),
            b"Hello Bob"
        );
    }

    #[test]
    fn multipart_text_attachment_has_stable_part_id() {
        let raw = b"Subject: Parts\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nBody\r\n--abc\r\nContent-Type: text/plain; name=note.txt\r\nContent-Disposition: attachment; filename=note.txt\r\n\r\nAttachment\r\n--abc--\r\n";
        let parsed = MessageParser::new().parse(raw).unwrap();
        let payload = serde_json::to_value(mime_part(&parsed, 0, "msg", "0".into())).unwrap();
        let parts = payload["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[0]["body"]["data"].is_string());
        assert_eq!(parts[1]["filename"], "note.txt");
        assert!(parts[1]["body"]["data"].is_null());
        assert_eq!(
            parts[1]["body"]["attachmentId"],
            format!("msg.{}", parts[1]["partId"].as_str().unwrap())
        );
    }

    #[test]
    fn attachment_ids_resolve_only_advertised_parts_and_keep_original_bytes() {
        let raw = b"Subject: Parts\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nInline body\r\n--abc\r\nContent-Type: application/octet-stream; name=data.bin\r\nContent-Disposition: attachment; filename=data.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECA/8=\r\n--abc\r\nContent-Type: text/plain; charset=iso-8859-1; name=note.txt\r\nContent-Disposition: attachment; filename=note.txt\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9\r\n--abc\r\nContent-Type: application/octet-stream; name=plain.bin\r\nContent-Disposition: attachment; filename=plain.bin\r\n\r\nraw bytes\r\n--abc--\r\n";
        let parsed = MessageParser::new().parse(raw).unwrap();
        let payload = serde_json::to_value(mime_part(&parsed, 0, "msg", "0".into())).unwrap();
        let parts = payload["parts"].as_array().unwrap();
        assert_eq!(parts[0]["body"]["attachmentId"], serde_json::Value::Null);

        for (part, expected) in [
            (&parts[1], &[0, 1, 2, 3, 255][..]),
            (&parts[2], &b"caf\xe9"[..]),
            (&parts[3], &b"raw bytes"[..]),
        ] {
            let attachment_id = part["body"]["attachmentId"].as_str().unwrap();
            let path = parse_attachment_path("msg", attachment_id).unwrap();
            let bytes = attachment_bytes(&parsed, 0, &path[1..]).unwrap();
            assert_eq!(bytes, expected);
            assert_eq!(part["body"]["size"], expected.len());
            let response = serde_json::to_value(AttachmentBody {
                size: bytes.len(),
                data: URL_SAFE_NO_PAD.encode(&bytes),
            })
            .unwrap();
            assert_eq!(response["size"], expected.len());
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(response["data"].as_str().unwrap())
                    .unwrap(),
                expected
            );
        }

        for invalid in ["other.0.1", "msg.0.01", "msg.0..1", "msg.1", "msg.0.-1"] {
            assert!(parse_attachment_path("msg", invalid).is_none(), "{invalid}");
        }
        assert!(attachment_bytes(&parsed, 0, &[0]).is_none());
        assert!(attachment_bytes(&parsed, 0, &[999]).is_none());
    }

    #[test]
    fn full_and_minimal_message_fields_match_macro_models() {
        let minimal = serde_json::to_value(MinimalMessage {
            id: "m".into(),
            thread_id: "t".into(),
            label_ids: vec!["INBOX".into()],
        })
        .unwrap();
        assert_eq!(minimal["threadId"], "t");
        assert_eq!(minimal["labelIds"][0], "INBOX");
        let full = serde_json::to_value(FullMessage {
            id: "m".into(),
            thread_id: "t".into(),
            label_ids: vec![],
            snippet: "preview".into(),
            size_estimate: 4,
            history_id: "5".into(),
            internal_date: "1700000000000".into(),
            payload: MimePart {
                part_id: "0".into(),
                mime_type: "text/plain".into(),
                filename: String::new(),
                headers: vec![],
                body: Some(MimeBody {
                    size: 4,
                    data: Some("dGVzdA".into()),
                    attachment_id: None,
                }),
                parts: None,
            },
        })
        .unwrap();
        for field in [
            "id",
            "threadId",
            "labelIds",
            "snippet",
            "sizeEstimate",
            "historyId",
            "internalDate",
            "payload",
        ] {
            assert!(full.get(field).is_some(), "missing {field}");
        }
    }
}
