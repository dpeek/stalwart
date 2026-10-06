/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{error, thread_get::parse_thread_id};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, auth::AccessToken};
use email::{
    cache::MessageCacheFetch,
    identity::Identity,
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
    submission::EmailSubmission as StoredSubmission,
};
use http_proto::{HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse};
use hyper::StatusCode;
use jmap::{email::set::EmailSet, identity::get::IdentityGet, submission::set::EmailSubmissionSet};
use jmap_proto::{
    method::set::SetRequest,
    object::{email::Email, email_submission::EmailSubmission},
};
use mail_parser::{HeaderName, MessageParser};
use registry::schema::enums::Permission;
use serde::{Deserialize, Serialize};
use serde_json::json;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use types::{collection::Collection, id::Id, keyword::Keyword, special_use::SpecialUse};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SendRequest {
    raw: String,
    thread_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SentMessage {
    id: String,
    thread_id: String,
}

fn valid_mime(raw: &[u8]) -> bool {
    let Some(message) = MessageParser::new().parse(raw) else {
        return false;
    };
    let Some(from) = message.from() else {
        return false;
    };
    from.iter().count() == 1
        && message.headers().iter().filter(|header| header.name == HeaderName::From).count() == 1
        && from
            .first()
            .and_then(|addr| addr.address.as_ref())
            .is_some()
        && [message.to(), message.cc(), message.bcc()]
            .into_iter()
            .flatten()
            .flat_map(|addresses| addresses.iter())
            .any(|address| address.address.is_some())
        // EmailSubmission strips one Bcc header from the outbound copy.
        && message.headers().iter().filter(|header| header.name == HeaderName::Bcc).count() <= 1
        && !message.headers().iter().any(|header| header.name == HeaderName::ResentBcc)
        && raw.windows(4).any(|window| window == b"\r\n\r\n")
}

async fn discard_unsent(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    document_id: u32,
) -> trc::Result<bool> {
    let encoded = serde_json::to_vec(&json!({
        "accountId": Id::from(access_token.account_id()).to_string(),
        "destroy": [Id::from(document_id).to_string()],
    }))
    .expect("valid JMAP destroy request");
    let request: SetRequest<'_, Email> = match serde_json::from_slice(&encoded) {
        Ok(request) => request,
        Err(_) => return Ok(false),
    };
    let result = server.email_set(request, access_token, session).await?;
    Ok(result.destroyed.len() == 1 && result.not_destroyed.is_empty())
}

pub(crate) async fn send_gmail_message(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    body: &[u8],
) -> trc::Result<HttpResponse> {
    for permission in [
        Permission::EmailSend,
        Permission::JmapEmailImport,
        Permission::JmapEmailUpdate,
        Permission::JmapEmailSubmissionCreate,
        Permission::JmapIdentityGet,
    ] {
        access_token.enforce_permission(permission)?;
    }
    let Ok(request) = serde_json::from_slice::<SendRequest>(body) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid send request"));
    };
    let Ok(raw) = URL_SAFE_NO_PAD.decode(request.raw.as_bytes()) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid base64url MIME"));
    };
    if raw.is_empty() || raw.len() > server.core.email.mail_max_size || !valid_mime(&raw) {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Invalid RFC 5322 MIME message",
        ));
    }
    let parsed = MessageParser::new()
        .parse(&raw)
        .expect("MIME was validated");
    let from = parsed
        .from()
        .and_then(|addresses| addresses.first())
        .and_then(|address| address.address.as_deref())
        .expect("From was validated");
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let expected_thread = if let Some(thread_id) = request.thread_id.as_deref() {
        let Some(id) = parse_thread_id(thread_id) else {
            return Ok(error(StatusCode::BAD_REQUEST, "Invalid thread ID"));
        };
        if !cache.emails.items.iter().any(|item| item.thread_id == id) {
            return Ok(error(StatusCode::NOT_FOUND, "Thread not found"));
        }
        Some(id)
    } else {
        None
    };

    let Some(drafts_id) = cache
        .mailboxes
        .items
        .iter()
        .find(|mb| mb.role == SpecialUse::Drafts)
        .map(|mb| mb.document_id)
    else {
        return Ok(error(StatusCode::CONFLICT, "Drafts mailbox is unavailable"));
    };
    let Some(sent_id) = cache
        .mailboxes
        .items
        .iter()
        .find(|mb| mb.role == SpecialUse::Sent)
        .map(|mb| mb.document_id)
    else {
        return Ok(error(StatusCode::CONFLICT, "Sent mailbox is unavailable"));
    };

    // The identity must belong to the authenticated account and match the
    // visible From header. EmailSubmission/set also checks the envelope From.
    let mut identity_id = None;
    for id in server.identity_get_or_create(account_id).await?.iter() {
        if let Some(archive) = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Identity,
                id,
            ))
            .await?
        {
            let identity = archive.unarchive::<Identity>()?;
            if identity.email.eq_ignore_ascii_case(from) {
                identity_id = Some(id);
                break;
            }
        }
    }
    let Some(identity_id) = identity_id else {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "From address is not a sending identity",
        ));
    };

    // Import to Drafts first. A rejected submission must never appear in Sent.
    // Stalwart's ingest assigns the authoritative message and thread IDs and
    // uses Stalwart's normal storage and change tracking.
    let ingested = server
        .email_ingest(IngestEmail {
            raw_message: &raw,
            blob_hash: None,
            message: Some(parsed),
            access_token,
            source: IngestSource::Jmap {
                train_classifier: false,
            },
            mailbox_ids: vec![drafts_id],
            keywords: vec![Keyword::Draft],
            received_at: None,
            session_id: session.session_id,
        })
        .await?;

    if expected_thread.is_some_and(|id| id != ingested.thread_id) {
        if !discard_unsent(server, access_token, session, ingested.document_id).await? {
            return Ok(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not discard unmatched reply",
            ));
        }
        return Ok(error(
            StatusCode::CONFLICT,
            "MIME reply headers did not match the requested thread",
        ));
    }

    let encoded = serde_json::to_vec(&json!({
        "accountId": Id::from(account_id).to_string(),
        "create": {"fog-send": {
            "emailId": Id::from_parts(ingested.thread_id, ingested.document_id).to_string(),
            "identityId": Id::from(identity_id).to_string(),
        }},
    }))
    .expect("valid submission request");
    let submission: SetRequest<'_, EmailSubmission> = match serde_json::from_slice(&encoded) {
        Ok(request) => request,
        Err(_) => {
            return Ok(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not construct submission",
            ));
        }
    };
    let mut next_call = None;
    let result = server
        .email_submission_set(submission, &session.instance, &mut next_call)
        .await?;
    if result.created.is_empty() || !result.not_created.is_empty() {
        if !discard_unsent(server, access_token, session, ingested.document_id).await? {
            return Ok(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not discard rejected submission",
            ));
        }
        return Ok(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Mail submission was rejected",
        ));
    }
    // EmailSubmission/set may create a final submission record when every
    // RCPT command was rejected. Only a queue ID proves that DATA was accepted.
    let submission_id = result
        .created
        .get("fog-send")
        .and_then(|created| serde_json::to_value(created).ok())
        .and_then(|created| created["id"].as_str().and_then(|id| id.parse::<Id>().ok()))
        .map(|id| id.document_id());
    let Some(submission_id) = submission_id else {
        return Ok(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Submission result is missing its ID",
        ));
    };
    let Some(record) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::EmailSubmission,
            submission_id,
        ))
        .await?
    else {
        return Ok(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Submission result is missing",
        ));
    };
    if record.unarchive::<StoredSubmission>()?.queue_id.is_none() {
        if !discard_unsent(server, access_token, session, ingested.document_id).await? {
            return Ok(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not discard rejected submission",
            ));
        }
        return Ok(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "All recipients were rejected",
        ));
    }

    // After SMTP accepts the submission, move the stored copy to Sent through
    // Email/set so IMAP/JMAP and the Gmail history adapter see one normal item.
    let message_id = Id::from(ingested.document_id).to_string();
    let encoded = serde_json::to_vec(&json!({
        "accountId": Id::from(account_id).to_string(),
        "update": {&message_id: {
            "mailboxIds": {Id::from(sent_id).to_string(): true},
            "keywords/$draft": false,
            "keywords/$seen": true,
        }},
    }))
    .expect("valid Sent update");
    let update: SetRequest<'_, Email> = match serde_json::from_slice(&encoded) {
        Ok(request) => request,
        Err(_) => {
            return Ok(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not construct Sent update",
            ));
        }
    };
    let result = server.email_set(update, access_token, session).await?;
    if result.updated.is_empty() || !result.not_updated.is_empty() {
        return Ok(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Mail was accepted but its Sent copy could not be finalized",
        ));
    }
    let cache = server.get_cached_messages(account_id).await?;
    let Some(stored) = cache
        .emails
        .items
        .iter()
        .find(|item| item.document_id == ingested.document_id)
        .filter(|item| {
            item.mailboxes
                .iter()
                .any(|mailbox| mailbox.mailbox_id == sent_id)
        })
    else {
        return Ok(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Mail was accepted but its Sent copy is unavailable",
        ));
    };
    Ok(JsonResponse::new(SentMessage {
        id: message_id,
        thread_id: Id::from(stored.thread_id).to_string(),
    })
    .no_cache()
    .into_http_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_plain_html_and_attachment_mime() {
        for mime in [
            &b"From: David <david@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: Plain\r\n\r\nHello"[..],
            &b"From: david@example.test\r\nTo: bob@example.test\r\nSubject: HTML\r\nContent-Type: text/html\r\n\r\n<b>Hello</b>"[..],
            &b"From: david@example.test\r\nTo: bob@example.test\r\nSubject: Attachment\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nHello\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAE=\r\n--x--\r\n"[..],
        ] { assert!(valid_mime(mime)); }
        assert!(!valid_mime(b"broken"));
        assert!(!valid_mime(
            b"From: a@example.test\r\nSubject: Bad\r\n\r\nBody"
        ));
        assert!(!valid_mime(b"From: a@example.test\r\nTo: b@example.test\r\nBcc: c@example.test\r\nBcc: d@example.test\r\n\r\nBody"));
    }
}
