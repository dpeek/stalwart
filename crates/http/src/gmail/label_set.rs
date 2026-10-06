/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Gmail label writes backed by JMAP mailbox and email mutations.

use super::{error, labels::mailbox_label_id};
use common::{Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use http_proto::{HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse};
use hyper::StatusCode;
use jmap::{changes::state::JmapCacheState, email::set::EmailSet, mailbox::set::MailboxSet};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::SetRequest,
    object::{
        email::Email,
        mailbox::{Mailbox, MailboxProperty},
    },
};
use registry::schema::enums::Permission;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use types::{id::Id, special_use::SpecialUse};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateLabelRequest {
    name: String,
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    message_list_visibility: Option<String>,
    label_list_visibility: Option<String>,
    color: Option<Value>,
}

impl CreateLabelRequest {
    fn valid(&self) -> bool {
        !self.name.is_empty()
            && self.name == self.name.trim()
            && !self.name.chars().any(char::is_control)
            && self.id.is_none()
            && self.kind.as_deref().is_none_or(|kind| kind == "user")
            && self
                .message_list_visibility
                .as_deref()
                .is_none_or(|visibility| visibility == "show")
            && self
                .label_list_visibility
                .as_deref()
                .is_none_or(|visibility| visibility == "labelShow")
            && self.color.is_none()
    }
}

fn set_failure(failure: &SetError<MailboxProperty>) -> HttpResponse {
    let (status, message) = match failure.error_type() {
        SetErrorType::AlreadyExists => (StatusCode::CONFLICT, "Label already exists"),
        SetErrorType::Forbidden
            if failure
                .description()
                .is_some_and(|description| description.starts_with("Another process")) =>
        {
            (StatusCode::SERVICE_UNAVAILABLE, "Mailbox changed; retry")
        }
        SetErrorType::Forbidden => (StatusCode::FORBIDDEN, "Mailbox operation forbidden"),
        SetErrorType::OverQuota => (StatusCode::CONFLICT, "Mailbox quota exceeded"),
        SetErrorType::NotFound => (StatusCode::NOT_FOUND, "Label not found"),
        SetErrorType::MailboxHasChild => (StatusCode::CONFLICT, "Label has child mailboxes"),
        SetErrorType::MailboxHasEmail => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Label changed; retry deletion",
        ),
        _ => (StatusCode::BAD_REQUEST, "Mailbox operation rejected"),
    };
    error(status, message)
}

// Gmail labels can be nested, while Stalwart mailboxes have real parents.
// Keep the destination outside the tree being deleted, including when a
// custom mailbox in that tree is named Archive.
async fn archive_for_deletion(
    server: &Server,
    access_token: &AccessToken,
    cache: &common::MessageStoreCache,
) -> trc::Result<Option<u32>> {
    if let Some(mailbox) = cache
        .mailboxes
        .items
        .iter()
        .find(|mailbox| mailbox.role == SpecialUse::Archive)
    {
        return Ok(Some(mailbox.document_id));
    }

    access_token.enforce_permission(Permission::JmapMailboxCreate)?;
    let name = if cache
        .mailboxes
        .items
        .iter()
        .any(|mailbox| mailbox.is_root() && mailbox.name.eq_ignore_ascii_case("Archive"))
    {
        (1..)
            .map(|index| format!("Fog Archive {index}"))
            .find(|candidate| {
                !cache.mailboxes.items.iter().any(|mailbox| {
                    mailbox.is_root() && mailbox.name.eq_ignore_ascii_case(candidate)
                })
            })
            .expect("an unused archive name")
    } else {
        "Archive".to_string()
    };
    let encoded = serde_json::to_vec(&json!({
        "accountId": Id::from(access_token.account_id()).to_string(),
        "create": {"fog-archive": {"name": name, "role": "archive"}},
    }))
    .expect("valid JMAP mailbox request");
    let set: SetRequest<'_, Mailbox> =
        serde_json::from_slice(&encoded).expect("valid JMAP mailbox request");
    let result = server.mailbox_set(set, access_token).await?;
    if !result.not_created.is_empty() || result.created.len() != 1 {
        return Ok(None);
    }
    Ok(server
        .get_cached_messages(access_token.account_id())
        .await?
        .mailboxes
        .items
        .iter()
        .find(|mailbox| mailbox.role == SpecialUse::Archive)
        .map(|mailbox| mailbox.document_id))
}

pub(crate) async fn create_label(
    server: &Server,
    access_token: &AccessToken,
    body: &[u8],
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapMailboxCreate)?;
    let Ok(request) = serde_json::from_slice::<CreateLabelRequest>(body) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid label request"));
    };
    if !request.valid() {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Unsupported label properties",
        ));
    }
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    if cache
        .mailboxes
        .items
        .iter()
        .any(|mailbox| mailbox.path.eq_ignore_ascii_case(&request.name))
    {
        return Ok(error(StatusCode::CONFLICT, "Label already exists"));
    }
    let encoded = serde_json::to_vec(&json!({
        "accountId": Id::from(account_id).to_string(),
        "create": {"fog-label": {"name": request.name}},
    }))
    .expect("valid JMAP mailbox request");
    let mut set: SetRequest<'_, Mailbox> =
        serde_json::from_slice(&encoded).expect("valid JMAP mailbox request");
    set.if_in_state = Some(cache.get_state(true));
    let result = server.mailbox_set(set, access_token).await?;
    if let Some((_, failure)) = result.not_created.iter().next() {
        return Ok(set_failure(failure));
    }
    if result.created.is_empty() {
        return Ok(error(StatusCode::CONFLICT, "Label was not created"));
    }
    let cache = server.get_cached_messages(account_id).await?;
    let Some(mailbox) = cache
        .mailboxes
        .items
        .iter()
        .find(|mailbox| mailbox.path == request.name && mailbox.role == SpecialUse::None)
    else {
        return Ok(error(
            StatusCode::CONFLICT,
            "Created label could not be read",
        ));
    };
    Ok(JsonResponse::new(json!({
        "id": mailbox_label_id(mailbox).expect("custom mailbox label"),
        "name": mailbox.path,
        "type": "user",
    }))
    .no_cache()
    .into_http_response())
}

pub(crate) async fn delete_label(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    label_id: &str,
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapMailboxDestroy)?;
    let Some(document_id) = label_id
        .strip_prefix("stalwart-mailbox-")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Only custom labels can be deleted",
        ));
    };
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let Some(mailbox) = cache
        .mailboxes
        .items
        .iter()
        .find(|mailbox| mailbox.document_id == document_id)
    else {
        return Ok(error(StatusCode::NOT_FOUND, "Label not found"));
    };
    if mailbox.role != SpecialUse::None {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "System label cannot be deleted",
        ));
    }
    let mut tree = vec![document_id];
    let mut deleting = HashSet::from([document_id]);
    let mut index = 0;
    while index < tree.len() {
        for child in &cache.mailboxes.items {
            if child.parent_id == tree[index] && deleting.insert(child.document_id) {
                if child.role != SpecialUse::None {
                    return Ok(error(
                        StatusCode::CONFLICT,
                        "Label contains a system mailbox",
                    ));
                }
                tree.push(child.document_id);
            }
        }
        index += 1;
    }

    // A Gmail label can be the only visible mailbox on a message. Move those
    // messages to Archive before removing the label, so deleting a label never
    // deletes mail. JMAP refuses to destroy a nonempty mailbox below.
    let has_exclusive_message = cache.emails.items.iter().any(|message| {
        message
            .mailboxes
            .iter()
            .any(|entry| deleting.contains(&entry.mailbox_id))
            && message
                .mailboxes
                .iter()
                .all(|entry| deleting.contains(&entry.mailbox_id))
    });
    let archive_id = if has_exclusive_message {
        let Some(id) = archive_for_deletion(server, access_token, &cache).await? else {
            return Ok(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Could not create Archive mailbox",
            ));
        };
        Some(id)
    } else {
        None
    };
    let message_ids: Vec<u32> = server
        .get_cached_messages(account_id)
        .await?
        .emails
        .items
        .iter()
        .filter(|message| {
            message
                .mailboxes
                .iter()
                .any(|entry| deleting.contains(&entry.mailbox_id))
        })
        .map(|message| message.document_id)
        .collect();
    for batch in message_ids.chunks(server.core.jmap.set_max_objects.min(100).max(1)) {
        let cache = server.get_cached_messages(account_id).await?;
        let messages: Vec<_> = batch
            .iter()
            .filter_map(|id| {
                cache.email_by_id(id).filter(|message| {
                    message
                        .mailboxes
                        .iter()
                        .any(|entry| deleting.contains(&entry.mailbox_id))
                })
            })
            .collect();
        if messages.is_empty() {
            continue;
        }
        access_token.enforce_permission(Permission::JmapEmailUpdate)?;
        let mut updates = serde_json::Map::new();
        for message in &messages {
            let mut memberships: Vec<u32> = message
                .mailboxes
                .iter()
                .map(|entry| entry.mailbox_id)
                .filter(|id| !deleting.contains(id))
                .collect();
            if memberships.is_empty() {
                let Some(archive_id) = archive_id else {
                    return Ok(error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Mailbox changed during deletion",
                    ));
                };
                memberships.push(archive_id);
            }
            let mailbox_ids: serde_json::Map<_, _> = memberships
                .into_iter()
                .map(|id| (Id::from(id).to_string(), Value::Bool(true)))
                .collect();
            updates.insert(
                Id::from(message.document_id).to_string(),
                json!({"mailboxIds": mailbox_ids}),
            );
        }
        let encoded = serde_json::to_vec(&json!({
            "accountId": Id::from(account_id).to_string(),
            "update": updates,
        }))
        .expect("valid JMAP email request");
        let mut set: SetRequest<'_, Email> =
            serde_json::from_slice(&encoded).expect("valid JMAP email request");
        set.if_in_state = Some(cache.get_state(false));
        let result = server.email_set(set, access_token, session).await?;
        if !result.not_updated.is_empty() || result.updated.len() != messages.len() {
            return Ok(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Message changed during label deletion; retry",
            ));
        }
    }

    // Descendants first, parent last: a failed request leaves the original
    // label ID available so the same request can finish the remaining tree.
    for mailbox_id in tree.into_iter().rev() {
        let encoded = serde_json::to_vec(&json!({
            "accountId": Id::from(account_id).to_string(),
            "destroy": [Id::from(mailbox_id).to_string()],
        }))
        .expect("valid JMAP mailbox request");
        let set: SetRequest<'_, Mailbox> =
            serde_json::from_slice(&encoded).expect("valid JMAP mailbox request");
        let result = server.mailbox_set(set, access_token).await?;
        if let Some((_, failure)) = result.not_destroyed.iter().next() {
            return Ok(
                if matches!(
                    failure.error_type(),
                    SetErrorType::MailboxHasChild
                        | SetErrorType::MailboxHasEmail
                        | SetErrorType::NotFound
                ) {
                    error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Label changed; retry deletion",
                    )
                } else {
                    set_failure(failure)
                },
            );
        }
        if result.destroyed.len() != 1 {
            return Ok(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Label was not deleted",
            ));
        }
    }
    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_no_store())
}
