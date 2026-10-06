/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    error,
    labels::mailbox_label_id,
    thread_get::{get_message, parse_message_id},
};
use common::{MessageStoreCache, Server, auth::AccessToken};
use email::cache::MessageCacheFetch;
use http_proto::{HttpResponse, HttpSessionData};
use hyper::StatusCode;
use jmap::{changes::state::JmapCacheState, email::set::EmailSet, mailbox::set::MailboxSet};
use jmap_proto::{
    method::set::SetRequest,
    object::{email::Email, mailbox::Mailbox},
};
use registry::schema::enums::Permission;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use types::{id::Id, special_use::SpecialUse};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModifyRequest {
    #[serde(default)]
    add_label_ids: Vec<String>,
    #[serde(default)]
    remove_label_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    Mailbox(u32),
    Unread,
    Starred,
    Important,
}

fn resolve_label(cache: &MessageStoreCache, label: &str) -> Result<Label, &'static str> {
    match label {
        "UNREAD" => Ok(Label::Unread),
        "STARRED" => Ok(Label::Starred),
        "IMPORTANT" => Ok(Label::Important),
        "SENT" | "DRAFT" => Err("SENT and DRAFT cannot be changed manually"),
        _ => cache
            .mailboxes
            .items
            .iter()
            .find(|mailbox| mailbox_label_id(mailbox).as_deref() == Some(label))
            .map(|mailbox| Label::Mailbox(mailbox.document_id))
            .ok_or("Unknown mailbox label"),
    }
}

fn plan(
    cache: &MessageStoreCache,
    current_mailboxes: impl IntoIterator<Item = u32>,
    request: &ModifyRequest,
) -> Result<(HashSet<u32>, Map<String, Value>), &'static str> {
    let adds: HashSet<&str> = request.add_label_ids.iter().map(String::as_str).collect();
    let removes: HashSet<&str> = request
        .remove_label_ids
        .iter()
        .map(String::as_str)
        .collect();
    if adds.len() != request.add_label_ids.len() || removes.len() != request.remove_label_ids.len()
    {
        return Err("Duplicate label ID");
    }
    if adds.iter().any(|id| removes.contains(id)) {
        return Err("Label ID cannot be added and removed together");
    }
    if ["INBOX", "TRASH", "SPAM"]
        .into_iter()
        .filter(|label| adds.contains(label))
        .count()
        > 1
    {
        return Err("INBOX, TRASH and SPAM cannot be added together");
    }

    let mut mailboxes: HashSet<u32> = current_mailboxes.into_iter().collect();
    let mut changes = Map::new();
    for (ids, add) in [
        (&request.add_label_ids, true),
        (&request.remove_label_ids, false),
    ] {
        for id in ids {
            match resolve_label(cache, id)? {
                Label::Mailbox(mailbox_id) => {
                    if add {
                        mailboxes.insert(mailbox_id);
                    } else {
                        mailboxes.remove(&mailbox_id);
                    }
                }
                Label::Unread => {
                    changes.insert("keywords/$seen".into(), Value::Bool(!add));
                }
                Label::Starred => {
                    changes.insert("keywords/$flagged".into(), Value::Bool(add));
                }
                Label::Important => {
                    changes.insert("keywords/$important".into(), Value::Bool(add));
                }
            }
        }
    }
    // Gmail treats these locations as exclusive. Apply the move even when the
    // caller only supplies the destination label.
    let destination = ["INBOX", "TRASH", "SPAM"]
        .into_iter()
        .find(|label| adds.contains(label));
    if let Some(destination) = destination {
        for mailbox in &cache.mailboxes.items {
            if matches!(
                mailbox_label_id(mailbox).as_deref(),
                Some("INBOX" | "TRASH" | "SPAM")
            ) && mailbox_label_id(mailbox).as_deref() != Some(destination)
            {
                mailboxes.remove(&mailbox.document_id);
            }
        }
    }
    Ok((mailboxes, changes))
}

pub(super) async fn ensure_archive_mailbox(
    server: &Server,
    access_token: &AccessToken,
    cache: &MessageStoreCache,
) -> trc::Result<Option<u32>> {
    if let Some(id) = cache
        .mailboxes
        .items
        .iter()
        .find(|mailbox| mailbox.role == SpecialUse::Archive)
        .map(|mailbox| mailbox.document_id)
    {
        return Ok(Some(id));
    }
    let existing = cache
        .mailboxes
        .items
        .iter()
        .find(|mailbox| mailbox.path.eq_ignore_ascii_case("Archive"))
        .map(|mailbox| mailbox.document_id);
    access_token.enforce_permission(if existing.is_some() {
        Permission::JmapMailboxUpdate
    } else {
        Permission::JmapMailboxCreate
    })?;
    let encoded = if let Some(id) = existing {
        serde_json::to_vec(&json!({
            "accountId": Id::from(access_token.account_id()).to_string(),
            "update": {Id::from(id).to_string(): {"role": "archive"}},
        }))
    } else {
        serde_json::to_vec(&json!({
            "accountId": Id::from(access_token.account_id()).to_string(),
            "create": {"fog-archive": {"name": "Archive", "role": "archive"}},
        }))
    }
    .expect("valid JMAP mailbox request");
    let request: SetRequest<'_, Mailbox> = match serde_json::from_slice(&encoded) {
        Ok(request) => request,
        Err(_) => return Ok(None),
    };
    let result = server.mailbox_set(request, access_token).await?;
    if !result.not_created.is_empty() || !result.not_updated.is_empty() {
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

pub(crate) async fn modify_message(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    raw_id: &str,
    body: &[u8],
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapEmailUpdate)?;
    let Some(document_id) = parse_message_id(raw_id) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid message ID"));
    };
    let Ok(request) = serde_json::from_slice::<ModifyRequest>(body) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid modify request"));
    };
    let account_id = access_token.account_id();
    let mut cache = server.get_cached_messages(account_id).await?;
    let Some(item) = cache
        .emails
        .items
        .iter()
        .find(|item| item.document_id == document_id)
    else {
        return Ok(error(StatusCode::NOT_FOUND, "Message not found"));
    };
    let current = item.mailboxes.iter().map(|mailbox| mailbox.mailbox_id);
    let (mut mailboxes, mut changes) = match plan(&cache, current, &request) {
        Ok(plan) => plan,
        Err(message) => return Ok(error(StatusCode::BAD_REQUEST, message)),
    };

    // JMAP rejects an empty membership set. Archive into the account's own
    // Archive mailbox when INBOX was the final membership.
    if mailboxes.is_empty() {
        let Some(archive_id) = ensure_archive_mailbox(server, access_token, &cache).await? else {
            return Ok(error(
                StatusCode::CONFLICT,
                "Could not create Archive mailbox",
            ));
        };
        cache = server.get_cached_messages(account_id).await?;
        mailboxes.insert(archive_id);
    }

    let mailbox_map: Map<_, _> = mailboxes
        .iter()
        .map(|id| (Id::from(*id).to_string(), Value::Bool(true)))
        .collect();
    changes.insert("mailboxIds".into(), Value::Object(mailbox_map));
    let encoded = serde_json::to_vec(&json!({
        "accountId": Id::from(account_id).to_string(),
        "update": {raw_id: Value::Object(changes)},
    }))
    .expect("valid JMAP request");
    let mut set: SetRequest<'_, Email> = match serde_json::from_slice(&encoded) {
        Ok(set) => set,
        Err(_) => {
            return Ok(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not construct label update",
            ));
        }
    };
    set.if_in_state = Some(cache.get_state(false));
    let result = server.email_set(set, access_token, session).await?;
    if !result.not_updated.is_empty() || result.updated.is_empty() {
        return Ok(error(
            StatusCode::CONFLICT,
            "Label update was rejected; retry after refreshing",
        ));
    }
    get_message(server, access_token, raw_id, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{MailboxCache, MailboxesCache, MessageStoreCache, MessagesCache, UpdateLock};
    use std::sync::Arc;

    fn cache() -> MessageStoreCache {
        let mailbox = |document_id, role, path: &str| MailboxCache {
            document_id,
            role,
            path: path.into(),
            name: path.into(),
            parent_id: u32::MAX,
            sort_order: 0,
            subscribers: Default::default(),
            uid_validity: 0,
            acls: Default::default(),
        };
        MessageStoreCache {
            emails: Arc::new(MessagesCache {
                change_id: 1,
                items: vec![].into_boxed_slice(),
                index: Default::default(),
                keywords: Default::default(),
                size: 0,
            }),
            mailboxes: Arc::new(MailboxesCache {
                change_id: 1,
                items: vec![
                    mailbox(0, SpecialUse::Inbox, "INBOX"),
                    mailbox(1, SpecialUse::Trash, "Trash"),
                    mailbox(42, SpecialUse::None, "Projects"),
                ]
                .into_boxed_slice(),
                index: Default::default(),
                size: 0,
            }),
            update_lock: Arc::new(UpdateLock::new()),
            last_change_id: 1,
            size: 0,
        }
    }

    #[test]
    fn plans_keywords_and_memberships_without_dropping_other_labels() {
        let request = ModifyRequest {
            add_label_ids: vec![
                "STARRED".into(),
                "UNREAD".into(),
                "stalwart-mailbox-42".into(),
                "TRASH".into(),
            ],
            remove_label_ids: vec!["INBOX".into()],
        };
        let (mailboxes, changes) = plan(&cache(), [0], &request).unwrap();
        assert_eq!(mailboxes, HashSet::from([1, 42]));
        assert_eq!(changes["keywords/$flagged"], true);
        assert_eq!(changes["keywords/$seen"], false);
        let request = ModifyRequest {
            add_label_ids: vec![],
            remove_label_ids: vec!["UNREAD".into(), "STARRED".into(), "IMPORTANT".into()],
        };
        let (_, changes) = plan(&cache(), [0], &request).unwrap();
        assert_eq!(changes["keywords/$seen"], true);
        assert_eq!(changes["keywords/$flagged"], false);
        assert_eq!(changes["keywords/$important"], false);
    }

    #[test]
    fn rejects_conflicts_unknown_and_foreign_mailboxes() {
        let cache = cache();
        for request in [
            ModifyRequest {
                add_label_ids: vec!["INBOX".into()],
                remove_label_ids: vec!["INBOX".into()],
            },
            ModifyRequest {
                add_label_ids: vec!["INBOX".into(), "INBOX".into()],
                remove_label_ids: vec![],
            },
            ModifyRequest {
                add_label_ids: vec!["stalwart-mailbox-99".into()],
                remove_label_ids: vec![],
            },
            ModifyRequest {
                add_label_ids: vec!["SENT".into()],
                remove_label_ids: vec![],
            },
        ] {
            assert!(plan(&cache, [0], &request).is_err());
        }
    }
}
