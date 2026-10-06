/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Gmail label listing backed by the authenticated account's mailbox cache.

use common::{MailboxCache, Server, auth::AccessToken};
use email::cache::MessageCacheFetch;
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use serde::Serialize;
use types::special_use::SpecialUse;

const SYSTEM_LABELS: &[(&str, &str)] = &[
    ("INBOX", "INBOX"),
    ("SENT", "SENT"),
    ("DRAFT", "DRAFT"),
    ("TRASH", "TRASH"),
    ("SPAM", "SPAM"),
    ("STARRED", "STARRED"),
    ("UNREAD", "UNREAD"),
    ("IMPORTANT", "IMPORTANT"),
];

#[derive(Serialize)]
struct LabelsPage {
    labels: Vec<Label>,
}

#[derive(Serialize)]
struct Label {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
}

pub(super) fn mailbox_label_id(mailbox: &MailboxCache) -> Option<String> {
    match mailbox.role {
        SpecialUse::Inbox => Some("INBOX".into()),
        SpecialUse::Sent => Some("SENT".into()),
        SpecialUse::Drafts => Some("DRAFT".into()),
        SpecialUse::Trash => Some("TRASH".into()),
        SpecialUse::Junk => Some("SPAM".into()),
        SpecialUse::Archive => None,
        _ => Some(format!("stalwart-mailbox-{}", mailbox.document_id)),
    }
}

fn labels_from_mailboxes(mailboxes: &[MailboxCache]) -> LabelsPage {
    let mut labels: Vec<_> = SYSTEM_LABELS
        .iter()
        .map(|(id, name)| Label {
            id: (*id).into(),
            name: (*name).into(),
            kind: "system",
        })
        .collect();
    labels.extend(mailboxes.iter().filter_map(|mailbox| {
        let id = mailbox_label_id(mailbox)?;
        (!SYSTEM_LABELS.iter().any(|(system_id, _)| *system_id == id)).then(|| Label {
            id,
            name: mailbox.path.clone(),
            kind: "user",
        })
    }));
    labels.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    LabelsPage { labels }
}

pub(super) async fn list_labels(
    server: &Server,
    access_token: &AccessToken,
) -> trc::Result<HttpResponse> {
    let cache = server
        .get_cached_messages(access_token.account_id())
        .await?;
    Ok(
        JsonResponse::new(labels_from_mailboxes(&cache.mailboxes.items))
            .no_cache()
            .into_http_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(document_id: u32, role: SpecialUse, path: &str) -> MailboxCache {
        MailboxCache {
            document_id,
            name: path.into(),
            path: path.into(),
            role,
            parent_id: u32::MAX,
            sort_order: 0,
            subscribers: Default::default(),
            uid_validity: 0,
            acls: Default::default(),
        }
    }

    #[test]
    fn system_and_custom_mailboxes_have_stable_macro_labels() {
        let inbox = mailbox(1, SpecialUse::Inbox, "INBOX");
        let custom = mailbox(42, SpecialUse::None, "Projects/Current");
        let page = labels_from_mailboxes(&[inbox.clone(), custom.clone()]);
        let value = serde_json::to_value(page).unwrap();
        let labels = value["labels"].as_array().unwrap();
        assert_eq!(mailbox_label_id(&inbox).as_deref(), Some("INBOX"));
        assert_eq!(
            mailbox_label_id(&custom).as_deref(),
            Some("stalwart-mailbox-42")
        );
        assert_eq!(
            mailbox_label_id(&mailbox(6, SpecialUse::Archive, "Archive")),
            None
        );
        assert_eq!(
            labels.iter().filter(|label| label["id"] == "INBOX").count(),
            1
        );
        assert!(
            labels
                .iter()
                .any(|label| label["id"] == "stalwart-mailbox-42"
                    && label["name"] == "Projects/Current"
                    && label["type"] == "user")
        );
        assert!(
            labels
                .iter()
                .any(|label| label["id"] == "UNREAD" && label["type"] == "system")
        );
    }
}
