/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Gmail response adapter for Macro. Message IDs use Stalwart's
//! JMAP document IDs; history IDs remain the email log's numeric change IDs.

mod filters;
mod label_set;
mod labels;
mod messages_list;
mod modify;
mod routes;
mod send;
mod send_as;
mod thread_get;
mod threads;
pub mod watch;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, auth::AccessToken};
use email::cache::MessageCacheFetch;
pub(crate) use filters::{create_filter, delete_filter, list_filters};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse, form_urlencoded};
use hyper::StatusCode;
pub(crate) use label_set::{create_label, delete_label};
use labels::list_labels;
use messages_list::list_messages;
pub(crate) use modify::modify_message;
pub(crate) use routes::route_request;
pub(crate) use send::send_gmail_message;
pub(crate) use send_as::list_send_as;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, future::Future};
use store::query::log::Change;
pub(crate) use thread_get::{get_attachment, get_message, get_thread};
use threads::list_threads;
use types::{collection::SyncCollection, id::Id};

const DEFAULT_MAX_RESULTS: usize = 100;
const MAX_RESULTS: usize = 500;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    email_address: String,
    messages_total: usize,
    threads_total: usize,
    history_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryPage {
    history: Vec<HistoryRecord>,
    history_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_page_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryRecord {
    id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    messages_added: Vec<MessageChange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    messages_deleted: Vec<MessageChange>,
}

#[derive(Serialize)]
struct MessageChange {
    message: HistoryMessage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryMessage {
    id: String,
    // Macro deserializes this field but refetches the message for its labels and thread.
    thread_id: String,
}

#[derive(Serialize, Deserialize)]
struct PageToken {
    account_id: u32,
    start: u64,
    through: u64,
    after: u64,
}

impl PageToken {
    fn valid_for(&self, account_id: u32, start: u64, latest: u64) -> bool {
        self.account_id == account_id
            && self.start == start
            && self.start <= self.after
            && self.after <= self.through
            && self.through <= latest
    }
}

#[derive(Default)]
struct HistoryQuery {
    start: Option<u64>,
    max_results: Option<usize>,
    page_token: Option<String>,
}

impl HistoryQuery {
    fn parse(query: Option<&str>) -> Option<Self> {
        let mut result = Self::default();
        for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "startHistoryId" if result.start.is_none() => {
                    result.start = Some(value.parse().ok()?);
                }
                "maxResults" if result.max_results.is_none() => {
                    let max: usize = value.parse().ok()?;
                    if max == 0 {
                        return None;
                    }
                    result.max_results = Some(max.min(MAX_RESULTS));
                }
                "pageToken" if result.page_token.is_none() => {
                    result.page_token = Some(value.into_owned());
                }
                "startHistoryId" | "maxResults" | "pageToken" => return None,
                _ => (),
            }
        }
        result.start.map(|_| result)
    }
}

pub(crate) fn error(status: StatusCode, message: &str) -> HttpResponse {
    JsonResponse::with_status(
        status,
        json!({
            "error": { "code": status.as_u16(), "message": message }
        }),
    )
    .no_cache()
    .into_http_response()
}

fn encode_token(token: &PageToken) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(token).expect("page token is serializable"))
}

fn decode_token(encoded: &str) -> Option<PageToken> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

fn history_record(id: u64, changes: Vec<Change>) -> HistoryRecord {
    let mut record = HistoryRecord {
        id: id.to_string(),
        messages_added: Vec::new(),
        messages_deleted: Vec::new(),
    };
    for change in changes {
        let (document_id, deleted) = match change {
            Change::InsertItem(id) | Change::UpdateItem(id) => (id, false),
            Change::DeleteItem(id) => (id, true),
            _ => continue,
        };
        let entry = MessageChange {
            message: HistoryMessage {
                // Email log item IDs may include a thread prefix in the high
                // 32 bits. Gmail message GET addresses the document ID alone.
                id: Id::from(document_id as u32).to_string(),
                thread_id: String::new(),
            },
        };
        if deleted {
            record.messages_deleted.push(entry);
        } else {
            record.messages_added.push(entry);
        }
    }
    record
}

pub trait GmailCompat: Sync + Send {
    fn handle_gmail_compat(
        &self,
        endpoint: &str,
        query: Option<&str>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl GmailCompat for Server {
    async fn handle_gmail_compat(
        &self,
        endpoint: &str,
        query: Option<&str>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        // No account ID from the URL or page token is ever used for a store read.
        let account_id = access_token.account_id();
        if endpoint == "profile" {
            let account = self.account(account_id).await?;
            let cache = self.get_cached_messages(account_id).await?;
            let threads: HashSet<_> = cache.emails.items.iter().map(|m| m.thread_id).collect();
            return Ok(JsonResponse::new(Profile {
                email_address: account.name().to_string(),
                messages_total: cache.emails.items.len(),
                threads_total: threads.len(),
                history_id: cache.last_change_id.to_string(),
            })
            .no_cache()
            .into_http_response());
        }

        if endpoint == "threads" {
            return list_threads(self, access_token, query).await;
        }

        if endpoint == "messages" {
            return list_messages(self, access_token, query).await;
        }

        if endpoint == "labels" {
            return list_labels(self, access_token).await;
        }

        let Some(query) = HistoryQuery::parse(query) else {
            return Ok(error(StatusCode::BAD_REQUEST, "Invalid history query"));
        };
        let start = query.start.unwrap();
        let latest = self
            .store()
            .get_last_change_id(account_id, SyncCollection::Email.into())
            .await?
            .unwrap_or_default();
        let (through, after) = if let Some(encoded) = query.page_token.as_deref() {
            let Some(token) =
                decode_token(encoded).filter(|token| token.valid_for(account_id, start, latest))
            else {
                return Ok(error(StatusCode::BAD_REQUEST, "Invalid page token"));
            };
            (token.through, token.after)
        } else {
            (latest, start)
        };
        if start > through {
            return Ok(error(StatusCode::NOT_FOUND, "History cursor is invalid"));
        }
        let page = self
            .store()
            .change_records(
                account_id,
                SyncCollection::Email.into(),
                after,
                through,
                query.max_results.unwrap_or(DEFAULT_MAX_RESULTS),
            )
            .await?;
        if !page.cursor_valid {
            return Ok(error(
                StatusCode::NOT_FOUND,
                "History cursor is invalid or has been pruned; resync required",
            ));
        }
        let next_page_token = page
            .records
            .last()
            .filter(|_| page.has_more)
            .map(|(id, _)| {
                encode_token(&PageToken {
                    account_id,
                    start,
                    through,
                    after: *id,
                })
            });
        Ok(JsonResponse::new(HistoryPage {
            history: page
                .records
                .into_iter()
                .map(|(id, changes)| history_record(id, changes))
                .collect(),
            history_id: through.to_string(),
            next_page_token,
        })
        .no_cache()
        .into_http_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_cursor_and_token_are_stable() {
        let profile = serde_json::to_value(Profile {
            email_address: "alice@example.test".into(),
            messages_total: 0,
            threads_total: 0,
            history_id: 0u64.to_string(),
        })
        .unwrap();
        assert_eq!(profile["emailAddress"], "alice@example.test");
        assert_eq!(profile["messagesTotal"], 0);
        assert_eq!(profile["threadsTotal"], 0);
        assert_eq!(profile["historyId"], "0");
        let token = PageToken {
            account_id: 17,
            start: 23,
            through: 31,
            after: 29,
        };
        let encoded = encode_token(&token);
        let decoded = decode_token(&encoded).unwrap();
        assert_eq!(
            (
                decoded.account_id,
                decoded.start,
                decoded.through,
                decoded.after
            ),
            (17, 23, 31, 29)
        );
        assert!(decoded.valid_for(17, 23, 31));
        assert!(!decoded.valid_for(18, 23, 31));
        assert!(!decoded.valid_for(17, 24, 31));
        assert!(decode_token("invalid!").is_none());
        assert_eq!(
            HistoryQuery::parse(Some("startHistoryId=0&maxResults=500"))
                .unwrap()
                .start,
            Some(0)
        );
        assert!(HistoryQuery::parse(Some("startHistoryId=abc")).is_none());
    }

    #[test]
    fn item_changes_match_macro_history_shape() {
        let record = history_record(
            42,
            vec![
                Change::InsertItem(Id::from_parts(7, 1).id()),
                Change::UpdateItem(2),
                Change::DeleteItem(3),
            ],
        );
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(value["id"], "42");
        assert_eq!(value["messagesAdded"].as_array().unwrap().len(), 2);
        assert_eq!(value["messagesDeleted"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["messagesAdded"][0]["message"]["id"],
            Id::from(1u32).to_string()
        );
        assert!(value["messagesAdded"][0]["message"]["threadId"].is_string());
    }
}
