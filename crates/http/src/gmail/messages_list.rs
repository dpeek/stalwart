/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Gmail-shaped message listing for Macro's sent-contact backfill.

use super::{error, thread_get::labels};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{MessageStoreCache, Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse, form_urlencoded};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use store::{
    search::{EmailSearchField, SearchComparator, SearchField, SearchQuery},
    write::SearchIndex,
};
use types::{collection::SyncCollection, id::Id};

const DEFAULT_MAX_RESULTS: usize = 100;
const MAX_RESULTS: usize = 500;

#[derive(Default)]
struct MessagesQuery {
    max_results: Option<usize>,
    page_token: Option<String>,
    label_ids: Vec<String>,
    include_spam_trash: bool,
}

impl MessagesQuery {
    fn parse(raw: Option<&str>) -> Option<Self> {
        let mut query = Self::default();
        let mut seen_include = false;
        for (key, value) in form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "maxResults" if query.max_results.is_none() => {
                    let max: usize = value.parse().ok()?;
                    if max == 0 {
                        return None;
                    }
                    query.max_results = Some(max.min(MAX_RESULTS));
                }
                "pageToken" if query.page_token.is_none() && !value.is_empty() => {
                    query.page_token = Some(value.into_owned());
                }
                "labelIds" | "labelIds[]" if !value.is_empty() => {
                    query.label_ids.push(value.into_owned());
                }
                "includeSpamTrash" if !seen_include => {
                    query.include_spam_trash = value.parse().ok()?;
                    seen_include = true;
                }
                // Gmail search syntax is not implemented. Reject it rather than
                // returning an unfiltered result to a caller that requested one.
                _ => return None,
            }
        }
        query.label_ids.sort_unstable();
        query.label_ids.dedup();
        Some(query)
    }
}

#[derive(Serialize, Deserialize)]
struct MessagesPageToken {
    account_id: u32,
    revision: u64,
    order_hash: [u8; 32],
    after: u32,
    label_ids: Vec<String>,
    include_spam_trash: bool,
}

impl MessagesPageToken {
    fn matches(&self, account_id: u32, query: &MessagesQuery) -> bool {
        self.account_id == account_id
            && self.label_ids == query.label_ids
            && self.include_spam_trash == query.include_spam_trash
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessagesPage {
    messages: Vec<MessageSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_page_token: Option<String>,
    result_size_estimate: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageSummary {
    id: String,
    thread_id: String,
}

fn encode_token(token: &MessagesPageToken) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(token).expect("message page token is serializable"))
}

fn decode_token(encoded: &str) -> Option<MessagesPageToken> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

fn matching_messages(cache: &MessageStoreCache, query: &MessagesQuery) -> HashMap<u32, u32> {
    cache
        .emails
        .items
        .iter()
        .filter_map(|item| {
            let present = labels(cache, item);
            let included = query.include_spam_trash
                || !present
                    .iter()
                    .any(|label| label == "SPAM" || label == "TRASH");
            (included && query.label_ids.iter().all(|label| present.contains(label)))
                .then_some((item.document_id, item.thread_id))
        })
        .collect()
}

fn ordered_messages(matches: &HashMap<u32, u32>, ordered_documents: &[u32]) -> Vec<(u32, u32)> {
    let mut seen = HashSet::new();
    let mut messages = Vec::with_capacity(matches.len());
    for document_id in ordered_documents {
        if let Some(&thread_id) = matches.get(document_id)
            && seen.insert(*document_id)
        {
            messages.push((*document_id, thread_id));
        }
    }
    // The search index can lag the cache. Include those messages until it catches up.
    let mut remainder: Vec<_> = matches
        .iter()
        .filter(|(document_id, _)| seen.insert(**document_id))
        .map(|(&document_id, &thread_id)| (document_id, thread_id))
        .collect();
    remainder.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    messages.extend(remainder);
    messages
}

fn order_hash(messages: &[(u32, u32)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (document_id, thread_id) in messages {
        hasher.update(document_id.to_be_bytes());
        hasher.update(thread_id.to_be_bytes());
    }
    hasher.finalize().into()
}

pub(super) async fn list_messages(
    server: &Server,
    access_token: &AccessToken,
    raw_query: Option<&str>,
) -> trc::Result<HttpResponse> {
    let Some(query) = MessagesQuery::parse(raw_query) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid message list query"));
    };
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let revision = cache.last_change_id;
    let page_token = if let Some(encoded) = query.page_token.as_deref() {
        let Some(token) = decode_token(encoded).filter(|token| token.matches(account_id, &query))
        else {
            return Ok(error(StatusCode::BAD_REQUEST, "Invalid page token"));
        };
        if token.revision != revision {
            return Ok(error(
                StatusCode::CONFLICT,
                "Mailbox changed; restart message listing",
            ));
        }
        Some(token)
    } else {
        None
    };

    let ordered_documents = server
        .search_store()
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(account_id)
                .with_mask(cache.email_document_ids())
                .with_comparator(SearchComparator::Field {
                    field: SearchField::Email(EmailSearchField::ReceivedAt),
                    ascending: false,
                }),
        )
        .await?;
    let current_revision = server
        .store()
        .get_last_change_id(account_id, SyncCollection::Email.into())
        .await?
        .unwrap_or_default();
    if current_revision != revision {
        return Ok(error(
            StatusCode::CONFLICT,
            "Mailbox changed; restart message listing",
        ));
    }
    let messages = ordered_messages(&matching_messages(&cache, &query), &ordered_documents);
    let hash = order_hash(&messages);
    if let Some(token) = &page_token
        && token.order_hash != hash
    {
        return Ok(error(
            StatusCode::CONFLICT,
            "Message order changed; restart message listing",
        ));
    }
    let start = if let Some(token) = &page_token {
        let Some(index) = messages
            .iter()
            .position(|(document_id, _)| *document_id == token.after)
        else {
            return Ok(error(StatusCode::BAD_REQUEST, "Invalid page token"));
        };
        index + 1
    } else {
        0
    };
    let end = start
        .saturating_add(query.max_results.unwrap_or(DEFAULT_MAX_RESULTS))
        .min(messages.len());
    let next_page_token = if end < messages.len() {
        Some(encode_token(&MessagesPageToken {
            account_id,
            revision,
            order_hash: hash,
            after: messages[end - 1].0,
            label_ids: query.label_ids,
            include_spam_trash: query.include_spam_trash,
        }))
    } else {
        None
    };
    Ok(JsonResponse::new(MessagesPage {
        messages: messages[start..end]
            .iter()
            .map(|(document_id, thread_id)| MessageSummary {
                id: Id::from(*document_id).to_string(),
                thread_id: Id::from(*thread_id).to_string(),
            })
            .collect(),
        next_page_token,
        result_size_estimate: u32::try_from(messages.len()).unwrap_or(u32::MAX),
    })
    .no_cache()
    .into_http_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macro_request_and_rejects_unsupported_queries() {
        let query = MessagesQuery::parse(Some("maxResults=200&labelIds=SENT")).unwrap();
        assert_eq!(query.max_results, Some(200));
        assert_eq!(query.label_ids, ["SENT"]);
        assert!(!query.include_spam_trash);
        assert!(
            MessagesQuery::parse(Some("labelIds=SENT&labelIds=STARRED&includeSpamTrash=true"))
                .is_some()
        );
        for raw in [
            "maxResults=0",
            "labelIds=",
            "q=from%3Abob",
            "includeSpamTrash=maybe",
        ] {
            assert!(MessagesQuery::parse(Some(raw)).is_none(), "{raw}");
        }
    }

    #[test]
    fn orders_messages_and_binds_page_tokens() {
        let matches = HashMap::from([(1, 10), (2, 20), (3, 10)]);
        let ordered = ordered_messages(&matches, &[3, 2, 3]);
        assert_eq!(ordered, [(3, 10), (2, 20), (1, 10)]);
        let query = MessagesQuery::parse(Some("labelIds=SENT")).unwrap();
        let token = MessagesPageToken {
            account_id: 7,
            revision: 42,
            order_hash: order_hash(&ordered),
            after: 2,
            label_ids: query.label_ids.clone(),
            include_spam_trash: false,
        };
        let decoded = decode_token(&encode_token(&token)).unwrap();
        assert!(decoded.matches(7, &query));
        assert!(!decoded.matches(8, &query));
        assert!(!decoded.matches(7, &MessagesQuery::default()));
        assert_ne!(decoded.order_hash, order_hash(&[(2, 20), (3, 10), (1, 10)]));
        let body = serde_json::to_value(MessagesPage {
            messages: vec![MessageSummary {
                id: Id::from(3u32).to_string(),
                thread_id: Id::from(10u32).to_string(),
            }],
            next_page_token: Some(encode_token(&token)),
            result_size_estimate: 3,
        })
        .unwrap();
        assert!(body["messages"][0]["id"].is_string());
        assert!(body["messages"][0]["threadId"].is_string());
        assert_eq!(body["resultSizeEstimate"], 3);
    }
}
