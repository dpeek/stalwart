/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Gmail-shaped thread listing for Macro's initial backfill.

use super::error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, auth::AccessToken};
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
use types::id::Id;

const DEFAULT_MAX_RESULTS: usize = 100;
const MAX_RESULTS: usize = 500;

#[derive(Default)]
struct ThreadsQuery {
    max_results: Option<usize>,
    page_token: Option<String>,
    personal: bool,
}

impl ThreadsQuery {
    fn parse(raw: Option<&str>) -> Option<Self> {
        let mut query = Self::default();
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
                // Stalwart has no Gmail category classifier. Macro's priority
                // pass can still seed the most recent threads before its full sweep.
                "labelIds" if value == "CATEGORY_PERSONAL" && !query.personal => {
                    query.personal = true;
                }
                _ => return None,
            }
        }
        Some(query)
    }
}

#[derive(Serialize, Deserialize)]
struct ThreadsPageToken {
    account_id: u32,
    revision: u64,
    order_hash: [u8; 32],
    after: u32,
    personal: bool,
}

impl ThreadsPageToken {
    fn valid_for(
        &self,
        account_id: u32,
        revision: u64,
        personal: bool,
        order_hash: &[u8; 32],
    ) -> bool {
        self.account_id == account_id
            && self.revision == revision
            && self.personal == personal
            && &self.order_hash == order_hash
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreadsPage {
    threads: Vec<ThreadSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_page_token: Option<String>,
}

#[derive(Serialize)]
struct ThreadSummary {
    id: String,
}

fn encode_token(token: &ThreadsPageToken) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(token).expect("thread page token is serializable"))
}

fn decode_token(encoded: &str) -> Option<ThreadsPageToken> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

fn ordered_threads(document_threads: &[(u32, u32)], ordered_documents: &[u32]) -> Vec<u32> {
    let by_document: HashMap<_, _> = document_threads.iter().copied().collect();
    let mut seen = HashSet::new();
    let mut threads = Vec::new();
    for document_id in ordered_documents {
        if let Some(&thread_id) = by_document.get(document_id)
            && seen.insert(thread_id)
        {
            threads.push(thread_id);
        }
    }
    // Include documents omitted by a lagging search index. Their deterministic
    // fallback order keeps the listing complete until the index catches up.
    let mut remainder: Vec<_> = document_threads
        .iter()
        .map(|(_, thread_id)| *thread_id)
        .filter(|thread_id| seen.insert(*thread_id))
        .collect();
    remainder.sort_unstable_by(|a, b| b.cmp(a));
    threads.extend(remainder);
    threads
}

fn order_hash(threads: &[u32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for thread in threads {
        hasher.update(thread.to_be_bytes());
    }
    hasher.finalize().into()
}

fn page_start(threads: &[u32], after: Option<u32>) -> Option<usize> {
    after.map_or(Some(0), |after| {
        threads
            .iter()
            .position(|thread_id| *thread_id == after)
            .map(|index| index + 1)
    })
}

pub(super) async fn list_threads(
    server: &Server,
    access_token: &AccessToken,
    raw_query: Option<&str>,
) -> trc::Result<HttpResponse> {
    let Some(query) = ThreadsQuery::parse(raw_query) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid thread list query"));
    };
    let account_id = access_token.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let revision = cache.last_change_id;
    let page_token = if let Some(encoded) = query.page_token.as_deref() {
        let Some(token) = decode_token(encoded) else {
            return Ok(error(StatusCode::BAD_REQUEST, "Invalid page token"));
        };
        if token.account_id != account_id || token.personal != query.personal {
            return Ok(error(
                StatusCode::BAD_REQUEST,
                "Page token belongs to another listing",
            ));
        }
        if token.revision != revision {
            return Ok(error(
                StatusCode::CONFLICT,
                "Mailbox changed; restart thread listing",
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
    // The cache is refreshed from Stalwart's log. Refuse a moving listing so
    // offset-based pagination never silently skips a thread after a mail change.
    let current_revision = server
        .store()
        .get_last_change_id(account_id, types::collection::SyncCollection::Email.into())
        .await?
        .unwrap_or_default();
    if current_revision != revision {
        return Ok(error(
            StatusCode::CONFLICT,
            "Mailbox changed; restart thread listing",
        ));
    }

    let document_threads: Vec<_> = cache
        .emails
        .items
        .iter()
        .map(|item| (item.document_id, item.thread_id))
        .collect();
    let threads = ordered_threads(&document_threads, &ordered_documents);
    let order_hash = order_hash(&threads);
    if let Some(token) = &page_token
        && !token.valid_for(account_id, revision, query.personal, &order_hash)
    {
        return Ok(error(
            StatusCode::CONFLICT,
            "Thread order changed; restart thread listing",
        ));
    }
    let Some(start) = page_start(&threads, page_token.as_ref().map(|token| token.after)) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid page token"));
    };
    let max = query.max_results.unwrap_or(DEFAULT_MAX_RESULTS);
    let end = start.saturating_add(max).min(threads.len());
    let next_page_token = if end < threads.len() {
        Some(encode_token(&ThreadsPageToken {
            account_id,
            revision,
            order_hash,
            after: threads[end - 1],
            personal: query.personal,
        }))
    } else {
        None
    };
    Ok(JsonResponse::new(ThreadsPage {
        threads: threads[start..end]
            .iter()
            .map(|id| ThreadSummary {
                id: Id::from(*id).to_string(),
            })
            .collect(),
        next_page_token,
    })
    .no_cache()
    .into_http_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_matches_macro_priority_and_sweep_requests() {
        let priority =
            ThreadsQuery::parse(Some("maxResults=200&labelIds=CATEGORY_PERSONAL")).unwrap();
        assert!(priority.personal);
        assert_eq!(priority.max_results, Some(200));
        assert!(ThreadsQuery::parse(Some("maxResults=500&pageToken=abc")).is_some());
        assert!(ThreadsQuery::parse(Some("labelIds=UNKNOWN")).is_none());
        assert!(ThreadsQuery::parse(Some("maxResults=0")).is_none());
    }

    #[test]
    fn orders_unique_threads_and_pages_without_duplicates() {
        let pairs = [(1, 10), (2, 20), (3, 10), (4, 30)];
        let ordered = ordered_threads(&pairs, &[3, 2, 1, 4]);
        assert_eq!(ordered, vec![10, 20, 30]);
        let token = ThreadsPageToken {
            account_id: 7,
            revision: 42,
            order_hash: order_hash(&ordered),
            after: ordered[1],
            personal: false,
        };
        let decoded = decode_token(&encode_token(&token)).unwrap();
        assert!(decoded.valid_for(7, 42, false, &order_hash(&ordered)));
        assert!(!decoded.valid_for(8, 42, false, &order_hash(&ordered)));
        assert!(!decoded.valid_for(7, 43, false, &order_hash(&ordered)));
        assert!(!decoded.valid_for(7, 42, true, &order_hash(&ordered)));
        assert!(!decoded.valid_for(7, 42, false, &order_hash(&[20, 10, 30])));
        assert_eq!(page_start(&ordered, None), Some(0));
        assert_eq!(page_start(&ordered, Some(ordered[1])), Some(2));
        assert_eq!(
            &ordered[page_start(&ordered, Some(ordered[1])).unwrap()..],
            &[30]
        );
        assert_eq!(page_start(&ordered, Some(99)), None);
        let body = serde_json::to_value(ThreadsPage {
            threads: vec![ThreadSummary {
                id: Id::from(10u32).to_string(),
            }],
            next_page_token: Some(encode_token(&token)),
        })
        .unwrap();
        assert!(body["threads"][0]["id"].is_string());
        assert!(body["nextPageToken"].is_string());
    }
}
