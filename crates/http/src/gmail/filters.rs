/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Macro's sender-to-Trash Gmail filters, stored in a single owned Sieve script.

use super::error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, auth::AccessToken};
use email::sieve::{SieveScript, ingest::SieveScriptIngest};
use http_proto::{HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse};
use hyper::StatusCode;
use jmap::{blob::upload::BlobUpload, changes::state::StateManager, sieve::set::SieveScriptSet};
use jmap_proto::{
    error::set::SetErrorType, method::set::SetRequest, object::sieve::Sieve, types::state::State,
};
use registry::schema::enums::Permission;
use serde::{Deserialize, Serialize};
use serde_json::json;
use store::{
    ValueKey,
    rand::{RngExt, rng},
    write::{AlignedBytes, Archive},
};
use types::{
    collection::{Collection, SyncCollection},
    field::SieveField,
    id::Id,
};

const SCRIPT_NAME: &str = "fog-gmail-filters-v1";
const HEADER: &str = "# fog-gmail-filters-v1\n";
const FILTER_PREFIX: &str = "# filter ";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Criteria {
    from: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Action {
    add_label_ids: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    id: String,
    criteria: Criteria,
    action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateFilter {
    criteria: Criteria,
    action: Action,
}

impl CreateFilter {
    fn valid(&self) -> bool {
        let address = self.criteria.from.as_str();
        let Some((local, domain)) = address.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && !domain.is_empty()
            && domain.contains('.')
            && address.is_ascii()
            && address.len() <= 254
            && !address.bytes().any(|b| {
                b.is_ascii_control()
                    || b.is_ascii_whitespace()
                    || matches!(b, b'"' | b'\\' | b'<' | b'>' | b',' | b';')
            })
            && !domain.contains('@')
            && self.action.add_label_ids == ["TRASH"]
    }
}

struct ManagedScript {
    id: Option<u32>,
    filters: Vec<Filter>,
    state: State,
}

fn render(filters: &[Filter]) -> String {
    let mut source = String::from(HEADER);
    for filter in filters {
        source.push_str(FILTER_PREFIX);
        source.push_str(
            &URL_SAFE_NO_PAD.encode(serde_json::to_vec(filter).expect("filter serializes")),
        );
        source.push('\n');
    }
    source.push_str("require [\"fileinto\", \"special-use\"];\n");
    for filter in filters {
        source.push_str("if address :is \"from\" \"");
        source.push_str(&filter.criteria.from);
        source.push_str("\" { fileinto :specialuse \"\\\\Trash\" \"Trash\"; stop; }\n");
    }
    source
}

fn parse(source: &str) -> Option<Vec<Filter>> {
    let mut lines = source.lines();
    if lines.next()? != HEADER.trim_end() {
        return None;
    }
    let mut filters = Vec::new();
    for line in lines.by_ref() {
        let Some(encoded) = line.strip_prefix(FILTER_PREFIX) else {
            break;
        };
        let filter: Filter = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()?;
        if !filter.id.starts_with("fog-filter-")
            || filter.id.len() != "fog-filter-".len() + 32
            || !filter.id["fog-filter-".len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || filters.iter().any(|prior: &Filter| {
                prior.id == filter.id
                    || prior
                        .criteria
                        .from
                        .eq_ignore_ascii_case(&filter.criteria.from)
            })
            || !(CreateFilter {
                criteria: filter.criteria.clone(),
                action: filter.action.clone(),
            })
            .valid()
        {
            return None;
        }
        filters.push(filter);
    }
    (render(&filters) == source).then_some(filters)
}

async fn load(
    server: &Server,
    account_id: u32,
) -> trc::Result<Result<ManagedScript, HttpResponse>> {
    let state = server
        .get_state(account_id, SyncCollection::SieveScript)
        .await?;
    let ids = server
        .document_ids_matching(
            account_id,
            Collection::SieveScript,
            SieveField::Name,
            SCRIPT_NAME.as_bytes(),
        )
        .await?;
    if ids.len() > 1 {
        return Ok(Err(error(
            StatusCode::CONFLICT,
            "Managed filter script is ambiguous",
        )));
    }
    let active = server.sieve_script_get_active_id(account_id).await?;
    let Some(id) = ids.min() else {
        if active.is_some() {
            return Ok(Err(error(
                StatusCode::CONFLICT,
                "Another Sieve script is active",
            )));
        }
        return Ok(Ok(ManagedScript {
            id: None,
            filters: Vec::new(),
            state,
        }));
    };
    if active != Some(id) {
        return Ok(Err(error(
            StatusCode::CONFLICT,
            "Managed filter script is not active",
        )));
    }
    let Some(record) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::SieveScript,
            id,
        ))
        .await?
    else {
        return Ok(Err(error(
            StatusCode::CONFLICT,
            "Managed filter script is missing",
        )));
    };
    let script = record.unarchive::<SieveScript>()?;
    let Some(bytes) = server
        .core
        .storage
        .blob
        .get_blob(script.blob_hash.0.as_ref(), 0..usize::MAX)
        .await?
    else {
        return Ok(Err(error(
            StatusCode::CONFLICT,
            "Managed filter script source is missing",
        )));
    };
    let source = bytes
        .get(..u32::from(script.size) as usize)
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let Some(filters) = source.and_then(parse) else {
        return Ok(Err(error(
            StatusCode::CONFLICT,
            "Managed filter script was edited outside Gmail API",
        )));
    };
    if server
        .get_state(account_id, SyncCollection::SieveScript)
        .await?
        != state
    {
        return Ok(Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Filter script changed; retry",
        )));
    }
    Ok(Ok(ManagedScript {
        id: Some(id),
        filters,
        state,
    }))
}

async fn save(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    managed: &ManagedScript,
) -> trc::Result<Option<HttpResponse>> {
    let account_id = access_token.account_id();
    let source = render(&managed.filters);
    let upload = server
        .blob_upload(
            account_id.into(),
            "application/sieve",
            source.as_bytes(),
            access_token,
        )
        .await?;
    let body = if let Some(id) = managed.id {
        json!({"accountId": Id::from(account_id).to_string(),
            "update": { (Id::from(id).to_string()): {"blobId": upload.blob_id.to_string()} }})
    } else {
        json!({"accountId": Id::from(account_id).to_string(),
            "create": {"fog": {"name": SCRIPT_NAME, "blobId": upload.blob_id.to_string(), "isActive": true}}})
    };
    let encoded = serde_json::to_vec(&body).expect("valid Sieve set request");
    let mut set: SetRequest<'_, Sieve> =
        serde_json::from_slice(&encoded).expect("valid Sieve set request");
    set.if_in_state = Some(managed.state.clone());
    let result = match server.sieve_script_set(set, access_token, session).await {
        Ok(result) => result,
        Err(err) if err.matches(trc::EventType::Jmap(trc::JmapEvent::StateMismatch)) => {
            return Ok(Some(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Filter script changed; retry",
            )));
        }
        Err(err) => return Err(err),
    };
    let failure = result
        .not_created
        .iter()
        .next()
        .map(|(_, failure)| failure)
        .or_else(|| result.not_updated.iter().next().map(|(_, failure)| failure));
    if let Some(failure) = failure {
        let status = match failure.error_type() {
            SetErrorType::Forbidden => StatusCode::FORBIDDEN,
            SetErrorType::OverQuota | SetErrorType::TooLarge => StatusCode::CONFLICT,
            SetErrorType::AlreadyExists => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        };
        return Ok(Some(error(status, "Filter script change was rejected")));
    }
    if managed.id.is_none() && result.created.len() != 1
        || managed.id.is_some() && result.updated.len() != 1
    {
        return Ok(Some(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Filter script did not change",
        )));
    }
    let active = server.sieve_script_get_active_id(account_id).await?;
    let updated = server
        .document_ids_matching(
            account_id,
            Collection::SieveScript,
            SieveField::Name,
            SCRIPT_NAME.as_bytes(),
        )
        .await?;
    if active.is_none() || active != updated.min() {
        return Ok(Some(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Filter script was not activated",
        )));
    }
    Ok(None)
}

pub(crate) async fn list_filters(
    server: &Server,
    access_token: &AccessToken,
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapSieveScriptGet)?;
    let managed = match load(server, access_token.account_id()).await? {
        Ok(managed) => managed,
        Err(response) => return Ok(response),
    };
    Ok(JsonResponse::new(json!({"filter": managed.filters}))
        .no_cache()
        .into_http_response())
}

pub(crate) async fn create_filter(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    body: &[u8],
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapSieveScriptCreate)?;
    access_token.enforce_permission(Permission::JmapSieveScriptUpdate)?;
    access_token.enforce_permission(Permission::SieveSetActive)?;
    let Ok(request) = serde_json::from_slice::<CreateFilter>(body) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid filter request"));
    };
    if !request.valid() {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Only an exact sender with addLabelIds [TRASH] is supported",
        ));
    }
    let mut managed = match load(server, access_token.account_id()).await? {
        Ok(managed) => managed,
        Err(response) => return Ok(response),
    };
    if let Some(existing) = managed.filters.iter().find(|filter| {
        filter
            .criteria
            .from
            .eq_ignore_ascii_case(&request.criteria.from)
    }) {
        return Ok(JsonResponse::new(existing).no_cache().into_http_response());
    }
    let filter = Filter {
        id: format!("fog-filter-{:032x}", rng().random::<u128>()),
        criteria: request.criteria,
        action: request.action,
    };
    managed.filters.push(filter.clone());
    if let Some(response) = save(server, access_token, session, &managed).await? {
        return Ok(response);
    }
    Ok(JsonResponse::new(filter).no_cache().into_http_response())
}

pub(crate) async fn delete_filter(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    id: &str,
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapSieveScriptUpdate)?;
    let mut managed = match load(server, access_token.account_id()).await? {
        Ok(managed) => managed,
        Err(response) => return Ok(response),
    };
    let previous = managed.filters.len();
    managed.filters.retain(|filter| filter.id != id);
    if managed.filters.len() == previous {
        return Ok(error(StatusCode::NOT_FOUND, "Filter not found"));
    }
    if let Some(response) = save(server, access_token, session, &managed).await? {
        return Ok(response);
    }
    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_no_store())
}
