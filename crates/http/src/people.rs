/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! The small Google People read surface used by Macro. Page snapshots live in
//! Stalwart's expiring lookup store; sync cursors use the address-book log.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use calcard::vcard::{VCardProperty, VCardValue};
use common::{
    Server,
    auth::oauth::{GrantType, SCOPE_CONTACTS, crypto::SymmetricEncrypt},
};
use groupware::{cache::GroupwareCache, contact::ContactCard};
use hmac::{Hmac, KeyInit, Mac};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse, form_urlencoded,
};
use hyper::{Method, StatusCode};
use registry::schema::enums::Permission;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use store::{
    ValueKey,
    dispatch::lookup::KeyValue,
    query::log::Change,
    rand::{RngExt, rng},
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};

use crate::auth::authenticate::{Authenticator, HttpHeaders};

const PAGE_LIFETIME: u64 = 60 * 60;
const SYNC_LIFETIME: u64 = 7 * 24 * 60 * 60;
const MAX_PAGE_SIZE: usize = 1000;
const KV_FOG_PEOPLE_PAGE: u8 = 27;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Kind {
    Connections,
    Other,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    resource_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    names: Vec<Name>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    email_addresses: Vec<EmailAddress>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    photos: Vec<Photo>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    metadata: Option<Metadata>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Name {
    display_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct EmailAddress {
    value: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Photo {
    url: String,
    default: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Metadata {
    deleted: bool,
}

impl Person {
    fn deleted(account_id: u32, document_id: u32) -> Self {
        Self {
            resource_name: resource_name(account_id, document_id),
            names: vec![],
            email_addresses: vec![],
            photos: vec![],
            metadata: Some(Metadata { deleted: true }),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    account_id: u32,
    kind: Kind,
    query: String,
    people: Vec<Person>,
    sync_cursor: u64,
    issued_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    account_id: u32,
    kind: Kind,
    change_id: u64,
    issued_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Page {
    key: String,
    offset: usize,
}

#[derive(Default)]
struct ListQuery {
    fields: String,
    sources: Vec<String>,
    page_size: usize,
    page_token: Option<String>,
    sync_token: Option<String>,
    request_sync_token: bool,
}

impl ListQuery {
    fn parse(query: Option<&str>, kind: Kind) -> Option<Self> {
        let mut parsed = Self {
            page_size: 100,
            ..Default::default()
        };
        let mut seen_size = false;
        let mut seen_fields = false;
        let mut seen_sync = false;
        for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "personFields" if kind == Kind::Connections && !seen_fields => {
                    parsed.fields = value.into_owned();
                    seen_fields = true;
                }
                "readMask" if kind == Kind::Other && !seen_fields => {
                    parsed.fields = value.into_owned();
                    seen_fields = true;
                }
                "sources" => parsed.sources.push(value.into_owned()),
                "pageSize" if !seen_size => {
                    seen_size = true;
                    let size: usize = value.parse().ok()?;
                    parsed.page_size = if size == 0 { 100 } else { size };
                    if parsed.page_size > MAX_PAGE_SIZE {
                        return None;
                    }
                }
                "requestSyncToken" if !seen_sync => {
                    seen_sync = true;
                    parsed.request_sync_token = value.parse().ok()?;
                }
                "pageToken" if parsed.page_token.is_none() && !value.is_empty() => {
                    parsed.page_token = Some(value.into_owned());
                }
                "syncToken" if parsed.sync_token.is_none() && !value.is_empty() => {
                    parsed.sync_token = Some(value.into_owned());
                }
                "personFields" | "readMask" | "pageSize" | "requestSyncToken" | "pageToken"
                | "syncToken" => return None,
                _ => (),
            }
        }
        if !seen_fields || parsed.fields.is_empty() {
            return None;
        }
        parsed.sources.sort();
        Some(parsed)
    }

    fn fingerprint(&self) -> String {
        // A page token is valid only with the original page request's options.
        format!(
            "{}|{}|{}|{}",
            self.fields,
            self.sources.join(","),
            self.page_size,
            self.request_sync_token
        )
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| v.as_secs())
}

fn resource_name(account_id: u32, document_id: u32) -> String {
    format!("people/{account_id}-{}", Id::from(document_id))
}

fn bad_request(message: &str) -> HttpResponse {
    JsonResponse::with_status(
        StatusCode::BAD_REQUEST,
        json!({"error": {"code": 400, "message": message}}),
    )
    .no_cache()
    .into_http_response()
}

fn expired() -> HttpResponse {
    JsonResponse::with_status(StatusCode::BAD_REQUEST,
        json!({"error": {"code": 400, "message": "EXPIRED_SYNC_TOKEN", "status": "INVALID_ARGUMENT", "details": [{"reason": "EXPIRED_SYNC_TOKEN"}]}}))
        .no_cache().into_http_response()
}

fn sign<T: Serialize>(server: &Server, value: &T) -> String {
    let payload = serde_json::to_vec(value).expect("People cursor serializable");
    let nonce = rng().random::<[u8; SymmetricEncrypt::NONCE_LEN]>();
    let ciphertext = SymmetricEncrypt::new(
        server.core.oauth.oauth_key.as_bytes(),
        "fog-people-cursor-v1",
    )
    .encrypt_with_aad(&payload, &nonce, &[])
    .expect("People cursor encryption");
    let mut bytes = Vec::with_capacity(nonce.len() + ciphertext.len());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn verify<T: for<'de> Deserialize<'de>>(server: &Server, encoded: &str) -> Option<T> {
    if encoded.len() > 8192 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if bytes.len() < SymmetricEncrypt::NONCE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = bytes.split_at(SymmetricEncrypt::NONCE_LEN);
    let payload = SymmetricEncrypt::new(
        server.core.oauth.oauth_key.as_bytes(),
        "fog-people-cursor-v1",
    )
    .decrypt_with_aad(ciphertext, nonce, &[])
    .ok()?;
    serde_json::from_slice(&payload).ok()
}

fn embedded_photo(contact: &ContactCard) -> Option<(&str, &[u8])> {
    contact
        .card
        .properties(&VCardProperty::Photo)
        .flat_map(|entry| entry.values.iter())
        .find_map(|value| match value {
            VCardValue::Binary(data) if !data.data.is_empty() && data.data.len() <= 512 * 1024 => {
                let content_type = data.content_type.as_deref()?;
                matches!(
                    content_type,
                    "image/jpeg" | "image/png" | "image/gif" | "image/webp"
                )
                .then_some((content_type, data.data.as_slice()))
            }
            _ => None,
        })
}

fn photo_url(server: &Server, account_id: u32, document_id: u32, bytes: &[u8]) -> String {
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
    let message = format!("fog-people-photo-v1:{account_id}:{document_id}:{digest}");
    let mut mac = Hmac::<Sha256>::new_from_slice(server.core.oauth.oauth_key.as_bytes())
        .expect("HMAC accepts arbitrary key length");
    mac.update(message.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!(
        "{}/people/v1/photos/{account_id}.{document_id}.{digest}.{signature}",
        server.core.network.http.url_https.trim_end_matches('/')
    )
}

fn map_contact(
    server: &Server,
    account_id: u32,
    document_id: u32,
    contact: &ContactCard,
) -> Person {
    let email_addresses: Vec<_> = contact
        .card
        .properties(&VCardProperty::Email)
        .flat_map(|entry| entry.values.iter())
        .filter_map(|value| value.as_text())
        .filter(|value| !value.trim().is_empty())
        .map(|value| EmailAddress {
            value: value.to_string(),
        })
        .collect();
    let name = contact
        .card
        .property(&VCardProperty::Fn)
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_text())
        .filter(|name| !name.trim().is_empty())
        .or(contact
            .display_name
            .as_deref()
            .filter(|name| !name.trim().is_empty()));
    Person {
        resource_name: resource_name(account_id, document_id),
        names: name
            .map(|display_name| {
                vec![Name {
                    display_name: display_name.to_string(),
                }]
            })
            .unwrap_or_default(),
        email_addresses,
        photos: embedded_photo(contact)
            .map(|(_, bytes)| Photo {
                url: photo_url(server, account_id, document_id, bytes),
                default: false,
            })
            .into_iter()
            .collect(),
        metadata: None,
    }
}

async fn load_card(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<ContactCard>> {
    let Some(archive) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::ContactCard,
            document_id,
        ))
        .await?
    else {
        return Ok(None);
    };
    archive
        .deserialize::<ContactCard>()
        .caused_by(trc::location!())
        .map(Some)
}

async fn load_contact(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<Person>> {
    Ok(load_card(server, account_id, document_id)
        .await?
        .map(|card| map_contact(server, account_id, document_id, &card)))
}

async fn self_photo(server: &Server, account_id: u32, email: &str) -> trc::Result<Vec<Photo>> {
    let cache = server
        .fetch_dav_resources(account_id, account_id, SyncCollection::AddressBook)
        .await?;
    for document_id in cache.document_ids(false) {
        if let Some(person) = load_contact(server, account_id, document_id).await?
            && person
                .email_addresses
                .iter()
                .any(|address| address.value.trim().eq_ignore_ascii_case(email))
            && !person.photos.is_empty()
        {
            return Ok(person.photos);
        }
    }
    Ok(vec![])
}

async fn serve_photo(server: &Server, token: &str) -> trc::Result<HttpResponse> {
    let not_found = || HttpResponse::new(StatusCode::NOT_FOUND);
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 4 {
        return Ok(not_found());
    }
    let (Ok(account_id), Ok(document_id), Ok(digest), Ok(signature)) = (
        parts[0].parse::<u32>(),
        parts[1].parse::<u32>(),
        URL_SAFE_NO_PAD.decode(parts[2]),
        URL_SAFE_NO_PAD.decode(parts[3]),
    ) else {
        return Ok(not_found());
    };
    if digest.len() != 32 || signature.len() != 32 {
        return Ok(not_found());
    }
    let message = format!(
        "fog-people-photo-v1:{account_id}:{document_id}:{}",
        parts[2]
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(server.core.oauth.oauth_key.as_bytes())
        .expect("HMAC accepts arbitrary key length");
    mac.update(message.as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return Ok(not_found());
    }
    let Some(card) = load_card(server, account_id, document_id).await? else {
        return Ok(not_found());
    };
    let Some((content_type, bytes)) = embedded_photo(&card) else {
        return Ok(not_found());
    };
    if Sha256::digest(bytes).as_slice() != digest {
        return Ok(not_found());
    }
    Ok(HttpResponse::new(StatusCode::OK)
        .with_content_type(content_type)
        .with_header("Cache-Control", "no-store")
        .with_binary_body(bytes.to_vec()))
}

async fn list_snapshot(
    server: &Server,
    account_id: u32,
    kind: Kind,
    query: &ListQuery,
    from: Option<u64>,
) -> trc::Result<Result<Snapshot, HttpResponse>> {
    let issued_at = now();
    if kind == Kind::Other {
        return Ok(Ok(Snapshot {
            account_id,
            kind,
            query: query.fingerprint(),
            people: vec![],
            sync_cursor: 0,
            issued_at,
        }));
    }
    let collection = SyncCollection::AddressBook.into();
    let through = server
        .store()
        .get_last_change_id(account_id, collection)
        .await?
        .unwrap_or_default();
    let cache = server
        .fetch_dav_resources(account_id, account_id, SyncCollection::AddressBook)
        .await?;
    let allowed = cache
        .document_ids(false)
        .collect::<store::roaring::RoaringBitmap>();
    let mut people = Vec::new();
    if let Some(from) = from {
        if from > through {
            return Ok(Err(expired()));
        }
        let changes = server
            .store()
            .change_records(account_id, collection, from, through, usize::MAX)
            .await?;
        if !changes.cursor_valid {
            return Ok(Err(expired()));
        }
        let mut changed = BTreeMap::new();
        for (_, record) in changes.records {
            for change in record {
                match change {
                    Change::InsertItem(id) | Change::UpdateItem(id) => {
                        changed.insert(id as u32, false);
                    }
                    Change::DeleteItem(id) => {
                        changed.insert(id as u32, true);
                    }
                    _ => (),
                }
            }
        }
        for (id, deleted) in changed {
            if deleted || !allowed.contains(id) {
                people.push(Person::deleted(account_id, id));
            } else if let Some(person) = load_contact(server, account_id, id).await? {
                people.push(person);
            } else {
                people.push(Person::deleted(account_id, id));
            }
        }
    } else {
        for id in allowed.iter() {
            if let Some(person) = load_contact(server, account_id, id).await? {
                people.push(person);
            }
        }
    }
    Ok(Ok(Snapshot {
        account_id,
        kind,
        query: query.fingerprint(),
        people,
        sync_cursor: through,
        issued_at,
    }))
}

async fn response_page(
    server: &Server,
    snapshot: Snapshot,
    page_size: usize,
    key: Option<String>,
    offset: usize,
) -> trc::Result<HttpResponse> {
    let end = offset.saturating_add(page_size).min(snapshot.people.len());
    let next_page_token = if end < snapshot.people.len() {
        let key = if let Some(key) = key {
            key
        } else {
            let key = URL_SAFE_NO_PAD.encode(rng().random::<[u8; 24]>());
            server
                .in_memory_store()
                .key_set(
                    KeyValue::with_prefix(
                        KV_FOG_PEOPLE_PAGE,
                        key.as_bytes(),
                        serde_json::to_string(&snapshot)
                            .expect("People snapshot serializable")
                            .into_bytes(),
                    )
                    .expires(PAGE_LIFETIME),
                )
                .await?;
            key
        };
        Some(sign(server, &Page { key, offset: end }))
    } else {
        None
    };
    let next_sync_token = next_page_token.is_none().then(|| {
        sign(
            server,
            &Cursor {
                account_id: snapshot.account_id,
                kind: snapshot.kind,
                change_id: snapshot.sync_cursor,
                issued_at: snapshot.issued_at,
            },
        )
    });
    let people = &snapshot.people[offset..end];
    let body = match snapshot.kind {
        Kind::Connections => json!({"connections": people, "nextPageToken": next_page_token,
            "nextSyncToken": next_sync_token}),
        Kind::Other => json!({"otherContacts": people, "nextPageToken": next_page_token,
            "nextSyncToken": next_sync_token}),
    };
    Ok(JsonResponse::new(body).no_cache().into_http_response())
}

async fn list(
    server: &Server,
    account_id: u32,
    kind: Kind,
    raw_query: Option<&str>,
) -> trc::Result<HttpResponse> {
    let Some(query) = ListQuery::parse(raw_query, kind) else {
        return Ok(bad_request("Invalid People list query"));
    };
    if let Some(encoded) = query.page_token.as_deref() {
        let Some(page) = verify::<Page>(server, encoded) else {
            return Ok(bad_request("Invalid page token"));
        };
        let Some(bytes) = server
            .in_memory_store()
            .key_get::<String>(KeyValue::<()>::build_key(
                KV_FOG_PEOPLE_PAGE,
                page.key.as_bytes(),
            ))
            .await?
        else {
            return Ok(bad_request("Expired page token"));
        };
        let Ok(snapshot) = serde_json::from_str::<Snapshot>(&bytes) else {
            return Ok(bad_request("Invalid page token"));
        };
        if snapshot.account_id != account_id
            || snapshot.kind != kind
            || snapshot.query != query.fingerprint()
            || now().saturating_sub(snapshot.issued_at) > PAGE_LIFETIME
            || page.offset == 0
            || page.offset >= snapshot.people.len()
        {
            return Ok(bad_request("Invalid page token"));
        }
        return response_page(
            server,
            snapshot,
            query.page_size,
            Some(page.key),
            page.offset,
        )
        .await;
    }
    let from = if let Some(encoded) = query.sync_token.as_deref() {
        let Some(cursor) = verify::<Cursor>(server, encoded) else {
            return Ok(bad_request("Invalid sync token"));
        };
        if cursor.account_id != account_id || cursor.kind != kind {
            return Ok(bad_request("Invalid sync token"));
        }
        if cursor.issued_at > now() || now().saturating_sub(cursor.issued_at) > SYNC_LIFETIME {
            return Ok(expired());
        }
        Some(cursor.change_id)
    } else {
        None
    };
    match list_snapshot(server, account_id, kind, &query, from).await? {
        Ok(snapshot) => response_page(server, snapshot, query.page_size, None, 0).await,
        Err(response) => Ok(response),
    }
}

pub(crate) async fn route_request(
    server: &Server,
    req: &HttpRequest,
    session: &HttpSessionData,
) -> trc::Result<Option<HttpResponse>> {
    if req.method() != Method::GET {
        return Ok(None);
    }
    if let Some(token) = req.uri().path().strip_prefix("/people/v1/photos/") {
        return serve_photo(server, token).await.map(Some);
    }
    let endpoint = match req.uri().path() {
        "/people/v1/people/me" => 0,
        "/people/v1/people/me/connections" => 1,
        "/people/v1/otherContacts" => 2,
        _ => return Ok(None),
    };
    let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
    // Internal OAuth tokens carry their granted scope. Old scope-less tokens,
    // external bearer tokens, and mail-only grants fail closed on this API.
    if let Some((mechanism, bearer)) = req.authorization()
        && mechanism.eq_ignore_ascii_case("bearer")
    {
        let scoped = server
            .validate_access_token(Some(GrantType::AccessToken), bearer)
            .await
            .ok()
            .is_some_and(|info| {
                info.account_id == access_token.account_id()
                    && info.claims.as_deref().is_some_and(|scopes| {
                        scopes
                            .split_ascii_whitespace()
                            .any(|scope| scope == SCOPE_CONTACTS)
                    })
            });
        if !scoped {
            return Ok(JsonResponse::with_status(
                StatusCode::FORBIDDEN,
                json!({"error": {"code": 403, "message": "Contact scope required"}}),
            )
            .no_cache()
            .into_http_response()
            .into());
        }
    }
    access_token.enforce_permission(Permission::JmapContactCardGet)?;
    if endpoint != 0 {
        access_token.enforce_permission(Permission::JmapContactCardQuery)?;
        access_token.enforce_permission(Permission::JmapContactCardChanges)?;
    }
    let account_id = access_token.account_id();
    let response = match endpoint {
        0 => {
            let account = server.account_info(account_id).await?;
            let email = account.name().to_string();
            let display_name = account
                .description()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(&email);
            JsonResponse::new(Person {
                resource_name: "people/me".into(),
                names: vec![Name {
                    display_name: display_name.to_string(),
                }],
                email_addresses: vec![EmailAddress { value: email }],
                photos: self_photo(server, account_id, account.name()).await?,
                metadata: None,
            })
            .no_cache()
            .into_http_response()
        }
        1 => list(server, account_id, Kind::Connections, req.uri().query()).await?,
        _ => list(server, account_id, Kind::Other, req.uri().query()).await?,
    };
    Ok(Some(response))
}
