/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Gmail-shaped mailbox change hints for Macro. The only persisted state here is
//! watch delivery metadata; mailbox history stays in Stalwart's email log.

use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use common::{BuildServer, Inner, Server, auth::AccessToken, config::build_rsa_keypair};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use hyper::StatusCode;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use store::{
    IterateParams, SUBSPACE_FOG_GMAIL_WATCH, Store,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, assert::AssertValue, now},
};
use types::collection::SyncCollection;

use super::error;

const WATCH_LIFETIME: u64 = 7 * 24 * 60 * 60;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
static CONFIG: OnceLock<Result<Arc<PushConfig>, String>> = OnceLock::new();

struct PushConfig {
    client: Client,
    webhook_url: Url,
    topic: String,
    sender: String,
    audience: String,
    issuer: String,
    kid: String,
    signing_key: EncodingKey,
    jwks: serde_json::Value,
}

impl PushConfig {
    fn from_env() -> Result<Arc<Self>, String> {
        fn required(name: &str) -> Result<String, String> {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{name} is not configured"))
        }

        let webhook_url = Url::parse(&required("FOG_GMAIL_PUSH_URL")?)
            .map_err(|_| "FOG_GMAIL_PUSH_URL is invalid".to_string())?;
        if webhook_url.scheme() != "https"
            || webhook_url.host_str().is_none()
            || !webhook_url.username().is_empty()
            || webhook_url.password().is_some()
        {
            return Err("FOG_GMAIL_PUSH_URL must be an HTTPS URL without credentials".into());
        }
        let pem = std::fs::read_to_string(required("FOG_GMAIL_PUSH_KEY_FILE")?)
            .map_err(|_| "Unable to read FOG_GMAIL_PUSH_KEY_FILE".to_string())?;
        let key = build_rsa_keypair(&pem)?;
        let kid = URL_SAFE_NO_PAD.encode(&store::blake3::hash(&key.modulus).as_bytes()[..12]);
        let jwks = public_keys(&kid, &key.modulus, &key.exponent);
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "Unable to build Fog push HTTP client".to_string())?;
        Ok(Arc::new(Self {
            client,
            webhook_url,
            topic: required("FOG_GMAIL_PUSH_TOPIC")?,
            sender: required("FOG_GMAIL_PUSH_SENDER")?,
            audience: required("FOG_GMAIL_PUSH_AUDIENCE")?,
            issuer: required("FOG_GMAIL_PUSH_ISSUER")?,
            kid,
            signing_key: EncodingKey::from_rsa_der(&key.pkcs1_der),
            jwks,
        }))
    }
}

fn public_keys(kid: &str, modulus: &[u8], exponent: &[u8]) -> serde_json::Value {
    json!({"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(modulus),
        "e": URL_SAFE_NO_PAD.encode(exponent)
    }]})
}

fn config() -> Result<Arc<PushConfig>, &'static str> {
    CONFIG
        .get_or_init(PushConfig::from_env)
        .as_ref()
        .cloned()
        .map_err(|_| "Fog Gmail push is not configured")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WatchRequest {
    topic_name: String,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    label_filter_behavior: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WatchResponse {
    history_id: String,
    expiration: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct WatchRegistration {
    topic: String,
    expires: u64,
    notified: Option<u64>,
}

impl WatchRegistration {
    fn needs_delivery(&self, topic: &str, history_id: u64, current_time: u64) -> bool {
        self.expires > current_time && self.topic == topic && self.notified != Some(history_id)
    }
}

#[derive(Serialize)]
struct PushClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    email: &'a str,
    email_verified: bool,
    iat: u64,
    exp: u64,
}

fn watch_class(account_id: u32) -> AnyClass {
    AnyClass {
        subspace: SUBSPACE_FOG_GMAIL_WATCH,
        key: account_id.to_be_bytes().to_vec(),
    }
}

#[cfg(test)]
fn watch_key(account_id: u32) -> AnyKey<[u8; 4]> {
    AnyKey {
        subspace: SUBSPACE_FOG_GMAIL_WATCH,
        key: account_id.to_be_bytes(),
    }
}

async fn put_watch(
    store: &Store,
    account_id: u32,
    registration: &WatchRegistration,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(watch_class(account_id)),
        serde_json::to_vec(registration).expect("watch registration is serializable"),
    );
    store.write(batch.build_all()).await.map(|_| ())
}

async fn clear_watch(store: &Store, account_id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Any(watch_class(account_id)));
    store.write(batch.build_all()).await.map(|_| ())
}

async fn mark_notified(
    store: &Store,
    account_id: u32,
    raw: &str,
    registration: &WatchRegistration,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(
        ValueClass::Any(watch_class(account_id)),
        AssertValue::Hash(store::xxhash_rust::xxh3::xxh3_64(raw.as_bytes())),
    );
    batch.set(
        ValueClass::Any(watch_class(account_id)),
        serde_json::to_vec(registration).expect("watch registration is serializable"),
    );
    store.write(batch.build_all()).await.map(|_| ())
}

pub async fn watch(
    server: &Server,
    access_token: &AccessToken,
    body: &[u8],
) -> trc::Result<HttpResponse> {
    let Ok(config) = config() else {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Fog Gmail push is not configured",
        ));
    };
    let Ok(request) = serde_json::from_slice::<WatchRequest>(body) else {
        return Ok(error(StatusCode::BAD_REQUEST, "Invalid watch request"));
    };
    if request.topic_name != config.topic {
        return Ok(error(StatusCode::BAD_REQUEST, "Unsupported topicName"));
    }
    if !request.label_ids.is_empty() || request.label_filter_behavior.is_some() {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Watch label filters are not supported",
        ));
    }
    let account_id = access_token.account_id();
    let _ = server.account(account_id).await?;
    let history_id = server
        .store()
        .get_last_change_id(account_id, SyncCollection::Email.into())
        .await?
        .unwrap_or_default();
    let expires = now().saturating_add(WATCH_LIFETIME);
    let registration = WatchRegistration {
        topic: request.topic_name,
        expires,
        notified: None,
    };
    put_watch(server.store(), account_id, &registration).await?;
    Ok(JsonResponse::new(WatchResponse {
        history_id: history_id.to_string(),
        expiration: expires.saturating_mul(1000).to_string(),
    })
    .no_cache()
    .into_http_response())
}

pub async fn stop(server: &Server, access_token: &AccessToken) -> trc::Result<HttpResponse> {
    clear_watch(server.store(), access_token.account_id()).await?;
    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_no_store())
}

pub fn jwks() -> HttpResponse {
    match config() {
        Ok(config) => HttpResponse::new(StatusCode::OK)
            .with_content_type("application/json")
            .with_cache_control("public, max-age=60")
            .with_text_body(config.jwks.to_string()),
        Err(_) => error(StatusCode::NOT_FOUND, "Fog Gmail push is not configured"),
    }
}

fn notification(
    config: &PushConfig,
    email: &str,
    account_id: u32,
    history_id: u64,
) -> Result<(String, serde_json::Value), String> {
    let issued = now();
    let jwt = jsonwebtoken::encode(
        &Header {
            kid: Some(config.kid.clone()),
            ..Header::new(Algorithm::RS256)
        },
        &PushClaims {
            iss: &config.issuer,
            sub: &config.sender,
            aud: &config.audience,
            email: &config.sender,
            email_verified: true,
            iat: issued,
            exp: issued.saturating_add(300),
        },
        &config.signing_key,
    )
    .map_err(|_| "Unable to sign Fog Gmail push JWT".to_string())?;
    let data = URL_SAFE.encode(
        serde_json::to_vec(&json!({
            "emailAddress": email,
            "historyId": history_id,
        }))
        .expect("notification is serializable"),
    );
    let payload = json!({
        "message": {
            "data": data,
            "messageId": format!("{account_id}-{history_id}-{issued}"),
            "publishTime": chrono::Utc::now().to_rfc3339(),
        },
        "subscription": config.topic,
    });
    Ok((jwt, payload))
}

async fn deliver(
    config: &PushConfig,
    email: &str,
    account_id: u32,
    history_id: u64,
) -> Result<(), String> {
    let (jwt, payload) = notification(config, email, account_id, history_id)?;
    for attempt in 0..3 {
        match config
            .client
            .post(config.webhook_url.clone())
            .bearer_auth(&jwt)
            .json(&payload)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) if attempt == 2 => {
                return Err(format!("Macro webhook returned {}", response.status()));
            }
            Err(err) if attempt == 2 => {
                return Err(format!("Macro webhook delivery failed: {err}"));
            }
            _ => tokio::time::sleep(Duration::from_secs(1 << attempt)).await,
        }
    }
    unreachable!()
}

async fn poll_once(server: &Server, config: &PushConfig) -> trc::Result<()> {
    let mut registrations = Vec::new();
    server
        .store()
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace: SUBSPACE_FOG_GMAIL_WATCH,
                    key: 0u32.to_be_bytes(),
                },
                AnyKey {
                    subspace: SUBSPACE_FOG_GMAIL_WATCH,
                    key: u32::MAX.to_be_bytes(),
                },
            ),
            |key, value| {
                if key.len() >= 4 {
                    let account_id = u32::from_be_bytes(
                        key[key.len() - 4..].try_into().expect("length checked"),
                    );
                    registrations.push((account_id, String::from_utf8_lossy(value).into_owned()));
                }
                Ok(true)
            },
        )
        .await?;

    for (account_id, raw) in registrations {
        let Ok(mut registration) = serde_json::from_str::<WatchRegistration>(&raw) else {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Invalid Fog Gmail watch registration"
            );
            continue;
        };
        if registration.expires <= now() || registration.topic != config.topic {
            continue;
        }
        let latest = match server
            .store()
            .get_last_change_id(account_id, SyncCollection::Email.into())
            .await
        {
            Ok(value) => value.unwrap_or_default(),
            Err(err) => {
                trc::error!(err);
                continue;
            }
        };
        if !registration.needs_delivery(&config.topic, latest, now()) {
            continue;
        }
        let account = match server.account(account_id).await {
            Ok(account) => account,
            Err(err) => {
                trc::error!(err);
                continue;
            }
        };
        if let Err(err) = deliver(config, account.name(), account_id, latest).await {
            trc::event!(Server(trc::ServerEvent::ThreadError), Details = err);
            continue;
        }
        registration.notified = Some(latest);
        // A concurrent renew or stop must win; its registration is picked up next poll.
        let _ = mark_notified(server.store(), account_id, &raw, &registration).await;
    }
    Ok(())
}

pub fn spawn_dispatcher(inner: Arc<Inner>) {
    let Ok(config) = config() else {
        return;
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(POLL_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(err) = poll_once(&inner.build_server(), &config).await {
                trc::error!(err);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_uses_camel_case_and_epoch_millis() {
        let body = serde_json::to_value(WatchResponse {
            history_id: "42".into(),
            expiration: "1790000000000".into(),
        })
        .unwrap();
        assert_eq!(
            body,
            json!({"historyId": "42", "expiration": "1790000000000"})
        );
        let request: WatchRequest =
            serde_json::from_value(json!({"topicName":"projects/fog/topics/macro"})).unwrap();
        assert_eq!(request.topic_name, "projects/fog/topics/macro");
    }

    #[test]
    fn watch_key_is_per_account() {
        assert_ne!(watch_class(1), watch_class(2));
        assert_eq!(watch_class(1).key, 1u32.to_be_bytes());
    }

    #[test]
    fn initial_change_and_expiration_decide_delivery() {
        let mut watch = WatchRegistration {
            topic: "topic".into(),
            expires: 100,
            notified: None,
        };
        assert!(watch.needs_delivery("topic", 0, 10)); // Gmail's initial hint.
        watch.notified = Some(10);
        assert!(!watch.needs_delivery("topic", 10, 10));
        assert!(watch.needs_delivery("topic", 11, 10));
        assert!(!watch.needs_delivery("other", 11, 10));
        assert!(!watch.needs_delivery("topic", 11, 100));
    }

    #[tokio::test]
    async fn watch_storage_isolates_accounts_and_rejects_stale_delivery() {
        use store::backend::ephemeral::EphemeralStore;
        let store = EphemeralStore::open();
        let alice = WatchRegistration {
            topic: "topic".into(),
            expires: 100,
            notified: None,
        };
        let bob = WatchRegistration {
            topic: "topic".into(),
            expires: 200,
            notified: None,
        };
        put_watch(&store, 1, &alice).await.unwrap();
        put_watch(&store, 2, &bob).await.unwrap();
        let old_raw = store
            .get_value::<String>(watch_key(1))
            .await
            .unwrap()
            .unwrap();
        put_watch(
            &store,
            1,
            &WatchRegistration {
                expires: 300,
                ..alice.clone()
            },
        )
        .await
        .unwrap();
        assert!(
            mark_notified(
                &store,
                1,
                &old_raw,
                &WatchRegistration {
                    notified: Some(5),
                    ..alice
                }
            )
            .await
            .is_err()
        );
        clear_watch(&store, 2).await.unwrap();
        assert!(
            store
                .get_value::<String>(watch_key(2))
                .await
                .unwrap()
                .is_none()
        );
        let current: WatchRegistration = serde_json::from_str(
            &store
                .get_value::<String>(watch_key(1))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(current.expires, 300);
        assert_eq!(current.notified, None);
    }

    #[test]
    fn notification_has_macro_payload_and_verifiable_fog_identity() {
        use jsonwebtoken::{DecodingKey, Validation, decode};
        use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};

        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let config = PushConfig {
            client: Client::new(),
            webhook_url: Url::parse("https://macro.example.test/webhook").unwrap(),
            topic: "projects/fog/topics/macro".into(),
            sender: "stalwart-push@example.test".into(),
            audience: "macro-gmail-webhook".into(),
            issuer: "https://mail.example.test/gmail".into(),
            kid: "fog-test".into(),
            signing_key: EncodingKey::from_rsa_der(key.to_pkcs1_der().unwrap().as_bytes()),
            jwks: public_keys("fog-test", &key.n().to_bytes_be(), &key.e().to_bytes_be()),
        };
        let (jwt, payload) = notification(&config, "alice@example.test", 1, 42).unwrap();
        assert_eq!(payload["subscription"], config.topic);
        assert!(payload["message"]["messageId"].is_string());
        assert!(payload["message"]["publishTime"].is_string());
        let data = URL_SAFE
            .decode(payload["message"]["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&data).unwrap(),
            json!({"emailAddress":"alice@example.test", "historyId":42})
        );

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["macro-gmail-webhook"]);
        validation.set_issuer(&["https://mail.example.test/gmail"]);
        let advertised = &config.jwks["keys"][0];
        assert_eq!(advertised["kid"], "fog-test");
        let claims = decode::<serde_json::Value>(
            &jwt,
            &DecodingKey::from_rsa_components(
                advertised["n"].as_str().unwrap(),
                advertised["e"].as_str().unwrap(),
            )
            .unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims["email"], "stalwart-push@example.test");
        assert_eq!(claims["email_verified"], true);
        assert_eq!(claims["iss"], "https://mail.example.test/gmail");
    }
}
