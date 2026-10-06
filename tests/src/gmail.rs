/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{smtp::inbound::TestMessage, utils::server::TestServerBuilder};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{auth::BuildAccessToken, ipc::PushNotification};
use email::mailbox::{INBOX_ID, SENT_ID, TRASH_ID};
use email::message::delivery::{IngestMessage, IngestRecipient, LocalDeliveryStatus, MailDelivery};
use jmap_client::mailbox::Role;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::{str::FromStr, time::Duration};
use types::{id::Id, type_state::DataType};
use utils::map::bitmap::Bitmap;

#[tokio::test(flavor = "multi_thread")]
async fn gmail_send_as_lists_account_identities_and_signatures() {
    let mut test = TestServerBuilder::new("fog_gmail_send_as")
        .await
        .with_http_listener(8904)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    for (name, password) in [
        ("alice@example.org", "velvet comet fern 7319"),
        ("bob@example.org", "copper lantern meadow 8427"),
    ] {
        let aliases: &'static [&'static str] = if name == "alice@example.org" {
            &["alice.alias@example.org"]
        } else {
            &[]
        };
        test.insert_account(
            admin
                .create_user_account(name, password, name, aliases, vec![])
                .await,
        );
    }

    let alice = test.account("alice@example.org");
    let client = alice.jmap_client().await;
    let mut request = client.build();
    request.get_identity();
    let identities = request.send_get_identity().await.unwrap().take_list();
    assert_eq!(identities.len(), 2);
    assert!(
        identities
            .iter()
            .any(|identity| identity.email() == Some(alice.name()))
    );
    // JMAP allows another identity for the same address. The configured
    // signature must take precedence over the blank automatic identity.
    let id = client
        .identity_create("Alice Signature", alice.name())
        .await
        .unwrap()
        .take_id();
    let signature = "<p>Sent from Alice</p>";
    let mut request = client.build();
    request.set_identity().update(&id).html_signature(signature);
    request
        .send_set_identity()
        .await
        .unwrap()
        .updated(&id)
        .unwrap();

    let http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let endpoint = "https://127.0.0.1:8904/gmail/v1/users/me/settings/sendAs";
    let unauthenticated = http.get(endpoint).send().await.unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"sendAs": [
            {
                "sendAsEmail": "alice.alias@example.org",
                "displayName": "alice@example.org",
                "signature": "",
                "isPrimary": false,
                "isDefault": false
            },
            {
                "sendAsEmail": "alice@example.org",
                "displayName": "Alice Signature",
                "signature": signature,
                "isPrimary": true,
                "isDefault": true
            }
        ]})
    );

    let bob = test.account("bob@example.org");
    let response = http
        .get(endpoint)
        .basic_auth(bob.name(), Some(bob.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"sendAs": [{
            "sendAsEmail": "bob@example.org",
            "displayName": "bob@example.org",
            "signature": "",
            "isPrimary": true,
            "isDefault": true
        }]})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gmail_message_list_isolated() {
    let mut test = TestServerBuilder::new("fog_gmail_message_list")
        .await
        .with_http_listener(8893)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    for (name, password) in [
        ("alice@example.org", "velvet comet fern 7319"),
        ("bob@example.org", "copper lantern meadow 8427"),
    ] {
        test.insert_account(
            admin
                .create_user_account(name, password, name, &[], vec![])
                .await,
        );
    }
    let alice = test.account("alice@example.org");
    let bob = test.account("bob@example.org");
    let alice_jmap = alice.jmap_client().await;
    let bob_jmap = bob.jmap_client().await;
    let import = |subject: &str| {
        format!(
            "From: alice@example.org\r\nTo: bob@example.org\r\nSubject: {subject}\r\nMessage-ID: <{subject}@example.org>\r\n\r\nBody"
        )
        .into_bytes()
    };
    let first = alice_jmap
        .email_import(
            import("sent-one"),
            [Id::from(SENT_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    let second = alice_jmap
        .email_import(
            import("sent-two"),
            [Id::from(SENT_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    alice_jmap
        .email_import(
            import("inbox"),
            [Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap();
    alice_jmap
        .email_import(
            import("trash"),
            [Id::from(TRASH_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap();
    bob_jmap
        .email_import(
            import("bob-sent"),
            [Id::from(SENT_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap();
    let first = Id::from(Id::from_str(&first).unwrap().document_id()).to_string();
    let second = Id::from(Id::from_str(&second).unwrap().document_id()).to_string();
    let http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let root = "https://127.0.0.1:8893/gmail/v1/users/me/messages";
    assert_eq!(
        http.get(root).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let fetch = |user: &str, password: &str, query: String| {
        http.get(format!("{root}{query}"))
            .basic_auth(user.to_string(), Some(password.to_string()))
    };
    let response = fetch(
        alice.name(),
        alice.secret(),
        "?maxResults=200&labelIds=SENT".into(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2, "{body}");
    assert_eq!(body["resultSizeEstimate"], 2);
    let ids: std::collections::HashSet<_> = messages
        .iter()
        .map(|message| message["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        std::collections::HashSet::from([first.as_str(), second.as_str()])
    );
    assert!(
        messages
            .iter()
            .all(|message| message["threadId"].is_string())
    );

    let first_page = fetch(
        alice.name(),
        alice.secret(),
        "?maxResults=1&labelIds=SENT".into(),
    )
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap();
    let page_token = first_page["nextPageToken"].as_str().unwrap();
    let next_page = fetch(
        alice.name(),
        alice.secret(),
        format!("?maxResults=1&labelIds=SENT&pageToken={page_token}"),
    )
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap();
    assert_ne!(
        first_page["messages"][0]["id"],
        next_page["messages"][0]["id"]
    );
    assert!(next_page.get("nextPageToken").is_none());
    assert_eq!(
        fetch(
            bob.name(),
            bob.secret(),
            format!("?labelIds=SENT&pageToken={page_token}")
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fetch(
            alice.name(),
            alice.secret(),
            format!("?labelIds=INBOX&pageToken={page_token}")
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fetch(alice.name(), alice.secret(), "?q=from%3Abob".into())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let all = fetch(alice.name(), alice.secret(), "".into())
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(all["messages"].as_array().unwrap().len(), 3);
    let all_with_trash = fetch(
        alice.name(),
        alice.secret(),
        "?includeSpamTrash=true".into(),
    )
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(all_with_trash["messages"].as_array().unwrap().len(), 4);
    let bob_list = fetch(bob.name(), bob.secret(), "?labelIds=SENT".into())
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(bob_list["messages"].as_array().unwrap().len(), 1);

    let starred = http
        .post(format!("{root}/{first}/modify"))
        .basic_auth(alice.name(), Some(alice.secret()))
        .json(&json!({"addLabelIds": ["STARRED"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(starred.status(), StatusCode::OK);
    let both = fetch(
        alice.name(),
        alice.secret(),
        "?labelIds=SENT&labelIds=STARRED".into(),
    )
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(both["messages"].as_array().unwrap().len(), 1);
    assert_eq!(both["messages"][0]["id"], first);
    assert_eq!(
        fetch(
            alice.name(),
            alice.secret(),
            format!("?labelIds=SENT&pageToken={page_token}")
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::CONFLICT
    );
    test.shutdown();
}

async fn deliver_filter_message(
    test: &crate::utils::server::TestServer,
    sender: &str,
    subject: &str,
) {
    let raw = format!(
        "From: {sender}\r\nTo: alice@example.org\r\nSubject: {subject}\r\nMessage-ID: <{}@remote.org>\r\n\r\nTest message",
        subject.replace(' ', "-")
    );
    let (blob, _) = test
        .server
        .put_temporary_blob(
            test.account("alice@example.org").id().document_id(),
            raw.as_bytes(),
            60,
        )
        .await
        .unwrap();
    let result = test
        .server
        .deliver_message(IngestMessage {
            sender_address: sender.to_string(),
            sender_authenticated: true,
            recipients: vec![IngestRecipient {
                address: "alice@example.org".to_string(),
                orcpt: None,
                spam_percentage: None,
            }],
            message_blob: blob,
            message_size: raw.len() as u64,
            session_id: 0,
        })
        .await;
    assert_eq!(result.status, vec![LocalDeliveryStatus::Success]);
}

#[tokio::test(flavor = "multi_thread")]
async fn gmail_sender_trash_filters_isolated() {
    let mut test = TestServerBuilder::new("fog_gmail_sender_trash_filters")
        .await
        .with_http_listener(8898)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    for (name, password) in [
        ("alice@example.org", "velvet comet fern 7319"),
        ("bob@example.org", "copper lantern meadow 8427"),
    ] {
        test.insert_account(
            admin
                .create_user_account(name, password, name, &[], vec![])
                .await,
        );
    }
    let alice = test.account("alice@example.org");
    let bob = test.account("bob@example.org");
    let jmap = alice.jmap_client().await;
    let http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let endpoint = "https://127.0.0.1:8898/gmail/v1/users/me/settings/filters";

    let empty = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    assert_eq!(empty.json::<Value>().await.unwrap(), json!({"filter": []}));

    let create =
        json!({"criteria": {"from": "blocked@remote.org"}, "action": {"addLabelIds": ["TRASH"]}});
    let response = http
        .post(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .json(&create)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let created = response.json::<Value>().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("fog-filter-"));
    assert_eq!(created["action"]["addLabelIds"], json!(["TRASH"]));
    let response = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"filter": [created]})
    );

    let repeated = http.post(endpoint).basic_auth(alice.name(), Some(alice.secret()))
        .json(&json!({"criteria": {"from": "BLOCKED@remote.org"}, "action": {"addLabelIds": ["TRASH"]}}))
        .send().await.unwrap();
    assert_eq!(repeated.status(), StatusCode::OK);
    assert_eq!(repeated.json::<Value>().await.unwrap()["id"], id);
    for invalid in [
        json!({"criteria": {"from": "blocked@remote.org"}, "action": {"addLabelIds": ["INBOX"]}}),
        json!({"criteria": {"subject": "hello"}, "action": {"addLabelIds": ["TRASH"]}}),
        json!({"criteria": {"from": "x\"; stop;@remote.org"}, "action": {"addLabelIds": ["TRASH"]}}),
    ] {
        let response = http
            .post(endpoint)
            .basic_auth(alice.name(), Some(alice.secret()))
            .json(&invalid)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let foreign = http
        .delete(format!("{endpoint}/{id}"))
        .basic_auth(bob.name(), Some(bob.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

    deliver_filter_message(&test, "blocked@remote.org", "Blocked one").await;
    let ids = jmap
        .email_query(None::<jmap_client::email::query::Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .take_ids();
    assert_eq!(ids.len(), 1);
    let blocked = jmap
        .email_get(&ids[0], [jmap_client::email::Property::MailboxIds].into())
        .await
        .unwrap()
        .unwrap();
    assert!(
        blocked
            .mailbox_ids()
            .contains(&Id::from(TRASH_ID).to_string().as_str())
    );
    assert!(
        !blocked
            .mailbox_ids()
            .contains(&Id::from(INBOX_ID).to_string().as_str())
    );

    deliver_filter_message(&test, "allowed@remote.org", "Allowed one").await;
    let ids = jmap
        .email_query(None::<jmap_client::email::query::Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .take_ids();
    assert_eq!(ids.len(), 2);
    let mut inbox_count = 0;
    for id in &ids {
        let email = jmap
            .email_get(id, [jmap_client::email::Property::MailboxIds].into())
            .await
            .unwrap()
            .unwrap();
        if email
            .mailbox_ids()
            .contains(&Id::from(INBOX_ID).to_string().as_str())
        {
            inbox_count += 1;
        }
    }
    assert_eq!(inbox_count, 1);

    let second_request =
        json!({"criteria": {"from": "other@remote.org"}, "action": {"addLabelIds": ["TRASH"]}});
    let response = http
        .post(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .json(&second_request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second_id = response.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let response = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.json::<Value>().await.unwrap()["filter"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let response = http
        .delete(format!("{endpoint}/{second_id}"))
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    let remaining = response.json::<Value>().await.unwrap();
    assert_eq!(remaining["filter"].as_array().unwrap().len(), 1);
    assert_eq!(remaining["filter"][0]["id"], id);

    let response = http
        .delete(format!("{endpoint}/{id}"))
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"filter": []})
    );
    deliver_filter_message(&test, "blocked@remote.org", "After unblock").await;
    let ids = jmap
        .email_query(None::<jmap_client::email::query::Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .take_ids();
    assert_eq!(ids.len(), 3);
    let mut inbox_count = 0;
    for id in &ids {
        let email = jmap
            .email_get(id, [jmap_client::email::Property::MailboxIds].into())
            .await
            .unwrap()
            .unwrap();
        if email
            .mailbox_ids()
            .contains(&Id::from(INBOX_ID).to_string().as_str())
        {
            inbox_count += 1;
        }
    }
    assert_eq!(inbox_count, 2);
    let response = http
        .delete(format!("{endpoint}/{id}"))
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = http
        .post(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let managed_script = jmap
        .sieve_script_query(
            jmap_client::sieve::query::Filter::is_active(true).into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap()
        .take_ids()
        .pop()
        .unwrap();
    jmap.sieve_script_replace(&managed_script, b"keep;".to_vec(), true)
        .await
        .unwrap();
    let response = http
        .get(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = http
        .post(endpoint)
        .basic_auth(alice.name(), Some(alice.secret()))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let bob_jmap = bob.jmap_client().await;
    bob_jmap
        .sieve_script_create("personal", b"keep;".to_vec(), true)
        .await
        .unwrap();
    let response = http
        .post(endpoint)
        .basic_auth(bob.name(), Some(bob.secret()))
        .json(&create)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    test.shutdown();
}

const ROOT: &str = "https://127.0.0.1:8899/gmail/v1/users/me";

async fn post(
    client: &Client,
    user: &str,
    password: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = client
        .post(format!("{ROOT}{path}"))
        .basic_auth(user, Some(password))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

async fn get(client: &Client, user: &str, password: &str, path: &str) -> (StatusCode, Value) {
    let response = client
        .get(format!("{ROOT}{path}"))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

async fn delete(client: &Client, user: &str, password: &str, path: &str) -> StatusCode {
    client
        .delete(format!("{ROOT}{path}"))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test(flavor = "multi_thread")]
async fn gmail_modify_and_send_isolated() {
    let mut test = TestServerBuilder::new("fog_gmail_modify_and_send")
        .await
        .with_http_listener(8899)
        .await
        .capture_queue()
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    for (name, password) in [
        ("alice@example.org", "velvet comet fern 7319"),
        ("bob@example.org", "copper lantern meadow 8427"),
    ] {
        test.insert_account(
            admin
                .create_user_account(name, password, name, &[], vec![])
                .await,
        );
    }
    let alice = test.account("alice@example.org");
    let jmap = alice.jmap_client().await;
    let bob_jmap = test.account("bob@example.org").jmap_client().await;
    bob_jmap
        .mailbox_create("Private 1", None::<String>, Role::None)
        .await
        .unwrap();
    let bob_only_mailbox = bob_jmap
        .mailbox_create("Private 2", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let custom_id = jmap
        .mailbox_create("Projects", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let imported = jmap.email_import(
        b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Pilot\r\nMessage-ID: <pilot@example.org>\r\n\r\nHello".to_vec(),
        [Id::from(INBOX_ID).to_string()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let message_id = Id::from(Id::from_str(&imported).unwrap().document_id()).to_string();
    let http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let (status, profile) = get(&http, alice.name(), alice.secret(), "/profile").await;
    assert_eq!(status, StatusCode::OK);
    let cursor = profile["historyId"].as_str().unwrap().to_string();
    let token = test
        .server
        .access_token(alice.id().document_id())
        .await
        .unwrap()
        .build();
    let mut push = test
        .server
        .subscribe_push_manager(&token, Bitmap::from_iter([DataType::Email]))
        .await
        .unwrap();
    let path = format!("/messages/{message_id}/modify");
    let (status, changed) = post(&http, alice.name(), alice.secret(), &path,
        json!({"addLabelIds": ["STARRED", format!("stalwart-mailbox-{}", Id::from_str(&custom_id).unwrap().document_id())], "removeLabelIds": ["UNREAD"]})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let notification = tokio::time::timeout(Duration::from_secs(2), push.recv())
        .await
        .unwrap()
        .unwrap();
    let PushNotification::StateChange(state) = notification else {
        panic!("Expected Email state change");
    };
    assert_eq!(state.account_id, alice.id().document_id());
    assert!(state.types.contains(DataType::Email));
    assert!(state.change_id > cursor.parse::<u64>().unwrap());
    assert!(
        changed["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "STARRED")
    );
    assert!(
        !changed["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "UNREAD")
    );
    let (status, repeated) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"addLabelIds": ["STARRED"], "removeLabelIds": ["UNREAD"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{repeated}");
    let (status, history) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/history?startHistoryId={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert!(history["history"].as_array().unwrap().iter().any(|record| {
        record["messagesAdded"].as_array().is_some_and(|messages| {
            messages
                .iter()
                .any(|entry| entry["message"]["id"] == message_id)
        })
    }));
    let (status, unread) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"addLabelIds": ["UNREAD"], "removeLabelIds": ["STARRED"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{unread}");
    assert!(
        unread["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "UNREAD")
    );
    assert!(
        !unread["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "STARRED")
    );

    let (status, archived) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"removeLabelIds": ["INBOX"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{archived}");
    assert!(
        !archived["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "INBOX")
    );
    let (status, unarchived) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"addLabelIds": ["INBOX"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{unarchived}");
    assert!(
        unarchived["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "INBOX")
    );
    let (status, trashed) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"addLabelIds": ["TRASH"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{trashed}");
    assert!(
        trashed["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "TRASH")
    );
    assert!(
        !trashed["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "INBOX")
    );
    let (status, spam) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"addLabelIds": ["SPAM", "IMPORTANT"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{spam}");
    assert!(
        spam["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "SPAM")
    );
    assert!(
        spam["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "IMPORTANT")
    );
    assert!(
        !spam["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "TRASH")
    );
    let (status, restored) = post(
        &http,
        alice.name(),
        alice.secret(),
        &path,
        json!({"addLabelIds": ["INBOX"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert!(
        restored["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "INBOX")
    );
    assert!(
        !restored["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "SPAM")
    );
    for body in [
        json!({"addLabelIds": ["SENT"]}),
        json!({"addLabelIds": ["stalwart-mailbox-999999"]}),
        json!({"addLabelIds": [format!("stalwart-mailbox-{}", Id::from_str(&bob_only_mailbox).unwrap().document_id())]}),
        json!({"addLabelIds": ["INBOX"], "removeLabelIds": ["INBOX"]}),
        json!({"addLabelIds": ["INBOX", "TRASH"]}),
    ] {
        let (status, _) = post(&http, alice.name(), alice.secret(), &path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = post(
        &http,
        "bob@example.org",
        "copper lantern meadow 8427",
        &path,
        json!({"addLabelIds": ["STARRED"]}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let attachment = b"From: alice@example.org\r\nTo: bob@example.org\r\nSubject: File\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nFile attached\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=data.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n--x--\r\n";
    let (status, attachment_sent) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(attachment)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{attachment_sent}");
    let (status, attachment_stored) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{}", attachment_sent["id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{attachment_stored}");
    assert_eq!(
        attachment_stored["payload"]["parts"][1]["filename"],
        "data.bin"
    );
    let (status, rejected) = post(&http, alice.name(), alice.secret(), "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(b"From: alice@example.org\r\nTo: nobody@example.org\r\nSubject: Rejected\r\n\r\nNot deliverable")})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{rejected}");
    let queued_before = test.read_queued_messages().await.len();
    let (status, partial) = post(&http, alice.name(), alice.secret(), "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(b"From: alice@example.org\r\nTo: bob@example.org, nobody@example.org\r\nSubject: Partial rejection\r\n\r\nDo not send")})).await;
    // The Gmail adapter uses Stalwart's normal EmailSubmission behavior:
    // accepted recipients are queued, and per-recipient failures remain in
    // the JMAP submission rather than changing the Gmail response shape.
    assert_eq!(status, StatusCode::OK, "{partial}");
    assert_eq!(test.read_queued_messages().await.len(), queued_before + 1);
    let (status, partially_sent) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{}", partial["id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{partially_sent}");
    assert!(
        partially_sent["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!("SENT"))
    );

    // Archive an Inbox-only message: the server must retain another mailbox.
    let inbox_only = jmap.email_import(
        b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Archive\r\nMessage-ID: <archive@example.org>\r\n\r\nArchive me".to_vec(),
        [Id::from(INBOX_ID).to_string()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let inbox_only = Id::from(Id::from_str(&inbox_only).unwrap().document_id()).to_string();
    let (status, archive) = post(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{inbox_only}/modify"),
        json!({"removeLabelIds": ["INBOX"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{archive}");
    assert!(!archive["labelIds"].as_array().unwrap().iter().any(|v| {
        v.as_str()
            .is_some_and(|s| s.starts_with("stalwart-mailbox-"))
    }));
    assert!(
        !archive["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "INBOX")
    );
    let (status, archived_again) = post(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{inbox_only}/modify"),
        json!({"removeLabelIds": ["INBOX"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{archived_again}");
    let (status, labels) = get(&http, alice.name(), alice.secret(), "/labels").await;
    assert_eq!(status, StatusCode::OK, "{labels}");
    assert!(
        !labels["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label["name"] == "Archive")
    );

    // Creating a label must create a real mailbox with the same ID that the
    // list and modify endpoints expose.
    let (status, created) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/labels",
        json!({"name": "Work", "type": "user", "messageListVisibility": "show", "labelListVisibility": "labelShow", "color": null, "id": null}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["name"], "Work");
    assert_eq!(created["type"], "user");
    let label_id = created["id"].as_str().unwrap();
    let mailbox_id = label_id
        .strip_prefix("stalwart-mailbox-")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let (status, listed) = get(&http, alice.name(), alice.secret(), "/labels").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label["id"] == label_id)
    );
    assert!(
        jmap.mailbox_get(&Id::from(mailbox_id).to_string(), None::<Vec<_>>)
            .await
            .unwrap()
            .is_some()
    );
    let (status, _) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/labels",
        json!({"name": "work"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for body in [
        json!({"name": ""}),
        json!({"name": "Trimmed "}),
        json!({"name": "Colored", "color": {"textColor": "#ffffff"}}),
        json!({"name": "Inbox copy", "type": "system"}),
    ] {
        let (status, _) = post(&http, alice.name(), alice.secret(), "/labels", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let sole = jmap.email_import(
        b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Sole label\r\nMessage-ID: <sole@example.org>\r\n\r\nKeep me".to_vec(),
        [Id::from(mailbox_id).to_string()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let sole_id = Id::from(Id::from_str(&sole).unwrap().document_id()).to_string();
    let shared = jmap.email_import(
        b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Shared label\r\nMessage-ID: <shared@example.org>\r\n\r\nKeep me too".to_vec(),
        [Id::from(INBOX_ID).to_string(), Id::from(mailbox_id).to_string()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let shared_id = Id::from(Id::from_str(&shared).unwrap().document_id()).to_string();
    let (status, before_delete) = get(&http, alice.name(), alice.secret(), "/profile").await;
    assert_eq!(status, StatusCode::OK);
    let before_delete = before_delete["historyId"].as_str().unwrap();
    assert_eq!(
        delete(&http, alice.name(), alice.secret(), "/labels/INBOX").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        delete(
            &http,
            alice.name(),
            alice.secret(),
            "/labels/stalwart-mailbox-999999"
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let mut private_index = 3;
    let bob_private = loop {
        let id = bob_jmap
            .mailbox_create(
                format!("Private {private_index}"),
                None::<String>,
                Role::None,
            )
            .await
            .unwrap()
            .take_id();
        if jmap
            .mailbox_get(&id, None::<Vec<_>>)
            .await
            .unwrap()
            .is_none()
        {
            break format!(
                "stalwart-mailbox-{}",
                Id::from_str(&id).unwrap().document_id()
            );
        }
        private_index += 1;
    };
    assert_eq!(
        delete(
            &http,
            alice.name(),
            alice.secret(),
            &format!("/labels/{bob_private}")
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(
            &http,
            alice.name(),
            alice.secret(),
            &format!("/labels/{label_id}")
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let notification = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(PushNotification::StateChange(state)) = push.recv().await
                && state.account_id == alice.id().document_id()
                && state.types.contains(DataType::Email)
                && state.change_id > before_delete.parse::<u64>().unwrap()
            {
                break state;
            }
        }
    })
    .await
    .unwrap();
    assert!(notification.change_id > before_delete.parse::<u64>().unwrap());
    assert_eq!(
        delete(
            &http,
            alice.name(),
            alice.secret(),
            &format!("/labels/{label_id}")
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let (status, after_delete) = get(&http, alice.name(), alice.secret(), "/labels").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !after_delete["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label["id"] == label_id)
    );
    assert!(
        jmap.mailbox_get(&Id::from(mailbox_id).to_string(), None::<Vec<_>>)
            .await
            .unwrap()
            .is_none()
    );
    let (status, sole_message) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{sole_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sole_message}");
    assert!(
        !sole_message["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label == label_id)
    );
    let (status, shared_message) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{shared_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shared_message}");
    assert!(
        shared_message["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label == "INBOX")
    );
    assert!(
        !shared_message["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label == label_id)
    );
    let (status, changed_history) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/history?startHistoryId={before_delete}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed_history}");
    assert!(
        changed_history["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["messagesAdded"].as_array().is_some_and(|messages| {
                    messages
                        .iter()
                        .any(|entry| entry["message"]["id"] == sole_id)
                })
            })
    );
    let (status, empty) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/labels",
        json!({"name": "Empty"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{empty}");
    assert_eq!(
        delete(
            &http,
            alice.name(),
            alice.secret(),
            &format!("/labels/{}", empty["id"].as_str().unwrap())
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let (status, parent) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/labels",
        json!({"name": "Parent"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{parent}");
    let parent_id = parent["id"].as_str().unwrap();
    let parent_mailbox_id = parent_id
        .strip_prefix("stalwart-mailbox-")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let child = jmap
        .mailbox_create(
            "Child",
            Some(Id::from(parent_mailbox_id).to_string()),
            Role::None,
        )
        .await
        .unwrap()
        .take_id();
    let grandchild = jmap
        .mailbox_create("Grandchild", Some(child.clone()), Role::None)
        .await
        .unwrap()
        .take_id();
    let sibling = jmap
        .mailbox_create(
            "Sibling",
            Some(Id::from(parent_mailbox_id).to_string()),
            Role::None,
        )
        .await
        .unwrap()
        .take_id();
    let nested_only = jmap.email_import(
        b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Nested sole\r\nMessage-ID: <nested-sole@example.org>\r\n\r\nKeep nested mail".to_vec(),
        [child.clone(), grandchild.clone()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let nested_only_id = Id::from(Id::from_str(&nested_only).unwrap().document_id()).to_string();
    let nested_shared = jmap.email_import(
        b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Nested shared\r\nMessage-ID: <nested-shared@example.org>\r\n\r\nKeep inbox mail".to_vec(),
        [grandchild.clone(), Id::from(INBOX_ID).to_string()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let nested_shared_id =
        Id::from(Id::from_str(&nested_shared).unwrap().document_id()).to_string();
    let (status, before_nested_delete) = get(&http, alice.name(), alice.secret(), "/profile").await;
    assert_eq!(status, StatusCode::OK);
    let before_nested_delete = before_nested_delete["historyId"].as_str().unwrap();
    assert_eq!(
        delete(
            &http,
            alice.name(),
            alice.secret(),
            &format!("/labels/{parent_id}")
        )
        .await,
        StatusCode::NO_CONTENT
    );
    for id in [&child, &grandchild, &sibling] {
        assert!(
            jmap.mailbox_get(id, None::<Vec<_>>)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        jmap.mailbox_get(&Id::from(parent_mailbox_id).to_string(), None::<Vec<_>>)
            .await
            .unwrap()
            .is_none()
    );
    let (status, nested_labels) = get(&http, alice.name(), alice.secret(), "/labels").await;
    assert_eq!(status, StatusCode::OK);
    for id in [&child, &grandchild, &sibling] {
        let label_id = format!(
            "stalwart-mailbox-{}",
            Id::from_str(id).unwrap().document_id()
        );
        assert!(
            !nested_labels["labels"]
                .as_array()
                .unwrap()
                .iter()
                .any(|label| label["id"] == label_id)
        );
    }
    assert!(
        !nested_labels["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label["id"] == parent_id)
    );
    let (status, nested_only_message) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{nested_only_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{nested_only_message}");
    let (status, nested_shared_message) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{nested_shared_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{nested_shared_message}");
    assert!(
        nested_shared_message["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label == "INBOX")
    );
    let (status, nested_history) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/history?startHistoryId={before_nested_delete}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{nested_history}");
    assert!(
        nested_history["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["messagesAdded"].as_array().is_some_and(|messages| {
                    messages
                        .iter()
                        .any(|entry| entry["message"]["id"] == nested_only_id)
                })
            })
    );
    let raw = b"From: alice@example.org\r\nTo: bob@example.org\r\nBcc: alice@example.org\r\nSubject: Sent test\r\nMessage-ID: <sent@example.org>\r\nContent-Type: text/html\r\n\r\n<b>Hi</b>";
    let (status, sent) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(raw)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let sent_id = sent["id"].as_str().unwrap();
    let (status, stored) = get(
        &http,
        alice.name(),
        alice.secret(),
        &format!("/messages/{sent_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert_eq!(stored["threadId"], sent["threadId"]);
    assert!(
        stored["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "SENT")
    );
    let jmap_sent_id = Id::from_parts(
        Id::from_str(sent["threadId"].as_str().unwrap())
            .unwrap()
            .document_id(),
        Id::from_str(sent_id).unwrap().document_id(),
    )
    .to_string();
    let jmap_sent = jmap
        .email_get(&jmap_sent_id, None::<Vec<_>>)
        .await
        .unwrap()
        .unwrap();
    let sent_mailbox_id = Id::from(SENT_ID).to_string();
    assert!(jmap_sent.mailbox_ids().contains(&sent_mailbox_id.as_str()));
    let queued = test.last_queued_message().await;
    assert!(
        queued
            .message
            .recipients
            .iter()
            .any(|recipient| recipient.address.as_ref() == "alice@example.org")
    );
    assert!(
        queued
            .message
            .recipients
            .iter()
            .any(|recipient| recipient.address.as_ref() == "bob@example.org")
    );
    assert!(!queued.read_message(&test).await.contains("Bcc:"));
    let reply = b"From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Re: Pilot\r\nMessage-ID: <reply@example.org>\r\nIn-Reply-To: <pilot@example.org>\r\nReferences: <pilot@example.org>\r\n\r\nReply";
    let (status, replied) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(reply), "threadId": changed["threadId"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replied}");
    assert_eq!(replied["threadId"], changed["threadId"]);
    let (status, _) = post(&http, "bob@example.org", "copper lantern meadow 8427", "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(b"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: Re: Pilot\r\n\r\nWrong thread"), "threadId": changed["threadId"]})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = post(
        &http,
        alice.name(),
        alice.secret(),
        "/messages/send",
        json!({"raw": "not-base64!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        &http,
        "bob@example.org",
        "copper lantern meadow 8427",
        "/messages/send",
        json!({"raw": URL_SAFE_NO_PAD.encode(raw)}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, bob_label) = post(
        &http,
        "bob@example.org",
        "copper lantern meadow 8427",
        "/labels",
        json!({"name": "Bob Sole"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bob_label}");
    let bob_label_id = bob_label["id"].as_str().unwrap();
    let bob_mailbox_id = bob_label_id
        .strip_prefix("stalwart-mailbox-")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let bob_sole = bob_jmap.email_import(
        b"From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Sole Bob label\r\nMessage-ID: <bob-sole@example.org>\r\n\r\nPreserve".to_vec(),
        [Id::from(bob_mailbox_id).to_string()], None::<Vec<&str>>, None,
    ).await.unwrap().take_id();
    let bob_sole = Id::from(Id::from_str(&bob_sole).unwrap().document_id()).to_string();
    assert_eq!(
        delete(
            &http,
            "bob@example.org",
            "copper lantern meadow 8427",
            &format!("/labels/{bob_label_id}")
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let (status, bob_preserved) = get(
        &http,
        "bob@example.org",
        "copper lantern meadow 8427",
        &format!("/messages/{bob_sole}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bob_preserved}");
    assert!(
        !bob_preserved["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|label| label == bob_label_id)
    );
}
