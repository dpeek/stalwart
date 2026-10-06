/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServerBuilder};
use common::auth::oauth::{GrantType, SCOPE_CONTACTS, SCOPE_MAIL};
use jmap_proto::request::method::MethodObject;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use store::{
    Key, LogKey, SUBSPACE_LOGS,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use types::collection::SyncCollection;

const BASE: &str = "https://127.0.0.1:8897/people/v1";
const FIELDS: &str = "names,emailAddresses,photos";

#[tokio::test(flavor = "multi_thread")]
async fn admin_oauth_token_can_create_user_with_default_permissions() {
    let test = TestServerBuilder::new("fog_admin_oauth_permissions")
        .await
        .with_http_listener(8898)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    let domain_id = admin.find_or_create_domain("example.org").await;
    let token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            admin.id().document_id(),
            admin.name(),
            600,
            Some("openid offline_access"),
            None,
        )
        .await
        .unwrap();
    let response: Value = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://127.0.0.1:8898/jmap")
        .bearer_auth(token)
        .json(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
            "methodCalls": [["x:Account/set", {"create": {"probe": {
                "@type": "User",
                "name": "scope-probe",
                "domainId": domain_id.to_string(),
                "credentials": {"0": {"@type": "Password", "secret": "velvet comet fern 7319"}},
                "permissions": {"@type": "Inherit"},
                "roles": {"@type": "User"}
            }}}, "c1"]]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["methodResponses"][0][0], "x:Account/set");
    assert!(
        response["methodResponses"][0][1]["created"]["probe"]["id"].is_string(),
        "{response}"
    );
}

async fn get(client: &Client, path: &str, user: &str, password: &str) -> (StatusCode, Value) {
    get_at(client, BASE, path, user, password).await
}

async fn get_at(
    client: &Client,
    base: &str,
    path: &str,
    user: &str,
    password: &str,
) -> (StatusCode, Value) {
    let response = client
        .get(format!("{base}{path}"))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

fn connections_query(extra: &str) -> String {
    format!("/people/me/connections?personFields={FIELDS}&requestSyncToken=true{extra}")
}

fn contact(book: &str, name: &str, first: &str, second: Option<&str>) -> Value {
    let mut emails = json!({"e1": {"address": first}});
    if let Some(second) = second {
        emails["e2"] = json!({"address": second});
    }
    let mut books = serde_json::Map::new();
    books.insert(book.to_string(), json!(true));
    json!({"@type": "Card", "name": {"full": name}, "emails": emails,
        "addressBookIds": books})
}

#[tokio::test(flavor = "multi_thread")]
async fn people_contacts_read_sync_and_isolation() {
    let mut test = TestServerBuilder::new("fog_people_contacts")
        .await
        .with_http_listener(8897)
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
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // The People compatibility API requires a contacts grant. Native JMAP
    // and CardDAV retain the account's permissions for a mail-only bearer.
    let unauthenticated = client
        .get(format!("{BASE}/people/me"))
        .send()
        .await
        .unwrap();
    assert!(!unauthenticated.status().is_success());
    let mail_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_MAIL),
            None,
        )
        .await
        .unwrap();
    let denied = client
        .get(format!("{BASE}/people/me"))
        .bearer_auth(&mail_token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let jmap_allowed: Value = client
        .post("https://127.0.0.1:8897/jmap")
        .bearer_auth(&mail_token)
        .json(&json!({"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"],
            "methodCalls": [["ContactCard/get", {"accountId": alice.id_string(), "ids": []}, "c1"]]}))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(jmap_allowed["methodResponses"][0][0], "ContactCard/get");
    let carddav_allowed = client
        .get("https://127.0.0.1:8897/dav/card/alice%40example.org/")
        .bearer_auth(&mail_token)
        .send()
        .await
        .unwrap();
    assert_ne!(carddav_allowed.status(), StatusCode::FORBIDDEN);
    let mail_profile = client
        .get("https://127.0.0.1:8897/gmail/v1/users/me/profile")
        .bearer_auth(&mail_token)
        .send()
        .await
        .unwrap();
    assert_eq!(mail_profile.status(), StatusCode::OK);
    // Bulwark's password login issues a scope-less OAuth token. It retains
    // normal JMAP access, while the People compatibility API requires an
    // explicit contacts grant.
    let unscoped_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            None,
            None,
        )
        .await
        .unwrap();
    let jmap_unscoped: Value = client
        .post("https://127.0.0.1:8897/jmap")
        .bearer_auth(&unscoped_token)
        .json(&json!({"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"],
            "methodCalls": [["ContactCard/get", {"accountId": alice.id_string(), "ids": []}, "c1"]]}))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(jmap_unscoped["methodResponses"][0][0], "ContactCard/get");
    let people_unscoped = client
        .get(format!("{BASE}/people/me"))
        .bearer_auth(&unscoped_token)
        .send()
        .await
        .unwrap();
    assert_eq!(people_unscoped.status(), StatusCode::FORBIDDEN);
    let contact_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CONTACTS),
            None,
        )
        .await
        .unwrap();
    let allowed = client
        .get(format!("{BASE}/people/me"))
        .bearer_auth(contact_token)
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let self_person: Value = allowed.json().await.unwrap();
    assert_eq!(self_person["names"][0]["displayName"], "alice@example.org");
    assert_eq!(
        self_person["emailAddresses"][0]["value"],
        "alice@example.org"
    );
    assert!(self_person.get("photos").is_none());

    // Refreshing a contact grant must not silently turn it into an
    // unscoped or mail-only grant.
    let refresh_token = test
        .server
        .encode_access_token(
            GrantType::RefreshToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CONTACTS),
            None,
        )
        .await
        .unwrap();
    let refreshed: Value = client
        .post("https://127.0.0.1:8897/auth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let refreshed_access = refreshed["access_token"].as_str().unwrap();
    let refreshed_people = client
        .get(format!("{BASE}/people/me"))
        .bearer_auth(refreshed_access)
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed_people.status(), StatusCode::OK);

    let (status, empty) = get(
        &client,
        &connections_query("&pageSize=1000"),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(empty["connections"].as_array().unwrap().is_empty());
    let empty_token = empty["nextSyncToken"].as_str().unwrap().to_string();
    let (status, other) = get(&client,
        "/otherContacts?readMask=names,emailAddresses,photos&sources=READ_SOURCE_TYPE_CONTACT&sources=READ_SOURCE_TYPE_PROFILE&requestSyncToken=true&pageSize=1000",
        alice.name(), alice.secret()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(other["otherContacts"].as_array().unwrap().is_empty());
    let other_token = other["nextSyncToken"].as_str().unwrap();
    assert_ne!(other_token, empty_token);
    let (_, other_incremental) = get(
        &client,
        &format!("/otherContacts?readMask={FIELDS}&requestSyncToken=true&syncToken={other_token}"),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert!(
        other_incremental["otherContacts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(other_incremental["nextSyncToken"].is_string());
    assert_eq!(
        get(
            &client,
            &connections_query(&format!("&syncToken={other_token}")),
            alice.name(),
            alice.secret()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(
            &client,
            &connections_query(&format!("&syncToken={empty_token}")),
            bob.name(),
            bob.secret()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    let book = alice
        .jmap_create(
            MethodObject::AddressBook,
            [json!({"name": "Friends"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let first = alice
        .jmap_create(
            MethodObject::ContactCard,
            [contact(
                &book,
                "Avery Example",
                "avery@example.org",
                Some("avery@work.example"),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let (_, created) = get(
        &client,
        &connections_query(&format!("&syncToken={empty_token}")),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(created["connections"].as_array().unwrap().len(), 1);
    assert_eq!(
        created["connections"][0]["names"][0]["displayName"],
        "Avery Example"
    );
    assert_eq!(
        created["connections"][0]["emailAddresses"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let created_token = created["nextSyncToken"].as_str().unwrap().to_string();

    alice
        .jmap_update(
            MethodObject::ContactCard,
            [(&first, json!({"name/full": "Avery Changed"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let (_, updated) = get(
        &client,
        &connections_query(&format!("&syncToken={created_token}")),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(
        updated["connections"][0]["names"][0]["displayName"],
        "Avery Changed"
    );
    let updated_token = updated["nextSyncToken"].as_str().unwrap().to_string();
    alice
        .jmap_destroy(
            MethodObject::ContactCard,
            [&first],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let (_, deleted) = get(
        &client,
        &connections_query(&format!("&syncToken={updated_token}")),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(deleted["connections"][0]["metadata"]["deleted"], true);
    assert!(
        deleted["connections"][0]["resourceName"]
            .as_str()
            .unwrap()
            .starts_with("people/")
    );

    alice
        .jmap_create(
            MethodObject::ContactCard,
            [
                contact(&book, "B One", "b1@example.org", None),
                contact(&book, "C Two", "c2@example.org", None),
                contact(&book, "D Three", "d3@example.org", None),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let (_, first_page) = get(
        &client,
        &connections_query("&pageSize=1"),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(first_page["connections"].as_array().unwrap().len(), 1);
    let page_token = first_page["nextPageToken"].as_str().unwrap().to_string();
    assert!(first_page["nextSyncToken"].is_null());
    let mut tampered = page_token.clone().into_bytes();
    tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert_eq!(
        get(
            &client,
            &connections_query(&format!("&pageSize=1&pageToken={tampered}")),
            alice.name(),
            alice.secret()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(
            &client,
            &connections_query(&format!("&pageSize=1&pageToken={page_token}")),
            bob.name(),
            bob.secret()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    alice
        .jmap_create(
            MethodObject::ContactCard,
            [contact(&book, "E Later", "e4@example.org", None)],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let mut names = vec![
        first_page["connections"][0]["names"][0]["displayName"]
            .as_str()
            .unwrap()
            .to_string(),
    ];
    let mut next = Some(page_token);
    let mut final_sync = None;
    while let Some(token) = next {
        let (_, page) = get(
            &client,
            &connections_query(&format!("&pageSize=1&pageToken={token}")),
            alice.name(),
            alice.secret(),
        )
        .await;
        names.push(
            page["connections"][0]["names"][0]["displayName"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        next = page["nextPageToken"].as_str().map(str::to_string);
        final_sync = page["nextSyncToken"].as_str().map(str::to_string);
    }
    assert_eq!(names, ["B One", "C Two", "D Three"]);
    let final_sync = final_sync.unwrap();
    let (_, later) = get(
        &client,
        &connections_query(&format!("&syncToken={final_sync}")),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(later["connections"].as_array().unwrap().len(), 1);
    assert_eq!(
        later["connections"][0]["names"][0]["displayName"],
        "E Later"
    );
    let (_, bob_empty) = get(
        &client,
        &connections_query("&pageSize=1000"),
        bob.name(),
        bob.secret(),
    )
    .await;
    assert!(bob_empty["connections"].as_array().unwrap().is_empty());

    // Replace the latest address-book log entry with Stalwart's pruning
    // marker, then confirm the old cursor triggers Macro's full-sync path.
    let latest = test
        .server
        .store()
        .get_last_change_id(alice.id().document_id(), SyncCollection::AddressBook.into())
        .await
        .unwrap()
        .unwrap();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(alice.id().document_id()).set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_LOGS,
            key: LogKey {
                account_id: alice.id().document_id(),
                collection: SyncCollection::AddressBook.into(),
                change_id: latest,
            }
            .serialize(0),
        }),
        Vec::new(),
    );
    test.server.store().write(batch.build_all()).await.unwrap();
    let (status, expired) = get(
        &client,
        &connections_query(&format!("&syncToken={empty_token}")),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(expired.to_string().contains("EXPIRED_SYNC_TOKEN"));
}

#[tokio::test(flavor = "multi_thread")]
async fn people_self_contact_photo() {
    let mut test = TestServerBuilder::new("fog_people_self_photo")
        .await
        .with_http_listener(8899)
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
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = "https://127.0.0.1:8899";
    let book = alice
        .jmap_create(
            MethodObject::AddressBook,
            [json!({"name": "Personal"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let people_base = "https://127.0.0.1:8899/people/v1";
    let (_, before) = get_at(
        &client,
        people_base,
        "/people/me?personFields=names,emailAddresses,photos",
        alice.name(),
        alice.secret(),
    )
    .await;
    assert!(before.get("photos").is_none());

    // A card for another person cannot become Alice's account photo.
    let mut other = contact(&book, "Bob", "bob@example.org", None);
    other["media"] = json!({"p1": {"kind": "photo", "uri": "data:image/png;base64,AQID"}});
    alice
        .jmap_create(
            MethodObject::ContactCard,
            [other],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let (_, unchanged) = get_at(
        &client,
        people_base,
        "/people/me?personFields=names,emailAddresses,photos",
        alice.name(),
        alice.secret(),
    )
    .await;
    assert!(unchanged.get("photos").is_none());

    let mut own = contact(&book, "Alice Self", "ALICE@EXAMPLE.ORG", None);
    own["media"] = json!({"p1": {"kind": "photo", "uri": "data:image/png;base64,AQID"}});
    let own_id = alice
        .jmap_create(MethodObject::ContactCard, [own], Vec::<(&str, &str)>::new())
        .await
        .created(0)
        .id()
        .to_string();
    let (_, profile) = get_at(
        &client,
        people_base,
        "/people/me?personFields=names,emailAddresses,photos",
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_eq!(profile["names"][0]["displayName"], "alice@example.org");
    assert_eq!(profile["emailAddresses"][0]["value"], "alice@example.org");
    assert_eq!(profile["photos"][0]["default"], false);
    let photo_url = profile["photos"][0]["url"].as_str().unwrap();
    let photo_path = &photo_url[photo_url.find("/people/v1/photos/").unwrap()..];
    let response = client
        .get(format!("{base}{photo_path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "image/png");
    assert_eq!(response.bytes().await.unwrap().as_ref(), &[1, 2, 3]);
    let mut forged_path = photo_path.to_string();
    let signature_start = forged_path.rfind('.').unwrap() + 1;
    forged_path.replace_range(signature_start..signature_start + 1, "A");
    if forged_path == photo_path {
        forged_path.replace_range(signature_start..signature_start + 1, "B");
    }
    assert_eq!(
        client
            .get(format!("{base}{forged_path}"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let (_, contacts) = get_at(
        &client,
        people_base,
        &connections_query(""),
        alice.name(),
        alice.secret(),
    )
    .await;
    assert!(
        contacts["connections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|person| { person["photos"][0]["url"] == profile["photos"][0]["url"] })
    );
    let (_, bob_profile) = get_at(
        &client,
        people_base,
        "/people/me?personFields=names,emailAddresses,photos",
        bob.name(),
        bob.secret(),
    )
    .await;
    assert!(bob_profile.get("photos").is_none());

    alice
        .jmap_update(
            MethodObject::ContactCard,
            [(
                &own_id,
                json!({"media/p1/uri": "data:image/png;base64,BAUG"}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let response = client
        .get(format!("{base}{photo_path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let (_, updated) = get_at(
        &client,
        people_base,
        "/people/me?personFields=names,emailAddresses,photos",
        alice.name(),
        alice.secret(),
    )
    .await;
    assert_ne!(updated["photos"][0]["url"], profile["photos"][0]["url"]);
}
