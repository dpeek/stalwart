/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServerBuilder};
use common::auth::oauth::{GrantType, SCOPE_CALENDARS, SCOPE_MAIL};
use jmap_proto::request::method::MethodObject;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::str::FromStr;
use types::id::Id;

const BASE: &str = "https://127.0.0.1:8896/calendar/v3";
const WINDOW: &str = "maxResults=2500&singleEvents=false&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC";

const WRITE_BASE: &str = "https://127.0.0.1:8897/calendar/v3";

async fn write_request(
    client: &Client,
    method: reqwest::Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = client
        .request(method, format!("{WRITE_BASE}{path}"))
        .bearer_auth(bearer);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)}))
    };
    (status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_write_routes_use_native_mutations() {
    let mut test = TestServerBuilder::new("fog_calendar_write")
        .await
        .with_http_listener(8897)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(
        admin
            .create_user_account(
                "alice@example.org",
                "velvet comet fern 7319",
                "Alice",
                &[],
                vec![],
            )
            .await,
    );
    test.insert_account(
        admin
            .create_user_account(
                "bob@example.org",
                "copper lantern meadow 8427",
                "Bob",
                &[],
                vec![],
            )
            .await,
    );
    let alice = test.account("alice@example.org");
    let bob = test.account("bob@example.org");
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
    let bob_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            bob.id().document_id(),
            bob.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
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
    let calendar = alice
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name":"Writes", "timeZone":"UTC"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let cal_doc = Id::from_str(&calendar).unwrap().document_id();
    let path = format!("/calendars/{}-{cal_doc}/events", alice.id().document_id());
    let draft = json!({"id":"0123456789abcdef0123456789abcdef", "summary":"Planning", "description":"Keep me",
        "start":{"dateTime":"2026-10-02T10:00:00Z","date":null,"timeZone":"UTC"},
        "end":{"dateTime":"2026-10-02T11:00:00Z","date":null,"timeZone":"UTC"},
        "reminders":{"useDefault":false,"overrides":[{"method":"popup","minutes":10}]}});
    let (status, created) = write_request(
        &client,
        reqwest::Method::POST,
        &format!("{path}?sendUpdates=all"),
        &token,
        Some(draft.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created:?}");
    assert_eq!(created["id"], draft["id"]);
    assert_eq!(created["summary"], "Planning");
    assert!(
        created["iCalUID"]
            .as_str()
            .unwrap()
            .contains("0123456789abcdef")
    );
    assert_eq!(created["reminders"]["overrides"][0]["minutes"], 10);
    let (status, unsupported) = write_request(&client, reqwest::Method::POST, &format!("{path}?conferenceDataVersion=1"), &token,
        Some(json!({"summary":"Meeting", "start":{"date":"2026-10-03"}, "end":{"date":"2026-10-04"},
            "conferenceData":{"createRequest":{"requestId":"one","conferenceSolutionKey":{"type":"hangoutsMeet"}}}}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        unsupported["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Meet")
    );
    let (status, unsupported) = write_request(
        &client,
        reqwest::Method::POST,
        &path,
        &token,
        Some(
            json!({"summary":"Away", "start":{"dateTime":"2026-10-03T10:00:00Z"},
            "end":{"dateTime":"2026-10-03T11:00:00Z"}, "eventType":"outOfOffice",
            "outOfOfficeProperties":{"autoDeclineMode":"declineAllConflictingInvitations"}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        unsupported["error"]["message"]
            .as_str()
            .unwrap()
            .contains("auto-decline")
    );
    let (status, _) = write_request(
        &client,
        reqwest::Method::POST,
        &path,
        &mail_token,
        Some(json!({"summary":"No scope"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let response = client
        .post(format!("{WRITE_BASE}{path}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (status, _) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/missing"),
        &token,
        Some(json!({"summary":"No event"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/0123456789abcdef0123456789abcdef"),
        &bob_token,
        Some(json!({"summary":"Wrong account"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    alice
        .jmap_update(
            MethodObject::Calendar,
            [(
                &calendar,
                json!({"shareWith": {bob.id_string(): {"mayReadItems": true}}}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&calendar);
    let (status, _) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/0123456789abcdef0123456789abcdef"),
        &bob_token,
        Some(json!({"summary":"Read only"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, duplicate) = write_request(
        &client,
        reqwest::Method::POST,
        &path,
        &token,
        Some(draft.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{duplicate:?}");
    let (status, patched) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/0123456789abcdef0123456789abcdef?sendUpdates=all"),
        &token,
        Some(json!({"summary":"Renamed"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched:?}");
    assert_eq!(patched["summary"], "Renamed");
    assert_eq!(patched["description"], "Keep me");
    assert_eq!(patched["reminders"]["overrides"][0]["minutes"], 10);
    let (status, cleared) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/0123456789abcdef0123456789abcdef"),
        &token,
        Some(
            json!({"description":null,"location":"", "reminders":{"useDefault":false,
            "overrides":[{"method":"email","minutes":5}]}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleared:?}");
    assert!(cleared["description"].is_null());
    assert!(cleared["location"].is_null());
    assert_eq!(cleared["reminders"]["overrides"][0]["method"], "email");
    assert_eq!(
        cleared["reminders"]["overrides"].as_array().unwrap().len(),
        1
    );
    let feed = format!(
        "{path}?maxResults=2500&singleEvents=false&showDeleted=true&timeMin=2026-10-01T00:00:00Z"
    );
    let (status, initial) = write_request(&client, reqwest::Method::GET, &feed, &token, None).await;
    assert_eq!(status, StatusCode::OK, "{initial:?}");
    assert_eq!(items(&initial).len(), 1);
    assert_eq!(items(&initial)[0]["id"], draft["id"]);
    let cursor = initial["nextSyncToken"].as_str().unwrap();
    let (status, deleted) = write_request(
        &client,
        reqwest::Method::DELETE,
        &format!("{path}/0123456789abcdef0123456789abcdef?sendUpdates=all"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{deleted:?}");
    let (status, delta) = write_request(
        &client,
        reqwest::Method::GET,
        &format!("{path}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={cursor}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{delta:?}");
    assert!(
        items(&delta)
            .iter()
            .any(|v| v["id"] == "0123456789abcdef0123456789abcdef" && v["status"] == "cancelled"),
        "{delta:?}"
    );
    let next_cursor = delta["nextSyncToken"].as_str().unwrap();
    let (status, empty) = write_request(
        &client,
        reqwest::Method::GET,
        &format!(
            "{path}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={next_cursor}"
        ),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{empty:?}");
    assert!(items(&empty).is_empty());
    let (status, all_day) = write_request(
        &client,
        reqwest::Method::POST,
        &path,
        &token,
        Some(
            json!({"summary":"Holiday", "start":{"date":"2026-10-03","dateTime":null},
            "end":{"date":"2026-10-05","dateTime":null}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{all_day:?}");
    assert_eq!(all_day["start"]["date"], "2026-10-03");
    assert_eq!(all_day["end"]["date"], "2026-10-05");
    let (status, zoned) = write_request(&client, reqwest::Method::POST, &path, &token,
        Some(json!({"summary":"Sydney", "start":{"dateTime":"2026-11-03T00:00:00Z","timeZone":"Australia/Sydney"},
            "end":{"dateTime":"2026-11-03T01:00:00Z","timeZone":"Australia/Sydney"}}))).await;
    assert_eq!(status, StatusCode::OK, "{zoned:?}");
    assert_eq!(zoned["start"]["dateTime"], "2026-11-03T00:00:00+00:00");
    let linked = alice
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({"@type":"Event", "uid":"existing-conference@example.org", "title":"Linked",
            "start":"2026-10-06T10:00:00", "duration":"PT1H", "timeZone":"UTC",
            "calendarIds": {&calendar: true},
            "virtualLocations":{"meeting":{"@type":"VirtualLocation",
                "uri":"https://example.org/room", "features":{"video":true}}}}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let linked_id = format!(
        "e{}-{}",
        alice.id().document_id(),
        Id::from_str(&linked).unwrap().document_id()
    );
    let (status, before) = write_request(
        &client,
        reqwest::Method::GET,
        &format!("{path}/{linked_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{before:?}");
    assert_eq!(
        before["conferenceData"]["entryPoints"][0]["uri"],
        "https://example.org/room"
    );
    let (status, after) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/{linked_id}?sendUpdates=all"),
        &token,
        Some(json!({"summary":"Linked renamed"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after:?}");
    assert_eq!(after["conferenceData"], before["conferenceData"]);
    let (status, optional_created) = write_request(
        &client,
        reqwest::Method::POST,
        &path,
        &token,
        Some(json!({"summary":"Optional guest", "start":{"date":"2026-10-03"},
            "end":{"date":"2026-10-04"},
            "attendees":[{"email":"guest@example.net","optional":true}]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{optional_created:?}");
    assert_eq!(optional_created["attendees"][0]["optional"], true);
    let (status, optional_patched) = write_request(
        &client,
        reqwest::Method::PATCH,
        &format!("{path}/{}", optional_created["id"].as_str().unwrap()),
        &token,
        Some(json!({"attendees":[{"email":"guest@example.net","optional":false}]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{optional_patched:?}");
    assert_eq!(optional_patched["attendees"][0]["optional"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_write_recurring_instances_use_native_overrides() {
    let mut test = TestServerBuilder::new("fog_calendar_write_recurrence")
        .await
        .with_http_listener(8898)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(
        admin
            .create_user_account(
                "alice@example.org",
                "velvet comet fern 7319",
                "Alice",
                &[],
                vec![],
            )
            .await,
    );
    let alice = test.account("alice@example.org");
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
    let calendar = alice
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name":"Series", "timeZone":"UTC"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let cal_doc = Id::from_str(&calendar).unwrap().document_id();
    let base = format!(
        "https://127.0.0.1:8898/calendar/v3/calendars/{}-{cal_doc}/events",
        alice.id().document_id()
    );
    let req = |method: reqwest::Method, url: String, body: Option<Value>| {
        let mut request = client.request(method, url).bearer_auth(&token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request
    };
    let response = req(
        reqwest::Method::POST,
        base.clone(),
        Some(json!({
            "summary":"Standup", "start":{"dateTime":"2026-10-03T10:00:00Z"},
            "end":{"dateTime":"2026-10-03T11:00:00Z"}, "recurrence":["RRULE:FREQ=DAILY;COUNT=3"]
        })),
    )
    .send()
    .await
    .unwrap();
    let status = response.status();
    let created: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{created:?}");
    assert_eq!(created["recurrence"][0], "RRULE:FREQ=DAILY;COUNT=3");
    let master = created["id"].as_str().unwrap();
    let instances_url = format!(
        "{base}/{master}/instances?maxResults=2500&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC"
    );
    let response = req(reqwest::Method::GET, instances_url.clone(), None)
        .send()
        .await
        .unwrap();
    let instances: Value = response.json().await.unwrap();
    assert_eq!(items(&instances).len(), 3, "{instances:?}");
    let first = items(&instances)[0]["id"].as_str().unwrap().to_string();
    let second = items(&instances)[1]["id"].as_str().unwrap().to_string();
    let response = req(reqwest::Method::GET,
        format!("{base}?maxResults=2500&singleEvents=false&showDeleted=true&timeMin=2026-10-01T00:00:00Z"), None).send().await.unwrap();
    let baseline: Value = response.json().await.unwrap();
    let cursor = baseline["nextSyncToken"].as_str().unwrap();
    let response = req(
        reqwest::Method::PATCH,
        format!("{base}/{first}?sendUpdates=all"),
        Some(
            json!({"summary":"Moved standup", "start":{"dateTime":"2026-10-03T12:00:00Z"},
            "end":{"dateTime":"2026-10-03T13:00:00Z"}}),
        ),
    )
    .send()
    .await
    .unwrap();
    let status = response.status();
    let patched: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{patched:?}");
    assert_eq!(patched["id"], first);
    assert_eq!(patched["summary"], "Moved standup");
    let response = req(
        reqwest::Method::DELETE,
        format!("{base}/{second}?sendUpdates=all"),
        None,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = req(reqwest::Method::GET, instances_url, None)
        .send()
        .await
        .unwrap();
    let after: Value = response.json().await.unwrap();
    assert_eq!(items(&after).len(), 2, "{after:?}");
    assert!(
        items(&after)
            .iter()
            .any(|v| v["id"] == first && v["summary"] == "Moved standup")
    );
    let response = req(reqwest::Method::GET, format!("{base}/{master}"), None)
        .send()
        .await
        .unwrap();
    let master_after: Value = response.json().await.unwrap();
    assert!(
        master_after["recurrence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().starts_with("EXDATE")),
        "{master_after:?}"
    );
    let response = req(
        reqwest::Method::GET,
        format!("{base}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={cursor}"),
        None,
    )
    .send()
    .await
    .unwrap();
    let delta: Value = response.json().await.unwrap();
    assert!(
        items(&delta)
            .iter()
            .any(|v| v["id"] == second && v["status"] == "cancelled"),
        "{delta:?}"
    );
    assert!(items(&delta).iter().any(|v| v["id"] == master), "{delta:?}");
    let response = req(
        reqwest::Method::PATCH,
        format!("{base}/{master}?sendUpdates=all"),
        Some(json!({"recurrence":["RRULE:FREQ=DAILY;COUNT=2", "EXDATE:20261004T100000"]})),
    )
    .send()
    .await
    .unwrap();
    let status = response.status();
    let truncated: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{truncated:?}");
    assert_eq!(truncated["recurrence"][0], "RRULE:FREQ=DAILY;COUNT=2");
    let response = req(reqwest::Method::GET, format!("{base}/{first}"), None)
        .send()
        .await
        .unwrap();
    let first_after: Value = response.json().await.unwrap();
    assert_eq!(first_after["summary"], "Moved standup", "{first_after:?}");
    let response = req(
        reqwest::Method::POST,
        base.clone(),
        Some(json!({
            "summary":"Extra date", "start":{"dateTime":"2026-10-03T10:00:00Z"},
            "end":{"dateTime":"2026-10-03T11:00:00Z"},
            "recurrence":["RRULE:FREQ=DAILY;COUNT=2", "RDATE:20261006T100000"]
        })),
    )
    .send()
    .await
    .unwrap();
    let status = response.status();
    let extra: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{extra:?}");
    let extra_id = extra["id"].as_str().unwrap();
    let response = req(reqwest::Method::GET,
        format!("{base}/{extra_id}/instances?maxResults=2500&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC"), None).send().await.unwrap();
    let extra_instances: Value = response.json().await.unwrap();
    assert_eq!(items(&extra_instances).len(), 3, "{extra_instances:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_write_scheduling_and_actor_rsvp() {
    let mut test = TestServerBuilder::new("fog_calendar_write_scheduling")
        .await
        .with_http_listener(8895)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    for (email, password) in [
        ("alice@example.org", "velvet comet fern 7319"),
        ("bob@example.org", "copper lantern meadow 8427"),
        ("carol@example.org", "silver river orchid 9531"),
    ] {
        test.insert_account(
            admin
                .create_user_account(email, password, email, &[], vec![])
                .await,
        );
    }
    let alice = test.account("alice@example.org");
    let bob = test.account("bob@example.org");
    let carol = test.account("carol@example.org");
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let alice_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
    let bob_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            bob.id().document_id(),
            bob.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
    let calendar = alice
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name":"Invitations", "timeZone":"UTC"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let cal_doc = Id::from_str(&calendar).unwrap().document_id();
    let base = format!(
        "https://127.0.0.1:8895/calendar/v3/calendars/{}-{cal_doc}/events",
        alice.id().document_id()
    );
    let bob_state = bob
        .jmap_get(
            MethodObject::CalendarEventNotification,
            ["id"],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    let carol_state = carol
        .jmap_get(
            MethodObject::CalendarEventNotification,
            ["id"],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    let draft = json!({"id":"abcdef0123456789abcdef0123456789", "summary":"Invited meeting",
        "start":{"dateTime":"2026-11-04T10:00:00Z"}, "end":{"dateTime":"2026-11-04T11:00:00Z"},
        "attendees":[{"email":"bob@example.org","responseStatus":"needsAction"},
            {"email":"carol@example.org","responseStatus":"needsAction"}]});
    let response = client
        .post(format!("{base}?sendUpdates=all"))
        .bearer_auth(&alice_token)
        .json(&draft)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let created: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{created:?}");
    let response = client
        .post(&base)
        .bearer_auth(&alice_token)
        .json(&draft)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    test.wait_for_tasks().await;
    assert_eq!(
        bob.jmap_changes(MethodObject::CalendarEventNotification, &bob_state)
            .await
            .changes()
            .count(),
        1
    );
    assert_eq!(
        carol
            .jmap_changes(MethodObject::CalendarEventNotification, &carol_state)
            .await
            .changes()
            .count(),
        1
    );
    let response = client.get("https://127.0.0.1:8895/calendar/v3/users/me/calendarList?maxResults=250&minAccessRole=reader")
        .bearer_auth(&bob_token).send().await.unwrap();
    let calendars: Value = response.json().await.unwrap();
    let bob_calendar = items(&calendars)
        .iter()
        .find(|v| v["primary"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let bob_base = format!("https://127.0.0.1:8895/calendar/v3/calendars/{bob_calendar}/events");
    let response = client.get(format!("{bob_base}?maxResults=2500&singleEvents=false&showDeleted=false&timeMin=2026-11-01T00:00:00Z&timeMax=2026-11-10T00:00:00Z&timeZone=UTC")).bearer_auth(&bob_token).send().await.unwrap();
    let bob_events: Value = response.json().await.unwrap();
    let bob_id = items(&bob_events)
        .iter()
        .find(|v| v["summary"] == "Invited meeting")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let response = client.patch(format!("{bob_base}/{bob_id}?sendUpdates=all")).bearer_auth(&bob_token)
        .json(&json!({"attendeesOmitted":true,"attendees":[{"email":"carol@example.org","responseStatus":"accepted"}]})).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let alice_state = alice
        .jmap_get(
            MethodObject::CalendarEventNotification,
            ["id"],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    let rsvp = json!({"attendeesOmitted":true,"attendees":[{"email":"bob@example.org","responseStatus":"accepted"}]});
    let response = client
        .patch(format!("{bob_base}/{bob_id}?sendUpdates=all"))
        .bearer_auth(&bob_token)
        .json(&rsvp)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let accepted: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{accepted:?}");
    let response = client
        .patch(format!("{bob_base}/{bob_id}?sendUpdates=all"))
        .bearer_auth(&bob_token)
        .json(&rsvp)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    test.wait_for_tasks().await;
    assert_eq!(
        alice
            .jmap_changes(MethodObject::CalendarEventNotification, &alice_state)
            .await
            .changes()
            .count(),
        1
    );
    let response = client
        .get(format!("{base}/abcdef0123456789abcdef0123456789"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    let owner_event: Value = response.json().await.unwrap();
    assert!(
        owner_event["attendees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["email"] == "bob@example.org" && v["responseStatus"] == "accepted"),
        "{owner_event:?}"
    );
    assert!(
        owner_event["attendees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["email"] == "carol@example.org" && v["responseStatus"] == "needsAction"),
        "{owner_event:?}"
    );
    let response = client
        .patch(format!(
            "{base}/abcdef0123456789abcdef0123456789?sendUpdates=all"
        ))
        .bearer_auth(&alice_token)
        .json(&json!({"attendees":[{"email":"carol@example.org","responseStatus":"needsAction"}]}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let replaced: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{replaced:?}");
    assert!(
        !replaced["attendees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["email"] == "bob@example.org"),
        "{replaced:?}"
    );
    let response = client
        .post(format!("{base}?sendUpdates=all"))
        .bearer_auth(&alice_token)
        .json(
            &json!({"summary":"Recurring invitation", "start":{"dateTime":"2026-11-06T10:00:00Z"},
            "end":{"dateTime":"2026-11-06T11:00:00Z"}, "recurrence":["RRULE:FREQ=DAILY;COUNT=2"],
            "attendees":[{"email":"bob@example.org","responseStatus":"needsAction"}]}),
        )
        .send()
        .await
        .unwrap();
    let status = response.status();
    let series: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{series:?}");
    test.wait_for_tasks().await;
    let response = client.get(format!("{bob_base}?maxResults=2500&singleEvents=false&showDeleted=false&timeMin=2026-11-01T00:00:00Z&timeMax=2026-11-10T00:00:00Z&timeZone=UTC"))
        .bearer_auth(&bob_token).send().await.unwrap();
    let bob_series: Value = response.json().await.unwrap();
    let bob_master = items(&bob_series)
        .iter()
        .find(|v| v["summary"] == "Recurring invitation")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let response = client.get(format!("{bob_base}/{bob_master}/instances?maxResults=2500&showDeleted=false&timeMin=2026-11-01T00:00:00Z&timeMax=2026-11-10T00:00:00Z&timeZone=UTC"))
        .bearer_auth(&bob_token).send().await.unwrap();
    let bob_instances: Value = response.json().await.unwrap();
    assert_eq!(items(&bob_instances).len(), 2, "{bob_instances:?}");
    let instance = items(&bob_instances)[0]["id"].as_str().unwrap();
    let series_alice_state = alice
        .jmap_get(
            MethodObject::CalendarEventNotification,
            ["id"],
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();
    let response = client
        .patch(format!("{bob_base}/{instance}?sendUpdates=all"))
        .bearer_auth(&bob_token)
        .json(&rsvp)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let instance_rsvp: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{instance_rsvp:?}");
    assert!(
        instance_rsvp["attendees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["email"] == "bob@example.org" && v["responseStatus"] == "accepted")
    );
    let response = client
        .patch(format!("{bob_base}/{instance}?sendUpdates=all"))
        .bearer_auth(&bob_token)
        .json(&rsvp)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    test.wait_for_tasks().await;
    assert_eq!(
        alice
            .jmap_changes(MethodObject::CalendarEventNotification, &series_alice_state)
            .await
            .changes()
            .count(),
        1
    );
    let series_id = series["id"].as_str().unwrap();
    let response = client.get(format!("{base}/{series_id}/instances?maxResults=2500&showDeleted=false&timeMin=2026-11-01T00:00:00Z&timeMax=2026-11-10T00:00:00Z&timeZone=UTC"))
        .bearer_auth(&alice_token).send().await.unwrap();
    let status = response.status();
    let owner_instances: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{owner_instances:?}");
    assert!(
        items(&owner_instances)
            .iter()
            .any(
                |v| v["attendees"].as_array().is_some_and(|attendees| attendees
                    .iter()
                    .any(|a| a["email"] == "bob@example.org" && a["responseStatus"] == "accepted"))
            ),
        "{owner_instances:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_caller_id_survives_server_restart() {
    let mut test = TestServerBuilder::new("fog_calendar_caller_restart")
        .await
        .with_http_listener(8894)
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(
        admin
            .create_user_account(
                "alice@example.org",
                "velvet comet fern 7319",
                "Alice",
                &[],
                vec![],
            )
            .await,
    );
    let alice = test.account("alice@example.org");
    let token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
    let calendar = alice
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name":"Durable", "timeZone":"UTC"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let cal_doc = Id::from_str(&calendar).unwrap().document_id();
    let base = format!(
        "https://127.0.0.1:8894/calendar/v3/calendars/{}-{cal_doc}/events",
        alice.id().document_id()
    );
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let draft = json!({"id":"abcdefabcdefabcdefabcdefabcdefab", "summary":"After restart",
        "start":{"date":"2026-10-03"}, "end":{"date":"2026-10-04"}});
    let response = client
        .post(&base)
        .bearer_auth(&token)
        .json(&draft)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created: Value = response.json().await.unwrap();
    test.shutdown();
    test.temp_dir.delete = false;
    drop(test);
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let mut restarted = TestServerBuilder::new_with_role(
        "fog_calendar_caller_restart",
        "mail.example.org".to_string(),
        None,
        false,
    )
    .await
    .build_with_opts(false)
    .await;
    let response = client
        .get(format!("{base}/abcdefabcdefabcdefabcdefabcdefab"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let got: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{got:?}");
    assert_eq!(got["id"], draft["id"]);
    assert_eq!(got["iCalUID"], created["iCalUID"]);
    let response = client
        .get(format!("{base}?{WINDOW}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let listed: Value = response.json().await.unwrap();
    assert!(
        items(&listed).iter().any(|v| v["id"] == draft["id"]),
        "{listed:?}"
    );
    let response = client.get(format!("{base}?maxResults=2500&singleEvents=false&showDeleted=true&timeMin=2026-10-01T00:00:00Z"))
        .bearer_auth(&token).send().await.unwrap();
    let feed: Value = response.json().await.unwrap();
    assert!(
        items(&feed).iter().any(|v| v["id"] == draft["id"]),
        "{feed:?}"
    );
    let response = client
        .post(&base)
        .bearer_auth(&token)
        .json(&draft)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    restarted.shutdown();
    restarted.temp_dir.delete = true;
}

async fn get(client: &Client, path: &str, bearer: &str) -> (StatusCode, Value) {
    let response = client
        .get(format!("{BASE}{path}"))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

fn items(body: &Value) -> &[Value] {
    body["items"].as_array().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_read_routes_use_native_storage_and_changes() {
    let mut test = TestServerBuilder::new("fog_calendar_read")
        .await
        .with_http_listener(8896)
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
    let token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            alice.id().document_id(),
            alice.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
    let bob_token = test
        .server
        .encode_access_token(
            GrantType::AccessToken,
            bob.id().document_id(),
            bob.name(),
            600,
            Some(SCOPE_CALENDARS),
            None,
        )
        .await
        .unwrap();
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

    assert_ne!(
        client
            .get(format!(
                "{BASE}/users/me/calendarList?maxResults=250&minAccessRole=reader"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        get(
            &client,
            "/users/me/calendarList?maxResults=250&minAccessRole=reader",
            &mail_token
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    let calendar = alice
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Macro test", "timeZone": "UTC"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let cal_doc = Id::from_str(&calendar).unwrap().document_id();
    let provider_calendar = format!("{}-{cal_doc}", alice.id().document_id());
    let (_, discovery) = get(
        &client,
        "/users/me/calendarList?maxResults=250&minAccessRole=reader",
        &token,
    )
    .await;
    let discovered = items(&discovery)
        .iter()
        .find(|v| v["id"] == provider_calendar)
        .unwrap();
    assert_eq!(discovered["summary"], "Macro test");
    assert_eq!(discovered["accessRole"], "owner");
    assert!(discovered["defaultReminders"].is_array());
    assert!(!items(&discovery).is_empty());
    assert_eq!(
        get(
            &client,
            "/users/me/calendarList?maxResults=250&minAccessRole=reader",
            &bob_token
        )
        .await
        .1["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == provider_calendar),
        false
    );

    let timed = alice
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({"@type": "Event", "uid": "timed@example.org", "title": "Planning",
            "start": "2026-10-02T10:00:00", "duration": "PT1H", "timeZone": "UTC",
            "calendarIds": {&calendar: true}}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let all_day = alice
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({"@type": "Event", "uid": "all-day@example.org", "title": "Holiday",
            "start": "2026-10-02T00:00:00", "duration": "P1D", "showWithoutTime": true,
            "calendarIds": {&calendar: true}}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let series = alice
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({"@type": "Event", "uid": "series@example.org", "title": "Standup",
            "start": "2026-10-03T10:00:00", "duration": "PT1H", "timeZone": "UTC",
            "recurrenceRule": {"frequency": "daily", "count": 3},
            "recurrenceOverrides": {"2026-10-04T10:00:00": {
                "title": "Moved standup", "start": "2026-10-04T12:00:00", "duration": "PT1H"}},
            "calendarIds": {&calendar: true}}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    alice
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({"@type": "Event", "uid": "later@example.org", "title": "Later",
                "start": "2026-11-02T10:00:00", "duration": "PT1H", "timeZone": "UTC",
                "calendarIds": {&calendar: true}}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0);
    test.wait_for_tasks().await;

    let base = format!("/calendars/{provider_calendar}/events");
    let (status, canonical) = get(&client, &format!("{base}?{WINDOW}"), &token).await;
    assert_eq!(status, StatusCode::OK, "{canonical:?}");
    assert_eq!(items(&canonical).len(), 4, "{canonical:?}");
    let timed_id = format!(
        "e{}-{}",
        alice.id().document_id(),
        Id::from_str(&timed).unwrap().document_id()
    );
    let series_id = format!(
        "e{}-{}",
        alice.id().document_id(),
        Id::from_str(&series).unwrap().document_id()
    );
    let timed_event = items(&canonical)
        .iter()
        .find(|v| v["id"] == timed_id)
        .unwrap();
    assert_eq!(
        timed_event["start"]["dateTime"],
        "2026-10-02T10:00:00+00:00"
    );
    assert_eq!(timed_event["iCalUID"], "timed@example.org");
    assert!(
        items(&canonical)
            .iter()
            .any(|v| v["iCalUID"] == "all-day@example.org"
                && v["start"]["date"] == "2026-10-02"
                && v["end"]["date"] == "2026-10-03")
    );
    assert!(
        items(&canonical)
            .iter()
            .any(|v| v["recurringEventId"] == series_id && v["originalStartTime"].is_object())
    );
    let (status, direct) = get(&client, &format!("{base}/{timed_id}"), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(direct["id"], timed_id);
    assert_eq!(
        get(&client, &format!("{base}/missing"), &token).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(get(&client, "/calendars/999-999/events?maxResults=2500&singleEvents=false&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC", &token).await.0,
        StatusCode::NOT_FOUND);
    assert_eq!(
        get(&client, &format!("{base}?{WINDOW}"), &bob_token)
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let (status, expanded) = get(&client, &format!("{base}?maxResults=2500&singleEvents=true&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC&orderBy=startTime"), &token).await;
    assert_eq!(status, StatusCode::OK, "{expanded:?}");
    assert_eq!(items(&expanded).len(), 5, "{expanded:?}");
    let (status, instances) = get(&client, &format!("{base}/{series_id}/instances?maxResults=2500&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC"), &token).await;
    assert_eq!(status, StatusCode::OK, "{instances:?}");
    assert_eq!(items(&instances).len(), 3);
    let first_instance = items(&instances)[0]["id"].as_str().unwrap();
    assert_eq!(
        get(&client, &format!("{base}/{first_instance}"), &token)
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        items(&instances)
            .iter()
            .any(|v| v["start"]["dateTime"] == "2026-10-04T12:00:00+00:00"
                && v["originalStartTime"]["dateTime"] == "2026-10-04T10:00:00+00:00")
    );
    let (_, by_uid) = get(
        &client,
        &format!(
            "{base}?maxResults=2500&singleEvents=false&showDeleted=false&iCalUID=series@example.org"
        ),
        &token,
    )
    .await;
    assert_eq!(items(&by_uid).len(), 2);

    let private_calendar = alice
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Private", "timeZone": "UTC"})],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let private_provider = format!(
        "{}-{}",
        alice.id().document_id(),
        Id::from_str(&private_calendar).unwrap().document_id()
    );
    alice
        .jmap_update(
            MethodObject::Calendar,
            [(
                &calendar,
                json!({"shareWith": {bob.id_string(): {"mayReadItems": true}}}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&calendar);
    let (_, shared_discovery) = get(
        &client,
        "/users/me/calendarList?maxResults=250&minAccessRole=reader",
        &bob_token,
    )
    .await;
    assert_eq!(
        items(&shared_discovery)
            .iter()
            .find(|v| v["id"] == provider_calendar)
            .unwrap()["accessRole"],
        "reader"
    );
    assert!(
        !items(&shared_discovery)
            .iter()
            .any(|v| v["id"] == private_provider)
    );
    assert_eq!(
        get(&client, &format!("{base}?{WINDOW}"), &bob_token)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        get(
            &client,
            &format!("/calendars/{private_provider}/events?{WINDOW}"),
            &bob_token
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let list_query = "/users/me/calendarList?maxResults=1&minAccessRole=reader";
    let (_, first_calendar_page) = get(&client, list_query, &token).await;
    let calendar_page_token = first_calendar_page["nextPageToken"].as_str().unwrap();
    let (status, second_calendar_page) = get(
        &client,
        &format!("{list_query}&pageToken={calendar_page_token}"),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        items(&first_calendar_page)[0]["id"],
        items(&second_calendar_page)[0]["id"]
    );
    assert_eq!(
        get(
            &client,
            &format!("{list_query}&pageToken={calendar_page_token}"),
            &bob_token
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    let feed_query =
        "maxResults=1&singleEvents=false&showDeleted=true&timeMin=2026-10-01T00:00:00Z";
    let mut page = get(&client, &format!("{base}?{feed_query}"), &token)
        .await
        .1;
    // A mutation after page one must not alter the frozen enumeration.
    alice
        .jmap_update(
            MethodObject::CalendarEvent,
            [(&timed, json!({"title": "Planning changed"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&timed);
    let mut seen = Vec::<Value>::new();
    loop {
        seen.extend(items(&page).iter().cloned());
        if let Some(next) = page["nextPageToken"].as_str() {
            page = get(
                &client,
                &format!("{base}?{feed_query}&pageToken={next}"),
                &token,
            )
            .await
            .1;
        } else {
            break;
        }
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(
        seen.iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        5
    );
    assert!(
        seen.iter()
            .any(|v| v["id"] == timed_id && v["summary"] == "Planning")
    );
    let sync = page["nextSyncToken"].as_str().unwrap().to_string();

    let series_doc = Id::from_str(&series).unwrap().document_id();
    let jmap_ids = alice
        .jmap_query(
            MethodObject::CalendarEvent,
            [
                ("inCalendar", Value::String(calendar.clone())),
                ("after", Value::String("2026-10-01T00:00:00".into())),
                ("before", Value::String("2026-10-10T00:00:00".into())),
            ],
            ["start"],
            [
                ("timeZone", json!("UTC")),
                ("expandRecurrences", json!(true)),
            ],
        )
        .await
        .ids()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let jmap_instances = alice
        .jmap_get(MethodObject::CalendarEvent, ["id", "start"], jmap_ids)
        .await;
    let cancelled = jmap_instances
        .list()
        .iter()
        .find(|v| {
            v["start"] == "2026-10-05T10:00:00"
                && Id::from_str(v["id"].as_str().unwrap())
                    .unwrap()
                    .document_id()
                    == series_doc
        })
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    alice
        .jmap_destroy(
            MethodObject::CalendarEvent,
            [&cancelled],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let (_, after_cancel) = get(&client, &format!("{base}/{series_id}/instances?maxResults=2500&showDeleted=false&timeMin=2026-10-01T00:00:00Z&timeMax=2026-10-10T00:00:00Z&timeZone=UTC"), &token).await;
    assert_eq!(items(&after_cancel).len(), 2);
    alice
        .jmap_destroy(
            MethodObject::CalendarEvent,
            [&all_day],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    test.wait_for_tasks().await;
    let (status, delta) = get(
        &client,
        &format!("{base}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={sync}"),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{delta:?}");
    assert!(
        items(&delta)
            .iter()
            .any(|v| v["id"] == timed_id && v["summary"] == "Planning changed")
    );
    assert_ne!(
        items(&delta).iter().find(|v| v["id"] == timed_id).unwrap()["etag"],
        timed_event["etag"]
    );
    assert!(
        items(&delta)
            .iter()
            .any(|v| { v["status"] == "cancelled" && v["recurringEventId"] == series_id })
    );
    assert!(items(&delta).iter().any(|v| v["id"] == series_id));
    assert!(delta["nextSyncToken"].is_string());
    let next_sync = delta["nextSyncToken"].as_str().unwrap();
    alice
        .jmap_update(
            MethodObject::CalendarEvent,
            [(&series, json!({"calendarIds": {&private_calendar: true}}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&series);
    let (status, moved) = get(
        &client,
        &format!(
            "{base}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={next_sync}"
        ),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{moved:?}");
    assert!(
        items(&moved)
            .iter()
            .any(|v| v["id"] == series_id && v["status"] == "cancelled")
    );
    assert_eq!(
        get(
            &client,
            &format!(
                "{base}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken=invalid"
            ),
            &token
        )
        .await
        .0,
        StatusCode::GONE
    );
    assert_eq!(
        get(
            &client,
            &format!("{base}?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={sync}"),
            &bob_token
        )
        .await
        .0,
        StatusCode::GONE
    );
    assert_eq!(get(&client,
        &format!("/calendars/{private_provider}/events?maxResults=2500&singleEvents=false&showDeleted=true&syncToken={sync}"),
        &token).await.0, StatusCode::GONE);
}
