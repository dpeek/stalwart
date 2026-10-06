/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Translate Macro's three Google Calendar writes to native CalendarEvent/set.

use super::*;
use calcard::{Entry, Parser};
use http_proto::request::fetch_body;
use jmap::calendar_event::set::CalendarEventSet;
use jmap_proto::{method::set::SetRequest, object::calendar_event};
use types::{blob::BlobId, id::Id};

fn invalid(message: &str) -> HttpResponse {
    error(StatusCode::BAD_REQUEST, message, "invalid")
}

fn unsupported(message: &str) -> HttpResponse {
    error(StatusCode::BAD_REQUEST, message, "unsupported")
}

fn mutation_error(value: &Value) -> HttpResponse {
    let kind = value["type"].as_str().unwrap_or("invalidProperties");
    let message = value["description"]
        .as_str()
        .unwrap_or("Calendar write rejected");
    let status = match kind {
        "notFound" => StatusCode::NOT_FOUND,
        "forbidden" | "noSupportedScheduleMethods" => StatusCode::FORBIDDEN,
        "alreadyExists" => StatusCode::CONFLICT,
        _ if message.contains("already exists") => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    };
    error(status, message, kind)
}

fn write_query(raw: Option<&str>) -> Result<(), HttpResponse> {
    let mut seen = false;
    for (key, value) in form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        if key == "sendUpdates" && value == "all" && !seen {
            seen = true;
        } else if key == "conferenceDataVersion" && value == "1" {
            // The request body is checked separately: version 1 without a
            // createRequest is harmless and used by Macro's PATCH helper.
        } else {
            return Err(bad_query());
        }
    }
    Ok(())
}

async fn target(
    server: &Server,
    token: &AccessToken,
    raw_calendar: &str,
    acl: Acl,
) -> trc::Result<Result<(u32, u32, std::sync::Arc<common::DavResources>, Tz), HttpResponse>> {
    let Ok(id) = percent_decode_str(raw_calendar).decode_utf8() else {
        return Ok(Err(not_found()));
    };
    let Some((owner, calendar)) = parse_calendar_id(&id) else {
        return Ok(Err(not_found()));
    };
    let Some((cache, tz)) = allowed_calendar(server, token, owner, calendar).await? else {
        return Ok(Err(not_found()));
    };
    if !token.is_member(owner) && !cache.container_acl(token, calendar).contains(acl) {
        return Ok(Err(error(
            StatusCode::FORBIDDEN,
            "Calendar is read-only",
            "forbidden",
        )));
    }
    Ok(Ok((owner, calendar, cache, tz)))
}

async fn body(req: &mut HttpRequest, session: &HttpSessionData) -> Result<Value, HttpResponse> {
    let Some(bytes) = fetch_body(req, 256 * 1024, session.session_id).await else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Calendar request body is too large",
            "invalid",
        ));
    };
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid("Invalid JSON event body"))?;
    if !value.is_object() {
        return Err(invalid("Event body must be an object"));
    }
    Ok(value)
}

fn reject_google_only(body: &Value) -> Result<(), HttpResponse> {
    if body.get("conferenceData").is_some_and(|v| !v.is_null()) {
        return Err(unsupported(
            "Google Meet conference creation is unavailable",
        ));
    }
    if body.get("eventType").and_then(Value::as_str) == Some("outOfOffice")
        || body.get("outOfOfficeProperties").is_some()
    {
        return Err(unsupported("Out-of-office auto-decline is unavailable"));
    }
    if body.get("eventType").is_some_and(|v| v != "default") {
        return Err(unsupported("Unsupported event type"));
    }
    if body.get("conferenceData").is_some_and(Value::is_null) {
        return Err(unsupported("Conference detachment is unavailable"));
    }
    Ok(())
}

fn time_fields(body: &Value) -> Result<serde_json::Map<String, Value>, HttpResponse> {
    let start = body
        .get("start")
        .ok_or_else(|| invalid("start and end are required"))?;
    let end = body
        .get("end")
        .ok_or_else(|| invalid("start and end are required"))?;
    let mut fields = serde_json::Map::new();
    if let (Some(a), Some(b)) = (start["date"].as_str(), end["date"].as_str()) {
        let a = chrono::NaiveDate::parse_from_str(a, "%Y-%m-%d")
            .map_err(|_| invalid("Invalid start date"))?;
        let b = chrono::NaiveDate::parse_from_str(b, "%Y-%m-%d")
            .map_err(|_| invalid("Invalid end date"))?;
        let days = (b - a).num_days();
        if days <= 0 {
            return Err(invalid("End must be after start"));
        }
        fields.insert("start".into(), json!(format!("{a}T00:00:00")));
        fields.insert("duration".into(), json!(format!("P{days}D")));
        fields.insert("showWithoutTime".into(), json!(true));
    } else if let (Some(a), Some(b)) = (start["dateTime"].as_str(), end["dateTime"].as_str()) {
        let a = DateTime::parse_from_rfc3339(a).map_err(|_| invalid("Invalid start dateTime"))?;
        let b = DateTime::parse_from_rfc3339(b).map_err(|_| invalid("Invalid end dateTime"))?;
        let seconds = (b - a).num_seconds();
        if seconds <= 0 {
            return Err(invalid("End must be after start"));
        }
        let zone = start["timeZone"].as_str().unwrap_or("UTC");
        let tz = Tz::from_str(zone).map_err(|_| invalid("Invalid timeZone"))?;
        fields.insert(
            "start".into(),
            json!(
                a.with_timezone(&tz)
                    .naive_local()
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()
            ),
        );
        fields.insert("duration".into(), json!(format!("PT{seconds}S")));
        fields.insert("timeZone".into(), json!(zone));
        fields.insert("showWithoutTime".into(), json!(false));
    } else {
        return Err(invalid("start and end must both be timed or all-day"));
    }
    Ok(fields)
}

fn recurrence_fields(
    lines: &Value,
    time: &Value,
) -> Result<serde_json::Map<String, Value>, HttpResponse> {
    let lines = lines
        .as_array()
        .ok_or_else(|| invalid("recurrence must be an array"))?;
    let mut result = serde_json::Map::new();
    if lines.is_empty() {
        result.insert("recurrenceRule".into(), Value::Null);
        result.insert("recurrenceOverrides".into(), json!({}));
        return Ok(result);
    }
    let start = time["start"]
        .as_str()
        .ok_or_else(|| invalid("Invalid recurrence start"))?;
    let duration = time["duration"]
        .as_str()
        .ok_or_else(|| invalid("Invalid recurrence duration"))?;
    let date = time["showWithoutTime"] == true;
    let stamp = if date {
        start[..10].replace('-', "")
    } else {
        start.replace(['-', ':'], "")
    };
    let mut ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:fog-recurrence-validation@calendar.fog.invalid\r\nDTSTART{}:{}\r\nDURATION:{}\r\n",
        if date { ";VALUE=DATE" } else { "" },
        stamp,
        duration
    );
    for line in lines {
        let line = line
            .as_str()
            .ok_or_else(|| invalid("Invalid recurrence line"))?;
        if line.contains(['\r', '\n'])
            || !["RRULE:", "RDATE:", "RDATE;", "EXDATE:", "EXDATE;"]
                .iter()
                .any(|p| line.starts_with(p))
        {
            return Err(invalid("Unsupported recurrence line"));
        }
        ics.push_str(line);
        ics.push_str("\r\n");
    }
    ics.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    let Entry::ICalendar(ical) = Parser::new(&ics).entry() else {
        return Err(invalid("Invalid recurrence"));
    };
    let parsed = serde_json::to_value(ical.into_jscalendar::<Id, BlobId>().into_inner())
        .map_err(|_| invalid("Invalid recurrence"))?;
    let event = &parsed["entries"][0];
    if let Some(rule) = event.get("recurrenceRule") {
        result.insert("recurrenceRule".into(), rule.clone());
    }
    if let Some(overrides) = event.get("recurrenceOverrides") {
        result.insert("recurrenceOverrides".into(), overrides.clone());
    }
    if result.is_empty() {
        return Err(invalid("Invalid recurrence"));
    }
    Ok(result)
}

fn field_patch(
    body: &Value,
    create: bool,
    current_time: Option<&Value>,
) -> Result<Value, HttpResponse> {
    reject_google_only(body)?;
    let mut out = serde_json::Map::new();
    if create {
        out.insert("@type".into(), json!("Event"));
    }
    for (source, dest) in [("summary", "title"), ("description", "description")] {
        if let Some(value) = body.get(source) {
            if !value.is_null() && !value.is_string() {
                return Err(invalid("Invalid text field"));
            }
            out.insert(dest.into(), value.clone());
        }
    }
    if let Some(value) = body.get("location") {
        if !value.is_null() && !value.is_string() {
            return Err(invalid("Invalid location"));
        }
        out.insert(
            "locations".into(),
            if let Some(name) = value.as_str().filter(|v| !v.is_empty()) {
                json!({"fog-location": {"@type": "Location", "name": name}})
            } else {
                json!({})
            },
        );
    }
    let time = if body.get("start").is_some() || body.get("end").is_some() {
        if body.get("start").is_none() || body.get("end").is_none() {
            return Err(invalid("start and end must be supplied together"));
        }
        let fields = time_fields(body)?;
        out.extend(fields.clone());
        Value::Object(fields)
    } else if let Some(time) = current_time {
        time.clone()
    } else if create {
        return Err(invalid("start and end are required"));
    } else {
        Value::Null
    };
    if let Some(lines) = body.get("recurrence") {
        out.extend(recurrence_fields(lines, &time)?);
    }
    if let Some(value) = body.get("visibility") {
        let privacy = match value.as_str() {
            Some("default") => Value::Null,
            Some("public") => json!("public"),
            Some("private") => json!("private"),
            Some("confidential") => json!("confidential"),
            _ => return Err(invalid("Invalid visibility")),
        };
        out.insert("privacy".into(), privacy);
    }
    if let Some(value) = body.get("transparency") {
        let status = match value.as_str() {
            Some("transparent") => "free",
            Some("opaque") => "busy",
            _ => return Err(invalid("Invalid transparency")),
        };
        out.insert("freeBusyStatus".into(), json!(status));
    }
    if let Some(value) = body.get("reminders") {
        let use_default = value["useDefault"]
            .as_bool()
            .ok_or_else(|| invalid("Invalid reminders"))?;
        let overrides = value["overrides"]
            .as_array()
            .ok_or_else(|| invalid("Invalid reminders"))?;
        let mut alerts = serde_json::Map::new();
        for (i, reminder) in overrides.iter().enumerate() {
            let action = match reminder["method"].as_str() {
                Some("popup") => "display",
                Some("email") => "email",
                _ => return Err(invalid("Invalid reminder method")),
            };
            let minutes = reminder["minutes"]
                .as_i64()
                .filter(|v| *v >= 0)
                .ok_or_else(|| invalid("Invalid reminder minutes"))?;
            alerts.insert(
                format!("fog-alert-{i}"),
                json!({"@type": "Alert", "action": action,
                "trigger": {"@type": "OffsetTrigger", "offset": format!("-PT{}M", minutes)}}),
            );
        }
        out.insert("useDefaultAlerts".into(), json!(use_default));
        out.insert("alerts".into(), Value::Object(alerts));
    }
    if let Some(attendees) = body.get("attendees") {
        if body["attendeesOmitted"] == true {
            return Err(invalid("RSVP must be handled separately"));
        }
        let attendees = attendees
            .as_array()
            .ok_or_else(|| invalid("attendees must be an array"))?;
        let mut participants = serde_json::Map::new();
        for attendee in attendees {
            let email = attendee["email"]
                .as_str()
                .filter(|v| v.contains('@'))
                .ok_or_else(|| invalid("Invalid attendee email"))?
                .to_ascii_lowercase();
            let status = match attendee["responseStatus"].as_str().unwrap_or("needsAction") {
                "needsAction" => "needs-action",
                "accepted" => "accepted",
                "declined" => "declined",
                "tentative" => "tentative",
                _ => return Err(invalid("Invalid attendee responseStatus")),
            };
            let key = format!(
                "fog-{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(email.as_bytes()))
            );
            let mut participant = json!({"@type": "Participant", "calendarAddress": format!("mailto:{email}"),
                "participationStatus": status});
            if attendee["optional"] == true {
                participant["roles"] = json!({"optional": true});
            }
            participants.insert(key, participant);
        }
        out.insert("participants".into(), Value::Object(participants));
    }
    let allowed = [
        "id",
        "summary",
        "description",
        "location",
        "start",
        "end",
        "attendees",
        "attendeesOmitted",
        "recurrence",
        "visibility",
        "transparency",
        "reminders",
        "conferenceData",
        "eventType",
        "outOfOfficeProperties",
    ];
    if body
        .as_object()
        .unwrap()
        .keys()
        .any(|key| !allowed.contains(&key.as_str()))
    {
        return Err(invalid("Unsupported event field"));
    }
    Ok(Value::Object(out))
}

async fn set(
    server: &Server,
    token: &AccessToken,
    session: &HttpSessionData,
    request: Value,
) -> trc::Result<Value> {
    let json = request.to_string();
    let request: SetRequest<'_, calendar_event::CalendarEvent> = serde_json::from_str(&json)
        .map_err(|err| {
            trc::ResourceEvent::BadParameters
                .into_err()
                .reason(err.to_string())
        })?;
    let response = server.calendar_event_set(request, token, session).await?;
    Ok(serde_json::to_value(response).expect("Native set response serializable"))
}

fn native_id(document: u32, recurrence: Option<u32>) -> String {
    Id::from_parts(recurrence.unwrap_or(0), document).to_string()
}

fn native_js_event(stored: &CalendarEvent) -> Value {
    let group = serde_json::to_value(
        stored
            .data
            .event
            .clone()
            .into_jscalendar::<Id, BlobId>()
            .into_inner(),
    )
    .expect("JSCalendar serializable");
    group["entries"][0].clone()
}

fn instance_override(event: &Value, recurrence: u32) -> Option<&Value> {
    event["recurrenceOverrides"]
        .as_object()?
        .iter()
        .find_map(|(key, value)| {
            let naive = chrono::NaiveDateTime::parse_from_str(key, "%Y-%m-%dT%H:%M:%S").ok()?;
            (RecurrenceKey::from_recurrence_id(naive.and_utc().timestamp())?.prefix() == recurrence)
                .then_some(value)
        })
}

fn find_participant<'a>(
    participants: &'a serde_json::Map<String, Value>,
    email: &str,
) -> Option<(&'a String, &'a Value)> {
    participants.iter().find(|(_, value)| {
        value["calendarAddress"].as_str().is_some_and(|address| {
            address
                .trim_start_matches("mailto:")
                .eq_ignore_ascii_case(email)
        })
    })
}

pub(super) async fn create(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
    token: &AccessToken,
    raw_calendar: &str,
) -> trc::Result<HttpResponse> {
    if let Err(response) = write_query(req.uri().query()) {
        return Ok(response);
    }
    let (owner, calendar, cache, _) =
        match target(server, token, raw_calendar, Acl::AddItems).await? {
            Ok(target) => target,
            Err(response) => return Ok(response),
        };
    let body = match body(req, session).await {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    let mut event = match field_patch(&body, true, None) {
        Ok(event) => event,
        Err(response) => return Ok(response),
    };
    let supplied = if let Some(id) = body.get("id") {
        let Some(id) = id.as_str() else {
            return Ok(invalid("Invalid caller event id"));
        };
        let Some(uid) = caller_uid(id) else {
            return Ok(invalid("Invalid caller event id"));
        };
        if resolve_event_id(server, &cache, owner, id).await?.is_some() {
            return Ok(error(
                StatusCode::CONFLICT,
                "Event id already exists",
                "duplicate",
            ));
        }
        event["uid"] = json!(uid);
        Some(id)
    } else {
        None
    };
    event["calendarIds"] = json!({Id::from(calendar).to_string(): true});
    let result = set(
        server,
        token,
        session,
        json!({"accountId": Id::from(owner),
        "sendSchedulingMessages": true, "create": {"fog": event}}),
    )
    .await?;
    if let Some(failed) = result["notCreated"]["fog"].as_object() {
        let response = mutation_error(&Value::Object(failed.clone()));
        return Ok(
            if supplied.is_some()
                && response.status() == StatusCode::BAD_REQUEST
                && resolve_event_id(server, &cache, owner, supplied.unwrap())
                    .await?
                    .is_some()
            {
                error(StatusCode::CONFLICT, "Event id already exists", "duplicate")
            } else {
                response
            },
        );
    }
    let Some(id) = result["created"]["fog"]["id"]
        .as_str()
        .and_then(|v| Id::from_str(v).ok())
    else {
        return Ok(invalid("Native calendar creation returned no event"));
    };
    let visible = supplied
        .map(str::to_string)
        .unwrap_or_else(|| event_id(owner, id.document_id()));
    event_get(server, token, owner, calendar, &visible, false, None).await
}

pub(super) async fn patch(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
    token: &AccessToken,
    raw_calendar: &str,
    raw_event: &str,
) -> trc::Result<HttpResponse> {
    if let Err(response) = write_query(req.uri().query()) {
        return Ok(response);
    }
    let (owner, calendar, cache, tz) =
        match target(server, token, raw_calendar, Acl::ModifyItems).await? {
            Ok(target) => target,
            Err(response) => return Ok(response),
        };
    let Ok(requested) = percent_decode_str(raw_event).decode_utf8() else {
        return Ok(not_found());
    };
    let Some((document, recurrence)) = resolve_event_id(server, &cache, owner, &requested).await?
    else {
        return Ok(not_found());
    };
    if !cache.children_ids(calendar).any(|id| id == document) {
        return Ok(not_found());
    }
    let Some((stored, _)) = load_event(server, owner, document, None, tz).await? else {
        return Ok(not_found());
    };
    let body = match body(req, session).await {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    if body.get("id").is_some() {
        return Ok(invalid("Event id cannot be patched"));
    }
    let mut patch = if body["attendeesOmitted"] == true {
        let Some(attendee) = body["attendees"]
            .as_array()
            .and_then(|v| v.as_slice().first())
        else {
            return Ok(invalid("RSVP requires one attendee"));
        };
        if body["attendees"].as_array().is_none_or(|v| v.len() != 1)
            || body.as_object().is_none_or(|v| v.len() != 2)
        {
            return Ok(invalid("RSVP may change only one attendee response"));
        }
        let Some(email) = attendee["email"].as_str() else {
            return Ok(invalid("Invalid RSVP attendee"));
        };
        let status = match attendee["responseStatus"].as_str() {
            Some("needsAction") => "needs-action",
            Some("accepted") => "accepted",
            Some("declined") => "declined",
            Some("tentative") => "tentative",
            _ => return Ok(invalid("Invalid RSVP status")),
        };
        let actor = server
            .scheduling_account_info(token.account_id(), token.account_id())
            .await?;
        if !actor
            .addresses()
            .iter()
            .any(|address| address.eq_ignore_ascii_case(email))
        {
            return Ok(error(
                StatusCode::FORBIDDEN,
                "Only the authenticated attendee may RSVP",
                "forbidden",
            ));
        }
        let js = native_js_event(&stored);
        let Some((key, current)) = recurrence
            .and_then(|rid| instance_override(&js, rid))
            .and_then(|override_| override_["participants"].as_object())
            .and_then(|participants| find_participant(participants, email))
            .or_else(|| {
                js["participants"]
                    .as_object()
                    .and_then(|participants| find_participant(participants, email))
            })
        else {
            return Ok(error(
                StatusCode::FORBIDDEN,
                "Authenticated actor is not an attendee",
                "forbidden",
            ));
        };
        let effective_status = recurrence
            .and_then(|rid| instance_override(&js, rid))
            .and_then(|override_| override_["participants"][key]["participationStatus"].as_str())
            .or_else(|| current["participationStatus"].as_str());
        if effective_status == Some(status) {
            return event_get(server, token, owner, calendar, &requested, false, None).await;
        }
        json!({format!("participants/{key}/participationStatus"): status})
    } else {
        let canonical = canonical_events(owner, document, &stored, tz, token.account_id());
        let Some(master) = canonical.as_ref().and_then(|items| items.first()) else {
            return Ok(unrepresentable());
        };
        let current_time = time_fields(master).ok().map(Value::Object);
        match field_patch(&body, false, current_time.as_ref()) {
            Ok(patch) => patch,
            Err(response) => return Ok(response),
        }
    };
    if recurrence.is_none() && body.get("recurrence").is_some() {
        // The Google recurrence array describes rules and date exclusions.
        // JMAP also keeps edited instances in recurrenceOverrides. Preserve
        // those native edits when Macro replaces the master's RRULE/EXDATE
        // lines to truncate a series.
        let current = native_js_event(&stored);
        let mut overrides = current["recurrenceOverrides"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        overrides.retain(|_, value| value["excluded"] != true);
        if let Some(replacement) = patch["recurrenceOverrides"].as_object() {
            overrides.extend(replacement.clone());
        }
        patch["recurrenceOverrides"] = Value::Object(overrides);
    }
    if patch.as_object().is_some_and(|v| v.is_empty()) {
        return event_get(server, token, owner, calendar, &requested, false, None).await;
    }
    let native = native_id(document, recurrence);
    let result = set(
        server,
        token,
        session,
        json!({"accountId": Id::from(owner),
        "sendSchedulingMessages": true, "update": {native.clone(): patch.take()}}),
    )
    .await?;
    if let Some(failed) = result["notUpdated"][&native].as_object() {
        return Ok(mutation_error(&Value::Object(failed.clone())));
    }
    event_get(server, token, owner, calendar, &requested, false, None).await
}

pub(super) async fn delete(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
    token: &AccessToken,
    raw_calendar: &str,
    raw_event: &str,
) -> trc::Result<HttpResponse> {
    if let Err(response) = write_query(req.uri().query()) {
        return Ok(response);
    }
    let (owner, calendar, cache, _) =
        match target(server, token, raw_calendar, Acl::RemoveItems).await? {
            Ok(target) => target,
            Err(response) => return Ok(response),
        };
    let Ok(requested) = percent_decode_str(raw_event).decode_utf8() else {
        return Ok(not_found());
    };
    let Some((document, recurrence)) = resolve_event_id(server, &cache, owner, &requested).await?
    else {
        return Ok(not_found());
    };
    if !cache.children_ids(calendar).any(|id| id == document) {
        return Ok(not_found());
    }
    let native = native_id(document, recurrence);
    let result = set(
        server,
        token,
        session,
        json!({"accountId": Id::from(owner),
        "sendSchedulingMessages": true, "destroy": [native]}),
    )
    .await?;
    if let Some(failed) = result["notDestroyed"]
        .as_object()
        .and_then(|v| v.get(&native))
    {
        return Ok(mutation_error(failed));
    }
    Ok(HttpResponse::new(StatusCode::NO_CONTENT))
}
