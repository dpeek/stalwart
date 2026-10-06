/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Google Calendar surface for Macro. Calendar content, mutations and
//! recurrence expansion remain in Stalwart's native calendar store.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry,
        ICalendarParameterName, ICalendarProperty, ICalendarValue,
    },
};
use chrono::{DateTime, Duration, Utc};
use common::{
    Server,
    auth::{
        AccessToken,
        oauth::{GrantType, SCOPE_CALENDARS, crypto::SymmetricEncrypt},
    },
    sharing::EffectiveAcl,
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CALENDAR_INVISIBLE, Calendar, CalendarEvent, PREF_USE_DEFAULT_ALERTS, expand::RecurrenceKey,
    },
};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse, form_urlencoded,
};
use hyper::{Method, StatusCode};
use percent_encoding::percent_decode_str;
use registry::schema::enums::Permission;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use store::{
    ValueKey,
    dispatch::lookup::KeyValue,
    query::log::Change,
    rand::{RngExt, rng},
    write::{AlignedBytes, Archive, ValueClass},
};
use trc::AddContext;
use types::{
    TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
    field::PrincipalField,
};

use crate::auth::authenticate::{Authenticator, HttpHeaders};

mod write;

const PAGE_TTL: u64 = 3600;
const SYNC_TTL: u64 = 7 * 86400;
const PAGE_PREFIX: u8 = 28;
const SYNC_PREFIX: u8 = 29;

#[derive(Clone, Serialize, Deserialize)]
struct Snapshot {
    account: u32,
    owner: u32,
    calendar: u32,
    query: String,
    items: Vec<Value>,
    change_id: Option<u64>,
    sync_key: Option<String>,
    issued: u64,
}

#[derive(Serialize, Deserialize)]
struct SyncState {
    account: u32,
    owner: u32,
    calendar: u32,
    change_id: u64,
    members: BTreeSet<u32>,
    #[serde(default)]
    ids: BTreeMap<u32, String>,
    issued: u64,
}

#[derive(Serialize, Deserialize)]
struct PageToken {
    key: String,
    offset: usize,
}

#[derive(Serialize, Deserialize)]
struct SyncToken {
    key: String,
    account: u32,
    owner: u32,
    calendar: u32,
    issued: u64,
}

#[derive(Clone, Default)]
struct ListQuery {
    max: usize,
    single: Option<bool>,
    deleted: Option<bool>,
    min: Option<i64>,
    max_time: Option<i64>,
    uid: Option<String>,
    order: Option<String>,
    page: Option<String>,
    sync: Option<String>,
    role: Option<String>,
    timezone: Option<String>,
}

impl ListQuery {
    fn parse(raw: Option<&str>, calendar_list: bool, instances: bool) -> Option<Self> {
        let mut q = Self {
            max: if calendar_list { 250 } else { 2500 },
            ..Self::default()
        };
        let mut seen = BTreeSet::new();
        for (key, value) in form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
            if !seen.insert(key.to_string()) {
                return None;
            }
            match key.as_ref() {
                "maxResults" => q.max = value.parse().ok()?,
                "minAccessRole" if calendar_list => q.role = Some(value.into_owned()),
                "singleEvents" if !calendar_list && !instances => {
                    q.single = Some(value.parse().ok()?)
                }
                "showDeleted" if !calendar_list => q.deleted = Some(value.parse().ok()?),
                "timeMin" if !calendar_list => {
                    q.min = Some(DateTime::parse_from_rfc3339(&value).ok()?.timestamp())
                }
                "timeMax" if !calendar_list => {
                    q.max_time = Some(DateTime::parse_from_rfc3339(&value).ok()?.timestamp())
                }
                "timeZone" if !calendar_list => q.timezone = Some(value.into_owned()),
                "orderBy" if !calendar_list && !instances => q.order = Some(value.into_owned()),
                "iCalUID" if !calendar_list && !instances => q.uid = Some(value.into_owned()),
                "pageToken" => q.page = Some(value.into_owned()),
                "syncToken" if !calendar_list && !instances => q.sync = Some(value.into_owned()),
                _ => return None,
            }
        }
        if q.max == 0 || q.max > if calendar_list { 250 } else { 2500 } {
            return None;
        }
        if calendar_list {
            return (q.role.as_deref() == Some("reader")).then_some(q);
        }
        if q.timezone.as_deref().is_some_and(|v| v != "UTC") {
            return None;
        }
        if instances {
            return (q.deleted == Some(false)
                && q.min.is_some()
                && q.max_time.is_some()
                && q.min < q.max_time
                && q.sync.is_none())
            .then_some(q);
        }
        if q.single.is_none() || q.deleted.is_none() {
            return None;
        }
        if q.order.as_deref().is_some_and(|v| v != "startTime")
            || (q.order.is_some() && q.single != Some(true))
        {
            return None;
        }
        if q.sync.is_some() {
            return (q.single == Some(false)
                && q.deleted == Some(true)
                && q.min.is_none()
                && q.max_time.is_none()
                && q.uid.is_none()
                && q.order.is_none())
            .then_some(q);
        }
        if q.uid.is_some() {
            return (q.single == Some(false)
                && q.deleted == Some(false)
                && q.min.is_none()
                && q.max_time.is_none()
                && q.order.is_none())
            .then_some(q);
        }
        if q.deleted == Some(true) {
            return (q.single == Some(false)
                && q.min.is_some()
                && q.max_time.is_none()
                && q.order.is_none())
            .then_some(q);
        }
        (q.min.is_some() && q.max_time.is_some() && q.min < q.max_time).then_some(q)
    }

    fn fingerprint(&self) -> String {
        format!(
            "{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            self.max,
            self.single,
            self.deleted,
            self.min,
            self.max_time,
            self.uid,
            self.order,
            self.sync,
            self.role,
            self.timezone
        )
    }

    fn is_feed(&self) -> bool {
        self.deleted == Some(true) && self.single == Some(false)
    }
    fn range(&self) -> TimeRange {
        TimeRange::new(
            self.min.unwrap_or(i64::MIN),
            self.max_time.unwrap_or(i64::MAX),
        )
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |t| t.as_secs())
}
fn random_key() -> String {
    URL_SAFE_NO_PAD.encode(rng().random::<[u8; 24]>())
}

fn error(status: StatusCode, message: &str, reason: &str) -> HttpResponse {
    JsonResponse::with_status(
        status,
        json!({"error": {"code": status.as_u16(),
        "message": message, "errors": [{"reason": reason}]}}),
    )
    .no_cache()
    .into_http_response()
}
fn bad_query() -> HttpResponse {
    error(
        StatusCode::BAD_REQUEST,
        "Unsupported calendar query",
        "invalid",
    )
}
fn not_found() -> HttpResponse {
    error(
        StatusCode::NOT_FOUND,
        "Calendar resource not found",
        "notFound",
    )
}
fn invalid_sync() -> HttpResponse {
    error(
        StatusCode::GONE,
        "Sync token is invalid or expired",
        "fullSyncRequired",
    )
}
fn unrepresentable() -> HttpResponse {
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Calendar event cannot be represented faithfully",
        "invalid",
    )
}

fn seal<T: Serialize>(server: &Server, payload: &T) -> String {
    let bytes = serde_json::to_vec(payload).expect("Calendar token serializable");
    let nonce = rng().random::<[u8; SymmetricEncrypt::NONCE_LEN]>();
    let ciphertext =
        SymmetricEncrypt::new(server.core.oauth.oauth_key.as_bytes(), "fog-calendar-v1")
            .encrypt_with_aad(&bytes, &nonce, &[])
            .expect("Calendar token encryption");
    URL_SAFE_NO_PAD.encode([nonce.as_slice(), ciphertext.as_slice()].concat())
}
fn open<T: for<'de> Deserialize<'de>>(server: &Server, token: &str) -> Option<T> {
    if token.len() > 8192 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    if bytes.len() < SymmetricEncrypt::NONCE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = bytes.split_at(SymmetricEncrypt::NONCE_LEN);
    let clear = SymmetricEncrypt::new(server.core.oauth.oauth_key.as_bytes(), "fog-calendar-v1")
        .decrypt_with_aad(ciphertext, nonce, &[])
        .ok()?;
    serde_json::from_slice(&clear).ok()
}

fn calendar_id(account: u32, document: u32) -> String {
    format!("{account}-{document}")
}
fn parse_calendar_id(value: &str) -> Option<(u32, u32)> {
    let (a, d) = value.split_once('-')?;
    Some((a.parse().ok()?, d.parse().ok()?))
}
fn event_id(account: u32, document: u32) -> String {
    format!("e{account}-{document}")
}
const CALLER_UID_PREFIX: &str = "fog-google-id-";
const CALLER_UID_SUFFIX: &str = "@calendar.fog.invalid";

fn caller_uid(id: &str) -> Option<String> {
    (id.len() >= 5
        && id.len() <= 256
        && id
            .bytes()
            .all(|c| (b'a'..=b'v').contains(&c) || (b'0'..=b'9').contains(&c)))
    .then(|| format!("{CALLER_UID_PREFIX}{id}{CALLER_UID_SUFFIX}"))
}

fn stored_event_id(account: u32, document: u32, event: &CalendarEvent) -> String {
    event
        .data
        .event
        .uids()
        .next()
        .and_then(|uid| uid.strip_prefix(CALLER_UID_PREFIX))
        .and_then(|uid| uid.strip_suffix(CALLER_UID_SUFFIX))
        .and_then(|id| caller_uid(id).map(|_| id.to_string()))
        .unwrap_or_else(|| event_id(account, document))
}

async fn resolve_event_id(
    server: &Server,
    cache: &common::DavResources,
    owner: u32,
    requested: &str,
) -> trc::Result<Option<(u32, Option<u32>)>> {
    let (main, recurrence) = requested
        .split_once("_r")
        .map_or((requested, None), |(a, b)| (a, Some(b)));
    let recurrence = match recurrence.map(str::parse::<u32>).transpose() {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if let Some((event_owner, document, _)) = parse_event_id(requested) {
        if event_owner == owner && cache.has_item_id(&document) {
            return Ok(Some((document, recurrence)));
        }
    }
    let Some(uid) = caller_uid(main) else {
        return Ok(None);
    };
    let hits = server
        .document_ids_matching(
            owner,
            Collection::CalendarEvent,
            CalendarEventField::Uid,
            uid.as_bytes(),
        )
        .await?;
    Ok(hits
        .iter()
        .find(|id| cache.has_item_id(id))
        .map(|id| (id, recurrence)))
}
fn event_etag(document: u32, event: &CalendarEvent) -> String {
    let mut content = String::new();
    event
        .data
        .event
        .write_to(&mut content)
        .expect("String writer");
    let mut hash = Sha256::new();
    hash.update(content.as_bytes());
    hash.update(event.modified.to_be_bytes());
    hash.update(event.flags.to_be_bytes());
    hash.update(format!("{:?}", event.preferences).as_bytes());
    format!(
        "\"{document}-{}\"",
        URL_SAFE_NO_PAD.encode(hash.finalize().as_slice())
    )
}
fn parse_event_id(value: &str) -> Option<(u32, u32, Option<u32>)> {
    let (main, recurrence) = value
        .split_once("_r")
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let (a, d) = main.strip_prefix('e')?.split_once('-')?;
    Some((
        a.parse().ok()?,
        d.parse().ok()?,
        recurrence.map(str::parse).transpose().ok()?,
    ))
}

fn text(comp: &ICalendarComponent, property: ICalendarProperty) -> Option<String> {
    comp.property(&property)?
        .values
        .first()?
        .as_text()
        .map(str::to_string)
}

fn date_value(timestamp: i64, all_day: bool, zone: Option<&str>) -> Option<Value> {
    let date = DateTime::<Utc>::from_timestamp(timestamp, 0)?;
    if all_day {
        Some(json!({"date": date.format("%Y-%m-%d").to_string()}))
    } else {
        Some(json!({"dateTime": date.to_rfc3339(), "timeZone": zone.unwrap_or("UTC")}))
    }
}

fn component_times(
    comp: &ICalendarComponent,
    default_tz: Tz,
) -> Option<(Value, Value, i64, i64, bool)> {
    let start_entry = comp.property(&ICalendarProperty::Dtstart)?;
    let start_raw = start_entry.values.first()?.as_partial_date_time()?;
    let all_day = start_raw.hour.is_none();
    let tz_name = start_entry.tz_id();
    let tz = tz_name
        .and_then(|v| Tz::from_str(v).ok())
        .unwrap_or(default_tz);
    let start = start_raw.to_date_time_with_tz(tz)?.timestamp();
    let end_entry = comp.property(&ICalendarProperty::Dtend);
    let end = if let Some(entry) = end_entry {
        let raw = entry.values.first()?.as_partial_date_time()?;
        if raw.hour.is_none() != all_day {
            return None;
        }
        let end_tz = entry
            .tz_id()
            .and_then(|v| Tz::from_str(v).ok())
            .unwrap_or(tz);
        raw.to_date_time_with_tz(end_tz)?.timestamp()
    } else if let Some(ICalendarValue::Duration(duration)) = comp
        .property(&ICalendarProperty::Duration)
        .and_then(|e| e.values.first())
    {
        start.checked_add(duration.as_seconds())?
    } else {
        start.checked_add(if all_day { 86400 } else { 0 })?
    };
    if end < start {
        return None;
    }
    // For all-day events the native local date, rather than the UTC day of
    // midnight in another zone, is the Google date.
    let start_value = if all_day {
        json!({"date": format!("{:04}-{:02}-{:02}", start_raw.year?, start_raw.month?, start_raw.day?)})
    } else {
        date_value(start, false, tz_name)?
    };
    let end_value = if all_day {
        let local = if let Some(entry) = end_entry {
            let raw = entry.values.first()?.as_partial_date_time()?;
            format!("{:04}-{:02}-{:02}", raw.year?, raw.month?, raw.day?)
        } else {
            let date = chrono::NaiveDate::from_ymd_opt(
                start_raw.year? as i32,
                start_raw.month? as u32,
                start_raw.day? as u32,
            )?;
            (date + Duration::seconds(end - start))
                .format("%Y-%m-%d")
                .to_string()
        };
        json!({"date": local})
    } else {
        date_value(end, false, tz_name)?
    };
    Some((start_value, end_value, start, end, all_day))
}

fn recurrence_lines(comp: &ICalendarComponent) -> Vec<String> {
    comp.entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.name,
                ICalendarProperty::Rrule | ICalendarProperty::Rdate | ICalendarProperty::Exdate
            )
        })
        .filter_map(|entry| {
            let mut line = String::new();
            entry.write_to(&mut line).ok()?;
            Some(line.trim_end_matches(['\r', '\n']).to_string())
        })
        .collect()
}

fn native_coverage_error(server: &Server, event: &CalendarEvent, q: &ListQuery) -> bool {
    let has_rule = event.data.event.components.iter().any(|comp| {
        comp.component_type == ICalendarComponentType::VEvent
            && comp.property(&ICalendarProperty::RecurrenceId).is_none()
            && (comp.property(&ICalendarProperty::Rrule).is_some()
                || comp.property(&ICalendarProperty::Rdate).is_some())
    });
    // Stalwart stores a bounded native expansion. Use the same calcard
    // expansion one step beyond that bound to detect a truncated rule. A
    // request beyond the stored horizon must fail rather than look empty.
    let limit = server.core.groupware.max_ical_instances;
    let probe = event
        .data
        .event
        .expand_dates(Tz::Floating, limit.saturating_add(1));
    !probe.errors.is_empty()
        || (has_rule
            && probe.events.len() > limit
            && (q
                .max_time
                .is_some_and(|end| end > event.data.event_range_end())
                || q.min
                    .is_some_and(|start| start > event.data.event_range_end())))
}

fn person(entry: &ICalendarEntry) -> Option<Value> {
    let address = entry.calendar_address()?;
    Some(
        json!({"email": address, "displayName": entry.parameter(&ICalendarParameterName::Cn)
        .and_then(|v| v.as_text())}),
    )
}

fn event_reminders(
    event: &CalendarEvent,
    comp: &ICalendarComponent,
    requester: u32,
) -> Option<Value> {
    let pref = event
        .preferences
        .iter()
        .find(|pref| pref.account_id == requester);
    let use_default = pref.is_some_and(|pref| pref.flags & PREF_USE_DEFAULT_ALERTS != 0);
    let alarms: Vec<&ICalendarComponent> =
        if let Some(pref) = pref.filter(|pref| !pref.alerts.is_empty()) {
            pref.alerts.iter().collect()
        } else {
            comp.component_ids
                .iter()
                .filter_map(|id| event.data.event.components.get(*id as usize))
                .filter(|alarm| alarm.component_type == ICalendarComponentType::VAlarm)
                .collect()
        };
    let mut overrides = Vec::new();
    for alarm in alarms {
        let action = text(alarm, ICalendarProperty::Action)?;
        let method = if action.eq_ignore_ascii_case("DISPLAY") {
            "popup"
        } else if action.eq_ignore_ascii_case("EMAIL") {
            "email"
        } else {
            return None;
        };
        let trigger = alarm.property(&ICalendarProperty::Trigger)?;
        if trigger
            .parameter(&ICalendarParameterName::Related)
            .and_then(|v| v.as_text())
            .is_some_and(|v| v.eq_ignore_ascii_case("END"))
        {
            return None;
        }
        let ICalendarValue::Duration(duration) = trigger.values.first()? else {
            return None;
        };
        let seconds = duration.as_seconds();
        if seconds > 0 || seconds % 60 != 0 {
            return None;
        }
        overrides.push(json!({"method": method, "minutes": -seconds / 60}));
    }
    Some(json!({"useDefault": use_default, "overrides": overrides}))
}

// iTIP replies may persist a sparse recurrence component containing only the
// changed attendee. Materialize inherited fields for this read projection;
// the stored iCalendar and native change log remain untouched.
fn effective_override(
    master: &ICalendarComponent,
    override_: &ICalendarComponent,
    default_tz: Tz,
) -> Option<ICalendarComponent> {
    let (start_value, end_value, start, end, all_day) = component_times(master, default_tz)?;
    let duration = if all_day {
        let start =
            chrono::NaiveDate::parse_from_str(start_value["date"].as_str()?, "%Y-%m-%d").ok()?;
        let end =
            chrono::NaiveDate::parse_from_str(end_value["date"].as_str()?, "%Y-%m-%d").ok()?;
        (end - start).num_days() * 86400
    } else {
        end - start
    };
    let mut effective = master.clone();
    effective.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Dtstart
                | ICalendarProperty::Dtend
                | ICalendarProperty::Duration
                | ICalendarProperty::Rrule
                | ICalendarProperty::Rdate
                | ICalendarProperty::Exdate
        )
    });
    for entry in &override_.entries {
        if entry.name == ICalendarProperty::Attendee {
            let address = entry.calendar_address();
            effective.entries.retain(|existing| {
                existing.name != ICalendarProperty::Attendee
                    || existing.calendar_address() != address
            });
        } else {
            effective
                .entries
                .retain(|existing| existing.name != entry.name);
        }
        effective.entries.push(entry.clone());
    }
    if effective.property(&ICalendarProperty::Dtstart).is_none() {
        let mut start = override_
            .property(&ICalendarProperty::RecurrenceId)?
            .clone();
        start.name = ICalendarProperty::Dtstart;
        effective.entries.push(start);
    }
    if effective.property(&ICalendarProperty::Dtend).is_none()
        && effective.property(&ICalendarProperty::Duration).is_none()
    {
        effective.entries.push(ICalendarEntry {
            name: ICalendarProperty::Duration,
            params: vec![],
            values: vec![ICalendarValue::Duration(ICalendarDuration::from_seconds(
                duration,
            ))],
        });
    }
    Some(effective)
}

fn event_json(
    account: u32,
    document: u32,
    event: &CalendarEvent,
    comp: &ICalendarComponent,
    master_id: Option<&str>,
    default_tz: Tz,
    requester: u32,
) -> Option<Value> {
    let uid = text(comp, ICalendarProperty::Uid)?;
    if uid.is_empty() {
        return None;
    }
    let (start, end, _, _, _) = component_times(comp, default_tz)?;
    let rid = comp.property(&ICalendarProperty::RecurrenceId);
    let base_id = stored_event_id(account, document, event);
    let id = if let Some(rid) = rid {
        let raw = rid.values.first()?.as_partial_date_time()?;
        let naive = raw.to_date_time()?.date_time.and_utc().timestamp();
        let key = RecurrenceKey::from_recurrence_id(naive)?;
        format!("{}_r{}", base_id, key.prefix())
    } else {
        base_id
    };
    let status = text(comp, ICalendarProperty::Status)
        .unwrap_or_else(|| "CONFIRMED".to_string())
        .to_ascii_lowercase();
    let visibility = text(comp, ICalendarProperty::Class).and_then(|v| {
        if v.eq_ignore_ascii_case("PRIVATE") {
            Some("private")
        } else if v.eq_ignore_ascii_case("CONFIDENTIAL") {
            Some("confidential")
        } else if v.eq_ignore_ascii_case("PUBLIC") {
            Some("public")
        } else {
            None
        }
    });
    let transparency = text(comp, ICalendarProperty::Transp).map(|v| {
        if v.eq_ignore_ascii_case("TRANSPARENT") {
            "transparent"
        } else {
            "opaque"
        }
    });
    let attendees = comp
        .properties(&ICalendarProperty::Attendee)
        .filter_map(|entry| {
            let mut value = person(entry)?;
            value["responseStatus"] = json!(
                entry
                    .parameter(&ICalendarParameterName::Partstat)
                    .and_then(|v| v.as_text())
                    .map(|v| match v.to_ascii_uppercase().as_str() {
                        "ACCEPTED" => "accepted",
                        "DECLINED" => "declined",
                        "TENTATIVE" => "tentative",
                        _ => "needsAction",
                    })
                    .unwrap_or("needsAction")
            );
            value["optional"] = json!(entry
                .parameter(&ICalendarParameterName::Role)
                .and_then(|value| value.as_text())
                .is_some_and(|role| role.eq_ignore_ascii_case("OPT-PARTICIPANT")));
            Some(value)
        })
        .collect::<Vec<_>>();
    let mut conference_entries = Vec::new();
    for entry in comp.properties(&ICalendarProperty::Conference) {
        let uri = entry.values.first()?.as_text()?;
        let kind = entry
            .parameter(&ICalendarParameterName::Feature)
            .and_then(|v| v.as_text());
        let entry_type = if kind.is_some_and(|v| v.eq_ignore_ascii_case("VIDEO")) {
            Some("video")
        } else if kind.is_some_and(|v| v.eq_ignore_ascii_case("AUDIO")) {
            Some("audio")
        } else {
            None
        };
        conference_entries.push(json!({"entryPointType": entry_type, "uri": uri}));
    }
    let original_start = rid.and_then(|entry| {
        let raw = entry.values.first()?.as_partial_date_time()?;
        if raw.hour.is_none() {
            Some(json!({"date": format!("{:04}-{:02}-{:02}", raw.year?, raw.month?, raw.day?)}))
        } else {
            let tz = entry
                .tz_id()
                .and_then(|v| Tz::from_str(v).ok())
                .unwrap_or(default_tz);
            date_value(
                raw.to_date_time_with_tz(tz)?.timestamp(),
                false,
                entry.tz_id(),
            )
        }
    });
    if rid.is_some() && original_start.is_none() {
        return None;
    }
    let mut value = json!({
        "id": id, "iCalUID": uid, "etag": event_etag(document, event),
        "status": status, "summary": text(comp, ICalendarProperty::Summary).unwrap_or_default(),
        "description": text(comp, ICalendarProperty::Description),
        "location": text(comp, ICalendarProperty::Location),
        "visibility": visibility, "transparency": transparency, "eventType": "default",
        "start": start, "end": end, "recurrence": if rid.is_none() { recurrence_lines(comp) } else { vec![] },
        "recurringEventId": master_id, "originalStartTime": original_start,
        "organizer": comp.property(&ICalendarProperty::Organizer).and_then(person),
        "attendees": attendees, "sequence": comp.property(&ICalendarProperty::Sequence)
            .and_then(|e| e.values.first()).and_then(|v| v.as_integer()).and_then(|v| u32::try_from(v).ok()),
        "created": DateTime::<Utc>::from_timestamp(event.created, 0).map(|v| v.to_rfc3339()),
        "updated": DateTime::<Utc>::from_timestamp(event.modified, 0).map(|v| v.to_rfc3339()),
        "reminders": event_reminders(event, comp, requester)?,
    });
    if !conference_entries.is_empty() {
        value["conferenceData"] = json!({"entryPoints": conference_entries});
    }
    Some(value)
}

fn canonical_events(
    account: u32,
    document: u32,
    event: &CalendarEvent,
    default_tz: Tz,
    requester: u32,
) -> Option<Vec<Value>> {
    let components = event
        .data
        .event
        .components
        .iter()
        .filter(|c| c.component_type == ICalendarComponentType::VEvent)
        .collect::<Vec<_>>();
    if components.is_empty() {
        return None;
    }
    let masters = components
        .iter()
        .filter(|c| c.property(&ICalendarProperty::RecurrenceId).is_none())
        .collect::<Vec<_>>();
    if masters.len() != 1 {
        return None;
    }
    let uid = text(masters[0], ICalendarProperty::Uid)?;
    if components
        .iter()
        .any(|c| text(c, ICalendarProperty::Uid).as_deref() != Some(uid.as_str()))
    {
        return None;
    }
    let mut result = vec![event_json(
        account, document, event, masters[0], None, default_tz, requester,
    )?];
    let master_id = stored_event_id(account, document, event);
    for comp in &components {
        if comp.property(&ICalendarProperty::RecurrenceId).is_some() {
            if text(comp, ICalendarProperty::Status)
                .is_some_and(|v| v.eq_ignore_ascii_case("CANCELLED"))
            {
                let rid = comp.property(&ICalendarProperty::RecurrenceId)?;
                let raw = rid.values.first()?.as_partial_date_time()?;
                let tz = rid
                    .tz_id()
                    .and_then(|v| Tz::from_str(v).ok())
                    .unwrap_or(default_tz);
                let naive = raw.to_date_time()?.date_time.and_utc().timestamp();
                let key = RecurrenceKey::from_recurrence_id(naive)?;
                let original = if raw.hour.is_none() {
                    json!({"date": format!("{:04}-{:02}-{:02}", raw.year?, raw.month?, raw.day?)})
                } else {
                    date_value(
                        raw.to_date_time_with_tz(tz)?.timestamp(),
                        false,
                        rid.tz_id(),
                    )?
                };
                result.push(json!({"id": format!("{}_r{}", master_id, key.prefix()),
                    "iCalUID": uid, "etag": event_etag(document, event),
                    "status": "cancelled", "recurringEventId": master_id,
                    "originalStartTime": original}));
            } else {
                let effective = effective_override(masters[0], comp, default_tz)?;
                result.push(event_json(
                    account,
                    document,
                    event,
                    &effective,
                    Some(&master_id),
                    default_tz,
                    requester,
                )?);
            }
        }
    }
    // Stalwart can record a cancelled occurrence as EXDATE on the master
    // instead of a separate cancelled VEVENT. Google exposes that exclusion
    // as an instance tombstone. An explicit exception with the same key wins.
    let mut existing = result
        .iter()
        .filter_map(|item| item["id"].as_str().map(str::to_string))
        .collect::<BTreeSet<_>>();
    for exclusion in masters[0].properties(&ICalendarProperty::Exdate) {
        let zone = exclusion
            .tz_id()
            .and_then(|value| Tz::from_str(value).ok())
            .unwrap_or(default_tz);
        for value in &exclusion.values {
            let raw = value.as_partial_date_time()?;
            let naive = raw.to_date_time()?.date_time.and_utc().timestamp();
            let key = RecurrenceKey::from_recurrence_id(naive)?;
            let id = format!("{}_r{}", master_id, key.prefix());
            if !existing.insert(id.clone()) {
                continue;
            }
            let original = if raw.hour.is_none() {
                json!({"date": format!("{:04}-{:02}-{:02}", raw.year?, raw.month?, raw.day?)})
            } else {
                date_value(
                    raw.to_date_time_with_tz(zone)?.timestamp(),
                    false,
                    exclusion.tz_id(),
                )?
            };
            result.push(json!({"id": id, "iCalUID": uid,
                "etag": event_etag(document, event), "status": "cancelled",
                "recurringEventId": master_id, "originalStartTime": original}));
        }
    }
    Some(result)
}

fn expanded_events(
    account: u32,
    document: u32,
    event: &CalendarEvent,
    expansions: &[groupware::calendar::expand::CalendarEventExpansion],
    default_tz: Tz,
    requester: u32,
) -> Option<Vec<Value>> {
    let canonical = canonical_events(account, document, event, default_tz, requester)?;
    let master = canonical.first()?;
    let master_id = stored_event_id(account, document, event);
    let recurring = master["recurrence"]
        .as_array()
        .is_some_and(|v| !v.is_empty())
        || canonical.len() > 1;
    let mut result = Vec::new();
    let master_comp = event.data.event.components.iter().find(|component| {
        component.component_type == ICalendarComponentType::VEvent
            && component
                .property(&ICalendarProperty::RecurrenceId)
                .is_none()
    })?;
    for occurrence in expansions {
        let stored_comp = event
            .data
            .event
            .components
            .get(occurrence.comp_id as usize)?;
        if stored_comp.component_type != ICalendarComponentType::VEvent {
            return None;
        }
        if text(stored_comp, ICalendarProperty::Status)
            .is_some_and(|v| v.eq_ignore_ascii_case("CANCELLED"))
        {
            continue;
        }
        let effective = if stored_comp
            .property(&ICalendarProperty::RecurrenceId)
            .is_some()
        {
            Some(effective_override(master_comp, stored_comp, default_tz)?)
        } else {
            None
        };
        let comp = effective.as_ref().unwrap_or(stored_comp);
        let mut value = event_json(
            account,
            document,
            event,
            comp,
            recurring
                .then_some(master_id.as_str())
                .filter(|_| comp.property(&ICalendarProperty::RecurrenceId).is_some()),
            default_tz,
            requester,
        )?;
        let all_day = comp
            .property(&ICalendarProperty::Dtstart)?
            .values
            .first()?
            .as_partial_date_time()?
            .hour
            .is_none();
        let zone = comp
            .property(&ICalendarProperty::Dtstart)
            .and_then(|e| e.tz_id());
        let (start, end, original) = if all_day {
            let local_duration = event
                .data
                .time_ranges
                .iter()
                .find(|range| range.id as u32 == occurrence.comp_id)?
                .duration as i64;
            (
                date_value(occurrence.start_naive, true, None)?,
                date_value(occurrence.start_naive + local_duration, true, None)?,
                date_value(occurrence.recurrence_id().naive, true, None)?,
            )
        } else {
            (
                date_value(occurrence.start, false, zone)?,
                date_value(occurrence.end, false, zone)?,
                date_value(occurrence.recurrence_id().utc, false, zone)?,
            )
        };
        value["start"] = start;
        value["end"] = end;
        value["recurrence"] = json!([]);
        if recurring {
            let key = occurrence.recurrence_key()?;
            value["id"] = json!(format!("{}_r{}", master_id, key.prefix()));
            value["recurringEventId"] = json!(master_id);
            value["originalStartTime"] = original;
        } else {
            value["id"] = json!(master_id);
            value["recurringEventId"] = Value::Null;
            value["originalStartTime"] = Value::Null;
        }
        result.push(value);
    }
    Some(result)
}

async fn load_event(
    server: &Server,
    account: u32,
    document: u32,
    range: Option<TimeRange>,
    default_tz: Tz,
) -> trc::Result<
    Option<(
        CalendarEvent,
        Vec<groupware::calendar::expand::CalendarEventExpansion>,
    )>,
> {
    let Some(archive) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account,
            Collection::CalendarEvent,
            document,
        ))
        .await?
    else {
        return Ok(None);
    };
    let expansions = if let Some(range) = range {
        let archived = archive
            .unarchive::<CalendarEvent>()
            .caused_by(trc::location!())?;
        archived.data.expand(default_tz, range).unwrap_or_default()
    } else {
        Vec::new()
    };
    let event = archive
        .deserialize::<CalendarEvent>()
        .caused_by(trc::location!())?;
    Ok(Some((event, expansions)))
}

async fn allowed_calendar(
    server: &Server,
    token: &AccessToken,
    account: u32,
    document: u32,
) -> trc::Result<Option<(std::sync::Arc<common::DavResources>, Tz)>> {
    if !token.has_access(account, Collection::CalendarEvent) {
        return Ok(None);
    }
    let cache = server
        .fetch_dav_resources(token.account_id(), account, SyncCollection::Calendar)
        .await?;
    if !cache.has_container_id(&document) {
        return Ok(None);
    }
    if !token.is_member(account)
        && !cache
            .container_acl(token, document)
            .contains(Acl::ReadItems)
    {
        return Ok(None);
    }
    let tz = cache
        .container_resource_by_id(document)
        .and_then(|res| res.calendar_preferences(token.account_id()))
        .map(|pref| pref.tz)
        .unwrap_or(Tz::UTC);
    Ok(Some((cache, tz)))
}

async fn calendar_list(
    server: &Server,
    token: &AccessToken,
) -> trc::Result<Result<Vec<Value>, HttpResponse>> {
    let mut accounts = BTreeSet::from([token.account_id()]);
    accounts.extend(token.shared_accounts(Collection::CalendarEvent).copied());
    let mut result = Vec::new();
    for account in accounts {
        if !token.has_access(account, Collection::CalendarEvent) {
            continue;
        }
        let cache = server
            .fetch_dav_resources(token.account_id(), account, SyncCollection::Calendar)
            .await?;
        let default_id = server
            .store()
            .get_value::<u32>(ValueKey {
                account_id: account,
                collection: Collection::Principal.into(),
                document_id: 0,
                class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
            })
            .await?
            .or_else(|| cache.document_ids(true).min());
        for document in cache.document_ids(true) {
            if !token.is_member(account)
                && !cache
                    .container_acl(token, document)
                    .contains(Acl::ReadItems)
            {
                continue;
            }
            let Some(archive) = server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account,
                    Collection::Calendar,
                    document,
                ))
                .await?
            else {
                continue;
            };
            let calendar = archive
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;
            let pref = calendar.preferences(token.account_id());
            let acl = calendar.acls.effective_acl(token);
            let role = if token.is_member(account) {
                "owner"
            } else if acl.contains(Acl::AddItems)
                && acl.contains(Acl::ModifyItems)
                && acl.contains(Acl::RemoveItems)
            {
                "writer"
            } else {
                "reader"
            };
            let alerts = |timed: bool| {
                pref.default_alerts
                    .iter()
                    .filter(|a| (a.flags & groupware::calendar::ALERT_WITH_TIME != 0) == timed)
                    .map(|a| {
                        (
                            a.flags & groupware::calendar::ALERT_EMAIL != 0,
                            a.offset.as_seconds(),
                        )
                    })
                    .collect::<BTreeSet<_>>()
            };
            let timed_alerts = alerts(true);
            let all_day_alerts = alerts(false);
            if timed_alerts != all_day_alerts {
                return Ok(Err(unrepresentable()));
            }
            if pref.default_alerts.iter().any(|alert| {
                alert.flags & groupware::calendar::ALERT_RELATIVE_TO_END != 0
                    || alert.offset.as_seconds() > 0
                    || alert.offset.as_seconds() % 60 != 0
            }) {
                return Ok(Err(unrepresentable()));
            }
            let reminders = timed_alerts.into_iter().map(|(email, seconds)| {
                json!({"method": if email { "email" } else { "popup" }, "minutes": -seconds / 60})
            }).collect::<Vec<_>>();
            result.push(json!({
                "id": calendar_id(account, document), "summary": pref.name,
                "description": pref.description, "timeZone": pref.time_zone.tz().map(|v| v.to_string()),
                "backgroundColor": pref.color, "accessRole": role,
                "primary": account == token.account_id() && default_id == Some(document),
                "selected": pref.flags & CALENDAR_INVISIBLE == 0,
                "defaultReminders": reminders,
            }));
        }
    }
    result.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(Ok(result))
}

async fn materialize_events(
    server: &Server,
    account: u32,
    calendar: u32,
    requester: u32,
    cache: &common::DavResources,
    tz: Tz,
    q: &ListQuery,
    ids: Option<&BTreeSet<u32>>,
) -> trc::Result<Result<Vec<Value>, HttpResponse>> {
    let mut items = Vec::new();
    let members = cache.children_ids(calendar).collect::<BTreeSet<_>>();
    let ids = ids.unwrap_or(&members);
    for &document in ids {
        if !members.contains(&document) {
            continue;
        }
        let range = if q.uid.is_some() {
            None
        } else {
            Some(q.range())
        };
        let Some((event, expansions)) = load_event(server, account, document, range, tz).await?
        else {
            return Ok(Err(unrepresentable()));
        };
        if native_coverage_error(server, &event, q) {
            return Ok(Err(unrepresentable()));
        }
        let Some(canonical) = canonical_events(account, document, &event, tz, requester) else {
            return Ok(Err(unrepresentable()));
        };
        if let Some(uid) = &q.uid {
            if canonical[0]["iCalUID"].as_str() != Some(uid) {
                continue;
            }
        } else if expansions.is_empty() {
            continue;
        }
        if q.single == Some(true) {
            let Some(expanded) =
                expanded_events(account, document, &event, &expansions, tz, requester)
            else {
                return Ok(Err(unrepresentable()));
            };
            items.extend(expanded);
        } else {
            items.extend(canonical);
        }
    }
    if q.single == Some(true) {
        fn start(v: &Value) -> &str {
            v["start"]["dateTime"]
                .as_str()
                .or_else(|| v["start"]["date"].as_str())
                .unwrap_or("")
        }
        items.sort_by(|a, b| {
            start(a)
                .cmp(start(b))
                .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
        });
    } else {
        items.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    }
    Ok(Ok(items))
}

async fn save_sync(server: &Server, state: &SyncState) -> trc::Result<String> {
    let key = random_key();
    server
        .in_memory_store()
        .key_set(
            KeyValue::with_prefix(
                SYNC_PREFIX,
                key.as_bytes(),
                serde_json::to_string(state)
                    .expect("Calendar sync state serializable")
                    .into_bytes(),
            )
            .expires(SYNC_TTL),
        )
        .await?;
    Ok(key)
}

async fn page_response(
    server: &Server,
    snapshot: Snapshot,
    size: usize,
    key: Option<String>,
    offset: usize,
) -> trc::Result<HttpResponse> {
    let end = offset.saturating_add(size).min(snapshot.items.len());
    let next_page = if end < snapshot.items.len() {
        let key = if let Some(key) = key {
            key
        } else {
            let key = random_key();
            server
                .in_memory_store()
                .key_set(
                    KeyValue::with_prefix(
                        PAGE_PREFIX,
                        key.as_bytes(),
                        serde_json::to_string(&snapshot)
                            .expect("Calendar page serializable")
                            .into_bytes(),
                    )
                    .expires(PAGE_TTL),
                )
                .await?;
            key
        };
        Some(seal(server, &PageToken { key, offset: end }))
    } else {
        None
    };
    let sync = if next_page.is_none() {
        snapshot.sync_key.as_ref().map(|key| {
            seal(
                server,
                &SyncToken {
                    key: key.clone(),
                    account: snapshot.account,
                    owner: snapshot.owner,
                    calendar: snapshot.calendar,
                    issued: snapshot.issued,
                },
            )
        })
    } else {
        None
    };
    let body = if snapshot.calendar == 0 {
        json!({"items": &snapshot.items[offset..end], "nextPageToken": next_page})
    } else {
        json!({"items": &snapshot.items[offset..end], "nextPageToken": next_page, "nextSyncToken": sync})
    };
    Ok(JsonResponse::new(body).no_cache().into_http_response())
}

async fn resume_page(
    server: &Server,
    account: u32,
    owner: u32,
    calendar: u32,
    q: &ListQuery,
    current_calendar_ids: Option<&BTreeSet<String>>,
) -> trc::Result<Option<HttpResponse>> {
    let Some(encoded) = q.page.as_deref() else {
        return Ok(None);
    };
    let Some(page) = open::<PageToken>(server, encoded) else {
        return Ok(Some(bad_query()));
    };
    let Some(data) = server
        .in_memory_store()
        .key_get::<String>(KeyValue::<()>::build_key(PAGE_PREFIX, page.key.as_bytes()))
        .await?
    else {
        return Ok(Some(bad_query()));
    };
    let Ok(snapshot) = serde_json::from_str::<Snapshot>(&data) else {
        return Ok(Some(bad_query()));
    };
    if snapshot.account != account
        || snapshot.owner != owner
        || snapshot.calendar != calendar
        || snapshot.query != q.fingerprint()
        || snapshot.issued > now()
        || now() - snapshot.issued > PAGE_TTL
        || page.offset == 0
        || page.offset >= snapshot.items.len()
    {
        return Ok(Some(bad_query()));
    }
    if let Some(allowed) = current_calendar_ids
        && snapshot
            .items
            .iter()
            .any(|item| item["id"].as_str().is_none_or(|id| !allowed.contains(id)))
    {
        return Ok(Some(error(
            StatusCode::FORBIDDEN,
            "Calendar access changed",
            "forbidden",
        )));
    }
    Ok(Some(
        page_response(server, snapshot, q.max, Some(page.key), page.offset).await?,
    ))
}

async fn events_list(
    server: &Server,
    token: &AccessToken,
    owner: u32,
    calendar: u32,
    q: &ListQuery,
) -> trc::Result<HttpResponse> {
    let Some((cache, tz)) = allowed_calendar(server, token, owner, calendar).await? else {
        return Ok(not_found());
    };
    if let Some(response) =
        resume_page(server, token.account_id(), owner, calendar, q, None).await?
    {
        return Ok(response);
    }
    let collection = SyncCollection::Calendar.into();
    let through = server
        .store()
        .get_last_change_id(owner, collection)
        .await?
        .unwrap_or_default();
    let issued = now();
    let members = cache.children_ids(calendar).collect::<BTreeSet<_>>();
    let mut member_ids = BTreeMap::new();
    if q.is_feed() && q.sync.is_none() {
        for &document in &members {
            if let Some((event, _)) = load_event(server, owner, document, None, tz).await? {
                member_ids.insert(document, stored_event_id(owner, document, &event));
            }
        }
    }
    let (items, sync_key) = if q.is_feed() && q.sync.is_some() {
        let Some(cursor) = q
            .sync
            .as_deref()
            .and_then(|value| open::<SyncToken>(server, value))
        else {
            return Ok(invalid_sync());
        };
        if cursor.account != token.account_id()
            || cursor.owner != owner
            || cursor.calendar != calendar
            || cursor.issued > now()
            || now() - cursor.issued > SYNC_TTL
        {
            return Ok(invalid_sync());
        }
        let Some(bytes) = server
            .in_memory_store()
            .key_get::<String>(KeyValue::<()>::build_key(
                SYNC_PREFIX,
                cursor.key.as_bytes(),
            ))
            .await?
        else {
            return Ok(invalid_sync());
        };
        let Ok(state) = serde_json::from_str::<SyncState>(&bytes) else {
            return Ok(invalid_sync());
        };
        if state.account != cursor.account
            || state.owner != owner
            || state.calendar != calendar
            || state.change_id > through
            || state.issued != cursor.issued
        {
            return Ok(invalid_sync());
        }
        let changes = server
            .store()
            .change_records(owner, collection, state.change_id, through, usize::MAX)
            .await?;
        if !changes.cursor_valid || changes.has_more {
            return Ok(invalid_sync());
        }
        let mut changed = BTreeSet::new();
        for (_, record) in changes.records {
            for change in record {
                match change {
                    Change::InsertItem(id) | Change::UpdateItem(id) | Change::DeleteItem(id) => {
                        if let Ok(id) = u32::try_from(id) {
                            changed.insert(id);
                        }
                    }
                    _ => (),
                }
            }
        }
        let mut items = Vec::new();
        let mut next_ids = state.ids.clone();
        for document in changed {
            if members.contains(&document) {
                let Some((event, _)) = load_event(server, owner, document, None, tz).await? else {
                    return Ok(error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Calendar changed during the request; retry",
                        "backendError",
                    ));
                };
                if native_coverage_error(server, &event, q) {
                    return Ok(unrepresentable());
                }
                let Some(canonical) =
                    canonical_events(owner, document, &event, tz, token.account_id())
                else {
                    return Ok(unrepresentable());
                };
                next_ids.insert(document, stored_event_id(owner, document, &event));
                items.extend(canonical);
            } else if state.members.contains(&document) {
                items.push(json!({"id": state.ids.get(&document).cloned().unwrap_or_else(|| event_id(owner, document)), "status": "cancelled"}));
                next_ids.remove(&document);
            }
        }
        items.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let key = save_sync(
            server,
            &SyncState {
                account: token.account_id(),
                owner,
                calendar,
                change_id: through,
                members: members.clone(),
                ids: next_ids,
                issued,
            },
        )
        .await?;
        (items, Some(key))
    } else {
        let items = match materialize_events(
            server,
            owner,
            calendar,
            token.account_id(),
            &cache,
            tz,
            q,
            None,
        )
        .await?
        {
            Ok(items) => items,
            Err(response) => return Ok(response),
        };
        let key = if q.is_feed() {
            Some(
                save_sync(
                    server,
                    &SyncState {
                        account: token.account_id(),
                        owner,
                        calendar,
                        change_id: through,
                        members: members.clone(),
                        ids: member_ids.clone(),
                        issued,
                    },
                )
                .await?,
            )
        } else {
            None
        };
        (items, key)
    };
    // The native store is not an MVCC snapshot. If it changed while building
    // this response, ask the client to retry rather than minting a cursor over
    // an inconsistent enumeration.
    if server
        .store()
        .get_last_change_id(owner, collection)
        .await?
        .unwrap_or_default()
        != through
    {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Calendar changed during the request; retry",
            "backendError",
        ));
    }
    page_response(
        server,
        Snapshot {
            account: token.account_id(),
            owner,
            calendar,
            query: q.fingerprint(),
            items,
            change_id: q.is_feed().then_some(through),
            sync_key,
            issued,
        },
        q.max,
        None,
        0,
    )
    .await
}

async fn event_get(
    server: &Server,
    token: &AccessToken,
    owner: u32,
    calendar: u32,
    requested: &str,
    instances: bool,
    q: Option<&ListQuery>,
) -> trc::Result<HttpResponse> {
    let Some((cache, tz)) = allowed_calendar(server, token, owner, calendar).await? else {
        return Ok(not_found());
    };
    let Some((document, recurrence)) = resolve_event_id(server, &cache, owner, requested).await?
    else {
        return Ok(not_found());
    };
    if !cache.children_ids(calendar).any(|id| id == document) {
        return Ok(not_found());
    }
    if instances {
        if recurrence.is_some() {
            return Ok(not_found());
        }
        let q = q.expect("instances query");
        if let Some(response) =
            resume_page(server, token.account_id(), owner, calendar, q, None).await?
        {
            return Ok(response);
        }
        let Some((event, expansions)) =
            load_event(server, owner, document, Some(q.range()), tz).await?
        else {
            return Ok(not_found());
        };
        if native_coverage_error(server, &event, q) {
            return Ok(unrepresentable());
        }
        let Some(items) =
            expanded_events(owner, document, &event, &expansions, tz, token.account_id())
        else {
            return Ok(unrepresentable());
        };
        return page_response(
            server,
            Snapshot {
                account: token.account_id(),
                owner,
                calendar,
                query: q.fingerprint(),
                items,
                change_id: None,
                sync_key: None,
                issued: now(),
            },
            q.max,
            None,
            0,
        )
        .await;
    }
    let Some((event, _)) = load_event(server, owner, document, None, tz).await? else {
        return Ok(not_found());
    };
    if native_coverage_error(server, &event, &ListQuery::default()) {
        return Ok(unrepresentable());
    }
    let Some(items) = canonical_events(owner, document, &event, tz, token.account_id()) else {
        return Ok(unrepresentable());
    };
    let mut found = items
        .into_iter()
        .find(|item| item["id"].as_str() == Some(requested));
    if found.is_none() && recurrence.is_some() {
        let Some((event, expansions)) =
            load_event(server, owner, document, Some(TimeRange::default()), tz).await?
        else {
            return Ok(unrepresentable());
        };
        let Some(instances) =
            expanded_events(owner, document, &event, &expansions, tz, token.account_id())
        else {
            return Ok(unrepresentable());
        };
        found = instances
            .into_iter()
            .find(|item| item["id"].as_str() == Some(requested));
    }
    Ok(found
        .map(|item| JsonResponse::new(item).no_cache().into_http_response())
        .unwrap_or_else(not_found))
}

pub(crate) async fn route_request(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
) -> trc::Result<Option<HttpResponse>> {
    let path = req.uri().path().to_string();
    if !path.starts_with("/calendar/v3/") {
        return Ok(None);
    }
    enum Route<'a> {
        Calendars,
        Events(&'a str),
        Event(&'a str, &'a str),
        Instances(&'a str, &'a str),
    }
    let route = if path == "/calendar/v3/users/me/calendarList" {
        Some(Route::Calendars)
    } else {
        let parts = path
            .trim_start_matches("/calendar/v3/")
            .split('/')
            .collect::<Vec<_>>();
        match parts.as_slice() {
            ["calendars", cal, "events"] => Some(Route::Events(cal)),
            ["calendars", cal, "events", event] => Some(Route::Event(cal, event)),
            ["calendars", cal, "events", event, "instances"] => Some(Route::Instances(cal, event)),
            _ => None,
        }
    };
    let Some(route) = route else {
        return Ok(Some(not_found()));
    };
    let write_permission = match (&route, req.method()) {
        (Route::Events(_), &Method::POST) => Some(Permission::JmapCalendarEventCreate),
        (Route::Event(_, _), &Method::PATCH) => Some(Permission::JmapCalendarEventUpdate),
        (Route::Event(_, _), &Method::DELETE) => Some(Permission::JmapCalendarEventDestroy),
        (_, &Method::GET) => None,
        _ => return Ok(Some(not_found())),
    };
    if write_permission.is_some() {
        let Some((mechanism, bearer)) = req.authorization() else {
            return Ok(Some(error(
                StatusCode::UNAUTHORIZED,
                "Bearer access token required",
                "authError",
            )));
        };
        if !mechanism.eq_ignore_ascii_case("bearer") {
            return Ok(Some(error(
                StatusCode::UNAUTHORIZED,
                "Bearer access token required",
                "authError",
            )));
        }
        let Ok(info) = server
            .validate_access_token(Some(GrantType::AccessToken), bearer)
            .await
        else {
            return Ok(Some(error(
                StatusCode::UNAUTHORIZED,
                "Invalid bearer access token",
                "authError",
            )));
        };
        if !info.claims.as_deref().is_some_and(|scopes| {
            scopes
                .split_ascii_whitespace()
                .any(|scope| scope == SCOPE_CALENDARS)
        }) {
            return Ok(Some(error(
                StatusCode::FORBIDDEN,
                "Calendar scope required",
                "forbidden",
            )));
        }
    }
    let (_flight, token) = server.authenticate_headers(req, session).await?;
    if let Some((mechanism, bearer)) = req.authorization()
        && mechanism.eq_ignore_ascii_case("bearer")
    {
        let scoped = server
            .validate_access_token(Some(GrantType::AccessToken), bearer)
            .await
            .ok()
            .is_some_and(|info| {
                info.account_id == token.account_id()
                    && info.claims.as_deref().is_some_and(|scopes| {
                        scopes
                            .split_ascii_whitespace()
                            .any(|scope| scope == SCOPE_CALENDARS)
                    })
            });
        if !scoped {
            return Ok(Some(error(
                StatusCode::FORBIDDEN,
                "Calendar scope required",
                "forbidden",
            )));
        }
    }
    if let Some(permission) = write_permission {
        if !token.has_permission(permission) {
            return Ok(Some(error(
                StatusCode::FORBIDDEN,
                "Calendar write permission required",
                "forbidden",
            )));
        }
        return Ok(Some(match route {
            Route::Events(raw_calendar) => {
                write::create(server, req, session, &token, raw_calendar).await?
            }
            Route::Event(raw_calendar, raw_event) if req.method() == Method::PATCH => {
                write::patch(server, req, session, &token, raw_calendar, raw_event).await?
            }
            Route::Event(raw_calendar, raw_event) => {
                write::delete(server, req, session, &token, raw_calendar, raw_event).await?
            }
            _ => not_found(),
        }));
    }
    let needs = match route {
        Route::Calendars => &[Permission::JmapCalendarGet][..],
        Route::Events(_) => &[
            Permission::JmapCalendarEventGet,
            Permission::JmapCalendarEventQuery,
            Permission::JmapCalendarEventChanges,
        ][..],
        Route::Event(_, _) => &[Permission::JmapCalendarEventGet][..],
        Route::Instances(_, _) => &[
            Permission::JmapCalendarEventGet,
            Permission::JmapCalendarEventQuery,
        ][..],
    };
    if needs
        .iter()
        .any(|permission| !token.has_permission(*permission))
    {
        return Ok(Some(error(
            StatusCode::FORBIDDEN,
            "Calendar read permission required",
            "forbidden",
        )));
    }
    let response = match route {
        Route::Calendars => {
            let Some(q) = ListQuery::parse(req.uri().query(), true, false) else {
                return Ok(Some(bad_query()));
            };
            let items = match calendar_list(server, &token).await? {
                Ok(items) => items,
                Err(response) => return Ok(Some(response)),
            };
            let allowed = items
                .iter()
                .filter_map(|v| v["id"].as_str().map(str::to_string))
                .collect::<BTreeSet<_>>();
            if let Some(response) = resume_page(
                server,
                token.account_id(),
                token.account_id(),
                0,
                &q,
                Some(&allowed),
            )
            .await?
            {
                response
            } else {
                page_response(
                    server,
                    Snapshot {
                        account: token.account_id(),
                        owner: token.account_id(),
                        calendar: 0,
                        query: q.fingerprint(),
                        items,
                        change_id: None,
                        sync_key: None,
                        issued: now(),
                    },
                    q.max,
                    None,
                    0,
                )
                .await?
            }
        }
        Route::Events(raw_calendar) => {
            let Ok(id) = percent_decode_str(raw_calendar).decode_utf8() else {
                return Ok(Some(not_found()));
            };
            let Some((owner, calendar)) = parse_calendar_id(&id) else {
                return Ok(Some(not_found()));
            };
            let Some(q) = ListQuery::parse(req.uri().query(), false, false) else {
                return Ok(Some(bad_query()));
            };
            events_list(server, &token, owner, calendar, &q).await?
        }
        Route::Event(raw_calendar, raw_event) | Route::Instances(raw_calendar, raw_event) => {
            let (Ok(id), Ok(event)) = (
                percent_decode_str(raw_calendar).decode_utf8(),
                percent_decode_str(raw_event).decode_utf8(),
            ) else {
                return Ok(Some(not_found()));
            };
            let Some((owner, calendar)) = parse_calendar_id(&id) else {
                return Ok(Some(not_found()));
            };
            let instances = matches!(route, Route::Instances(_, _));
            let query = if instances {
                match ListQuery::parse(req.uri().query(), false, true) {
                    Some(mut q) => {
                        q.uid = Some(event.to_string());
                        Some(q)
                    }
                    None => return Ok(Some(bad_query())),
                }
            } else {
                if req.uri().query().is_some() {
                    return Ok(Some(bad_query()));
                }
                None
            };
            event_get(
                server,
                &token,
                owner,
                calendar,
                &event,
                instances,
                query.as_ref(),
            )
            .await?
        }
    };
    Ok(Some(response))
}
