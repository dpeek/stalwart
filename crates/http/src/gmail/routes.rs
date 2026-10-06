/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! HTTP dispatch for the Gmail-shaped compatibility API.

use super::{
    GmailCompat, create_filter, create_label, delete_filter, delete_label, get_attachment,
    get_message, get_thread, list_filters, list_send_as, modify_message, send_gmail_message, watch,
};
use crate::auth::authenticate::Authenticator;
use common::Server;
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{Method, StatusCode};

pub(crate) async fn route_request(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
) -> trc::Result<Option<HttpResponse>> {
    let mut path = req.uri().path().split('/');
    path.next(); // leading slash
    path.next(); // gmail, already selected by fog.rs

    if path.next() != Some("v1") {
        return Ok(None);
    }
    let resource = path.next();
    if resource == Some("jwks") && path.next().is_none() && req.method() == Method::GET {
        server
            .is_http_anonymous_request_allowed(session.remote_ip)
            .await?;
        return Ok(Some(watch::jwks()));
    }
    if resource != Some("users") || path.next() != Some("me") {
        return Err(trc::ResourceEvent::NotFound.into_err());
    }

    let endpoint = path.next().unwrap_or_default();
    let resource_id = path.next();
    let trailing = path.next();
    if endpoint == "settings"
        && resource_id == Some("sendAs")
        && trailing.is_none()
        && path.next().is_none()
        && req.method() == Method::GET
    {
        let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
        return list_send_as(server, &access_token).await.map(Some);
    }
    if endpoint == "settings" && resource_id == Some("filters") {
        let filter_id = trailing;
        if path.next().is_none() {
            let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
            match (req.method(), filter_id) {
                (&Method::GET, None) => {
                    return list_filters(server, &access_token).await.map(Some);
                }
                (&Method::POST, None) => {
                    let Some(body) = fetch_body(req, 64 * 1024, session.session_id).await else {
                        return Ok(Some(super::error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "Filter request too large",
                        )));
                    };
                    return create_filter(server, &access_token, session, &body)
                        .await
                        .map(Some);
                }
                (&Method::DELETE, Some(id)) => {
                    return delete_filter(server, &access_token, session, id)
                        .await
                        .map(Some);
                }
                _ => (),
            }
        }
    }
    if endpoint == "labels" && trailing.is_none() {
        if req.method() == Method::POST && resource_id.is_none() {
            let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
            let Some(body) = fetch_body(req, 64 * 1024, session.session_id).await else {
                return Ok(Some(super::error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Label request too large",
                )));
            };
            return create_label(server, &access_token, &body).await.map(Some);
        }
        if req.method() == Method::DELETE
            && let Some(label_id) = resource_id
        {
            let label_id = label_id.to_string();
            let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
            return delete_label(server, &access_token, session, &label_id)
                .await
                .map(Some);
        }
    }
    if req.method() == Method::POST
        && endpoint == "messages"
        && resource_id == Some("send")
        && trailing.is_none()
    {
        let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
        let Some(body) = fetch_body(req, 40 * 1024 * 1024, session.session_id).await else {
            return Ok(Some(super::error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Send request too large",
            )));
        };
        return send_gmail_message(server, &access_token, session, &body)
            .await
            .map(Some);
    }
    if req.method() == Method::POST
        && endpoint == "messages"
        && let Some(message_id) = resource_id
        && trailing == Some("modify")
        && path.next().is_none()
    {
        let message_id = message_id.to_string();
        let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
        let Some(body) = fetch_body(req, 64 * 1024, session.session_id).await else {
            return Ok(Some(super::error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Modify request too large",
            )));
        };
        return modify_message(server, &access_token, session, &message_id, &body)
            .await
            .map(Some);
    }
    if req.method() == Method::POST
        && resource_id.is_none()
        && trailing.is_none()
        && matches!(endpoint, "watch" | "stop")
    {
        let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
        return if endpoint == "watch" {
            let Some(body) = fetch_body(req, 8192, session.session_id).await else {
                return Ok(Some(super::error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Watch request too large",
                )));
            };
            watch::watch(server, &access_token, &body).await.map(Some)
        } else {
            watch::stop(server, &access_token).await.map(Some)
        };
    }
    if req.method() == Method::GET
        && endpoint == "messages"
        && let Some(message_id) = resource_id
        && trailing == Some("attachments")
        && let Some(attachment_id) = path.next()
        && path.next().is_none()
    {
        let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
        return get_attachment(
            server,
            &access_token,
            message_id,
            attachment_id,
            req.uri().query(),
        )
        .await
        .map(Some);
    }
    if req.method() == Method::GET
        && trailing.is_none()
        && ((resource_id.is_none()
            && matches!(
                endpoint,
                "profile" | "history" | "threads" | "messages" | "labels"
            ))
            || (matches!(endpoint, "threads" | "messages") && resource_id.is_some()))
    {
        let (_in_flight, access_token) = server.authenticate_headers(req, session).await?;
        if let Some(id) = resource_id {
            return if endpoint == "threads" {
                get_thread(server, &access_token, id, req.uri().query())
                    .await
                    .map(Some)
            } else {
                get_message(server, &access_token, id, req.uri().query())
                    .await
                    .map(Some)
            };
        }
        return server
            .handle_gmail_compat(endpoint, req.uri().query(), &access_token)
            .await
            .map(Some);
    }
    Ok(None)
}
