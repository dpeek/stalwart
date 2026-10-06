/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Routes Fog's compatibility endpoints without extending Stalwart's main dispatcher.

use crate::{calendar, gmail, people};
use common::Server;
use http_proto::{HttpRequest, HttpResponse, HttpSessionData};

pub(crate) async fn route_request(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
) -> trc::Result<Option<HttpResponse>> {
    if req.uri().path().split('/').nth(1) == Some("gmail") {
        gmail::route_request(server, req, session).await
    } else if req.uri().path().split('/').nth(1) == Some("people") {
        people::route_request(server, req, session).await
    } else if req.uri().path().starts_with("/calendar/v3/") {
        calendar::route_request(server, req, session).await
    } else {
        Ok(None)
    }
}
