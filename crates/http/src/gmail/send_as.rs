/*
 * SPDX-FileCopyrightText: 2026 Fog contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Read-only Gmail send-as aliases backed by the account's JMAP identities.

use common::{Server, auth::AccessToken};
use email::identity::Identity;
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use jmap::identity::get::IdentityGet;
use registry::schema::enums::Permission;
use serde::Serialize;
use std::collections::BTreeMap;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use types::collection::Collection;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendAsAlias {
    send_as_email: String,
    display_name: String,
    signature: String,
    is_primary: bool,
    is_default: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListSendAs {
    send_as: Vec<SendAsAlias>,
}

pub(crate) async fn list_send_as(
    server: &Server,
    access_token: &AccessToken,
) -> trc::Result<HttpResponse> {
    access_token.enforce_permission(Permission::JmapIdentityGet)?;
    let account_id = access_token.account_id();
    let primary_address = server.account_info(account_id).await?.name().to_string();
    let mut aliases = BTreeMap::<String, SendAsAlias>::new();

    for id in server.identity_get_or_create(account_id).await?.iter() {
        let Some(archive) = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Identity,
                id,
            ))
            .await?
        else {
            continue;
        };
        let identity = archive.unarchive::<Identity>()?;
        let key = identity.email.to_ascii_lowercase();
        let candidate = SendAsAlias {
            send_as_email: identity.email.to_string(),
            display_name: identity.name.to_string(),
            signature: identity.html_signature.to_string(),
            is_primary: key.eq_ignore_ascii_case(&primary_address),
            is_default: false,
        };

        // JMAP permits multiple identities for one address. Prefer one with a
        // signature so a blank automatic identity cannot hide a configured one.
        match aliases.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if entry.get().signature.is_empty() && !candidate.signature.is_empty() =>
            {
                entry.insert(candidate);
            }
            _ => {}
        }
    }

    let mut send_as: Vec<_> = aliases.into_values().collect();
    // Stalwart has no preferred sending identity. Use the primary address as
    // the default, falling back to the first configured identity if needed.
    let default_index = send_as
        .iter()
        .position(|alias| alias.is_primary)
        .unwrap_or(0);
    if let Some(default) = send_as.get_mut(default_index) {
        default.is_default = true;
    }

    Ok(JsonResponse::new(ListSendAs { send_as })
        .no_cache()
        .into_http_response())
}
