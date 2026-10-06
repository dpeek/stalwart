/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::DavError;
use calcard::vcard::{
    ArchivedVCard, ArchivedVCardEntry, VCardEntry, VCardParameterName, VCardProperty, VCardVersion,
};
use dav_proto::schema::property::CardDavPropertyName;
use std::fmt::Write;
use store::write::serialize::rkyv_deserialize;

pub(crate) fn serialize_vcard_with_props(
    card: &ArchivedVCard,
    props: &[CardDavPropertyName],
    version: VCardVersion,
) -> crate::Result<String> {
    if version == VCardVersion::V4_0 {
        return Ok(super::query::serialize_vcard_with_props(
            card, props, version,
        ));
    }

    let mut vcard = String::with_capacity(128);
    if props.is_empty() {
        let _ = write!(&mut vcard, "BEGIN:VCARD\r\nVERSION:3.0\r\n");
        for entry in card.entries.iter() {
            if entry.name == VCardProperty::Begin
                || entry.name == VCardProperty::End
                || entry.name == VCardProperty::Version
            {
                continue;
            }
            write_vcard3_entry(&mut vcard, entry, true)?;
        }
        let _ = write!(&mut vcard, "END:VCARD\r\n");
    } else {
        let _ = write!(&mut vcard, "BEGIN:VCARD\r\n");
        for entry in card.entries.iter() {
            for item in props {
                if entry.name == item.name && entry.group == item.group {
                    if item.name != VCardProperty::Version {
                        write_vcard3_entry(&mut vcard, entry, !item.no_value)?;
                    } else {
                        let _ = write!(&mut vcard, "VERSION:{version}\r\n");
                    }
                    break;
                }
            }
        }
        let _ = write!(&mut vcard, "END:VCARD\r\n");
    }

    Ok(vcard)
}

fn write_vcard3_entry(
    out: &mut String,
    entry: &ArchivedVCardEntry,
    with_value: bool,
) -> crate::Result<()> {
    // Native v3 output keeps JSContact parameters that Contacts.app cannot parse.
    // Do not fall back to that output when an archived entry is invalid.
    let mut owned = rkyv_deserialize::<_, VCardEntry>(entry).map_err(DavError::Internal)?;
    owned.params.retain(|param| {
        !matches!(
            param.name,
            VCardParameterName::Jscomps | VCardParameterName::Jsptr | VCardParameterName::PropId
        )
    });
    if !with_value {
        owned.values.clear();
    }
    let _ = owned.write_to(out, false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::serialize_vcard_with_props;
    use calcard::{
        Entry, Parser,
        vcard::{ArchivedVCard, VCardProperty, VCardVersion},
    };
    use dav_proto::schema::property::CardDavPropertyName;

    #[test]
    fn native_v3_needs_jscontact_parameter_cleanup() {
        let input = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:David Peek\r\nN;JSCOMPS=\";1;0\";PROP-ID=name:Peek;David;;;\r\nNOTE:Numero Uno\r\nEND:VCARD\r\n";
        let Entry::VCard(card) = Parser::new(input).entry() else {
            panic!("Expected a vCard");
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&card).unwrap();
        let archived = rkyv::access::<ArchivedVCard, rkyv::rancor::Error>(&bytes).unwrap();
        let mut native_v3 = String::new();
        archived
            .write_to(&mut native_v3, VCardVersion::V3_0)
            .unwrap();
        assert!(native_v3.contains("JSCOMPS"));
        assert!(native_v3.contains("PROP-ID"));

        let output = serialize_vcard_with_props(archived, &[], VCardVersion::V3_0)
            .unwrap_or_else(|_| panic!("vCard serialization failed"));
        assert!(output.contains("VERSION:3.0\r\n"));
        assert!(output.contains("NOTE:Numero Uno\r\n"));
        assert!(!output.contains("JSCOMPS"));
        assert!(!output.contains("PROP-ID"));

        let name_only = serialize_vcard_with_props(
            archived,
            &[CardDavPropertyName {
                group: None,
                name: VCardProperty::N,
                no_value: false,
            }],
            VCardVersion::V3_0,
        )
        .unwrap_or_else(|_| panic!("partial vCard serialization failed"));
        assert!(!name_only.contains("VERSION:"));
        assert!(!name_only.contains("JSCOMPS"));
        assert!(!name_only.contains("PROP-ID"));
    }
}
