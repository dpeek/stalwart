/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;
use types::collection::{SyncCollection, VanishedCollection};
use utils::codec::leb128::Leb128Iterator;

use crate::{
    IterateParams, LogKey, Store, U32_LEN, U64_LEN,
    write::{LogCollection, key::DeserializeBigEndian},
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    InsertContainer(u64),
    UpdateContainer(u64),
    UpdateContainerProperty(u64),
    DeleteContainer(u64),
    InsertItem(u64),
    UpdateItem(u64),
    DeleteItem(u64),
}

#[derive(Debug)]
pub struct Changes {
    pub changes: Vec<Change>,
    pub from_change_id: u64,
    pub to_change_id: u64,
    pub container_change_id: Option<u64>,
    pub item_change_id: Option<u64>,
    pub is_truncated: bool,
}

/// A page of individual log entries. Unlike `Changes`, entries are not merged
/// across change IDs, so a consumer can resume after the last returned entry.
#[derive(Debug, Default)]
pub struct ChangeRecords {
    pub records: Vec<(u64, Vec<Change>)>,
    pub has_more: bool,
    pub cursor_valid: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Query {
    All,
    Since(u64),
    SinceInclusive(u64),
    RangeInclusive(u64, u64),
}

pub trait DeserializeVanished: Sized + Sync + Send {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self>;
}

impl Default for Changes {
    fn default() -> Self {
        Self {
            changes: Vec::with_capacity(10),
            from_change_id: 0,
            to_change_id: 0,
            container_change_id: None,
            item_change_id: None,
            is_truncated: false,
        }
    }
}

impl Store {
    pub async fn change_records(
        &self,
        account_id: u32,
        collection: LogCollection,
        after: u64,
        through: u64,
        limit: usize,
    ) -> trc::Result<ChangeRecords> {
        let mut page = ChangeRecords {
            cursor_valid: after == 0,
            ..Default::default()
        };
        self.iterate(
            IterateParams::new(
                LogKey {
                    account_id,
                    collection: u8::from(collection),
                    change_id: after,
                },
                LogKey {
                    account_id,
                    collection: u8::from(collection),
                    change_id: through,
                },
            )
            .ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if value.is_empty() {
                    // The empty entry marks the earliest resumable position after pruning.
                    if change_id > after {
                        page.cursor_valid = false;
                        return Ok(false);
                    } else {
                        page.cursor_valid = true;
                    }
                    return Ok(true);
                }
                if change_id == after {
                    page.cursor_valid = true;
                    return Ok(true);
                }
                if !page.cursor_valid {
                    return Ok(false);
                }

                let mut entry = Changes::default();
                entry.deserialize(value).ok_or_else(|| {
                    trc::Error::corrupted_key(key, value.into(), trc::location!())
                })?;
                let items: Vec<_> = entry
                    .changes
                    .into_iter()
                    .filter(Change::is_item_change)
                    .collect();
                if !items.is_empty() {
                    if page.records.len() == limit {
                        page.has_more = true;
                        return Ok(false);
                    }
                    page.records.push((change_id, items));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
        Ok(page)
    }

    pub async fn changes(
        &self,
        account_id: u32,
        collection_: LogCollection,
        query: Query,
    ) -> trc::Result<Changes> {
        let is_share_log = matches!(
            collection_,
            LogCollection::Sync(SyncCollection::ShareNotification)
        );
        let collection = u8::from(collection_);

        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
        };
        let from_key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: to_change_id,
        };

        let mut changelog = Changes::default();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if is_inclusive || change_id != from_change_id {
                    if value.is_empty() {
                        changelog.is_truncated = true;
                        return Ok(true);
                    }
                    if changelog.changes.is_empty() {
                        changelog.from_change_id = change_id;
                    }
                    changelog.to_change_id = change_id;
                    if !is_share_log {
                        let (has_container_changes, has_item_changes) =
                            changelog.deserialize(value).ok_or_else(|| {
                                trc::Error::corrupted_key(key, value.into(), trc::location!())
                            })?;
                        if has_container_changes {
                            changelog.container_change_id = Some(change_id);
                        }
                        if has_item_changes {
                            changelog.item_change_id = Some(change_id);
                        }
                    } else {
                        changelog.changes.push(Change::InsertItem(change_id));
                    }
                } else {
                    changelog.from_change_id = change_id;
                    changelog.to_change_id = change_id;
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(changelog)
    }

    pub async fn vanished<T: DeserializeVanished>(
        &self,
        account_id: u32,
        collection: LogCollection,
        query: Query,
    ) -> trc::Result<Vec<T>> {
        let collection = u8::from(collection);
        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
        };
        let from_key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: to_change_id,
        };

        let mut vanished = Vec::default();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if is_inclusive || change_id != from_change_id {
                    let mut iter = value.iter().peekable();

                    while iter.peek().is_some() {
                        if let Some(item) = T::deserialize_vanished(&mut iter) {
                            vanished.push(item);
                        } else {
                            return Err(trc::Error::corrupted_key(
                                key,
                                value.into(),
                                trc::location!(),
                            ));
                        }
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(vanished)
    }

    pub async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: LogCollection,
    ) -> trc::Result<Option<u64>> {
        let collection = u8::from(collection);
        let from_key = LogKey {
            account_id,
            collection,
            change_id: 0,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: u64::MAX,
        };

        let mut last_change_id = None;

        self.iterate(
            IterateParams::new(from_key, to_key)
                .descending()
                .no_values()
                .only_first(),
            |key, _| {
                last_change_id = key.deserialize_be_u64(key.len() - U64_LEN)?.into();
                Ok(false)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(last_change_id)
    }
}

impl From<VanishedCollection> for LogCollection {
    fn from(value: VanishedCollection) -> Self {
        LogCollection::Vanished(value)
    }
}

impl From<SyncCollection> for LogCollection {
    fn from(value: SyncCollection) -> Self {
        LogCollection::Sync(value)
    }
}

impl Changes {
    pub fn deserialize(&mut self, bytes: &[u8]) -> Option<(bool, bool)> {
        let mut bytes_it = bytes.iter();

        let container_inserts: usize = bytes_it.next_leb128()?;
        let container_updates: usize = bytes_it.next_leb128()?;
        let container_property_changes: usize = bytes_it.next_leb128()?;
        let container_deletes: usize = bytes_it.next_leb128()?;

        let item_inserts: usize = bytes_it.next_leb128()?;
        let item_updates: usize = bytes_it.next_leb128()?;
        let item_deletes: usize = bytes_it.next_leb128()?;

        let has_container_changes =
            container_inserts + container_updates + container_property_changes + container_deletes
                > 0;
        let has_item_changes = item_inserts + item_updates + item_deletes > 0;

        if container_inserts > 0 {
            for _ in 0..container_inserts {
                self.changes
                    .push(Change::InsertContainer(bytes_it.next_leb128()?));
            }
        }

        if container_updates > 0 || container_property_changes > 0 {
            'update_outer: for change_pos in 0..(container_updates + container_property_changes) {
                let id = bytes_it.next_leb128()?;
                let mut is_property_change = change_pos >= container_updates;

                for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertContainer(insert_id) if *insert_id == id => {
                            // Item updated after inserted, no need to count this change.
                            continue 'update_outer;
                        }
                        Change::UpdateContainer(update_id) if *update_id == id => {
                            // Move update to the front
                            is_property_change = false;
                            self.changes.remove(idx);
                            break;
                        }
                        Change::UpdateContainerProperty(update_id) if *update_id == id => {
                            // Move update to the front
                            self.changes.remove(idx);
                            break;
                        }
                        _ => (),
                    }
                }

                self.changes.push(if !is_property_change {
                    Change::UpdateContainer(id)
                } else {
                    Change::UpdateContainerProperty(id)
                });
            }
        }

        if container_deletes > 0 {
            'delete_outer: for _ in 0..container_deletes {
                let id = bytes_it.next_leb128()?;

                'delete_inner: for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertContainer(insert_id) if *insert_id == id => {
                            self.changes.remove(idx);
                            continue 'delete_outer;
                        }
                        Change::UpdateContainer(update_id) if *update_id == id => {
                            self.changes.remove(idx);
                            break 'delete_inner;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::DeleteContainer(id));
            }
        }

        // Item changes
        if item_inserts > 0 {
            for _ in 0..item_inserts {
                self.changes
                    .push(Change::InsertItem(bytes_it.next_leb128()?));
            }
        }

        if item_updates > 0 {
            'update_outer: for _ in 0..item_updates {
                let id = bytes_it.next_leb128()?;

                for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertItem(insert_id) if *insert_id == id => {
                            // Item updated after inserted, no need to count this change.
                            continue 'update_outer;
                        }
                        Change::UpdateItem(update_id) if *update_id == id => {
                            // Move update to the front
                            self.changes.remove(idx);
                            break;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::UpdateItem(id));
            }
        }

        if item_deletes > 0 {
            'delete_outer: for _ in 0..item_deletes {
                let id = bytes_it.next_leb128()?;

                'delete_inner: for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertItem(insert_id) if *insert_id == id => {
                            self.changes.remove(idx);
                            continue 'delete_outer;
                        }
                        Change::UpdateItem(update_id) if *update_id == id => {
                            self.changes.remove(idx);
                            break 'delete_inner;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::DeleteItem(id));
            }
        }

        Some((has_container_changes, has_item_changes))
    }
}

impl Changes {
    pub fn total_container_changes(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.is_container_change())
            .count()
    }

    pub fn total_item_changes(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.is_item_change())
            .count()
    }
}

impl Change {
    pub fn item_id(&self) -> Option<u64> {
        match self {
            Change::InsertItem(id) => Some(*id),
            Change::UpdateItem(id) => Some(*id),
            Change::DeleteItem(id) => Some(*id),
            _ => None,
        }
    }

    pub fn container_id(&self) -> Option<u64> {
        match self {
            Change::InsertContainer(id) => Some(*id),
            Change::UpdateContainer(id) => Some(*id),
            Change::UpdateContainerProperty(id) => Some(*id),
            Change::DeleteContainer(id) => Some(*id),
            _ => None,
        }
    }

    pub fn try_unwrap_item_id(self) -> Option<u64> {
        match self {
            Change::InsertItem(id) => Some(id),
            Change::UpdateItem(id) => Some(id),
            Change::DeleteItem(id) => Some(id),
            _ => None,
        }
    }

    pub fn try_unwrap_container_id(self) -> Option<u64> {
        match self {
            Change::InsertContainer(id) => Some(id),
            Change::UpdateContainer(id) => Some(id),
            Change::UpdateContainerProperty(id) => Some(id),
            Change::DeleteContainer(id) => Some(id),
            _ => None,
        }
    }

    pub fn is_container_change(&self) -> bool {
        matches!(
            self,
            Change::InsertContainer(_)
                | Change::UpdateContainer(_)
                | Change::UpdateContainerProperty(_)
                | Change::DeleteContainer(_)
        )
    }

    pub fn is_item_change(&self) -> bool {
        matches!(
            self,
            Change::InsertItem(_) | Change::UpdateItem(_) | Change::DeleteItem(_)
        )
    }
}

impl DeserializeVanished for u64 {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let mut num = [0u8; U64_LEN];
        for i in num.iter_mut() {
            *i = *bytes.next()?;
        }
        Some(u64::from_be_bytes(num))
    }
}

impl DeserializeVanished for (u32, u32) {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let mut num1 = [0u8; U32_LEN];
        let mut num2 = [0u8; U32_LEN];
        for i in num1.iter_mut().chain(num2.iter_mut()) {
            *i = *bytes.next()?;
        }
        Some((u32::from_be_bytes(num1), u32::from_be_bytes(num2)))
    }
}

impl DeserializeVanished for String {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let mut name = Vec::with_capacity(16);

        loop {
            let byte = bytes.next()?;
            if *byte != 0 {
                name.push(*byte);
            } else {
                break;
            }
        }

        String::from_utf8(name).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Key, SUBSPACE_LOGS, SerializeInfallible,
        backend::ephemeral::EphemeralStore,
        write::{AnyClass, BatchBuilder, ValueClass, log::Changes as LogChanges},
    };

    async fn put(store: &Store, account_id: u32, change_id: u64, change: Option<Change>) {
        let mut entry = LogChanges::default();
        match change {
            Some(Change::InsertItem(id)) => {
                entry.item_inserts.insert(id);
            }
            Some(Change::UpdateItem(id)) => {
                entry.item_updates.insert(id);
            }
            Some(Change::DeleteItem(id)) => {
                entry.item_deletes.insert(id);
            }
            Some(Change::InsertContainer(id)) => {
                entry.container_inserts.insert(id as u32);
            }
            None => (),
            _ => unreachable!(),
        }
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id).set(
            ValueClass::Any(AnyClass {
                subspace: SUBSPACE_LOGS,
                key: LogKey {
                    account_id,
                    collection: SyncCollection::Email.into(),
                    change_id,
                }
                .serialize(0),
            }),
            if change.is_some() {
                entry.serialize()
            } else {
                Vec::new()
            },
        );
        store.write(batch.build_all()).await.unwrap();
    }

    #[tokio::test]
    async fn paginates_insert_update_delete_without_skipping() {
        let store = EphemeralStore::open();
        put(&store, 1, 10, Some(Change::InsertItem(7))).await;
        put(&store, 1, 11, Some(Change::InsertContainer(3))).await;
        put(&store, 1, 12, Some(Change::UpdateItem(7))).await;
        put(&store, 1, 13, Some(Change::DeleteItem(7))).await;
        let first = store
            .change_records(1, SyncCollection::Email.into(), 10, 13, 1)
            .await
            .unwrap();
        assert!(first.cursor_valid && first.has_more);
        assert_eq!(first.records, vec![(12, vec![Change::UpdateItem(7)])]);
        // A later write must not enter the snapshot selected by the first page.
        put(&store, 1, 14, Some(Change::InsertItem(8))).await;
        let second = store
            .change_records(1, SyncCollection::Email.into(), 12, 13, 1)
            .await
            .unwrap();
        assert!(second.cursor_valid && !second.has_more);
        assert_eq!(second.records, vec![(13, vec![Change::DeleteItem(7)])]);
        let from_zero = store
            .change_records(1, SyncCollection::Email.into(), 0, 13, 1)
            .await
            .unwrap();
        assert!(from_zero.cursor_valid && from_zero.has_more);
        assert_eq!(from_zero.records, vec![(10, vec![Change::InsertItem(7)])]);
    }

    #[tokio::test]
    async fn rejects_invalid_or_pruned_cursor_and_isolates_accounts() {
        let store = EphemeralStore::open();
        put(&store, 1, 10, Some(Change::InsertItem(7))).await;
        put(&store, 1, 12, Some(Change::DeleteItem(7))).await;
        put(&store, 2, 11, Some(Change::InsertItem(9))).await;
        assert!(
            !store
                .change_records(1, SyncCollection::Email.into(), 11, 12, 10)
                .await
                .unwrap()
                .cursor_valid
        );
        assert!(
            !store
                .change_records(2, SyncCollection::Email.into(), 10, 11, 10)
                .await
                .unwrap()
                .cursor_valid
        );
        assert_eq!(
            store
                .change_records(2, SyncCollection::Email.into(), 0, 11, 10)
                .await
                .unwrap()
                .records,
            vec![(11, vec![Change::InsertItem(9)])]
        );
        put(&store, 1, 10, None).await;
        assert!(
            !store
                .change_records(1, SyncCollection::Email.into(), 0, 12, 10)
                .await
                .unwrap()
                .cursor_valid
        );
        assert!(
            store
                .change_records(1, SyncCollection::Email.into(), 10, 12, 10)
                .await
                .unwrap()
                .cursor_valid
        );
    }
}
