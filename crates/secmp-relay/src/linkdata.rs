// SPDX-License-Identifier: AGPL-3.0-or-later
//! `LinkDataStore` (spec §9.3, §9.4): the inviters' link-data blobs by `ld_id`.
//!
//! An entry keeps `one_time`, `expires_bucket`, `owner_pk` and the blob. A consume-mode `LINK_GET` of a one-time
//! blob drops the blob (wiped) and leaves a **consumption marker** (the entry without its blob, reading REF-M5 5),
//! which reports `consumed` until it expires with the blob's expiry; a `LINK_PUT` on a marker's `ld_id` is
//! `ERR_EXISTS` until then. Link data is valid **through** `expires_bucket` (OPEN-M5-05 B): expired iff
//! `now > expires_bucket`. This module holds the data; the command semantics are in [`crate::exec`].

use std::collections::HashMap;
use std::collections::hash_map::RandomState;

use secmp_proto::keys::Ed25519Pk;
use secmp_proto::wire::Id;

use crate::buf::BlobBuf;
use crate::clock::HourBucket;
use crate::queue::IdMap;

/// One link-data entry; `blob` is `None` for a consumption marker.
pub struct Entry {
    /// One-time link data (§9.4).
    pub one_time: bool,
    /// The last bucket the entry is valid in.
    pub expires: HourBucket,
    /// The owner key (owner-status signatures, §9.3).
    pub owner_pk: Ed25519Pk,
    /// The blob; `None` once a one-time blob was consumed.
    pub blob: Option<BlobBuf>,
}

impl Entry {
    /// `present` of `LINKR`: the blob is stored.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.blob.is_some()
    }

    /// `consumed` of `LINKR`: a consumption marker.
    #[must_use]
    pub const fn consumed(&self) -> bool {
        self.blob.is_none()
    }
}

/// The link data.
pub struct LinkDataStore {
    entries: IdMap<Entry>,
}

impl Default for LinkDataStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkDataStore {
    /// No entries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::with_hasher(RandomState::new()),
        }
    }

    /// The number of entries and markers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry or marker `ld_id`.
    #[must_use]
    pub fn get(&self, ld_id: &Id) -> Option<&Entry> {
        self.entries.get(ld_id)
    }

    /// The entry or marker `ld_id`, mutable.
    pub fn get_mut(&mut self, ld_id: &Id) -> Option<&mut Entry> {
        self.entries.get_mut(ld_id)
    }

    /// Insert an entry (the caller has checked that `ld_id` is free and reserved its budget).
    pub fn insert(&mut self, ld_id: Id, entry: Entry) {
        self.entries.insert(ld_id, entry);
    }

    /// Remove every entry and marker past its `expires_bucket` at `now`; returns the removed entries' `present`
    /// flags (the caller releases their reservations: the whole entry, or a marker's overhead).
    pub fn expire(&mut self, now: HourBucket) -> Vec<bool> {
        let gone: Vec<Id> = self
            .entries
            .iter()
            .filter(|(_, e)| now > e.expires)
            .map(|(id, _)| *id)
            .collect();
        gone.iter()
            .filter_map(|id| self.entries.remove(id))
            .map(|e| e.present())
            .collect()
    }

    /// Every entry, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&Id, &Entry)> {
        self.entries.iter()
    }

    /// The map (test RL-18: its hasher is `RandomState`).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn map_kat(&self) -> &IdMap<Entry> {
        &self.entries
    }
}
