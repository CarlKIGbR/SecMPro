// SPDX-License-Identifier: AGPL-3.0-or-later
//! `QueueStore` (spec §9.1, §9.3, §9.5): the queues by derived `rid`, with the `sid` index.
//!
//! A queue holds its recipient and sender keys, its cells ([`Cells`], capacity `QUEUE_CAPACITY`), its creation
//! bucket and the bucket of its last non-error `FETCH` (spec §9.1 state list; hour buckets only). The ids are derived
//! from the keys (`rid` from `recv_pk`, `sid` from both), so a re-created queue has the same ids (§9.1, ADR-025).
//! The maps are keyed by values a client chooses and use `std`'s randomly keyed `RandomState` (`docs/06` §2,
//! hash flooding; test RL-18). This module holds the data; the command semantics are in [`crate::exec`].

use std::collections::HashMap;
use std::collections::hash_map::RandomState;

use secmp_proto::keys::Ed25519Pk;
use secmp_proto::link::{CELL_TTL_HOURS, QUEUE_CAPACITY, QUEUE_IDLE_TTL_HOURS};
use secmp_proto::wire::Id;

use crate::buf::CellBuf;
use crate::cells::Cells;
use crate::clock::HourBucket;

/// A map keyed by a client-chosen or client-derived id (`rid`, `sid`, `ld_id`): `std`'s `RandomState`.
pub type IdMap<V> = HashMap<Id, V, RandomState>;

/// One queue.
pub struct Queue {
    /// The recipient key (`QUEUE_NEW`, `FETCH`, `FETCH_MULTI`, `QUEUE_DEL` signatures).
    pub recv_pk: Ed25519Pk,
    /// The sender key (`SEND` signatures).
    pub send_pk: Ed25519Pk,
    /// The derived sender id.
    pub sid: Id,
    /// The cells.
    pub cells: Cells<CellBuf, QUEUE_CAPACITY>,
    /// The creation bucket.
    pub created: HourBucket,
    /// The bucket of the last non-error `FETCH` / `FETCH_MULTI` entry.
    pub last_fetch: Option<HourBucket>,
}

impl Queue {
    /// The idle anchor of `QUEUE_IDLE_TTL` (spec §4.2, OPEN-M5-05 B): the last non-error fetch, else the creation.
    #[must_use]
    pub fn idle_anchor(&self) -> HourBucket {
        self.last_fetch.unwrap_or(self.created)
    }
}

/// The queues.
pub struct QueueStore {
    queues: IdMap<Queue>,
    sids: IdMap<Id>,
    /// The next relay-global arrival number (spec §9.1 `arrival`); from 1.
    next_arrival: u64,
}

impl Default for QueueStore {
    fn default() -> Self {
        Self::new()
    }
}

/// What expiry removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Expired {
    /// Cells past `CELL_TTL`.
    pub cells: usize,
    /// Queues past `QUEUE_IDLE_TTL` (their cells included).
    pub queues: usize,
}

impl QueueStore {
    /// No queues.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queues: HashMap::with_hasher(RandomState::new()),
            sids: HashMap::with_hasher(RandomState::new()),
            next_arrival: 1,
        }
    }

    /// The queue `rid`.
    #[must_use]
    pub fn get(&self, rid: &Id) -> Option<&Queue> {
        self.queues.get(rid)
    }

    /// The queue `rid`, mutable.
    pub fn get_mut(&mut self, rid: &Id) -> Option<&mut Queue> {
        self.queues.get_mut(rid)
    }

    /// The `rid` of the queue with sender id `sid`.
    #[must_use]
    pub fn rid_of_sid(&self, sid: &Id) -> Option<Id> {
        self.sids.get(sid).copied()
    }

    /// Whether `sid` names a queue.
    #[must_use]
    pub fn has_sid(&self, sid: &Id) -> bool {
        self.sids.contains_key(sid)
    }

    /// Insert a new queue (the caller has checked that neither id exists and has reserved its budget).
    pub fn insert(
        &mut self,
        rid: Id,
        sid: Id,
        recv_pk: Ed25519Pk,
        send_pk: Ed25519Pk,
        now: HourBucket,
    ) {
        self.sids.insert(sid, rid);
        self.queues.insert(
            rid,
            Queue {
                recv_pk,
                send_pk,
                sid,
                cells: Cells::new(),
                created: now,
                last_fetch: None,
            },
        );
    }

    /// Remove the queue `rid` with its cells (wiped as they drop); whether it existed.
    pub fn remove(&mut self, rid: &Id) -> bool {
        match self.queues.remove(rid) {
            Some(q) => {
                self.sids.remove(&q.sid);
                true
            }
            None => false,
        }
    }

    /// The arrival number the next stored cell gets.
    #[must_use]
    pub const fn next_arrival(&self) -> u64 {
        self.next_arrival
    }

    /// Take the next arrival number (`checked_add`: `None` once exhausted, a local abort).
    pub fn take_arrival(&mut self) -> Option<u64> {
        let a = self.next_arrival;
        self.next_arrival = a.checked_add(1)?;
        Some(a)
    }

    /// Expire cells past `CELL_TTL` and queues past `QUEUE_IDLE_TTL` at `now` (spec §9.7 item 3, OPEN-M5-05 B);
    /// returns the `rid`s of the removed queues with the counts (the caller releases their reservations).
    pub fn expire(&mut self, now: HourBucket) -> (Vec<Id>, Expired) {
        let mut out = Expired::default();
        let idle: Vec<Id> = self
            .queues
            .iter()
            .filter(|(_, q)| q.idle_anchor().expired_at(QUEUE_IDLE_TTL_HOURS, now))
            .map(|(rid, _)| *rid)
            .collect();
        for rid in &idle {
            if self.remove(rid) {
                out.queues = out.queues.saturating_add(1);
            }
        }
        for q in self.queues.values_mut() {
            out.cells = out
                .cells
                .saturating_add(q.cells.expire(CELL_TTL_HOURS, now));
        }
        (idle, out)
    }

    /// Every queue, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&Id, &Queue)> {
        self.queues.iter()
    }

    /// The maps (test RL-18: their hasher is `RandomState`).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn maps_kat(&self) -> (&IdMap<Queue>, &IdMap<Id>) {
        (&self.queues, &self.sids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Option<Ed25519Pk> {
        let sk = secmp_crypto::Ed25519SigningKey::from_seed(&[b; 32]).ok()?;
        Ed25519Pk::from_bytes(sk.verifying_key().as_bytes()).ok()
    }

    #[test]
    fn ids_index_the_queue_until_it_is_removed() -> Result<(), &'static str> {
        let recv = key(1).ok_or("key")?;
        let send = key(2).ok_or("key")?;
        let mut s = QueueStore::new();
        let (rid, sid) = ([1; 16], [2; 16]);
        assert!(!s.has_sid(&sid) && s.rid_of_sid(&sid).is_none() && s.get(&rid).is_none());
        s.insert(rid, sid, recv, send, HourBucket(5));
        assert!(s.has_sid(&sid));
        assert_eq!(s.rid_of_sid(&sid), Some(rid));
        assert_eq!(s.get(&rid).map(|q| q.sid), Some(sid));
        assert!(!s.has_sid(&rid));
        assert!(s.remove(&rid));
        assert!(!s.has_sid(&sid) && s.get(&rid).is_none());
        assert!(!s.remove(&rid));
        Ok(())
    }

    #[test]
    fn arrivals_count_from_one() {
        let mut s = QueueStore::new();
        assert_eq!(s.next_arrival(), 1);
        assert_eq!(s.take_arrival(), Some(1));
        assert_eq!(s.take_arrival(), Some(2));
        assert_eq!(s.next_arrival(), 3);
        s.next_arrival = u64::MAX;
        assert_eq!(s.take_arrival(), None);
        assert_eq!(s.next_arrival(), u64::MAX);
    }
}
