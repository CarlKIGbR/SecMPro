// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`StoreOutbox`]: the outbox of one contact backed by the profile store (spec §10.4 `docs/03:682`; `docs/02:95`). The
//! scheduler never sees it (OB-07, PC-12): it reaches the scheduler only as an [`Outbox`].
//!
//! It is the in-memory outbox ([`MemOutbox`], the model of the scheduler's tests, P-03 of M6) with every state change
//! written through to the `outbox` table: a new message is inserted, a changed state (and its `cell_id`, its first
//! relayed time) updated. What is in flight — a message taken but not yet relayed — is not durable: after a restart it
//! is queued again (`Outbox::restart`, spec §10.4). A view-once message stays in memory only (CS-3.4). A write the
//! store refuses is retried with the next change and counted ([`StoreOutbox::write_errors`]); the outbox is not the
//! ratchet state (persist-before-send is the [`crate::persist::StorePersist`]'s). A receipt's `Delivered` is written
//! in its own transaction after the receive commit (F9b): a refused write or a crash in between loses it (the
//! message stays `Relayed`); Phase B moves it into the receive transaction (SE-21).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use secmp_proto::wire::cell::AppKind;
use secmp_store::outbox::{OutboxRow, state};

use crate::persist::SharedStore;
use crate::scheduler::outbox::{MemOutbox, MsgId, MsgState, OutMessage, Outbox, PersistError};

/// A message state as stored: the state code and the `cell_id`.
const fn code_of(s: MsgState) -> (i64, Option<u64>) {
    match s {
        MsgState::Queued => (state::QUEUED, None),
        MsgState::Relayed(cell) => (state::RELAYED, Some(cell)),
        MsgState::Delivered => (state::DELIVERED, None),
        MsgState::Failed => (state::FAILED, None),
    }
}

/// The message state of a stored row.
fn state_of(code: i64, cell: Option<u64>) -> Result<MsgState, PersistError> {
    match (code, cell) {
        (state::QUEUED, _) => Ok(MsgState::Queued),
        (state::RELAYED, Some(c)) => Ok(MsgState::Relayed(c)),
        (state::DELIVERED, _) => Ok(MsgState::Delivered),
        (state::FAILED, _) => Ok(MsgState::Failed),
        _ => Err(PersistError),
    }
}

/// What the store holds of a message: its state and when it was first relayed.
type Synced = (MsgState, Option<u64>);

/// The store-backed outbox of one contact (see the module documentation).
pub struct StoreOutbox {
    mem: MemOutbox,
    store: SharedStore,
    contact: i64,
    /// What the store holds, per message.
    synced: BTreeMap<MsgId, Synced>,
    /// The messages kept in memory only (view-once).
    memory_only: BTreeSet<MsgId>,
    next_seq: i64,
    write_errors: u64,
}

impl StoreOutbox {
    /// The outbox of `contact` as the store holds it (nothing in flight).
    ///
    /// # Errors
    /// [`PersistError`] if the store cannot be read or holds a row that is not an outbox entry.
    pub fn open(store: SharedStore, contact: i64) -> Result<Self, PersistError> {
        let rows = {
            let s = store.lock().map_err(|_| PersistError)?;
            s.outbox_rows(contact).map_err(|_| PersistError)?
        };
        let mut synced = BTreeMap::new();
        let mut entries = Vec::with_capacity(rows.len());
        let mut next_seq = 0_i64;
        for row in rows {
            let kind = AppKind::ALL
                .into_iter()
                .find(|k| k.byte() == row.kind)
                .ok_or(PersistError)?;
            let st = state_of(row.state, row.cell_id)?;
            synced.insert(row.msg_id, (st, row.first_relayed_ms));
            next_seq = next_seq.max(row.seq.checked_add(1).ok_or(PersistError)?);
            entries.push((
                OutMessage {
                    msg_id: row.msg_id,
                    kind,
                    expire_after: row.expire_after,
                    payload: row.payload,
                },
                row.queued_ms,
                row.first_relayed_ms,
                st,
            ));
        }
        Ok(Self {
            mem: MemOutbox::from_entries(entries),
            store,
            contact,
            synced,
            memory_only: BTreeSet::new(),
            next_seq,
            write_errors: 0,
        })
    }

    /// Writes the store refused so far (each retried with the next change).
    #[must_use]
    pub const fn write_errors(&self) -> u64 {
        self.write_errors
    }

    /// The store handle.
    #[must_use]
    pub fn store(&self) -> SharedStore {
        Arc::clone(&self.store)
    }

    /// Write every change of the in-memory outbox to the store.
    fn sync(&mut self) {
        let Ok(mut s) = self.store.lock() else {
            self.write_errors = self.write_errors.saturating_add(1);
            return;
        };
        for (message, queued_at, first, st) in self.mem.entries() {
            let id = message.msg_id;
            if self.memory_only.contains(&id) {
                continue;
            }
            let written = match self.synced.get(&id) {
                Some(have) if *have == (st, first) => continue,
                Some(_) => {
                    let (code, cell) = code_of(st);
                    s.outbox_set_state(&id, code, cell, first)
                }
                None => {
                    let row = OutboxRow {
                        msg_id: id,
                        seq: self.next_seq,
                        kind: message.kind.byte(),
                        expire_after: message.expire_after,
                        payload: secmp_crypto::Zeroizing::new(message.payload.to_vec()),
                        queued_ms: queued_at,
                        first_relayed_ms: None,
                        state: state::QUEUED,
                        cell_id: None,
                    };
                    match s.outbox_insert(self.contact, &row) {
                        Ok(()) => {
                            self.next_seq = self.next_seq.saturating_add(1);
                            // a message changed before its first sync (never: `enqueue` syncs at once) is updated next time
                            self.synced.insert(id, (MsgState::Queued, None));
                            continue;
                        }
                        Err(secmp_store::Error::Unsupported) => {
                            // a view-once stays in memory; its id is recorded so a restart reports it lost (V1-F10)
                            if s.queue_view_once(id, &message.payload).is_err() {
                                self.write_errors = self.write_errors.saturating_add(1);
                            }
                            self.memory_only.insert(id);
                            continue;
                        }
                        Err(e) => Err(e),
                    }
                }
            };
            match written {
                Ok(()) => {
                    self.synced.insert(id, (st, first));
                }
                Err(_) => self.write_errors = self.write_errors.saturating_add(1),
            }
        }
    }
}

impl Outbox for StoreOutbox {
    fn enqueue(&mut self, message: OutMessage, now_ms: u64) {
        self.mem.enqueue(message, now_ms);
        self.sync();
    }

    fn state(&self, id: &MsgId) -> Option<MsgState> {
        self.mem.state(id)
    }

    fn take_next(&mut self) -> Option<OutMessage> {
        // taken is in flight, not durable
        self.mem.take_next()
    }

    fn relayed(&mut self, id: &MsgId, cell_id: u64) {
        self.mem.relayed(id, cell_id);
        self.sync();
    }

    fn requeue(&mut self, id: &MsgId) {
        self.mem.requeue(id);
        self.sync();
    }

    fn requeue_unreceipted(&mut self) {
        self.mem.requeue_unreceipted();
        self.sync();
    }

    fn delivered(&mut self, id: &MsgId) {
        self.mem.delivered(id);
        self.sync();
    }

    fn restart(&mut self) {
        self.mem.restart();
    }

    fn expire(&mut self, now_ms: u64) {
        self.mem.expire(now_ms);
        self.sync();
    }

    fn waiting(&self) -> usize {
        self.mem.waiting()
    }
}

#[cfg(test)]
mod tests {
    // The bodies need the `kat` test key, so each test is gated inside (see `persist::tests`).

    #[cfg(feature = "kat")]
    use super::*;
    #[cfg(feature = "kat")]
    use crate::scheduler::outbox::FAIL_AFTER_MS;

    #[cfg(feature = "kat")]
    type R = Result<(), String>;

    /// A text message `n`.
    #[cfg(feature = "kat")]
    fn message(n: u8) -> OutMessage {
        OutMessage {
            msg_id: [n; 16],
            kind: AppKind::Text,
            expire_after: 0,
            payload: secmp_crypto::Zeroizing::new(vec![n; 8]),
        }
    }

    /// The profile store in `dir`, opened with the test key.
    #[cfg(feature = "kat")]
    fn shared(dir: &std::path::Path) -> Result<SharedStore, String> {
        secmp_store::Store::open(dir, &secmp_store::kat::TestKey::db_key())
            .map(|s| Arc::new(std::sync::Mutex::new(s)))
            .map_err(|e| format!("open: {e:?}"))
    }

    /// PC-10 (§10.4 `docs/03:682`; `Outbox::restart`): queued 3, relayed 2, delivered 1, in flight 1; after a restart
    /// (the process reopens the store) 3 + 1 are `Queued` — the one in flight too — 2 `Relayed` (their `cell_id`s) and
    /// 1 `Delivered`, and the queued ones are sent in their enqueue order.
    #[test]
    #[cfg(feature = "kat")]
    fn store_outbox_survives_restart() -> R {
        let dir = secmp_store::kat::TempDir::new("pc10").map_err(|e| e.to_string())?;
        let ids: Vec<MsgId> = (1..=7_u8).map(|n| [n; 16]).collect();
        {
            let store = shared(dir.path())?;
            let mut o = StoreOutbox::open(store, 4).map_err(|_| "open outbox")?;
            for n in 1..=7_u8 {
                o.enqueue(message(n), u64::from(n));
            }
            // 1, 2 relayed; 3 relayed and delivered; 4 in flight; 5, 6, 7 queued
            for (i, cell) in [(0_usize, 40_u64), (1, 41), (2, 42)] {
                let taken = o.take_next().ok_or("take")?;
                assert_eq!(Some(&taken.msg_id), ids.get(i));
                o.relayed(&taken.msg_id, cell);
            }
            o.delivered(ids.get(2).ok_or("id")?);
            let in_flight = o.take_next().ok_or("take")?;
            assert_eq!(Some(&in_flight.msg_id), ids.get(3));
            assert_eq!(o.waiting(), 3);
            assert_eq!(o.write_errors(), 0);
        }
        let store = shared(dir.path())?;
        let mut o = StoreOutbox::open(store, 4).map_err(|_| "reopen outbox")?;
        let states: Vec<Option<MsgState>> = ids.iter().map(|id| o.state(id)).collect();
        assert_eq!(
            states,
            vec![
                Some(MsgState::Relayed(40)),
                Some(MsgState::Relayed(41)),
                Some(MsgState::Delivered),
                Some(MsgState::Queued),
                Some(MsgState::Queued),
                Some(MsgState::Queued),
                Some(MsgState::Queued),
            ]
        );
        assert_eq!(o.waiting(), 4, "3 + 1 queued");
        for want in ids.get(3..).ok_or("ids")? {
            assert_eq!(&o.take_next().ok_or("take")?.msg_id, want, "enqueue order");
        }
        Ok(())
    }

    /// PC-11 (§10.4; `FAIL_AFTER_MS`): a message queued at 0 and never relayed is `Queued` at 30 d − 1 ms and `Failed` at
    /// 30 d, also after a restart; a message relayed once and requeued is not failed, also after a restart.
    #[test]
    #[cfg(feature = "kat")]
    fn never_relayed_30_days_fails() -> R {
        let dir = secmp_store::kat::TempDir::new("pc11").map_err(|e| e.to_string())?;
        let (never, once) = ([1_u8; 16], [2_u8; 16]);
        {
            let store = shared(dir.path())?;
            let mut o = StoreOutbox::open(store, 5).map_err(|_| "open outbox")?;
            o.enqueue(message(1), 0);
            o.enqueue(message(2), 0);
            // 1 is taken and comes back without a relay; 2 is relayed once and requeued
            let first = o.take_next().ok_or("take")?;
            assert_eq!(first.msg_id, never);
            o.requeue(&never);
            assert_eq!(o.take_next().ok_or("take")?.msg_id, never);
            let second = o.take_next().ok_or("take")?;
            assert_eq!(second.msg_id, once);
            o.relayed(&once, 7);
            o.requeue(&once);
            o.expire(FAIL_AFTER_MS.saturating_sub(1));
            assert_eq!(o.state(&never), Some(MsgState::Queued), "30 d − 1 ms");
            o.expire(FAIL_AFTER_MS);
            assert_eq!(o.state(&never), Some(MsgState::Failed), "30 d");
            assert_eq!(
                o.state(&once),
                Some(MsgState::Queued),
                "relayed once: not failed"
            );
        }
        let store = shared(dir.path())?;
        let mut o = StoreOutbox::open(store, 5).map_err(|_| "reopen outbox")?;
        assert_eq!(o.state(&never), Some(MsgState::Failed), "after a restart");
        o.expire(FAIL_AFTER_MS.saturating_mul(2));
        assert_eq!(
            o.state(&once),
            Some(MsgState::Queued),
            "its first relay survived the restart"
        );
        Ok(())
    }

    /// V1-F10 (PC-10, kind 3): a view-once queued through the store outbox is never an outbox row; after a restart it
    /// has no state and the store reports it lost, once.
    #[test]
    #[cfg(feature = "kat")]
    fn store_outbox_view_once_reported_lost() -> R {
        let dir = secmp_store::kat::TempDir::new("pc10-vo").map_err(|e| e.to_string())?;
        let id = [0x33_u8; 16];
        {
            let store = shared(dir.path())?;
            let mut o = StoreOutbox::open(store, 4).map_err(|_| "open outbox")?;
            let mut vo = message(0x33);
            vo.kind = AppKind::ViewOnceText;
            o.enqueue(vo, 1);
            assert_eq!(o.state(&id), Some(MsgState::Queued), "held in memory");
            assert_eq!(o.write_errors(), 0);
        }
        let store = shared(dir.path())?;
        let o = StoreOutbox::open(Arc::clone(&store), 4).map_err(|_| "reopen outbox")?;
        assert_eq!(o.state(&id), None, "no outbox state for the view-once");
        let mut s = store.lock().map_err(|_| "lock")?;
        assert_eq!(
            s.take_view_once_lost().map_err(|e| format!("{e:?}"))?,
            vec![id]
        );
        assert_eq!(
            s.take_view_once_lost().map_err(|e| format!("{e:?}"))?,
            Vec::<MsgId>::new()
        );
        Ok(())
    }

    /// V2-1 (killer, `outbox.rs:74`): a reopened outbox restores every field of a queued message — its kind among
    /// them, read back by its code.
    #[test]
    #[cfg(feature = "kat")]
    fn store_outbox_restores_every_field() -> R {
        let dir = secmp_store::kat::TempDir::new("outbox-fields").map_err(|e| e.to_string())?;
        {
            let mut o = StoreOutbox::open(shared(dir.path())?, 4).map_err(|_| "open")?;
            let mut m = message(9);
            m.kind = AppKind::Edit;
            m.expire_after = 77;
            o.enqueue(m, 5);
        }
        let mut o = StoreOutbox::open(shared(dir.path())?, 4).map_err(|_| "reopen")?;
        let m = o.take_next().ok_or("take")?;
        assert_eq!(m.msg_id, [9; 16]);
        assert_eq!(m.kind.byte(), AppKind::Edit.byte());
        assert_eq!(m.expire_after, 77);
        assert_eq!(m.payload.as_slice(), [9_u8; 8].as_slice());
        Ok(())
    }

    /// V2-1 (killer, `outbox.rs:105`): a write the store refuses is counted.
    #[test]
    #[cfg(feature = "kat")]
    fn store_outbox_counts_refused_writes() -> R {
        let dir = secmp_store::kat::TempDir::new("outbox-refused").map_err(|e| e.to_string())?;
        let mut o = StoreOutbox::open(shared(dir.path())?, 4).map_err(|_| "open")?;
        secmp_store::kat::fail_at(secmp_store::kat::FailAt(1));
        o.enqueue(message(1), 1);
        assert_eq!(o.write_errors(), 1);
        Ok(())
    }

    /// V2-1 (killer, `outbox.rs:126`): a change writes only the rows that changed — an expiry that fails nothing writes
    /// nothing.
    #[test]
    #[cfg(feature = "kat")]
    fn store_outbox_writes_only_changes() -> R {
        let dir = secmp_store::kat::TempDir::new("outbox-changes").map_err(|e| e.to_string())?;
        let mut o = StoreOutbox::open(shared(dir.path())?, 4).map_err(|_| "open")?;
        for n in 1..=3_u8 {
            o.enqueue(message(n), 0);
        }
        let before = secmp_store::kat::store_txn_commits();
        o.expire(1_000);
        assert_eq!(
            secmp_store::kat::store_txn_commits(),
            before,
            "no state changed, no write"
        );
        let taken = o.take_next().ok_or("take")?;
        o.relayed(&taken.msg_id, 9);
        assert_eq!(
            secmp_store::kat::store_txn_commits(),
            before + 1,
            "one row changed, one write"
        );
        Ok(())
    }

    /// V2-1 (killer, `outbox.rs:208`): a restart queues the message that was in flight again.
    #[test]
    #[cfg(feature = "kat")]
    fn store_outbox_restart_requeues_in_flight() -> R {
        let dir = secmp_store::kat::TempDir::new("outbox-restart").map_err(|e| e.to_string())?;
        let mut o = StoreOutbox::open(shared(dir.path())?, 4).map_err(|_| "open")?;
        o.enqueue(message(1), 0);
        let _in_flight = o.take_next().ok_or("take")?;
        assert_eq!(o.waiting(), 0);
        o.restart();
        assert_eq!(o.waiting(), 1);
        assert_eq!(o.take_next().ok_or("take again")?.msg_id, [1; 16]);
        Ok(())
    }
}
