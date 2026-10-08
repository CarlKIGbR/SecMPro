// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay: its keys, its limits and its state (spec §9.7; `docs/02` §5.1).
//!
//! [`Relay`] is shared by every connection (`Arc` in the server). Its state — `QueueStore`, `LinkDataStore`,
//! `MemoryBudget`, the drain flag — sits behind one lock, and every command runs under it from its first check to
//! its last store change, so commands are atomic with respect to each other (the one-time consumption of §9.4 has
//! exactly one winner). The keys are fixed for the process's life (rotation is the offline `rotate-static` and a
//! restart, `docs/05` §6); RAM only: a new `Relay` starts empty (§9.7 item 1).
//!
//! **Sweeper** (§9.7 item 3, OPEN-M5-05 B): expiry runs whenever the hour bucket has changed since the last sweep —
//! at the start of every command and on [`Relay::tick`] — so nothing expired is ever served and an idle relay still
//! releases memory.

use std::sync::{Mutex, MutexGuard};

use secmp_proto::wire::Id;

use crate::budget::{
    LINKDATA_OVERHEAD, LINKDATA_RESERVATION, MemoryBudget, Pool, QUEUE_RESERVATION,
};
use crate::clock::{HourBucket, Now};
use crate::config::Limits;
use crate::event::{Event, EventSink};
use crate::exec::{self, Abort, Command, Ctx, RelayPlan};
use crate::keys::KeyRing;
use crate::linkdata::LinkDataStore;
use crate::queue::QueueStore;
use crate::rate::TokenBucket;

/// The relay's mutable state.
pub struct State {
    /// The queues.
    pub queues: QueueStore,
    /// The link data.
    pub linkdata: LinkDataStore,
    /// The memory budget.
    pub budget: MemoryBudget,
    /// When the drain began (monotonic ms), if it has.
    draining_since: Option<u64>,
    /// The bucket of the last sweep.
    swept: Option<HourBucket>,
}

impl State {
    fn new(limits: &Limits) -> Self {
        Self {
            queues: QueueStore::new(),
            linkdata: LinkDataStore::new(),
            budget: MemoryBudget::new(limits.budget),
            draining_since: None,
            swept: None,
        }
    }

    /// Expire everything past its TTL at `now`, once per bucket; reservations are released.
    fn sweep_if_due(&mut self, now: HourBucket) {
        if self.swept == Some(now) {
            return;
        }
        self.swept = Some(now);
        let (gone, _) = self.queues.expire(now);
        for _ in &gone {
            self.budget.release(Pool::Queues, QUEUE_RESERVATION);
        }
        for present in self.linkdata.expire(now) {
            // a consumed marker kept only its overhead
            let bytes = if present {
                LINKDATA_RESERVATION
            } else {
                LINKDATA_OVERHEAD
            };
            self.budget.release(Pool::LinkData, bytes);
        }
    }
}

/// The relay.
pub struct Relay {
    keys: KeyRing,
    limits: Limits,
    state: Mutex<State>,
    hello: Mutex<Option<TokenBucket>>,
    events: Box<dyn EventSink>,
}

impl Relay {
    /// A relay with these keys and limits, empty (spec §9.7 item 1); events go to `events`.
    #[must_use]
    pub fn new(keys: KeyRing, limits: Limits, events: Box<dyn EventSink>, now: Now) -> Self {
        let hello = limits.hello_rate.map(|r| TokenBucket::new(r, now.mono_ms));
        events.emit(&Event::KeysLoaded {
            generations: keys.ring().len(),
        });
        Self {
            state: Mutex::new(State::new(&limits)),
            keys,
            limits,
            hello: Mutex::new(hello),
            events,
        }
    }

    /// The key generations.
    #[must_use]
    pub const fn keys(&self) -> &KeyRing {
        &self.keys
    }

    /// The limits in effect (test RL-23).
    #[must_use]
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The event sink.
    #[must_use]
    pub fn events(&self) -> &dyn EventSink {
        self.events.as_ref()
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, Abort> {
        // a poisoned lock (a panic under it, which the lints rule out) fails closed
        self.state.lock().map_err(|_| Abort)
    }

    /// Take a `HELLO` token of the listener's handshake rate (spec §9.7 item 7); `false`: over the rate.
    pub(crate) fn take_hello(&self, now: Now) -> bool {
        match self.hello.lock() {
            Ok(mut b) => b.as_mut().is_none_or(|b| b.take(now.mono_ms)),
            Err(_) => false,
        }
    }

    /// Run one command atomically (spec §9.3–§9.7).
    pub(crate) fn execute(
        &self,
        sess_id: &Id,
        cmd_seq: u32,
        now: Now,
        command: Command,
    ) -> Result<RelayPlan, Abort> {
        let access_key = self.keys.access_key().map_err(|_| Abort)?;
        let mut st = self.lock()?;
        st.sweep_if_due(now.bucket());
        let ctx = Ctx {
            sess_id,
            cmd_seq,
            now: now.bucket(),
            access_key,
            draining: st.draining_since.is_some(),
        };
        exec::run(&mut st, &ctx, command)
    }

    /// Expire what is due (the sweeper's periodic call).
    pub fn tick(&self, now: Now) {
        if let Ok(mut st) = self.lock() {
            st.sweep_if_due(now.bucket());
        }
    }

    /// Begin the graceful drain (OPEN-M5-09 A): new connections are refused, `QUEUE_NEW` and `LINK_PUT` answer
    /// ERR 2, everything else is served; [`Relay::drain_finished`] after `drain_secs`.
    pub fn start_drain(&self, now: Now) {
        if let Ok(mut st) = self.lock()
            && st.draining_since.is_none()
        {
            st.draining_since = Some(now.mono_ms);
            self.events.emit(&Event::DrainStarted);
        }
    }

    /// Whether the relay is draining.
    #[must_use]
    pub fn draining(&self) -> bool {
        self.lock().is_ok_and(|st| st.draining_since.is_some())
    }

    /// Whether the drain has lasted `drain_secs`: the process exits.
    #[must_use]
    pub fn drain_finished(&self, now: Now) -> bool {
        let wait = self.limits.drain_secs.saturating_mul(1000);
        self.lock().is_ok_and(|st| {
            st.draining_since
                .is_some_and(|t| now.mono_ms.saturating_sub(t) >= wait)
        })
    }

    /// Whether the listener accepts a new connection (not while draining).
    #[must_use]
    pub fn accepts_connections(&self) -> bool {
        !self.draining()
    }
}

/// The stores as the `link` vectors list them (`vectors/SCHEMA-4.11-link.md` `store_post`; feature `kat`).
#[cfg(feature = "kat")]
pub mod kat {
    use secmp_proto::wire::Id;

    /// One queue of `store_post.queues`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct QueueSnapshot {
        /// `rid`.
        pub rid: Id,
        /// `sid`.
        pub sid: Id,
        /// The `cell_id`s in queue order.
        pub cell_ids: Vec<u64>,
        /// `next_cell_id`.
        pub next_cell_id: u64,
    }

    /// One entry of `store_post.linkdata`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LinkDataSnapshot {
        /// `ld_id`.
        pub ld_id: Id,
        /// `one_time`.
        pub one_time: bool,
        /// `expires_bucket`.
        pub expires_bucket: u32,
        /// The blob is stored.
        pub present: bool,
        /// A consumption marker.
        pub consumed: bool,
    }

    /// `store_post`: queues ascending by `rid`, link data ascending by `ld_id`.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct StoreSnapshot {
        /// The queues.
        pub queues: Vec<QueueSnapshot>,
        /// The link data.
        pub linkdata: Vec<LinkDataSnapshot>,
    }
}

#[cfg(feature = "kat")]
impl Relay {
    /// `store_post` (vectors).
    #[must_use]
    pub fn snapshot_kat(&self) -> kat::StoreSnapshot {
        let Ok(st) = self.lock() else {
            return kat::StoreSnapshot::default();
        };
        let mut queues: Vec<kat::QueueSnapshot> = st
            .queues
            .iter()
            .map(|(rid, q)| kat::QueueSnapshot {
                rid: *rid,
                sid: q.sid,
                cell_ids: q.cells.iter().map(|s| s.cell_id).collect(),
                next_cell_id: q.cells.next_cell_id(),
            })
            .collect();
        queues.sort_by_key(|q| q.rid);
        let mut linkdata: Vec<kat::LinkDataSnapshot> = st
            .linkdata
            .iter()
            .map(|(ld_id, e)| kat::LinkDataSnapshot {
                ld_id: *ld_id,
                one_time: e.one_time,
                expires_bucket: e.expires.0,
                present: e.present(),
                consumed: e.consumed(),
            })
            .collect();
        linkdata.sort_by_key(|e| e.ld_id);
        kat::StoreSnapshot { queues, linkdata }
    }

    /// A digest of everything the stores hold (TEST-SPEC "store unchanged"): every queue's rid, sid, keys, cells
    /// with their ids, arrivals and buckets, `next_cell_id`, buckets; every link-data entry and marker with its
    /// blob; the budget counters; the arrival counter.
    #[must_use]
    pub fn store_digest_kat(&self) -> [u8; 32] {
        let Ok(st) = self.lock() else {
            return [0; 32];
        };
        let mut out: Vec<u8> = Vec::new();
        let mut rids: Vec<&Id> = st.queues.iter().map(|(rid, _)| rid).collect();
        rids.sort();
        for rid in rids {
            let Some(q) = st.queues.get(rid) else {
                continue;
            };
            out.extend_from_slice(rid);
            out.extend_from_slice(&q.sid);
            out.extend_from_slice(q.recv_pk.as_bytes());
            out.extend_from_slice(q.send_pk.as_bytes());
            out.extend_from_slice(&q.created.0.to_be_bytes());
            out.extend_from_slice(
                &q.last_fetch
                    .map_or(u64::MAX, |b| u64::from(b.0))
                    .to_be_bytes(),
            );
            out.extend_from_slice(&q.cells.next_cell_id().to_be_bytes());
            for s in q.cells.iter() {
                out.extend_from_slice(&s.cell_id.to_be_bytes());
                out.extend_from_slice(&s.arrival.to_be_bytes());
                out.extend_from_slice(&s.bucket.0.to_be_bytes());
                out.extend_from_slice(s.buf.as_bytes());
            }
        }
        let mut lds: Vec<&Id> = st.linkdata.iter().map(|(id, _)| id).collect();
        lds.sort();
        for ld_id in lds {
            let Some(e) = st.linkdata.get(ld_id) else {
                continue;
            };
            out.extend_from_slice(ld_id);
            out.push(u8::from(e.one_time));
            out.extend_from_slice(&e.expires.0.to_be_bytes());
            out.extend_from_slice(e.owner_pk.as_bytes());
            out.push(u8::from(e.present()));
            if let Some(b) = &e.blob {
                out.extend_from_slice(b.as_bytes());
            }
        }
        out.extend_from_slice(&st.budget.used(Pool::Queues).to_be_bytes());
        out.extend_from_slice(&st.budget.used(Pool::LinkData).to_be_bytes());
        out.extend_from_slice(&st.queues.next_arrival().to_be_bytes());
        secmp_crypto::sha256(&[&out])
    }

    /// The bytes reserved in each pool (queues, link data).
    #[must_use]
    pub fn budget_used_kat(&self) -> (u64, u64) {
        self.lock().map_or((0, 0), |st| {
            (st.budget.used(Pool::Queues), st.budget.used(Pool::LinkData))
        })
    }

    /// Run `f` on the state (tests: the hasher types of RL-18, the live buffers of RL-10).
    pub fn with_state_kat<T>(&self, f: impl FnOnce(&State) -> T) -> Option<T> {
        self.lock().ok().map(|st| f(&st))
    }
}
