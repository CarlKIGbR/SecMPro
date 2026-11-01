// SPDX-License-Identifier: AGPL-3.0-or-later
//! The outbox (spec §9.5, §10.4) behind a trait, and `Persist`, the durability boundary of the ratchet states. M6
//! implements both in memory ([`MemOutbox`], [`MemPersist`]); the encrypted store of M7 implements the same traits
//! (OB-07: the scheduler sees nothing else).
//!
//! **States (§10.4).** A message is *queued* locally, *relayed* when `OK_SEND` arrived and the cell was not later
//! reported evicted, and *delivered* when an E2E `Receipt{delivered}` arrives. A message **never relayed** within 30
//! days is *failed* (spec §10.4: "Messages never relayed within 30 days are surfaced as failed"); one that was relayed
//! once and went back to queued (eviction, lost queue) is not, however long it waits to be sent again. An evicted real cell, a lost queue (`ERR_NOQUEUE`) or a link that died before the answer put the message
//! back to *queued*: it is re-encrypted under a new key and sent again, the receiver deduplicates by `msg_id`.

use secmp_crypto::Zeroizing;
use secmp_proto::tr::RatchetParts;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::AppKind;

/// A message id (spec §7.6): the receiver's dedup key.
pub type MsgId = Id;

/// 30 days in milliseconds (spec §10.4).
pub const FAIL_AFTER_MS: u64 = 2_592_000_000;

/// What the user wants sent: one application message.
pub struct OutMessage {
    /// Its id.
    pub msg_id: MsgId,
    /// Its kind.
    pub kind: AppKind,
    /// Seconds until it expires at the receiver (0: never).
    pub expire_after: u32,
    /// The payload, zeroized on drop.
    pub payload: Zeroizing<Vec<u8>>,
}

/// The delivery state of a message (spec §10.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgState {
    /// Waiting (or being sent: not yet relayed).
    Queued,
    /// `OK_SEND` returned this `cell_id` (of its last cell) and it was not reported evicted.
    Relayed(u64),
    /// A `Receipt{delivered}` arrived.
    Delivered,
    /// Never relayed within 30 days.
    Failed,
}

/// The queue of what the user sent (see the module documentation).
pub trait Outbox {
    /// Queue a message at `now_ms`.
    fn enqueue(&mut self, message: OutMessage, now_ms: u64);

    /// The state of a message.
    fn state(&self, id: &MsgId) -> Option<MsgState>;

    /// The next message to send, in enqueue order; it stays [`MsgState::Queued`] until [`Outbox::relayed`].
    fn take_next(&mut self) -> Option<OutMessage>;

    /// The last cell of the message was stored under `cell_id`.
    fn relayed(&mut self, id: &MsgId, cell_id: u64);

    /// Back to queued (evicted, lost, or the link went down before the answer).
    fn requeue(&mut self, id: &MsgId);

    /// Every relayed message that is not yet delivered goes back to queued (the queue was lost, spec §10.4).
    fn requeue_unreceipted(&mut self);

    /// A `Receipt{delivered}` for the message.
    fn delivered(&mut self, id: &MsgId);

    /// The process restarted: a message that was being sent (taken, no `OK_SEND` yet) is waiting again — the outbox
    /// survives restarts, what was in flight does not (spec §10.4).
    fn restart(&mut self);

    /// Fail the messages never relayed within 30 days of being queued (a message that was relayed once and requeued
    /// is not failed).
    fn expire(&mut self, now_ms: u64);

    /// How many messages wait to be sent (queued and not being sent).
    fn waiting(&self) -> usize;
}

struct Entry {
    message: OutMessage,
    queued_at: u64,
    /// When `OK_SEND` first reported the message relayed (the outbox's last known time then); `requeue` and
    /// `requeue_unreceipted` keep it. A message with `None` has never been relayed.
    first_relayed_at: Option<u64>,
    state: MsgState,
    taken: bool,
}

/// The in-memory outbox.
#[derive(Default)]
pub struct MemOutbox {
    entries: Vec<Entry>,
    /// The latest time the outbox was told (`enqueue`, `expire`): `relayed` carries no clock of its own.
    clock: u64,
}

impl MemOutbox {
    /// An empty outbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            clock: 0,
        }
    }

    /// The messages and their states, in enqueue order.
    #[must_use]
    pub fn states(&self) -> Vec<(MsgId, MsgState)> {
        self.entries
            .iter()
            .map(|e| (e.message.msg_id, e.state))
            .collect()
    }

    /// The entries in enqueue order as a durable outbox keeps them: the message, when it was queued, when it was first
    /// relayed, its state (what is in flight is not durable, spec §10.4).
    pub fn entries(&self) -> impl Iterator<Item = (&OutMessage, u64, Option<u64>, MsgState)> {
        self.entries
            .iter()
            .map(|e| (&e.message, e.queued_at, e.first_relayed_at, e.state))
    }

    /// The outbox of a restarted process from durable entries ([`MemOutbox::entries`], enqueue order): nothing in
    /// flight.
    #[must_use]
    pub fn from_entries(entries: Vec<(OutMessage, u64, Option<u64>, MsgState)>) -> Self {
        let clock = entries
            .iter()
            .map(|(_, queued, first, _)| first.unwrap_or(*queued).max(*queued))
            .max()
            .unwrap_or(0);
        Self {
            entries: entries
                .into_iter()
                .map(|(message, queued_at, first_relayed_at, state)| Entry {
                    message,
                    queued_at,
                    first_relayed_at,
                    state,
                    taken: false,
                })
                .collect(),
            clock,
        }
    }

    fn entry(&mut self, id: &MsgId) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.message.msg_id == *id)
    }
}

impl Outbox for MemOutbox {
    fn enqueue(&mut self, message: OutMessage, now_ms: u64) {
        self.clock = self.clock.max(now_ms);
        self.entries.push(Entry {
            message,
            queued_at: now_ms,
            first_relayed_at: None,
            state: MsgState::Queued,
            taken: false,
        });
    }

    fn state(&self, id: &MsgId) -> Option<MsgState> {
        self.entries
            .iter()
            .find(|e| e.message.msg_id == *id)
            .map(|e| e.state)
    }

    fn take_next(&mut self) -> Option<OutMessage> {
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.state == MsgState::Queued && !e.taken)?;
        e.taken = true;
        Some(OutMessage {
            msg_id: e.message.msg_id,
            kind: e.message.kind,
            expire_after: e.message.expire_after,
            payload: Zeroizing::new(e.message.payload.to_vec()),
        })
    }

    fn relayed(&mut self, id: &MsgId, cell_id: u64) {
        let now = self.clock;
        if let Some(e) = self.entry(id)
            && e.state == MsgState::Queued
        {
            e.state = MsgState::Relayed(cell_id);
            e.first_relayed_at.get_or_insert(now);
            e.taken = false;
        }
    }

    fn requeue(&mut self, id: &MsgId) {
        if let Some(e) = self.entry(id)
            && matches!(e.state, MsgState::Queued | MsgState::Relayed(_))
        {
            e.state = MsgState::Queued;
            e.taken = false;
        }
    }

    fn requeue_unreceipted(&mut self) {
        for e in &mut self.entries {
            if matches!(e.state, MsgState::Relayed(_)) {
                e.state = MsgState::Queued;
                e.taken = false;
            }
        }
    }

    fn delivered(&mut self, id: &MsgId) {
        if let Some(e) = self.entry(id)
            && e.state != MsgState::Failed
        {
            e.state = MsgState::Delivered;
            e.taken = false;
        }
    }

    fn restart(&mut self) {
        for e in &mut self.entries {
            e.taken = false;
        }
    }

    fn waiting(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state == MsgState::Queued && !e.taken)
            .count()
    }

    fn expire(&mut self, now_ms: u64) {
        self.clock = self.clock.max(now_ms);
        for e in &mut self.entries {
            if e.state == MsgState::Queued
                && e.first_relayed_at.is_none()
                && now_ms.saturating_sub(e.queued_at) >= FAIL_AFTER_MS
            {
                e.state = MsgState::Failed;
                e.taken = false;
            }
        }
    }
}

/// Why a state could not be made durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistError;

/// Which transition is being persisted (spec §7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistKind {
    /// The state after `encrypt`: durable before the cell is sealed into a frame.
    Send,
    /// The state after `decrypt`, with what was derived: durable before the cell is acknowledged.
    Receive,
}

/// A message a receiving commit records as delivered: the history row and the dedup key are durable together with the
/// ratchet state that consumed its cell (persist-before-ack covers the delivery, PC-05).
pub struct DeliveredMessage<'a> {
    /// Its id.
    pub msg_id: MsgId,
    /// `AppMessage.kind`.
    pub kind: u8,
    /// The payload.
    pub payload: &'a [u8],
    /// `AppMessage.expire_after` (seconds, 0: never).
    pub expire_after: u32,
    /// Unix ms of the latest slot preparation, ≤ one period before the fetch; before the first preparation,
    /// `unix_base`·1000 (V1-F4).
    pub received_ms: u64,
}

/// What one commit makes durable together, in one store transaction (OPEN-M7-14 A; PC-09): the ratchet state in its
/// parts (CS-3.7: fixed part and skipped entries), and with a received cell the reassembly state, the trust and the
/// messages the cell delivered.
pub struct CommitParts<'a> {
    /// The ratchet state.
    pub ratchet: &'a RatchetParts,
    /// The reassembly state (`Inbox`), when it changed.
    pub inbox: Option<&'a [u8]>,
    /// The trust, when it changed.
    pub trust: Option<u8>,
    /// The messages delivered by the received cell.
    pub delivered: &'a [DeliveredMessage<'a>],
}

/// The code of a trust in [`CommitParts::trust`] (the `sessions` trust row).
#[must_use]
pub const fn trust_code(trust: secmp_proto::tr::content::Trust) -> u8 {
    use secmp_proto::tr::content::Trust;
    match trust {
        Trust::Unverified => 0,
        Trust::Verified => 1,
        Trust::KeyChanged => 2,
        Trust::Frozen => 3,
    }
}

/// Where a ratchet state becomes durable (the encrypted store of M7).
pub trait Persist {
    /// Make `state` (the serialised `RatchetStateV1`) durable.
    ///
    /// # Errors
    /// [`PersistError`]: nothing is durable; the caller neither sends nor acknowledges.
    fn commit(&mut self, kind: PersistKind, state: &[u8]) -> Result<(), PersistError>;

    /// Make `parts` durable in one commit; the default writes the whole state ([`Persist::commit`]) and keeps nothing
    /// else (the in-memory durability); an incremental store overrides it.
    ///
    /// # Errors
    /// [`PersistError`]: nothing is durable; the caller neither sends nor acknowledges.
    fn commit_parts(
        &mut self,
        kind: PersistKind,
        parts: &CommitParts<'_>,
    ) -> Result<(), PersistError> {
        let bytes = parts.ratchet.to_bytes().map_err(|_| PersistError)?;
        self.commit(kind, &bytes)
    }
}

/// The in-memory durability: the last durable state, counters, and failure injection for the tests.
#[derive(Default)]
pub struct MemPersist {
    durable: Option<Zeroizing<Vec<u8>>>,
    commits: u64,
    fail: bool,
    /// Fail every commit once this many have succeeded (failure injection at the n-th commit).
    fail_from: Option<u64>,
    /// The next commit is made durable and then the "process dies": it reports an error to the caller.
    crash_after: bool,
    /// A second durability every commit goes to first (the store behind the in-memory copy in the tests, PC-03).
    mirror: Option<Box<dyn Persist + Send>>,
}

impl MemPersist {
    /// Nothing durable yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            durable: None,
            commits: 0,
            fail: false,
            fail_from: None,
            crash_after: false,
            mirror: None,
        }
    }

    /// Make every later commit durable in `mirror` first (its failure fails the commit); the in-memory copy follows.
    pub fn set_mirror(&mut self, mirror: Box<dyn Persist + Send>) {
        self.mirror = Some(mirror);
    }

    /// The last durable state.
    #[must_use]
    pub fn durable(&self) -> Option<&[u8]> {
        self.durable.as_deref().map(Vec::as_slice)
    }

    /// Successful commits so far.
    #[must_use]
    pub const fn commits(&self) -> u64 {
        self.commits
    }

    /// Make every later commit fail (or succeed again).
    pub const fn set_failing(&mut self, failing: bool) {
        self.fail = failing;
    }

    /// The next commit is made durable and then fails towards its caller, as if the process died right after the write
    /// (crash injection after `Persist::commit(Send)` returned from the store, before the cell is released).
    pub const fn crash_after_next_commit(&mut self) {
        self.crash_after = true;
    }

    /// Let `n` more commits succeed, then fail every later one (`None`: no such rule).
    pub const fn fail_after_commits(&mut self, n: Option<u64>) {
        self.fail_from = match n {
            Some(n) => Some(self.commits.saturating_add(n)),
            None => None,
        };
    }

    /// Seed the durable state (a restart from a snapshot).
    pub fn set_durable(&mut self, state: &[u8]) {
        self.durable = Some(Zeroizing::new(state.to_vec()));
    }
}

impl MemPersist {
    fn refuses(&self) -> bool {
        self.fail || self.fail_from.is_some_and(|n| self.commits >= n)
    }
}

impl Persist for MemPersist {
    fn commit(&mut self, kind: PersistKind, state: &[u8]) -> Result<(), PersistError> {
        if self.refuses() {
            return Err(PersistError);
        }
        if let Some(m) = self.mirror.as_mut() {
            m.commit(kind, state)?;
        }
        self.keep(state)
    }

    fn commit_parts(
        &mut self,
        kind: PersistKind,
        parts: &CommitParts<'_>,
    ) -> Result<(), PersistError> {
        if self.refuses() {
            return Err(PersistError);
        }
        if let Some(m) = self.mirror.as_mut() {
            m.commit_parts(kind, parts)?;
        }
        let bytes = parts.ratchet.to_bytes().map_err(|_| PersistError)?;
        self.keep(&bytes)
    }
}

impl MemPersist {
    fn keep(&mut self, state: &[u8]) -> Result<(), PersistError> {
        self.durable = Some(Zeroizing::new(state.to_vec()));
        self.commits = self.commits.saturating_add(1);
        if self.crash_after {
            self.crash_after = false;
            return Err(PersistError);
        }
        Ok(())
    }
}
