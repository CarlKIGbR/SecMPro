// SPDX-License-Identifier: AGPL-3.0-or-later
//! The outbox (spec §9.5, §10.4) behind a trait, and `Persist`, the durability boundary of the ratchet states. M6
//! implements both in memory ([`MemOutbox`], [`MemPersist`]); the encrypted store of M7 implements the same traits
//! (OB-07: the scheduler sees nothing else).
//!
//! **States (§10.4).** A message is *queued* locally, *relayed* when `OK_SEND` arrived and the cell was not later
//! reported evicted, and *delivered* when an E2E `Receipt{delivered}` arrives. A message never relayed within 30 days
//! is *failed*. An evicted real cell, a lost queue (`ERR_NOQUEUE`) or a link that died before the answer put the message
//! back to *queued*: it is re-encrypted under a new key and sent again, the receiver deduplicates by `msg_id`.

use secmp_crypto::Zeroizing;
use secmp_proto::wire::cell::AppKind;
use secmp_proto::wire::Id;

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

    /// Fail the messages never relayed within 30 days of being queued.
    fn expire(&mut self, now_ms: u64);
}

struct Entry {
    message: OutMessage,
    queued_at: u64,
    state: MsgState,
    taken: bool,
}

/// The in-memory outbox.
#[derive(Default)]
pub struct MemOutbox {
    entries: Vec<Entry>,
}

impl MemOutbox {
    /// An empty outbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
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

    fn entry(&mut self, id: &MsgId) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.message.msg_id == *id)
    }
}

impl Outbox for MemOutbox {
    fn enqueue(&mut self, message: OutMessage, now_ms: u64) {
        self.entries.push(Entry {
            message,
            queued_at: now_ms,
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
        if let Some(e) = self.entry(id)
            && e.state == MsgState::Queued
        {
            e.state = MsgState::Relayed(cell_id);
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

    fn expire(&mut self, now_ms: u64) {
        for e in &mut self.entries {
            if e.state == MsgState::Queued && now_ms.saturating_sub(e.queued_at) >= FAIL_AFTER_MS {
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

/// Where a ratchet state becomes durable (the encrypted store of M7).
pub trait Persist {
    /// Make `state` (the serialised `RatchetStateV1`) durable.
    ///
    /// # Errors
    /// [`PersistError`]: nothing is durable; the caller neither sends nor acknowledges.
    fn commit(&mut self, kind: PersistKind, state: &[u8]) -> Result<(), PersistError>;
}

/// The in-memory durability: the last durable state, counters, and failure injection for the tests.
#[derive(Default)]
pub struct MemPersist {
    durable: Option<Zeroizing<Vec<u8>>>,
    commits: u64,
    fail: bool,
}

impl MemPersist {
    /// Nothing durable yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            durable: None,
            commits: 0,
            fail: false,
        }
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

    /// Seed the durable state (a restart from a snapshot).
    pub fn set_durable(&mut self, state: &[u8]) {
        self.durable = Some(Zeroizing::new(state.to_vec()));
    }
}

impl Persist for MemPersist {
    fn commit(&mut self, _kind: PersistKind, state: &[u8]) -> Result<(), PersistError> {
        if self.fail {
            return Err(PersistError);
        }
        self.durable = Some(Zeroizing::new(state.to_vec()));
        self.commits = self.commits.saturating_add(1);
        Ok(())
    }
}
