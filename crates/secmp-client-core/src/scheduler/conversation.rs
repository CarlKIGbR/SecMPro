// SPDX-License-Identifier: AGPL-3.0-or-later
//! The in-memory conversation behind the cell source (M6; M7's `Sessions` replace it): one ratchet state, the queue it
//! sends to and the queue it receives on, an [`Outbox`], a [`Persist`], the receiver's dedup by `msg_id`, receipts.
//!
//! **One path for real and dummy cells (spec §10.1, CLAUDE.md §1.4).** Every cell — a message, a fragment, a receipt, a
//! dummy — is sealed by [`Conversation::seal`], the only call of `RatchetState::encrypt_with` in the crate, and
//! persisted (`Sealed::persist`) before it is released: persist-before-send (spec §7.5). A received cell is decrypted,
//! its content processed, the new state committed, and only then is the cell reported as decided
//! (persist-before-ack); a cell that does not decrypt is discarded and is decided too (spec §9.3: every delivered cell
//! is acknowledged).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use secmp_crypto::{HybridVerifyingKey, Zeroizing};
use secmp_proto::Encode;
use secmp_proto::tr::content::{Delivery, Inbox, Trust, dummy, split_chunks};
use secmp_proto::tr::{Entropy, OsEntropy, RatchetState};
use secmp_proto::wire::cell::{
    AppKind, AppMessage, BatchBody, Cell, Content, ContentBody, Fragment, FragmentPayload,
    ReceiptBody, ReceiptKind,
};

use crate::scheduler::outbox::{MsgId, Outbox, OutMessage, Persist, PersistKind};
use crate::scheduler::types::{
    CellSource, CellToken, PreparedCell, QueueId, SendFailure, SourceError,
};

/// Counting accessors of the `kat` build (`tr_encrypt_calls`, `persist_calls`; TEST-SPEC-M6 "Conventions"):
/// thread-local, read before and after a unit.
pub mod counters {
    #[cfg(feature = "kat")]
    mod imp {
        use core::cell::{Cell, RefCell};

        thread_local! {
            pub(super) static ENCRYPT: Cell<u64> = const { Cell::new(0) };
            pub(super) static PERSIST: Cell<u64> = const { Cell::new(0) };
            pub(super) static SITES: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        }
    }

    /// Calls of `RatchetState::encrypt_with` on this thread.
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn tr_encrypt_calls() -> u64 {
        imp::ENCRYPT.with(core::cell::Cell::get)
    }

    /// State commits (send and receive) on this thread.
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn persist_calls() -> u64 {
        imp::PERSIST.with(core::cell::Cell::get)
    }

    /// The distinct call sites of `encrypt_with` seen on this thread.
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn encrypt_sites() -> Vec<&'static str> {
        imp::SITES.with(|s| s.borrow().clone())
    }

    #[cfg(feature = "kat")]
    pub(crate) fn note_encrypt(site: &'static str) {
        imp::ENCRYPT.with(|c| c.set(c.get().saturating_add(1)));
        imp::SITES.with(|s| {
            let mut s = s.borrow_mut();
            if !s.contains(&site) {
                s.push(site);
            }
        });
    }

    #[cfg(feature = "kat")]
    pub(crate) fn note_persist() {
        imp::PERSIST.with(|c| c.set(c.get().saturating_add(1)));
    }

    #[cfg(not(feature = "kat"))]
    pub(crate) const fn note_encrypt(_site: &'static str) {}

    #[cfg(not(feature = "kat"))]
    pub(crate) const fn note_persist() {}
}

/// Where a conversation gets its ratchet randomness.
pub trait EntropySource {
    /// The entropy.
    type E: Entropy;
    /// The entropy, for one operation.
    fn entropy(&mut self) -> &mut Self::E;
}

/// The operating system's randomness (the only source of a shipped build).
pub struct OsSource(OsEntropy);

impl OsSource {
    /// The operating system.
    #[must_use]
    pub const fn new() -> Self {
        Self(OsEntropy)
    }
}

impl Default for OsSource {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for OsSource {
    type E = OsEntropy;

    fn entropy(&mut self) -> &mut OsEntropy {
        &mut self.0
    }
}

/// A message delivered to the application.
pub struct Received {
    /// Its id.
    pub msg_id: MsgId,
    /// Its kind.
    pub kind: AppKind,
    /// Its payload.
    pub payload: Zeroizing<Vec<u8>>,
}

/// What a cell on the way carries (to map `OK_SEND` and eviction back to the outbox).
#[derive(Clone)]
enum Owner {
    Message(MsgId),
    Receipt(Vec<MsgId>),
    Dummy,
}

struct Planned {
    content: Content,
    owner: Owner,
    /// How many cells the owner's message takes in all.
    total: u16,
}

#[derive(Clone)]
struct Sent {
    owner: Owner,
    total: u16,
}

/// The largest number of ids in one receipt: `2 + 16·n ≤ 1689` (spec §7.6).
const RECEIPT_IDS_MAX: usize = 100;

/// One conversation (see the module documentation).
pub struct Conversation<O: Outbox, P: Persist, S: EntropySource> {
    state: Option<RatchetState>,
    durable: Zeroizing<Vec<u8>>,
    send_queue: Option<QueueId>,
    recv_queue: Option<QueueId>,
    outbox: O,
    persist: P,
    source: S,
    plan: VecDeque<Planned>,
    inflight: BTreeMap<u64, Sent>,
    by_cell: BTreeMap<u64, Sent>,
    relayed_cells: BTreeMap<MsgId, u16>,
    next_token: u64,
    next_seq: u64,
    unix_base: u64,
    inbox: Inbox,
    trust: Trust,
    peer: HybridVerifyingKey,
    seen: BTreeSet<MsgId>,
    received: Vec<Received>,
    receipts_due: Vec<MsgId>,
    send_receipts: bool,
    discarded: u64,
}

impl<O: Outbox, P: Persist, S: EntropySource> Conversation<O, P, S> {
    /// A conversation over `state`; `peer` is the contact's `IK_sig` (key changes), `unix_base` the Unix time at
    /// monotonic 0 (the `ts` field of a Content).
    ///
    /// # Panics
    /// Never; a state that does not serialise starts with an empty durable copy.
    #[must_use]
    pub fn new(
        state: RatchetState,
        outbox: O,
        persist: P,
        source: S,
        peer: HybridVerifyingKey,
        unix_base: u64,
    ) -> Self {
        let durable = state
            .to_bytes()
            .unwrap_or_else(|_| Zeroizing::new(Vec::new()));
        Self {
            state: Some(state),
            durable,
            send_queue: None,
            recv_queue: None,
            outbox,
            persist,
            source,
            plan: VecDeque::new(),
            inflight: BTreeMap::new(),
            by_cell: BTreeMap::new(),
            relayed_cells: BTreeMap::new(),
            next_token: 0,
            next_seq: 1,
            unix_base,
            inbox: Inbox::new(),
            trust: Trust::Verified,
            peer,
            seen: BTreeSet::new(),
            received: Vec::new(),
            receipts_due: Vec::new(),
            send_receipts: true,
            discarded: 0,
        }
    }

    /// The scheduler queues of this conversation.
    pub const fn bind(&mut self, send: QueueId, recv: QueueId) {
        self.send_queue = Some(send);
        self.recv_queue = Some(recv);
    }

    /// Replace the queue we send to (the same queue re-created, or a route update).
    pub const fn set_send_queue(&mut self, send: QueueId) {
        self.send_queue = Some(send);
    }

    /// Replace the queue we receive on.
    pub const fn set_recv_queue(&mut self, recv: QueueId) {
        self.recv_queue = Some(recv);
    }

    /// Receipts on or off (on by default for verified contacts, spec §10.4).
    pub const fn set_send_receipts(&mut self, on: bool) {
        self.send_receipts = on;
    }

    /// The outbox.
    #[must_use]
    pub const fn outbox(&self) -> &O {
        &self.outbox
    }

    /// The outbox, mutable (the application enqueues here).
    pub const fn outbox_mut(&mut self) -> &mut O {
        &mut self.outbox
    }

    /// The durability.
    #[must_use]
    pub const fn persist(&self) -> &P {
        &self.persist
    }

    /// The durability, mutable (failure injection).
    pub const fn persist_mut(&mut self) -> &mut P {
        &mut self.persist
    }

    /// The randomness.
    pub const fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// The messages delivered to the application, in order.
    #[must_use]
    pub fn received(&self) -> &[Received] {
        &self.received
    }

    /// Cells discarded because they did not decrypt.
    #[must_use]
    pub const fn discarded(&self) -> u64 {
        self.discarded
    }

    /// Receipts waiting for a slot.
    #[must_use]
    pub fn receipts_due(&self) -> usize {
        self.receipts_due.len()
    }

    /// How many cell ids are mapped to what they carried (S-32).
    #[must_use]
    pub fn mapped_cells(&self) -> usize {
        self.by_cell.len()
    }

    /// The last durable ratchet state.
    #[must_use]
    pub fn durable(&self) -> &[u8] {
        &self.durable
    }

    fn ts(&self, now_ms: u64) -> u64 {
        self.unix_base.saturating_add(now_ms.checked_div(1000).unwrap_or(0))
    }

    fn take_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        s
    }

    /// Break a message into the contents of its cells: one Batch if it fits a Content, else Fragments of the Batch
    /// (spec §7.6).
    fn plan_message(&mut self, message: &OutMessage, now_ms: u64) {
        let id = message.msg_id;
        let batch = BatchBody {
            messages: vec![AppMessage {
                msg_id: message.msg_id,
                kind: message.kind,
                expire_after: message.expire_after,
                payload: Zeroizing::new(message.payload.to_vec()),
            }],
        };
        let ts = self.ts(now_ms);
        let fits = batch
            .encode()
            .is_ok_and(|b| b.len() <= secmp_proto::sizes::CONTENT_BODY_MAX);
        if fits {
            let seq = self.take_seq();
            self.plan.push_back(Planned {
                content: Content {
                    seq,
                    ts,
                    body: ContentBody::Batch(batch),
                },
                owner: Owner::Message(id),
                total: 1,
            });
            return;
        }
        let Ok(bytes) = FragmentPayload::Batch(batch).encode() else {
            self.outbox.relayed(&id, 0);
            return;
        };
        let chunks = split_chunks(&bytes);
        let total = u16::try_from(chunks.len()).unwrap_or(u16::MAX);
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let seq = self.take_seq();
            self.plan.push_back(Planned {
                content: Content {
                    seq,
                    ts,
                    body: ContentBody::Fragment(Fragment {
                        msg_id: id,
                        idx: u16::try_from(idx).unwrap_or(u16::MAX),
                        total,
                        chunk: Zeroizing::new(chunk.to_vec()),
                    }),
                },
                owner: Owner::Message(id),
                total,
            });
        }
    }

    fn plan_receipt(&mut self, now_ms: u64) {
        let take = self.receipts_due.len().min(RECEIPT_IDS_MAX);
        let ids: Vec<MsgId> = self.receipts_due.drain(..take).collect();
        let seq = self.take_seq();
        let ts = self.ts(now_ms);
        self.plan.push_back(Planned {
            content: Content {
                seq,
                ts,
                body: ContentBody::Receipt(ReceiptBody {
                    kind: ReceiptKind::Delivered,
                    msg_ids: ids.clone(),
                }),
            },
            owner: Owner::Receipt(ids),
            total: 1,
        });
    }

    /// The one place a cell is sealed: `encrypt`, then persist-before-send. `Err` leaves the durable state as it was.
    fn seal(&mut self, content: &Content) -> Result<Cell, SourceError> {
        let state = match self.state.take() {
            Some(s) => s,
            None => RatchetState::from_bytes(&self.durable).map_err(|_| SourceError)?,
        };
        counters::note_encrypt("Conversation::seal");
        let sealed = match state.encrypt_with(content, self.source.entropy()) {
            Ok(sealed) => sealed,
            Err(refused) => {
                self.state = Some(refused.into_state());
                return Err(SourceError);
            }
        };
        let new_durable = &mut self.durable;
        let persist = &mut self.persist;
        let result = sealed.persist(|bytes| {
            counters::note_persist();
            persist.commit(PersistKind::Send, bytes)?;
            *new_durable = Zeroizing::new(bytes.to_vec());
            Ok::<(), crate::scheduler::outbox::PersistError>(())
        });
        if let Ok((state, cell)) = result {
            self.state = Some(state);
            Ok(cell)
        } else {
            // the new state was dropped: the durable one is the truth
            self.state = RatchetState::from_bytes(&self.durable).ok();
            Err(SourceError)
        }
    }

    /// Put an owner back where it came from (a cell that did not make it).
    fn restore(&mut self, owner: &Owner) {
        match owner {
            Owner::Message(id) => {
                self.relayed_cells.remove(id);
                // the rest of the message has no use alone
                self.plan
                    .retain(|p| !matches!(&p.owner, Owner::Message(m) if m == id));
                self.outbox.requeue(id);
            }
            Owner::Receipt(ids) => {
                for id in ids.iter().rev() {
                    self.receipts_due.insert(0, *id);
                }
            }
            Owner::Dummy => {}
        }
    }
}

impl<O: Outbox, P: Persist, S: EntropySource> Conversation<O, P, S> {
    /// Build the next cell of this conversation (what the scheduler's cell source does for the send queue), for
    /// callers that drive a conversation by hand.
    ///
    /// # Errors
    /// [`SourceError`] if the new state could not be persisted: no cell leaves.
    pub fn prepare_direct(&mut self, now_ms: u64) -> Result<PreparedCell, SourceError> {
        self.prepare(now_ms)
    }

    fn prepare(&mut self, now_ms: u64) -> Result<PreparedCell, SourceError> {
        self.outbox.expire(now_ms);
        if self.plan.is_empty() {
            if self.send_receipts && !self.receipts_due.is_empty() {
                self.plan_receipt(now_ms);
            } else if let Some(message) = self.outbox.take_next() {
                self.plan_message(&message, now_ms);
            }
        }
        let planned = self.plan.pop_front().unwrap_or(Planned {
            content: dummy(),
            owner: Owner::Dummy,
            total: 1,
        });
        match self.seal(&planned.content) {
            Ok(cell) => {
                let token = self.next_token;
                self.next_token = self.next_token.saturating_add(1);
                self.inflight.insert(
                    token,
                    Sent {
                        owner: planned.owner,
                        total: planned.total,
                    },
                );
                Ok(PreparedCell {
                    cell,
                    token: CellToken(token),
                })
            }
            Err(e) => {
                self.restore(&planned.owner);
                Err(e)
            }
        }
    }
}

impl<O: Outbox, P: Persist, S: EntropySource> Conversation<O, P, S> {
    fn on_relayed(&mut self, token: CellToken, cell_id: u64) {
        let Some(sent) = self.inflight.remove(&token.0) else {
            return;
        };
        if let Owner::Message(id) = &sent.owner {
            let done = self.relayed_cells.entry(*id).or_insert(0);
            *done = done.saturating_add(1);
            if *done >= sent.total {
                self.relayed_cells.remove(id);
                self.outbox.relayed(id, cell_id);
            }
        }
        self.by_cell.insert(cell_id, sent);
        // an evicted id is always among the newest `QUEUE_CAPACITY`: older entries are dead weight
        let floor = cell_id.saturating_sub(256);
        self.by_cell = self.by_cell.split_off(&floor);
    }

    fn on_evicted(&mut self, cell_id: u64) {
        if let Some(sent) = self.by_cell.remove(&cell_id) {
            self.restore(&sent.owner);
        }
    }

    fn on_failed(&mut self, token: CellToken) {
        if let Some(sent) = self.inflight.remove(&token.0) {
            self.restore(&sent.owner);
        }
    }

    fn on_lost(&mut self) {
        self.by_cell.clear();
        self.outbox.requeue_unreceipted();
        let planned: Vec<Planned> = self.plan.drain(..).collect();
        for p in planned {
            self.restore(&p.owner);
        }
        self.relayed_cells.clear();
    }

    fn on_deliver(&mut self, cell: &Cell) -> Result<(), SourceError> {
        let state = match self.state.take() {
            Some(s) => s,
            None => RatchetState::from_bytes(&self.durable).map_err(|_| SourceError)?,
        };
        let opened = match state.decrypt_with(cell.as_bytes(), self.source.entropy()) {
            Ok(opened) => opened,
            Err(refused) => {
                let (state, error) = refused.into_parts();
                self.state = Some(state);
                if error == secmp_proto::Error::Unavailable {
                    return Err(SourceError);
                }
                // not a cell of this conversation: decided (discarded), acknowledged
                self.discarded = self.discarded.saturating_add(1);
                return Ok(());
            }
        };
        let delivery = self
            .inbox
            .receive(opened.plaintext(), &self.peer, &mut self.trust);
        let durable = &mut self.durable;
        let persist = &mut self.persist;
        let committed = opened.commit(|bytes| {
            counters::note_persist();
            persist.commit(PersistKind::Receive, bytes)?;
            *durable = Zeroizing::new(bytes.to_vec());
            Ok::<(), crate::scheduler::outbox::PersistError>(())
        });
        if let Ok((state, _plaintext)) = committed {
            self.state = Some(state);
        } else {
            self.state = RatchetState::from_bytes(&self.durable).ok();
            return Err(SourceError);
        }
        match delivery {
            Delivery::Messages(messages) => {
                for m in messages {
                    if self.seen.insert(m.msg_id) {
                        self.receipts_due.push(m.msg_id);
                        self.received.push(Received {
                            msg_id: m.msg_id,
                            kind: m.kind,
                            payload: m.payload,
                        });
                    }
                }
            }
            Delivery::Receipt(body) => {
                for id in &body.msg_ids {
                    self.outbox.delivered(id);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// The conversations of a client, as the scheduler's cell source: a cell is routed by the queue it is for.
pub struct Conversations<O: Outbox, P: Persist, S: EntropySource> {
    items: Vec<Conversation<O, P, S>>,
}

impl<O: Outbox, P: Persist, S: EntropySource> Default for Conversations<O, P, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O: Outbox, P: Persist, S: EntropySource> Conversations<O, P, S> {
    /// No conversation.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Add a conversation (bound to its queues); returns its index.
    pub fn add(&mut self, conversation: Conversation<O, P, S>) -> usize {
        self.items.push(conversation);
        self.items.len().saturating_sub(1)
    }

    /// The conversation at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Conversation<O, P, S>> {
        self.items.get(index)
    }

    /// The conversation at `index`, mutable.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Conversation<O, P, S>> {
        self.items.get_mut(index)
    }

    fn by_send(&mut self, q: QueueId) -> Option<&mut Conversation<O, P, S>> {
        self.items.iter_mut().find(|c| c.send_queue == Some(q))
    }

    fn by_recv(&mut self, q: QueueId) -> Option<&mut Conversation<O, P, S>> {
        self.items.iter_mut().find(|c| c.recv_queue == Some(q))
    }
}

impl<O: Outbox, P: Persist, S: EntropySource> CellSource for Conversations<O, P, S> {
    fn prepare_cell(
        &mut self,
        queue: QueueId,
        now: u64,
    ) -> Result<Option<PreparedCell>, SourceError> {
        match self.by_send(queue) {
            Some(c) => c.prepare(now).map(Some),
            None => Ok(None),
        }
    }

    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        if let Some(c) = self.by_send(queue) {
            c.on_relayed(token, cell_id);
        }
    }

    fn evicted(&mut self, queue: QueueId, cell_id: u64) {
        if let Some(c) = self.by_send(queue) {
            c.on_evicted(cell_id);
        }
    }

    fn send_failed(&mut self, queue: QueueId, token: CellToken, _why: SendFailure) {
        if let Some(c) = self.by_send(queue) {
            c.on_failed(token);
        }
    }

    fn discard(&mut self, queue: QueueId, token: CellToken) {
        if let Some(c) = self.by_send(queue) {
            c.on_failed(token);
        }
    }

    fn queue_lost(&mut self, queue: QueueId) {
        if let Some(c) = self.by_send(queue) {
            c.on_lost();
        }
    }

    fn deliver(&mut self, queue: QueueId, _cell_id: u64, cell: &Cell) -> Result<(), SourceError> {
        match self.by_recv(queue) {
            Some(c) => c.on_deliver(cell),
            // a queue without a conversation (a spare of the pool): nothing to decrypt, the cell is discarded
            None => Ok(()),
        }
    }
}
