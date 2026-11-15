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
use secmp_proto::tr::{Entropy, OsEntropy, RatchetParts, RatchetState};
use secmp_proto::wire::cell::{
    AppKind, AppMessage, BatchBody, Cell, Content, ContentBody, ControlCode, Fragment,
    FragmentPayload, KeyChangeBody, ReceiptBody, ReceiptKind, RouteDescriptor, RouteUpdateBody,
};
use secmp_proto::wire::inv::IksPublic;

use crate::scheduler::outbox::{
    CommitParts, DeliveredMessage, MsgId, OutMessage, Outbox, Persist, PersistError, PersistKind,
    trust_code,
};
use crate::scheduler::types::{
    CellSource, CellToken, Delivered, PreparedCell, QueueId, SendFailure, SourceError,
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
    /// A dummy, or a content planned by the tests only.
    Dummy,
    /// A persisted handshake cell (its bytes), sent again if its send fails.
    Handshake(Vec<u8>),
    /// A cell of an attempt of a control content (Q222 (1), spec §9.5, §10.6).
    Control(ControlRef),
}

struct Planned {
    content: Content,
    owner: Owner,
    /// How many cells the owner's message takes in all.
    total: u16,
}

/// An attempt of a control content (Q222): `id` is the conversation's own number of the content — never the `ord` of
/// its row, the store reuses `ord`s — and `attempt` counts its plans; the outcomes of a superseded attempt count nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ControlRef {
    id: u64,
    attempt: u64,
}

/// A control content of the session (a `RouteUpdate`, a `Control{1|2}`, a `KeyChange`) from its plan until every cell of
/// its current attempt has its `OK_SEND` without an eviction (Q222 (2), spec §9.5): an eviction, a failed `SEND`, a lost
/// queue and a send-queue switch plan the whole content again (new seals, a new fragment `msg_id`, Q222 (3)).
struct ControlEntry {
    /// [`PendingControl::encode`] of the content: it is planned again from this.
    row: Zeroizing<Vec<u8>>,
    /// Its durable row; `None`: in memory only, or deleted after the last `OK_SEND`.
    ord: Option<i64>,
    /// Made by [`Conversation::queue_pending`]: a plan after the row went writes the row again.
    durable: bool,
    attempt: u64,
    /// How many cells its current attempt takes; 0: none planned (Q240: no randomness for the fragment `msg_id`) — the
    /// entry stays and the next preparation plans it.
    total: u16,
    relayed: u16,
    /// Every cell of `attempt` has its `OK_SEND`: the row goes at the next preparation.
    done: bool,
    /// Q224: superseded by a newer `RouteUpdate`: never planned again, its row is never written again; kept only until its
    /// row delete succeeded. A retired entry always has `ord.is_some()`; an entry whose row is gone is removed.
    retired: bool,
    /// Q241 (D-B72): the cells of this `KeyChange` that may still wait on an old send queue (queue, cell id). Such a cell is
    /// gone once a cell of that queue with an id at least `QUEUE_CAPACITY` higher has its `OK_SEND`, or once the queue is
    /// lost.
    stranded: Vec<(QueueId, u64)>,
    /// Q241: the cells of this `KeyChange` whose `SEND` ended without an answer (queue, cell token): the relay may have
    /// stored them under an id not known here. Such a mark becomes a stranded one with the id of the first `OK_SEND` on
    /// that queue of a cell prepared after it.
    unknown: Vec<(QueueId, u64)>,
}

impl ControlEntry {
    /// Q241: a copy of this content may still wait on a queue it is no longer tracked on.
    fn marked(&self) -> bool {
        !self.stranded.is_empty() || !self.unknown.is_empty()
    }
}

/// Q240: a `KeyChange` (row tag 3).
fn is_key_change(row: &[u8]) -> bool {
    row.first() == Some(&3)
}

/// A control content that is durable from the commit that makes its effect durable until the last cell's `OK_SEND`
/// (Q210 c, Q222): the rotation's `RouteUpdate`, the `KeyChange` of an identity rotation, the `Control{1|2}` of a removal or
/// a reset. Its row (the store's CONTROL part, sealed) is `tag u8 ‖ body`: 1 `RouteUpdateBody`, 2 `ControlBody` (no
/// argument), 3 `KeyChangeBody` — the bodies in their wire encodings; the decoding is strict.
pub enum PendingControl {
    /// A `RouteUpdate`.
    Routes(RouteUpdateBody),
    /// A `Control` without an argument.
    Control(ControlCode),
    /// A `KeyChange`, signed by the old `IK_sig`.
    KeyChange(KeyChangeBody),
}

impl PendingControl {
    /// The row of this content.
    ///
    /// # Errors
    /// [`SourceError`] if the body does not encode.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SourceError> {
        let (tag, body) = match self {
            Self::Routes(b) => (1, b.encode()),
            Self::Control(code) => (
                2,
                secmp_proto::wire::cell::ControlBody {
                    code: *code,
                    arg: Zeroizing::new(Vec::new()),
                }
                .encode(),
            ),
            Self::KeyChange(b) => (3, b.encode()),
        };
        let body = body.map_err(|_| SourceError)?;
        let mut out = Zeroizing::new(Vec::with_capacity(body.len().saturating_add(1)));
        out.push(tag);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The content of a row.
    ///
    /// # Errors
    /// [`SourceError`] for an unknown tag, a body that does not decode, or a `Control` with an argument.
    pub fn decode(row: &[u8]) -> Result<Self, SourceError> {
        use secmp_proto::Decode as _;
        let (tag, body) = row.split_first().ok_or(SourceError)?;
        match tag {
            1 => Ok(Self::Routes(
                RouteUpdateBody::decode(body).map_err(|_| SourceError)?,
            )),
            2 => {
                let control =
                    secmp_proto::wire::cell::ControlBody::decode(body).map_err(|_| SourceError)?;
                if control.arg.is_empty() {
                    Ok(Self::Control(control.code))
                } else {
                    Err(SourceError)
                }
            }
            3 => Ok(Self::KeyChange(
                KeyChangeBody::decode(body).map_err(|_| SourceError)?,
            )),
            _ => Err(SourceError),
        }
    }
}

#[derive(Clone)]
struct Sent {
    owner: Owner,
    total: u16,
}

/// ADR-054 items 1 and 3 (EXTB2-3): an `AppMessage` of kind 1 (text) or 3 (view-once text) whose payload is
/// well-formed UTF-8 of 1 … [`super::MESSAGE_MAX`] bytes without U+0000; kinds 2, 4, 5 and 6 are not defined for M7. The
/// `Api` refuses what fails here; a receiver drops it (the cell is committed and acknowledged, spec §9.3).
pub(crate) fn app_payload_ok(kind: AppKind, payload: &[u8]) -> bool {
    matches!(kind, AppKind::Text | AppKind::ViewOnceText)
        && (1..=super::MESSAGE_MAX).contains(&payload.len())
        && !payload.contains(&0)
        && core::str::from_utf8(payload).is_ok()
}

/// Q225 (CLAUDE.md §1.7): a cell of a durable control content whose row is not in the store waits.
fn row_missing(controls: &BTreeMap<u64, ControlEntry>, owner: &Owner) -> bool {
    matches!(owner, Owner::Control(c) if controls.get(&c.id).is_some_and(|e| e.durable && e.ord.is_none()))
}

/// The largest number of ids in one receipt: `2 + 16·n ≤ 1689` (spec §7.6).
const RECEIPT_IDS_MAX: usize = 100;

/// The ratchet state of a new session in its parts, as the session's rows hold them (CS-3.7): the accept transaction of an
/// invitation writes them through the `sessions` functions of the store (B-3, F-M7). The only `RatchetState` call outside
/// a conversation.
///
/// # Errors
/// [`PersistError`] if the state does not serialise.
pub fn initial_parts(state: &RatchetState) -> Result<RatchetParts, PersistError> {
    state.to_parts().map_err(|_| PersistError)
}

/// The shortest `T_RS`: 24 h in ms.
pub const T_RS_MIN_MS: u64 = 24 * 60 * 60 * 1000;

/// `T_RS` (spec §10.4; OPEN-M7-07, a reading that is not normative; Q159, D-B4): after how long a relayed message without
/// a receipt is reported as not confirmed — `max(24 h, 2 · QUEUE_CAPACITY · P_q)` from the `OK_SEND`, a function of the
/// send period `P_q` of the queue in ms. Once per `msg_id`; only for contacts that send receipts.
#[must_use]
pub fn receipt_timeout_ms(period_ms: u64) -> u64 {
    let queue = u64::try_from(secmp_proto::link::QUEUE_CAPACITY).unwrap_or(u64::MAX);
    T_RS_MIN_MS.max(queue.saturating_mul(2).saturating_mul(period_ms))
}

/// What a received cell told the session beyond its messages (taken with [`Conversation::take_events`], after the cell's
/// commit): the host applies it to the contact (routes, key change, removal, reset) and to the user interface.
pub enum SessionEvent {
    /// A `RouteUpdate`: the routes of a known kind (0x01), already persisted with the receive commit.
    Routes(Vec<RouteDescriptor>),
    /// A verified `KeyChange` (spec §7.7): the peer's new identity; the trust is now `KeyChanged` and real sends are held.
    KeyChanged(Box<IksPublic>),
    /// An unverifiable `KeyChange`: the session is frozen.
    KeyChangeInvalid,
    /// `Control{ContactRemoved}` without an argument (ADR-054 item 4).
    ContactRemoved,
    /// `Control{SessionResetRequest}` without an argument (spec §7.6 code 2; ADR-054 item 4, EXTB2-2).
    ResetRequested,
    /// A message was relayed and no receipt came within `T_RS` (spec §10.4; OPEN-M7-07 A): not re-sent.
    NotConfirmed(MsgId),
}

/// Why real content is refused at the one send entry ([`Conversation::may_send_real`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The trust forbids it (`KeyChanged`, `Frozen`).
    Trust,
    /// The peer removed us.
    Removed,
    /// A session reset was asked for (either side).
    Reset,
    /// An initiator holds real content until the first reply of the responder is decrypted (spec §6.5; IN-15).
    AwaitingReply,
}

/// The block byte of the session's trust row for `block` (0 none, 1 `Removed`, 2 `Reset`; Q210 b): `None` for a refusal
/// that is not a block.
#[must_use]
pub const fn block_code(block: Refusal) -> Option<u8> {
    match block {
        Refusal::Removed => Some(1),
        Refusal::Reset => Some(2),
        Refusal::Trust | Refusal::AwaitingReply => None,
    }
}

/// The block of a stored block byte (`Some(None)`: none); `None` for an unknown byte.
#[must_use]
pub const fn block_of(code: u8) -> Option<Option<Refusal>> {
    match code {
        0 => Some(None),
        1 => Some(Some(Refusal::Removed)),
        2 => Some(Some(Refusal::Reset)),
        _ => None,
    }
}

/// One conversation (see the module documentation).
pub struct Conversation<O: Outbox, P: Persist, S: EntropySource> {
    state: Option<RatchetState>,
    durable: Zeroizing<Vec<u8>>,
    send_queue: Option<QueueId>,
    recv_queue: Option<QueueId>,
    /// The queues we sent to before the peer's `RouteUpdate` moved us to a new one: they carry dummies only until they are
    /// dropped (spec §10.6 (4)).
    overlap_send: Vec<QueueId>,
    /// The queues we receive on besides the current one: the ones in overlap, fetched until their `QUEUE_DEL`.
    overlap_recv: Vec<QueueId>,
    outbox: O,
    persist: P,
    source: S,
    plan: VecDeque<Planned>,
    /// The control contents until their last `OK_SEND` (Q222), by their conversation-local id.
    controls: BTreeMap<u64, ControlEntry>,
    next_control: u64,
    inflight: BTreeMap<u64, Sent>,
    by_cell: BTreeMap<u64, Sent>,
    relayed_cells: BTreeMap<MsgId, u16>,
    next_token: u64,
    next_seq: u64,
    unix_base: u64,
    /// The latest `now_ms` of a preparation (the time a delivered message is stamped with, V1-F4).
    last_now_ms: u64,
    inbox: Inbox,
    trust: Trust,
    peer: HybridVerifyingKey,
    /// The identity the contact row holds (`IK_sig` of it is `peer`), when the host knows it (ADR-058).
    peer_iks: Option<IksPublic>,
    /// The `IK_sig` before the last accepted `KeyChange`: a repeat of that `KeyChange` verifies under it (ADR-058).
    prev_peer: Option<HybridVerifyingKey>,
    seen: BTreeSet<MsgId>,
    received: Vec<Received>,
    receipts_due: Vec<MsgId>,
    send_receipts: bool,
    discarded: u64,
    block: Option<Refusal>,
    /// An initiator's three handshake cells still to send (byte-identical to the persisted ones, §6.5), and whether the
    /// first reply is still awaited (Q150).
    handshake_out: VecDeque<Vec<u8>>,
    awaiting_first_reply: bool,
    events: Vec<SessionEvent>,
    /// When (monotonic ms) each relayed message was relayed, until its receipt (SE-13b).
    relayed_at: BTreeMap<MsgId, u64>,
    notified: BTreeSet<MsgId>,
    /// `T_RS` in ms; 0: no confirmation timeout (the host sets it from the queue's period).
    receipt_timeout_ms: u64,
    /// ADR-054 items 1 and 3 at delivery (EXTB2-3): on in every constructor; off only through the test kit's
    /// `raw_app_payloads_kat`.
    app_rules: bool,
    /// SHA-256 of every message key this conversation sealed a cell under, in order (feature `kat`; TEST-SPEC-M6 (K)).
    #[cfg(feature = "kat")]
    mk_digests: Vec<[u8; 32]>,
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
            overlap_send: Vec::new(),
            overlap_recv: Vec::new(),
            outbox,
            persist,
            source,
            plan: VecDeque::new(),
            controls: BTreeMap::new(),
            next_control: 0,
            inflight: BTreeMap::new(),
            by_cell: BTreeMap::new(),
            relayed_cells: BTreeMap::new(),
            next_token: 0,
            next_seq: 1,
            unix_base,
            last_now_ms: 0,
            inbox: Inbox::new(),
            trust: Trust::Verified,
            peer,
            peer_iks: None,
            prev_peer: None,
            seen: BTreeSet::new(),
            received: Vec::new(),
            receipts_due: Vec::new(),
            send_receipts: true,
            discarded: 0,
            block: None,
            handshake_out: VecDeque::new(),
            awaiting_first_reply: false,
            events: Vec::new(),
            relayed_at: BTreeMap::new(),
            notified: BTreeSet::new(),
            receipt_timeout_ms: 0,
            app_rules: true,
            #[cfg(feature = "kat")]
            mk_digests: Vec::new(),
        }
    }

    /// A conversation over the durable state `parts` (a session's rows, CS-3.7): the ratchet state is rebuilt from them,
    /// the reassembly state and the trust restored. `RatchetState::from_parts` is called here only (SE-18).
    ///
    /// # Errors
    /// [`SourceError`] if the parts are not a ratchet state or the inbox does not decode.
    pub fn from_parts(
        parts: &RatchetParts,
        inbox: Option<&[u8]>,
        trust: Trust,
        (outbox, persist, source): (O, P, S),
        peer: HybridVerifyingKey,
        unix_base: u64,
    ) -> Result<Self, SourceError> {
        let state = RatchetState::from_parts(parts).map_err(|_| SourceError)?;
        let mut conversation = Self::new(state, outbox, persist, source, peer, unix_base);
        conversation.trust = trust;
        if let Some(bytes) = inbox {
            conversation.inbox = Inbox::from_bytes(bytes).map_err(|_| SourceError)?;
        }
        Ok(conversation)
    }

    /// Plan a control content of the session (not a user message) as one cell of `owner`: it is sealed on a coming slot
    /// like every cell, through the same path; it is not held by the trust or by a reset (a reset request is sent from
    /// `Frozen`, SE-15), but it waits for the first reply of an initiator (IN-15, Q210 e).
    fn plan_control(&mut self, body: ContentBody, owner: Owner) {
        let seq = self.take_seq();
        let ts = self.ts(self.last_now_ms);
        self.plan.push_back(Planned {
            content: Content { seq, ts, body },
            owner,
            total: 1,
        });
    }

    /// Announce `routes` to the peer (`RouteUpdate`, spec §9.8, §10.6 (5)), in memory only — test kit (Q226); the
    /// product's `RouteUpdate`s are durable ([`Conversation::queue_pending`]). A body that does not encode is not planned.
    #[cfg(any(test, feature = "kat"))]
    pub fn queue_route_update(&mut self, routes: Vec<RouteDescriptor>) {
        self.add_control(PendingControl::Routes(RouteUpdateBody { routes }), None)
            .ok();
    }

    /// Send `Control{code}` without an argument (spec §7.6 codes 1 and 2; ADR-054 item 4), in memory only (see
    /// [`Conversation::queue_pending`]). A body that does not encode is not planned.
    pub fn queue_control(&mut self, code: ControlCode) {
        self.add_control(PendingControl::Control(code), None).ok();
    }

    /// Announce a new identity (`KeyChange`, spec §7.7): 5390 bytes, always fragmented, signed by the old `IK_sig`; in
    /// memory only (see [`Conversation::queue_pending`]).
    ///
    /// # Errors
    /// [`SourceError`] without randomness for the message id or if the body does not encode.
    pub fn queue_key_change(&mut self, body: KeyChangeBody) -> Result<(), SourceError> {
        self.add_control(PendingControl::KeyChange(body), None)
    }

    /// Plan the pending control content stored at `ord` (Q210 c, Q222): planned as a `RouteUpdate`,
    /// [`Conversation::queue_control`] or [`Conversation::queue_key_change`] plan it; its row lives until the last cell's
    /// `OK_SEND` and goes at the next preparation. The host calls this after the commit that wrote the row, and on open
    /// for every row.
    ///
    /// # Errors
    /// [`SourceError`] as [`Conversation::queue_key_change`].
    pub fn queue_pending(&mut self, ord: i64, content: PendingControl) -> Result<(), SourceError> {
        self.add_control(content, Some(ord))
    }

    /// Whether a `KeyChange` of this conversation is live: unplanned, planned, on the way, relayed and still in the eviction
    /// window of its cells, or possibly stranded on an old send queue (Q222, Q240, Q241, OPEN-M7-B-12). Its durable row
    /// lives as long, so an open rebuilds this from the rows.
    #[must_use]
    pub fn key_change_in_flight(&self) -> bool {
        self.controls.values().any(|e| is_key_change(&e.row))
    }

    /// Keep `content` as a control content until its last `OK_SEND` and plan its first attempt (Q222 (1); spec §9.5,
    /// §10.6). `ord` is its durable row.
    fn add_control(
        &mut self,
        content: PendingControl,
        ord: Option<i64>,
    ) -> Result<(), SourceError> {
        let row = content.encode()?;
        if matches!(content, PendingControl::Routes(_)) {
            self.retire_routes();
        }
        let id = self.next_control;
        self.next_control = self.next_control.saturating_add(1);
        self.controls.insert(
            id,
            ControlEntry {
                row,
                ord,
                durable: ord.is_some(),
                attempt: 0,
                total: 0,
                relayed: 0,
                done: false,
                retired: false,
                stranded: Vec::new(),
                unknown: Vec::new(),
            },
        );
        match self.plan_content(ControlRef { id, attempt: 0 }, content) {
            Ok(total) => {
                if let Some(e) = self.controls.get_mut(&id) {
                    e.total = total;
                }
                Ok(())
            }
            Err(_) if ord.is_some() => {
                // Q240 (OPEN-M7-B-19): a durable content stays without cells (`total` 0; a `KeyChange` keeps the guard)
                // and is planned at the next preparation
                Ok(())
            }
            Err(e) => {
                // an in-memory content that cannot be planned is not kept
                self.controls.remove(&id);
                Err(e)
            }
        }
    }

    /// Q240: plan the current attempt of the entry `id` that has no planned cells.
    fn plan_unplanned(&mut self, id: u64) {
        let Some(entry) = self.controls.get(&id) else {
            return;
        };
        let r = ControlRef {
            id,
            attempt: entry.attempt,
        };
        if let Ok(total) = PendingControl::decode(&entry.row).and_then(|c| self.plan_content(r, c))
            && let Some(e) = self.controls.get_mut(&id)
        {
            e.total = total;
        }
    }

    /// Q224 (spec §7.6 docs/03:502, §10.6 (5)): a `RouteUpdate` replaces the routes by which the peer reaches us — every
    /// Routes entry already kept is retired before the newer one is planned.
    fn retire_routes(&mut self) {
        let ids: Vec<u64> = self
            .controls
            .iter()
            .filter(|(_, e)| e.row.first() == Some(&1))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.plan
                .retain(|p| !matches!(p.owner, Owner::Control(c) if c.id == id));
            let Some(e) = self.controls.get_mut(&id) else {
                continue;
            };
            e.retired = true;
            if let Some(o) = e.ord
                && self.persist.control_relayed(o).is_ok()
            {
                e.ord = None;
            }
            if e.ord.is_none() {
                self.controls.remove(&id);
            }
        }
    }

    /// Plan the cells of the attempt `r` of `content`; returns how many (a `RouteUpdate` and a `Control` take one cell).
    fn plan_content(&mut self, r: ControlRef, content: PendingControl) -> Result<u16, SourceError> {
        match content {
            PendingControl::Routes(body) => {
                self.plan_control(ContentBody::RouteUpdate(body), Owner::Control(r));
                Ok(1)
            }
            PendingControl::Control(code) => {
                self.plan_control(
                    ContentBody::Control(secmp_proto::wire::cell::ControlBody {
                        code,
                        arg: Zeroizing::new(Vec::new()),
                    }),
                    Owner::Control(r),
                );
                Ok(1)
            }
            PendingControl::KeyChange(body) => self.plan_key_change(body, Owner::Control(r)),
        }
    }

    /// Plan the attempt `r` of a control content once more (Q222 (3), spec §9.5, §10.6): an outcome of a superseded attempt
    /// or of a retired `RouteUpdate` (Q224) plans nothing; else every cell of the content is sealed anew under a new
    /// attempt, and a durable content whose row went writes it again (its cells wait until it is written, Q225).
    fn replan_control(&mut self, r: ControlRef) {
        let Some(entry) = self.controls.get_mut(&r.id) else {
            return;
        };
        if entry.retired || entry.attempt != r.attempt {
            return;
        }
        entry.attempt = entry.attempt.saturating_add(1);
        entry.relayed = 0;
        entry.done = false;
        if entry.ord.is_none() && entry.durable {
            match self.persist.control_requeued(&entry.row) {
                Ok(Some(o)) => entry.ord = Some(o),
                // this durability keeps no rows (MemPersist without mirror)
                Ok(None) => entry.durable = false,
                // retried at the next prepare; its cells wait (Q225)
                Err(_) => {}
            }
        }
        let attempt = entry.attempt;
        let content = PendingControl::decode(&entry.row);
        self.plan
            .retain(|p| !matches!(p.owner, Owner::Control(c) if c.id == r.id));
        // a content that does not plan is planned at the next preparation (Q240)
        let planned = content.and_then(|c| self.plan_content(ControlRef { id: r.id, attempt }, c));
        if let Some(e) = self.controls.get_mut(&r.id) {
            match planned {
                Ok(total) => e.total = total,
                Err(_) => e.total = 0,
            }
        }
    }

    /// Settle the control contents before the next seal (Q222 (2); the scheduler reports an `OK_SEND` as `relayed`, then
    /// the evictions it names, so a row goes only at the next preparation): a durable content planned again whose row
    /// could not be written again writes it now; the row of a content whose cells all have their `OK_SEND` goes (a
    /// failed delete is tried again at the next preparation); a settled content is dropped once no cell of its current
    /// attempt is in the eviction window; the row of a retired `RouteUpdate` (Q224) goes the same way, and the entry is
    /// dropped once its row is gone; the row of a newer `RouteUpdate` stays while a retired one still holds its row
    /// (Q230: a crash in between must not leave the older row alone).
    ///
    /// A `KeyChange` keeps its row and its entry until no copy can reach the peer any more (Q240, Q241): every cell of its
    /// current attempt has its `OK_SEND`, none of them is in the eviction window, and no copy is stranded on an old send
    /// queue. Its row then goes, and the entry with it — so a restart before that re-reads the row (one more copy, a no-op at
    /// the peer, ADR-058), and a restart after it re-sends nothing.
    fn settle_controls(&mut self) {
        let unplanned: Vec<u64> = self
            .controls
            .iter()
            .filter(|(_, e)| e.total == 0 && !e.retired)
            .map(|(id, _)| *id)
            .collect();
        for id in unplanned {
            self.plan_unplanned(id);
        }
        let by_cell = &self.by_cell;
        let windowed = |id: u64, e: &ControlEntry| {
            by_cell.values().any(
                |s| matches!(s.owner, Owner::Control(c) if c.id == id && c.attempt == e.attempt),
            )
        };
        let held =
            |id: u64, e: &ControlEntry| is_key_change(&e.row) && (windowed(id, e) || e.marked());
        let retired_row = self.controls.values().any(|e| e.retired && e.ord.is_some());
        for (id, e) in &mut self.controls {
            let id = *id;
            if !e.done && e.durable && e.ord.is_none() {
                match self.persist.control_requeued(&e.row) {
                    Ok(Some(o)) => e.ord = Some(o),
                    // this durability keeps no rows (MemPersist without mirror)
                    Ok(None) => e.durable = false,
                    // retried at the next prepare; its cells wait (Q225)
                    Err(_) => {}
                }
            }
            if (e.retired
                || (e.done && !held(id, e) && !(retired_row && e.row.first() == Some(&1))))
                && let Some(o) = e.ord
                && self.persist.control_relayed(o).is_ok()
            {
                e.ord = None;
            }
        }
        self.controls.retain(|id, e| {
            if e.retired {
                e.ord.is_some()
            } else {
                !e.done || e.ord.is_some() || windowed(*id, e) || e.marked()
            }
        });
    }

    fn plan_key_change(&mut self, body: KeyChangeBody, owner: Owner) -> Result<u16, SourceError> {
        let id: MsgId = *self
            .source
            .entropy()
            .secret::<16>()
            .map_err(|_| SourceError)?
            .expose_secret();
        let bytes = FragmentPayload::KeyChange(body)
            .encode()
            .map_err(|_| SourceError)?;
        let chunks = split_chunks(&bytes);
        let total = u16::try_from(chunks.len()).map_err(|_| SourceError)?;
        let owners = core::iter::repeat_n(owner, chunks.len());
        for ((idx, chunk), owner) in chunks.into_iter().enumerate().zip(owners) {
            let seq = self.take_seq();
            let ts = self.ts(self.last_now_ms);
            self.plan.push_back(Planned {
                content: Content {
                    seq,
                    ts,
                    body: ContentBody::Fragment(Fragment {
                        msg_id: id,
                        idx: u16::try_from(idx).map_err(|_| SourceError)?,
                        total,
                        chunk: Zeroizing::new(chunk.to_vec()),
                    }),
                },
                owner,
                total,
            });
        }
        Ok(total)
    }

    /// This conversation is an initiator's that has not heard from the responder yet: the three handshake cells go out
    /// first, on the slots of the invitation queue, byte for byte as persisted (§6.5, IN-14); until the first reply is
    /// decrypted every other cell is a dummy (IN-15).
    pub fn queue_handshake(&mut self, cells: &[Cell; 3]) {
        self.handshake_out = cells.iter().map(|c| c.as_bytes().to_vec()).collect();
        self.awaiting_first_reply = true;
    }

    /// Whether the first reply of the responder is still awaited.
    #[must_use]
    pub const fn awaiting_first_reply(&self) -> bool {
        self.awaiting_first_reply
    }

    /// The trust changed outside a received cell (the user verified the safety number, or a key change was re-verified).
    ///
    /// A frozen session stays frozen (spec §7.7, §7.8): only a new invitation helps, no call here un-freezes it.
    pub fn set_trust(&mut self, trust: Trust) {
        if self.trust != Trust::Frozen {
            self.trust = trust;
        }
    }

    /// Test kit only: this conversation delivers the M6/M7 harness payloads ADR-054 items 1 and 3 drop (binary, NUL,
    /// empty, over 16 KiB, kinds 2, 4, 5, 6); not in a product build (ADR-054, CLAUDE.md §1.5).
    #[cfg(any(test, feature = "kat"))]
    pub const fn raw_app_payloads_kat(&mut self) {
        self.app_rules = false;
    }

    /// The identity the contact row holds (`current`, whose `IK_sig` is the conversation's peer key) and the `IK_sig` the
    /// contact had before its last accepted `KeyChange` (`previous`): a `KeyChange` naming `current` and signed by
    /// `previous` is the accepted succession again and changes nothing (ADR-058, spec §7.7).
    pub fn set_peer_identity(&mut self, current: IksPublic, previous: Option<HybridVerifyingKey>) {
        self.peer_iks = Some(current);
        self.prev_peer = previous;
    }

    /// `T_RS` of this conversation in ms (0: none).
    pub const fn set_receipt_timeout_ms(&mut self, ms: u64) {
        self.receipt_timeout_ms = ms;
    }

    /// The session was reset or the contact removed us: real content is refused (dummies go on).
    pub const fn mark_removed(&mut self) {
        self.block = Some(Refusal::Removed);
    }

    /// A session reset was asked for.
    pub const fn mark_reset(&mut self) {
        self.block = Some(Refusal::Reset);
    }

    /// The block of this session (`Removed`, `Reset`), restored from its trust row or set by a request.
    pub const fn restore_block(&mut self, block: Option<Refusal>) {
        if block.is_some() {
            self.block = block;
        }
    }

    /// The one entry through which real content (a message, a fragment, a receipt) reaches a cell: `Ok` if it may be
    /// sealed now. SE-17 (F29): everything that is not a dummy asks here, and [`Conversation::seal`] is the only seal.
    ///
    /// # Errors
    /// [`Refusal`] naming why not.
    pub const fn may_send_real(&self) -> Result<(), Refusal> {
        if let Some(why) = self.block {
            Err(why)
        } else if !self.trust.may_send_real() {
            Err(Refusal::Trust)
        } else if self.awaiting_first_reply {
            Err(Refusal::AwaitingReply)
        } else {
            Ok(())
        }
    }

    /// The events of the cells received since the last call (see [`SessionEvent`]).
    pub fn take_events(&mut self) -> Vec<SessionEvent> {
        core::mem::take(&mut self.events)
    }

    /// The process died and restarted from `durable` (a serialised ratchet state, e.g. `MemPersist::durable`): what was in
    /// flight — planned cells, tokens, the cell-id map — is gone, a message that was being sent is waiting again
    /// ([`Outbox::restart`]); the outbox, the delivered messages, the queues and the trust survive.
    ///
    /// # Errors
    /// [`SourceError`] if `durable` is not a ratchet state.
    pub fn restart_from(mut self, durable: &[u8]) -> Result<Self, SourceError> {
        let state = RatchetState::from_bytes(durable).map_err(|_| SourceError)?;
        self.outbox.restart();
        self.state = Some(state);
        self.durable = Zeroizing::new(durable.to_vec());
        self.plan.clear();
        self.controls.clear();
        self.inflight.clear();
        self.by_cell.clear();
        self.relayed_cells.clear();
        Ok(self)
    }

    /// The messages already delivered by an earlier run (the history of the store): the dedup set after a restart.
    pub fn seed_seen(&mut self, ids: impl IntoIterator<Item = MsgId>) {
        self.seen.extend(ids);
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

    /// A rotation made `new` the queue we receive on; the previous one stays in overlap, its cells are this conversation's
    /// until [`Conversation::drop_recv_queue`] (spec §10.6 (4)).
    pub fn rotate_recv_queue(&mut self, new: QueueId) {
        if let Some(old) = self.recv_queue.replace(new)
            && old != new
            && !self.overlap_recv.contains(&old)
        {
            self.overlap_recv.push(old);
        }
    }

    /// The overlap queue `queue` is gone (its `QUEUE_DEL` ran).
    pub fn drop_recv_queue(&mut self, queue: QueueId) {
        self.overlap_recv.retain(|q| *q != queue);
        if self.recv_queue == Some(queue) {
            self.recv_queue = None;
        }
    }

    /// The peer's `RouteUpdate` moved us to the queue `new` (spec §10.6 (4)): the old queue carries dummies only from now on
    /// ([`Conversations`] prepares those), and every real message among the last `QUEUE_CAPACITY` cells sent on it goes
    /// back to the outbox, to be sent again on the new queue — the receiver deduplicates by `msg_id` — and every control
    /// content that is not retired and either has a cell of its current attempt without `OK_SEND` or one among those last
    /// `QUEUE_CAPACITY` cells (settled, but stranded on the old queue) is planned again for the new queue (Q222 (3), Q-5,
    /// Q238): a row that went is written again before its cells are sealed (Q225), a repeated `KeyChange` is a no-op at the
    /// peer (ADR-058), a repeated `RouteUpdate` registers nothing there (Q222, Q236).
    /// Returns how many messages were requeued.
    pub fn switch_send_queue(&mut self, new: QueueId) -> usize {
        let previous = self.send_queue.replace(new);
        if let Some(old) = previous
            && old != new
            && !self.overlap_send.contains(&old)
        {
            self.overlap_send.push(old);
        }
        let newest = self.by_cell.keys().next_back().copied().unwrap_or(0);
        let floor = newest.saturating_sub(
            u64::try_from(secmp_proto::link::QUEUE_CAPACITY.saturating_sub(1)).unwrap_or(0),
        );
        let ids: BTreeSet<MsgId> = self
            .by_cell
            .range(floor..)
            .filter_map(|(_, sent)| match &sent.owner {
                Owner::Message(id) => Some(*id),
                _ => None,
            })
            .collect();
        let stranded: Vec<ControlRef> = self
            .by_cell
            .range(floor..)
            .filter_map(|(_, sent)| match sent.owner {
                Owner::Control(c) => Some(c),
                _ => None,
            })
            .collect();
        // Q241 (D-B72): a `KeyChange` cell among the old queue's last QUEUE_CAPACITY cells may still be fetched from there
        if let Some(old) = previous.filter(|old| *old != new) {
            let cells: Vec<(u64, u64)> = self
                .by_cell
                .range(floor..)
                .filter_map(|(cell_id, sent)| match sent.owner {
                    Owner::Control(c) => Some((c.id, *cell_id)),
                    _ => None,
                })
                .collect();
            for (id, cell_id) in cells {
                self.mark_stranded(id, old, cell_id);
            }
        }
        for id in &ids {
            self.outbox.requeue(id);
        }
        // a cell still in flight on the old queue only drops its token (overlap branch): without this re-plan an
        // unsettled control content would never settle (§10.6 (4), Q222 (3)); a settled one whose cells are among the old
        // queue's last QUEUE_CAPACITY cells is not known to be fetched, and the old queue's evictions are not reported
        // back (Q238)
        let open: Vec<ControlRef> = self
            .controls
            .iter()
            .map(|(id, e)| {
                let r = ControlRef {
                    id: *id,
                    attempt: e.attempt,
                };
                // a retired `RouteUpdate` is not planned again (`replan_control`, Q224)
                (r, !e.done || stranded.contains(&r))
            })
            .filter_map(|(r, again)| again.then_some(r))
            .collect();
        for r in open {
            self.replan_control(r);
        }
        // the new queue numbers its cells from 1
        self.by_cell.clear();
        ids.len()
    }

    /// Q241: the `KeyChange` entry `id` may have its cell `cell_id` waiting on the old send queue `queue`.
    fn mark_stranded(&mut self, id: u64, queue: QueueId, cell_id: u64) {
        if let Some(e) = self.controls.get_mut(&id)
            && is_key_change(&e.row)
        {
            e.stranded.push((queue, cell_id));
        }
    }

    /// `OK_SEND` of the cell `cell_id` on `queue`, a queue in send overlap (Q241): a `KeyChange` cell that was on the way
    /// there at the switch is marked stranded; a stranded cell `QUEUE_CAPACITY` or more ids older has left that queue
    /// (fetched or evicted, spec §9.5).
    fn on_overlap_relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        if let Some(Sent {
            owner: Owner::Control(c),
            ..
        }) = self.inflight.remove(&token.0)
        {
            self.mark_stranded(c.id, queue, cell_id);
        }
        self.count_stranded(queue, token, cell_id);
    }

    /// An `OK_SEND` of `cell_id` for the cell of `token` on `queue` (Q241): a cell of unknown outcome (see
    /// [`Conversation::on_unknown_send`]) prepared before this one takes this id — it was written to `queue` earlier, and
    /// the relay numbers a queue's cells in the order they arrive, so if it was stored it has a lower one (an answer to a
    /// cell prepared before it, handed over after the failure, names no id for it); a mark `QUEUE_CAPACITY` or more ids
    /// older has left the queue (fetched or evicted, spec §9.5).
    fn count_stranded(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        let capacity = u64::try_from(secmp_proto::link::QUEUE_CAPACITY).unwrap_or(u64::MAX);
        for e in self.controls.values_mut() {
            let before = e.unknown.len();
            e.unknown.retain(|(q, t)| *q != queue || *t >= token.0);
            if e.unknown.len() < before {
                e.stranded.push((queue, cell_id));
            }
            e.stranded
                .retain(|(q, stranded)| *q != queue || cell_id < stranded.saturating_add(capacity));
        }
    }

    /// The `SEND` of `token` on `queue` ended without an answer (`SendFailure::Unknown`: the link went down first): the
    /// relay may have stored the cell under an id not known here, so a `KeyChange` cell is marked on `queue` until an
    /// `OK_SEND` there of a cell prepared after it names an id for it (Q241).
    fn on_unknown_send(&mut self, queue: QueueId, token: CellToken) {
        if let Some(Sent {
            owner: Owner::Control(c),
            ..
        }) = self.inflight.get(&token.0)
            && let Some(e) = self.controls.get_mut(&c.id)
            && is_key_change(&e.row)
        {
            e.unknown.push((queue, token.0));
        }
    }

    /// The queue `queue` (in send overlap, or the current one) is gone at the relay (`ERR_NOQUEUE`): no copy waits there
    /// any more (Q241).
    fn on_overlap_lost(&mut self, queue: QueueId) {
        for e in self.controls.values_mut() {
            e.stranded.retain(|(q, _)| *q != queue);
            e.unknown.retain(|(q, _)| *q != queue);
        }
    }

    /// The old queue `queue` is no longer sent to. A `KeyChange` copy marked stranded there stays marked (Q241): nothing
    /// shows that it has left the queue.
    pub fn drop_send_queue(&mut self, queue: QueueId) {
        self.overlap_send.retain(|q| *q != queue);
    }

    /// The queue we receive on and the ones in overlap (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn recv_queues_kat(&self) -> (Option<QueueId>, Vec<QueueId>) {
        (self.recv_queue, self.overlap_recv.clone())
    }

    /// `T_RS` of this conversation in ms (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn receipt_timeout_ms_kat(&self) -> u64 {
        self.receipt_timeout_ms
    }

    /// The queue we send to and the ones in send overlap (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn send_queues_kat(&self) -> (Option<QueueId>, Vec<QueueId>) {
        (self.send_queue, self.overlap_send.clone())
    }

    /// Whether receipts are sent (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn send_receipts_kat(&self) -> bool {
        self.send_receipts
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

    /// The messages delivered to the application since the last call; the application stores them (the `Api` writes the
    /// history, or holds a view-once in memory).
    pub fn take_received(&mut self) -> Vec<Received> {
        core::mem::take(&mut self.received)
    }

    /// The trust in the contact's identity (a key change moves it).
    #[must_use]
    pub const fn trust(&self) -> Trust {
        self.trust
    }

    /// Messages in reassembly (fragments received, message not complete).
    #[must_use]
    pub fn partials(&self) -> usize {
        self.inbox.partials()
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

    /// Whether something real waits for a slot: a planned cell, a queued message, a receipt (a control cell held for its
    /// durable row, Q225, counts as waiting).
    #[must_use]
    pub fn has_pending_real(&self) -> bool {
        !self.plan.is_empty()
            || self.outbox.waiting() > 0
            || (self.send_receipts && !self.receipts_due.is_empty())
    }

    /// How many cell ids are mapped to what they carried (S-32).
    #[must_use]
    pub fn mapped_cells(&self) -> usize {
        self.by_cell.len()
    }

    /// SHA-256 of the message key of every cell this conversation sealed — real, dummy, receipt, including cells that
    /// were never written — in sealing order (feature `kat`): the sender's side of the H-12 method (no key used twice).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn message_key_digests_kat(&self) -> &[[u8; 32]] {
        &self.mk_digests
    }

    /// The last durable ratchet state.
    #[must_use]
    pub fn durable(&self) -> &[u8] {
        &self.durable
    }

    fn ts(&self, now_ms: u64) -> u64 {
        self.unix_base
            .saturating_add(now_ms.checked_div(1000).unwrap_or(0))
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
        #[cfg(feature = "kat")]
        let digest = sealed.message_key_digest_kat();
        let new_durable = &mut self.durable;
        let persist = &mut self.persist;
        let result = sealed.persist(|bytes| {
            counters::note_persist();
            let ratchet = RatchetParts::split(bytes).map_err(|_| PersistError)?;
            persist.commit_parts(
                PersistKind::Send,
                &CommitParts {
                    ratchet: &ratchet,
                    inbox: None,
                    trust: None,
                    block: None,
                    identity: None,
                    previous_identity: None,
                    delivered: &[],
                    receipted: &[],
                    routes: None,
                    clear_handshake: false,
                },
            )?;
            *new_durable = Zeroizing::new(bytes.to_vec());
            Ok::<(), PersistError>(())
        });
        if let Ok((state, cell)) = result {
            // a key counts as used once its state is durable: a cell that was never persisted was never released
            #[cfg(feature = "kat")]
            self.mk_digests.push(digest);
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
            Owner::Handshake(bytes) => self.handshake_out.push_front(bytes.clone()),
            // the whole content again (Q222 (3))
            Owner::Control(r) => self.replan_control(*r),
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

    /// Decide a received cell of this conversation (what the scheduler's `deliver` does), for callers that drive a
    /// conversation by hand: decrypted, processed, committed — then it counts as decided.
    ///
    /// # Errors
    /// [`SourceError`] if the new state could not be committed: nothing is decided, the cell comes again.
    pub fn deliver_direct(&mut self, cell: &Cell) -> Result<(), SourceError> {
        self.on_deliver(cell)
    }

    /// `OK_SEND` for the cell of `token` (what the scheduler's `relayed` does), for callers that drive a conversation by
    /// hand.
    pub fn relayed_direct(&mut self, token: CellToken, cell_id: u64) {
        self.on_relayed(token, cell_id);
    }

    /// Plan `body` as session content without a durable row (tests only: a content the product never plans).
    #[cfg(test)]
    pub(crate) fn queue_raw_content_test(&mut self, body: ContentBody) {
        self.plan_control(body, Owner::Dummy);
    }

    /// The relay evicted the cell `cell_id` (what the scheduler's `evicted` does; tests only).
    #[cfg(test)]
    pub(crate) fn evicted_direct(&mut self, cell_id: u64) {
        self.on_evicted(cell_id);
    }

    /// The queue we send to was lost (what the scheduler's `queue_lost` does; tests only).
    #[cfg(test)]
    pub(crate) fn lost_direct(&mut self) {
        self.on_lost();
    }

    /// How many control contents are kept (tests only).
    #[cfg(test)]
    pub(crate) fn live_controls_test(&self) -> usize {
        self.controls.len()
    }

    /// The `SEND` of the cell of `token` failed or was discarded (what the scheduler's `send_failed` and `discard` do;
    /// tests only).
    #[cfg(test)]
    pub(crate) fn failed_direct(&mut self, token: CellToken) {
        self.on_failed(token);
    }

    /// A dummy for a queue in send overlap: sealed by the same path as every cell, never real content and never a handshake
    /// cell (spec §10.6 (4): "only dummies on the old queue").
    fn prepare_overlap(&mut self, now_ms: u64) -> Result<PreparedCell, SourceError> {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        let cell = self.seal(&dummy())?;
        let token = self.next_token;
        self.next_token = self.next_token.saturating_add(1);
        self.inflight.insert(
            token,
            Sent {
                owner: Owner::Dummy,
                total: 1,
            },
        );
        Ok(PreparedCell::committed(cell, CellToken(token)))
    }

    fn prepare(&mut self, now_ms: u64) -> Result<PreparedCell, SourceError> {
        // the rows of control contents whose cells all have their `OK_SEND` go before the next seal (Q222 (2))
        self.settle_controls();
        self.last_now_ms = self.last_now_ms.max(now_ms);
        self.outbox.expire(now_ms);
        self.note_unconfirmed(now_ms);
        // an initiator's handshake cells go first, as persisted (they are already sealed and durable, §6.5)
        if let Some(bytes) = self.handshake_out.pop_front() {
            let cell = Cell::from_bytes(&bytes).map_err(|_| SourceError)?;
            let token = self.next_token;
            self.next_token = self.next_token.saturating_add(1);
            self.inflight.insert(
                token,
                Sent {
                    owner: Owner::Handshake(bytes),
                    total: 1,
                },
            );
            return Ok(PreparedCell::committed(cell, CellToken(token)));
        }
        // SE-17 per cell (Q210 e): planned real content — a message's fragments, a receipt — is sealed only while real
        // sends are allowed; a trust or a block that changed since it was planned holds it again
        if matches!(
            self.may_send_real(),
            Err(Refusal::Trust | Refusal::Removed | Refusal::Reset)
        ) {
            self.hold_planned_real();
        }
        let sendable = self
            .plan
            .iter()
            .position(|p| !row_missing(&self.controls, &p.owner));
        if sendable.is_none() && self.may_send_real().is_ok() {
            if self.send_receipts && !self.receipts_due.is_empty() {
                self.plan_receipt(now_ms);
            } else if let Some(message) = self.outbox.take_next() {
                self.plan_message(&message, now_ms);
            }
        }
        // until the first reply of the responder only dummies: control content waits too (IN-15)
        let next = if self.awaiting_first_reply {
            None
        } else {
            self.plan
                .iter()
                .position(|p| !row_missing(&self.controls, &p.owner))
                .and_then(|i| self.plan.remove(i))
        };
        let from_plan = next.is_some();
        let planned = next.unwrap_or(Planned {
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
                Ok(PreparedCell::committed(cell, CellToken(token)))
            }
            Err(e) => {
                // control content goes back to the front; a message or a receipt to where it came from
                if from_plan && matches!(planned.owner, Owner::Control(_) | Owner::Dummy) {
                    self.plan.push_front(planned);
                } else {
                    self.restore(&planned.owner);
                }
                Err(e)
            }
        }
    }

    /// The planned messages and receipts go back to the outbox and the due receipts (held while real sends are refused,
    /// Q210 e); control content stays planned.
    fn hold_planned_real(&mut self) {
        let mut held: Vec<Owner> = Vec::new();
        for p in &self.plan {
            let seen = match &p.owner {
                Owner::Message(id) => held
                    .iter()
                    .any(|o| matches!(o, Owner::Message(m) if m == id)),
                Owner::Receipt(_) => false,
                Owner::Dummy | Owner::Handshake(_) | Owner::Control(_) => true,
            };
            if !seen {
                held.push(p.owner.clone());
            }
        }
        self.plan.retain(|p| {
            matches!(
                p.owner,
                Owner::Dummy | Owner::Handshake(_) | Owner::Control(_)
            )
        });
        for owner in held.iter().rev() {
            self.restore(owner);
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
                self.relayed_at.insert(*id, self.last_now_ms);
            }
        }
        // a cell of the current attempt of a control content: done once all its cells have their `OK_SEND` (Q222 (2));
        // a superseded attempt counts nothing
        if let Owner::Control(r) = &sent.owner
            && let Some(e) = self.controls.get_mut(&r.id)
            && e.attempt == r.attempt
        {
            e.relayed = e.relayed.saturating_add(1);
            if e.relayed >= e.total {
                e.done = true;
            }
        }
        self.by_cell.insert(cell_id, sent);
        // an evicted id is always among the newest `QUEUE_CAPACITY`: older entries are dead weight
        let floor = cell_id.saturating_sub(256);
        self.by_cell = self.by_cell.split_off(&floor);
        if let Some(queue) = self.send_queue {
            self.count_stranded(queue, token, cell_id);
        }
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
            if !matches!(p.owner, Owner::Control(_)) {
                self.restore(&p.owner);
            }
        }
        self.relayed_cells.clear();
        // every control content again, sealed or not, in id order (spec §10.4, Q222 (3)); a retired `RouteUpdate` stays
        // retired (Q224)
        let all: Vec<ControlRef> = self
            .controls
            .iter()
            .map(|(id, e)| ControlRef {
                id: *id,
                attempt: e.attempt,
            })
            .collect();
        for r in all {
            self.replan_control(r);
        }
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
        // the cell's effect on the reassembly and on the trust is staged on copies: it is kept only once the commit of
        // the new ratchet state succeeded (persist-before-ack: a failed commit leaves everything as it was and the cell
        // comes again)
        let mut inbox = self.inbox.clone();
        let mut trust = self.trust;
        // a repeat of the accepted key change, signed by the previous `IK_sig`, changes nothing (ADR-058)
        let delivery = inbox.receive_known(
            opened.plaintext(),
            &self.peer,
            self.peer_iks.as_ref(),
            self.prev_peer.as_ref(),
            &mut trust,
        );
        // a verified key change whose new `IK_sig` cannot be loaded is unverifiable: the session freezes (spec §7.7)
        let (delivery, new_peer) = admit_key_change(delivery, &mut trust);
        // the identity an admitted key change replaces is durable with it (ADR-058); one that does not encode fails the
        // commit, as the new identity does
        let previous_identity = replaced_identity(&delivery, self.peer_iks.as_ref());
        // the messages this cell delivers for the first time are durable with the state that consumed it
        let received_ms = self
            .unix_base
            .saturating_mul(1000)
            .saturating_add(self.last_now_ms);
        let fresh = self.fresh_messages(&delivery, received_ms);
        // the reassembly state when it is or was non-empty, the trust when it changed: in the same commit (PC-09)
        let inbox_changed = inbox.partials() != 0 || self.inbox.partials() != 0;
        let trust_changed = (trust != self.trust).then_some(trust_code(trust));
        let Effects {
            block,
            receipted,
            routes,
            identity,
        } = effects(&delivery);
        // the first decrypted reply of an initiator: its stored handshake cells go with this commit (Q150)
        let clear_handshake = self.awaiting_first_reply;
        let durable = &mut self.durable;
        let persist = &mut self.persist;
        let staged = &inbox;
        let committed = opened.commit(|bytes| {
            counters::note_persist();
            let ratchet = RatchetParts::split(bytes).map_err(|_| PersistError)?;
            let inbox_bytes = if inbox_changed {
                Some(staged.to_bytes().map_err(|_| PersistError)?)
            } else {
                None
            };
            persist.commit_parts(
                PersistKind::Receive,
                &CommitParts {
                    ratchet: &ratchet,
                    inbox: inbox_bytes.as_ref().map(|b| b.as_slice()),
                    trust: trust_changed,
                    block,
                    identity: identity
                        .as_ref()
                        .map_err(|e| *e)?
                        .as_ref()
                        .map(|(iks, fp)| (iks.as_slice(), fp.as_slice())),
                    delivered: &fresh,
                    receipted: &receipted,
                    routes: routes.as_ref().map(|r| r.as_slice()),
                    clear_handshake,
                    previous_identity: previous_identity
                        .as_ref()
                        .map_err(|e| *e)?
                        .as_ref()
                        .map(|b| b.as_slice()),
                },
            )?;
            *durable = Zeroizing::new(bytes.to_vec());
            Ok::<(), PersistError>(())
        });
        drop(fresh);
        if let Ok((state, _plaintext)) = committed {
            self.state = Some(state);
            self.inbox = inbox;
            self.trust = trust;
            if clear_handshake {
                self.awaiting_first_reply = false;
                self.handshake_out.clear();
            }
        } else {
            self.state = RatchetState::from_bytes(&self.durable).ok();
            return Err(SourceError);
        }
        self.apply_delivery(delivery, new_peer);
        Ok(())
    }

    /// The messages of `delivery` the history does not hold yet, stamped `received_ms`: durable with the state that
    /// consumed their cell. ADR-054 items 1 and 3 (EXTB2-3): an invalid message is dropped, the cell is still committed
    /// and acknowledged.
    fn fresh_messages<'d>(
        &self,
        delivery: &'d Delivery,
        received_ms: u64,
    ) -> Vec<DeliveredMessage<'d>> {
        match delivery {
            Delivery::Messages(messages) => messages
                .iter()
                .filter(|m| !self.app_rules || app_payload_ok(m.kind, &m.payload))
                .filter(|m| !self.seen.contains(&m.msg_id))
                .map(|m| DeliveredMessage {
                    msg_id: m.msg_id,
                    kind: m.kind.byte(),
                    payload: m.payload.as_slice(),
                    expire_after: m.expire_after,
                    received_ms,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// What a committed cell tells the session: messages for the application, receipts, the events for the host.
    fn apply_delivery(&mut self, delivery: Delivery, new_peer: Option<HybridVerifyingKey>) {
        match delivery {
            Delivery::Messages(messages) => {
                for m in messages {
                    // ADR-054 items 1 and 3 first: a dropped message is not taken into the dedup set (EXTB2-3)
                    if (!self.app_rules || app_payload_ok(m.kind, &m.payload))
                        && self.seen.insert(m.msg_id)
                    {
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
                // durable already (in the receive commit); only the in-memory view follows
                for id in &body.msg_ids {
                    self.outbox.delivered_committed(id);
                    self.relayed_at.remove(id);
                }
            }
            Delivery::Routes(rs) => {
                let known: Vec<RouteDescriptor> = rs
                    .into_iter()
                    .filter(|r| matches!(r, RouteDescriptor::RelayQueue(_)))
                    .collect();
                if !known.is_empty() {
                    self.events.push(SessionEvent::Routes(known));
                }
            }
            Delivery::KeyChange(iks) => {
                // the contact row holds the new identity already (the receive commit); later key changes verify under it
                // the replaced key verifies a repeat of this change (ADR-058)
                if let Some(peer) = new_peer {
                    self.prev_peer = Some(core::mem::replace(&mut self.peer, peer));
                }
                self.peer_iks = Some(iks.clone());
                self.events.push(SessionEvent::KeyChanged(Box::new(iks)));
            }
            Delivery::KeyChangeRefused => self.events.push(SessionEvent::KeyChangeInvalid),
            Delivery::Control(body) => match body.code {
                ControlCode::ContactRemoved if body.arg.is_empty() => {
                    self.block = Some(Refusal::Removed);
                    self.events.push(SessionEvent::ContactRemoved);
                }
                // EXTB2-2: a reset request carries no argument (ADR-054 item 4); one with an argument is ignored
                ControlCode::SessionResetRequest if body.arg.is_empty() => {
                    self.block = Some(Refusal::Reset);
                    self.events.push(SessionEvent::ResetRequested);
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// SE-13b (spec §10.4, OPEN-M7-07 A): a message relayed `T_RS` ago with no receipt is reported once, never re-sent —
    /// for a verified contact only: receipts are sent only to verified contacts (SE-12), and our verification of the
    /// contact is the proxy for its verification of us (Q159, Q210 d).
    fn note_unconfirmed(&mut self, now_ms: u64) {
        if self.receipt_timeout_ms == 0 || !matches!(self.trust, Trust::Verified) {
            return;
        }
        let due: Vec<MsgId> = self
            .relayed_at
            .iter()
            .filter(|(id, at)| {
                now_ms.saturating_sub(**at) >= self.receipt_timeout_ms
                    && !self.notified.contains(*id)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            self.notified.insert(id);
            self.relayed_at.remove(&id);
            self.events.push(SessionEvent::NotConfirmed(id));
        }
    }
}

/// `contacts.routes` / `RouteUpdate` bytes of the routes of a known kind: `count u8 ‖ RouteDescriptor × count`; `None`
/// if there is none.
fn routes_bytes(routes: &[RouteDescriptor]) -> Option<Zeroizing<Vec<u8>>> {
    let known: Vec<&RouteDescriptor> = routes
        .iter()
        .filter(|r| matches!(r, RouteDescriptor::RelayQueue(_)))
        .collect();
    let mut out = Zeroizing::new(vec![u8::try_from(known.len()).ok()?]);
    if known.is_empty() {
        return None;
    }
    for r in known {
        out.extend_from_slice(&r.encode().ok()?);
    }
    Some(out)
}

/// The identity an admitted `KeyChange` replaces (`current`, encoded), durable with the new one (ADR-058); `None` for
/// any other delivery or when the conversation does not know the identity. One that does not encode fails the commit, as
/// the new identity does.
fn replaced_identity(
    delivery: &Delivery,
    current: Option<&IksPublic>,
) -> Result<Option<Zeroizing<Vec<u8>>>, PersistError> {
    match (delivery, current) {
        (Delivery::KeyChange(_), Some(cur)) => cur.encode().map(Some).map_err(|_| PersistError),
        _ => Ok(None),
    }
}

/// The peer's new identity of a verified `KeyChange`: the encoded `IksPublic` and its fingerprint.
type NewIdentity = (Zeroizing<Vec<u8>>, [u8; 32]);

/// What a received cell's delivery makes durable besides the ratchet, the reassembly state and the trust (the receive
/// commit, persist-before-ack).
struct Effects {
    /// A `Control{1}` or `Control{2}`, each without an argument: real sends are blocked durably (Q210 b; EXTB2-2).
    block: Option<u8>,
    /// The messages a `Receipt{delivered}` confirms: `Delivered` (SE-21, F9b).
    receipted: Vec<MsgId>,
    /// The routes of a `RouteUpdate`, of the kind this version knows (spec §9.8; an unknown kind is ignored).
    routes: Option<Zeroizing<Vec<u8>>>,
    /// A verified key change's new identity (Q210 a, spec §7.7); one that does not encode fails the commit — nothing is
    /// decided, the cell comes again.
    identity: Result<Option<NewIdentity>, PersistError>,
}

/// A verified key change (spec §7.7) is admitted only if its new `IK_sig` loads (`tr::content::ik_sig`): the key that later
/// key changes verify under is returned with it. Otherwise the change is unverifiable — the session freezes (`trust` becomes
/// `Frozen`), the delivery becomes `KeyChangeRefused` (no identity is committed, the event is `KeyChangeInvalid`) and the
/// peer key stays. Any other delivery passes unchanged.
fn admit_key_change(
    delivery: Delivery,
    trust: &mut Trust,
) -> (Delivery, Option<HybridVerifyingKey>) {
    admit_key_change_with(delivery, trust, secmp_proto::tr::content::ik_sig)
}

/// [`admit_key_change`] with the loader of the `IK_sig` given.
fn admit_key_change_with(
    delivery: Delivery,
    trust: &mut Trust,
    verify: impl FnOnce(&IksPublic) -> Result<HybridVerifyingKey, secmp_proto::Error>,
) -> (Delivery, Option<HybridVerifyingKey>) {
    let Delivery::KeyChange(iks) = delivery else {
        return (delivery, None);
    };
    if let Ok(key) = verify(&iks) {
        return (Delivery::KeyChange(iks), Some(key));
    }
    *trust = Trust::Frozen;
    (Delivery::KeyChangeRefused, None)
}

fn effects(delivery: &Delivery) -> Effects {
    let block = match delivery {
        Delivery::Control(body) => match body.code {
            ControlCode::ContactRemoved if body.arg.is_empty() => block_code(Refusal::Removed),
            ControlCode::SessionResetRequest if body.arg.is_empty() => block_code(Refusal::Reset),
            _ => None,
        },
        _ => None,
    };
    let receipted = match delivery {
        Delivery::Receipt(body) => body.msg_ids.clone(),
        _ => Vec::new(),
    };
    let routes = match delivery {
        Delivery::Routes(rs) => routes_bytes(rs),
        _ => None,
    };
    let identity = match delivery {
        Delivery::KeyChange(iks) => match (iks.encode(), secmp_proto::prekeys::fingerprint_of(iks))
        {
            (Ok(bytes), Ok(fp)) => Ok(Some((bytes, fp))),
            _ => Err(PersistError),
        },
        _ => Ok(None),
    };
    Effects {
        block,
        receipted,
        routes,
        identity,
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

    /// The process holding conversation `index` died and restarted from `durable`
    /// ([`Conversation::restart_from`]).
    ///
    /// # Errors
    /// [`SourceError`] if `durable` is not a ratchet state or there is no such conversation.
    pub fn restart(&mut self, index: usize, durable: &[u8]) -> Result<(), SourceError> {
        if index >= self.items.len() {
            return Err(SourceError);
        }
        let old = self.items.remove(index);
        let restarted = old.restart_from(durable)?;
        self.items.insert(index, restarted);
        Ok(())
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

    /// Whether the conversation that sends on `queue` has something real waiting for a slot (a planned cell, a queued
    /// message, a receipt): the next cell it prepares for `queue` is then a real one, not a dummy (a control cell held
    /// for its durable row, Q225, counts as waiting). For the cost models of the test drivers; the scheduler never asks.
    pub fn pending_real(&mut self, queue: QueueId) -> bool {
        self.by_send(queue).is_some_and(|c| c.has_pending_real())
    }

    fn by_send(&mut self, q: QueueId) -> Option<&mut Conversation<O, P, S>> {
        self.items.iter_mut().find(|c| c.send_queue == Some(q))
    }

    /// The conversation for which `q` is a queue in send overlap (dummies only).
    fn by_overlap_send(&mut self, q: QueueId) -> Option<&mut Conversation<O, P, S>> {
        self.items.iter_mut().find(|c| c.overlap_send.contains(&q))
    }

    fn by_recv(&mut self, q: QueueId) -> Option<&mut Conversation<O, P, S>> {
        self.items
            .iter_mut()
            .find(|c| c.recv_queue == Some(q) || c.overlap_recv.contains(&q))
    }
}

impl<O: Outbox, P: Persist, S: EntropySource> CellSource for Conversations<O, P, S> {
    fn prepare_cell(
        &mut self,
        queue: QueueId,
        now: u64,
    ) -> Result<Option<PreparedCell>, SourceError> {
        if let Some(c) = self.by_send(queue) {
            return c.prepare(now).map(Some);
        }
        // a queue in send overlap carries dummies, from the same ratchet (spec §10.6 (4))
        match self.by_overlap_send(queue) {
            Some(c) => c.prepare_overlap(now).map(Some),
            None => Ok(None),
        }
    }

    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        if let Some(c) = self.by_send(queue) {
            c.on_relayed(token, cell_id);
        } else if let Some(c) = self.by_overlap_send(queue) {
            c.on_overlap_relayed(queue, token, cell_id);
        }
    }

    fn evicted(&mut self, queue: QueueId, cell_id: u64) {
        if let Some(c) = self.by_send(queue) {
            c.on_evicted(cell_id);
        }
    }

    fn send_failed(&mut self, queue: QueueId, token: CellToken, why: SendFailure) {
        let unknown = matches!(why, SendFailure::Unknown);
        if let Some(c) = self.by_send(queue) {
            if unknown {
                c.on_unknown_send(queue, token);
            }
            c.on_failed(token);
        } else if let Some(c) = self.by_overlap_send(queue) {
            if unknown {
                c.on_unknown_send(queue, token);
            }
            c.inflight.remove(&token.0);
        }
    }

    fn discard(&mut self, queue: QueueId, token: CellToken) {
        if let Some(c) = self.by_send(queue) {
            c.on_failed(token);
        } else if let Some(c) = self.by_overlap_send(queue) {
            c.inflight.remove(&token.0);
        }
    }

    fn queue_lost(&mut self, queue: QueueId) {
        if let Some(c) = self.by_send(queue) {
            c.on_lost();
            c.on_overlap_lost(queue);
        } else if let Some(c) = self.by_overlap_send(queue) {
            c.on_overlap_lost(queue);
        }
    }

    fn deliver(
        &mut self,
        queue: QueueId,
        _generation: u64,
        _cell_id: u64,
        cell: &Cell,
    ) -> Result<Delivered, SourceError> {
        match self.by_recv(queue) {
            // decided and committed before it returns
            Some(c) => c.on_deliver(cell).map(|()| Delivered::Committed),
            // a queue without a conversation (a spare of the pool): nothing to decrypt, the cell is discarded
            None => Ok(Delivered::Committed),
        }
    }
}

#[cfg(test)]
mod tests {
    // The module is plain `cfg(test)`; the bodies that need the `kat` accessors are gated inside (a module under
    // `cfg(all(test, feature))` is compiled out of the mutation gate's first run). The tests return `Result`: an in-crate
    // test module has no `unwrap` allowance (only whole files under `tests/` do).

    /// The failure of a step of the fixture.
    #[cfg(feature = "kat")]
    type Fail = &'static str;

    /// A deterministic byte stream for `FixedEntropy` (a counter pushed through a multiplicative mix; not random, not secret).
    #[cfg(feature = "kat")]
    fn stream(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(23) ^ 0x5851_f42d;
                x.to_be_bytes().first().copied().unwrap_or(0)
            })
            .collect()
    }

    /// The entropy source of a test conversation: a fixed stream.
    #[cfg(feature = "kat")]
    struct Fixed(secmp_proto::tr::FixedEntropy);

    #[cfg(feature = "kat")]
    impl super::EntropySource for Fixed {
        type E = secmp_proto::tr::FixedEntropy;

        fn entropy(&mut self) -> &mut Self::E {
            &mut self.0
        }
    }

    /// The initiator's ratchet state of a session from one shared secret.
    #[cfg(feature = "kat")]
    fn initiator_state() -> Result<secmp_proto::tr::RatchetState, Fail> {
        use secmp_crypto::SecretBytes;
        use secmp_proto::keys::{MlKem768Ek, X25519Pk};
        use secmp_proto::tr::{Entropy as _, FixedEntropy, RatchetState};
        let mut responder = FixedEntropy::new(&stream(2, 1 << 16));
        let mut initiator = FixedEntropy::new(&stream(1, 1 << 16));
        let spk_dh = responder.x25519().map_err(|_| "x25519")?;
        let rpk_kem = responder.mlkem768().map_err(|_| "ml-kem")?;
        let spk = X25519Pk::from_bytes(spk_dh.public_key().as_bytes()).map_err(|_| "spk")?;
        let ek =
            MlKem768Ek::from_bytes(rpk_kem.encapsulation_key().as_bytes()).map_err(|_| "ek")?;
        let sk = SecretBytes::from_slice(&[7_u8; 32]).map_err(|_| "secret")?;
        RatchetState::init_initiator_with(&sk, &[9_u8; 32], &spk, &ek, &mut initiator)
            .map_err(|_| "initiator")
    }

    #[cfg(feature = "kat")]
    type TestConversation = super::Conversation<
        crate::scheduler::outbox::MemOutbox,
        crate::scheduler::outbox::MemPersist,
        Fixed,
    >;

    #[cfg(feature = "kat")]
    fn conversation(
        state: secmp_proto::tr::RatchetState,
        persist: crate::scheduler::outbox::MemPersist,
    ) -> Result<TestConversation, Fail> {
        use secmp_proto::tr::{Entropy as _, FixedEntropy};
        let peer = FixedEntropy::new(&stream(3, 1 << 20))
            .hybrid_signing_key()
            .map_err(|_| "peer key")?
            .verifying_key();
        Ok(super::Conversation::new(
            state,
            crate::scheduler::outbox::MemOutbox::new(),
            persist,
            Fixed(FixedEntropy::new(&stream(4, 1 << 20))),
            peer,
            0,
        ))
    }

    /// Run `encrypt_with` of the same dummy content on a twin of the initial state with the same entropy: the digests of
    /// the message keys the conversation must have recorded, in order.
    #[cfg(feature = "kat")]
    fn expected_digests(
        initial: &secmp_proto::tr::RatchetState,
        n: usize,
    ) -> Result<Vec<[u8; 32]>, Fail> {
        use secmp_proto::tr::{FixedEntropy, RatchetState};
        let bytes = initial.to_bytes().map_err(|_| "to_bytes")?;
        let mut state = RatchetState::from_bytes(&bytes).map_err(|_| "from_bytes")?;
        let mut entropy = FixedEntropy::new(&stream(4, 1 << 20));
        let mut out = Vec::new();
        for _ in 0..n {
            let sealed = state
                .encrypt_with(&secmp_proto::tr::content::dummy(), &mut entropy)
                .map_err(|_| "encrypt")?;
            out.push(sealed.message_key_digest_kat());
            let (next, _cell) = sealed
                .persist(|_| Ok::<(), ()>(()))
                .map_err(|()| "persist")?;
            state = next;
        }
        Ok(out)
    }

    /// Run #176 of the mutation gate: `message_key_digests_kat` mutated to an empty or a constant slice survived, because
    /// its only consumers are the simulations (on the skip list of the per-mutant run). It records, in sealing order, the
    /// digest of the message key of every cell the conversation sealed: three seals give three digests, pairwise distinct,
    /// neither of the constants the mutants return, and each the digest of the key of the cell sealed at that position
    /// (`Sealed::message_key_digest_kat` of a twin run of the same seals; dummies, because the content of a dummy is fixed).
    #[test]
    #[cfg(feature = "kat")]
    fn message_key_digests_track_each_seal() -> Result<(), Fail> {
        let state = initiator_state()?;
        let want = expected_digests(&state, 3)?;
        let mut conv = conversation(state, crate::scheduler::outbox::MemPersist::new())?;
        assert!(conv.message_key_digests_kat().is_empty());
        for _ in 0..3 {
            conv.prepare_direct(0).map_err(|_| "seal")?;
        }
        let got = conv.message_key_digests_kat();
        assert_eq!(got.len(), 3);
        for (i, a) in got.iter().enumerate() {
            assert_ne!(*a, [0_u8; 32]);
            assert_ne!(*a, [1_u8; 32]);
            for b in got.iter().skip(i.saturating_add(1)) {
                assert_ne!(a, b, "a message key used twice");
            }
        }
        assert_eq!(
            got,
            want.as_slice(),
            "the digests of the keys, in sealing order"
        );
        Ok(())
    }

    /// A digest is recorded only once its state is durable (a cell whose persist failed was never released): a failing
    /// `Persist` makes the seal an `Err` and the list keeps its length; the next seal after the store recovers records
    /// one digest.
    #[test]
    #[cfg(feature = "kat")]
    fn message_key_digest_not_recorded_when_persist_fails() -> Result<(), Fail> {
        let mut persist = crate::scheduler::outbox::MemPersist::new();
        persist.set_failing(true);
        let mut conv = conversation(initiator_state()?, persist)?;
        assert!(conv.prepare_direct(0).is_err());
        assert!(conv.message_key_digests_kat().is_empty());
        conv.persist_mut().set_failing(false);
        conv.prepare_direct(0).map_err(|_| "seal")?;
        assert_eq!(conv.message_key_digests_kat().len(), 1);
        Ok(())
    }

    /// The `received_ms` of every delivered message a `Persist` was handed.
    #[cfg(feature = "kat")]
    #[derive(Default)]
    struct Stamps(Vec<u64>);

    #[cfg(feature = "kat")]
    impl crate::scheduler::outbox::Persist for Stamps {
        fn commit(
            &mut self,
            _kind: crate::scheduler::outbox::PersistKind,
            _state: &[u8],
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            Ok(())
        }

        fn commit_parts(
            &mut self,
            _kind: crate::scheduler::outbox::PersistKind,
            parts: &crate::scheduler::outbox::CommitParts<'_>,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.0.extend(parts.delivered.iter().map(|m| m.received_ms));
            Ok(())
        }

        fn control_relayed(
            &mut self,
            _ord: i64,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            Ok(())
        }

        fn control_requeued(
            &mut self,
            _row: &[u8],
        ) -> Result<Option<i64>, crate::scheduler::outbox::PersistError> {
            Ok(None)
        }
    }

    /// V1-F4 (extra test): a delivered message carries the Unix ms of the latest slot preparation — `unix_base`·1000 +
    /// the `now_ms` of `prepare`.
    #[test]
    #[cfg(feature = "kat")]
    fn delivered_carries_unix_ms() -> Result<(), Fail> {
        use crate::scheduler::outbox::{MemOutbox, MemPersist, OutMessage, Outbox};
        use crate::scheduler::types::{CellSource, QueueId};
        use secmp_proto::tr::{Entropy as _, FixedEntropy, RatchetState};
        use secmp_proto::wire::cell::AppKind;
        // the two ends of one session (as `initiator_state`, with the responder kept)
        let mut responder = FixedEntropy::new(&stream(2, 1 << 16));
        let mut initiator = FixedEntropy::new(&stream(1, 1 << 16));
        let spk_dh = responder.x25519().map_err(|_| "x25519")?;
        let rpk_kem = responder.mlkem768().map_err(|_| "ml-kem")?;
        let spk = secmp_proto::keys::X25519Pk::from_bytes(spk_dh.public_key().as_bytes())
            .map_err(|_| "spk")?;
        let ek = secmp_proto::keys::MlKem768Ek::from_bytes(rpk_kem.encapsulation_key().as_bytes())
            .map_err(|_| "ek")?;
        let sk = secmp_crypto::SecretBytes::from_slice(&[7_u8; 32]).map_err(|_| "secret")?;
        let a_state =
            RatchetState::init_initiator_with(&sk, &[9_u8; 32], &spk, &ek, &mut initiator)
                .map_err(|_| "initiator")?;
        let b_state = RatchetState::init_responder(&sk, &[9_u8; 32], spk_dh, rpk_kem)
            .map_err(|_| "responder")?;
        let peer = FixedEntropy::new(&stream(3, 1 << 20))
            .hybrid_signing_key()
            .map_err(|_| "peer key")?
            .verifying_key();
        let mut a = super::Conversation::new(
            a_state,
            MemOutbox::new(),
            MemPersist::new(),
            Fixed(FixedEntropy::new(&stream(4, 1 << 20))),
            peer.clone(),
            0,
        );
        a.outbox_mut().enqueue(
            OutMessage {
                msg_id: [5; 16],
                kind: AppKind::Text,
                expire_after: 0,
                payload: secmp_crypto::Zeroizing::new(vec![1; 8]),
            },
            0,
        );
        let cell = a.prepare_direct(0).map_err(|_| "seal")?.cell;
        let mut b = super::Conversation::new(
            b_state,
            MemOutbox::new(),
            Stamps::default(),
            Fixed(FixedEntropy::new(&stream(6, 1 << 20))),
            peer,
            1_700_000_000,
        );
        // the responder's first preparation fails (no sending chain yet) but stamps the time
        let _ = b.prepare_direct(5_000);
        b.bind(QueueId(2), QueueId(1));
        let mut convs = super::Conversations::new();
        convs.add(b);
        convs
            .deliver(QueueId(1), 0, 1, &cell)
            .map_err(|_| "deliver")?;
        let b = convs.get(0).ok_or("conversation")?;
        assert_eq!(b.received().len(), 1, "the text was delivered");
        assert_eq!(b.persist().0, vec![1_700_000_005_000]);
        Ok(())
    }

    /// What a recording `Persist` saw of each receive commit: the reassembly state present, the trust code.
    #[cfg(feature = "kat")]
    #[derive(Default)]
    struct Commits(Vec<(bool, Option<u8>)>);

    #[cfg(feature = "kat")]
    impl crate::scheduler::outbox::Persist for Commits {
        fn commit(
            &mut self,
            _kind: crate::scheduler::outbox::PersistKind,
            _state: &[u8],
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            Ok(())
        }

        fn commit_parts(
            &mut self,
            kind: crate::scheduler::outbox::PersistKind,
            parts: &crate::scheduler::outbox::CommitParts<'_>,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            if kind == crate::scheduler::outbox::PersistKind::Receive {
                self.0.push((parts.inbox.is_some(), parts.trust));
            }
            Ok(())
        }

        fn control_relayed(
            &mut self,
            _ord: i64,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            Ok(())
        }

        fn control_requeued(
            &mut self,
            _row: &[u8],
        ) -> Result<Option<i64>, crate::scheduler::outbox::PersistError> {
            Ok(None)
        }
    }

    /// Two conversations of one session: the initiator (`MemPersist`) and the responder with `persist`, its receive queue
    /// bound to 1, inside a `Conversations`.
    #[cfg(feature = "kat")]
    type Session<P> = (
        TestConversation,
        super::Conversations<crate::scheduler::outbox::MemOutbox, P, Fixed>,
    );

    /// Two conversations of one session with their own durabilities: the initiator (`pa`) and the responder (`pb`), its
    /// receive queue bound to 1, inside a `Conversations`.
    #[cfg(feature = "kat")]
    type Pair<PA, PB> = (
        super::Conversation<crate::scheduler::outbox::MemOutbox, PA, Fixed>,
        super::Conversations<crate::scheduler::outbox::MemOutbox, PB, Fixed>,
    );

    #[cfg(feature = "kat")]
    fn session<P: crate::scheduler::outbox::Persist>(persist: P) -> Result<Session<P>, Fail> {
        pair(crate::scheduler::outbox::MemPersist::new(), persist)
    }

    #[cfg(feature = "kat")]
    fn pair<PA: crate::scheduler::outbox::Persist, PB: crate::scheduler::outbox::Persist>(
        pa: PA,
        pb: PB,
    ) -> Result<Pair<PA, PB>, Fail> {
        use crate::scheduler::outbox::MemOutbox;
        use crate::scheduler::types::QueueId;
        use secmp_proto::tr::{Entropy as _, FixedEntropy, RatchetState};
        let mut responder = FixedEntropy::new(&stream(2, 1 << 16));
        let mut initiator = FixedEntropy::new(&stream(1, 1 << 16));
        let spk_dh = responder.x25519().map_err(|_| "x25519")?;
        let rpk_kem = responder.mlkem768().map_err(|_| "ml-kem")?;
        let spk = secmp_proto::keys::X25519Pk::from_bytes(spk_dh.public_key().as_bytes())
            .map_err(|_| "spk")?;
        let ek = secmp_proto::keys::MlKem768Ek::from_bytes(rpk_kem.encapsulation_key().as_bytes())
            .map_err(|_| "ek")?;
        let sk = secmp_crypto::SecretBytes::from_slice(&[7_u8; 32]).map_err(|_| "secret")?;
        let a_state =
            RatchetState::init_initiator_with(&sk, &[9_u8; 32], &spk, &ek, &mut initiator)
                .map_err(|_| "initiator")?;
        let b_state = RatchetState::init_responder(&sk, &[9_u8; 32], spk_dh, rpk_kem)
            .map_err(|_| "responder")?;
        let peer = FixedEntropy::new(&stream(3, 1 << 20))
            .hybrid_signing_key()
            .map_err(|_| "peer key")?
            .verifying_key();
        let a = super::Conversation::new(
            a_state,
            MemOutbox::new(),
            pa,
            Fixed(FixedEntropy::new(&stream(4, 1 << 20))),
            peer.clone(),
            0,
        );
        let mut b = super::Conversation::new(
            b_state,
            MemOutbox::new(),
            pb,
            Fixed(FixedEntropy::new(&stream(6, 1 << 20))),
            peer,
            0,
        );
        b.bind(QueueId(2), QueueId(1));
        let mut convs = super::Conversations::new();
        convs.add(b);
        Ok((a, convs))
    }

    /// A text message `n` of `len` bytes.
    #[cfg(feature = "kat")]
    fn text_message(n: u8, len: usize) -> crate::scheduler::outbox::OutMessage {
        crate::scheduler::outbox::OutMessage {
            msg_id: [n; 16],
            kind: secmp_proto::wire::cell::AppKind::Text,
            expire_after: 0,
            payload: secmp_crypto::Zeroizing::new(vec![n; len]),
        }
    }

    /// V2-1 (killers, `conversation.rs:644`, `:645`): a receive commit carries the reassembly state while a message is in
    /// fragments (also the commit that completes it), not for a one-cell message, and no trust when the trust did not
    /// change.
    #[test]
    #[cfg(feature = "kat")]
    fn receive_commit_carries_inbox_only_while_fragmented() -> Result<(), Fail> {
        use crate::scheduler::outbox::Outbox as _;
        use crate::scheduler::types::{CellSource as _, QueueId};
        let (mut a, mut convs) = session(Commits::default())?;
        a.outbox_mut().enqueue(text_message(1, 3_000), 0);
        let first = a.prepare_direct(0).map_err(|_| "seal 1")?.cell;
        let second = a.prepare_direct(0).map_err(|_| "seal 2")?.cell;
        a.outbox_mut().enqueue(text_message(2, 10), 0);
        let third = a.prepare_direct(0).map_err(|_| "seal 3")?.cell;
        for (id, cell) in [(1, &first), (2, &second), (3, &third)] {
            convs
                .deliver(QueueId(1), 0, id, cell)
                .map_err(|_| "deliver")?;
        }
        let b = convs.get(0).ok_or("conversation")?;
        assert_eq!(b.received().len(), 2, "the long and the short message");
        assert_eq!(
            b.persist().0,
            vec![(true, None), (true, None), (false, None)],
            "fragment, completing fragment, one-cell message"
        );
        Ok(())
    }

    /// What a recording `Persist` saw of each receive commit's block (Q210 b).
    #[cfg(feature = "kat")]
    #[derive(Default)]
    struct Blocks(Vec<Option<u8>>);

    #[cfg(feature = "kat")]
    impl crate::scheduler::outbox::Persist for Blocks {
        fn commit(
            &mut self,
            _kind: crate::scheduler::outbox::PersistKind,
            _state: &[u8],
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            Ok(())
        }

        fn commit_parts(
            &mut self,
            kind: crate::scheduler::outbox::PersistKind,
            parts: &crate::scheduler::outbox::CommitParts<'_>,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            if kind == crate::scheduler::outbox::PersistKind::Receive {
                self.0.push(parts.block);
            }
            Ok(())
        }

        fn control_relayed(
            &mut self,
            _ord: i64,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            Ok(())
        }

        fn control_requeued(
            &mut self,
            _row: &[u8],
        ) -> Result<Option<i64>, crate::scheduler::outbox::PersistError> {
            Ok(None)
        }
    }

    /// B-4c killers (`effects`, Q210 b): the receive commit of a `Control{ContactRemoved}` carries the block `Removed` only
    /// without an argument, of a `Control{SessionResetRequest}` the block `Reset`; another content carries none.
    #[test]
    #[cfg(feature = "kat")]
    fn receive_commit_carries_the_block() -> Result<(), Fail> {
        use crate::scheduler::types::{CellSource as _, QueueId};
        use secmp_proto::wire::cell::{ContentBody, ControlBody, ControlCode};
        let (mut a, mut convs) = session(Blocks::default())?;
        for (id, (code, arg)) in (1_u64..).zip([
            (ControlCode::ContactRemoved, vec![1_u8]),
            (ControlCode::ContactRemoved, Vec::new()),
            (ControlCode::SessionResetRequest, Vec::new()),
        ]) {
            a.plan_control(
                ContentBody::Control(ControlBody {
                    code,
                    arg: secmp_crypto::Zeroizing::new(arg),
                }),
                super::Owner::Dummy,
            );
            let cell = a.prepare_direct(0).map_err(|_| "seal")?.cell;
            convs
                .deliver(QueueId(1), 0, id, &cell)
                .map_err(|_| "deliver")?;
        }
        let dummy = a.prepare_direct(0).map_err(|_| "dummy")?.cell;
        convs
            .deliver(QueueId(1), 0, 4, &dummy)
            .map_err(|_| "deliver")?;
        let b = convs.get(0).ok_or("conversation")?;
        assert_eq!(b.persist().0, vec![None, Some(1), Some(2), None]);
        Ok(())
    }

    /// B-4c killer (`prepare`, Q210 c): a cell that is not sealed (the persist refuses) puts back only what it carried —
    /// a dummy nothing, a control content to the front of the plan, where the next slot finds it.
    #[test]
    #[cfg(feature = "kat")]
    fn failed_seal_keeps_only_control_content() -> Result<(), Fail> {
        use crate::scheduler::types::{CellSource as _, QueueId};
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.persist_mut().set_failing(true);
        assert!(a.prepare_direct(0).is_err());
        assert!(!a.has_pending_real(), "a dummy leaves nothing planned");
        a.queue_control(secmp_proto::wire::cell::ControlCode::ContactRemoved);
        assert!(a.prepare_direct(0).is_err());
        assert!(a.has_pending_real(), "the control content stays planned");
        a.persist_mut().set_failing(false);
        let cell = a.prepare_direct(0).map_err(|_| "seal")?.cell;
        convs
            .deliver(QueueId(1), 0, 1, &cell)
            .map_err(|_| "deliver")?;
        assert!(matches!(
            convs
                .get_mut(0)
                .ok_or("conversation")?
                .take_events()
                .as_slice(),
            [super::SessionEvent::ContactRemoved]
        ));
        assert!(!a.has_pending_real());
        Ok(())
    }

    /// A Batch of text messages `(id byte, payload)`.
    #[cfg(feature = "kat")]
    fn text_batch(messages: &[(u8, &[u8])]) -> secmp_proto::wire::cell::ContentBody {
        use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody, ContentBody};
        ContentBody::Batch(BatchBody {
            messages: messages
                .iter()
                .map(|(n, payload)| AppMessage {
                    msg_id: [*n; 16],
                    kind: AppKind::Text,
                    expire_after: 0,
                    payload: secmp_crypto::Zeroizing::new(payload.to_vec()),
                })
                .collect(),
        })
    }

    /// SE-36 (EXTB2-3; ADR-054 items 1, 3; CLAUDE.md §1.5): a conversation built by `Conversation::new` applies the
    /// receive rules without being asked — of a Batch with a text containing U+0000 and a valid one only the valid one is
    /// delivered and receipted; only the test kit's switch lets the harness payloads through.
    #[test]
    #[cfg(feature = "kat")]
    fn adr054_receive_rules_on_without_the_switch() -> Result<(), Fail> {
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.queue_raw_content_test(text_batch(&[(50, b"a\0b"), (51, b"ok")]));
        let cell = a.prepare_direct(0).map_err(|_| "seal")?.cell;
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&cell).map_err(|_| "deliver")?;
        let ids: Vec<super::MsgId> = b.take_received().iter().map(|r| r.msg_id).collect();
        assert_eq!(ids, [[51; 16]]);
        assert_eq!(b.receipts_due(), 1);
        b.raw_app_payloads_kat();
        a.queue_raw_content_test(text_batch(&[(52, b"a\0b")]));
        let cell = a.prepare_direct(1_000).map_err(|_| "seal")?.cell;
        b.deliver_direct(&cell).map_err(|_| "deliver")?;
        let ids: Vec<super::MsgId> = b.take_received().iter().map(|r| r.msg_id).collect();
        assert_eq!(ids, [[52; 16]], "the test kit's switch");
        Ok(())
    }

    /// SE-26 (EXTB2-1; Q222 (3)): a control content whose `SEND` failed (`send_failed`, `discard`) is planned again and
    /// reaches the peer.
    #[test]
    #[cfg(feature = "kat")]
    fn extb2_failed_control_send_remains_retryable() -> Result<(), Fail> {
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(
            0,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let prepared = a.prepare_direct(0).map_err(|_| "seal")?;
        a.on_failed(prepared.token);
        let b = convs.get_mut(0).ok_or("conversation")?;
        for i in 1..5 {
            b.deliver_direct(&a.prepare_direct(i * 1_000).map_err(|_| "retry")?.cell)
                .map_err(|_| "delivery")?;
        }
        assert!(
            matches!(
                b.take_events().as_slice(),
                [super::SessionEvent::ResetRequested]
            ),
            "a failed SEND lost the reset notification"
        );
        Ok(())
    }

    /// A durability whose first row delete fails; it logs the `ord` of every delete.
    #[cfg(feature = "kat")]
    struct FlakyDelete {
        inner: crate::scheduler::outbox::MemPersist,
        deletes: Vec<i64>,
    }

    #[cfg(feature = "kat")]
    impl crate::scheduler::outbox::Persist for FlakyDelete {
        fn commit(
            &mut self,
            kind: crate::scheduler::outbox::PersistKind,
            state: &[u8],
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.inner.commit(kind, state)
        }

        fn commit_parts(
            &mut self,
            kind: crate::scheduler::outbox::PersistKind,
            parts: &crate::scheduler::outbox::CommitParts<'_>,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.inner.commit_parts(kind, parts)
        }

        fn control_relayed(
            &mut self,
            ord: i64,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.deletes.push(ord);
            if self.deletes.len() == 1 {
                Err(crate::scheduler::outbox::PersistError)
            } else {
                Ok(())
            }
        }

        fn control_requeued(
            &mut self,
            _row: &[u8],
        ) -> Result<Option<i64>, crate::scheduler::outbox::PersistError> {
            Ok(None)
        }
    }

    /// SE-40 (Q222 (2)): a row delete that fails after the last `OK_SEND` is tried again at the next preparation, and
    /// only until it succeeds.
    #[test]
    #[cfg(feature = "kat")]
    fn settle_retries_a_failed_row_delete() -> Result<(), Fail> {
        use secmp_proto::tr::{Entropy as _, FixedEntropy};
        use secmp_proto::wire::cell::ControlCode;
        let peer = FixedEntropy::new(&stream(3, 1 << 20))
            .hybrid_signing_key()
            .map_err(|_| "peer key")?
            .verifying_key();
        let mut a = super::Conversation::new(
            initiator_state()?,
            crate::scheduler::outbox::MemOutbox::new(),
            FlakyDelete {
                inner: crate::scheduler::outbox::MemPersist::new(),
                deletes: Vec::new(),
            },
            Fixed(FixedEntropy::new(&stream(4, 1 << 20))),
            peer,
            0,
        );
        a.queue_pending(
            4,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p = a.prepare_direct(0).map_err(|_| "seal")?;
        a.relayed_direct(p.token, 1);
        a.prepare_direct(1_000).map_err(|_| "seal")?;
        a.prepare_direct(2_000).map_err(|_| "seal")?;
        assert_eq!(a.persist().deletes, [4, 4], "failed once, tried again");
        a.prepare_direct(3_000).map_err(|_| "seal")?;
        assert_eq!(a.persist().deletes, [4, 4], "deleted: not tried again");
        Ok(())
    }

    /// A durability that logs its control row calls and fails the first `fail_relayed` deletes and the first
    /// `fail_requeued` re-writes (Q224, Q225).
    #[cfg(feature = "kat")]
    struct Script {
        inner: crate::scheduler::outbox::MemPersist,
        log: Vec<(&'static str, i64)>,
        fail_relayed: u32,
        fail_requeued: u32,
        next_ord: i64,
    }

    #[cfg(feature = "kat")]
    fn script(fail_relayed: u32, fail_requeued: u32) -> Script {
        Script {
            inner: crate::scheduler::outbox::MemPersist::new(),
            log: Vec::new(),
            fail_relayed,
            fail_requeued,
            next_ord: 100,
        }
    }

    #[cfg(feature = "kat")]
    impl crate::scheduler::outbox::Persist for Script {
        fn commit(
            &mut self,
            kind: crate::scheduler::outbox::PersistKind,
            state: &[u8],
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.inner.commit(kind, state)
        }

        fn commit_parts(
            &mut self,
            kind: crate::scheduler::outbox::PersistKind,
            parts: &crate::scheduler::outbox::CommitParts<'_>,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.inner.commit_parts(kind, parts)
        }

        fn control_relayed(
            &mut self,
            ord: i64,
        ) -> Result<(), crate::scheduler::outbox::PersistError> {
            self.log.push(("relayed", ord));
            if self.fail_relayed > 0 {
                self.fail_relayed = self.fail_relayed.saturating_sub(1);
                Err(crate::scheduler::outbox::PersistError)
            } else {
                Ok(())
            }
        }

        fn control_requeued(
            &mut self,
            _row: &[u8],
        ) -> Result<Option<i64>, crate::scheduler::outbox::PersistError> {
            self.log.push(("requeued", self.next_ord));
            if self.fail_requeued > 0 {
                self.fail_requeued = self.fail_requeued.saturating_sub(1);
                Err(crate::scheduler::outbox::PersistError)
            } else {
                let o = self.next_ord;
                self.next_ord = self.next_ord.saturating_add(1);
                Ok(Some(o))
            }
        }
    }

    /// A `RouteUpdate` of the relay queue `n` as pending control content.
    #[cfg(feature = "kat")]
    fn routes(n: u8) -> Result<super::PendingControl, Fail> {
        use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor, RouteUpdateBody};
        Ok(super::PendingControl::Routes(RouteUpdateBody {
            routes: vec![RouteDescriptor::RelayQueue(RelayQueue {
                relay: crate::testutil::relay_ref(),
                sid: [n; 16],
                send_seed: secmp_crypto::SecretBytes::from_slice(&[n; 32]).map_err(|_| "seed")?,
                period_s: secmp_proto::wire::Period::S20,
            })],
        }))
    }

    /// The `sid`s of the relay-queue routes of the `Routes` events `b` raised since the last call.
    #[cfg(feature = "kat")]
    fn sids<
        O: crate::scheduler::outbox::Outbox,
        P: crate::scheduler::outbox::Persist,
        S: super::EntropySource,
    >(
        b: &mut super::Conversation<O, P, S>,
    ) -> Vec<[u8; 16]> {
        use secmp_proto::wire::cell::RouteDescriptor;
        let mut out = Vec::new();
        for e in b.take_events() {
            if let super::SessionEvent::Routes(r) = e {
                for d in &r {
                    if let RouteDescriptor::RelayQueue(q) = d {
                        out.push(q.sid);
                    }
                }
            }
        }
        out
    }

    /// How many `ResetRequested` events `b` raised since the last call.
    #[cfg(feature = "kat")]
    fn resets<
        O: crate::scheduler::outbox::Outbox,
        P: crate::scheduler::outbox::Persist,
        S: super::EntropySource,
    >(
        b: &mut super::Conversation<O, P, S>,
    ) -> usize {
        b.take_events()
            .iter()
            .filter(|e| matches!(e, super::SessionEvent::ResetRequested))
            .count()
    }

    /// SE-49 (Q225, CLAUDE.md §1.7): a control content planned again after an eviction whose row could not be written
    /// again waits — its cell is not sealed — until the row is back; then it is sent once.
    #[test]
    #[cfg(feature = "kat")]
    fn control_cell_waits_for_its_row() -> Result<(), Fail> {
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = pair(script(0, 2), crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(
            4,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p = a.prepare(0).map_err(|_| "seal")?;
        a.relayed_direct(p.token, 1);
        a.prepare(1_000).map_err(|_| "seal")?;
        a.on_evicted(1);
        let p2 = a.prepare(2_000).map_err(|_| "seal")?;
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p2.cell).map_err(|_| "delivery")?;
        assert_eq!(
            resets(b),
            0,
            "Q225: a control cell waits for its durable row"
        );
        let p3 = a.prepare(3_000).map_err(|_| "seal")?;
        b.deliver_direct(&p3.cell).map_err(|_| "delivery")?;
        assert_eq!(resets(b), 1, "sent once the row is back");
        let p4 = a.prepare(4_000).map_err(|_| "seal")?;
        b.deliver_direct(&p4.cell).map_err(|_| "delivery")?;
        assert_eq!(resets(b), 0, "sent once");
        assert_eq!(
            a.persist()
                .log
                .iter()
                .filter(|(k, _)| *k == "requeued")
                .count(),
            3
        );
        Ok(())
    }

    /// SE-50 (Q225): a durability that keeps no rows (`control_requeued` is `Ok(None)`) holds no control cell.
    #[test]
    #[cfg(feature = "kat")]
    fn durability_without_rows_holds_nothing() -> Result<(), Fail> {
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(
            0,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p = a.prepare(0).map_err(|_| "seal")?;
        a.relayed_direct(p.token, 1);
        a.prepare(1_000).map_err(|_| "seal")?;
        a.on_evicted(1);
        let p2 = a.prepare(2_000).map_err(|_| "seal")?;
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p2.cell).map_err(|_| "delivery")?;
        assert_eq!(
            resets(b),
            1,
            "Q225: a durability that keeps no rows holds nothing"
        );
        Ok(())
    }

    /// SE-35 (spec §10.6 (4), Q-5): a send-queue switch plans control content whose current attempt has a cell without
    /// `OK_SEND` again for the new queue; the old queue's outcome only drops its token; the content settles on the new
    /// queue and reaches the peer.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_replans_unsettled_control_content() -> Result<(), Fail> {
        use crate::scheduler::types::{CellSource as _, QueueId};
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.bind(QueueId(1), QueueId(2));
        a.queue_pending(
            0,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p0 = a.prepare_direct(0).map_err(|_| "seal")?;
        assert_eq!(a.switch_send_queue(QueueId(9)), 0);
        assert!(
            a.has_pending_real(),
            "Q-5: unsettled control content is planned again for the new queue"
        );
        let mut mine = super::Conversations::new();
        let i = mine.add(a);
        // the old queue's OK_SEND: its token is dropped
        mine.relayed(QueueId(1), p0.token, 1);
        let a = mine.get_mut(i).ok_or("conversation")?;
        let p1 = a.prepare_direct(1_000).map_err(|_| "seal")?;
        a.relayed_direct(p1.token, 1);
        let p2 = a.prepare_direct(2_000).map_err(|_| "seal")?;
        a.relayed_direct(p2.token, 300);
        a.prepare_direct(3_000).map_err(|_| "seal")?;
        assert_eq!(a.live_controls_test(), 0, "settled and collected");
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p1.cell).map_err(|_| "delivery")?;
        assert!(matches!(
            b.take_events().as_slice(),
            [super::SessionEvent::ResetRequested]
        ));
        Ok(())
    }

    /// SE-60 (Q238, EXT2c-2; spec §10.6 (4)): a control content whose cells all have their `OK_SEND` on the old queue
    /// and are among its last `QUEUE_CAPACITY` cells (row gone, entry kept for the eviction window) is planned again for
    /// the new queue after a send-queue switch and reaches the peer.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_resends_settled_control_in_window() -> Result<(), Fail> {
        use crate::scheduler::types::QueueId;
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.bind(QueueId(1), QueueId(2));
        a.queue_pending(
            0,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p0 = a.prepare_direct(0).map_err(|_| "seal")?;
        a.relayed_direct(p0.token, 1);
        // settles: done, the row goes; the entry stays while its cell is in the window
        a.prepare_direct(1_000).map_err(|_| "seal")?;
        assert_eq!(a.live_controls_test(), 1);
        a.switch_send_queue(QueueId(9));
        assert!(
            a.has_pending_real(),
            "Q238: settled control content stranded on the old queue is planned again"
        );
        let p1 = a.prepare_direct(2_000).map_err(|_| "seal")?;
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p1.cell).map_err(|_| "delivery")?;
        assert_eq!(resets(b), 1, "the new queue's copy reaches the peer");
        Ok(())
    }

    /// SE-61 (Q238, negative control): a settled control content whose cell is no longer among the old queue's last
    /// `QUEUE_CAPACITY` cells (128 later cells had their `OK_SEND` without its eviction: it was fetched) is not planned
    /// again by a switch.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_leaves_control_content_outside_the_window() -> Result<(), Fail> {
        use crate::scheduler::types::QueueId;
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, _convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.bind(QueueId(1), QueueId(2));
        a.queue_pending(
            0,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p0 = a.prepare_direct(0).map_err(|_| "seal")?;
        a.relayed_direct(p0.token, 1);
        let d = a.prepare_direct(1_000).map_err(|_| "seal")?;
        // cell 1 is outside the last 128 (73..=200) but still held by the 256-cell eviction map
        a.relayed_direct(d.token, 200);
        assert_eq!(a.live_controls_test(), 1);
        a.switch_send_queue(QueueId(9));
        assert!(!a.has_pending_real(), "fetched content is not sent again");
        Ok(())
    }

    /// SE-32 (spec §10.1, CLAUDE.md §1.4): planning control content again — after a failed `SEND`, an eviction, a lost
    /// queue — seals nothing outside a slot: every seal is one preparation's.
    #[test]
    #[cfg(feature = "kat")]
    fn replanning_control_seals_nothing_outside_a_slot() -> Result<(), Fail> {
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(
            0,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let e = super::counters::tr_encrypt_calls();
        let p0 = a.prepare_direct(0).map_err(|_| "seal")?;
        assert_eq!(super::counters::tr_encrypt_calls() - e, 1);
        a.on_failed(p0.token);
        assert_eq!(
            super::counters::tr_encrypt_calls() - e,
            1,
            "after on_failed"
        );
        let p1 = a.prepare_direct(1_000).map_err(|_| "seal")?;
        assert_eq!(super::counters::tr_encrypt_calls() - e, 2);
        a.relayed_direct(p1.token, 1);
        a.on_evicted(1);
        assert_eq!(
            super::counters::tr_encrypt_calls() - e,
            2,
            "after on_evicted"
        );
        let p2 = a.prepare_direct(2_000).map_err(|_| "seal")?;
        assert_eq!(super::counters::tr_encrypt_calls() - e, 3);
        a.on_lost();
        assert_eq!(super::counters::tr_encrypt_calls() - e, 3, "after on_lost");
        let mut cells = vec![p1.cell, p2.cell];
        for k in 3..=6_u64 {
            cells.push(a.prepare_direct(k * 1_000).map_err(|_| "seal")?.cell);
            assert_eq!(
                super::counters::tr_encrypt_calls() - e,
                k + 1,
                "prepare {k}"
            );
        }
        let b = convs.get_mut(0).ok_or("conversation")?;
        for cell in &cells {
            b.deliver_direct(cell).map_err(|_| "delivery")?;
        }
        let events = b.take_events();
        assert!(!events.is_empty());
        assert!(
            events
                .iter()
                .all(|e| matches!(e, super::SessionEvent::ResetRequested)),
            "no other event"
        );
        Ok(())
    }

    /// SE-53 (Q230, Q224): the row of a done newer `RouteUpdate` stays while a retired older one still holds its row
    /// (its deletes failed) — a crash in between cannot leave the older row alone; it goes once the older row is gone.
    #[test]
    #[cfg(feature = "kat")]
    fn newer_routes_row_outlives_a_retired_one() -> Result<(), Fail> {
        let (mut a, _convs) = pair(script(3, 0), crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(4, routes(3)?).map_err(|_| "queue")?;
        a.queue_pending(5, routes(4)?).map_err(|_| "queue")?;
        let p = a.prepare_direct(0).map_err(|_| "seal")?;
        a.relayed_direct(p.token, 1);
        a.prepare_direct(1_000).map_err(|_| "seal")?;
        assert_eq!(
            a.persist().log,
            [("relayed", 4); 3],
            "Q230: the newer row stays while the retired older row is kept"
        );
        a.prepare_direct(2_000).map_err(|_| "seal")?;
        assert_eq!(
            a.persist().log,
            [("relayed", 4); 4],
            "the older row goes first"
        );
        a.prepare_direct(3_000).map_err(|_| "seal")?;
        assert_eq!(
            a.persist().log,
            [
                ("relayed", 4),
                ("relayed", 4),
                ("relayed", 4),
                ("relayed", 4),
                ("relayed", 5)
            ],
            "then the newer row goes"
        );
        assert_eq!(a.live_controls_test(), 1, "the newer entry, settled");
        Ok(())
    }

    /// B-4f killer (`prepare`, `actor.rs:1314:27`; Q225): a control cell held for its row does not hold the slot — a
    /// queued message is planned and sealed in it.
    #[test]
    #[cfg(feature = "kat")]
    fn held_control_cell_lets_a_message_through() -> Result<(), Fail> {
        use crate::scheduler::outbox::Outbox as _;
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, mut convs) = pair(script(0, 2), crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(
            4,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p = a.prepare(0).map_err(|_| "seal")?;
        a.relayed_direct(p.token, 1);
        a.prepare(1_000).map_err(|_| "seal")?;
        a.on_evicted(1);
        a.outbox_mut().enqueue(text_message(7, 10), 0);
        let p2 = a.prepare(2_000).map_err(|_| "seal")?;
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p2.cell).map_err(|_| "delivery")?;
        let ids: Vec<super::MsgId> = b.take_received().iter().map(|r| r.msg_id).collect();
        assert_eq!(
            ids,
            [[7; 16]],
            "the held control cell does not take the slot"
        );
        assert_eq!(resets(b), 0, "and is not sealed");
        Ok(())
    }

    /// B-4f killer (`on_lost`, `actor.rs:1438:16`; Q222 (3)): a lost queue plans each control content once — a planned cell
    /// is not restored on its own before the re-plan of every content (one re-write attempt of a missing row, not two).
    #[test]
    #[cfg(feature = "kat")]
    fn lost_queue_replans_each_control_content_once() -> Result<(), Fail> {
        use secmp_proto::wire::cell::ControlCode;
        let (mut a, _convs) = pair(script(0, 9), crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(
            4,
            super::PendingControl::Control(ControlCode::SessionResetRequest),
        )
        .map_err(|_| "queue")?;
        let p = a.prepare(0).map_err(|_| "seal")?;
        a.relayed_direct(p.token, 1);
        a.prepare(1_000).map_err(|_| "seal")?;
        a.on_evicted(1);
        let requeued = |a: &super::Conversation<_, Script, _>| {
            a.persist()
                .log
                .iter()
                .filter(|(k, _)| *k == "requeued")
                .count()
        };
        assert_eq!(requeued(&a), 1, "the eviction's re-write (fails)");
        a.on_lost();
        assert_eq!(requeued(&a), 2, "one re-plan per content on a lost queue");
        Ok(())
    }

    /// SE-46 (Q224, Option R): adding a newer `RouteUpdate` deletes the older one's row at once; a failed delete is
    /// retried at the next preparation and only until it succeeds; the outcomes of the older one's cells plan nothing,
    /// and only the newer one reaches the peer.
    #[test]
    #[cfg(feature = "kat")]
    fn superseded_route_row_delete_is_retried() -> Result<(), Fail> {
        let (mut a, mut convs) = pair(script(1, 0), crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(4, routes(3)?).map_err(|_| "queue")?;
        let p1 = a.prepare_direct(0).map_err(|_| "seal")?;
        a.queue_pending(5, routes(4)?).map_err(|_| "queue")?;
        assert_eq!(
            a.persist().log,
            [("relayed", 4)],
            "Q224: the older row goes when the newer is added"
        );
        a.on_failed(p1.token);
        let p2 = a.prepare_direct(1_000).map_err(|_| "seal")?;
        assert_eq!(
            a.persist().log,
            [("relayed", 4), ("relayed", 4)],
            "a failed delete is retried at the next settle"
        );
        let p3 = a.prepare_direct(2_000).map_err(|_| "seal")?;
        assert_eq!(a.persist().log.len(), 2, "deleted: not tried again");
        assert_eq!(a.live_controls_test(), 1, "only the newer entry");
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p2.cell).map_err(|_| "delivery")?;
        b.deliver_direct(&p3.cell).map_err(|_| "delivery")?;
        assert_eq!(sids(b), [[4; 16]], "only the newer RouteUpdate");
        Ok(())
    }

    /// SE-47 (Q224): an evicted older `RouteUpdate` whose row is being re-written is retired by a newer one: its row is
    /// never written again, and only the newer one reaches the peer.
    #[test]
    #[cfg(feature = "kat")]
    fn superseded_routes_row_is_not_rewritten() -> Result<(), Fail> {
        let (mut a, mut convs) = pair(script(0, 1), crate::scheduler::outbox::MemPersist::new())?;
        a.queue_pending(4, routes(3)?).map_err(|_| "queue")?;
        let p1 = a.prepare_direct(0).map_err(|_| "seal")?;
        a.relayed_direct(p1.token, 1);
        a.prepare_direct(1_000).map_err(|_| "seal")?;
        a.on_evicted(1);
        a.queue_pending(6, routes(4)?).map_err(|_| "queue")?;
        let p2 = a.prepare_direct(2_000).map_err(|_| "seal")?;
        let p3 = a.prepare_direct(3_000).map_err(|_| "seal")?;
        assert_eq!(
            a.persist()
                .log
                .iter()
                .filter(|(k, _)| *k == "requeued")
                .count(),
            1,
            "Q224: a retired entry's row is never written again"
        );
        let b = convs.get_mut(0).ok_or("conversation")?;
        b.deliver_direct(&p2.cell).map_err(|_| "delivery")?;
        b.deliver_direct(&p3.cell).map_err(|_| "delivery")?;
        assert_eq!(sids(b), [[4; 16]], "only the newer RouteUpdate");
        Ok(())
    }

    /// V2-1 (killer, `conversation.rs:254`): the delivered ids of an earlier run suppress a redelivery.
    #[test]
    #[cfg(feature = "kat")]
    fn seed_seen_suppresses_redelivery() -> Result<(), Fail> {
        use crate::scheduler::outbox::Outbox as _;
        use crate::scheduler::types::{CellSource as _, QueueId};
        let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
        a.outbox_mut().enqueue(text_message(5, 10), 0);
        let cell = a.prepare_direct(0).map_err(|_| "seal")?.cell;
        convs
            .get_mut(0)
            .ok_or("conversation")?
            .seed_seen([[5_u8; 16]]);
        convs
            .deliver(QueueId(1), 0, 1, &cell)
            .map_err(|_| "deliver")?;
        assert!(convs.get(0).ok_or("conversation")?.received().is_empty());
        Ok(())
    }

    /// B-4 killers (`rotate_recv_queue`, `drop_recv_queue`): the queue a rotation leaves joins the overlap once and never
    /// twice; rotating onto the current queue moves nothing; a dropped queue leaves the overlap, and dropping the current
    /// one clears it.
    #[test]
    #[cfg(feature = "kat")]
    fn recv_overlap_follows_rotations_and_drops() -> Result<(), Fail> {
        use crate::scheduler::types::QueueId as Q;
        let mut conv = conversation(
            initiator_state()?,
            crate::scheduler::outbox::MemPersist::new(),
        )?;
        conv.rotate_recv_queue(Q(1));
        assert_eq!(conv.recv_queues_kat(), (Some(Q(1)), vec![]));
        conv.rotate_recv_queue(Q(2));
        assert_eq!(conv.recv_queues_kat(), (Some(Q(2)), vec![Q(1)]));
        conv.rotate_recv_queue(Q(2));
        assert_eq!(
            conv.recv_queues_kat(),
            (Some(Q(2)), vec![Q(1)]),
            "the same queue again"
        );
        conv.rotate_recv_queue(Q(1));
        assert_eq!(conv.recv_queues_kat(), (Some(Q(1)), vec![Q(1), Q(2)]));
        conv.drop_recv_queue(Q(2));
        assert_eq!(conv.recv_queues_kat(), (Some(Q(1)), vec![Q(1)]));
        conv.drop_recv_queue(Q(9));
        assert_eq!(
            conv.recv_queues_kat(),
            (Some(Q(1)), vec![Q(1)]),
            "an unknown queue"
        );
        conv.drop_recv_queue(Q(1));
        assert_eq!(conv.recv_queues_kat(), (None, vec![]));
        Ok(())
    }

    /// B-4 killers (`switch_send_queue`, `drop_send_queue`, SE-02): the queue we leave stays as a dummy-only queue until it
    /// is dropped; every real message among the last 128 cells sent on it goes back to the outbox — the ones before them do
    /// not, nor does a message that was delivered.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_requeues_the_real_messages_of_the_last_128_cells() -> Result<(), Fail> {
        use crate::scheduler::outbox::{MemPersist, MsgState, Outbox as _};
        use crate::scheduler::types::QueueId as Q;
        let mut conv = conversation(initiator_state()?, MemPersist::new())?;
        conv.bind(Q(1), Q(2));
        let mut cell_id = 0_u64;
        let mut send = |conv: &mut TestConversation, message: Option<u8>| -> Result<(), Fail> {
            if let Some(n) = message {
                conv.outbox_mut().enqueue(text_message(n, 5), 0);
            }
            let prepared = conv.prepare_direct(0).map_err(|_| "seal")?;
            cell_id = cell_id.saturating_add(1);
            conv.relayed_direct(prepared.token, cell_id);
            Ok(())
        };
        // two early messages (cells 1, 2), 130 dummies (3…132), three late messages (133…135), one of them delivered later
        send(&mut conv, Some(1))?;
        send(&mut conv, Some(2))?;
        for _ in 0..130 {
            send(&mut conv, None)?;
        }
        for n in [11, 12, 13] {
            send(&mut conv, Some(n))?;
        }
        conv.outbox_mut().delivered(&[13; 16]);
        assert_eq!(
            conv.switch_send_queue(Q(9)),
            3,
            "11, 12 and 13 are in the window"
        );
        assert_eq!(conv.outbox().state(&[11; 16]), Some(MsgState::Queued));
        assert_eq!(conv.outbox().state(&[12; 16]), Some(MsgState::Queued));
        assert_eq!(conv.outbox().state(&[13; 16]), Some(MsgState::Delivered));
        assert!(matches!(
            conv.outbox().state(&[1; 16]),
            Some(MsgState::Relayed(_))
        ));
        assert!(matches!(
            conv.outbox().state(&[2; 16]),
            Some(MsgState::Relayed(_))
        ));
        assert_eq!(conv.send_queues_kat(), (Some(Q(9)), vec![Q(1)]));
        // a second switch onto the same queue leaves the overlap as it was
        assert_eq!(conv.switch_send_queue(Q(9)), 0);
        assert_eq!(conv.send_queues_kat(), (Some(Q(9)), vec![Q(1)]));
        conv.drop_send_queue(Q(7));
        assert_eq!(
            conv.send_queues_kat(),
            (Some(Q(9)), vec![Q(1)]),
            "an unknown queue"
        );
        conv.drop_send_queue(Q(1));
        assert_eq!(conv.send_queues_kat(), (Some(Q(9)), vec![]));
        Ok(())
    }

    /// B-4 killer (`mark_removed`): a removed contact takes no real content.
    #[test]
    #[cfg(feature = "kat")]
    fn marked_removed_refuses_real_content() -> Result<(), Fail> {
        let mut conv = conversation(
            initiator_state()?,
            crate::scheduler::outbox::MemPersist::new(),
        )?;
        assert_eq!(conv.may_send_real(), Ok(()));
        conv.mark_removed();
        assert_eq!(conv.may_send_real(), Err(super::Refusal::Removed));
        Ok(())
    }

    /// B-4 killer (the guard of the `ContactRemoved` arm of `apply_delivery`, ADR-054 item 4): `Control{ContactRemoved}`
    /// without an argument removes the contact; with an argument it does nothing.
    #[test]
    #[cfg(feature = "kat")]
    fn contact_removed_needs_an_empty_argument() -> Result<(), Fail> {
        use crate::scheduler::types::{CellSource as _, QueueId};
        use secmp_crypto::Zeroizing;
        use secmp_proto::wire::cell::{ContentBody, ControlBody, ControlCode};
        for (arg, removed) in [(vec![1_u8], false), (Vec::new(), true)] {
            let (mut a, mut convs) = session(crate::scheduler::outbox::MemPersist::new())?;
            a.plan_control(
                ContentBody::Control(ControlBody {
                    code: ControlCode::ContactRemoved,
                    arg: Zeroizing::new(arg),
                }),
                super::Owner::Dummy,
            );
            let cell = a.prepare_direct(0).map_err(|_| "seal")?.cell;
            convs
                .deliver(QueueId(1), 0, 1, &cell)
                .map_err(|_| "deliver")?;
            let events = convs.get_mut(0).ok_or("conversation")?.take_events();
            assert_eq!(
                matches!(events.as_slice(), [super::SessionEvent::ContactRemoved]),
                removed
            );
            assert_eq!(
                convs.get(0).ok_or("conversation")?.may_send_real().is_err(),
                removed
            );
        }
        Ok(())
    }

    /// C1-4 c (spec §7.7: "Unsigned/unverifiable changes freeze the session with a warning"): a verified `KeyChange`
    /// whose new `IK_sig` cannot be loaded freezes the session — the delivery becomes `KeyChangeRefused`, the trust
    /// `Frozen`, no key is taken. With a loader that works, the change is admitted with its key and the trust is left as
    /// it was. (No such `IksPublic` can be built through `secmp-proto`: `Ed25519Pk` decodes strictly and the ML-DSA key
    /// decode cannot fail, hence the injected loader.)
    #[cfg(feature = "kat")]
    #[test]
    fn unloadable_new_ik_sig_freezes() -> Result<(), Fail> {
        use super::Delivery;
        use secmp_proto::prekeys::IdentityKeys;
        use secmp_proto::tr::FixedEntropy;
        use secmp_proto::tr::content::{Trust, ik_sig};

        let keys = IdentityKeys::generate(&mut FixedEntropy::new(&stream(907, 1 << 20)))
            .map_err(|_| "keys")?;
        let iks = keys.public().clone();

        let mut trust = Trust::KeyChanged;
        let (delivery, key) =
            super::admit_key_change_with(Delivery::KeyChange(iks.clone()), &mut trust, |_| {
                Err(secmp_proto::Error::Rejected)
            });
        assert!(matches!(delivery, Delivery::KeyChangeRefused));
        assert_eq!(trust, Trust::Frozen);
        assert!(key.is_none());

        let mut trust = Trust::KeyChanged;
        let (delivery, key) =
            super::admit_key_change_with(Delivery::KeyChange(iks.clone()), &mut trust, |i| {
                ik_sig(i)
            });
        assert!(matches!(delivery, Delivery::KeyChange(_)));
        assert_eq!(trust, Trust::KeyChanged);
        assert_eq!(key, Some(ik_sig(&iks).map_err(|_| "ik_sig")?));
        Ok(())
    }
}
