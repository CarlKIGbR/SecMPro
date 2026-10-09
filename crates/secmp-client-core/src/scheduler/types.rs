// SPDX-License-Identifier: AGPL-3.0-or-later
//! The vocabulary of the scheduler core: ids, outputs, local events and the cell interface (TEST-SPEC-M6
//! "Conventions"). Nothing here reaches the wire.

use secmp_proto::wire::cell::Cell;

/// A queue the scheduler knows (send or receive), numbered in creation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueueId(pub u32);

/// A relay, numbered by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayId(pub u32);

/// One connection, numbered in creation order (the `link_slot` of a trace).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub u64);

/// What a provider must isolate a connection by (a Tor circuit, spec §8.1): fresh for every connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IsolationKey(pub u64);

/// A control operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

/// A cell prepared for a queue, to match `OK_SEND` to the message it carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellToken(pub u64);

/// Why a link went down (local event; spec §10.3, §10.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A third tick with two outstanding (spec §10.3).
    InFlight,
    /// The frame of a tick was not ready in time.
    Overrun,
    /// `LINK_LIFETIME` ran out.
    Lifetime,
    /// `LINK_MAX_FRAMES` or the `cmd_seq` space used up.
    NewLinkRequired,
    /// The stream ended.
    Closed,
    /// The relay closed before `RELAYINFO`.
    ClosedBeforeRelayInfo,
    /// A frame did not fit (spec §8.5).
    Rejected,
    /// The mode changed (`docs/02` §4.4).
    ModeChange,
}

/// A relay answer worth telling the user (spec §10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alert {
    /// `ERR_AUTH` on a queue.
    QueueAuth,
    /// `ERR_RATE` on a queue.
    QueueRate,
}

/// What the scheduler reports locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkEvent {
    /// `HS2` accepted.
    Up(LinkId),
    /// The link is gone.
    TornDown(LinkId, Reason),
    /// An alert about a queue.
    Alert(QueueId, Alert),
    /// The route of a send queue is marked dead (`ERR_NOQUEUE`; the recipient will re-create it).
    RouteDead(QueueId),
}

/// A control operation to run on its own one-shot link (spec §10.6 (2)); the host owns the key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    /// `QUEUE_NEW` for this queue (a pool queue, or the identical re-creation of §9.1).
    QueueNew(QueueId),
    /// `QUEUE_DEL` for this queue.
    QueueDel(QueueId),
    /// `LINK_PUT` of the host's link data `n`.
    LinkPut(u32),
    /// `LINK_GET` in owner-status mode for link data `n`.
    LinkGetOwner(u32),
    /// `LINK_GET` in consume mode for link data `n`.
    LinkGetConsume(u32),
}

/// What a link is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// One `SEND` per period (Strict).
    Send,
    /// One `FETCH` per period (Strict).
    Recv,
    /// One slot per `T` for a whole relay (Balanced, Low-bw).
    Relay,
}

/// How a connection reaches the relay (CLAUDE.md §1.5: the user's choice, never changed by a failure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Through Tor (the default).
    Tor,
    /// Direct TLS (the user chose it; implies Balanced).
    Direct,
}

/// What the scheduler asks of its driver.
pub enum Output {
    /// Open a connection (isolated by `key`) to `relay`, run the SecMP-LINK handshake, then report
    /// [`crate::scheduler::core::Scheduler::link_up`] or `connect_failed`.
    Connect {
        /// The connection.
        link: LinkId,
        /// Its isolation.
        key: IsolationKey,
        /// The relay.
        relay: RelayId,
        /// The transport, the same for every attempt.
        transport: Transport,
        /// What the link is for.
        kind: LinkKind,
        /// Its tick period in milliseconds.
        period_ms: u64,
    },
    /// Write these prepared frames (a multiple of 4352 bytes) to the link, now.
    Write {
        /// The connection.
        link: LinkId,
        /// The sealed frames.
        bytes: Vec<u8>,
    },
    /// Close the connection.
    Close {
        /// The connection.
        link: LinkId,
    },
    /// Run a control operation on a fresh one-shot connection, then report `control_done` or `control_failed`.
    Control {
        /// The operation.
        op: OpId,
        /// Its isolation.
        key: IsolationKey,
        /// The relay.
        relay: RelayId,
        /// What to run.
        kind: ControlKind,
        /// The transport.
        transport: Transport,
    },
    /// A local event.
    Event(LinkEvent),
}

/// Why a cell could not be prepared or taken (storage unavailable): nothing was sent, nothing acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceError;

/// A cell ready for a `SEND`, with the token that ties `OK_SEND` to the message it carries.
pub struct PreparedCell {
    /// The 4096-byte cell (a real message or a dummy, indistinguishable).
    pub cell: Cell,
    /// Its token.
    pub token: CellToken,
}

/// Why a `SEND` did not store its cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendFailure {
    /// `ERR_NOQUEUE`.
    NoQueue,
    /// `ERR_AUTH`.
    Auth,
    /// `ERR_RATE`.
    Rate,
    /// `ERR_MALFORMED`, or the link went down before the answer arrived.
    Unknown,
}

/// The conversations behind the scheduler: they build the cell of a send slot (real or dummy through one path,
/// persist-before-send), take delivered cells (persist-before-ack) and keep the outbox. The scheduler calls it only
/// while preparing and while handling a response — never on the tick path (spec §10.1).
pub trait CellSource {
    /// Build the next cell of `queue` for the slot being prepared. `Ok(None)` if it is not ready (the tick then
    /// finds no frame: an overrun).
    ///
    /// # Errors
    /// [`SourceError`] if the new state could not be persisted: no cell leaves.
    fn prepare_cell(&mut self, queue: QueueId, now: u64) -> Result<Option<PreparedCell>, SourceError>;

    /// `OK_SEND`: the cell of `token` is stored under `cell_id`.
    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64);

    /// `OK_SEND` reported this cell of `queue` evicted: a real message is re-queued, a dummy forgotten (spec §9.5).
    fn evicted(&mut self, queue: QueueId, cell_id: u64);

    /// The cell of `token` was not stored (an error answer, or the link went down before one): a real message is
    /// re-queued.
    fn send_failed(&mut self, queue: QueueId, token: CellToken, why: SendFailure);

    /// A prepared cell was never written (the link went down first): a real message is re-queued.
    fn discard(&mut self, queue: QueueId, token: CellToken);

    /// The sender observed `ERR_NOQUEUE` on `queue`: forget the `cell_id → message` map and re-queue the messages
    /// not yet receipted (spec §9.1, §10.4).
    fn queue_lost(&mut self, queue: QueueId);

    /// A cell fetched from the recipient queue `queue`: decide it (decrypt, or discard), commit the decision.
    ///
    /// # Errors
    /// [`SourceError`] if the decision could not be committed: the cell is not acknowledged and will be fetched again.
    fn deliver(&mut self, queue: QueueId, cell_id: u64, cell: &Cell) -> Result<(), SourceError>;
}
