// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sans-IO core of the constant-rate scheduler (spec §10, `docs/02` §4.4).
//!
//! **Shape.** The core owns the queues, one task per link, the control operations and the pool; it owns no stream and
//! reads no clock. A driver (the virtual one of the testkit, the asynchronous one of M6 Phase B) opens connections when
//! [`Output::Connect`] says so, runs the SecMP-LINK handshake, hands the resulting [`Channel`] to
//! [`Scheduler::link_up`], delivers received frames with [`Scheduler::on_frame`], and calls [`Scheduler::poll_due`] and
//! [`Scheduler::work`] at [`Scheduler::next_deadline`]. Every unit the client emits is an [`Output::Write`] of a
//! **prepared** frame.
//!
//! **The driver's calls (reviewer VD-M6-A-12).** [`Scheduler::poll_due`] decides what is due *now* — connections whose
//! time has come, lifetimes, the writes of due ticks, teardown and overrun decisions — and touches no cell source,
//! seals nothing and persists nothing; the driver writes its [`Output::Write`]s to the sockets *before* it calls
//! anything else. [`Scheduler::work`] then does everything that depends on activity: it releases what a teardown held,
//! decides the cells that responses delivered, prepares the frames of the next ticks and starts control operations.
//! The driver reports the instant the preparation finished with [`Scheduler::prepared_until`]; a frame whose
//! preparation ended after its tick is an overrun even if the driver wakes inside the jitter. `poll` is `poll_due` +
//! `work` + `prepared_until(now)` for callers that do not model the cost of the work.
//!
//! **Invariant (spec §10.1, CLAUDE.md §1.4).** The times, sizes and counts of the frames depend only on the mode, the
//! periods, the set of links and the random phases and lifetimes drawn when a link is created or comes up — never on
//! the cells' content or on whether a message is waiting. Preparation (the cell source, the ratchet, persistence,
//! sealing) happens in `prepare_link` off the tick path; [`World::tick`] writes bytes that exist. Time comes in as an
//! argument; randomness from the [`TimingRng`] only.

pub mod backoff;
pub mod pure;

use std::collections::VecDeque;

use secmp_transport::{
    Channel, Command, Error as TransportError, Outcome, Prepared, QueueRef, RecvCap, SendCap,
};

use crate::scheduler::control::{ControlOps, OpSpec, When};
use crate::scheduler::params::{FETCH_MULTI_LIMIT, Mode, Params};
use crate::scheduler::pool::QueuePool;
pub use crate::scheduler::types::LinkKind;
use crate::scheduler::types::{
    Alert, CellSource, CellToken, ControlKind, FrameId, IsolationKey, LinkEvent, LinkId,
    LogicalLinkId, OpId, Output, QueueId, Reason, RelayId, SendFailure, Transport,
};
use crate::timing::{TimingRng, Unavailable};

use self::backoff::reconnect_delay;
use self::pure::{
    InFlight, RECEIVED_MAX, RecvLedger, Ticked, complete_oldest, fetch_due, fetch_gate,
    fetch_lead_deadline, hand_out, ledger_admits, note_sent, reserved_rr, send_choice,
    send_missing, sendable, take_response, tick_time, unwritten_max,
};

/// Why a scheduler call was refused (nothing changed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedError {
    /// `period_s` is not in `PERIODS` (spec §9.8).
    BadPeriod,
    /// The recv-queues would exceed `Σ 1/P_q ≤ F_M/(2·T)` (spec §10.2).
    RateBound,
    /// More than 32 recv-queues on a relay in a mode with one `FETCH_MULTI` link.
    TooManyQueues,
    /// No such queue.
    UnknownQueue,
    /// A queue with this id is already registered.
    DuplicateQueue,
    /// A key does not give a capability.
    BadKey,
    /// No randomness (fail closed).
    Unavailable,
    /// `frame_written` named a frame that is not the oldest one handed out on the link (a duplicate or unknown report;
    /// nothing changed).
    UnknownFrame,
}

impl From<Unavailable> for SchedError {
    fn from(_: Unavailable) -> Self {
        Self::Unavailable
    }
}

impl core::fmt::Display for SchedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BadPeriod => "period not in PERIODS",
            Self::RateBound => "recv-queue rate bound exceeded",
            Self::TooManyQueues => "too many recv-queues for one FETCH_MULTI",
            Self::UnknownQueue => "unknown queue",
            Self::DuplicateQueue => "queue id in use",
            Self::BadKey => "not a queue key",
            Self::Unavailable => "randomness unavailable",
            Self::UnknownFrame => "not the oldest frame handed out",
        })
    }
}

impl std::error::Error for SchedError {}

struct SendQ {
    id: QueueId,
    relay: RelayId,
    period_ms: u64,
    cap: SendCap,
    last_send: Option<u64>,
    dead: bool,
}

struct RecvQ {
    id: QueueId,
    relay: RelayId,
    period_ms: u64,
    cap: RecvCap,
    /// The cumulative acknowledgement (spec §9.3; every cell at or below it is decided and committed — also the dedup),
    /// the generation, and the fetched cells above the acknowledgement (OQ-20).
    ledger: RecvLedger<RECEIVED_MAX>,
    pool: bool,
    recreating: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Spec {
    Send(QueueId),
    Recv(QueueId),
    Relay(RelayId),
}

/// What a request was (kept until its response is complete).
enum ReqKind {
    Send {
        queue: QueueId,
        token: CellToken,
    },
    Ping,
    /// The queue and the generation it was asked in.
    Fetch(QueueId, u64),
    /// The queues and the generation each was asked in.
    FetchMulti(Vec<(QueueId, u64)>),
}

struct Req {
    tick: u32,
    seq: u32,
    kind: ReqKind,
}

impl Ticked for Req {
    fn tick(&self) -> u32 {
        self.tick
    }
}

struct Part {
    prepared: Prepared,
    kind: ReqKind,
    /// When the preparation of this frame was finished (reviewer VD-M6-A-12): the start of the `work` call that built it,
    /// raised by [`Scheduler::prepared_until`]. A frame is written at its tick only if this is not after the tick.
    ready: u64,
    /// Built by the latest `work` call, whose end the driver has not reported yet.
    open: bool,
    /// The Balanced round-robin position after this `SEND` (GLM2B-1): applied when the part is written, together with
    /// `last_send`, so a teardown between obtaining the cell and the tick leaves the position where it was.
    next_rr: Option<usize>,
}

struct Up {
    id: LinkId,
    chan: Channel,
    since: u64,
    die_at: u64,
    /// Ticks written so far; the next tick is `k + 1`.
    k: u32,
    period: u64,
    send_part: Option<Part>,
    fetch_part: Option<Part>,
    /// The requests whose responses are outstanding and the in-flight count of their ticks (spec §10.3, SC-06).
    flight: InFlight<Req>,
    /// One entry per frame handed to the driver and not yet reported as written ([`Scheduler::frame_written`]), oldest
    /// first: the frame's id and the round-robin position it commits when it is completely written (a `SEND`), or `None`.
    unwritten: Vec<(FrameId, Option<usize>)>,
}

enum State {
    Down { at: u64 },
    Connecting { id: LinkId },
    Up(Box<Up>),
    Gone,
}

struct Link {
    spec: Spec,
    /// The logical link (FIN5b-1): the same id on every connection of this link.
    logical: LogicalLinkId,
    state: State,
    /// Consecutive closes before `RELAYINFO` (back-off, LR-03); reset when `HS2` is accepted.
    closed_before: u32,
    /// The round-robin pointer of a Balanced link (survives reconnects, spec §10.2 "fixed round-robin order").
    rr: usize,
}

/// A link as the tests and the UI see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// The current connection, if any.
    pub id: Option<LinkId>,
    /// What the link is for.
    pub kind: LinkKind,
    /// The queue (Strict) or none (a relay link).
    pub queue: Option<QueueId>,
    /// Waiting to connect at this time.
    pub starts_at: Option<u64>,
    /// `HS2` accepted at.
    pub t_up: Option<u64>,
    /// Closes at.
    pub die_at: Option<u64>,
    /// Ticks written on the current connection.
    pub ticks: u32,
    /// Ticks whose responses are outstanding.
    pub in_flight: u8,
    /// Consecutive closes before `RELAYINFO` (the back-off exponent, LR-03).
    pub closed_before: u32,
}

/// One preparation, for the tests (feature `kat`).
#[cfg(feature = "kat")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrepRecord {
    /// The connection.
    pub link: LinkId,
    /// The tick the frame is for.
    pub tick: u32,
    /// The time of that tick.
    pub tick_at: u64,
    /// When it was prepared.
    pub at: u64,
    /// `b'S'` send, `b'P'` ping, `b'F'` fetch, `b'M'` fetch-multi.
    pub kind: u8,
    /// The queue of a send or a single fetch.
    pub queue: Option<QueueId>,
    /// `seal_calls` right after the frame was sealed (the frame's place among the seals of the thread; TEST-SPEC-M7
    /// PC-04 orders the decisions before and after it).
    pub seal: u64,
}

/// What a teardown hands back to the cell source (`release`): done at once by the work-phase calls, and noted by
/// `poll_due`, which touches no cell source, to be handed over by the next `work` ([`Deferred`]).
trait Release {
    fn release_discard(&mut self, queue: QueueId, token: CellToken);
    fn release_failed(&mut self, queue: QueueId, token: CellToken);
}

impl<S: CellSource> Release for S {
    fn release_discard(&mut self, queue: QueueId, token: CellToken) {
        self.discard(queue, token);
    }

    fn release_failed(&mut self, queue: QueueId, token: CellToken) {
        self.send_failed(queue, token, SendFailure::Unknown);
    }
}

/// The releases noted by `poll_due`.
#[derive(Default)]
struct Deferred {
    discards: Vec<(QueueId, CellToken)>,
    failures: Vec<(QueueId, CellToken)>,
}

impl Release for Deferred {
    fn release_discard(&mut self, queue: QueueId, token: CellToken) {
        self.discards.push((queue, token));
    }

    fn release_failed(&mut self, queue: QueueId, token: CellToken) {
        self.failures.push((queue, token));
    }
}

/// The reason a tick did not happen.
enum TickResult {
    Idle,
    Wrote,
    Tear(Reason),
}

struct World {
    params: Params,
    mode: Mode,
    direct: bool,
    rng: TimingRng,
    /// The randomness of the control operations and the pool (apart from the links', CO-07).
    ctl: TimingRng,
    sends: Vec<SendQ>,
    recvs: Vec<RecvQ>,
    control: ControlOps,
    pool: QueuePool,
    next_queue: u32,
    next_link: u64,
    next_logical: u64,
    next_frame: u64,
    next_key: u64,
    next_op: u64,
    /// Created spares whose registration found no randomness (`Scheduler::pool_queue_ready`; EXT3b-3): still creations under way in the pool, registered at a later `work` pass, one attempt per pass, without a second `QUEUE_NEW`.
    parked: Vec<(QueueId, RecvCap)>,
    overruns: u64,
    /// `frame_written` calls on an up link that named no handed-out frame or not the oldest one
    /// ([`Scheduler::unmatched_written`]).
    unmatched_written: u64,
    last_now: u64,
    out: Vec<Output>,
    prep: PrepLog,
    /// Releases of teardowns decided by `poll_due`, for the next `work`.
    deferred: Deferred,
    /// Responses that arrived complete (`on_frame`) and whose cells are decided by the next `work`.
    pending: VecDeque<PendingOutcome>,
}

/// A completed response waiting for `work`: the cells it carries are decided (and committed) there, never between
/// `poll_due` and the driver's flush (reviewer VD-M6-A-12).
struct PendingOutcome {
    link: LinkId,
    req: Req,
    outcome: Outcome,
    at: u64,
}

/// What one tick cost in the counted work (feature `kat`): `[seal_calls, sign_calls, tr_encrypt_calls,
/// persist_calls]` between the start and the end of the tick, and the bytes it wrote (S-19).
#[cfg(feature = "kat")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickAudit {
    /// The connection.
    pub link: LinkId,
    /// The tick's time.
    pub at: u64,
    /// The change of each counter during the tick.
    pub delta: [u64; 4],
    /// The bytes written.
    pub bytes: usize,
}

#[cfg(feature = "kat")]
fn counters_now() -> [u64; 4] {
    [
        secmp_transport::channel::counters::seal_calls(),
        secmp_transport::channel::counters::sign_calls(),
        crate::sessions::actor::counters::tr_encrypt_calls(),
        crate::sessions::actor::counters::persist_calls(),
    ]
}

/// The preparation log (feature `kat`; empty and free otherwise).
#[derive(Default)]
struct PrepLog {
    #[cfg(feature = "kat")]
    records: Vec<PrepRecord>,
    #[cfg(feature = "kat")]
    ticks: Vec<TickAudit>,
}

impl PrepLog {
    #[cfg(feature = "kat")]
    fn record(&mut self, up: &Up, slot: u64, now: u64, kind: (u8, Option<QueueId>)) {
        self.records.push(PrepRecord {
            link: up.id,
            tick: up.k.saturating_add(1),
            tick_at: slot,
            at: now,
            kind: kind.0,
            queue: kind.1,
            seal: secmp_transport::channel::counters::seal_calls(),
        });
    }

    #[cfg(not(feature = "kat"))]
    const fn record(&mut self, _up: &Up, _slot: u64, _now: u64, _kind: (u8, Option<QueueId>)) {}
}

/// The scheduler (see the module documentation).
pub struct Scheduler {
    world: World,
    links: Vec<Link>,
}

impl World {
    fn effective_mode(&self) -> Mode {
        if self.direct && self.mode == Mode::Strict {
            Mode::Balanced
        } else {
            self.mode
        }
    }

    const fn transport(&self) -> Transport {
        if self.direct {
            Transport::Direct
        } else {
            Transport::Tor
        }
    }

    fn new_key(&mut self) -> IsolationKey {
        let k = self.next_key;
        self.next_key = self.next_key.saturating_add(1);
        IsolationKey(k)
    }

    fn new_link_id(&mut self) -> LinkId {
        let id = self.next_link;
        self.next_link = self.next_link.saturating_add(1);
        LinkId(id)
    }

    fn new_logical_id(&mut self) -> LogicalLinkId {
        let id = self.next_logical;
        self.next_logical = self.next_logical.saturating_add(1);
        LogicalLinkId(id)
    }

    fn new_frame_id(&mut self) -> FrameId {
        let id = self.next_frame;
        self.next_frame = self.next_frame.saturating_add(1);
        FrameId(id)
    }

    fn new_op_id(&mut self) -> OpId {
        let id = self.next_op;
        self.next_op = self.next_op.saturating_add(1);
        OpId(id)
    }

    fn phase(&mut self) -> Result<u64, SchedError> {
        Ok(self.rng.uniform(0, self.params.phase_max_ms)?)
    }

    fn period_of(&self, spec: Spec) -> Option<u64> {
        match spec {
            Spec::Send(q) => self.sends.iter().find(|s| s.id == q).map(|s| s.period_ms),
            Spec::Recv(q) => self.recvs.iter().find(|r| r.id == q).map(|r| r.period_ms),
            Spec::Relay(_) => self.params.slot_ms(self.effective_mode()),
        }
    }

    fn send_mut(&mut self, q: QueueId) -> Option<&mut SendQ> {
        self.sends.iter_mut().find(|s| s.id == q)
    }

    fn recv_mut(&mut self, q: QueueId) -> Option<&mut RecvQ> {
        self.recvs.iter_mut().find(|r| r.id == q)
    }

    fn relay_has_recv(&self, relay: RelayId) -> bool {
        self.recvs.iter().any(|r| r.relay == relay)
    }

    /// The links the queue set needs in `mode`, in creation order (one per queue in Strict, one per relay otherwise), with
    /// `adding` — a queue about to be registered, `(id, relay, recv)` — counted as registered (Q301: drawn before it is).
    fn wanted_specs(&self, mode: Mode, adding: Option<(QueueId, RelayId, bool)>) -> Vec<Spec> {
        let mut queues: Vec<(QueueId, RelayId, Spec)> = self
            .sends
            .iter()
            .map(|s| (s.id, s.relay, Spec::Send(s.id)))
            .chain(self.recvs.iter().map(|r| (r.id, r.relay, Spec::Recv(r.id))))
            .chain(adding.map(|(id, relay, recv)| {
                (
                    id,
                    relay,
                    if recv { Spec::Recv(id) } else { Spec::Send(id) },
                )
            }))
            .collect();
        queues.sort_by_key(|(q, _, _)| *q);
        if mode == Mode::Strict {
            return queues.into_iter().map(|(_, _, s)| s).collect();
        }
        let mut wanted: Vec<Spec> = Vec::new();
        for (_, relay, _) in queues {
            if !wanted.contains(&Spec::Relay(relay)) {
                wanted.push(Spec::Relay(relay));
            }
        }
        wanted
    }

    /// Release what a link held: prepared cells go back, written `SEND`s whose answer never came are re-queued.
    fn release<R: Release>(up: &mut Up, source: &mut R) {
        for part in [up.send_part.take(), up.fetch_part.take()]
            .into_iter()
            .flatten()
        {
            if let ReqKind::Send { queue, token } = part.kind {
                source.release_discard(queue, token);
            }
        }
        for req in up.flight.drain() {
            if let ReqKind::Send { queue, token } = req.kind {
                source.release_failed(queue, token);
            }
        }
    }

    /// Take the connection down with nothing drawn (Q301): what it held goes back, `Close` and `TornDown(reason)` are output,
    /// and the link is `Down` at `now + delay` (a delay drawn before anything changed) or removed (`None`). Cannot fail.
    fn close<R: Release>(
        &mut self,
        link: &mut Link,
        now: u64,
        reason: Reason,
        source: &mut R,
        delay: Option<u64>,
    ) {
        match core::mem::replace(&mut link.state, State::Gone) {
            State::Up(mut up) => {
                Self::release(&mut up, source);
                self.out.push(Output::Close { link: up.id });
                self.out.push(Output::Event(LinkEvent::TornDown(
                    up.id,
                    link.logical,
                    reason,
                )));
            }
            State::Connecting { id } => {
                self.out.push(Output::Close { link: id });
                self.out
                    .push(Output::Event(LinkEvent::TornDown(id, link.logical, reason)));
            }
            State::Down { .. } | State::Gone => {}
        }
        if let Some(delay) = delay {
            link.state = State::Down {
                at: now.saturating_add(delay),
            };
        }
    }

    /// Take the connection down. `ModeChange` removes the link; any other reason schedules the next attempt.
    fn tear<R: Release>(
        &mut self,
        link: &mut Link,
        now: u64,
        reason: Reason,
        source: &mut R,
    ) -> Result<(), SchedError> {
        // Q301: the back-off is drawn before anything changes; `ModeChange` removes the link and draws nothing
        let delay = if reason == Reason::ModeChange {
            None
        } else {
            Some(reconnect_delay(
                &self.params,
                &mut self.rng,
                link.closed_before,
            )?)
        };
        self.close(link, now, reason, source, delay);
        Ok(())
    }

    /// `tear` for the calls that touch no cell source: what the link held is handed over by the next `work`.
    fn tear_deferred(
        &mut self,
        link: &mut Link,
        now: u64,
        reason: Reason,
    ) -> Result<(), SchedError> {
        let mut held = core::mem::take(&mut self.deferred);
        let result = self.tear(link, now, reason, &mut held);
        self.deferred = held;
        result
    }

    fn start_connect(&mut self, link: &mut Link) {
        let relay = match link.spec {
            Spec::Send(q) => self.sends.iter().find(|s| s.id == q).map(|s| s.relay),
            Spec::Recv(q) => self.recvs.iter().find(|r| r.id == q).map(|r| r.relay),
            Spec::Relay(r) => Some(r),
        };
        let Some(relay) = relay else {
            link.state = State::Gone;
            return;
        };
        let id = self.new_link_id();
        let key = self.new_key();
        link.state = State::Connecting { id };
        let transport = self.transport();
        let (kind, period_ms) = (
            match link.spec {
                Spec::Send(_) => LinkKind::Send,
                Spec::Recv(_) => LinkKind::Recv,
                Spec::Relay(_) => LinkKind::Relay,
            },
            self.period_of(link.spec).unwrap_or(0),
        );
        self.out.push(Output::Connect {
            link: id,
            logical: link.logical,
            key,
            relay,
            transport,
            kind,
            period_ms,
        });
    }

    /// The tick: write the frames prepared for it, and nothing else. No cell source, no ratchet, no persistence, no
    /// signing, no sealing — those ran in `prepare_link` (spec §10.1).
    fn tick(&mut self, link: &mut Link, now: u64) -> TickResult {
        let (spec, has_fetch) = (
            link.spec,
            match link.spec {
                Spec::Relay(r) => self.relay_has_recv(r),
                Spec::Recv(_) => true,
                Spec::Send(_) => false,
            },
        );
        let State::Up(up) = &mut link.state else {
            return TickResult::Idle;
        };
        let Some(next) = up.k.checked_add(1) else {
            return TickResult::Tear(Reason::NewLinkRequired);
        };
        let Some(at) = tick_time(up.since, next, up.period) else {
            return TickResult::Tear(Reason::NewLinkRequired);
        };
        if now < at {
            return TickResult::Idle;
        }
        if now.saturating_sub(at) > self.params.driver_jitter_ms {
            self.overruns = self.overruns.saturating_add(1);
            return TickResult::Tear(Reason::Overrun);
        }
        if !up.flight.admit() {
            return TickResult::Tear(Reason::InFlight);
        }
        let needs_send = matches!(spec, Spec::Send(_) | Spec::Relay(_));
        let needs_fetch =
            matches!(spec, Spec::Recv(_)) || (matches!(spec, Spec::Relay(_)) && has_fetch);
        // a frame that is missing, or whose preparation ended after the tick (the driver reported it with
        // `prepared_until`): the tick is lost even if the driver woke inside the jitter (OPEN-M6-13, VD-M6-A-12)
        let unfinished = [&up.send_part, &up.fetch_part]
            .into_iter()
            .flatten()
            .any(|part| part.ready > at);
        if (needs_send && up.send_part.is_none())
            || (needs_fetch && up.fetch_part.is_none())
            || unfinished
        {
            self.overruns = self.overruns.saturating_add(1);
            return TickResult::Tear(Reason::Overrun);
        }
        // the ledger bound (spec §10.3, `:678`; `pure::unwritten_max`): a tick that would pass it is not written — the driver
        // is not reporting its writes, and a write pending at the next tick closes the link on its side anyway
        let adding = usize::from(up.send_part.is_some())
            .saturating_add(usize::from(up.fetch_part.is_some()));
        let unwritten_max = unwritten_max(self.params.max_in_flight);
        if !ledger_admits(up.unwritten.len(), adding, unwritten_max) {
            return TickResult::Tear(Reason::InFlight);
        }
        let mut sent_to = None;
        for part in [up.send_part.take(), up.fetch_part.take()]
            .into_iter()
            .flatten()
        {
            if up.chan.begin_write(&part.prepared).is_err() {
                return TickResult::Tear(Reason::Rejected);
            }
            // the round-robin position of a `SEND` is committed when the driver reports the frame completely written
            // (`Scheduler::frame_written`, FIN-2), not here; `last_send` stays at the tick
            let commits = if let ReqKind::Send { queue, .. } = part.kind {
                sent_to = Some(queue);
                part.next_rr
            } else {
                None
            };
            let frame = self.new_frame_id();
            hand_out(&mut up.unwritten, frame, commits);
            debug_assert!(up.unwritten.len() <= unwritten_max);
            self.out.push(Output::Write {
                link: up.id,
                at,
                bytes: part.prepared.bytes().to_vec(),
                frame,
            });
            let held = up.flight.push(Req {
                tick: next,
                seq: part.prepared.seq(),
                kind: part.kind,
            });
            // not reachable (two ticks of two requests): an unheld request fails its response's match, fail closed
            debug_assert!(held);
        }
        up.k = next;
        if let Some(q) = sent_to
            && let Some(sq) = self.sends.iter_mut().find(|s| s.id == q)
        {
            note_sent(&mut sq.last_send, at);
        }
        TickResult::Wrote
    }

    /// Build the frames of the next tick (spec §10.1: persistence included, off the tick path).
    fn prepare_link<S: CellSource>(
        &mut self,
        link: &mut Link,
        now: u64,
        source: &mut S,
    ) -> Result<(), SchedError> {
        let spec = link.spec;
        let mut tear = None;
        {
            let State::Up(up) = &mut link.state else {
                return Ok(());
            };
            let Some(next) = up.k.checked_add(1) else {
                return Ok(());
            };
            let Some(slot) = tick_time(up.since, next, up.period) else {
                return Ok(());
            };
            let needs_send = matches!(spec, Spec::Send(_) | Spec::Relay(_));
            let needs_fetch = match spec {
                Spec::Recv(_) => true,
                Spec::Relay(r) => self.recvs.iter().any(|q| q.relay == r),
                Spec::Send(_) => false,
            };
            if needs_send && up.send_part.is_none() {
                // the successor the newest unwritten SEND will commit, else the committed position (FIN2-1): the
                // choice never depends on whether a write completed before or after this preparation
                let rr = reserved_rr(&up.unwritten, link.rr);
                tear = self.prepare_send(rr, up, spec, slot, now, source);
            }
            // a tick's parts go out SEND first (`tick`): its FETCH is sealed only after its SEND, so the counters are in
            // write order even when the cell source answers "not ready" (EXTB-1)
            let unsent = send_missing(needs_send, up.send_part.is_some());
            if fetch_gate(
                tear.is_some(),
                unsent,
                needs_fetch && up.fetch_part.is_none(),
            ) {
                let fetch_outstanding = up
                    .flight
                    .iter()
                    .any(|r| matches!(r.kind, ReqKind::Fetch(..) | ReqKind::FetchMulti(_)));
                // the acknowledgement the FETCH carries is fixed when it is sealed: it waits for the commits of the cells
                // already fetched (OQ-20), at most until its lead (OPEN-M6-13) — the frame's time never moves
                let commits_pending = self.recvs.iter().any(|q| {
                    q.ledger.has_pending()
                        && match spec {
                            Spec::Recv(r) => q.id == r,
                            Spec::Relay(r) => q.relay == r,
                            Spec::Send(_) => false,
                        }
                });
                if fetch_due(
                    fetch_outstanding,
                    commits_pending,
                    now,
                    slot,
                    self.params.fetch_lead_ms,
                ) {
                    tear = self.prepare_fetch(up, spec, slot, now);
                }
            }
        }
        if let Some(reason) = tear {
            self.tear(link, now, reason, source)?;
        }
        Ok(())
    }

    fn prepare_send<S: CellSource>(
        &mut self,
        rr: usize,
        up: &mut Up,
        spec: Spec,
        slot: u64,
        now: u64,
        source: &mut S,
    ) -> Option<Reason> {
        let mut next_rr = None;
        let queue = match spec {
            Spec::Send(q) => Some(q),
            Spec::Relay(r) => {
                let members: Vec<(QueueId, Option<u64>, u64)> = self
                    .sends
                    .iter()
                    .filter(|s| s.relay == r)
                    .map(|s| (s.id, s.last_send, s.period_ms))
                    .collect();
                let table: Vec<(Option<u64>, u64)> =
                    members.iter().map(|(_, l, p)| (*l, *p)).collect();
                match send_choice(rr, &table, slot) {
                    Some((at, next)) => {
                        next_rr = Some(next);
                        members.get(at).map(|(q, _, _)| *q)
                    }
                    None => None,
                }
            }
            Spec::Recv(_) => return None,
        };
        let Some(queue) = queue else {
            // a Balanced slot with nobody due carries a PING
            return match up.chan.prepare(&Command::Ping) {
                Ok(prepared) => {
                    up.send_part = Some(Part {
                        prepared,
                        kind: ReqKind::Ping,
                        ready: now,
                        open: true,
                        next_rr: None,
                    });
                    self.prep.record(up, slot, now, (b'P', None));
                    None
                }
                Err(e) => Some(reason_of(e)),
            };
        };
        let cap = self.sends.iter().find(|s| s.id == queue).map(|s| &s.cap)?;
        // not ready, or not persisted: nothing is built, the tick finds no frame — and the same queue is asked again at
        // the next pass (the round-robin position moves only when a SEND is written, EXTB-1, GLM2B-1)
        let cell = sendable(source.prepare_cell(queue, now))?;
        // the round-robin position moves in `tick`, when this SEND is written (GLM2B-1)
        match up.chan.prepare(&Command::Send {
            to: cap,
            cell: &cell.cell,
        }) {
            Ok(prepared) => {
                up.send_part = Some(Part {
                    prepared,
                    kind: ReqKind::Send {
                        queue,
                        token: cell.token,
                    },
                    ready: now,
                    open: true,
                    next_rr,
                });
                self.prep.record(up, slot, now, (b'S', Some(queue)));
                None
            }
            Err(e) => {
                source.discard(queue, cell.token);
                Some(reason_of(e))
            }
        }
    }

    fn prepare_fetch(&mut self, up: &mut Up, spec: Spec, slot: u64, now: u64) -> Option<Reason> {
        match spec {
            Spec::Recv(q) => {
                let rq = self.recvs.iter().find(|r| r.id == q)?;
                match up.chan.prepare(&Command::Fetch {
                    from: &rq.cap,
                    ack: rq.ledger.acked(),
                }) {
                    Ok(prepared) => {
                        up.fetch_part = Some(Part {
                            prepared,
                            kind: ReqKind::Fetch(q, rq.ledger.generation()),
                            ready: now,
                            open: true,
                            next_rr: None,
                        });
                        self.prep.record(up, slot, now, (b'F', Some(q)));
                        None
                    }
                    Err(e) => Some(reason_of(e)),
                }
            }
            Spec::Relay(r) => {
                let members: Vec<&RecvQ> = self.recvs.iter().filter(|q| q.relay == r).collect();
                if members.is_empty() || members.len() > FETCH_MULTI_LIMIT {
                    return None;
                }
                let entries: Vec<(&RecvCap, u64)> =
                    members.iter().map(|q| (&q.cap, q.ledger.acked())).collect();
                let ids: Vec<(QueueId, u64)> = members
                    .iter()
                    .map(|q| (q.id, q.ledger.generation()))
                    .collect();
                match up.chan.prepare(&Command::FetchMulti { from: &entries }) {
                    Ok(prepared) => {
                        up.fetch_part = Some(Part {
                            prepared,
                            kind: ReqKind::FetchMulti(ids),
                            ready: now,
                            open: true,
                            next_rr: None,
                        });
                        self.prep.record(up, slot, now, (b'M', None));
                        None
                    }
                    Err(e) => Some(reason_of(e)),
                }
            }
            Spec::Send(_) => None,
        }
    }

    /// One link at `now`, the part that is due and needs no cell source: connect when its time has come, end it at its
    /// lifetime, tick. Preparation is `prepare_link`, in `work`.
    fn step_due<R: Release>(
        &mut self,
        link: &mut Link,
        now: u64,
        source: &mut R,
    ) -> Result<(), SchedError> {
        enum Todo {
            Connect,
            Lifetime,
            Run,
            Nothing,
        }
        let todo = match &link.state {
            State::Down { at } if *at <= now => Todo::Connect,
            State::Up(up) if now >= up.die_at => Todo::Lifetime,
            State::Up(_) => Todo::Run,
            _ => Todo::Nothing,
        };
        match todo {
            Todo::Connect => self.start_connect(link),
            Todo::Lifetime => {
                // spec §10.6 (1), S-1 (Q296): a recv link whose queue was handed out at another period ends at the
                // instant drawn at the hand-out, and its successor (new key, the new period) connects at that instant
                let handover = matches!(link.spec, Spec::Recv(_))
                    && matches!(&link.state, State::Up(up) if self.period_of(link.spec) != Some(up.period));
                self.tear(link, now, Reason::Lifetime, source)?;
                if handover {
                    self.start_connect(link);
                }
            }
            Todo::Run => {
                #[cfg(feature = "kat")]
                let (before, out_before) = (counters_now(), self.out.len());
                let result = self.tick(link, now);
                #[cfg(feature = "kat")]
                if matches!(result, TickResult::Wrote)
                    && let State::Up(up) = &link.state
                {
                    let after = counters_now();
                    let mut delta = [0_u64; 4];
                    for ((d, a), b) in delta.iter_mut().zip(after).zip(before) {
                        *d = a.saturating_sub(b);
                    }
                    let bytes = self
                        .out
                        .iter()
                        .skip(out_before)
                        .map(|o| {
                            if let Output::Write { bytes, .. } = o {
                                bytes.len()
                            } else {
                                0
                            }
                        })
                        .sum();
                    self.prep.ticks.push(TickAudit {
                        link: up.id,
                        at: now,
                        delta,
                        bytes,
                    });
                }
                if let TickResult::Tear(reason) = result {
                    self.tear(link, now, reason, source)?;
                }
            }
            Todo::Nothing => {}
        }
        Ok(())
    }

    /// A `work` call begins: what the previous one built is closed (its end was reported, or it ended at its start).
    fn begin_work(links: &mut [Link]) {
        for link in links {
            if let State::Up(up) = &mut link.state {
                for part in [up.send_part.as_mut(), up.fetch_part.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    part.open = false;
                }
            }
        }
    }

    fn recreate(&mut self, queue: QueueId, now: u64) -> Result<(), SchedError> {
        let (lo, hi) = self.params.recreate_delay_ms;
        let Some(relay) = self
            .recvs
            .iter()
            .find(|r| r.id == queue && !r.recreating)
            .map(|r| r.relay)
        else {
            return Ok(());
        };
        // Q301: the delay is drawn before the queue changes generation
        let at = now.saturating_add(self.ctl.uniform(lo, hi)?);
        if let Some(rq) = self.recvs.iter_mut().find(|r| r.id == queue) {
            // a new generation: nothing acknowledged, nothing fetched; a response asked before changes nothing (SC-07)
            rq.recreating = true;
            rq.ledger.recreate();
        }
        let op = self.new_op_id();
        self.control.schedule(
            &self.params,
            &mut self.ctl,
            op,
            now,
            OpSpec {
                kind: ControlKind::QueueNew(queue),
                relay,
                related: u64::from(queue.0),
                when: When::At(at),
            },
        )?;
        Ok(())
    }

    /// The cells of a `FETCH` response for `queue`, asked in `generation`: every present cell goes to the cell source in one
    /// pass and the acknowledgement moves to the highest committed prefix (OQ-20, `pure::RecvLedger::take`). A response
    /// with no present cell is an empty `FETCH`: a `QUEUE_DEL` that waited for it starts its delay (Q163, Q194).
    fn fetched<S: CellSource>(
        &mut self,
        queue: QueueId,
        generation: u64,
        cells: Vec<(u64, secmp_proto::wire::cell::Cell)>,
        source: &mut S,
        now: u64,
    ) {
        let empty = cells.is_empty();
        self.take_cells(queue, generation, cells, source);
        self.note_empty(queue, generation, empty, now);
    }

    /// The present cells of a response for `queue`, asked in `generation`, to the cell source (see [`World::fetched`]).
    fn take_cells<S: CellSource>(
        &mut self,
        queue: QueueId,
        generation: u64,
        cells: Vec<(u64, secmp_proto::wire::cell::Cell)>,
        source: &mut S,
    ) {
        let queues = self.recvs.iter_mut().map(|r| (r.id, &mut r.ledger));
        take_response(queues, &queue, generation, cells, |id, cell| {
            source.deliver(queue, generation, id, &cell)
        });
    }

    /// A response of the current generation of `queue` held no present cell of it (`empty`): the `QUEUE_DEL` that waited
    /// for it starts its delay (Q163, Q194).
    fn note_empty(&mut self, queue: QueueId, generation: u64, empty: bool, now: u64) {
        if empty && self.current(queue, generation) {
            self.control
                .note_empty_fetch(&self.params, &mut self.ctl, queue, now);
        }
    }

    /// Whether `queue` exists and is in `generation` (a response asked in an older generation changes nothing, SC-07).
    fn current(&self, queue: QueueId, generation: u64) -> bool {
        self.recvs
            .iter()
            .any(|r| r.id == queue && r.ledger.generation() == generation)
    }

    fn queue_error(
        &mut self,
        queue: QueueId,
        error: TransportError,
        now: u64,
    ) -> Result<(), SchedError> {
        match error {
            // a queue whose `QUEUE_DEL` waits is not re-created (SE-14): the relay has already forgotten it, the retirement is
            // complete (Q201)
            TransportError::NoQueue if self.control.queue_del_pending(queue) => {
                self.out.push(Output::Event(LinkEvent::QueueGone(queue)));
            }
            TransportError::NoQueue => self.recreate(queue, now)?,
            TransportError::Auth => self
                .out
                .push(Output::Event(LinkEvent::Alert(queue, Alert::QueueAuth))),
            TransportError::Rate => self
                .out
                .push(Output::Event(LinkEvent::Alert(queue, Alert::QueueRate))),
            _ => {}
        }
        Ok(())
    }

    /// The response of a `FETCH_MULTI` of `queues` (each with the generation it was asked in): `cells` and `errors` as the
    /// transport decoded the `F_M` frames. Every queue's present cells go to the cell source and its error is handled; a
    /// queue counts as "a `FETCH` returned no present cell" only if, after the error loop, it is not in error, no present
    /// frame is for it (decodable or not) and the response held at least one dummy frame — present and error frames fewer
    /// than `F_M` (docs/03 `FETCH_MULTI`: "… then dummies"; Q209) — the `F_M` the transport enforces, the frames of a
    /// response (`secmp_proto::link::FETCH_MULTI_BATCH`), not the scheduler's parameter. A queue starved by a full batch of
    /// other queues' cells may still hold cells. The cells are taken by value: each queue's go to the source as they are
    /// (no copy, no second parse), so a queue is "present" exactly if it has a cell here.
    fn fetched_multi<S: CellSource>(
        &mut self,
        queues: &[(QueueId, u64)],
        cells: Vec<(QueueRef, u64, secmp_proto::wire::cell::Cell)>,
        errors: &[(QueueRef, TransportError)],
        source: &mut S,
        now: u64,
    ) -> Result<(), SchedError> {
        let frames = u64::try_from(cells.len().saturating_add(errors.len())).unwrap_or(u64::MAX);
        let batch = u64::try_from(secmp_proto::link::FETCH_MULTI_BATCH).unwrap_or(u64::MAX);
        let had_dummy = frames < batch;
        let mut cells = cells;
        let mut quiet = Vec::new();
        for (q, generation) in queues {
            let Some(rid) = self
                .recvs
                .iter()
                .find(|r| r.id == *q)
                .map(|r| r.cap.queue())
            else {
                continue;
            };
            let (taken, rest): (Vec<_>, Vec<_>) =
                cells.into_iter().partition(|(r, _, _)| *r == rid);
            cells = rest;
            let mine: Vec<_> = taken.into_iter().map(|(_, id, cell)| (id, cell)).collect();
            // a present cell counts, whatever the source decides about it
            let present = !mine.is_empty();
            self.take_cells(*q, *generation, mine, source);
            if !self.current(*q, *generation) {
                continue;
            }
            let mut errored = false;
            for (r, e) in errors {
                if *r == rid {
                    errored = true;
                    self.queue_error(*q, *e, now)?;
                }
            }
            if !present && !errored && had_dummy {
                quiet.push((*q, *generation));
            }
        }
        // after the error loop: a queue re-created by its error is in another generation and arms nothing
        for (q, generation) in quiet {
            self.note_empty(q, generation, true, now);
        }
        Ok(())
    }

    fn outcome<S: CellSource>(
        &mut self,
        req: Req,
        outcome: Outcome,
        now: u64,
        source: &mut S,
    ) -> Result<bool, SchedError> {
        match (req.kind, outcome) {
            (ReqKind::Send { queue, token }, Outcome::Send(result)) => match result {
                Ok(done) => {
                    if let Some(sq) = self.send_mut(queue) {
                        sq.dead = false;
                    }
                    source.relayed(queue, token, done.cell_id);
                    if let Some(evicted) = done.evicted {
                        source.evicted(queue, evicted);
                    }
                }
                Err(TransportError::NoQueue) => {
                    if let Some(sq) = self.send_mut(queue) {
                        sq.dead = true;
                    }
                    self.out.push(Output::Event(LinkEvent::RouteDead(queue)));
                    source.send_failed(queue, token, SendFailure::NoQueue);
                    source.queue_lost(queue);
                }
                Err(TransportError::Auth) => {
                    self.out
                        .push(Output::Event(LinkEvent::Alert(queue, Alert::QueueAuth)));
                    source.send_failed(queue, token, SendFailure::Auth);
                }
                Err(TransportError::Rate) => {
                    self.out
                        .push(Output::Event(LinkEvent::Alert(queue, Alert::QueueRate)));
                    source.send_failed(queue, token, SendFailure::Rate);
                }
                Err(_) => source.send_failed(queue, token, SendFailure::Unknown),
            },
            (ReqKind::Ping, Outcome::Ping(_)) => {}
            (ReqKind::Fetch(queue, generation), Outcome::Fetch(result)) => match result {
                Ok(cells) => self.fetched(queue, generation, cells, source, now),
                Err(e) if self.current(queue, generation) => self.queue_error(queue, e, now)?,
                Err(_) => {}
            },
            (ReqKind::FetchMulti(queues), Outcome::FetchMulti(result)) => match result {
                Ok(done) => self.fetched_multi(&queues, done.cells, &done.errors, source, now)?,
                Err(e) => {
                    if let Some((first, generation)) = queues.first()
                        && self.current(*first, *generation)
                    {
                        self.queue_error(*first, e, now)?;
                    }
                }
            },
            // the channel matched the answer to the request: a mismatch here is a bug, treated as a LINK failure
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// `missing` capped per relay by the entries its `FETCH_MULTI` link has left, in a mode with one (spec D.2: at most [`FETCH_MULTI_LIMIT`]; EXT3b-3, Q304): a created spare must be admitted (`Scheduler::check_balanced` counts every recv queue of the relay), so the creations under way count too. Strict mode has no such link: `missing` as it is.
    fn room_for(&self, missing: Vec<(RelayId, usize)>) -> Vec<(RelayId, usize)> {
        if self.params.slot_ms(self.effective_mode()).is_none() {
            return missing;
        }
        missing
            .into_iter()
            .filter_map(|(relay, need)| {
                let held = self
                    .recvs
                    .iter()
                    .filter(|r| r.relay == relay)
                    .count()
                    .saturating_add(self.pool.pending_on(relay));
                let need = need.min(FETCH_MULTI_LIMIT.saturating_sub(held));
                (need > 0).then_some((relay, need))
            })
            .collect()
    }

    /// The refill's delays `U[1 min, 60 min]`, one per creation `missing` asks for, drawn before anything changes (Q301): the
    /// same draws, in the same order, as `ControlOps::schedule` made.
    fn draw_top_up(&mut self, missing: &[(RelayId, usize)]) -> Result<Vec<u64>, SchedError> {
        let (lo, hi) = self.params.control_delay_ms;
        let mut delays = Vec::new();
        for (_, need) in missing {
            for _ in 0..*need {
                delays.push(self.ctl.uniform(lo, hi)?);
            }
        }
        Ok(delays)
    }

    /// Queue the creations of `missing` with the delays of [`World::draw_top_up`]; cannot fail.
    fn apply_top_up(&mut self, now: u64, missing: &[(RelayId, usize)], delays: Vec<u64>) {
        let mut drawn_delays = delays.into_iter();
        for (relay, need) in missing {
            for _ in 0..*need {
                let Some(drawn) = drawn_delays.next() else {
                    return;
                };
                let queue = QueueId(self.next_queue);
                self.next_queue = self.next_queue.saturating_add(1);
                let op = self.new_op_id();
                self.control.schedule_drawn(
                    op,
                    now,
                    OpSpec {
                        kind: ControlKind::QueueNew(queue),
                        relay: *relay,
                        related: u64::MAX.saturating_sub(u64::from(queue.0)),
                        when: When::Delayed,
                    },
                    drawn,
                );
                self.pool.creating(*relay, queue);
            }
        }
    }
}

const fn reason_of(e: TransportError) -> Reason {
    match e {
        TransportError::NewLinkRequired => Reason::NewLinkRequired,
        TransportError::Closed => Reason::Closed,
        _ => Reason::Rejected,
    }
}

/// Whether `spec` is the link of `queue`.
fn on_queue(spec: Spec, queue: QueueId) -> bool {
    matches!(spec, Spec::Send(q) | Spec::Recv(q) if q == queue)
}

/// Whether the link `spec` ends when `queue` is removed: its own, or a relay link with no other queue (`remove_queue`).
fn ends_with(world: &World, spec: Spec, queue: QueueId) -> bool {
    match spec {
        Spec::Send(q) | Spec::Recv(q) => q == queue,
        Spec::Relay(r) => {
            !world.sends.iter().any(|s| s.relay == r && s.id != queue)
                && !world.recvs.iter().any(|x| x.relay == r && x.id != queue)
        }
    }
}

impl Scheduler {
    /// A scheduler with no queues.
    #[must_use]
    pub fn new(params: Params, mode: Mode, mut rng: TimingRng) -> Self {
        // forking cannot fail for a seeded generator; the operating system's has been used before
        let ctl = rng.fork().unwrap_or_else(|_| TimingRng::os());
        let pool = QueuePool::new(params.pool_target);
        Self {
            world: World {
                params,
                mode,
                direct: false,
                rng,
                ctl,
                sends: Vec::new(),
                recvs: Vec::new(),
                control: ControlOps::new(),
                pool,
                next_queue: 0,
                next_link: 0,
                next_logical: 0,
                next_frame: 0,
                next_key: 0,
                next_op: 0,
                parked: Vec::new(),
                overruns: 0,
                unmatched_written: 0,
                last_now: 0,
                out: Vec::new(),
                prep: PrepLog::default(),
                deferred: Deferred::default(),
                pending: VecDeque::new(),
            },
            links: Vec::new(),
        }
    }

    /// The mode in force (direct mode implies Balanced, spec §10.2).
    #[must_use]
    pub fn effective_mode(&self) -> Mode {
        self.world.effective_mode()
    }

    /// The mode the user chose (Q301: the runtime's `sched_mode` is re-read from it); in direct mode
    /// [`Scheduler::effective_mode`] is Balanced (spec §10.2).
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.world.mode
    }

    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> &Params {
        &self.world.params
    }

    /// Uniform timing draws so far, `(links, control)`: the generator of the links' phases, lifetimes and back-off, and the
    /// separate one of the control operations and the pool (CO-07). The activity-independence tests compare both: a sum
    /// could hide one stream drawing more and the other less.
    #[must_use]
    pub const fn timing_draws(&self) -> (u64, u64) {
        (self.world.rng.draws(), self.world.ctl.draws())
    }

    /// Ticks lost to a frame that was not ready (OPEN-M6-13).
    #[must_use]
    pub const fn overruns(&self) -> u64 {
        self.world.overruns
    }

    /// `frame_written` calls that found an up link with an empty ledger: the caller reported a write it was never handed
    /// (a trusted-caller contract violation; the call itself changes nothing else).
    #[must_use]
    pub const fn unmatched_written(&self) -> u64 {
        self.world.unmatched_written
    }

    /// The length of the unwritten ledger of the up link `link` (tests only).
    #[cfg(any(test, feature = "kat"))]
    #[must_use]
    pub fn unwritten_len(&self, link: LinkId) -> Option<usize> {
        self.links.iter().find_map(|l| match &l.state {
            State::Up(up) if up.id == link => Some(up.unwritten.len()),
            _ => None,
        })
    }

    /// The cumulative acknowledgement of a recv-queue.
    #[must_use]
    pub fn acked(&self, queue: QueueId) -> Option<u64> {
        self.world
            .recvs
            .iter()
            .find(|r| r.id == queue)
            .map(|r| r.ledger.acked())
    }

    /// The cell source finished committing the decision of cell `cell_id` of `queue`, which `deliver` answered
    /// [`crate::scheduler::types::Delivered::Pending`] (OQ-20): the acknowledgement moves to the highest committed prefix
    /// of what was fetched, and the next `FETCH` carries it (spec §9.3). A report for a cell the queue does not hold
    /// (another generation's, or decided already) changes nothing.
    pub fn delivery_committed(&mut self, queue: QueueId, generation: u64, cell_id: u64) {
        if let Some(rq) = self.world.recv_mut(queue)
            && rq.ledger.generation() == generation
        {
            rq.ledger.committed(cell_id);
        }
    }

    /// What each tick cost in counted work (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn tick_audit(&self) -> &[TickAudit] {
        &self.world.prep.ticks
    }

    /// Set the send counter of a connection's link (the rotation tests; feature `kat`): what was prepared under the old
    /// counter is dropped and prepared again.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    #[cfg(feature = "kat")]
    pub fn set_send_counter_kat<S: CellSource>(
        &mut self,
        id: LinkId,
        value: u64,
        now: u64,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        for link in &mut self.links {
            if let State::Up(up) = &mut link.state
                && up.id == id
            {
                up.chan.set_send_counter_kat(value);
                if let Some(Part {
                    kind: ReqKind::Send { queue, token },
                    ..
                }) = up.send_part.take()
                {
                    source.discard(queue, token);
                }
                up.fetch_part = None;
            }
        }
        self.work_pass(now, source)?;
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The preparations so far (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn prep_log(&self) -> &[PrepRecord] {
        &self.world.prep.records
    }

    /// The links, in creation order.
    #[must_use]
    pub fn links(&self) -> Vec<LinkInfo> {
        self.links
            .iter()
            .filter(|l| !matches!(l.state, State::Gone))
            .map(|l| {
                let (kind, queue) = match l.spec {
                    Spec::Send(q) => (LinkKind::Send, Some(q)),
                    Spec::Recv(q) => (LinkKind::Recv, Some(q)),
                    Spec::Relay(_) => (LinkKind::Relay, None),
                };
                let mut info = LinkInfo {
                    id: None,
                    kind,
                    queue,
                    starts_at: None,
                    t_up: None,
                    die_at: None,
                    ticks: 0,
                    in_flight: 0,
                    closed_before: l.closed_before,
                };
                match &l.state {
                    State::Down { at } => info.starts_at = Some(*at),
                    State::Connecting { id } => info.id = Some(*id),
                    State::Up(up) => {
                        info.id = Some(up.id);
                        info.t_up = Some(up.since);
                        info.die_at = Some(up.die_at);
                        info.ticks = up.k;
                        info.in_flight = up.flight.count();
                    }
                    State::Gone => {}
                }
                info
            })
            .collect()
    }

    /// Whether the route of a send queue is marked dead (`ERR_NOQUEUE`, spec §10.3).
    #[must_use]
    pub fn route_dead(&self, queue: QueueId) -> bool {
        self.world.sends.iter().any(|s| s.id == queue && s.dead)
    }

    // ---- queues ---------------------------------------------------------------------------------------------------

    fn next_queue_id(&mut self) -> QueueId {
        let q = QueueId(self.world.next_queue);
        self.world.next_queue = self.world.next_queue.saturating_add(1);
        q
    }

    /// Whether the recv-queues of `relay` fit a mode with one `FETCH_MULTI` link. `added` is a queue about to join:
    /// `(its period, whether it counts in Σ 1/P)`. Every queue is an entry of the `FETCH_MULTI` (a pool spare too, spec
    /// D.2: at most 32); only the queues outside the pool enter the rate sum.
    fn check_balanced(
        &self,
        relay: RelayId,
        added: Option<(u64, bool)>,
        mode: Mode,
    ) -> Result<(), SchedError> {
        if self.world.params.slot_ms(mode).is_none() {
            return Ok(());
        }
        let on_relay = self.world.recvs.iter().filter(|r| r.relay == relay);
        let entries = on_relay
            .clone()
            .count()
            .saturating_add(usize::from(added.is_some()));
        if entries > FETCH_MULTI_LIMIT {
            return Err(SchedError::TooManyQueues);
        }
        let periods = on_relay
            .filter(|r| !r.pool)
            .map(|r| r.period_ms)
            .chain(added.and_then(|(period, counts)| counts.then_some(period)));
        if self.world.params.rate_bound_ok(mode, periods) {
            Ok(())
        } else {
            Err(SchedError::RateBound)
        }
    }

    /// Add the queue we send to. Its link starts `U[0, 3 min]` from `now` (spec §10.6 (1)).
    ///
    /// # Errors
    /// [`SchedError::BadPeriod`] if `period_ms` is not in `PERIODS` (nothing is drawn); [`SchedError::Unavailable`].
    pub fn add_send_queue(
        &mut self,
        now: u64,
        relay: RelayId,
        cap: SendCap,
        period_ms: u64,
    ) -> Result<QueueId, SchedError> {
        if !self.world.params.period_valid(period_ms) {
            return Err(SchedError::BadPeriod);
        }
        let id = self.next_queue_id();
        let plan = self.missing_links(Some((id, relay, false)), None)?;
        self.world.sends.push(SendQ {
            id,
            relay,
            period_ms,
            cap,
            last_send: None,
            dead: false,
        });
        self.add_links(now, plan);
        Ok(id)
    }

    /// Add a queue we receive on (`pool`: a spare of the pool, fetched at `P_POOL`, outside the rate bound).
    ///
    /// # Errors
    /// [`SchedError::BadPeriod`]; [`SchedError::RateBound`] and [`SchedError::TooManyQueues`] in a mode with a
    /// `FETCH_MULTI` link; [`SchedError::Unavailable`].
    pub fn add_recv_queue(
        &mut self,
        now: u64,
        relay: RelayId,
        cap: RecvCap,
        period_ms: u64,
    ) -> Result<QueueId, SchedError> {
        let id = self.next_queue_id();
        self.add_recv_with_id(now, id, relay, cap, period_ms, false)?;
        Ok(id)
    }

    /// Add the queue we receive on as `id` (a stable id the host keeps: a pool queue, a contact's queue), from the recipient
    /// seed — the capability is made here, so the host names no transport type. The queue is fetched at `period_ms`.
    ///
    /// # Errors
    /// [`SchedError::DuplicateQueue`], [`SchedError::BadKey`], and those of [`Scheduler::add_recv_queue`].
    pub fn add_recv_queue_seed(
        &mut self,
        now: u64,
        id: QueueId,
        relay: RelayId,
        seed: &secmp_crypto::SecretBytes<32>,
        period_ms: u64,
    ) -> Result<(), SchedError> {
        if self.world.recv_mut(id).is_some() || self.world.send_mut(id).is_some() {
            return Err(SchedError::DuplicateQueue);
        }
        let cap = RecvCap::from_seed(seed).map_err(|_| SchedError::BadKey)?;
        self.add_recv_with_id(now, id, relay, cap, period_ms, false)
    }

    /// Add the queue we send to as `id`, from a route's `sid` and sender seed (spec §9.8).
    ///
    /// # Errors
    /// [`SchedError::DuplicateQueue`], [`SchedError::BadKey`], and those of [`Scheduler::add_send_queue`].
    pub fn add_send_queue_route(
        &mut self,
        now: u64,
        id: QueueId,
        relay: RelayId,
        route: (secmp_proto::wire::Id, &secmp_crypto::SecretBytes<32>),
        period_ms: u64,
    ) -> Result<(), SchedError> {
        if self.world.recv_mut(id).is_some() || self.world.send_mut(id).is_some() {
            return Err(SchedError::DuplicateQueue);
        }
        if !self.world.params.period_valid(period_ms) {
            return Err(SchedError::BadPeriod);
        }
        let cap = SendCap::from_route(route.0, route.1).map_err(|_| SchedError::BadKey)?;
        let plan = self.missing_links(Some((id, relay, false)), None)?;
        self.world.sends.push(SendQ {
            id,
            relay,
            period_ms,
            cap,
            last_send: None,
            dead: false,
        });
        self.add_links(now, plan);
        Ok(())
    }

    /// Whether `queue` is registered (as a send or a recv queue).
    #[must_use]
    pub fn has_queue(&self, queue: QueueId) -> bool {
        self.world.sends.iter().any(|s| s.id == queue)
            || self.world.recvs.iter().any(|r| r.id == queue)
    }

    fn add_recv_with_id(
        &mut self,
        now: u64,
        id: QueueId,
        relay: RelayId,
        cap: RecvCap,
        period_ms: u64,
        pool: bool,
    ) -> Result<(), SchedError> {
        let plan = self.plan_recv(id, relay, period_ms, pool)?;
        self.push_recv(now, (id, relay, period_ms, pool), cap, plan);
        Ok(())
    }

    /// The checks and the drawn link plan of the recv queue `id` about to be added (Q301: every draw before any change).
    fn plan_recv(
        &mut self,
        id: QueueId,
        relay: RelayId,
        period_ms: u64,
        pool: bool,
    ) -> Result<Vec<(Spec, u64)>, SchedError> {
        if !self.world.params.period_valid(period_ms) {
            return Err(SchedError::BadPeriod);
        }
        let mode = self.world.effective_mode();
        self.check_balanced(relay, Some((period_ms, !pool)), mode)?;
        self.missing_links(Some((id, relay, true)), None)
    }

    /// Register the recv queue `id` with the links of a plan of [`Scheduler::plan_recv`]; cannot fail.
    fn push_recv(
        &mut self,
        now: u64,
        (id, relay, period_ms, pool): (QueueId, RelayId, u64, bool),
        cap: RecvCap,
        plan: Vec<(Spec, u64)>,
    ) {
        self.world.recvs.push(RecvQ {
            id,
            relay,
            period_ms,
            cap,
            ledger: RecvLedger::new(),
            pool,
            recreating: false,
        });
        self.add_links(now, plan);
    }

    /// The created spares whose registration found no randomness, once more (EXT3b-3, Q304): one attempt each; one that fails again waits for the next pass. Nothing is sent: the queue exists on the relay.
    fn register_parked(&mut self, now: u64) {
        let period = self.world.params.p_pool_ms;
        for (queue, cap) in core::mem::take(&mut self.world.parked) {
            let Some(relay) = self.world.pool.pending_relay(queue) else {
                continue;
            };
            match self.plan_recv(queue, relay, period, true) {
                Ok(plan) => {
                    self.push_recv(now, (queue, relay, period, true), cap, plan);
                    self.world.pool.created(queue);
                }
                Err(_) => self.world.parked.push((queue, cap)),
            }
        }
    }

    /// Stop sending to / receiving on a queue; its link ends.
    ///
    /// # Errors
    /// [`SchedError::UnknownQueue`].
    pub fn remove_queue<S: CellSource>(
        &mut self,
        now: u64,
        queue: QueueId,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        let known = self.world.sends.iter().any(|s| s.id == queue)
            || self.world.recvs.iter().any(|r| r.id == queue);
        if !known {
            return Err(SchedError::UnknownQueue);
        }
        // Q301: the teardown draws of the links that end come first (made and discarded, as before: the links are removed)
        for link in &self.links {
            // the immutable borrow of `self.world` ends before the draw borrows `self.world.rng`
            if ends_with(&self.world, link.spec, queue) {
                reconnect_delay(&self.world.params, &mut self.world.rng, link.closed_before)?;
            }
        }
        self.world.sends.retain(|s| s.id != queue);
        self.world.recvs.retain(|r| r.id != queue);
        self.world.control.drop_queue_ops(queue);
        let (world, links) = (&mut self.world, &mut self.links);
        for link in links.iter_mut() {
            if ends_with(world, link.spec, queue) {
                world.close(link, now, Reason::Closed, source, None);
            }
        }
        self.links.retain(|l| !matches!(l.state, State::Gone));
        Ok(core::mem::take(&mut self.world.out))
    }

    /// Change the period of a queue (spec §10.6 (1)). Strict: a send queue's link is replaced (new key and phase); a
    /// recv queue's link is untouched at the call and hands over at an instant drawn at it (S-1, Q296; `World::step_due`).
    ///
    /// # Errors
    /// [`SchedError::UnknownQueue`], [`SchedError::BadPeriod`], [`SchedError::RateBound`], [`SchedError::Unavailable`]
    /// (nothing changes, Q301).
    pub fn set_queue_period<S: CellSource>(
        &mut self,
        now: u64,
        queue: QueueId,
        period_ms: u64,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        if !self.world.params.period_valid(period_ms) {
            return Err(SchedError::BadPeriod);
        }
        if self.world.sends.iter().any(|s| s.id == queue) {
            self.set_send_period(now, queue, period_ms, source)?;
        } else {
            let end = self.plan_recv_period(now, queue, period_ms, false)?;
            self.apply_recv_period(queue, period_ms, end);
        }
        Ok(core::mem::take(&mut self.world.out))
    }

    /// `check_balanced` for the recv-queue `queue` (on `relay`) at `period_ms`, in the rate sum if `counts`, with nothing
    /// changed (Q301: a refusal comes before any draw).
    fn check_changed(
        &self,
        relay: RelayId,
        queue: QueueId,
        period_ms: u64,
        counts: bool,
        mode: Mode,
    ) -> Result<(), SchedError> {
        if self.world.params.slot_ms(mode).is_none() {
            return Ok(());
        }
        let on_relay = self.world.recvs.iter().filter(|r| r.relay == relay);
        if on_relay.clone().count() > FETCH_MULTI_LIMIT {
            return Err(SchedError::TooManyQueues);
        }
        let periods = on_relay
            .filter(|r| r.id != queue && !r.pool)
            .map(|r| r.period_ms)
            .chain(counts.then_some(period_ms));
        if self.world.params.rate_bound_ok(mode, periods) {
            Ok(())
        } else {
            Err(SchedError::RateBound)
        }
    }

    /// A recv-queue's period change, checked and drawn with nothing changed (Q301; S-1, Q296): the instant its Strict link
    /// ends — `U[0, 3 min]` after `now` when the period changes in Strict — or `None`. `leaves_pool`: a hand-out.
    fn plan_recv_period(
        &mut self,
        now: u64,
        queue: QueueId,
        period_ms: u64,
        leaves_pool: bool,
    ) -> Result<Option<u64>, SchedError> {
        let rq = self
            .world
            .recvs
            .iter()
            .find(|r| r.id == queue)
            .ok_or(SchedError::UnknownQueue)?;
        let (relay, was, counts) = (rq.relay, rq.period_ms, leaves_pool || !rq.pool);
        let mode = self.world.effective_mode();
        self.check_changed(relay, queue, period_ms, counts, mode)?;
        if mode == Mode::Strict && was != period_ms {
            return Ok(Some(now.saturating_add(self.world.phase()?)));
        }
        Ok(None)
    }

    /// Apply [`Scheduler::plan_recv_period`]; cannot fail.
    fn apply_recv_period(&mut self, queue: QueueId, period_ms: u64, end: Option<u64>) {
        if let Some(rq) = self.world.recv_mut(queue) {
            rq.period_ms = period_ms;
        }
        let Some(end) = end else {
            return;
        };
        // spec §10.1, §10.6 (1), S-1 (Q296): nothing reaches the wire at a hand-out (a user action or a
        // received reply); the successor starts at an independent draw `U[0, 3 min]` after it, and the old
        // link ends there
        for link in &mut self.links {
            if link.spec != Spec::Recv(queue) {
                continue;
            }
            match &mut link.state {
                State::Up(up) if up.period != period_ms => {
                    up.die_at = up.die_at.min(end);
                }
                State::Down { at } => *at = (*at).min(end),
                State::Up(_) | State::Connecting { .. } | State::Gone => {}
            }
        }
    }

    /// A send queue's new period (spec §10.6 (1), HB-53): in Strict its link is replaced (new key and phase). Every draw
    /// comes first (Q301): first the teardown draws of the replaced links, made and discarded as before, then the
    /// successor's phase.
    fn set_send_period<S: CellSource>(
        &mut self,
        now: u64,
        queue: QueueId,
        period_ms: u64,
        source: &mut S,
    ) -> Result<(), SchedError> {
        let mut plan = None;
        if self.world.effective_mode() == Mode::Strict {
            for link in self.links.iter().filter(|l| on_queue(l.spec, queue)) {
                reconnect_delay(&self.world.params, &mut self.world.rng, link.closed_before)?;
            }
            plan = Some(self.missing_links(None, Some(queue))?);
        }
        if let Some(sq) = self.world.send_mut(queue) {
            sq.period_ms = period_ms;
        }
        if let Some(plan) = plan {
            let (world, links) = (&mut self.world, &mut self.links);
            for link in links.iter_mut() {
                if on_queue(link.spec, queue) {
                    world.close(link, now, Reason::Closed, source, None);
                }
            }
            self.links.retain(|l| !matches!(l.state, State::Gone));
            self.add_links(now, plan);
        }
        Ok(())
    }

    /// Whether a link of `spec` exists that is not `Gone` (Q301: the plan of the links to add is drawn before it is applied).
    fn has_link(&self, spec: Spec) -> bool {
        self.links
            .iter()
            .any(|l| l.spec == spec && !matches!(l.state, State::Gone))
    }

    /// One phase `U[0, 3 min]` per spec, in order, drawn before any link is added (Q301); stops at the first failure.
    fn draw_links(&mut self, specs: Vec<Spec>) -> Result<Vec<(Spec, u64)>, SchedError> {
        specs
            .into_iter()
            .map(|s| Ok((s, self.world.phase()?)))
            .collect()
    }

    /// Add the links of a plan drawn by [`Scheduler::draw_links`]: each starts at its phase after `now`; cannot fail (Q301).
    fn add_links(&mut self, now: u64, plan: Vec<(Spec, u64)>) {
        for (spec, phase) in plan {
            let logical = self.world.new_logical_id();
            self.links.push(Link {
                spec,
                logical,
                state: State::Down {
                    at: now.saturating_add(phase),
                },
                closed_before: 0,
                rr: 0,
            });
        }
    }

    /// The links the queue set needs and does not have yet, with their phases drawn (Q301): `adding` is a queue about to be
    /// registered, and the links of `replacing` count as missing (they are about to be closed).
    fn missing_links(
        &mut self,
        adding: Option<(QueueId, RelayId, bool)>,
        replacing: Option<QueueId>,
    ) -> Result<Vec<(Spec, u64)>, SchedError> {
        let mut specs = self.world.wanted_specs(self.world.effective_mode(), adding);
        specs.retain(|s| replacing.is_some_and(|q| on_queue(*s, q)) || !self.has_link(*s));
        self.draw_links(specs)
    }

    /// Change the mode (spec `docs/02` §4.4): every link is torn down (`TornDown(ModeChange)`) and the links of the
    /// new mode start `U[0, 3 min]` from `now`, each drawn on its own.
    ///
    /// # Errors
    /// [`SchedError::RateBound`] / [`SchedError::TooManyQueues`] if the recv-queues do not fit the new mode (nothing
    /// changes); [`SchedError::Unavailable`] without randomness (nothing changes either, Q301).
    pub fn set_mode<S: CellSource>(
        &mut self,
        now: u64,
        mode: Mode,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        self.change_mode(now, mode, self.world.direct, source)
    }

    /// Direct (non-Tor) mode implies Balanced (spec §10.2).
    ///
    /// # Errors
    /// As [`Scheduler::set_mode`].
    pub fn set_direct<S: CellSource>(
        &mut self,
        now: u64,
        direct: bool,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        self.change_mode(now, self.world.mode, direct, source)
    }

    fn change_mode<S: CellSource>(
        &mut self,
        now: u64,
        mode: Mode,
        direct: bool,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        let effective = if direct && mode == Mode::Strict {
            Mode::Balanced
        } else {
            mode
        };
        let relays: Vec<RelayId> = self.world.recvs.iter().map(|r| r.relay).collect();
        for relay in relays {
            self.check_balanced(relay, None, effective)?;
        }
        let before = self.world.effective_mode();
        if effective == before {
            (self.world.mode, self.world.direct) = (mode, direct);
            return Ok(Vec::new());
        }
        // Q301 (Q276 extended to the scheduler; EXT3-2): the phases of the new mode's links are drawn before anything changes —
        // a failed draw leaves the mode, the links and the outputs as they were
        let plan = self.draw_links(self.world.wanted_specs(effective, None))?;
        (self.world.mode, self.world.direct) = (mode, direct);
        let (world, links) = (&mut self.world, &mut self.links);
        for link in links.iter_mut() {
            world.close(link, now, Reason::ModeChange, source, None);
        }
        self.links.clear();
        self.add_links(now, plan);
        Ok(core::mem::take(&mut self.world.out))
    }

    // ---- the pool and the control operations ----------------------------------------------------------------------

    /// Keep spare recv-queues on `relay` (spec §10.6 (3)): the creations are queued as control operations.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn manage_pool(&mut self, now: u64, relay: RelayId) -> Result<(), SchedError> {
        // Q301 (EXT3b-5, Q304): the refill is drawn before the relay is managed — a failed draw changes nothing — then applied through a path that cannot fail
        let missing = self.world.room_for(self.world.pool.missing_with(relay));
        let delays = self.world.draw_top_up(&missing)?;
        self.world.pool.manage(relay);
        self.world.apply_top_up(now, &missing, delays);
        Ok(())
    }

    /// Whether the pool still creates the spare `queue` (its `QUEUE_NEW` is scheduled or running).
    #[must_use]
    pub fn pool_pending(&self, queue: QueueId) -> bool {
        self.world.pool.pending_relay(queue).is_some()
    }

    /// Spare queues on `relay`.
    #[must_use]
    pub fn pool_spares(&self, relay: RelayId) -> usize {
        self.world.pool.spares(relay)
    }

    /// The host created the queue of a `QueueNew(queue)` operation: it is a spare, fetched at `P_POOL`.
    /// Without randomness it stays a creation under way and is registered at a later `work` pass (EXT3b-3, Q304): `Ok`.
    ///
    /// # Errors
    /// [`SchedError::UnknownQueue`] if `queue` was not a pool creation; the add errors.
    pub fn pool_queue_ready(
        &mut self,
        now: u64,
        queue: QueueId,
        cap: RecvCap,
    ) -> Result<(), SchedError> {
        let relay = self
            .world
            .pool
            .pending_relay(queue)
            .ok_or(SchedError::UnknownQueue)?;
        let period = self.world.params.p_pool_ms;
        // admitted first: a refused queue (more than 32 entries) leaves the pool as it was
        let plan = match self.plan_recv(queue, relay, period, true) {
            Ok(plan) => plan,
            // EXT3b-3 (Q304): the queue exists on the relay; without randomness it waits for a later pass, never created twice
            Err(SchedError::Unavailable) => {
                self.world.parked.push((queue, cap));
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        self.push_recv(now, (queue, relay, period, true), cap, plan);
        self.world.pool.created(queue);
        Ok(())
    }

    /// A spare that already exists on the relay — one the host stored, at an open (M7-C1, D4′): it is registered as created
    /// and fetched at `P_POOL`, counted in the pool, and the queue-id counter is raised above it. Nothing is created.
    ///
    /// # Errors
    /// [`SchedError::DuplicateQueue`] if `queue` is registered; the add errors.
    pub fn adopt_pool_queue(
        &mut self,
        now: u64,
        relay: RelayId,
        queue: QueueId,
        cap: RecvCap,
    ) -> Result<(), SchedError> {
        if self.has_queue(queue) {
            return Err(SchedError::DuplicateQueue);
        }
        let period = self.world.params.p_pool_ms;
        self.add_recv_with_id(now, queue, relay, cap, period, true)?;
        self.world.pool.adopt(relay, queue);
        self.floor_queue_ids(queue.0.saturating_add(1));
        Ok(())
    }

    /// Raise the queue-id counter to at least `next`: the ids the scheduler makes for its own pool creations stay above
    /// every id the host stored (the hub's and the scheduler's ids share one space).
    pub fn floor_queue_ids(&mut self, next: u32) {
        self.world.next_queue = self.world.next_queue.max(next);
    }

    /// Hand out a spare of `relay` for an invitation announced with `announced_ms`: its link is replaced by one at the
    /// announced period, and a replacement spare is queued (not now: a `QUEUE_NEW` is never needed at that moment).
    ///
    /// # Errors
    /// [`SchedError::BadPeriod`], [`SchedError::RateBound`], [`SchedError::Unavailable`]. A refusal or a failed draw changes
    /// nothing (Q301).
    pub fn take_pool_queue<S: CellSource>(
        &mut self,
        now: u64,
        relay: RelayId,
        announced_ms: u64,
        source: &mut S,
    ) -> Result<(Option<QueueId>, Vec<Output>), SchedError> {
        self.take_spare(now, (relay, None), announced_ms, source)
    }

    /// [`Scheduler::take_pool_queue`] for the named spare `queue` (the one the host's store handed out, M7-C1, D4′);
    /// `None` if it is not a spare of `relay` (yet).
    ///
    /// # Errors
    /// As [`Scheduler::take_pool_queue`].
    pub fn take_pool_queue_id<S: CellSource>(
        &mut self,
        now: u64,
        relay: RelayId,
        queue: QueueId,
        announced_ms: u64,
        source: &mut S,
    ) -> Result<(Option<QueueId>, Vec<Output>), SchedError> {
        self.take_spare(now, (relay, Some(queue)), announced_ms, source)
    }

    fn take_spare<S: CellSource>(
        &mut self,
        now: u64,
        (relay, named): (RelayId, Option<QueueId>),
        announced_ms: u64,
        _source: &mut S,
    ) -> Result<(Option<QueueId>, Vec<Output>), SchedError> {
        if !self.world.params.period_valid(announced_ms) {
            return Err(SchedError::BadPeriod);
        }
        // Q301 (Q276 extended to the scheduler; EXT3-2): which spare, the rate bound and every draw — the handover instant, the
        // refill's delays — come before the first change; a refusal or a failed draw leaves the pool, the spare and its link as they were
        let found = match named {
            None => self.world.pool.oldest(relay),
            Some(q) => self.world.pool.position(relay, q).map(|_| q),
        };
        let Some(queue) = found else {
            return Ok((None, Vec::new()));
        };
        let end = self.plan_recv_period(now, queue, announced_ms, true)?;
        let missing = self
            .world
            .room_for(self.world.pool.missing_after_take(relay, queue));
        let delays = self.world.draw_top_up(&missing)?;
        // nothing below can fail
        let handed = self.world.pool.take_named(relay, queue);
        debug_assert_eq!(handed, Some(queue));
        if let Some(rq) = self.world.recv_mut(queue) {
            rq.pool = false;
        }
        self.apply_recv_period(queue, announced_ms, end);
        self.world.apply_top_up(now, &missing, delays);
        Ok((Some(queue), core::mem::take(&mut self.world.out)))
    }

    /// The control operations' randomness, replaced (tests only; EXT3b-3: a schedule that finds none).
    #[cfg(test)]
    pub(crate) fn set_control_rng(&mut self, rng: TimingRng) {
        self.world.ctl = rng;
    }

    /// Queue a control operation (spec §10.6 (2)).
    /// A `LINK_PUT` or owner-status `LINK_GET` that joins the operation already queued for its link data (Q304, `ControlOps::coalesced`) returns that operation's id; no id is taken and nothing is drawn.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn schedule_control(
        &mut self,
        now: u64,
        kind: ControlKind,
        relay: RelayId,
        related: u64,
        when: When,
    ) -> Result<OpId, SchedError> {
        // Q304 (EXT3b-4): it joins the link data's waiting or running operation
        if let Some(op) = self.world.control.coalesced(kind, relay) {
            return Ok(op);
        }
        let op = self.world.new_op_id();
        self.world.control.schedule(
            &self.world.params,
            &mut self.world.ctl,
            op,
            now,
            OpSpec {
                kind,
                relay,
                related,
                when,
            },
        )?;
        Ok(op)
    }

    /// When `op` starts, while it waits.
    #[must_use]
    pub fn control_due(&self, op: OpId) -> Option<u64> {
        self.world.control.due_of(op)
    }

    /// The operation ran: it is done.
    pub fn control_done(&mut self, op: OpId) {
        if let Some(ControlKind::QueueNew(q)) = self.world.control.kind_of(op)
            && let Some(rq) = self.world.recv_mut(q)
        {
            rq.recreating = false;
        }
        self.world.control.done(op);
    }

    /// The operation's link failed before it could run; it is attempted again after the back-off.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn control_failed(
        &mut self,
        now: u64,
        op: OpId,
        closed_before_relayinfo: bool,
    ) -> Result<(), SchedError> {
        self.world.control.failed(
            &self.world.params,
            &mut self.world.ctl,
            op,
            now,
            closed_before_relayinfo,
        )?;
        Ok(())
    }

    /// The link was up and no answer was committed (Q300 phase rule, M7-S4d): it is queued again as a fresh delayed
    /// operation (spec §10.6 (2)).
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn control_answered(&mut self, now: u64, op: OpId) -> Result<(), SchedError> {
        self.world
            .control
            .answered(&self.world.params, &mut self.world.ctl, op, now)?;
        Ok(())
    }

    /// The owner-status answer for link data `ld` (spec §9.7 (1)): `{0, 0}` before `expires` re-issues the identical
    /// `LINK_PUT` after `U[1 min, 60 min]`.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn owner_status(
        &mut self,
        now: u64,
        relay: RelayId,
        ld: u32,
        present: bool,
        consumed: bool,
        expired: bool,
    ) -> Result<Option<OpId>, SchedError> {
        if present || consumed || expired {
            return Ok(None);
        }
        self.schedule_control(
            now,
            ControlKind::LinkPut(ld),
            relay,
            u64::from(ld),
            When::Delayed,
        )
        .map(Some)
    }

    // ---- the driver's calls ---------------------------------------------------------------------------------------

    /// The earliest time the scheduler needs [`Scheduler::poll`] again.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        let mut best: Option<u64> = self.world.control.next_due();
        let mut take = |t: u64| best = Some(best.map_or(t, |b| b.min(t)));
        for link in &self.links {
            match &link.state {
                State::Down { at } => take(*at),
                State::Up(up) => {
                    take(up.die_at);
                    if let Some(next) = up.k.checked_add(1)
                        && let Some(at) = tick_time(up.since, next, up.period)
                    {
                        take(at);
                        let lead = fetch_lead_deadline(at, self.world.params.fetch_lead_ms);
                        if lead > self.world.last_now {
                            take(lead);
                        }
                    }
                }
                State::Connecting { .. } | State::Gone => {}
            }
        }
        best
    }

    /// The activity-dependent part of a pass at `now`: what teardowns held goes back to the cell source, the next
    /// ticks' frames are prepared (the cell source is called, cells are sealed and persisted), due control operations
    /// start. Nothing here writes a frame.
    fn work_pass<S: CellSource>(&mut self, now: u64, source: &mut S) -> Result<(), SchedError> {
        self.world.last_now = self.world.last_now.max(now);
        // EXT3b-3 (Q304): a created spare that found no randomness, once per pass
        self.register_parked(now);
        let (world, links) = (&mut self.world, &mut self.links);
        World::begin_work(links);
        let held = core::mem::take(&mut world.deferred);
        for (queue, token) in held.discards {
            source.discard(queue, token);
        }
        for (queue, token) in held.failures {
            source.send_failed(queue, token, SendFailure::Unknown);
        }
        // the responses that arrived: their cells are decided, committed and acknowledged here
        for p in core::mem::take(&mut world.pending) {
            let fit = world.outcome(p.req, p.outcome, p.at, source)?;
            if !fit
                && let Some(link) = links.iter_mut().find(|l| match &l.state {
                    State::Up(up) => up.id == p.link,
                    _ => false,
                })
            {
                world.tear(link, now, Reason::Rejected, source)?;
            }
        }
        for link in links.iter_mut() {
            world.prepare_link(link, now, source)?;
        }
        for due in world.control.take_due(now) {
            let key = world.new_key();
            let transport = world.transport();
            world.out.push(Output::Control {
                op: due.id,
                key,
                relay: due.relay,
                kind: due.kind,
                transport,
            });
        }
        self.links.retain(|l| !matches!(l.state, State::Gone));
        Ok(())
    }

    /// What is due at `now`, and nothing that depends on activity (reviewer VD-M6-A-12): connections whose time has
    /// come ([`Output::Connect`]), links at their lifetime, the writes of due ticks ([`Output::Write`]), teardown and
    /// overrun decisions. It calls no cell source, seals nothing and persists nothing. The driver writes the returned
    /// frames to its sockets before it calls [`Scheduler::work`] or anything else.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`] without randomness (fail closed).
    pub fn poll_due(&mut self, now: u64) -> Result<Vec<Output>, SchedError> {
        self.world.last_now = self.world.last_now.max(now);
        let (world, links) = (&mut self.world, &mut self.links);
        let mut held = core::mem::take(&mut world.deferred);
        let mut result = Ok(());
        for link in links.iter_mut() {
            result = world.step_due(link, now, &mut held);
            if result.is_err() {
                break;
            }
        }
        world.deferred = held;
        self.links.retain(|l| !matches!(l.state, State::Gone));
        result?;
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The activity-dependent work at `now` (the start of the work): what teardowns held goes back to the cell source,
    /// the frames of the next ticks are prepared, due control operations start. Received cells are decided by the
    /// calls that carry the responses ([`Scheduler::on_frame`]), which run the same pass. The driver reports when this
    /// work finished with [`Scheduler::prepared_until`].
    ///
    /// # Errors
    /// [`SchedError::Unavailable`] without randomness (fail closed).
    pub fn work<S: CellSource>(
        &mut self,
        now: u64,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        self.work_pass(now, source)?;
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The driver reports that the work that began with the latest [`Scheduler::work`] (or response call) finished at
    /// `end`: the frames it prepared are ready at `end`. A frame whose tick is before `end` is an overrun at its tick.
    pub fn prepared_until(&mut self, end: u64) {
        for link in &mut self.links {
            if let State::Up(up) = &mut link.state {
                for part in [up.send_part.as_mut(), up.fetch_part.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    if part.open {
                        part.ready = part.ready.max(end);
                        part.open = false;
                    }
                }
            }
        }
    }

    /// `poll_due`, `work` and `prepared_until(now)` in one call, for callers that do not model the cost of the work
    /// (the unit tests of the core). The writes come first in the returned list. A driver that models costs or has real
    /// sockets uses the three calls.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`] without randomness (fail closed).
    pub fn poll<S: CellSource>(
        &mut self,
        now: u64,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        let mut outs = self.poll_due(now)?;
        outs.extend(self.work(now, source)?);
        self.prepared_until(now);
        Ok(outs)
    }

    fn find(&mut self, id: LinkId) -> Option<usize> {
        self.links.iter().position(|l| match &l.state {
            State::Connecting { id: c } => *c == id,
            State::Up(up) => up.id == id,
            State::Down { .. } | State::Gone => false,
        })
    }

    /// The driver has written frame `frame` of `link` (an [`Output::Write`]) completely — the stream took every byte; a
    /// failed or partial write is not a completion. A `SEND` frame commits the Balanced round-robin position here (A′,
    /// GLM2B-1 / FIN-2): a link torn down before its frame was written leaves the rotation where it was. Frames complete
    /// in the order they were handed out; an unknown or closed link is ignored (`Ok`).
    ///
    /// # Errors
    /// [`SchedError::UnknownFrame`] if `frame` is not the oldest frame handed out on the up link `link` — its ledger is
    /// empty (a write that was never handed out) or the report is a duplicate (FINAL3 (e)): it is counted
    /// ([`Scheduler::unmatched_written`]) and changes nothing else (the ledger and the rotation are untouched).
    pub fn frame_written(&mut self, link: LinkId, frame: FrameId) -> Result<(), SchedError> {
        for l in &mut self.links {
            if let State::Up(up) = &mut l.state
                && up.id == link
            {
                if complete_oldest(&mut up.unwritten, &mut l.rr, &frame) {
                    return Ok(());
                }
                self.world.unmatched_written = self.world.unmatched_written.saturating_add(1);
                return Err(SchedError::UnknownFrame);
            }
        }
        Ok(())
    }

    /// The handshake of connection `id` succeeded at `now`: the link is up; its lifetime is drawn now.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn link_up(
        &mut self,
        id: LinkId,
        now: u64,
        chan: Channel,
    ) -> Result<Vec<Output>, SchedError> {
        let Some(at) = self.find(id) else {
            return Ok(Vec::new());
        };
        let (lo, hi) = self.world.params.lifetime_ms;
        let life = self.world.rng.uniform(lo, hi)?;
        let (world, links) = (&mut self.world, &mut self.links);
        if let Some(link) = links.get_mut(at)
            && let State::Connecting { .. } = link.state
        {
            let Some(period) = world.period_of(link.spec) else {
                link.state = State::Gone;
                return Ok(Vec::new());
            };
            link.closed_before = 0;
            link.state = State::Up(Box::new(Up {
                id,
                chan,
                since: now,
                die_at: now.saturating_add(life),
                k: 0,
                period,
                send_part: None,
                fetch_part: None,
                flight: InFlight::new(world.params.max_in_flight),
                unwritten: Vec::new(),
            }));
            world
                .out
                .push(Output::Event(LinkEvent::Up(id, link.logical)));
        }
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The connection could not be made (`closed_before_relayinfo`: the relay closed before `RELAYINFO`, spec §9.7
    /// (7)): the next attempt follows the back-off.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn connect_failed(
        &mut self,
        id: LinkId,
        now: u64,
        closed_before_relayinfo: bool,
    ) -> Result<Vec<Output>, SchedError> {
        let Some(at) = self.find(id) else {
            return Ok(Vec::new());
        };
        let (world, links) = (&mut self.world, &mut self.links);
        if let Some(link) = links.get_mut(at) {
            let (closed, reason) = if closed_before_relayinfo {
                (
                    link.closed_before.saturating_add(1),
                    Reason::ClosedBeforeRelayInfo,
                )
            } else {
                (0, Reason::Closed)
            };
            // Q301: the back-off is drawn before anything changes
            let delay = reconnect_delay(&world.params, &mut world.rng, closed)?;
            link.closed_before = closed;
            // the driver already dropped the connection: no `Close` for it
            world
                .out
                .push(Output::Event(LinkEvent::TornDown(id, link.logical, reason)));
            link.state = State::Down {
                at: now.saturating_add(delay),
            };
        }
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The stream of connection `id` ended.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn on_closed(&mut self, id: LinkId, now: u64) -> Result<Vec<Output>, SchedError> {
        let Some(at) = self.find(id) else {
            return Ok(Vec::new());
        };
        let (world, links) = (&mut self.world, &mut self.links);
        if let Some(link) = links.get_mut(at) {
            world.tear_deferred(link, now, Reason::Closed)?;
        }
        Ok(core::mem::take(&mut self.world.out))
    }

    /// A frame arrived on connection `id` (exactly 4352 bytes): it is matched to the oldest outstanding request, and the
    /// in-flight count moves when that request's response is complete. This is cheap and touches no cell source: the
    /// cells of a completed response are decided, committed and acknowledged by the next [`Scheduler::work`], never
    /// between `poll_due` and the driver's flush (reviewer VD-M6-A-12).
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn on_frame(
        &mut self,
        id: LinkId,
        now: u64,
        unit: &[u8],
    ) -> Result<Vec<Output>, SchedError> {
        let Some(at) = self.find(id) else {
            return Ok(Vec::new());
        };
        let (world, links) = (&mut self.world, &mut self.links);
        if let Some(link) = links.get_mut(at) {
            let mut bad = false;
            let mut done = None;
            if let State::Up(up) = &mut link.state {
                match up.chan.accept(unit) {
                    Ok(None) => {}
                    Ok(Some(completed)) => done = Some(completed),
                    Err(_) => bad = true,
                }
                if let Some(completed) = &done
                    && up.flight.front().is_none_or(|r| r.seq != completed.seq)
                {
                    bad = true;
                    done = None;
                }
            }
            if bad {
                world.tear_deferred(link, now, Reason::Rejected)?;
            } else if let Some(completed) = done {
                let mut req = None;
                if let State::Up(up) = &mut link.state {
                    req = up.flight.complete();
                }
                if let Some(req) = req {
                    world.pending.push_back(PendingOutcome {
                        link: id,
                        req,
                        outcome: completed.outcome,
                        at: now,
                    });
                }
            }
        }
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The `QueueRef` of a recv-queue (what `FETCH_MULTI` names).
    #[must_use]
    pub fn queue_ref(&self, queue: QueueId) -> Option<QueueRef> {
        self.world
            .recvs
            .iter()
            .find(|r| r.id == queue)
            .map(|r| r.cap.queue())
    }
}

/// Unit tests of the core with an up link (feature `kat`: a channel over a real SecMP-LINK handshake).
#[cfg(test)]
#[cfg(feature = "kat")]
mod tests {
    use secmp_crypto::{Ed25519SigningKey, MlKem1024Dk, SecretBytes, X25519Secret};
    use secmp_proto::link::client;
    use secmp_proto::link::relay::{self, RelayKeys};
    use secmp_proto::tr::OsEntropy;
    use secmp_proto::wire::cell::Cell;
    use secmp_transport::{Channel, Error as TransportError, Outcome, RecvCap, SendCap};

    use super::{LinkId, SchedError, Scheduler};
    use crate::scheduler::params::{Mode, Params};
    use crate::scheduler::types::{
        CellSource, CellToken, ControlKind, Delivered, FrameId, LinkEvent, LinkKind, Output,
        PreparedCell, QueueId, Reason, RelayId, SendFailure, SourceError,
    };
    use crate::timing::TimingRng;

    type Fail = &'static str;

    const NOW: u64 = 1_760_000_000;

    /// The client end of an honest SecMP-LINK handshake (spec §8.2, §8.3) as a channel.
    fn channel() -> Result<Channel, Fail> {
        let access = SecretBytes::from_slice(&[4; 32]).map_err(|_| "access")?;
        let keys = RelayKeys::new(
            Ed25519SigningKey::from_seed(&[1; 32]).map_err(|_| "sig")?,
            X25519Secret::from_bytes(&[2; 32]).map_err(|_| "dh")?,
            MlKem1024Dk::from_seed(&[3; 64]).map_err(|_| "kem")?,
            SecretBytes::from_slice(&[4; 32]).map_err(|_| "access")?,
            1,
        )
        .map_err(|_| "keys")?;
        let (hello, wait_info) =
            client::start(keys.fp(), Some(&access), NOW).map_err(|_| "hello")?;
        let (info, wait_hs1) = relay::accept(&keys)
            .on_hello(&hello, NOW.saturating_add(86_400))
            .map_err(|_| "relayinfo")?;
        let (hs1, wait_hs2) = wait_info
            .on_relayinfo(&info, &mut OsEntropy)
            .map_err(|_| "hs1")?;
        let (hs2, _relay) = wait_hs1.on_hs1(&hs1, &mut OsEntropy).map_err(|_| "hs2")?;
        let link = wait_hs2.on_hs2(&hs2).map_err(|_| "link")?;
        Ok(Channel::from_link_kat(link))
    }

    /// A cell source with a dummy cell for every slot.
    struct Dummies(u64);

    impl CellSource for Dummies {
        fn prepare_cell(
            &mut self,
            _: QueueId,
            _: u64,
        ) -> Result<Option<PreparedCell>, SourceError> {
            self.0 = self.0.saturating_add(1);
            let cell = Cell::from_bytes(&[0x5a; 4096]).map_err(|_| SourceError)?;
            Ok(Some(PreparedCell::unpersisted_kat(cell, CellToken(self.0))))
        }
        fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
        fn evicted(&mut self, _: QueueId, _: u64) {}
        fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
        fn discard(&mut self, _: QueueId, _: CellToken) {}
        fn queue_lost(&mut self, _: QueueId) {}
        fn deliver(
            &mut self,
            _: QueueId,
            _: u64,
            _: u64,
            _: &Cell,
        ) -> Result<Delivered, SourceError> {
            Ok(Delivered::Committed)
        }
    }

    /// A cell source that refuses every received cell (`deliver` fails) and has nothing to send.
    struct Refusing;

    impl CellSource for Refusing {
        fn prepare_cell(
            &mut self,
            _: QueueId,
            _: u64,
        ) -> Result<Option<PreparedCell>, SourceError> {
            Ok(None)
        }
        fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
        fn evicted(&mut self, _: QueueId, _: u64) {}
        fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
        fn discard(&mut self, _: QueueId, _: CellToken) {}
        fn queue_lost(&mut self, _: QueueId) {}
        fn deliver(
            &mut self,
            _: QueueId,
            _: u64,
            _: u64,
            _: &Cell,
        ) -> Result<Delivered, SourceError> {
            Err(SourceError)
        }
    }

    /// A cell source whose decisions are never committed in the call (`Delivered::Pending`).
    struct PendingSource;

    impl CellSource for PendingSource {
        fn prepare_cell(
            &mut self,
            _: QueueId,
            _: u64,
        ) -> Result<Option<PreparedCell>, SourceError> {
            Ok(None)
        }
        fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
        fn evicted(&mut self, _: QueueId, _: u64) {}
        fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
        fn discard(&mut self, _: QueueId, _: CellToken) {}
        fn queue_lost(&mut self, _: QueueId) {}
        fn deliver(
            &mut self,
            _: QueueId,
            _: u64,
            _: u64,
            _: &Cell,
        ) -> Result<Delivered, SourceError> {
            Ok(Delivered::Pending)
        }
    }

    /// The frames written (link, id).
    fn writes(outs: &[Output]) -> Vec<(LinkId, FrameId)> {
        outs.iter()
            .filter_map(|o| match o {
                Output::Write { link, frame, .. } => Some((*link, *frame)),
                _ => None,
            })
            .collect()
    }

    /// SC-05 (FINAL3 (e)): two frames handed out on a Strict send link and not reported; the second reported before the
    /// first is `Err(UnknownFrame)`; the first is reported written (`Ok`); the same id again — a duplicate with a non-empty
    /// ledger — is `Err(UnknownFrame)`, counted, and leaves the ledger as it was; so does any id on an empty ledger. An
    /// unknown link is ignored.
    #[test]
    fn frame_written_duplicate_detected() -> Result<(), Fail> {
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(9));
        let seed = SecretBytes::from_slice(&[9; 32]).map_err(|_| "seed")?;
        let cap = SendCap::from_route([1; 16], &seed).map_err(|_| "cap")?;
        sched
            .add_send_queue(0, RelayId(0), cap, 10_000)
            .map_err(|_| "queue")?;
        let mut src = Dummies(0);
        let outs = sched.poll(0, &mut src).map_err(|_| "poll")?;
        let link = outs
            .iter()
            .find_map(|o| match o {
                Output::Connect { link, .. } => Some(*link),
                _ => None,
            })
            .ok_or("no connect")?;
        sched.link_up(link, 0, channel()?).map_err(|_| "up")?;
        let _ = sched.work(0, &mut src).map_err(|_| "work")?;
        let first = writes(&sched.poll(10_000, &mut src).map_err(|_| "tick 1")?);
        let second = writes(&sched.poll(20_000, &mut src).map_err(|_| "tick 2")?);
        let (Some((l1, a)), Some((l2, b))) = (first.first().copied(), second.first().copied())
        else {
            return Err("two writes");
        };
        assert_eq!((l1, l2), (link, link));
        assert_ne!(a, b);
        assert_eq!(sched.unwritten_len(link), Some(2));
        // the second frame before the first: not the oldest
        assert_eq!(sched.frame_written(link, b), Err(SchedError::UnknownFrame));
        assert_eq!(
            (sched.unwritten_len(link), sched.unmatched_written()),
            (Some(2), 1)
        );
        assert_eq!(sched.frame_written(link, a), Ok(()));
        assert_eq!(sched.unwritten_len(link), Some(1));
        // the duplicate report of `a` with `b` still in the ledger
        assert_eq!(sched.frame_written(link, a), Err(SchedError::UnknownFrame));
        assert_eq!(
            (sched.unwritten_len(link), sched.unmatched_written()),
            (Some(1), 2)
        );
        assert_eq!(sched.frame_written(link, b), Ok(()));
        // an empty ledger
        assert_eq!(sched.frame_written(link, b), Err(SchedError::UnknownFrame));
        assert_eq!(
            (sched.unwritten_len(link), sched.unmatched_written()),
            (Some(0), 3)
        );
        // an unknown link is ignored
        assert_eq!(sched.frame_written(LinkId(9_999), a), Ok(()));
        assert_eq!(sched.unmatched_written(), 3);
        assert_eq!(
            SchedError::UnknownFrame.to_string(),
            "not the oldest frame handed out"
        );
        Ok(())
    }

    /// Q219 (the fuzz target `scheduler_event_sequence` stamped a `SEND` with the driver's poll time, not the tick's): a
    /// Strict send link up at 200 000 on a queue of period 10 000, polled 35 ms and then 20 ms after its ticks (inside
    /// `driver_jitter_ms`). `Output::Write::at` is the tick's time — 210 000 and 220 000, exactly one period apart — and
    /// the poll times are 35 and 20 ms later (green before and after; the red of Q219 is the fuzz seed
    /// `regress-b4c13-00c9f834`).
    #[test]
    fn sends_stamped_at_tick_are_period_apart_under_late_polls() -> Result<(), Fail> {
        fn stamps(outs: &[Output]) -> Vec<u64> {
            outs.iter()
                .filter_map(|o| match o {
                    Output::Write { at, .. } => Some(*at),
                    _ => None,
                })
                .collect()
        }
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let jitter = params.driver_jitter_ms;
        let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(9));
        let seed = SecretBytes::from_slice(&[9; 32]).map_err(|_| "seed")?;
        let cap = SendCap::from_route([1; 16], &seed).map_err(|_| "cap")?;
        sched
            .add_send_queue(0, RelayId(0), cap, 10_000)
            .map_err(|_| "queue")?;
        let mut src = Dummies(0);
        let outs = sched.poll(200_000, &mut src).map_err(|_| "poll")?;
        let link = outs
            .iter()
            .find_map(|o| match o {
                Output::Connect { link, .. } => Some(*link),
                _ => None,
            })
            .ok_or("no connect")?;
        sched.link_up(link, 200_000, channel()?).map_err(|_| "up")?;
        let _ = sched.work(200_000, &mut src).map_err(|_| "work")?;
        let first = stamps(&sched.poll(210_035, &mut src).map_err(|_| "tick 1")?);
        let second = stamps(&sched.poll(220_020, &mut src).map_err(|_| "tick 2")?);
        let ([a], [b]) = (first.as_slice(), second.as_slice()) else {
            return Err("one write per poll");
        };
        assert_eq!((*a, *b), (210_000, 220_000));
        assert_eq!(b.checked_sub(*a), Some(10_000));
        assert_eq!(
            (210_035_u64.checked_sub(*a), 220_020_u64.checked_sub(*b)),
            (Some(35), Some(20))
        );
        assert!(35 <= jitter);
        Ok(())
    }

    /// OPEN-M7-B-3 (red first on the tree where `delivery_committed` took no generation: the old generation's report
    /// acknowledged the new generation's cell 1): a commit of generation `g` that arrives after the queue was re-created as
    /// `g + 1` is ignored — the acknowledgement of `g + 1` is unchanged; the commit of the current generation moves it.
    #[test]
    fn late_commit_of_old_generation_ignored() -> Result<(), Fail> {
        use secmp_proto::wire::cell::Cell;
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(9));
        let seed = SecretBytes::from_slice(&[0x23; 32]).map_err(|_| "seed")?;
        let cap = RecvCap::from_seed(&seed).map_err(|_| "cap")?;
        let q = sched
            .add_recv_queue(0, RelayId(0), cap, 10_000)
            .map_err(|_| "queue")?;
        let cell = || Cell::from_bytes(&[7_u8; 4096]).map_err(|_| "cell");
        // generation 0 fetches cell 1 (pending), the queue is re-created, generation 1 fetches its cell 1 (pending)
        let mut pending = PendingSource;
        sched
            .world
            .fetched(q, 0, vec![(1, cell()?)], &mut pending, 0);
        sched.world.recreate(q, 0).map_err(|_| "recreate")?;
        sched
            .world
            .fetched(q, 1, vec![(1, cell()?)], &mut pending, 0);
        assert_eq!(sched.acked(q), Some(0));
        // generation 0's worker finishes late
        sched.delivery_committed(q, 0, 1);
        assert_eq!(
            sched.acked(q),
            Some(0),
            "the old generation's commit is ignored"
        );
        sched.delivery_committed(q, 1, 1);
        assert_eq!(
            sched.acked(q),
            Some(1),
            "the current generation's commit counts"
        );
        Ok(())
    }

    /// Q201: `ERR_NOQUEUE` on a recv-queue whose `QUEUE_DEL` waits does not re-create the queue — the retirement is complete
    /// (`LinkEvent::QueueGone`); on any other recv-queue it does (SE-14). Removing the queue drops its `QUEUE_DEL`.
    #[test]
    fn no_queue_on_a_retiring_queue_completes_the_retirement() -> Result<(), Fail> {
        use crate::scheduler::control::When;
        use crate::scheduler::types::{ControlKind, LinkEvent};
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(9));
        let mk = |b: u8| -> Result<RecvCap, &'static str> {
            let seed = SecretBytes::from_slice(&[b; 32]).map_err(|_| "seed")?;
            RecvCap::from_seed(&seed).map_err(|_| "cap")
        };
        let gone = sched
            .add_recv_queue(0, RelayId(0), mk(0x31)?, 10_000)
            .map_err(|_| "queue")?;
        let other = sched
            .add_recv_queue(0, RelayId(0), mk(0x32)?, 10_000)
            .map_err(|_| "queue")?;
        sched
            .schedule_control(
                0,
                ControlKind::QueueDel(gone),
                RelayId(0),
                1,
                When::AfterEmptyFetch(gone),
            )
            .map_err(|_| "del")?;
        assert_eq!(sched.world.control.len(), 1);

        sched
            .world
            .queue_error(gone, TransportError::NoQueue, 0)
            .map_err(|_| "error")?;
        let events = |out: &[Output]| {
            out.iter()
                .filter(|o| matches!(o, Output::Event(LinkEvent::QueueGone(_))))
                .count()
        };
        assert_eq!(events(&sched.world.out), 1);
        assert_eq!(
            sched.world.control.len(),
            1,
            "no QUEUE_NEW: it is not re-created"
        );
        assert!(
            !sched
                .world
                .recvs
                .iter()
                .any(|r| r.id == gone && r.recreating)
        );

        sched
            .world
            .queue_error(other, TransportError::NoQueue, 0)
            .map_err(|_| "error")?;
        assert_eq!(events(&sched.world.out), 1, "another queue raises nothing");
        assert_eq!(sched.world.control.len(), 2, "its QUEUE_NEW is queued");

        let mut src = Dummies(0);
        sched
            .remove_queue(0, gone, &mut src)
            .map_err(|_| "remove")?;
        assert!(!sched.world.control.queue_del_pending(gone));
        assert_eq!(
            sched.world.control.len(),
            1,
            "only the QUEUE_NEW of the other queue is left"
        );
        Ok(())
    }

    /// B-SC mutant killers (`core/mod.rs` `impl Ticked for Req`, `World::current`, the generation guard of
    /// `World::outcome`): a request's tick is its own; `current` holds for the queue's id in its generation only; after a
    /// re-creation an error answer to a `FETCH` asked in the old generation raises nothing, one asked in the new does.
    #[test]
    fn old_generation_errors_change_nothing() -> Result<(), Fail> {
        use super::{Req, ReqKind};
        use crate::scheduler::core::pure::Ticked;
        use crate::scheduler::types::{Alert, LinkEvent};
        let ping = Req {
            tick: 5,
            seq: 1,
            kind: ReqKind::Ping,
        };
        assert_eq!(Ticked::tick(&ping), 5);
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(9));
        let seed = SecretBytes::from_slice(&[0x21; 32]).map_err(|_| "seed")?;
        let cap = RecvCap::from_seed(&seed).map_err(|_| "cap")?;
        let q = sched
            .add_recv_queue(0, RelayId(0), cap, 10_000)
            .map_err(|_| "queue")?;
        assert!(sched.world.current(q, 0));
        assert!(!sched.world.current(q, 1));
        assert!(!sched.world.current(QueueId(99), 0));
        sched.world.recreate(q, 0).map_err(|_| "recreate")?;
        assert!(sched.world.current(q, 1));
        let fetch = |generation| Req {
            tick: 1,
            seq: 1,
            kind: ReqKind::Fetch(q, generation),
        };
        let auth = || Outcome::Fetch(Err(TransportError::Auth));
        let mut src = Dummies(0);
        let fit = sched
            .world
            .outcome(fetch(0), auth(), 0, &mut src)
            .map_err(|_| "old")?;
        assert!(fit);
        let alert = |out: &[Output]| {
            out.iter()
                .any(|o| matches!(o, Output::Event(LinkEvent::Alert(_, Alert::QueueAuth))))
        };
        assert!(
            !alert(&sched.world.out),
            "an old generation's error raises nothing"
        );
        sched
            .world
            .outcome(fetch(1), auth(), 0, &mut src)
            .map_err(|_| "new")?;
        assert!(
            alert(&sched.world.out),
            "the current generation's error raises the alert"
        );
        Ok(())
    }
    /// B-4 killers (`Scheduler::has_queue`, `add_recv_queue_seed`, `add_send_queue_route`): a queue the host registered by
    /// id is known, whichever kind it is; an id in use is refused for both kinds and both orders.
    #[test]
    fn queues_by_id_and_seed() -> Result<(), Fail> {
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(3));
        let seed = |byte: u8| SecretBytes::<32>::from_slice(&[byte; 32]).map_err(|_| "seed");
        assert!(!sched.has_queue(QueueId(5)));
        sched
            .add_recv_queue_seed(0, QueueId(5), RelayId(0), &seed(0x21)?, 10_000)
            .map_err(|_| "recv")?;
        assert!(sched.has_queue(QueueId(5)));
        assert!(!sched.has_queue(QueueId(6)));
        sched
            .add_send_queue_route(0, QueueId(6), RelayId(0), ([7; 16], &seed(0x22)?), 10_000)
            .map_err(|_| "send")?;
        assert!(sched.has_queue(QueueId(6)));
        assert!(!sched.has_queue(QueueId(7)));
        for id in [QueueId(5), QueueId(6)] {
            assert_eq!(
                sched.add_recv_queue_seed(0, id, RelayId(0), &seed(0x23)?, 10_000),
                Err(SchedError::DuplicateQueue)
            );
            assert_eq!(
                sched.add_send_queue_route(0, id, RelayId(0), ([8; 16], &seed(0x24)?), 10_000),
                Err(SchedError::DuplicateQueue)
            );
        }
        assert_eq!(
            sched.add_recv_queue_seed(0, QueueId(8), RelayId(0), &seed(0x25)?, 15_000),
            Err(SchedError::BadPeriod)
        );
        assert_eq!(
            sched.add_send_queue_route(0, QueueId(8), RelayId(0), ([9; 16], &seed(0x26)?), 15_000),
            Err(SchedError::BadPeriod)
        );
        Ok(())
    }

    /// Q209 (VERIFY-B4 P2 M-2; §10.6 (4) `docs/03:696`, the `FETCH_MULTI` row `docs/03:606`): in a `FETCH_MULTI` response a
    /// waiting `QUEUE_DEL` of a queue is armed only if the queue returned no present cell — not when it is in error, not when
    /// the `F_M` frames are all other queues' cells (it may still hold cells), not when a present frame is for it (the
    /// transport's frames are 4096-byte cells: a present frame is present, decodable or not); with only dummies left for
    /// it, it is.
    #[test]
    fn empty_fetch_not_armed_on_error_or_starved_queue() -> Result<(), Fail> {
        use crate::scheduler::control::When;
        use crate::scheduler::types::ControlKind;
        let cell = || Cell::from_bytes(&[7_u8; 4096]).map_err(|_| "cell");
        let seed = |b: u8| SecretBytes::<32>::from_slice(&[b; 32]).map_err(|_| "seed");
        let cap =
            |b: u8| -> Result<RecvCap, Fail> { RecvCap::from_seed(&seed(b)?).map_err(|_| "cap") };
        // (cells for the queue, cells for the other queue, the queue in error, `F_M` of the parameters) -> armed. The one
        // present cell of `(1, 0, ..)` is present although its source refuses it; `F_M = 16` with 8 frames of the other
        // queue: the response is full at the transport's batch of 8, whatever the parameter says (C1-6 a)
        for (mine, others, error, f_m, armed) in [
            (0_u64, 0_u64, true, 8_u64, false),
            (0, 8, false, 8, false),
            (1, 0, false, 8, false),
            (0, 2, false, 8, true),
            (0, 0, false, 8, true),
            (0, 8, false, 16, false),
        ] {
            let params = Params {
                f_m,
                ..Params::default()
            };
            let mut sched = Scheduler::new(params, Mode::Balanced, TimingRng::seeded(21));
            let q = sched
                .add_recv_queue(0, RelayId(0), cap(0x41)?, 10_000)
                .map_err(|_| "queue")?;
            let o = sched
                .add_recv_queue(0, RelayId(0), cap(0x42)?, 10_000)
                .map_err(|_| "queue")?;
            let (rq, ro) = (cap(0x41)?.queue(), cap(0x42)?.queue());
            let op = sched
                .schedule_control(
                    0,
                    ControlKind::QueueDel(q),
                    RelayId(0),
                    1,
                    When::AfterEmptyFetch(q),
                )
                .map_err(|_| "op")?;
            let mut cells = Vec::new();
            for id in 1..=mine {
                cells.push((rq, id, cell()?));
            }
            for id in 1..=others {
                cells.push((ro, id, cell()?));
            }
            let errors = if error {
                vec![(rq, TransportError::Auth)]
            } else {
                Vec::new()
            };
            let queues = [(q, 0), (o, 0)];
            let done = if mine == 1 {
                sched
                    .world
                    .fetched_multi(&queues, cells, &errors, &mut Refusing, 1_000)
            } else {
                sched
                    .world
                    .fetched_multi(&queues, cells, &errors, &mut Dummies(0), 1_000)
            };
            done.map_err(|_| "fetched")?;
            assert_eq!(
                !sched.world.control.awaits_empty_fetch(op),
                armed,
                "mine {mine}, others {others}, error {error}, F_M {f_m}"
            );
        }
        Ok(())
    }

    /// B-4 killer (`World::fetched`, Q194): a `FETCH` response without a cell starts the delay of a waiting `QUEUE_DEL` only
    /// when it was asked in the queue's current generation.
    #[test]
    fn empty_response_of_an_old_generation_arms_nothing() -> Result<(), Fail> {
        use crate::scheduler::control::When;
        use crate::scheduler::types::ControlKind;
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(11));
        let seed = SecretBytes::<32>::from_slice(&[0x31; 32]).map_err(|_| "seed")?;
        sched
            .add_recv_queue_seed(0, QueueId(4), RelayId(0), &seed, 10_000)
            .map_err(|_| "queue")?;
        let op = sched
            .schedule_control(
                0,
                ControlKind::QueueDel(QueueId(4)),
                RelayId(0),
                4,
                When::AfterEmptyFetch(QueueId(4)),
            )
            .map_err(|_| "op")?;
        sched
            .world
            .recreate(QueueId(4), 0)
            .map_err(|_| "recreate")?;
        let mut source = Dummies(0);
        sched
            .world
            .fetched(QueueId(4), 0, Vec::new(), &mut source, 1_000);
        assert!(
            sched.world.control.awaits_empty_fetch(op),
            "generation 0 is old"
        );
        sched
            .world
            .fetched(QueueId(4), 1, Vec::new(), &mut source, 1_000);
        assert!(
            !sched.world.control.awaits_empty_fetch(op),
            "generation 1 is current"
        );
        Ok(())
    }

    /// The connection of every `Output::Connect`.
    fn connects(outs: &[Output]) -> Vec<LinkId> {
        outs.iter()
            .filter_map(|o| match o {
                Output::Connect { link, .. } => Some(*link),
                _ => None,
            })
            .collect()
    }

    /// Strict, no phase, a send queue on relay 1 (`QueueId(0)`) and a recv queue on relay 2 (`QueueId(1)`), both at
    /// 10 000 ms, both links up at 0 (Q301 sweep).
    fn two_relays_up() -> Result<(Scheduler, Dummies), Fail> {
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(31));
        let seed = SecretBytes::from_slice(&[0x51; 32]).map_err(|_| "seed")?;
        let out_cap = SendCap::from_route([5; 16], &seed).map_err(|_| "send cap")?;
        sched
            .add_send_queue(0, RelayId(1), out_cap, 10_000)
            .map_err(|_| "send queue")?;
        let recv = RecvCap::from_seed(&seed).map_err(|_| "recv cap")?;
        sched
            .add_recv_queue(0, RelayId(2), recv, 10_000)
            .map_err(|_| "recv queue")?;
        let mut src = Dummies(0);
        let ids = connects(&sched.poll(0, &mut src).map_err(|_| "poll")?);
        if ids.len() != 2 {
            return Err("two connects");
        }
        for id in ids {
            sched.link_up(id, 0, channel()?).map_err(|_| "up")?;
        }
        Ok((sched, src))
    }

    /// Strict, no phase, a pool of one spare on relay 1 created and up at `T` = 3 600 000: the scheduler, its source, the
    /// spare and `T` (Q301, EXT3-2).
    fn spare_up() -> Result<(Scheduler, Dummies, QueueId, u64), Fail> {
        const T: u64 = 3_600_000;
        let params = Params {
            phase_max_ms: 0,
            pool_target: 1,
            ..Params::default()
        };
        let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(41));
        sched
            .manage_pool(0, RelayId(1))
            .map_err(|_| "manage pool")?;
        let mut src = Dummies(0);
        let outs = sched.poll(T, &mut src).map_err(|_| "poll 1")?;
        let (op, spare) = outs
            .iter()
            .find_map(|o| match o {
                Output::Control {
                    op,
                    kind: ControlKind::QueueNew(q),
                    ..
                } => Some((*op, *q)),
                _ => None,
            })
            .ok_or("no QueueNew")?;
        let seed = SecretBytes::from_slice(&[0x52; 32]).map_err(|_| "seed")?;
        let cap = RecvCap::from_seed(&seed).map_err(|_| "cap")?;
        sched.pool_queue_ready(T, spare, cap).map_err(|_| "ready")?;
        sched.control_done(op);
        let ids = connects(&sched.poll(T, &mut src).map_err(|_| "poll 2")?);
        let [it] = ids.as_slice() else {
            return Err("one connect");
        };
        sched.link_up(*it, T, channel()?).map_err(|_| "up")?;
        Ok((sched, src, spare, T))
    }

    /// The period and the pool flag of the recv queue `q`.
    fn recv_state(sched: &Scheduler, q: QueueId) -> Option<(u64, bool)> {
        sched
            .world
            .recvs
            .iter()
            .find(|r| r.id == q)
            .map(|r| (r.period_ms, r.pool))
    }

    /// Q301 (Q276 extended to the scheduler; EXT3-2): a mode change whose phase draw fails — at the first or at the second
    /// of the two new links — leaves the mode, the links and the outputs as they were, and nothing is torn down later.
    #[test]
    fn set_mode_without_randomness_changes_nothing() -> Result<(), Fail> {
        for budget in [0_u64, 1] {
            let (mut sched, mut src) = two_relays_up()?;
            let before = sched.links();
            sched.world.rng = TimingRng::failing_after(31, budget);
            let call = sched.set_mode(1, Mode::Balanced, &mut src);
            assert_eq!(call.err(), Some(SchedError::Unavailable), "{budget}");
            assert_eq!(
                (sched.effective_mode(), sched.mode()),
                (Mode::Strict, Mode::Strict),
                "{budget}"
            );
            assert_eq!(sched.links(), before, "{budget}");
            assert!(sched.world.out.is_empty(), "{budget}");
            sched.world.rng = TimingRng::seeded(32);
            let outs = sched.poll_due(2).map_err(|_| "poll_due")?;
            let torn = outs.iter().any(|o| {
                matches!(
                    o,
                    Output::Close { .. } | Output::Event(LinkEvent::TornDown(..))
                )
            });
            assert!(!torn, "{budget}");
        }
        Ok(())
    }

    /// Q301 (EXT3-2): a spare handed out whose handover draw fails keeps its period, its pool place and its link.
    #[test]
    fn take_spare_draw_failure_restores_period() -> Result<(), Fail> {
        let (mut sched, mut src, spare, t) = spare_up()?;
        let before = sched.links();
        let ops = sched.world.control.len();
        sched.world.rng = TimingRng::failing();
        let call = sched.take_pool_queue_id(t + 1, RelayId(1), spare, 10_000, &mut src);
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert_eq!(recv_state(&sched, spare), Some((80_000, true)));
        assert_eq!(sched.pool_spares(RelayId(1)), 1);
        assert_eq!(sched.links(), before);
        assert!(sched.world.out.is_empty());
        assert_eq!(sched.world.control.len(), ops);
        Ok(())
    }

    /// Q301 (EXT3-2): after a failed draw the same hand-out, retried, is announced and fetched at the announced period: the
    /// spare's link ends at the handover instant (not at its 6–24 h lifetime) and its successor fetches at 10 s.
    #[test]
    fn take_spare_retry_after_failed_draw_hands_over() -> Result<(), Fail> {
        let (mut sched, mut src, spare, t) = spare_up()?;
        let ops = sched.world.control.len();
        sched.world.rng = TimingRng::failing();
        let first = sched.take_pool_queue_id(t + 1, RelayId(1), spare, 10_000, &mut src);
        assert_eq!(first.err(), Some(SchedError::Unavailable));
        sched.world.rng = TimingRng::seeded(42);
        let at = t + 1;
        let (taken, outs) = sched
            .take_pool_queue_id(at, RelayId(1), spare, 10_000, &mut src)
            .map_err(|_| "retry")?;
        assert_eq!(taken, Some(spare));
        let moved = outs.iter().any(|o| {
            matches!(
                o,
                Output::Close { .. }
                    | Output::Connect { .. }
                    | Output::Event(LinkEvent::TornDown(..))
            )
        });
        assert!(!moved);
        let die_at = sched
            .links()
            .iter()
            .find(|l| l.queue == Some(spare))
            .and_then(|l| l.die_at);
        assert_eq!(die_at, Some(at));
        assert_eq!(recv_state(&sched, spare), Some((10_000, false)));
        assert_eq!(sched.pool_spares(RelayId(1)), 0);
        assert_eq!(sched.world.control.len(), ops + 1);
        let outs = sched.poll(at, &mut src).map_err(|_| "poll")?;
        let torn = outs
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    Output::Event(LinkEvent::TornDown(_, _, Reason::Lifetime))
                )
            })
            .count();
        let connected = outs
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    Output::Connect {
                        kind: LinkKind::Recv,
                        period_ms: 10_000,
                        ..
                    }
                )
            })
            .count();
        assert_eq!((torn, connected), (1, 1));
        Ok(())
    }

    /// Q301 (V-EXT3-2's sibling): a hand-out whose refill draw fails answers `Err` and hands nothing out — the spare, its
    /// period and its link are as they were.
    #[test]
    fn take_spare_refill_draw_failure_hands_out_nothing() -> Result<(), Fail> {
        let (mut sched, mut src, spare, t) = spare_up()?;
        let before = sched.links();
        let ops = sched.world.control.len();
        sched.world.ctl = TimingRng::failing();
        let call = sched.take_pool_queue_id(t + 1, RelayId(1), spare, 10_000, &mut src);
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert_eq!(recv_state(&sched, spare), Some((80_000, true)));
        assert_eq!(sched.pool_spares(RelayId(1)), 1);
        assert_eq!(sched.links(), before);
        assert!(sched.world.out.is_empty());
        assert_eq!(sched.world.control.len(), ops);
        Ok(())
    }

    /// Q301 sweep: a send queue's period change in Strict whose draws fail — in the teardown back-off or in the successor's
    /// phase — changes neither the period nor the links.
    #[test]
    fn send_period_change_without_randomness_changes_nothing() -> Result<(), Fail> {
        for budget in [0_u64, 1] {
            let (mut sched, mut src) = two_relays_up()?;
            let before = sched.links();
            sched.world.rng = TimingRng::failing_after(31, budget);
            let call = sched.set_queue_period(1, QueueId(0), 20_000, &mut src);
            assert_eq!(call.err(), Some(SchedError::Unavailable), "{budget}");
            let period = sched
                .world
                .sends
                .iter()
                .find(|s| s.id == QueueId(0))
                .map(|s| s.period_ms);
            assert_eq!(period, Some(10_000), "{budget}");
            assert_eq!(sched.links(), before, "{budget}");
            assert!(sched.world.out.is_empty(), "{budget}");
        }
        Ok(())
    }

    /// Q301 sweep: a queue removal whose teardown draw fails removes nothing.
    #[test]
    fn remove_queue_without_randomness_changes_nothing() -> Result<(), Fail> {
        let (mut sched, mut src) = two_relays_up()?;
        let before = sched.links();
        sched.world.rng = TimingRng::failing();
        let call = sched.remove_queue(1, QueueId(0), &mut src);
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert!(sched.has_queue(QueueId(0)));
        assert_eq!(sched.links(), before);
        assert!(sched.world.out.is_empty());
        Ok(())
    }

    /// Q301 sweep: a close of an up link whose back-off draw fails leaves the link as it was.
    #[test]
    fn teardown_without_randomness_leaves_the_link() -> Result<(), Fail> {
        let (mut sched, _src) = two_relays_up()?;
        let before = sched.links();
        let id = before.first().and_then(|l| l.id).ok_or("no link id")?;
        sched.world.rng = TimingRng::failing();
        let call = sched.on_closed(id, 1);
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert_eq!(sched.links(), before);
        assert!(sched.world.out.is_empty());
        Ok(())
    }

    /// Q301 sweep: a failed connect whose back-off draw fails does not count the close.
    #[test]
    fn connect_failed_without_randomness_changes_nothing() -> Result<(), Fail> {
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(33));
        let seed = SecretBytes::from_slice(&[0x53; 32]).map_err(|_| "seed")?;
        let cap = SendCap::from_route([6; 16], &seed).map_err(|_| "cap")?;
        sched
            .add_send_queue(0, RelayId(1), cap, 10_000)
            .map_err(|_| "queue")?;
        let mut src = Dummies(0);
        let ids = connects(&sched.poll(0, &mut src).map_err(|_| "poll")?);
        let [id] = ids.as_slice() else {
            return Err("one connect");
        };
        let before = sched.links();
        sched.world.rng = TimingRng::failing();
        let call = sched.connect_failed(*id, 1, true);
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert_eq!(sched.links(), before);
        assert!(sched.world.out.is_empty());
        Ok(())
    }

    /// Q301 sweep: a re-creation whose delay draw fails keeps the generation of the queue and queues nothing.
    #[test]
    fn recreate_without_randomness_keeps_the_generation() -> Result<(), Fail> {
        let (mut sched, _src) = two_relays_up()?;
        let ops = sched.world.control.len();
        sched.world.ctl = TimingRng::failing();
        let call = sched.world.recreate(QueueId(1), 1);
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert!(sched.world.current(QueueId(1), 0));
        let recreating = sched
            .world
            .recvs
            .iter()
            .any(|r| r.id == QueueId(1) && r.recreating);
        assert!(!recreating);
        assert_eq!(sched.world.control.len(), ops);
        Ok(())
    }

    /// Q301 sweep: a pool refill whose second creation's delay draw fails queues nothing, and a later refill queues both.
    #[test]
    fn manage_pool_failed_draw_queues_nothing() -> Result<(), Fail> {
        let params = Params {
            pool_target: 2,
            ..Params::default()
        };
        let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(43));
        sched.world.ctl = TimingRng::failing_after(43, 1);
        let call = sched.manage_pool(0, RelayId(1));
        assert_eq!(call.err(), Some(SchedError::Unavailable));
        assert_eq!(sched.world.control.len(), 0);
        assert!(!sched.pool_pending(QueueId(0)));
        assert_eq!(sched.world.next_queue, 0);
        assert!(
            sched.world.pool.missing().is_empty(),
            "the relay is not managed after a failed draw"
        );
        sched.world.ctl = TimingRng::seeded(44);
        sched.manage_pool(0, RelayId(1)).map_err(|_| "retry")?;
        assert_eq!(sched.world.control.len(), 2);
        assert!(sched.pool_pending(QueueId(0)) && sched.pool_pending(QueueId(1)));
        Ok(())
    }

    /// UA3 — Q304 (EXT3b-4): `schedule_control` and `owner_status` of a `LINK_PUT` whose link data has one waiting return that operation's id: no operation, no id and no draw is added.
    #[test]
    fn schedule_control_returns_the_waiting_link_put() -> Result<(), Fail> {
        use crate::scheduler::control::When;
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(46));
        let first = sched
            .schedule_control(0, ControlKind::LinkPut(7), RelayId(0), 7, When::Delayed)
            .map_err(|_| "first")?;
        let draws = sched.world.ctl.draws();
        let again = sched
            .schedule_control(1, ControlKind::LinkPut(7), RelayId(0), 7, When::Delayed)
            .map_err(|_| "again")?;
        let answer = sched
            .owner_status(2, RelayId(0), 7, false, false, false)
            .map_err(|_| "owner")?;
        assert_eq!((again, answer), (first, Some(first)));
        assert_eq!(
            (
                sched.world.control.len(),
                sched.world.next_op,
                sched.world.ctl.draws()
            ),
            (1, 1, draws)
        );
        Ok(())
    }

    /// The first `QueueNew` control output of `outs`: its operation and queue (T3-1, T3-2).
    fn queue_new(outs: &[Output]) -> Result<(crate::scheduler::types::OpId, QueueId), Fail> {
        outs.iter()
            .find_map(|o| match o {
                Output::Control {
                    op,
                    kind: ControlKind::QueueNew(q),
                    ..
                } => Some((*op, *q)),
                _ => None,
            })
            .ok_or("no QueueNew")
    }

    /// T3-1 — EXT3b-3 (V-EXT3b-34 T3-1): a created spare whose registration finds no randomness stays a creation under way, nothing is registered, and a later pass with randomness registers it — one attempt per pass, no second `QUEUE_NEW`.
    #[test]
    fn pool_queue_ready_without_randomness_registers_at_a_later_pass() -> Result<(), Fail> {
        const T: u64 = 3_600_000;
        let params = Params {
            phase_max_ms: 0,
            pool_target: 1,
            ..Params::default()
        };
        let (mut sched, mut src) = (
            Scheduler::new(params, Mode::Strict, TimingRng::seeded(41)),
            Dummies(0),
        );
        sched
            .manage_pool(0, RelayId(1))
            .map_err(|_| "manage pool")?;
        let (op, spare) = queue_new(&sched.poll(T, &mut src).map_err(|_| "poll 1")?)?;
        let cap = RecvCap::from_seed(&SecretBytes::from_slice(&[0x52; 32]).map_err(|_| "seed")?)
            .map_err(|_| "cap")?;
        sched.world.rng = TimingRng::failing();
        assert_eq!(sched.pool_queue_ready(T, spare, cap), Ok(()));
        assert!(!sched.has_queue(spare) && sched.pool_pending(spare));
        sched.control_done(op);
        sched
            .poll(T.saturating_add(1), &mut src)
            .map_err(|_| "poll without randomness")?;
        assert!(
            !sched.has_queue(spare) && sched.pool_pending(spare),
            "one attempt per pass"
        );
        sched.world.rng = TimingRng::seeded(42);
        sched
            .poll(T.saturating_add(2), &mut src)
            .map_err(|_| "poll 2")?;
        assert!(sched.has_queue(spare) && !sched.pool_pending(spare));
        assert_eq!(
            (sched.pool_spares(RelayId(1)), sched.world.control.len()),
            (1, 0),
            "no second QUEUE_NEW"
        );
        let ids = connects(
            &sched
                .poll(T.saturating_add(3), &mut src)
                .map_err(|_| "poll 3")?,
        );
        assert_eq!(ids.len(), 1, "the spare is fetched");
        Ok(())
    }

    /// T3-2 — EXT3b-3 (V-EXT3b-34 T3-2; spec D.2): in Balanced the pool plans no creation the relay's `FETCH_MULTI` link has no entry for: 31 queues leave room for one spare, and handing it out (it stays an entry) plans no refill.
    #[test]
    fn pool_refill_respects_fetch_multi_entries() -> Result<(), Fail> {
        const T: u64 = 3_600_000;
        let (mut sched, mut src) = (
            Scheduler::new(Params::default(), Mode::Balanced, TimingRng::seeded(45)),
            Dummies(0),
        );
        let cap = |n: u8| -> Result<RecvCap, Fail> {
            RecvCap::from_seed(&SecretBytes::from_slice(&[n; 32]).map_err(|_| "seed")?)
                .map_err(|_| "cap")
        };
        for n in 1..=31_u8 {
            sched
                .add_recv_queue(0, RelayId(1), cap(n)?, 80_000)
                .map_err(|_| "queue")?;
        }
        sched
            .manage_pool(0, RelayId(1))
            .map_err(|_| "manage pool")?;
        assert_eq!(sched.world.control.len(), 1, "room for one spare");
        let (op, spare) = queue_new(&sched.poll(T, &mut src).map_err(|_| "poll")?)?;
        sched
            .pool_queue_ready(T, spare, cap(0x55)?)
            .map_err(|_| "ready")?;
        sched.control_done(op);
        let (taken, _) = sched
            .take_pool_queue_id(T.saturating_add(1), RelayId(1), spare, 80_000, &mut src)
            .map_err(|_| "take")?;
        assert_eq!(
            (taken, sched.world.control.len()),
            (Some(spare), 0),
            "no refill beyond 32 entries"
        );
        Ok(())
    }

    /// S5-1 — Q301 (XREVIEW-M7-S5 S5-1): a queue add whose phase draw fails registers nothing — neither a recv queue nor a send queue, no link.
    #[test]
    fn add_without_randomness_registers_nothing() -> Result<(), Fail> {
        let (mut sched, _src) = two_relays_up()?;
        let before = sched.links();
        let seed = SecretBytes::from_slice(&[0x54; 32]).map_err(|_| "seed")?;
        let cap = RecvCap::from_seed(&seed).map_err(|_| "cap")?;
        sched.world.rng = TimingRng::failing();
        assert_eq!(
            sched.add_recv_queue(1, RelayId(3), cap, 10_000).err(),
            Some(SchedError::Unavailable)
        );
        let added = sched.add_send_queue_route(1, QueueId(9), RelayId(3), ([5; 16], &seed), 10_000);
        assert_eq!(added.err(), Some(SchedError::Unavailable));
        assert!(!sched.has_queue(QueueId(2)) && !sched.has_queue(QueueId(9)));
        assert_eq!(sched.links(), before);
        assert!(sched.world.out.is_empty());
        Ok(())
    }
}

/// Positive control of the tick audit (WEISUNG M6-C1-4, mutants `counters_now -> [0; 4]` / `[1; 4]`): the instrument moves
/// when counted work happens — a blind audit would pass every tick. The counters are thread-local, so the deltas are exact.
#[cfg(test)]
#[cfg(feature = "kat")]
mod m6_mut {
    use super::counters_now;
    use crate::sessions::actor::counters;

    #[test]
    fn counters_now_moves_when_a_counted_step_runs() {
        let before = counters_now();
        counters::note_encrypt("m6_mut");
        counters::note_persist();
        counters::note_persist();
        let after = counters_now();
        let delta: Vec<u64> = after
            .iter()
            .zip(before)
            .map(|(a, b)| a.saturating_sub(b))
            .collect();
        // [seal, sign, tr_encrypt, persist]: nothing sealed or signed here, one encryption, two commits
        assert_eq!(delta, vec![0, 0, 1, 2]);
    }
}
