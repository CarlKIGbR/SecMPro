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
    InFlight, RECEIVED_MAX, RecvLedger, Ticked, complete_oldest, hand_out, ledger_admits,
    reserved_rr, rr_select, sendable, take_response, tick_time, unwritten_max,
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
        crate::scheduler::conversation::counters::tr_encrypt_calls(),
        crate::scheduler::conversation::counters::persist_calls(),
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

    /// Take the connection down. `ModeChange` removes the link; any other reason schedules the next attempt.
    fn tear<R: Release>(
        &mut self,
        link: &mut Link,
        now: u64,
        reason: Reason,
        source: &mut R,
    ) -> Result<(), SchedError> {
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
        if reason != Reason::ModeChange {
            let delay = reconnect_delay(&self.params, &mut self.rng, link.closed_before)?;
            link.state = State::Down {
                at: now.saturating_add(delay),
            };
        }
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
            sq.last_send = Some(at);
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
            let send_missing = needs_send && up.send_part.is_none();
            if tear.is_none() && !send_missing && needs_fetch && up.fetch_part.is_none() {
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
                let lead_reached = now >= slot.saturating_sub(self.params.fetch_lead_ms);
                if (!fetch_outstanding && !commits_pending) || lead_reached {
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
                match rr_select(rr, &table, slot) {
                    Some(at) => {
                        next_rr = Some(
                            at.checked_add(1)
                                .and_then(|n| n.checked_rem(members.len()))
                                .unwrap_or(0),
                        );
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
            Todo::Lifetime => self.tear(link, now, Reason::Lifetime, source)?,
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
        let Some(rq) = self.recvs.iter_mut().find(|r| r.id == queue) else {
            return Ok(());
        };
        if rq.recreating {
            return Ok(());
        }
        rq.recreating = true;
        // a new generation: nothing acknowledged, nothing fetched; a response asked before changes nothing (SC-07)
        rq.ledger.recreate();
        let relay = rq.relay;
        let at = now.saturating_add(self.ctl.uniform(lo, hi)?);
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

    /// The cells of a response for `queue`, asked in `generation`: every present cell goes to the cell source in one pass
    /// and the acknowledgement moves to the highest committed prefix (OQ-20, `pure::RecvLedger::take`).
    fn fetched<S: CellSource>(
        &mut self,
        queue: QueueId,
        generation: u64,
        cells: Vec<(u64, secmp_proto::wire::cell::Cell)>,
        source: &mut S,
    ) {
        let queues = self.recvs.iter_mut().map(|r| (r.id, &mut r.ledger));
        take_response(queues, &queue, generation, cells, |id, cell| {
            source.deliver(queue, id, &cell)
        });
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
                Ok(cells) => self.fetched(queue, generation, cells, source),
                Err(e) if self.current(queue, generation) => self.queue_error(queue, e, now)?,
                Err(_) => {}
            },
            (ReqKind::FetchMulti(queues), Outcome::FetchMulti(result)) => match result {
                Ok(done) => {
                    for (q, generation) in &queues {
                        let Some(rid) = self
                            .recvs
                            .iter()
                            .find(|r| r.id == *q)
                            .map(|r| r.cap.queue())
                        else {
                            continue;
                        };
                        let cells: Vec<_> = done
                            .cells
                            .iter()
                            .filter(|(r, _, _)| *r == rid)
                            .map(|(_, id, cell)| {
                                (
                                    *id,
                                    secmp_proto::wire::cell::Cell::from_bytes(cell.as_bytes()),
                                )
                            })
                            .filter_map(|(id, c)| c.ok().map(|c| (id, c)))
                            .collect();
                        self.fetched(*q, *generation, cells, source);
                        if !self.current(*q, *generation) {
                            continue;
                        }
                        for (r, e) in &done.errors {
                            if *r == rid {
                                self.queue_error(*q, *e, now)?;
                            }
                        }
                    }
                }
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

    fn top_up_pool(&mut self, now: u64) -> Result<(), SchedError> {
        for (relay, need) in self.pool.missing() {
            for _ in 0..need {
                let queue = QueueId(self.next_queue);
                self.next_queue = self.next_queue.saturating_add(1);
                let op = self.new_op_id();
                self.control.schedule(
                    &self.params,
                    &mut self.ctl,
                    op,
                    now,
                    OpSpec {
                        kind: ControlKind::QueueNew(queue),
                        relay,
                        related: u64::MAX.saturating_sub(u64::from(queue.0)),
                        when: When::Delayed,
                    },
                )?;
                self.pool.creating(relay, queue);
            }
        }
        Ok(())
    }
}

const fn reason_of(e: TransportError) -> Reason {
    match e {
        TransportError::NewLinkRequired => Reason::NewLinkRequired,
        TransportError::Closed => Reason::Closed,
        _ => Reason::Rejected,
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
    pub fn delivery_committed(&mut self, queue: QueueId, cell_id: u64) {
        if let Some(rq) = self.world.recv_mut(queue) {
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
        self.world.sends.push(SendQ {
            id,
            relay,
            period_ms,
            cap,
            last_send: None,
            dead: false,
        });
        self.sync_links(now)?;
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

    fn add_recv_with_id(
        &mut self,
        now: u64,
        id: QueueId,
        relay: RelayId,
        cap: RecvCap,
        period_ms: u64,
        pool: bool,
    ) -> Result<(), SchedError> {
        if !self.world.params.period_valid(period_ms) {
            return Err(SchedError::BadPeriod);
        }
        let mode = self.world.effective_mode();
        self.check_balanced(relay, Some((period_ms, !pool)), mode)?;
        self.world.recvs.push(RecvQ {
            id,
            relay,
            period_ms,
            cap,
            ledger: RecvLedger::new(),
            pool,
            recreating: false,
        });
        self.sync_links(now)
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
        self.world.sends.retain(|s| s.id != queue);
        self.world.recvs.retain(|r| r.id != queue);
        let (world, links) = (&mut self.world, &mut self.links);
        for link in links.iter_mut() {
            let gone = match link.spec {
                Spec::Send(q) | Spec::Recv(q) => q == queue,
                Spec::Relay(r) => {
                    !world.sends.iter().any(|s| s.relay == r)
                        && !world.recvs.iter().any(|q| q.relay == r)
                }
            };
            if gone {
                world.tear(link, now, Reason::Closed, source)?;
                link.state = State::Gone;
            }
        }
        self.links.retain(|l| !matches!(l.state, State::Gone));
        Ok(core::mem::take(&mut self.world.out))
    }

    /// Change the period of a queue (a hand-out announced with another period, spec §10.6 (1)): a Strict link is
    /// replaced by a new one with its own key and phase.
    ///
    /// # Errors
    /// [`SchedError::UnknownQueue`], [`SchedError::BadPeriod`], [`SchedError::RateBound`].
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
        if let Some(sq) = self.world.send_mut(queue) {
            sq.period_ms = period_ms;
        } else if let Some(rq) = self.world.recvs.iter().find(|r| r.id == queue) {
            let (relay, was) = (rq.relay, rq.period_ms);
            let mode = self.world.effective_mode();
            if let Some(rq) = self.world.recv_mut(queue) {
                rq.period_ms = period_ms;
            }
            if let Err(e) = self.check_balanced(relay, None, mode) {
                if let Some(rq) = self.world.recv_mut(queue) {
                    rq.period_ms = was;
                }
                return Err(e);
            }
        } else {
            return Err(SchedError::UnknownQueue);
        }
        if self.world.effective_mode() == Mode::Strict {
            let (world, links) = (&mut self.world, &mut self.links);
            for link in links.iter_mut() {
                if matches!(link.spec, Spec::Send(q) | Spec::Recv(q) if q == queue) {
                    world.tear(link, now, Reason::Closed, source)?;
                    link.state = State::Gone;
                }
            }
            self.links.retain(|l| !matches!(l.state, State::Gone));
            self.sync_links(now)?;
        }
        Ok(core::mem::take(&mut self.world.out))
    }

    /// Add the links a queue set needs and does not have yet; each starts `U[0, 3 min]` from `now`.
    fn sync_links(&mut self, now: u64) -> Result<(), SchedError> {
        let mode = self.world.effective_mode();
        let mut wanted: Vec<Spec> = Vec::new();
        if mode == Mode::Strict {
            let mut ids: Vec<(QueueId, Spec)> = self
                .world
                .sends
                .iter()
                .map(|s| (s.id, Spec::Send(s.id)))
                .chain(self.world.recvs.iter().map(|r| (r.id, Spec::Recv(r.id))))
                .collect();
            ids.sort_by_key(|(q, _)| *q);
            wanted.extend(ids.into_iter().map(|(_, s)| s));
        } else {
            let mut seen: Vec<RelayId> = Vec::new();
            let relays = self
                .world
                .sends
                .iter()
                .map(|s| (s.id, s.relay))
                .chain(self.world.recvs.iter().map(|r| (r.id, r.relay)));
            let mut ordered: Vec<(QueueId, RelayId)> = relays.collect();
            ordered.sort_by_key(|(q, _)| *q);
            for (_, r) in ordered {
                if !seen.contains(&r) {
                    seen.push(r);
                    wanted.push(Spec::Relay(r));
                }
            }
        }
        for spec in wanted {
            if self
                .links
                .iter()
                .any(|l| l.spec == spec && !matches!(l.state, State::Gone))
            {
                continue;
            }
            let at = now.saturating_add(self.world.phase()?);
            let logical = self.world.new_logical_id();
            self.links.push(Link {
                spec,
                logical,
                state: State::Down { at },
                closed_before: 0,
                rr: 0,
            });
        }
        Ok(())
    }

    /// Change the mode (spec `docs/02` §4.4): every link is torn down (`TornDown(ModeChange)`) and the links of the
    /// new mode start `U[0, 3 min]` from `now`, each drawn on its own.
    ///
    /// # Errors
    /// [`SchedError::RateBound`] / [`SchedError::TooManyQueues`] if the recv-queues do not fit the new mode (nothing
    /// changes); [`SchedError::Unavailable`].
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
        self.world.mode = mode;
        self.world.direct = direct;
        if effective == before {
            return Ok(Vec::new());
        }
        let (world, links) = (&mut self.world, &mut self.links);
        for link in links.iter_mut() {
            world.tear(link, now, Reason::ModeChange, source)?;
        }
        self.links.clear();
        self.sync_links(now)?;
        Ok(core::mem::take(&mut self.world.out))
    }

    // ---- the pool and the control operations ----------------------------------------------------------------------

    /// Keep spare recv-queues on `relay` (spec §10.6 (3)): the creations are queued as control operations.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn manage_pool(&mut self, now: u64, relay: RelayId) -> Result<(), SchedError> {
        self.world.pool.manage(relay);
        self.world.top_up_pool(now)
    }

    /// Spare queues on `relay`.
    #[must_use]
    pub fn pool_spares(&self, relay: RelayId) -> usize {
        self.world.pool.spares(relay)
    }

    /// The host created the queue of a `QueueNew(queue)` operation: it is a spare, fetched at `P_POOL`.
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
        self.add_recv_with_id(now, queue, relay, cap, period, true)?;
        self.world.pool.created(queue);
        Ok(())
    }

    /// Hand out a spare of `relay` for an invitation announced with `announced_ms`: its link is replaced by one at the
    /// announced period, and a replacement spare is queued (not now: a `QUEUE_NEW` is never needed at that moment).
    ///
    /// # Errors
    /// [`SchedError::BadPeriod`], [`SchedError::RateBound`], [`SchedError::Unavailable`].
    pub fn take_pool_queue<S: CellSource>(
        &mut self,
        now: u64,
        relay: RelayId,
        announced_ms: u64,
        source: &mut S,
    ) -> Result<(Option<QueueId>, Vec<Output>), SchedError> {
        if !self.world.params.period_valid(announced_ms) {
            return Err(SchedError::BadPeriod);
        }
        let Some(queue) = self.world.pool.take(relay) else {
            return Ok((None, Vec::new()));
        };
        if let Some(rq) = self.world.recv_mut(queue) {
            rq.pool = false;
        }
        let out = match self.set_queue_period(now, queue, announced_ms, source) {
            Ok(out) => out,
            Err(e) => {
                // refused (e.g. the rate bound at the announced period): the spare stays the oldest one, unchanged
                if let Some(rq) = self.world.recv_mut(queue) {
                    rq.pool = true;
                }
                self.world.pool.untake(relay, queue);
                return Err(e);
            }
        };
        self.world.top_up_pool(now)?;
        Ok((Some(queue), out))
    }

    /// Queue a control operation (spec §10.6 (2)).
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
                        let lead = at.saturating_sub(self.world.params.fetch_lead_ms);
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
            let reason = if closed_before_relayinfo {
                link.closed_before = link.closed_before.saturating_add(1);
                Reason::ClosedBeforeRelayInfo
            } else {
                link.closed_before = 0;
                Reason::Closed
            };
            // the driver already dropped the connection: no `Close` for it
            world
                .out
                .push(Output::Event(LinkEvent::TornDown(id, link.logical, reason)));
            let delay = reconnect_delay(&world.params, &mut world.rng, link.closed_before)?;
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
    use secmp_transport::{Channel, SendCap};

    use super::{LinkId, SchedError, Scheduler};
    use crate::scheduler::params::{Mode, Params};
    use crate::scheduler::types::{
        CellSource, CellToken, Delivered, FrameId, Output, PreparedCell, QueueId, RelayId,
        SendFailure, SourceError,
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
        fn deliver(&mut self, _: QueueId, _: u64, _: &Cell) -> Result<Delivered, SourceError> {
            Ok(Delivered::Committed)
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
}

/// Positive control of the tick audit (WEISUNG M6-C1-4, mutants `counters_now -> [0; 4]` / `[1; 4]`): the instrument moves
/// when counted work happens — a blind audit would pass every tick. The counters are thread-local, so the deltas are exact.
#[cfg(test)]
#[cfg(feature = "kat")]
mod m6_mut {
    use super::counters_now;
    use crate::scheduler::conversation::counters;

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
