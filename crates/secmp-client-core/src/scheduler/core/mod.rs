// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sans-IO core of the constant-rate scheduler (spec §10, `docs/02` §4.4).
//!
//! **Shape.** The core owns the queues, one task per link, the control operations and the pool; it owns no stream and
//! reads no clock. A driver (the virtual one of the testkit, the tokio one of M6 Phase B) opens connections when
//! [`Output::Connect`] says so, runs the SecMP-LINK handshake, hands the resulting [`Channel`] to
//! [`Scheduler::link_up`], delivers received frames with [`Scheduler::on_frame`], and calls [`Scheduler::poll`] at
//! [`Scheduler::next_deadline`]. Every unit the client emits is an [`Output::Write`] of a **prepared** frame.
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
use crate::scheduler::types::{
    Alert, CellSource, CellToken, ControlKind, IsolationKey, LinkEvent, LinkId, OpId, Output,
    QueueId, Reason, RelayId, SendFailure, Transport,
};
use crate::timing::{TimingRng, Unavailable};

use self::backoff::reconnect_delay;
use self::pure::{Flight, rr_select, tick_time};

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
    /// The cumulative acknowledgement (spec §9.3): every cell at or below it is decided and committed — also the dedup.
    acked: u64,
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
    Send { queue: QueueId, token: CellToken },
    Ping,
    Fetch(QueueId),
    FetchMulti(Vec<QueueId>),
}

struct Req {
    tick: u32,
    seq: u32,
    kind: ReqKind,
}

struct Part {
    prepared: Prepared,
    kind: ReqKind,
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
    flight: Flight,
    reqs: VecDeque<Req>,
}

enum State {
    Down { at: u64 },
    Connecting { id: LinkId },
    Up(Box<Up>),
    Gone,
}

struct Link {
    spec: Spec,
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
    next_key: u64,
    next_op: u64,
    overruns: u64,
    last_now: u64,
    out: Vec<Output>,
    prep: PrepLog,
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
    fn release<S: CellSource>(up: &mut Up, source: &mut S) {
        for part in [up.send_part.take(), up.fetch_part.take()].into_iter().flatten() {
            if let ReqKind::Send { queue, token } = part.kind {
                source.discard(queue, token);
            }
        }
        for req in up.reqs.drain(..) {
            if let ReqKind::Send { queue, token } = req.kind {
                source.send_failed(queue, token, SendFailure::Unknown);
            }
        }
    }

    /// Take the connection down. `ModeChange` removes the link; any other reason schedules the next attempt.
    fn tear<S: CellSource>(
        &mut self,
        link: &mut Link,
        now: u64,
        reason: Reason,
        source: &mut S,
    ) -> Result<(), SchedError> {
        match core::mem::replace(&mut link.state, State::Gone) {
            State::Up(mut up) => {
                Self::release(&mut up, source);
                self.out.push(Output::Close { link: up.id });
                self.out
                    .push(Output::Event(LinkEvent::TornDown(up.id, reason)));
            }
            State::Connecting { id } => {
                self.out.push(Output::Close { link: id });
                self.out.push(Output::Event(LinkEvent::TornDown(id, reason)));
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
        self.out.push(Output::Connect {
            link: id,
            key,
            relay,
            transport,
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
        if now.saturating_sub(at) > self.params.late_tolerance_ms {
            self.overruns = self.overruns.saturating_add(1);
            return TickResult::Tear(Reason::Overrun);
        }
        if !up.flight.on_tick() {
            return TickResult::Tear(Reason::InFlight);
        }
        let needs_send = matches!(spec, Spec::Send(_) | Spec::Relay(_));
        let needs_fetch = matches!(spec, Spec::Recv(_)) || (matches!(spec, Spec::Relay(_)) && has_fetch);
        if (needs_send && up.send_part.is_none()) || (needs_fetch && up.fetch_part.is_none()) {
            self.overruns = self.overruns.saturating_add(1);
            return TickResult::Tear(Reason::Overrun);
        }
        let mut sent_to = None;
        for part in [up.send_part.take(), up.fetch_part.take()].into_iter().flatten() {
            if up.chan.begin_write(&part.prepared).is_err() {
                return TickResult::Tear(Reason::Rejected);
            }
            if let ReqKind::Send { queue, .. } = part.kind {
                sent_to = Some(queue);
            }
            self.out.push(Output::Write {
                link: up.id,
                bytes: part.prepared.bytes().to_vec(),
            });
            up.reqs.push_back(Req {
                tick: next,
                seq: part.prepared.seq(),
                kind: part.kind,
            });
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
                tear = self.prepare_send(&mut link.rr, up, spec, slot, now, source);
            }
            if tear.is_none() && needs_fetch && up.fetch_part.is_none() {
                let fetch_outstanding = up
                    .reqs
                    .iter()
                    .any(|r| matches!(r.kind, ReqKind::Fetch(_) | ReqKind::FetchMulti(_)));
                let lead_reached = now >= slot.saturating_sub(self.params.fetch_lead_ms);
                if !fetch_outstanding || lead_reached {
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
        rr: &mut usize,
        up: &mut Up,
        spec: Spec,
        slot: u64,
        now: u64,
        source: &mut S,
    ) -> Option<Reason> {
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
                match rr_select(*rr, &table, slot) {
                    Some(at) => {
                        *rr = at.checked_add(1).and_then(|n| n.checked_rem(members.len())).unwrap_or(0);
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
                    });
                    self.prep.record(up, slot, now, (b'P', None));
                    None
                }
                Err(e) => Some(reason_of(e)),
            };
        };
        let cap = self.sends.iter().find(|s| s.id == queue).map(|s| &s.cap)?;
        // not ready, or not persisted: nothing is built, the tick finds no frame
        let Ok(Some(cell)) = source.prepare_cell(queue, now) else {
            return None;
        };
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
                    ack: rq.acked,
                }) {
                    Ok(prepared) => {
                        up.fetch_part = Some(Part {
                            prepared,
                            kind: ReqKind::Fetch(q),
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
                    members.iter().map(|q| (&q.cap, q.acked)).collect();
                let ids: Vec<QueueId> = members.iter().map(|q| q.id).collect();
                match up.chan.prepare(&Command::FetchMulti { from: &entries }) {
                    Ok(prepared) => {
                        up.fetch_part = Some(Part {
                            prepared,
                            kind: ReqKind::FetchMulti(ids),
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

    /// One link at `now`: connect when its time has come, end it at its lifetime, tick, then prepare.
    fn step<S: CellSource>(
        &mut self,
        link: &mut Link,
        now: u64,
        source: &mut S,
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
                        .map(|o| if let Output::Write { bytes, .. } = o { bytes.len() } else { 0 })
                        .sum();
                    self.prep.ticks.push(TickAudit {
                        link: up.id,
                        at: now,
                        delta,
                        bytes,
                    });
                }
                match result {
                    TickResult::Tear(reason) => self.tear(link, now, reason, source)?,
                    TickResult::Idle | TickResult::Wrote => self.prepare_link(link, now, source)?,
                }
            }
            Todo::Nothing => {}
        }
        Ok(())
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
        rq.acked = 0;
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

    fn fetched<S: CellSource>(
        &mut self,
        queue: QueueId,
        cells: Vec<(u64, secmp_proto::wire::cell::Cell)>,
        source: &mut S,
    ) {
        let Some(rq) = self.recvs.iter_mut().find(|r| r.id == queue) else {
            return;
        };
        for (id, cell) in cells {
            // at or below the acknowledgement: decided already (a re-fetch with an older `ack`, spec §9.3)
            if id <= rq.acked {
                continue;
            }
            if source.deliver(queue, id, &cell).is_err() {
                // not committed: no acknowledgement, the cell comes again
                break;
            }
            rq.acked = id;
        }
    }

    fn queue_error(&mut self, queue: QueueId, error: TransportError, now: u64) -> Result<(), SchedError> {
        match error {
            TransportError::NoQueue => self.recreate(queue, now)?,
            TransportError::Auth => self.out.push(Output::Event(LinkEvent::Alert(queue, Alert::QueueAuth))),
            TransportError::Rate => self.out.push(Output::Event(LinkEvent::Alert(queue, Alert::QueueRate))),
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
            (ReqKind::Fetch(queue), Outcome::Fetch(result)) => match result {
                Ok(cells) => self.fetched(queue, cells, source),
                Err(e) => self.queue_error(queue, e, now)?,
            },
            (ReqKind::FetchMulti(queues), Outcome::FetchMulti(result)) => match result {
                Ok(done) => {
                    for q in &queues {
                        let Some(rid) = self.recvs.iter().find(|r| r.id == *q).map(|r| r.cap.queue())
                        else {
                            continue;
                        };
                        let cells: Vec<_> = done
                            .cells
                            .iter()
                            .filter(|(r, _, _)| *r == rid)
                            .map(|(_, id, cell)| {
                                (*id, secmp_proto::wire::cell::Cell::from_bytes(cell.as_bytes()))
                            })
                            .filter_map(|(id, c)| c.ok().map(|c| (id, c)))
                            .collect();
                        self.fetched(*q, cells, source);
                        for (r, e) in &done.errors {
                            if *r == rid {
                                self.queue_error(*q, *e, now)?;
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Some(first) = queues.first() {
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
                next_key: 0,
                next_op: 0,
                overruns: 0,
                last_now: 0,
                out: Vec::new(),
                prep: PrepLog::default(),
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

    /// Uniform timing draws so far (the activity-independence tests compare them).
    #[must_use]
    pub const fn timing_draws(&self) -> u64 {
        self.world.rng.draws().saturating_add(self.world.ctl.draws())
    }

    /// Ticks lost to a frame that was not ready (OPEN-M6-13).
    #[must_use]
    pub const fn overruns(&self) -> u64 {
        self.world.overruns
    }

    /// The cumulative acknowledgement of a recv-queue.
    #[must_use]
    pub fn acked(&self, queue: QueueId) -> Option<u64> {
        self.world.recvs.iter().find(|r| r.id == queue).map(|r| r.acked)
    }

    /// What each tick cost in counted work (tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn tick_audit(&self) -> &[TickAudit] {
        &self.world.prep.ticks
    }

    /// Set the send counter of a connection's link (the rotation tests; feature `kat`).
    #[cfg(feature = "kat")]
    pub fn set_send_counter_kat(&mut self, id: LinkId, value: u64) {
        for link in &mut self.links {
            if let State::Up(up) = &mut link.state
                && up.id == id
            {
                up.chan.set_send_counter_kat(value);
            }
        }
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

    fn check_balanced(&self, relay: RelayId, extra: Option<u64>, mode: Mode) -> Result<(), SchedError> {
        if self.world.params.slot_ms(mode).is_none() {
            return Ok(());
        }
        let on_relay = self.world.recvs.iter().filter(|r| r.relay == relay);
        let entries = on_relay.clone().count().saturating_add(usize::from(extra.is_some()));
        if entries > FETCH_MULTI_LIMIT {
            return Err(SchedError::TooManyQueues);
        }
        let periods = on_relay
            .filter(|r| !r.pool)
            .map(|r| r.period_ms)
            .chain(extra);
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
        self.check_balanced(relay, (!pool).then_some(period_ms), mode)?;
        self.world.recvs.push(RecvQ {
            id,
            relay,
            period_ms,
            cap,
            acked: 0,
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
                    !world.sends.iter().any(|s| s.relay == r) && !world.recvs.iter().any(|q| q.relay == r)
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
            if self.links.iter().any(|l| l.spec == spec && !matches!(l.state, State::Gone)) {
                continue;
            }
            let at = now.saturating_add(self.world.phase()?);
            self.links.push(Link {
                spec,
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
        let effective = if direct && mode == Mode::Strict { Mode::Balanced } else { mode };
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
    pub fn pool_queue_ready(&mut self, now: u64, queue: QueueId, cap: RecvCap) -> Result<(), SchedError> {
        let relay = self.world.pool.created(queue).ok_or(SchedError::UnknownQueue)?;
        let period = self.world.params.p_pool_ms;
        self.add_recv_with_id(now, queue, relay, cap, period, true)
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
                if let Some(rq) = self.world.recv_mut(queue) {
                    rq.pool = true;
                }
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
        self.world
            .control
            .failed(&self.world.params, &mut self.world.ctl, op, now, closed_before_relayinfo)?;
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
        self.schedule_control(now, ControlKind::LinkPut(ld), relay, u64::from(ld), When::Delayed)
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

    fn pass<S: CellSource>(&mut self, now: u64, source: &mut S) -> Result<(), SchedError> {
        self.world.last_now = self.world.last_now.max(now);
        let (world, links) = (&mut self.world, &mut self.links);
        for link in links.iter_mut() {
            world.step(link, now, source)?;
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

    /// Advance to `now`: connect links whose time has come, end links at their lifetime, write the frames of due
    /// ticks, prepare the next ones, start due control operations.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`] without randomness (fail closed).
    pub fn poll<S: CellSource>(
        &mut self,
        now: u64,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        self.pass(now, source)?;
        Ok(core::mem::take(&mut self.world.out))
    }

    fn find(&mut self, id: LinkId) -> Option<usize> {
        self.links.iter().position(|l| match &l.state {
            State::Connecting { id: c } => *c == id,
            State::Up(up) => up.id == id,
            State::Down { .. } | State::Gone => false,
        })
    }

    /// The handshake of connection `id` succeeded at `now`: the link is up; its lifetime is drawn now.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn link_up<S: CellSource>(
        &mut self,
        id: LinkId,
        now: u64,
        chan: Channel,
        source: &mut S,
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
                flight: Flight::new(world.params.max_in_flight),
                reqs: VecDeque::new(),
            }));
            world.out.push(Output::Event(LinkEvent::Up(id)));
        }
        self.pass(now, source)?;
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
            world.out.push(Output::Event(LinkEvent::TornDown(id, reason)));
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
    pub fn on_closed<S: CellSource>(
        &mut self,
        id: LinkId,
        now: u64,
        source: &mut S,
    ) -> Result<Vec<Output>, SchedError> {
        let Some(at) = self.find(id) else {
            return Ok(Vec::new());
        };
        let (world, links) = (&mut self.world, &mut self.links);
        if let Some(link) = links.get_mut(at) {
            world.tear(link, now, Reason::Closed, source)?;
        }
        self.pass(now, source)?;
        Ok(core::mem::take(&mut self.world.out))
    }

    /// A frame arrived on connection `id` (exactly 4352 bytes): it is matched to the oldest outstanding request; when
    /// that request's response is complete the cells are decided and committed, then the next frames are prepared.
    ///
    /// # Errors
    /// [`SchedError::Unavailable`].
    pub fn on_frame<S: CellSource>(
        &mut self,
        id: LinkId,
        now: u64,
        unit: &[u8],
        source: &mut S,
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
                    && up.reqs.front().is_none_or(|r| r.seq != completed.seq)
                {
                    bad = true;
                    done = None;
                }
            }
            if bad {
                world.tear(link, now, Reason::Rejected, source)?;
            } else if let Some(completed) = done {
                let mut fit = true;
                let mut req = None;
                if let State::Up(up) = &mut link.state {
                    req = up.reqs.pop_front();
                    if let Some(r) = &req
                        && !up.reqs.iter().any(|o| o.tick == r.tick)
                    {
                        up.flight.on_response();
                    }
                }
                if let Some(req) = req {
                    fit = world.outcome(req, completed.outcome, now, source)?;
                }
                if !fit {
                    world.tear(link, now, Reason::Rejected, source)?;
                }
            }
        }
        self.pass(now, source)?;
        Ok(core::mem::take(&mut self.world.out))
    }

    /// The `QueueRef` of a recv-queue (what `FETCH_MULTI` names).
    #[must_use]
    pub fn queue_ref(&self, queue: QueueId) -> Option<QueueRef> {
        self.world.recvs.iter().find(|r| r.id == queue).map(|r| r.cap.queue())
    }
}
