// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tokio driver of the sans-IO scheduler core (ADR-051 Part 1.1, `docs/02` §4.4, spec §10.1).
//!
//! [`Driver`] owns the sockets, the clock reads and the worker of the cell source; the [`Scheduler`] decides everything
//! else. It is generic over the transport ([`Providers`], over a [`StreamProvider`]: TEST-SPEC-M6 AD-10), the relay
//! [`Directory`], the [`ControlRunner`] of one-shot operations, the cell-source [`Worker`] and the [`Clock`].
//!
//! **The driver obligations** (from `scheduler/mod.rs`, BRIEF M6-B §2.2):
//! - (i) at every wake the driver takes in what arrived (frames: cheap, no cell source), calls
//!   [`Scheduler::poll_due`] and waits until every [`Output::Write`] it returned has been written and flushed to its
//!   stream by the link's writer task, and only then calls [`Scheduler::work`]. Writes of different links go out in
//!   parallel (one writer task per link).
//! - (vi) the work never runs on the I/O path: [`Scheduler::work`] sees a non-blocking cell source (`Deferred`). A cell
//!   the core asks for is prepared by the serial [`Worker`], off the loop; until it is ready the facade answers "not
//!   ready" and the core prepares the link again at its next pass (the tick finds no frame only if the worker is later
//!   than the tick: an overrun). A received cell is decided and committed by the worker; until it is committed the
//!   facade answers "not committed", so the core does not acknowledge it (spec §10.1, CLAUDE.md §1.7: persist before
//!   ack) and the cell is fetched again — the next `FETCH` finds it committed. The notifications (`relayed`, `evicted`,
//!   `send_failed`, `discard`, `queue_lost`) are queued to the worker in order. No preparation or receive cost of one
//!   link can delay a due write of another.
//! - (ii) after `work` the driver reports [`Scheduler::prepared_until`] with the time it read from the same clock right
//!   then; a cell the worker delivers after its tick makes the core count an overrun.
//! - (iii) every [`Output::Connect`] is resolved: the connect task reports its outcome through a guard that reports a
//!   failure if the task ends any other way, and the driver calls `link_up` or `connect_failed`.
//! - (iv) the driver sleeps until [`Scheduler::next_deadline`], which includes the `FETCH`-lead deadline.
//! - (v) time comes only from the [`Clock`] (`clock.rs` is the only module that reads one; AD-11).
//!
//! **Fail closed.** A connection is made only with the provider of the transport the scheduler names (the user's
//! choice, CLAUDE.md §1.5); a failure is a failure, never a fallback.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use secmp_proto::link::ids::AccessKey;
use secmp_proto::sizes::FRAME_LEN;
use secmp_proto::tr::{Entropy, OsEntropy};
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::RelayRef;
use secmp_transport::driver::{
    AsyncConnectOutcome, AsyncRelayQueueTransport, AsyncSession, EitherStream, Isolation,
    ProviderStream, StreamProvider,
};
use secmp_transport::{Channel, Error as TransportError, RecvCap};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::scheduler::core::{SchedError, Scheduler};
use crate::scheduler::types::{
    CellSource, CellToken, ControlKind, IsolationKey, LinkEvent, LinkId, OpId, Output,
    PreparedCell, QueueId, RelayId, SendFailure, SourceError, Transport,
};

// ---- what the driver is generic over ---------------------------------------------------------------------------------

/// The stream providers by transport (TEST-SPEC-M6 AD-10, TOR-06): the driver asks for the transport the scheduler
/// names and nothing else.
pub trait Providers: Send + Sync + 'static {
    /// The stream type.
    type Stream: ProviderStream;

    /// Open a stream to `relay` over `transport`, isolated by `isolation`.
    ///
    /// # Errors
    /// The provider's error; a transport without a provider is [`TransportError::Closed`].
    fn connect(
        &self,
        transport: Transport,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> impl Future<Output = Result<Self::Stream, TransportError>> + Send;
}

/// One provider serving one transport; a connection over the other transport fails (never another provider).
pub struct Only<P> {
    provider: P,
    transport: Transport,
}

impl<P> Only<P> {
    /// `provider` for `transport`.
    pub const fn new(provider: P, transport: Transport) -> Self {
        Self {
            provider,
            transport,
        }
    }

    /// The provider.
    pub const fn provider(&self) -> &P {
        &self.provider
    }
}

impl<P: StreamProvider + 'static> Providers for Only<P> {
    type Stream = P::Stream;

    async fn connect(
        &self,
        transport: Transport,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> Result<Self::Stream, TransportError> {
        if transport != self.transport {
            return Err(TransportError::Closed);
        }
        self.provider.connect(relay, isolation).await
    }
}

/// The two providers of a client: Tor and direct TLS, selected by the transport the scheduler names — which is the
/// user's explicit direct-mode setting and nothing else (`Scheduler::set_direct`; spec §5.3, §8.1; TEST-SPEC-M6 TOR-05,
/// TOR-06). Direct mode for a relay whose `RelayRef` has no direct endpoint is
/// [`TransportError::NoDirectEndpoint`] with no attempt over any transport; a Tor failure is returned as it is and
/// never reaches the direct provider (CLAUDE.md §1.5).
pub struct Selected<T, D> {
    tor: T,
    direct: D,
}

impl<T, D> Selected<T, D> {
    /// The Tor provider `tor` and the direct provider `direct`.
    pub const fn new(tor: T, direct: D) -> Self {
        Self { tor, direct }
    }
}

impl<T: StreamProvider + 'static, D: StreamProvider + 'static> Providers for Selected<T, D> {
    type Stream = EitherStream<T::Stream, D::Stream>;

    async fn connect(
        &self,
        transport: Transport,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> Result<Self::Stream, TransportError> {
        match transport {
            Transport::Tor => self
                .tor
                .connect(relay, isolation)
                .await
                .map(EitherStream::Left),
            Transport::Direct if relay.direct.is_none() => Err(TransportError::NoDirectEndpoint),
            Transport::Direct => self
                .direct
                .connect(relay, isolation)
                .await
                .map(EitherStream::Right),
        }
    }
}

/// Where the relays are and what credential each needs (the host's relay records).
pub trait Directory: Send + Sync + 'static {
    /// The relay's `RelayRef` (pinned fingerprint, onion, direct endpoint).
    fn relay(&self, relay: RelayId) -> Option<&RelayRef>;
    /// The relay's access key, if the client holds one (`akc` is checked only then, spec §8.2).
    fn access_key(&self, relay: RelayId) -> Option<&AccessKey>;
}

/// The randomness of each handshake (every connection gets its own source, so handshakes run concurrently).
pub trait HandshakeEntropy: Send + 'static {
    /// The source of one handshake.
    type E: Entropy + Send + 'static;
    /// A source for the next connection.
    fn next(&mut self) -> Self::E;
}

/// The operating system's randomness for every handshake (a shipped build).
pub struct OsHandshakes;

impl HandshakeEntropy for OsHandshakes {
    type E = OsEntropy;

    fn next(&mut self) -> OsEntropy {
        OsEntropy
    }
}

/// What a finished control operation tells the scheduler besides "done".
pub enum ControlEffect {
    /// Nothing more.
    None,
    /// A pool queue exists on the relay now.
    PoolQueueReady(QueueId, RecvCap),
    /// The owner status of link data `ld`.
    OwnerStatus {
        /// The relay.
        relay: RelayId,
        /// The link data.
        ld: u32,
        /// The entry exists.
        present: bool,
        /// It was consumed.
        consumed: bool,
        /// It expired.
        expired: bool,
    },
}

/// Runs a control operation on its own one-shot link (spec §10.6 (2)); the host owns the key material.
pub trait ControlRunner: Send + Sync + 'static {
    /// Run `kind` on `transport` (a fresh link to `relay`).
    ///
    /// # Errors
    /// The transport's error; the driver reports the operation failed.
    fn run<S: ProviderStream>(
        &self,
        op: OpId,
        kind: ControlKind,
        relay: RelayId,
        transport: &mut AsyncRelayQueueTransport<S>,
    ) -> impl Future<Output = Result<ControlEffect, TransportError>> + Send;
}

// ---- the cell-source worker ------------------------------------------------------------------------------------------

/// One call of the cell source, run by the [`Worker`] off the I/O loop.
pub enum Job {
    /// Build the next cell of `queue` (real or dummy through one path; persisted before it is handed out).
    Prepare {
        /// The queue.
        queue: QueueId,
        /// The time the core asked.
        now: u64,
    },
    /// Decide and commit a fetched cell.
    Deliver {
        /// The recipient queue.
        queue: QueueId,
        /// Its id.
        cell_id: u64,
        /// The cell.
        cell: Cell,
    },
    /// `OK_SEND`.
    Relayed {
        /// The queue.
        queue: QueueId,
        /// The prepared cell's token.
        token: CellToken,
        /// Its id.
        cell_id: u64,
    },
    /// `OK_SEND` reported an eviction.
    Evicted {
        /// The queue.
        queue: QueueId,
        /// The evicted id.
        cell_id: u64,
    },
    /// The cell was not stored.
    SendFailed {
        /// The queue.
        queue: QueueId,
        /// The token.
        token: CellToken,
        /// Why.
        why: SendFailure,
    },
    /// The cell was never written.
    Discard {
        /// The queue.
        queue: QueueId,
        /// The token.
        token: CellToken,
    },
    /// `ERR_NOQUEUE` on a send queue.
    QueueLost {
        /// The queue.
        queue: QueueId,
    },
}

/// What a [`Job`] ended with.
pub enum JobDone {
    /// A `Prepare`.
    Prepared {
        /// The queue.
        queue: QueueId,
        /// The cell, "not ready", or not persisted.
        cell: Result<Option<PreparedCell>, SourceError>,
    },
    /// A `Deliver`.
    Delivered {
        /// The queue.
        queue: QueueId,
        /// The cell.
        cell_id: u64,
        /// The decision was committed.
        committed: bool,
    },
    /// A notification.
    Noted,
}

impl Job {
    /// Run the job against `source` (what every worker does, on whatever thread it chooses).
    pub fn apply<S: CellSource>(self, source: &mut S) -> JobDone {
        match self {
            Self::Prepare { queue, now } => JobDone::Prepared {
                queue,
                cell: source.prepare_cell(queue, now),
            },
            Self::Deliver {
                queue,
                cell_id,
                cell,
            } => JobDone::Delivered {
                queue,
                cell_id,
                committed: source.deliver(queue, cell_id, &cell).is_ok(),
            },
            Self::Relayed {
                queue,
                token,
                cell_id,
            } => {
                source.relayed(queue, token, cell_id);
                JobDone::Noted
            }
            Self::Evicted { queue, cell_id } => {
                source.evicted(queue, cell_id);
                JobDone::Noted
            }
            Self::SendFailed { queue, token, why } => {
                source.send_failed(queue, token, why);
                JobDone::Noted
            }
            Self::Discard { queue, token } => {
                source.discard(queue, token);
                JobDone::Noted
            }
            Self::QueueLost { queue } => {
                source.queue_lost(queue);
                JobDone::Noted
            }
        }
    }

    /// The result of this job if the worker cannot run it (its source is gone): nothing prepared, nothing committed.
    #[must_use]
    pub const fn failed(&self) -> JobDone {
        match self {
            Self::Prepare { queue, .. } => JobDone::Prepared {
                queue: *queue,
                cell: Err(SourceError),
            },
            Self::Deliver { queue, cell_id, .. } => JobDone::Delivered {
                queue: *queue,
                cell_id: *cell_id,
                committed: false,
            },
            _ => JobDone::Noted,
        }
    }
}

/// Runs the cell-source jobs one at a time, off the driver's I/O loop (obligation (vi)).
pub trait Worker: Send + 'static {
    /// Run one job.
    fn run(&mut self, job: Job) -> impl Future<Output = JobDone> + Send;
}

/// The worker of a shipped build: each job runs the cell source on tokio's blocking pool, one after the other.
pub struct BlockingWorker<S> {
    source: Option<S>,
}

impl<S> BlockingWorker<S> {
    /// A worker over `source`.
    pub const fn new(source: S) -> Self {
        Self {
            source: Some(source),
        }
    }
}

impl<S: CellSource + Send + 'static> Worker for BlockingWorker<S> {
    async fn run(&mut self, job: Job) -> JobDone {
        let failed = job.failed();
        let Some(mut source) = self.source.take() else {
            return failed;
        };
        match tokio::task::spawn_blocking(move || {
            let done = job.apply(&mut source);
            (source, done)
        })
        .await
        {
            Ok((source, done)) => {
                self.source = Some(source);
                done
            }
            // the source is lost with the panicked job: every later job fails (nothing is sent or acknowledged)
            Err(_) => failed,
        }
    }
}

/// The cell source the core sees inside the driver: it never blocks (see obligation (vi) in the module documentation).
///
/// What it knows of received cells belongs to one *generation* of a receive queue: when the scheduler re-creates a
/// queue (after `NoQueue`, spec §9.1, its `QUEUE_NEW` control operation), the relay numbers the new queue's cells from 1
/// again, so the committed high-water mark of the old queue is dropped and a delivery the worker finishes for the old
/// generation commits nothing (WEISUNG M6-B-5 EXTB-2: persist before ack, CLAUDE.md §1.7).
#[derive(Default)]
struct Deferred {
    ready: BTreeMap<QueueId, PreparedCell>,
    preparing: BTreeSet<QueueId>,
    /// The current generation of each receive queue (0 until its first re-creation).
    generation: BTreeMap<QueueId, u64>,
    /// The highest cell id committed in the current generation.
    committed: BTreeMap<QueueId, u64>,
    /// The deliveries handed to the worker and not finished, with the generation each was asked in, oldest first (the
    /// worker runs its jobs in order).
    delivering: BTreeMap<(QueueId, u64), VecDeque<u64>>,
    jobs: Vec<Job>,
}

impl Deferred {
    fn generation_of(&self, queue: QueueId) -> u64 {
        self.generation.get(&queue).copied().unwrap_or(0)
    }

    /// `queue` is re-created on the relay: a new generation begins.
    fn recreated(&mut self, queue: QueueId) {
        let next = self.generation_of(queue).saturating_add(1);
        self.generation.insert(queue, next);
        self.committed.remove(&queue);
    }

    fn on_done(&mut self, done: JobDone) {
        match done {
            JobDone::Prepared { queue, cell } => {
                self.preparing.remove(&queue);
                if let Ok(Some(cell)) = cell {
                    self.ready.insert(queue, cell);
                }
            }
            JobDone::Delivered {
                queue,
                cell_id,
                committed,
            } => {
                let current = self.generation_of(queue);
                let asked = match self.delivering.get_mut(&(queue, cell_id)) {
                    Some(gens) => {
                        let first = gens.pop_front();
                        if gens.is_empty() {
                            self.delivering.remove(&(queue, cell_id));
                        }
                        first
                    }
                    None => None,
                };
                // a completion of an older generation commits nothing in the current one
                if committed && asked == Some(current) {
                    let entry = self.committed.entry(queue).or_insert(0);
                    *entry = (*entry).max(cell_id);
                }
            }
            JobDone::Noted => {}
        }
    }
}

impl CellSource for Deferred {
    fn prepare_cell(
        &mut self,
        queue: QueueId,
        now: u64,
    ) -> Result<Option<PreparedCell>, SourceError> {
        if let Some(cell) = self.ready.remove(&queue) {
            return Ok(Some(cell));
        }
        if self.preparing.insert(queue) {
            self.jobs.push(Job::Prepare { queue, now });
        }
        Ok(None)
    }

    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        self.jobs.push(Job::Relayed {
            queue,
            token,
            cell_id,
        });
    }

    fn evicted(&mut self, queue: QueueId, cell_id: u64) {
        self.jobs.push(Job::Evicted { queue, cell_id });
    }

    fn send_failed(&mut self, queue: QueueId, token: CellToken, why: SendFailure) {
        self.jobs.push(Job::SendFailed { queue, token, why });
    }

    fn discard(&mut self, queue: QueueId, token: CellToken) {
        self.jobs.push(Job::Discard { queue, token });
    }

    fn queue_lost(&mut self, queue: QueueId) {
        self.jobs.push(Job::QueueLost { queue });
    }

    fn deliver(&mut self, queue: QueueId, cell_id: u64, cell: &Cell) -> Result<(), SourceError> {
        if self.committed.get(&queue).is_some_and(|c| *c >= cell_id) {
            return Ok(());
        }
        let current = self.generation_of(queue);
        let pending = self
            .delivering
            .get(&(queue, cell_id))
            .is_some_and(|gens| gens.contains(&current));
        if !pending {
            let copy = Cell::from_bytes(cell.as_bytes()).map_err(|_| SourceError)?;
            self.delivering
                .entry((queue, cell_id))
                .or_default()
                .push_back(current);
            self.jobs.push(Job::Deliver {
                queue,
                cell_id,
                cell: copy,
            });
        }
        // not committed yet: no acknowledgement, the cell comes again (persist before ack)
        Err(SourceError)
    }
}

// ---- the driver ------------------------------------------------------------------------------------------------------

/// What a connection was opened for (the run log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A scheduled link.
    Link(LinkId),
    /// A control operation's one-shot link.
    Control(OpId),
}

/// One step of the driver, in order (the run log; the obligation tests read it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `poll_due` at this time.
    PollDue(u64),
    /// Every write `poll_due` returned is flushed.
    Flushed(u64),
    /// `work` began at the first time and ended (as reported to `prepared_until`) at the second.
    Work(u64, u64),
    /// A job was handed to the worker.
    Job(u64),
    /// A frame of this many bytes was written to the link's stream (by its writer task) at this time.
    Wrote(u64, LinkId, usize),
}

/// What the driver did (recorded only when asked for: [`Driver::with_log`]).
#[derive(Default)]
pub struct RunLog {
    /// Every connection opened: time, purpose, isolation.
    pub connects: Vec<(u64, Purpose, Isolation)>,
    /// Connect outcomes: time, link, up.
    pub resolved: Vec<(u64, LinkId, bool)>,
    /// The local events of the scheduler.
    pub events: Vec<(u64, LinkEvent)>,
    /// The steps of the loop.
    pub steps: Vec<Step>,
}

enum Conn<S> {
    Up(Box<(S, Channel)>),
    ClosedBefore,
    Failed,
}

enum Event<S> {
    Frame(LinkId, Vec<u8>),
    Closed(LinkId),
    Connected(LinkId, Conn<S>),
    Control(OpId, Result<ControlEffect, bool>),
    Job(JobDone),
    Wrote(LinkId, usize, u64),
}

type WriteReq = (Vec<u8>, oneshot::Sender<bool>);

struct LinkIo {
    writer: mpsc::UnboundedSender<WriteReq>,
    tasks: [JoinHandle<()>; 2],
}

impl LinkIo {
    fn stop(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

/// Reports a connect outcome exactly once: if the connect task ends without reporting (cancelled, panicked), the drop
/// reports a failure, so no `Connect` stays unresolved (obligation (iii)).
struct Resolve<S: Send + 'static> {
    link: LinkId,
    events: mpsc::UnboundedSender<Event<S>>,
    sent: bool,
}

impl<S: Send + 'static> Resolve<S> {
    fn send(mut self, conn: Conn<S>) {
        self.sent = true;
        let _ = self.events.send(Event::Connected(self.link, conn));
    }
}

impl<S: Send + 'static> Drop for Resolve<S> {
    fn drop(&mut self) {
        if !self.sent {
            let _ = self.events.send(Event::Connected(self.link, Conn::Failed));
        }
    }
}

/// The tokio driver (see the module documentation).
pub struct Driver<P: Providers, D, R, H, W, C> {
    providers: Arc<P>,
    directory: Arc<D>,
    runner: Arc<R>,
    entropy: H,
    clock: Arc<C>,
    worker: Option<W>,
    jobs: Option<mpsc::UnboundedSender<Job>>,
    events_tx: mpsc::UnboundedSender<Event<P::Stream>>,
    events_rx: mpsc::UnboundedReceiver<Event<P::Stream>>,
    links: BTreeMap<LinkId, LinkIo>,
    deferred: Deferred,
    log: Option<RunLog>,
    connect_timeout: Duration,
}

/// How long a connection attempt (stream and SecMP-LINK handshake) may take before it counts as failed: a provider that
/// never answers must not leave a link in `Connecting`, which has no deadline in the core (obligation (iii)). Two
/// minutes: a Tor circuit to an onion service plus the handshake.
pub const CONNECT_TIMEOUT_MS: u64 = 120_000;

impl<P, D, R, H, W, C> Driver<P, D, R, H, W, C>
where
    P: Providers,
    D: Directory,
    R: ControlRunner,
    H: HandshakeEntropy,
    W: Worker,
    C: Clock + Send + Sync + 'static,
{
    /// A driver over these parts.
    pub fn new(
        providers: Arc<P>,
        directory: Arc<D>,
        runner: Arc<R>,
        entropy: H,
        worker: W,
        clock: Arc<C>,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            providers,
            directory,
            runner,
            entropy,
            clock,
            worker: Some(worker),
            jobs: None,
            events_tx,
            events_rx,
            links: BTreeMap::new(),
            deferred: Deferred::default(),
            log: None,
            connect_timeout: Duration::from_millis(CONNECT_TIMEOUT_MS),
        }
    }

    /// Change the connect timeout (default [`CONNECT_TIMEOUT_MS`]).
    #[must_use]
    pub const fn with_connect_timeout(mut self, ms: u64) -> Self {
        self.connect_timeout = Duration::from_millis(ms);
        self
    }

    /// Record a [`RunLog`] (tests and diagnostics; it grows with the run).
    #[must_use]
    pub fn with_log(mut self) -> Self {
        self.log = Some(RunLog::default());
        self
    }

    /// The run log, if recorded.
    pub const fn log(&self) -> Option<&RunLog> {
        self.log.as_ref()
    }

    fn step(&mut self, step: Step) {
        if let Some(log) = &mut self.log {
            log.steps.push(step);
        }
    }

    /// The worker task: jobs one at a time, results back to the loop.
    fn ensure_worker(&mut self) {
        if self.jobs.is_some() {
            return;
        }
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
        let events = self.events_tx.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let done = worker.run(job).await;
                if events.send(Event::Job(done)).is_err() {
                    break;
                }
            }
        });
        self.jobs = Some(tx);
    }

    fn dispatch_jobs(&mut self, now: u64) {
        let jobs = core::mem::take(&mut self.deferred.jobs);
        for job in jobs {
            self.step(Step::Job(now));
            let failed = job.failed();
            let sent = self.jobs.as_ref().is_some_and(|tx| tx.send(job).is_ok());
            if !sent {
                self.deferred.on_done(failed);
            }
        }
    }

    /// Run the scheduler until the clock reads `until` (that instant included).
    ///
    /// # Errors
    /// [`SchedError::Unavailable`] without randomness (fail closed).
    pub async fn run_until(&mut self, sched: &mut Scheduler, until: u64) -> Result<(), SchedError> {
        self.ensure_worker();
        loop {
            let now = self.clock.mono_ms();
            // what arrived: frames (cheap, no cell source), connect outcomes, finished jobs
            while let Ok(ev) = self.events_rx.try_recv() {
                self.on_event(sched, ev, now).await?;
            }
            // (i) what is due now, written and flushed before anything else
            self.step(Step::PollDue(now));
            let due = sched.poll_due(now)?;
            self.apply(sched, due, now).await?;
            self.step(Step::Flushed(now));
            // (vi) the activity-dependent work over the non-blocking facade; (ii) its end from the same clock
            let outs = sched.work(now, &mut self.deferred)?;
            let end = self.clock.mono_ms();
            sched.prepared_until(end);
            self.step(Step::Work(now, end));
            self.apply(sched, outs, end).await?;
            self.dispatch_jobs(end);
            if now >= until {
                return Ok(());
            }
            // (iv) the next deadline (the FETCH lead included) or the next event
            let next = sched.next_deadline().map_or(until, |d| d.min(until));
            let wait = next.saturating_sub(self.clock.mono_ms());
            if let Ok(Some(ev)) =
                tokio::time::timeout(Duration::from_millis(wait), self.events_rx.recv()).await
            {
                let at = self.clock.mono_ms();
                self.on_event(sched, ev, at).await?;
            }
        }
    }

    async fn on_event(
        &mut self,
        sched: &mut Scheduler,
        ev: Event<P::Stream>,
        now: u64,
    ) -> Result<(), SchedError> {
        let outs = match ev {
            Event::Frame(link, unit) => sched.on_frame(link, now, &unit)?,
            Event::Closed(link) => {
                if let Some(io) = self.links.remove(&link) {
                    io.stop();
                }
                sched.on_closed(link, now)?
            }
            Event::Connected(link, conn) => {
                let up = matches!(conn, Conn::Up(..));
                if let Some(log) = &mut self.log {
                    log.resolved.push((now, link, up));
                }
                match conn {
                    Conn::Up(up) => {
                        let (stream, chan) = *up;
                        self.start_io(link, stream);
                        sched.link_up(link, now, chan)?
                    }
                    Conn::ClosedBefore => sched.connect_failed(link, now, true)?,
                    Conn::Failed => sched.connect_failed(link, now, false)?,
                }
            }
            Event::Control(op, result) => {
                match result {
                    Ok(effect) => {
                        match effect {
                            ControlEffect::None => {}
                            ControlEffect::PoolQueueReady(queue, cap) => {
                                let _ = sched.pool_queue_ready(now, queue, cap);
                            }
                            ControlEffect::OwnerStatus {
                                relay,
                                ld,
                                present,
                                consumed,
                                expired,
                            } => {
                                let _ =
                                    sched.owner_status(now, relay, ld, present, consumed, expired);
                            }
                        }
                        sched.control_done(op);
                    }
                    Err(closed_before) => sched.control_failed(now, op, closed_before)?,
                }
                Vec::new()
            }
            Event::Job(done) => {
                self.deferred.on_done(done);
                Vec::new()
            }
            Event::Wrote(link, len, at) => {
                self.step(Step::Wrote(at, link, len));
                Vec::new()
            }
        };
        self.apply(sched, outs, now).await
    }

    /// Carry out the scheduler's outputs; returns once every write among them is flushed to its stream.
    async fn apply(
        &mut self,
        sched: &mut Scheduler,
        outs: Vec<Output>,
        now: u64,
    ) -> Result<(), SchedError> {
        let _ = &sched;
        let mut queue: VecDeque<Output> = outs.into();
        let mut acks = Vec::new();
        while let Some(out) = queue.pop_front() {
            match out {
                Output::Event(e) => {
                    if let Some(log) = &mut self.log {
                        log.events.push((now, e));
                    }
                }
                Output::Connect {
                    link,
                    key,
                    relay,
                    transport,
                    ..
                } => self.connect(now, link, key, relay, transport),
                Output::Write { link, bytes, .. } => {
                    if let Some(io) = self.links.get(&link) {
                        let (tx, rx) = oneshot::channel();
                        if io.writer.send((bytes, tx)).is_ok() {
                            acks.push(rx);
                        }
                    }
                }
                Output::Close { link } => {
                    if let Some(io) = self.links.remove(&link) {
                        io.stop();
                    }
                }
                Output::Control {
                    op,
                    key,
                    relay,
                    kind,
                    transport,
                } => {
                    // a re-creation (or a new pool queue): what the facade knew of the queue's cells is void (EXTB-2)
                    if let ControlKind::QueueNew(queue) = kind {
                        self.deferred.recreated(queue);
                    }
                    self.control(now, op, key, relay, kind, transport);
                }
            }
        }
        // (i) flushed before the caller goes on; the writer tasks of different links write in parallel
        for ack in acks {
            let _ = ack.await;
        }
        Ok(())
    }

    fn start_io(&mut self, link: LinkId, stream: P::Stream) {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let events = self.events_tx.clone();
        let reader = tokio::spawn(async move {
            loop {
                let mut unit = vec![0_u8; FRAME_LEN];
                if rd.read_exact(&mut unit).await.is_err() {
                    let _ = events.send(Event::Closed(link));
                    break;
                }
                if events.send(Event::Frame(link, unit)).is_err() {
                    break;
                }
            }
        });
        let (tx, mut rx) = mpsc::unbounded_channel::<WriteReq>();
        let events = self.events_tx.clone();
        let clock = Arc::clone(&self.clock);
        let log = self.log.is_some();
        let writer = tokio::spawn(async move {
            while let Some((bytes, ack)) = rx.recv().await {
                let ok = wr.write_all(&bytes).await.is_ok() && wr.flush().await.is_ok();
                if ok && log {
                    let _ = events.send(Event::Wrote(link, bytes.len(), clock.mono_ms()));
                }
                let _ = ack.send(ok);
                if !ok {
                    let _ = events.send(Event::Closed(link));
                    break;
                }
            }
        });
        if let Some(old) = self.links.insert(
            link,
            LinkIo {
                writer: tx,
                tasks: [reader, writer],
            },
        ) {
            old.stop();
        }
    }

    fn connect(
        &mut self,
        now: u64,
        link: LinkId,
        key: IsolationKey,
        relay: RelayId,
        transport: Transport,
    ) {
        let isolation = Isolation(key.0);
        if let Some(log) = &mut self.log {
            log.connects.push((now, Purpose::Link(link), isolation));
        }
        let resolve = Resolve {
            link,
            events: self.events_tx.clone(),
            sent: false,
        };
        let providers = Arc::clone(&self.providers);
        let directory = Arc::clone(&self.directory);
        let clock = Arc::clone(&self.clock);
        let mut entropy = self.entropy.next();
        let limit = self.connect_timeout;
        tokio::spawn(async move {
            let attempt = async {
                let relay_ref = directory.relay(relay)?;
                let stream = providers
                    .connect(transport, relay_ref, isolation)
                    .await
                    .ok()?;
                let access = directory.access_key(relay);
                let unix = clock.unix_secs();
                Some(
                    match AsyncSession::connect_outcome(
                        stream,
                        relay_ref.relay_fp,
                        access,
                        unix,
                        &mut entropy,
                    )
                    .await
                    {
                        AsyncConnectOutcome::Up(session) => {
                            Conn::Up(Box::new(session.into_parts()))
                        }
                        AsyncConnectOutcome::ClosedBeforeRelayInfo => Conn::ClosedBefore,
                        AsyncConnectOutcome::Failed(_) => Conn::Failed,
                    },
                )
            };
            let conn = match tokio::time::timeout(limit, attempt).await {
                Ok(Some(conn)) => conn,
                Ok(None) | Err(_) => Conn::Failed,
            };
            resolve.send(conn);
        });
    }

    fn control(
        &mut self,
        now: u64,
        op: OpId,
        key: IsolationKey,
        relay: RelayId,
        kind: ControlKind,
        transport: Transport,
    ) {
        let isolation = Isolation(key.0);
        if let Some(log) = &mut self.log {
            log.connects.push((now, Purpose::Control(op), isolation));
        }
        let events = self.events_tx.clone();
        let providers = Arc::clone(&self.providers);
        let directory = Arc::clone(&self.directory);
        let runner = Arc::clone(&self.runner);
        let clock = Arc::clone(&self.clock);
        let mut entropy = self.entropy.next();
        let limit = self.connect_timeout;
        tokio::spawn(async move {
            let attempt = async {
                let relay_ref = directory.relay(relay).ok_or(false)?;
                let stream = providers
                    .connect(transport, relay_ref, isolation)
                    .await
                    .map_err(|_| false)?;
                let access = directory.access_key(relay);
                let unix = clock.unix_secs();
                let session = match AsyncSession::connect_outcome(
                    stream,
                    relay_ref.relay_fp,
                    access,
                    unix,
                    &mut entropy,
                )
                .await
                {
                    AsyncConnectOutcome::Up(session) => *session,
                    AsyncConnectOutcome::ClosedBeforeRelayInfo => return Err(true),
                    AsyncConnectOutcome::Failed(_) => return Err(false),
                };
                let mut t = AsyncRelayQueueTransport::new(session);
                runner.run(op, kind, relay, &mut t).await.map_err(|_| false)
            };
            // the whole one-shot operation under the connect timeout: a hanging relay fails it, never stalls it
            let result = tokio::time::timeout(limit, attempt)
                .await
                .unwrap_or(Err(false));
            let _ = events.send(Event::Control(op, result));
        });
    }

    /// Hand every cell the worker prepared but the core never took back to the source (a real message is re-queued):
    /// call when the run is over.
    pub fn release_unused(&mut self) {
        let ready = core::mem::take(&mut self.deferred.ready);
        for (queue, cell) in ready {
            self.deferred.jobs.push(Job::Discard {
                queue,
                token: cell.token,
            });
        }
        let now = self.clock.mono_ms();
        self.dispatch_jobs(now);
    }
}

impl<P: Providers, D, R, H, W, C> Drop for Driver<P, D, R, H, W, C> {
    fn drop(&mut self) {
        for (_, io) in core::mem::take(&mut self.links) {
            io.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell() -> Result<Cell, secmp_proto::Error> {
        Cell::from_bytes(&[0x5a; secmp_proto::sizes::CELL_LEN])
    }

    /// EXTB-2: a delivery asked in an older generation of a queue and finished after its re-creation commits nothing;
    /// the same cell id in the new generation needs its own delivery.
    #[test]
    fn late_delivery_of_an_old_generation_commits_nothing() -> Result<(), secmp_proto::Error> {
        let q = QueueId(3);
        let mut d = Deferred::default();
        assert!(d.deliver(q, 1, &cell()?).is_err());
        assert_eq!(d.jobs.len(), 1);
        d.recreated(q);
        // the old generation's job finishes now
        d.on_done(JobDone::Delivered {
            queue: q,
            cell_id: 1,
            committed: true,
        });
        assert!(!d.committed.contains_key(&q));
        // the new generation's cell 1 is delivered on its own
        assert!(d.deliver(q, 1, &cell()?).is_err());
        assert_eq!(d.jobs.len(), 2);
        assert!(
            d.deliver(q, 1, &cell()?).is_err(),
            "pending: not asked twice"
        );
        assert_eq!(d.jobs.len(), 2);
        d.on_done(JobDone::Delivered {
            queue: q,
            cell_id: 1,
            committed: true,
        });
        assert_eq!(d.deliver(q, 1, &cell()?), Ok(()));
        // a committed high-water mark of the old generation is dropped by the re-creation
        d.recreated(q);
        assert!(d.deliver(q, 1, &cell()?).is_err());
        // a completion that was never asked commits nothing
        d.on_done(JobDone::Delivered {
            queue: q,
            cell_id: 9,
            committed: true,
        });
        assert!(!d.committed.contains_key(&q));
        Ok(())
    }
}
