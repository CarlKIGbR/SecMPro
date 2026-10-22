// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The engine of `two-clients`: the scripted invitation and handshake (spec §5.5, §6.4–6.6), then two clients — each a
//! [`Scheduler`] driven by the tokio [`Driver`] — that exchange the script's messages over constant-rate links.
//!
//! **What is scripted** (deviation D-C2-1, report §5). Each client first fills its queue pool through the scheduler
//! (`manage_pool`, `QUEUE_NEW` control operations) and takes the invitation queue and the reply queues from it. The
//! invitation (`LINK_PUT`, `LINK_GET` consume), the three handshake cells and the responder's acceptance then run on
//! set-up links, one connection per step, outside the scheduler: the first reply of the responder carries a
//! `RouteUpdate` (spec §6.6 step 4) and `secmp-client-core` has no sender of Content type 0x04 (`OutMessage` has no such
//! kind), so the inviter's reply route travels in the invitation file next to the URI (testkit-only). Everything after the
//! handshake — every message, every receipt, every dummy — goes through the scheduler and its links, as in a shipped
//! client.
//!
//! **Time.** On `mem` the runtime's clock is paused (virtual): a run of hours takes seconds and is reproducible (all
//! randomness is the harness's deterministic streams). On every real transport time is the runtime's real clock and all
//! randomness is the operating system's.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use secmp_client_core::clock::{Clock as _, TokioClock};
use secmp_client_core::scheduler::conversation::{Conversation, Conversations, OsSource};
use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, MsgState, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::{Driver, Job, JobDone, Only, Worker};
use secmp_client_core::scheduler::types::{
    CellSource, CellToken, QueueId, RelayId, SendFailure, SourceError, Transport,
};
use secmp_crypto::{Fingerprint, SafetyNumber, SecretBytes, Zeroizing};
use secmp_proto::hx::{Accepted, Initiator, Responder};
use secmp_proto::inv::{invitation_uri, invitee_check, parse_invitation_uri};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::prekeys::{
    IdentityKeys, InvitationRecord, IssueParams, Issued, MemoryPrekeyStore, fingerprint_of,
};
use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::ik_sig;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{AppKind, Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{Profile, RelayRef};
use secmp_proto::{Decode as _, Encode as _};
use secmp_relay::clock::HourBucket;
use secmp_transport::driver::{
    AsyncQueueTransport, AsyncRelayQueueTransport, Isolation, StreamProvider,
};
use secmp_transport::{LinkGetMode, RecvCap, SendCap};

use super::cli::{Cli, Role, Script, TransportArg};
use super::rand::Rand;
use super::trace::{Recorder, Traced};
use crate::harness::{EntropyPool, MemProvider, MemRelay, START_UNIX, TestControl, TestDirectory};

/// How a run ends badly.
#[derive(Debug)]
pub enum Fail {
    /// The chosen transport cannot be used (exit 3); never another transport is tried.
    Unavailable(String),
    /// The run failed (exit 1).
    Run(String),
    /// A usage error found while running (exit 2): a bad script or file.
    Usage(String),
}

fn run_err<E: core::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Fail {
    move |e| Fail::Run(format!("{what}: {e}"))
}

/// The isolation of set-up connections: far above the scheduler's keys.
const SETUP_ISO: u64 = 1 << 50;
/// The controller's step, and the length of one `run_until` of a driver.
const CHUNK_MS: u64 = 1_000;
/// The invitation's validity.
const INVITATION_SECS: u64 = 7 * 86_400;
/// The send period of both clients' queues (`PERIODS`, 10 s).
const PERIOD: Period = Period::S10;
/// How long Arti may take to become ready before `--transport tor` is unavailable.
const TOR_READY_LIMIT: Duration = Duration::from_secs(600);
/// How long the pool of a client may take to fill before the transport counts as unavailable.
const POOL_FILL_LIMIT_MS: u64 = 3_600_000;

// ---- the relay's reference file ------------------------------------------------------------------------------------

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [hi, lo] => Some((digit(*hi)? << 4) | digit(*lo)?),
            _ => None,
        })
        .collect()
}

/// The text of a relay reference file (`--relay-ref`): `relay_ref = <hex RelayRef>` and `access_key = <hex 32 B>`. The
/// `RelayRef`'s direct endpoint is where `loopback` (plain TCP; the pin is ignored) and `tls` (pinned) connect.
///
/// # Panics
/// Never for a well-formed `RelayRef`.
#[must_use]
pub fn relay_ref_file(relay: &RelayRef, access: &AccessKey) -> String {
    format!(
        "relay_ref = {}\naccess_key = {}\n",
        hex(&relay.encode().unwrap()),
        hex(access.expose_secret())
    )
}

fn read_relay_ref(text: &str) -> Result<(RelayRef, AccessKey), String> {
    let (mut relay, mut access) = (None, None);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let bytes = unhex(v.trim()).ok_or("a relay reference line is not hex")?;
        match k.trim() {
            "relay_ref" => relay = RelayRef::decode(&bytes).ok(),
            "access_key" => access = SecretBytes::<32>::from_slice(&bytes).ok(),
            _ => {}
        }
    }
    match (relay, access) {
        (Some(r), Some(a)) => Ok((r, a)),
        _ => {
            Err("the relay reference file needs `relay_ref` and a 32-byte `access_key`".to_owned())
        }
    }
}

// ---- the script's messages --------------------------------------------------------------------------------------------

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Direction of a script message: 0 the inviter's, 1 the invitee's.
fn salt(script: &Script, dir: u64, idx: u64) -> u64 {
    mix(script.seed ^ mix(dir.wrapping_shl(56) ^ idx))
}

/// The payload of message `idx` of direction `dir`: a seeded size in `[size_min, size_max]` and seeded bytes.
pub(crate) fn payload(script: &Script, dir: u64, idx: u64) -> Vec<u8> {
    let span = script
        .size_max
        .saturating_sub(script.size_min)
        .saturating_add(1);
    let size = script
        .size_min
        .saturating_add(salt(script, dir, idx).checked_rem(span).unwrap_or(0));
    let n = usize::try_from(size).unwrap_or(1);
    let mut state = salt(script, dir, idx) ^ 0x5851_f42d_4c95_7f2d;
    let mut out = Vec::with_capacity(n.saturating_add(8));
    while out.len() < n {
        state = mix(state);
        out.extend_from_slice(&state.to_be_bytes());
    }
    out.truncate(n);
    out
}

/// `msg_id`: the direction and the ordinal (an id of the test script, not secret).
pub(crate) fn msg_id(dir: u64, idx: u64) -> [u8; 16] {
    let mut id = [0_u8; 16];
    if let Some(b) = id.first_mut() {
        *b = u8::try_from(dir).unwrap_or(0);
    }
    for (d, s) in id.iter_mut().skip(8).zip(idx.to_be_bytes()) {
        *d = s;
    }
    id
}

// ---- the worker and the nodes ----------------------------------------------------------------------------------------

/// The conversations of a client (one: its contact).
pub type Convs<R> = Conversations<MemOutbox, MemPersist, R>;

/// Runs the cell-source jobs on the driver's task, against the conversations the controller also reads. The shipped
/// worker runs them on the blocking pool; a paused runtime needs the work to take no real time between two instants.
struct InlineWorker<S>(Arc<Mutex<S>>, Option<Arc<Observer>>);

impl<S: CellSource + Send + 'static> Worker for InlineWorker<S> {
    fn run(&mut self, job: Job) -> impl core::future::Future<Output = JobDone> + Send {
        if let (Job::Evicted { cell_id, .. }, Some(o)) = (&job, &self.1) {
            o.evicted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(*cell_id);
        }
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        core::future::ready(job.apply(&mut *g))
    }
}

/// A cell source with nothing to send (`set_direct` before any queue exists).
struct NoCells;

impl CellSource for NoCells {
    fn prepare_cell(
        &mut self,
        _: QueueId,
        _: u64,
    ) -> Result<Option<secmp_client_core::scheduler::types::PreparedCell>, SourceError> {
        Ok(None)
    }
    fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
    fn evicted(&mut self, _: QueueId, _: u64) {}
    fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
    fn discard(&mut self, _: QueueId, _: CellToken) {}
    fn queue_lost(&mut self, _: QueueId) {}
    fn deliver(&mut self, _: QueueId, _: u64, _: &Cell) -> Result<(), SourceError> {
        Ok(())
    }
}

type NodeDriver<P, R> = Driver<
    Only<Traced<P>>,
    TestDirectory,
    TestControl,
    <R as Rand>::Hs,
    InlineWorker<Convs<R>>,
    TokioClock,
>;

struct Node<P: StreamProvider + 'static, R: Rand> {
    sched: Scheduler,
    driver: NodeDriver<P, R>,
    convs: Arc<Mutex<Convs<R>>>,
}

/// What a client that restarts needs besides its conversations (which survive in memory, like a disk): its two queues
/// as capability bytes, the periods, and its place in the script.
#[derive(Clone)]
pub struct Restart {
    name: &'static str,
    dir: u64,
    send: Vec<u8>,
    send_period_ms: u64,
    recv: Vec<u8>,
    recv_period_ms: u64,
    recv_seeds: Seeds,
}

impl Restart {
    /// The recipient id of the queue the client receives on (what a relay that restarted must see re-created).
    #[must_use]
    pub fn recv_rid(&self) -> Option<secmp_proto::wire::Id> {
        RecvCap::from_bytes(&self.recv)
            .ok()
            .map(|c| *c.queue().rid())
    }
}

/// A client the engine brought up: its conversations and what a restart needs.
struct Registered {
    convs: Box<dyn core::any::Any + Send>,
    restart: Restart,
}

/// What the host of an engine run (a network simulation) can see of it from outside: the trace recorder of the world
/// and, per client, its conversations and its [`Restart`] data. Create one per client, outside the host, and pass it to
/// [`World::new`].
#[derive(Default)]
pub struct Observer {
    /// The cell ids the relay reported evicted from the client's send queues.
    evicted: Mutex<Vec<u64>>,
    /// Every connection the drivers opened: time (ms), purpose.
    connects: Mutex<Vec<(u64, secmp_client_core::scheduler::run::Purpose)>>,
    events: Mutex<Vec<(u64, secmp_client_core::scheduler::types::LinkEvent)>>,
    rec: Mutex<Option<Arc<Recorder>>>,
    registered: Mutex<Vec<Registered>>,
}

impl Observer {
    /// An empty observer.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The recorder of the latest world made with this observer.
    #[must_use]
    pub fn recorder(&self) -> Option<Arc<Recorder>> {
        self.rec
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The conversations and the restart data of the client of the latest start, if it is up.
    #[must_use]
    pub fn client<R: Rand>(&self) -> Option<(Arc<Mutex<Convs<R>>>, Restart)> {
        let g = self
            .registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let r = g.last()?;
        let convs = r.convs.downcast_ref::<Arc<Mutex<Convs<R>>>>()?;
        Some((Arc::clone(convs), r.restart.clone()))
    }

    /// The cell ids reported evicted to the client so far.
    #[must_use]
    pub fn evicted(&self) -> Vec<u64> {
        self.evicted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The connections the drivers opened, as far as the runs ended and reported.
    #[must_use]
    pub fn connects(&self) -> Vec<(u64, secmp_client_core::scheduler::run::Purpose)> {
        self.connects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The local events of the scheduler (`Up`, `TornDown`, …) with their times, as far as the runs ended and reported.
    #[must_use]
    pub fn events(&self) -> Vec<(u64, secmp_client_core::scheduler::types::LinkEvent)> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn register<R: Rand>(&self, convs: &Arc<Mutex<Convs<R>>>, restart: &Restart) {
        self.registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Registered {
                convs: Box::new(Arc::clone(convs)),
                restart: restart.clone(),
            });
    }
}

/// What a client needs to start: its conversation and its two queues.
struct Start<R: Rand> {
    state: RatchetState,
    peer: secmp_crypto::HybridVerifyingKey,
    rand: R,
    send: SendCap,
    send_period_ms: u64,
    recv: RecvCap,
    recv_period_ms: u64,
    recv_seeds: Seeds,
}

/// The driver of a pool scheduler: no conversations, so a worker over a source without cells.
type PoolDriver<P, R> = Driver<
    Only<Traced<P>>,
    TestDirectory,
    TestControl,
    <R as Rand>::Hs,
    InlineWorker<NoCells>,
    TokioClock,
>;

/// A queue taken from the pool: its recipient and sender seeds, and the pool's spares before and after.
type Taken = (SecretBytes<32>, SecretBytes<32>, usize, usize);

/// A client's queue pool before its conversation exists (spec §10.6 (3)): a scheduler that manages the pool of its relay
/// — the spares are made by `QUEUE_NEW` control operations on one-shot links, delayed from each other — and the driver
/// that runs them. The driver runs only while the pool fills; the queues the script takes are taken from the scheduler's
/// pool (`take_pool_queue`), and the driver never runs again, so nothing fetches (and acknowledges) a taken queue
/// before the script reads it.
struct Pooled<P: StreamProvider + 'static, R: Rand> {
    sched: Scheduler,
    driver: PoolDriver<P, R>,
    material: Arc<Mutex<crate::harness::ControlMaterial>>,
    clock: TokioClock,
    /// The `QUEUE_NEW` control operations that had run when the pool was full.
    filled_ops: usize,
}

fn copy_seed(s: &SecretBytes<32>) -> SecretBytes<32> {
    SecretBytes::from_slice(s.expose_secret()).unwrap()
}

impl<P: StreamProvider + 'static, R: Rand> Pooled<P, R> {
    /// The `QUEUE_NEW` control operations the pool's runner has carried out.
    fn queue_new_ops(&self) -> usize {
        self.material
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .done
            .iter()
            .filter(|k| {
                matches!(
                    k,
                    secmp_client_core::scheduler::types::ControlKind::QueueNew(_)
                )
            })
            .count()
    }

    /// Those carried out since the pool was full: the invitation takes spares and creates nothing.
    fn queue_new_ops_since_fill(&self) -> usize {
        self.queue_new_ops().saturating_sub(self.filled_ops)
    }

    /// Take the oldest spare: its two seeds, and the pool's spares before and after.
    fn take(&mut self) -> Result<Taken, Fail> {
        let relay = RelayId(0);
        let before = self.sched.pool_spares(relay);
        let (queue, _outputs) = self
            .sched
            .take_pool_queue(self.clock.mono_ms(), relay, PERIOD_MS, &mut NoCells)
            .map_err(|_| Fail::Run("the pool refused the queue".to_owned()))?;
        let queue = queue.ok_or_else(|| Fail::Run("the pool has no spare queue".to_owned()))?;
        let seeds = self
            .material
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .queues
            .get(&queue.0)
            .copied()
            .ok_or_else(|| Fail::Run("a pool queue without seeds".to_owned()))?;
        let seed = |b: [u8; 32]| SecretBytes::from_slice(&b).map_err(run_err("seed"));
        Ok((
            seed(seeds.0)?,
            seed(seeds.1)?,
            before,
            self.sched.pool_spares(relay),
        ))
    }

    fn finish(mut self) -> Result<(), Fail> {
        self.driver
            .shutdown(&mut self.sched)
            .map_err(|_| Fail::Run("the pool driver could not shut down".to_owned()))
    }
}

/// Everything the nodes of a process share.
pub struct World<P: StreamProvider + 'static> {
    provider: Arc<P>,
    relay: RelayRef,
    access: AccessKey,
    clock: TokioClock,
    unix_base: u64,
    mode: Mode,
    direct: bool,
    rec: Arc<Recorder>,
    /// `QUEUE_NEW` commands sent over the script's set-up links.
    queue_news: Arc<AtomicU64>,
    /// The drivers' connect timeout.
    connect_timeout_ms: Option<u64>,
    /// What a host outside the engine can see of the run.
    observer: Option<Arc<Observer>>,
}

fn copy_key(k: &AccessKey) -> AccessKey {
    SecretBytes::from_slice(k.expose_secret()).unwrap()
}

impl<P: StreamProvider + 'static> World<P> {
    fn node<R: Rand>(
        &self,
        s: Start<R>,
        label: &'static str,
        seed: u64,
    ) -> Result<Node<P, R>, Fail> {
        let conv = Conversation::new(
            s.state,
            MemOutbox::new(),
            MemPersist::new(),
            s.rand,
            s.peer,
            self.unix_base,
        );
        let mut all = Conversations::new();
        all.add(conv);
        let convs = Arc::new(Mutex::new(all));
        self.node_over(
            convs,
            (s.send, s.send_period_ms),
            (s.recv, s.recv_period_ms, s.recv_seeds),
            label,
            seed,
        )
    }

    /// A node over conversations that exist: a scheduler with the two queues, bound to conversation 0, and a driver.
    fn node_over<R: Rand>(
        &self,
        convs: Arc<Mutex<Convs<R>>>,
        send_to: (SendCap, u64),
        recv: (RecvCap, u64, Seeds),
        label: &'static str,
        seed: u64,
    ) -> Result<Node<P, R>, Fail> {
        let now = self.clock.mono_ms();
        let mut sched = Scheduler::new(Params::default(), self.mode, R::timing(seed));
        if self.direct {
            let _ = sched
                .set_direct(now, true, &mut NoCells)
                .map_err(|_| Fail::Run("the sched refused direct mode".to_owned()))?;
        }
        let refused = |_| Fail::Run("the scheduler refused a queue".to_owned());
        let sq = sched
            .add_send_queue(now, RelayId(0), send_to.0, send_to.1)
            .map_err(refused)?;
        let rq = sched
            .add_recv_queue(now, RelayId(0), recv.0, recv.1)
            .map_err(refused)?;
        convs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(0)
            .ok_or_else(|| Fail::Run("no conversation".to_owned()))?
            .bind(sq, rq);
        let transport = if self.direct {
            Transport::Direct
        } else {
            Transport::Tor
        };
        // the queue this client receives on is re-created from its own seeds when the relay forgets it (spec §9.1)
        let control = TestControl::new(copy_key(&self.access), label, 0);
        control
            .material
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .queues
            .insert(rq.0, recv.2);
        let driver = Driver::new(
            Arc::new(Only::new(
                if self.observer.is_some() {
                    // a simulation breaks connections on purpose: a stream dropped inside a unit is no error
                    Traced::lenient(Arc::clone(&self.provider), Arc::clone(&self.rec))
                } else {
                    Traced::new(Arc::clone(&self.provider), Arc::clone(&self.rec))
                },
                transport,
            )),
            Arc::new(TestDirectory::new(
                self.relay.clone(),
                copy_key(&self.access),
            )),
            Arc::new(control),
            R::handshakes(label, 0),
            InlineWorker(Arc::clone(&convs), self.observer.clone()),
            Arc::new(self.clock),
        );
        let driver = match self.connect_timeout_ms {
            Some(ms) => driver.with_connect_timeout(ms),
            None => driver,
        };
        // a simulation reads the scheduler's local events
        let driver = if self.observer.is_some() {
            driver.with_log()
        } else {
            driver
        };
        Ok(Node {
            sched,
            driver,
            convs,
        })
    }

    /// The `QUEUE_NEW` commands the script itself has sent so far (the pool's are control operations, not counted).
    fn queue_new_commands(&self) -> u64 {
        self.queue_news.load(Ordering::SeqCst)
    }

    /// A set-up connection (one step of the script): a link to the relay, handshake done.
    async fn open<R: Rand>(
        &self,
        iso: &mut u64,
        rand: &mut R,
    ) -> Result<SetupLink<P::Stream>, Fail> {
        *iso = iso.saturating_add(1);
        let stream = self
            .provider
            .connect(&self.relay, Isolation(SETUP_ISO | *iso))
            .await
            .map_err(|e| Fail::Unavailable(format!("connect: {e}")))?;
        let inner = AsyncRelayQueueTransport::connect(
            stream,
            self.relay.relay_fp,
            Some(&self.access),
            self.clock.unix_secs(),
            rand.entropy(),
        )
        .await
        .map_err(run_err("link handshake"))?;
        Ok(SetupLink {
            inner,
            queue_news: Arc::clone(&self.queue_news),
        })
    }
}

/// A set-up link of the script. It counts the `QUEUE_NEW` commands sent over it: the script takes its queues from the
/// pool, so the count stays 0 (TC-03 reads it at run time; the pool's own creations are control operations).
struct SetupLink<S> {
    inner: AsyncRelayQueueTransport<S>,
    queue_news: Arc<AtomicU64>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncQueueTransport
    for SetupLink<S>
{
    async fn create_queue(
        &mut self,
        recv: &SecretBytes<32>,
        send: &SecretBytes<32>,
        token: &secmp_transport::Token,
    ) -> secmp_transport::Result<(RecvCap, SendCap)> {
        self.queue_news.fetch_add(1, Ordering::SeqCst);
        self.inner.create_queue(recv, send, token).await
    }

    async fn send(
        &mut self,
        to: &SendCap,
        cell: &Cell,
    ) -> secmp_transport::Result<secmp_transport::SendOutcome> {
        self.inner.send(to, cell).await
    }

    async fn fetch(
        &mut self,
        from: &RecvCap,
        ack: secmp_transport::CellId,
    ) -> secmp_transport::Result<Vec<(secmp_transport::CellId, Cell)>> {
        self.inner.fetch(from, ack).await
    }

    async fn fetch_multi(
        &mut self,
        from: &[(&RecvCap, secmp_transport::CellId)],
    ) -> secmp_transport::Result<secmp_transport::FetchMultiOutcome> {
        self.inner.fetch_multi(from).await
    }

    async fn delete_queue(&mut self, q: &RecvCap) -> secmp_transport::Result<()> {
        self.inner.delete_queue(q).await
    }

    async fn put_link_data(
        &mut self,
        id: secmp_transport::LdId,
        owner: &SecretBytes<32>,
        blob: &secmp_proto::wire::inv::LinkBlob,
        one_time: bool,
        expires: secmp_transport::Bucket,
        token: &secmp_transport::Token,
    ) -> secmp_transport::Result<()> {
        self.inner
            .put_link_data(id, owner, blob, one_time, expires, token)
            .await
    }

    async fn get_link_data(
        &mut self,
        id: secmp_transport::LdId,
        mode: LinkGetMode<'_>,
    ) -> secmp_transport::Result<secmp_transport::LinkGetOutcome> {
        self.inner.get_link_data(id, mode).await
    }
}

// ---- the invitation and the handshake --------------------------------------------------------------------------------

fn public_key(seed: &SecretBytes<32>) -> Ed25519Pk {
    let key = secmp_crypto::Ed25519SigningKey::from_seed(seed.expose_secret()).unwrap();
    Ed25519Pk::from_bytes(key.verifying_key().as_bytes()).unwrap()
}

/// The inviter: its identity, prekey store, invitation, and the two queues it made.
/// A queue of the client's own that the conversation receives on: the capability and the seeds it was made from
/// (a restart of the relay re-creates the identical queue from them, spec §9.1).
struct Reply {
    cap: RecvCap,
    seeds: Seeds,
}

/// The recipient and the sender seed of a queue.
type Seeds = ([u8; 32], [u8; 32]);

struct Inviter {
    identity: IdentityKeys,
    store: MemoryPrekeyStore,
    issued: Issued,
    record: InvitationRecord,
    invitation_queue: RecvCap,
    reply: Reply,
    /// The hex encoding of the reply route (it travels in the invitation file).
    reply_route: String,
}

/// The invitation file: `invitation = <uri>` and `route = <hex RouteDescriptor>` (see the module documentation).
struct InviteFile {
    uri: String,
    route: RouteDescriptor,
}

impl InviteFile {
    fn text(uri: &str, route_hex: &str) -> String {
        format!("invitation = {uri}\nroute = {route_hex}\n")
    }

    fn parse(text: &str) -> Result<Self, String> {
        let (mut uri, mut route) = (None, None);
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k.trim() {
                "invitation" => uri = Some(v.trim().to_owned()),
                "route" => {
                    route = unhex(v.trim()).and_then(|b| RouteDescriptor::decode(&b).ok());
                }
                _ => {}
            }
        }
        match (uri, route) {
            (Some(uri), Some(route)) => Ok(Self { uri, route }),
            _ => Err("the invitation file needs `invitation` and `route`".to_owned()),
        }
    }
}

impl<P: StreamProvider + 'static> World<P> {
    /// Stage 1: the inviter issues the invitation, publishes its link data, creates the invitation queue and its reply
    /// queue.
    async fn issue<R: Rand>(
        &self,
        iso: &mut u64,
        rand: &mut R,
        pool: &mut Pooled<P, R>,
        out: &mut dyn Write,
    ) -> Result<Inviter, Fail> {
        let now = self.clock.unix_secs();
        let identity = IdentityKeys::generate(rand.entropy()).map_err(run_err("identity"))?;
        let mut store = MemoryPrekeyStore::default();
        let expires = now.saturating_add(INVITATION_SECS);
        let params = IssueParams {
            relay: self.relay.clone(),
            inv_period: PERIOD,
            profile: Profile::new("inviter", None).map_err(run_err("profile"))?,
            now,
            expires,
            spk_expiry: expires,
        };
        let mut issued = store
            .issue_invitation(&identity, params, rand.entropy())
            .map_err(run_err("invitation"))?;
        let mut record = store
            .record(&issued.invitation.ld_id)
            .ok_or_else(|| Fail::Run("no invitation record".to_owned()))?
            .duplicate_kat()
            .map_err(run_err("record"))?;
        // the invitation queue is a pooled queue (spec §5.2, §10.6 (3)): `issue_invitation` draws seeds of its own and
        // has no input for a queue that exists, so the invitation and the record take the pooled queue's seeds (the
        // link data does not depend on them)
        let (inv_recv, inv_send, spares_before, spares_after) = pool.take()?;
        issued.invitation.inv_sid =
            secmp_proto::link::ids::sid(&public_key(&inv_recv), &public_key(&inv_send))
                .map_err(run_err("invitation queue"))?;
        issued.invitation.inv_send_seed = inv_send;
        record.invq_recv_seed = copy_seed(&inv_recv);
        let invitation_queue =
            RecvCap::from_seed(&inv_recv).map_err(run_err("invitation queue"))?;
        let (reply_recv_seed, reply_send_seed, _, _) = pool.take()?;
        let reply = Reply {
            cap: RecvCap::from_seed(&reply_recv_seed).map_err(run_err("reply queue"))?,
            seeds: (
                *reply_recv_seed.expose_secret(),
                *reply_send_seed.expose_secret(),
            ),
        };
        let mut t = self.open(iso, rand).await?;
        t.put_link_data(
            issued.invitation.ld_id,
            &record.owner_seed,
            &issued.blob,
            true,
            HourBucket::from_unix_secs(expires).0,
            &self.access,
        )
        .await
        .map_err(run_err("LINK_PUT"))?;
        say(out, "step=link_put");
        say(
            out,
            &format!(
                "step=invitation_queue source=pool spares_before={spares_before} spares_after={spares_after} queue_new_commands={} queue_new_ops_since_fill={}",
                self.queue_new_commands(),
                pool.queue_new_ops_since_fill()
            ),
        );
        let route = RelayQueue::derived(
            self.relay.clone(),
            &public_key(&reply_recv_seed),
            reply_send_seed,
            PERIOD,
        )
        .map_err(run_err("reply route"))?;
        Ok(Inviter {
            identity,
            store,
            issued,
            record,
            invitation_queue,
            reply,
            reply_route: hex(&RouteDescriptor::RelayQueue(route).encode().unwrap()),
        })
    }

    /// Stage 2: the invitee consumes the link data, checks it (§5.5), builds its reply route and sends the three
    /// handshake cells to the invitation queue.
    async fn respond<R: Rand>(
        &self,
        iso: &mut u64,
        rand: &mut R,
        file: &InviteFile,
        pool: &mut Pooled<P, R>,
        out: &mut dyn Write,
    ) -> Result<Invitee, Fail> {
        let now = self.clock.unix_secs();
        let parsed = parse_invitation_uri(&file.uri)
            .map_err(|_| Fail::Usage("the invitation does not parse".to_owned()))?;
        let mut t = self.open(iso, rand).await?;
        let got = t
            .get_link_data(parsed.ld_id, LinkGetMode::Consume)
            .await
            .map_err(run_err("LINK_GET"))?;
        let blob = got
            .blob
            .filter(|_| got.present && !got.consumed)
            .ok_or_else(|| Fail::Run("the link data is gone or was consumed".to_owned()))?
            .encode()
            .map_err(run_err("blob"))?;
        say(out, "step=link_get_consume");
        let accepted = invitee_check(parsed, &blob, now)
            .map_err(|_| Fail::Run("the invitation is refused (§5.5)".to_owned()))?;
        let identity = IdentityKeys::generate(rand.entropy()).map_err(run_err("identity"))?;
        // the reply queue is a pooled queue too (spec §5.5 step 5)
        let (recv_seed, send_seed, spares_before, spares_after) = pool.take()?;
        let reply = Reply {
            cap: RecvCap::from_seed(&recv_seed).map_err(run_err("reply queue"))?,
            seeds: (*recv_seed.expose_secret(), *send_seed.expose_secret()),
        };
        say(
            out,
            &format!(
                "step=reply_queue side=invitee source=pool spares_before={spares_before} spares_after={spares_after} queue_new_commands={} queue_new_ops_since_fill={}",
                self.queue_new_commands(),
                pool.queue_new_ops_since_fill()
            ),
        );
        let route = RelayQueue::derived(
            self.relay.clone(),
            &public_key(&recv_seed),
            send_seed,
            PERIOD,
        )
        .map_err(run_err("reply route"))?;
        let (handshake, state) = Initiator::start(
            &accepted,
            &identity.initiator_keys(),
            &[RouteDescriptor::RelayQueue(route)],
            &Profile::new("invitee", None).map_err(run_err("profile"))?,
            now,
            rand.entropy(),
        )
        .map_err(run_err("handshake"))?;
        let cells: [Cell; 3] = handshake
            .release(&state, |_, _| Ok::<(), secmp_proto::Error>(()))
            .map_err(run_err("handshake cells"))?;
        let inv = accepted.invitation();
        let to_invitation = SendCap::from_route(inv.inv_sid, &inv.inv_send_seed)
            .map_err(run_err("invitation route"))?;
        for cell in &cells {
            t.send(&to_invitation, cell)
                .await
                .map_err(run_err("handshake SEND"))?;
        }
        say(out, "step=hx_initiator cells=3");
        let inviter_iks = &accepted.link_data().inviter_iks;
        let peer = ik_sig(inviter_iks).map_err(run_err("inviter key"))?;
        let sas = sas_of(
            &identity.fingerprint().map_err(run_err("fingerprint"))?,
            &fingerprint_of(inviter_iks).map_err(run_err("fingerprint"))?,
        )?;
        let to_inviter = match &file.route {
            RouteDescriptor::RelayQueue(q) => (
                SendCap::from_route(q.sid, &q.send_seed).map_err(run_err("inviter route"))?,
                u64::from(q.period_s.seconds()).saturating_mul(1000),
            ),
            RouteDescriptor::Unknown { .. } => {
                return Err(Fail::Usage(
                    "the inviter's route is not a relay queue".to_owned(),
                ));
            }
        };
        Ok(Invitee {
            state,
            peer,
            reply,
            to_inviter,
            sas,
        })
    }

    /// Stage 3: the inviter fetches the three cells (polling every 2 s up to `wait_ms`) and accepts the handshake.
    async fn accept<R: Rand>(
        &self,
        iso: &mut u64,
        rand: &mut R,
        host: &mut Inviter,
        wait_ms: u64,
        out: &mut dyn Write,
    ) -> Result<Inviter2, Fail> {
        let t0 = self.clock.mono_ms();
        let fetched: Vec<Cell> = loop {
            let mut t = self.open(iso, rand).await?;
            let cells: Vec<Cell> = t
                .fetch(&host.invitation_queue, 0)
                .await
                .map_err(run_err("FETCH"))?
                .into_iter()
                .map(|(_, c)| c)
                .collect();
            if cells.len() >= 3 {
                break cells;
            }
            if self.clock.mono_ms().saturating_sub(t0) > wait_ms {
                return Err(Fail::Run("no handshake arrived".to_owned()));
            }
            drop(t);
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        let accepted: Accepted = Responder::accept(
            &fetched,
            &host.record,
            &mut host.store,
            &host.identity.responder_keys(),
            rand.entropy(),
        )
        .map_err(|_| Fail::Run("the handshake is refused (§6.6)".to_owned()))?;
        let status = {
            let mut t = self.open(iso, rand).await?;
            t.get_link_data(
                host.issued.invitation.ld_id,
                LinkGetMode::OwnerStatus(&host.record.owner_seed),
            )
            .await
            .map_err(run_err("LINK_GET owner status"))?
        };
        say(
            out,
            &format!(
                "step=hx_responder accepted=true link_data present={} consumed={}",
                status.present, status.consumed
            ),
        );
        let peer = ik_sig(&accepted.peer).map_err(run_err("invitee key"))?;
        let sas = sas_of(
            &host
                .identity
                .fingerprint()
                .map_err(run_err("fingerprint"))?,
            &fingerprint_of(&accepted.peer).map_err(run_err("fingerprint"))?,
        )?;
        let to_invitee = match accepted.routes.first() {
            Some(RouteDescriptor::RelayQueue(q)) => (
                SendCap::from_route(q.sid, &q.send_seed).map_err(run_err("invitee route"))?,
                u64::from(q.period_s.seconds()).saturating_mul(1000),
            ),
            _ => {
                return Err(Fail::Run(
                    "the handshake carries no relay-queue route".to_owned(),
                ));
            }
        };
        Ok(Inviter2 {
            state: accepted.state,
            peer,
            to_invitee,
            sas,
        })
    }
}

/// The invitee after its handshake cells are on the relay.
struct Invitee {
    state: RatchetState,
    peer: secmp_crypto::HybridVerifyingKey,
    reply: Reply,
    to_inviter: (SendCap, u64),
    sas: String,
}

/// The inviter after it accepted.
struct Inviter2 {
    state: RatchetState,
    peer: secmp_crypto::HybridVerifyingKey,
    to_invitee: (SendCap, u64),
    sas: String,
}

/// The 60-digit safety number of two identity fingerprints (spec §6.7).
fn sas_of(a: &[u8; 32], b: &[u8; 32]) -> Result<String, Fail> {
    let fa = Fingerprint::from_bytes(a).map_err(run_err("fingerprint"))?;
    let fb = Fingerprint::from_bytes(b).map_err(run_err("fingerprint"))?;
    Ok(SafetyNumber::new(&fa, &fb).as_str().to_owned())
}

// ---- the conversation ----------------------------------------------------------------------------------------------

/// One local client in the conversation phase.
struct Side<P: StreamProvider + 'static, R: Rand> {
    name: &'static str,
    node: Node<P, R>,
    /// The direction of its own messages (0 inviter, 1 invitee).
    dir: u64,
    seen: usize,
    /// Messages of the script queued before (a restart goes on where the run was).
    queued: u64,
    /// What a restart of this client needs.
    restart: Restart,
}

/// What the conversation phase reports.
struct Done {
    /// `(name, received, expected)` per local client.
    delivered: Vec<(&'static str, usize, usize)>,
    /// Every received message was the expected one, once, in order.
    exact: bool,
    /// They arrived in the script's order.
    in_order: bool,
    /// The script was completed (all received, all own messages receipted) before the run ended.
    complete: bool,
    end_ms: u64,
}

/// What the controller keeps of a local client while its driver runs on a task of its own.
struct Shell<R: Rand> {
    name: &'static str,
    convs: Arc<Mutex<Convs<R>>>,
    dir: u64,
    seen: usize,
    /// Messages of the script queued so far.
    queued: u64,
}

impl<R: Rand> Shell<R> {
    fn with<T>(&self, f: impl FnOnce(&Conversation<MemOutbox, MemPersist, R>) -> T) -> T {
        let convs = self.convs.lock().unwrap_or_else(PoisonError::into_inner);
        f(convs.get(0).unwrap())
    }

    /// Queue the messages of the script that are due at `now` (message `i` at `t0 + i × interval_s`; the outbox sends
    /// them one cell per slot, in order).
    fn enqueue_due(&mut self, rec: &Recorder, script: &Script, t0: u64, now: u64) {
        while self.queued < script.messages
            && t0.saturating_add(script.enqueue_at_ms(self.queued)) <= now
        {
            let idx = self.queued;
            let mut convs = self.convs.lock().unwrap_or_else(PoisonError::into_inner);
            convs.get_mut(0).unwrap().outbox_mut().enqueue(
                OutMessage {
                    msg_id: msg_id(self.dir, idx),
                    kind: AppKind::Text,
                    expire_after: 0,
                    payload: Zeroizing::new(payload(script, self.dir, idx)),
                },
                now,
            );
            rec.event(
                "enqueue",
                self.dir.saturating_mul(script.messages).saturating_add(idx),
                now,
            );
            self.queued = self.queued.saturating_add(1);
        }
    }

    /// The client has queued the whole script, received everything the script sends it, and every message of its own
    /// is receipted.
    fn complete(&self, script: &Script) -> bool {
        let want = usize::try_from(script.messages).unwrap_or(usize::MAX);
        self.queued >= script.messages
            && self.with(|c| {
                c.received().len() >= want
                    && c.outbox()
                        .states()
                        .iter()
                        .all(|(_, s)| *s == MsgState::Delivered)
            })
    }

    /// Record a `deliver` event for each message received since the last look.
    fn observe(&mut self, rec: &Recorder, script: &Script, now: u64) {
        let got = self.with(|c| c.received().len());
        let peer_dir = 1_u64.saturating_sub(self.dir);
        while self.seen < got {
            let ordinal = peer_dir
                .saturating_mul(script.messages)
                .saturating_add(u64::try_from(self.seen).unwrap_or(u64::MAX));
            rec.event("deliver", ordinal, now);
            self.seen = self.seen.saturating_add(1);
        }
    }
}

/// What a client's task returns: the node, and whether its driver ran to the end (no randomness lost).
type Finished<P, R> = (Node<P, R>, bool);

/// The driver tasks and the controller's view of the clients they run.
type Spawned<P, R> = (Vec<tokio::task::JoinHandle<Finished<P, R>>>, Vec<Shell<R>>);

/// Run each client's driver on a task of its own, in steps of [`CHUNK_MS`], until `stop`.
fn spawn_drivers<P: StreamProvider + 'static, R: Rand>(
    clock: TokioClock,
    sides: Vec<Side<P, R>>,
    stop: &Arc<AtomicBool>,
) -> Spawned<P, R> {
    let (mut handles, mut shells) = (Vec::new(), Vec::new());
    for side in sides {
        let Side {
            name,
            node,
            dir,
            seen,
            queued,
            restart: _,
        } = side;
        shells.push(Shell {
            name,
            convs: Arc::clone(&node.convs),
            dir,
            seen,
            queued,
        });
        let stop = Arc::clone(stop);
        handles.push(tokio::spawn(async move {
            let mut node = node;
            let mut ok = true;
            while !stop.load(Ordering::SeqCst) {
                let until = clock.mono_ms().saturating_add(CHUNK_MS);
                if node.driver.run_until(&mut node.sched, until).await.is_err() {
                    ok = false;
                    break;
                }
            }
            (node, ok)
        }));
    }
    (handles, shells)
}

/// Wait for the driver tasks and shut each driver down (nothing opens a connection or writes a byte afterwards).
async fn finish<P: StreamProvider + 'static, R: Rand>(
    handles: Vec<tokio::task::JoinHandle<Finished<P, R>>>,
    observer: Option<&Observer>,
) -> Result<(), Fail> {
    for h in handles {
        let (mut node, ok) = h
            .await
            .map_err(|_| Fail::Run("a client task failed".to_owned()))?;
        if let (Some(o), Some(log)) = (observer, node.driver.log()) {
            o.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(log.events.iter().copied());
            o.connects
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(log.connects.iter().map(|(t, p, _)| (*t, *p)));
        }
        node.driver
            .shutdown(&mut node.sched)
            .map_err(|_| Fail::Run("the driver could not shut down".to_owned()))?;
        if !ok {
            return Err(Fail::Run("a driver stopped: no randomness".to_owned()));
        }
    }
    Ok(())
}

/// What [`verify`] found.
struct Verified {
    /// `(name, received, expected)` per local client.
    delivered: Vec<(&'static str, usize, usize)>,
    /// Every received message is one of the script's, with its payload, once.
    exact: bool,
    /// They arrived in the script's order.
    in_order: bool,
}

/// What each local client received, and whether every received message was the expected one: an id of the script, once,
/// with the script's payload (`exact`; (E) of the simulations) and in the script's order (`in_order`; a message evicted
/// or lost on the way is re-sent after later ones, so only a run without faults keeps the order).
fn verify<R: Rand>(shells: &[Shell<R>], script: &Script) -> Verified {
    let want = usize::try_from(script.messages).unwrap_or(0);
    let mut v = Verified {
        delivered: Vec::new(),
        exact: true,
        in_order: true,
    };
    for shell in shells {
        let peer_dir = 1_u64.saturating_sub(shell.dir);
        let (len, exact, in_order) = shell.with(|c| {
            let mut ids = std::collections::BTreeSet::new();
            let (mut exact, mut in_order) = (true, true);
            for (arrival, m) in c.received().iter().enumerate() {
                // the message's own index is in its id (`msg_id`)
                let idx = m
                    .msg_id
                    .get(8..)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map_or(u64::MAX, u64::from_be_bytes);
                exact &= m.msg_id == msg_id(peer_dir, idx)
                    && idx < script.messages
                    && m.payload.as_slice() == payload(script, peer_dir, idx).as_slice()
                    && ids.insert(m.msg_id);
                in_order &= u64::try_from(arrival).ok() == Some(idx);
            }
            (c.received().len(), exact, in_order)
        });
        v.exact &= exact;
        v.in_order &= in_order;
        v.delivered.push((shell.name, len, want));
    }
    v
}

async fn converse<P: StreamProvider + 'static, R: Rand>(
    world: &World<P>,
    sides: Vec<Side<P, R>>,
    script: &Script,
    cli: &Cli,
) -> Result<Done, Fail> {
    let t0 = world.clock.mono_ms();
    let cap_ms = if cli.transport == TransportArg::Mem {
        172_800_000
    } else {
        3_600_000
    };
    let limit_ms = cli.duration_s.map(|d| d.saturating_mul(1000));
    let grace_ms = u64::from(PERIOD.seconds()).saturating_mul(2000);
    let stop = Arc::new(AtomicBool::new(false));
    let (handles, mut shells) = spawn_drivers(world.clock, sides, &stop);
    for shell in &mut shells {
        shell.enqueue_due(&world.rec, script, t0, t0);
    }
    let mut complete_at = None::<u64>;
    let mut timed_out;
    loop {
        tokio::time::sleep(Duration::from_millis(CHUNK_MS)).await;
        let now = world.clock.mono_ms();
        // a simulation host counts the duration from its start (the clock's origin), a run from the conversation's
        let elapsed = now.saturating_sub(if world.observer.is_some() { 0 } else { t0 });
        for shell in &mut shells {
            shell.enqueue_due(&world.rec, script, t0, now);
            shell.observe(&world.rec, script, now);
        }
        if complete_at.is_none() && shells.iter().all(|s| s.complete(script)) {
            complete_at = Some(now);
        }
        let finished = match limit_ms {
            Some(limit) => elapsed >= limit,
            None => complete_at.is_some_and(|c| now.saturating_sub(c) >= grace_ms),
        };
        timed_out = limit_ms.is_none() && !finished && elapsed >= cap_ms;
        if finished || timed_out || handles.iter().any(tokio::task::JoinHandle::is_finished) {
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
    // the run is over: the streams the shutdown drops are dropped on purpose
    world.rec.seal();
    let end_ms = world.clock.mono_ms();
    finish(handles, world.observer.as_deref()).await?;
    let Verified {
        delivered,
        exact,
        in_order,
    } = verify(&shells, script);
    if timed_out {
        return Err(Fail::Run(format!(
            "timeout after {} s: delivered {delivered:?}",
            cap_ms / 1000
        )));
    }
    Ok(Done {
        delivered,
        exact,
        in_order,
        complete: complete_at.is_some(),
        end_ms: end_ms.saturating_sub(t0),
    })
}

// ---- one run ----------------------------------------------------------------------------------------------------------

fn say(out: &mut dyn Write, line: &str) {
    let _ = writeln!(out, "{line}");
}

fn read_text(path: &Path, what: &str) -> Result<String, Fail> {
    std::fs::read_to_string(path).map_err(|_| Fail::Usage(format!("cannot read {what}")))
}

/// A local client after the handshake, and the safety number it shows.
type Up<P, R> = (Side<P, R>, (&'static str, String));

/// The period both clients' queues are made with, in milliseconds.
const PERIOD_MS: u64 = 10_000;

impl<P: StreamProvider + 'static> World<P> {
    fn inviter_up<R: Rand>(&self, a: Inviter2, reply: Reply, rand: R) -> Result<Up<P, R>, Fail> {
        let restart = Restart {
            name: "inviter",
            dir: 0,
            send: a.to_invitee.0.to_bytes().to_vec(),
            send_period_ms: a.to_invitee.1,
            recv: reply.cap.to_bytes().to_vec(),
            recv_period_ms: PERIOD_MS,
            recv_seeds: reply.seeds,
        };
        let node = self.node(
            Start {
                state: a.state,
                peer: a.peer,
                rand,
                send: a.to_invitee.0,
                send_period_ms: a.to_invitee.1,
                recv: reply.cap,
                recv_period_ms: PERIOD_MS,
                recv_seeds: reply.seeds,
            },
            "two-clients-inviter",
            1,
        )?;
        let side = Side {
            name: "inviter",
            node,
            dir: 0,
            seen: 0,
            queued: 0,
            restart,
        };
        Ok((side, ("inviter", a.sas)))
    }

    fn invitee_up<R: Rand>(&self, g: Invitee, rand: R) -> Result<Up<P, R>, Fail> {
        let restart = Restart {
            name: "invitee",
            dir: 1,
            send: g.to_inviter.0.to_bytes().to_vec(),
            send_period_ms: g.to_inviter.1,
            recv: g.reply.cap.to_bytes().to_vec(),
            recv_period_ms: PERIOD_MS,
            recv_seeds: g.reply.seeds,
        };
        let node = self.node(
            Start {
                state: g.state,
                peer: g.peer,
                rand,
                send: g.to_inviter.0,
                send_period_ms: g.to_inviter.1,
                recv: g.reply.cap,
                recv_period_ms: PERIOD_MS,
                recv_seeds: g.reply.seeds,
            },
            "two-clients-invitee",
            2,
        )?;
        let side = Side {
            name: "invitee",
            node,
            dir: 1,
            seen: 0,
            queued: 0,
            restart,
        };
        Ok((side, ("invitee", g.sas)))
    }

    /// Fill the pool of client `label` with `want` spares (spec §10.6 (3)): the scheduler's `QUEUE_NEW` control
    /// operations, delayed from each other. The test tool shortens that delay (`control_delay_ms` 2…5 s, the spec's
    /// `U[1 min, 60 min]` hides which queue belongs to which invitation); nothing else in `Params` changes.
    async fn pool<R: Rand>(
        &self,
        label: &'static str,
        want: usize,
        out: &mut dyn Write,
    ) -> Result<Pooled<P, R>, Fail> {
        let mut named = R::actor(label, 2);
        let suite = format!(
            "two-clients-pool-{label}-{}",
            hex(named.seed().expose_secret())
        );
        let params = Params {
            control_delay_ms: (2_000, 5_000),
            ..Params::default()
        };
        let now = self.clock.mono_ms();
        let mut sched = Scheduler::new(params, self.mode, R::timing(3));
        let refused = |_| Fail::Run("the scheduler refused the pool".to_owned());
        if self.direct {
            let _ = sched.set_direct(now, true, &mut NoCells).map_err(refused)?;
        }
        sched.manage_pool(now, RelayId(0)).map_err(refused)?;
        let control = TestControl::new(copy_key(&self.access), &suite, 0);
        let material = Arc::clone(&control.material);
        let transport = if self.direct {
            Transport::Direct
        } else {
            Transport::Tor
        };
        let driver = Driver::new(
            Arc::new(Only::new(
                Traced::new(Arc::clone(&self.provider), Arc::clone(&self.rec)),
                transport,
            )),
            Arc::new(TestDirectory::new(
                self.relay.clone(),
                copy_key(&self.access),
            )),
            Arc::new(control),
            R::handshakes(label, 1),
            InlineWorker(Arc::new(Mutex::new(NoCells)), None),
            Arc::new(self.clock),
        );
        let driver = match self.connect_timeout_ms {
            Some(ms) => driver.with_connect_timeout(ms),
            None => driver,
        };
        let mut pool = Pooled {
            sched,
            driver,
            material,
            clock: self.clock,
            filled_ops: 0,
        };
        while pool.sched.pool_spares(RelayId(0)) < want {
            if self.clock.mono_ms().saturating_sub(now) > POOL_FILL_LIMIT_MS {
                return Err(Fail::Unavailable("the queue pool did not fill".to_owned()));
            }
            let until = self.clock.mono_ms().saturating_add(CHUNK_MS);
            pool.driver
                .run_until(&mut pool.sched, until)
                .await
                .map_err(|_| Fail::Run("the pool driver stopped: no randomness".to_owned()))?;
        }
        let made = pool.queue_new_ops();
        pool.filled_ops = made;
        say(
            out,
            &format!(
                "step=pool side={label} spares={} queue_new_ops={made}",
                pool.sched.pool_spares(RelayId(0))
            ),
        );
        Ok(pool)
    }

    /// The inviter issues its invitation; the invitation file's text (and `--invite-out`) is made.
    async fn publish<R: Rand>(
        &self,
        cli: &Cli,
        iso: &mut u64,
        rand: &mut R,
        pool: &mut Pooled<P, R>,
        out: &mut dyn Write,
    ) -> Result<(Inviter, String), Fail> {
        let host = self.issue(iso, rand, pool, out).await?;
        let text = InviteFile::text(
            &invitation_uri(&host.issued.invitation).map_err(run_err("invitation uri"))?,
            &host.reply_route,
        );
        if let Some(p) = &cli.invite_out {
            std::fs::write(p, &text).map_err(run_err("--invite-out"))?;
        }
        Ok((host, text))
    }

    /// The clients this process runs, up after the handshake: the role of `cli`; an observer sees each of them.
    async fn start<R: Rand>(&self, cli: &Cli, out: &mut dyn Write) -> Result<Vec<Up<P, R>>, Fail> {
        let up = self.start_inner::<R>(cli, out).await?;
        if let Some(o) = &self.observer {
            for (side, _) in &up {
                o.register(&side.node.convs, &side.restart);
            }
        }
        Ok(up)
    }

    async fn start_inner<R: Rand>(
        &self,
        cli: &Cli,
        out: &mut dyn Write,
    ) -> Result<Vec<Up<P, R>>, Fail> {
        let mut iso = 0_u64;
        let wait_ms = cli.duration_s.unwrap_or(1_800).saturating_mul(1000);
        let (mut ra, mut rb) = (
            R::actor("two-clients-inviter", 0),
            R::actor("two-clients-invitee", 0),
        );
        let mut up = Vec::new();
        // the transport is available or the run ends here (exit 3), before any pool is made
        drop(self.open(&mut iso, &mut ra).await?);
        if cli.role == Role::Invitee {
            let path = cli
                .invite_in
                .as_ref()
                .ok_or_else(|| Fail::Usage("--invite-in".to_owned()))?;
            let file = InviteFile::parse(&read_text(path, "--invite-in")?).map_err(Fail::Usage)?;
            let mut pool = self.pool::<R>("invitee", 2, out).await?;
            let guest = self
                .respond(&mut iso, &mut rb, &file, &mut pool, out)
                .await?;
            pool.finish()?;
            say(out, "session=up side=invitee");
            up.push(self.invitee_up(guest, rb)?);
            return Ok(up);
        }
        // the inviter's pool holds the invitation queue and its reply queue, the invitee's its reply queue
        let mut pool_a = self.pool::<R>("inviter", 2, out).await?;
        let (mut host, text) = self
            .publish(cli, &mut iso, &mut ra, &mut pool_a, out)
            .await?;
        let guest = if cli.role == Role::Both {
            let file = InviteFile::parse(&text).map_err(Fail::Usage)?;
            let mut pool_b = self.pool::<R>("invitee", 2, out).await?;
            let guest = self
                .respond(&mut iso, &mut rb, &file, &mut pool_b, out)
                .await?;
            pool_b.finish()?;
            Some(guest)
        } else {
            say(out, "invitation=written");
            None
        };
        let accepted = self
            .accept(&mut iso, &mut ra, &mut host, wait_ms, out)
            .await?;
        pool_a.finish()?;
        say(out, "session=up side=inviter");
        up.push(self.inviter_up(accepted, host.reply, ra)?);
        if let Some(guest) = guest {
            say(out, "session=up side=invitee");
            up.push(self.invitee_up(guest, rb)?);
        }
        Ok(up)
    }
}

/// One run over `world` (the transport) for the role in `cli`.
///
/// # Errors
/// [`Fail`], mapped to the exit code by the caller.
pub async fn session<P: StreamProvider + 'static, R: Rand>(
    cli: &Cli,
    world: World<P>,
    script: &Script,
    out: &mut dyn Write,
) -> Result<(), Fail> {
    let (sides, sas): (Vec<_>, Vec<_>) = world.start::<R>(cli, out).await?.into_iter().unzip();
    for (side, digits) in &sas {
        say(out, &format!("sas side={side} {digits}"));
    }
    if let [(_, a), (_, b)] = sas.as_slice() {
        say(out, if a == b { "sas=equal" } else { "sas=DIFFERENT" });
        if a != b {
            return Err(Fail::Run("the safety numbers differ".to_owned()));
        }
    }
    drive(cli, &world, sides, script, out).await
}

/// A client that restarts (a crash of its process): its conversation restarts from the last durable ratchet state
/// (`MemPersist`; the outbox and the messages received survive, what was in flight does not), a new scheduler and driver
/// open fresh links over the same two queues, and the run goes on with the script where it was.
///
/// # Errors
/// [`Fail`], mapped to the exit code by the caller.
pub async fn resume<P: StreamProvider + 'static, R: Rand>(
    cli: &Cli,
    world: World<P>,
    restart: &Restart,
    convs: Arc<Mutex<Convs<R>>>,
    script: &Script,
    out: &mut dyn Write,
) -> Result<(), Fail> {
    let (seen, queued) = {
        let mut g = convs.lock().unwrap_or_else(PoisonError::into_inner);
        let conv = g
            .get(0)
            .ok_or_else(|| Fail::Run("no conversation".to_owned()))?;
        let durable = conv
            .persist()
            .durable()
            .map_or_else(|| conv.durable().to_vec(), <[u8]>::to_vec);
        let seen = conv.received().len();
        let queued = u64::try_from(conv.outbox().states().len()).unwrap_or(u64::MAX);
        g.restart(0, &durable)
            .map_err(|_| Fail::Run("the ratchet state does not restart".to_owned()))?;
        (seen, queued)
    };
    let send = SendCap::from_bytes(&restart.send).map_err(run_err("send queue"))?;
    let recv = RecvCap::from_bytes(&restart.recv).map_err(run_err("receive queue"))?;
    let label = if restart.dir == 0 {
        "two-clients-inviter"
    } else {
        "two-clients-invitee"
    };
    let node = world.node_over(
        convs,
        (send, restart.send_period_ms),
        (recv, restart.recv_period_ms, restart.recv_seeds),
        label,
        restart.dir.saturating_add(11),
    )?;
    let side = Side {
        name: restart.name,
        node,
        dir: restart.dir,
        seen,
        queued,
        restart: restart.clone(),
    };
    drive(cli, &world, vec![side], script, out).await
}

/// The conversation phase and what follows it: the messages, the checks, the output and the trace file.
async fn drive<P: StreamProvider + 'static, R: Rand>(
    cli: &Cli,
    world: &World<P>,
    sides: Vec<Side<P, R>>,
    script: &Script,
    out: &mut dyn Write,
) -> Result<(), Fail> {
    let done = converse(world, sides, script, cli).await?;
    world
        .rec
        .check()
        .map_err(|e| Fail::Run(format!("the trace is not sound: {e}")))?;
    for (name, got, want) in &done.delivered {
        say(out, &format!("delivered side={name} {got}/{want}"));
    }
    say(
        out,
        &format!(
            "result exact={} in_order={} complete={} end_ms={}",
            done.exact, done.in_order, done.complete, done.end_ms
        ),
    );
    // the Unix time at the clock's origin: aligns the `t_ms` of two traces (the latency of a message between two
    // machines is its `deliver` time at one minus its `enqueue` time at the other, both plus their origin)
    say(out, &format!("clock unix_origin={}", world.unix_base));
    if let Some(p) = &cli.trace_out {
        super::trace::write_file(p, &world.rec.jsonl()).map_err(run_err("--trace-out"))?;
    }
    let want_all = done.delivered.iter().all(|(_, got, want)| got == want);
    if !done.exact || (!want_all && cli.duration_s.is_none()) {
        return Err(Fail::Run("messages lost, duplicated or altered".to_owned()));
    }
    Ok(())
}

fn world<P: StreamProvider + 'static>(
    cli: &Cli,
    provider: P,
    relay: RelayRef,
    access: AccessKey,
    clock: TokioClock,
    unix_base: u64,
) -> World<P> {
    World::new(
        provider,
        WorldConfig {
            relay,
            access,
            clock,
            unix_base,
            mode: cli.mode,
            direct: cli.transport == TransportArg::Tls,
            connect_timeout_ms: None,
        },
        None,
    )
}

/// What a world is made of.
pub struct WorldConfig {
    /// The relay's reference.
    pub relay: RelayRef,
    /// The relay's access key.
    pub access: AccessKey,
    /// The clock of the run (made inside the runtime the run is on).
    pub clock: TokioClock,
    /// The Unix time at the clock's origin.
    pub unix_base: u64,
    /// The scheduler mode.
    pub mode: Mode,
    /// Direct TLS mode (the scheduler names the direct transport).
    pub direct: bool,
    /// The drivers' connect timeout in ms (`None`: the driver's default, 120 s).
    pub connect_timeout_ms: Option<u64>,
}

impl<P: StreamProvider + 'static> World<P> {
    /// A world over `provider`. With an `observer` the run is a simulation: the observer sees the world's recorder
    /// and the client's conversations, the streams that break mid-unit (the network is broken on purpose) are not
    /// errors, and the trace is not checked for them.
    pub fn new(provider: P, c: WorldConfig, observer: Option<Arc<Observer>>) -> Self {
        let rec = Recorder::new(c.clock);
        if let Some(o) = &observer {
            *o.rec.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&rec));
        }
        Self {
            provider: Arc::new(provider),
            relay: c.relay,
            access: c.access,
            clock: c.clock,
            unix_base: c.unix_base,
            mode: c.mode,
            direct: c.direct,
            rec,
            queue_news: Arc::new(AtomicU64::new(0)),
            connect_timeout_ms: c.connect_timeout_ms,
            observer,
        }
    }
}

fn load_relay(cli: &Cli) -> Result<(RelayRef, AccessKey), Fail> {
    let path = cli
        .relay_ref
        .as_ref()
        .ok_or_else(|| Fail::Usage("--relay-ref".to_owned()))?;
    read_relay_ref(&read_text(path, "--relay-ref")?).map_err(Fail::Usage)
}

fn now_unix() -> u64 {
    secmp_client_core::clock::SystemClock::new().unix_secs()
}

/// Run the command line `cli`; `script` is the parsed `--script` (or the default).
///
/// # Errors
/// [`Fail`], mapped to the exit code by the caller.
pub fn run(cli: &Cli, script: &Script, out: &mut dyn Write) -> Result<(), Fail> {
    let runtime = if cli.transport == TransportArg::Mem {
        // real time: a virtual clock needs tokio's `test-util`, which no build of this binary has (ADR-051 Am. 3);
        // the tests call `run_in` with a paused runtime
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            // the ratchet and the handshake keep large frames in an unoptimised build
            .thread_stack_size(16 << 20)
            .enable_all()
            .build()
    }
    .map_err(run_err("runtime"))?;
    run_in(&runtime, cli, script, out)
}

/// As [`run`], on `runtime`. The `mem` transport reads the runtime's clock: given a paused runtime
/// (`tokio::time::pause`, tests only) a run of hours takes seconds and is reproducible.
///
/// # Errors
/// [`Fail`], mapped to the exit code by the caller.
pub fn run_in(
    runtime: &tokio::runtime::Runtime,
    cli: &Cli,
    script: &Script,
    out: &mut dyn Write,
) -> Result<(), Fail> {
    say(
        out,
        &format!(
            "two-clients transport={:?} mode={:?} role={:?}",
            cli.transport, cli.mode, cli.role
        )
        .to_lowercase(),
    );
    if cli.transport == TransportArg::Mem {
        return runtime.block_on(async {
            let relay = MemRelay::new(crate::harness::HarnessConfig::default());
            let w = world(
                cli,
                MemProvider::new(relay.clone()),
                relay.relay_ref(),
                relay.access_key(),
                relay.clock(),
                START_UNIX,
            );
            Box::pin(session::<MemProvider, EntropyPool>(cli, w, script, out)).await
        });
    }
    runtime.block_on(async {
        let (relay, access) = load_relay(cli)?;
        let unix = now_unix();
        let clock = TokioClock::new(unix);
        match cli.transport {
            TransportArg::Mem => unreachable!("handled above"),
            TransportArg::Loopback => {
                let w = world(cli, super::trace::TcpProvider, relay, access, clock, unix);
                Box::pin(session::<_, OsSource>(cli, w, script, out)).await
            }
            TransportArg::Tls => {
                let w = world(
                    cli,
                    secmp_transport::tls::TlsProvider::new(),
                    relay,
                    access,
                    clock,
                    unix,
                );
                Box::pin(session::<_, OsSource>(cli, w, script, out)).await
            }
            TransportArg::Tor => {
                let dir = cli
                    .tor_dir
                    .as_ref()
                    .ok_or_else(|| Fail::Usage("--tor-dir".to_owned()))?;
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                let provider = secmp_transport::tor::arti::start(dir, tx)
                    .map_err(|e| Fail::Unavailable(format!("Arti: {e}")))?;
                let ready = tokio::time::timeout(TOR_READY_LIMIT, async {
                    while let Some(event) = rx.recv().await {
                        if event == secmp_transport::tor::TorEvent::Ready {
                            return true;
                        }
                    }
                    false
                })
                .await;
                if ready != Ok(true) {
                    return Err(Fail::Unavailable("Tor did not become ready".to_owned()));
                }
                let w = world(cli, provider, relay, access, clock, unix);
                Box::pin(session::<_, OsSource>(cli, w, script, out)).await
            }
        }
    })
}
