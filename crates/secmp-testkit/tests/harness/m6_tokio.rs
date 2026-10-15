// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase B: the tokio driver of the scheduler core (`secmp_client_core::scheduler::run`) over the in-process relay
//! (`MemRelay`/`MemProvider`) on a paused tokio clock — the shared rig of the driver tests (`m6_driver`) and the tokio
//! repeats of AI-01…AI-06 (`m6_tokio_ai`).

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use secmp_client_core::clock::{Clock, TokioClock};
use secmp_client_core::scheduler::conversation::{Conversation, Conversations};
use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::{Driver, Only, Purpose};
use secmp_client_core::scheduler::types::{CellSource, QueueId, RelayId, Transport};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::tr::{Entropy, FixedEntropy};
use secmp_proto::wire::cell::AppKind;
use secmp_testkit::harness::{
    CONTROL_SLOT_BASE, CostedWorker, Costs, Dir, EntropyPool, HarnessConfig, JobRecord,
    MemProvider, MemRelay, START_UNIX, TestControl, TestDirectory, TestHandshakes, Trace,
    TraceEntry, ratchet_pair,
};
use secmp_transport::driver::{
    AsyncQueueTransport, AsyncRelayQueueTransport, Isolation, StreamProvider,
};
use secmp_transport::{RecvCap, SendCap};
use tokio::io::DuplexStream;

use crate::m6_activity::{Activity, Event, Scenario};

/// The isolations of set-up and peer connections (not the client under test): far above the scheduler's keys.
pub const SETUP_ISO: u64 = 1 << 50;

/// The driver of the tests over provider `P`.
pub type TDriver<P = MemProvider> =
    Driver<Only<P>, TestDirectory, TestControl, TestHandshakes, CostedWorker, TokioClock>;

/// A current-thread runtime whose clock is paused (`tokio::time::pause`): time moves only when every task waits.
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
}

/// The relay and the provider of a test, and the set-up connections.
pub struct Setup {
    pub relay: MemRelay,
    pub provider: MemProvider,
    next_iso: u64,
}

impl Setup {
    /// Call inside the runtime.
    pub fn new() -> Self {
        let relay = MemRelay::new(HarnessConfig::default());
        let provider = MemProvider::new(relay.clone());
        Self {
            relay,
            provider,
            next_iso: 0,
        }
    }

    pub fn iso(&mut self) -> Isolation {
        self.next_iso = self.next_iso.saturating_add(1);
        Isolation(SETUP_ISO | self.next_iso)
    }

    pub fn now(&self) -> u64 {
        self.relay.clock().mono_ms()
    }

    /// A fresh set-up link (not traced as the client under test).
    pub async fn transport(
        &mut self,
        pool: &mut EntropyPool,
    ) -> AsyncRelayQueueTransport<DuplexStream> {
        let iso = self.iso();
        let stream = self
            .provider
            .connect(&self.relay.relay_ref(), iso)
            .await
            .unwrap();
        let access = self.relay.access_key();
        let unix = self.relay.clock().unix_secs();
        AsyncRelayQueueTransport::connect(
            stream,
            self.relay.relay_fp(),
            Some(&access),
            unix,
            pool.get(),
        )
        .await
        .unwrap()
    }

    /// A queue created on a set-up link with seeds from `pool`.
    pub async fn new_queue(&mut self, pool: &mut EntropyPool) -> (RecvCap, SendCap) {
        let (recv, send) = (pool.bytes(32), pool.bytes(32));
        let mut t = self.transport(pool).await;
        let access = self.relay.access_key();
        t.create_queue(
            &SecretBytes::from_slice(&recv).unwrap(),
            &SecretBytes::from_slice(&send).unwrap(),
            &access,
        )
        .await
        .unwrap()
    }
}

/// A client driven by the tokio driver.
pub struct TClient<P: StreamProvider + 'static = MemProvider> {
    pub sched: Scheduler,
    pub driver: TDriver<P>,
    pub convs: Arc<Mutex<secmp_testkit::harness::Convs>>,
    pub pool: EntropyPool,
    pub work_total: Arc<AtomicU64>,
    pub jobs: Arc<Mutex<Vec<JobRecord>>>,
}

impl TClient {
    pub fn new(
        setup: &Setup,
        mode: Mode,
        params: Params,
        seed: u64,
        costs: Costs,
        index: u32,
    ) -> Self {
        Self::with_provider(
            setup,
            setup.provider.clone(),
            mode,
            params,
            seed,
            costs,
            index,
        )
    }
}

impl<P: StreamProvider + 'static> TClient<P> {
    pub fn with_provider(
        setup: &Setup,
        provider: P,
        mode: Mode,
        params: Params,
        seed: u64,
        costs: Costs,
        index: u32,
    ) -> Self {
        let relay = &setup.relay;
        let convs = Arc::new(Mutex::new(Conversations::new()));
        let worker = CostedWorker::new(Arc::clone(&convs), costs, relay.clock());
        let (work_total, jobs) = (Arc::clone(&worker.work_total), Arc::clone(&worker.log));
        let control = TestControl::new(relay.access_key(), "m6-tokio-ctl", index);
        let driver = Driver::new(
            Arc::new(Only::new(provider, Transport::Tor)),
            Arc::new(TestDirectory::new(relay.relay_ref(), relay.access_key())),
            Arc::new(control),
            TestHandshakes::new("m6-tokio-hs", index),
            worker,
            Arc::new(relay.clock()),
        )
        .with_log();
        Self {
            sched: Scheduler::new(params, mode, TimingRng::seeded(seed)),
            driver,
            convs,
            pool: EntropyPool::new("m6-client", index),
            work_total,
            jobs,
        }
    }

    pub async fn run_until(&mut self, t: u64) {
        self.driver.run_until(&mut self.sched, t).await.unwrap();
    }

    /// The units of this client's connections as a trace: scheduled links by link id, control links at
    /// `CONTROL_SLOT_BASE + op`; sorted by time, slot, direction (concurrent connections of one instant may be read in
    /// another order).
    pub fn trace(&self, relay: &MemRelay) -> Trace {
        let log = self.driver.log().unwrap();
        let slot_of = |iso: Isolation| {
            log.connects
                .iter()
                .find(|(_, _, i)| *i == iso)
                .map(|(_, p, _)| match p {
                    Purpose::Link(l) => l.0,
                    Purpose::Control(op) => CONTROL_SLOT_BASE.saturating_add(op.0),
                })
        };
        let mut trace: Trace = relay
            .units()
            .into_iter()
            .filter(|u| u.isolation.0 < SETUP_ISO)
            .filter_map(|u| {
                slot_of(u.isolation).map(|slot| TraceEntry {
                    t_ms: u.t_ms,
                    len: u.len,
                    dir: u.dir,
                    slot,
                    at_ms: u.t_ms,
                })
            })
            .collect();
        trace.sort_by_key(|e| (e.t_ms, e.slot, e.dir, e.len));
        trace
    }
}

/// A ratchet pair for two conversations from two clients' pools (as `VirtualDriver::ratchet_states`).
pub fn ratchet_states(
    a: &mut EntropyPool,
    b: &mut EntropyPool,
) -> (secmp_proto::tr::RatchetState, secmp_proto::tr::RatchetState) {
    let sk = SecretBytes::from_slice(&a.bytes(32)).unwrap();
    let transcript: [u8; 32] = a.bytes(32).try_into().unwrap();
    let mut ea = FixedEntropy::new(&a.bytes(1 << 16));
    let mut eb = FixedEntropy::new(&b.bytes(1 << 16));
    ratchet_pair(&sk, &transcript, &mut ea, &mut eb)
}

pub fn peer_key(pool: &mut EntropyPool) -> secmp_crypto::HybridVerifyingKey {
    pool.get().hybrid_signing_key().unwrap().verifying_key()
}

type PeerConvs = Conversations<MemOutbox, MemPersist, EntropyPool>;

struct TPeer {
    convs: PeerConvs,
    pool: EntropyPool,
    drain: RecvCap,
    drained_to: u64,
    into_x: SendCap,
    x_conv: usize,
}

/// The tokio twin of `m6_activity::Rig`: the client under test (`x`) is run by the tokio driver; its contacts are
/// hand-driven peers that drain `x`'s send-queues and answer every ten minutes of virtual time.
pub struct TokioRig<P: StreamProvider + 'static = MemProvider> {
    pub setup: Setup,
    pub x: TClient<P>,
    peers: Vec<TPeer>,
}

/// The modelled costs of the AI repeats (VD-M6-A-13): a real cell 20 ms, a dummy 1 ms, a received cell 5 ms.
pub const AI_COSTS: Costs = Costs {
    prepare_real: 20,
    prepare_dummy: 1,
    receive: 5,
};

fn text(n: u64, len: usize) -> OutMessage {
    let mut id = [0_u8; 16];
    id.get_mut(..8).unwrap().copy_from_slice(&n.to_be_bytes());
    OutMessage {
        msg_id: id,
        kind: AppKind::Text,
        expire_after: 0,
        payload: Zeroizing::new(vec![0x61; len]),
    }
}

impl TokioRig {
    /// Call inside the runtime: the client under test with the AI costs.
    pub async fn new(sc: &Scenario, params: Params) -> Self {
        let setup = Setup::new();
        let x = TClient::new(&setup, sc.mode, params, sc.seed, AI_COSTS, 0);
        Self::assemble(setup, x, sc).await
    }
}

impl<P: StreamProvider + 'static> TokioRig<P> {
    /// The scenario's contacts around a client made by the caller over `setup` (call inside the runtime).
    pub async fn assemble(mut setup: Setup, mut x: TClient<P>, sc: &Scenario) -> Self {
        let now = setup.now();
        let mut peers = Vec::new();
        for (n, (ab, ba)) in sc.contacts.iter().enumerate() {
            let index = u32::try_from(n).unwrap().saturating_add(1);
            let mut pool = EntropyPool::new("m6-client", index);
            let (rc_p, sc_p) = setup.new_queue(&mut pool).await;
            let (rc_x, sc_x) = setup.new_queue(&mut x.pool).await;
            let x_send = x.sched.add_send_queue(now, RelayId(0), sc_p, *ab).unwrap();
            let x_recv = x.sched.add_recv_queue(now, RelayId(0), rc_x, *ba).unwrap();
            let (state_x, state_p) = ratchet_states(&mut x.pool, &mut pool);
            let key_x = peer_key(&mut x.pool);
            let key_p = peer_key(&mut pool);
            let tag = u32::try_from(n).unwrap();
            let mut conv_x = Conversation::new(
                state_x,
                MemOutbox::new(),
                MemPersist::new(),
                EntropyPool::new("m6-act-x", tag),
                key_p,
                START_UNIX,
            );
            conv_x.bind(x_send, x_recv);
            let mut conv_p = Conversation::new(
                state_p,
                MemOutbox::new(),
                MemPersist::new(),
                EntropyPool::new("m6-act-p", tag),
                key_x,
                START_UNIX,
            );
            conv_p.bind(QueueId(0), QueueId(1));
            let first = conv_x.prepare_direct(0).unwrap();
            let mut convs = PeerConvs::new();
            convs.add(conv_p);
            convs.deliver(QueueId(1), 0, &first.cell).unwrap();
            let x_conv = x.convs.lock().unwrap().add(conv_x);
            peers.push(TPeer {
                convs,
                pool,
                drain: rc_p,
                drained_to: 0,
                into_x: sc_x,
                x_conv,
            });
        }
        if sc.pool {
            x.sched.manage_pool(now, RelayId(0)).unwrap();
        }
        Self { setup, x, peers }
    }

    /// The peers read what `x` sent and answer with what they have, at most 20 cells each.
    async fn pump(&mut self, now: u64) {
        let Self { setup, peers, .. } = self;
        for peer in peers.iter_mut() {
            let mut t = setup.transport(&mut peer.pool).await;
            loop {
                let cells = t.fetch(&peer.drain, peer.drained_to).await.unwrap();
                if cells.is_empty() {
                    break;
                }
                for (id, cell) in cells {
                    CellSource::deliver(&mut peer.convs, QueueId(1), id, &cell).unwrap();
                    peer.drained_to = peer.drained_to.max(id);
                }
            }
            let mut sent = 0_usize;
            while sent < 20
                && peer
                    .convs
                    .get(0)
                    .is_some_and(Conversation::has_pending_real)
            {
                let cell = CellSource::prepare_cell(&mut peer.convs, QueueId(0), now)
                    .unwrap()
                    .unwrap();
                t.send(&peer.into_x, &cell.cell).await.unwrap();
                sent = sent.saturating_add(1);
            }
        }
    }

    pub fn apply(&mut self, e: Event, now: u64, n: u64) {
        match e {
            Event::UserSend { contact, len } => {
                let idx = self.peers.get(contact).unwrap().x_conv;
                self.x
                    .convs
                    .lock()
                    .unwrap()
                    .get_mut(idx)
                    .unwrap()
                    .outbox_mut()
                    .enqueue(text(n, len), now);
            }
            Event::PeerSend { contact, len } => {
                self.peers
                    .get_mut(contact)
                    .unwrap()
                    .convs
                    .get_mut(0)
                    .unwrap()
                    .outbox_mut()
                    .enqueue(text(n.saturating_add(1_000_000), len), now);
            }
            Event::Focus => {}
        }
    }

    /// Run `hours` of virtual time with `act` applied around the scheduler (as `Rig::run`).
    pub async fn run(&mut self, hours: u64, act: Option<&Activity>) -> TRun {
        self.run_ms(hours.saturating_mul(3_600_000), act).await
    }

    /// As [`TokioRig::run`], for `minutes`.
    pub async fn run_minutes(&mut self, minutes: u64, act: Option<&Activity>) -> TRun {
        self.run_ms(minutes.saturating_mul(60_000), act).await
    }

    async fn run_ms(&mut self, end: u64, act: Option<&Activity>) -> TRun {
        let mut events = act.map(|a| a.events.iter().copied().peekable());
        let mut next_pump = 600_000;
        let mut next_hour = 3_600_000;
        let mut draws = Vec::new();
        let mut n = 0_u64;
        loop {
            let next_event = events.as_mut().and_then(|it| it.peek().map(|(t, _)| *t));
            let t = [next_event, Some(next_pump), Some(next_hour), Some(end)]
                .into_iter()
                .flatten()
                .min()
                .unwrap();
            self.x.run_until(t).await;
            while let Some((_, e)) = events
                .as_mut()
                .and_then(|it| it.next_if(|(et, _)| *et <= t))
            {
                n = n.saturating_add(1);
                self.apply(e, t, n);
            }
            if t == next_pump {
                self.pump(t).await;
                next_pump = next_pump.saturating_add(600_000);
            }
            if t == next_hour {
                draws.push(self.x.sched.timing_draws());
                next_hour = next_hour.saturating_add(3_600_000);
            }
            if t == end {
                break;
            }
        }
        let relay = &self.setup.relay;
        let to_peers = self
            .peers
            .iter()
            .map(|p| p.convs.get(0).unwrap().received().len())
            .sum();
        let to_x = {
            let convs = self.x.convs.lock().unwrap();
            self.peers
                .iter()
                .map(|p| convs.get(p.x_conv).unwrap().received().len())
                .sum()
        };
        let trace = self.x.trace(relay);
        let control = {
            let mut units: Vec<(u64, usize, Dir)> = trace
                .iter()
                .filter(|e| e.slot >= CONTROL_SLOT_BASE)
                .map(|e| (e.t_ms, e.len, e.dir))
                .collect();
            units.sort();
            units
        };
        TRun {
            to_peers,
            to_x,
            work_ms: self.x.work_total.load(std::sync::atomic::Ordering::SeqCst),
            c2r: trace
                .iter()
                .filter(|e| e.slot < CONTROL_SLOT_BASE && e.dir == Dir::C2R)
                .copied()
                .collect(),
            r2c: trace
                .iter()
                .filter(|e| e.slot < CONTROL_SLOT_BASE && e.dir == Dir::R2C)
                .copied()
                .collect(),
            draws,
            control,
            overruns: self.x.sched.overruns(),
        }
    }
}

pub struct TRun {
    pub to_peers: usize,
    pub to_x: usize,
    pub work_ms: u64,
    pub c2r: Trace,
    pub r2c: Trace,
    pub draws: Vec<(u64, u64)>,
    pub control: Vec<(u64, usize, Dir)>,
    pub overruns: u64,
}

/// One scenario run under its own paused runtime.
pub fn run_scenario(sc: &Scenario, hours: u64, act: Option<&Activity>) -> TRun {
    runtime().block_on(async {
        let mut rig = TokioRig::new(sc, Params::default()).await;
        rig.run(hours, act).await
    })
}

/// Smoke: one hour of Strict with two contacts over the tokio driver — frames flow, messages arrive both ways, no
/// overrun, every unit 4352 B after the handshakes.
#[test]
fn tokio_driver_smoke_strict_one_hour() {
    let sc = Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000), (20_000, 40_000)],
        pool: true,
        seed: 5,
    };
    let act = crate::m6_activity::activity(3, 1, 2);
    let run = run_scenario(&sc, 1, Some(&act));
    assert!(run.c2r.len() > 300, "{}", run.c2r.len());
    assert!(
        run.c2r
            .iter()
            .all(|e| e.len == 4352 || e.len == 9 || e.len == 2856)
    );
    assert!(
        run.to_peers + run.to_x > 0,
        "messages moved: {} {}",
        run.to_peers,
        run.to_x
    );
    assert_eq!(run.overruns, 0);
}
