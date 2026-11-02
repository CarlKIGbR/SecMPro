// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `VirtualDriver`: the virtual-clock driver of the scheduler core (M6 Phase A; `docs/06` §4). N clients, each a
//! [`Scheduler`] with its conversations, share one in-process relay. Time moves only in [`VirtualDriver::run_until`],
//! which jumps from deadline to deadline: no thread, no timer, no wall clock. Every record or frame a client writes or
//! reads is recorded in the [`Trace`] (TEST-SPEC-M6 "Conventions").
//!
//! The driver does what the tokio driver of Phase B does for real sockets: opens the connection when the core says
//! `Connect` (the SecMP-LINK handshake, then `link_up`), writes the prepared frames the core hands out, reads the relay's
//! answers (after `latency_ms`, or never while `withhold` is set) and reports them, and runs control operations on
//! their own one-shot connections.

use std::collections::{BTreeMap, VecDeque};

use secmp_client_core::clock::ManualClock;
use secmp_client_core::hub::{Action, Hub};
use secmp_client_core::scheduler::core::{SchedError, Scheduler};
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{
    CellSource, CellToken, ControlKind, Delivered, FrameId, IsolationKey, LinkEvent, LinkId,
    LinkKind, OpId, Output, PreparedCell, QueueId, RelayId, SendFailure, SourceError,
};
use secmp_client_core::sessions::actor::{Conversation, Conversations, EntropySource, counters};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::{Aead, HybridSigningKey, Label, Nonce24, SecretBytes};
use secmp_proto::Decode;
use secmp_proto::tr::{Entropy, FixedEntropy, RatchetState};
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::Request;
use secmp_proto::wire::inv::LinkBlob;
use secmp_transport::{
    ConnectOutcome, Error as TransportError, LinkGetMode, QueueTransport, RecvCap,
    RelayQueueTransport, SendCap, Session,
};

use super::convo::ratchet_pair;
use super::entropy::EntropyPool;
use super::stream::{FRAME, HarnessStream};
use super::world::{Harness, HarnessConfig};

/// The handshake record lengths (D.1).
const HELLO: usize = 9;
const RELAYINFO: usize = 1744;
const HS1: usize = 2856;
const HS2: usize = 1156;

/// Trace slots of control connections start here, apart from the scheduler's link ids.
pub const CONTROL_SLOT_BASE: u64 = 1 << 40;

/// Direction of a traced unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dir {
    /// Client to relay.
    C2R,
    /// Relay to client.
    R2C,
}

/// One record or frame (TEST-SPEC-M6 "Trace").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TraceEntry {
    /// Virtual milliseconds: when the driver wrote the frame to the stream (client to relay), or read it (relay to
    /// client) — the driver's own time at that moment, not the time the core stamped on the frame (VD-M6-A-13).
    pub t_ms: u64,
    /// Bytes.
    pub len: usize,
    /// Direction.
    pub dir: Dir,
    /// The connection's slot (creation order, not an id).
    pub slot: u64,
    /// The time the core stamped on the frame (`Output::Write::at`, the tick); `t_ms` for everything else.
    pub at_ms: u64,
}

/// The trace of one client.
pub type Trace = Vec<TraceEntry>;

impl EntropySource for EntropyPool {
    type E = FixedEntropy;

    fn entropy(&mut self) -> &mut FixedEntropy {
        self.get()
    }
}

/// The conversations of a simulated client.
pub type Convs = Conversations<MemOutbox, MemPersist, EntropyPool>;
/// One conversation.
pub type Conv = Conversation<MemOutbox, MemPersist, EntropyPool>;

/// A stream that is closed from the start: reads end at once, writes vanish.
struct Dead;

impl std::io::Read for Dead {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl std::io::Write for Dead {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How a handshake ended.
enum Hs {
    Up(Box<Session<HarnessStream>>),
    ClosedBefore,
    Failed,
}

struct Conn {
    stream: HarnessStream,
    /// `k_c2r` and `sess_id`, to decode the requests written (feature of the tests).
    keys: ([u8; 32], [u8; 16]),
    written: u64,
    /// Frames from the relay waiting for their delivery time.
    rx: VecDeque<(u64, Vec<u8>)>,
    buf: Vec<u8>,
    ended: bool,
}

/// The key material the host holds for a queue the scheduler knows by id.
#[derive(Default)]
pub struct Material {
    /// `(recv seed, send seed)` by queue.
    pub queues: BTreeMap<u32, ([u8; 32], [u8; 32])>,
}

/// The link data the host holds for a `LinkPut` / `LinkGet` control operation.
pub struct LinkMaterial {
    /// `ld_id`.
    pub ld_id: [u8; 16],
    /// The seed of the owner key.
    pub owner_seed: [u8; 32],
    /// The 12 360-byte blob.
    pub blob: Vec<u8>,
    /// One-time entry.
    pub one_time: bool,
    /// `expires_bucket`.
    pub expires_bucket: u32,
}

/// What the driver does with a client's connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Hold every answer back (the relay "withholds responses").
    pub withhold: bool,
    /// Refuse the handshake of new connections (the relay "closes before RELAYINFO").
    pub refuse_connections: bool,
    /// What to keep of the scheduled connections.
    pub inspect: Inspect,
}

/// What the driver keeps of a scheduled connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Inspect {
    /// Nothing but the trace.
    #[default]
    Off,
    /// Also decode every request written (the tests that inspect the commands).
    Requests,
    /// Also the byte capture (memory grows with the run).
    Capture,
}

/// The modelled cost of the work the core asks of the cell source, in virtual milliseconds (VD-M6-A-13): preparing a
/// real cell, preparing a dummy, deciding one received cell. The work runs on a worker that is serial but does not
/// block the driver's loop: its end is reported with `prepared_until`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Costs {
    /// One real cell prepared.
    pub prepare_real: u64,
    /// One dummy prepared.
    pub prepare_dummy: u64,
    /// One received cell decided and committed.
    pub receive: u64,
    /// The upper bound of the random latency added to every cell prepared and every cell decided — the store's commit
    /// completing late (TEST-SPEC-M7 SE-19, Q160): `U[0, jitter]` virtual milliseconds, drawn on the worker, never on a tick.
    pub jitter: u64,
}

/// What the gate in front of the conversations records or does (S-22, S-26, S-29).
#[derive(Default)]
pub struct GateState {
    /// The modelled cost of each kind of work.
    pub costs: Costs,
    /// The modelled work since the last reset (the driver resets it before each `work`).
    pub work_ms: u64,
    /// Hold the preparation of cells back: `prepare_cell` is "not ready".
    pub block_prepare: bool,
    /// The state of the latency generator (`SplitMix64`).
    pub jitter_state: u64,
    /// Deliveries per `(queue, cell_id)`.
    pub delivered: BTreeMap<(u32, u64), u32>,
    /// The cells prepared per queue: `(real, dummy)` (SE-02: the old queue carries dummies only after a route update).
    pub prepared: BTreeMap<u32, (u64, u64)>,
    /// The order of preparations and writes with the counters at that moment.
    pub audit: Vec<Audit>,
    /// The highest `cell_id` an `OK_SEND` reported.
    pub relayed_max: u64,
    /// How many evicted ids `OK_SEND` reported.
    pub evicted_count: u64,
}

/// One audited event (feature `kat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audit {
    /// A cell was prepared: `(tr_encrypt_calls, persist_calls, seal_calls)` right after.
    Prepared([u64; 3]),
    /// Frames were written: `seal_calls` at that moment.
    Wrote(u64),
    /// A received cell was decided and its decision committed: `(queue, cell_id, seal_calls)` right after (TEST-SPEC-M7
    /// PC-04: the acknowledgements of the frames sealed later may cover it, none sealed earlier).
    Decided([u64; 3]),
}

/// A cell source the gate can sit in front of: the scheduler's [`CellSource`] and whether the conversation that sends on a
/// queue has something real waiting (for the cost models).
pub trait Source: CellSource {
    /// Whether the next cell prepared for `queue` is a real one.
    fn pending_real(&mut self, queue: QueueId) -> bool;
}

impl Source for Convs {
    fn pending_real(&mut self, queue: QueueId) -> bool {
        Conversations::pending_real(self, queue)
    }
}

/// A store-backed client (`secmp_client_core::hub::Hub`) as the driver runs it: the cell source, and what the driver does
/// for it besides — hands it the time, takes its actions for the scheduler, supplies the key material of its control
/// operations and reports their results.
pub trait StoreHub: Source {
    /// The virtual time is `now_ms`; the hub works on what the sessions delivered and retires what is due.
    fn step(&mut self, now_ms: u64);
    /// What the hub asks of the scheduler since the last call.
    fn actions(&mut self) -> Vec<Action>;
    /// The material of the `LINK_PUT` of link data `n`.
    fn link_put(&mut self, n: u32) -> Option<LinkMaterial>;
    /// The seeds `(recipient, sender)` of `queue`.
    fn queue_material(&self, queue: QueueId) -> Option<([u8; 32], [u8; 32])>;
    /// The consuming `LINK_GET` of `n` returned `blob`.
    ///
    /// # Errors
    /// The hub's refusal of the accept, as text.
    fn link_consumed(&mut self, n: u32, blob: Option<Vec<u8>>) -> Result<(), String>;
    /// The `QUEUE_DEL` of `queue` ran.
    fn queue_deleted(&mut self, queue: QueueId);
    /// The hub as `Any`, for the tests to reach its own methods.
    fn any(&mut self) -> &mut dyn std::any::Any;
}

impl<S: EntropySource> Source for Hub<ManualClock, S> {
    fn pending_real(&mut self, queue: QueueId) -> bool {
        Hub::pending_real(self, queue)
    }
}

impl<S: EntropySource + 'static> StoreHub for Hub<ManualClock, S> {
    fn step(&mut self, now_ms: u64) {
        self.core().clock().set_ms(now_ms);
        let _ = self.pump();
        self.tick(now_ms);
    }

    fn actions(&mut self) -> Vec<Action> {
        self.take_actions()
    }

    fn link_put(&mut self, n: u32) -> Option<LinkMaterial> {
        let args = self.link_put_args(n).ok()?;
        Some(LinkMaterial {
            ld_id: args.ld_id,
            owner_seed: *args.owner_seed.expose_secret(),
            blob: args.blob.to_vec(),
            one_time: true,
            expires_bucket: u32::try_from(args.expires / 3600).ok()?,
        })
    }

    fn queue_material(&self, queue: QueueId) -> Option<([u8; 32], [u8; 32])> {
        Hub::queue_material(self, queue)
    }

    fn link_consumed(&mut self, n: u32, blob: Option<Vec<u8>>) -> Result<(), String> {
        Hub::link_consumed(self, n, blob.as_deref())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn queue_deleted(&mut self, queue: QueueId) {
        let _ = Hub::queue_deleted(self, queue);
    }

    fn any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// The cell source the scheduler sees: the conversations behind a gate that can hold preparation back and audits the
/// order of the work.
pub struct Gate<'a> {
    convs: &'a mut dyn Source,
    state: &'a mut GateState,
}

impl<'a> Gate<'a> {
    fn new(convs: &'a mut dyn Source, state: &'a mut GateState) -> Self {
        Self { convs, state }
    }

    /// The latency of one commit: `U[0, jitter]` from the gate's own generator (nothing to do with the timing randomness).
    fn latency(&mut self) -> u64 {
        let max = self.state.costs.jitter;
        if max == 0 {
            return 0;
        }
        self.state.jitter_state = self.state.jitter_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state.jitter_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        z.checked_rem(max.saturating_add(1)).unwrap_or(0)
    }
}

impl CellSource for Gate<'_> {
    fn prepare_cell(
        &mut self,
        queue: QueueId,
        now: u64,
    ) -> Result<Option<PreparedCell>, SourceError> {
        if self.state.block_prepare {
            return Ok(None);
        }
        let real = self.convs.pending_real(queue);
        let out = self.convs.prepare_cell(queue, now);
        if matches!(out, Ok(Some(_))) {
            let counts = self.state.prepared.entry(queue.0).or_insert((0, 0));
            if real {
                counts.0 = counts.0.saturating_add(1);
            } else {
                counts.1 = counts.1.saturating_add(1);
            }
            let cost = if real {
                self.state.costs.prepare_real
            } else {
                self.state.costs.prepare_dummy
            };
            let late = self.latency();
            self.state.work_ms = self.state.work_ms.saturating_add(cost).saturating_add(late);
            self.state.audit.push(Audit::Prepared([
                counters::tr_encrypt_calls(),
                counters::persist_calls(),
                secmp_transport::channel::counters::seal_calls(),
            ]));
        }
        out
    }

    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        self.state.relayed_max = self.state.relayed_max.max(cell_id);
        self.convs.relayed(queue, token, cell_id);
    }

    fn evicted(&mut self, queue: QueueId, cell_id: u64) {
        self.state.evicted_count = self.state.evicted_count.saturating_add(1);
        self.convs.evicted(queue, cell_id);
    }

    fn send_failed(&mut self, queue: QueueId, token: CellToken, why: SendFailure) {
        self.convs.send_failed(queue, token, why);
    }

    fn discard(&mut self, queue: QueueId, token: CellToken) {
        self.convs.discard(queue, token);
    }

    fn queue_lost(&mut self, queue: QueueId) {
        self.convs.queue_lost(queue);
    }

    fn deliver(
        &mut self,
        queue: QueueId,
        generation: u64,
        cell_id: u64,
        cell: &Cell,
    ) -> Result<Delivered, SourceError> {
        let late = self.latency();
        self.state.work_ms = self
            .state
            .work_ms
            .saturating_add(self.state.costs.receive)
            .saturating_add(late);
        let n = self.state.delivered.entry((queue.0, cell_id)).or_insert(0);
        *n = n.saturating_add(1);
        let out = self.convs.deliver(queue, generation, cell_id, cell);
        if out.is_ok() {
            self.state.audit.push(Audit::Decided([
                u64::from(queue.0),
                cell_id,
                secmp_transport::channel::counters::seal_calls(),
            ]));
        }
        out
    }
}

/// Called right after the driver wrote `bytes` to the stream of a client, with the client's conversations: the place
/// to kill and restart the process at the boundary "after the write" (VD-M6-A-21).
pub type AfterWrite = Box<dyn FnMut(&mut Convs, &[u8])>;

/// One simulated client.
pub struct SimClient {
    /// The scheduler core.
    pub sched: Scheduler,
    /// Its conversations (the cell source).
    pub convs: Convs,
    /// A store-backed client instead of `convs` (the hub is the cell source then).
    pub hub: Option<Box<dyn StoreHub>>,
    /// What the hub refused in a control operation's result (the tests assert it is empty).
    pub hub_errors: Vec<String>,
    /// Content randomness of the handshakes and queue keys.
    pub entropy: EntropyPool,
    /// Key material by queue id.
    pub material: Material,
    /// The local events, in order.
    pub events: Vec<(u64, LinkEvent)>,
    /// The trace.
    pub trace: Trace,
    /// How long the relay's answers take.
    pub latency_ms: u64,
    /// The relay of this client.
    pub relay: RelayId,
    /// What the driver does with this client's connections.
    pub opts: Options,
    /// The gate in front of the conversations.
    pub gate: GateState,
    /// The hook called after each write to the stream (none by default).
    pub after_write: Option<AfterWrite>,
    /// The modelled work done in all (virtual milliseconds).
    pub work_total_ms: u64,
    /// When the serial worker is free again.
    worker_free: u64,
    conns: BTreeMap<LinkId, Conn>,
    /// Control operations completed, with their kind.
    pub controls_done: Vec<(u64, ControlKind)>,
    /// Control operations started, with their kind and time.
    pub controls_started: Vec<(u64, OpId, ControlKind)>,
    /// Connect attempts that were refused.
    pub refused: u64,
    /// The requests written: time, slot, request.
    pub requests: Vec<(u64, u64, Request)>,
    /// Link data by number, for the link-data control operations.
    pub links: BTreeMap<u32, LinkMaterial>,
    /// Owner-status answers: time, link data, present, consumed.
    pub link_status: Vec<(u64, u32, bool, bool)>,
    /// Consume answers: time, link data, present, consumed, blob returned.
    pub link_consumed: Vec<(u64, u32, bool, bool, bool)>,
    /// The requests of every control connection: time, operation, requests in order.
    pub control_requests: Vec<(u64, OpId, Vec<Request>)>,
    /// The isolation key of every control operation.
    pub control_keys: Vec<(OpId, IsolationKey)>,
    /// Every `Connect` the scheduler asked for: time, connection, isolation key.
    pub connects: Vec<(u64, LinkId, IsolationKey)>,
    /// What each connection is for and its tick period.
    pub link_kinds: BTreeMap<u64, (LinkKind, u64)>,
}

/// The driver (see the module documentation).
pub struct VirtualDriver {
    harness: Harness,
    clients: Vec<SimClient>,
    now: u64,
    swept_minute: u64,
    costs: Costs,
    jitter_seed: u64,
    /// Whether a completed write is reported to the scheduler (`frame_written`); `false` models a driver that never
    /// does (C2-07: the ledger bound of item 11).
    report_written: bool,
}

fn to_usize(n: u64) -> usize {
    usize::try_from(n).unwrap()
}

impl VirtualDriver {
    /// A relay and no clients.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn new(config: HarnessConfig) -> Self {
        Self {
            harness: Harness::new(config),
            clients: Vec::new(),
            now: 0,
            swept_minute: 0,
            costs: Costs::default(),
            jitter_seed: 0,
            report_written: true,
        }
    }

    /// Whether completed writes are reported to the scheduler (default `true`).
    pub const fn report_written(&mut self, on: bool) {
        self.report_written = on;
    }

    /// Model the cost of preparing a cell: `real` virtual milliseconds for a real one, `dummy` for a dummy (every
    /// client, present and future).
    pub fn prepare_cost(&mut self, real: u64, dummy: u64) {
        self.costs.prepare_real = real;
        self.costs.prepare_dummy = dummy;
        let costs = self.costs;
        for c in &mut self.clients {
            c.gate.costs = costs;
        }
    }

    /// Model a commit that completes late: every cell prepared or decided takes `U[0, max_ms]` virtual milliseconds more, from
    /// a generator seeded with `seed` (every client, present and future).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn commit_latency(&mut self, max_ms: u64, seed: u64) {
        self.costs.jitter = max_ms;
        let costs = self.costs;
        for (n, c) in self.clients.iter_mut().enumerate() {
            c.gate.costs = costs;
            c.gate.jitter_state = seed.wrapping_add(u64::try_from(n).unwrap());
        }
        self.jitter_seed = seed;
    }

    /// Model the cost of deciding (decrypting and committing) one received cell: `per_cell` virtual milliseconds.
    pub fn receive_cost(&mut self, per_cell: u64) {
        self.costs.receive = per_cell;
        let costs = self.costs;
        for c in &mut self.clients {
            c.gate.costs = costs;
        }
    }

    /// The harness (relay, virtual clock).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub const fn harness(&self) -> &Harness {
        &self.harness
    }

    /// The harness, mutable.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub const fn harness_mut(&mut self) -> &mut Harness {
        &mut self.harness
    }

    /// Virtual milliseconds now.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }

    /// Add a client with the scheduler `mode`, `params`, and timing seed `seed` (the content entropy has its own
    /// stream by client index).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn add_client(&mut self, mode: Mode, params: Params, seed: u64) -> usize {
        let index = u32::try_from(self.clients.len()).unwrap();
        self.clients.push(SimClient {
            sched: Scheduler::new(params, mode, TimingRng::seeded(seed)),
            convs: Conversations::new(),
            hub: None,
            hub_errors: Vec::new(),
            entropy: EntropyPool::new("m6-client", index),
            material: Material::default(),
            events: Vec::new(),
            trace: Vec::new(),
            latency_ms: 0,
            relay: RelayId(0),
            opts: Options::default(),
            gate: GateState {
                costs: self.costs,
                jitter_state: self.jitter_seed.wrapping_add(u64::from(index)),
                ..GateState::default()
            },
            after_write: None,
            work_total_ms: 0,
            worker_free: 0,
            conns: BTreeMap::new(),
            controls_done: Vec::new(),
            controls_started: Vec::new(),
            refused: 0,
            connects: Vec::new(),
            link_kinds: BTreeMap::new(),
            links: BTreeMap::new(),
            link_status: Vec::new(),
            link_consumed: Vec::new(),
            control_requests: Vec::new(),
            control_keys: Vec::new(),
            requests: Vec::new(),
        });
        to_usize(u64::from(index))
    }

    /// The client.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn client(&mut self, i: usize) -> &mut SimClient {
        self.clients.get_mut(i).unwrap()
    }

    /// The client, read-only.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn client_ref(&self, i: usize) -> &SimClient {
        self.clients.get(i).unwrap()
    }

    /// Create a queue on the relay for client `i` (set-up traffic: not part of any trace, not scheduled): fresh keys
    /// from its stream, `QUEUE_NEW`.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn new_queue(&mut self, i: usize) -> (RecvCap, SendCap, [u8; 32], [u8; 32]) {
        let access = self.harness.access_key();
        let fp = self.harness.relay_fp();
        let stream = self.harness.open_stream().unwrap();
        let unix = self.harness.clock().unix();
        let c = self.clients.get_mut(i).unwrap();
        let (recv, send) = (c.entropy.bytes(32), c.entropy.bytes(32));
        let mut t =
            RelayQueueTransport::connect(stream, fp, Some(&access), unix, c.entropy.get()).unwrap();
        let (rc, sc) = t
            .create_queue(
                &SecretBytes::from_slice(&recv).unwrap(),
                &SecretBytes::from_slice(&send).unwrap(),
                &access,
            )
            .unwrap();
        (rc, sc, recv.try_into().unwrap(), send.try_into().unwrap())
    }

    /// A ratchet pair for two clients' conversation: `(state of a, state of b)`, `a` sends first.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn ratchet_states(&mut self, a: usize, b: usize) -> (RatchetState, RatchetState) {
        let sk =
            SecretBytes::from_slice(&self.clients.get_mut(a).unwrap().entropy.bytes(32)).unwrap();
        let transcript: [u8; 32] = self
            .clients
            .get_mut(a)
            .unwrap()
            .entropy
            .bytes(32)
            .try_into()
            .unwrap();
        let mut ea = FixedEntropy::new(&self.clients.get_mut(a).unwrap().entropy.bytes(1 << 16));
        let mut eb = FixedEntropy::new(&self.clients.get_mut(b).unwrap().entropy.bytes(1 << 16));
        ratchet_pair(&sk, &transcript, &mut ea, &mut eb)
    }

    /// A signing key's public half for a conversation's peer.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn peer_key(&mut self, i: usize) -> secmp_crypto::HybridVerifyingKey {
        let key: HybridSigningKey = self
            .clients
            .get_mut(i)
            .unwrap()
            .entropy
            .get()
            .hybrid_signing_key()
            .unwrap();
        key.verifying_key()
    }

    // ---- time -----------------------------------------------------------------------------------------------------

    fn advance_clock(&mut self, t: u64) {
        let delta = t.saturating_sub(self.now);
        if delta > 0 {
            self.harness.clock().advance_ms(delta);
            self.now = t;
            let minute = t / 60_000;
            if minute > self.swept_minute {
                self.swept_minute = minute;
                self.harness.relay().tick(self.harness.clock().now());
            }
        }
    }

    fn next_event(&self) -> Option<u64> {
        let mut best: Option<u64> = None;
        for c in &self.clients {
            // answers held back are not an event until they are let go
            let waiting = c
                .conns
                .values()
                .filter(|_| !c.opts.withhold)
                .filter_map(|k| k.rx.front().map(|(t, _)| *t));
            for t in c.sched.next_deadline().into_iter().chain(waiting) {
                best = Some(best.map_or(t, |b| b.min(t)));
            }
        }
        best
    }

    /// Run to virtual time `t_end` (inclusive): every deadline up to it is processed in order.
    ///
    /// # Panics
    /// If the scheduler fails (no randomness: never in a virtual run) or the loop does not make progress.
    pub fn run_until(&mut self, t_end: u64) {
        // what a hub asked for since the last run (an invitation issued, a request answered) is registered first
        for i in 0..self.clients.len() {
            let now = self.now;
            self.hub_step(i, now);
        }
        let mut guard = 0_u64;
        loop {
            guard = guard.saturating_add(1);
            assert!(guard < 50_000_000, "the virtual run does not make progress");
            match self.next_event() {
                Some(t) if t <= t_end => {
                    let t = t.max(self.now);
                    self.advance_clock(t);
                    self.process(t);
                }
                _ => {
                    self.advance_clock(t_end);
                    self.process(t_end);
                    break;
                }
            }
        }
    }

    /// One client at virtual time `t`, in the order of a real driver (reviewer VD-M6-A-12): the frames that arrived are
    /// taken in (cheap), what is due is decided and its writes are flushed *first*, then the activity-dependent work
    /// runs (cells decided, next frames prepared, control operations started).
    fn process(&mut self, t: u64) {
        for i in 0..self.clients.len() {
            self.hub_step(i, t);
            self.deliver_due(i, t);
            let outs = self.clients.get_mut(i).unwrap().sched.poll_due(t).unwrap();
            // the frames due now leave at `t`: nothing the work costs comes before them
            self.apply(i, t, outs);
            self.deliver_due(i, t);
            let outs = {
                let c = self.clients.get_mut(i).unwrap();
                // the work starts when the worker is free and ends after its modelled cost; the core is told
                let start = t.max(c.worker_free);
                c.gate.work_ms = 0;
                let source: &mut dyn Source = match c.hub.as_mut() {
                    Some(hub) => &mut **hub,
                    None => &mut c.convs,
                };
                let outs = c
                    .sched
                    .work(start, &mut Gate::new(source, &mut c.gate))
                    .unwrap();
                let end = start.saturating_add(c.gate.work_ms);
                c.sched.prepared_until(end);
                c.work_total_ms = c.work_total_ms.saturating_add(c.gate.work_ms);
                c.worker_free = end;
                outs
            };
            self.apply(i, t, outs);
            self.hub_step(i, t);
        }
    }

    /// A store-backed client at virtual time `t`: the hub works on what its sessions delivered, and what it asks of the
    /// scheduler is done (a queue to fetch or send to, a queue to drop, a control operation). Nothing here adds a slot: the
    /// scheduler decides when a new queue's link starts.
    fn hub_step(&mut self, i: usize, t: u64) {
        for _ in 0..8 {
            let actions = {
                let c = self.clients.get_mut(i).unwrap();
                let Some(hub) = c.hub.as_mut() else { return };
                hub.step(t);
                hub.actions()
            };
            if actions.is_empty() {
                return;
            }
            for action in actions {
                self.apply_action(i, t, action);
            }
        }
    }

    fn apply_action(&mut self, i: usize, t: u64, action: Action) {
        let c = self.clients.get_mut(i).unwrap();
        let result = match action {
            Action::AddRecv {
                queue,
                relay,
                seed,
                period_ms,
            } => c
                .sched
                .add_recv_queue_seed(t, queue, relay, &seed, period_ms),
            Action::AddSend {
                queue,
                relay,
                sid,
                seed,
                period_ms,
            } => c
                .sched
                .add_send_queue_route(t, queue, relay, (sid, &seed), period_ms),
            Action::Control(spec) => c
                .sched
                .schedule_control(t, spec.kind, spec.relay, spec.related, spec.when)
                .map(|_| ()),
            Action::Remove { queue } => {
                let source: &mut dyn Source = match c.hub.as_mut() {
                    Some(hub) => &mut **hub,
                    None => &mut c.convs,
                };
                let outs = c
                    .sched
                    .remove_queue(t, queue, &mut Gate::new(source, &mut c.gate));
                match outs {
                    Ok(outs) => {
                        self.apply(i, t, outs);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        };
        if let Err(e) = result {
            // a queue that is known already (a restart registers what the hub registered before) is no error
            if e != SchedError::DuplicateQueue {
                self.clients
                    .get_mut(i)
                    .unwrap()
                    .hub_errors
                    .push(e.to_string());
            }
        }
    }

    /// Give client `i` a store-backed hub as its cell source.
    ///
    /// # Panics
    /// If there is no client `i`: a test failure, never a production path.
    pub fn attach_hub(&mut self, i: usize, hub: Box<dyn StoreHub>) {
        self.clients.get_mut(i).unwrap().hub = Some(hub);
    }

    /// Client `i`'s process dies and starts again from its store (SE-14): every connection is cut, the scheduler is new
    /// (`mode`, `params`, timing seed `seed`) and so is the hub, which registers what the store holds.
    ///
    /// # Panics
    /// If there is no client `i`: a test failure, never a production path.
    pub fn restart_client(
        &mut self,
        i: usize,
        hub: Box<dyn StoreHub>,
        (mode, params, seed): (Mode, Params, u64),
    ) {
        let c = self.clients.get_mut(i).unwrap();
        for conn in c.conns.values() {
            conn.stream.cut();
        }
        c.conns.clear();
        c.sched = Scheduler::new(params, mode, TimingRng::seeded(seed));
        c.hub = Some(hub);
        c.worker_free = 0;
    }

    /// Create a queue on the relay for client `i` with the given seeds (set-up traffic like [`VirtualDriver::new_queue`]:
    /// a pool queue the client made earlier).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn new_queue_with(&mut self, i: usize, recv: &[u8; 32], send: &[u8; 32]) {
        let access = self.harness.access_key();
        let fp = self.harness.relay_fp();
        let stream = self.harness.open_stream().unwrap();
        let unix = self.harness.clock().unix();
        let c = self.clients.get_mut(i).unwrap();
        let mut t =
            RelayQueueTransport::connect(stream, fp, Some(&access), unix, c.entropy.get()).unwrap();
        t.create_queue(
            &SecretBytes::from_slice(recv).unwrap(),
            &SecretBytes::from_slice(send).unwrap(),
            &access,
        )
        .unwrap();
    }

    // ---- connections ----------------------------------------------------------------------------------------------

    fn deliver_due(&mut self, i: usize, t: u64) {
        loop {
            let next = {
                let c = self.clients.get_mut(i).unwrap();
                let hold = c.opts.withhold;
                let mut found = None;
                if !hold {
                    for (id, conn) in &mut c.conns {
                        if let Some((at, _)) = conn.rx.front()
                            && *at <= t
                        {
                            let (_, frame) = conn.rx.pop_front().unwrap();
                            found = Some((*id, frame));
                            break;
                        }
                    }
                }
                found
            };
            let Some((id, frame)) = next else { break };
            let outs = {
                let c = self.clients.get_mut(i).unwrap();
                c.trace.push(TraceEntry {
                    t_ms: t,
                    len: frame.len(),
                    dir: Dir::R2C,
                    slot: id.0,
                    at_ms: t,
                });
                c.sched.on_frame(id, t, &frame).unwrap()
            };
            self.apply(i, t, outs);
        }
    }

    /// Read what the relay answered on `id` into the delivery queue.
    fn collect(&mut self, i: usize, id: LinkId, t: u64) {
        let c = self.clients.get_mut(i).unwrap();
        let latency = c.latency_ms;
        let Some(conn) = c.conns.get_mut(&id) else {
            return;
        };
        let mut chunk = [0_u8; FRAME];
        loop {
            let n = std::io::Read::read(&mut conn.stream, &mut chunk).unwrap();
            if n == 0 {
                break;
            }
            conn.buf.extend_from_slice(chunk.get(..n).unwrap());
        }
        while conn.buf.len() >= FRAME {
            let frame: Vec<u8> = conn.buf.drain(..FRAME).collect();
            conn.rx.push_back((t.saturating_add(latency), frame));
        }
        if conn.stream.is_closed() {
            conn.ended = true;
        }
    }

    fn apply(&mut self, i: usize, t: u64, outs: Vec<Output>) {
        let mut queue: VecDeque<Output> = outs.into();
        while let Some(out) = queue.pop_front() {
            match out {
                Output::Event(e) => {
                    let client = self.clients.get_mut(i).unwrap();
                    // the retirement of a queue the relay no longer has is complete (Q201)
                    if let (LinkEvent::QueueGone(q), Some(hub)) = (&e, client.hub.as_mut()) {
                        hub.queue_deleted(*q);
                    }
                    client.events.push((t, e));
                }
                Output::Connect {
                    link,
                    key,
                    kind,
                    period_ms,
                    ..
                } => {
                    let c = self.clients.get_mut(i).unwrap();
                    c.connects.push((t, link, key));
                    c.link_kinds.insert(link.0, (kind, period_ms));
                    let more = self.connect(i, t, link);
                    queue.extend(more);
                }
                Output::Write {
                    link,
                    bytes,
                    at,
                    frame,
                } => {
                    let more = self.write(i, t, at, (link, frame), &bytes);
                    queue.extend(more);
                }
                Output::Close { link } => {
                    if let Some(conn) = self.clients.get_mut(i).unwrap().conns.remove(&link) {
                        conn.stream.cut();
                    }
                }
                Output::Control { op, kind, key, .. } => {
                    self.clients
                        .get_mut(i)
                        .unwrap()
                        .control_keys
                        .push((op, key));
                    let more = self.control(i, t, op, kind);
                    queue.extend(more);
                }
            }
        }
    }

    fn trace(&mut self, i: usize, t: u64, len: usize, dir: Dir, slot: u64) {
        self.trace_at(i, t, t, len, dir, slot);
    }

    /// A trace entry written at `t` for a frame the core stamped `at`.
    fn trace_at(&mut self, i: usize, t: u64, at: u64, len: usize, dir: Dir, slot: u64) {
        self.clients.get_mut(i).unwrap().trace.push(TraceEntry {
            t_ms: t,
            len,
            dir,
            slot,
            at_ms: at,
        });
    }

    fn trace_handshake(&mut self, i: usize, t: u64, slot: u64) {
        self.trace(i, t, HELLO, Dir::C2R, slot);
        self.trace(i, t, RELAYINFO, Dir::R2C, slot);
        self.trace(i, t, HS1, Dir::C2R, slot);
        self.trace(i, t, HS2, Dir::R2C, slot);
    }

    fn handshake(&mut self, i: usize) -> (HarnessStream, Hs) {
        let access = self.harness.access_key();
        let fp = self.harness.relay_fp();
        let unix = self.harness.clock().unix();
        let refuse = self.clients.get(i).unwrap().opts.refuse_connections;
        let stream = self.harness.open_stream().unwrap();
        let keep = stream.clone();
        let c = self.clients.get_mut(i).unwrap();
        if refuse {
            // the relay closes right after HELLO: nothing but the 9 bytes crossed
            c.refused = c.refused.saturating_add(1);
            keep.cut();
            let outcome = Session::connect_outcome(Dead, fp, Some(&access), unix, c.entropy.get());
            let hs = match outcome {
                ConnectOutcome::ClosedBeforeRelayInfo => Hs::ClosedBefore,
                _ => Hs::Failed,
            };
            return (keep, hs);
        }
        let hs = match Session::connect_outcome(stream, fp, Some(&access), unix, c.entropy.get()) {
            ConnectOutcome::Up(session) => Hs::Up(session),
            ConnectOutcome::ClosedBeforeRelayInfo => Hs::ClosedBefore,
            ConnectOutcome::Failed(_) => Hs::Failed,
        };
        (keep, hs)
    }

    fn connect(&mut self, i: usize, t: u64, link: LinkId) -> Vec<Output> {
        let (keep, outcome) = self.handshake(i);
        match outcome {
            Hs::Up(session) => {
                self.trace_handshake(i, t, link.0);
                let (_stream, chan) = session.into_parts();
                let c = self.clients.get_mut(i).unwrap();
                keep.set_capture(c.opts.inspect == Inspect::Capture);
                let (k_c2r, _) = chan.link_kat().keys_kat();
                let keys = (*k_c2r, *chan.sess_id());
                c.conns.insert(
                    link,
                    Conn {
                        stream: keep,
                        keys,
                        written: 0,
                        rx: VecDeque::new(),
                        buf: Vec::new(),
                        ended: false,
                    },
                );
                c.sched.link_up(link, t, chan).unwrap()
            }
            Hs::ClosedBefore => {
                self.trace(i, t, HELLO, Dir::C2R, link.0);
                let c = self.clients.get_mut(i).unwrap();
                c.sched.connect_failed(link, t, true).unwrap()
            }
            Hs::Failed => {
                let c = self.clients.get_mut(i).unwrap();
                c.sched.connect_failed(link, t, false).unwrap()
            }
        }
    }

    fn write(
        &mut self,
        i: usize,
        t: u64,
        at: u64,
        (link, frame): (LinkId, FrameId),
        bytes: &[u8],
    ) -> Vec<Output> {
        // the entry carries the driver's own time of the write; the tick the core stamped is kept apart
        for _ in 0..bytes.len() / FRAME {
            self.trace_at(i, t, at, FRAME, Dir::C2R, link.0);
        }
        self.record(i, t, link, bytes);
        self.clients
            .get_mut(i)
            .unwrap()
            .gate
            .audit
            .push(Audit::Wrote(
                secmp_transport::channel::counters::seal_calls(),
            ));
        let ok = {
            let c = self.clients.get_mut(i).unwrap();
            c.conns.get_mut(&link).is_some_and(|conn| {
                std::io::Write::write_all(&mut conn.stream, bytes).is_ok() && !conn.ended
            })
        };
        if ok {
            // the whole frame is on the stream: the core commits what the frame stood for (FIN-2)
            if self.report_written {
                // reported once, in order, by its id (FINAL3 (e)): a trusted caller is never refused
                let reported = self
                    .clients
                    .get_mut(i)
                    .unwrap()
                    .sched
                    .frame_written(link, frame);
                debug_assert_eq!(reported, Ok(()));
            }
            // the write is on the wire: the hook may kill the process here
            let c = self.clients.get_mut(i).unwrap();
            if let Some(mut hook) = c.after_write.take() {
                hook(&mut c.convs, bytes);
                c.after_write = Some(hook);
            }
            self.collect(i, link, t);
        }
        let ended = self
            .clients
            .get(i)
            .unwrap()
            .conns
            .get(&link)
            .is_none_or(|c| c.ended || !ok);
        if ended {
            // the relay closed the connection (or it is gone): report once the answers it gave are delivered
            let c = self.clients.get_mut(i).unwrap();
            if let Some(conn) = c.conns.get_mut(&link) {
                conn.ended = true;
            }
            if c.conns.get(&link).is_some_and(|k| k.rx.is_empty()) {
                c.conns.remove(&link);
                return c.sched.on_closed(link, t).unwrap();
            }
        }
        Vec::new()
    }

    /// Decode the requests of `bytes` (frames of `link`) when the client records them.
    fn record(&mut self, i: usize, t: u64, link: LinkId, bytes: &[u8]) {
        let c = self.clients.get_mut(i).unwrap();
        if c.opts.inspect == Inspect::Off {
            return;
        }
        let Some(conn) = c.conns.get_mut(&link) else {
            return;
        };
        let (key, sess) = conn.keys;
        let key = SecretBytes::<32>::from_slice(&key).unwrap();
        let ad = [Label::LinkFrame.as_bytes(), sess.as_slice()].concat();
        for unit in bytes.as_chunks::<FRAME>().0 {
            let nonce = *Nonce24::from_link_counter(conn.written).as_bytes();
            conn.written = conn.written.saturating_add(1);
            let plain = Aead::open(&key, &nonce, &ad, unit).unwrap();
            let request = Request::decode(&plain).unwrap();
            c.requests.push((t, link.0, request));
        }
    }

    // ---- control operations ---------------------------------------------------------------------------------------

    fn control(&mut self, i: usize, t: u64, op: OpId, kind: ControlKind) -> Vec<Output> {
        self.clients
            .get_mut(i)
            .unwrap()
            .controls_started
            .push((t, op, kind));
        let slot = CONTROL_SLOT_BASE.saturating_add(op.0);
        let (keep, outcome) = self.handshake(i);
        let Hs::Up(session) = outcome else {
            let closed_before = matches!(outcome, Hs::ClosedBefore);
            let c = self.clients.get_mut(i).unwrap();
            c.sched.control_failed(t, op, closed_before).unwrap();
            return Vec::new();
        };
        self.trace_handshake(i, t, slot);
        let mut transport = RelayQueueTransport::new(*session);
        let access = self.harness.access_key();
        let result = self.run_control(i, &mut transport, kind, &access, t);
        let capture = keep.capture();
        keep.cut();
        {
            let (k_send, _) = transport.session().link_kat().keys_kat();
            let sess = *transport.session().link_kat().sess_id();
            let key = SecretBytes::<32>::from_slice(k_send).unwrap();
            let ad = [Label::LinkFrame.as_bytes(), sess.as_slice()].concat();
            let mut requests = Vec::new();
            for (n, unit) in capture
                .frames_to_relay()
                .as_chunks::<FRAME>()
                .0
                .iter()
                .enumerate()
            {
                let nonce = *Nonce24::from_link_counter(u64::try_from(n).unwrap()).as_bytes();
                let plain = Aead::open(&key, &nonce, &ad, unit).unwrap();
                requests.push(Request::decode(&plain).unwrap());
            }
            self.clients
                .get_mut(i)
                .unwrap()
                .control_requests
                .push((t, op, requests));
        }
        for _ in 0..capture.frames_to_relay().len() / FRAME {
            self.trace(i, t, FRAME, Dir::C2R, slot);
        }
        for _ in 0..capture.frames_to_client().len() / FRAME {
            self.trace(i, t, FRAME, Dir::R2C, slot);
        }
        let c = self.clients.get_mut(i).unwrap();
        match result {
            Ok(()) => {
                c.sched.control_done(op);
                c.controls_done.push((t, kind));
            }
            Err(_) => c.sched.control_failed(t, op, false).unwrap(),
        }
        Vec::new()
    }

    fn run_control(
        &mut self,
        idx: usize,
        transport: &mut RelayQueueTransport<HarnessStream>,
        kind: ControlKind,
        access: &secmp_proto::link::ids::AccessKey,
        now: u64,
    ) -> Result<(), TransportError> {
        self.hub_material(idx, kind);
        match kind {
            ControlKind::QueueNew(queue) => {
                let client = self.clients.get_mut(idx).unwrap();
                let known = client.material.queues.get(&queue.0).copied();
                let (recv, send) = if let Some(m) = known {
                    m
                } else {
                    let m: ([u8; 32], [u8; 32]) = (
                        client.entropy.bytes(32).try_into().unwrap(),
                        client.entropy.bytes(32).try_into().unwrap(),
                    );
                    client.material.queues.insert(queue.0, m);
                    m
                };
                let (rc, _sc) = transport.create_queue(
                    &SecretBytes::from_slice(&recv).unwrap(),
                    &SecretBytes::from_slice(&send).unwrap(),
                    access,
                )?;
                // a pool creation registers the new spare; a re-creation after ERR_NOQUEUE finds its queue already known
                let _ = client.sched.pool_queue_ready(now, queue, rc);
                Ok(())
            }
            ControlKind::QueueDel(queue) => {
                let client = self.clients.get_mut(idx).unwrap();
                let (recv, _) = *client
                    .material
                    .queues
                    .get(&queue.0)
                    .ok_or(TransportError::Invalid)?;
                let cap = RecvCap::from_seed(&SecretBytes::from_slice(&recv).unwrap())?;
                // a queue the relay does not have (the `QUEUE_DEL` ran, the host did not record it) is deleted all the same
                match transport.delete_queue(&cap) {
                    Ok(()) | Err(TransportError::NoQueue) => {}
                    Err(e) => return Err(e),
                }
                if let Some(hub) = client.hub.as_mut() {
                    hub.queue_deleted(queue);
                }
                Ok(())
            }
            ControlKind::LinkPut(n) => {
                let client = self.clients.get_mut(idx).unwrap();
                let m = client.links.get(&n).ok_or(TransportError::Invalid)?;
                let blob = LinkBlob::decode(&m.blob).map_err(|_| TransportError::Invalid)?;
                transport.put_link_data(
                    m.ld_id,
                    &SecretBytes::from_slice(&m.owner_seed).unwrap(),
                    &blob,
                    m.one_time,
                    m.expires_bucket,
                    access,
                )
            }
            ControlKind::LinkGetOwner(n) => {
                let client = self.clients.get_mut(idx).unwrap();
                let m = client.links.get(&n).ok_or(TransportError::Invalid)?;
                let owner = SecretBytes::from_slice(&m.owner_seed).unwrap();
                let ld = m.ld_id;
                let got = transport.get_link_data(ld, LinkGetMode::OwnerStatus(&owner))?;
                client.link_status.push((now, n, got.present, got.consumed));
                let relay = client.relay;
                let expired = false;
                let _ =
                    client
                        .sched
                        .owner_status(now, relay, n, got.present, got.consumed, expired);
                Ok(())
            }
            ControlKind::LinkGetConsume(n) => {
                let client = self.clients.get_mut(idx).unwrap();
                let m = client.links.get(&n).ok_or(TransportError::Invalid)?;
                let ld = m.ld_id;
                let got = transport.get_link_data(ld, LinkGetMode::Consume)?;
                client
                    .link_consumed
                    .push((now, n, got.present, got.consumed, got.blob.is_some()));
                if let Some(hub) = client.hub.as_mut() {
                    let blob = got
                        .blob
                        .as_ref()
                        .map(|b| secmp_proto::Encode::encode(b).unwrap().to_vec());
                    if let Err(e) = hub.link_consumed(n, blob) {
                        client.hub_errors.push(e);
                    }
                }
                Ok(())
            }
        }
    }

    /// A store-backed client keeps the material of its control operations in the store: the queues' seeds, the link data.
    fn hub_material(&mut self, idx: usize, kind: ControlKind) {
        let client = self.clients.get_mut(idx).unwrap();
        let Some(hub) = client.hub.as_mut() else {
            return;
        };
        match kind {
            ControlKind::QueueNew(queue) | ControlKind::QueueDel(queue) => {
                if let Some(m) = hub.queue_material(queue) {
                    client.material.queues.entry(queue.0).or_insert(m);
                }
            }
            ControlKind::LinkPut(n) => {
                if let Some(m) = hub.link_put(n) {
                    client.links.entry(n).or_insert(m);
                }
            }
            _ => {}
        }
    }

    /// Set the send counter of connection `link` of client `i` (the rotation tests).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn set_send_counter(&mut self, i: usize, link: LinkId, value: u64) {
        let now = self.now;
        let outs = {
            let c = self.clients.get_mut(i).unwrap();
            let source: &mut dyn Source = match c.hub.as_mut() {
                Some(hub) => &mut **hub,
                None => &mut c.convs,
            };
            c.sched
                .set_send_counter_kat(link, value, now, &mut Gate::new(source, &mut c.gate))
                .unwrap()
        };
        self.apply(i, now, outs);
    }

    /// Restart the relay (spec §9.7 item 1): same keys, no state, every connection of every client cut.
    pub fn restart_relay(&mut self) {
        for c in &mut self.clients {
            for conn in c.conns.values() {
                conn.stream.cut();
            }
        }
        self.harness.restart_relay();
    }

    // ---- scenario helpers -----------------------------------------------------------------------------------------

    /// The trace of client `i` restricted to scheduled links (control connections excluded) and one direction.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn scheduled(&self, i: usize, dir: Dir) -> Trace {
        self.client_ref(i)
            .trace
            .iter()
            .filter(|e| e.slot < CONTROL_SLOT_BASE && e.dir == dir)
            .copied()
            .collect()
    }

    /// Map a scheduler error for the tests.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn describe(e: SchedError) -> String {
        e.to_string()
    }

    /// Add queue `q`'s queue id helper.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub const fn queue_id(n: u32) -> QueueId {
        QueueId(n)
    }
}
