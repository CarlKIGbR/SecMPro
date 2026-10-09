// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (g) activity independence on the virtual clock (AI-01…AI-06, AI-08, AI-09; spec §10.1, CLAUDE.md §1.4).
//!
//! The client under test (`x`) has its contacts as hand-driven peers: a peer is a conversation whose cells the test
//! injects into `x`'s recv-queue and which drains `x`'s send-queue every ten minutes of virtual time. The activity of a
//! trace — the user's messages, the peers' messages, receipts, focus changes — is applied around the scheduler, never to
//! it; the idle run is the same scenario with the same timing seed and no activity.

use secmp_client_core::scheduler::control::When;
use secmp_client_core::scheduler::conversation::{Conversation, Conversations};
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{CellSource, ControlKind, QueueId, RelayId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::cell::AppKind;
use secmp_testkit::harness::{
    CONTROL_SLOT_BASE, Dir, EntropyPool, START_UNIX, Trace, VirtualDriver,
};
use secmp_transport::{QueueTransport, RecvCap, RelayQueueTransport, SendCap};

use crate::m6_common::{client_with, driver, evidence, max_dt};
use crate::m6_rand::Mix;

type PeerConvs = Conversations<MemOutbox, MemPersist, EntropyPool>;

/// One contact of the client under test.
struct Peer {
    convs: PeerConvs,
    /// The queue `x` sends on (owned by the peer): drained by the peer.
    drain: RecvCap,
    drained_to: u64,
    /// The queue `x` receives on (the peer holds its sender capability).
    into_x: SendCap,
    /// `x`'s conversation with this peer.
    x_conv: usize,
}

pub struct Rig {
    pub sim: VirtualDriver,
    pub x: usize,
    peers: Vec<Peer>,
}

pub struct Scenario {
    pub mode: Mode,
    /// `(period x→peer, period peer→x)` per contact.
    pub contacts: Vec<(u64, u64)>,
    pub pool: bool,
    pub seed: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum Event {
    UserSend { contact: usize, len: usize },
    PeerSend { contact: usize, len: usize },
    Focus,
}

/// The activity of one trace.
pub struct Activity {
    pub events: Vec<(u64, Event)>,
}

/// A trace of `hours` of user activity: per second the user sends with probability `rate`/1000 (bursts of 100 now and
/// then), the peers send at a fifth of that, focus toggles at random.
pub fn activity(trace: u64, hours: u64, contacts: usize) -> Activity {
    let mut mix = Mix::new(0xac71_0000 ^ trace.wrapping_mul(0x9e37_79b9));
    let user_milli = mix.below(1001);
    let peer_milli = user_milli.checked_div(5).unwrap();
    let mut events = Vec::new();
    let contacts_u64 = u64::try_from(contacts).unwrap();
    for sec in 1..hours.saturating_mul(3600) {
        let t = sec.saturating_mul(1000).saturating_add(mix.below(1000));
        if mix.below(1000) < user_milli {
            let contact = usize::try_from(mix.below(contacts_u64)).unwrap();
            let burst = if mix.below(500) == 0 { 100 } else { 1 };
            for _ in 0..burst {
                events.push((
                    t,
                    Event::UserSend {
                        contact,
                        len: mix.len(),
                    },
                ));
            }
        }
        if mix.below(1000) < peer_milli {
            let contact = usize::try_from(mix.below(contacts_u64)).unwrap();
            events.push((
                t,
                Event::PeerSend {
                    contact,
                    len: mix.len(),
                },
            ));
        }
        if mix.below(900) == 0 {
            events.push((t, Event::Focus));
        }
    }
    events.sort_by_key(|(t, _)| *t);
    Activity { events }
}

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

impl Rig {
    pub fn new(sc: &Scenario, params: Params) -> Self {
        let mut sim = driver();
        let x = client_with(&mut sim, sc.mode, params, sc.seed);
        let now = sim.now();
        let mut peers = Vec::new();
        for (n, (ab, ba)) in sc.contacts.iter().enumerate() {
            let y = client_with(
                &mut sim,
                Mode::Strict,
                Params::default(),
                sc.seed
                    .wrapping_add(1000)
                    .wrapping_add(u64::try_from(n).unwrap()),
            );
            let (rc_p, sc_p, _, _) = sim.new_queue(y);
            let (rc_x, sc_x, _, _) = sim.new_queue(x);
            let x_send = sim
                .client(x)
                .sched
                .add_send_queue(now, RelayId(0), sc_p, *ab)
                .unwrap();
            let x_recv = sim
                .client(x)
                .sched
                .add_recv_queue(now, RelayId(0), rc_x, *ba)
                .unwrap();
            let (state_x, state_p) = sim.ratchet_states(x, y);
            let key_x = sim.peer_key(x);
            let key_p = sim.peer_key(y);
            let tag = u32::try_from(n).unwrap();
            let mut conv_x: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
                state_x,
                MemOutbox::new(),
                MemPersist::new(),
                EntropyPool::new("m6-act-x", tag),
                key_p,
                START_UNIX,
            );
            conv_x.bind(x_send, x_recv);
            let mut conv_p: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
                state_p,
                MemOutbox::new(),
                MemPersist::new(),
                EntropyPool::new("m6-act-p", tag),
                key_x,
                START_UNIX,
            );
            conv_p.bind(QueueId(0), QueueId(1));
            // the first cell goes to the peer by hand: from then on it can answer
            let first = conv_x.prepare_direct(0).unwrap();
            let mut convs = PeerConvs::new();
            convs.add(conv_p);
            convs.deliver(QueueId(1), 0, &first.cell).unwrap();
            let x_conv = sim.client(x).convs.add(conv_x);
            peers.push(Peer {
                convs,
                drain: rc_p,
                drained_to: 0,
                into_x: sc_x,
                x_conv,
            });
        }
        if sc.pool {
            sim.client(x).sched.manage_pool(now, RelayId(0)).unwrap();
        }
        Self { sim, x, peers }
    }

    fn transport(&mut self) -> RelayQueueTransport<secmp_testkit::harness::HarnessStream> {
        let access = self.sim.harness().access_key();
        let fp = self.sim.harness().relay_fp();
        let unix = self.sim.harness().clock().unix();
        let stream = self.sim.harness_mut().open_stream().unwrap();
        let x = self.x;
        RelayQueueTransport::connect(
            stream,
            fp,
            Some(&access),
            unix,
            self.sim.client(x).entropy.get(),
        )
        .unwrap()
    }

    /// The peers read what `x` sent and answer with what they have (receipts, their messages), at most 20 cells each.
    fn pump(&mut self, now: u64) {
        for i in 0..self.peers.len() {
            let mut t = self.transport();
            let peer = self.peers.get_mut(i).unwrap();
            loop {
                let cells = t.fetch(&peer.drain, peer.drained_to).unwrap();
                if cells.is_empty() {
                    break;
                }
                for (id, cell) in cells {
                    peer.convs.deliver(QueueId(1), id, &cell).unwrap();
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
                let cell = peer.convs.prepare_cell(QueueId(0), now).unwrap().unwrap();
                t.send(&peer.into_x, &cell.cell).unwrap();
                sent = sent.saturating_add(1);
            }
        }
    }

    pub fn apply(&mut self, e: Event, now: u64, n: u64) {
        match e {
            Event::UserSend { contact, len } => {
                let idx = self.peers.get(contact).unwrap().x_conv;
                let x = self.x;
                self.sim
                    .client(x)
                    .convs
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
            // fed to the application layer, never to the scheduler: there is nothing to feed in M6
            Event::Focus => {}
        }
    }

    /// Run `hours` of virtual time; `act` is applied around the scheduler. Returns the traces and the timing draws at the
    /// end of every hour.
    pub fn run(&mut self, hours: u64, act: Option<&Activity>) -> Run {
        let end = hours.saturating_mul(3_600_000);
        let mut events = act.map(|a| a.events.iter().copied().peekable());
        let mut next_pump = 600_000;
        let mut next_hour = 3_600_000;
        let mut draws = Vec::new();
        let mut n = 0_u64;
        let x = self.x;
        loop {
            let next_event = events.as_mut().and_then(|it| it.peek().map(|(t, _)| *t));
            let t = [next_event, Some(next_pump), Some(next_hour), Some(end)]
                .into_iter()
                .flatten()
                .min()
                .unwrap();
            self.sim.run_until(t);
            while let Some((_, e)) = events
                .as_mut()
                .and_then(|it| it.next_if(|(et, _)| *et <= t))
            {
                n = n.saturating_add(1);
                self.apply(e, t, n);
            }
            if t == next_pump {
                self.pump(t);
                next_pump = next_pump.saturating_add(600_000);
            }
            if t == next_hour {
                draws.push(self.sim.client_ref(x).sched.timing_draws());
                next_hour = next_hour.saturating_add(3_600_000);
            }
            if t == end {
                break;
            }
        }
        let to_peers = self
            .peers
            .iter()
            .map(|p| p.convs.get(0).unwrap().received().len())
            .sum();
        let to_x = self
            .peers
            .iter()
            .map(|p| {
                self.sim
                    .client_ref(x)
                    .convs
                    .get(p.x_conv)
                    .unwrap()
                    .received()
                    .len()
            })
            .sum();
        Run {
            to_peers,
            to_x,
            c2r: self.sim.scheduled(x, Dir::C2R),
            r2c: self.sim.scheduled(x, Dir::R2C),
            draws,
            extra_units: self
                .sim
                .client_ref(x)
                .trace
                .iter()
                .filter(|e| e.slot >= CONTROL_SLOT_BASE)
                .count(),
            control_c2r: self
                .sim
                .client_ref(x)
                .trace
                .iter()
                .filter(|e| e.slot >= CONTROL_SLOT_BASE && e.dir == Dir::C2R)
                .copied()
                .collect(),
        }
    }
}

pub struct Run {
    /// Messages that reached the peers / the client under test (the activity really happened).
    pub to_peers: usize,
    pub to_x: usize,
    pub c2r: Trace,
    pub r2c: Trace,
    pub draws: Vec<u64>,
    pub extra_units: usize,
    pub control_c2r: Trace,
}

/// Map `f` over `items` on as many threads as the machine offers.
pub fn par_map<T: Send, R: Send>(items: Vec<T>, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let workers = std::thread::available_parallelism()
        .map_or(2, usize::from)
        .min(items.len().max(1));
    let queue = std::sync::Mutex::new(items.into_iter().enumerate().collect::<Vec<_>>());
    let out = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let job = queue.lock().unwrap().pop();
                    let Some((i, item)) = job else { break };
                    let r = f(item);
                    out.lock().unwrap().push((i, r));
                }
            });
        }
    });
    let mut v = out.into_inner().unwrap();
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

/// Compare an active run with the idle one: same length, sizes, directions, slots; the largest |Δt|.
pub fn compare(idle: &Run, active: &Run) -> (Option<u64>, Option<u64>) {
    (
        max_dt(&idle.c2r, &active.c2r),
        max_dt(&idle.r2c, &active.r2c),
    )
}

fn independence(mode: Mode, contacts: &[(u64, u64)], traces: u64, hours: u64) -> (u64, u64) {
    let sc = |seed: u64| Scenario {
        mode,
        contacts: contacts.to_vec(),
        pool: true,
        seed,
    };
    let idle = {
        let mut rig = Rig::new(&sc(77), Params::default());
        rig.run(hours, None)
    };
    assert!(idle.c2r.len() > 100);
    let results = par_map((0..traces).collect(), |trace| {
        let act = activity(trace, hours, sc(0).contacts.len());
        let mut rig = Rig::new(&sc(77), Params::default());
        let run = rig.run(hours, Some(&act));
        let (c, r) = compare(&idle, &run);
        (
            trace,
            c,
            r,
            run.draws == idle.draws,
            run.to_peers.saturating_add(run.to_x),
        )
    });
    let (mut max_c2r, mut max_r2c) = (0, 0);
    let real: usize = results.iter().map(|r| r.4).sum();
    assert!(real > 50, "the traces carried real messages: {real}");
    for (trace, c, r, same_draws, _) in results {
        let c = c.expect("the C2R trace differs in length, size, direction or slot");
        let r = r.expect("the R2C trace differs in length, size, direction or slot");
        assert!(c <= 5, "trace {trace}: C2R max |Δt| = {c}");
        assert!(r <= 5, "trace {trace}: R2C max |Δt| = {r}");
        assert!(same_draws, "trace {trace}: timing draws differ");
        max_c2r = max_c2r.max(c);
        max_r2c = max_r2c.max(r);
    }
    (max_c2r, max_r2c)
}

fn report(name: &str, c2r: u64, r2c: u64) {
    evidence(
        name,
        &format!("{name}: max |Δt| C2R = {c2r} ms, R2C = {r2c} ms"),
    );
}

/// AI-01: Strict, two contacts and the pool, 64 activity traces of 6 h each: the emitted frames equal the idle run's.
#[test]
fn activity_independence_strict_virtual() {
    let (c, r) = independence(Mode::Strict, &[(10_000, 10_000), (20_000, 40_000)], 64, 6);
    report("AI-01", c, r);
}

/// AI-02: as AI-01, Balanced with four contacts.
#[test]
fn activity_independence_balanced_virtual() {
    let (c, r) = independence(Mode::Balanced, &[(10_000, 10_000); 4], 64, 6);
    report("AI-02", c, r);
}

/// AI-03: as AI-01, Low-bw with five contacts at 40 s.
#[test]
fn activity_independence_lowbw_virtual() {
    let (c, r) = independence(Mode::LowBw, &[(40_000, 40_000); 5], 64, 6);
    report("AI-03", c, r);
}

/// AI-04: the peers are active, the local user idle — the local emission equals that of two idle sides.
#[test]
fn activity_independence_when_receiving() {
    let hours = 6;
    let sc = |seed: u64| Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000), (20_000, 40_000)],
        pool: true,
        seed,
    };
    let idle = Rig::new(&sc(78), Params::default()).run(hours, None);
    let results = par_map((0..8_u64).collect(), |trace| {
        let mut act = activity(trace + 500, hours, 2);
        act.events
            .retain(|(_, e)| !matches!(e, Event::UserSend { .. }));
        let mut rig = Rig::new(&sc(78), Params::default());
        let run = rig.run(hours, Some(&act));
        compare(&idle, &run)
    });
    for (n, (c, r)) in results.into_iter().enumerate() {
        assert_eq!(c, Some(0), "trace {n}");
        assert_eq!(r, Some(0), "trace {n}");
    }
}

/// AI-05: the timing randomness is drawn the same way with or without activity.
#[test]
fn timing_draws_independent_of_activity() {
    let hours = 6;
    let sc = Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000), (20_000, 40_000)],
        pool: true,
        seed: 79,
    };
    let idle = Rig::new(&sc, Params::default()).run(hours, None);
    assert!(idle.draws.len() == 6 && idle.draws.iter().all(|d| *d > 0));
    for trace in 0..4_u64 {
        let act = activity(trace + 900, hours, 2);
        let run = Rig::new(&sc, Params::default()).run(hours, Some(&act));
        assert_eq!(run.draws, idle.draws, "trace {trace}");
    }
}

/// AI-06: the relay's answers carry no activity either — same length, sizes, times.
#[test]
fn activity_independence_both_directions() {
    let hours = 6;
    let sc = |seed: u64| Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000), (20_000, 40_000)],
        pool: true,
        seed,
    };
    let idle = Rig::new(&sc(80), Params::default()).run(hours, None);
    let results = par_map((0..8_u64).collect(), |trace| {
        let act = activity(trace + 700, hours, 2);
        let run = Rig::new(&sc(80), Params::default()).run(hours, Some(&act));
        (idle.r2c.len() == run.r2c.len(), compare(&idle, &run).1)
    });
    for (n, (same_len, dt)) in results.into_iter().enumerate() {
        assert!(same_len, "trace {n}");
        assert!(dt.is_some_and(|d| d <= 5), "trace {n}: {dt:?}");
    }
}

/// AI-08: with an invitation created and accepted (one-shot `LINK_PUT`, `LINK_GET`, `QUEUE_NEW`) the only extra units
/// are those of one-shot links.
#[test]
fn control_ops_are_the_only_extra_units() {
    let hours = 3;
    let sc = Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000)],
        pool: false,
        seed: 81,
    };
    let idle = Rig::new(&sc, Params::default()).run(hours, None);
    let mut rig = Rig::new(&sc, Params::default());
    let x = rig.x;
    rig.sim.client(x).links.insert(
        1,
        secmp_testkit::harness::LinkMaterial {
            ld_id: [1; 16],
            owner_seed: [2; 32],
            blob: vec![3; 12_360],
            one_time: true,
            expires_bucket: 488_990,
        },
    );
    rig.sim.run_until(1_000_000);
    let t = rig.sim.now();
    for (n, kind) in [
        ControlKind::QueueNew(QueueId(900)),
        ControlKind::LinkPut(1),
        ControlKind::LinkGetConsume(1),
    ]
    .into_iter()
    .enumerate()
    {
        rig.sim
            .client(x)
            .sched
            .schedule_control(t, kind, RelayId(0), u64::try_from(n).unwrap(), When::Prompt)
            .unwrap();
    }
    let active = rig.run(hours, None);
    assert_eq!(
        compare(&idle, &active),
        (Some(0), Some(0)),
        "the scheduled links are unchanged"
    );
    assert!(
        active.extra_units > 0 && idle.extra_units == 0,
        "extra units: {}",
        active.extra_units
    );
    assert!(
        active
            .control_c2r
            .iter()
            .all(|e| e.slot >= CONTROL_SLOT_BASE)
    );
}

/// AI-09: nothing on the tick path reads the outbox — `tick` names neither the outbox nor the cell source, and the core
/// knows no outbox at all.
#[test]
fn tick_path_reads_no_outbox() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../secmp-client-core/src/scheduler");
    let core = std::fs::read_to_string(root.join("core/mod.rs")).unwrap();
    let start = core.find("fn tick(").expect("the tick function");
    let rest = core.get(start..).unwrap();
    let open = rest.find('{').unwrap();
    let mut depth = 0_usize;
    let mut end = open;
    for (i, ch) in rest.char_indices().skip(open) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = rest.get(open..=end).unwrap().to_lowercase();
    for word in ["outbox", "cellsource", "source."] {
        assert!(!body.contains(word), "`tick` mentions `{word}`");
    }
    for f in [
        "core/mod.rs",
        "core/pure.rs",
        "core/backoff.rs",
        "control.rs",
        "pool.rs",
    ] {
        let text = std::fs::read_to_string(root.join(f))
            .unwrap()
            .to_lowercase();
        assert!(!text.contains("outbox"), "{f} mentions the outbox");
    }
}

/// Extra (negative control of the comparator): two runs that differ in their timing seed are told apart.
#[test]
fn activity_comparator_detects_a_different_schedule() {
    let sc = |seed: u64| Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000)],
        pool: false,
        seed,
    };
    let one = Rig::new(&sc(1), Params::default()).run(1, None);
    let two = Rig::new(&sc(2), Params::default()).run(1, None);
    let (c, _) = compare(&one, &two);
    assert!(c.is_none_or(|d| d > 5), "different phases must show: {c:?}");
}
