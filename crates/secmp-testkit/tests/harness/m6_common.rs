// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared set-up of the M6 scheduler tests: contacts over the in-process relay on the virtual clock.

use secmp_client_core::scheduler::conversation::Conversation;
use secmp_client_core::scheduler::core::LinkKind;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{QueueId, RelayId};
use secmp_proto::wire::cell::Cell;
use secmp_testkit::harness::{
    Dir, EntropyPool, HarnessConfig, START_UNIX, TraceEntry, VirtualDriver,
};
use secmp_transport::{QueueTransport, RelayQueueTransport, SendCap};

pub const FRAME: usize = 4352;

pub type TestConv = Conversation<MemOutbox, MemPersist, EntropyPool>;

/// One contact between two clients: the queues in both directions and the conversations.
pub struct Contact {
    /// The first client's scheduler queue for sending to the second.
    pub a_send: QueueId,
    /// The first client's scheduler queue for receiving from the second.
    pub a_recv: QueueId,
    /// The index of the conversation in the first and in the second client's `convs`.
    pub conv_a: usize,
    pub conv_b: usize,
}

pub fn driver() -> VirtualDriver {
    VirtualDriver::new(HarnessConfig::default())
}

pub fn client(sim: &mut VirtualDriver, mode: Mode, seed: u64) -> usize {
    sim.add_client(mode, Params::default(), seed)
}

pub fn client_with(sim: &mut VirtualDriver, mode: Mode, params: Params, seed: u64) -> usize {
    sim.add_client(mode, params, seed)
}

/// Create the two queues of a contact and register them (and the conversations) with both schedulers at the driver's
/// current time. `period_ab` is the period `bob` asks of `alice` (the queue `alice` sends on), `period_ba` the reverse.
pub fn contact(
    sim: &mut VirtualDriver,
    alice: usize,
    bob: usize,
    period_ab: u64,
    period_ba: u64,
) -> Contact {
    contact_on(sim, alice, bob, period_ab, period_ba, RelayId(0))
}

/// As [`contact`], with the queues labelled as being on `relay` (the harness has one physical relay; the label is what
/// Balanced groups by).
pub fn contact_on(
    sim: &mut VirtualDriver,
    alice: usize,
    bob: usize,
    period_ab: u64,
    period_ba: u64,
    relay: RelayId,
) -> Contact {
    let now = sim.now();
    // the queue bob receives on, alice sends to
    let (rc_bob, sc_bob, rb, sb) = sim.new_queue(bob);
    let (rc_alice, sc_alice, ra, sa) = sim.new_queue(alice);
    let bob_recv = sim
        .client(bob)
        .sched
        .add_recv_queue(now, relay, rc_bob, period_ab)
        .unwrap();
    let alice_send = sim
        .client(alice)
        .sched
        .add_send_queue(now, relay, sc_bob, period_ab)
        .unwrap();
    let alice_recv = sim
        .client(alice)
        .sched
        .add_recv_queue(now, relay, rc_alice, period_ba)
        .unwrap();
    let bob_send = sim
        .client(bob)
        .sched
        .add_send_queue(now, relay, sc_alice, period_ba)
        .unwrap();
    sim.client(bob).material.queues.insert(bob_recv.0, (rb, sb));
    sim.client(alice)
        .material
        .queues
        .insert(alice_recv.0, (ra, sa));
    let (state_alice, state_bob) = sim.ratchet_states(alice, bob);
    let peer_alice = sim.peer_key(alice);
    let peer_bob = sim.peer_key(bob);
    let tag_alice = u32::try_from(alice).unwrap();
    let tag_bob = u32::try_from(bob).unwrap();
    let mut conv_alice: TestConv = Conversation::new(
        state_alice,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new(
            "m6-conv",
            tag_alice.wrapping_mul(1000).wrapping_add(tag_bob),
        ),
        peer_bob,
        START_UNIX,
    );
    let mut conv_bob: TestConv = Conversation::new(
        state_bob,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new(
            "m6-conv",
            tag_bob.wrapping_mul(1000).wrapping_add(tag_alice),
        ),
        peer_alice,
        START_UNIX,
    );
    conv_alice.bind(alice_send, alice_recv);
    conv_bob.bind(bob_send, bob_recv);
    let index_alice = sim.client(alice).convs.add(conv_alice);
    let index_bob = sim.client(bob).convs.add(conv_bob);
    Contact {
        a_send: alice_send,
        a_recv: alice_recv,
        conv_a: index_alice,
        conv_b: index_bob,
    }
}

/// The frames (4 352 B) of one direction in a client's trace, handshake records excluded.
pub fn frames(sim: &VirtualDriver, client: usize, dir: Dir) -> Vec<TraceEntry> {
    sim.client_ref(client)
        .trace
        .iter()
        .filter(|e| e.len == FRAME && e.dir == dir)
        .copied()
        .collect()
}

/// The frames of one slot in one direction.
pub fn frames_of(sim: &VirtualDriver, client: usize, dir: Dir, slot: u64) -> Vec<TraceEntry> {
    frames(sim, client, dir)
        .into_iter()
        .filter(|e| e.slot == slot)
        .collect()
}

/// Two traces of equal length: the largest |Δt| between their entries (`None` if the lengths, sizes, directions or slots
/// differ).
pub fn max_dt(one: &[TraceEntry], other: &[TraceEntry]) -> Option<u64> {
    if one.len() != other.len() {
        return None;
    }
    let mut max = 0_u64;
    for (x, y) in one.iter().zip(other) {
        if x.len != y.len || x.dir != y.dir || x.slot != y.slot {
            return None;
        }
        max = max.max(x.t_ms.abs_diff(y.t_ms));
    }
    Some(max)
}

/// A queue owned by `alice` (which receives on it, scheduled) whose other end is driven by hand: `bob`'s conversation
/// exists but `bob` has no scheduler queue, so the test decides what is sent and when.
pub struct Half {
    pub a_recv: QueueId,
    pub send_cap: Vec<u8>,
    pub conv_a: usize,
    pub conv_b: usize,
}

pub fn half_contact(sim: &mut VirtualDriver, alice: usize, bob: usize, period: u64) -> Half {
    let now = sim.now();
    let (rc, sc, recv_seed, send_seed) = sim.new_queue(alice);
    let a_recv = sim
        .client(alice)
        .sched
        .add_recv_queue(now, RelayId(0), rc, period)
        .unwrap();
    sim.client(alice)
        .material
        .queues
        .insert(a_recv.0, (recv_seed, send_seed));
    let (state_bob, state_alice) = sim.ratchet_states(bob, alice);
    let peer_alice = sim.peer_key(alice);
    let peer_bob = sim.peer_key(bob);
    let mut conv_alice: TestConv = Conversation::new(
        state_alice,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-half", 1),
        peer_bob,
        START_UNIX,
    );
    let mut conv_bob: TestConv = Conversation::new(
        state_bob,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-half", 2),
        peer_alice,
        START_UNIX,
    );
    conv_alice.bind(QueueId(u32::MAX - 1), a_recv);
    conv_bob.bind(QueueId(u32::MAX), QueueId(u32::MAX - 2));
    let conv_a = sim.client(alice).convs.add(conv_alice);
    let conv_b = sim.client(bob).convs.add(conv_bob);
    Half {
        a_recv,
        send_cap: sc.to_bytes().to_vec(),
        conv_a,
        conv_b,
    }
}

/// `SEND` a cell to the queue of `half` over a fresh connection (not traced, not scheduled).
pub fn inject(sim: &mut VirtualDriver, client: usize, half: &Half, cell: &Cell) -> u64 {
    let access = sim.harness().access_key();
    let fp = sim.harness().relay_fp();
    let unix = sim.harness().clock().unix();
    let stream = sim.harness_mut().open_stream().unwrap();
    let mut transport = RelayQueueTransport::connect(
        stream,
        fp,
        Some(&access),
        unix,
        sim.client(client).entropy.get(),
    )
    .unwrap();
    let cap = SendCap::from_bytes(&half.send_cap).unwrap();
    transport.send(&cap, cell).unwrap().cell_id
}

/// Client `alice` sends to a queue that `bob` owns (nobody receives): one send link, one conversation. Returns the
/// conversation's index. `bob` has no scheduler queue, so the only traffic and the only counted work is `alice`'s.
pub fn send_only(sim: &mut VirtualDriver, alice: usize, bob: usize, period: u64) -> usize {
    let now = sim.now();
    let (_rc, sc, _, _) = sim.new_queue(bob);
    let a_send = sim
        .client(alice)
        .sched
        .add_send_queue(now, RelayId(0), sc, period)
        .unwrap();
    let (state_alice, _state_bob) = sim.ratchet_states(alice, bob);
    let peer = sim.peer_key(bob);
    let tag = u32::try_from(alice).unwrap();
    let mut conv: TestConv = Conversation::new(
        state_alice,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-sendonly", tag),
        peer,
        START_UNIX,
    );
    conv.bind(a_send, QueueId(u32::MAX));
    sim.client(alice).convs.add(conv)
}

/// Run until a link of `kind` is up; returns `(its slot, t_up)`. The first tick of the link is a whole period away.
pub fn run_until_link_up(sim: &mut VirtualDriver, client: usize, kind: LinkKind) -> (u64, u64) {
    loop {
        let infos = sim.client_ref(client).sched.links();
        if let Some(info) = infos.iter().find(|l| l.kind == kind && l.t_up.is_some()) {
            return (info.id.unwrap().0, info.t_up.unwrap());
        }
        let next = sim.now().saturating_add(500);
        sim.run_until(next);
    }
}

/// `t_up + k·period`, checked.
pub fn at(t_up: u64, k: u64, period: u64) -> u64 {
    t_up.checked_add(k.checked_mul(period).unwrap()).unwrap()
}

/// The Kolmogorov distribution's tail `Q(λ) = 2 Σ (−1)^(j−1) e^(−2 j² λ²)`.
fn kolmogorov_tail(lambda: f64) -> f64 {
    let mut sum = 0.0_f64;
    for j in 1..=100_u32 {
        let jf = f64::from(j);
        let term = 2.0 * (-2.0 * jf * jf * lambda * lambda).exp();
        sum += if j % 2 == 1 { term } else { -term };
    }
    sum.clamp(0.0, 1.0)
}

/// The one-sample Kolmogorov–Smirnov test of `samples` against the uniform distribution on `[lo, hi]`: `(D, p)` with
/// the asymptotic p-value.
pub fn ks_uniform(samples: &[u64], lo: u64, hi: u64) -> (f64, f64) {
    let count = f64::from(u32::try_from(samples.len()).unwrap());
    let span = f64::from(u32::try_from(hi.checked_sub(lo).unwrap()).unwrap());
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mut worst = 0.0_f64;
    for (i, x) in sorted.iter().enumerate() {
        let cdf = f64::from(u32::try_from(x.checked_sub(lo).unwrap()).unwrap()) / span;
        let above = f64::from(u32::try_from(i.checked_add(1).unwrap()).unwrap()) / count - cdf;
        let below = cdf - f64::from(u32::try_from(i).unwrap()) / count;
        worst = worst.max(above).max(below);
    }
    let root = count.sqrt();
    (worst, kolmogorov_tail((root + 0.12 + 0.11 / root) * worst))
}

/// Write a line of evidence (a number the report quotes) to `target/m6-evidence/<name>.txt`; the gate copies it to
/// `docs/reviews/M06-evidence/`.
pub fn evidence(name: &str, text: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/m6-evidence");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{name}.txt")), format!("{text}\n")).unwrap();
}
