// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared set-up of the M6 scheduler tests: contacts over the in-process relay on the virtual clock.

use secmp_client_core::scheduler::conversation::Conversation;
use secmp_client_core::scheduler::core::LinkInfo;
use secmp_proto::wire::cell::Cell as WireCell;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{LinkEvent, QueueId, RelayId};
use secmp_testkit::harness::{
    Dir, EntropyPool, HarnessConfig, START_UNIX, TraceEntry, VirtualDriver,
};

pub const FRAME: usize = 4352;

pub type TestConv = Conversation<MemOutbox, MemPersist, EntropyPool>;

/// One contact between client `a` and client `b`: the queues in both directions and the conversations.
pub struct Contact {
    pub a: usize,
    pub b: usize,
    /// `a`'s scheduler queue for sending to `b`, and `b`'s for receiving from `a`.
    pub a_send: QueueId,
    pub b_recv: QueueId,
    /// `b`'s queue for sending to `a`, and `a`'s for receiving from `b`.
    pub b_send: QueueId,
    pub a_recv: QueueId,
    /// The index of the conversation in each client's `convs`.
    pub conv_a: usize,
    pub conv_b: usize,
}

pub fn driver() -> VirtualDriver {
    VirtualDriver::new(HarnessConfig::default())
}

pub fn client(d: &mut VirtualDriver, mode: Mode, seed: u64) -> usize {
    d.add_client(mode, Params::default(), seed)
}

pub fn client_with(d: &mut VirtualDriver, mode: Mode, params: Params, seed: u64) -> usize {
    d.add_client(mode, params, seed)
}

/// Create the two queues of a contact and register them (and the conversations) with both schedulers at the driver's
/// current time. `period_ab` is the period `b` asks of `a` (the queue `a` sends on), `period_ba` the reverse.
pub fn contact(
    d: &mut VirtualDriver,
    a: usize,
    b: usize,
    period_ab: u64,
    period_ba: u64,
) -> Contact {
    contact_on(d, a, b, period_ab, period_ba, RelayId(0))
}

/// As [`contact`], with the queues labelled as being on `relay` (the harness has one physical relay; the label is what
/// Balanced groups by).
pub fn contact_on(
    d: &mut VirtualDriver,
    a: usize,
    b: usize,
    period_ab: u64,
    period_ba: u64,
    relay: RelayId,
) -> Contact {
    let now = d.now();
    // the queue b receives on, a sends to
    let (rc_b, sc_b, rb, sb) = d.new_queue(b);
    let (rc_a, sc_a, ra, sa) = d.new_queue(a);
    let b_recv = d.client(b).sched.add_recv_queue(now, relay, rc_b, period_ab).unwrap();
    let a_send = d.client(a).sched.add_send_queue(now, relay, sc_b, period_ab).unwrap();
    let a_recv = d.client(a).sched.add_recv_queue(now, relay, rc_a, period_ba).unwrap();
    let b_send = d.client(b).sched.add_send_queue(now, relay, sc_a, period_ba).unwrap();
    d.client(b).material.queues.insert(b_recv.0, (rb, sb));
    d.client(a).material.queues.insert(a_recv.0, (ra, sa));
    let (state_a, state_b) = d.ratchet_states(a, b);
    let peer_a = d.peer_key(a);
    let peer_b = d.peer_key(b);
    let idx_a = u32::try_from(a).unwrap();
    let idx_b = u32::try_from(b).unwrap();
    let mut conv_a: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
        state_a,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-conv", idx_a.wrapping_mul(1000).wrapping_add(idx_b)),
        peer_b,
        START_UNIX,
    );
    let mut conv_b: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
        state_b,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-conv", idx_b.wrapping_mul(1000).wrapping_add(idx_a)),
        peer_a,
        START_UNIX,
    );
    conv_a.bind(a_send, a_recv);
    conv_b.bind(b_send, b_recv);
    let index_a = d.client(a).convs.add(conv_a);
    let index_b = d.client(b).convs.add(conv_b);
    Contact {
        a,
        b,
        a_send,
        b_recv,
        b_send,
        a_recv,
        conv_a: index_a,
        conv_b: index_b,
    }
}

/// The frames (4 352 B) of one direction in a client's trace, handshake records excluded.
pub fn frames(d: &VirtualDriver, client: usize, dir: Dir) -> Vec<TraceEntry> {
    d.client_ref(client)
        .trace
        .iter()
        .filter(|e| e.len == FRAME && e.dir == dir)
        .copied()
        .collect()
}

/// The frames of one slot in one direction.
pub fn frames_of(d: &VirtualDriver, client: usize, dir: Dir, slot: u64) -> Vec<TraceEntry> {
    frames(d, client, dir)
        .into_iter()
        .filter(|e| e.slot == slot)
        .collect()
}

/// `t_up` of the link `info`.
pub fn t_up(info: &LinkInfo) -> u64 {
    info.t_up.unwrap()
}

/// The `Up`/`TornDown` events of a client with their times.
pub fn events(d: &VirtualDriver, client: usize) -> Vec<(u64, LinkEvent)> {
    d.client_ref(client).events.clone()
}

/// Two-sample helper: the maximum |Δt| between two traces of equal length (None if the lengths, sizes, directions or
/// slots differ).
pub fn max_dt(a: &[TraceEntry], b: &[TraceEntry]) -> Option<u64> {
    if a.len() != b.len() {
        return None;
    }
    let mut max = 0_u64;
    for (x, y) in a.iter().zip(b) {
        if x.len != y.len || x.dir != y.dir || x.slot != y.slot {
            return None;
        }
        max = max.max(x.t_ms.abs_diff(y.t_ms));
    }
    Some(max)
}

/// A queue owned by `a` (which receives on it, scheduled) whose other end is driven by hand: `b`'s conversation exists
/// but `b` has no scheduler queue, so the test decides what is sent and when.
pub struct Half {
    pub a_recv: QueueId,
    pub send_cap: Vec<u8>,
    pub conv_a: usize,
    pub conv_b: usize,
    pub b_queue: QueueId,
}

pub fn half_contact(d: &mut VirtualDriver, a: usize, b: usize, period: u64) -> Half {
    let now = d.now();
    let (rc, sc, recv_seed, send_seed) = d.new_queue(a);
    let a_recv = d
        .client(a)
        .sched
        .add_recv_queue(now, RelayId(0), rc, period)
        .unwrap();
    d.client(a).material.queues.insert(a_recv.0, (recv_seed, send_seed));
    let (state_b, state_a) = d.ratchet_states(b, a);
    let peer_a = d.peer_key(a);
    let peer_b = d.peer_key(b);
    let b_queue = QueueId(u32::MAX);
    let mut conv_a: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
        state_a,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-half", 1),
        peer_b,
        START_UNIX,
    );
    let mut conv_b: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
        state_b,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-half", 2),
        peer_a,
        START_UNIX,
    );
    conv_a.bind(QueueId(u32::MAX - 1), a_recv);
    conv_b.bind(b_queue, QueueId(u32::MAX - 2));
    let idx_a = d.client(a).convs.add(conv_a);
    let idx_b = d.client(b).convs.add(conv_b);
    Half {
        a_recv,
        send_cap: sc.to_bytes().to_vec(),
        conv_a: idx_a,
        conv_b: idx_b,
        b_queue,
    }
}

/// `SEND` a cell to the queue of `half` over a fresh connection (not traced, not scheduled).
pub fn inject(d: &mut VirtualDriver, client: usize, half: &Half, cell: &secmp_proto::wire::cell::Cell) -> u64 {
    let access = d.harness().access_key();
    let fp = d.harness().relay_fp();
    let unix = d.harness().clock().unix();
    let stream = d.harness_mut().open_stream().unwrap();
    let mut t = secmp_transport::RelayQueueTransport::connect(
        stream,
        fp,
        Some(&access),
        unix,
        d.client(client).entropy.get(),
    )
    .unwrap();
    let cap = secmp_transport::SendCap::from_bytes(&half.send_cap).unwrap();
    secmp_transport::QueueTransport::send(&mut t, &cap, cell).unwrap().cell_id
}

/// The one-sample Kolmogorov–Smirnov test of `samples` against the uniform distribution on `[lo, hi]`: `(D, p)` with
/// the asymptotic p-value.
pub fn ks_uniform(samples: &[u64], lo: u64, hi: u64) -> (f64, f64) {
    let n = samples.len();
    let nf = f64::from(u32::try_from(n).unwrap());
    let span = f64::from(u32::try_from(hi - lo).unwrap());
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mut d = 0.0_f64;
    for (i, x) in sorted.iter().enumerate() {
        let f = f64::from(u32::try_from(*x - lo).unwrap()) / span;
        let above = f64::from(u32::try_from(i + 1).unwrap()) / nf - f;
        let below = f - f64::from(u32::try_from(i).unwrap()) / nf;
        d = d.max(above).max(below);
    }
    let root = nf.sqrt();
    let lambda = (root + 0.12 + 0.11 / root) * d;
    let mut p = 0.0_f64;
    for k in 1..=100_u32 {
        let kf = f64::from(k);
        let term = (-2.0 * kf * kf * lambda * lambda).exp();
        if k % 2 == 1 {
            p += 2.0 * term;
        } else {
            p -= 2.0 * term;
        }
    }
    (d, p.clamp(0.0, 1.0))
}

/// Two-sample KS (D, p) for the inter-departure analysis.
pub fn ks_two_sample(a: &[u64], b: &[u64]) -> (f64, f64) {
    let (mut x, mut y) = (a.to_vec(), b.to_vec());
    x.sort_unstable();
    y.sort_unstable();
    let (n, m) = (x.len(), y.len());
    let (mut i, mut j) = (0_usize, 0_usize);
    let mut d = 0.0_f64;
    let (nf, mf) = (f64::from(u32::try_from(n).unwrap()), f64::from(u32::try_from(m).unwrap()));
    while i < n && j < m {
        let (xv, yv) = (x[i], y[j]);
        let v = xv.min(yv);
        while i < n && x[i] <= v {
            i += 1;
        }
        while j < m && y[j] <= v {
            j += 1;
        }
        let fx = f64::from(u32::try_from(i).unwrap()) / nf;
        let fy = f64::from(u32::try_from(j).unwrap()) / mf;
        d = d.max((fx - fy).abs());
    }
    let en = (nf * mf / (nf + mf)).sqrt();
    let lambda = (en + 0.12 + 0.11 / en) * d;
    let mut p = 0.0_f64;
    for k in 1..=100_u32 {
        let kf = f64::from(k);
        let term = (-2.0 * kf * kf * lambda * lambda).exp();
        if k % 2 == 1 {
            p += 2.0 * term;
        } else {
            p -= 2.0 * term;
        }
    }
    (d, p.clamp(0.0, 1.0))
}

/// Run until a link of `kind` is up; returns `(its slot, t_up)`. The first tick of the link is a whole period away.
pub fn run_until_link_up(
    d: &mut VirtualDriver,
    client: usize,
    kind: secmp_client_core::scheduler::core::LinkKind,
) -> (u64, u64) {
    loop {
        let infos = d.client_ref(client).sched.links();
        if let Some(i) = infos.iter().find(|l| l.kind == kind && l.t_up.is_some()) {
            return (i.id.unwrap().0, i.t_up.unwrap());
        }
        let next = d.now().saturating_add(500);
        d.run_until(next);
    }
}

/// Client `a` sends to a queue that `b` owns (nobody receives): one send link, one conversation. Returns the
/// conversation's index. `b` has no scheduler queue, so the only traffic and the only counted work is `a`'s.
pub fn send_only(d: &mut VirtualDriver, a: usize, b: usize, period: u64) -> usize {
    let now = d.now();
    let (_rc, sc, _, _) = d.new_queue(b);
    let a_send = d.client(a).sched.add_send_queue(now, RelayId(0), sc, period).unwrap();
    let (state_a, _state_b) = d.ratchet_states(a, b);
    let peer = d.peer_key(b);
    let idx = u32::try_from(a).unwrap();
    let mut conv: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
        state_a,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-sendonly", idx),
        peer,
        START_UNIX,
    );
    conv.bind(a_send, QueueId(u32::MAX));
    d.client(a).convs.add(conv)
}
