// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared set-up of the M6 scheduler tests: contacts over the in-process relay on the virtual clock.

use secmp_client_core::scheduler::conversation::Conversation;
use secmp_client_core::scheduler::core::LinkInfo;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{LinkEvent, QueueId, RelayId};
use secmp_testkit::harness::{
    Dir, EntropyPool, HarnessConfig, START_UNIX, TraceEntry, VirtualDriver,
};

pub const FRAME: usize = 4352;

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
    let now = d.now();
    let relay = RelayId(0);
    // the queue b receives on, a sends to
    let (rc_b, sc_b, _, _) = d.new_queue(b);
    let (rc_a, sc_a, _, _) = d.new_queue(a);
    let b_recv = d.client(b).sched.add_recv_queue(now, relay, rc_b, period_ab).unwrap();
    let a_send = d.client(a).sched.add_send_queue(now, relay, sc_b, period_ab).unwrap();
    let a_recv = d.client(a).sched.add_recv_queue(now, relay, rc_a, period_ba).unwrap();
    let b_send = d.client(b).sched.add_send_queue(now, relay, sc_a, period_ba).unwrap();
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
