// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d2) ControlOps and (d3) QueuePool (CO-01…CO-08, QP-01…QP-05; spec §10.6 (2), (3)).

use secmp_client_core::scheduler::control::When;
use secmp_client_core::scheduler::core::{LinkKind, Scheduler};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{ControlKind, LinkEvent, QueueId, Reason, RelayId};
use secmp_client_core::timing::TimingRng;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{CONTROL_SLOT_BASE, Dir, Inspect, LinkMaterial, VirtualDriver};

use crate::m6_common::{FRAME, client, client_with, contact, driver, frames_of, ks_uniform, run_until_link_up};

fn material(n: u8) -> LinkMaterial {
    LinkMaterial {
        ld_id: [n; 16],
        owner_seed: [n.wrapping_add(1); 32],
        blob: vec![n; 12_360],
        one_time: true,
        expires_bucket: 488_988,
    }
}

fn plain_scheduler(seed: u64) -> Scheduler {
    Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(seed))
}

/// CO-01: each control operation runs on its own one-shot link with its own isolation key: handshake, the command
/// (1 / 1 / 3 / 1 request frames), the response, close — never on a scheduled link.
#[test]
fn control_ops_run_on_one_shot_links() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 11);
    let bob = client(&mut sim, Mode::Strict, 12);
    contact(&mut sim, alice, bob, 10_000, 80_000);
    sim.client(alice).opts.inspect = Inspect::Requests;
    sim.client(alice).links.insert(1, material(1));
    sim.run_until(50_000);
    let now = sim.now();
    let kinds = [
        ControlKind::QueueNew(QueueId(500)),
        ControlKind::QueueDel(QueueId(500)),
        ControlKind::LinkPut(1),
        ControlKind::LinkGetOwner(1),
    ];
    let ops: Vec<_> = kinds
        .iter()
        .enumerate()
        .map(|(n, k)| {
            sim.client(alice)
                .sched
                .schedule_control(now, *k, RelayId(0), u64::try_from(n).unwrap(), When::Prompt)
                .unwrap()
        })
        .collect();
    sim.run_until(now);
    let c = sim.client_ref(alice);
    assert_eq!(c.controls_done.len(), 4);
    for (op, want) in ops.iter().zip([1_usize, 1, 3, 1]) {
        let (_, _, reqs) = c.control_requests.iter().find(|(_, o, _)| o == op).unwrap();
        assert_eq!(reqs.len(), want, "request frames of {op:?}");
    }
    // 4 distinct keys, none a scheduled link's
    let mut keys: Vec<u64> = c.control_keys.iter().map(|(_, k)| k.0).collect();
    keys.extend(c.connects.iter().map(|(_, _, k)| k.0));
    let total = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), total, "every connection has its own key");
    // and the scheduled links carried none of these commands
    for (_, _, r) in &c.requests {
        assert!(matches!(
            r.cmd,
            RequestCmd::Send { .. } | RequestCmd::Fetch { .. } | RequestCmd::Ping | RequestCmd::FetchMulti { .. }
        ));
    }
    // each operation's trace slot is its own and above the scheduled ones
    let control_slots: std::collections::BTreeSet<u64> = c
        .trace
        .iter()
        .filter(|e| e.slot >= CONTROL_SLOT_BASE)
        .map(|e| e.slot)
        .collect();
    assert_eq!(control_slots.len(), 4);
}

/// CO-02: the delay of an unrelated control operation is uniform on [1 min, 60 min].
#[test]
fn control_op_delay_uniform_1_to_60_min() {
    let mut sched = plain_scheduler(0xc0);
    let t = 1_000_000;
    let mut delays = Vec::new();
    for n in 0..1000_u32 {
        let op = sched
            .schedule_control(t, ControlKind::QueueNew(QueueId(n)), RelayId(0), u64::from(n), When::Delayed)
            .unwrap();
        delays.push(sched.control_due(op).unwrap() - t);
    }
    assert!(delays.iter().all(|d| (60_000..=3_600_000).contains(d)));
    let (dstat, p) = ks_uniform(&delays, 60_000, 3_600_000);
    assert!(p >= 0.01, "KS D = {dstat}, p = {p}");
}

/// CO-03: operations on the same correlation never run within a minute of each other.
#[test]
fn control_op_delay_from_related_op() {
    let mut sched = plain_scheduler(0xc3);
    let t1 = 5_000_000;
    // a LINK_PUT due at t1, a related QUEUE_DEL enqueued 10 s before it
    let put = sched
        .schedule_control(t1 - 20_000, ControlKind::LinkPut(1), RelayId(0), 77, When::At(t1))
        .unwrap();
    assert_eq!(sched.control_due(put), Some(t1));
    let del = sched
        .schedule_control(t1 - 10_000, ControlKind::QueueDel(QueueId(1)), RelayId(0), 77, When::Delayed)
        .unwrap();
    assert!(sched.control_due(del).unwrap() >= t1 + 60_000);
    // and one enqueued after the PUT started
    let after = sched
        .schedule_control(t1 + 5_000, ControlKind::LinkGetOwner(1), RelayId(0), 77, When::Delayed)
        .unwrap();
    assert!(sched.control_due(after).unwrap() >= t1 + 60_000);
    // an unrelated operation is not held back by it
    let other = sched
        .schedule_control(t1 - 10_000, ControlKind::QueueDel(QueueId(2)), RelayId(0), 99, When::Delayed)
        .unwrap();
    assert!(sched.control_due(other).unwrap() <= t1 - 10_000 + 3_600_000);
}

/// CO-04: where a user is waiting the operation starts at once, on a one-shot link.
#[test]
fn prompt_ops_are_not_delayed() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 41);
    sim.client(alice).links.insert(2, material(2));
    sim.client(alice).links.insert(3, material(3));
    sim.run_until(1_000);
    let t = sim.now();
    let consume = sim
        .client(alice)
        .sched
        .schedule_control(t, ControlKind::LinkGetConsume(3), RelayId(0), 3, When::Prompt)
        .unwrap();
    let put = sim
        .client(alice)
        .sched
        .schedule_control(t, ControlKind::LinkPut(2), RelayId(0), 2, When::Prompt)
        .unwrap();
    sim.run_until(t);
    let started = &sim.client_ref(alice).controls_started;
    for op in [consume, put] {
        let (at, _, _) = started.iter().find(|(_, o, _)| *o == op).unwrap();
        assert_eq!(*at, t, "delay 0");
    }
    assert!(sim.client_ref(alice).control_requests.iter().all(|(_, _, r)| !r.is_empty()));
}

fn put_fields(sim: &VirtualDriver, client: usize, nth: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, ([u8; 16], bool, u32), Vec<u8>) {
    let puts: Vec<_> = sim
        .client_ref(client)
        .control_requests
        .iter()
        .filter(|(_, _, reqs)| matches!(reqs.first().map(|r| &r.cmd), Some(RequestCmd::LinkPut { .. })))
        .collect();
    let (_, _, reqs) = puts.get(nth).unwrap();
    let Some(RequestCmd::LinkPut { ld_id, one_time, expires_bucket, owner_pk, token, blob_part, .. }) = reqs.first().map(|r| &r.cmd) else {
        unreachable!()
    };
    let conts: Vec<u8> = reqs
        .iter()
        .skip(1)
        .flat_map(|r| match &r.cmd {
            RequestCmd::Cont(c) => c.data.to_vec(),
            _ => Vec::new(),
        })
        .collect();
    (
        blob_part.to_vec(),
        conts,
        owner_pk.as_bytes().to_vec(),
        (*ld_id, *one_time, *expires_bucket),
        token.to_vec(),
    )
}

/// CO-05: an owner-status answer `{0, 0}` before `expires` makes the inviter re-issue the identical `LINK_PUT` on a
/// one-shot link after `U[1 min, 60 min]`.
#[test]
fn owner_status_reissues_identical_put() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 51);
    sim.client(alice).links.insert(1, material(1));
    sim.run_until(1_000);
    let t0 = sim.now();
    sim.client(alice)
        .sched
        .schedule_control(t0, ControlKind::LinkPut(1), RelayId(0), 1, When::Prompt)
        .unwrap();
    sim.run_until(t0);
    // the relay restarts: it has forgotten the link data (spec §9.7 (1))
    sim.restart_relay();
    let t1 = t0 + 10_000;
    sim.run_until(t1);
    sim.client(alice)
        .sched
        .schedule_control(t1, ControlKind::LinkGetOwner(1), RelayId(0), 1, When::Prompt)
        .unwrap();
    sim.run_until(t1);
    assert_eq!(sim.client_ref(alice).link_status.last().map(|s| (s.2, s.3)), Some((false, false)));
    sim.run_until(t1 + 3_700_000);
    let puts: Vec<u64> = sim
        .client_ref(alice)
        .controls_started
        .iter()
        .filter(|(_, _, k)| matches!(k, ControlKind::LinkPut(1)))
        .map(|(t, _, _)| *t)
        .collect();
    assert_eq!(puts.len(), 2, "the PUT was issued once more");
    let again = *puts.get(1).unwrap();
    assert!((t1 + 60_000..=t1 + 3_600_000).contains(&again), "after U[1 min, 60 min]: {again}");
    let (b1, c1, pk1, meta1, token1) = put_fields(&sim, alice, 0);
    let (b2, c2, pk2, meta2, token2) = put_fields(&sim, alice, 1);
    assert_eq!((b1, c1, pk1, meta1), (b2, c2, pk2, meta2), "identical LINK_PUT");
    assert_ne!(token1, token2, "a new token for the new link");
}

/// CO-06: an operation whose link closes before `RELAYINFO` is retried with the back-off and runs exactly once after
/// success.
#[test]
fn control_op_retried_after_link_failure() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 61);
    sim.run_until(1_000);
    sim.client(alice).opts.refuse_connections = true;
    let t = sim.now();
    sim.client(alice)
        .sched
        .schedule_control(t, ControlKind::QueueNew(QueueId(700)), RelayId(0), 1, When::Prompt)
        .unwrap();
    while sim.client_ref(alice).controls_started.len() < 2 {
        let next = sim.now() + 30_000;
        sim.run_until(next);
    }
    sim.client(alice).opts.refuse_connections = false;
    sim.run_until(sim.now() + 2_000_000);
    let c = sim.client_ref(alice);
    assert_eq!(c.controls_done.len(), 1, "executed exactly once");
    let starts: Vec<u64> = c.controls_started.iter().map(|(t, _, _)| *t).collect();
    assert_eq!(starts.len(), 3);
    assert!(starts[1] - starts[0] <= 180_000, "first retry within U[0, 180 s]");
    assert!(starts[2] - starts[1] <= 360_000, "second within U[0, 360 s]");
}

/// CO-07: control operations leave the scheduled traces unchanged; the only extra units are the one-shot links'.
#[test]
fn control_ops_leave_scheduled_traces_unchanged() {
    let run = |with_ops: bool| {
        let mut sim = driver();
        let alice = client(&mut sim, Mode::Strict, 71);
        let bob = client(&mut sim, Mode::Strict, 72);
        contact(&mut sim, alice, bob, 10_000, 40_000);
        sim.run_until(100_000);
        if with_ops {
            let now = sim.now();
            for n in 0..5_u32 {
                sim.client(alice)
                    .sched
                    .schedule_control(now, ControlKind::QueueNew(QueueId(800 + n)), RelayId(0), u64::from(n), When::Prompt)
                    .unwrap();
            }
        }
        sim.run_until(900_000);
        (
            sim.scheduled(alice, Dir::C2R),
            sim.scheduled(alice, Dir::R2C),
            sim.client_ref(alice)
                .trace
                .iter()
                .filter(|e| e.slot >= CONTROL_SLOT_BASE)
                .count(),
        )
    };
    let (c2r_idle, r2c_idle, extra_idle) = run(false);
    let (c2r_ops, r2c_ops, extra_ops) = run(true);
    assert_eq!(c2r_idle, c2r_ops, "scheduled C2R trace unchanged");
    assert_eq!(r2c_idle, r2c_ops, "scheduled R2C trace unchanged");
    assert_eq!(extra_idle, 0);
    assert!(extra_ops > 0, "the one-shot links' units");
}

/// CO-08: a control operation's delay is a timing draw; the content randomness is untouched.
#[test]
fn control_op_draws_from_timing_rng() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 81);
    let mut twin = driver();
    let alice2 = client(&mut twin, Mode::Strict, 81);
    for n in 0..5_u32 {
        let before = sim.client_ref(alice).sched.timing_draws();
        sim.client(alice)
            .sched
            .schedule_control(0, ControlKind::QueueNew(QueueId(n)), RelayId(0), u64::from(n), When::Delayed)
            .unwrap();
        assert_eq!(sim.client_ref(alice).sched.timing_draws() - before, 1);
    }
    assert_eq!(
        sim.client(alice).entropy.bytes(32),
        twin.client(alice2).entropy.bytes(32),
        "content draws unaffected"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// QueuePool

fn pool_params(target: usize) -> Params {
    Params {
        pool_target: target,
        ..Params::default()
    }
}

/// QP-01: two spares per relay are kept; a hand-out is replaced; creations are control operations, never synchronous.
#[test]
fn pool_keeps_two_spares_per_relay() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 91);
    let now = sim.now();
    sim.client(alice).sched.manage_pool(now, RelayId(0)).unwrap();
    assert_eq!(sim.client_ref(alice).sched.pool_spares(RelayId(0)), 0, "not refilled synchronously");
    sim.run_until(3_600_000 + 10);
    assert_eq!(sim.client_ref(alice).sched.pool_spares(RelayId(0)), 2);
    let t = sim.now();
    let (taken, _) = {
        let c = sim.client(alice);
        c.sched.take_pool_queue(t, RelayId(0), 80_000, &mut NoCells).unwrap()
    };
    assert!(taken.is_some());
    assert_eq!(sim.client_ref(alice).sched.pool_spares(RelayId(0)), 1, "one left right after the hand-out");
    sim.run_until(t + 3_600_010);
    assert_eq!(sim.client_ref(alice).sched.pool_spares(RelayId(0)), 2, "replaced");
}

use crate::m6_sched_bal::NoCells;

/// QP-02: a spare is fetched on its own recv link at the pool period (80 s).
#[test]
fn pool_queue_fetched_at_pool_period() {
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, pool_params(1), 101);
    let now = sim.now();
    sim.client(alice).sched.manage_pool(now, RelayId(0)).unwrap();
    sim.run_until(3_600_000 + 190_000);
    let (slot, _) = run_until_link_up(&mut sim, alice, LinkKind::Recv);
    sim.run_until(sim.now() + 900_000);
    let fetches: Vec<u64> = frames_of(&sim, alice, Dir::C2R, slot).iter().map(|e| e.t_ms).collect();
    assert!(fetches.len() >= 10);
    for pair in fetches.windows(2) {
        assert_eq!(pair[1] - pair[0], 80_000);
    }
    assert!(frames_of(&sim, alice, Dir::C2R, slot).iter().all(|e| e.len == FRAME));
}

/// QP-03: accepting an invitation takes a spare without a `QUEUE_NEW` at that moment; the replacement comes later.
#[test]
fn pool_handout_needs_no_queue_new() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 111);
    let now = sim.now();
    sim.client(alice).sched.manage_pool(now, RelayId(0)).unwrap();
    sim.run_until(3_600_000 + 10);
    let t = sim.now();
    let started_before = sim.client_ref(alice).controls_started.len();
    let (taken, _) = sim
        .client(alice)
        .sched
        .take_pool_queue(t, RelayId(0), 80_000, &mut NoCells)
        .unwrap();
    assert!(taken.is_some());
    sim.run_until(t);
    assert_eq!(sim.client_ref(alice).controls_started.len(), started_before, "no QUEUE_NEW at the hand-out");
    sim.run_until(t + 3_700_000);
    let replacement = sim
        .client_ref(alice)
        .controls_started
        .iter()
        .skip(started_before)
        .map(|(at, _, _)| *at)
        .next()
        .unwrap();
    assert!(replacement >= t + 60_000, "the replacement starts ≥ 1 min later: {replacement} vs {t}");
}

/// QP-04: a spare is fetched like any queue, so it never reaches `QUEUE_IDLE_TTL` (31 days with the relay's sweeper).
#[test]
fn pool_queue_never_idles_out() {
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, pool_params(1), 121);
    let now = sim.now();
    sim.client(alice).sched.manage_pool(now, RelayId(0)).unwrap();
    sim.run_until(31 * 86_400_000);
    let c = sim.client_ref(alice);
    let creations = c
        .controls_started
        .iter()
        .filter(|(_, _, k)| matches!(k, ControlKind::QueueNew(_)))
        .count();
    assert_eq!(creations, 1, "never re-created: it never answered present 2");
    assert_eq!(c.sched.pool_spares(RelayId(0)), 1);
    // and it is still being fetched at the end: the last hour has its 45 `FETCH`es
    let end = 31 * 86_400_000_u64;
    let last_hour = c
        .trace
        .iter()
        .filter(|e| e.dir == Dir::C2R && e.len == FRAME && e.t_ms > end - 3_600_000 && e.slot < CONTROL_SLOT_BASE)
        .count();
    assert!(last_hour >= 44, "{last_hour} FETCHes in the last hour");
}

/// QP-05: a spare handed out with another period gets a new recv link (new key, new phase) at that period.
#[test]
fn pool_handout_recreates_link_with_announced_period() {
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, pool_params(1), 131);
    let now = sim.now();
    sim.client(alice).sched.manage_pool(now, RelayId(0)).unwrap();
    sim.run_until(3_600_000 + 190_000);
    let (old_slot, _) = run_until_link_up(&mut sim, alice, LinkKind::Recv);
    let t = sim.now();
    let (taken, outs) = sim
        .client(alice)
        .sched
        .take_pool_queue(t, RelayId(0), 10_000, &mut NoCells)
        .unwrap();
    assert!(taken.is_some());
    assert!(outs.iter().any(|o| matches!(
        o,
        secmp_client_core::scheduler::types::Output::Event(LinkEvent::TornDown(id, Reason::Closed)) if id.0 == old_slot
    )), "the 80 s link closes");
    let keys_before = sim.client_ref(alice).connects.len();
    sim.run_until(t + 190_000);
    let new = sim.client_ref(alice).connects.iter().skip(keys_before).find(|(_, id, _)| id.0 != old_slot).unwrap();
    assert!(new.0 >= t && new.0 <= t + 180_000, "new phase");
    let new_slot = new.1.0;
    sim.run_until(new.0 + 120_000);
    let fetches: Vec<u64> = frames_of(&sim, alice, Dir::C2R, new_slot).iter().map(|e| e.t_ms).collect();
    assert!(fetches.len() >= 5);
    for pair in fetches.windows(2) {
        assert_eq!(pair[1] - pair[0], 10_000);
    }
}
