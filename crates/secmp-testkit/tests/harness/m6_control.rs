// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d2) `ControlOps` and (d3) `QueuePool` (CO-01…CO-08, QP-01…QP-05; spec §10.6 (2), (3)).

use secmp_client_core::scheduler::control::When;
use secmp_client_core::scheduler::core::{LinkKind, SchedError, Scheduler};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{
    ControlKind, LinkEvent, OpId, Output, QueueId, Reason, RelayId,
};
use secmp_client_core::timing::TimingRng;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{
    CONTROL_SLOT_BASE, Dir, Inspect, LinkMaterial, SimClient, TraceEntry, VirtualDriver,
};
use secmp_transport::Error as TransportError;

use crate::m6_common::{
    FRAME, client, client_with, contact, driver, frames_of, ks_uniform, run_until_link_up,
};

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

/// The control operations the scheduler starts at `now`.
fn started(sched: &mut Scheduler, now: u64) -> Vec<OpId> {
    sched
        .poll(now, &mut NoCells)
        .unwrap()
        .into_iter()
        .filter_map(|o| match o {
            Output::Control { op, .. } => Some(op),
            _ => None,
        })
        .collect()
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
            RequestCmd::Send { .. }
                | RequestCmd::Fetch { .. }
                | RequestCmd::Ping
                | RequestCmd::FetchMulti { .. }
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
            .schedule_control(
                t,
                ControlKind::QueueNew(QueueId(n)),
                RelayId(0),
                u64::from(n),
                When::Delayed,
            )
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
        .schedule_control(
            t1 - 20_000,
            ControlKind::LinkPut(1),
            RelayId(0),
            77,
            When::At(t1),
        )
        .unwrap();
    assert_eq!(sched.control_due(put), Some(t1));
    let del = sched
        .schedule_control(
            t1 - 10_000,
            ControlKind::QueueDel(QueueId(1)),
            RelayId(0),
            77,
            When::Delayed,
        )
        .unwrap();
    assert!(sched.control_due(del).unwrap() >= t1 + 60_000);
    // and one enqueued after the PUT started
    let after = sched
        .schedule_control(
            t1 + 5_000,
            ControlKind::LinkGetOwner(1),
            RelayId(0),
            77,
            When::Delayed,
        )
        .unwrap();
    assert!(sched.control_due(after).unwrap() >= t1 + 60_000);
    // an unrelated operation is not held back by it
    let other = sched
        .schedule_control(
            t1 - 10_000,
            ControlKind::QueueDel(QueueId(2)),
            RelayId(0),
            99,
            When::Delayed,
        )
        .unwrap();
    assert!(sched.control_due(other).unwrap() <= t1 - 10_000 + 3_600_000);

    // VD-M6-A-15: executed — the delay counts from the related operation's actual start. The PUT starts at t1; a
    // related prompt PUT then runs shortly before the delayed QUEUE_DEL is due: the delayed one is pushed back to at
    // least a minute after that start, and the start times the scheduler hands out are at least 60 000 ms apart.
    assert_eq!(started(&mut sched, t1), vec![put]);
    let planned = sched.control_due(del).unwrap();
    let t_put = planned - 10_000;
    let prompt = sched
        .schedule_control(t_put, ControlKind::LinkPut(2), RelayId(0), 77, When::Prompt)
        .unwrap();
    assert_eq!(started(&mut sched, t_put), vec![prompt]);
    let pushed = sched.control_due(del).unwrap();
    assert!(pushed >= t_put + 60_000, "pushed back: {pushed} vs {t_put}");
    assert!(
        started(&mut sched, pushed - 1).is_empty(),
        "not within a minute of the prompt PUT"
    );
    assert_eq!(started(&mut sched, pushed), vec![del]);
    assert!(pushed - t_put >= 60_000);
}

/// VD-M6-A-15 `related_control_ops_never_start_within_a_minute`: two related delayed operations that are both overdue
/// at one poll — one starts per call, the other is rebased on that start.
#[test]
fn related_control_ops_never_start_within_a_minute() {
    let mut sched = plain_scheduler(0xc5);
    let first = sched
        .schedule_control(
            0,
            ControlKind::QueueDel(QueueId(1)),
            RelayId(0),
            5,
            When::Delayed,
        )
        .unwrap();
    let second = sched
        .schedule_control(
            0,
            ControlKind::LinkGetOwner(1),
            RelayId(0),
            5,
            When::Delayed,
        )
        .unwrap();
    // far past both due times
    let late = 100_000_000;
    let a = started(&mut sched, late);
    assert_eq!(a, vec![first], "one operation per call");
    assert!(started(&mut sched, late).is_empty());
    let due = sched.control_due(second).unwrap();
    assert!(due >= late + 60_000, "rebased on the start: {due}");
    assert!(started(&mut sched, due - 1).is_empty());
    assert_eq!(started(&mut sched, due), vec![second]);
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
        .schedule_control(
            t,
            ControlKind::LinkGetConsume(3),
            RelayId(0),
            3,
            When::Prompt,
        )
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
    assert!(
        sim.client_ref(alice)
            .control_requests
            .iter()
            .all(|(_, _, r)| !r.is_empty())
    );
}

/// The fields of a `LINK_PUT` that a re-issue must repeat, and its token.
type PutFields = (Vec<u8>, Vec<u8>, Vec<u8>, ([u8; 16], bool, u32), Vec<u8>);

fn put_fields(sim: &VirtualDriver, client: usize, nth: usize) -> PutFields {
    let puts: Vec<_> = sim
        .client_ref(client)
        .control_requests
        .iter()
        .filter(|(_, _, reqs)| {
            matches!(
                reqs.first().map(|r| &r.cmd),
                Some(RequestCmd::LinkPut { .. })
            )
        })
        .collect();
    let (_, _, reqs) = puts.get(nth).unwrap();
    let Some(RequestCmd::LinkPut {
        ld_id,
        one_time,
        expires_bucket,
        owner_pk,
        token,
        blob_part,
        ..
    }) = reqs.first().map(|r| &r.cmd)
    else {
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
        .schedule_control(
            t1,
            ControlKind::LinkGetOwner(1),
            RelayId(0),
            1,
            When::Prompt,
        )
        .unwrap();
    sim.run_until(t1);
    assert_eq!(
        sim.client_ref(alice).link_status.last().map(|s| (s.2, s.3)),
        Some((false, false))
    );
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
    assert!(
        (t1 + 60_000..=t1 + 3_600_000).contains(&again),
        "after U[1 min, 60 min]: {again}"
    );
    let (b1, c1, pk1, meta1, token1) = put_fields(&sim, alice, 0);
    let (b2, c2, pk2, meta2, token2) = put_fields(&sim, alice, 1);
    assert_eq!(
        (b1, c1, pk1, meta1),
        (b2, c2, pk2, meta2),
        "identical LINK_PUT"
    );
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
        .schedule_control(
            t,
            ControlKind::QueueNew(QueueId(700)),
            RelayId(0),
            1,
            When::Prompt,
        )
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
    let gap = |i: usize| starts.get(i + 1).unwrap() - starts.get(i).unwrap();
    assert!(gap(0) <= 180_000, "first retry within U[0, 180 s]");
    assert!(gap(1) <= 360_000, "second within U[0, 360 s]");
}

/// The least difference of consecutive start times (`u64::MAX` for fewer than two).
fn min_gap(starts: &[u64]) -> u64 {
    let mut sorted = starts.to_vec();
    sorted.sort_unstable();
    sorted
        .windows(2)
        .filter_map(|w| w.get(1).zip(w.first()).map(|(b, a)| b.saturating_sub(*a)))
        .min()
        .unwrap_or(u64::MAX)
}

/// The start times of the runs of `kind` of client `c`.
fn starts_of(sim: &VirtualDriver, c: usize, kind: ControlKind) -> Vec<u64> {
    sim.client_ref(c)
        .controls_started
        .iter()
        .filter(|(_, _, k)| *k == kind)
        .map(|(t, _, _)| *t)
        .collect()
}

/// Q300 (EXT3-4; spec §10.6 (2)): an operation whose command the relay answers with an `ERR` is queued again exactly as
/// a fresh delayed one — never within a minute of its last start, a handful of links over 12 hours, never done.
fn answered_is_spaced(seed: u64, kind: ControlKind, related: u64, err: TransportError) {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, seed);
    sim.client(alice).links.insert(1, material(1));
    sim.client(alice).opts.answer_err = Some((kind, err));
    sim.run_until(1_000);
    let t = sim.now();
    sim.client(alice)
        .sched
        .schedule_control(t, kind, RelayId(0), related, When::Prompt)
        .unwrap();
    sim.run_until(t.saturating_add(12 * 3_600_000));
    let starts = starts_of(&sim, alice, kind);
    let n = starts.len();
    let gap = min_gap(&starts);
    assert_eq!(starts.first().copied(), Some(t), "the first run is at once");
    assert!(n >= 2, "queued again: {n}");
    assert!(
        n <= 60 && gap >= 60_000,
        "spaced like a delayed operation: {n} runs, min_gap {gap} ms"
    );
    assert!(
        !sim.client_ref(alice)
            .controls_done
            .iter()
            .any(|(_, k)| *k == kind),
        "an answered operation is never done"
    );
}

/// Q300 (EXT3-4; §10.6 (2)): an answered `LINK_PUT` is spaced like a delayed operation.
#[test]
fn answered_link_put_is_spaced_like_a_delayed_op() {
    answered_is_spaced(91, ControlKind::LinkPut(1), 1, TransportError::Rate);
}

/// Q300: an answered `QUEUE_NEW` (`ERR_AUTH`) is not terminal and is spaced like a delayed operation.
#[test]
fn answered_queue_new_auth_is_spaced_not_terminal() {
    answered_is_spaced(
        92,
        ControlKind::QueueNew(QueueId(700)),
        700,
        TransportError::Auth,
    );
}

/// Q300 (M7-S4d, XREVIEW-M7-S4 S4-3): link data whose stored blob does not decode is caught in the prepare step — no link
/// opens, no command is sent; the operation stays link failed (CO-06's back-off), local only.
#[test]
fn corrupt_link_material_opens_no_link() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 93);
    sim.client(alice).links.insert(
        1,
        LinkMaterial {
            ld_id: [1; 16],
            owner_seed: [2; 32],
            blob: vec![0; 3],
            one_time: true,
            expires_bucket: 488_988,
        },
    );
    sim.run_until(1_000);
    let t = sim.now();
    let kind = ControlKind::LinkPut(1);
    let op = sim
        .client(alice)
        .sched
        .schedule_control(t, kind, RelayId(0), 1, When::Prompt)
        .unwrap();
    sim.run_until(t.saturating_add(1_800_000));
    let slot = CONTROL_SLOT_BASE.saturating_add(op.0);
    let c = sim.client_ref(alice);
    let traced = c.trace.iter().filter(|e| e.slot == slot).count();
    let sent = c
        .control_requests
        .iter()
        .filter(|(_, o, _)| *o == op)
        .count();
    assert_eq!(
        (traced, sent),
        (0, 0),
        "trace entries and command records of the operation"
    );
    let runs = starts_of(&sim, alice, kind).len();
    assert!(runs >= 8, "retried after the back-off (CO-06): {runs} runs");
    assert!(!c.controls_done.iter().any(|(_, k)| *k == kind));
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
                    .schedule_control(
                        now,
                        ControlKind::QueueNew(QueueId(800 + n)),
                        RelayId(0),
                        u64::from(n),
                        When::Prompt,
                    )
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
            .schedule_control(
                0,
                ControlKind::QueueNew(QueueId(n)),
                RelayId(0),
                u64::from(n),
                When::Delayed,
            )
            .unwrap();
        let after = sim.client_ref(alice).sched.timing_draws();
        // one draw, from the control generator; the links' generator is untouched (CO-07)
        assert_eq!((after.0 - before.0, after.1 - before.1), (0, 1));
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
    sim.client(alice)
        .sched
        .manage_pool(now, RelayId(0))
        .unwrap();
    assert_eq!(
        sim.client_ref(alice).sched.pool_spares(RelayId(0)),
        0,
        "not refilled synchronously"
    );
    sim.run_until(3_600_000 + 10);
    assert_eq!(sim.client_ref(alice).sched.pool_spares(RelayId(0)), 2);
    let t = sim.now();
    let (taken, _) = {
        let c = sim.client(alice);
        c.sched
            .take_pool_queue(t, RelayId(0), 80_000, &mut NoCells)
            .unwrap()
    };
    assert!(taken.is_some());
    assert_eq!(
        sim.client_ref(alice).sched.pool_spares(RelayId(0)),
        1,
        "one left right after the hand-out"
    );
    sim.run_until(t + 3_600_010);
    assert_eq!(
        sim.client_ref(alice).sched.pool_spares(RelayId(0)),
        2,
        "replaced"
    );
}

use crate::m6_sched_bal::{NoCells, fresh_recv_cap};

/// QP-02: a spare is fetched on its own recv link at the pool period (80 s).
#[test]
fn pool_queue_fetched_at_pool_period() {
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, pool_params(1), 101);
    let now = sim.now();
    sim.client(alice)
        .sched
        .manage_pool(now, RelayId(0))
        .unwrap();
    sim.run_until(3_600_000 + 190_000);
    let (slot, _) = run_until_link_up(&mut sim, alice, LinkKind::Recv);
    sim.run_until(sim.now() + 900_000);
    let fetches: Vec<u64> = frames_of(&sim, alice, Dir::C2R, slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert!(fetches.len() >= 10);
    for pair in fetches.windows(2) {
        assert_eq!(pair.get(1).unwrap() - pair.first().unwrap(), 80_000);
    }
    assert!(
        frames_of(&sim, alice, Dir::C2R, slot)
            .iter()
            .all(|e| e.len == FRAME)
    );
}

/// QP-03: accepting an invitation takes a spare without a `QUEUE_NEW` at that moment; the replacement comes later.
#[test]
fn pool_handout_needs_no_queue_new() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 111);
    let now = sim.now();
    sim.client(alice)
        .sched
        .manage_pool(now, RelayId(0))
        .unwrap();
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
    assert_eq!(
        sim.client_ref(alice).controls_started.len(),
        started_before,
        "no QUEUE_NEW at the hand-out"
    );
    sim.run_until(t + 3_700_000);
    let replacement = sim
        .client_ref(alice)
        .controls_started
        .iter()
        .skip(started_before)
        .map(|(at, _, _)| *at)
        .next()
        .unwrap();
    assert!(
        replacement >= t + 60_000,
        "the replacement starts ≥ 1 min later: {replacement} vs {t}"
    );
}

/// QP-04: a spare is fetched like any queue, so it never reaches `QUEUE_IDLE_TTL` (31 days with the relay's sweeper).
#[test]
fn pool_queue_never_idles_out() {
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, pool_params(1), 121);
    let now = sim.now();
    sim.client(alice)
        .sched
        .manage_pool(now, RelayId(0))
        .unwrap();
    sim.run_until(31 * 86_400_000);
    let c = sim.client_ref(alice);
    let creations = c
        .controls_started
        .iter()
        .filter(|(_, _, k)| matches!(k, ControlKind::QueueNew(_)))
        .count();
    assert_eq!(
        creations, 1,
        "never re-created: it never answered present 2"
    );
    assert_eq!(c.sched.pool_spares(RelayId(0)), 1);
    // and it is still being fetched at the end: the last hour has its 45 `FETCH`es
    let end = 31 * 86_400_000_u64;
    let last_hour = c
        .trace
        .iter()
        .filter(|e| {
            e.dir == Dir::C2R
                && e.len == FRAME
                && e.t_ms > end - 3_600_000
                && e.slot < CONTROL_SLOT_BASE
        })
        .count();
    assert!(last_hour >= 44, "{last_hour} FETCHes in the last hour");
}

/// A client in `mode` with one spare (`pool_target` 1) whose link (Strict: its own, Balanced: the relay link) is up and has run
/// 500 s more: the driver, the client and the link's slot.
fn pool_client_up(mode: Mode, seed: u64) -> (VirtualDriver, usize, u64) {
    let mut sim = driver();
    let x = client_with(&mut sim, mode, pool_params(1), seed);
    let now = sim.now();
    sim.client(x).sched.manage_pool(now, RelayId(0)).unwrap();
    sim.run_until(3_600_000 + 190_000);
    let (slot, _) = run_until_link_up(
        &mut sim,
        x,
        if mode == Mode::Strict {
            LinkKind::Recv
        } else {
            LinkKind::Relay
        },
    );
    let up = sim.now();
    sim.run_until(up.saturating_add(500_000));
    (sim, x, slot)
}

/// The trace of the scheduled links of `c` before `end`, without the connections in `skip`.
fn scheduled_before(c: &SimClient, end: u64, skip: &[u64]) -> Vec<TraceEntry> {
    c.trace
        .iter()
        .filter(|e| e.slot < CONTROL_SLOT_BASE && e.t_ms < end && !skip.contains(&e.slot))
        .copied()
        .collect()
}

/// The link events of `c` in `[from, end)`, without those of the connections in `skip`.
fn events_between(c: &SimClient, (from, end): (u64, u64), skip: &[u64]) -> Vec<(u64, LinkEvent)> {
    let of = |e: &LinkEvent| match e {
        LinkEvent::Up(id, _) | LinkEvent::TornDown(id, _, _) => Some(id.0),
        LinkEvent::Alert(..) | LinkEvent::RouteDead(_) | LinkEvent::QueueGone(_) => None,
    };
    c.events
        .iter()
        .filter(|(at, e)| (from..end).contains(at) && !of(e).is_some_and(|i| skip.contains(&i)))
        .copied()
        .collect()
}

/// Whether `o` is a link event on the wire: a connection closed or opened, or a teardown.
fn on_wire(o: &Output) -> bool {
    matches!(
        o,
        Output::Close { .. } | Output::Connect { .. } | Output::Event(LinkEvent::TornDown(..))
    )
}

/// QP-05 (re-dictated by S-1, Q296; spec §10.6 (1), (3)): a spare handed out with another period gets a new recv link (new key,
/// the announced period) that connects at an instant drawn `U[0, 180 000]` after the hand-out; the 80 s link is not touched at
/// the hand-out (no `Close`, its `FETCH`es every 80 000) and ends (`TornDown(.., Lifetime)`) at that instant.
#[test]
fn pool_handout_recreates_link_with_announced_period() {
    let (mut sim, alice, old_slot) = pool_client_up(Mode::Strict, 131);
    let t = sim.now();
    let (taken, outs) = sim
        .client(alice)
        .sched
        .take_pool_queue(t, RelayId(0), 10_000, &mut NoCells)
        .unwrap();
    assert!(taken.is_some());
    assert!(!outs.iter().any(on_wire), "no link event at the hand-out");
    let info = sim
        .client_ref(alice)
        .sched
        .links()
        .into_iter()
        .find(|l| l.queue == taken)
        .unwrap();
    assert_eq!(
        info.id.map(|l| l.0),
        Some(old_slot),
        "the 80 s link is still up"
    );
    let end = info.die_at.unwrap();
    assert!(
        (t..=t.saturating_add(180_000)).contains(&end),
        "drawn U[0, 180 000] after the hand-out: {end} vs {t}"
    );
    let keys_before = sim.client_ref(alice).connects.len();
    sim.run_until(end);
    let old: Vec<u64> = frames_of(&sim, alice, Dir::C2R, old_slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert!(old.len() >= 5, "{old:?}");
    for pair in old.windows(2) {
        assert_eq!(
            pair.get(1).unwrap().saturating_sub(*pair.first().unwrap()),
            80_000,
            "until {end}"
        );
    }
    let c = sim.client_ref(alice);
    let downs: Vec<(u64, Reason)> = c
        .events
        .iter()
        .filter_map(|(at, e)| match e {
            LinkEvent::TornDown(id, _, why) if id.0 == old_slot => Some((*at, *why)),
            _ => None,
        })
        .collect();
    assert_eq!(
        downs,
        vec![(end, Reason::Lifetime)],
        "the 80 s link ends once, at the drawn instant"
    );
    let new: Vec<(u64, u64)> = c
        .connects
        .iter()
        .skip(keys_before)
        .filter(|(_, id, _)| c.link_kinds.get(&id.0) == Some(&(LinkKind::Recv, 10_000)))
        .map(|(at, id, _)| (*at, id.0))
        .collect();
    assert_eq!(new.len(), 1, "one successor: {new:?}");
    let (at, new_slot) = *new.first().unwrap();
    assert_eq!(at, end, "the successor connects when the 80 s link ends");
    assert_ne!(new_slot, old_slot);
    sim.run_until(end.saturating_add(120_000));
    let fetches: Vec<u64> = frames_of(&sim, alice, Dir::C2R, new_slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert!(fetches.len() >= 5);
    for pair in fetches.windows(2) {
        assert_eq!(
            pair.get(1).unwrap().saturating_sub(*pair.first().unwrap()),
            10_000
        );
    }
}

/// S-1 (Q296; spec §10.1, §10.6 (1)–(3); review L1-1/L2-1): Strict, a named hand-out (`take_pool_queue_id`: the core entry of
/// all four triggers) emits nothing; until the drawn handover instant the scheduled links' trace, events and connects are the
/// run's without the take, but the refill spare (§10.6 (2), (3)); then one handover. Balanced: nothing, links unchanged.
#[test]
fn strict_take_emits_nothing_at_the_take() {
    let (mut with, x, old_slot) = pool_client_up(Mode::Strict, 141);
    let (mut without, _, _) = pool_client_up(Mode::Strict, 141);
    let t = with.now();
    assert_eq!(without.now(), t, "the two runs are one up to the take");
    let links = with.client_ref(x).sched.links();
    let spare = links
        .iter()
        .find(|l| l.id.map(|i| i.0) == Some(old_slot))
        .and_then(|l| l.queue)
        .unwrap();
    let (taken, outs) = with
        .client(x)
        .sched
        .take_pool_queue_id(t, RelayId(0), spare, 10_000, &mut NoCells)
        .unwrap();
    assert_eq!(taken, Some(spare));
    assert!(!outs.iter().any(on_wire), "nothing at the take");
    let end = with
        .client_ref(x)
        .sched
        .links()
        .iter()
        .find(|l| l.queue == Some(spare))
        .and_then(|l| l.die_at)
        .unwrap();
    assert!((t..=t.saturating_add(180_000)).contains(&end));
    with.run_until(end);
    without.run_until(end);
    let (wc, oc) = (with.client_ref(x), without.client_ref(x));
    let refill: Vec<u64> = wc
        .connects
        .iter()
        .filter(|(at, id, _)| {
            (t..end).contains(at) && wc.link_kinds.get(&id.0) == Some(&(LinkKind::Recv, 80_000))
        })
        .map(|(_, id, _)| id.0)
        .collect();
    let others = |c: &SimClient, skip: &[u64]| -> Vec<u64> {
        c.connects
            .iter()
            .filter(|(at, id, _)| (t..end).contains(at) && !skip.contains(&id.0))
            .map(|(at, _, _)| *at)
            .collect()
    };
    assert_eq!(
        others(wc, &refill),
        others(oc, &[]),
        "no other connection before the handover"
    );
    assert_eq!(
        scheduled_before(wc, end, &refill),
        scheduled_before(oc, end, &[]),
        "the trace is the run without the take"
    );
    assert_eq!(
        events_between(wc, (t, end), &refill),
        events_between(oc, (t, end), &[]),
        "no link event before the handover"
    );
    assert!(
        wc.controls_started
            .iter()
            .filter(|(at, _, _)| (t..end).contains(at))
            .all(|(at, _, k)| matches!(k, ControlKind::QueueNew(_))
                && *at >= t.saturating_add(60_000)),
        "only the refill, delayed"
    );
    let downs: Vec<LinkEvent> = wc
        .events
        .iter()
        .filter(|(at, e)| *at == end && matches!(e, LinkEvent::TornDown(..)))
        .map(|(_, e)| *e)
        .collect();
    assert!(
        matches!(downs.as_slice(), [LinkEvent::TornDown(id, _, Reason::Lifetime)] if id.0 == old_slot),
        "{downs:?}"
    );
    let ups: Vec<u64> = wc
        .connects
        .iter()
        .filter(|(at, _, _)| *at == end)
        .map(|(_, id, _)| id.0)
        .collect();
    assert_eq!(ups.len(), 1, "{ups:?}");
    assert_eq!(
        ups.first().and_then(|id| wc.link_kinds.get(id)),
        Some(&(LinkKind::Recv, 10_000))
    );
    balanced_take_changes_no_link();
}

/// The Balanced leg of S-1: a take outputs nothing and leaves the links as they were.
fn balanced_take_changes_no_link() {
    let (mut bal, bx, _) = pool_client_up(Mode::Balanced, 141);
    let (tb, before) = (bal.now(), bal.client_ref(bx).sched.links());
    let (taken, outs) = bal
        .client(bx)
        .sched
        .take_pool_queue(tb, RelayId(0), 10_000, &mut NoCells)
        .unwrap();
    assert!(taken.is_some());
    assert!(outs.is_empty(), "Balanced: nothing at the take");
    assert_eq!(
        bal.client_ref(bx).sched.links(),
        before,
        "Balanced: the links are as they were"
    );
}

/// The `QueueNew` creations the scheduler hands out at `now`: `(operation, queue)`.
fn creations(sched: &mut Scheduler, now: u64) -> Vec<(OpId, QueueId)> {
    sched
        .poll(now, &mut NoCells)
        .unwrap()
        .into_iter()
        .filter_map(|o| match o {
            Output::Control {
                op,
                kind: ControlKind::QueueNew(q),
                ..
            } => Some((op, q)),
            _ => None,
        })
        .collect()
}

/// VD-M6-A-16 `pool_admission_respects_fetch_multi_limit`: a pool spare is an entry of the `FETCH_MULTI` like any queue
/// (spec D.2: at most 32); only the rate sum leaves it out. With 32 ordinary queues the 33rd entry — a spare whose
/// creation completes — is refused, and the pool and the queues are as they were.
#[test]
fn pool_admission_respects_fetch_multi_limit() {
    let mut sched = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::seeded(0x516));
    for n in 0..32 {
        sched
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(n), 80_000)
            .unwrap();
    }
    sched.manage_pool(0, RelayId(0)).unwrap();
    let made = creations(&mut sched, 10_000_000);
    assert_eq!(made.len(), 2);
    let links = sched.links().len();
    for (op, queue) in made {
        let refused = sched.pool_queue_ready(10_000_000, queue, fresh_recv_cap(1000 + queue.0));
        assert_eq!(refused, Err(SchedError::TooManyQueues));
        assert_eq!(
            sched.pool_spares(RelayId(0)),
            0,
            "not registered as a spare"
        );
        assert!(sched.queue_ref(queue).is_none(), "not a recv-queue");
        sched.control_done(op);
    }
    assert_eq!(sched.links().len(), links);
    assert_eq!(sched.overruns(), 0);
    assert_eq!(
        sched.add_recv_queue(10_000_000, RelayId(0), fresh_recv_cap(2000), 80_000),
        Err(SchedError::TooManyQueues),
        "the 33rd ordinary queue is refused too"
    );
}

/// VD-M6-A-17 `rejected_pool_handout_keeps_spare`: a hand-out whose announced period breaks the rate bound is refused
/// and the spare stays — the oldest one, still outside the rate sum, nothing queued to replace it.
#[test]
fn rejected_pool_handout_keeps_spare() {
    let mut sched = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::seeded(0x517));
    let mut ordinary = Vec::new();
    for n in 0..4 {
        ordinary.push(
            sched
                .add_recv_queue(0, RelayId(0), fresh_recv_cap(n), 10_000)
                .unwrap(),
        );
    }
    sched.manage_pool(0, RelayId(0)).unwrap();
    let late = 10_000_000;
    let made = creations(&mut sched, late);
    let mut spares = Vec::new();
    for (op, queue) in made {
        sched
            .pool_queue_ready(late, queue, fresh_recv_cap(100 + queue.0))
            .unwrap();
        sched.control_done(op);
        spares.push(queue);
    }
    assert_eq!(sched.pool_spares(RelayId(0)), 2);
    // Σ 80 000/P = 32: any hand-out is over the bound
    for _ in 0..2 {
        let refused = sched.take_pool_queue(late, RelayId(0), 10_000, &mut NoCells);
        assert!(matches!(refused, Err(SchedError::RateBound)));
        assert_eq!(sched.pool_spares(RelayId(0)), 2, "both spares are kept");
    }
    assert!(
        creations(&mut sched, late * 2).is_empty(),
        "no replacement was queued"
    );
    // the spare is still outside the rate sum: one ordinary queue out, one in, is exactly the bound again
    sched
        .remove_queue(late, ordinary.first().copied().unwrap(), &mut NoCells)
        .unwrap();
    sched
        .add_recv_queue(late, RelayId(0), fresh_recv_cap(300), 10_000)
        .unwrap();
    // and the oldest spare is the one handed out once there is room
    sched
        .remove_queue(late, ordinary.get(1).copied().unwrap(), &mut NoCells)
        .unwrap();
    let (taken, _) = sched
        .take_pool_queue(late, RelayId(0), 10_000, &mut NoCells)
        .unwrap();
    assert_eq!(taken, spares.first().copied());
    assert_eq!(sched.pool_spares(RelayId(0)), 1);
}

/// M7-C1b (C1-2): removing a recv queue drops its pending re-create too. A `FETCH` answered `NoQueue` schedules `QUEUE_NEW`
/// of the queue at `U[10 s, 5 min]`; `remove_queue` leaves no `QUEUE_NEW` (and no `QUEUE_DEL`) of it, so no control operation
/// for it ever runs and the host is never asked for its material (it would mint a spare under that id).
#[test]
fn removed_queue_drops_pending_recreate() {
    use secmp_crypto::SecretBytes;
    use secmp_transport::{QueueTransport, RecvCap, RelayQueueTransport};

    use crate::m6_common::at;

    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 321);
    let bob = client(&mut sim, Mode::Strict, 322);
    let link = contact(&mut sim, alice, bob, 10_000, 10_000);
    let (_, t_up) = run_until_link_up(&mut sim, alice, LinkKind::Recv);
    sim.run_until(at(t_up, 40, 10_000));
    let (recv_seed, _) = *sim
        .client_ref(alice)
        .material
        .queues
        .get(&link.a_recv.0)
        .unwrap();
    {
        let access = sim.harness().access_key();
        let fp = sim.harness().relay_fp();
        let unix = sim.harness().clock().unix();
        let stream = sim.harness_mut().open_stream().unwrap();
        let mut t = RelayQueueTransport::connect(
            stream,
            fp,
            Some(&access),
            unix,
            sim.client(alice).entropy.get(),
        )
        .unwrap();
        t.delete_queue(&RecvCap::from_seed(&SecretBytes::from_slice(&recv_seed).unwrap()).unwrap())
            .unwrap();
    }
    // the next FETCH sees NoQueue: the re-create is scheduled, not yet started (it is due ≥ 10 s later)
    let t_seen = at(t_up, 41, 10_000);
    sim.run_until(t_seen);
    let before = sim.client_ref(alice).controls_started.len();
    assert!(
        !sim.client_ref(alice)
            .controls_started
            .iter()
            .any(|(_, _, k)| matches!(k, ControlKind::QueueNew(q) if *q == link.a_recv)),
        "pending, not started"
    );
    let t = sim.now();
    sim.client(alice)
        .sched
        .remove_queue(t, link.a_recv, &mut NoCells)
        .unwrap();
    sim.run_until(t + 360_000);
    let ops_of_q = sim
        .client_ref(alice)
        .controls_started
        .iter()
        .skip(before)
        .filter(|(_, _, k)| {
            matches!(k, ControlKind::QueueNew(q) | ControlKind::QueueDel(q) if *q == link.a_recv)
        })
        .count();
    assert_eq!(ops_of_q, 0, "no QUEUE_NEW / QUEUE_DEL of the removed queue");
}
