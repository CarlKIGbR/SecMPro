// SPDX-License-Identifier: AGPL-3.0-or-later
//! The external review of `f68d923` (WEISUNG M6-B-5, EXTB-1…EXTB-4): the tokio driver's findings, each test the
//! reviewer's probe on the real driver (`MemProvider`, paused clock).

use secmp_client_core::scheduler::params::{Mode, Params};

use secmp_client_core::scheduler::types::LinkEvent;
use secmp_testkit::harness::Dir;

use crate::m6_activity::{Scenario, activity};
use crate::m6_tokio::{AI_COSTS, Setup, TClient, TokioRig, runtime};

/// EXTB-1: four Balanced contacts at 10 s, no phase, the AI costs (a real cell 20 ms, a dummy 1 ms): the link's first
/// tick carries its frames — the SEND part was sealed before the FETCH part, so the counters go out in order — and no
/// link is torn down `Rejected` over the first minute, idle and active.
#[test]
fn driver_balanced_first_tick_sends_and_fetches_in_order() {
    for active in [false, true] {
        runtime().block_on(async {
            let setup = Setup::new();
            let sc = Scenario {
                mode: Mode::Balanced,
                contacts: vec![(10_000, 10_000); 4],
                pool: false,
                seed: 21,
            };
            let params = Params {
                phase_max_ms: 0,
                ..Params::default()
            };
            let x = TClient::new(&setup, sc.mode, params, sc.seed, AI_COSTS, 0);
            let mut rig = TokioRig::assemble(setup, x, &sc).await;
            let act = activity(21, 3, sc.contacts.len());
            let run = rig
                .run_minutes(1, if active { Some(&act) } else { None })
                .await;
            let events = &rig.x.driver.log().unwrap().events;
            let torn: Vec<_> = events
                .iter()
                .filter(|(_, e)| matches!(e, LinkEvent::TornDown(..)))
                .collect();
            assert!(torn.is_empty(), "active {active}: {torn:?}");
            let up = events
                .iter()
                .find_map(|(t, e)| matches!(e, LinkEvent::Up(_, _)).then_some(*t))
                .unwrap();
            for k in 1..=5_u64 {
                let tick = up + k * 10_000;
                let frames = run
                    .c2r
                    .iter()
                    .filter(|e| e.dir == Dir::C2R && e.len == 4352 && e.t_ms == tick)
                    .count();
                assert_eq!(
                    frames, 2,
                    "active {active}: tick {k} at {tick} carries SEND and FETCH"
                );
            }
            assert_eq!(run.overruns, 0, "active {active}");
        });
    }
}

fn deliveries(x: &TClient) -> usize {
    x.jobs
        .lock()
        .unwrap()
        .iter()
        .filter(|j| j.kind == b'D')
        .count()
}

/// EXTB-2: persist before ack across a queue's re-creation. Cell 1 of a receive queue is committed and acknowledged;
/// the queue is deleted on the relay, the driver's next `FETCH` gets `NoQueue`, the scheduler re-creates the same
/// queue (same keys), and the relay's new cell 1 — other bytes — must go through the worker (a `Deliver` job) before
/// it is acknowledged: the high-water mark of the old queue does not cover it.
#[test]
fn driver_queue_recreation_does_not_ack_undelivered_cells() {
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_crypto::SecretBytes;
    use secmp_proto::wire::cell::Cell;
    use secmp_testkit::harness::Costs;
    use secmp_transport::RecvCap;
    use secmp_transport::driver::AsyncQueueTransport as _;
    runtime().block_on(async {
        let mut setup = Setup::new();
        let mut x = TClient::new(
            &setup,
            Mode::Strict,
            Params::default(),
            31,
            Costs::default(),
            0,
        );
        let recv: [u8; 32] = x.pool.bytes(32).try_into().unwrap();
        let send: [u8; 32] = x.pool.bytes(32).try_into().unwrap();
        let access = setup.relay.access_key();
        let mut peer_pool = secmp_testkit::harness::EntropyPool::new("extb2-peer", 0);
        let mut t = setup.transport(&mut peer_pool).await;
        let (_, into_x) = t
            .create_queue(
                &SecretBytes::from_slice(&recv).unwrap(),
                &SecretBytes::from_slice(&send).unwrap(),
                &access,
            )
            .await
            .unwrap();
        let cap = || RecvCap::from_seed(&SecretBytes::from_slice(&recv).unwrap()).unwrap();
        let now = setup.now();
        let q = x
            .sched
            .add_recv_queue(now, RelayId(0), cap(), 10_000)
            .unwrap();
        x.control.lock().unwrap().queues.insert(q.0, (recv, send));
        // cell 1, committed and acknowledged
        t.send(&into_x, &Cell::from_bytes(&[0x11; 4096]).unwrap())
            .await
            .unwrap();
        x.run_until(now + 240_000).await;
        assert_eq!(deliveries(&x), 1);
        assert_eq!(x.sched.acked(q), Some(1));
        // the queue is deleted on the relay; the scheduler sees NoQueue and re-creates it
        let mut t = setup.transport(&mut peer_pool).await;
        t.delete_queue(&cap()).await.unwrap();
        x.run_until(now + 900_000).await;
        assert!(
            x.control
                .lock()
                .unwrap()
                .done
                .contains(&ControlKind::QueueNew(q)),
            "the queue was re-created"
        );
        // the re-created queue's cell 1, other bytes: delivered, then acknowledged
        let mut t = setup.transport(&mut peer_pool).await;
        t.send(&into_x, &Cell::from_bytes(&[0x22; 4096]).unwrap())
            .await
            .unwrap();
        x.run_until(now + 1_200_000).await;
        assert_eq!(deliveries(&x), 2, "the new cell 1 went through the worker");
        assert_eq!(x.sched.acked(q), Some(1));
    });
}

/// Where the control operation `op` ran: its start (virtual ms), its isolation key, its relay connection (`None` when no
/// connection was opened for it).
fn control_link(
    setup: &Setup,
    x: &TClient,
    op: secmp_client_core::scheduler::types::OpId,
) -> (u64, secmp_transport::driver::Isolation, Option<u64>) {
    use secmp_client_core::scheduler::run::Purpose;
    let log = x.driver.log().unwrap();
    let (start, iso) = log
        .connects
        .iter()
        .find_map(|(t, p, i)| matches!(p, Purpose::Control(o) if *o == op).then_some((*t, *i)))
        .unwrap();
    let conn = setup
        .relay
        .isolations()
        .iter()
        .find_map(|(c, i)| (*i == iso).then_some(*c));
    (start, iso, conn)
}

/// The time of the unit of `conn` in direction `dir` and length `len`: the first, or the last.
fn unit_time(setup: &Setup, conn: u64, dir: Dir, len: usize, last: bool) -> u64 {
    let times: Vec<u64> = setup
        .relay
        .units()
        .iter()
        .filter(|u| u.conn == conn && u.dir == dir && u.len == len)
        .map(|u| u.t_ms)
        .collect();
    let t = if last { times.last() } else { times.first() };
    *t.unwrap()
}

/// Q300 (EXT3-1 Repro B; spec §10.1): the host's material is ready before the one-shot link opens — a hub wait of 5 s in
/// the prepare step delays the connect, and the command follows the handshake at once.
#[test]
fn driver_control_material_is_ready_before_the_link_opens() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::types::{ControlKind, QueueId, RelayId};
    use secmp_testkit::harness::Costs;
    runtime().block_on(async {
        let setup = Setup::new();
        let mut x = TClient::new(
            &setup,
            Mode::Strict,
            Params::default(),
            41,
            Costs::default(),
            0,
        );
        let t0 = setup.now();
        x.control.lock().unwrap().prepare_wait_ms = 5_000;
        let kind = ControlKind::QueueNew(QueueId(900));
        let op = x
            .sched
            .schedule_control(t0, kind, RelayId(0), 900, When::Prompt)
            .unwrap();
        x.run_until(t0 + 20_000).await;
        let (start, iso, conn) = control_link(&setup, &x, op);
        let connected = setup
            .provider
            .connects()
            .iter()
            .find_map(|(t, i)| (*i == iso).then_some(*t))
            .unwrap();
        let conn = conn.unwrap();
        let hs2 = unit_time(&setup, conn, Dir::R2C, 1156, false);
        let cmd = unit_time(&setup, conn, Dir::C2R, 4352, false);
        assert!(
            connected >= start + 5_000,
            "connect {} ms after the start",
            connected - start
        );
        assert!(
            cmd.checked_sub(hs2).is_some_and(|d| d < 200),
            "command {cmd} ms after handshake end {hs2}"
        );
        assert!(x.control.lock().unwrap().done.contains(&kind));
    });
}

/// Q300 (EXT3-1 Repro B; spec §10.1, CLAUDE.md §1.7): the one-shot link is closed before the host commits the answer — a
/// commit that waits 5 s leaves the link closed within 200 ms of its last response, and the operation done only after.
#[test]
fn driver_control_link_closes_before_the_commit() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_testkit::harness::{Costs, LinkMaterial};
    runtime().block_on(async {
        let setup = Setup::new();
        let mut x = TClient::new(
            &setup,
            Mode::Strict,
            Params::default(),
            42,
            Costs::default(),
            0,
        );
        let t0 = setup.now();
        {
            let mut m = x.control.lock().unwrap();
            m.commit_wait_ms = 5_000;
            m.links.insert(
                1,
                LinkMaterial {
                    ld_id: [7; 16],
                    owner_seed: [8; 32],
                    blob: Vec::new(),
                    one_time: true,
                    expires_bucket: 0,
                },
            );
        }
        let kind = ControlKind::LinkGetOwner(1);
        let op = x
            .sched
            .schedule_control(t0, kind, RelayId(0), 1, When::Prompt)
            .unwrap();
        x.run_until(t0 + 3_000).await;
        let (_, _, conn) = control_link(&setup, &x, op);
        let conn = conn.unwrap();
        let last = setup
            .relay
            .units()
            .iter()
            .filter(|u| u.conn == conn && u.dir == Dir::R2C)
            .map(|u| u.t_ms)
            .max()
            .unwrap();
        let closed = setup
            .relay
            .closes()
            .iter()
            .find_map(|(c, t)| (*c == conn).then_some(*t));
        assert!(
            closed.is_some_and(|c| c >= last && c - last < 200),
            "closed {closed:?}, last response {last}"
        );
        assert!(!x.control.lock().unwrap().done.contains(&kind));
        x.run_until(t0 + 10_000).await;
        let m = x.control.lock().unwrap();
        assert!(m.done.contains(&kind));
        assert_eq!(m.link_status.last(), Some(&(1, false, false)));
    });
}

/// Q300 (HB-55): an operation the host has nothing to do for opens no link.
#[test]
fn driver_control_with_nothing_to_do_opens_no_link() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::Purpose;
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_testkit::harness::Costs;
    runtime().block_on(async {
        let setup = Setup::new();
        let mut x = TClient::new(
            &setup,
            Mode::Strict,
            Params::default(),
            43,
            Costs::default(),
            0,
        );
        let t0 = setup.now();
        let kind = ControlKind::LinkPut(9);
        x.control.lock().unwrap().skip.push(kind);
        let op = x
            .sched
            .schedule_control(t0, kind, RelayId(0), 9, When::Prompt)
            .unwrap();
        x.run_until(t0 + 10_000).await;
        let entries: Vec<_> = x
            .driver
            .log()
            .unwrap()
            .connects
            .iter()
            .filter(|(_, p, _)| matches!(p, Purpose::Control(o) if *o == op))
            .copied()
            .collect();
        assert_eq!(entries.len(), 1, "one start");
        let iso = entries.first().map(|(_, _, i)| *i).unwrap();
        let opened = setup
            .provider
            .connects()
            .iter()
            .filter(|(_, i)| *i == iso)
            .count();
        assert_eq!(opened, 0, "provider connects with the operation's key");
        assert_eq!(x.sched.control_due(op), None);
        assert!(!x.control.lock().unwrap().done.contains(&kind));
    });
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

/// What the product `Driver::control` did with one control operation over 30 min of virtual time (M7-S4d, Q300 phase rule):
/// its start times, its due time `first_ms` after the start, what the runner reported, and the provider connects with its
/// keys.
struct PhaseRun {
    starts: Vec<u64>,
    due: Option<u64>,
    unanswered: Vec<secmp_client_core::scheduler::types::ControlKind>,
    done: Vec<secmp_client_core::scheduler::types::ControlKind>,
    connects: usize,
}

/// Run `kind` (related `related`, on `relay`) at once through the product driver with the runner hooks `hook`.
fn phase_run(
    seed: u64,
    kind: secmp_client_core::scheduler::types::ControlKind,
    relay: secmp_client_core::scheduler::types::RelayId,
    related: u64,
    first_ms: u64,
    hook: impl FnOnce(&mut secmp_testkit::harness::ControlMaterial),
) -> PhaseRun {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::Purpose;
    use secmp_testkit::harness::Costs;
    runtime().block_on(async {
        let setup = Setup::new();
        let mut x = TClient::new(
            &setup,
            Mode::Strict,
            Params::default(),
            seed,
            Costs::default(),
            0,
        );
        let t0 = setup.now();
        hook(&mut x.control.lock().unwrap());
        let op = x
            .sched
            .schedule_control(t0, kind, relay, related, When::Prompt)
            .unwrap();
        x.run_until(t0.saturating_add(first_ms)).await;
        let due = x.sched.control_due(op);
        x.run_until(t0.saturating_add(1_800_000)).await;
        let runs: Vec<_> = x
            .driver
            .log()
            .unwrap()
            .connects
            .iter()
            .filter(|(_, p, _)| matches!(p, Purpose::Control(o) if *o == op))
            .map(|(t, _, i)| (*t, *i))
            .collect();
        let connects = setup
            .provider
            .connects()
            .iter()
            .filter(|(_, i)| runs.iter().any(|(_, r)| r == i))
            .count();
        let m = x.control.lock().unwrap();
        PhaseRun {
            starts: runs.iter().map(|(t, _)| *t).collect(),
            due,
            unanswered: m.unanswered.clone(),
            done: m.done.clone(),
            connects,
        }
    })
}

/// The answered class: ≤ 5 runs in 30 min, none within a minute of another; due U[1 min, 60 min] after the end of the first
/// attempt (which ends between `lo_ms` and `first_ms` after the start); the link was opened.
fn assert_answered(r: &PhaseRun, lo_ms: u64, first_ms: u64) {
    let (n, gap) = (r.starts.len(), min_gap(&r.starts));
    assert!(
        n <= 5 && gap >= 60_000,
        "answered, spaced like a delayed operation: {n} runs, min_gap {gap} ms"
    );
    let (start, due) = (r.starts.first().copied().unwrap(), r.due.unwrap());
    assert!(
        due >= start.saturating_add(lo_ms).saturating_add(60_000)
            && due <= start.saturating_add(first_ms).saturating_add(3_600_000),
        "due {} ms after the start",
        due.saturating_sub(start)
    );
    assert!(r.connects >= 1, "the link was opened");
}

/// Q300 phase rule (M7-S4d; XREVIEW-M7-S4 S4-1, S4-2): a relay `ERR` is answered, through the product `Driver::control`.
#[test]
fn driver_control_relay_err_is_answered() {
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_transport::Error as TransportError;
    let kind = ControlKind::LinkPut(1);
    let r = phase_run(44, kind, RelayId(0), 1, 5_000, |m| {
        m.answer = Some((kind, TransportError::Rate));
    });
    assert_answered(&r, 0, 5_000);
}

/// Q300 phase rule (M7-S4d; XREVIEW-M7-S4 S4-1, S4-2): a link closed after the command is answered, through the product
/// `Driver::control`.
#[test]
fn driver_control_close_after_the_command_is_answered() {
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_transport::Error as TransportError;
    let kind = ControlKind::LinkPut(2);
    let r = phase_run(45, kind, RelayId(0), 2, 5_000, |m| {
        m.answer = Some((kind, TransportError::Closed));
    });
    assert_answered(&r, 0, 5_000);
}

/// Q300 phase rule (M7-S4d; XREVIEW-M7-S4 S4-1, S4-2): an unfitting or garbled answer is answered, through the product
/// `Driver::control`.
#[test]
fn driver_control_unfitting_answer_is_answered() {
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_transport::Error as TransportError;
    let kind = ControlKind::LinkGetOwner(3);
    let r = phase_run(46, kind, RelayId(0), 3, 5_000, |m| {
        m.answer = Some((kind, TransportError::Rejected));
    });
    assert_answered(&r, 0, 5_000);
}

/// Q300 phase rule (M7-S4d; XREVIEW-M7-S4 S4-1, S4-2): a relay that never answers, until the timeout, is answered, through
/// the product `Driver::control`.
#[test]
fn driver_control_stall_until_the_timeout_is_answered() {
    use secmp_client_core::scheduler::run::CONNECT_TIMEOUT_MS;
    use secmp_client_core::scheduler::types::{ControlKind, QueueId, RelayId};
    let kind = ControlKind::QueueNew(QueueId(904));
    let first = CONNECT_TIMEOUT_MS.saturating_add(5_000);
    let r = phase_run(47, kind, RelayId(0), 904, first, |m| m.hang.push(kind));
    assert_answered(&r, CONNECT_TIMEOUT_MS, first);
}

/// Q300 phase rule (M7-S4d; XREVIEW-M7-S4 S4-1, S4-2): a failure before the link is up stays link failed (CO-06), through
/// the product `Driver::control`.
#[test]
fn driver_control_failure_before_the_link_is_up_stays_link_failed() {
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    let kind = ControlKind::LinkPut(6);
    let r = phase_run(48, kind, RelayId(1), 6, 5_000, |_| {});
    assert_eq!(r.connects, 0);
    assert!(r.unanswered.is_empty());
    assert!(
        r.starts.len() >= 8,
        "retried after the back-off (CO-06): {} runs",
        r.starts.len()
    );
}

/// Q300 phase rule (M7-S4d; XREVIEW-M7-S4 S4-1, S4-2): a consuming `LINK_GET` lost after the handshake ends once, through
/// the product `Driver::control`.
#[test]
fn driver_control_consume_lost_after_the_handshake_ends_once() {
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_transport::Error as TransportError;
    let kind = ControlKind::LinkGetConsume(5);
    let r = phase_run(49, kind, RelayId(0), 5, 5_000, |m| {
        m.answer = Some((kind, TransportError::Closed));
    });
    assert_eq!(r.starts.len(), 1, "terminal");
    assert_eq!(r.due, None);
    assert_eq!(r.unanswered, vec![kind]);
    assert!(!r.done.contains(&kind));
}
