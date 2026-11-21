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

// EXT3d-1 (M8-E1, HB-64): the limit of a control operation is counted from its admission `t_a`, not from the end of
// `prepare`: no command write starts at or after `t_a + L`, and the attempt is not polled from then on.

/// The limit (ms), as the tests count it.
const L: u64 = secmp_client_core::scheduler::run::CONNECT_TIMEOUT_MS;

/// A provider whose connect is pending for `delay_ms` of virtual time (the connect and the handshake of a slow circuit).
#[derive(Clone)]
struct Late {
    inner: secmp_testkit::harness::MemProvider,
    delay_ms: u64,
}

impl secmp_transport::driver::StreamProvider for Late {
    type Stream = tokio::io::DuplexStream;

    fn connect(
        &self,
        relay: &secmp_proto::wire::inv::RelayRef,
        isolation: secmp_transport::driver::Isolation,
    ) -> impl core::future::Future<Output = Result<tokio::io::DuplexStream, secmp_transport::Error>> + Send
    {
        let (inner, relay, delay) = (self.inner.clone(), relay.clone(), self.delay_ms);
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            secmp_transport::driver::StreamProvider::connect(&inner, &relay, isolation).await
        }
    }
}

/// One control operation run through the product driver.
struct Cfg {
    seed: u64,
    kind: secmp_client_core::scheduler::types::ControlKind,
    when: secmp_client_core::scheduler::control::When,
    /// `params.control_delay_ms` (lo = hi).
    delay_ms: u64,
    /// `prepare` of `kind` awaits this long.
    prepare_ms: u64,
    /// The connect awaits this long.
    connect_ms: u64,
    /// `run` never returns.
    hang: bool,
    /// Run until this long after the first admission.
    horizon_ms: u64,
}

/// What one control operation did under the limit.
struct Limited {
    setup: Setup,
    x: TClient<Late>,
    op: secmp_client_core::scheduler::types::OpId,
    /// `t_a` of the first attempt.
    t_a: u64,
}

impl Limited {
    fn start(c: &Cfg) -> Self {
        use secmp_client_core::scheduler::types::RelayId;
        use secmp_testkit::harness::Costs;
        runtime().block_on(async {
            let setup = Setup::new();
            let late = Late {
                inner: setup.provider.clone(),
                delay_ms: c.connect_ms,
            };
            let params = Params {
                control_delay_ms: (c.delay_ms, c.delay_ms),
                ..Params::default()
            };
            let mut x = TClient::with_provider(
                &setup,
                late,
                Mode::Strict,
                params,
                c.seed,
                Costs::default(),
                0,
            );
            let t0 = setup.now();
            {
                let mut m = x.control.lock().unwrap();
                m.prepare_wait_kind.push((c.kind, c.prepare_ms));
                if c.hang {
                    m.hang.push(c.kind);
                }
            }
            let op = x
                .sched
                .schedule_control(t0, c.kind, RelayId(0), 1, c.when)
                .unwrap();
            x.run_until(t0.saturating_add(c.delay_ms).saturating_add(1_000))
                .await;
            let t_a = x
                .driver
                .log()
                .unwrap()
                .admitted
                .iter()
                .find_map(|(o, t)| (*o == op).then_some(*t))
                .expect("admitted");
            x.run_until(t_a.saturating_add(c.horizon_ms)).await;
            Limited { setup, x, op, t_a }
        })
    }

    /// `(time, how)` of every report of the operation to the scheduler.
    fn ends(&self) -> Vec<(u64, secmp_client_core::scheduler::run::ControlEnd)> {
        let log = self.x.driver.log().unwrap();
        log.controls
            .iter()
            .filter(|(_, o, _)| *o == self.op)
            .map(|(t, _, e)| (*t, *e))
            .collect()
    }

    /// The times `run` was entered for `kind`.
    fn runs(&self, kind: secmp_client_core::scheduler::types::ControlKind) -> Vec<u64> {
        let m = self.x.control.lock().unwrap();
        m.run_entered
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, t)| *t)
            .collect()
    }

    /// The first report is `want`, made at `t_a + L` (not before, not much after).
    fn assert_first_end(&self, want: secmp_client_core::scheduler::run::ControlEnd) {
        let d = self.t_a.saturating_add(L);
        let (t, end) = *self.ends().first().expect("a report");
        assert_eq!(end, want);
        assert!(
            t >= d && t <= d.saturating_add(1_000),
            "reported at t_a + {} ms",
            t.saturating_sub(self.t_a)
        );
    }
}

fn cfg(
    seed: u64,
    kind: secmp_client_core::scheduler::types::ControlKind,
    when: secmp_client_core::scheduler::control::When,
) -> Cfg {
    Cfg {
        seed,
        kind,
        when,
        delay_ms: 60_000,
        prepare_ms: 0,
        connect_ms: 0,
        hang: false,
        horizon_ms: L + 10_000,
    }
}

/// T1: a `prepare` that stalls past the limit sends nothing: no connect, `run` never entered, link failed (before the
/// link) at `t_a + L`.
#[test]
fn driver_control_prepare_stalled_past_limit_sends_nothing() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::ControlEnd;
    use secmp_client_core::scheduler::types::ControlKind;
    let kind = ControlKind::LinkPut(1);
    let r = Limited::start(&Cfg {
        prepare_ms: L + 1_000,
        ..cfg(60, kind, When::Delayed)
    });
    assert!(r.runs(kind).is_empty(), "run entered");
    assert!(r.setup.provider.connects().is_empty(), "connected");
    r.assert_first_end(ControlEnd::LinkFailed(false));
}

/// T2: `prepare` and the handshake share one limit: 100 s and 30 s do not fit in 120 s.
#[test]
fn driver_control_prepare_and_handshake_share_one_limit() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::ControlEnd;
    use secmp_client_core::scheduler::types::ControlKind;
    let kind = ControlKind::LinkPut(2);
    let r = Limited::start(&Cfg {
        prepare_ms: 100_000,
        connect_ms: 30_000,
        ..cfg(61, kind, When::Prompt)
    });
    assert!(r.runs(kind).is_empty(), "run entered");
    r.assert_first_end(ControlEnd::LinkFailed(false));
}

/// T3: a link that comes up exactly at `t_a + L` writes no command.
#[test]
fn driver_control_up_at_deadline_writes_no_command() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::ControlEnd;
    use secmp_client_core::scheduler::types::ControlKind;
    let kind = ControlKind::LinkPut(3);
    let r = Limited::start(&Cfg {
        prepare_ms: 10_000,
        connect_ms: L - 10_000,
        ..cfg(62, kind, When::Prompt)
    });
    assert!(r.runs(kind).is_empty(), "run entered");
    r.assert_first_end(ControlEnd::LinkFailed(false));
}

/// T4: a command started before the deadline is cut at it; the operation is then answered (Q300 phase rule).
#[test]
fn driver_control_command_started_before_deadline_is_cut_at_it() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::ControlEnd;
    use secmp_client_core::scheduler::types::ControlKind;
    let kind = ControlKind::LinkPut(4);
    let r = Limited::start(&Cfg {
        prepare_ms: 10_000,
        connect_ms: L - 11_000,
        hang: true,
        ..cfg(63, kind, When::Prompt)
    });
    let runs = r.runs(kind);
    assert_eq!(runs.len(), 1);
    assert!(
        runs.iter().all(|t| *t < r.t_a + L),
        "entered before the deadline"
    );
    r.assert_first_end(ControlEnd::Answered);
    assert_eq!(r.x.control.lock().unwrap().unanswered, vec![kind]);
}

/// T5: the stalled `prepare` is reported as a link failure and the operation keeps its drawn delay as the floor of its
/// next start.
#[test]
fn driver_control_stalled_prepare_reports_and_keeps_delay_floor() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::ControlEnd;
    use secmp_client_core::scheduler::types::ControlKind;
    let kind = ControlKind::LinkPut(5);
    let drawn = 200_000;
    let r = Limited::start(&Cfg {
        delay_ms: drawn,
        prepare_ms: L + 50_000,
        horizon_ms: 500_000,
        ..cfg(64, kind, When::Delayed)
    });
    r.assert_first_end(ControlEnd::LinkFailed(false));
    let starts: Vec<u64> =
        r.x.driver
            .log()
            .unwrap()
            .admitted
            .iter()
            .filter(|(o, _)| *o == r.op)
            .map(|(_, t)| *t)
            .collect();
    assert!(starts.len() >= 2, "retried: {starts:?}");
    assert!(
        starts
            .get(1)
            .is_some_and(|s| *s >= r.t_a.saturating_add(drawn)),
        "next start {starts:?} before t_a + {drawn}"
    );
}

/// T6: a `QUEUE_DEL` armed while the put's `prepare` stalls keeps its 60 s from the put's last possible command start.
#[test]
fn driver_deletion_armed_while_put_prepare_stalls_keeps_60s() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::types::{ControlKind, RelayId};
    use secmp_testkit::harness::Costs;
    runtime().block_on(async {
        let mut setup = Setup::new();
        let params = Params {
            control_delay_ms: (60_000, 60_000),
            ..Params::default()
        };
        let period = *params.periods_ms.first().unwrap();
        let mut x = TClient::new(&setup, Mode::Strict, params, 65, Costs::default(), 0);
        let t0 = setup.now();
        let (rc, _) = setup.new_queue(&mut x.pool).await;
        let q = x.sched.add_recv_queue(t0, RelayId(0), rc, period).unwrap();
        let (put, del) = (ControlKind::LinkPut(6), ControlKind::QueueDel(q));
        x.control
            .lock()
            .unwrap()
            .prepare_wait_kind
            .push((put, 170_000));
        let op = x
            .sched
            .schedule_control(t0, put, RelayId(0), 6, When::Prompt)
            .unwrap();
        x.run_until(t0 + 2_000).await;
        x.sched
            .schedule_control(setup.now(), del, RelayId(0), 6, When::AfterEmptyFetch(q))
            .unwrap();
        x.run_until(t0 + 600_000).await;
        let t_a = x
            .driver
            .log()
            .unwrap()
            .admitted
            .iter()
            .find_map(|(o, t)| (*o == op).then_some(*t))
            .unwrap();
        let m = x.control.lock().unwrap();
        let at = |k: ControlKind| -> Vec<u64> {
            m.run_entered
                .iter()
                .filter(|(c, _)| *c == k)
                .map(|(_, t)| *t)
                .collect()
        };
        let puts = at(put);
        assert!(
            puts.iter().all(|t| *t <= t_a + L),
            "put commands {puts:?}, t_a {t_a}"
        );
        let dels = at(del);
        let first_del = *dels.first().expect("the deletion ran");
        let last_put = puts.iter().copied().max().unwrap_or(t_a);
        assert!(
            first_del >= last_put + 60_000,
            "gap {} ms",
            first_del - last_put
        );
    });
}

/// T7: a prompt `LINK_PUT` obeys the same limit.
#[test]
fn driver_prompt_link_put_obeys_the_limit() {
    use secmp_client_core::scheduler::control::When;
    use secmp_client_core::scheduler::run::ControlEnd;
    use secmp_client_core::scheduler::types::ControlKind;
    let kind = ControlKind::LinkPut(7);
    let r = Limited::start(&Cfg {
        prepare_ms: L + 1_000,
        ..cfg(66, kind, When::Prompt)
    });
    assert!(r.runs(kind).is_empty(), "run entered");
    assert!(r.setup.provider.connects().is_empty(), "connected");
    r.assert_first_end(ControlEnd::LinkFailed(false));
}
