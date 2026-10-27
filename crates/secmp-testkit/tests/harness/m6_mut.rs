// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests that kill the mutants PR run #156 left undocumented in Phase-B code (WEISUNG M6-CI-9); each names the mutant it is
//! for. Evidence table: `docs/reviews/M06-evidence/mutants-156.md`.

use secmp_client_core::scheduler::control::{ControlOps, OpSpec, When};
use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{ControlKind, OpId, Output, QueueId, RelayId};
use secmp_client_core::timing::{TimingRng, sample_with};

use crate::m6_sched_bal::NoCells;

fn spec(kind: ControlKind, related: u64, when: When) -> OpSpec {
    OpSpec {
        kind,
        relay: RelayId(0),
        related,
        when,
    }
}

/// `control.rs:92` (`ControlOps::is_empty` → `false`): nothing waits before an operation is queued and after it is done.
#[test]
fn control_ops_is_empty_follows_the_queue() {
    let params = Params::default();
    let mut rng = TimingRng::seeded(1);
    let mut ops = ControlOps::new();
    assert!(ops.is_empty());
    assert_eq!(ops.len(), 0);
    ops.schedule(
        &params,
        &mut rng,
        OpId(1),
        0,
        spec(ControlKind::LinkPut(1), 1, When::Prompt),
    )
    .unwrap();
    assert!(!ops.is_empty());
    assert_eq!(ops.len(), 1);
    ops.done(OpId(1));
    assert!(ops.is_empty());
}

/// `control.rs:209` (`==` → `!=` in `take_due`, the `last_start` entry of the operation's correlation): of two delayed
/// operations of one correlation that are overdue together only the first starts per call, the second is rebased on its
/// start — also when another correlation has started before (the mutant records the start under that one).
#[test]
fn take_due_records_the_start_under_the_operations_correlation() {
    let params = Params::default();
    let mut rng = TimingRng::seeded(2);
    let mut ops = ControlOps::new();
    let mut put = |id: u64, kind, related, when| {
        ops.schedule(&params, &mut rng, OpId(id), 0, spec(kind, related, when))
            .unwrap();
    };
    put(1, ControlKind::LinkPut(9), 2, When::Prompt);
    put(2, ControlKind::QueueNew(QueueId(1)), 1, When::Delayed);
    put(3, ControlKind::QueueDel(QueueId(1)), 1, When::Delayed);
    let now = 10_000_000;
    let due: Vec<OpId> = ops.take_due(now).into_iter().map(|d| d.id).collect();
    assert_eq!(due, vec![OpId(1), OpId(2)], "the third is rebased");
    let later = ops.due_of(OpId(3)).unwrap();
    assert!(
        later > now && later >= now + params.control_delay_ms.0,
        "{later}"
    );
    let again: Vec<OpId> = ops.take_due(later).into_iter().map(|d| d.id).collect();
    assert_eq!(again, vec![OpId(3)]);
}

/// `core/mod.rs:1611` (`Scheduler::control_failed` → `Ok(())`, which timed out in CI): an operation whose link failed is not
/// left running — it is due again within the back-off cap. Bounded: one call and one poll, no waiting loop.
#[test]
fn control_failed_makes_the_operation_due_again() {
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(3));
    let op = sched
        .schedule_control(0, ControlKind::LinkPut(1), RelayId(0), 1, When::Prompt)
        .unwrap();
    let started = |sched: &mut Scheduler, t: u64| -> Vec<OpId> {
        sched
            .poll(t, &mut NoCells)
            .unwrap()
            .into_iter()
            .filter_map(|o| match o {
                Output::Control { op, .. } => Some(op),
                _ => None,
            })
            .collect()
    };
    assert_eq!(started(&mut sched, 0), vec![op]);
    assert!(
        started(&mut sched, 1).is_empty(),
        "running: not started twice"
    );
    sched.control_failed(10, op, false).unwrap();
    let cap = Params::default().backoff_cap_ms;
    assert_eq!(started(&mut sched, 10 + cap + 1), vec![op]);
}

/// `timing.rs:47` (`sample_with` → `None`): an accepted draw gives `x mod span + lo`, a draw at or above the ceiling is rejected.
#[test]
fn sample_with_accepts_below_and_rejects_at_the_ceiling() {
    assert_eq!(sample_with(5, 10, 3, 9), Some(12));
    assert_eq!(sample_with(0, 7, 4, 8), Some(7));
    assert_eq!(sample_with(8, 7, 4, 8), None);
    assert_eq!(sample_with(u64::MAX, 0, 6, 12), None);
}

/// `driver/session.rs:209` (`AsyncSession::is_closed` → `true`): the async link of a fresh connection, and after a `PING`
/// that the relay answered, is open.
#[test]
fn async_link_is_open_after_connect_and_ping() {
    use secmp_testkit::harness::EntropyPool;

    use crate::m6_tokio::{Setup, runtime};
    runtime().block_on(async {
        let mut setup = Setup::new();
        let mut pool = EntropyPool::new("m6-mut-async", 0);
        let mut t = setup.transport(&mut pool).await;
        assert!(!t.is_closed());
        t.ping().await.unwrap();
        assert!(!t.is_closed());
    });
}

/// A stream whose read side ends (EOF) after `left` bytes; writes pass.
struct Cut {
    inner: tokio::io::DuplexStream,
    left: usize,
}

impl tokio::io::AsyncRead for Cut {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.left == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let mut limited = buf.take(self.left);
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut limited);
        let n = limited.filled().len();
        buf.advance(n);
        self.left = self.left.saturating_sub(n);
        polled
    }
}

impl tokio::io::AsyncWrite for Cut {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `driver/session.rs:209`, `relay_queue.rs:66` (`is_closed` → `false`): an async link whose stream ends right after the
/// handshake (no answer to the first command) fails that command with `Closed` and reports closed.
#[test]
fn async_link_reports_closed_when_the_stream_ends() {
    use secmp_client_core::clock::Clock as _;
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::Error;
    use secmp_transport::driver::{AsyncRelayQueueTransport, StreamProvider as _};

    use crate::m6_tokio::{Setup, runtime};
    // the relay's handshake bytes: RELAYINFO 1744 + HS2 1156
    const RELAY_HANDSHAKE: usize = 1744 + 1156;
    runtime().block_on(async {
        let mut setup = Setup::new();
        let iso = setup.iso();
        let stream = setup
            .provider
            .connect(&setup.relay.relay_ref(), iso)
            .await
            .unwrap();
        let access = setup.relay.access_key();
        let unix = setup.relay.clock().unix_secs();
        let mut pool = EntropyPool::new("m6-mut-closed", 0);
        let mut t = AsyncRelayQueueTransport::connect(
            Cut {
                inner: stream,
                left: RELAY_HANDSHAKE,
            },
            setup.relay.relay_fp(),
            Some(&access),
            unix,
            pool.get(),
        )
        .await
        .unwrap();
        assert!(!t.is_closed());
        assert_eq!(t.ping().await.err(), Some(Error::Closed));
        assert!(t.is_closed());
    });
}

/// `core/mod.rs:960`, `952` (`==` → `!=` in `World::outcome`, which queue's entry a `FETCH_MULTI` answer's cells go to): two
/// contacts of a Balanced client each get one message from the peer, on their own queue; each conversation receives its
/// own message (cells of another queue do not decrypt, they would be dropped), and both queues are acknowledged.
#[test]
fn fetch_multi_cells_go_to_their_own_queue() {
    use secmp_client_core::scheduler::outbox::{OutMessage, Outbox};
    use secmp_crypto::Zeroizing;
    use secmp_proto::wire::cell::AppKind;

    use crate::m6_common::{client, contact, driver};
    let mut sim = driver();
    let a = client(&mut sim, Mode::Balanced, 311);
    let b = client(&mut sim, Mode::Strict, 312);
    let c1 = contact(&mut sim, a, b, 10_000, 10_000);
    let c2 = contact(&mut sim, a, b, 10_000, 10_000);
    for (n, c) in [(1_u8, &c1), (2, &c2)] {
        sim.client(b)
            .convs
            .get_mut(c.conv_b)
            .unwrap()
            .outbox_mut()
            .enqueue(
                OutMessage {
                    msg_id: [n; 16],
                    kind: AppKind::Text,
                    expire_after: 0,
                    payload: Zeroizing::new(vec![n; 30]),
                },
                0,
            );
    }
    sim.run_until(600_000);
    for (n, c) in [(1_u8, &c1), (2, &c2)] {
        let got = sim.client_ref(a).convs.get(c.conv_a).unwrap().received();
        assert_eq!(got.len(), 1, "contact {n}");
        assert_eq!(got.first().map(|m| m.msg_id), Some([n; 16]), "contact {n}");
    }
    assert!(
        sim.client_ref(a)
            .sched
            .acked(c1.a_recv)
            .is_some_and(|n| n >= 1)
    );
    assert!(
        sim.client_ref(a)
            .sched
            .acked(c2.a_recv)
            .is_some_and(|n| n >= 1)
    );
}

/// `core/mod.rs:1303`, `1312`, `1315` (`==` → `!=` in `Scheduler::remove_queue`): an unknown id is refused when only receive
/// queues exist; removing a queue ends exactly the links that were for it — in Strict the queue's own link, in Balanced the
/// relay's link only with its last queue (send or receive).
#[test]
fn remove_queue_ends_exactly_the_links_of_the_queue() {
    use secmp_client_core::scheduler::core::SchedError;
    use secmp_client_core::scheduler::core::Scheduler;

    use crate::m6_sched_bal::fresh_recv_cap;
    for (mode, links_before, after_first) in [(Mode::Strict, 2, 1), (Mode::Balanced, 1, 1)] {
        let mut sched = Scheduler::new(Params::default(), mode, TimingRng::seeded(5));
        let recv = sched
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(1), 10_000)
            .unwrap();
        let send = sched
            .add_send_queue(
                0,
                RelayId(0),
                secmp_transport::SendCap::from_route(
                    [4; 16],
                    &secmp_crypto::SecretBytes::from_slice(&[9; 32]).unwrap(),
                )
                .unwrap(),
                10_000,
            )
            .unwrap();
        assert_eq!(sched.links().len(), links_before, "{mode:?}");
        assert!(
            matches!(
                sched.remove_queue(0, QueueId(99), &mut NoCells),
                Err(SchedError::UnknownQueue)
            ),
            "{mode:?}"
        );
        sched.remove_queue(1, send, &mut NoCells).unwrap();
        assert_eq!(
            sched.links().len(),
            after_first,
            "{mode:?}: after the first"
        );
        if mode == Mode::Strict {
            // the link that stays is the receive queue's, not the removed send queue's
            assert_eq!(sched.links().first().and_then(|l| l.queue), Some(recv));
        }
        sched.remove_queue(2, recv, &mut NoCells).unwrap();
        assert_eq!(sched.links().len(), 0, "{mode:?}: after the last");
    }
    // only a receive queue: an id that is not it is unknown
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(6));
    sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(2), 10_000)
        .unwrap();
    assert!(matches!(
        sched.remove_queue(0, QueueId(99), &mut NoCells),
        Err(SchedError::UnknownQueue)
    ));
}

/// `core/mod.rs:971` (`==` → `!=` in `World::outcome`, the per-queue errors of a `FETCH_MULTI` answer): one queue of a Balanced
/// link's `FETCH_MULTI` is deleted on the relay; the relay answers that entry with `ERR_NOQUEUE` and the cells of the other as
/// usual; exactly the deleted queue is re-created (a `QUEUE_NEW` for it), the intact one is left alone.
#[test]
fn fetch_multi_error_is_attributed_to_its_own_queue() {
    use secmp_crypto::SecretBytes;
    use secmp_transport::{QueueTransport, RecvCap, RelayQueueTransport};

    use crate::m6_common::{client, contact, driver};
    let mut sim = driver();
    let a = client(&mut sim, Mode::Balanced, 301);
    let b = client(&mut sim, Mode::Strict, 302);
    let c1 = contact(&mut sim, a, b, 10_000, 10_000);
    let c2 = contact(&mut sim, a, b, 10_000, 10_000);
    sim.run_until(60_000);
    // the relay loses the queue of the second contact
    let (recv_seed, _) = *sim.client_ref(a).material.queues.get(&c2.a_recv.0).unwrap();
    let access = sim.harness().access_key();
    let fp = sim.harness().relay_fp();
    let unix = sim.harness().clock().unix();
    let stream = sim.harness_mut().open_stream().unwrap();
    let mut transport =
        RelayQueueTransport::connect(stream, fp, Some(&access), unix, sim.client(a).entropy.get())
            .unwrap();
    transport
        .delete_queue(&RecvCap::from_seed(&SecretBytes::from_slice(&recv_seed).unwrap()).unwrap())
        .unwrap();
    // past the re-creation delay (≤ 300 s) and the control delay
    sim.run_until(60_000 + 5_000_000);
    let created: Vec<QueueId> = sim
        .client_ref(a)
        .controls_done
        .iter()
        .filter_map(|(_, k)| match k {
            ControlKind::QueueNew(q) => Some(*q),
            _ => None,
        })
        .collect();
    assert!(created.contains(&c2.a_recv), "{created:?}");
    assert!(!created.contains(&c1.a_recv), "{created:?}");
}

// ---- WEISUNG M6-C1-2/-3, item 1 (PHASE C-3): survivors of PR run #160 ------------------------------------------------

use secmp_client_core::clock::{Clock, ManualClock};
use secmp_client_core::scheduler::types::{Alert, LinkEvent};
use secmp_proto::wire::frame::{ErrCode, Request, RequestCmd, Response, ResponseCmd};

use crate::m6_sched_bal::fresh_recv_cap;
use crate::m6_sched_io::Rig;
use crate::scripted::Script;

/// `clock.rs:107` (`ManualClock::set_ms` → `()`): the virtual clock moves to the time it is set to and never backwards.
#[test]
fn manual_clock_set_ms_moves_forward_never_back() {
    let clock = ManualClock::new(1_000);
    clock.set_ms(5_000);
    assert_eq!(clock.mono_ms(), 5_000);
    clock.set_ms(3_000);
    assert_eq!(clock.mono_ms(), 5_000, "never backwards");
    clock.set_ms(5_001);
    assert_eq!(clock.mono_ms(), 5_001);
    assert_eq!(clock.unix_secs(), 1_005, "unix time follows");
}

/// `control.rs:98` (`ControlOps::kind_of` → `None` / `==` → `!=`): the kind of an operation is looked up by its own id.
#[test]
fn control_ops_kind_of_finds_the_operation_by_id() {
    let params = Params::default();
    let mut rng = TimingRng::seeded(11);
    let mut ops = ControlOps::new();
    for (id, kind) in [(1, ControlKind::LinkPut(1)), (2, ControlKind::LinkPut(2))] {
        ops.schedule(&params, &mut rng, OpId(id), 0, spec(kind, id, When::Prompt))
            .unwrap();
    }
    assert_eq!(ops.kind_of(OpId(1)), Some(ControlKind::LinkPut(1)));
    assert_eq!(ops.kind_of(OpId(2)), Some(ControlKind::LinkPut(2)));
    assert_eq!(ops.kind_of(OpId(9)), None);
}

/// `control.rs:138` (`==` → `!=` in `ControlOps::schedule`, the latest start of the same correlation): a delayed operation is
/// pushed back only by a start of its own correlation — an operation of another correlation that started later does not
/// move it beyond its own `U[1 min, 60 min]` draw.
#[test]
fn control_ops_schedule_ignores_the_starts_of_other_correlations() {
    let params = Params::default();
    let mut rng = TimingRng::seeded(12);
    let mut ops = ControlOps::new();
    ops.schedule(
        &params,
        &mut rng,
        OpId(1),
        0,
        spec(ControlKind::LinkPut(9), 2, When::Prompt),
    )
    .unwrap();
    let started = 50_000_000;
    assert_eq!(ops.take_due(started).len(), 1, "correlation 2 starts late");
    ops.schedule(
        &params,
        &mut rng,
        OpId(2),
        0,
        spec(ControlKind::QueueNew(QueueId(1)), 1, When::Delayed),
    )
    .unwrap();
    let due = ops.due_of(OpId(2)).unwrap();
    assert!(
        due <= params.control_delay_ms.1,
        "due {due} is within its own draw, not after the start of correlation 2"
    );
}

/// `core/mod.rs:1646` (`||` → `&&` twice in `Scheduler::owner_status`): any one of `present`, `consumed`, `expired` ends the
/// matter; only `{0, 0, 0}` schedules the re-issue.
#[test]
fn owner_status_schedules_only_when_nothing_is_known() {
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(13));
    for (present, consumed, expired) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (true, true, true),
    ] {
        let got = sched
            .owner_status(0, RelayId(0), 7, present, consumed, expired)
            .unwrap();
        assert!(got.is_none(), "{present} {consumed} {expired}");
    }
    let op = sched
        .owner_status(0, RelayId(0), 7, false, false, false)
        .unwrap();
    assert!(op.is_some());
}

/// `core/mod.rs:1604` (`Scheduler::control_done` → `()`): a finished operation is gone.
#[test]
fn control_done_removes_the_operation() {
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(14));
    let op = sched
        .schedule_control(0, ControlKind::LinkPut(1), RelayId(0), 1, When::Prompt)
        .unwrap();
    assert!(sched.control_due(op).is_some());
    sched.control_done(op);
    assert!(sched.control_due(op).is_none());
}

fn answer(request: &Request, cmd: ResponseCmd) -> Vec<Response> {
    vec![Response {
        cmd_seq: request.cmd_seq,
        cmd,
    }]
}

/// `core/mod.rs:1191` (`&&` → `||` and `→ true` in `Scheduler::route_dead`): of three queues on one Balanced link only the
/// one whose `SEND` the relay answered with `ERR_NOQUEUE` is dead; a live and an unknown queue are not.
#[test]
fn route_dead_marks_only_the_queue_the_relay_refused() {
    let script: Script = Box::new(|request, n| {
        if n == 0 {
            answer(request, ResponseCmd::Err(ErrCode::NoQueue))
        } else {
            answer(
                request,
                ResponseCmd::OkSend {
                    cell_id: u64::try_from(n).unwrap(),
                    evicted: None,
                },
            )
        }
    });
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(script, Mode::Balanced, params);
    let queues = crate::m6_sched_io::rig_with_three_queues(&mut rig);
    rig.run_to(35_000);
    assert!(rig.sched.route_dead(*queues.first().unwrap()), "Q0 is dead");
    assert!(!rig.sched.route_dead(*queues.get(1).unwrap()), "Q1 is live");
    assert!(!rig.sched.route_dead(*queues.get(2).unwrap()), "Q2 is live");
    assert!(!rig.sched.route_dead(QueueId(99)), "unknown");
}

/// `core/mod.rs:903`, `:906` (the `Auth` and `Rate` arms of `World::queue_error` deleted): a `FETCH_MULTI` answered with an
/// `Auth` error entry for the recv queue, then one answered with `ERR_RATE`, raises that queue's two alerts.
#[test]
fn queue_error_raises_the_auth_and_rate_alerts_of_a_recv_queue() {
    use secmp_proto::link::FETCH_MULTI_BATCH;
    use secmp_proto::wire::cell::Cell;
    use secmp_proto::wire::frame::{Cellr, CellrError};
    let cap = fresh_recv_cap(1);
    let rid = *cap.queue().rid();
    let mut fetches = 0_usize;
    let script: Script = Box::new(move |request, n| match &request.cmd {
        RequestCmd::FetchMulti { .. } => {
            fetches += 1;
            if fetches == 1 {
                let cell = || Cell::from_bytes(&[3; 4096]).unwrap();
                let mut frames = vec![Response {
                    cmd_seq: request.cmd_seq,
                    cmd: ResponseCmd::Cellr(Cellr::Error {
                        error: CellrError::Auth,
                        rid,
                        cell: cell(),
                    }),
                }];
                while frames.len() < FETCH_MULTI_BATCH {
                    frames.push(Response {
                        cmd_seq: request.cmd_seq,
                        cmd: ResponseCmd::Cellr(Cellr::Dummy { cell: cell() }),
                    });
                }
                frames
            } else {
                answer(request, ResponseCmd::Err(ErrCode::Rate))
            }
        }
        _ => answer(
            request,
            ResponseCmd::OkSend {
                cell_id: u64::try_from(n).unwrap().saturating_add(1),
                evicted: None,
            },
        ),
    });
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(script, Mode::Balanced, params);
    let recv = rig
        .sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(1), 10_000)
        .unwrap();
    rig.run_to(40_000);
    let alerts: Vec<Alert> = rig
        .events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Alert(q, a) if *q == recv => Some(*a),
            _ => None,
        })
        .collect();
    assert!(alerts.contains(&Alert::QueueAuth), "{alerts:?}");
    assert!(alerts.contains(&Alert::QueueRate), "{alerts:?}");
}

use secmp_client_core::scheduler::core::{LinkKind, SchedError};
use secmp_transport::SendCap;

use crate::m6_sched_io::{Call, ok_script};

/// A script that never answers: a written `SEND` stays in flight.
fn silent_script() -> Script {
    Box::new(|_: &Request, _: usize| Vec::new())
}

/// `core/mod.rs:241` (`<impl Release for Deferred>::release_failed` → `()`): a link the driver reports closed while its
/// `SEND` is unanswered hands that cell back as failed — at the next `work`, which flushes what `poll_due`-phase teardowns
/// noted.
#[test]
fn release_failed_by_a_closed_link_reaches_the_cell_source() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(silent_script(), Mode::Strict, params);
    rig.run_to(10_000);
    assert_eq!(
        rig.writes,
        vec![10_000],
        "the SEND is written and unanswered"
    );
    let link = rig.link.unwrap();
    let outs = rig.sched.on_closed(link, 10_001).unwrap();
    rig.apply(outs);
    let _ = rig.sched.work(10_002, &mut rig.src).unwrap();
    assert!(
        rig.src.calls.contains(&Call::Failed(SendFailure::Unknown)),
        "{:?}",
        rig.src.calls
    );
}

/// `core/mod.rs:224` (`<impl Release for S>::release_failed` → `()`): a teardown made inside a call that has the cell source
/// (a mode change) hands the unanswered `SEND` back as failed at once.
#[test]
fn release_failed_by_a_mode_change_reaches_the_cell_source() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(silent_script(), Mode::Strict, params);
    rig.run_to(10_000);
    assert_eq!(rig.writes, vec![10_000]);
    let _ = rig
        .sched
        .set_mode(10_001, Mode::Balanced, &mut rig.src)
        .unwrap();
    assert!(
        rig.src.calls.contains(&Call::Failed(SendFailure::Unknown)),
        "{:?}",
        rig.src.calls
    );
}

/// `core/mod.rs:1378` (`!` deleted in `Scheduler::set_queue_period`): a period outside `PERIODS` is refused, one inside is taken.
#[test]
fn set_queue_period_accepts_only_the_periods_of_the_spec() {
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(21));
    let cap = SendCap::from_route(
        [1; 16],
        &secmp_crypto::SecretBytes::from_slice(&[9; 32]).unwrap(),
    )
    .unwrap();
    let q = sched.add_send_queue(0, RelayId(0), cap, 10_000).unwrap();
    assert!(matches!(
        sched.set_queue_period(0, q, 15_000, &mut NoCells),
        Err(SchedError::BadPeriod)
    ));
    assert!(sched.set_queue_period(0, q, 20_000, &mut NoCells).is_ok());
    assert!(matches!(
        sched.set_queue_period(0, QueueId(99), 20_000, &mut NoCells),
        Err(SchedError::UnknownQueue)
    ));
}

/// `core/mod.rs:1469` (`&&` → `||` in `Scheduler::change_mode`, the effective mode `direct && mode == Strict`): Strict over
/// Tor is Strict — a client in Balanced that goes Strict gets its per-queue links, a send link of its own.
#[test]
fn change_mode_to_strict_over_tor_gives_per_queue_links() {
    let mut sched = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::seeded(22));
    let cap = SendCap::from_route(
        [1; 16],
        &secmp_crypto::SecretBytes::from_slice(&[9; 32]).unwrap(),
    )
    .unwrap();
    sched.add_send_queue(0, RelayId(0), cap, 10_000).unwrap();
    assert!(
        !sched.links().iter().any(|l| l.kind == LinkKind::Send),
        "Balanced: one relay link"
    );
    let _ = sched.set_mode(1, Mode::Strict, &mut NoCells).unwrap();
    assert!(
        sched.links().iter().any(|l| l.kind == LinkKind::Send),
        "Strict: a send link per queue"
    );
}

/// `core/mod.rs:518` (`>` → `>=` in `World::tick`, the lateness bound): a driver that wakes exactly `driver_jitter_ms` after
/// the tick still writes it; one millisecond later the tick is an overrun.
#[test]
fn tick_tolerates_a_wake_exactly_at_the_jitter_bound() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let jitter = params.driver_jitter_ms;
    let mut on_time = Rig::with(ok_script(), Mode::Strict, params.clone());
    on_time.run_to(9_999);
    on_time.poll_at(10_000 + jitter);
    assert_eq!(on_time.writes, vec![10_000], "written at its own tick time");
    assert_eq!(on_time.sched.overruns(), 0);
    let mut late = Rig::with(ok_script(), Mode::Strict, params);
    late.run_to(9_999);
    late.poll_at(10_001 + jitter);
    assert!(late.writes.is_empty());
    assert_eq!(late.sched.overruns(), 1);
}

/// `core/mod.rs:527` (`||` → `&&` in `World::tick`, a missing frame): a tick whose `SEND` the cell source did not have ready is
/// an overrun — it writes nothing and the link goes down.
#[test]
fn tick_without_a_prepared_send_is_an_overrun() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(ok_script(), Mode::Strict, params);
    rig.src.ready_at = u64::MAX;
    rig.remake = Some(ok_script);
    rig.run_to(10_000);
    assert!(rig.writes.is_empty(), "nothing is written");
    assert_eq!(rig.sched.overruns(), 1);
    assert!(
        rig.events
            .iter()
            .any(|e| matches!(e, LinkEvent::TornDown(_, Reason::Overrun)))
    );
}

/// `core/mod.rs:404` (`World::relay_has_recv` → `false`, `==` → `!=` at :399): a Balanced link whose relay has a recv-queue needs
/// a `FETCH_MULTI` at every tick — when its frame was not prepared (the pass at the `FETCH` lead was skipped, the previous
/// `FETCH` is still unanswered) the tick is an overrun instead of a tick with a `SEND` alone.
#[test]
fn relay_with_a_recv_queue_needs_its_fetch_at_every_tick() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(silent_script(), Mode::Balanced, params);
    rig.remake = Some(ok_script);
    rig.sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(5), 10_000)
        .unwrap();
    rig.run_to(10_000);
    assert_eq!(
        rig.writes.len(),
        2,
        "tick 1: SEND and FETCH_MULTI: {:?}",
        rig.writes
    );
    // jump over the pass at the FETCH lead (19 s) to the tick at 20 s: the first FETCH is still unanswered
    rig.run_to(18_000);
    rig.poll_at(20_000);
    assert_eq!(rig.sched.overruns(), 1, "tick 2 has no FETCH_MULTI frame");
    assert_eq!(rig.writes.len(), 2, "and writes nothing: {:?}", rig.writes);
}

/// `core/mod.rs:532` (`||` → `&&` in `World::tick`, `needs_fetch` of a Strict recv link): a recv link whose `FETCH` was not
/// prepared (the pass at the lead skipped, the previous `FETCH` unanswered) has a missing frame at its tick: an overrun.
#[test]
fn recv_link_needs_its_fetch_at_every_tick() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(silent_script(), Mode::Strict, params);
    rig.remake = Some(ok_script);
    let outs = rig.sched.remove_queue(0, QueueId(0), &mut rig.src).unwrap();
    rig.apply(outs);
    rig.sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(6), 10_000)
        .unwrap();
    rig.run_to(10_000);
    assert_eq!(rig.writes, vec![10_000], "tick 1: the FETCH");
    rig.run_to(18_000);
    rig.poll_at(20_000);
    assert_eq!(rig.sched.overruns(), 1, "tick 2 has no FETCH frame");
    assert_eq!(rig.writes.len(), 1, "and writes nothing: {:?}", rig.writes);
}

/// `core/mod.rs:1405` (`!` deleted in the `retain` of `Scheduler::set_queue_period`, which keeps only the replaced links): a Strict
/// queue's new period replaces the link of that queue only — the other queue's link is left exactly as it was.
#[test]
fn set_queue_period_replaces_only_the_links_of_its_queue() {
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(23));
    let recv = sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(40), 10_000)
        .unwrap();
    let cap = SendCap::from_route(
        [2; 16],
        &secmp_crypto::SecretBytes::from_slice(&[9; 32]).unwrap(),
    )
    .unwrap();
    let send = sched.add_send_queue(0, RelayId(0), cap, 10_000).unwrap();
    let start_of = |sched: &Scheduler, q: QueueId| {
        sched
            .links()
            .into_iter()
            .find(|l| l.queue == Some(q))
            .map(|l| l.starts_at)
    };
    let before = start_of(&sched, recv);
    assert!(before.is_some());
    let outs = sched
        .set_queue_period(1, send, 20_000, &mut NoCells)
        .unwrap();
    assert!(outs.is_empty(), "nothing connected yet");
    assert_eq!(sched.links().len(), 2, "one link per queue");
    assert_eq!(
        start_of(&sched, recv),
        before,
        "the recv queue's link was not touched"
    );
}

/// `core/mod.rs:1995` (`==` → `!=` in `Scheduler::on_frame`, the test that no other request of the tick is outstanding): a
/// tick counts as in flight until *all* its responses are in. Only the `SEND` of tick 1 is answered, its `FETCH_MULTI` and
/// everything after stay open: the link is torn down at its third tick (two ticks outstanding), not one tick later.
#[test]
fn in_flight_counts_a_tick_until_every_answer_is_in() {
    let script: Script = Box::new(|request: &Request, n: usize| {
        if n == 0 {
            answer(
                request,
                ResponseCmd::OkSend {
                    cell_id: 1,
                    evicted: None,
                },
            )
        } else {
            Vec::new()
        }
    });
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(script, Mode::Balanced, params);
    rig.remake = Some(ok_script);
    rig.sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(7), 10_000)
        .unwrap();
    rig.run_to(30_000);
    assert!(
        rig.events
            .iter()
            .any(|e| matches!(e, LinkEvent::TornDown(_, Reason::InFlight))),
        "{:?}",
        rig.events
    );
}

/// `core/mod.rs:842` (`World::begin_work` → `()`): the frames a `work` call built are open only until the driver reports its
/// end. A later `work` closes them: a frame built at the start is not made late by the end of a long later pass.
#[test]
fn begin_work_closes_the_frames_of_the_previous_pass() {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(ok_script(), Mode::Strict, params);
    // the connect pass builds the first frame and nobody reports its end
    let outs = rig.sched.poll_due(0).unwrap();
    rig.apply(outs);
    let _ = rig.sched.work(5_000, &mut rig.src).unwrap();
    rig.sched.prepared_until(10_500);
    rig.poll_at(10_000);
    assert_eq!(
        rig.writes,
        vec![10_000],
        "the frame built at the link's start is on time"
    );
    assert_eq!(rig.sched.overruns(), 0);
}

/// `core/mod.rs:751` (`>` → `>=` in `World::prepare_fetch`, the 32-queue limit of a `FETCH_MULTI`): exactly 32 recv-queues on a
/// Balanced relay link are fetched with one `FETCH_MULTI` of 32 entries at every tick.
#[test]
fn prepare_fetch_takes_exactly_thirty_two_queues() {
    use std::cell::Cell;
    use std::rc::Rc;
    let widest = Rc::new(Cell::new(0_usize));
    let seen = Rc::clone(&widest);
    let script: Script = Box::new(move |request: &Request, n: usize| match &request.cmd {
        RequestCmd::FetchMulti { entries } => {
            seen.set(seen.get().max(entries.len()));
            (0..secmp_proto::link::FETCH_MULTI_BATCH)
                .map(|_| Response {
                    cmd_seq: request.cmd_seq,
                    cmd: ResponseCmd::Cellr(secmp_proto::wire::frame::Cellr::Dummy {
                        cell: secmp_proto::wire::cell::Cell::from_bytes(&[1; 4096]).unwrap(),
                    }),
                })
                .collect()
        }
        _ => answer(
            request,
            ResponseCmd::OkSend {
                cell_id: u64::try_from(n).unwrap().saturating_add(1),
                evicted: None,
            },
        ),
    });
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(script, Mode::Balanced, params);
    for n in 1..=32_u32 {
        rig.sched
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(100 + n), 80_000)
            .unwrap();
    }
    rig.run_to(10_000);
    assert_eq!(widest.get(), 32, "one FETCH_MULTI of 32 entries");
    assert_eq!(rig.sched.overruns(), 0);
}

/// `run.rs:1300` (`Driver::release_unused` → `()`): a cell the worker prepared after the core stopped taking cells (the link was
/// reported closed while the job ran) goes back to the source as a discard when the run ends.
#[test]
fn release_unused_hands_the_untaken_cell_back() {
    runtime().block_on(async {
        // the shipped phase (U[0, 3 min]): a reconnect is not immediate, so no new link takes the cell
        let setup = Setup::new();
        let provider = Holding::new(setup.provider.clone(), usize::MAX, None, 0);
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(10_000, 10_000)],
            pool: false,
            seed: 66,
        };
        let x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            Params::default(),
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let t0 = rig.setup.now();
        let mut t = t0;
        let send = loop {
            t = t.saturating_add(5_000);
            assert!(t < t0 + 600_000, "the send link never came up");
            rig.x.run_until(t).await;
            if let Some(l) = rig
                .x
                .sched
                .links()
                .into_iter()
                .find(|l| l.kind == LinkKind::Send && l.t_up.is_some())
            {
                break l;
            }
        };
        let (link, tick) = (send.id.unwrap(), send.t_up.unwrap() + 10_000);
        // the pass at the first tick asks the worker for the next cell and returns with that job in flight
        rig.x.run_until(tick).await;
        let outs = rig.x.sched.on_closed(link, tick).unwrap();
        rig.x.driver.submit(&mut rig.x.sched, outs).unwrap();
        // the job's result arrives, nobody takes the cell
        rig.x.run_until(tick + 100).await;
        let notes = |rig: &TokioRig<Holding>| {
            rig.x
                .jobs
                .lock()
                .unwrap()
                .iter()
                .filter(|j| j.kind == b'N')
                .count()
        };
        let before = notes(&rig);
        rig.x.driver.release_unused();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(notes(&rig) > before, "a discard reached the worker");
    });
}

/// `core/mod.rs:1114` (the guard `up.id == link` of the test accessor `Scheduler::unwritten_len` → `true`): the ledger of the
/// named link, not of the first up link. A Strict client with a 10-s send link and a 40-s recv link, no completion reported:
/// at 25 s the send link has handed out two frames, the recv link none.
#[test]
fn unwritten_len_is_the_ledger_of_the_named_link() {
    use crate::m6_common::{client_with, contact, driver};
    let mut sim = driver();
    sim.report_written(false);
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let a = client_with(&mut sim, Mode::Strict, params, 351);
    let b = client_with(&mut sim, Mode::Strict, Params::default(), 352);
    contact(&mut sim, a, b, 10_000, 40_000);
    sim.run_until(25_000);
    let links = sim.client_ref(a).sched.links();
    let id_of = |kind: LinkKind| links.iter().find(|l| l.kind == kind).and_then(|l| l.id);
    let (send, recv) = (
        id_of(LinkKind::Send).unwrap(),
        id_of(LinkKind::Recv).unwrap(),
    );
    let sched = &sim.client_ref(a).sched;
    assert_eq!(sched.unwritten_len(send), Some(2));
    assert_eq!(sched.unwritten_len(recv), Some(0));
    assert_eq!(sched.unwritten_len(LinkId(9_999)), None);
}

// ---- pool, outbox, timing ----------------------------------------------------------------------------------------------

use secmp_client_core::scheduler::outbox::{MemPersist, Outbox, Persist, PersistKind};
use secmp_client_core::scheduler::pool::QueuePool;
use secmp_client_core::timing::Unavailable;

/// `pool.rs:53` (`>` → `>=` in `QueuePool::missing`) and `pool.rs:114` (`is_spare` → `true` / `false`): a relay with every
/// spare created or under way is not listed (no creation "missing: 0"); a queue is a spare only once its creation succeeded.
#[test]
fn queue_pool_lists_only_relays_that_are_short_and_knows_its_spares() {
    let relay = RelayId(0);
    let mut pool = QueuePool::new(2);
    pool.manage(relay);
    assert_eq!(pool.missing(), vec![(relay, 2)]);
    pool.creating(relay, QueueId(1));
    assert_eq!(pool.missing(), vec![(relay, 1)]);
    pool.creating(relay, QueueId(2));
    assert!(pool.missing().is_empty(), "two under way: nothing missing");
    assert!(!pool.is_spare(QueueId(1)), "under way is not a spare");
    assert_eq!(pool.created(QueueId(1)), Some(relay));
    assert!(pool.is_spare(QueueId(1)));
    assert!(!pool.is_spare(QueueId(2)));
    assert!(!pool.is_spare(QueueId(9)));
    assert!(pool.missing().is_empty(), "one spare and one under way");
}

/// `outbox.rs:278` (`MemPersist::commits` → `0` / `1`): the count of successful commits.
#[test]
fn mem_persist_counts_its_commits() {
    let mut persist = MemPersist::new();
    assert_eq!(persist.commits(), 0);
    persist.commit(PersistKind::Send, b"one").unwrap();
    assert_eq!(persist.commits(), 1);
    persist.commit(PersistKind::Receive, b"two").unwrap();
    persist.commit(PersistKind::Send, b"three").unwrap();
    assert_eq!(persist.commits(), 3);
    persist.set_failing(true);
    assert!(persist.commit(PersistKind::Send, b"x").is_err());
    assert_eq!(persist.commits(), 3, "a failed commit is not counted");
}

/// `outbox.rs:302` (`MemPersist::set_durable` → `()`, new in PR run 163): seeding the durable state (a restart from a snapshot)
/// is read back through `durable()`, is not a commit, and is replaced by the next commit.
#[test]
fn mem_persist_set_durable_is_read_back() {
    let mut persist = MemPersist::new();
    assert_eq!(persist.durable(), None);
    persist.set_durable(b"snapshot");
    assert_eq!(persist.durable(), Some(&b"snapshot"[..]));
    assert_eq!(persist.commits(), 0, "seeding is not a commit");
    persist.set_durable(b"newer snapshot");
    assert_eq!(persist.durable(), Some(&b"newer snapshot"[..]));
    persist.commit(PersistKind::Send, b"after").unwrap();
    assert_eq!(persist.durable(), Some(&b"after"[..]));
    assert_eq!(persist.commits(), 1);
}

/// `timing.rs:113` (`^` → `|` in `TimingRng::next_u64`): the seeded test generator is `SplitMix64` — the first outputs of
/// the public-domain reference <https://prng.di.unimi.it/splitmix64.c> for the seeds 0 and 1234567.
#[test]
fn timing_rng_seeded_is_splitmix64() {
    let full = |rng: &mut TimingRng| rng.uniform(0, u64::MAX).unwrap();
    let mut zero = TimingRng::seeded(0);
    assert_eq!(full(&mut zero), 0xe220_a839_7b1d_cdaf);
    assert_eq!(full(&mut zero), 0x6e78_9e6a_a1b9_65f4);
    assert_eq!(full(&mut zero), 0x06c4_5d18_8009_454f);
    let mut other = TimingRng::seeded(1_234_567);
    for expected in [
        6_457_827_717_110_365_317_u64,
        3_203_168_211_198_807_973,
        9_817_491_932_198_370_423,
        4_593_380_528_125_082_431,
        16_408_922_859_458_223_821,
    ] {
        assert_eq!(full(&mut other), expected);
    }
}

/// `timing.rs:18` (`Display for Unavailable` → `Ok(Default::default())`): the message of the error.
#[test]
fn unavailable_displays_its_message() {
    assert_eq!(Unavailable.to_string(), "randomness unavailable");
}

// ---- conversation ------------------------------------------------------------------------------------------------------

use secmp_client_core::scheduler::types::{CellSource, SendFailure};
use secmp_proto::wire::cell::Cell;

use crate::m6_outbox::{A_RECV, A_SEND, B_RECV, B_SEND, pair, text};

/// `conversation.rs:249`, `:254` (`set_send_queue`, `set_recv_queue` → `()`): re-binding the queues re-routes the cell source —
/// the conversation is served on its new send queue and not on the old one, and receives on its new recv queue.
#[test]
fn conversation_rebinding_the_queues_redirects_the_cell_source() {
    let (mut convs, a, b) = pair(31);
    convs
        .get_mut(a)
        .unwrap()
        .outbox_mut()
        .enqueue(text(1, 50), 0);
    convs.get_mut(a).unwrap().set_send_queue(QueueId(10));
    assert!(convs.prepare_cell(A_SEND, 10_000).unwrap().is_none());
    let cell = convs.prepare_cell(QueueId(10), 10_000).unwrap().unwrap();
    convs.get_mut(b).unwrap().set_recv_queue(QueueId(11));
    convs.deliver(QueueId(11), 1, &cell.cell).unwrap();
    assert_eq!(convs.get(b).unwrap().received().len(), 1);
    // the old recv queue of b has no conversation any more: a cell there is dropped, not decrypted
    let again = convs.prepare_cell(QueueId(10), 20_000).unwrap().unwrap();
    convs.deliver(B_RECV, 2, &again.cell).unwrap();
    assert_eq!(convs.get(b).unwrap().discarded(), 0);
}

/// `conversation.rs:310` (`discarded` → `1`): cells that do not decrypt are counted, from zero.
#[test]
fn conversation_discarded_counts_cells_that_do_not_decrypt() {
    let (mut convs, _a, b) = pair(32);
    assert_eq!(convs.get(b).unwrap().discarded(), 0);
    let junk = Cell::from_bytes(&[0x5a; 4096]).unwrap();
    convs.deliver(B_RECV, 1, &junk).unwrap();
    assert_eq!(convs.get(b).unwrap().discarded(), 1);
    convs.deliver(B_RECV, 2, &junk).unwrap();
    assert_eq!(convs.get(b).unwrap().discarded(), 2);
}

/// `conversation.rs:322…324` (`has_pending_real`: `!` deleted, `→ true`, `>` → `==` / `>=`, `&&` → `||`) and `:682`
/// (`Conversations::pending_real` → `true`): nothing real waits in a fresh conversation, a queued message and a receipt do —
/// the receipt only while receipts are on.
#[test]
fn conversation_has_pending_real_follows_the_queue_and_the_receipts() {
    let (mut convs, a, b) = pair(33);
    assert!(!convs.get(a).unwrap().has_pending_real(), "fresh");
    assert!(!convs.pending_real(A_SEND), "fresh, by queue");
    assert!(!convs.pending_real(QueueId(77)), "no such queue");
    convs
        .get_mut(a)
        .unwrap()
        .outbox_mut()
        .enqueue(text(1, 50), 0);
    assert!(convs.get(a).unwrap().has_pending_real(), "a queued message");
    assert!(convs.pending_real(A_SEND));
    let cell = convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    assert!(!convs.get(a).unwrap().has_pending_real(), "taken");
    // the peer owes a receipt
    convs.deliver(B_RECV, 1, &cell.cell).unwrap();
    assert!(convs.get(b).unwrap().has_pending_real(), "a receipt is due");
    convs.get_mut(b).unwrap().set_send_receipts(false);
    assert!(!convs.get(b).unwrap().has_pending_real(), "receipts off");
    convs.get_mut(b).unwrap().set_send_receipts(true);
    assert!(convs.get(b).unwrap().has_pending_real());
    let _ = convs.prepare_cell(B_SEND, 20_000).unwrap().unwrap();
    assert!(!convs.get(b).unwrap().has_pending_real(), "receipt sent");
}

/// `conversation.rs:336` (`durable` → `[]`, `[0]`, `[1]`): the durable ratchet state is the serialised state and changes with
/// every sealed cell.
#[test]
fn conversation_durable_follows_each_commit() {
    let (mut convs, a, _b) = pair(34);
    let first = convs.get(a).unwrap().durable().to_vec();
    assert!(first.len() > 100, "{}", first.len());
    convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    let second = convs.get(a).unwrap().durable().to_vec();
    assert!(second.len() > 100);
    assert_ne!(first, second);
}

/// `conversation.rs:340` (`ts` → `0` / `1`): the sender's clock in the cell is the Unix origin plus the elapsed whole
/// seconds — read by the peer's ratchet from the opened content.
#[test]
fn conversation_cells_carry_the_senders_clock() {
    use secmp_crypto::SecretBytes;
    use secmp_proto::tr::{Entropy, FixedEntropy};
    use secmp_testkit::harness::{EntropyPool, START_UNIX, ratchet_pair};
    type Conv = secmp_client_core::scheduler::conversation::Conversation<
        secmp_client_core::scheduler::outbox::MemOutbox,
        MemPersist,
        EntropyPool,
    >;
    let sk = SecretBytes::from_slice(&[7_u8; 32]).unwrap();
    let mut pool = EntropyPool::new("m6-mut-ts", 1);
    let transcript: [u8; 32] = pool.bytes(32).try_into().unwrap();
    let mut ea = FixedEntropy::new(&pool.bytes(1 << 16));
    let mut eb = FixedEntropy::new(&pool.bytes(1 << 16));
    let (sa, sb) = ratchet_pair(&sk, &transcript, &mut ea, &mut eb);
    let key = pool.get().hybrid_signing_key().unwrap().verifying_key();
    let mut conv: Conv = secmp_client_core::scheduler::conversation::Conversation::new(
        sa,
        secmp_client_core::scheduler::outbox::MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-mut-ts-a", 1),
        key,
        START_UNIX,
    );
    conv.bind(A_SEND, A_RECV);
    let mut convs = secmp_client_core::scheduler::conversation::Conversations::new();
    let a = convs.add(conv);
    convs
        .get_mut(a)
        .unwrap()
        .outbox_mut()
        .enqueue(text(1, 50), 0);
    let cell = convs.prepare_cell(A_SEND, 123_456).unwrap().unwrap();
    let opened = sb
        .decrypt_with(
            cell.cell.as_bytes(),
            &mut FixedEntropy::new(&pool.bytes(1 << 16)),
        )
        .ok()
        .unwrap();
    let content = opened.plaintext().content().unwrap();
    assert_eq!(content.ts, START_UNIX + 123, "origin + whole seconds");
}

fn real_cells_until_idle(
    convs: &mut secmp_client_core::scheduler::conversation::Conversations<
        secmp_client_core::scheduler::outbox::MemOutbox,
        MemPersist,
        secmp_testkit::harness::EntropyPool,
    >,
    queue: QueueId,
    from_ms: u64,
) -> usize {
    let (mut n, mut t) = (0_usize, from_ms);
    while convs.pending_real(queue) {
        convs.prepare_cell(queue, t).unwrap().unwrap();
        n = n.saturating_add(1);
        t = t.saturating_add(10_000);
        assert!(n < 64, "never idle");
    }
    n
}

/// `conversation.rs:462` (`!` deleted in `Conversation::restore`, which keeps the failed message's remaining fragments in
/// the plan instead of dropping them): a multi-cell message whose first cell failed starts over — exactly as many real
/// cells are needed afterwards as for an undisturbed message, not the stale rest and then the whole message again.
#[test]
fn conversation_restore_drops_the_rest_of_a_failed_message() {
    let (mut convs, a, _b) = pair(35);
    convs
        .get_mut(a)
        .unwrap()
        .outbox_mut()
        .enqueue(text(1, 6_000), 0);
    let undisturbed = real_cells_until_idle(&mut convs, A_SEND, 10_000);
    assert!(
        undisturbed >= 3,
        "a message of several cells: {undisturbed}"
    );
    let (mut convs, a, _b) = pair(36);
    convs
        .get_mut(a)
        .unwrap()
        .outbox_mut()
        .enqueue(text(1, 6_000), 0);
    let first = convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    convs.send_failed(A_SEND, first.token, SendFailure::Unknown);
    assert_eq!(
        real_cells_until_idle(&mut convs, A_SEND, 20_000),
        undisturbed
    );
}

// ---- tokio driver ------------------------------------------------------------------------------------------------------

use secmp_client_core::scheduler::run::Purpose;
use secmp_client_core::scheduler::types::{LinkId, Reason};
use secmp_testkit::harness::Costs;

use crate::m6_activity::Scenario;
use crate::m6_driver_io::{Hold, Holding, client_connects, late_rig, no_phase};
use crate::m6_tokio::{Setup, TClient, TokioRig, runtime};

/// A Strict rig through a provider whose connection 0 holds (or fails) its first frame after the handshake.
async fn hold_rig(hold: Hold, contacts: Vec<(u64, u64)>, seed: u64) -> TokioRig<Holding> {
    let setup = Setup::new();
    let provider = Holding::new(setup.provider.clone(), 0, Some(hold), 0);
    let sc = Scenario {
        mode: Mode::Strict,
        contacts,
        pool: false,
        seed,
    };
    let x = TClient::with_provider(
        &setup,
        provider,
        sc.mode,
        no_phase(),
        sc.seed,
        Costs::default(),
        0,
    );
    TokioRig::assemble(setup, x, &sc).await
}

/// `(up, torn_down, reason)` of the first link of `rig` as logged by the driver: the time it came up, and the time and
/// reason of its first teardown.
fn first_link_life(rig: &TokioRig<Holding>) -> (u64, Option<(u64, Reason)>) {
    let log = rig.x.driver.log().unwrap();
    let link = crate::m6_driver_io::link_of(rig, 0);
    let up = log
        .events
        .iter()
        .find_map(|(t, e)| matches!(e, LinkEvent::Up(l) if *l == link).then_some(*t))
        .unwrap();
    let down = log.events.iter().find_map(|(t, e)| match e {
        LinkEvent::TornDown(l, why) if *l == link => Some((*t, *why)),
        _ => None,
    });
    (up, down)
}

/// `run.rs:1244` (`Driver::submit` → `Ok(())`): what the host gets from a scheduler call of its own is carried out at once —
/// after a mode change the old links' stream tasks are stopped before `submit` returns, not at the next pass.
#[test]
fn driver_submit_carries_out_the_hosts_outputs_at_once() {
    runtime().block_on(async {
        let mut rig = late_rig(0, 61).await;
        let t0 = rig.setup.now();
        rig.x.run_until(t0 + 30_000).await;
        let up: Vec<LinkId> = rig
            .x
            .sched
            .links()
            .iter()
            .filter(|l| l.t_up.is_some())
            .filter_map(|l| l.id)
            .collect();
        assert!(!up.is_empty(), "links are up");
        for l in &up {
            assert!(rig.x.driver.has_link_io(*l), "{l:?} runs");
        }
        let outs = rig
            .x
            .sched
            .set_mode(t0 + 30_000, Mode::Balanced, &mut NoCells)
            .unwrap();
        rig.x.driver.submit(&mut rig.x.sched, outs).unwrap();
        for l in &up {
            assert!(
                !rig.x.driver.has_link_io(*l),
                "{l:?} was closed by the submitted outputs"
            );
        }
    });
}

/// `run.rs` `close_stalled` (→ `Ok(())`, which made the driver spin at the stall deadline and time out at 900 s): a write still
/// pending `WRITE_STALL_MS` (10 s) after it was handed out closes its link then — not at the next tick, 40 s later with the
/// 40-s period here. The first frame hangs for an hour. The run stops exactly at the stall bound (`run_until` returns at
/// `until` before it waits again), so a driver that does not close the link fails the assertion instead of spinning.
#[test]
fn close_stalled_closes_a_write_pending_for_the_stall_bound() {
    runtime().block_on(async {
        let hold = Hold {
            first: 0,
            delay_ms: 3_600_000,
        };
        let mut rig = hold_rig(hold, vec![(40_000, 40_000)], 64).await;
        let t0 = rig.setup.now();
        rig.x.run_until(t0 + 1_000).await;
        let (up, _) = first_link_life(&rig);
        let link = crate::m6_driver_io::link_of(&rig, 0);
        let tick = up + 40_000;
        rig.x.run_until(tick + 9_999).await;
        assert!(
            rig.x.driver.has_link_io(link),
            "pending for 9.999 s: not closed yet"
        );
        rig.x.run_until(tick + 10_000).await;
        assert!(
            !rig.x.driver.has_link_io(link),
            "pending for 10 s: closed by the stall bound"
        );
    });
}

/// `run.rs` `start_io` (`&&` → `||` in the writer's `write_all(..).is_ok() && flush(..).is_ok()`) and `close_link` (→ `Ok(())`):
/// a stream whose write fails (its flush would succeed) is a failed write: the link is closed at that tick, reason `Closed`,
/// and not later by an overrun or the in-flight bound.
#[test]
fn start_io_reports_a_failed_write_and_close_link_closes_the_link() {
    runtime().block_on(async {
        let hold = Hold {
            first: 0,
            delay_ms: crate::m6_driver_io::Throttled::FAILING_WRITES,
        };
        let mut rig = hold_rig(hold, vec![(10_000, 10_000)], 65).await;
        rig.run_minutes(2, None).await;
        let (up, down) = first_link_life(&rig);
        let (at, why) = down.expect("the link whose write failed was closed");
        assert_eq!(why, Reason::Closed, "closed by the failed write");
        let tick = up + 10_000;
        assert!(
            at >= tick && at <= tick + 500,
            "closed at {at}, the write failed at {tick}"
        );
    });
}

/// `run.rs` `control` (`!` deleted in `self.controls.retain(|t| !t.is_finished())`, which drops the handles of the control
/// tasks still running): with two one-shot operations pending, `shutdown` aborts both — no connection of either reaches the
/// relay afterwards.
#[test]
fn driver_shutdown_aborts_every_pending_control_operation() {
    runtime().block_on(async {
        let mut rig = late_rig(60_000, 62).await;
        let t0 = rig.setup.now();
        for (ld, related) in [(1_u32, 1_u64), (2, 2)] {
            rig.x
                .sched
                .schedule_control(
                    t0,
                    ControlKind::LinkPut(ld),
                    RelayId(0),
                    related,
                    When::Prompt,
                )
                .unwrap();
        }
        rig.x.run_until(t0 + 1_000).await;
        let controls = rig
            .x
            .driver
            .log()
            .unwrap()
            .connects
            .iter()
            .filter(|(_, p, _)| matches!(p, Purpose::Control(_)))
            .count();
        assert_eq!(controls, 2, "both operations started");
        let before = client_connects(&rig);
        rig.x.driver.shutdown(&mut rig.x.sched).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        assert_eq!(
            client_connects(&rig),
            before,
            "a control operation connected after the shutdown"
        );
    });
}

// ---- transport: the channel's judgement of the relay's answers, the blocking session ---------------------------------------

/// Whether a run of `script` (Strict, one send queue) ended its link with `Reason::Rejected` at its first tick (10 s).
fn rejected_by(script: Script) -> bool {
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(script, Mode::Strict, params);
    rig.remake = Some(crate::m6_sched_io::ok_script);
    rig.run_to(10_000);
    rig.events
        .iter()
        .any(|e| matches!(e, LinkEvent::TornDown(_, Reason::Rejected)))
}

/// `channel.rs:459` (the guard `cell_id != 0 && evicted_is_plausible(..)` → `true`), `:485` (`fits(code, allowed)` → `true`):
/// a `SEND` answered with `OK_SEND` of cell 0, with an evicted id that cannot be (not below the new id), with an `ERR` the
/// command does not allow (token), or with an answer of the wrong type is a misfit — the link is closed as `Rejected`;
/// a good answer is not.
#[test]
fn channel_finish_rejects_misfit_send_answers() {
    let reply = |make: fn() -> ResponseCmd| -> Script {
        Box::new(move |request: &Request, _: usize| answer(request, make()))
    };
    assert!(!rejected_by(reply(|| ResponseCmd::OkSend {
        cell_id: 5,
        evicted: Some(4)
    })));
    let bad: [fn() -> ResponseCmd; 4] = [
        || ResponseCmd::OkSend {
            cell_id: 0,
            evicted: None,
        },
        || ResponseCmd::OkSend {
            cell_id: 5,
            evicted: Some(9),
        },
        || ResponseCmd::Err(ErrCode::Token),
        || ResponseCmd::Ok,
    ];
    for make in bad {
        assert!(rejected_by(reply(make)));
    }
}

/// `channel.rs:487` (the guard `ok(&other)` of `single` → `true`): a `PING` answered with an `OK_SEND` is a misfit. Balanced
/// slots with nobody due carry `PING`s; the relay answers every request with `OK_SEND`.
#[test]
fn channel_single_rejects_a_ping_answered_with_the_wrong_type() {
    let script: Script = Box::new(|request, n| {
        answer(
            request,
            ResponseCmd::OkSend {
                cell_id: u64::try_from(n).unwrap().saturating_add(1),
                evicted: None,
            },
        )
    });
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut rig = Rig::with(script, Mode::Balanced, params);
    rig.remake = Some(crate::m6_sched_io::ok_script);
    rig.run_to(0);
    // the one queue is sent to every 80 s: the slots in between carry a PING
    let outs = rig
        .sched
        .set_queue_period(0, QueueId(0), 80_000, &mut rig.src)
        .unwrap();
    rig.apply(outs);
    rig.run_to(20_000);
    assert!(
        rig.events
            .iter()
            .any(|e| matches!(e, LinkEvent::TornDown(_, Reason::Rejected))),
        "a PING answered with OK_SEND ends the link: {:?}",
        rig.events
    );
}

/// `channel.rs:308` (`from.is_empty() || from.len() > FETCH_MULTI_MAX`: `||` → `&&`, `>` → `==` / `>=`): a `FETCH_MULTI` of
/// 1 to 32 queues is built; 0 and 33 are refused as `Invalid` before a `cmd_seq` is taken.
#[test]
fn channel_prepare_bounds_the_fetch_multi_list() {
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::{Command, Error, RecvCap, Session};

    use crate::scripted::{self, Scripted};
    let id = scripted::identity();
    let mut entropy = EntropyPool::new("m6-mut-prepare", 0);
    let stream = Scripted::new(silent_script());
    let session =
        Session::connect(stream, id.fp, Some(&id.access), scripted::T0, entropy.get()).unwrap();
    let (_stream, mut chan) = session.into_parts();
    let caps: Vec<RecvCap> = (1..=33_u32).map(fresh_recv_cap).collect();
    let list = |n: usize| -> Vec<(&RecvCap, u64)> { caps.iter().take(n).map(|c| (c, 0)).collect() };
    assert!(matches!(
        chan.prepare(&Command::FetchMulti { from: &list(0) }),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        chan.prepare(&Command::FetchMulti { from: &list(33) }),
        Err(Error::Invalid)
    ));
    let prepared = chan
        .prepare(&Command::FetchMulti { from: &list(32) })
        .unwrap();
    assert_eq!(prepared.seq(), 1, "the refused lists took no cmd_seq");
    let one = chan
        .prepare(&Command::FetchMulti { from: &list(1) })
        .unwrap();
    assert_eq!(one.seq(), 2);
}

/// FIN4-4 (a), `core/mod.rs:1037` (`delete match arm TransportError::Closed in reason_of`; the earlier row called it
/// unreachable): a channel that is closed and then handed to the public `Scheduler::link_up` fails its first preparation with
/// `Closed`, and the link is torn down with `Reason::Closed` — the mutant says `Rejected`.
#[test]
fn reason_of_a_closed_channel_is_closed() {
    use secmp_client_core::scheduler::types::Output;
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::Session;

    use crate::m6_sched_io::Fake;
    use crate::scripted::{self, Scripted};
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let mut sched = Scheduler::new(params, Mode::Strict, TimingRng::seeded(31));
    let cap = SendCap::from_route(
        [3; 16],
        &secmp_crypto::SecretBytes::from_slice(&[9; 32]).unwrap(),
    )
    .unwrap();
    sched.add_send_queue(0, RelayId(0), cap, 10_000).unwrap();
    let outs = sched.poll_due(0).unwrap();
    let link = outs
        .iter()
        .find_map(|o| match o {
            Output::Connect { link, .. } => Some(*link),
            _ => None,
        })
        .unwrap();
    let id = scripted::identity();
    let mut entropy = EntropyPool::new("m6-mut-closed-channel", 0);
    let session = Session::connect(
        Scripted::new(silent_script()),
        id.fp,
        Some(&id.access),
        scripted::T0,
        entropy.get(),
    )
    .unwrap();
    let (_stream, mut chan) = session.into_parts();
    chan.close();
    let mut src = Fake::default();
    let mut outs = sched.link_up(link, 0, chan).unwrap();
    outs.extend(sched.work(0, &mut src).unwrap());
    let reasons: Vec<Reason> = outs
        .iter()
        .filter_map(|o| match o {
            Output::Event(LinkEvent::TornDown(l, why)) if *l == link => Some(*why),
            _ => None,
        })
        .collect();
    assert_eq!(reasons, vec![Reason::Closed]);
}

/// The frame bound of a link (`LINK_MAX_FRAMES`) as a counter value.
fn frame_limit() -> u64 {
    secmp_proto::link::LINK_MAX_FRAMES
}

/// FIN4-1 (a), `channel.rs:329` (`delete !` in `Channel::prepare`; the earlier row claimed the `u64` counter space had to be
/// used up — `Link::seal` returns `NewLinkRequired` at `LINK_MAX_FRAMES` = 2^20): at the bound `prepare` returns
/// `NewLinkRequired` and the channel stays open, because nothing was sealed (it is used again once a counter is set back);
/// the mutant closes it.
#[test]
fn channel_prepare_at_the_frame_limit_needs_a_new_link_and_stays_open() {
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::{Command, Error, Session};

    use crate::scripted::{self, Scripted};
    let id = scripted::identity();
    let mut entropy = EntropyPool::new("m6-mut-limit", 0);
    let stream = Scripted::new(silent_script());
    let session =
        Session::connect(stream, id.fp, Some(&id.access), scripted::T0, entropy.get()).unwrap();
    let (_stream, mut chan) = session.into_parts();
    chan.set_send_counter_kat(frame_limit() - 1);
    assert!(chan.prepare(&Command::Ping).is_ok(), "the last frame seals");
    assert!(matches!(
        chan.prepare(&Command::Ping),
        Err(Error::NewLinkRequired)
    ));
    assert!(
        !chan.is_closed(),
        "nothing was sealed: the channel stays open"
    );
    chan.set_send_counter_kat(0);
    assert!(chan.prepare(&Command::Ping).is_ok(), "and is usable");
}

/// FIN4-1 (b), `driver/session.rs:241` (`delete !` in `AsyncSession::send`): a three-frame request (`LINK_PUT`) whose first
/// frame seals and whose second crosses the bound closes the session — frames of the command are sealed, the counters moved,
/// the link is unusable — and nothing is written. (The mutant closes only when nothing was sealed.)
#[test]
fn async_send_closes_the_session_when_the_bound_falls_inside_a_command() {
    use secmp_crypto::SecretBytes;
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::Error;
    use secmp_transport::driver::{AsyncQueueTransport, AsyncRelayQueueTransport};

    runtime().block_on(async {
        let mut setup = Setup::new();
        let mut pool = EntropyPool::new("m6-mut-async-limit-b", 0);
        let token = setup.relay.access_key();
        let mut session = setup.session(&mut pool).await;
        session
            .channel_mut()
            .set_send_counter_kat(frame_limit() - 1);
        let mut t = AsyncRelayQueueTransport::new(session);
        let owner = SecretBytes::from_slice(&[0x31; 32]).unwrap();
        let put = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            t.put_link_data([7; 16], &owner, &crate::fixture::blob(1), true, 5, &token),
        )
        .await;
        assert!(
            matches!(put, Ok(Err(Error::NewLinkRequired))),
            "the second frame crosses the bound"
        );
        assert!(t.is_closed(), "frames were sealed: the session is closed");
    });
}

/// FIN4-1 (c), `driver/session.rs:241`: through the public async transport a `PING` at the bound fails at once with
/// `NewLinkRequired`, before anything is written, and the session stays open (the mutant closes it). The wait is bounded by
/// a 60-s timeout of the paused clock.
#[test]
fn async_ping_at_the_frame_limit_fails_locally_and_leaves_the_session_open() {
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::Error;
    use secmp_transport::driver::AsyncRelayQueueTransport;

    runtime().block_on(async {
        let mut setup = Setup::new();
        let mut pool = EntropyPool::new("m6-mut-async-limit-c", 0);
        let mut session = setup.session(&mut pool).await;
        session.channel_mut().set_send_counter_kat(frame_limit());
        let mut t = AsyncRelayQueueTransport::new(session);
        let ping = tokio::time::timeout(std::time::Duration::from_secs(60), t.ping()).await;
        assert!(
            matches!(ping, Ok(Err(Error::NewLinkRequired))),
            "failed locally"
        );
        assert!(!t.is_closed(), "nothing was sealed: the session is open");
        assert!(
            setup
                .relay
                .units()
                .iter()
                .all(|u| u.len != 4352 || u.isolation.0 < crate::m6_tokio::SETUP_ISO),
            "no frame reached the relay"
        );
    });
}

/// A blocking stream that fails its first `fail` writes and records the bytes of the others; it reads as ended.
struct Flaky {
    fail: usize,
    written: Vec<u8>,
}

impl std::io::Read for Flaky {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl std::io::Write for Flaky {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fail > 0 {
            self.fail = self.fail.saturating_sub(1);
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `session.rs:244`, `:240` (`Session::close` → `()`, `Session::ensure_open` → `Ok(())`): a blocking session whose write fails
/// is closed, and a closed session writes nothing more — the next command fails without a byte on the stream even though
/// the stream would take it now.
#[test]
fn blocking_session_closes_on_a_failed_write_and_stays_closed() {
    use secmp_testkit::harness::EntropyPool;
    use secmp_transport::{Error, RelayQueueTransport, Session};

    use crate::scripted::{self, Scripted};
    let id = scripted::identity();
    let mut entropy = EntropyPool::new("m6-mut-flaky", 0);
    let stream = Scripted::new(silent_script());
    let session =
        Session::connect(stream, id.fp, Some(&id.access), scripted::T0, entropy.get()).unwrap();
    let (_old, chan) = session.into_parts();
    let flaky = Flaky {
        fail: 1,
        written: Vec::new(),
    };
    let mut t = RelayQueueTransport::new(Session::from_parts(flaky, chan));
    assert!(!t.is_closed());
    assert!(matches!(t.ping(), Err(Error::Closed)));
    assert!(t.is_closed(), "the failed write closed the session");
    assert!(matches!(t.ping(), Err(Error::Closed)));
    assert!(
        t.session().stream().written.is_empty(),
        "nothing is written on a closed session"
    );
}

/// `conversation.rs:725` (`Conversations::discard` → `()`): a cell the scheduler discarded unsent puts its message back.
#[test]
fn conversations_discard_puts_the_message_back() {
    let (mut convs, a, _b) = pair(37);
    convs
        .get_mut(a)
        .unwrap()
        .outbox_mut()
        .enqueue(text(1, 50), 0);
    let cell = convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    assert!(!convs.pending_real(A_SEND), "taken");
    convs.discard(A_SEND, cell.token);
    assert!(convs.pending_real(A_SEND), "back in the outbox");
}
