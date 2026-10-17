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
