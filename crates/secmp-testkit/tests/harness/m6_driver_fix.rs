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
                .find_map(|(t, e)| matches!(e, LinkEvent::Up(_)).then_some(*t))
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
