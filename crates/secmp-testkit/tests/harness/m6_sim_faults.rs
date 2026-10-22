// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the fault simulations — SIM-01 loss, SIM-02 partition, SIM-04 both clients restart, SIM-05 crash between
//! persist and write, SIM-09 `HELLO` flood (TEST-SPEC-M6 (f)).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_client_core::scheduler::params::Mode;
use secmp_client_core::scheduler::run::Purpose;
use secmp_client_core::scheduler::types::{LinkEvent, Reason};
use secmp_proto::wire::Id;
use secmp_testkit::harness::{Dir, EntropyPool, HarnessConfig, MemRelay, RelayLimits};

use crate::m6_sim::{Flood, Outcome, Rig, Spec, simulate};

/// The cell ids in the queue `rid` of the current relay and its `next_cell_id`.
fn queue_state(relay: &Mutex<Option<MemRelay>>, rid: &Id) -> (Vec<u64>, u64) {
    let guard = relay.lock().unwrap();
    let snap = guard.as_ref().unwrap().relay().snapshot_kat();
    snap.queues
        .iter()
        .find(|q| q.rid == *rid)
        .map_or((Vec::new(), 1), |q| (q.cell_ids.clone(), q.next_cell_id))
}

/// The id of the queue client `idx` receives on.
fn recv_rid(rig: &Rig<'_, '_>, idx: usize) -> Option<Id> {
    rig.observers
        .get(idx)?
        .client::<EntropyPool>()
        .and_then(|(_, r)| r.recv_rid())
}

/// SIM-01 `sim_loss_breaks_links_eventual_delivery` (`docs/07:124`): `fail_rate(0.01)` on both client links from 15 min on,
/// `repair_rate(0.5)` (turmoil breaks the TCP connection on a loss), 200 messages each way over 2 h — (E), (K); every
/// reconnect follows its teardown within the bound of LR-02 (`U[0, 180 s]` after a failure) or, for a close before
/// `RELAYINFO`, LR-03 (the cap of 3 600 s).
#[test]
fn sim_loss_breaks_links_eventual_delivery() {
    let spec = Spec {
        messages: 200,
        interval_s: 20,
        end_s: 3 * 3_600,
        fail_rate: Some((0.01, 0.5)),
        ..Spec::default()
    };
    let run = simulate("loss", &spec, |_| {});
    run.assert_e_and_k("SIM-01");
    let mut teardowns = 0_usize;
    for idx in 0..2 {
        let o = run.observers.get(idx).unwrap();
        let (events, connects) = (o.events(), o.connects());
        let mut link_connects: Vec<u64> = connects
            .iter()
            .filter(|(_, p)| matches!(p, Purpose::Link(_)))
            .map(|(t, _)| *t)
            .collect();
        link_connects.sort_unstable();
        for (t, e) in &events {
            let LinkEvent::TornDown(_, why) = e else {
                continue;
            };
            let bound = match why {
                Reason::Closed | Reason::InFlight | Reason::Overrun | Reason::Rejected => 180_000,
                Reason::ClosedBeforeRelayInfo => 3_600_000,
                _ => continue,
            };
            teardowns += 1;
            // the link's own reconnect is at most `bound` after the teardown, so the first connect of any link after it is
            if let Some(next) = link_connects.iter().find(|c| **c >= *t) {
                assert!(
                    next - t <= bound + 1_000,
                    "client {idx}: {why:?} at {t}: the next connect {} ms later, bound {bound}",
                    next - t
                );
            }
        }
    }
    assert!(
        teardowns >= 10,
        "{teardowns} teardowns: the loss did not break links"
    );
}

/// SIM-02 `sim_partition_heals` (`docs/07:124`): A ↔ relay partitioned for 30 min — (E), (K), and the ids the relay
/// reported evicted to B for the queue B → A are exactly the ids the test predicts from the relay's queue: A fetched
/// nothing, so every cell from the head at the partition to the head at the heal (the queue holds 128) was evicted.
#[test]
fn sim_partition_heals() {
    let spec = Spec {
        messages: 100,
        interval_s: 30,
        end_s: 3 * 3_600,
        ..Spec::default()
    };
    let snapshots: Arc<Mutex<Vec<(u64, u64)>>> = Arc::default();
    let seen = Arc::clone(&snapshots);
    let mut step = 0_u8;
    let run = simulate("partition", &spec, move |rig| {
        let rid = recv_rid(rig, 0);
        let Some(rid) = rid else { return };
        let at = |s: u64| rig.now >= Duration::from_secs(s);
        if step == 0 && at(1_800) {
            step = 1;
            let (ids, next) = queue_state(rig.relay, &rid);
            seen.lock()
                .unwrap()
                .push((ids.first().copied().unwrap_or(next), next));
            rig.sim.partition("a", "relay");
        } else if step == 1 && at(3_600) {
            step = 2;
            let (ids, next) = queue_state(rig.relay, &rid);
            seen.lock()
                .unwrap()
                .push((ids.first().copied().unwrap_or(next), next));
            rig.sim.repair("a", "relay");
        } else if step == 2 && at(3_700) {
            step = 3;
        }
    });
    let snaps = snapshots.lock().unwrap().clone();
    assert_eq!(
        snaps.len(),
        2,
        "the timeline took {} snapshots",
        snaps.len()
    );
    let ((head_start, _), (head_heal, next_heal)) = (
        snaps.first().copied().unwrap(),
        snaps.get(1).copied().unwrap(),
    );
    let predicted: Vec<u64> = (head_start..head_heal).collect();
    assert!(
        predicted.len() >= 20 && next_heal.saturating_sub(head_heal) == 128,
        "the partition did not fill the queue: head {head_start} → {head_heal}, next {next_heal}"
    );
    let mut reported: Vec<u64> = run
        .observers
        .get(1)
        .unwrap()
        .evicted()
        .into_iter()
        .filter(|id| (head_start..head_heal).contains(id))
        .collect();
    reported.sort_unstable();
    reported.dedup();
    assert_eq!(
        reported, predicted,
        "the evicted ids reported to B are not the ids the queue predicts"
    );
    run.assert_e_and_k("SIM-02");
}

/// SIM-04 `sim_both_clients_restart` [O-18] (`docs/07:124`): both clients crash at 1 h and restart from their `MemPersist`
/// snapshots (the last durable ratchet state; what was in flight is gone, the outbox and the received messages stay) —
/// the sessions continue; (E); (K) across the restart.
#[test]
fn sim_both_clients_restart() {
    let spec = Spec {
        messages: 100,
        interval_s: 60,
        end_s: 3 * 3_600,
        ..Spec::default()
    };
    let mut done = false;
    let run = simulate("both-restart", &spec, move |rig| {
        if !done && rig.now >= Duration::from_secs(3_600) {
            done = true;
            rig.sim.bounce("a");
            rig.sim.bounce("b");
        }
    });
    for idx in 0..2 {
        // the killed first run printed nothing; the restarted one resumed (no invitation, no handshake again)
        let out = run.out.get(idx).unwrap();
        assert_eq!(out.len(), 1, "client {idx}: {out:?}");
        assert!(
            !run.report(idx).contains("session=up"),
            "client {idx} made a new invitation after the restart"
        );
    }
    run.assert_e_and_k("SIM-04");
}

/// Cells client `idx` sealed (every one whose state became durable) and cells the relay stored in the queue it sends to.
fn sealed_and_stored(rig: &Rig<'_, '_>, idx: usize) -> (u64, u64) {
    let (convs, _) = rig
        .observers
        .get(idx)
        .unwrap()
        .client::<EntropyPool>()
        .unwrap();
    let sealed = convs
        .lock()
        .unwrap()
        .get(0)
        .unwrap()
        .message_key_digests_kat()
        .len();
    let peer = recv_rid(rig, 1_usize.saturating_sub(idx)).unwrap();
    let (_, next) = queue_state(rig.relay, &peer);
    (u64::try_from(sealed).unwrap(), next.saturating_sub(1))
}

/// SIM-05 `sim_crash_between_persist_and_write` (§7.5 `:488`): A crashes while a prepared cell — sealed, its new ratchet
/// state persisted — waits for its tick. The persisted-but-unsent position is skipped: the cell is lost, the restarted
/// conversation continues from the durable state, so the next cell uses the next position and no message key is reused
/// (K). Measured: at the crash A had sealed more cells than the relay stored (the prepared one); at the end the surplus is
/// that count plus at most the two cells prepared at the end — nothing was resealed under a used key.
#[test]
fn sim_crash_between_persist_and_write() {
    let spec = Spec {
        messages: 100,
        interval_s: 60,
        end_s: 3 * 3_600,
        ..Spec::default()
    };
    let lost: Arc<Mutex<Option<u64>>> = Arc::default();
    let at_crash = Arc::clone(&lost);
    let mut done = false;
    let run = simulate("crash-persist-write", &spec, move |rig| {
        if done || rig.now < Duration::from_secs(3_605) {
            return;
        }
        // half a period after the latest frame of the client: its next cell is prepared and not yet written
        let latest_frame = rig
            .observers
            .first()
            .unwrap()
            .recorder()
            .unwrap()
            .units()
            .iter()
            .filter(|u| u.dir == Dir::C2R && u.len == 4352)
            .map(|u| u.t_ms)
            .max()
            .unwrap_or(0);
        let now_ms = u64::try_from(rig.now.as_millis()).unwrap();
        if now_ms >= latest_frame.saturating_add(5_000)
            && now_ms < latest_frame.saturating_add(6_000)
        {
            done = true;
            let (sealed, stored) = sealed_and_stored(rig, 0);
            *at_crash.lock().unwrap() = Some(sealed - stored);
            rig.sim.bounce("a");
        }
    });
    let lost = lost.lock().unwrap().expect("the crash was never injected");
    assert!(lost >= 1, "no prepared cell was waiting at the crash");
    // the end state: read from the outcome's conversations and the relay
    let sealed = u64::try_from(
        run.convs(0)
            .lock()
            .unwrap()
            .get(0)
            .unwrap()
            .message_key_digests_kat()
            .len(),
    )
    .unwrap();
    let peer = run
        .observers
        .get(1)
        .unwrap()
        .client::<EntropyPool>()
        .unwrap()
        .1
        .recv_rid()
        .unwrap();
    let next = {
        let guard = run.relay.lock().unwrap();
        let snap = guard.as_ref().unwrap().relay().snapshot_kat();
        snap.queues
            .iter()
            .find(|q| q.rid == peer)
            .unwrap()
            .next_cell_id
    };
    let surplus = sealed - (next - 1);
    assert!(
        (lost..=lost + 2).contains(&surplus),
        "sealed {sealed}, stored {}, lost at the crash {lost}: surplus {surplus}",
        next - 1
    );
    run.assert_e_and_k("SIM-05");
}

/// SIM-09 `sim_hello_flood_backoff_recovery` [O-14] (F-1): an attacker host sends `HELLO` at 8/s for 600 s against the
/// relay's bucket (16, 4/s) while a partition of 90 s breaks every honest link so that it has to connect again — the honest links back
/// off (LR-03: no more than a few dozen attempts in the flood, never one per tick), and every scheduled link is up again by
/// the flood's end + 3 600 s + 60 s; (E), (K).
#[test]
fn sim_hello_flood_backoff_recovery() {
    let flood = Flood {
        rate: 8,
        start: 1_800,
        length: 600,
    };
    let spec = Spec {
        messages: 100,
        interval_s: 60,
        end_s: 4 * 3_600,
        flood: Some(flood),
        relay: HarnessConfig {
            limits: RelayLimits {
                link_rate: None,
                ..RelayLimits::defaults()
            },
            ..HarnessConfig::default()
        },
        ..Spec::default()
    };
    // the honest links must connect again while the flood runs: a partition of 90 s at its start breaks them (the
    // relay keeps its store; a relay restart would add the loss of the cells it held, which SIM-03 covers)
    let mut step = 0_u8;
    let run: Outcome = simulate("hello-flood", &spec, move |rig| {
        if step == 0 && rig.now >= Duration::from_secs(flood.start) {
            step = 1;
            rig.sim.partition("a", "relay");
            rig.sim.partition("b", "relay");
        } else if step == 1 && rig.now >= Duration::from_secs(flood.start + 90) {
            step = 2;
            rig.sim.repair("a", "relay");
            rig.sim.repair("b", "relay");
        }
    });
    let flood_end = (flood.start + flood.length) * 1000;
    for idx in 0..2 {
        let o = run.observers.get(idx).unwrap();
        let attempts = o
            .connects()
            .iter()
            .filter(|(t, p)| {
                matches!(p, Purpose::Link(_)) && (flood.start * 1000..flood_end).contains(t)
            })
            .count();
        assert!(
            attempts <= 40,
            "client {idx}: {attempts} connection attempts during the flood: no back-off"
        );
        let ups_after: Vec<u64> = o
            .events()
            .iter()
            .filter_map(|(t, e)| match e {
                LinkEvent::Up(_) if *t >= flood.start * 1000 => Some(*t),
                _ => None,
            })
            .collect();
        assert!(
            ups_after.len() >= 2,
            "client {idx}: {} links up again after the flood began",
            ups_after.len()
        );
        assert!(
            ups_after
                .iter()
                .take(2)
                .all(|t| *t <= flood_end + 3_660_000),
            "client {idx}: links up at {ups_after:?}, later than flood end + 3660 s"
        );
    }
    run.assert_e_and_k("SIM-09");
    let _ = Mode::Strict;
}
