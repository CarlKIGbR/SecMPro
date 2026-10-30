// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the fault simulations — SIM-01 loss, SIM-02 partition, SIM-04 both clients restart, SIM-05 crash between
//! persist and write, SIM-09 `HELLO` flood (TEST-SPEC-M6 (f)).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_client_core::scheduler::run::Purpose;
use secmp_client_core::scheduler::types::{LinkEvent, Reason};
use secmp_proto::wire::Id;
use secmp_testkit::harness::{Dir, EntropyPool, HarnessConfig, MemRelay, RelayLimits};

use crate::m6_sim::{Flood, Outcome, Rig, Spec, check_reconnects, simulate};

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

/// SIM-01 `sim_loss_breaks_links_eventual_delivery` (`docs/07:124`): `fail_rate(0.01)` on both client links,
/// `repair_rate(0.5)` (turmoil breaks the TCP connection on a loss), 200 messages each way over 2 h — (E), (K); the
/// teardowns have a reconnect within the bound of LR-02 (`U[0, 180 s]` after a failure) or, for a close before
/// `RELAYINFO`, LR-03 (the cap of 3 600 s) — a pooled bound (`check_reconnects`: a matching of teardowns to distinct
/// connects, not a per-link one), and a teardown in the last bound of the run is excused; with the 3 600 s bound of LR-03
/// that excuses every such teardown of the second hour. The loss starts at 15 min, not at 0: the clients' set-up (the scripted
/// handshake of deviation D-C2-1) runs on single links without a retry and ends within the first minutes.
#[test]
fn sim_loss_breaks_links_eventual_delivery() {
    let spec = Spec {
        messages: 200,
        interval_s: 20,
        end_s: 2 * 3_600,
        fail_rate: Some((0.01, 0.5)),
        ..Spec::default()
    };
    let run = simulate("loss", &spec, |_| {});
    run.assert_e_and_k("SIM-01");
    let mut teardowns = 0_usize;
    for idx in 0..2 {
        let o = run.observers.get(idx).unwrap();
        // FIN5b-1: the pooled bound, and every teardown has a reconnect (see `check_reconnects`)
        let checked = check_reconnects(
            &o.events(),
            &o.connects(),
            spec.end_s.saturating_mul(1_000),
            |why| match why {
                Reason::Closed | Reason::InFlight | Reason::Overrun | Reason::Rejected => {
                    Some(180_000)
                }
                Reason::ClosedBeforeRelayInfo => Some(3_600_000),
                _ => None,
            },
        );
        assert!(checked.is_ok(), "client {idx}: {checked:?}");
        teardowns += checked.unwrap_or(0);
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
    let ((head_start, _), (_, next_heal)) = (
        snaps.first().copied().unwrap(),
        snaps.get(1).copied().unwrap(),
    );
    // The prediction comes from the relay's own record of the queue B → A, not from B: a store that raises `next_cell_id`
    // by one and moves the head evicted the cells from the old head to the new one (an acknowledgement moves the head
    // with `next_cell_id` unchanged). The queue keeps 128 cells, so after the partition it evicts until A has drained it.
    let rid = run
        .observers
        .first()
        .unwrap()
        .client::<EntropyPool>()
        .unwrap()
        .1
        .recv_rid()
        .unwrap();
    let predicted: Vec<u64> = {
        let guard = run.relay.lock().unwrap();
        let changes = guard.as_ref().unwrap().store_changes();
        let mut out = Vec::new();
        let mut prev: Option<(u64, u64)> = None;
        for c in changes.iter().filter(|c| c.rid == rid) {
            if let Some((next, head)) = prev
                && c.next_cell_id == next + 1
                && c.head > head
            {
                // anchored in the protocol constant: the store that evicts finds the queue at QUEUE_CAPACITY cells (`secmp_proto::link::QUEUE_CAPACITY`, spec §4.2)
                assert_eq!(
                    next - head,
                    u64::try_from(secmp_proto::link::QUEUE_CAPACITY).unwrap(),
                    "an eviction from a queue of {} cells",
                    next - head
                );
                out.extend(head..c.head);
            }
            prev = Some((c.next_cell_id, c.head));
        }
        out
    };
    assert!(
        predicted.len() >= 20 && predicted.first().is_some_and(|f| *f >= head_start),
        "the partition did not fill the queue: head {head_start}, next {next_heal}, {} predicted evictions",
        predicted.len()
    );
    let mut reported: Vec<u64> = run.observers.get(1).unwrap().evicted();
    reported.sort_unstable();
    reported.dedup();
    // the eviction of the last store may still be on its way to B when the simulation ends
    let mut want = predicted.clone();
    if want.last().is_some_and(|l| !reported.contains(l)) {
        want.pop();
    }
    assert_eq!(
        reported, want,
        "the evicted ids reported to B are not the ids the queue predicts"
    );
    assert_drained(&run, &rid);
    run.assert_e_and_k("SIM-02");
}

/// SC-03 (Q167, OQ-20): every cell of a response goes to the worker at once and the acknowledgement is the highest
/// committed prefix, so A drains the backlog after the heal — the queue B → A (`rid`) holds at most 6 cells at the end of
/// the run (the M6 run ended at 128).
fn assert_drained(run: &Outcome, rid: &Id) {
    let (left, next) = queue_state(&run.relay, rid);
    crate::m6_common::evidence(
        "SIM-02-queue",
        &format!(
            "queue B -> A at the end of the run: {} cells (ids {left:?}, next_cell_id {next})",
            left.len()
        ),
    );
    assert!(
        left.len() <= 6,
        "queue B -> A holds {} cells at the end of the run",
        left.len()
    );
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
    let lost: Arc<Mutex<Option<(u64, u32)>>> = Arc::default();
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
            // the send counter of A's durable state (it includes the cell sealed and not sent): the next position is it, the
            // lost one is the one before
            let (convs, _) = rig
                .observers
                .first()
                .unwrap()
                .client::<EntropyPool>()
                .unwrap();
            let durable = convs.lock().unwrap().get(0).unwrap().durable().to_vec();
            let n_s = ratchet_tail(&durable).unwrap().0;
            *at_crash.lock().unwrap() = Some((sealed - stored, n_s));
            rig.sim.bounce("a");
        }
    });
    let (lost, n_s_at_crash) = lost.lock().unwrap().expect("the crash was never injected");
    assert!(lost >= 1, "no prepared cell was waiting at the crash");
    // the end state: read from the outcome's conversations and the relay
    let (sealed, next) = sealed_and_next_at_end(&run);
    let surplus = sealed - (next - 1);
    assert!(
        (lost..=lost + 2).contains(&surplus),
        "sealed {sealed}, stored {}, lost at the crash {lost}: surplus {surplus}",
        next - 1
    );
    // the direct assertion: B's durable ratchet state keeps one skipped message key per position it never received — the
    // position A persisted and never sent — and no other (the cells after it were opened at their own positions, so the
    // next cell used position + 1)
    let b_durable = run
        .convs(1)
        .lock()
        .unwrap()
        .get(0)
        .unwrap()
        .durable()
        .to_vec();
    let skipped = ratchet_tail(&b_durable).unwrap().1;
    assert_eq!(
        skipped.len(),
        usize::try_from(lost).unwrap(),
        "B skipped positions {skipped:?}, A lost {lost} at the crash"
    );
    // the position itself: the one before A's send counter at the crash (lost == 1, one link sends)
    assert_eq!(lost, 1, "more than one prepared cell at the crash");
    assert_eq!(
        skipped,
        vec![n_s_at_crash - 1],
        "B skipped {skipped:?}, A's persisted-but-unsent position is {}",
        n_s_at_crash - 1
    );
    run.assert_e_and_k("SIM-05");
}

/// The cells A sealed in all, and the `next_cell_id` of the queue A sends to, at the end of the run.
fn sealed_and_next_at_end(run: &Outcome) -> (u64, u64) {
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
    let guard = run.relay.lock().unwrap();
    let snap = guard.as_ref().unwrap().relay().snapshot_kat();
    let next = snap
        .queues
        .iter()
        .find(|q| q.rid == peer)
        .unwrap()
        .next_cell_id;
    (sealed, next)
}

/// The tail of a serialised ratchet state (`RatchetStateV1`, `tr/state.rs`): the encoding ends with `n_s`, `n_r`, `pn`
/// (4 B each), the count of skipped keys (2 B) and the entries `hk` (32) ‖ `n` (4) ‖ `mk` (32). Returns `(n_s, positions
/// of the skipped keys)`.
fn ratchet_tail(state: &[u8]) -> Option<(u32, Vec<u32>)> {
    const ENTRY: usize = 68;
    for count in 0..=512_usize {
        let at = state
            .len()
            .checked_sub(ENTRY.saturating_mul(count).saturating_add(2))?;
        let stored = state
            .get(at..at.saturating_add(2))
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_be_bytes);
        if stored.map(usize::from) != Some(count) {
            continue;
        }
        let n_s = state
            .get(at.checked_sub(12)?..at.checked_sub(8)?)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)?;
        let positions = (0..count)
            .map(|i| {
                let e = at
                    .saturating_add(2)
                    .saturating_add(i.saturating_mul(ENTRY))
                    .saturating_add(32);
                let n = state.get(e..e.saturating_add(4)).unwrap();
                u32::from_be_bytes(n.try_into().unwrap())
            })
            .collect();
        return Some((n_s, positions));
    }
    None
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
        // the `HELLO` bucket (16, 4/s) of the defaults is what the row tests; the per-link frame rate is off as in every
        // simulation of the harness (the clients' own rate, one frame per 10 s, is far below it)
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
        // the flood reached the honest clients: the relay closed at least one of their links before `RELAYINFO` (the
        // `HELLO` bucket was empty), so the back-off path of LR-03 was exercised
        let refused = o
            .events()
            .iter()
            .filter(|(t, e)| {
                (flood.start * 1000..flood_end).contains(t)
                    && matches!(e, LinkEvent::TornDown(_, Reason::ClosedBeforeRelayInfo))
            })
            .count();
        assert!(
            refused >= 1,
            "client {idx}: the relay refused none of its HELLOs during the flood"
        );
        // every scheduled link (two per client) is up at the flood's end + 3 600 s + 60 s: the links that came up minus
        // the links that went down by then
        let deadline = flood_end + 3_660_000;
        let mut up = std::collections::BTreeSet::new();
        for (t, e) in o.events() {
            match e {
                LinkEvent::Up(l) if t <= deadline => {
                    up.insert(l.0);
                }
                LinkEvent::TornDown(l, _) if t <= deadline => {
                    up.remove(&l.0);
                }
                _ => {}
            }
        }
        let live = up.len();
        assert_eq!(
            live, 2,
            "client {idx}: {live} scheduled links up at the deadline"
        );
    }
    run.assert_e_and_k("SIM-09");
}
