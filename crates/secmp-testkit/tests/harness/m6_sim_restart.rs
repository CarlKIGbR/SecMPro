// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the relay-restart simulations — SIM-08 `sim_replay_deterministic` (SIM-03 twice, same seeds), SIM-03
//! `sim_relay_restart_recovery` and SIM-10 `sim_balanced_relay_restart` (TEST-SPEC-M6 (f)).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_client_core::scheduler::outbox::MsgState;
use secmp_client_core::scheduler::params::Mode;
use secmp_client_core::scheduler::run::Purpose;
use secmp_client_core::scheduler::types::LinkEvent;
use secmp_proto::wire::Id;
use secmp_testkit::harness::{Dir, EntropyPool, MemRelay};

use crate::m6_sim::{Outcome, Rig, Spec, simulate};

/// The queues of the relay (their `rid`s) now.
fn rids(relay: &Mutex<Option<MemRelay>>) -> Vec<Id> {
    let guard = relay.lock().unwrap();
    let relay = guard.as_ref().unwrap();
    relay
        .relay()
        .snapshot_kat()
        .queues
        .iter()
        .map(|q| q.rid)
        .collect()
}

/// What the timeline saw around the restart.
#[derive(Clone, Default)]
pub struct Restart {
    /// The queues the relay held at the restart.
    pub before: Vec<Id>,
    /// The restart, in the clients' milliseconds (they started with the simulation).
    pub at_ms: u64,
    /// Messages `Relayed` (stored by an `OK_SEND`) whose last cell was still in the relay's queue at the restart: real
    /// cells that the restart destroyed.
    pub real_cells_lost: usize,
    /// None of the clients' queues existed two seconds after the restart.
    pub absent_after: bool,
}

/// The ids of the cells in the queue `rid`.
fn cells_of(relay: &Mutex<Option<MemRelay>>, rid: &Id) -> Vec<u64> {
    let guard = relay.lock().unwrap();
    let snap = guard.as_ref().unwrap().relay().snapshot_kat();
    snap.queues
        .iter()
        .find(|q| q.rid == *rid)
        .map(|q| q.cell_ids.clone())
        .unwrap_or_default()
}

/// Real cells in the relay's queues now: for each client, its messages that are `Relayed` with their last cell still
/// stored in the queue it sends to.
fn real_cells_in_store(rig: &Rig<'_, '_>) -> usize {
    let mut n = 0_usize;
    for idx in 0..2_usize {
        let (Some((convs, _)), Some((_, peer))) = (
            rig.observers.get(idx).unwrap().client::<EntropyPool>(),
            rig.observers
                .get(1_usize.saturating_sub(idx))
                .unwrap()
                .client::<EntropyPool>(),
        ) else {
            return 0;
        };
        let Some(rid) = peer.recv_rid() else {
            return 0;
        };
        let stored = cells_of(rig.relay, &rid);
        let g = convs.lock().unwrap();
        n = n.saturating_add(
            g.get(0)
                .unwrap()
                .outbox()
                .states()
                .iter()
                .filter(|(_, s)| matches!(s, MsgState::Relayed(id) if stored.contains(id)))
                .count(),
        );
    }
    n
}

/// The relay host restarts after 1 h of virtual time, at the first moment a real message sits in its queues (a fresh
/// store, the same keys); what the timeline saw, and the outcome of the run.
pub fn relay_restart(name: &str, spec: &Spec) -> (Outcome, Restart) {
    let seen: Arc<Mutex<Restart>> = Arc::default();
    let log = Arc::clone(&seen);
    let mut step = 0_u8;
    let outcome = simulate(name, spec, move |rig| {
        let now_ms = u64::try_from(rig.now.as_millis()).unwrap();
        let mut r = log.lock().unwrap();
        if step == 0 && rig.now >= Duration::from_secs(3_600) {
            let lost = real_cells_in_store(rig);
            if lost > 0 {
                step = 1;
                r.before = rids(rig.relay);
                r.at_ms = now_ms;
                r.real_cells_lost = lost;
                rig.sim.bounce("relay");
            }
        } else if step == 1 && now_ms >= r.at_ms.saturating_add(2_000) {
            step = 2;
            let mine: Vec<Id> = (0..2)
                .filter_map(|i| rig.observers.get(i).unwrap().client::<EntropyPool>())
                .filter_map(|(_, c)| c.recv_rid())
                .collect();
            let held = rids(rig.relay);
            r.absent_after = mine.len() == 2 && mine.iter().all(|m| !held.contains(m));
        }
    });
    let r = seen.lock().unwrap().clone();
    (outcome, r)
}

/// SIM-08 `sim_replay_deterministic` (`docs/06` §4): SIM-03 twice with the same seeds gives byte-identical traces — the
/// units both clients wrote and read, and the message events — and the same reports. A source of nondeterminism (a
/// wall clock, a hash order, a thread) in the scheduler, the driver, the engine or the relay host would show here.
#[test]
fn sim_replay_deterministic() {
    let spec = Spec::default();
    let (first, _) = relay_restart("replay-1", &spec);
    let (second, _) = relay_restart("replay-2", &spec);
    for idx in 0..2 {
        let trace = |o: &Outcome| o.observers.get(idx).unwrap().recorder().unwrap().jsonl();
        let (a, b) = (trace(&first), trace(&second));
        assert!(
            a.lines().count() > 1_000,
            "client {idx}: a trace of {} lines proves nothing",
            a.lines().count()
        );
        assert_eq!(a, b, "client {idx}: the traces of the two runs differ");
        assert_eq!(first.report(idx), second.report(idx), "client {idx}");
    }
    assert_eq!(first.elapsed, second.elapsed);
}

/// The slack on the delay bounds: the driver wakes a few milliseconds after a due time.
const SLACK_MS: u64 = 250;
/// The send period of the conversation's queues.
const PERIOD_MS: u64 = 10_000;

/// After the restart: the relay holds exactly the two conversation queues with the ids they had; for each recipient the
/// queue is re-created `U[10 s, 300 s]` after it noticed `ERR_NOQUEUE` (spec §9.1); the senders kept writing frames
/// during the outage; real cells were in the store at the restart; each client ran its handshake once.
///
/// The recipient notices `ERR_NOQUEUE` (`present = 2`) with the `FETCH` of the first tick of a link that came up after
/// the restart — `Up` + `P` — and the re-creation is the `QUEUE_NEW` control connection that follows; which of the two
/// links is the one fetching the queue is not in the events, so the delay is measured from either (one of them is it).
fn assert_recreated(run: &Outcome, info: &Restart) {
    assert!(
        info.real_cells_lost >= 1,
        "no real cell was in the store at the restart"
    );
    assert!(
        info.absent_after,
        "a conversation queue existed 2 s after the restart"
    );
    let mine: Vec<Id> = (0..2)
        .map(|i| {
            let (_, restart) = run
                .observers
                .get(i)
                .unwrap()
                .client::<EntropyPool>()
                .unwrap();
            restart.recv_rid().unwrap()
        })
        .collect();
    for rid in &mine {
        assert!(
            info.before.contains(rid),
            "queue {rid:02x?} did not exist before the restart"
        );
    }
    let mut after = rids(&run.relay);
    after.sort_unstable();
    let mut want = mine.clone();
    want.sort_unstable();
    assert_eq!(
        after, want,
        "the relay holds the identical queues after the restart"
    );
    let mut window_end = 0;
    for idx in 0..2 {
        let o = run.observers.get(idx).unwrap();
        let ups: Vec<u64> = o
            .events()
            .iter()
            .filter_map(|(t, e)| matches!(e, LinkEvent::Up(_)).then_some(*t))
            .filter(|t| *t > info.at_ms)
            .take(2)
            .collect();
        let created = o
            .connects()
            .iter()
            .find(|(t, p)| *t > info.at_ms && matches!(p, Purpose::Control(_)))
            .map(|(t, _)| *t);
        let created = created.expect("a client's queue was never re-created");
        window_end = window_end.max(created);
        let fits = ups.iter().any(|up| {
            let delay = created.saturating_sub(up.saturating_add(PERIOD_MS));
            (10_000_u64.saturating_sub(SLACK_MS)..=300_000 + SLACK_MS).contains(&delay)
        });
        assert!(
            fits,
            "client {idx}: re-created at {created} ms, links up at {ups:?} + P: no delay in U[10 s, 300 s]"
        );
        assert_eq!(
            run.out.get(idx).unwrap().len(),
            1,
            "client {idx} started again: {:?}",
            run.out.get(idx)
        );
    }
    // the senders keep sending: frames are written during the outage
    for idx in 0..2 {
        let written = run
            .observers
            .get(idx)
            .unwrap()
            .recorder()
            .unwrap()
            .units()
            .iter()
            .filter(|u| u.dir == Dir::C2R && u.len == 4352)
            .filter(|u| (info.at_ms..window_end).contains(&u.t_ms))
            .count();
        assert!(written > 0, "client {idx} wrote no frame during the outage");
    }
}

/// SIM-03 `sim_relay_restart_recovery` (§9.1, §10.4 `:683`): the relay restarts at 1 h — at a moment real cells are in
/// its queues; the recipients re-create the identical queues `U[10 s, 300 s]` after their `ERR_NOQUEUE`, the senders keep
/// sending, no invitation is made again; (E) including the messages lost in the restart, and (K).
#[test]
fn sim_relay_restart_recovery() {
    let (run, info) = relay_restart("relay-restart", &Spec::default());
    assert_recreated(&run, &info);
    run.assert_e_and_k("SIM-03");
}

/// SIM-10 `sim_balanced_relay_restart` (§10.2): SIM-03 in Balanced — the same recovery. The `FETCH_MULTI` entries of the
/// restarted queues answer `present = 2` until re-creation (spec §9.3): the field is read inside the client's channel and
/// is not exposed to the driver's host, so the test asserts what only that answer causes and what the spec ties to it —
/// the queues are absent from the relay two seconds after the restart, each recipient re-created its queue (the only
/// trigger of `QUEUE_NEW` for a conversation queue is a `present = 2` answer, `Scheduler::queue_error`), the client kept
/// fetching in the outage (frames every `T_BALANCED` = 10 s), and after re-creation the relay holds the pre-restart
/// queues again; (E), (K).
#[test]
fn sim_balanced_relay_restart() {
    let spec = Spec {
        mode: Mode::Balanced,
        ..Spec::default()
    };
    let (run, info) = relay_restart("balanced-restart", &spec);
    assert_recreated(&run, &info);
    run.assert_e_and_k("SIM-10");
}
