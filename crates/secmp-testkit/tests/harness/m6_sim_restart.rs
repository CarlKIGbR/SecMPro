// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the relay-restart simulations — SIM-08 `sim_replay_deterministic` (SIM-03 twice, same seeds), SIM-03
//! `sim_relay_restart_recovery` and SIM-10 `sim_balanced_relay_restart` (TEST-SPEC-M6 (f)).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_client_core::scheduler::params::Mode;
use secmp_proto::wire::Id;
use secmp_testkit::harness::{EntropyPool, MemRelay};

use crate::m6_sim::{Outcome, Spec, simulate};

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

/// The relay host restarts at 1 h of virtual time (a fresh store, the same keys); the queues it held then, and the
/// outcome of the run.
pub fn relay_restart(name: &str, spec: &Spec) -> (Outcome, Vec<Id>) {
    let before: Arc<Mutex<Vec<Id>>> = Arc::default();
    let seen = Arc::clone(&before);
    let mut done = false;
    let outcome = simulate(name, spec, move |rig| {
        if !done && rig.now >= Duration::from_secs(3_600) {
            done = true;
            *seen.lock().unwrap() = rids(rig.relay);
            rig.sim.bounce("relay");
        }
    });
    let before = before.lock().unwrap().clone();
    (outcome, before)
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

/// After the restart the relay holds exactly the two conversation queues, with the ids they had, each created within
/// the window of the re-creation delay (the relay's clock starts at its restart); each client ran its handshake once.
fn assert_recreated(run: &Outcome, before: &[Id]) {
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
            before.contains(rid),
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
    let guard = run.relay.lock().unwrap();
    let changes = guard.as_ref().unwrap().store_changes();
    for rid in &mine {
        let first = changes.iter().find(|c| c.rid == *rid).unwrap().t_ms;
        assert!(
            (10_000..=560_000).contains(&first),
            "queue {rid:02x?} re-created {first} ms after the restart: outside the window: reconnect U[0, 180 s] + one period (<= 80 s) + U[10 s, 300 s]"
        );
    }
    for idx in 0..2 {
        assert_eq!(
            run.out.get(idx).unwrap().len(),
            1,
            "client {idx} started again: {:?}",
            run.out.get(idx)
        );
    }
}

/// SIM-03 `sim_relay_restart_recovery` (§9.1, §10.4 `:683`): the relay restarts at 1 h; the recipients re-create the
/// identical queues — the same `rid`s, each at a time after the restart within the client's noticing (one period) plus
/// `U[10 s, 300 s]` — the senders keep sending, no invitation is made again; (E) including the messages lost in the
/// restart, and (K).
#[test]
fn sim_relay_restart_recovery() {
    let (run, before) = relay_restart("relay-restart", &Spec::default());
    assert_recreated(&run, &before);
    run.assert_e_and_k("SIM-03");
}

/// SIM-10 `sim_balanced_relay_restart` (§10.2): SIM-03 in Balanced — (E), (K); the same queues are re-created.
#[test]
fn sim_balanced_relay_restart() {
    let spec = Spec {
        mode: Mode::Balanced,
        ..Spec::default()
    };
    let (run, before) = relay_restart("balanced-restart", &spec);
    assert_recreated(&run, &before);
    run.assert_e_and_k("SIM-10");
}
