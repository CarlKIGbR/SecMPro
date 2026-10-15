// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase B (BRIEF M6-B §2.2): AI-01…AI-06 repeated over the tokio driver (`scheduler::run`) on a paused tokio clock,
//! with the asymmetric-cost worker (a real cell 20 ms, a dummy 1 ms, a received cell 5 ms) — the emission times of the
//! frames, read where they cross the in-process relay, must equal the idle run's: max |Δt| = 0 ms in both directions.
//! The scenarios and the activity traces are those of `m6_activity`; AI-01…AI-03 run 16 traces here (the virtual-driver
//! originals run 64), AI-04…AI-06 the originals' 8, 4 and 8 — the CI budget of `kat` and `coverage` (report §7).

use secmp_client_core::scheduler::params::Mode;

use crate::m6_activity::{Event, Scenario, activity, par_map};
use crate::m6_common::{evidence, max_dt};
use crate::m6_tokio::{TRun, run_scenario};

fn compare(idle: &TRun, active: &TRun) -> (Option<u64>, Option<u64>) {
    (
        max_dt(&idle.c2r, &active.c2r),
        max_dt(&idle.r2c, &active.r2c),
    )
}

fn scenario(mode: Mode, contacts: &[(u64, u64)], seed: u64) -> Scenario {
    Scenario {
        mode,
        contacts: contacts.to_vec(),
        pool: true,
        seed,
    }
}

/// `traces` activity traces of `hours` against the idle run: max |Δt| per direction (both must be 0), the timing draws
/// and the one-shot links equal, real messages carried.
fn independence(mode: Mode, contacts: &[(u64, u64)], traces: u64, hours: u64) -> (u64, u64) {
    let sc = scenario(mode, contacts, 77);
    let idle = run_scenario(&sc, hours, None);
    assert!(idle.c2r.len() > 100, "{}", idle.c2r.len());
    assert_eq!(idle.overruns, 0);
    let results = par_map((0..traces).collect(), |trace| {
        let act = activity(trace, hours, contacts.len());
        let run = run_scenario(&sc, hours, Some(&act));
        let (c, r) = compare(&idle, &run);
        (
            trace,
            c,
            r,
            run.draws == idle.draws && run.control == idle.control,
            run.to_peers.saturating_add(run.to_x),
            run.work_ms,
        )
    });
    let real: usize = results.iter().map(|r| r.4).sum();
    assert!(real > 50, "the traces carried real messages: {real}");
    // the activity cost the worker more than the idle run: the asymmetry is really there
    assert!(
        results.iter().any(|r| r.5 > idle.work_ms),
        "work {} vs idle {}",
        results.iter().map(|r| r.5).max().unwrap_or(0),
        idle.work_ms
    );
    let (mut max_c2r, mut max_r2c) = (0, 0);
    for (trace, c, r, same, _, _) in results {
        let c = c.expect("the C2R trace differs in length, size, direction or slot");
        let r = r.expect("the R2C trace differs in length, size, direction or slot");
        assert!(c == 0, "trace {trace}: C2R max |Δt| = {c}");
        assert!(r == 0, "trace {trace}: R2C max |Δt| = {r}");
        assert!(
            same,
            "trace {trace}: timing draws or the one-shot links differ"
        );
        max_c2r = max_c2r.max(c);
        max_r2c = max_r2c.max(r);
    }
    (max_c2r, max_r2c)
}

fn report(name: &str, traces: u64, c2r: u64, r2c: u64) {
    evidence(
        name,
        &format!(
            "{name} (tokio driver, paused clock, costs 20/1/5 ms, {traces} traces x 6 h): max |Δt| C2R = {c2r} ms, R2C = {r2c} ms"
        ),
    );
}

/// The traces of the AI-01…AI-03 repeats.
const TRACES: u64 = 16;

/// The trace count of a repeat: `default`, or `SECMP_AI_TRACES` if set (the one-off 64-trace local run of WEISUNG
/// M6-B-3 §0.4; CI never sets it).
fn traces(default: u64) -> u64 {
    std::env::var("SECMP_AI_TRACES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// AI-01 over the tokio driver: Strict, two contacts and the pool, 16 traces of 6 h.
#[test]
fn ai01_strict_tokio() {
    let (c, r) = independence(
        Mode::Strict,
        &[(10_000, 10_000), (20_000, 40_000)],
        traces(TRACES),
        6,
    );
    report("AI-01-tokio", traces(TRACES), c, r);
}

/// AI-02 over the tokio driver: Balanced, four contacts.
#[test]
fn ai02_balanced_tokio() {
    let (c, r) = independence(Mode::Balanced, &[(10_000, 10_000); 4], traces(TRACES), 6);
    report("AI-02-tokio", traces(TRACES), c, r);
}

/// AI-03 over the tokio driver: Low-bw, five contacts at 40 s.
#[test]
fn ai03_lowbw_tokio() {
    let (c, r) = independence(Mode::LowBw, &[(40_000, 40_000); 5], traces(TRACES), 6);
    report("AI-03-tokio", traces(TRACES), c, r);
}

/// AI-04 over the tokio driver: the peers active, the local user idle.
#[test]
fn ai04_when_receiving_tokio() {
    let hours = 6;
    let sc = scenario(Mode::Strict, &[(10_000, 10_000), (20_000, 40_000)], 78);
    let idle = run_scenario(&sc, hours, None);
    let results = par_map((0..traces(8)).collect(), |trace| {
        let mut act = activity(trace + 500, hours, 2);
        act.events
            .retain(|(_, e)| !matches!(e, Event::UserSend { .. }));
        let run = run_scenario(&sc, hours, Some(&act));
        (compare(&idle, &run), run.control == idle.control, run.to_x)
    });
    assert!(
        results.iter().map(|r| r.2).sum::<usize>() > 0,
        "the peers' messages arrived"
    );
    for (n, ((c, r), same, _)) in results.into_iter().enumerate() {
        assert_eq!(c, Some(0), "trace {n}");
        assert_eq!(r, Some(0), "trace {n}");
        assert!(same, "trace {n}: the one-shot links differ");
    }
    report("AI-04-tokio", traces(8), 0, 0);
}

/// AI-05 over the tokio driver: the timing randomness is drawn the same way with or without activity.
#[test]
fn ai05_timing_draws_tokio() {
    let hours = 6;
    let sc = scenario(Mode::Strict, &[(10_000, 10_000), (20_000, 40_000)], 79);
    let idle = run_scenario(&sc, hours, None);
    assert!(idle.draws.len() == 6 && idle.draws.iter().all(|d| d.0 > 0 && d.1 > 0));
    let results = par_map((0..traces(4)).collect(), |trace| {
        let act = activity(trace + 900, hours, 2);
        run_scenario(&sc, hours, Some(&act)).draws
    });
    for (trace, draws) in results.into_iter().enumerate() {
        assert_eq!(draws, idle.draws, "trace {trace}");
    }
    evidence(
        "AI-05-tokio",
        &format!(
            "AI-05-tokio ({} traces x 6 h): timing draws equal to the idle run in every trace",
            traces(4)
        ),
    );
}

/// AI-06 over the tokio driver: the relay's answers carry no activity either.
#[test]
fn ai06_both_directions_tokio() {
    let hours = 6;
    let sc = scenario(Mode::Strict, &[(10_000, 10_000), (20_000, 40_000)], 80);
    let idle = run_scenario(&sc, hours, None);
    let results = par_map((0..traces(8)).collect(), |trace| {
        let act = activity(trace + 700, hours, 2);
        let run = run_scenario(&sc, hours, Some(&act));
        (
            idle.r2c.len() == run.r2c.len(),
            compare(&idle, &run).1,
            run.control == idle.control,
        )
    });
    for (n, (same_len, dt, same)) in results.into_iter().enumerate() {
        assert!(same_len, "trace {n}");
        assert!(same, "trace {n}: the one-shot links differ");
        assert_eq!(dt, Some(0), "trace {n}");
    }
    report("AI-06-tokio", traces(8), 0, 0);
}
