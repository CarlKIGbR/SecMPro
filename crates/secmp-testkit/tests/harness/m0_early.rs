// SPDX-License-Identifier: AGPL-3.0-or-later
//! Killers of the mutants that make other tests run for ever (WEISUNG M6-C1-3, item 1). The second mutants run starts them
//! before `m6_activity`, whose six-hour simulations a mutant of a period or a clock turns into runs of hours: with four test
//! threads (the runner) four of them hold every thread and a failing test behind them never starts, so the mutant times out
//! at 900 s. The tests here fail within a second; none of them loops or waits for a wall clock (the waits are virtual: the
//! paused tokio clock advances at once when every task is idle).
//!
//! **Why the four `m6_activity::activity_comparator_detects_*` tests matter:** they run six-hour simulations; under a mutated
//! period or clock they never end, hold all four threads of the runner, and a failing test queued behind them is never started.
//!
//! **The order is an explicit filter** (TEST-SPEC-M7 G7-10, ADR-047 Amendment 9; until M7 it was this module's name, which
//! sorted first). The second mutants run uses the nextest profile `mutants-harness` of `.config/nextest.toml`, whose one
//! override gives the tests of `expect::MUTANT_KILLER_MODULE` (this module) priority 100, so nextest starts them before every
//! other test whatever the module is called. Renaming this file means changing that constant and the profile's filter in the
//! same commit; the test `mutant_killers_run_first_by_filter` fails otherwise (`mutants-c1-41ee485.md`, "Timeouts", shows
//! what a late killer costs).

use std::time::Duration;

use secmp_client_core::clock::{Clock, TokioClock};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::timing::{accept_ceiling, sample_round, sample_with};

use crate::m6_sched_io::{Rig, ok_script};
use crate::m6_tokio::{Setup, runtime};

/// `core/mod.rs:388` (`World::period_of` → `Some(0)` / `Some(1)`, which spun the simulations): the first tick of a link is one
/// period after it came up — 10 s for a Strict send link, one slot for a Balanced relay link — and the next deadline is the `FETCH` lead before it
/// (1 s). One pass, no waiting loop.
#[test]
fn period_of_gives_the_deadline_of_the_first_tick() {
    for mode in [Mode::Strict, Mode::Balanced] {
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let expected = params
            .slot_ms(mode)
            .unwrap_or(10_000)
            .saturating_sub(params.fetch_lead_ms);
        let mut rig = Rig::with(ok_script(), mode, params);
        rig.poll_at(0);
        assert_eq!(rig.sched.next_deadline(), Some(expected), "{mode:?}");
    }
}

/// `clock.rs:74` (`<impl Clock for TokioClock>::mono_ms` → `0` / `1`): the clock of the tokio runtime starts at 0 and follows the
/// runtime's clock — here advanced by hand — and the Unix time follows in whole seconds.
#[test]
fn tokio_clock_follows_the_paused_runtime() {
    runtime().block_on(async {
        let clock = TokioClock::new(1_000);
        assert_eq!(clock.mono_ms(), 0);
        tokio::time::advance(Duration::from_millis(5_250)).await;
        assert_eq!(clock.mono_ms(), 5_250);
        assert_eq!(clock.unix_secs(), 1_005);
        tokio::time::advance(Duration::from_millis(750)).await;
        assert_eq!(clock.mono_ms(), 6_000);
        assert_eq!(clock.unix_secs(), 1_006);
    });
}

/// `driver/session.rs:50` (`write_all` → `Ok(())`, which left every async handshake waiting for ever): the async handshake
/// writes its records and the relay answers. A 60-s timeout of the paused clock bounds the wait in virtual time.
#[test]
fn async_handshake_writes_its_records() {
    use secmp_testkit::harness::EntropyPool;
    runtime().block_on(async {
        let mut setup = Setup::new();
        let mut pool = EntropyPool::new("m0-early-handshake", 0);
        let up = tokio::time::timeout(Duration::from_secs(60), setup.transport(&mut pool)).await;
        assert!(up.is_ok(), "the handshake completed");
    });
}

/// `driver/session.rs:233` (`AsyncSession::send` → `Ok(())`, which timed out at 900 s: nothing is written, the relay never
/// answers and the read waits for ever): a `PING` over the async link is written and answered. The wait is bounded by a
/// 60-s timeout of the paused tokio clock, which advances at once when every task is idle — a link that wrote nothing fails
/// the assertion, in virtual time.
#[test]
fn async_session_send_writes_the_request_the_relay_answers() {
    use secmp_testkit::harness::EntropyPool;
    runtime().block_on(async {
        let mut setup = Setup::new();
        let mut pool = EntropyPool::new("m6-mut-async-send", 0);
        let mut t = setup.transport(&mut pool).await;
        let answered = tokio::time::timeout(std::time::Duration::from_secs(60), t.ping()).await;
        assert!(matches!(answered, Ok(Ok(()))), "the PING was answered");
    });
}

/// `u64::MAX - 5`, the largest multiple of 10 that fits 64 bits.
const C10: u64 = 18_446_744_073_709_551_610;

/// `timing.rs:40` (`accept_ceiling` → `None` / `Some(0)` / `Some(1)`; PR-run 41193864080, mutants shards 2, 3, 4): under these
/// mutants `TimingRng::uniform` never accepts a draw, loops for ever, and every test that draws holds a runner thread (G7-10).
/// Pure function, one pass, no draw loop.
#[test]
fn accept_ceiling_is_the_largest_multiple_of_span() {
    assert_eq!(accept_ceiling(1), Some(u64::MAX));
    assert_eq!(accept_ceiling(10), Some(C10));
    assert_eq!(accept_ceiling(u64::MAX), Some(u64::MAX));
    assert_eq!(accept_ceiling(0), None);
}

/// `timing.rs:47` (`sample_with` → `None` / `Some(0)` / `Some(1)` and `>=` → `<`; PR-run 41193864080, shards 5 and 8): the
/// same endless loop of `uniform`. A draw below the ceiling is accepted, one at or above it is rejected.
#[test]
fn sample_with_accepts_below_the_ceiling_and_rejects_at_it() {
    assert_eq!(sample_with(0, 5, 10, C10), Some(5));
    assert_eq!(
        sample_with(18_446_744_073_709_551_609, 5, 10, C10),
        Some(14)
    );
    assert_eq!(sample_with(C10, 5, 10, C10), None);
    assert_eq!(sample_with(u64::MAX, 5, 10, C10), None);
}

/// `timing.rs:56` (`sample_round` → `None`; PR-run 41193864080, shard 9): the round composes the ceiling and the sample.
#[test]
fn sample_round_composes_ceiling_and_sample() {
    assert_eq!(sample_round(7, 100, 5), Some(102));
    // 2^64 ≡ 1 (mod 5), so `u64::MAX % 5 == 0` and `accept_ceiling(5) == Some(u64::MAX)`: the draw equals the ceiling and is rejected.
    assert_eq!(sample_round(u64::MAX, 100, 5), None);
    assert_eq!(sample_round(3, 0, 0), None);
}

/// `core/mod.rs:860` (`World::step_due`: the guard `now >= up.die_at` → `false`; PR-run 43385042727, shard 14: TIMEOUT at
/// 900 s): under it a link never dies of its lifetime, `Scheduler::next_deadline` stays at the passed `die_at`, and every
/// run beyond a lifetime spins at one instant — the virtual driver until its 50 000 000-pass guard
/// (`m6_props::prop_at_most_once_per_period`, `m6_reconnect::rotation_and_reconnect_keep_send_spacing`), the tokio driver
/// for ever (`m7_links::logical_link_id_in_events`). Here the core is polled by hand at fixed times, no deadline loop: a
/// Strict send link living exactly 30 s is up 1 ms before its end, and at `t_up + 30 s` it is torn down with
/// `Reason::Lifetime` instead of ticking.
#[test]
fn link_is_torn_down_at_the_end_of_its_lifetime() {
    use secmp_client_core::scheduler::types::{LinkEvent, Reason};
    let params = Params {
        phase_max_ms: 0,
        lifetime_ms: (30_000, 30_000),
        ..Params::default()
    };
    let mut rig = Rig::with(ok_script(), Mode::Strict, params);
    rig.poll_at(0);
    let info = *rig.sched.links().first().unwrap();
    let (t_up, die_at) = (info.t_up.unwrap(), info.die_at.unwrap());
    assert_eq!(die_at, t_up + 30_000, "the configured lifetime");
    for t in [9_000, 10_000, 19_000, 20_000, 29_000, 29_999] {
        rig.poll_at(t_up + t);
    }
    let torn = |rig: &Rig| {
        rig.events
            .iter()
            .filter(|e| matches!(e, LinkEvent::TornDown(..)))
            .copied()
            .collect::<Vec<_>>()
    };
    assert!(torn(&rig).is_empty(), "up before its end: {:?}", torn(&rig));
    rig.poll_at(die_at);
    assert!(
        matches!(
            torn(&rig).as_slice(),
            [LinkEvent::TornDown(_, _, Reason::Lifetime)]
        ),
        "torn down at its end: {:?}",
        torn(&rig)
    );
    assert!(!rig.writes.contains(&die_at), "no tick at the end");
}

/// `core/mod.rs:1907` (`Scheduler::next_deadline`: `lead > self.world.last_now` → `>=`): under it the `FETCH` lead stays
/// the next deadline once the driver has woken at it, so every run spins at that instant — the virtual driver until its
/// 50 000 000-pass guard, the tokio driver for ever — and the mutant is caught only by a long wait. Here the core is polled
/// by hand, no deadline loop: after the wake at the lead the next deadline is the tick itself, one `FETCH` lead later.
#[test]
fn next_deadline_moves_past_the_lead_once_it_is_reached() {
    for mode in [Mode::Strict, Mode::Balanced] {
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let tick = params.slot_ms(mode).unwrap_or(10_000);
        let lead = tick.saturating_sub(params.fetch_lead_ms);
        let mut rig = Rig::with(ok_script(), mode, params);
        rig.poll_at(0);
        assert_eq!(rig.sched.next_deadline(), Some(lead), "{mode:?}: the lead");
        rig.poll_at(lead);
        assert_eq!(
            rig.sched.next_deadline(),
            Some(tick),
            "{mode:?}: the tick after the lead"
        );
    }
}
