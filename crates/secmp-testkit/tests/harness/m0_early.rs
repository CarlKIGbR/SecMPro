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
