// SPDX-License-Identifier: AGPL-3.0-or-later
//! WIN2-DIAG (D-CI14, Q260; a throw-away commit, reverted before any further unit): one `W2DIAG` line per instrumented
//! test and one `W2DIAG-JOB` line per job of SE-19 on stdout — the lock counters of `secmp_sys_mem::diag`, the process
//! totals (Windows) and the test's own wall time and store commits. Shown in a green run by the `.config/nextest.toml`
//! override of this unit (nextest shows a passing test's output only when told to). Counts and durations only.

use std::io::Write;
use std::time::{Duration, Instant};

fn emit(line: &str) {
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes()).unwrap();
    out.write_all(b"\n").unwrap();
    out.flush().unwrap();
}

fn millis(d: Duration) -> u128 {
    d.as_millis()
}

fn process() -> String {
    secmp_sys_mem::diag::process().map_or_else(|| "process=none".to_owned(), |p| p.to_string())
}

/// The worker threads `par_map` uses on this machine (`m6_activity::par_map`).
fn threads() -> usize {
    std::thread::available_parallelism().map_or(0, usize::from)
}

/// The end-of-test line: `test` (an SE/PC tag), its wall time since `started`, `extra` (`key=value` pairs).
pub fn report(test: &str, started: Instant, extra: &str) {
    emit(&format!(
        "W2DIAG test={test} wall_ms={} threads={} {} {} {extra}",
        millis(started.elapsed()),
        threads(),
        secmp_sys_mem::diag::snapshot(),
        process()
    ));
}

/// One SE-19 job: its label, wall time since `started` and the store commits of its thread (`kat::store_txn_commits`,
/// thread-local) during it; the counters are process-wide (the jobs overlap).
pub fn job(label: &str, started: Instant, commits: u64) {
    emit(&format!(
        "W2DIAG-JOB test=SE-19 job={label} wall_ms={} commits={commits} {} {}",
        millis(started.elapsed()),
        secmp_sys_mem::diag::snapshot(),
        process()
    ));
}
