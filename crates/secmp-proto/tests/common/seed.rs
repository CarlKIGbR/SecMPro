// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The master seed of the seeded property tests (ADR-040; M4 review R-93, TEST-SPEC-M5 X-07): the one place that
//! reads `SECMP_PROPTEST_SEED`. Every file with seeded properties includes this module
//! (`#[path = ".../common/seed.rs"] mod seed;`) and draws its generators from [`master_seed`] with its own
//! `DEFAULT_SEED`; `cargo xtask` checks that by a source scan (`xtask/src/testscan.rs`).
//!
//! The `kat` gate step runs every property once with the variable removed (each file's `DEFAULT_SEED`) and, in a
//! GitHub Actions run, once more with the run's seed (`SECMP_PROPTEST_SEED=<GITHUB_RUN_ID>`, printed in the step
//! output and the job summary with the command that repeats the pass); the nightly `fuzz-nightly.yml` sets it to its
//! run id as well. Other crates' test binaries include this file by a relative `#[path]` too (e.g.
//! `crates/secmp-relay/tests/relay/`: `#[path = "../../../secmp-proto/tests/common/seed.rs"]`).

/// The master seed of this run: the decimal `u64` in `SECMP_PROPTEST_SEED` if it is set and not empty (surrounding
/// whitespace ignored), else `default`. A value that is not valid Unicode or not a decimal `u64` fails the test that
/// asks, naming the value: a mistyped seed never falls back to the default silently.
pub(crate) fn master_seed(default: u64) -> u64 {
    let raw = match std::env::var("SECMP_PROPTEST_SEED") {
        Err(std::env::VarError::NotPresent) => return default,
        other => other
            .map_err(|e| format!("SECMP_PROPTEST_SEED: {e}"))
            .unwrap(),
    };
    let value = raw.trim();
    if value.is_empty() {
        return default;
    }
    value
        .parse()
        .map_err(|e| format!("SECMP_PROPTEST_SEED={raw:?} is not a decimal u64: {e}"))
        .unwrap()
}
