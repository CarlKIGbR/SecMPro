// SPDX-License-Identifier: AGPL-3.0-or-later
//! The seed of the property tests in a CI run, and source scans of the test suites.
//!
//! **Property seeds (M4 review R-93, TEST-SPEC-M5 X-07).** Every seeded property test takes its master seed from one
//! helper, `crates/secmp-proto/tests/common/seed.rs` (`scan::SEED_HELPER`): the decimal `u64` in
//! `SECMP_PROPTEST_SEED` if it is set and not empty, else the file's own `DEFAULT_SEED`. The property tests live in
//! the packages of [`PROPERTY_PACKAGES`], and their test crates need the feature `kat` (`secmp-relay`'s `relay` is
//! built by no workspace run), so the `kat` step carries the seeds ([`kat_runs`]): it runs every KAT package with
//! `--features kat` and the variable removed (every property with its `DEFAULT_SEED`), and in a GitHub Actions run
//! (`GITHUB_ACTIONS=true`: every pull request, push and scheduled run of `ci.yml`, in `linux-fast`, `windows-native`
//! and `linux-full`) then each property package once more, filtered to its property tests ([`property_filter`]),
//! with the CI run seed ([`ci_run_seed`]). That pass reuses the build of the package's kat run (same arguments, one
//! filter more), so it costs the run time of the property tests only. The seed is printed before the pass and is part
//! of the step's verdict line in the ADR-045 job summary and of its failure message, together with the command that
//! repeats the pass locally. Locally (no `GITHUB_ACTIONS`) only the `DEFAULT_SEED` runs take place. The `nextest`
//! step's runs ([`nextest_runs`]) and the kat step's portable-backend reruns remove the variable as well.
//!
//! The test `pr_ci_runs_props_with_ci_run_seed` proves the wiring: the steps' invocations, the derivation, and — by a
//! scan of every Rust file under `crates/` (`scan::scan_seeds`) — that every `prop_*` test reaches the helper, that no
//! other file reads the variable, that every property's package is a property package and a KAT package, and that
//! the filter's binaries still hold seeded tests.
//!
//! **Doctest fences (M4 review R-92, TEST-SPEC-M5 X-06).** Every `compile_fail` code block in a doc comment of a
//! first-party Rust file names its error code (`compile_fail,E0624`), so the block documents which error it expects
//! (`scan::compile_fail_fences_without_code`). Rustdoc checks the code only on a nightly toolchain; on the pinned
//! stable one any compile error still passes the block.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use crate::gates;
use crate::util::{Cmd, Error, Result, bail, say};

/// The environment variable the seed helper reads.
pub(crate) const SEED_ENV: &str = "SECMP_PROPTEST_SEED";

/// The range every `DEFAULT_SEED` lies in (`0x5ec3_2d00_0000_00NN`, checked by the scan); [`ci_run_seed_from`] refuses
/// a run id in it, so the CI run seed always differs from every `DEFAULT_SEED`.
pub(crate) const DEFAULT_SEED_RANGE: RangeInclusive<u64> =
    0x5ec3_2d00_0000_0000..=0x5ec3_2d00_ffff_ffff;

/// The packages with property tests (each a KAT package, `expect::KAT_PACKAGES`): the kat step runs each once more
/// with the CI run seed. The scan checks that every property test is in one of them and that each holds one (a
/// property package without the feature `kat` would need a pass of its own; the scan fails until it has one).
pub(crate) const PROPERTY_PACKAGES: &[&str] = &["secmp-proto", "secmp-relay"];

/// Test binaries (nextest `binary_id`) whose seeded property tests predate the `prop_` names (M2 `canonical`, M3
/// `tr_properties`): the CI-seed pass runs them whole. Every other property test is named `prop_*`.
pub(crate) const PROPERTY_BINARIES: &[&str] =
    &["secmp-proto::canonical", "secmp-proto::tr_properties"];

/// The nextest filterset of the CI-seed pass: every `prop_*` test and the binaries of [`PROPERTY_BINARIES`].
pub(crate) fn property_filter() -> String {
    let mut parts = vec!["test(/(^|::)prop_/)".to_owned()];
    parts.extend(PROPERTY_BINARIES.iter().map(|b| format!("binary_id(={b})")));
    parts.join(" | ")
}

/// The CI run seed of this process: [`ci_run_seed_from`] on `GITHUB_ACTIONS` and `GITHUB_RUN_ID`.
pub(crate) fn ci_run_seed() -> Result<Option<u64>> {
    let var = |k: &str| std::env::var(k).ok();
    ci_run_seed_from(
        var("GITHUB_ACTIONS").as_deref(),
        var("GITHUB_RUN_ID").as_deref(),
    )
}

/// The CI run seed: `None` outside GitHub Actions (`GITHUB_ACTIONS` other than `true`); in a GitHub Actions run the
/// run id `GITHUB_RUN_ID` as a decimal `u64` — the convention of the nightly `fuzz-nightly.yml`, so the printed seed
/// is the number in the run's URL. Every job of a run gets the same seed; the attempt number is left out on purpose,
/// so re-running a failed job repeats the failing seed instead of drawing a new one that could hide it. A missing or
/// malformed run id, and one in [`DEFAULT_SEED_RANGE`], fail (no silent fallback to the defaults).
pub(crate) fn ci_run_seed_from(actions: Option<&str>, run_id: Option<&str>) -> Result<Option<u64>> {
    if actions != Some("true") {
        return Ok(None);
    }
    let id = run_id.map(str::trim).unwrap_or_default();
    if id.is_empty() {
        bail!(
            "GITHUB_ACTIONS=true without GITHUB_RUN_ID: no CI run seed for the property tests (M4 review R-93)"
        );
    }
    let seed: u64 = id
        .parse()
        .map_err(|e| Error(format!("GITHUB_RUN_ID={id:?} is not a decimal u64: {e}")))?;
    if DEFAULT_SEED_RANGE.contains(&seed) {
        bail!(
            "GITHUB_RUN_ID={seed} lies in the range of the DEFAULT_SEEDs ({:#x}..={:#x}): no distinct CI run seed",
            DEFAULT_SEED_RANGE.start(),
            DEFAULT_SEED_RANGE.end()
        );
    }
    Ok(Some(seed))
}

/// One `cargo nextest` invocation of the `nextest` or `kat` step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NextestRun {
    pub(crate) args: Vec<String>,
    /// `None`: [`SEED_ENV`] removed, every property with its `DEFAULT_SEED`; `Some`: set to the CI run seed.
    pub(crate) seed: Option<u64>,
}

impl NextestRun {
    pub(crate) fn cmd(&self) -> Cmd {
        let cmd = Cmd::cargo().args(self.args.iter().cloned());
        match self.seed {
            None => cmd.env_remove(SEED_ENV),
            Some(seed) => cmd.env(SEED_ENV, seed.to_string()),
        }
    }

    /// The shell command that repeats this invocation locally (arguments with spaces or shell characters quoted).
    pub(crate) fn reproduction(&self) -> String {
        let mut line = self
            .seed
            .map(|seed| format!("{SEED_ENV}={seed} "))
            .unwrap_or_default();
        line.push_str("cargo");
        for a in &self.args {
            line.push(' ');
            if a.chars()
                .any(|c| c.is_whitespace() || "|()^$*?'\"".contains(c))
            {
                line.push('\'');
                line.push_str(a);
                line.push('\'');
            } else {
                line.push_str(a);
            }
        }
        line
    }

    /// Run it; the CI-seed pass prints its seed first and names it, with the local reproduction, on failure.
    pub(crate) fn run(&self) -> Result<()> {
        let Some(seed) = self.seed else {
            return self.cmd().run();
        };
        say(&format!(
            "  property tests with the CI run seed {SEED_ENV}={seed} (GITHUB_RUN_ID); reproduce: {}",
            self.reproduction()
        ));
        self.cmd().run().map_err(|e| {
            Error(format!(
                "property tests with the CI run seed {SEED_ENV}={seed} failed (reproduce: {}): {e}",
                self.reproduction()
            ))
        })
    }
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_owned()).collect()
}

/// The invocations of the `nextest` step: the workspace run and the non-kat run of `secmp-proto` (M3 review F20),
/// both with [`SEED_ENV`] removed.
pub(crate) fn nextest_runs() -> Vec<NextestRun> {
    vec![
        NextestRun {
            args: owned(&gates::nextest_args()),
            seed: None,
        },
        NextestRun {
            args: owned(&gates::nextest_nonkat_args()),
            seed: None,
        },
    ]
}

/// The verdict line of the `nextest` step (one row per `; `-separated part in the ADR-045 summary).
pub(crate) fn nextest_detail() -> String {
    format!(
        "cargo nextest run --workspace; cargo nextest run --package secmp-proto (non-kat); both with {SEED_ENV} removed (every property with its DEFAULT_SEED, the CI run seed pass is in the kat step)"
    )
}

/// The kat run of one package: `cargo nextest run --locked --package <p> --features kat`.
pub(crate) fn kat_args(package: &str) -> Vec<String> {
    owned(&[
        "nextest",
        "run",
        "--locked",
        "--package",
        package,
        "--features",
        "kat",
    ])
}

/// The invocations of the `kat` step before its portable-backend reruns: the kat run of every package of `packages`
/// with [`SEED_ENV`] removed, then — with a CI run seed — the kat run of every [`PROPERTY_PACKAGES`] package filtered
/// to its property tests with [`SEED_ENV`] set to it. A property package that is not among `packages` fails.
pub(crate) fn kat_runs(
    packages: &BTreeSet<String>,
    ci_seed: Option<u64>,
) -> Result<Vec<NextestRun>> {
    let mut runs: Vec<NextestRun> = packages
        .iter()
        .map(|p| NextestRun {
            args: kat_args(p),
            seed: None,
        })
        .collect();
    if let Some(seed) = ci_seed {
        for p in PROPERTY_PACKAGES {
            if !packages.contains(*p) {
                bail!(
                    "property package {p} is not a KAT package: the CI-seed pass needs its `kat` run (M4 review R-93)"
                );
            }
            let mut args = kat_args(p);
            args.extend(["-E".to_owned(), property_filter()]);
            runs.push(NextestRun {
                args,
                seed: Some(seed),
            });
        }
    }
    Ok(runs)
}

/// The kat step's verdict part about the seeds.
pub(crate) fn kat_seed_detail(ci_seed: Option<u64>) -> String {
    match ci_seed {
        None => format!(
            "property tests with their DEFAULT_SEED only ({SEED_ENV} removed, no CI run seed outside GitHub Actions)"
        ),
        Some(seed) => {
            let again: Vec<String> = PROPERTY_PACKAGES
                .iter()
                .map(|p| {
                    let mut args = kat_args(p);
                    args.extend(["-E".to_owned(), property_filter()]);
                    NextestRun {
                        args,
                        seed: Some(seed),
                    }
                    .reproduction()
                })
                .collect();
            format!(
                "property tests with their DEFAULT_SEED ({SEED_ENV} removed); property tests of {} again with the CI run seed {SEED_ENV}={seed} (GITHUB_RUN_ID, reproduce: {})",
                PROPERTY_PACKAGES.join(", "),
                again.join(" && ")
            )
        }
    }
}

/// The source scans and their tests (test-only).
#[cfg(test)]
mod scan;
