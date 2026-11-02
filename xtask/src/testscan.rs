// SPDX-License-Identifier: AGPL-3.0-or-later
//! The seed of the property tests in a CI run, and source scans of the test suites.
//!
//! **Property seeds (M4 review R-93, TEST-SPEC-M5 X-07).** Every seeded property test takes its master seed from one
//! helper, `crates/secmp-proto/tests/common/seed.rs` (`scan::SEED_HELPER`): the decimal `u64` in
//! `SECMP_PROPTEST_SEED` if it is set and not empty, else the file's own `DEFAULT_SEED`. The property tests live in
//! the packages of [`PROPERTY_PACKAGES`], and their test crates need the feature `kat` (`secmp-relay`'s `relay` is
//! built by no workspace run), so the `kat` step carries the seeds ([`kat_runs`]), and for the testkit's `harness` binary
//! the `harness` step ([`harness_runs`], TEST-SPEC-M7 G7-07): it runs every KAT package with
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
pub(crate) const PROPERTY_PACKAGES: &[&str] = &[
    "secmp-client-core",
    "secmp-proto",
    "secmp-relay",
    "secmp-testkit",
];

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

/// The package of the testkit `harness` binary (TEST-SPEC-M7 G7-07, ADR-045 Amendment 12): the `harness` step is the
/// one runner of that binary, the `kat` step runs the rest of the package.
pub(crate) const HARNESS_PACKAGE: &str = "secmp-testkit";

/// The nextest filterset of the testkit `harness` binary.
pub(crate) const HARNESS_BINARY: &str = "binary(=harness)";

/// `args` with the filterset `filter`.
fn filtered(mut args: Vec<String>, filter: String) -> Vec<String> {
    args.extend(["-E".to_owned(), filter]);
    args
}

/// The invocations of the `kat` step before its portable-backend reruns: the kat run of every package of `packages`
/// with [`SEED_ENV`] removed — [`HARNESS_PACKAGE`] without its `harness` binary, which the `harness` step runs
/// ([`harness_runs`]) — then, with a CI run seed, the kat run of every other [`PROPERTY_PACKAGES`] package filtered to
/// its property tests with [`SEED_ENV`] set to it (the testkit's property tests are all in the `harness` binary). A
/// property package that is not among `packages` fails.
pub(crate) fn kat_runs(
    packages: &BTreeSet<String>,
    ci_seed: Option<u64>,
) -> Result<Vec<NextestRun>> {
    let mut runs: Vec<NextestRun> = packages
        .iter()
        .map(|p| NextestRun {
            args: if p == HARNESS_PACKAGE {
                filtered(kat_args(p), format!("not {HARNESS_BINARY}"))
            } else {
                kat_args(p)
            },
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
            if *p == HARNESS_PACKAGE {
                continue;
            }
            runs.push(NextestRun {
                args: filtered(kat_args(p), property_filter()),
                seed: Some(seed),
            });
        }
    }
    Ok(runs)
}

/// The invocations of the `harness` step (TEST-SPEC-M7 G7-07): the kat run of [`HARNESS_PACKAGE`] filtered to its
/// `harness` binary with [`SEED_ENV`] removed, then — with a CI run seed — the same filtered to the binary's property
/// tests with [`SEED_ENV`] set to it. Same arguments as the kat run of the package plus one filterset, so it reuses
/// that build.
pub(crate) fn harness_runs(ci_seed: Option<u64>) -> Vec<NextestRun> {
    let mut runs = vec![NextestRun {
        args: filtered(kat_args(HARNESS_PACKAGE), HARNESS_BINARY.to_owned()),
        seed: None,
    }];
    if let Some(seed) = ci_seed {
        runs.push(NextestRun {
            args: filtered(
                kat_args(HARNESS_PACKAGE),
                format!("({}) and {HARNESS_BINARY}", property_filter()),
            ),
            seed: Some(seed),
        });
    }
    runs
}

/// The `harness` step's verdict part about the seeds.
pub(crate) fn harness_seed_detail(ci_seed: Option<u64>) -> String {
    match ci_seed {
        None => format!(
            "{HARNESS_PACKAGE} harness binary; property tests with their DEFAULT_SEED only ({SEED_ENV} removed, no CI run seed outside GitHub Actions)"
        ),
        Some(seed) => {
            let again: Vec<String> = harness_runs(Some(seed))
                .iter()
                .filter(|r| r.seed.is_some())
                .map(NextestRun::reproduction)
                .collect();
            format!(
                "{HARNESS_PACKAGE} harness binary; property tests with their DEFAULT_SEED ({SEED_ENV} removed), then again with the CI run seed {SEED_ENV}={seed} (GITHUB_RUN_ID, reproduce: {})",
                again.join(" && ")
            )
        }
    }
}

/// The nextest filterset that leaves out `expect::WINDOWS_SKIP_TESTS` (each matched by its last path segment).
pub(crate) fn windows_skip_filter() -> String {
    let parts: Vec<String> = crate::expect::WINDOWS_SKIP_TESTS
        .iter()
        .map(|(name, _)| format!("test(/(^|::){name}$/)"))
        .collect();
    format!("not ({})", parts.join(" | "))
}

/// A kat run as it runs on Windows (WEISUNG M6-B-3 §1): without the tests of `expect::WINDOWS_SKIP_TESTS` — a run that
/// already has a filterset (the CI-seed property pass) gets the intersection, nextest's `-E` options being a union.
#[must_use]
pub(crate) fn windows_scoped(mut run: NextestRun) -> NextestRun {
    let skip = windows_skip_filter();
    if let Some(at) = run.args.iter().position(|a| a == "-E") {
        if let Some(filter) = run.args.get_mut(at.saturating_add(1)) {
            *filter = format!("({filter}) and {skip}");
        }
    } else {
        run.args.extend(["-E".to_owned(), skip]);
    }
    run
}

/// The kat step's verdict part about the seeds.
pub(crate) fn kat_seed_detail(ci_seed: Option<u64>) -> String {
    match ci_seed {
        None => format!(
            "property tests with their DEFAULT_SEED only ({SEED_ENV} removed, no CI run seed outside GitHub Actions)"
        ),
        Some(seed) => {
            let packages: Vec<&str> = PROPERTY_PACKAGES
                .iter()
                .copied()
                .filter(|p| *p != HARNESS_PACKAGE)
                .collect();
            let again: Vec<String> = packages
                .iter()
                .map(|p| {
                    NextestRun {
                        args: filtered(kat_args(p), property_filter()),
                        seed: Some(seed),
                    }
                    .reproduction()
                })
                .collect();
            format!(
                "property tests with their DEFAULT_SEED ({SEED_ENV} removed); property tests of {} again with the CI run seed {SEED_ENV}={seed} (GITHUB_RUN_ID, reproduce: {}; those of {HARNESS_PACKAGE} in the harness step)",
                packages.join(", "),
                again.join(" && ")
            )
        }
    }
}

/// Whether `line` is a `cfg` attribute that limits the next item to the `kat` feature (alone or with `test`).
#[cfg(test)]
fn is_kat_cfg(line: &str) -> bool {
    let t = line.trim();
    t == "#[cfg(feature = \"kat\")]" || t == "#[cfg(any(test, feature = \"kat\"))]"
}

/// The lines of a Rust source that lie outside every `kat`-gated item and outside the trailing `#[cfg(test)] mod tests`
/// module: a gated item starts at a line after an [`is_kat_cfg`] attribute and ends where its braces close (or at its
/// `;` when it has none).
#[cfg(test)]
fn ungated_lines(src: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut pending = false;
    let mut gated_depth: Option<i64> = None;
    let mut depth: i64 = 0;
    let mut in_tests = false;
    let mut prev_test_cfg = false;
    for (n, line) in src.lines().enumerate() {
        let t = line.trim();
        if prev_test_cfg && t.starts_with("mod tests") {
            in_tests = true;
        }
        prev_test_cfg = t == "#[cfg(test)]";
        let gated = in_tests || pending || gated_depth.is_some();
        if !gated && !t.starts_with("//") {
            out.push((n.saturating_add(1), line));
        }
        let before = depth;
        let opens = i64::try_from(line.matches('{').count()).unwrap_or(0);
        let closes = i64::try_from(line.matches('}').count()).unwrap_or(0);
        depth = depth.saturating_add(opens).saturating_sub(closes);
        if is_kat_cfg(line) {
            pending = true;
        } else if pending && !t.starts_with("#[") && !t.starts_with("///") && !t.is_empty() {
            pending = false;
            if depth > before {
                gated_depth = Some(before);
            }
        } else if gated_depth.is_some_and(|g| depth <= g) {
            gated_depth = None;
        }
    }
    out
}

/// Whether `lib` declares the store's `kat` module under `cfg(any(test, feature = "kat"))` (ST-09).
#[cfg(test)]
fn declares_kat_module(lib: &str) -> bool {
    lib.replace("\r\n", "\n")
        .contains("#[cfg(any(test, feature = \"kat\"))]\npub mod kat;")
}

/// V1-F7 (extra test): the declaration check of ST-09 holds for LF and for CRLF text (a Windows checkout) and fails
/// without the `cfg` line.
#[cfg(test)]
#[test]
fn kat_mod_declaration_matches_crlf() {
    let lf = "#[cfg(any(test, feature = \"kat\"))]\npub mod kat;\n";
    assert!(declares_kat_module(lf));
    assert!(declares_kat_module(&lf.replace('\n', "\r\n")));
    assert!(!declares_kat_module("pub mod kat;\n"));
}

/// TEST-SPEC-M7 ST-09 (`docs/06` §2; M4 review RT-2): the test-only constructors stay test-only. In every shipped
/// crate's `src/` (all but `secmp-testkit`): `kat_small` is defined only under `cfg(feature = "kat")` (one site since
/// A-4: `secmp-store` `wrap::Argon2Params::kat_small`); every line naming `TestKey`, `CrashAt` or `FailAt` is inside a
/// `kat`-gated item, a test module, or `secmp-store/src/kat.rs`, which `lib.rs` declares under
/// `cfg(any(test, feature = "kat"))`; at least one `TestKey` site exists; and `cargo tree -e features -p secmp-cli` shows no `kat` feature.
#[cfg(test)]
#[test]
fn kat_argon2_params_only_with_kat() -> Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let store_lib = std::fs::read_to_string(root.join("crates/secmp-store/src/lib.rs"))?;
    assert!(declares_kat_module(&store_lib));
    let mut test_key_sites = 0_usize;
    let mut kat_small_sites = 0_usize;
    let mut bad = Vec::new();
    for file in crate::util::walk_files(&root.join("crates"), &|p| {
        p.extension().is_some_and(|x| x == "rs")
            && p.components().any(|c| c.as_os_str() == "src")
            && !p.components().any(|c| c.as_os_str() == "secmp-testkit")
    })? {
        let rel = crate::util::rel(&root, &file);
        let src = std::fs::read_to_string(&file)?.replace("\r\n", "\n");
        let words = |l: &str, w: &str| {
            l.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|x| x == w)
        };
        for line in src.lines() {
            if words(line, "TestKey") {
                test_key_sites = test_key_sites.saturating_add(1);
            }
            if words(line, "kat_small") && line.contains("fn kat_small") {
                kat_small_sites = kat_small_sites.saturating_add(1);
            }
        }
        if rel.ends_with("crates/secmp-store/src/kat.rs") {
            continue;
        }
        for (n, line) in ungated_lines(&src) {
            for w in ["TestKey", "CrashAt", "FailAt", "kat_small"] {
                if words(line, w) {
                    bad.push(format!("{rel}:{n}: {w}"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "outside a kat gate: {bad:?}");
    assert!(test_key_sites >= 1, "no TestKey site");
    assert_eq!(kat_small_sites, 1, "kat_small: one site (A-4, secmp-store)");
    let tree = Cmd::cargo()
        .args(["tree", "--locked", "-e", "features", "-p", "secmp-cli"])
        .read()?;
    assert!(!tree.contains("feature \"kat\""), "{tree}");
    assert!(!tree.contains("feature \"harness\""));
    // the scanner itself: a gated item and a test module are skipped, an ungated line is found
    let fixture = "fn a() { TestKey }\n#[cfg(feature = \"kat\")]\nfn b() {\n    TestKey\n}\nfn c() {}\n#[cfg(test)]\nmod tests {\n    TestKey\n}\n";
    let lines: Vec<usize> = ungated_lines(fixture)
        .into_iter()
        .filter(|(_, l)| l.contains("TestKey"))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(lines, [1]);
    Ok(())
}

/// The names of the store and of its client-side implementations (`secmp-client-core/src/{persist,outbox}.rs`), as
/// [`scheduler_sees_only_traits`] looks for them.
#[cfg(test)]
const STORE_NAMES: &[&str] = &[
    "secmp_store",
    "secmp-store",
    "StorePersist",
    "StoreOutbox",
    "SharedStore",
    "crate::persist",
    "crate::outbox",
];

/// The lines of `src` that name one of [`STORE_NAMES`], comments included.
#[cfg(test)]
fn store_lines(src: &str) -> Vec<(usize, &str)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| STORE_NAMES.iter().any(|w| l.contains(w)))
        .map(|(i, l)| (i.saturating_add(1), l))
        .collect()
}

/// TEST-SPEC-M7 PC-12 (OB-07; `docs/02:104`): the scheduler sees only the `Outbox` and `Persist` traits — no file under
/// `crates/secmp-client-core/src/scheduler/**` names the store crate (`secmp_store`, `secmp-store`), its client-side
/// implementations (`StorePersist`, `StoreOutbox`, `SharedStore`) or their modules (`crate::persist`, `crate::outbox`),
/// not even in a comment; the scan reads at least the scheduler's known files, and finds the names where they are.
#[cfg(test)]
#[test]
fn scheduler_sees_only_traits() -> Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let scheduler = root.join("crates/secmp-client-core/src/scheduler");
    let mut files = Vec::new();
    let mut bad = Vec::new();
    // Q171: the scan reads `scheduler/**` and `sessions/actor.rs` (the conversation moved there, SE-18)
    let mut scanned =
        crate::util::walk_files(&scheduler, &|p| p.extension().is_some_and(|x| x == "rs"))?;
    scanned.push(root.join("crates/secmp-client-core/src/sessions/actor.rs"));
    for file in scanned {
        let rel = crate::util::rel(&root, &file);
        let src = std::fs::read_to_string(&file)?;
        for (n, line) in store_lines(&src) {
            bad.push(format!("{rel}:{n}: {}", line.trim()));
        }
        files.push(rel);
    }
    assert!(bad.is_empty(), "the scheduler names the store: {bad:?}");
    for known in [
        "scheduler/mod.rs",
        "scheduler/outbox.rs",
        "sessions/actor.rs",
        "scheduler/run.rs",
    ] {
        assert!(
            files.iter().any(|f| f.ends_with(known)),
            "{known} not scanned: {files:?}"
        );
    }
    // the positive control: the implementations outside the scheduler name the store
    for outside in ["persist.rs", "outbox.rs"] {
        let src = std::fs::read_to_string(root.join("crates/secmp-client-core/src").join(outside))?;
        assert!(!store_lines(&src).is_empty(), "{outside}");
    }
    Ok(())
}

/// The function a line of `lines` lies in: the nearest line at or above it that declares a function (`fn <name>`).
#[cfg(test)]
fn enclosing_fn(lines: &[&str], at: usize) -> Option<String> {
    lines.get(..=at)?.iter().rev().find_map(|line| {
        let t = line.trim_start();
        let decl = !t.starts_with("//")
            && (t.starts_with(concat!("fn", " ")) || t.contains(concat!(" fn", " ")));
        let after = t.split_once(concat!("fn", " "))?.1;
        decl.then(|| {
            after
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default()
                .to_owned()
        })
    })
}

/// The lines of function `name` in `lines`: from its declaration to the next function declaration.
#[cfg(test)]
fn fn_body(lines: &[&str], name: &str) -> String {
    let decl = format!("{} {name}", "fn");
    let declares = |l: &&&str| {
        l.split_once(&decl)
            .is_some_and(|(_, rest)| rest.starts_with('(') || rest.starts_with('<'))
    };
    let Some(start) = lines.iter().position(|l| declares(&l)) else {
        return String::new();
    };
    let rest = lines.get(start.saturating_add(1)..).unwrap_or_default();
    let end = rest
        .iter()
        .position(|l| {
            let t = l.trim_start();
            !t.starts_with("//")
                && (t.starts_with(concat!("fn", " ")) || t.contains(concat!(" fn", " ")))
        })
        .map_or(lines.len(), |n| start.saturating_add(1).saturating_add(n));
    lines.get(start..end).unwrap_or_default().join("\n")
}

/// Whether `body` keeps an inline `saturating_sub(…fetch_lead_ms)`: a `saturating_sub(` whose argument names the lead.
#[cfg(test)]
fn inline_lead(body: &str) -> bool {
    body.match_indices(concat!("saturating", "_sub("))
        .any(|(at, needle)| {
            body.get(at.saturating_add(needle.len())..)
                .and_then(|rest| rest.split(')').next())
                .is_some_and(|arg| arg.contains(concat!("fetch", "_lead_ms")))
        })
}

/// TEST-SPEC-M7 SC-10 `kc5_calls_extracted` (Q157, path deviation D-B3): the deadline arithmetic K-C5
/// (`kani_deadline_arithmetic_checked`) proves is the production code's. `pure::fetch_lead_deadline` and
/// `pure::flush_bound` (`core/pure.rs`, where they are defined and unit-tested) are called, outside `core/pure.rs`, from
/// exactly the named sites — the lead deadline of `next_deadline`, the driver's `flush_wait`, and the K-C5 harness; the
/// `FETCH` lead of `prepare_link` goes through `pure::fetch_due` (called from `prepare_link` and the SC-09 harness only),
/// which calls `fetch_lead_deadline` (WEISUNG M7-B-SC2b, the Q183 amendment) — and none of those bodies keeps the inline
/// expression
/// (`saturating_sub(…fetch_lead_ms)`, `saturating_add(250)`, `saturating_add(FLUSH_WAIT_MS)`). CRLF is normalised; the
/// needles are spelled in parts so that this file matches none of them.
#[cfg(test)]
#[test]
fn kc5_calls_extracted() -> Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let src = root.join("crates/secmp-client-core/src");
    let lead_fn = concat!("fetch", "_lead_deadline(");
    let flush_fn = concat!("flush", "_bound(");
    // Q183 amendment (WEISUNG M7-B-SC2b): prepare_link reaches the lead through pure::fetch_due
    let due_fn = concat!("fetch", "_due(");
    let mut calls: Vec<(String, String, String)> = Vec::new();
    let mut texts = std::collections::BTreeMap::new();
    for file in crate::util::walk_files(&src, &|p| p.extension().is_some_and(|x| x == "rs"))? {
        let rel = crate::util::rel(&src, &file);
        let text = std::fs::read_to_string(&file)?.replace("\r\n", "\n");
        if !rel.ends_with("core/pure.rs") {
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                for needle in [lead_fn, flush_fn, due_fn] {
                    if code.contains(needle) {
                        let site = enclosing_fn(&lines, n).unwrap_or_default();
                        calls.push((rel.clone(), site, needle.trim_end_matches('(').to_owned()));
                    }
                }
            }
        }
        texts.insert(rel, text);
    }
    calls.sort();
    let lead = concat!("fetch", "_lead_deadline");
    let flush = concat!("flush", "_bound");
    let due = concat!("fetch", "_due");
    let mut want: Vec<(String, String, String)> = [
        ("kani_proofs.rs", "kani_deadline_arithmetic_checked", lead),
        ("kani_proofs.rs", "kani_deadline_arithmetic_checked", flush),
        ("scheduler/core/mod.rs", "next_deadline", lead),
        // the SC-09 harness `kani_paired_executions`, through its run `balanced_run`
        ("kani_proofs.rs", "balanced_run", due),
        ("scheduler/core/mod.rs", "prepare_link", due),
        ("scheduler/run.rs", "flush_wait", flush),
    ]
    .into_iter()
    .map(|(f, s, n)| (f.to_owned(), s.to_owned(), n.to_owned()))
    .collect();
    want.sort();
    assert_eq!(calls, want, "the call sites of the K-C5 functions");
    for (file, site) in [
        ("scheduler/core/mod.rs", "prepare_link"),
        ("scheduler/core/mod.rs", "next_deadline"),
        ("scheduler/run.rs", "flush_wait"),
        ("kani_proofs.rs", "kani_deadline_arithmetic_checked"),
    ] {
        let text = texts.get(file).map_or("", String::as_str);
        let lines: Vec<&str> = text.lines().collect();
        let body = fn_body(&lines, site);
        assert!(!body.is_empty(), "{file}: {site} not found");
        assert!(!inline_lead(&body), "{file}: {site} keeps the inline lead");
        for needle in [
            concat!("saturating", "_add(250)"),
            concat!("saturating", "_add(FLUSH", "_WAIT_MS)"),
        ] {
            assert!(!body.contains(needle), "{file}: {site} keeps `{needle}`");
        }
    }
    // the positive control of the needles: the definitions keep the arithmetic
    let pure = texts
        .get("scheduler/core/pure.rs")
        .map_or("", String::as_str);
    let lines: Vec<&str> = pure.lines().collect();
    assert!(inline_lead("x.saturating_sub(self.params.fetch_lead_ms)"));
    assert!(!inline_lead("x.saturating_sub(lead)"));
    assert!(fn_body(&lines, flush).contains(concat!("saturating", "_add(FLUSH", "_WAIT_MS)")));
    // the chain prepare_link -> fetch_due -> fetch_lead_deadline (the `pure.rs` exclusion lifted for this needle only)
    let due_body = fn_body(&lines, due);
    assert!(
        due_body.contains(lead_fn),
        "pure::fetch_due does not call fetch_lead_deadline: {due_body:?}"
    );
    assert_eq!(
        enclosing_fn(&["    pub fn outer() {", "        let x = 1;"], 1).as_deref(),
        Some("outer")
    );
    let generic = [
        "    fn g<S: X>(",
        "        a.saturating_add(250)",
        "    fn h() {",
    ];
    assert!(fn_body(&generic, "g").contains("saturating_add(250)"));
    assert!(!fn_body(&generic, "g").contains("fn h"));
    Ok(())
}

/// The source scans and their tests (test-only).
#[cfg(test)]
mod scan;

/// TEST-SPEC-M7 SE-18 (`docs/02:104`; Q152, Q171): the ratchet is driven in one place — no file of `secmp-client-core/src`
/// but `sessions/actor.rs` calls a `RatchetState` constructor or method (`RatchetState::…`, `.encrypt_with(`,
/// `.decrypt_with(`, `.decrypt_first_with(`, `.to_parts(`, and — Q212 (9), VERIFY-B4 P3 m-5 — `.encrypt(`, `.decrypt(`,
/// `.to_bytes(`). The `#[cfg(test)] mod tests` of a file (V-18), the test helper files (`testutil.rs`, `*_tests.rs`) and
/// `kani_proofs.rs` are excluded; `.to_bytes(` is a name other types share, so the two calls of it on other types are
/// pinned exceptions (an addition is a change of this test). A text scan: a call through an alias or a re-export is not
/// seen. The scan finds the calls where they are (the actor) and a fixture with a call outside it, one per needle.
#[cfg(test)]
#[test]
fn session_actor_owns_ratchet() -> Result<()> {
    fn calls(src: &str) -> Vec<(usize, String)> {
        let product = src
            .replace("\r\n", "\n")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default()
            .to_owned();
        let needles = [
            concat!("RatchetState", "::"),
            concat!(".encrypt", "_with("),
            concat!(".decrypt", "_with("),
            concat!(".decrypt_first", "_with("),
            concat!(".to_", "parts("),
            concat!(".encrypt", "("),
            concat!(".decrypt", "("),
            concat!(".to_", "bytes("),
        ];
        // the `.to_bytes(` calls on other types (Q212 (9)): an `InvitationRecord`, the joining of `RatchetParts` by the
        // in-memory `Persist`
        let other_types = [
            concat!("v.extend_from_slice(&self.record.to_", "bytes());"),
            concat!(
                "let bytes = parts.ratchet.to_",
                "bytes().map_err(|_| PersistError)?;"
            ),
        ];
        product
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim_start().starts_with("//"))
            .filter(|(_, l)| needles.iter().any(|n| l.contains(n)))
            .filter(|(_, l)| !other_types.contains(&l.trim()))
            .map(|(i, l)| (i.saturating_add(1), l.trim().to_owned()))
            .collect()
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let src = root.join("crates/secmp-client-core/src");
    let mut outside = Vec::new();
    let mut inside = 0_usize;
    for file in crate::util::walk_files(&src, &|p| p.extension().is_some_and(|x| x == "rs"))? {
        let rel = crate::util::rel(&root, &file);
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "testutil.rs" || name == "kani_proofs.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let found = calls(&std::fs::read_to_string(&file)?);
        if rel.ends_with("sessions/actor.rs") {
            inside = found.len();
        } else {
            outside.extend(found.into_iter().map(|(n, l)| format!("{rel}:{n}: {l}")));
        }
    }
    assert!(
        outside.is_empty(),
        "RatchetState used outside the actor: {outside:?}"
    );
    assert!(inside >= 5, "the scan finds the actor's calls: {inside}");
    // the fixture: a call outside the actor is found; a test module is skipped
    let fixture = format!(
        "fn a() {{ s{} }}\n#[cfg(test)]\nmod tests {{\n    fn t() {{ s{} }}\n}}\n",
        concat!(".encrypt", "_with(c, e)"),
        concat!(".to_", "parts()")
    );
    assert_eq!(calls(&fixture).len(), 1);
    // one fixture per needle of Q212 (9); a pinned other-type call is not one
    for call in [
        concat!(".encrypt", "(c)"),
        concat!(".decrypt", "(b)"),
        concat!(".to_", "bytes()"),
    ] {
        assert_eq!(
            calls(&format!("fn a() {{ state{call}; }}\n")).len(),
            1,
            "{call}"
        );
    }
    assert!(
        calls(concat!(
            "        v.extend_from_slice(&self.record.to_",
            "bytes());\n"
        ))
        .is_empty()
    );
    Ok(())
}

/// The product part of a Rust source (CRLF-normalised, the `#[cfg(test)] mod tests` cut off).
#[cfg(test)]
fn product(src: &str) -> String {
    src.replace("\r\n", "\n")
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// The declarations of `src` that are public API: every `pub` item header, every `pub` field, and the whole body of a `pub
/// enum` (its variants carry types) — as `(line, text)`. Items gated by `#[cfg(feature = "kat")]` are test-only accessors
/// of the shipped crate and left out; so are comments.
#[cfg(test)]
fn public_surface(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let lines: Vec<&str> = product(src)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .leak()
        .iter()
        .map(String::as_str)
        .collect();
    let (mut i, mut gated) = (0_usize, false);
    while let Some(line) = lines.get(i).copied() {
        let t = line.trim();
        if t == r#"#[cfg(feature = "kat")]"# {
            gated = true;
            i = i.saturating_add(1);
            continue;
        }
        if t.starts_with("//") || t.starts_with("#[") || t.is_empty() {
            i = i.saturating_add(1);
            continue;
        }
        // the extent of the item starting here: to its closing brace at this indent, or its `;`/`,` for a one-liner
        let indent = line.len().saturating_sub(line.trim_start().len());
        let mut end = i;
        let mut text = String::new();
        loop {
            let l = lines.get(end).copied().unwrap_or_default();
            text.push_str(l.trim());
            text.push(' ');
            let done_here = l.trim_end().ends_with(';')
                || (l.trim_end().ends_with(',') && !l.contains('{'))
                || l.trim_end().ends_with('{');
            if done_here || end.saturating_add(1) >= lines.len() {
                break;
            }
            end = end.saturating_add(1);
        }
        let public = t.starts_with("pub ") && !t.starts_with("pub(");
        let opens_block = text.trim_end().ends_with('{');
        if opens_block {
            // find the closing line of the block
            let close = (end.saturating_add(1)..lines.len())
                .find(|k| {
                    let l = lines.get(*k).copied().unwrap_or_default();
                    l.trim() == "}"
                        || (l.trim_start().starts_with('}')
                            && l.len().saturating_sub(l.trim_start().len()) == indent)
                })
                .unwrap_or(lines.len().saturating_sub(1));
            let is_enum = t.starts_with("pub enum ");
            if public && !gated {
                if is_enum {
                    for k in i..=close {
                        out.push((
                            k.saturating_add(1),
                            lines.get(k).copied().unwrap_or_default().trim().to_owned(),
                        ));
                    }
                } else {
                    out.push((i.saturating_add(1), text.trim().to_owned()));
                }
            }
            // the members of an impl or a struct are items of their own: look inside, unless this item is gated or an enum
            if gated || is_enum || t.starts_with("fn ") || t.contains(" fn ") {
                i = close.saturating_add(1);
            } else {
                i = i.saturating_add(1);
            }
        } else {
            if public && !gated {
                out.push((i.saturating_add(1), text.trim().to_owned()));
            }
            i = end.saturating_add(1);
        }
        gated = false;
    }
    out
}

/// Whether `word` occurs in `text` as a whole identifier.
#[cfg(test)]
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text
            .get(at.saturating_add(word.len())..)
            .and_then(|s| s.chars().next());
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

/// TEST-SPEC-M7 AP-02 (`docs/02` §4.5, §6): the `Api` exposes no store type and no secret — no public item of
/// `secmp-client-core/src/api.rs` (a signature, a field, a variant) names the store crate, its handle types, a secret
/// newtype (`SecretBytes`, `SecretPage`, `LockedSecret`), a key type or the ratchet state. Test-only (`kat`) accessors are not
/// part of the shipped surface. The scan finds the public items where they are, and a fixture that leaks a store handle.
#[cfg(test)]
#[test]
fn api_exposes_no_secrets_or_store() -> Result<()> {
    const FORBIDDEN: &[&str] = &[
        "secmp_store",
        "Store",
        "StoreOutbox",
        "StorePersist",
        "StoreConversation",
        "SharedStore",
        "SecretBytes",
        "SecretPage",
        "LockedSecret",
        "RatchetState",
        "HybridSigningKey",
        "Ed25519SigningKey",
        "X25519Secret",
        "MlKem768Dk",
        "MlKem1024Dk",
        "IdentityKeys",
        "Unlocked",
        "DbKey",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let src = std::fs::read_to_string(root.join("crates/secmp-client-core/src/api.rs"))?;
    let items = public_surface(&src);
    let leaks: Vec<String> = items
        .iter()
        .filter(|(_, text)| FORBIDDEN.iter().any(|w| has_word(text, w)))
        .map(|(n, text)| format!("api.rs:{n}: {text}"))
        .collect();
    assert!(leaks.is_empty(), "the Api exposes: {leaks:?}");
    // the scan sees the surface: the request and response enums, the handle, the core
    for name in [
        "pub enum Request",
        "pub enum Response",
        "pub enum Event",
        "pub struct Api",
        "pub struct Core",
        "pub async fn call",
        "pub fn handle",
    ] {
        assert!(items.iter().any(|(_, t)| t.starts_with(name)), "{name}");
    }
    assert!(items.len() > 40, "{} public declarations", items.len());
    // the fixtures: a leaked handle is found, a kat-gated accessor and a private field are not
    let leak = "pub struct Core {\n    pub store: SharedStore,\n    secret: SecretBytes<32>,\n}\n";
    assert!(
        public_surface(leak)
            .iter()
            .any(|(_, t)| has_word(t, "SharedStore"))
    );
    assert!(
        !public_surface(leak)
            .iter()
            .any(|(_, t)| has_word(t, "SecretBytes"))
    );
    let gated = "impl Core {\n    #[cfg(feature = \"kat\")]\n    pub fn open_kat(a: secmp_store::wrap::Argon2Params) {}\n}\n";
    assert!(
        public_surface(gated)
            .iter()
            .all(|(_, t)| !has_word(t, "secmp_store"))
    );
    let variant = "pub enum Response {\n    Done,\n    Handle(DbKey),\n}\n";
    assert!(
        public_surface(variant)
            .iter()
            .any(|(_, t)| has_word(t, "DbKey"))
    );
    Ok(())
}

/// The attribute lines (`#[…]`) right above the declaration of the struct or enum `name` in the product part of `src`,
/// joined; `None` if `src` declares no such type.
#[cfg(test)]
fn attributes_of(src: &str, name: &str) -> Option<String> {
    let text = product(src);
    let lines: Vec<&str> = text.lines().collect();
    let declares = |l: &str| {
        let t = l.trim_start();
        let t = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        ["struct ", "enum "].iter().any(|k| {
            t.strip_prefix(k)
                .and_then(|rest| rest.strip_prefix(name))
                .is_some_and(|after| {
                    !after
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
        })
    };
    let at = lines.iter().position(|l| declares(l))?;
    let mut attrs = Vec::new();
    for l in lines.get(..at).unwrap_or_default().iter().rev() {
        let t = l.trim();
        if t.starts_with("#[") {
            attrs.push(t);
        } else if !t.starts_with("///") {
            break;
        }
    }
    Some(attrs.join(" "))
}

/// Q206 (VERIFY-B4 P1 B-2; CLAUDE.md §1.6): no type of `secmp-client-core/src` that carries a passphrase, a message
/// payload, a view-once plaintext, a seed or a key derives `Debug` — `Request`, `Response` and `Event` have a redacting
/// `Debug` by hand, the others none. The list is pinned here (an addition is a change of this test); every listed type
/// must be found, and a fixture with a derive is caught.
#[cfg(test)]
#[test]
fn no_derive_debug_on_secret_carriers() -> Result<()> {
    const CARRIERS: &[(&str, &str)] = &[
        ("api.rs", "Request"),
        ("api.rs", "Response"),
        ("api.rs", "Event"),
        ("api.rs", "RotationDone"),
        ("hub.rs", "Action"),
        ("invitations.rs", "Stored"),
        ("invitations.rs", "PoolQueue"),
        ("invitations.rs", "SparePool"),
        ("invitations.rs", "Issuance"),
        ("invitations.rs", "OpenQueue"),
        ("invitations.rs", "LinkPutArgs"),
        ("persist.rs", "EntryKey"),
        ("sessions/actor.rs", "Received"),
        ("sessions/actor.rs", "Conversation"),
        ("sessions/mod.rs", "Outgoing"),
        ("sessions/rotation.rs", "QueueEntry"),
        ("sessions/rotation.rs", "QueueSet"),
        ("scheduler/outbox.rs", "OutMessage"),
        ("scheduler/outbox.rs", "DeliveredMessage"),
        ("scheduler/outbox.rs", "CommitParts"),
        ("scheduler/outbox.rs", "MemPersist"),
    ];
    fn derives_debug(attrs: &str) -> bool {
        attrs
            .split("#[")
            .any(|a| a.trim_start().starts_with("derive(") && has_word(a, "Debug"))
    }
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/secmp-client-core/src");
    let mut derived = Vec::new();
    for (file, name) in CARRIERS {
        let src = std::fs::read_to_string(root.join(file))?;
        let Some(attrs) = attributes_of(&src, name) else {
            bail!("{file}: no type {name}");
        };
        if derives_debug(&attrs) {
            derived.push(format!("{file}: {name}: {attrs}"));
        }
    }
    assert!(
        derived.is_empty(),
        "secret carriers derive Debug: {derived:?}"
    );
    // the fixtures: a listed type with a derive is caught, one with another derive is not
    let fixture = "/// A request.\n#[derive(Clone, Debug)]\n#[non_exhaustive]\npub enum Request {\n    A,\n}\n";
    assert!(attributes_of(fixture, "Request").is_some_and(|a| derives_debug(&a)));
    let other = "#[derive(Clone)]\npub(crate) struct Stored {\n    seed: [u8; 32],\n}\n";
    assert!(attributes_of(other, "Stored").is_some_and(|a| !derives_debug(&a)));
    assert!(attributes_of(other, "Store").is_none());
    Ok(())
}

/// The public signatures of the product part of `src` (`pub fn`, `pub const fn`, `pub type`), each joined to one line up to
/// its `{` or `;`, as `(line, text)`; an item right after `#[cfg(feature = "kat")]` (doc comments between) is left out.
#[cfg(test)]
fn public_signatures(src: &str) -> Vec<(usize, String)> {
    let text = product(src);
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut gated = false;
    let mut i = 0_usize;
    while let Some(line) = lines.get(i) {
        let t = line.trim();
        if t == r#"#[cfg(feature = "kat")]"# {
            gated = true;
        } else if ["pub fn ", "pub const fn ", "pub type "]
            .iter()
            .any(|k| t.starts_with(k))
        {
            let mut sig = String::new();
            let mut k = i;
            while let Some(l) = lines.get(k) {
                sig.push_str(l.trim());
                sig.push(' ');
                if l.contains('{') || l.trim_end().ends_with(';') {
                    break;
                }
                k = k.saturating_add(1);
            }
            if !gated {
                out.push((i.saturating_add(1), sig.trim().to_owned()));
            }
            gated = false;
            i = k;
        } else if !t.starts_with("///") && !t.starts_with("#[") && !t.is_empty() {
            gated = false;
        }
        i = i.saturating_add(1);
    }
    out
}

/// The public functions of `src` (outside `kat`-gated items and the test module, [`public_signatures`]) that hand out
/// queue seeds as plain bytes: a name or the file's path holds one of the needles (`seed`, `material`) and the return type
/// holds `[u8; 32]` or a public type alias of `src` that does — plus every such alias whose name holds a needle.
#[cfg(test)]
fn plain_seed_returns(path: &str, src: &str) -> Vec<(usize, String)> {
    const NEEDLES: &[&str] = &["seed", "material"];
    const PLAIN: &str = "[u8; 32]";
    let items = public_signatures(src);
    let named = |text: &str| NEEDLES.iter().any(|n| text.to_lowercase().contains(n));
    let mut aliases = Vec::new();
    let mut out = Vec::new();
    for (line, text) in &items {
        if let Some(rest) = text.strip_prefix("pub type ")
            && let Some((name, def)) = rest.split_once('=')
            && def.contains(PLAIN)
        {
            let name = name.trim().to_owned();
            if named(&name) {
                out.push((*line, text.clone()));
            }
            aliases.push(name);
        }
    }
    for (line, text) in &items {
        let Some(signature) = text
            .strip_prefix("pub fn ")
            .or_else(|| text.strip_prefix("pub const fn "))
        else {
            continue;
        };
        let name: String = signature
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let Some((_, returns)) = signature.split_once("->") else {
            continue;
        };
        let plain = returns.contains(PLAIN) || aliases.iter().any(|a| has_word(returns, a));
        if plain && (named(&name) || named(path)) {
            out.push((*line, text.clone()));
        }
    }
    out
}
/// Q211 (VERIFY-B4 P1 M-5 = P2 M-4; CLAUDE.md §1.6): no public function of `secmp-client-core/src` outside `kat`/test
/// items returns queue seeds as plain `[u8; 32]` (or through a type alias that holds one) — they are `SecretBytes<32>`,
/// an absent sender seed is `None`. The needles are pinned here; the scan finds a fixture's plain return and alias.
#[cfg(test)]
#[test]
fn no_plain_seed_returns() -> Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let src = root.join("crates/secmp-client-core/src");
    let mut found = Vec::new();
    let mut fns = 0_usize;
    for file in crate::util::walk_files(&src, &|p| p.extension().is_some_and(|x| x == "rs"))? {
        let rel = crate::util::rel(&root, &file);
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "testutil.rs" || name == "kani_proofs.rs" || name.ends_with("tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file)?;
        fns = fns.saturating_add(
            public_signatures(&text)
                .iter()
                .filter(|(_, t)| t.starts_with("pub fn "))
                .count(),
        );
        found.extend(
            plain_seed_returns(&rel, &text)
                .into_iter()
                .map(|(n, t)| format!("{rel}:{n}: {t}")),
        );
    }
    assert!(found.is_empty(), "plain seed returns: {found:?}");
    assert!(fns > 100, "the scan sees the public functions: {fns}");
    // the fixtures: a plain return by name, through an alias, by path; a typed one and a kat-gated one pass
    let fixture = "pub type PoolSeeds = (QueueId, [u8; 32], [u8; 32]);\n\
                   pub fn queue_material(&self) -> Option<([u8; 32], [u8; 32])> {\n    None\n}\n\
                   pub fn seeds(&self) -> Vec<PoolSeeds> {\n    Vec::new()\n}\n\
                   pub fn typed_seed(&self) -> SecretBytes<32> {\n    todo()\n}\n\
                   #[cfg(feature = \"kat\")]\n\
                   pub fn seed_kat(&self) -> [u8; 32] {\n    [0; 32]\n}\n";
    let hits = plain_seed_returns("crates/x/src/a.rs", fixture);
    assert_eq!(hits.len(), 3, "{hits:?}");
    let by_path = "pub fn fingerprint(&self) -> [u8; 32] {\n    [0; 32]\n}\n";
    assert!(plain_seed_returns("crates/x/src/a.rs", by_path).is_empty());
    assert_eq!(
        plain_seed_returns("crates/x/src/seeds.rs", by_path).len(),
        1
    );
    Ok(())
}

/// The names `secmp_transport` items are used under in `src` (CRLF-normalised, tests and comments left out): every
/// identifier of a `secmp_transport::…` path or `use` list, without the aliases after `as`.
#[cfg(test)]
fn transport_names(src: &str) -> BTreeSet<String> {
    let text = product(src);
    let mut names = BTreeSet::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("secmp_transport::") {
        let (before, after) = rest.split_at(at);
        let line_start = before.rfind('\n').map_or(0, |n| n.saturating_add(1));
        let commented = before
            .get(line_start..)
            .is_some_and(|l| l.trim_start().starts_with("//"));
        let tail = after.get("secmp_transport::".len()..).unwrap_or_default();
        // a path ends at `;`, or at the first space/paren outside braces
        let mut depth = 0_usize;
        let mut end = tail.len();
        for (k, c) in tail.char_indices() {
            match c {
                '{' => depth = depth.saturating_add(1),
                '}' => depth = depth.saturating_sub(1),
                ';' | '(' | ',' | ' ' | ')' | '\n' | '<' | '>' | '?' | '.' if depth == 0 => {
                    end = k;
                    break;
                }
                _ => {}
            }
        }
        let path = tail.get(..end).unwrap_or_default();
        rest = tail.get(end..).unwrap_or_default();
        if commented {
            continue;
        }
        let mut skip_next = false;
        for token in path
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
        {
            if skip_next {
                skip_next = false;
            } else if token == "as" {
                skip_next = true;
            } else if token != "self" {
                names.insert(token.to_owned());
            }
        }
    }
    names
}

/// TEST-SPEC-M7 AP-04 (Q153; `docs/07:147`, §12.2 `docs/03:748`): no identifier reaches a transport type. The modules of
/// `secmp-client-core` that import `secmp_transport` are exactly `scheduler::core`, `scheduler::run` and `kani_proofs`; and
/// every `secmp_transport` item they name is a capability or cell type of the allowlist or one of the plumbing names pinned
/// here from `grep -rn secmp_transport crates/secmp-client-core/src` at the head of B-6. A new name needs a change of this
/// test. AP-05 is the dynamic identifier oracle.
#[cfg(test)]
#[test]
fn no_identifiers_reach_transport_types() -> Result<()> {
    /// The capability and wire types the allowlist of Q153 names.
    const TYPES: &[&str] = &[
        "RecvCap", "SendCap", "LdId", "LinkBlob", "Cell", "CellId", "Token", "RelayRef", "Period",
        "Bucket", "OwnerKey",
    ];
    /// The plumbing the scheduler core and its tokio driver use (`secmp_transport::channel::counters` is the `kat` counters;
    /// `driver::…` is the async transport the tokio driver runs).
    const PLUMBING: &[&str] = &[
        "AsyncConnectOutcome",
        "AsyncRelayQueueTransport",
        "AsyncSession",
        "Channel",
        "Command",
        "EitherStream",
        "Error",
        "Isolation",
        "Outcome",
        "Prepared",
        "ProviderStream",
        "QueueRef",
        "StreamProvider",
        "channel",
        "counters",
        "driver",
        "evicted",
        "evicted_is_plausible",
        "seal_calls",
        "sign_calls",
    ];
    const IMPORTERS: &[&str] = &[
        "crates/secmp-client-core/src/kani_proofs.rs",
        "crates/secmp-client-core/src/scheduler/core/mod.rs",
        "crates/secmp-client-core/src/scheduler/run.rs",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let src = root.join("crates/secmp-client-core/src");
    let mut importers = BTreeSet::new();
    let mut named: BTreeSet<String> = BTreeSet::new();
    for file in crate::util::walk_files(&src, &|p| p.extension().is_some_and(|x| x == "rs"))? {
        let rel = crate::util::rel(&root, &file);
        let used = transport_names(&std::fs::read_to_string(&file)?);
        if !used.is_empty() {
            importers.insert(rel);
            named.extend(used);
        }
    }
    let want: BTreeSet<String> = IMPORTERS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(importers, want, "the modules that import secmp_transport");
    let allowed: BTreeSet<&str> = TYPES.iter().chain(PLUMBING).copied().collect();
    let outside: Vec<&String> = named
        .iter()
        .filter(|n| !allowed.contains(n.as_str()))
        .collect();
    assert!(
        outside.is_empty(),
        "secmp_transport items outside the allowlist: {outside:?}"
    );
    // the scan finds what is there (the core names the capabilities), and the fixtures:
    assert!(named.contains("RecvCap") && named.contains("SendCap") && named.contains("Channel"));
    let fixture = "use secmp_transport::{Channel, Error as TransportError, ProviderStream};\nfn f() -> secmp_transport::LinkBlobPart {}\n";
    let found = transport_names(fixture);
    assert!(
        found.contains("Channel") && found.contains("Error") && found.contains("ProviderStream")
    );
    assert!(!found.contains("TransportError"), "an alias is not an item");
    assert!(found.contains("LinkBlobPart"), "an inline path is found");
    assert!(transport_names("// secmp_transport::Channel\n").is_empty());
    assert!(
        transport_names("#[cfg(test)]\nmod tests {\n    use secmp_transport::Channel;\n}\n")
            .is_empty()
    );
    Ok(())
}

/// TEST-SPEC-M7 AP-06 (`docs/02` §3, the dependency direction): `secmp-transport` depends, directly or through any chain,
/// on neither `secmp-store` nor `secmp-client-core` (`cargo metadata`, normal dependencies: its dev-dependency on the test
/// kit is the harness of its own tests).
#[cfg(test)]
#[test]
fn transport_has_no_core_or_store_dep() -> Result<()> {
    let ws = crate::meta::Workspace::load()?;
    let id_of = |name: &str| {
        ws.all
            .iter()
            .find(|(_, (n, _, member))| n == name && *member)
            .map(|(id, _)| id.clone())
    };
    let transport =
        id_of("secmp-transport").ok_or_else(|| Error("secmp-transport is not a member".into()))?;
    let mut seen = BTreeSet::new();
    let mut stack = vec![transport];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for (dep, normal) in ws.edges.get(&id).map(Vec::as_slice).unwrap_or_default() {
            // the dev-dependency on the test kit (the harness of its own tests) is not a direction of the product
            if *normal {
                stack.push(dep.clone());
            }
        }
    }
    let names: BTreeSet<&str> = seen
        .iter()
        .filter_map(|id| ws.all.get(id).map(|(n, _, _)| n.as_str()))
        .collect();
    for forbidden in ["secmp-store", "secmp-client-core"] {
        assert!(
            !names.contains(forbidden),
            "secmp-transport reaches {forbidden}"
        );
    }
    // the graph is read: the transport reaches the crates it is documented to use, and the core does reach the transport
    assert!(
        names.contains("secmp-proto") && names.contains("secmp-crypto"),
        "{names:?}"
    );
    let core = id_of("secmp-client-core")
        .ok_or_else(|| Error("secmp-client-core is not a member".into()))?;
    let core_deps: BTreeSet<&str> = ws
        .edges
        .get(&core)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|(id, _)| ws.all.get(id).map(|(n, _, _)| n.as_str()))
        .collect();
    assert!(core_deps.contains("secmp-transport") && core_deps.contains("secmp-store"));
    Ok(())
}
