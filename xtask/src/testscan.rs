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
    for file in crate::util::walk_files(&scheduler, &|p| p.extension().is_some_and(|x| x == "rs"))?
    {
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
        "scheduler/conversation.rs",
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
