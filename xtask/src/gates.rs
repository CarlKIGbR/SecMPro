// SPDX-License-Identifier: AGPL-3.0-or-later
//! The individual gates of docs/06 §5. Each returns an [`Outcome`] or fails; the driver in `ci.rs` decides
//! what a skip means (`--strict` turns every skip into a failure).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::ci::{Ctx, Outcome};
use crate::ctreport;
use crate::expect;
use crate::tools;
use crate::util::{Cmd, Error, Result, bail, rel, say, walk_files};

/// Compare a discovered input set with the expected one (`expect.rs`); any difference fails.
pub(crate) fn same_set(what: &str, discovered: &BTreeSet<String>, expected: &[&str]) -> Result<()> {
    let want: BTreeSet<String> = expected.iter().map(|s| (*s).to_owned()).collect();
    if *discovered != want {
        let missing: Vec<&String> = want.difference(discovered).collect();
        let extra: Vec<&String> = discovered.difference(&want).collect();
        bail!(
            "{what}: discovered set differs from xtask/src/expect.rs (missing: {missing:?}, unexpected: {extra:?})"
        );
    }
    Ok(())
}

fn list(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "none".to_owned()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

// ---- steps 1–5 -------------------------------------------------------------------------------------------

pub(crate) fn fmt(_: &Ctx) -> Result<Outcome> {
    Cmd::cargo().args(["fmt", "--all", "--check"]).run()?;
    Ok(Outcome::Pass("rustfmt: no changes".into()))
}

pub(crate) fn clippy(ctx: &Ctx) -> Result<Outcome> {
    Cmd::cargo()
        .args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ])
        .run()?;
    Ok(Outcome::Pass(format!(
        "clippy --all-features -D warnings on {} ({} crates)",
        ctx.host,
        ctx.ws.members.len()
    )))
}

pub(crate) fn policy(ctx: &Ctx) -> Result<Outcome> {
    let mut detail = crate::policy::run(&ctx.ws)?;
    detail.push_str("; ");
    detail.push_str(&workflows(&ctx.root)?);
    Ok(Outcome::Pass(detail))
}

pub(crate) fn deny(_: &Ctx) -> Result<Outcome> {
    tools::require(tools::DENY)?;
    Cmd::cargo().args(["deny", "--locked", "check"]).run()?;
    Ok(Outcome::Pass(
        "advisories, bans, licenses, sources: ok".into(),
    ))
}

pub(crate) fn vet(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::VET)?;
    Cmd::cargo().args(["vet", "--locked"]).run()?;
    Ok(Outcome::Pass(crate::policy::check_vet_closure(&ctx.ws)?))
}

pub(crate) fn audit(_: &Ctx) -> Result<Outcome> {
    tools::require(tools::AUDIT)?;
    let mut c = Cmd::cargo().args(["audit", "--deny", "warnings"]);
    for (id, _) in expect::AUDIT_IGNORES {
        c = c.args(["--ignore", id]);
    }
    c.run()?;
    let ignored: Vec<&str> = expect::AUDIT_IGNORES.iter().map(|(id, _)| *id).collect();
    Ok(Outcome::Pass(format!(
        "RustSec: no advisories (warnings denied); ignored with an ADR: {}",
        if ignored.is_empty() {
            "none".to_owned()
        } else {
            ignored.join(", ")
        }
    )))
}

pub(crate) fn cooldown(ctx: &Ctx) -> Result<Outcome> {
    Ok(Outcome::Pass(crate::cooldown::run(&ctx.root)?))
}

/// The workspace `cargo nextest` arguments (feature unification enables `kat` of `secmp-proto` through `secmp-testkit`).
pub(crate) fn nextest_args() -> Vec<&'static str> {
    vec![
        "nextest",
        "run",
        "--workspace",
        "--locked",
        "--no-fail-fast",
    ]
}

/// M3 review F20 (R-48): the non-kat run of the shipped configuration of `secmp-proto`. `--workspace` unifies the
/// `kat` feature, so the package is selected alone, without `--features kat`.
pub(crate) fn nextest_nonkat_args() -> Vec<&'static str> {
    vec![
        "nextest",
        "run",
        "--locked",
        "--no-fail-fast",
        "--package",
        "secmp-proto",
    ]
}

/// The workspace run and the non-kat run with `SECMP_PROPTEST_SEED` removed (every property with its `DEFAULT_SEED`;
/// the CI run seed pass is in `kat`, M4 review R-93, TEST-SPEC-M5 X-07, `testscan.rs`).
pub(crate) fn nextest(_: &Ctx) -> Result<Outcome> {
    tools::require(tools::NEXTEST)?;
    for run in crate::testscan::nextest_runs() {
        run.run()?;
    }
    Ok(Outcome::Pass(crate::testscan::nextest_detail()))
}

pub(crate) fn doctest(_: &Ctx) -> Result<Outcome> {
    Cmd::cargo()
        .args(["test", "--workspace", "--locked", "--doc"])
        .run()?;
    Ok(Outcome::Pass("cargo test --doc".into()))
}

/// Run every workspace binary once and show its banner (the M0 hello-world; on Windows this is the evidence
/// collected by `win-test`).
pub(crate) fn hello(_: &Ctx) -> Result<Outcome> {
    let mut banners = Vec::new();
    for bin in expect::BINARIES {
        let out = Cmd::cargo()
            .args(["run", "--quiet", "--locked", "--package", bin, "--bin", bin])
            .read()?;
        let line = out.trim().to_owned();
        if !line.starts_with(&format!("{bin} ")) {
            bail!("{bin}: unexpected banner {line:?}");
        }
        say(&format!("  hello-world: {line}"));
        banners.push(line);
    }
    Ok(Outcome::Pass(banners.join(" | ")))
}

/// The test targets `kat` runs a second time with libcrux's portable backend, per package.
pub(crate) const KAT_PORTABLE_RERUN: &[(&str, &[&str])] = &[
    ("secmp-crypto", &["kat_mlkem", "vectors"]),
    ("secmp-proto", &["tr_vectors", "hx", "link"]),
];

pub(crate) fn kat(ctx: &Ctx) -> Result<Outcome> {
    let found: BTreeSet<String> = ctx
        .ws
        .members
        .iter()
        .filter(|p| p.features.contains("kat"))
        .map(|p| p.name.clone())
        .collect();
    same_set("KAT packages (feature `kat`)", &found, expect::KAT_PACKAGES)?;
    // every package with SECMP_PROPTEST_SEED removed, then in a GitHub Actions run the property packages' property
    // tests with the CI run seed (M4 review R-93, TEST-SPEC-M5 X-07; `testscan.rs`)
    let ci_seed = crate::testscan::ci_run_seed()?;
    for run in crate::testscan::kat_runs(&found, ci_seed)? {
        run.run()?;
    }
    // libcrux's build scripts compile its SIMD backends on aarch64 (NEON) and x86_64 (AVX2, chosen at run time),
    // so the run above tests the backend this host uses. A CPU without AVX2 runs the portable backend: the ML-KEM
    // KATs and the frozen vectors run again with the SIMD backends compiled out (own target directory, because
    // the build scripts do not declare the variables and Cargo would reuse a stale build) — `secmp-crypto`'s M1
    // suites, from M3 the `tr` suite of `secmp-proto` (ML-KEM-768 at every ratchet step) and, from M4, its `hx`
    // suite (the handshake's ML-KEM-768 encapsulations, the frozen HX vectors and the generator; docs/06 §5, M4
    // review R-94).
    let portable_dir = ctx.root.join("target").join("kat-portable");
    for &(package, tests) in KAT_PORTABLE_RERUN {
        let mut args = vec![
            "nextest",
            "run",
            "--locked",
            "--package",
            package,
            "--features",
            "kat",
        ];
        for t in tests {
            args.push("--test");
            args.push(t);
        }
        Cmd::cargo()
            .args(args)
            .env("LIBCRUX_DISABLE_SIMD128", "1")
            .env("LIBCRUX_DISABLE_SIMD256", "1")
            .env("CARGO_TARGET_DIR", portable_dir.to_string_lossy())
            .env_remove(crate::testscan::SEED_ENV)
            .run()?;
    }
    Ok(Outcome::Pass(format!(
        "KAT/differential packages: {} (expected set matches); ML-KEM KATs and frozen vectors (M1 suites, tr, hx, link) also with libcrux's portable backend; {}",
        list(&found),
        crate::testscan::kat_seed_detail(ci_seed)
    )))
}

/// dudect-style constant-time tests (docs/06 §2, §4; ADR-038, ADR-041 with Amendment 1): `cargo bench --package
/// secmp-testkit --features kat --bench ct` (`crates/secmp-testkit/benches/ct.rs`, ADR-042) in the release profile,
/// timed with the CPU counter; per target two measurements, FAIL only for a shift reproduced at the same crop and
/// sign (|t| > 4.5) that reaches the effect floor (one effective quantum, at least 10 ns), a reproduced smaller shift
/// reported as `SUB_FLOOR_SHIFT`; the positive control must be detected; a failing inline A/A control or a
/// sensitivity control (`min_leak_control`) below the floor makes the run `CONTROL_FAIL`; a target the runner's timer
/// cannot resolve is NOT MEASURABLE. All but PASS and `SUB_FLOOR_SHIFT` fail the gate with their wording.
///
/// ADR-045 Amendment 1 (M4 review C-1): the bench is built first, then its executable runs with stdout and stderr in
/// `target/ct-bench.log` while the gate echoes every line the bench appends to `target/ct-progress.jsonl` (one per
/// finished phase of a target); after `expect::CT_STEP_TIMEOUT_SECONDS` the gate kills it and fails naming the target
/// and phase of the last progress line. No target is ever skipped.
pub(crate) fn ct(ctx: &Ctx) -> Result<Outcome> {
    let dir = ctx.root.join("target");
    let report = dir.join("ct-report.json");
    let progress = dir.join("ct-progress.jsonl");
    let log = dir.join("ct-bench.log");
    for f in [&report, &progress] {
        if f.exists() {
            std::fs::remove_file(f)?;
        }
    }
    let exe = ct_bench_executable()?;
    // M2 review C3 (c): the full sample counts of expect.rs, whatever the caller's environment says; the arguments
    // and working directory `cargo bench` gives a bench
    let bench = Cmd::new(exe)
        .arg("--bench")
        .dir(ctx.root.join("crates").join("secmp-testkit"))
        .env_remove("SECMP_CT_SCALE");
    let success = run_ct_bench(
        &bench,
        &log,
        &progress,
        std::time::Duration::from_secs(expect::CT_STEP_TIMEOUT_SECONDS),
    )?;
    let json = std::fs::read_to_string(&report).map_err(|e| {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        for l in lines.iter().skip(lines.len().saturating_sub(20)) {
            say(&format!("  {l}"));
        }
        Error(format!(
            "ct: no report written ({e}); bench log {}",
            log.display()
        ))
    })?;
    // the whole report first (clock, both measurements, per-crop t), so a CI log carries it even on failure
    say(&format!("  ct report: {}", json.trim_end()));
    let table = ctreport::ct_table(&json)?;
    // M3 review R-45 (F19): each target's claimed reject site on its verdict line; a missing or failed pre-check fails
    let (lines, mut problems) = ct_site_lines(&json, &table.lines)?;
    for l in &lines {
        say(&format!("  ct {l}"));
    }
    if !table.not_measurable.is_empty() {
        problems.push(format!(
            "ct: not measurable on this runner: {}",
            table.not_measurable.join(", ")
        ));
    }
    if !table.failed.is_empty() {
        problems.push(format!(
            "constant-time test failed: {}",
            table.failed.join("; ")
        ));
    }
    if !success && problems.is_empty() {
        problems.push("ct: the bench failed without a failing target in its report".to_owned());
    }
    if !problems.is_empty() {
        bail!("{}", problems.join("; "));
    }
    Ok(Outcome::Pass(lines.join("; ")))
}

/// Build the ct bench (`cargo bench --no-run`, release profile, feature `kat`) and return the path of its executable.
/// The gate runs the executable itself, so a kill at the step budget stops the measurement, not only `cargo`.
fn ct_bench_executable() -> Result<String> {
    let out = Cmd::cargo()
        .args([
            "bench",
            "--locked",
            "--package",
            "secmp-testkit",
            "--features",
            "kat",
            "--bench",
            "ct",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .read()?;
    ct_bench_executable_in(&out).ok_or_else(|| {
        Error("ct: `cargo bench --no-run` named no executable of the bench `ct`".to_owned())
    })
}

/// The executable of the bench `ct` among cargo's JSON messages.
fn ct_bench_executable_in(messages: &str) -> Option<String> {
    messages
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("reason").and_then(Value::as_str) == Some("compiler-artifact"))
        .filter(|v| {
            let target = v.get("target");
            target.and_then(|t| t.get("name")).and_then(Value::as_str) == Some("ct")
                && target
                    .and_then(|t| t.get("kind"))
                    .and_then(Value::as_array)
                    .is_some_and(|k| k.iter().any(|k| k.as_str() == Some("bench")))
        })
        .find_map(|v| {
            v.get("executable")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

/// How often the ct gate polls the bench and its progress file: seldom, so the poll adds no load next to a timing
/// measurement.
const CT_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// ADR-045 Amendment 1 (M4 review C-1): run the ct bench `bench` with stdout and stderr in `log`, echo each new
/// complete line of `progress` (the bench appends one JSON object per finished phase), and stop the bench once
/// `timeout` has passed: the gate then fails naming the target and phase of the last progress line. Returns whether
/// the bench exited successfully.
pub(crate) fn run_ct_bench(
    bench: &Cmd,
    log: &Path,
    progress: &Path,
    timeout: std::time::Duration,
) -> Result<bool> {
    let mut tail = LineTail::new(progress);
    let mut last = None;
    let status = run_budgeted(bench, log, timeout, CT_POLL, || {
        for line in tail.lines() {
            say(&format!("  ct progress {line}"));
            last = Some(ct_progress_label(&line));
        }
    })?;
    match status {
        Some(status) => Ok(status.success()),
        None => bail!(
            "ct: timeout, killed after {} s; last progress: {}; bench log {}, progress {}",
            timeout.as_secs(),
            last.as_deref()
                .unwrap_or("none (no line in the progress file)"),
            log.display(),
            progress.display()
        ),
    }
}

/// `<target> <phase>` of a progress line of the ct bench, or the raw line if it is not such an object.
fn ct_progress_label(line: &str) -> String {
    let v: Option<Value> = serde_json::from_str(line).ok();
    let field = |k: &str| v.as_ref().and_then(|v| v.get(k)).and_then(Value::as_str);
    match (field("target"), field("phase")) {
        (Some(t), Some(p)) => format!("{t} {p}"),
        _ => line.to_owned(),
    }
}

/// The complete lines a growing file gained since the last read (ADR-045 Amendment 1: the progress of a gate that
/// runs for hours).
struct LineTail {
    path: PathBuf,
    read: usize,
}

impl LineTail {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            read: 0,
        }
    }

    /// The complete, non-empty lines appended since the last call; none while the file is missing. A file shorter than
    /// what was read has been truncated by a new run and is read from its start.
    fn lines(&mut self) -> Vec<String> {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return Vec::new();
        };
        if bytes.len() < self.read {
            self.read = 0;
        }
        let new = bytes.get(self.read..).unwrap_or_default();
        let Some(end) = new.iter().rposition(|b| *b == b'\n') else {
            return Vec::new();
        };
        let complete = new.get(..=end).unwrap_or_default();
        self.read = self.read.saturating_add(complete.len());
        String::from_utf8_lossy(complete)
            .lines()
            .map(str::trim_end)
            .filter(|l| !l.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// How long a child stopped at its budget may take to end after SIGINT before it is killed (cargo-mutants stops its
/// own `cargo` children on an interrupt; a kill of the parent alone would leave them running). Unix only: elsewhere
/// the child is killed at once (`stop_child`).
#[cfg(unix)]
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Run `cmd` with stdin closed and stdout and stderr in `log` under the wall-clock budget `timeout` (ADR-045
/// Amendment 1; M4 review C-1, C-3), calling `poll` every `every` and once more after the end. Returns the exit status,
/// or `None` if the budget ran out: the child was then stopped (on Unix with SIGINT first, then killed after
/// `STOP_GRACE`) and reaped.
fn run_budgeted(
    cmd: &Cmd,
    log: &Path,
    timeout: std::time::Duration,
    every: std::time::Duration,
    mut poll: impl FnMut(),
) -> Result<Option<std::process::ExitStatus>> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error("the step budget is out of range".to_owned()))?;
    let mut child = cmd.spawn_logged(log)?;
    loop {
        let status = child.try_wait()?;
        poll();
        if let Some(status) = status {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= deadline {
            stop_child(&mut child)?;
            poll();
            return Ok(None);
        }
        std::thread::sleep(every);
    }
}

/// Stop a child at its budget and reap it: SIGINT first on Unix (a tool may end its own children), a kill if it is
/// still running after `STOP_GRACE`; elsewhere a kill at once. The child may have exited meanwhile: a failed signal
/// or kill is then harmless.
fn stop_child(child: &mut std::process::Child) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let until = std::time::Instant::now().checked_add(STOP_GRACE);
        while until.is_some_and(|u| std::time::Instant::now() < u) {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    let _ = child.kill();
    child.wait()?;
    Ok(())
}

/// The `ct` gate's reading of the reject sites (M3 review R-45, F19; the bench's per-class pre-checks). Each target
/// line of `lines` (from [`ctreport::ct_table`], which ignores the report's `site` and `precheck`) gets ` — site
/// <site>` at the end of its first `; `-segment — the segment with the target's name and verdict, which is one row
/// of the step's summary (ADR-045, `summary::step_rows`). Problems: a target with a site but no passed pre-check; a
/// site outside `expect::KNOWN_SITES` (M4 review R-63); and, by the binding of `expect::CT_TARGET_SITES` (M4 review
/// R-47, TEST-SPEC-M5 X-08), a listed target that claims another known site or none, and a target not listed that
/// claims a site. (A pre-check that fails aborts the bench, whose report then carries only `error`, which
/// [`ctreport::ct_table`] refuses.)
fn ct_site_lines(json: &str, lines: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("ct report: {e}")))?;
    let results = v
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut problems = Vec::new();
    let mut sites: Vec<(String, &str)> = Vec::new();
    for r in results {
        let name = r.get("name").and_then(Value::as_str).unwrap_or("?");
        let passed = r
            .get("precheck")
            .and_then(|p| p.get("passed"))
            .and_then(Value::as_bool)
            == Some(true);
        // M4 review R-47 (TEST-SPEC-M5 X-08): the site this target is bound to, if it claims one
        let bound = expect::CT_TARGET_SITES
            .iter()
            .find(|(target, _)| *target == name)
            .map(|(_, site)| *site);
        match r.get("site").and_then(Value::as_str) {
            Some(site) => {
                if !expect::KNOWN_SITES.contains(&site) {
                    problems.push(format!(
                        "ct: {name} claims the unknown reject site {site:?} (expect::KNOWN_SITES, M4 review R-63)"
                    ));
                } else if bound != Some(site) {
                    problems.push(match bound {
                        Some(b) => format!(
                            "ct: {name} claims the reject site {site:?}, but expect::CT_TARGET_SITES binds it to \
                             {b:?} (M4 review R-47)"
                        ),
                        None => format!(
                            "ct: {name} claims the reject site {site:?}, but expect::CT_TARGET_SITES binds no site \
                             to it (M4 review R-47)"
                        ),
                    });
                }
                if !passed {
                    problems.push(format!(
                        "ct: {name} claims the reject site {site:?} without a passed per-class pre-check (M3 \
                         review R-45)"
                    ));
                }
                sites.push((format!("{name}: "), site));
            }
            None if bound.is_some() => problems.push(format!(
                "ct: {name} has no reject site and per-class pre-check in the report (M3 review R-45)"
            )),
            None => {}
        }
    }
    let lines = lines
        .iter()
        .map(|l| {
            let Some((_, site)) = sites
                .iter()
                .find(|(prefix, _)| l.starts_with(prefix.as_str()))
            else {
                return l.clone();
            };
            match l.split_once("; ") {
                Some((head, tail)) => format!("{head} — site {site}; {tail}"),
                None => format!("{l} — site {site}"),
            }
        })
        .collect();
    Ok((lines, problems))
}

/// docs/07 M3 acceptance "encrypt+decrypt of a message < 3 ms" (M3 plan D11): `cargo run --release --locked -p
/// secmp-proto --example tr-perf -- target/tr-perf.txt` (`crates/secmp-proto/examples/tr-perf.rs`: one session with
/// OS randomness, `expect::TR_PERF_MESSAGES` timed messages of each kind of `expect::TR_PERF_KINDS`, each encrypt,
/// persist, decrypt and commit), then the report is read (`tr_perf`) and every kind's **maximum** must stay below
/// `expect::TR_PERF_MAX_MS` (`tr_perf_verdict`).
pub(crate) fn perf(ctx: &Ctx) -> Result<Outcome> {
    let report = ctx.root.join("target").join("tr-perf.txt");
    if report.exists() {
        std::fs::remove_file(&report)?;
    }
    let run = Cmd::cargo()
        .args([
            "run",
            "--release",
            "--locked",
            "-p",
            "secmp-proto",
            "--example",
            "tr-perf",
            "--",
            "target/tr-perf.txt",
        ])
        .dir(&ctx.root)
        .run();
    let text = match std::fs::read_to_string(&report) {
        Ok(text) => text,
        Err(e) => {
            // a build failure or a crash: its error first
            run?;
            bail!("perf: no report written ({e})");
        }
    };
    for line in text.lines() {
        say(&format!("  tr-perf {line}"));
    }
    // an `error=` line (the example's reason) before the bare exit status
    let perf = tr_perf(&text)?;
    run?;
    Ok(Outcome::Pass(tr_perf_verdict(&perf)?))
}

/// The `perf` report of `tr-perf`: the host triple, the message count and, per kind of `expect::TR_PERF_KINDS`,
/// (kind, median µs, maximum µs).
#[derive(Debug, PartialEq)]
pub(crate) struct TrPerf {
    pub(crate) host: String,
    pub(crate) n: usize,
    pub(crate) kinds: Vec<(String, f64, f64)>,
}

/// Read the `key=value` lines of a `tr-perf` report: exactly the keys `host`, `n`, `warmup` and, for every kind of
/// `expect::TR_PERF_KINDS`, `<kind>_median_us` and `<kind>_max_us`, each once; `n` = `expect::TR_PERF_MESSAGES`; every
/// time finite, non-negative and the median at most the maximum. An `error=` line is the example's failure.
pub(crate) fn tr_perf(text: &str) -> Result<TrPerf> {
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some((key, value)) = line.split_once('=') else {
            bail!("tr-perf: not a key=value line: {line:?}");
        };
        if key == "error" {
            bail!("tr-perf failed: {value}");
        }
        if values.insert(key, value).is_some() {
            bail!("tr-perf: {key} given twice");
        }
    }
    let mut keys = vec!["host".to_owned(), "n".to_owned(), "warmup".to_owned()];
    for kind in expect::TR_PERF_KINDS {
        keys.push(format!("{kind}_median_us"));
        keys.push(format!("{kind}_max_us"));
    }
    let found: BTreeSet<String> = values.keys().map(|k| (*k).to_owned()).collect();
    same_set(
        "tr-perf report keys",
        &found,
        &keys.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let get = |key: &str| values.get(key).copied().unwrap_or_default();
    let n: usize = get("n")
        .parse()
        .map_err(|_| Error(format!("tr-perf: n = {:?} is not a count", get("n"))))?;
    if n != expect::TR_PERF_MESSAGES {
        bail!(
            "tr-perf: {n} messages per kind, expect::TR_PERF_MESSAGES is {}",
            expect::TR_PERF_MESSAGES
        );
    }
    get("warmup").parse::<usize>().map_err(|_| {
        Error(format!(
            "tr-perf: warmup = {:?} is not a count",
            get("warmup")
        ))
    })?;
    let micros = |key: String| -> Result<f64> {
        match get(&key).parse::<f64>() {
            Ok(x) if x.is_finite() && x >= 0.0 => Ok(x),
            _ => bail!("tr-perf: {key} = {:?} is not a time in µs", get(&key)),
        }
    };
    let mut kinds = Vec::new();
    for kind in expect::TR_PERF_KINDS {
        let median = micros(format!("{kind}_median_us"))?;
        let max = micros(format!("{kind}_max_us"))?;
        if median > max {
            bail!("tr-perf: {kind} median {median} µs above its maximum {max} µs");
        }
        kinds.push(((*kind).to_owned(), median, max));
    }
    Ok(TrPerf {
        host: get("host").to_owned(),
        n,
        kinds,
    })
}

/// The `perf` verdict: every kind's maximum below `expect::TR_PERF_MAX_MS` (a maximum of exactly the limit fails).
pub(crate) fn tr_perf_verdict(perf: &TrPerf) -> Result<String> {
    let limit_us = expect::TR_PERF_MAX_MS * 1000.0;
    let rows: Vec<String> = perf
        .kinds
        .iter()
        .map(|(kind, median, max)| format!("{kind}: median {median:.1} µs, max {max:.1} µs"))
        .collect();
    let slow: Vec<String> = perf
        .kinds
        .iter()
        .filter(|(_, _, max)| *max >= limit_us)
        .map(|(kind, _, max)| format!("{kind} maximum {max:.1} µs"))
        .collect();
    if !slow.is_empty() {
        bail!(
            "encrypt+decrypt of a message must stay below {} ms (docs/07 M3): {} ({})",
            expect::TR_PERF_MAX_MS,
            slow.join(", "),
            rows.join("; ")
        );
    }
    Ok(format!(
        "encrypt+persist+decrypt+commit per message, {} messages per kind on {}: {}; every maximum below {} ms",
        perf.n,
        perf.host,
        rows.join("; "),
        expect::TR_PERF_MAX_MS
    ))
}

// ---- steps 6–10 ------------------------------------------------------------------------------------------

fn file_stems(dir: &Path, ext: &str) -> Result<BTreeSet<String>> {
    if !dir.exists() {
        return Ok(BTreeSet::new());
    }
    Ok(
        walk_files(dir, &|p: &Path| p.extension().is_some_and(|e| e == ext))?
            .iter()
            .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .collect(),
    )
}

/// Step 6, the fuzz smoke (docs/06 §4): every target of `expect::FUZZ_TARGETS` for `expect::FUZZ_SMOKE_SECONDS`.
///
/// Per target (M2 review F7): the seeding step (`fuzzseed::seed_scratch_corpus`) deletes and re-creates the scratch
/// corpus `target/fuzz-corpus/<t>/` and writes the inputs derived from the frozen vectors into it (the mapping from
/// suites to targets and layouts is the table of `fuzzseed.rs`: `msg_open` ← `msgencrypt`, `caead_open` ← `caead`,
/// `mlkem_parse` and `x25519_dh` ← `hybridkem-768`/`-1024`, `ed25519_verify`, `hybrid_sign_verify` and
/// `mldsa65_verify` ← `hybridsign`, the five `proto_*` targets ← every decodable `encodings` row by structure →
/// selector; a target without a rule relies on its tracked corpus); then libFuzzer runs on the scratch corpus
/// **first** and the tracked `fuzz/corpus/<t>/` second (`fuzz_args`). libFuzzer writes new inputs only into the
/// first corpus directory, so the gate never changes the tracked corpus; crashes go to `fuzz/artifacts/<t>/`.
/// `-max_len` comes from `expect::FUZZ_MAX_LEN` (M2 review C4, F18). Every target runs even after a failure, so the
/// log shows all of them.
pub(crate) fn fuzz(ctx: &Ctx) -> Result<Outcome> {
    let (targets, seeds) = fuzz_with(ctx, expect::FUZZ_SMOKE_SECONDS)?;
    Ok(Outcome::Pass(format!(
        "fuzz smoke, {} s per target on the vector-seeded scratch corpus plus the tracked corpus (read-only), \
         -max_len from expect::FUZZ_MAX_LEN: {targets} (expected set matches); vector seeds: {seeds}",
        expect::FUZZ_SMOKE_SECONDS
    )))
}

/// The scheduled campaign (`.github/workflows/fuzz-nightly.yml`, docs/06 §4 "nightly 4 h", M2 review F2): the gate
/// of [`fuzz`] with `expect::FUZZ_NIGHTLY_SECONDS` shared equally by the targets (`nightly_seconds_per_target`).
/// Not part of `ci-full`; the workflow uploads the scratch corpus and any crash artefacts.
pub(crate) fn fuzz_nightly(ctx: &Ctx) -> Result<Outcome> {
    let seconds =
        nightly_seconds_per_target(expect::FUZZ_NIGHTLY_SECONDS, expect::FUZZ_TARGETS.len())?;
    let (targets, seeds) = fuzz_with(ctx, seconds)?;
    Ok(Outcome::Pass(format!(
        "fuzz campaign, {} s in total, {seconds} s per target on the vector-seeded scratch corpus plus the tracked \
         corpus (read-only), -max_len from expect::FUZZ_MAX_LEN: {targets}; vector seeds: {seeds}; new inputs in \
         target/fuzz-corpus/",
        expect::FUZZ_NIGHTLY_SECONDS
    )))
}

/// Each target's share of a campaign of `total` seconds; never below the per-PR smoke.
pub(crate) fn nightly_seconds_per_target(total: u64, targets: usize) -> Result<u64> {
    let n = u64::try_from(targets).map_err(|_| Error("too many fuzz targets".to_owned()))?;
    match total.checked_div(n) {
        Some(s) if s >= expect::FUZZ_SMOKE_SECONDS => Ok(s),
        Some(s) => bail!(
            "fuzz campaign: {s} s per target is below the per-PR smoke of {} s",
            expect::FUZZ_SMOKE_SECONDS
        ),
        None => bail!("fuzz campaign: no targets"),
    }
}

/// Seed and fuzz every target for `seconds`; returns the target list and the seed counts for the summary.
fn fuzz_with(ctx: &Ctx, seconds: u64) -> Result<(String, String)> {
    tools::require(tools::FUZZ)?;
    tools::require_nightly(&[])?;
    let found = file_stems(&ctx.root.join("fuzz").join("fuzz_targets"), "rs")?;
    same_set("fuzz targets", &found, expect::FUZZ_TARGETS)?;
    let missing =
        targets_without_corpus(&ctx.root.join("fuzz").join("corpus"), expect::FUZZ_TARGETS);
    if !missing.is_empty() {
        bail!(
            "fuzz: no tracked seed in fuzz/corpus/<target>/ for {} (libFuzzer refuses the missing second corpus directory)",
            missing.join(", ")
        );
    }
    let mut seeded = Vec::new();
    let mut failed = Vec::new();
    for t in &found {
        let n = crate::fuzzseed::seed_scratch_corpus(&ctx.root, t)?;
        say(&format!(
            "  {t}: {n} vector seeds in target/fuzz-corpus/{t}/"
        ));
        seeded.push(format!("{t} {n}"));
        let run = Cmd::cargo_on(tools::NIGHTLY)
            .args(fuzz_args(t, seconds)?)
            .dir(&ctx.root)
            .run();
        if let Err(e) = run {
            say(&format!("  FAIL {t}: {e}"));
            failed.push(t.clone());
        }
    }
    if !failed.is_empty() {
        bail!(
            "fuzz: {} of {} targets failed: {} (inputs in fuzz/artifacts/<target>/)",
            failed.len(),
            found.len(),
            failed.join(", ")
        );
    }
    Ok((list(&found), seeded.join(", ")))
}

/// M4 review C-6 (R-07): the targets of `targets` whose tracked corpus `corpus/<t>/` holds no regular file. The fuzz
/// gate passes that directory as libFuzzer's second corpus, which must exist; a seed is committed for every target
/// (no `.gitkeep`: libFuzzer would read it as an empty input).
pub(crate) fn targets_without_corpus(corpus: &Path, targets: &[&str]) -> Vec<String> {
    targets
        .iter()
        .filter(|t| {
            std::fs::read_dir(corpus.join(t)).map_or(true, |entries| {
                !entries
                    .filter_map(std::result::Result::ok)
                    .any(|e| e.file_type().is_ok_and(|ft| ft.is_file()))
            })
        })
        .map(|t| (*t).to_owned())
        .collect()
}

/// The arguments of `cargo fuzz run` for target `t` (M2 review F7, F18): the scratch corpus first (libFuzzer's
/// output directory), the tracked corpus second (read only), then the libFuzzer options — the time budget, the
/// target's `-max_len` and the per-input `-timeout` (`expect::FUZZ_INPUT_TIMEOUT_SECONDS`, M3). Paths are relative
/// to the workspace root, where the command runs.
pub(crate) fn fuzz_args(t: &str, seconds: u64) -> Result<Vec<String>> {
    Ok(vec![
        "fuzz".to_owned(),
        "run".to_owned(),
        "--fuzz-dir".to_owned(),
        "fuzz".to_owned(),
        t.to_owned(),
        format!("target/fuzz-corpus/{t}"),
        format!("fuzz/corpus/{t}"),
        "--".to_owned(),
        format!("-max_total_time={seconds}"),
        format!("-max_len={}", fuzz_max_len(t)?),
        format!("-timeout={}", expect::FUZZ_INPUT_TIMEOUT_SECONDS),
    ])
}

/// The libFuzzer `-max_len` of target `t` (`expect::FUZZ_MAX_LEN`, M2 review C4); a target without one is refused.
pub(crate) fn fuzz_max_len(t: &str) -> Result<usize> {
    expect::FUZZ_MAX_LEN
        .iter()
        .find(|(name, _)| *name == t)
        .map(|(_, n)| *n)
        .ok_or_else(|| {
            Error(format!(
                "fuzz target {t} has no -max_len in expect::FUZZ_MAX_LEN"
            ))
        })
}

/// Per-crate line coverage from a `cargo llvm-cov --json --summary-only` export.
pub(crate) fn coverage_by_crate(
    json: &str,
    crates: &[(String, PathBuf)],
) -> Result<Vec<(String, u64, u64)>> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("llvm-cov JSON: {e}")))?;
    let files = v
        .get("data")
        .and_then(Value::as_array)
        .and_then(|d| d.first())
        .and_then(|d| d.get("files"))
        .and_then(Value::as_array)
        .ok_or_else(|| Error("llvm-cov JSON: no data[0].files".to_owned()))?;
    let mut out: Vec<(String, u64, u64)> = crates.iter().map(|(n, _)| (n.clone(), 0, 0)).collect();
    for f in files {
        let name = f
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let lines = f.get("summary").and_then(|s| s.get("lines"));
        let count = lines
            .and_then(|l| l.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let covered = lines
            .and_then(|l| l.get("covered"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        for (i, (_, dir)) in crates.iter().enumerate() {
            if Path::new(name).starts_with(dir)
                && let Some(entry) = out.get_mut(i)
            {
                entry.1 = entry.1.saturating_add(count);
                entry.2 = entry.2.saturating_add(covered);
            }
        }
    }
    Ok(out)
}

fn percent(covered: u64, count: u64) -> f64 {
    // Line counts stay far below 2^52, so the conversion through u32 is exact; larger values saturate.
    let c = f64::from(u32::try_from(covered).unwrap_or(u32::MAX));
    let n = f64::from(u32::try_from(count).unwrap_or(u32::MAX));
    if n > 0.0 { c * 100.0 / n } else { 100.0 }
}

/// Files that are test code and not measured (M3 review F18, R-42): the denominator must not contain
/// `src/**/tests.rs` or `kani_proofs.rs`.
pub(crate) const COVERAGE_IGNORE_RE: &str = r"(/tests\.rs|/kani_proofs\.rs)$";

/// The features the coverage run turns on: `secmp-relay`'s `relay` suite is `required-features = ["kat"]` and no
/// workspace crate enables `secmp-relay/kat` by unification (as `secmp-testkit` does for `secmp-proto/kat`, ADR-042),
/// so without it the run measured none of the relay's integration tests (M5-B-3, run 37817187858: 58.9 %).
/// M5-C: `secmp-testkit/harness` adds the in-process harness and its tests (`tests/harness`), which are the tests of
/// `secmp-transport` (the transport has no relay of its own to talk to) — without it the transport would be measured
/// at its one unit test. The testkit's differential suites (`kat`, 151–289 s each under instrumentation) stay out.
pub(crate) const COVERAGE_FEATURES: &str = "secmp-relay/kat,secmp-testkit/harness";

/// The `cargo llvm-cov` arguments.
pub(crate) fn coverage_args(out_path: &str) -> Vec<String> {
    [
        "llvm-cov",
        "nextest",
        "--workspace",
        "--locked",
        "--features",
        COVERAGE_FEATURES,
        "--json",
        "--summary-only",
        "--ignore-filename-regex",
        COVERAGE_IGNORE_RE,
        "--output-path",
        out_path,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

pub(crate) fn coverage(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::LLVM_COV)?;
    tools::require(tools::NEXTEST)?;
    let out_path = ctx.root.join("target").join("llvm-cov-summary.json");
    Cmd::cargo()
        .args(coverage_args(&out_path.to_string_lossy()))
        .run()?;
    let crates: Vec<(String, PathBuf)> = ctx
        .ws
        .members
        .iter()
        .filter(|p| p.name != "xtask")
        .filter_map(|p| {
            p.manifest_path
                .parent()
                .map(|d| (p.name.clone(), d.to_path_buf()))
        })
        .collect();
    let rows = coverage_by_crate(&std::fs::read_to_string(&out_path)?, &crates)?;
    let mut failures = Vec::new();
    let mut parts = Vec::new();
    for (name, count, covered) in rows {
        let min = if expect::COVERAGE_STRICT.contains(&name.as_str()) {
            expect::COVERAGE_STRICT_MIN
        } else {
            expect::COVERAGE_MIN
        };
        if count == 0 {
            parts.push(format!("{name}: no code"));
            continue;
        }
        let pct = percent(covered, count);
        parts.push(format!(
            "{name}: {covered}/{count} lines = {pct:.1} % (min {min} %)"
        ));
        if pct < min {
            failures.push(name);
        }
    }
    for p in &parts {
        say(&format!("  coverage {p}"));
    }
    if !failures.is_empty() {
        bail!("coverage below threshold: {}", failures.join(", "));
    }
    Ok(Outcome::Pass(format!(
        "{} (xtask not measured)",
        parts.join("; ")
    )))
}

/// Missed or timed-out mutants (lines `<path>:<line>:<col>: <description>` of `cargo mutants`' `missed.txt` /
/// `timeout.txt`) that no line of `docs/mutants-accepted.md` documents with both its place and its description
/// ([`survivor_documented`]; M5 review R-114, C-7: keyed on `path:line`, so the same description elsewhere in the file
/// is not accepted, and a row whose code moves is updated to the new line).
pub(crate) fn undocumented_survivors(listing: &str, accepted: &str) -> Vec<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| !survivor_documented(l, accepted))
        .map(str::to_owned)
        .collect()
}

/// Whether one line of `accepted` names the survivor `<path>:<line>:<col>: <description>` by its place —
/// `` `<path>:<line>` ``, or `` `<path>:<line>:<col>` `` where two survivors share a line — and by
/// `` `<description>` ``.
fn survivor_documented(survivor: &str, accepted: &str) -> bool {
    let mut parts = survivor.splitn(4, ':');
    let (Some(path), Some(line), Some(col), Some(desc)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next().map(str::trim),
    ) else {
        return false;
    };
    if [path, line, col, desc].iter().any(|p| p.is_empty()) {
        return false;
    }
    let places = [format!("`{path}:{line}`"), format!("`{path}:{line}:{col}`")];
    let desc = format!("`{desc}`");
    accepted
        .lines()
        .any(|a| a.contains(&desc) && places.iter().any(|p| a.contains(p.as_str())))
}

/// The survivors of a cargo-mutants run (`missed.txt` and `timeout.txt` of `mutants.out`), refusing a listing that
/// the exit code says must exist and does not (M2 review C3 (d): exit 2 means missed mutants, 3 timeouts; a
/// missing file must not read as "no survivors").
pub(crate) fn mutant_survivors(
    code: Option<i32>,
    missed: Option<String>,
    timeout: Option<String>,
) -> Result<String> {
    if code == Some(2) && missed.is_none() {
        bail!("cargo mutants exited 2 (missed mutants) but mutants.out/missed.txt is missing");
    }
    if code == Some(3) && timeout.is_none() {
        bail!("cargo mutants exited 3 (timeouts) but mutants.out/timeout.txt is missing");
    }
    Ok(format!(
        "{}\n{}",
        missed.unwrap_or_default(),
        timeout.unwrap_or_default()
    ))
}

/// One shard of the mutation gate (`step mutants --shard K/N`, ADR-047 Amendment 1 (2)): `k` < `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MutantsShard {
    pub(crate) k: usize,
    pub(crate) n: usize,
}

impl MutantsShard {
    /// `K/N` with `N` ≥ 1 and `K` < `N`.
    pub(crate) fn parse(v: &str) -> Result<Self> {
        let parsed = v
            .split_once('/')
            .and_then(|(k, n)| Some((k.parse::<usize>().ok()?, n.parse::<usize>().ok()?)));
        match parsed {
            Some((k, n)) if k < n => Ok(Self { k, n }),
            _ => bail!("--shard {v:?}: expected K/N with 0 <= K < N"),
        }
    }
}

impl std::fmt::Display for MutantsShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.k, self.n)
    }
}

/// The shard of this invocation (set at most once, before any step runs); unset: every mutant.
static MUTANTS_SHARD: std::sync::OnceLock<MutantsShard> = std::sync::OnceLock::new();

/// Record the shard of this invocation (`main.rs`); a second call is refused.
pub(crate) fn set_mutants_shard(s: MutantsShard) -> Result<()> {
    MUTANTS_SHARD
        .set(s)
        .map_err(|_| Error("the mutants shard can be set once".to_owned()))
}

/// The `cargo mutants` arguments of the gate (ADR-047 with Amendment 1): feature `kat` for both packages (R-60: the HX
/// integration suite; with it the external KATs and the frozen-vector tests join the unit tests in killing mutants),
/// three mutants in parallel, `--caught --unviable` so the log shows every outcome as it happens, the shard if one is
/// given (round-robin, so every shard gets a share of both packages), the packages and exclusions of `expect.rs`, and
/// after `-- --` the libtest `--skip` filters of `expect::MUTANT_SKIP_TESTS`.
pub(crate) fn mutants_args(shard: Option<MutantsShard>) -> Vec<String> {
    let mut a: Vec<String> = [
        "mutants",
        "--no-shuffle",
        // M4-12 (ADR-047): three mutants in parallel on the 4-core runner
        "-j",
        "3",
        "--output",
        "target",
        "--features",
        "kat",
        "--caught",
        "--unviable",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    if let Some(shard) = shard {
        a.extend([
            "--shard".to_owned(),
            shard.to_string(),
            "--sharding".to_owned(),
            "round-robin".to_owned(),
        ]);
    }
    for p in expect::MUTANT_PACKAGES {
        a.extend(["--package".to_owned(), (*p).to_owned()]);
    }
    for f in expect::MUTANT_EXCLUDE_FILES {
        a.extend(["--exclude".to_owned(), (*f).to_owned()]);
    }
    for re in expect::MUTANT_EXCLUDE_RE {
        a.extend(["--exclude-re".to_owned(), (*re).to_owned()]);
    }
    // the remaining arguments go to `cargo test`, and after its own `--` to every test binary
    a.extend(["--".to_owned(), "--".to_owned()]);
    for (test, _) in expect::MUTANT_SKIP_TESTS {
        a.extend(["--skip".to_owned(), (*test).to_owned()]);
    }
    a
}

/// How often the mutation gate polls cargo-mutants and echoes its new output lines.
const MUTANTS_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// The file in which a sharded `mutants` step records its verdict for the merge (`mutants.out` is the shard's
/// artefact).
const MUTANTS_SHARD_VERDICT: &str = "xtask-shard.json";

/// docs/06 §5 step 8 (ADR-047 with Amendment 1): `cargo mutants` over `expect::MUTANT_PACKAGES` with output in
/// `target/mutants-step.log` (echoed as it grows) under the budget `expect::MUTANTS_STEP_TIMEOUT_SECONDS`; every
/// missed or timed-out mutant must be documented in `docs/mutants-accepted.md`. With `--shard K/N` (one CI shard) the
/// step records its verdict in `target/mutants.out/xtask-shard.json` for `mutants-merge`, which applies the
/// per-package floor; without, the step applies the floor itself.
pub(crate) fn mutants(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::MUTANTS)?;
    let shard = MUTANTS_SHARD.get().copied();
    let target = ctx.root.join("target");
    let out = target.join("mutants.out");
    let verdict_file = out.join(MUTANTS_SHARD_VERDICT);
    if verdict_file.exists() {
        std::fs::remove_file(&verdict_file)?;
    }
    let log = target.join("mutants-step.log");
    let timeout = std::time::Duration::from_secs(expect::MUTANTS_STEP_TIMEOUT_SECONDS);
    let mut tail = LineTail::new(&log);
    let mut last = None;
    let status = run_budgeted(
        &Cmd::cargo().args(mutants_args(shard)).dir(&ctx.root),
        &log,
        timeout,
        MUTANTS_POLL,
        || {
            for line in tail.lines() {
                say(&format!("  {line}"));
                last = Some(line);
            }
        },
    )?;
    let verdict = mutants_shard_verdict(ctx, status, &out, &log, last.as_deref());
    if let Some(shard) = shard {
        let (passed, detail) = match &verdict {
            Ok(d) => ("PASS", d.clone()),
            Err(e) => ("FAIL", e.0.clone()),
        };
        std::fs::create_dir_all(&out)?;
        std::fs::write(
            &verdict_file,
            serde_json::json!({
                "shard": shard.to_string(),
                "verdict": passed,
                "exit_code": status.and_then(|s| s.code()),
                "detail": detail,
            })
            .to_string(),
        )?;
        let detail = verdict?;
        return Ok(Outcome::Pass(format!(
            "shard {shard}: {detail}; the per-package floor is applied by mutants-merge"
        )));
    }
    let detail = verdict?;
    let outcomes = read_outcomes(&out.join("outcomes.json"))?;
    let counts = mutant_counts(&outcomes.outcomes)?;
    let floor = mutants_floor(&counts);
    for l in floor.lines.iter().chain(&floor.warnings) {
        say(&format!("  mutants {l}"));
    }
    if !floor.failures.is_empty() {
        bail!(
            "mutation floor (ADR-047 Amendment 2): {}",
            [floor.lines, floor.warnings, floor.failures]
                .concat()
                .join("; ")
        );
    }
    Ok(Outcome::Pass(format!(
        "{detail}; {}",
        [floor.lines, floor.warnings].concat().join("; ")
    )))
}

/// The verdict of one `cargo mutants` run (one shard or all): Err on a timeout, a baseline or usage failure, and an
/// undocumented survivor; else the summary line with the count of documented survivors.
fn mutants_shard_verdict(
    ctx: &Ctx,
    status: Option<std::process::ExitStatus>,
    out: &Path,
    log: &Path,
    last: Option<&str>,
) -> Result<String> {
    let Some(status) = status else {
        bail!(
            "mutants: timeout, killed after {} s; last line: {}; log {}",
            expect::MUTANTS_STEP_TIMEOUT_SECONDS,
            last.unwrap_or("none"),
            log.display()
        );
    };
    let code = status.code();
    let read = |name: &str| std::fs::read_to_string(out.join(name)).ok();
    let accepted = std::fs::read_to_string(ctx.root.join("docs").join("mutants-accepted.md"))?;
    let survivors = mutant_survivors(code, read("missed.txt"), read("timeout.txt"))?;
    let undocumented = undocumented_survivors(&survivors, &accepted);
    let documented = survivors
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
        .saturating_sub(undocumented.len());
    // cargo-mutants: 0 all caught, 2 missed mutants, 3 timeouts; anything else (baseline failure, usage) fails
    let only_survivors = matches!(code, Some(0 | 2 | 3));
    if !only_survivors || !undocumented.is_empty() {
        for u in &undocumented {
            say(&format!("  UNDOCUMENTED SURVIVOR {u}"));
        }
        bail!(
            "cargo mutants (exit {code:?}): {} undocumented survivor(s) (docs/mutants-accepted.md){}; log {}",
            undocumented.len(),
            if only_survivors {
                ""
            } else {
                "; baseline or usage failure"
            },
            log.display()
        );
    }
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let summary = text
        .lines()
        .rev()
        .find(|l| l.contains("mutants tested"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    Ok(format!(
        "{}: {summary}; survivors documented in docs/mutants-accepted.md: {documented}",
        expect::MUTANT_PACKAGES.join(", ")
    ))
}

/// The outcomes of one cargo-mutants run (`outcomes.json`): every mutant's outcome (the baseline left out) and the
/// run's own count of mutants, which must equal the number of mutant outcomes.
struct MutantOutcomes {
    outcomes: Vec<Value>,
}

fn read_outcomes(path: &Path) -> Result<MutantOutcomes> {
    let text =
        std::fs::read_to_string(path).map_err(|e| Error(format!("{}: {e}", path.display())))?;
    let v: Value =
        serde_json::from_str(&text).map_err(|e| Error(format!("{}: {e}", path.display())))?;
    let all = v
        .get("outcomes")
        .and_then(Value::as_array)
        .ok_or_else(|| Error(format!("{}: no `outcomes` array", path.display())))?;
    let outcomes: Vec<Value> = all
        .iter()
        .filter(|o| o.get("scenario").and_then(|s| s.get("Mutant")).is_some())
        .cloned()
        .collect();
    let total = v.get("total_mutants").and_then(Value::as_u64);
    if total != u64::try_from(outcomes.len()).ok() {
        bail!(
            "{}: {} mutant outcomes, but total_mutants {total:?} (an incomplete run)",
            path.display(),
            outcomes.len()
        );
    }
    Ok(MutantOutcomes { outcomes })
}

/// The outcome counts of one package.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MutantCounts {
    total: usize,
    caught: usize,
    missed: usize,
    timeout: usize,
    unviable: usize,
}

/// Per package (the `package` field cargo-mutants 27.1.0 writes for every mutant), the outcome counts of `outcomes`
/// (mutant outcomes of `outcomes.json`, possibly merged from several shards). A mutant without a package, of a
/// package outside `expect::MUTANT_PACKAGES`, in a file outside `crates/<package>/`, or with an unknown outcome is an
/// error: it cannot be attributed, so the floor could not be judged.
fn mutant_counts(outcomes: &[Value]) -> Result<std::collections::BTreeMap<String, MutantCounts>> {
    let mut counts: std::collections::BTreeMap<String, MutantCounts> = expect::MUTANT_PACKAGES
        .iter()
        .map(|p| ((*p).to_owned(), MutantCounts::default()))
        .collect();
    for o in outcomes {
        let mutant = o.get("scenario").and_then(|s| s.get("Mutant"));
        let name = mutant
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let package = mutant
            .and_then(|m| m.get("package"))
            .and_then(Value::as_str);
        let file = mutant.and_then(|m| m.get("file")).and_then(Value::as_str);
        let Some(package) = package else {
            bail!("mutants: the mutant {name:?} names no package");
        };
        if !file.is_some_and(|f| f.starts_with(&format!("crates/{package}/"))) {
            bail!(
                "mutants: the mutant {name:?} of {package} is not in crates/{package}/ ({file:?})"
            );
        }
        let Some(c) = counts.get_mut(package) else {
            bail!(
                "mutants: the mutant {name:?} is in the package {package}, which is not one of {:?}",
                expect::MUTANT_PACKAGES
            );
        };
        let slot = match o.get("summary").and_then(Value::as_str) {
            Some("CaughtMutant") => &mut c.caught,
            Some("MissedMutant") => &mut c.missed,
            Some("Timeout") => &mut c.timeout,
            Some("Unviable") => &mut c.unviable,
            other => bail!("mutants: the mutant {name:?} has the unknown outcome {other:?}"),
        };
        *slot = slot.saturating_add(1);
        c.total = c.total.saturating_add(1);
    }
    Ok(counts)
}

/// The per-package verdict of the mutation gate (`mutants_floor`): one line of counts per package, the warnings and
/// the failures (each naming its package).
struct MutantsFloor {
    lines: Vec<String>,
    warnings: Vec<String>,
    failures: Vec<String>,
}

/// `part` of `total` as a percentage with one decimal, rounded half up (`0.0 %` for an empty package); printed only,
/// the floor compares the integer counts.
fn per_mille(part: usize, total: usize) -> String {
    let p = part
        .saturating_mul(1000)
        .saturating_add(total.checked_div(2).unwrap_or(0))
        .checked_div(total)
        .unwrap_or(0);
    format!("{}.{} %", p / 10, p % 10)
}

/// ADR-047 Amendment 2 (1), (2) (Amendment 1 (4), M4 review R-06): the floor per package of `expect::MUTANT_PACKAGES`
/// — at least one caught mutant, and caught at least `expect::MUTANT_MIN_CAUGHT_PERCENT` % of all its generated
/// mutants (caught + missed + unviable + timeout), so a build that fails for every mutant cannot pass; the unviable
/// share is printed per package and, above `expect::MUTANT_UNVIABLE_WARN_PERCENT` %, is a warning, never a failure
/// (the `FnValue` mutants of types without `Default` are unviable by design: PR run 37127247911, `secmp-crypto` 99 of
/// 268). The survivors are judged against `docs/mutants-accepted.md` by the callers.
fn mutants_floor(counts: &std::collections::BTreeMap<String, MutantCounts>) -> MutantsFloor {
    let mut floor = MutantsFloor {
        lines: Vec::new(),
        warnings: Vec::new(),
        failures: Vec::new(),
    };
    let min = expect::MUTANT_MIN_CAUGHT_PERCENT;
    let warn = expect::MUTANT_UNVIABLE_WARN_PERCENT;
    for p in expect::MUTANT_PACKAGES {
        let c = counts.get(*p).copied().unwrap_or_default();
        floor.lines.push(format!(
            "{p}: caught {}, missed {}, timeout {}, unviable {} of {} (caught {}, at least {min} %, unviable {})",
            c.caught,
            c.missed,
            c.timeout,
            c.unviable,
            c.total,
            per_mille(c.caught, c.total),
            per_mille(c.unviable, c.total)
        ));
        if c.caught == 0 {
            floor
                .failures
                .push(format!("{p}: no caught mutant (of {})", c.total));
        } else if c.caught.saturating_mul(100) < min.saturating_mul(c.total) {
            floor.failures.push(format!(
                "{p}: caught {} of {} mutants ({}) is below {min} %",
                c.caught,
                c.total,
                per_mille(c.caught, c.total)
            ));
        }
        if c.unviable.saturating_mul(100) > warn.saturating_mul(c.total) {
            floor.warnings.push(format!(
                "WARNING {p}: unviable {} > {warn} % ({} of {} mutants, informative, ADR-047 Amendment 2)",
                per_mille(c.unviable, c.total),
                c.unviable,
                c.total
            ));
        }
    }
    floor
}

/// The shard results of a CI mutation run as the merge reads them (ADR-047 Amendment 2 (3)): the outcomes of every
/// shard whose `outcomes.json` is complete, one verdict line per shard, and the shard failures.
struct MergedShards {
    outcomes: Vec<Value>,
    /// One line per shard K = 0…n−1: its verdict, number of mutants and directory, or what is missing.
    shards: Vec<String>,
    failures: Vec<String>,
}

/// The result directories of the shards under `dir` (the artefacts `mutants-<K>-<attempt>` of the `mutants-shard`
/// jobs), by shard number.
fn shard_dirs(dir: &Path) -> Result<std::collections::BTreeMap<usize, Vec<PathBuf>>> {
    let mut by_shard: std::collections::BTreeMap<usize, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    let entries = std::fs::read_dir(dir).map_err(|e| {
        Error(format!(
            "mutants-merge: {}: {e} (no shard results downloaded)",
            dir.display()
        ))
    })?;
    for entry in entries {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let k = name
            .strip_prefix("mutants-")
            .and_then(|r| r.split_once('-'))
            .and_then(|(k, _)| k.parse::<usize>().ok());
        let Some(k) = k else {
            bail!(
                "mutants-merge: unexpected directory {name:?} in {}",
                dir.display()
            );
        };
        by_shard.entry(k).or_default().push(path);
    }
    Ok(by_shard)
}

/// Read the `n` shard results under `dir` (each with `mutants.out/`): exactly one directory per shard K = 0…n−1 and
/// no other, each with a PASS verdict of shard `K/n` (written by the shard's `mutants` step) and a complete
/// `outcomes.json`. Every shard is read and reported before anything fails (ADR-047 Amendment 2 (3)): a shard that
/// is missing, unfinished or failed is a failure naming it, and the outcomes of a failed shard that finished still
/// count in the package tallies.
fn merge_mutant_shards(dir: &Path, n: usize) -> Result<MergedShards> {
    let mut by_shard = shard_dirs(dir)?;
    let mut merged = MergedShards {
        outcomes: Vec::new(),
        shards: Vec::new(),
        failures: Vec::new(),
    };
    for k in 0..n {
        let dirs = by_shard.remove(&k).unwrap_or_default();
        let [d] = dirs.as_slice() else {
            let line = format!(
                "shard {k}/{n}: {} result directories (exactly one expected)",
                dirs.len()
            );
            merged.shards.push(line.clone());
            merged.failures.push(line);
            continue;
        };
        let out = d.join("mutants.out");
        let verdict: Option<Value> = std::fs::read_to_string(out.join(MUTANTS_SHARD_VERDICT))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        let field = |f: &str| {
            verdict
                .as_ref()
                .and_then(|v| v.get(f))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let read = read_outcomes(&out.join("outcomes.json"));
        let mutants = read
            .as_ref()
            .map_or_else(|e| e.0.clone(), |r| format!("{} mutants", r.outcomes.len()));
        let dir_name = d
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let problem = if verdict.is_none() {
            Some(format!(
                "no verdict ({}) — the shard did not finish",
                out.join(MUTANTS_SHARD_VERDICT).display()
            ))
        } else if field("shard") != format!("{k}/{n}") || field("verdict") != "PASS" {
            Some(format!(
                "verdict {} for shard {}: {}",
                field("verdict"),
                field("shard"),
                field("detail").replace("; ", ", ")
            ))
        } else {
            read.as_ref().err().map(|e| e.0.clone())
        };
        merged.shards.push(format!(
            "shard {k}/{n}: {} — {mutants} ({dir_name})",
            if problem.is_some() { "FAIL" } else { "PASS" }
        ));
        if let Some(problem) = problem {
            merged.failures.push(format!("shard {k}/{n}: {problem}"));
        }
        if let Ok(read) = read {
            merged.outcomes.extend(read.outcomes);
        }
    }
    for k in by_shard.keys() {
        merged
            .failures
            .push(format!("a result directory for shard {k}, outside 0..{n}"));
    }
    Ok(merged)
}

/// The names (`path:line:col: description`, as `missed.txt`/`timeout.txt` list them) of the mutants with `summary`.
fn mutant_names(outcomes: &[Value], summary: &str) -> String {
    outcomes
        .iter()
        .filter(|o| o.get("summary").and_then(Value::as_str) == Some(summary))
        .filter_map(|o| {
            o.get("scenario")
                .and_then(|s| s.get("Mutant"))
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
        })
        .fold(String::new(), |mut all, n| {
            all.push_str(n);
            all.push('\n');
            all
        })
}

/// The verdict of a merged mutation run: every line in report order (shards, packages, warnings, survivors, the
/// failures), and the failures.
struct MergeVerdict {
    lines: Vec<String>,
    failures: Vec<String>,
}

/// The merge of the `n` shard results under `dir` into `out` (`outcomes.json`, `missed.txt`, `timeout.txt`,
/// `summary.txt`) and its verdict (ADR-047 Amendment 2): every shard's verdict line, every package's tally and floor
/// (`mutants_floor`), the unviable warnings, and each survivor that `accepted` (`docs/mutants-accepted.md`) does not
/// document, as a failure naming its package — all evaluated before the merge fails.
fn merge_verdict(dir: &Path, n: usize, accepted: &str, out: &Path) -> Result<MergeVerdict> {
    let merged = merge_mutant_shards(dir, n)?;
    let missed = mutant_names(&merged.outcomes, "MissedMutant");
    let timeout = mutant_names(&merged.outcomes, "Timeout");
    let counts = mutant_counts(&merged.outcomes)?;
    let floor = mutants_floor(&counts);
    let survivors = format!("{missed}{timeout}");
    let undocumented = undocumented_survivors(&survivors, accepted);
    let documented = survivors
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
        .saturating_sub(undocumented.len());
    let package_of = |name: &str| {
        expect::MUTANT_PACKAGES
            .iter()
            .find(|p| name.starts_with(&format!("crates/{p}/")))
            .map_or("an unknown package", |p| *p)
    };
    let survivor_failures: Vec<String> = undocumented
        .iter()
        .map(|u| {
            format!(
                "{}: survivor not in docs/mutants-accepted.md: {u}",
                package_of(u)
            )
        })
        .collect();
    std::fs::create_dir_all(out)?;
    std::fs::write(
        out.join("outcomes.json"),
        serde_json::json!({ "outcomes": merged.outcomes }).to_string(),
    )?;
    std::fs::write(out.join("missed.txt"), &missed)?;
    std::fs::write(out.join("timeout.txt"), &timeout)?;
    let failures = [merged.failures, floor.failures, survivor_failures].concat();
    let lines = [
        merged.shards,
        floor.lines,
        floor.warnings,
        vec![format!(
            "survivors documented in docs/mutants-accepted.md: {documented}, undocumented: {}",
            undocumented.len()
        )],
        failures.iter().map(|f| format!("FAIL {f}")).collect(),
    ]
    .concat();
    std::fs::write(out.join("summary.txt"), lines.join("\n"))?;
    Ok(MergeVerdict { lines, failures })
}

/// The verdict of the sharded mutation gate (ADR-047 Amendment 1 (2), Amendment 2; the `mutants` job of `ci.yml`): the
/// `expect::MUTANT_SHARDS` shard results under `target/mutants-shards/` merged into `target/mutants-merged/`
/// ([`merge_verdict`]); prints every shard's and every package's verdict, then fails unless every shard passed, every
/// survivor is documented in `docs/mutants-accepted.md`, and every package meets the floor.
pub(crate) fn mutants_merge(ctx: &Ctx) -> Result<Outcome> {
    let target = ctx.root.join("target");
    let accepted = std::fs::read_to_string(ctx.root.join("docs").join("mutants-accepted.md"))?;
    let verdict = merge_verdict(
        &target.join("mutants-shards"),
        expect::MUTANT_SHARDS,
        &accepted,
        &target.join("mutants-merged"),
    )?;
    for l in &verdict.lines {
        say(&format!("  mutants {l}"));
    }
    if !verdict.failures.is_empty() {
        bail!("mutants-merge: {}", verdict.lines.join("; "));
    }
    Ok(Outcome::Pass(format!(
        "{} shards merged; {}",
        expect::MUTANT_SHARDS,
        verdict.lines.join("; ")
    )))
}

/// Miri in `ci-full`: the bounded scope, skipping the tests of `expect::MIRI_SKIP` (runtime) and
/// `expect::MIRI_UNSUPPORTED` (docs/06 §4).
pub(crate) fn miri(ctx: &Ctx) -> Result<Outcome> {
    miri_with(
        ctx,
        &[expect::MIRI_SKIP, expect::MIRI_UNSUPPORTED].concat(),
        None,
    )
}

/// `miri-full` (on demand; the weekly `miri-full` workflow, docs/06 §4, M1 review F3): the complete set, without
/// the runtime skips; only the tests Miri cannot run at all (`expect::MIRI_UNSUPPORTED`) are left out.
pub(crate) fn miri_full(ctx: &Ctx) -> Result<Outcome> {
    miri_with(ctx, expect::MIRI_UNSUPPORTED, None)
}

/// `miri-full-<package>` (M3 review F22, Q-4): the same complete set for one package, one job each in the weekly
/// workflow, so that a package's run time does not share the 6-hour limit.
pub(crate) fn miri_full_package(ctx: &Ctx, package: &str) -> Result<Outcome> {
    miri_with(ctx, expect::MIRI_UNSUPPORTED, Some(package))
}

/// The integration-test targets of `package` that a Miri run builds: those without `required-features`. Test targets
/// with `required-features` (M3: the `kat`-only `tr` vector, generator and property suites; M4: the `hx` suite) are not
/// built by a Miri run without features — they run natively in the `kat` step — and naming one with `--test` would make
/// cargo refuse the whole run. M4 review C-4 (R-12): they must be exactly the package's entries of `listed`
/// (`expect::MIRI_FEATURE_GATED`), in both directions, so no suite leaves Miri unnamed.
pub(crate) fn miri_test_targets(
    package: &crate::meta::Package,
    listed: &[(&str, &str, &str)],
) -> Result<Vec<String>> {
    let tests = package
        .targets
        .iter()
        .filter(|t| t.kinds.iter().any(|k| k == "test"));
    let gated: BTreeSet<String> = tests
        .clone()
        .filter(|t| !t.required_features.is_empty())
        .map(|t| t.name.clone())
        .collect();
    let named: BTreeSet<String> = listed
        .iter()
        .filter(|(p, _, _)| *p == package.name)
        .map(|(_, t, _)| (*t).to_owned())
        .collect();
    if gated != named {
        let unlisted: Vec<&String> = gated.difference(&named).collect();
        let ungated: Vec<&String> = named.difference(&gated).collect();
        bail!(
            "miri: {}: the test targets with required-features differ from expect::MIRI_FEATURE_GATED (not listed: \
             {unlisted:?}; listed without required-features or absent: {ungated:?})",
            package.name
        );
    }
    Ok(tests
        .filter(|t| t.required_features.is_empty())
        .map(|t| t.name.clone())
        .collect())
}

/// The filter prefix of a `MIRI_SKIP` / `MIRI_UNSUPPORTED` entry that leaves out a whole integration-test target
/// (`tests/<name>.rs`) rather than tests by name.
pub(crate) const MIRI_TEST_TARGET: &str = "test-target:";

/// The `cargo miri test` invocations for one package of `expect::MIRI_PACKAGES` (its test targets `test_targets`,
/// `has_lib` if it has a library): the package's entries of `skip` are libtest `--skip <filter>` arguments (a
/// substring of the test path, applied to every test binary of the package) or, prefixed `test-target:`, an
/// integration-test target that is not run at all. Without such a target: one run over the package's default
/// targets. With one: a run over `--lib`, `--bins` and each remaining `--test` target, and a separate `--doc` run
/// (cargo does not combine `--doc` with target selection). A named test target that does not exist is refused.
pub(crate) fn miri_runs(
    package: &str,
    test_targets: &[String],
    has_lib: bool,
    skip: &[(&str, &str, &str)],
) -> Result<Vec<Vec<String>>> {
    let entries: Vec<&str> = skip
        .iter()
        .filter(|(p, _, _)| *p == package)
        .map(|(_, f, _)| *f)
        .collect();
    let excluded: Vec<&str> = entries
        .iter()
        .filter_map(|f| f.strip_prefix(MIRI_TEST_TARGET))
        .collect();
    if let Some(t) = excluded
        .iter()
        .find(|t| !test_targets.iter().any(|x| x == *t))
    {
        bail!("miri: {package} has no test target {t:?} (expect::MIRI_SKIP / MIRI_UNSUPPORTED)");
    }
    let base = |extra: &[&str]| -> Vec<String> {
        [
            "miri",
            "test",
            "--locked",
            "--target",
            expect::MIRI_TARGET,
            "--package",
            package,
        ]
        .iter()
        .chain(extra)
        .map(|s| (*s).to_owned())
        .collect()
    };
    let filters = || {
        let mut args = vec!["--".to_owned()];
        for f in entries.iter().filter(|f| !f.starts_with(MIRI_TEST_TARGET)) {
            args.push("--skip".to_owned());
            args.push((*f).to_owned());
        }
        args
    };
    if excluded.is_empty() {
        return Ok(vec![[base(&[]), filters()].concat()]);
    }
    let mut selection: Vec<&str> = Vec::new();
    if has_lib {
        selection.push("--lib");
    }
    selection.push("--bins");
    for t in test_targets
        .iter()
        .filter(|t| !excluded.contains(&t.as_str()))
    {
        selection.push("--test");
        selection.push(t);
    }
    let mut runs = vec![[base(&selection), filters()].concat()];
    if has_lib {
        runs.push([base(&["--doc"]), filters()].concat());
    }
    Ok(runs)
}

fn miri_with(ctx: &Ctx, skip: &[(&str, &str, &str)], only: Option<&str>) -> Result<Outcome> {
    tools::require_nightly(&["miri", "rust-src"])?;
    if let Some((p, f, _)) = skip
        .iter()
        .find(|(p, _, _)| !expect::MIRI_PACKAGES.contains(p))
    {
        bail!("miri: the skip filter {f:?} names {p}, which is not in expect::MIRI_PACKAGES");
    }
    Cmd::cargo_on(tools::NIGHTLY)
        .args(["miri", "setup", "--target", expect::MIRI_TARGET])
        .dir(&ctx.root)
        .run()?;
    // One run per package (two where a test target is left out), so that each package's filters apply to its own
    // tests only. Miri cannot execute SIMD intrinsics: libcrux is built with its portable backend (own target
    // directory, because libcrux's build scripts do not declare these variables and Cargo would reuse a stale build).
    if let Some(o) = only
        && !expect::MIRI_PACKAGES.contains(&o)
    {
        bail!("miri: {o} is not in expect::MIRI_PACKAGES");
    }
    for p in expect::MIRI_PACKAGES
        .iter()
        .filter(|p| only.is_none_or(|o| o == **p))
    {
        let package = ctx
            .ws
            .member(p)
            .ok_or_else(|| Error(format!("miri: {p} is not a workspace member")))?;
        let test_targets = miri_test_targets(package, expect::MIRI_FEATURE_GATED)?;
        let has_lib = package
            .targets
            .iter()
            .any(|t| t.kinds.iter().any(|k| k == "lib"));
        for args in miri_runs(p, &test_targets, has_lib, skip)? {
            Cmd::cargo_on(tools::NIGHTLY)
                .args(args)
                .env("LIBCRUX_DISABLE_SIMD128", "1")
                .env("LIBCRUX_DISABLE_SIMD256", "1")
                .env(
                    "CARGO_TARGET_DIR",
                    ctx.root
                        .join("target")
                        .join("miri-portable")
                        .to_string_lossy(),
                )
                .dir(&ctx.root)
                .run()?;
        }
    }
    let skipped = if skip.is_empty() {
        "none (complete set)".to_owned()
    } else {
        skip.iter()
            .map(|(p, f, _)| format!("{p}: {f}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Ok(Outcome::Pass(format!(
        "Miri ({}, interpreting {}, libcrux portable backend): {}; skipped tests: {skipped}",
        tools::NIGHTLY,
        expect::MIRI_TARGET,
        only.map_or_else(|| expect::MIRI_PACKAGES.join(", "), str::to_owned),
    )))
}

pub(crate) fn kani(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::KANI)?;
    let mut found = BTreeSet::new();
    let mut packages = Vec::new();
    for p in &ctx.ws.members {
        let Some(dir) = p.manifest_path.parent() else {
            continue;
        };
        for f in walk_files(dir, &|x: &Path| x.extension().is_some_and(|e| e == "rs"))? {
            // spelled in two parts so that this file does not count as a harness
            if std::fs::read_to_string(&f)?.contains(concat!("#[kani", "::proof]"))
                && found.insert(p.name.clone())
            {
                packages.push(p);
            }
        }
    }
    same_set("Kani harness packages", &found, expect::KANI_PACKAGES)?;
    // `cargo kani --package` from the workspace root does not apply the package's `[package.metadata.kani]` (M2: the
    // stubbed harnesses did not compile in CI run 36614956208), and `--manifest-path` could not start `cargo
    // metadata` on the CI runner (run 36633643390): the gate passes the package's unstable features as `-Z` itself
    let mut output = String::new();
    for p in &packages {
        let mut c = Cmd::cargo().args(["kani", "--package", &p.name]);
        for feature in &p.kani_unstable {
            c = c.args(["-Z", feature]);
        }
        let cap = c.dir(&ctx.root).capture()?;
        // the harness verdicts and Kani's summary into the log (the full output only on failure)
        for line in cap.stdout.lines().filter(|l| {
            l.starts_with("Checking harness")
                || l.starts_with("VERIFICATION:-")
                || l.starts_with("Verification Time")
                || l.starts_with("Complete -")
                || l.contains("cover properties satisfied")
        }) {
            say(&format!("  {line}"));
        }
        if !cap.success {
            say(cap.stdout.trim_end());
            say(cap.stderr.trim_end());
            bail!("cargo kani --package {} failed", p.name);
        }
        output.push_str(&cap.stdout);
    }
    let verified = kani_verified(&output)?;
    let covers = kani_covers(&output)?;
    for c in &covers {
        say(&format!("  cover {c}"));
    }
    let pin = kani_cover_pin_findings(&covers);
    if !pin.is_empty() {
        bail!(
            "kani: the covers differ from expect::KANI_COVERS: {}",
            pin.join("; ")
        );
    }
    Ok(Outcome::Pass(format!(
        "Kani {}: harness packages {} (expected set matches); {}/{} harnesses verified (expect::KANI_HARNESSES): {}; \
         every cover satisfied: {}",
        tools::KANI.version,
        list(&found),
        verified.len(),
        expect::KANI_HARNESSES.len(),
        verified.join(", "),
        if covers.is_empty() {
            "no cover".to_owned()
        } else {
            covers.join("; ")
        }
    )))
}

/// M4 review C-15 (R-34): the `kani::cover!` results of a Kani run, per harness ("<harness>: N of M cover properties
/// satisfied"). A cover Kani reports as not satisfied — `Status: UNSATISFIABLE` or `UNREACHABLE`, or a summary with
/// fewer satisfied than there are — fails the gate naming the harness: a cover that cannot be reached shows a
/// vacuous harness, which `VERIFICATION:- SUCCESSFUL` alone does not (Kani 0.68 has no flag that fails on it).
pub(crate) fn kani_covers(output: &str) -> Result<Vec<String>> {
    let mut current = "(no harness)";
    let mut in_cover = false;
    let mut lines = Vec::new();
    let mut failed = Vec::new();
    for line in output.lines() {
        let t = line.trim();
        if let Some(name) = t
            .strip_prefix("Checking harness ")
            .and_then(|n| n.strip_suffix("..."))
        {
            current = name;
            in_cover = false;
        } else if t.starts_with("Check ") {
            in_cover = t.contains(".cover.");
        } else if in_cover
            && let Some(status) = t.strip_prefix("- Status: ")
            && status != "SATISFIED"
        {
            failed.push(format!("{current}: a cover is {status}"));
        } else if let Some((counts, suffix)) = t
            .strip_prefix("** ")
            .and_then(|r| r.split_once(" cover properties satisfied"))
        {
            let numbers: Vec<usize> = counts
                .split(" of ")
                .filter_map(|n| n.trim().parse().ok())
                .collect();
            // delta review VD1-5: Kani appends " (K unreachable)" when a cover cannot be reached
            match numbers.as_slice() {
                [n, m] if n == m && suffix.is_empty() => {
                    lines.push(format!("{current}: {counts} satisfied"));
                }
                _ => failed.push(format!(
                    "{current}: {counts} cover properties satisfied{suffix}"
                )),
            }
        }
    }
    if !failed.is_empty() {
        bail!("kani: a cover is not satisfied: {}", failed.join("; "));
    }
    Ok(lines)
}

/// M4 delta review VD1-5: the cover summaries of a Kani run ([`kani_covers`]) differ from `expect::KANI_COVERS` —
/// a pinned summary missing, one not pinned, or a harness reported twice.
pub(crate) fn kani_cover_pin_findings(covers: &[String]) -> Vec<String> {
    let want: BTreeSet<String> = expect::KANI_COVERS
        .iter()
        .map(|(h, m)| format!("{h}: {m} of {m} satisfied"))
        .collect();
    let got: BTreeSet<String> = covers.iter().cloned().collect();
    let mut out: Vec<String> = want
        .difference(&got)
        .map(|w| format!("missing: {w}"))
        .collect();
    out.extend(got.difference(&want).map(|g| format!("not pinned: {g}")));
    if got.len() != covers.len() {
        out.push("a cover summary reported twice".to_owned());
    }
    out
}

/// M2 review C5: the harnesses a Kani run verified. Refuses the run unless every "Complete - N successfully verified
/// harnesses, M failures, T total." line has M = 0 and N = T, the N add up to `expect::KANI_HARNESSES.len()`, and
/// the harnesses reported `VERIFICATION:- SUCCESSFUL` are exactly `expect::KANI_HARNESSES` (none missing, none
/// unknown, none twice).
pub(crate) fn kani_verified(output: &str) -> Result<Vec<String>> {
    let mut current: Option<&str> = None;
    let mut verified: Vec<String> = Vec::new();
    let mut total = 0_usize;
    let mut summaries = 0_usize;
    for line in output.lines() {
        if let Some(name) = line
            .strip_prefix("Checking harness ")
            .and_then(|n| n.strip_suffix("..."))
        {
            current = Some(name);
        } else if line.starts_with("VERIFICATION:- SUCCESSFUL") {
            let name =
                current.ok_or_else(|| Error("kani: a verdict before any harness".to_owned()))?;
            verified.push(name.to_owned());
        } else if let Some(summary) = line.strip_prefix("Complete - ") {
            let numbers: Vec<usize> = summary
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            let [ok, failures, all] = numbers.as_slice() else {
                bail!("kani: cannot read the summary {line:?}");
            };
            if *failures != 0 || ok != all {
                bail!("kani: {line}");
            }
            total = total.saturating_add(*ok);
            summaries = summaries.saturating_add(1);
        }
    }
    if summaries == 0 {
        bail!("kani: no \"Complete - …\" summary in the output");
    }
    let mut sorted = verified.clone();
    sorted.sort();
    sorted.dedup();
    let expected: BTreeSet<&str> = expect::KANI_HARNESSES.iter().copied().collect();
    let got: BTreeSet<&str> = sorted.iter().map(String::as_str).collect();
    if total != expect::KANI_HARNESSES.len() || sorted.len() != verified.len() || got != expected {
        let missing: Vec<&str> = expected.difference(&got).copied().collect();
        let unknown: Vec<&str> = got.difference(&expected).copied().collect();
        bail!(
            "kani: {total} harnesses verified, expected the {} of expect::KANI_HARNESSES; missing: {missing:?}; \
             unknown: {unknown:?}",
            expect::KANI_HARNESSES.len()
        );
    }
    Ok(sorted)
}

/// The `RESULT ...` verdicts of a ProVerif run, in order: `Some(true)` = "is true.", `Some(false)` = "is
/// false.", `None` = anything else (e.g. "cannot be proved.").
pub(crate) fn proverif_results(output: &str) -> Vec<Option<bool>> {
    output
        .lines()
        .filter(|l| l.trim_start().starts_with("RESULT"))
        .map(|l| {
            let t = l.trim_end();
            if t.ends_with("is true.") {
                Some(true)
            } else if t.ends_with("is false.") {
                Some(false)
            } else {
                None
            }
        })
        .collect()
}

/// Which ProVerif models the `proverif` step runs (WEISUNG M4-5 §4 (a), gate F7, M3 review R-14; M5 OPEN-M5-16 A):
/// `--models tr|hx|link|all`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProverifModels {
    /// The single-file models of `expect::PROVERIF_MODELS` (M4: `formal/tr.pv`).
    Tr,
    /// Every `formal/hx/*.pv`, each with `-lib formal/hx.pvl`.
    Hx,
    /// Every `formal/link/*.pv`, each with `-lib formal/link.pvl` (M5, CLAIMS §LINK).
    Link,
    /// All three (the default).
    All,
}

impl ProverifModels {
    /// The value of `--models`; anything but `tr`, `hx`, `link` and `all` is refused.
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "tr" => Ok(Self::Tr),
            "hx" => Ok(Self::Hx),
            "link" => Ok(Self::Link),
            "all" => Ok(Self::All),
            other => bail!("--models {other:?}: expected tr, hx, link or all"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Tr => "tr",
            Self::Hx => "hx",
            Self::Link => "link",
            Self::All => "all",
        }
    }

    fn single_files(self) -> bool {
        matches!(self, Self::Tr | Self::All)
    }

    /// Whether the session models of `family` are selected.
    fn sessions(self, family: SessionFamily) -> bool {
        match family {
            SessionFamily::Hx => matches!(self, Self::Hx | Self::All),
            SessionFamily::Link => matches!(self, Self::Link | Self::All),
        }
    }
}

/// A ProVerif model made of a library and one file per session, each run as `proverif -lib <lib> <dir>/<session>.pv`
/// and checked against its own expectation table: SecMP-HX (M4, WEISUNG M4-5, ADR-046) and SecMP-LINK (M5,
/// OPEN-M5-16 A, CLAIMS §LINK LO-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionFamily {
    /// `formal/hx.pvl` + `formal/hx/<session>.pv`, `expect::PROVERIF_EXPECTED_HX`.
    Hx,
    /// `formal/link.pvl` + `formal/link/<session>.pv`, `expect::PROVERIF_EXPECTED_LINK`.
    Link,
}

impl SessionFamily {
    /// Both families, in the order the step runs them.
    pub(crate) const ALL: [Self; 2] = [Self::Hx, Self::Link];

    pub(crate) fn lib(self) -> &'static str {
        match self {
            Self::Hx => expect::PROVERIF_HX_LIB,
            Self::Link => expect::PROVERIF_LINK_LIB,
        }
    }

    pub(crate) fn dir(self) -> &'static str {
        match self {
            Self::Hx => expect::PROVERIF_HX_DIR,
            Self::Link => expect::PROVERIF_LINK_DIR,
        }
    }

    pub(crate) fn table(self) -> &'static [expect::HxExpected] {
        match self {
            Self::Hx => expect::PROVERIF_EXPECTED_HX,
            Self::Link => expect::PROVERIF_EXPECTED_LINK,
        }
    }

    pub(crate) fn table_name(self) -> &'static str {
        match self {
            Self::Hx => "expect::PROVERIF_EXPECTED_HX",
            Self::Link => "expect::PROVERIF_EXPECTED_LINK",
        }
    }

    /// The short name: the prefix of its logs (`target/proverif/<name>-<session>.log`) and its label in the summary.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Hx => "hx",
            Self::Link => "link",
        }
    }
}

/// The options of the `proverif` step, taken from the command line of `ci-full`/`step` by `main.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProverifOptions {
    pub(crate) models: ProverifModels,
    /// `--jobs N` (1 to `expect::PROVERIF_MAX_JOBS`); `None`: the available cores, at most that cap.
    pub(crate) jobs: Option<usize>,
}

/// The process-wide ProVerif options (set at most once, before any step runs); unset: every model, default jobs.
static PROVERIF_OPTIONS: std::sync::OnceLock<ProverifOptions> = std::sync::OnceLock::new();

/// Record the ProVerif options of this invocation (`main.rs`); a second call is refused.
pub(crate) fn set_proverif_options(o: ProverifOptions) -> Result<()> {
    PROVERIF_OPTIONS
        .set(o)
        .map_err(|_| Error("the ProVerif options can be set once".to_owned()))
}

/// The value of `--jobs`: a number from 1 to `expect::PROVERIF_MAX_JOBS`.
pub(crate) fn parse_proverif_jobs(s: &str) -> Result<usize> {
    match s.parse::<usize>() {
        Ok(n) if (1..=expect::PROVERIF_MAX_JOBS).contains(&n) => Ok(n),
        _ => bail!(
            "--jobs {s:?}: expected a number from 1 to {}",
            expect::PROVERIF_MAX_JOBS
        ),
    }
}

fn proverif_jobs(o: ProverifOptions) -> usize {
    o.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .min(expect::PROVERIF_MAX_JOBS)
    })
}

fn proverif_program() -> String {
    std::env::var("SECMP_PROVERIF").unwrap_or_else(|_| "proverif".to_owned())
}

fn proverif_cmd() -> Cmd {
    Cmd::new(proverif_program())
}

/// The stems of the `*.<ext>` files directly in `dir` (not below it); empty if `dir` does not exist.
fn dir_stems(dir: &Path, ext: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for entry in rd {
        let p = entry?.path();
        if p.is_file()
            && p.extension().is_some_and(|e| e == ext)
            && let Some(s) = p.file_stem()
        {
            out.insert(s.to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

/// The files of a SecMP-HX expectation table.
fn hx_table_files(table: &[expect::HxExpected]) -> BTreeSet<String> {
    table.iter().map(|(f, ..)| (*f).to_owned()).collect()
}

/// WEISUNG M4-5 §4 (a): the discovered `formal/hx/*.pv` stems are exactly the files of the table — an `hx` file without
/// expected entries fails, and so does a file of the table that does not exist (the step calls [`session_set_check`]).
#[cfg(test)]
pub(crate) fn hx_set_check(found: &BTreeSet<String>, table: &[expect::HxExpected]) -> Result<()> {
    session_set_check(SessionFamily::Hx, found, table)
}

/// [`hx_set_check`] for the session models of `family` (`formal/hx/*.pv`, `formal/link/*.pv`) against `table`.
pub(crate) fn session_set_check(
    family: SessionFamily,
    found: &BTreeSet<String>,
    table: &[expect::HxExpected],
) -> Result<()> {
    let want = hx_table_files(table);
    let without: Vec<&String> = found.difference(&want).collect();
    let absent: Vec<&String> = want.difference(found).collect();
    if !without.is_empty() || !absent.is_empty() {
        bail!(
            "{}/*.pv against {}: files without expected entries: {without:?}; expected files that do not exist: \
             {absent:?}",
            family.dir(),
            family.table_name()
        );
    }
    Ok(())
}

/// The models one run of the `proverif` step checks: the single-file models (`formal/<name>.pv`) and the session files
/// (family, session).
type ProverifInputs = (Vec<String>, Vec<(SessionFamily, String)>);

/// The input set of the `proverif` step for `models` (WEISUNG M4-5 §4 (a)): the old joint model `formal/hx.pv` must
/// not exist; the single-file models `formal/*.pv` are exactly `expect::PROVERIF_MODELS` (so a joint `formal/link.pv`
/// fails too); for each selected session family (`hx`, `link`; `link` not when `skip_link`), its library exists and
/// `<dir>/*.pv` matches its table ([`session_set_check`]). Returns the single-file models and the sessions to run.
fn proverif_inputs(root: &Path, models: ProverifModels, skip_link: bool) -> Result<ProverifInputs> {
    if root.join("formal").join("hx.pv").exists() {
        bail!(
            "formal/hx.pv (the old joint SecMP-HX model) must not exist: the model is {} and {}/*.pv",
            expect::PROVERIF_HX_LIB,
            expect::PROVERIF_HX_DIR
        );
    }
    let single = dir_stems(&root.join("formal"), "pv")?;
    same_set(
        "ProVerif single-file models (formal/*.pv)",
        &single,
        expect::PROVERIF_MODELS,
    )?;
    let single = if models.single_files() {
        single.into_iter().collect()
    } else {
        Vec::new()
    };
    let mut sessions = Vec::new();
    for family in SessionFamily::ALL {
        if !models.sessions(family) || (skip_link && family == SessionFamily::Link) {
            continue;
        }
        if !root.join(family.lib()).is_file() {
            bail!(
                "{} is missing (the library of every {}/*.pv)",
                family.lib(),
                family.dir()
            );
        }
        let found = dir_stems(&root.join(family.dir()), "pv")?;
        session_set_check(family, &found, family.table())?;
        sessions.extend(found.into_iter().map(|s| (family, s)));
    }
    Ok((single, sessions))
}

/// The last progress line ProVerif printed (`… rules inserted. Base: … Queue: … rules.`), if any.
fn last_progress_line(log: &str) -> Option<&str> {
    log.lines()
        .rev()
        .find(|l| l.contains("rules inserted"))
        .map(str::trim)
}

/// How often a running ProVerif process is polled.
const PROVERIF_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Run `program args` with stdin closed and stdout and stderr into `log` (created or truncated), polling until it exits
/// or `timeout` has passed (WEISUNG M4-5 §4 (a)). A timeout kills the process and fails, naming `file` and the last
/// progress line of the log; a non-zero exit fails, naming `file` and the log, after printing the log's last lines.
/// Returns the log.
pub(crate) fn run_logged(
    program: &str,
    args: &[String],
    log: &Path,
    timeout: std::time::Duration,
    file: &str,
) -> Result<String> {
    use std::process::Stdio;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let out = std::fs::File::create(log)?;
    let err = out.try_clone()?;
    say(&format!(
        "$ {program} {} > {}",
        args.join(" "),
        log.display()
    ));
    let started = std::time::Instant::now();
    let deadline = started
        .checked_add(timeout)
        .ok_or_else(|| Error(format!("{file}: the timeout is out of range")))?;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| Error(format!("{file}: cannot start `{program}`: {e}")))?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            // the process may have exited since `try_wait`: a failed kill is then harmless, `wait` reaps it either way
            let _ = child.kill();
            child.wait()?;
            let text = String::from_utf8_lossy(&std::fs::read(log)?).into_owned();
            let progress = last_progress_line(&text).map_or_else(
                || "none (no \"rules inserted\" line in the log)".to_owned(),
                |l| format!("`{l}`"),
            );
            bail!(
                "{file}: timeout, killed after {} s; last progress line: {progress}; log {}",
                timeout.as_secs(),
                log.display()
            );
        }
        std::thread::sleep(PROVERIF_POLL);
    };
    let text = String::from_utf8_lossy(&std::fs::read(log)?).into_owned();
    if !status.success() {
        let lines: Vec<&str> = text.lines().collect();
        for l in lines.iter().skip(lines.len().saturating_sub(20)) {
            say(&format!("  {l}"));
        }
        bail!("{file}: ProVerif failed ({status}); log {}", log.display());
    }
    Ok(text)
}

/// ADR-046 Amendment 1 (1), M4 review C-7: the model files under `root` (`formal/*.pv`, the libraries `formal/*.pvl`,
/// `formal/hx/*.pv` and, M5, `formal/link/*.pv`) are exactly the files of `pins`, each with the pinned SHA-256 of its
/// committed text ([`crate::sha256::text_file_hex`]); every difference is a finding naming the file.
pub(crate) fn proverif_model_hash_findings(root: &Path, pins: &[(&str, &str)]) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for (dir, ext) in [
        ("formal", "pv"),
        ("formal", "pvl"),
        (expect::PROVERIF_HX_DIR, "pv"),
        (expect::PROVERIF_LINK_DIR, "pv"),
    ] {
        if let Ok(stems) = dir_stems(&root.join(dir), ext) {
            found.extend(stems.into_iter().map(|s| format!("{dir}/{s}.{ext}")));
        }
    }
    let pinned: BTreeSet<String> = pins.iter().map(|(f, _)| (*f).to_owned()).collect();
    let mut out: Vec<String> = found
        .difference(&pinned)
        .map(|f| format!("{f}: a model file without a pinned sha256"))
        .collect();
    for (file, want) in pins {
        match crate::sha256::text_file_hex(&root.join(file)) {
            None => out.push(format!("{file}: missing")),
            Some(got) if got != *want => {
                out.push(format!("{file}: sha256 {got}, pinned {want}"));
            }
            Some(_) => {}
        }
    }
    out
}

/// The model a ProVerif process checks.
enum ProverifModel {
    /// A single-file model of `expect::PROVERIF_EXPECTED` (`formal/<name>.pv`).
    Single(String),
    /// A session file of a family (`formal/hx/<session>.pv` of `expect::PROVERIF_EXPECTED_HX`,
    /// `formal/link/<session>.pv` of `expect::PROVERIF_EXPECTED_LINK`).
    Session(SessionFamily, String),
}

/// One ProVerif process of the step.
struct ProverifTask {
    /// The model file as shown (`formal/tr.pv`, `formal/hx/<session>.pv`, `formal/link/<session>.pv`).
    file: String,
    model: ProverifModel,
    log: PathBuf,
    args: Vec<String>,
}

/// The end of one ProVerif process: its log or its failure, and its wall time in seconds.
type ProverifEnd = (Result<String>, f64);

/// Run every task, at most `jobs` at a time, each under `timeout`; returns the end of each task, in the order of
/// `tasks`. Every task runs even after another one failed.
fn run_pool(tasks: &[ProverifTask], jobs: usize, timeout: std::time::Duration) -> Vec<ProverifEnd> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let program = proverif_program();
    let next = AtomicUsize::new(0);
    let done: std::sync::Mutex<Vec<Option<ProverifEnd>>> =
        std::sync::Mutex::new(tasks.iter().map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..jobs.min(tasks.len()).max(1) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(t) = tasks.get(i) else {
                        break;
                    };
                    let started = std::time::Instant::now();
                    let r = run_logged(&program, &t.args, &t.log, timeout, &t.file);
                    let secs = started.elapsed().as_secs_f64();
                    let how = if r.is_ok() { "finished" } else { "FAILED" };
                    say(&format!("  {}: {how} after {secs:.1} s", t.file));
                    if let Ok(mut d) = done.lock()
                        && let Some(slot) = d.get_mut(i)
                    {
                        *slot = Some((r, secs));
                    }
                }
            });
        }
    });
    done.into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .into_iter()
        .map(|r| r.unwrap_or_else(|| (Err(Error("not run".to_owned())), 0.0)))
        .collect()
}

/// What a file contributes to the evidence of the step (WEISUNG M4-5 §4 (c), (d)).
struct ProverifRecord {
    file: String,
    results: usize,
    secrecy: usize,
    secs: f64,
    /// The check's summary per ID, or the failure.
    checked: Result<String>,
    /// The results-table rows of the file.
    rows: Vec<crate::summary::ProverifRow>,
}

/// The evidence file `target/proverif/summary.txt`: the options, the SHA-256 of every model file, and per file the
/// `RESULT` lines, the "secrecy assumption verified" lines, the wall time and the verdict.
fn proverif_evidence(
    header: &str,
    shas: &[(String, Option<String>)],
    records: &[ProverifRecord],
) -> String {
    let mut lines = vec![header.to_owned(), "sha256 of the model files:".to_owned()];
    lines.extend(shas.iter().map(|(f, h)| {
        format!(
            "{}  {f}",
            h.as_deref().unwrap_or("(no sha256 tool on this host)")
        )
    }));
    lines.push(
        "per file: RESULT lines, \"secrecy assumption verified\" lines, wall time, verdict:"
            .to_owned(),
    );
    lines.extend(records.iter().map(|r| {
        format!(
            "{}: {} RESULT lines, {} secrecy assumptions verified, wall {:.1} s, {}",
            r.file,
            r.results,
            r.secrecy,
            r.secs,
            match &r.checked {
                Ok(_) => "PASS".to_owned(),
                Err(e) => format!("FAIL: {e}"),
            }
        )
    }));
    lines.push(String::new());
    lines.join("\n")
}

/// The ProVerif version and the gate's self-test (`xtask/fixtures/proverif/selftest.pv`: one query true, one false).
fn proverif_preflight(root: &Path) -> Result<()> {
    let help = proverif_cmd().arg("-help").capture().map_err(|e| {
        Error(format!(
            "ProVerif {} is required and missing ({e}); see README.md",
            tools::PROVERIF_VERSION
        ))
    })?;
    let banner = format!("{}{}", help.stdout, help.stderr);
    if !banner.contains(&format!("Proverif {}.", tools::PROVERIF_VERSION)) {
        bail!(
            "ProVerif {} required, found: {:?}",
            tools::PROVERIF_VERSION,
            banner.lines().next().unwrap_or_default()
        );
    }
    let fixture = root
        .join("xtask")
        .join("fixtures")
        .join("proverif")
        .join("selftest.pv");
    let cap = proverif_cmd().arg(fixture.to_string_lossy()).capture()?;
    let verdicts = proverif_results(&cap.stdout);
    if !cap.success || verdicts != [Some(true), Some(false)] {
        say(cap.stdout.trim_end());
        bail!("ProVerif self-test: expected [true, false], got {verdicts:?}");
    }
    Ok(())
}

/// The processes of the step: each single-file model `formal/<m>.pv` (log `target/proverif/<m>.log`) and each session
/// `<dir>/<s>.pv` of a family with `-lib <lib>` (`formal/hx/<s>.pv` with `-lib formal/hx.pvl`, log
/// `target/proverif/hx-<s>.log`; `formal/link/<s>.pv` with `-lib formal/link.pvl`, log `target/proverif/link-<s>.log`).
fn proverif_tasks(
    root: &Path,
    out_dir: &Path,
    single: &[String],
    sessions: &[(SessionFamily, String)],
) -> Vec<ProverifTask> {
    let path_arg = |p: &str| root.join(p).to_string_lossy().into_owned();
    let mut tasks = Vec::new();
    for m in single {
        let file = format!("formal/{m}.pv");
        tasks.push(ProverifTask {
            args: vec![path_arg(&file)],
            file,
            model: ProverifModel::Single(m.clone()),
            log: out_dir.join(format!("{m}.log")),
        });
    }
    for (family, s) in sessions {
        let file = format!("{}/{s}.pv", family.dir());
        tasks.push(ProverifTask {
            args: vec!["-lib".to_owned(), path_arg(family.lib()), path_arg(&file)],
            file,
            model: ProverifModel::Session(*family, s.clone()),
            log: out_dir.join(format!("{}-{s}.log", family.name())),
        });
    }
    tasks
}

/// Judge one finished process: its verdicts against `formal/CLAIMS.md` (fixed by the reviewer), as `expect.rs` lists
/// them, and its contribution to the evidence. On a failed check, its `RESULT` lines are printed.
fn proverif_record(root: &Path, t: &ProverifTask, end: ProverifEnd) -> ProverifRecord {
    let (run, secs) = end;
    let output = run.as_ref().ok().map(String::as_str);
    let checked = match (&run, &t.model) {
        (Err(e), _) => Err(Error(e.0.clone())),
        (Ok(out), ProverifModel::Single(m)) => proverif_check(m, out),
        (Ok(out), ProverifModel::Session(f, s)) => proverif_check_session(*f, s, out),
    };
    let text = output.unwrap_or_default();
    match &checked {
        Ok(summary) => say(&format!("  {summary} ({secs:.1} s)")),
        Err(_) => {
            for line in text
                .lines()
                .filter(|l| l.trim_start().starts_with("RESULT"))
            {
                say(&format!("  {line}"));
            }
        }
    }
    let sha = crate::summary::file_sha256(&root.join(&t.file));
    let sha12 = sha
        .as_deref()
        .map_or("-", |h| h.get(..12).unwrap_or(h))
        .to_owned();
    let rows = match &t.model {
        ProverifModel::Single(m) => single_rows(m, output),
        ProverifModel::Session(f, s) => hx_rows(f.table(), s, output),
    };
    ProverifRecord {
        file: t.file.clone(),
        results: proverif_result_lines(text).len(),
        secrecy: text
            .lines()
            .filter(|l| l.contains("secrecy assumption verified"))
            .count(),
        secs,
        checked,
        rows: rows
            .into_iter()
            .map(|(id, verdict, expected)| crate::summary::ProverifRow {
                file: t.file.clone(),
                id,
                verdict,
                expected,
                wall_s: secs,
                sha12: sha12.clone(),
            })
            .collect(),
    }
}

/// `docs/06 §5 step 10` (M3 plan D10; M4 WEISUNG M4-5 §4, gate F7): the ProVerif version and the self-test, then the
/// models selected by `--models` — the single-file models (`formal/tr.pv`) and every SecMP-HX session file
/// (`formal/hx/<session>.pv` with `-lib formal/hx.pvl`) — as `--jobs` parallel processes, each under
/// `expect::PROVERIF_TIMEOUT_SECONDS`, with its output in `target/proverif/<tr | hx-<session>>.log`. Each output is
/// checked against `expect::PROVERIF_EXPECTED` ([`proverif_check`]) or `expect::PROVERIF_EXPECTED_HX`
/// ([`proverif_check_hx`]), both by query text (M4 review C-7); before any run, the model files must have the SHA-256 of
/// `expect::PROVERIF_MODEL_SHA256`. Writes `target/proverif/summary.txt` (SHA-256 of every model file, per file the
/// `RESULT` count, the "secrecy assumption verified" count and the wall time) and `target/proverif/results.tsv` (one
/// row per (file, CLAIMS ID), the ADR-045 summary table), on failure too.
///
/// M5 (OPEN-M5-16 A, BRIEF_M5-B §1): `--models link` and `all` add every SecMP-LINK session file
/// (`formal/link/<session>.pv` with `-lib formal/link.pvl`, checked against `expect::PROVERIF_EXPECTED_LINK`). When the
/// same invocation also runs the step `proverif-link` (`ci-full`; there it may be delegated to the job `proverif-link`
/// with `--delegated proverif-link`), this step leaves the SecMP-LINK models to it ([`proverif_link`]).
pub(crate) fn proverif(ctx: &Ctx) -> Result<Outcome> {
    let opts = proverif_options();
    let skip_link = ctx.steps.contains(&PROVERIF_LINK_STEP);
    proverif_run(ctx, opts.models, skip_link, opts, PROVERIF_FILES)
}

/// The id of the `ci-full` step that runs the SecMP-LINK models on its own (`ci.rs`; M5, BRIEF_M5-B §1).
pub(crate) const PROVERIF_LINK_STEP: &str = "proverif-link";

/// The evidence files of the `proverif` step under `target/proverif/` (summary, results table).
pub(crate) const PROVERIF_FILES: (&str, &str) = ("summary.txt", "results.tsv");

/// The evidence files of the `proverif-link` step under `target/proverif/` (its own, so that both steps of one `ci-full`
/// keep their evidence).
pub(crate) const PROVERIF_LINK_FILES: (&str, &str) = ("link-summary.txt", "link-results.tsv");

/// The process-wide ProVerif options, or the default (every model, default jobs).
fn proverif_options() -> ProverifOptions {
    PROVERIF_OPTIONS.get().copied().unwrap_or(ProverifOptions {
        models: ProverifModels::All,
        jobs: None,
    })
}

/// `ci-full` step `proverif-link` (M5, BRIEF_M5-B §1, OPEN-M5-16 A): the SecMP-LINK session models alone, as the
/// `proverif` step runs them with `--models link` (same preflight, model hashes, 30-min cap per file, `--jobs`, checks
/// against `expect::PROVERIF_EXPECTED_LINK`), with the evidence `target/proverif/link-summary.txt` and
/// `link-results.tsv`. `linux-full` delegates it (`--delegated proverif-link`) to the job `proverif-link`, which runs
/// `cargo xtask step --strict proverif --models link --jobs 4`.
pub(crate) fn proverif_link(ctx: &Ctx) -> Result<Outcome> {
    let opts = proverif_options();
    proverif_run(ctx, ProverifModels::Link, false, opts, PROVERIF_LINK_FILES)
}

/// The body of the steps `proverif` and `proverif-link`: the models of `models` (without the SecMP-LINK sessions when
/// `skip_link`), `opts.jobs` processes, the evidence into `files` under `target/proverif/`.
fn proverif_run(
    ctx: &Ctx,
    models: ProverifModels,
    skip_link: bool,
    opts: ProverifOptions,
    files: (&str, &str),
) -> Result<Outcome> {
    let (summary_name, results_name) = files;
    let jobs = proverif_jobs(opts);
    let out_dir = ctx.root.join("target").join("proverif");
    for stale in [summary_name, results_name] {
        let p = out_dir.join(stale);
        if p.exists() {
            std::fs::remove_file(&p)?;
        }
    }
    proverif_preflight(&ctx.root)?;
    // ADR-046 Amendment 1 (1): only the reviewed models run
    let hashes = proverif_model_hash_findings(&ctx.root, expect::PROVERIF_MODEL_SHA256);
    if !hashes.is_empty() {
        bail!(
            "ProVerif models differ from expect::PROVERIF_MODEL_SHA256: {}",
            hashes.join("; ")
        );
    }
    let (single, sessions) = proverif_inputs(&ctx.root, models, skip_link)?;
    let options = format!(
        "--models {}{}, {jobs} parallel processes, timeout {} s per file",
        models.name(),
        if skip_link && models.sessions(SessionFamily::Link) {
            format!(" without the SecMP-LINK models (they run in step {PROVERIF_LINK_STEP})")
        } else {
            String::new()
        },
        expect::PROVERIF_TIMEOUT_SECONDS
    );
    if single.is_empty() && sessions.is_empty() {
        return Ok(Outcome::Pass(format!(
            "ProVerif {} self-test [true, false] ok; {options}; model hashes: {} of {} match \
             expect::PROVERIF_MODEL_SHA256; no model left for this step",
            tools::PROVERIF_VERSION,
            expect::PROVERIF_MODEL_SHA256.len(),
            expect::PROVERIF_MODEL_SHA256.len(),
        )));
    }
    let tasks = proverif_tasks(&ctx.root, &out_dir, &single, &sessions);
    say(&format!("  ProVerif: {} files, {options}", tasks.len()));
    let timeout = std::time::Duration::from_secs(expect::PROVERIF_TIMEOUT_SECONDS);
    let ends = run_pool(&tasks, jobs, timeout);
    let records: Vec<ProverifRecord> = tasks
        .iter()
        .zip(ends)
        .map(|(t, end)| proverif_record(&ctx.root, t, end))
        .collect();
    let shas: Vec<(String, Option<String>)> = crate::summary::proverif_model_files(&ctx.root)
        .into_iter()
        .map(|f| {
            let h = crate::summary::file_sha256(&ctx.root.join(&f));
            (f, h)
        })
        .collect();
    let header = format!("ProVerif {} gate: {options}", tools::PROVERIF_VERSION);
    let evidence = proverif_evidence(&header, &shas, &records);
    let rows: Vec<crate::summary::ProverifRow> = records
        .iter()
        .flat_map(|r| r.rows.iter().cloned())
        .collect();
    std::fs::create_dir_all(&out_dir)?;
    std::fs::write(out_dir.join(summary_name), &evidence)?;
    std::fs::write(
        out_dir.join(results_name),
        crate::summary::proverif_tsv(&rows),
    )?;
    say(evidence.trim_end());
    let failures: Vec<&str> = records
        .iter()
        .filter_map(|r| r.checked.as_ref().err().map(|e| e.0.as_str()))
        .collect();
    if !failures.is_empty() {
        bail!(
            "{} of {} ProVerif files failed: {}",
            failures.len(),
            tasks.len(),
            failures.join("; ")
        );
    }
    let summaries: Vec<String> = records
        .iter()
        .filter_map(|r| {
            r.checked
                .as_ref()
                .ok()
                .map(|s| format!("{s} ({:.1} s)", r.secs))
        })
        .collect();
    Ok(Outcome::Pass(proverif_pass_detail(
        &options,
        &(single, sessions),
        &summaries,
        files,
    )))
}

/// The detail line of a passing `proverif`/`proverif-link` step.
fn proverif_pass_detail(
    options: &str,
    inputs: &ProverifInputs,
    summaries: &[String],
    (summary_name, results_name): (&str, &str),
) -> String {
    let (single, sessions) = inputs;
    let none_or = |v: String| if v.is_empty() { "none".to_owned() } else { v };
    let of_family = |family: SessionFamily| -> String {
        let names: Vec<&str> = sessions
            .iter()
            .filter(|(f, _)| *f == family)
            .map(|(_, s)| s.as_str())
            .collect();
        none_or(names.join(", "))
    };
    format!(
        "ProVerif {} self-test [true, false] ok; {options}; model hashes: {} of {} match \
         expect::PROVERIF_MODEL_SHA256; single-file models: {} (expected set matches); HX sessions over {}: {} (= the \
         files of expect::PROVERIF_EXPECTED_HX); LINK sessions over {}: {} (= the files of \
         expect::PROVERIF_EXPECTED_LINK); {}; evidence target/proverif/{summary_name}, {results_name} and one log per \
         file",
        tools::PROVERIF_VERSION,
        expect::PROVERIF_MODEL_SHA256.len(),
        expect::PROVERIF_MODEL_SHA256.len(),
        none_or(single.join(", ")),
        expect::PROVERIF_HX_LIB,
        of_family(SessionFamily::Hx),
        expect::PROVERIF_LINK_LIB,
        of_family(SessionFamily::Link),
        summaries.join("; ")
    )
}

/// The `RESULT` lines of a ProVerif output in order. The `RESULT (but …)` / `RESULT (even …)` remark ProVerif prints
/// under an injective query that does not hold states the non-injective version's verdict (`(even … is false.)` when
/// that version is false too, first seen with H8/H9, M4-11; `(but … is true.)` when it holds): it is no result of its
/// own and is attached to the line above it (M5 review R-117, C-9: the gate reads it for the injective lines expected
/// false). A remark without a line above it is an unreadable line of its own (ProVerif never prints one).
pub(crate) fn proverif_result_lines(output: &str) -> Vec<ResultLine> {
    let mut out: Vec<ResultLine> = Vec::new();
    for r in output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("RESULT "))
    {
        let remark = r.starts_with("(but ") || r.starts_with("(even ");
        match out.last_mut() {
            Some(above) if remark => above.remarks.push(r.to_owned()),
            _ => out.push(result_line(r, remark)),
        }
    }
    out
}

/// One `RESULT` line (the text after `RESULT `) read as query and verdict; `orphan`: a remark without a line above it.
fn result_line(r: &str, orphan: bool) -> ResultLine {
    let unreadable = ResultLine {
        query: r.to_owned(),
        verdict: PvVerdict::Unreadable,
        remarks: Vec::new(),
    };
    if orphan {
        return unreadable;
    }
    for (suffix, verdict) in [
        (" is true.", PvVerdict::True),
        (" is false.", PvVerdict::False),
        (" cannot be proved.", PvVerdict::CannotBeProved),
    ] {
        if let Some(query) = r.strip_suffix(suffix) {
            return ResultLine {
                query: query.to_owned(),
                verdict,
                remarks: Vec::new(),
            };
        }
    }
    unreadable
}

/// M5 review R-117 (C-9): the remarks under an injective `RESULT` line that is false say that the non-injective
/// version is false as well — exactly one remark, `(even … is false.)`. `(but … is true.)` (only injectivity fails: a
/// replay) or no remark does not.
fn even_remark(remarks: &[String]) -> bool {
    matches!(remarks, [r] if r.starts_with("(even ") && r.ends_with(" is false.)"))
}

/// What ProVerif says about one query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PvVerdict {
    /// "… is true.": proved.
    True,
    /// "… is false.": ProVerif found a trace (an attack, or for a reachability query: the event is reachable).
    False,
    /// "… cannot be proved.".
    CannotBeProved,
    /// None of the three endings.
    Unreadable,
}

impl PvVerdict {
    fn word(self) -> &'static str {
        match self {
            Self::True => "true",
            Self::False => "false",
            Self::CannotBeProved => "cannot be proved",
            Self::Unreadable => "unreadable",
        }
    }
}

/// One `RESULT` line: the query text (between `RESULT ` and the verdict), the verdict, and the `RESULT (but …)` /
/// `RESULT (even …)` remarks printed under it (the text after `RESULT `; none for a query that holds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResultLine {
    pub(crate) query: String,
    pub(crate) verdict: PvVerdict,
    pub(crate) remarks: Vec<String>,
}

/// The expected entries of one SecMP-HX file: (CLAIMS ID, query text, verdict), in table order.
fn hx_expected<'a>(
    table: &'a [expect::HxExpected],
    file: &str,
) -> Vec<(&'a str, &'a str, expect::Proved)> {
    table
        .iter()
        .filter(|(f, ..)| *f == file)
        .map(|(_, id, query, proved)| (*id, *query, *proved))
        .collect()
}

/// For every `RESULT` line, the index of the expected entry with the same query text (`None`: an extra line). Each
/// entry matches at most one line: the entry at the line's own position if its text is the same, else the first unused
/// entry with that text.
fn hx_match(expected: &[(&str, &str, expect::Proved)], got: &[ResultLine]) -> Vec<Option<usize>> {
    let mut used = vec![false; expected.len()];
    let mut out = Vec::new();
    for (i, g) in got.iter().enumerate() {
        let free = |j: usize, used: &[bool]| {
            expected.get(j).is_some_and(|e| e.1 == g.query) && used.get(j) == Some(&false)
        };
        let j = if free(i, &used) {
            Some(i)
        } else {
            (0..expected.len()).find(|j| free(*j, &used))
        };
        if let Some(slot) = j.and_then(|j| used.get_mut(j)) {
            *slot = true;
        }
        out.push(j);
    }
    out
}

/// WEISUNG M4-5 §4 (b): the `RESULT` lines of one SecMP-HX session file (`formal/hx/<file>.pv`) against its entries
/// in `expect::PROVERIF_EXPECTED_HX`, matched by query text, not by position ([`proverif_check_hx_in`]; the step calls
/// [`proverif_check_session`]).
#[cfg(test)]
pub(crate) fn proverif_check_hx(file: &str, output: &str) -> Result<String> {
    proverif_check_hx_in(expect::PROVERIF_EXPECTED_HX, file, output)
}

/// [`proverif_check_hx`] against `table`: the file must have entries; every `RESULT` line must match an entry by its
/// query text (else "extra"), every entry a line (else "missing"), the matched entries must come in table order (else
/// "re-ordered") and their number must be the same; a `True` entry's line must say "is true.", a `False` entry's
/// line "is false." (an `Informative` entry's line may say anything), and a `False` entry's line whose query is
/// injective (its text contains `inj-event`) must carry exactly one remark `RESULT (even … is false.)` (M5 review
/// R-117, C-9); anything else fails, naming the file, the CLAIMS ID and the query text. Returns the summary per ID.
/// Also the check of the single-file models (`file` one of `expect::PROVERIF_MODELS`, M4 review C-7).
pub(crate) fn proverif_check_hx_in(
    table: &[expect::HxExpected],
    file: &str,
    output: &str,
) -> Result<String> {
    // a single-file model (`formal/tr.pv`, rows of `expect::PROVERIF_EXPECTED`) or an HX session file
    let (path, table_name) = if expect::PROVERIF_MODELS.contains(&file) {
        (format!("formal/{file}.pv"), "expect::PROVERIF_EXPECTED")
    } else {
        (
            format!("{}/{file}.pv", expect::PROVERIF_HX_DIR),
            "expect::PROVERIF_EXPECTED_HX",
        )
    };
    proverif_check_lines(table, &path, table_name, file, output)
}

/// M5 (OPEN-M5-16 A): the `RESULT` lines of one session file of `family` (`<dir>/<file>.pv`) against its entries in the
/// family's table, with the rules of [`proverif_check_hx_in`]; for SecMP-LINK, `formal/link/<file>.pv` against
/// `expect::PROVERIF_EXPECTED_LINK`.
pub(crate) fn proverif_check_session(
    family: SessionFamily,
    file: &str,
    output: &str,
) -> Result<String> {
    proverif_check_lines(
        family.table(),
        &format!("{}/{file}.pv", family.dir()),
        family.table_name(),
        file,
        output,
    )
}

/// The check of [`proverif_check_hx_in`] for the model `path` with the entries of `file` in `table` (`table_name`).
fn proverif_check_lines(
    table: &[expect::HxExpected],
    path: &str,
    table_name: &str,
    file: &str,
    output: &str,
) -> Result<String> {
    use expect::Proved;
    let expected = hx_expected(table, file);
    if expected.is_empty() {
        bail!("{path}: no expected entries in {table_name}");
    }
    let got = proverif_result_lines(output);
    let matched = hx_match(&expected, &got);
    let mut problems = Vec::new();
    if got.len() != expected.len() {
        problems.push(format!(
            "{} RESULT lines, expected {}",
            got.len(),
            expected.len()
        ));
    }
    let mut furthest: Option<usize> = None;
    for (line, (g, m)) in (1_usize..).zip(got.iter().zip(&matched)) {
        let Some((j, (id, _, want))) = m.and_then(|j| expected.get(j).map(|e| (j, e))) else {
            problems.push(format!(
                "extra RESULT line {line} (no such query in the table), {}: {}",
                g.verdict.word(),
                g.query
            ));
            continue;
        };
        if furthest.is_some_and(|f| j < f) {
            problems.push(format!(
                "RESULT line {line} ({id}) is re-ordered: the table has it as entry {} of the file, before the entry of \
                 an earlier line: {}",
                j.saturating_add(1),
                g.query
            ));
        }
        furthest = Some(furthest.map_or(j, |f| f.max(j)));
        let wanted = match want {
            Proved::True if g.verdict != PvVerdict::True => Some("true (proved)"),
            Proved::False if g.verdict != PvVerdict::False => {
                Some("false (ProVerif finds the trace)")
            }
            _ => None,
        };
        if let Some(wanted) = wanted {
            problems.push(format!(
                "RESULT line {line} ({id}) is {}, expected {wanted}: {}",
                g.verdict.word(),
                g.query
            ));
        }
        // M5 review R-117 (C-9): an injective query expected false (the line's own text says `inj-event`) must be false
        // in its non-injective version too; `(but … is true.)` under it is a replay-only failure, not the expected one
        if *want == Proved::False
            && g.verdict == PvVerdict::False
            && g.query.contains("inj-event")
            && !even_remark(&g.remarks)
        {
            let remarks = if g.remarks.is_empty() {
                "none".to_owned()
            } else {
                g.remarks
                    .iter()
                    .map(|r| format!("`RESULT {r}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            problems.push(format!(
                "RESULT line {line} ({id}) is an injective query expected false, but its remark is {remarks}, \
                 expected one `RESULT (even … is false.)` (the non-injective version false too): {}",
                g.query
            ));
        }
    }
    for (j, (id, query, _)) in expected.iter().enumerate() {
        if !matched.contains(&Some(j)) {
            problems.push(format!(
                "missing RESULT line for {id} (entry {} of the file): {query}",
                j.saturating_add(1)
            ));
        }
    }
    if !problems.is_empty() {
        bail!("{path} against {table_name}: {}", problems.join("; "));
    }
    let mut groups: Vec<(&str, &str, usize)> = Vec::new();
    for ((id, ..), g) in expected.iter().zip(&got) {
        match groups.last_mut() {
            Some((last, word, n)) if last == id && *word == g.verdict.word() => {
                *n = n.saturating_add(1);
            }
            _ => groups.push((*id, g.verdict.word(), 1)),
        }
    }
    Ok(format!(
        "{path}: {} RESULT lines as expected — {}",
        got.len(),
        groups
            .iter()
            .map(|(id, word, n)| format!("{id} {word} ×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// The expected verdict of a table entry as a word of the results table.
fn expected_word(p: expect::Proved) -> &'static str {
    match p {
        expect::Proved::True => "true",
        expect::Proved::False => "false",
        expect::Proved::Informative => "any (informative)",
    }
}

/// `words` counted in the order of their first appearance: "false ×4", "true ×5, missing ×1".
fn counted(words: &[&str]) -> String {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for w in words {
        match counts.iter_mut().find(|(x, _)| x == w) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => counts.push((w, 1)),
        }
    }
    counts
        .iter()
        .map(|(w, n)| format!("{w} ×{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Group (ID, verdict word, expected word) triples into one (ID, verdicts, expected) row per ID, in the order of the
/// IDs' first appearance.
fn group_rows(entries: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
    let mut ids: Vec<&str> = Vec::new();
    for (id, ..) in entries {
        if !ids.contains(id) {
            ids.push(*id);
        }
    }
    ids.iter()
        .map(|id| {
            let of_id: Vec<&(&str, &str, &str)> = entries.iter().filter(|e| e.0 == *id).collect();
            let got: Vec<&str> = of_id.iter().map(|e| e.1).collect();
            let want: Vec<&str> = of_id.iter().map(|e| e.2).collect();
            ((*id).to_owned(), counted(&got), counted(&want))
        })
        .collect()
}

/// The results-table rows (ADR-045) of a single-file model: its rows of `expect::PROVERIF_EXPECTED`, matched by query
/// text as [`hx_rows`] does; `output` `None`: the run failed ("no result").
fn single_rows(model: &str, output: Option<&str>) -> Vec<(String, String, String)> {
    expect::PROVERIF_EXPECTED
        .iter()
        .find(|(m, _)| *m == model)
        .map(|(_, rows)| hx_rows(rows, model, output))
        .unwrap_or_default()
}

/// The results-table rows (ADR-045) of a SecMP-HX file: per CLAIMS ID the verdicts of its lines, matched by query text
/// like [`proverif_check_hx_in`] ("missing" for an entry without a line, a row "(not in the table)" for extra lines);
/// `output` `None`: the run failed ("no result").
fn hx_rows(
    table: &[expect::HxExpected],
    file: &str,
    output: Option<&str>,
) -> Vec<(String, String, String)> {
    let expected = hx_expected(table, file);
    let got = output.map(proverif_result_lines);
    let matched = got.as_ref().map(|g| hx_match(&expected, g));
    let mut entries = Vec::new();
    for (j, (id, _, proved)) in expected.iter().enumerate() {
        let word = match (&got, &matched) {
            (Some(g), Some(m)) => m
                .iter()
                .position(|x| *x == Some(j))
                .and_then(|i| g.get(i))
                .map_or("missing", |l| l.verdict.word()),
            _ => "no result",
        };
        entries.push((*id, word, expected_word(*proved)));
    }
    if let (Some(g), Some(m)) = (&got, &matched) {
        for (l, _) in g.iter().zip(m).filter(|(_, x)| x.is_none()) {
            entries.push(("(not in the table)", l.verdict.word(), "none"));
        }
    }
    group_rows(&entries)
}

/// Step 10 per single-file model (M3 plan D10; M4 review C-7, ADR-046 Amendment 1 (3)): the `RESULT` lines of one
/// ProVerif run against the model's rows in `expect::PROVERIF_EXPECTED`, matched by query text like the HX files
/// ([`proverif_check_hx_in`]); a model without rows is refused. Returns the summary per ID.
pub(crate) fn proverif_check(model: &str, output: &str) -> Result<String> {
    let Some((_, rows)) = expect::PROVERIF_EXPECTED.iter().find(|(m, _)| *m == model) else {
        bail!("formal/{model}.pv: no expected verdicts in expect::PROVERIF_EXPECTED");
    };
    proverif_check_hx_in(rows, model, output)
}

// ---- step 11: Windows and Linux targets -----------------------------------------------------------------------

pub(crate) fn windows_cross(ctx: &Ctx) -> Result<Outcome> {
    if ctx.host.contains("windows") {
        return Ok(Outcome::Skip(
            "host is Windows: the native build replaces the cross-build".into(),
        ));
    }
    tools::require(tools::XWIN)?;
    Cmd::cargo()
        .args([
            "xwin",
            "build",
            "--workspace",
            "--all-targets",
            "--locked",
            "--target",
            "x86_64-pc-windows-msvc",
        ])
        .run()?;
    Ok(Outcome::Pass(
        "cargo xwin build --all-targets for x86_64-pc-windows-msvc".into(),
    ))
}

pub(crate) fn windows_native(ctx: &Ctx) -> Outcome {
    if ctx.host.contains("windows") {
        return Outcome::Skip(
            "run `cargo xtask step clippy nextest doctest kat hello` natively instead".into(),
        );
    }
    Outcome::Skip(
        "Windows tests run on windows-latest (A1 §2): `cargo xtask win-test --backend github` or CI job windows-native".into(),
    )
}

pub(crate) fn linux_target(ctx: &Ctx) -> Result<Outcome> {
    if ctx.host == "x86_64-unknown-linux-gnu" {
        return Ok(Outcome::Pass(
            "host is x86_64-unknown-linux-gnu: every step above ran natively".into(),
        ));
    }
    if ctx.host.contains("apple-darwin") {
        tools::require(tools::ZIGBUILD)?;
        let zig = Cmd::new("zig").arg("version").read()?;
        if zig.trim() != tools::ZIG_VERSION {
            bail!("zig {} found, pinned {}", zig.trim(), tools::ZIG_VERSION);
        }
        Cmd::cargo()
            .args([
                "zigbuild",
                "--workspace",
                "--all-targets",
                "--locked",
                "--target",
                "x86_64-unknown-linux-gnu",
            ])
            .run()?;
        return Ok(Outcome::Pass(
            "cargo zigbuild --all-targets for x86_64-unknown-linux-gnu (build only, A1 §3)".into(),
        ));
    }
    Ok(Outcome::Skip(
        "Linux-target build is checked on Linux and macOS hosts".into(),
    ))
}

// ---- steps 12–14 -----------------------------------------------------------------------------------------

/// Step 12a: the frozen SecMP vectors equal the committed reference files of the independent `ref/` session,
/// structurally and byte for byte (ADR-026 as amended; M2 review F8; CI compares with the committed
/// `vectors/ref/*.json` and never runs the Python generator, M1 brief Q-4). The Rust side is re-checked against the frozen files by the `kat` step (`tests/vectors.rs`).
pub(crate) fn ref_vectors(ctx: &Ctx) -> Result<Outcome> {
    Ok(Outcome::Pass(crate::vectors::check_frozen_against_ref(
        &ctx.root,
    )?))
}

pub(crate) fn repro(_: &Ctx) -> Outcome {
    Outcome::Stub(
        "two-builder reproducibility check becomes real in M11 (`cargo xtask repro-check`)".into(),
    )
}

pub(crate) fn sbom(ctx: &Ctx) -> Result<Outcome> {
    Ok(Outcome::Pass(crate::sbom::run(&ctx.root)?))
}

/// "Overall exposure level for <unit>: <float> ..." → the float.
pub(crate) fn systemd_exposure(output: &str) -> Option<f64> {
    output.lines().find_map(|l| {
        let (_, rest) = l.split_once("Overall exposure level for ")?;
        let (_, value) = rest.split_once(": ")?;
        value.split_whitespace().next()?.parse::<f64>().ok()
    })
}

fn analyze(unit: &Path) -> Result<f64> {
    let cap = Cmd::new("systemd-analyze")
        .args(["security", "--offline=true", "--no-pager"])
        .arg(unit.to_string_lossy())
        .capture()?;
    let text = format!("{}{}", cap.stdout, cap.stderr);
    systemd_exposure(&text).ok_or_else(|| {
        say(text.trim_end());
        Error(format!(
            "systemd-analyze printed no exposure level for {}",
            unit.display()
        ))
    })
}

pub(crate) fn systemd(ctx: &Ctx) -> Result<Outcome> {
    if !ctx.host.contains("linux") {
        return Ok(Outcome::Skip(
            "systemd-analyze is Linux-only (CI jobs linux-fast/linux-full run it)".into(),
        ));
    }
    let version = Cmd::new("systemd-analyze").arg("--version").read()?;
    let weak = ctx
        .root
        .join("xtask")
        .join("fixtures")
        .join("systemd")
        .join("weak.service");
    let weak_level = analyze(&weak)?;
    if weak_level <= expect::SYSTEMD_MAX_EXPOSURE {
        bail!(
            "self-test: the unhardened fixture scored {weak_level}, the gate would not detect a weak unit"
        );
    }
    let dir = ctx.root.join("deploy");
    let units: BTreeSet<String> = if dir.exists() {
        walk_files(&dir, &|p: &Path| {
            p.extension().is_some_and(|e| e == "service")
        })?
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect()
    } else {
        BTreeSet::new()
    };
    same_set("systemd units in deploy/", &units, expect::SYSTEMD_UNITS)?;
    let mut parts = Vec::new();
    for u in &units {
        let level = analyze(&dir.join(u))?;
        if level > expect::SYSTEMD_MAX_EXPOSURE {
            bail!("{u}: exposure {level} > {}", expect::SYSTEMD_MAX_EXPOSURE);
        }
        parts.push(format!("{u} {level}"));
    }
    Ok(Outcome::Pass(format!(
        "{}; self-test: unhardened fixture {weak_level} > {} rejected; units: {}",
        version.lines().next().unwrap_or_default().trim(),
        expect::SYSTEMD_MAX_EXPOSURE,
        if parts.is_empty() {
            "none (deploy/secmp-relay.service arrives in M10)".to_owned()
        } else {
            parts.join(", ")
        }
    )))
}

// ---- CI hygiene --------------------------------------------------------------------------------------------

/// Findings for one workflow file: forbidden triggers, actions not pinned to a full commit SHA, flow-style YAML inside
/// `jobs:`, `continue-on-error` outside the jobs allowed by `expect::CONTINUE_ON_ERROR_JOBS`, and artefact names
/// without the run attempt. An accident guard against careless workflow edits, not a tamper-proof control: the real
/// control is review (M3 review F23, R-08).
pub(crate) fn workflow_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        for trigger in ["pull_request_target", "workflow_run"] {
            if t.contains(trigger) {
                out.push(format!("{name}: forbidden trigger `{trigger}`"));
            }
        }
        if let Some(v) = t.strip_prefix("run:").or_else(|| t.strip_prefix("- run:")) {
            let v = v.trim_start();
            let plain = !(v.is_empty() || v.starts_with(['|', '>', '"', '\'']));
            if plain && (v.contains(": ") || v.contains(" #")) {
                out.push(format!(
                    "{name}: plain-scalar `run:` containing \": \" or \" #\" is not valid YAML: {v}"
                ));
            }
        }
    }
    // F3 (R-09): the value is read as YAML would (`true # false` is `true`; `"continue-on-error"` and any
    // indentation are the same key)
    let lines = yaml_lines(text);
    // M4 review C-5 (R-15): `uses` read as YAML would (a quoted key, a space before the colon), and no flow-style
    // mapping or sequence inside `jobs:`, which this reader does not parse (`- {uses: …}`, `job: {if: false}`)
    for l in &lines {
        if l.job.is_some() && (l.key.starts_with(['{', '[']) || l.value.starts_with(['{', '['])) {
            out.push(format!(
                "{name}: flow-style YAML inside jobs (job {:?}): {}: {}",
                l.job, l.key, l.value
            ));
        }
        // delta review VD1-4: nor on the `jobs:` line itself — `jobs: {a: {…}}` would hide every job from this reader
        if l.col == 0 && l.dash.is_none() && l.key == "jobs" && !l.value.is_empty() {
            out.push(format!(
                "{name}: flow-style YAML on the `jobs:` line: jobs: {}",
                l.value
            ));
        }
        if l.key == "uses" {
            let u = l.value.as_str();
            let pinned = u.split_once('@').is_some_and(|(_, r)| {
                let r = r.split_whitespace().next().unwrap_or_default();
                r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
            });
            if !u.starts_with("./") && !pinned {
                out.push(format!("{name}: action not pinned by commit SHA: {u}"));
            }
        }
    }
    for l in &lines {
        if l.key == "continue-on-error" && l.value != "false" {
            let ok = l
                .job
                .as_deref()
                .is_some_and(|j| expect::CONTINUE_ON_ERROR_JOBS.contains(&j));
            if !ok {
                out.push(format!(
                    "{name}: continue-on-error in job {:?} is not allowed",
                    l.job
                ));
            }
        }
    }
    // F21 (R-49): every uploaded artefact name ends with the run attempt, so a re-run of the same run (same SHA,
    // same run id) uploads under a new name instead of failing on the existing one
    for n in upload_artifact_names(&lines) {
        match n {
            Some(n) if n.ends_with(ARTEFACT_SUFFIX) => {}
            other => out.push(format!(
                "{name}: upload-artifact name {other:?} does not end with `{ARTEFACT_SUFFIX}`"
            )),
        }
    }
    out
}

/// M4 review C-5 (R-16): the workflow-level `permissions` of every workflow is exactly `contents: read`, no job sets
/// its own `permissions`, and no workflow mentions `SECMP_PROVERIF` (the variable that replaces the ProVerif binary of
/// the `proverif` step). An accident guard like [`workflow_findings`].
pub(crate) fn workflow_token_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines = yaml_lines(text);
    let mut top = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.col == 0 && l.dash.is_none() && l.key == "permissions");
    match (top.next(), top.next()) {
        (Some((i, p)), None) => {
            let body: Vec<(&str, &str)> = lines
                .iter()
                .skip(i.saturating_add(1))
                .take_while(|l| l.col > 0 || l.dash.is_some())
                .map(|l| (l.key.as_str(), l.value.as_str()))
                .collect();
            if !p.value.is_empty() || body != [("contents", "read")] {
                out.push(format!(
                    "{name}: workflow permissions are not exactly `contents: read`: {:?} {body:?}",
                    p.value
                ));
            }
        }
        (None, _) => out.push(format!(
            "{name}: no workflow-level `permissions: contents: read`"
        )),
        (Some(_), Some(_)) => out.push(format!("{name}: two workflow-level `permissions`")),
    }
    for l in lines
        .iter()
        .filter(|l| l.job.is_some() && l.key == "permissions")
    {
        out.push(format!(
            "{name}: job {:?} sets its own `permissions`",
            l.job
        ));
    }
    if text.contains("SECMP_PROVERIF") {
        out.push(format!(
            "{name}: mentions SECMP_PROVERIF, which replaces the prover of the proverif step"
        ));
    }
    out
}

/// The end of every artefact name (M2 review F5, M3 review F21).
pub(crate) const ARTEFACT_SUFFIX: &str = "-${{ github.run_attempt }}";

/// The `with: name:` of every `actions/upload-artifact` step (`None`: the step has no name).
fn upload_artifact_names(lines: &[YLine]) -> Vec<Option<String>> {
    let mut out = Vec::new();
    for (i, uses) in lines.iter().enumerate() {
        if uses.key != "uses" || !uses.value.starts_with("actions/upload-artifact@") {
            continue;
        }
        let mut in_with = false;
        let mut found = None;
        for x in lines.iter().skip(i.saturating_add(1)) {
            if x.dash.is_some() || x.col < uses.col {
                break;
            }
            if x.col == uses.col {
                in_with = x.key == "with";
            } else if in_with && x.key == "name" {
                found = Some(x.value.clone());
                break;
            }
        }
        out.push(found);
    }
    out
}

// A minimal reader for the block-style subset of YAML the workflows use (no YAML crate is a dependency). It
// normalises what a line-syntactic match missed (M3 review F3, R-09): `if : false`, `"if": false`, any indentation
// width, trailing comments, block scalars. It is an accident guard, not a YAML implementation: flow-style jobs
// (`job: {if: false}`) are refused for the required jobs rather than parsed.

/// One logical line of a workflow: the column of its key, the column of a leading `- `, the unquoted key, the
/// scalar value without a trailing comment, and the job it belongs to (the job id itself for a job header).
struct YLine {
    col: usize,
    dash: Option<usize>,
    key: String,
    value: String,
    job: Option<String>,
    header: bool,
}

/// A scalar without quotes and without a trailing ` # comment`.
fn yaml_scalar(v: &str) -> String {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q)
            && let Some((inner, after)) = rest.split_once(q)
        {
            let after = after.trim();
            if after.is_empty() || after.starts_with('#') {
                return inner.to_owned();
            }
        }
    }
    if v.starts_with('#') {
        return String::new();
    }
    v.split(" #").next().unwrap_or_default().trim().to_owned()
}

/// `key: value` of a line with its dash removed; no key (a plain list item) gives an empty key.
fn yaml_key_value(rest: &str) -> (String, String) {
    for q in ['"', '\''] {
        if let Some(r) = rest.strip_prefix(q)
            && let Some((k, after)) = r.split_once(q)
            && let Some(v) = after.trim_start().strip_prefix(':')
            && (v.is_empty() || v.starts_with(' '))
        {
            return (k.trim().to_owned(), yaml_scalar(v));
        }
    }
    if let Some((k, v)) = rest.split_once(": ") {
        return (k.trim().to_owned(), yaml_scalar(v));
    }
    if let Some(k) = rest.strip_suffix(':') {
        return (k.trim().to_owned(), String::new());
    }
    (String::new(), yaml_scalar(rest))
}

fn yaml_lines(text: &str) -> Vec<YLine> {
    let mut out = Vec::new();
    let mut in_jobs = false;
    let mut job_col: Option<usize> = None;
    let mut job: Option<String> = None;
    let mut block: Option<usize> = None;
    for raw in text.lines() {
        let raw = raw.trim_end();
        let body = raw.trim_start_matches(' ');
        let lead = raw.len().saturating_sub(body.len());
        if let Some(c) = block {
            if body.is_empty() || lead > c {
                continue;
            }
            block = None;
        }
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let item = if body == "-" {
            Some("")
        } else {
            body.strip_prefix("- ")
        };
        let (dash, rest, col) = match item {
            Some(r) => {
                let r = r.trim_start_matches(' ');
                (
                    Some(lead),
                    r,
                    lead.saturating_add(body.len().saturating_sub(r.len())),
                )
            }
            None => (None, body, lead),
        };
        let (key, value) = yaml_key_value(rest);
        if value.starts_with(['|', '>']) {
            block = Some(col);
        }
        let mut header = false;
        let mut current = None;
        if col == 0 && dash.is_none() {
            in_jobs = key == "jobs";
            job_col = None;
            job = None;
        } else if in_jobs {
            if job_col.is_none() && dash.is_none() {
                job_col = Some(col);
            }
            if dash.is_none() && Some(col) == job_col {
                job = Some(key.clone());
                header = true;
            }
            current.clone_from(&job);
        }
        out.push(YLine {
            col,
            dash,
            key,
            value,
            job: current,
            header,
        });
    }
    out
}

/// A job of a workflow: its id, whether its header carries an inline value (flow style), its direct properties
/// (key, value) and the direct properties of each of its steps.
struct YJob {
    id: String,
    inline: bool,
    props: Vec<(String, String)>,
    steps: Vec<Vec<(String, String)>>,
}

impl YJob {
    fn prop(&self, key: &str) -> Option<&str> {
        self.props
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn yaml_jobs(text: &str) -> Vec<YJob> {
    let mut jobs: Vec<YJob> = Vec::new();
    let mut prop_col: Option<usize> = None;
    let mut cur_prop = String::new();
    let mut step_dash: Option<usize> = None;
    let mut step_col: Option<usize> = None;
    for l in yaml_lines(text) {
        let Some(id) = &l.job else {
            continue;
        };
        if l.header {
            jobs.push(YJob {
                id: id.clone(),
                inline: !l.value.is_empty(),
                props: Vec::new(),
                steps: Vec::new(),
            });
            prop_col = None;
            cur_prop.clear();
            step_dash = None;
            step_col = None;
            continue;
        }
        let Some(j) = jobs.last_mut() else {
            continue;
        };
        if prop_col.is_none() && l.dash.is_none() {
            prop_col = Some(l.col);
        }
        if l.dash.is_none() && Some(l.col) == prop_col {
            cur_prop.clone_from(&l.key);
            j.props.push((l.key, l.value));
            step_dash = None;
            step_col = None;
            continue;
        }
        if cur_prop != "steps" {
            continue;
        }
        if let Some(d) = l.dash {
            if step_dash.is_none() {
                step_dash = Some(d);
                step_col = Some(l.col);
            }
            if Some(d) == step_dash {
                j.steps.push(vec![(l.key, l.value)]);
            }
        } else if Some(l.col) == step_col
            && let Some(step) = j.steps.last_mut()
        {
            step.push((l.key, l.value));
        }
    }
    jobs
}

/// The job ids of a workflow and the `name:` of each job (a check run carries the name, or the id without one).
fn job_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for j in yaml_jobs(text) {
        out.push(j.id.clone());
        if let Some(n) = j.prop("name") {
            out.push(n.to_owned());
        }
    }
    out
}

/// The job-level `if:` of every job of a workflow: (job id, the condition as written after `if:`, trimmed), `None`
/// for a job without one. Step-level conditions (deeper indentation) are not job conditions.
fn job_conditions(text: &str) -> Vec<(String, Option<String>)> {
    yaml_jobs(text)
        .into_iter()
        .map(|j| {
            let cond = j.prop("if").map(str::to_owned);
            (j.id, cond)
        })
        .collect()
}

/// A step that runs a `cargo xtask` gate (not the tool installation).
fn is_gate_run(run: &str) -> bool {
    run.contains("cargo xtask") && !run.contains("install-tools")
}

/// F3 (R-09), M4 review C-5: structural findings for the pinned jobs (`expect::PINNED_JOBS`) of the required workflow —
/// a `needs:` other than the one of `expect::PINNED_JOB_NEEDS` (a skipped or failing dependency would skip the job),
/// flow-style or renamed or doubly conditioned jobs, a step-level `if:` on a gate step, a `defaults:` and a step
/// `shell:` (either changes the shell a gate line runs in); and a `defaults:` anywhere in the workflow. An accident
/// guard (see [`required_job_findings`]).
fn required_job_structure_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    if yaml_lines(text).iter().any(|l| l.key == "defaults") {
        out.push(format!(
            "{name}: a `defaults:` changes the shell of the pinned gate lines"
        ));
    }
    for j in yaml_jobs(text) {
        if !expect::PINNED_JOBS.contains(&j.id.as_str()) {
            continue;
        }
        let id = &j.id;
        if j.inline {
            out.push(format!("{name}: pinned job `{id}` is in flow style"));
        }
        let pinned_needs = expect::PINNED_JOB_NEEDS
            .iter()
            .find(|(job, _)| job == id)
            .map(|(_, needs)| *needs);
        let needs: Vec<&str> = j
            .props
            .iter()
            .filter(|(k, _)| k == "needs")
            .map(|(_, v)| v.as_str())
            .collect();
        match (pinned_needs, needs.as_slice()) {
            (None, []) => {}
            (Some(p), [n]) if p == *n => {}
            (pinned, found) => out.push(format!(
                "{name}: pinned job `{id}`: `needs:` {found:?}, pinned {pinned:?} (a `needs:` can skip the job)"
            )),
        }
        for (key, why) in [
            ("name", "a `name:` changes the check-run name"),
            (
                "defaults",
                "a `defaults:` changes the shell of its gate lines",
            ),
        ] {
            if j.props.iter().any(|(k, _)| k == key) {
                out.push(format!("{name}: pinned job `{id}`: {why}"));
            }
        }
        if j.props.iter().filter(|(k, _)| k == "if").count() > 1 {
            out.push(format!("{name}: pinned job `{id}` has two `if:`"));
        }
        for step in &j.steps {
            let gate = step.iter().any(|(k, v)| k == "run" && is_gate_run(v));
            if gate && step.iter().any(|(k, _)| k == "if") {
                out.push(format!(
                    "{name}: pinned job `{id}`: a gate step has a step-level `if:`"
                ));
            }
            if step.iter().any(|(k, _)| k == "shell") {
                out.push(format!("{name}: pinned job `{id}`: a step sets `shell:`"));
            }
        }
    }
    out
}

/// M4 review C-5 (V5 (d)): every `--delegated <step>` of a pinned gate line (`runs`, as `expect::REQUIRED_GATE_RUNS`)
/// is listed in `expect::DELEGATED_TO` with a job that has a pinned gate line of its own, a pinned `--models tr` comes
/// with a pinned `proverif --models hx` line, and (M5) a pinned `--models tr`/`hx` or `--delegated proverif-link` with a
/// pinned `proverif --models link` line — so no delegation hands a step to nothing.
pub(crate) fn delegation_findings(
    runs: &[(&str, &[&str])],
    delegated_to: &[(&str, &str)],
) -> Vec<String> {
    let mut out = Vec::new();
    let has_line = |job: &str| runs.iter().any(|(j, lines)| *j == job && !lines.is_empty());
    let all_lines = || runs.iter().flat_map(|(_, lines)| lines.iter());
    for (job, lines) in runs {
        for line in *lines {
            for d in line.split("--delegated ").skip(1) {
                let step = d.split_whitespace().next().unwrap_or_default();
                match delegated_to.iter().find(|(s, _)| *s == step) {
                    None => out.push(format!(
                        "`{job}` delegates `{step}`, which expect::DELEGATED_TO does not map to a job"
                    )),
                    Some((_, target)) if !has_line(target) => out.push(format!(
                        "`{job}` delegates `{step}` to `{target}`, which has no pinned gate line"
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    if all_lines().any(|l| l.contains("--models tr"))
        && !all_lines().any(|l| l.contains("proverif --models hx"))
    {
        out.push(
            "a pinned line runs `--models tr` but no pinned line runs `proverif --models hx`"
                .to_owned(),
        );
    }
    // M5 (BRIEF_M5-B §1): a pinned selection without the SecMP-LINK models, or a delegated `proverif-link`, needs the
    // pinned `proverif --models link` line
    if all_lines().any(|l| {
        l.contains("--models tr")
            || l.contains("--models hx")
            || l.contains(&format!("--delegated {PROVERIF_LINK_STEP}"))
    }) && !all_lines().any(|l| l.contains("proverif --models link"))
    {
        out.push(
            "a pinned line runs `--models tr`/`--models hx` or delegates `proverif-link`, but no pinned line runs \
             `proverif --models link`"
                .to_owned(),
        );
    }
    out
}

/// F3 (R-09), M4 review C-5: the `cargo xtask` gate `run:` lines of every pinned job are exactly those pinned in
/// `expect::REQUIRED_GATE_RUNS` (an appended `|| true`, a changed step list or a missing gate is a finding).
/// `name`/`text`: the required workflow.
pub(crate) fn required_gate_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let jobs = yaml_jobs(text);
    for (job, pinned) in expect::REQUIRED_GATE_RUNS {
        let Some(j) = jobs.iter().find(|j| j.id.as_str() == *job) else {
            out.push(format!("{name}: pinned job `{job}` missing"));
            continue;
        };
        let found: Vec<&str> = j
            .steps
            .iter()
            .flat_map(|s| s.iter())
            .filter(|(k, v)| k == "run" && is_gate_run(v))
            .map(|(_, v)| v.as_str())
            .collect();
        if found.as_slice() != *pinned {
            out.push(format!(
                "{name}: pinned job `{job}` runs the gates {found:?}, pinned {pinned:?}"
            ));
        }
    }
    out
}

/// M2 review C2: the required job names exist only in `expect::REQUIRED_WORKFLOW`, all of them, and that workflow
/// has no `workflow_dispatch` trigger (a dispatch would add `skipped` check runs under the required names, and
/// GitHub counts a skipped check as passing). F19 (external review EXT-1): the job-level `if:` of each required job
/// is exactly the one pinned in `expect::REQUIRED_JOB_CONDITIONS` (or absent where that says `None`), so no later
/// condition can skip a required check on a pull request while it reports green. F3 (R-09): also no `needs:` on a
/// required job and no step-level `if:` on a gate step ([`required_job_structure_findings`]).
///
/// This is an accident guard: it catches a careless edit of the workflow, it is not a tamper-proof control (a
/// determined change of the workflow, of this check or of `expect.rs` removes it, and the check itself runs inside
/// the jobs it guards). The real control is review of `.github/workflows/**` and `xtask/src/{expect,gates,ci}.rs`
/// (M3 review F23, R-08). `files`: (repository-relative path, text).
pub(crate) fn required_job_findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    // the required checks of the ruleset are a subset of the pinned jobs
    for r in expect::REQUIRED_JOBS {
        if !expect::PINNED_JOBS.contains(r) {
            out.push(format!(
                "required check `{r}` is not in expect::PINNED_JOBS"
            ));
        }
    }
    let mut seen_required = false;
    for (name, text) in files {
        let jobs = job_names(text);
        if name == expect::REQUIRED_WORKFLOW {
            seen_required = true;
            if text
                .lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains("workflow_dispatch"))
            {
                out.push(format!(
                    "{name}: a `workflow_dispatch` trigger next to the required checks"
                ));
            }
            for pinned in expect::PINNED_JOBS {
                if !jobs.iter().any(|j| j == pinned) {
                    out.push(format!("{name}: pinned job `{pinned}` missing"));
                }
            }
            out.extend(required_job_structure_findings(name, text));
            let conditions = job_conditions(text);
            for (job, found) in &conditions {
                if !expect::PINNED_JOBS.contains(&job.as_str()) {
                    continue;
                }
                let pinned = expect::REQUIRED_JOB_CONDITIONS
                    .iter()
                    .find(|(j, _)| j == job)
                    .map(|(_, c)| *c);
                match pinned {
                    Some(pinned) if pinned == found.as_deref() => {}
                    Some(pinned) => out.push(format!(
                        "{name}: pinned job `{job}` has the condition {found:?}, pinned {pinned:?}"
                    )),
                    None => out.push(format!(
                        "{name}: pinned job `{job}` has no pinned condition in expect::REQUIRED_JOB_CONDITIONS"
                    )),
                }
            }
        } else {
            for j in jobs
                .iter()
                .filter(|j| expect::PINNED_JOBS.contains(&j.as_str()))
            {
                out.push(format!(
                    "{name}: job `{j}` uses a pinned job name outside {}",
                    expect::REQUIRED_WORKFLOW
                ));
            }
        }
    }
    if !seen_required {
        out.push(format!("{} missing", expect::REQUIRED_WORKFLOW));
    }
    out
}

/// `s` with every `\r\n` as `\n`: a Windows checkout may convert the workflows, the readers below are line-anchored
/// (M4 review R-100).
fn lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn workflows(root: &Path) -> Result<String> {
    let dir = root.join(".github").join("workflows");
    let files = walk_files(&dir, &|p: &Path| {
        p.extension().is_some_and(|e| e == "yml" || e == "yaml")
    })?;
    let mut findings = Vec::new();
    let mut texts = Vec::new();
    for f in &files {
        let text = lf(&std::fs::read_to_string(f)?);
        findings.extend(workflow_findings(&rel(root, f), &text));
        findings.extend(workflow_token_findings(&rel(root, f), &text));
        texts.push((rel(root, f), text));
    }
    findings.extend(required_job_findings(&texts));
    findings.extend(delegation_findings(
        expect::REQUIRED_GATE_RUNS,
        expect::DELEGATED_TO,
    ));
    if let Some((_, text)) = texts.iter().find(|(n, _)| n == expect::REQUIRED_WORKFLOW) {
        findings.extend(required_gate_findings(expect::REQUIRED_WORKFLOW, text));
    }
    for f in &findings {
        say(&format!("  FINDING {f}"));
    }
    if !findings.is_empty() {
        bail!("{} CI-hygiene finding(s)", findings.len());
    }
    Ok(format!(
        "workflows: {} files, triggers/SHA pins/flow style/continue-on-error/permissions ok; pinned jobs ({}) only in ci.yml, no dispatch there, job conditions, needs, defaults/shell and gate run lines as pinned, delegations mapped (accident guard, not tamper-proof)",
        files.len(),
        expect::PINNED_JOBS.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_comparison() -> Result<()> {
        let found: BTreeSet<String> = ["a".to_owned()].into_iter().collect();
        same_set("x", &found, &["a"])?;
        assert!(same_set("x", &found, &[]).is_err(), "extra input must fail");
        assert!(
            same_set("x", &BTreeSet::new(), &["a"]).is_err(),
            "missing input must fail"
        );
        Ok(())
    }

    /// M0 review F1: fixture workflows — every hygiene rule violated once, and a clean one.
    #[test]
    fn workflow_fixture_files() {
        let bad = workflow_findings(
            "bad.yml",
            include_str!("../fixtures/policy/workflow-bad.yml"),
        );
        for expected in [
            "forbidden trigger `pull_request_target`",
            "forbidden trigger `workflow_run`",
            "continue-on-error in job Some(\"build\")",
            "action not pinned by commit SHA: actions/checkout@v4",
            "action not pinned by commit SHA: actions/cache@0123456789abcdef",
            "plain-scalar `run:`",
        ] {
            assert!(
                bad.iter().any(|f| f.contains(expected)),
                "{expected}: {bad:?}"
            );
        }
        assert_eq!(bad.len(), 6, "{bad:?}");
        let good = workflow_findings(
            "good.yml",
            include_str!("../fixtures/policy/workflow-good.yml"),
        );
        assert!(good.is_empty(), "{good:?}");
    }

    #[test]
    fn mutation_survivors_must_be_documented() {
        let accepted =
            "| `crates/a/src/x.rs:59`: `replace <impl Drop for S>::drop with ()` | reason |\n";
        let listing = "crates/a/src/x.rs:59:9: replace <impl Drop for S>::drop with ()\n\
                       crates/a/src/x.rs:12:5: replace f -> bool with true\n\n";
        let u = undocumented_survivors(listing, accepted);
        assert_eq!(
            u,
            vec!["crates/a/src/x.rs:12:5: replace f -> bool with true".to_owned()]
        );
        // the file matters (the line: `accepted_mutant_requires_matching_line`)
        assert_eq!(
            undocumented_survivors(
                "crates/b/src/x.rs:59:9: replace <impl Drop for S>::drop with ()",
                accepted
            )
            .len(),
            1
        );
        assert_eq!(undocumented_survivors("garbage", accepted).len(), 1);
        assert!(undocumented_survivors("", accepted).is_empty());
    }

    /// Rows of an accepted-survivors file: one keyed on `path:line`, two on `path:line:col` sharing a line.
    const ACCEPTED_ROWS: &str = "\
        | `crates/a/src/x.rs:59`: `replace <impl Drop for S>::drop with ()` | reason | control | M1 |\n\
        | `crates/a/src/y.rs:163:32`: `replace | with ^ in enc` | reason | control | M4 |\n\
        | `crates/a/src/y.rs:163:44`: `replace | with ^ in enc` | reason | control | M4 |\n";

    /// M5 review R-114 (C-7): a survivor is accepted only at the line its row names — the same description on another
    /// line (also one whose number has the row's as prefix or suffix), at another column of a `path:line:col` row, or
    /// without a parseable place is undocumented; so are a survivor of the committed `docs/mutants-accepted.md` moved by
    /// one line and the two relay shim survivors whose rows C-7 removed.
    #[test]
    fn accepted_mutant_requires_matching_line() -> Result<()> {
        for survivor in [
            "crates/a/src/x.rs:60:9: replace <impl Drop for S>::drop with ()",
            "crates/a/src/x.rs:5:9: replace <impl Drop for S>::drop with ()",
            "crates/a/src/x.rs:159:9: replace <impl Drop for S>::drop with ()",
            "crates/a/src/x.rs:590:9: replace <impl Drop for S>::drop with ()",
            "crates/a/src/y.rs:163:33: replace | with ^ in enc",
            "crates/a/src/y.rs:164:32: replace | with ^ in enc",
            "crates/a/src/x.rs:59: replace <impl Drop for S>::drop with ()",
            "crates/a/src/x.rs::9: replace <impl Drop for S>::drop with ()",
        ] {
            assert_eq!(
                undocumented_survivors(survivor, ACCEPTED_ROWS),
                vec![survivor.to_owned()],
                "{survivor}"
            );
        }
        let committed = accepted_survivors()?;
        for survivor in [
            "crates/secmp-crypto/src/secret.rs:60:9: replace <impl Drop for SecretBytes<N>>::drop with ()",
            "crates/secmp-proto/src/inv.rs:164:32: replace | with ^ in base64url_encode",
            "crates/secmp-proto/src/inv.rs:163:36: replace | with ^ in base64url_encode",
            "crates/secmp-proto/src/inv.rs:203:34: replace | with ^ in base64url_decode",
            "crates/secmp-relay/src/server.rs:81:9: replace <impl Stream for TcpStream>::set_poll -> io::Result<()> \
             with Ok(())",
            "crates/secmp-relay/src/server.rs:86:9: replace <impl Stream for TcpStream>::close with ()",
        ] {
            assert_eq!(
                undocumented_survivors(survivor, &committed),
                vec![survivor.to_owned()],
                "{survivor}"
            );
        }
        Ok(())
    }

    /// M5 review R-114 (C-7): a survivor whose place (`path:line`, or `path:line:col`) and description one row names
    /// is accepted; the same place with another description is not. The survivors of CI run 37882708499 (pin 3b29ca8,
    /// `missed.txt` of its eight shards, `docs/reviews/M05-evidence/review-binding.txt`) against the committed
    /// `docs/mutants-accepted.md`: the four accepted rows document four of them, the two relay shim survivors are
    /// undocumented (their rows removed; the loopback test kills them).
    #[test]
    fn accepted_mutant_matches_line_and_description() -> Result<()> {
        for survivor in [
            "crates/a/src/x.rs:59:9: replace <impl Drop for S>::drop with ()",
            "crates/a/src/x.rs:59:1: replace <impl Drop for S>::drop with ()",
            "crates/a/src/y.rs:163:32: replace | with ^ in enc",
            "crates/a/src/y.rs:163:44: replace | with ^ in enc",
        ] {
            assert!(
                undocumented_survivors(survivor, ACCEPTED_ROWS).is_empty(),
                "{survivor}"
            );
        }
        for survivor in [
            "crates/a/src/x.rs:59:9: replace <impl Drop for T>::drop with ()",
            "crates/a/src/x.rs:59:9: replace f -> bool with true",
            "crates/a/src/y.rs:163:32: replace | with & in enc",
            "crates/a/src/y.rs:163:44: replace | with ^ in dec",
        ] {
            assert_eq!(
                undocumented_survivors(survivor, ACCEPTED_ROWS),
                vec![survivor.to_owned()],
                "{survivor}"
            );
        }
        let ci_37882708499 = "\
            crates/secmp-proto/src/inv.rs:163:32: replace | with ^ in base64url_encode\n\
            crates/secmp-crypto/src/secret.rs:59:9: replace <impl Drop for SecretBytes<N>>::drop with ()\n\
            crates/secmp-proto/src/inv.rs:202:34: replace | with ^ in base64url_decode\n\
            crates/secmp-relay/src/server.rs:81:9: replace <impl Stream for TcpStream>::set_poll -> io::Result<()> \
            with Ok(())\n\
            crates/secmp-relay/src/server.rs:86:9: replace <impl Stream for TcpStream>::close with ()\n\
            crates/secmp-proto/src/inv.rs:163:44: replace | with ^ in base64url_encode\n";
        assert_eq!(
            undocumented_survivors(ci_37882708499, &accepted_survivors()?),
            vec![
                "crates/secmp-relay/src/server.rs:81:9: replace <impl Stream for TcpStream>::set_poll -> \
                 io::Result<()> with Ok(())"
                    .to_owned(),
                "crates/secmp-relay/src/server.rs:86:9: replace <impl Stream for TcpStream>::close with ()"
                    .to_owned(),
            ]
        );
        Ok(())
    }

    #[test]
    fn proverif_verdicts() {
        let out = "Verification summary:\nRESULT not attacker(s[]) is true.\nRESULT not attacker(p[]) is false.\nRESULT event(x) ==> event(y) cannot be proved.\n";
        assert_eq!(proverif_results(out), vec![Some(true), Some(false), None]);
        let lines = proverif_result_lines(&format!(
            "{out}RESULT (but event(x) ==> event(y) is true.)\nRESULT (even event(x) ==> event(y) is false.)\n  \
             RESULT not attacker(q[]) is maybe.\n"
        ));
        let got: Vec<(&str, PvVerdict)> = lines
            .iter()
            .map(|l| (l.query.as_str(), l.verdict))
            .collect();
        assert_eq!(
            got,
            vec![
                ("not attacker(s[])", PvVerdict::True),
                ("not attacker(p[])", PvVerdict::False),
                ("event(x) ==> event(y)", PvVerdict::CannotBeProved),
                ("not attacker(q[]) is maybe.", PvVerdict::Unreadable),
            ]
        );
    }

    /// The ending ProVerif prints for an expected verdict (an informative line: "cannot be proved.").
    fn ending(p: expect::Proved) -> &'static str {
        match p {
            expect::Proved::True => "is true.",
            expect::Proved::False => "is false.",
            expect::Proved::Informative => "cannot be proved.",
        }
    }

    /// The opposite verdict of a gate line.
    fn flipped(p: expect::Proved) -> &'static str {
        match p {
            expect::Proved::True => "is false.",
            expect::Proved::False | expect::Proved::Informative => "is true.",
        }
    }

    /// A ProVerif output of an HX session file whose `RESULT` lines are `lines` (query text, ending), with the lines a
    /// run prints around them: progress, secrecy assumptions, the remark under an injective query that does not hold
    /// (not a line of its own: `RESULT (even …)` under a false one, as ProVerif 2.05 prints for H8/H9, `RESULT (but
    /// …)` otherwise), and the summary (`Query …`, not read by the gate).
    fn hx_output(lines: &[(&str, &str)]) -> String {
        let mut out = vec![
            "Process 0 (that is, the initial process):".to_owned(),
            "200 rules inserted. Base: 190 rules (10 with conclusion selected). Queue: 30 rules."
                .to_owned(),
            "ok, secrecy assumption verified: fact unreachable attacker(dhsk(hA,kIKR))".to_owned(),
        ];
        for (query, end) in lines {
            out.push(format!("-- Query {query} in process 1."));
            out.push(format!("RESULT {query} {end}"));
            if query.starts_with("inj-event") && *end == "is false." {
                out.push(
                    "RESULT (even event(RAccept(x,y)) ==> event(IStart(x,y)) is false.)".to_owned(),
                );
            } else if query.starts_with("inj-event") && *end != "is true." {
                out.push(
                    "RESULT (but event(RAccept(x,y)) ==> event(IStart(x,y)) is true.)".to_owned(),
                );
            }
        }
        out.push("--------------------------------------------------------------".to_owned());
        out.push("Verification summary:".to_owned());
        for (query, end) in lines {
            out.push(format!("Query {query} {end}"));
        }
        out.join("\n")
    }

    /// The lines of `file` as `table` expects them (query text, ending).
    fn hx_lines<'a>(table: &'a [expect::HxExpected], file: &str) -> Vec<(&'a str, &'static str)> {
        table
            .iter()
            .filter(|(f, ..)| *f == file)
            .map(|(_, _, q, p)| (*q, ending(*p)))
            .collect()
    }

    /// A synthetic HX table (independent of the measured one in `expect.rs`): two files, the first with four lines, two
    /// of them under the same ID.
    const HX_TABLE: &[expect::HxExpected] = &[
        (
            "hA",
            "H1 (i)",
            "not (event(IStart(hA,iI,b_2,sk_2)) && attacker(sk_2))",
            expect::Proved::True,
        ),
        (
            "hA",
            "H11",
            "not event(IStart(hA,iI,iR,b_3,sk_4))",
            expect::Proved::False,
        ),
        (
            "hA",
            "H11",
            "not event(BundleSigned(hA,iR,b_3))",
            expect::Proved::False,
        ),
        (
            "hA",
            "H5",
            "inj-event(RAccept(hA,iR,iI,sk)) ==> inj-event(IStart(hA,iI,iR,sk))",
            expect::Proved::True,
        ),
        (
            "hB",
            "H4",
            "not (event(IStart(hB,iI,b_2,sk_2)) && attacker(sk_2))",
            expect::Proved::False,
        ),
    ];

    /// `check(output)` is refused with a message containing each of `expected`.
    fn refused_with(got: Result<String>, expected: &[&str]) -> Result<()> {
        match got {
            Ok(s) => bail!("accepted: {s}"),
            Err(e) if expected.iter().all(|x| e.0.contains(x)) => Ok(()),
            Err(e) => bail!("refused, but not with {expected:?}: {e}"),
        }
    }

    /// M3 plan D10, M4 review C-7 (ADR-046 Amendment 1 (3)): `formal/tr.pv`'s 47 `RESULT` lines are matched by query
    /// text against `expect::PROVERIF_EXPECTED` — the output the rows describe passes with a summary per ID; a true query
    /// turning false, a false query turning true, a "cannot be proved" line, a missing and an extra line are each refused,
    /// naming the line and the ID; the informative T12 may say anything; a model without rows is refused. WEISUNG M4-5
    /// §4 (b), (e): every HX session file of `expect::PROVERIF_EXPECTED_HX` passes with the output its entries describe
    /// (the `RESULT (but …)` / `RESULT (even …)` remark is no line of its own), and a flipped or undecided verdict is
    /// refused naming the file, the ID and the query.
    #[test]
    fn proverif_verdicts_against_the_claims_table() -> Result<()> {
        let good = hx_lines(expect::PROVERIF_EXPECTED_TR, "tr");
        assert_eq!(good.len(), 47);
        let summary = proverif_check("tr", &hx_output(&good))?;
        assert!(
            summary.starts_with(
                "formal/tr.pv: 47 RESULT lines as expected — T1 true ×6, T2 true ×2, T3 true ×4"
            ) && summary.contains("T7 false ×2")
                && summary.contains("T8 true ×12, T9 true ×4, T10 false ×1, T11 true ×1")
                && summary.contains("T12 cannot be proved ×1")
                && summary.ends_with("T13 false ×7, T14 true ×1"),
            "{summary}"
        );
        let with = |at: usize, end: &'static str| {
            let mut v = good.clone();
            if let Some(l) = v.get_mut(at) {
                l.1 = end;
            }
            proverif_check("tr", &hx_output(&v))
        };
        // T1 (line 1) turns false; T7 (line 19) and T10 (line 37) turn true; T11 (line 38) and T7 (line 20) undecided
        refused_with(
            with(0, "is false."),
            &["RESULT line 1 (T1) is false, expected true (proved)"],
        )?;
        refused_with(
            with(18, "is true."),
            &["RESULT line 19 (T7) is true, expected false (ProVerif finds the trace)"],
        )?;
        refused_with(
            with(36, "is true."),
            &["RESULT line 37 (T10) is true, expected false"],
        )?;
        refused_with(
            with(37, "cannot be proved."),
            &["RESULT line 38 (T11) is cannot be proved, expected true"],
        )?;
        refused_with(
            with(19, "cannot be proved."),
            &["RESULT line 20 (T7) is cannot be proved"],
        )?;
        // a T13 session whose honest run no longer completes (line 46: the event is unreachable)
        refused_with(
            with(45, "is true."),
            &["RESULT line 46 (T13) is true, expected false"],
        )?;
        // a missing line (the last one, T14) and an extra line
        let mut v = good.clone();
        v.pop();
        refused_with(
            proverif_check("tr", &hx_output(&v)),
            &[
                "46 RESULT lines, expected 47",
                "missing RESULT line for T14",
            ],
        )?;
        let mut v = good.clone();
        v.push(("not attacker_p1(content(sX,st1,c0))", "is true."));
        refused_with(
            proverif_check("tr", &hx_output(&v)),
            &["48 RESULT lines, expected 47", "extra RESULT line 48"],
        )?;
        // the informative T12 (line 39) may say anything
        for t12 in ["is true.", "is false.", "cannot be proved."] {
            assert!(with(38, t12)?.contains("T12"));
        }
        // no RESULT line at all, and a model without an expected table
        refused_with(proverif_check("tr", ""), &["0 RESULT lines, expected 47"])?;
        assert!(proverif_check("hx", &hx_output(&good)).is_err());
        hx_verdicts_against_the_table()
    }

    /// M4 review C-7 (ADR-046 Amendment 1 (3), R-19): the `tr` gate matches by query text — the committed output of the
    /// gate run with T14 (M5 PV-02; before it the M4 run on `569c2e2`) passes; the same output with T4's query text
    /// swapped for another true query, with two same-verdict lines of different queries reordered, or with a query text
    /// changed (same verdict) is refused.
    #[test]
    fn proverif_tr_gate_matches_by_query_text() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let committed = lf(&std::fs::read_to_string(
            root.join("docs/reviews/M05-evidence/proverif-tr-t14-local.txt"),
        )?);
        let summary = proverif_check("tr", &committed)?;
        assert!(
            summary.starts_with("formal/tr.pv: 47 RESULT lines as expected"),
            "{summary}"
        );
        let t3 = "RESULT not attacker_p1(content(sFS,st1,c0)) is true.";
        let t4 = "RESULT not attacker_p1(content(sPCS,st3,c0)) is true.";
        let t5 = "RESULT not attacker_p1(content(sPCSdh,st3,c0)) is true.";
        for line in [t3, t4, t5] {
            assert_eq!(committed.matches(line).count(), 1, "{line}");
        }
        // T4's first query text replaced by T5's (another true query): T5's line is then extra, T4's missing
        let swapped = committed.replacen(t4, t5, 1);
        refused_with(
            proverif_check("tr", &swapped),
            &["missing RESULT line for T4"],
        )?;
        // the first lines of T3 and T4 (both true) exchanged
        let reordered = committed
            .replacen(t3, "@@T3@@", 1)
            .replacen(t4, t3, 1)
            .replacen("@@T3@@", t4, 1);
        refused_with(proverif_check("tr", &reordered), &["is re-ordered"])?;
        // a changed query text with the same verdict at the same position
        let changed = committed.replacen(
            t4,
            "RESULT not attacker_p1(content(sPCS,st3,c2)) is true.",
            1,
        );
        refused_with(
            proverif_check("tr", &changed),
            &["extra RESULT line", "missing RESULT line for T4"],
        )?;
        Ok(())
    }

    /// The HX half of `proverif_verdicts_against_the_claims_table`: every file of `expect::PROVERIF_EXPECTED_HX` passes
    /// with the output its entries describe, a flipped or undecided verdict is refused naming the file, the ID and the
    /// query; the summary groups the lines per ID; the `RESULT (but …)` / `RESULT (even …)` remark is no line of its own.
    fn hx_verdicts_against_the_table() -> Result<()> {
        let files = hx_table_files(expect::PROVERIF_EXPECTED_HX);
        assert_eq!(files.len(), 19, "{files:?}");
        for file in &files {
            let lines = hx_lines(expect::PROVERIF_EXPECTED_HX, file);
            let summary = proverif_check_hx(file, &hx_output(&lines))?;
            assert!(
                summary.starts_with(&format!(
                    "formal/hx/{file}.pv: {} RESULT lines as expected — ",
                    lines.len()
                )),
                "{summary}"
            );
            // each entry's verdict flipped, and undecided, is refused naming the file, the ID and the query
            for (k, (_, id, query, proved)) in expect::PROVERIF_EXPECTED_HX
                .iter()
                .filter(|(f, ..)| f == file)
                .enumerate()
            {
                for wrong in [flipped(*proved), "cannot be proved."] {
                    let mut bad = lines.clone();
                    if let Some(l) = bad.get_mut(k) {
                        l.1 = wrong;
                    }
                    refused_with(
                        proverif_check_hx(file, &hx_output(&bad)),
                        &[
                            &format!("formal/hx/{file}.pv against expect::PROVERIF_EXPECTED_HX"),
                            &format!("RESULT line {} ({id}) is ", k.saturating_add(1)),
                            &format!(", expected {}", expected_word(*proved)),
                            query,
                        ],
                    )?;
                }
            }
        }
        // the synthetic table: the summary groups consecutive lines of one ID; the remark under an injective query
        // that is not proved does not count as a line, so the refusal names the query, not an extra line
        let lines = hx_lines(HX_TABLE, "hA");
        assert_eq!(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&lines))?,
            "formal/hx/hA.pv: 4 RESULT lines as expected — H1 (i) true ×1, H11 false ×2, H5 true ×1"
        );
        let mut bad = lines.clone();
        if let Some(l) = bad.get_mut(3) {
            l.1 = "cannot be proved.";
        }
        let got = proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&bad));
        refused_with(
            got,
            &[
                "RESULT line 4 (H5) is cannot be proved, expected true (proved): inj-event(RAccept(hA",
            ],
        )?;
        let got = proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&bad));
        assert!(
            got.is_err_and(|e| !e.0.contains("extra") && !e.0.contains("RESULT lines, expected"))
        );
        // a verdict line ProVerif never prints is unreadable
        let unreadable = hx_output(&lines).replace(
            "RESULT not event(BundleSigned(hA,iR,b_3)) is false.",
            "RESULT not event(BundleSigned(hA,iR,b_3)) is perhaps.",
        );
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &unreadable),
            &[
                "extra RESULT line 3",
                "missing RESULT line for H11 (entry 3 of the file)",
            ],
        )?;
        Ok(())
    }

    /// WEISUNG M4-5 §4 (b), (e): HX `RESULT` lines are matched by query text, so two lines in another order than the
    /// table's are refused as re-ordered (not as missing or extra), whatever their verdicts.
    #[test]
    fn proverif_gate_rejects_reordered_result_lines() -> Result<()> {
        let lines = hx_lines(HX_TABLE, "hA");
        proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&lines))?;
        // the two H11 lines swapped
        let mut swapped = lines.clone();
        swapped.swap(1, 2);
        let got = proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&swapped));
        refused_with(
            got,
            &[
                "formal/hx/hA.pv against expect::PROVERIF_EXPECTED_HX",
                "RESULT line 3 (H11) is re-ordered: the table has it as entry 2 of the file",
                "not event(IStart(hA,iI,iR,b_3,sk_4))",
            ],
        )?;
        let got = proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&swapped));
        assert!(got.is_err_and(|e| !e.0.contains("missing") && !e.0.contains("extra")));
        // the first and the last line swapped: the moved lines are re-ordered, the verdicts are still checked
        let mut swapped = lines.clone();
        swapped.swap(0, 3);
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&swapped)),
            &["(H11) is re-ordered", "(H1 (i)) is re-ordered"],
        )?;
        if let Some(l) = swapped.first_mut() {
            l.1 = "is false.";
        }
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&swapped)),
            &["re-ordered", "RESULT line 1 (H5) is false, expected true"],
        )?;
        // the measured table: in every file with two lines of different text, the first two swapped
        for file in hx_table_files(expect::PROVERIF_EXPECTED_HX) {
            let mut lines = hx_lines(expect::PROVERIF_EXPECTED_HX, &file);
            if lines.len() < 2 || lines.first().map(|l| l.0) == lines.get(1).map(|l| l.0) {
                continue;
            }
            lines.swap(0, 1);
            refused_with(
                proverif_check_hx(&file, &hx_output(&lines)),
                &[
                    &format!("formal/hx/{file}.pv"),
                    "RESULT line 2",
                    "is re-ordered",
                ],
            )?;
        }
        Ok(())
    }

    /// WEISUNG M4-5 §4 (a), (b), (e): a missing HX `RESULT` line is refused naming the file, the ID and the query (and
    /// does not make the later lines "re-ordered"); so are an extra line, a duplicated line, an output without any line,
    /// a file without entries in the table, and a `formal/hx/*.pv` set that differs from the table's files.
    #[test]
    fn proverif_gate_rejects_missing_hx_line() -> Result<()> {
        let lines = hx_lines(HX_TABLE, "hA");
        // the second line missing
        let mut short = lines.clone();
        short.remove(1);
        let got = proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&short));
        refused_with(
            got,
            &[
                "formal/hx/hA.pv against expect::PROVERIF_EXPECTED_HX",
                "3 RESULT lines, expected 4",
                "missing RESULT line for H11 (entry 2 of the file): not event(IStart(hA,iI,iR,b_3,sk_4))",
            ],
        )?;
        let got = proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&short));
        assert!(got.is_err_and(|e| !e.0.contains("re-ordered") && !e.0.contains("extra")));
        // the last line missing; no line at all
        let mut short = lines.clone();
        short.pop();
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&short)),
            &["missing RESULT line for H5 (entry 4 of the file)"],
        )?;
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&[])),
            &[
                "0 RESULT lines, expected 4",
                "missing RESULT line for H1 (i)",
            ],
        )?;
        // an extra line, and a duplicated one
        let mut long = lines.clone();
        long.push(("not attacker(sk[])", "is true."));
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&long)),
            &[
                "5 RESULT lines, expected 4",
                "extra RESULT line 5 (no such query in the table), true: not attacker(sk[])",
            ],
        )?;
        let mut long = lines.clone();
        long.insert(1, ("not event(BundleSigned(hA,iR,b_3))", "is false."));
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hA", &hx_output(&long)),
            &["5 RESULT lines, expected 4", "extra RESULT line"],
        )?;
        // a file without entries (even with RESULT lines); the other file's lines are not this file's
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hC", &hx_output(&lines)),
            &["formal/hx/hC.pv: no expected entries in expect::PROVERIF_EXPECTED_HX"],
        )?;
        refused_with(
            proverif_check_hx_in(HX_TABLE, "hB", &hx_output(&lines)),
            &["missing RESULT line for H4", "extra RESULT line 1"],
        )?;
        // the measured table: every file with its last line missing
        for file in hx_table_files(expect::PROVERIF_EXPECTED_HX) {
            let mut lines = hx_lines(expect::PROVERIF_EXPECTED_HX, &file);
            lines.pop();
            refused_with(
                proverif_check_hx(&file, &hx_output(&lines)),
                &[&format!("formal/hx/{file}.pv"), "missing RESULT line for "],
            )?;
        }
        // the input set: formal/hx/*.pv equals the table's files, in both directions
        let set = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|n| (*n).to_owned()).collect()
        };
        hx_set_check(&set(&["hA", "hB"]), HX_TABLE)?;
        assert!(
            hx_set_check(&set(&["hA", "hB", "hC"]), HX_TABLE)
                .is_err_and(|e| e.0.contains("files without expected entries: [\"hC\"]"))
        );
        assert!(
            hx_set_check(&set(&["hA"]), HX_TABLE)
                .is_err_and(|e| e.0.contains("expected files that do not exist: [\"hB\"]"))
        );
        // the results table: per (file, ID), a missing line shows as such
        let mut short = lines.clone();
        short.remove(1);
        assert_eq!(
            hx_rows(HX_TABLE, "hA", Some(&hx_output(&short))),
            vec![
                (
                    "H1 (i)".to_owned(),
                    "true ×1".to_owned(),
                    "true ×1".to_owned()
                ),
                (
                    "H11".to_owned(),
                    "missing ×1, false ×1".to_owned(),
                    "false ×2".to_owned()
                ),
                ("H5".to_owned(), "true ×1".to_owned(), "true ×1".to_owned()),
            ]
        );
        assert_eq!(
            hx_rows(HX_TABLE, "hB", None),
            vec![(
                "H4".to_owned(),
                "no result ×1".to_owned(),
                "false ×1".to_owned()
            )]
        );
        Ok(())
    }

    /// WEISUNG M4-5 §4 (a), (e): a ProVerif process still running at its timeout is killed and fails the gate, naming
    /// the file and the last progress line of its log; a process that ends in time passes with its log, one that exits
    /// non-zero fails naming the file.
    #[test]
    fn proverif_gate_timeout_is_a_fail() -> Result<()> {
        use std::time::Duration;
        let progress =
            "123 rules inserted. Base: 1 rules (0 with conclusion selected). Queue: 2 rules.";
        let dir = std::env::temp_dir().join(format!(
            "secmp-xtask-proverif-timeout-{}",
            std::process::id()
        ));
        let log = dir.join("hx-hSlow.log");
        #[cfg(not(windows))]
        let (program, slow, quick, failing) = (
            "/bin/sh",
            format!("echo '{progress}'; exec sleep 30"),
            "echo 'RESULT not attacker(s[]) is true.'".to_owned(),
            "exit 3".to_owned(),
        );
        #[cfg(windows)]
        let (program, slow, quick, failing) = (
            "cmd.exe",
            format!("echo {progress}&& ping -n 30 127.0.0.1"),
            "echo RESULT not attacker(s[]) is true.".to_owned(),
            "exit 3".to_owned(),
        );
        let flag = if cfg!(windows) { "/C" } else { "-c" };
        let file = "formal/hx/hSlow.pv";
        let started = std::time::Instant::now();
        let got = run_logged(
            program,
            &[flag.to_owned(), slow],
            &log,
            Duration::from_secs(2),
            file,
        );
        let elapsed = started.elapsed();
        refused_with(
            got,
            &[
                "formal/hx/hSlow.pv: timeout, killed after 2 s",
                &format!("last progress line: `{progress}`"),
            ],
        )?;
        assert!(elapsed < Duration::from_secs(20), "not killed: {elapsed:?}");
        let out = run_logged(
            program,
            &[flag.to_owned(), quick],
            &dir.join("quick.log"),
            Duration::from_secs(60),
            file,
        )?;
        assert!(out.contains("RESULT not attacker(s[]) is true."), "{out}");
        let got = run_logged(
            program,
            &[flag.to_owned(), failing],
            &dir.join("failing.log"),
            Duration::from_secs(60),
            file,
        );
        refused_with(got, &["formal/hx/hSlow.pv: ProVerif failed"])?;
        // each run has its own log; the cleanup may fail on Windows while the orphaned `ping` still holds the first
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            last_progress_line(&format!("x\n  {progress}  \nRESULT y is true.\n")),
            Some(progress)
        );
        assert_eq!(last_progress_line("RESULT y is true."), None);
        Ok(())
    }

    /// ADR-045 Amendment 1 (M4 review C-1): a ct bench still running at the step budget is killed and fails the gate,
    /// naming the target and phase of its last progress line; the progress lines are read as the bench appends them,
    /// and a bench that ends in time returns its exit status.
    #[test]
    fn ct_gate_timeout_is_a_fail_naming_the_target() -> Result<()> {
        use std::time::Duration;
        let dir =
            std::env::temp_dir().join(format!("secmp-xtask-ct-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let progress = dir.join("ct-progress.jsonl");
        let log = dir.join("ct-bench.log");
        let line = r#"{"target":"hx_accept_reject_first_msg","phase":"first","elapsed_s":1.0,"k":1,"median_ticks":2}"#;
        #[cfg(not(windows))]
        let (program, flag, slow, quick, failing) = (
            "/bin/sh",
            "-c",
            format!("echo '{line}' >> '{}'; exec sleep 30", progress.display()),
            "echo bench output".to_owned(),
            "exit 1".to_owned(),
        );
        // the slow bench as a batch file: a `/C` command line with inner quotes is quoted once more by
        // `std::process::Command`, and cmd.exe then mis-parses it and exits at once (PR run 37127247911, R-98)
        #[cfg(windows)]
        let (program, flag, slow, quick, failing) = {
            let script = dir.join("slow.cmd");
            std::fs::write(
                &script,
                format!(
                    "@echo {line}>> \"{}\"\r\n@ping -n 30 127.0.0.1 >nul\r\n",
                    progress.display()
                ),
            )?;
            (
                "cmd.exe",
                "/C",
                script.display().to_string(),
                "echo bench output".to_owned(),
                "exit 1".to_owned(),
            )
        };
        let started = std::time::Instant::now();
        let got = run_ct_bench(
            &Cmd::new(program).args([flag, slow.as_str()]),
            &log,
            &progress,
            Duration::from_secs(2),
        );
        let elapsed = started.elapsed();
        refused_with(
            got.map(|ok| ok.to_string()),
            &[
                "ct: timeout, killed after 2 s",
                "last progress: hx_accept_reject_first_msg first",
            ],
        )?;
        assert!(elapsed < Duration::from_secs(20), "not killed: {elapsed:?}");
        assert!(run_ct_bench(
            &Cmd::new(program).args([flag, quick.as_str()]),
            &log,
            &progress,
            Duration::from_secs(60),
        )?);
        assert!(std::fs::read_to_string(&log)?.contains("bench output"));
        assert!(!run_ct_bench(
            &Cmd::new(program).args([flag, failing.as_str()]),
            &log,
            &progress,
            Duration::from_secs(60),
        )?);
        // no progress line at all is named as such
        std::fs::remove_file(&progress)?;
        let got = run_ct_bench(
            &Cmd::new(program).args([
                flag,
                if cfg!(windows) {
                    "ping -n 30 127.0.0.1"
                } else {
                    "exec sleep 30"
                },
            ]),
            &log,
            &progress,
            Duration::from_secs(1),
        );
        refused_with(
            got.map(|ok| ok.to_string()),
            &["ct: timeout, killed after 1 s; last progress: none"],
        )?;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// The ct gate runs the bench's executable, which `cargo bench --no-run --message-format=json…` names.
    #[test]
    fn ct_bench_executable_is_read_from_cargo_messages() {
        let messages = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"secmp_testkit","kind":["lib"]},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"ct","kind":["bench"]},"executable":"/t/release/deps/ct-0123"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
            "\n"
        );
        assert_eq!(
            ct_bench_executable_in(messages).as_deref(),
            Some("/t/release/deps/ct-0123")
        );
        assert_eq!(
            ct_bench_executable_in(r#"{"reason":"build-finished"}"#),
            None
        );
    }

    /// The rows of `formal/CLAIMS.md` whose first cell starts with `prefix`: (ID, the verdict of the "Expected" column;
    /// `None`: neither true nor false, e.g. H6 "not claimed").
    fn claim_rows(claims: &str, prefix: &str) -> Vec<(String, Option<expect::Proved>)> {
        claims
            .lines()
            .filter(|l| l.starts_with(prefix))
            .map(|l| {
                let cells: Vec<&str> = l.split('|').map(str::trim).collect();
                let id = cells.get(1).copied().unwrap_or_default().to_owned();
                let proved = match cells.iter().rev().find(|c| !c.is_empty()).copied() {
                    Some("true") => Some(expect::Proved::True),
                    Some(c) if c.contains("not a gate") => Some(expect::Proved::Informative),
                    Some(c) if c.starts_with("**false**") => Some(expect::Proved::False),
                    _ => None,
                };
                (id, proved)
            })
            .collect()
    }

    /// M4 review C-7 (ADR-046 Amendment 1 (2)): the expected tables against `formal/CLAIMS.md` in both directions —
    /// `tr`: the IDs in order, each once, every line with its row's verdict; HX: every entry's ID (up to its first space:
    /// "H1 (i)" is row H1) is a row of §HX with the entry's verdict, every §HX row expected true or false has at least
    /// one entry, H11 has exactly four entries per base file (a file without `-auth`) and one per auth file (erratum
    /// 5). Returns the findings.
    fn claims_table_findings(
        claims: &str,
        tr: &[expect::HxExpected],
        hx: &[expect::HxExpected],
    ) -> Vec<String> {
        let mut out = Vec::new();
        let t_rows = claim_rows(claims, "| T");
        let mut ids: Vec<&str> = Vec::new();
        for (_, id, _, proved) in tr {
            if ids.last() != Some(id) {
                ids.push(id);
            }
            match t_rows.iter().find(|(r, _)| r == id) {
                Some((_, Some(p))) if p == proved => {}
                other => out.push(format!("tr {id}: CLAIMS {other:?}, the table {proved:?}")),
            }
        }
        let t_ids: Vec<&str> = t_rows.iter().map(|(id, _)| id.as_str()).collect();
        if ids != t_ids {
            out.push(format!(
                "tr: the table's IDs {ids:?} are not CLAIMS §TR's {t_ids:?}"
            ));
        }
        let h_rows = claim_rows(claims, "| H");
        for (file, id, query, proved) in hx {
            let row = id.split(' ').next().unwrap_or_default();
            match h_rows.iter().find(|(r, _)| r == row).map(|(_, p)| *p) {
                Some(Some(p)) if p == *proved => {}
                claimed => out.push(format!(
                    "{file} {id}: CLAIMS row {row} expects {claimed:?}, the table {proved:?}: {query}"
                )),
            }
        }
        for (row, proved) in &h_rows {
            if proved.is_some()
                && !hx
                    .iter()
                    .any(|(_, id, ..)| id.split(' ').next() == Some(row.as_str()))
            {
                out.push(format!(
                    "CLAIMS row {row} has no entry in expect::PROVERIF_EXPECTED_HX"
                ));
            }
        }
        for file in hx_table_files(hx) {
            let n = hx
                .iter()
                .filter(|(f, id, ..)| *f == file && *id == "H11")
                .count();
            let (want, what) = if file.ends_with("-auth") {
                (1, "one per auth file")
            } else {
                (4, "four per base file")
            };
            if n != want {
                out.push(format!("{file}: {n} H11 entries, CLAIMS H11 has {what}"));
            }
        }
        out
    }

    /// TEST-SPEC-M5 PV-02 (R-41, M3 F6; CLAIMS §TR T14): the `tr` gate expects exactly one T14 line — injective
    /// agreement of `Accepted` with `Sent` in the session of the F5 branch, proved true — and CLAIMS row T14 states
    /// that query with Expected true; the model file carries the second receive attempt (`Again`) and the query.
    #[test]
    fn proverif_tr_t14_second_receive() -> Result<()> {
        let t14: Vec<&expect::HxExpected> = expect::PROVERIF_EXPECTED_TR
            .iter()
            .filter(|(_, id, ..)| *id == "T14")
            .collect();
        assert_eq!(t14.len(), 1, "{t14:?}");
        let Some(&&(file, _, query, proved)) = t14.first() else {
            return Err(Error("no T14 row".into()));
        };
        assert_eq!((file, proved), ("tr", expect::Proved::True));
        assert!(
            query.starts_with("inj-event(Accepted(") && query.contains("==> inj-event(Sent("),
            "{query}"
        );
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let claims = lf(&std::fs::read_to_string(root.join("formal/CLAIMS.md"))?);
        let row = claims
            .lines()
            .find(|l| l.starts_with("| T14 |"))
            .unwrap_or_default();
        assert!(
            row.contains("inj-event(Accepted(kid, n, m)) ==> inj-event(Sent(kid, n, m))")
                && row.trim_end().ends_with("| true |"),
            "{row}"
        );
        let model = std::fs::read_to_string(root.join("formal/tr.pv"))?;
        assert!(
            model.contains("inj-event(Accepted("),
            "the T14 query is in tr.pv"
        );
        assert!(
            model.contains("Again"),
            "the second receive attempt is modelled"
        );
        Ok(())
    }

    /// `expect::PROVERIF_EXPECTED` covers exactly `expect::PROVERIF_MODELS`, the files of `expect::PROVERIF_EXPECTED_HX`
    /// are exactly `formal/hx/*.pv`, and both tables follow `formal/CLAIMS.md` in both directions
    /// ([`claims_table_findings`]).
    #[test]
    fn proverif_table_follows_the_claims() -> Result<()> {
        let tables: BTreeSet<String> = expect::PROVERIF_EXPECTED
            .iter()
            .map(|(m, _)| (*m).to_owned())
            .collect();
        same_set("PROVERIF_EXPECTED", &tables, expect::PROVERIF_MODELS)?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let claims = lf(&std::fs::read_to_string(root.join("formal/CLAIMS.md"))?);
        assert_eq!(claim_rows(&claims, "| T").len(), 14);
        hx_set_check(
            &dir_stems(&root.join(expect::PROVERIF_HX_DIR), "pv")?,
            expect::PROVERIF_EXPECTED_HX,
        )?;
        assert!(claim_rows(&claims, "| H").len() >= 20);
        assert_eq!(
            claims_table_findings(
                &claims,
                expect::PROVERIF_EXPECTED_TR,
                expect::PROVERIF_EXPECTED_HX
            ),
            Vec::<String>::new()
        );
        // M5: the files of `expect::PROVERIF_EXPECTED_LINK` are exactly `formal/link/*.pv` (its CLAIMS check is X-04,
        // `proverif_link_table_covers_every_claims_row`)
        session_set_check(
            SessionFamily::Link,
            &dir_stems(&root.join(expect::PROVERIF_LINK_DIR), "pv")?,
            expect::PROVERIF_EXPECTED_LINK,
        )?;
        for (_, _, query, _) in expect::PROVERIF_EXPECTED_TR
            .iter()
            .chain(expect::PROVERIF_EXPECTED_HX)
            .chain(expect::PROVERIF_EXPECTED_LINK)
        {
            assert!(!query.is_empty() && !query.contains('\n'), "{query}");
        }
        Ok(())
    }

    /// M4 review C-7 (ADR-046 Amendment 1 (2), R-18): the HX table covers every CLAIMS §HX row expected true or false —
    /// the H10 entry deleted, or the H10 row deleted, fails naming H10; H11 has four entries per base file.
    #[test]
    fn proverif_table_covers_every_claims_row() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let claims = lf(&std::fs::read_to_string(root.join("formal/CLAIMS.md"))?);
        let tr = expect::PROVERIF_EXPECTED_TR;
        let hx = expect::PROVERIF_EXPECTED_HX;
        assert_eq!(claims_table_findings(&claims, tr, hx), Vec::<String>::new());
        let without_h10: Vec<expect::HxExpected> = hx
            .iter()
            .copied()
            .filter(|(_, id, ..)| *id != "H10")
            .collect();
        let found = claims_table_findings(&claims, tr, &without_h10);
        assert_eq!(
            found,
            vec!["CLAIMS row H10 has no entry in expect::PROVERIF_EXPECTED_HX".to_owned()]
        );
        let no_h10_row = claims
            .lines()
            .filter(|l| !l.starts_with("| H10 "))
            .collect::<Vec<_>>()
            .join("\n");
        let found = claims_table_findings(&no_h10_row, tr, hx);
        assert!(
            !found.is_empty() && found.iter().all(|f| f.contains("H10")),
            "{found:?}"
        );
        // H11: four per base file
        let mut seen = false;
        let three_h11: Vec<expect::HxExpected> = hx
            .iter()
            .copied()
            .filter(|(f, id, ..)| {
                let drop = !seen && *f == "hClean" && *id == "H11";
                seen |= drop;
                !drop
            })
            .collect();
        assert_eq!(
            claims_table_findings(&claims, tr, &three_h11),
            vec!["hClean: 3 H11 entries, CLAIMS H11 has four per base file".to_owned()]
        );
        // ... and one per auth file (erratum 5): 92 entries in all
        for file in hx_table_files(hx) {
            let want = if file.ends_with("-auth") { 1 } else { 4 };
            assert_eq!(
                hx.iter()
                    .filter(|(f, id, ..)| *f == file && *id == "H11")
                    .count(),
                want,
                "{file}"
            );
        }
        assert_eq!(hx.len(), 92);
        let no_auth_h11: Vec<expect::HxExpected> = hx
            .iter()
            .copied()
            .filter(|(f, id, ..)| !(*f == "hKEM-auth" && *id == "H11"))
            .collect();
        assert_eq!(
            claims_table_findings(&claims, tr, &no_auth_h11),
            vec!["hKEM-auth: 0 H11 entries, CLAIMS H11 has one per auth file".to_owned()]
        );
        // a §TR row without its lines, and a verdict that differs from CLAIMS
        let no_t12: Vec<expect::HxExpected> = tr
            .iter()
            .copied()
            .filter(|(_, id, ..)| *id != "T12")
            .collect();
        assert!(!claims_table_findings(&claims, &no_t12, hx).is_empty());
        Ok(())
    }

    /// M4 review C-7 (ADR-046 Amendment 1 (1), R-18): the model files are exactly the files of
    /// `expect::PROVERIF_MODEL_SHA256` with their pinned SHA-256; a changed byte in any of them, a missing one and an
    /// unpinned extra model file are findings naming the file.
    #[test]
    fn proverif_model_hashes_are_pinned() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let pins = expect::PROVERIF_MODEL_SHA256;
        // tr.pv, hx.pvl and 19 hx/*.pv; M5: link.pvl and the nine link/*.pv
        assert_eq!(pins.len(), 31);
        assert_eq!(
            proverif_model_hash_findings(&root, pins),
            Vec::<String>::new()
        );
        // a copy of the models, then one changed byte per file
        let dir =
            std::env::temp_dir().join(format!("secmp-xtask-model-hashes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(expect::PROVERIF_HX_DIR))?;
        std::fs::create_dir_all(dir.join(expect::PROVERIF_LINK_DIR))?;
        for (file, _) in pins {
            std::fs::copy(root.join(file), dir.join(file))?;
        }
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            Vec::<String>::new()
        );
        for (file, _) in pins {
            let original = std::fs::read(dir.join(file))?;
            let mut changed = original.clone();
            if let Some(b) = changed.iter_mut().rev().find(|b| b.is_ascii_alphabetic()) {
                *b ^= 0x20;
            }
            std::fs::write(dir.join(file), &changed)?;
            let found = proverif_model_hash_findings(&dir, pins);
            assert!(
                found.len() == 1
                    && found
                        .iter()
                        .all(|f| f.starts_with(&format!("{file}: sha256 "))),
                "{file}: {found:?}"
            );
            std::fs::write(dir.join(file), &original)?;
        }
        // CRLF line ends (a Windows checkout) hash like the committed text; the variant is built from the LF form, so
        // a checkout that already has CRLF does not get `\r\r\n` (R-102), and converting the CRLF file once more
        // through the same path (what a Windows host does) stays clean
        let to_crlf = |s: &str| s.replace("\r\n", "\n").replace('\n', "\r\n");
        let crlf = to_crlf(&std::fs::read_to_string(dir.join("formal/tr.pv"))?);
        assert!(crlf.contains("\r\n") && !crlf.contains("\r\r"));
        std::fs::write(dir.join("formal/tr.pv"), &crlf)?;
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            Vec::<String>::new()
        );
        let again = to_crlf(&std::fs::read_to_string(dir.join("formal/tr.pv"))?);
        assert_eq!(again, crlf);
        std::fs::write(dir.join("formal/tr.pv"), again)?;
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            Vec::<String>::new()
        );
        std::fs::write(
            dir.join(expect::PROVERIF_HX_DIR).join("hNew.pv"),
            "process 0\n",
        )?;
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            vec!["formal/hx/hNew.pv: a model file without a pinned sha256".to_owned()]
        );
        std::fs::remove_file(dir.join("formal/hx.pvl"))?;
        assert!(
            proverif_model_hash_findings(&dir, pins).contains(&"formal/hx.pvl: missing".to_owned())
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// The rows of CLAIMS §LINK (the `| L…` lines of the section `## LINK`): (ID, the verdict of the "Expected" column,
    /// the "M" column without emphasis). `None`: neither true nor false (L9 "by construction").
    fn link_claim_rows(claims: &str) -> Vec<(String, Option<expect::Proved>, String)> {
        let section = claims.split("\n## LINK").nth(1).unwrap_or_default();
        let section = section.split("\n## ").next().unwrap_or_default();
        section
            .lines()
            .filter(|l| l.starts_with("| L"))
            .map(|l| {
                // | ID | Property | Query (sketch) | Assumptions | Expected | M |
                let cells: Vec<&str> = l.split('|').map(str::trim).collect();
                let cell = |i: usize| cells.get(i).copied().unwrap_or_default();
                let expected = cell(5);
                let proved = if expected == "true" || expected.starts_with("true ") {
                    Some(expect::Proved::True)
                } else if expected.starts_with("**false**") {
                    Some(expect::Proved::False)
                } else {
                    None
                };
                (
                    cell(1).to_owned(),
                    proved,
                    cell(6).trim_matches('*').to_owned(),
                )
            })
            .collect()
    }

    /// The CLAIMS §LINK gate rule: the IDs that "must be proved true", those that "must be false", and the session
    /// files it names (`lClean`, …).
    fn link_gate_rule(claims: &str) -> (Vec<String>, Vec<String>, BTreeSet<String>) {
        let flat = claims.replace('\n', " ");
        let rule = flat.split("Gate rule (M5):").nth(1).unwrap_or_default();
        let rule = rule.split("A model change").next().unwrap_or_default();
        let (proved, rest) = rule.split_once("must be proved true").unwrap_or_default();
        let refuted = rest.split_once("must be false").map_or("", |(f, _)| f);
        let words = |s: &str| -> Vec<String> {
            s.split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let ids = |s: &str| -> Vec<String> {
            words(s)
                .into_iter()
                .filter(|w| {
                    w.starts_with('L')
                        && w.get(1..2)
                            .is_some_and(|c| c.chars().all(|d| d.is_ascii_digit()))
                })
                .collect()
        };
        let sessions = words(rule)
            .into_iter()
            .filter(|w| {
                w.starts_with('l')
                    && w.get(1..2)
                        .is_some_and(|c| c.chars().all(|d| d.is_ascii_uppercase()))
            })
            .collect();
        (ids(proved), ids(refuted), sessions)
    }

    /// X-04 (TEST-SPEC-M5 (i), the C-7 pattern of [`claims_table_findings`]): `expect::PROVERIF_EXPECTED_LINK` against
    /// CLAIMS §LINK in both directions — every entry's ID is an ID of the gate rule with the rule's verdict, and its row
    /// (the ID's own row, or for L3a/L3b the row L3 that names them as its claim lines) is an M5 row expecting that
    /// verdict; every ID of the gate rule and every M5 row expected true or false has at least one entry; an M11 row
    /// (L10–L12) or L9 (structural) has none; the table's files are exactly the sessions the gate rule names, and each
    /// has three L8 lines (every file is a base file: `CStart`, the honest pair, `RExec`). Returns the findings.
    fn link_claims_findings(claims: &str, link: &[expect::HxExpected]) -> Vec<String> {
        use expect::Proved;
        let mut out = Vec::new();
        let rows = link_claim_rows(claims);
        let (true_ids, false_ids, sessions) = link_gate_rule(claims);
        let rule = |id: &str| -> Option<Proved> {
            if true_ids.iter().any(|t| t == id) {
                Some(Proved::True)
            } else if false_ids.iter().any(|f| f == id) {
                Some(Proved::False)
            } else {
                None
            }
        };
        let row_of = |id: &str| {
            rows.iter().find(|(r, ..)| r == id).or_else(|| {
                let base = id.trim_end_matches(|c: char| c.is_ascii_lowercase());
                rows.iter().find(|(r, ..)| r == base)
            })
        };
        for (file, id, query, proved) in link {
            if rule(id) != Some(*proved) {
                out.push(format!(
                    "{file} {id}: the CLAIMS §LINK gate rule expects {:?}, the table {proved:?}: {query}",
                    rule(id)
                ));
            }
            match row_of(id) {
                Some((_, Some(p), m)) if p == proved && m == "M5" => {}
                other => out.push(format!(
                    "{file} {id}: CLAIMS §LINK row {other:?}, the table {proved:?}: {query}"
                )),
            }
        }
        for id in true_ids.iter().chain(&false_ids) {
            if !link.iter().any(|(_, i, ..)| i == id) {
                out.push(format!(
                    "the CLAIMS §LINK gate rule names {id}, which has no entry in expect::PROVERIF_EXPECTED_LINK"
                ));
            }
        }
        for (row, proved, m) in &rows {
            if m == "M5"
                && proved.is_some()
                && !link
                    .iter()
                    .any(|(_, i, ..)| row_of(i).is_some_and(|(r, ..)| r == row))
            {
                out.push(format!(
                    "CLAIMS row {row} has no entry in expect::PROVERIF_EXPECTED_LINK"
                ));
            }
        }
        let files = hx_table_files(link);
        if files != sessions {
            out.push(format!(
                "the table's files {files:?} are not the sessions of the CLAIMS §LINK gate rule {sessions:?}"
            ));
        }
        for file in &files {
            let n = link
                .iter()
                .filter(|(f, id, ..)| f == file && *id == "L8")
                .count();
            if n != 3 {
                out.push(format!(
                    "{file}: {n} L8 entries, CLAIMS L8 has three per base file"
                ));
            }
        }
        out
    }

    /// X-04 `proverif_link_table_covers_every_claims_row` [O-16] (TEST-SPEC-M5 (i)): CLAIMS §LINK rows ⇔
    /// `expect::PROVERIF_EXPECTED_LINK` rows, both directions (C-7 pattern) — the real table gives no finding; the L6
    /// entry deleted, the L6 row deleted, the L3a entries deleted (L3a is a claim line of row L3, named by the gate
    /// rule), an L8 line dropped in one file, a flipped verdict, an entry for an M11 row (L10) or for L9 and a file the
    /// gate rule does not name are each a finding naming what is wrong.
    #[test]
    fn proverif_link_table_covers_every_claims_row() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let claims = lf(&std::fs::read_to_string(root.join("formal/CLAIMS.md"))?);
        let link = expect::PROVERIF_EXPECTED_LINK;
        // the CLAIMS text as read: 19 rows L1…L12 (incl. L1a–L1c, L3c, L5a, L5b, L6a), M11 for L10–L12, L9 structural;
        // the gate rule's 11 true and 6 false IDs and its nine sessions
        let rows = link_claim_rows(&claims);
        assert_eq!(rows.len(), 19, "{rows:?}");
        let m11: Vec<&str> = rows
            .iter()
            .filter(|(_, _, m)| m == "M11")
            .map(|(id, ..)| id.as_str())
            .collect();
        assert_eq!(m11, ["L10", "L11", "L12"]);
        assert!(
            rows.iter()
                .any(|(id, p, m)| id == "L9" && p.is_none() && m == "M5")
        );
        let (t, f, sessions) = link_gate_rule(&claims);
        assert_eq!(
            t,
            [
                "L1", "L1a", "L1b", "L3", "L3a", "L3b", "L4", "L5", "L5a", "L6", "L7"
            ]
        );
        assert_eq!(f, ["L1c", "L2", "L3c", "L5b", "L6a", "L8"]);
        let want: BTreeSet<String> = [
            "lClean", "lDH", "lKEM", "lBoth", "lSig", "lFS", "lFSDH", "lFSEph", "lQKey",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(sessions, want);
        // both directions on the real table
        assert_eq!(link_claims_findings(&claims, link), Vec::<String>::new());
        link_claims_mutations_are_findings(&claims, link);
        Ok(())
    }

    /// The mutations of X-04: each edit of the table or of CLAIMS is a finding naming what is wrong.
    fn link_claims_mutations_are_findings(claims: &str, link: &[expect::HxExpected]) {
        let claims = claims.to_owned();
        let without = |id: &str| -> Vec<expect::HxExpected> {
            link.iter().copied().filter(|(_, i, ..)| *i != id).collect()
        };
        let found = link_claims_findings(&claims, &without("L6"));
        assert_eq!(
            found,
            vec![
                "the CLAIMS §LINK gate rule names L6, which has no entry in expect::PROVERIF_EXPECTED_LINK"
                    .to_owned(),
                "CLAIMS row L6 has no entry in expect::PROVERIF_EXPECTED_LINK".to_owned(),
            ]
        );
        let found = link_claims_findings(&claims, &without("L3a"));
        assert_eq!(
            found,
            vec![
                "the CLAIMS §LINK gate rule names L3a, which has no entry in expect::PROVERIF_EXPECTED_LINK"
                    .to_owned()
            ]
        );
        // the row deleted: every L6 entry is a finding, nothing else
        let no_l6_row = claims
            .lines()
            .filter(|l| !l.starts_with("| L6 "))
            .collect::<Vec<_>>()
            .join("\n");
        let found = link_claims_findings(&no_l6_row, link);
        assert!(
            found.len() == 1
                && found
                    .iter()
                    .all(|f| f.starts_with("lClean L6: CLAIMS §LINK row None, the table True")),
            "{found:?}"
        );
        // one L8 line dropped in lClean
        let mut seen = false;
        let two_l8: Vec<expect::HxExpected> = link
            .iter()
            .copied()
            .filter(|(f, id, ..)| {
                let drop = !seen && *f == "lClean" && *id == "L8";
                seen |= drop;
                !drop
            })
            .collect();
        assert_eq!(
            link_claims_findings(&claims, &two_l8),
            vec!["lClean: 2 L8 entries, CLAIMS L8 has three per base file".to_owned()]
        );
        // a flipped verdict, an M11 entry, an L9 entry, a file the gate rule does not name
        let flipped: Vec<expect::HxExpected> = link
            .iter()
            .copied()
            .map(|(f, id, q, p)| {
                if id == "L1" {
                    (f, id, q, expect::Proved::False)
                } else {
                    (f, id, q, p)
                }
            })
            .collect();
        let found = link_claims_findings(&claims, &flipped);
        assert!(
            found.len() == 2 && found.iter().all(|f| f.starts_with("lClean L1:")),
            "{found:?}"
        );
        for extra in [
            ("lClean", "L10", "x", expect::Proved::True),
            ("lClean", "L9", "x", expect::Proved::True),
        ] {
            let mut more = link.to_vec();
            more.push(extra);
            let found = link_claims_findings(&claims, &more);
            assert!(
                found.len() == 2
                    && found
                        .iter()
                        .all(|f| f.starts_with(&format!("lClean {}:", extra.1))),
                "{found:?}"
            );
        }
        let mut more = link.to_vec();
        more.push(("lNew", "L1", "x", expect::Proved::True));
        assert!(
            link_claims_findings(&claims, &more)
                .iter()
                .any(|f| f.contains("are not the sessions of the CLAIMS §LINK gate rule"))
        );
    }

    /// X-05 `proverif_link_model_hashes_are_pinned` [O-16] (TEST-SPEC-M5 (i), ADR-046 Amendment 1 (1)):
    /// `expect::PROVERIF_MODEL_SHA256` pins exactly `formal/link.pvl` and every `formal/link/*.pv` (the files of
    /// `expect::PROVERIF_EXPECTED_LINK`) with the committed text's SHA-256; in a copy of the models, a changed byte in
    /// any link file, an unpinned `formal/link/*.pv` and a missing `formal/link.pvl` are each a finding naming the file;
    /// the ADR-045 summary lists every link file.
    #[test]
    fn proverif_link_model_hashes_are_pinned() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let pins = expect::PROVERIF_MODEL_SHA256;
        let is_link = |f: &str| f == expect::PROVERIF_LINK_LIB || f.starts_with("formal/link/");
        let pinned: BTreeSet<String> = pins
            .iter()
            .map(|(f, _)| (*f).to_owned())
            .filter(|f| is_link(f))
            .collect();
        let stems = dir_stems(&root.join(expect::PROVERIF_LINK_DIR), "pv")?;
        assert_eq!(stems, hx_table_files(expect::PROVERIF_EXPECTED_LINK));
        assert_eq!(stems.len(), 9);
        let mut on_disk: BTreeSet<String> = stems
            .iter()
            .map(|s| format!("{}/{s}.pv", expect::PROVERIF_LINK_DIR))
            .collect();
        on_disk.insert(expect::PROVERIF_LINK_LIB.to_owned());
        assert_eq!(pinned, on_disk);
        assert_eq!(
            proverif_model_hash_findings(&root, pins),
            Vec::<String>::new()
        );
        let listed: BTreeSet<String> = crate::summary::proverif_model_files(&root)
            .into_iter()
            .filter(|f| is_link(f))
            .collect();
        assert_eq!(listed, on_disk);
        // a copy of every pinned model, then one changed byte per link file
        let dir =
            std::env::temp_dir().join(format!("secmp-xtask-link-hashes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(expect::PROVERIF_HX_DIR))?;
        std::fs::create_dir_all(dir.join(expect::PROVERIF_LINK_DIR))?;
        for (file, _) in pins {
            std::fs::copy(root.join(file), dir.join(file))?;
        }
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            Vec::<String>::new()
        );
        for file in &on_disk {
            let original = std::fs::read(dir.join(file))?;
            let mut changed = original.clone();
            if let Some(b) = changed.iter_mut().rev().find(|b| b.is_ascii_alphabetic()) {
                *b ^= 0x20;
            }
            std::fs::write(dir.join(file), &changed)?;
            let found = proverif_model_hash_findings(&dir, pins);
            assert!(
                found.len() == 1
                    && found
                        .iter()
                        .all(|f| f.starts_with(&format!("{file}: sha256 "))),
                "{file}: {found:?}"
            );
            std::fs::write(dir.join(file), &original)?;
        }
        std::fs::write(
            dir.join(expect::PROVERIF_LINK_DIR).join("lNew.pv"),
            "process 0\n",
        )?;
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            vec!["formal/link/lNew.pv: a model file without a pinned sha256".to_owned()]
        );
        std::fs::remove_file(dir.join(expect::PROVERIF_LINK_DIR).join("lNew.pv"))?;
        std::fs::remove_file(dir.join(expect::PROVERIF_LINK_LIB))?;
        assert_eq!(
            proverif_model_hash_findings(&dir, pins),
            vec!["formal/link.pvl: missing".to_owned()]
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// The `RESULT` lines of each file in a committed SecMP-LINK evidence file: the lines after each
    /// `=== formal/link/<stem>.pv` header, up to the next header.
    fn link_evidence_sections(text: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            if let Some(stem) = line
                .strip_prefix("=== formal/link/")
                .and_then(|r| r.strip_suffix(".pv"))
            {
                out.push((stem.to_owned(), String::new()));
            } else if let Some((_, body)) = out.last_mut()
                && line.trim_start().starts_with("RESULT")
            {
                body.push_str(line.trim());
                body.push('\n');
            }
        }
        out
    }

    /// PV-01 `proverif_link_matches_claims` [O-16] (TEST-SPEC-M5 (h)): the gate's reading of the SecMP-LINK files —
    /// every file of `expect::PROVERIF_EXPECTED_LINK` passes with the output its entries describe and is refused, naming
    /// the file, the CLAIMS ID and the query, when one of its lines has the opposite or no verdict; the `RESULT` lines of
    /// the committed local run (`docs/reviews/M05-evidence/proverif-link-local-2.txt`, one section per file) pass the
    /// gate for every file, so the table is the measured one. The verdicts against CLAIMS: X-04.
    #[test]
    fn proverif_link_matches_claims() -> Result<()> {
        let table = expect::PROVERIF_EXPECTED_LINK;
        let files = hx_table_files(table);
        assert_eq!(files.len(), 9);
        for file in &files {
            let lines = hx_lines(table, file);
            let summary = proverif_check_session(SessionFamily::Link, file, &hx_output(&lines))?;
            assert!(
                summary.starts_with(&format!(
                    "formal/link/{file}.pv: {} RESULT lines as expected — ",
                    lines.len()
                )),
                "{summary}"
            );
            for (k, (_, id, query, proved)) in table.iter().filter(|(f, ..)| f == file).enumerate()
            {
                for wrong in [flipped(*proved), "cannot be proved."] {
                    let mut bad = lines.clone();
                    if let Some(l) = bad.get_mut(k) {
                        l.1 = wrong;
                    }
                    refused_with(
                        proverif_check_session(SessionFamily::Link, file, &hx_output(&bad)),
                        &[
                            &format!(
                                "formal/link/{file}.pv against expect::PROVERIF_EXPECTED_LINK"
                            ),
                            &format!("RESULT line {} ({id}) is ", k.saturating_add(1)),
                            &format!(", expected {}", expected_word(*proved)),
                            query,
                        ],
                    )?;
                }
            }
        }
        // a link file is not an HX file, and the HX table knows no link file
        refused_with(
            proverif_check_hx("lClean", &hx_output(&hx_lines(table, "lClean"))),
            &["formal/hx/lClean.pv: no expected entries in expect::PROVERIF_EXPECTED_HX"],
        )?;
        // the committed local run
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let evidence = lf(&std::fs::read_to_string(
            root.join("docs/reviews/M05-evidence/proverif-link-local-2.txt"),
        )?);
        let sections = link_evidence_sections(&evidence);
        let stems: BTreeSet<String> = sections.iter().map(|(s, _)| s.clone()).collect();
        assert_eq!(stems, files);
        for (stem, body) in &sections {
            let summary = proverif_check_session(SessionFamily::Link, stem, body)?;
            assert!(
                summary.starts_with(&format!("formal/link/{stem}.pv: ")),
                "{summary}"
            );
        }
        Ok(())
    }

    /// The remark of the synthetic outputs ([`hx_output`]) under an injective query that is false.
    const EVEN_REMARK: &str = "RESULT (even event(RAccept(x,y)) ==> event(IStart(x,y)) is false.)";

    /// M5 review R-117 (C-9): an injective query expected false passes only with exactly one remark `RESULT (even … is
    /// false.)` under it. A synthetic lQKey output whose L6a line carries `RESULT (but … is true.)` (the non-injective
    /// version holds: a replay-only failure) is refused naming the file, the line, the ID, the remark and the query; so
    /// are no remark and two remarks, the committed lQKey run edited that way (the reviewer's V7), and every injective
    /// expected-false entry of the HX and LINK tables (H8, H9, L1c, L2, L6a) with the `(but …)` remark. A remark
    /// attaches to the line above it; one without a line above is an unreadable line.
    #[test]
    fn proverif_inj_false_requires_even_remark() -> Result<()> {
        let l6a = "inj-event(RExec(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1))))) ==> \
                   inj-event(CSign(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1)))))";
        assert!(expect::PROVERIF_EXPECTED_LINK.contains(&(
            "lQKey",
            "L6a",
            l6a,
            expect::Proved::False
        )));
        let but = "RESULT (but event(RExec(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1))))) ==> \
                   event(CSign(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1))))) is true.)";
        let even = but
            .replace("RESULT (but ", "RESULT (even ")
            .replace(" is true.)", " is false.)");
        let l8: Vec<String> = hx_lines(expect::PROVERIF_EXPECTED_LINK, "lQKey")
            .iter()
            .filter(|(q, _)| *q != l6a)
            .map(|(q, end)| format!("RESULT {q} {end}"))
            .collect();
        assert_eq!(l8.len(), 3);
        let output = |remarks: &[&str]| -> String {
            let mut v = l8.clone();
            v.push(format!("RESULT {l6a} is false."));
            v.extend(remarks.iter().map(|r| (*r).to_owned()));
            v.join("\n")
        };
        assert!(
            proverif_check_session(SessionFamily::Link, "lQKey", &output(&[&even]))?
                .ends_with("L8 false ×3, L6a false ×1")
        );
        for (remarks, shown) in [
            (
                vec![but],
                format!("but its remark is `{but}`, expected one"),
            ),
            (vec![], "but its remark is none, expected one".to_owned()),
            (
                vec![even.as_str(), even.as_str()],
                format!("but its remark is `{even}`, `{even}`, expected one"),
            ),
        ] {
            refused_with(
                proverif_check_session(SessionFamily::Link, "lQKey", &output(&remarks)),
                &[
                    "formal/link/lQKey.pv against expect::PROVERIF_EXPECTED_LINK",
                    "RESULT line 4 (L6a) is an injective query expected false",
                    &shown,
                    "`RESULT (even … is false.)`",
                    l6a,
                ],
            )?;
        }
        // the committed lQKey run (docs/reviews/M05-evidence/proverif-link-local-2.txt) with its remark edited
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let evidence = lf(&std::fs::read_to_string(
            root.join("docs/reviews/M05-evidence/proverif-link-local-2.txt"),
        )?);
        let sections = link_evidence_sections(&evidence);
        let Some((_, lqkey)) = sections.iter().find(|(s, _)| s == "lQKey") else {
            bail!("no lQKey section in the committed link run");
        };
        assert_eq!(lqkey.matches(&even).count(), 1);
        proverif_check_session(SessionFamily::Link, "lQKey", lqkey)?;
        refused_with(
            proverif_check_session(SessionFamily::Link, "lQKey", &lqkey.replace(&even, but)),
            &["RESULT line 4 (L6a)", but],
        )?;
        inj_false_entries_need_even_remark()
    }

    /// The second half of `proverif_inj_false_requires_even_remark`: every injective expected-false entry of both
    /// session families is refused with the `(but …)` remark, and a remark attaches to the line above it.
    fn inj_false_entries_need_even_remark() -> Result<()> {
        let mut seen = Vec::new();
        for family in SessionFamily::ALL {
            for (file, id, query, _) in family
                .table()
                .iter()
                .filter(|(_, _, q, p)| *p == expect::Proved::False && q.contains("inj-event"))
            {
                let good = hx_output(&hx_lines(family.table(), file));
                assert_eq!(good.matches(EVEN_REMARK).count(), 1, "{file}");
                proverif_check_session(family, file, &good)?;
                let bad = good.replace(
                    EVEN_REMARK,
                    "RESULT (but event(RAccept(x,y)) ==> event(IStart(x,y)) is true.)",
                );
                refused_with(
                    proverif_check_session(family, file, &bad),
                    &[
                        &format!("{}/{file}.pv against {}", family.dir(), family.table_name()),
                        &format!(
                            "({id}) is an injective query expected false, but its remark is `RESULT (but "
                        ),
                        query,
                    ],
                )?;
                seen.push(*id);
            }
        }
        assert_eq!(seen, ["H8", "H9", "L1c", "L2", "L6a"]);
        // attachment: a remark belongs to the line above it, one without a line above is unreadable
        let lines = proverif_result_lines(
            "RESULT (even e is false.)\nRESULT not attacker(s[]) is true.\nRESULT q is false.\n  RESULT (but p is true.)\n",
        );
        let got: Vec<(&str, PvVerdict, Vec<String>)> = lines
            .iter()
            .map(|l| (l.query.as_str(), l.verdict, l.remarks.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("(even e is false.)", PvVerdict::Unreadable, vec![]),
                ("not attacker(s[])", PvVerdict::True, vec![]),
                ("q", PvVerdict::False, vec!["(but p is true.)".to_owned()]),
            ]
        );
        Ok(())
    }

    /// M5 review R-117 (C-9): the remarks ProVerif 2.05 prints today — lines 96, 104 and 136 of the committed link run
    /// (`docs/reviews/M05-evidence/proverif-link-local-2.txt`: L1c in lBoth, L2 in lSig, L6a in lQKey) — are
    /// `RESULT (even … is false.)`, attach to the injective line above them and pass the gate; the nine files of that
    /// run pass with the summaries the gate printed then (9/9 unchanged).
    #[test]
    fn proverif_inj_false_accepts_even_remark() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let evidence = lf(&std::fs::read_to_string(
            root.join("docs/reviews/M05-evidence/proverif-link-local-2.txt"),
        )?);
        let text: Vec<&str> = evidence.lines().collect();
        let sections = link_evidence_sections(&evidence);
        for (number, stem, id) in [
            (96_usize, "lBoth", "L1c"),
            (104, "lSig", "L2"),
            (136, "lQKey", "L6a"),
        ] {
            let Some(line) = number.checked_sub(1).and_then(|i| text.get(i)) else {
                bail!("the committed link run has no line {number}");
            };
            let remark = line.strip_prefix("RESULT ").unwrap_or_default();
            assert!(
                remark.starts_with("(even event(") && remark.ends_with(" is false.)"),
                "line {number}: {line}"
            );
            let Some((_, body)) = sections.iter().find(|(s, _)| s == stem) else {
                bail!("no {stem} section in the committed link run");
            };
            let got = proverif_result_lines(body);
            let Some(last) = got.last() else {
                bail!("{stem}: no RESULT line");
            };
            assert!(
                last.query.starts_with("inj-event("),
                "{stem}: {}",
                last.query
            );
            assert_eq!(last.verdict, PvVerdict::False);
            assert_eq!(last.remarks, vec![remark.to_owned()]);
            assert!(expect::PROVERIF_EXPECTED_LINK.contains(&(
                stem,
                id,
                last.query.as_str(),
                expect::Proved::False
            )));
            assert_eq!(
                got.iter().map(|l| l.remarks.len()).sum::<usize>(),
                1,
                "{stem}"
            );
        }
        assert_eq!(sections.len(), 9);
        for (stem, body) in &sections {
            let summary = proverif_check_session(SessionFamily::Link, stem, body)?;
            assert!(
                evidence.contains(&format!("    {summary} (")),
                "{stem}: {summary}"
            );
        }
        Ok(())
    }

    /// A `tr-perf` report as the example writes it.
    const TR_PERF: &str = "host=aarch64-apple-darwin\nn=200\nwarmup=20\nchain_median_us=62.5\nchain_max_us=86.2\nstep_median_us=227.4\nstep_max_us=383.3\n";

    /// M3 plan D11: the `perf` report is read strictly and every kind's maximum must stay below 3 ms.
    #[test]
    fn tr_perf_report_and_verdict() -> Result<()> {
        let perf = tr_perf(TR_PERF)?;
        assert_eq!(
            perf,
            TrPerf {
                host: "aarch64-apple-darwin".to_owned(),
                n: 200,
                kinds: vec![
                    ("chain".to_owned(), 62.5, 86.2),
                    ("step".to_owned(), 227.4, 383.3)
                ],
            }
        );
        let verdict = tr_perf_verdict(&perf)?;
        assert!(
            verdict.contains(
                "chain: median 62.5 µs, max 86.2 µs; step: median 227.4 µs, max 383.3 µs"
            ) && verdict.ends_with("every maximum below 3 ms"),
            "{verdict}"
        );
        // the verdict is on the maximum: 2999.9 µs passes, 3000.0 µs (= 3 ms) fails, whatever the median
        let with = |key: &str, value: &str| -> String {
            TR_PERF
                .lines()
                .map(|l| match l.split_once('=') {
                    Some((k, _)) if k == key => format!("{k}={value}"),
                    _ => l.to_owned(),
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(tr_perf_verdict(&tr_perf(&with("step_max_us", "2999.9"))?).is_ok());
        let slow = tr_perf_verdict(&tr_perf(&with("step_max_us", "3000.0"))?);
        assert!(
            slow.as_ref().is_err_and(
                |e| e.0.contains("below 3 ms") && e.0.contains("step maximum 3000.0 µs")
            ),
            "{slow:?}"
        );
        assert!(tr_perf_verdict(&tr_perf(&with("chain_max_us", "12000"))?).is_err());
        // refused reports
        for (bad, why) in [
            (with("n", "20"), "20 messages per kind"),
            (with("n", "x"), "is not a count"),
            (with("warmup", "-1"), "is not a count"),
            (with("chain_max_us", "NaN"), "is not a time"),
            (with("chain_max_us", "-1"), "is not a time"),
            (
                with("step_median_us", "400"),
                "median 400 µs above its maximum",
            ),
            (
                TR_PERF.replace("step_max_us=383.3\n", ""),
                "missing: [\"step_max_us\"]",
            ),
            (
                format!("{TR_PERF}extra_us=1\n"),
                "unexpected: [\"extra_us\"]",
            ),
            (format!("{TR_PERF}n=200\n"), "n given twice"),
            (format!("{TR_PERF}garbage\n"), "not a key=value line"),
            (
                "error=encrypt refused\n".to_owned(),
                "tr-perf failed: encrypt refused",
            ),
            (String::new(), "missing"),
        ] {
            let got = tr_perf(&bad);
            assert!(
                got.as_ref().is_err_and(|e| e.0.contains(why)),
                "{why}: {got:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn systemd_levels() {
        let out = "  NAME  DESCRIPTION  EXPOSURE\n→ Overall exposure level for weak.service: 9.6 UNSAFE 😨\n";
        assert_eq!(systemd_exposure(out), Some(9.6));
        assert_eq!(systemd_exposure("nothing"), None);
    }

    #[test]
    fn coverage_grouping() -> Result<()> {
        let json = r#"{"data":[{"files":[
            {"filename":"/w/crates/a/src/lib.rs","summary":{"lines":{"count":10,"covered":9}}},
            {"filename":"/w/crates/b/src/main.rs","summary":{"lines":{"count":4,"covered":4}}},
            {"filename":"/w/xtask/src/main.rs","summary":{"lines":{"count":100,"covered":0}}}]}]}"#;
        let crates = vec![
            ("a".to_owned(), PathBuf::from("/w/crates/a")),
            ("b".to_owned(), PathBuf::from("/w/crates/b")),
        ];
        let rows = coverage_by_crate(json, &crates)?;
        assert_eq!(rows, vec![("a".to_owned(), 10, 9), ("b".to_owned(), 4, 4)]);
        assert!((percent(9, 10) - 90.0).abs() < 1e-9);
        assert!(coverage_by_crate("{}", &crates).is_err());
        Ok(())
    }

    #[test]
    fn workflow_hygiene() {
        let good = "on:\n  pull_request:\njobs:\n  xwin-cross:\n    continue-on-error: false\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n";
        assert!(workflow_findings("w", good).is_empty());
        // the M0 allowance for xwin-cross ended with condition C1 of the M0 review
        let soft_xwin = good.replace("continue-on-error: false", "continue-on-error: true");
        assert_eq!(workflow_findings("w", &soft_xwin).len(), 1);
        let bad = "on:\n  pull_request_target:\n  workflow_run:\njobs:\n  build:\n    continue-on-error: true\n    steps:\n      - uses: actions/checkout@v7\n";
        assert_eq!(workflow_findings("w", bad).len(), 4);
        let yaml_trap = "jobs:\n  a:\n    steps:\n      - run: echo \"done: ok\"\n      - run: |\n          echo \"done: ok\"\n";
        assert_eq!(workflow_findings("w", yaml_trap).len(), 1);
    }

    /// The pinned jobs `linux-full` delegates to (M4 review C-5), with their pinned conditions, `needs:` and gate lines,
    /// as they follow the required jobs in a `ci.yml` fixture.
    const PINNED_EXTRA: &str = "  ct:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n    steps:\n      - run: cargo xtask step --strict ct\n  mutants-shard:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n    strategy:\n      matrix:\n        shard:\n          - 0\n          - 1\n    steps:\n      - run: cargo xtask install-tools --set mutants\n      - run: cargo xtask step --strict mutants --shard ${{ matrix.shard }}/8\n  mutants:\n    needs: mutants-shard\n    if: always() && (github.event_name == 'schedule' || github.event_name == 'pull_request')\n    runs-on: x\n    steps:\n      - run: cargo xtask step --strict mutants-merge\n  proverif-hx:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n    steps:\n      - run: cargo xtask step --strict proverif --models hx --jobs 4\n  proverif-link:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n    steps:\n      - run: cargo xtask step --strict proverif --models link --jobs 4\n";

    /// M2 review C2: the required job names only in ci.yml, all four there, and no dispatch trigger in ci.yml; M4
    /// review C-5: likewise the pinned jobs `linux-full` delegates to.
    #[test]
    fn required_checks_only_in_the_pull_request_workflow() {
        let ci = format!(
            "on:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  linux-fast:\n    runs-on: x\n  windows-native:\n    runs-on: x\n  xwin-cross:\n    runs-on: x\n  linux-full:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n{PINNED_EXTRA}"
        );
        let ci = ci.as_str();
        let dispatch = "on:\n  workflow_dispatch:\njobs:\n  dispatch-ct:\n    runs-on: x\n  dispatch-full:\n    runs-on: x\n";
        let files = |ci: &str, other: &str| {
            vec![
                (expect::REQUIRED_WORKFLOW.to_owned(), ci.to_owned()),
                (
                    ".github/workflows/ci-dispatch.yml".to_owned(),
                    other.to_owned(),
                ),
            ]
        };
        assert!(required_job_findings(&files(ci, dispatch)).is_empty());
        // the pre-C2 ci.yml: a dispatch trigger next to the required jobs
        let with_dispatch = ci.replace("  push:\n", "  workflow_dispatch:\n  push:\n");
        assert_eq!(
            required_job_findings(&files(&with_dispatch, dispatch)).len(),
            1
        );
        // a required name in another workflow, as a job id or as a job's `name:`
        let reuse_id = dispatch.replace("dispatch-full:", "linux-full:");
        assert_eq!(required_job_findings(&files(ci, &reuse_id)).len(), 1);
        let reuse_name = dispatch.replace(
            "  dispatch-ct:\n    runs-on: x\n",
            "  dispatch-ct:\n    name: windows-native\n    runs-on: x\n",
        );
        assert_eq!(required_job_findings(&files(ci, &reuse_name)).len(), 1);
        // a required job missing from ci.yml, or ci.yml missing
        let missing = ci.replace("  xwin-cross:\n    runs-on: x\n", "");
        assert_eq!(required_job_findings(&files(&missing, dispatch)).len(), 1);
        // a delegated pinned job's name in another workflow
        let reuse_ct = dispatch.replace("dispatch-ct:", "ct:");
        assert_eq!(required_job_findings(&files(ci, &reuse_ct)).len(), 1);
        assert_eq!(
            required_job_findings(&[("other.yml".to_owned(), dispatch.to_owned())]).len(),
            1
        );
    }

    /// F19 (external review EXT-1): a job-level `if:` on a required job other than the pinned one is refused — a
    /// new condition, a changed one, a removed pinned one; step-level conditions and other jobs are not affected.
    #[test]
    fn required_jobs_keep_their_pinned_conditions() {
        let ci = format!(
            "on:\n  pull_request:\njobs:\n  linux-fast:\n    runs-on: x\n    steps:\n      - if: always()\n        run: x\n  windows-native:\n    runs-on: x\n  xwin-cross:\n    runs-on: x\n  linux-full:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n  extra:\n    if: false\n    runs-on: x\n{PINNED_EXTRA}"
        );
        let ci = ci.as_str();
        let dispatch = "on:\n  workflow_dispatch:\njobs:\n  dispatch-ct:\n    runs-on: x\n";
        let files = |ci: &str| {
            vec![
                (expect::REQUIRED_WORKFLOW.to_owned(), ci.to_owned()),
                (
                    ".github/workflows/ci-dispatch.yml".to_owned(),
                    dispatch.to_owned(),
                ),
            ]
        };
        assert!(required_job_findings(&files(ci)).is_empty());
        // a condition on a job that has none pinned
        let skipped_fast = ci.replace(
            "  linux-fast:\n    runs-on: x\n",
            "  linux-fast:\n    if: github.event_name == 'push'\n    runs-on: x\n",
        );
        let found = required_job_findings(&files(&skipped_fast));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found.iter().any(|f| f.contains("`linux-fast`")));
        // the pinned condition changed, or removed
        let changed = ci.replacen("|| github.event_name == 'pull_request'", "", 1);
        assert_eq!(required_job_findings(&files(&changed)).len(), 1);
        let removed = ci.replacen(
            "    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n",
            "",
            1,
        );
        assert_eq!(required_job_findings(&files(&removed)).len(), 1);
        // likewise on every pinned job (M4 review C-5; M5 adds `proverif-link`): each condition changed alone is one
        // finding
        assert_eq!(
            required_job_findings(&files(
                &ci.replace("|| github.event_name == 'pull_request'", "")
            ))
            .len(),
            6
        );
        // the conditions as parsed
        let parsed = job_conditions(ci);
        assert_eq!(parsed.len(), 10);
        assert_eq!(parsed.first(), Some(&("linux-fast".to_owned(), None)));
        assert_eq!(
            parsed.get(4),
            Some(&("extra".to_owned(), Some("false".to_owned())))
        );
        // the real ci.yml keeps its pinned conditions
        let real = lf(include_str!("../../.github/workflows/ci.yml"));
        for (job, cond) in expect::REQUIRED_JOB_CONDITIONS {
            let found = job_conditions(&real)
                .into_iter()
                .find(|(j, _)| j == job)
                .map(|(_, c)| c);
            assert_eq!(found, Some(cond.map(str::to_owned)), "{job}");
        }
    }

    /// M2 review F5, M3 review F21 (R-49): every uploaded artefact of every workflow (the ct reports, the SBOMs, the
    /// fuzz corpus and artefacts) carries the run attempt in its name, so a re-run attempt of the same run (same SHA,
    /// same run id) uploads under a new name instead of failing on the existing one.
    #[test]
    fn every_artefact_name_is_unique_per_attempt() {
        for (file, text) in [
            ("ci.yml", include_str!("../../.github/workflows/ci.yml")),
            (
                "ci-dispatch.yml",
                include_str!("../../.github/workflows/ci-dispatch.yml"),
            ),
            (
                "fuzz-nightly.yml",
                include_str!("../../.github/workflows/fuzz-nightly.yml"),
            ),
        ] {
            let text = lf(text);
            let names = upload_artifact_names(&yaml_lines(&text));
            assert!(!names.is_empty(), "{file}");
            for n in &names {
                assert!(
                    n.as_deref()
                        .is_some_and(|n| n.ends_with("-${{ github.run_attempt }}")),
                    "{file}: {n:?}"
                );
            }
            assert!(workflow_findings(file, &text).is_empty(), "{file}");
            // the same file with one name lacking the suffix, or without a name, is a finding
            let first = names.first().cloned().flatten().unwrap_or_default();
            let stripped = text.replacen(
                &first,
                first.trim_end_matches("-${{ github.run_attempt }}"),
                1,
            );
            assert_eq!(workflow_findings(file, &stripped).len(), 1, "{file}");
        }
        let nameless = "jobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          path: x\n";
        assert_eq!(workflow_findings("w", nameless).len(), 1);
    }

    /// The pinned jobs with their gate steps (the four required ones, then [`PINNED_EXTRA`]); `fast` is spliced into
    /// `linux-fast` after its `runs-on`, `fast_step` replaces its first gate step line.
    fn gate_ci(fast: &str, fast_step: &str) -> String {
        format!(
            "on:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  linux-fast:\n    runs-on: x\n{fast}    steps:\n      - uses: actions/cache/save@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6\n        if: steps.c.outputs.hit != 'true'\n{fast_step}      - run: cargo xtask step --strict sbom systemd\n  windows-native:\n    runs-on: x\n    steps:\n      - run: cargo xtask install-tools --set windows\n      - run: cargo xtask step --strict clippy nextest doctest kat hello\n  xwin-cross:\n    runs-on: x\n    steps:\n      - run: cargo xtask step --strict windows-cross\n  linux-full:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n    steps:\n      - run: cargo xtask ci-full --strict --delegated windows-native --delegated windows-cross --delegated mutants --delegated ct --delegated proverif-link --models tr\n{PINNED_EXTRA}"
        )
    }

    /// Every check of the policy step on one `ci.yml` text (the dispatch workflow is the clean fixture).
    fn all_ci_findings(ci: &str) -> Vec<String> {
        let dispatch = "on:\n  workflow_dispatch:\njobs:\n  dispatch-ct:\n    runs-on: x\n";
        let mut out = workflow_findings(expect::REQUIRED_WORKFLOW, ci);
        out.extend(workflow_token_findings(expect::REQUIRED_WORKFLOW, ci));
        out.extend(required_job_findings(&[
            (expect::REQUIRED_WORKFLOW.to_owned(), ci.to_owned()),
            (
                ".github/workflows/ci-dispatch.yml".to_owned(),
                dispatch.to_owned(),
            ),
        ]));
        out.extend(required_gate_findings(expect::REQUIRED_WORKFLOW, ci));
        out
    }

    /// F3 (R-09), the cases 2–7 of the review's parser replica: each bypass of the F19 condition pin or of the
    /// hygiene rules now yields a finding, as do `needs:`, a step-level `if` on a gate step and a changed gate line.
    #[test]
    fn required_job_bypasses_are_findings() {
        let gate = "      - run: cargo xtask ci-fast --strict\n";
        let good = gate_ci("", gate);
        assert_eq!(all_ci_findings(&good), Vec::<String>::new());
        // 2: `if : false`
        let case2 = gate_ci("    if : false\n", gate);
        assert!(!all_ci_findings(&case2).is_empty(), "case 2");
        // 3: a quoted key
        let case3 = gate_ci("    \"if\": false\n", gate);
        assert!(!all_ci_findings(&case3).is_empty(), "case 3");
        let case3b = gate_ci("    'if': false\n", gate);
        assert!(!all_ci_findings(&case3b).is_empty(), "case 3b");
        // 4: another indentation width on the job's property (the job keeps the pinned shape, the property moves)
        let case4 = good.replace(
            "  linux-fast:\n    runs-on: x\n",
            "  linux-fast:\n      if: false\n      runs-on: x\n",
        );
        assert!(!all_ci_findings(&case4).is_empty(), "case 4");
        // 5: `needs:` on a required job (on a job that is skipped)
        let case5 = gate_ci("    needs: [linux-full]\n", gate);
        assert!(
            all_ci_findings(&case5).iter().any(|f| f.contains("needs")),
            "case 5"
        );
        let case5b = gate_ci("    needs:\n      - linux-full\n", gate);
        assert!(!all_ci_findings(&case5b).is_empty(), "case 5b");
        // 6: a step-level `if` on a gate step
        let case6 = gate_ci(
            "",
            "      - if: false\n        run: cargo xtask ci-fast --strict\n",
        );
        assert!(
            all_ci_findings(&case6)
                .iter()
                .any(|f| f.contains("step-level")),
            "case 6"
        );
        let case6b = gate_ci(
            "",
            "      - run: cargo xtask ci-fast --strict\n        if: false\n",
        );
        assert!(!all_ci_findings(&case6b).is_empty(), "case 6b");
        // 7: `continue-on-error: true # false`, and the quoted-key and expression forms
        for coe in [
            "    continue-on-error: true # false\n",
            "    \"continue-on-error\": true\n",
            "    continue-on-error: ${{ true }}\n",
        ] {
            assert!(!all_ci_findings(&gate_ci(coe, gate)).is_empty(), "{coe}");
        }
        let case7 = gate_ci(
            "",
            "      - run: cargo xtask ci-fast --strict\n        continue-on-error: true # false\n",
        );
        assert!(!all_ci_findings(&case7).is_empty(), "case 7 step");
        // a flow-style job and a renamed check run
        let flow = good.replace(
            "  xwin-cross:\n    runs-on: x\n",
            "  xwin-cross: {if: false, runs-on: x}\n    runs-on: x\n",
        );
        assert!(!all_ci_findings(&flow).is_empty(), "flow style");
        let renamed = gate_ci("    name: other\n", gate);
        assert!(!all_ci_findings(&renamed).is_empty(), "name");
        // the gate lines are pinned: a changed flag, an appended `|| true`, a missing gate
        for line in [
            "      - run: cargo xtask ci-fast\n",
            "      - run: cargo xtask ci-fast --strict || true\n",
            "      - run: cargo xtask ci-fast --strict --delegated clippy\n",
            "",
        ] {
            let found = all_ci_findings(&gate_ci("", line));
            assert!(
                found.iter().any(|f| f.contains("gates")),
                "{line:?}: {found:?}"
            );
        }
        // an `if` text inside a block scalar is content, not a key
        let block = gate_ci(
            "",
            "      - run: cargo xtask ci-fast --strict\n      - run: |\n          if: false\n          echo done\n",
        );
        assert_eq!(all_ci_findings(&block), Vec::<String>::new());
        // the real ci.yml passes every check
        let real = lf(include_str!("../../.github/workflows/ci.yml"));
        assert_eq!(all_ci_findings(&real), Vec::<String>::new());
    }

    /// `text` without the job `id` (its header line and every deeper line up to the next job or the end).
    fn without_job(text: &str, id: &str) -> String {
        let header = format!("  {id}:");
        let mut out = String::new();
        let mut skipping = false;
        for line in text.lines() {
            let is_job_header = line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':');
            if is_job_header {
                skipping = line.trim_end() == header;
            }
            if !skipping {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// M4 review C-5 (R-01; V5 variants v01, v02, v03, v05, v14): deleting the job `mutants` or `proverif-hx`, an
    /// `if: false` on a pinned job, `--models tr` instead of `--models hx` and an appended `|| true` are each a finding,
    /// on the fixture and on the real `ci.yml`; the pristine texts give none.
    #[test]
    fn deleting_or_neutering_a_pinned_job_is_a_finding() {
        let real = lf(include_str!("../../.github/workflows/ci.yml"));
        let fixture = gate_ci("", "      - run: cargo xtask ci-fast --strict\n");
        for (what, ci) in [("fixture", fixture.as_str()), ("ci.yml", real.as_str())] {
            assert_eq!(all_ci_findings(ci), Vec::<String>::new(), "{what}");
            let variants = pin_edit_variants(ci);
            for (name, text) in &variants {
                assert_ne!(text.as_str(), ci, "{what} {name}: the edit did not apply");
                let found = all_ci_findings(text);
                assert!(!found.is_empty(), "{what} {name}: no finding");
            }
        }
    }

    /// The pin-edit variants of `deleting_or_neutering_a_pinned_job_is_a_finding` (LF text).
    fn pin_edit_variants(ci: &str) -> Vec<(&'static str, String)> {
        {
            let variants = [
                ("v01 delete mutants", without_job(ci, "mutants")),
                ("v02 delete proverif-hx", without_job(ci, "proverif-hx")),
                // M5 (BRIEF_M5-B §1): the SecMP-LINK job deleted, or running another model set
                ("delete proverif-link", without_job(ci, "proverif-link")),
                (
                    "proverif-link --models hx",
                    ci.replacen("proverif --models link --jobs 4", "proverif --models hx --jobs 4", 1),
                ),
                (
                    "linux-full without --delegated proverif-link",
                    ci.replacen(" --delegated proverif-link --models tr", " --models tr", 1),
                ),
                ("delete ct", without_job(ci, "ct")),
                ("delete mutants-shard", without_job(ci, "mutants-shard")),
                (
                    "v03 if: false",
                    ci.replacen(
                        "    if: always() && (github.event_name == 'schedule' || github.event_name == 'pull_request')\n",
                        "    if: false\n",
                        1,
                    ),
                ),
                (
                    "v05 --models tr",
                    ci.replacen("proverif --models hx --jobs 4", "proverif --models tr --jobs 4", 1),
                ),
                (
                    "v14 || true",
                    ci.replacen("cargo xtask step --strict ct\n", "cargo xtask step --strict ct || true\n", 1),
                ),
                (
                    "a second needs",
                    ci.replacen("    needs: mutants-shard\n", "    needs: proverif-hx\n", 1),
                ),
                (
                    "needs on ct",
                    ci.replacen(
                        "  ct:\n",
                        "  ct:\n    needs: linux-fast\n",
                        1,
                    ),
                ),
            ];
            variants.into()
        }
    }

    /// M4 review R-100: the policy reads a CRLF checkout like an LF one — the committed `ci.yml` as CRLF gives no
    /// finding, and each pin-edit variant applied to the CRLF text gives the finding it gives on LF.
    #[test]
    fn policy_reads_crlf_workflows_like_lf() {
        let real = lf(include_str!("../../.github/workflows/ci.yml"));
        let crlf = real.replace('\n', "\r\n");
        assert_ne!(crlf, real);
        assert_eq!(all_ci_findings(&lf(&crlf)), Vec::<String>::new());
        for (name, edited) in pin_edit_variants(&real) {
            let on_lf = all_ci_findings(&edited);
            let on_crlf = all_ci_findings(&lf(&edited.replace('\n', "\r\n")));
            assert!(!on_lf.is_empty(), "{name}: no finding on LF");
            assert_eq!(on_lf, on_crlf, "{name}");
        }
    }

    /// M4 review C-5 (R-15): `uses` is read as YAML would — a flow-style step, a quoted key and a space before the
    /// colon each give one finding; an action pinned by SHA (in any of those spellings but flow style) none.
    #[test]
    fn flow_style_and_quoted_uses_are_findings() {
        let step = |line: &str| format!("jobs:\n  a:\n    runs-on: x\n    steps:\n{line}\n");
        for line in [
            "      - {uses: evil/action@main}",
            "      - \"uses\": evil/action@main",
            "      - uses : evil/action@main",
            "      - 'uses': evil/action@main",
        ] {
            let found = workflow_findings("w", &step(line));
            assert_eq!(found.len(), 1, "{line}: {found:?}");
        }
        let sha = "3d3c42e5aac5ba805825da76410c181273ba90b1";
        for line in [
            format!("      - uses: actions/checkout@{sha} # v7.0.1"),
            format!("      - \"uses\": actions/checkout@{sha}"),
            format!("      - uses : actions/checkout@{sha}"),
        ] {
            assert_eq!(
                workflow_findings("w", &step(&line)),
                Vec::<String>::new(),
                "{line}"
            );
        }
        // a flow-style pinned step is still refused: the reader does not parse flow style
        assert_eq!(
            workflow_findings(
                "w",
                &step(&format!("      - {{uses: actions/checkout@{sha}}}"))
            )
            .len(),
            1
        );
        // flow style outside `jobs:` (the `on:` lists) is not inside a job
        assert_eq!(
            workflow_findings(
                "w",
                "on:\n  push:\n    branches: [main]\njobs:\n  a:\n    runs-on: x\n"
            ),
            Vec::<String>::new()
        );
    }

    /// M4 delta review VD1-4: a flow-style value on the `jobs:` line itself (quoted key or not) is a finding; the
    /// block form, with or without a trailing comment, is none.
    #[test]
    fn policy_refuses_flow_style_jobs_line() {
        let sha = "3d3c42e5aac5ba805825da76410c181273ba90b1";
        for jobs in [
            format!("jobs: {{a: {{runs-on: x, steps: [{{uses: evil/action@{sha}}}]}}}}"),
            "jobs: {a: {if: false, runs-on: x}}".to_owned(),
            "\"jobs\": {a: {runs-on: x}}".to_owned(),
            "jobs: [a]".to_owned(),
        ] {
            let found = workflow_findings("w", &format!("on:\n  push:\n{jobs}\n"));
            assert_eq!(found.len(), 1, "{jobs}: {found:?}");
            assert!(
                found.iter().all(|f| f.contains("on the `jobs:` line")),
                "{found:?}"
            );
        }
        for jobs in ["jobs:", "jobs: # the jobs", "\"jobs\":"] {
            assert_eq!(
                workflow_findings(
                    "w",
                    &format!("on:\n  push:\n{jobs}\n  a:\n    runs-on: x\n")
                ),
                Vec::<String>::new(),
                "{jobs}"
            );
        }
    }

    /// M4 review C-5 (R-16): workflow permissions other than exactly `contents: read`, job-level permissions, a
    /// `defaults.run.shell`, a step `shell:` in a pinned job and `SECMP_PROVERIF` in the environment are each a
    /// finding; every real workflow passes.
    #[test]
    fn workflow_permissions_shell_and_prover_override_are_findings() {
        let good = gate_ci("", "      - run: cargo xtask ci-fast --strict\n");
        assert_eq!(all_ci_findings(&good), Vec::<String>::new());
        let block = "permissions:\n  contents: read\n";
        let variants = [
            ("write-all", good.replacen(block, "permissions: write-all\n", 1)),
            ("no permissions", good.replacen(block, "", 1)),
            ("contents: write", good.replacen(block, "permissions:\n  contents: write\n", 1)),
            (
                "an extra scope",
                good.replacen(block, "permissions:\n  contents: read\n  id-token: write\n", 1),
            ),
            (
                "job-level permissions",
                gate_ci("    permissions:\n      contents: write\n      id-token: write\n", "      - run: cargo xtask ci-fast --strict\n"),
            ),
            (
                "defaults.run.shell",
                good.replacen(block, "permissions:\n  contents: read\ndefaults:\n  run:\n    shell: bash -c 'exit 0'\n", 1),
            ),
            (
                "job defaults",
                gate_ci("    defaults:\n      run:\n        shell: 'bash -c \"exit 0\"'\n", "      - run: cargo xtask ci-fast --strict\n"),
            ),
            (
                "step shell",
                gate_ci("", "      - run: cargo xtask ci-fast --strict\n        shell: 'bash -c \"exit 0\"'\n"),
            ),
            (
                "env SECMP_PROVERIF",
                good.replacen(block, "permissions:\n  contents: read\nenv:\n  SECMP_PROVERIF: /bin/true\n", 1),
            ),
        ];
        for (name, text) in &variants {
            assert_ne!(text, &good, "{name}: the edit did not apply");
            assert!(!all_ci_findings(text).is_empty(), "{name}: no finding");
        }
        for (file, text) in [
            ("ci.yml", include_str!("../../.github/workflows/ci.yml")),
            (
                "ci-dispatch.yml",
                include_str!("../../.github/workflows/ci-dispatch.yml"),
            ),
            (
                "fuzz-nightly.yml",
                include_str!("../../.github/workflows/fuzz-nightly.yml"),
            ),
            (
                "miri-full.yml",
                include_str!("../../.github/workflows/miri-full.yml"),
            ),
        ] {
            let text = lf(text);
            let text = text.as_str();
            assert_eq!(
                workflow_token_findings(file, text),
                Vec::<String>::new(),
                "{file}"
            );
            assert_eq!(
                workflow_findings(file, text),
                Vec::<String>::new(),
                "{file}"
            );
        }
    }

    /// M4 review C-5 (V5 (d)): every delegation of a pinned line maps to a pinned job with its own gate line, and the
    /// pinned `--models tr` comes with a pinned `proverif --models hx`; the constants are consistent with each other.
    #[test]
    fn delegations_map_to_pinned_jobs() {
        assert_eq!(
            delegation_findings(expect::REQUIRED_GATE_RUNS, expect::DELEGATED_TO),
            Vec::<String>::new()
        );
        // a delegation without a mapping, or mapped to a job without a pinned line
        let unmapped: Vec<(&str, &str)> = expect::DELEGATED_TO
            .iter()
            .copied()
            .filter(|(step, _)| *step != "ct")
            .collect();
        let found = delegation_findings(expect::REQUIRED_GATE_RUNS, &unmapped);
        assert!(found.iter().any(|f| f.contains("`ct`")), "{found:?}");
        let without = |job: &str| -> Vec<(&'static str, &'static [&'static str])> {
            expect::REQUIRED_GATE_RUNS
                .iter()
                .copied()
                .filter(|(j, _)| *j != job)
                .collect()
        };
        for job in ["ct", "mutants", "xwin-cross", "windows-native"] {
            assert!(
                !delegation_findings(&without(job), expect::DELEGATED_TO).is_empty(),
                "{job}"
            );
        }
        // `--models tr` without the HX line
        assert!(!delegation_findings(&without("proverif-hx"), expect::DELEGATED_TO).is_empty());
        // M5: `--delegated proverif-link` (and `--models tr`) without the pinned `proverif --models link` line
        let found = delegation_findings(&without("proverif-link"), expect::DELEGATED_TO);
        assert!(
            found.iter().any(|f| f.contains("`proverif-link`"))
                && found.iter().any(|f| f.contains("proverif --models link")),
            "{found:?}"
        );
        let only_link_delegated: &[(&str, &[&str])] = &[(
            "linux-full",
            &["cargo xtask ci-full --strict --delegated proverif-link"],
        )];
        assert!(
            delegation_findings(only_link_delegated, expect::DELEGATED_TO)
                .iter()
                .any(|f| f.contains("proverif --models link"))
        );
        // an unknown delegation
        let extra: &[(&str, &[&str])] = &[(
            "linux-full",
            &["cargo xtask ci-full --strict --delegated fuzz"],
        )];
        assert!(!delegation_findings(extra, expect::DELEGATED_TO).is_empty());
        // the constants: the gate lines and conditions cover exactly the pinned jobs, the required checks are pinned, the
        // pinned needs name pinned jobs
        let pinned: BTreeSet<String> = expect::PINNED_JOBS
            .iter()
            .map(|j| (*j).to_owned())
            .collect();
        let runs: BTreeSet<String> = expect::REQUIRED_GATE_RUNS
            .iter()
            .map(|(j, _)| (*j).to_owned())
            .collect();
        let conditions: BTreeSet<String> = expect::REQUIRED_JOB_CONDITIONS
            .iter()
            .map(|(j, _)| (*j).to_owned())
            .collect();
        assert_eq!(runs, pinned);
        assert_eq!(conditions, pinned);
        assert!(expect::REQUIRED_JOBS.iter().all(|j| pinned.contains(*j)));
        for (job, needs) in expect::PINNED_JOB_NEEDS {
            assert!(
                pinned.contains(*job) && pinned.contains(*needs),
                "{job} {needs}"
            );
        }
        for (_, job) in expect::DELEGATED_TO {
            assert!(pinned.contains(*job), "{job}");
        }
    }

    /// F22 (Q-4): `miri-full.yml` has one job per package of `MIRI_PACKAGES`, each running its own `miri-full-<p>`
    /// step, and is no required check.
    #[test]
    fn miri_full_workflow_has_one_job_per_package() {
        let text = lf(include_str!("../../.github/workflows/miri-full.yml"));
        let jobs = yaml_jobs(&text);
        assert_eq!(jobs.len(), expect::MIRI_PACKAGES.len());
        for p in expect::MIRI_PACKAGES {
            let id = format!("miri-full-{p}");
            let job = jobs.iter().find(|j| j.id == id);
            let run = format!("cargo xtask step --strict {id}");
            assert!(
                job.is_some_and(|j| j
                    .steps
                    .iter()
                    .flat_map(|s| s.iter())
                    .any(|(k, v)| k == "run" && *v == run)),
                "{id}"
            );
        }
        assert!(workflow_findings("miri-full.yml", &text).is_empty());
    }

    /// F18 (R-42): the coverage run leaves test-only files out of the denominator; M5-B-3: it builds with
    /// `secmp-relay/kat`, so the relay's `relay` suite is measured; M5-C: and `secmp-testkit/harness`, so the harness and
    /// the transport tests are.
    #[test]
    fn coverage_ignores_test_files() {
        let args = coverage_args("out.json");
        let at = args
            .iter()
            .position(|a| a == "--ignore-filename-regex")
            .unwrap_or(usize::MAX);
        assert_eq!(
            args.get(at.saturating_add(1)).map(String::as_str),
            Some(r"(/tests\.rs|/kani_proofs\.rs)$")
        );
        assert_eq!(args.last().map(String::as_str), Some("out.json"));
        // M5-B-3: the relay's kat-gated `relay` suite is measured
        let at = args
            .iter()
            .position(|a| a == "--features")
            .unwrap_or(usize::MAX);
        assert_eq!(
            args.get(at.saturating_add(1)).map(String::as_str),
            Some("secmp-relay/kat,secmp-testkit/harness")
        );
        assert_eq!(args.iter().filter(|a| *a == "--features").count(), 1);
        // the regex's two alternatives name the files of the secmp-proto test code
        assert!(
            COVERAGE_IGNORE_RE.contains("/tests") && COVERAGE_IGNORE_RE.contains("/kani_proofs")
        );
    }

    /// F20 (R-48): step 4 runs the workspace nextest and, after it, a non-kat run of `secmp-proto` alone.
    #[test]
    fn nextest_has_a_non_kat_run() {
        assert_eq!(
            nextest_args(),
            [
                "nextest",
                "run",
                "--workspace",
                "--locked",
                "--no-fail-fast"
            ]
        );
        let nonkat = nextest_nonkat_args();
        assert_eq!(
            nonkat,
            [
                "nextest",
                "run",
                "--locked",
                "--no-fail-fast",
                "--package",
                "secmp-proto"
            ]
        );
        assert!(!nonkat.contains(&"--workspace") && !nonkat.iter().any(|a| a.contains("kat")));
    }

    /// M4 review R-94 (Codex EXT-6): the portable-backend rerun of `kat` covers the HX suite of `secmp-proto`.
    #[test]
    fn kat_portable_rerun_includes_the_hx_suite() -> Result<()> {
        let proto: Vec<&str> = KAT_PORTABLE_RERUN
            .iter()
            .filter(|(package, _)| *package == "secmp-proto")
            .flat_map(|(_, tests)| tests.iter().copied())
            .collect();
        assert!(proto.contains(&"hx"), "{proto:?}");
        assert!(proto.contains(&"tr_vectors"), "{proto:?}");
        // M5: the handshakes of the SecMP-LINK tests encapsulate with ML-KEM-768 and -1024
        assert!(proto.contains(&"link"), "{proto:?}");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let manifest = std::fs::read_to_string(root.join("crates/secmp-proto/Cargo.toml"))?;
        for t in &proto {
            assert!(
                manifest.contains(&format!("name = \"{t}\"")),
                "{t} is not a test target of secmp-proto"
            );
        }
        Ok(())
    }

    /// The string literals of `text` (between unescaped double quotes; escapes are kept as written).
    fn string_literals(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c != '"' {
                continue;
            }
            let mut lit = String::new();
            while let Some(d) = chars.next() {
                match d {
                    '"' => break,
                    '\\' => {
                        lit.push(d);
                        if let Some(e) = chars.next() {
                            lit.push(e);
                        }
                    }
                    _ => lit.push(d),
                }
            }
            out.push(lit);
        }
        out
    }

    /// The text from `start` to the parenthesis that closes the first `(` at or after it.
    fn balanced_call(text: &str, start: usize) -> &str {
        let rest = text.get(start..).unwrap_or_default();
        let mut depth = 0_usize;
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth = depth.saturating_add(1),
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return rest.get(..=i).unwrap_or(rest);
                    }
                }
                _ => {}
            }
        }
        rest
    }

    /// The `let` statement at the start of `text`: up to its first `;` outside braces.
    fn let_statement(text: &str) -> &str {
        let mut depth = 0_usize;
        for (i, c) in text.char_indices() {
            match c {
                '{' => depth = depth.saturating_add(1),
                '}' => depth = depth.saturating_sub(1),
                ';' if depth == 0 => return text.get(..=i).unwrap_or(text),
                _ => {}
            }
        }
        text
    }

    /// M4 review C-14 (R-27, R-63): the reject-site tags the product sets — every string literal in a
    /// `…_SITE_KAT.set(…)` call of `crates/secmp-proto/src` outside its test modules, and in a `let` binding such a call
    /// reads (the TR selection's `reject_site`) — are exactly `expect::KNOWN_SITES` without the `x25519_zero_check`
    /// Output claim; a site added without its entry, or an entry no code sets, fails.
    #[test]
    fn known_sites_equal_the_product_site_tags() -> Result<()> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/secmp-proto/src");
        let mut tags: BTreeSet<String> = BTreeSet::new();
        let mut calls = 0_usize;
        for f in walk_files(&src, &|p: &Path| {
            p.extension().is_some_and(|e| e == "rs") && !p.ends_with("tests.rs")
        })? {
            let full = lf(&std::fs::read_to_string(&f)?);
            let text = full.split("#[cfg(test)]\nmod ").next().unwrap_or_default();
            for (at, _) in text.match_indices("_SITE_KAT.set(") {
                let call = balanced_call(text, at);
                calls = calls.saturating_add(1);
                tags.extend(string_literals(call));
                // a binding the call reads (`.set(match path { Path::Reject => reject_site, … })`)
                for word in call.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                    let decl = format!("let {word} = ");
                    if word.len() > 2
                        && let Some(d) = text.find(&decl)
                    {
                        tags.extend(string_literals(let_statement(
                            text.get(d..).unwrap_or_default(),
                        )));
                    }
                }
            }
        }
        assert!(calls >= 30, "{calls} site-tag calls found");
        let output_claim = "§3/§6.4 all-zero check of the output (passes: not a reject target)";
        let known: BTreeSet<String> = expect::KNOWN_SITES
            .iter()
            .filter(|s| **s != output_claim)
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(known.len(), expect::KNOWN_SITES.len().saturating_sub(1));
        assert_eq!(tags, known);
        assert!(tags.contains("skipped: (hk, n) not stored"));
        Ok(())
    }

    /// M2 review C3 (d): exit 2 or 3 of cargo-mutants without its survivor listing is refused, not read as "no
    /// survivors"; with the listing (or exit 0) the survivors are read.
    #[test]
    fn mutants_refuses_a_missing_survivor_listing() -> Result<()> {
        assert!(mutant_survivors(Some(2), None, Some(String::new())).is_err());
        assert!(mutant_survivors(Some(3), Some(String::new()), None).is_err());
        let line = "crates/a.rs:1:1: replace f with ()";
        assert_eq!(
            mutant_survivors(Some(2), Some(line.to_owned()), None)?.trim(),
            line
        );
        assert_eq!(mutant_survivors(Some(0), None, None)?.trim(), "");
        Ok(())
    }

    /// TEST-SPEC-M5 X-02 (ADR-047 Amendment 3, OPEN-M5-12): `secmp-relay` (executor, stores, link server) is in the
    /// 8-shard gate with the Amendment 2 floor, every shard's command line names it, and its Kani-only file is kept
    /// out like `secmp-proto`'s; the package builds with feature `kat` like the other two.
    #[test]
    fn mutants_scope_includes_relay() -> Result<()> {
        assert_eq!(
            expect::MUTANT_PACKAGES,
            &["secmp-crypto", "secmp-proto", "secmp-relay"]
        );
        assert_eq!(expect::MUTANT_SHARDS, 8);
        assert_eq!(expect::MUTANT_MIN_CAUGHT_PERCENT, 50);
        assert_eq!(expect::MUTANT_UNVIABLE_WARN_PERCENT, 35);
        assert!(expect::MUTANT_EXCLUDE_FILES.contains(&"crates/secmp-relay/src/kani_proofs.rs"));
        for k in 0..8 {
            let args = mutants_args(Some(MutantsShard { k, n: 8 }));
            assert!(
                args.windows(2)
                    .any(|w| w.first().map(String::as_str) == Some("--package")
                        && w.get(1).map(String::as_str) == Some("secmp-relay")),
                "shard {k}: {args:?}"
            );
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let manifest = std::fs::read_to_string(root.join("crates/secmp-relay/Cargo.toml"))?;
        assert!(
            manifest.contains("\nkat = ["),
            "secmp-relay has feature kat"
        );
        let standards = std::fs::read_to_string(root.join("docs/06-engineering-standards.md"))?;
        assert!(
            standards.contains("`secmp-crypto`, `secmp-proto`, `secmp-relay`"),
            "docs/06 §4 Mutation names the three packages (ADR-047 Am. 3 consequence)"
        );
        Ok(())
    }

    /// `expect::RELAY_TRACE_ALLOW` equals the relay's closed event set (`secmp_relay::event::EVENT_NAMES`, read from
    /// the source), in order and in both directions (OPEN-M5-08; the `policy` step runs the same check; test RL-03
    /// checks the captured events against the list); a missing, an extra and a renamed event are findings.
    #[test]
    fn relay_trace_allow_equals_the_event_names() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        // a Windows checkout has CRLF: the line-anchored edits below need `\n`
        let src = lf(&std::fs::read_to_string(
            root.join("crates/secmp-relay/src/event.rs"),
        )?);
        assert_eq!(
            crate::policy::relay_event_names(&src),
            expect::RELAY_TRACE_ALLOW
        );
        assert_eq!(
            crate::policy::relay_event_findings(&src),
            Vec::<String>::new()
        );
        for bad in [
            src.replace("    \"exit\",\n", ""),
            src.replace("    \"exit\",\n", "    \"exit\",\n    \"request\",\n"),
            src.replace("\"drain_started\"", "\"drain\""),
            String::new(),
        ] {
            assert_eq!(crate::policy::relay_event_findings(&bad).len(), 1);
        }
        Ok(())
    }

    /// ADR-047 Amendment 1 (3), M4 review R-06: the gate builds both packages with `--features kat` (a per-package
    /// `secmp-proto/kat` makes cargo refuse the `secmp-crypto` build), passes the shard through with round-robin
    /// sharding, and skips the tests of `expect::MUTANT_SKIP_TESTS` after `-- --`.
    #[test]
    fn mutants_command_line_builds_with_features_kat() {
        let args = mutants_args(Some(MutantsShard { k: 3, n: 8 }));
        let pair = |a: &str, b: &str| {
            args.windows(2).any(|w| {
                w.first().map(String::as_str) == Some(a) && w.get(1).map(String::as_str) == Some(b)
            })
        };
        assert!(pair("--features", "kat"), "{args:?}");
        assert!(pair("--shard", "3/8"), "{args:?}");
        assert!(pair("--sharding", "round-robin"), "{args:?}");
        assert!(
            !args
                .iter()
                .any(|a| a.contains("secmp-proto/kat") || a.contains("secmp-crypto/kat"))
        );
        assert_eq!(args.iter().filter(|a| *a == "--features").count(), 1);
        for p in expect::MUTANT_PACKAGES {
            assert!(pair("--package", p), "{p}");
        }
        // the skip filters come after `-- --`: cargo-mutants hands the rest to `cargo test`, which hands it to libtest
        let at = args.iter().position(|a| a == "--").unwrap_or(usize::MAX);
        assert_eq!(
            args.get(at.saturating_add(1)).map(String::as_str),
            Some("--")
        );
        let tail: Vec<&str> = args
            .iter()
            .skip(at.saturating_add(2))
            .map(String::as_str)
            .collect();
        let want: Vec<&str> = expect::MUTANT_SKIP_TESTS
            .iter()
            .flat_map(|(t, _)| ["--skip", *t])
            .collect();
        assert_eq!(tail, want);
        // without a shard: no shard arguments
        let all = mutants_args(None);
        assert!(!all.iter().any(|a| a.starts_with("--shard")), "{all:?}");
        assert_eq!(
            MutantsShard::parse("7/8")
                .map(|s| s.to_string())
                .ok()
                .as_deref(),
            Some("7/8")
        );
        assert!(MutantsShard::parse("8/8").is_err() && MutantsShard::parse("3/0").is_err());
    }

    /// One mutant outcome of cargo-mutants 27.1.0's `outcomes.json`.
    fn mutant_outcome(package: &str, i: usize, summary: &str) -> Value {
        let name = format!("crates/{package}/src/lib.rs:{i}:1: replace f{i} with ()");
        serde_json::json!({"scenario": {"Mutant": {"name": name, "package": package,
            "file": format!("crates/{package}/src/lib.rs")}}, "summary": summary})
    }

    /// `caught`, `unviable` and `missed` mutants of `package`.
    fn mutant_outcomes(package: &str, caught: usize, unviable: usize, missed: usize) -> Vec<Value> {
        let kinds = [
            ("CaughtMutant", caught),
            ("Unviable", unviable),
            ("MissedMutant", missed),
        ];
        let mut out = Vec::new();
        for (summary, n) in kinds {
            for _ in 0..n {
                out.push(mutant_outcome(package, out.len(), summary));
            }
        }
        out
    }

    /// ADR-047 Amendment 1 (4), M4 review R-06, with Amendment 2: the floor per package — every `secmp-crypto` mutant
    /// unviable fails naming `secmp-crypto`; 36 % unviable passes with a WARNING line naming the package (re-pointed
    /// from the failure of Amendment 1 (4)); 35 % and a balanced input pass without one; a package without mutants
    /// fails (the unattributable outcomes: `mutants_floor_refuses_unattributable_outcomes`).
    #[test]
    fn mutants_floor_fails_a_package_without_a_caught_mutant() -> Result<()> {
        let floor = |outcomes: Vec<Value>| -> Result<MutantsFloor> {
            Ok(mutants_floor(&mutant_counts(&outcomes)?))
        };
        // every crypto mutant unviable (the R-06 build failure)
        let all_unviable = [
            mutant_outcomes("secmp-crypto", 0, 241, 0),
            mutant_outcomes("secmp-proto", 60, 30, 1),
            mutant_outcomes("secmp-relay", 50, 10, 0),
        ]
        .concat();
        let MutantsFloor {
            lines, failures, ..
        } = floor(all_unviable)?;
        assert!(
            !failures.is_empty() && failures.iter().all(|f| f.starts_with("secmp-crypto: ")),
            "{failures:?}"
        );
        assert!(
            failures.iter().any(|f| f.contains("no caught mutant")),
            "{failures:?}"
        );
        assert!(lines.iter().any(|l| {
            l.starts_with("secmp-crypto: caught 0, missed 0, timeout 0, unviable 241 of 241")
        }));
        // 36 % unviable: a WARNING naming the package, no failure (ADR-047 Amendment 2 (2))
        let f = floor(
            [
                mutant_outcomes("secmp-crypto", 64, 36, 0),
                mutant_outcomes("secmp-proto", 70, 30, 0),
                mutant_outcomes("secmp-relay", 50, 10, 0),
            ]
            .concat(),
        )?;
        assert!(f.failures.is_empty(), "{:?}", f.failures);
        assert_eq!(
            f.warnings,
            vec![
                "WARNING secmp-crypto: unviable 36.0 % > 35 % (36 of 100 mutants, informative, ADR-047 Amendment 2)"
                    .to_owned()
            ]
        );
        let f = floor(
            [
                mutant_outcomes("secmp-crypto", 70, 30, 0),
                mutant_outcomes("secmp-proto", 63, 36, 1),
                mutant_outcomes("secmp-relay", 50, 10, 0),
            ]
            .concat(),
        )?;
        assert!(f.failures.is_empty(), "{:?}", f.failures);
        assert_eq!(
            f.warnings,
            vec![
                "WARNING secmp-proto: unviable 36.0 % > 35 % (36 of 100 mutants, informative, ADR-047 Amendment 2)"
                    .to_owned()
            ]
        );
        // exactly 35 % and a balanced input pass, without a warning
        let f = floor(
            [
                mutant_outcomes("secmp-crypto", 65, 35, 0),
                mutant_outcomes("secmp-proto", 80, 18, 2),
                mutant_outcomes("secmp-relay", 50, 10, 0),
            ]
            .concat(),
        )?;
        assert!(
            f.failures.is_empty() && f.warnings.is_empty(),
            "{:?}",
            f.failures
        );
        assert_eq!(
            f.lines,
            vec![
                "secmp-crypto: caught 65, missed 0, timeout 0, unviable 35 of 100 (caught 65.0 %, at least 50 %, unviable 35.0 %)".to_owned(),
                "secmp-proto: caught 80, missed 2, timeout 0, unviable 18 of 100 (caught 80.0 %, at least 50 %, unviable 18.0 %)".to_owned(),
                "secmp-relay: caught 50, missed 0, timeout 0, unviable 10 of 60 (caught 83.3 %, at least 50 %, unviable 16.7 %)".to_owned(),
            ]
        );
        // a package without any mutant: no caught mutant
        let MutantsFloor { failures, .. } = floor(mutant_outcomes("secmp-proto", 5, 0, 0))?;
        assert_eq!(
            failures,
            vec![
                "secmp-crypto: no caught mutant (of 0)".to_owned(),
                "secmp-relay: no caught mutant (of 0)".to_owned()
            ]
        );
        Ok(())
    }

    /// ADR-047 Amendment 1 (4): a mutant of an unknown package, outside its crate, without a package or with an
    /// unknown outcome cannot be counted.
    #[test]
    fn mutants_floor_refuses_unattributable_outcomes() {
        let mut foreign = mutant_outcome("secmp-ui", 1, "CaughtMutant");
        assert!(mutant_counts(&[foreign.clone()]).is_err());
        if let Some(m) = foreign.pointer_mut("/scenario/Mutant") {
            m["package"] = Value::from("secmp-crypto");
        }
        assert!(
            mutant_counts(&[foreign]).is_err(),
            "file outside crates/secmp-crypto/"
        );
        assert!(mutant_counts(&[mutant_outcome("secmp-proto", 1, "Success")]).is_err());
        let mut nameless = mutant_outcome("secmp-proto", 1, "CaughtMutant");
        if let Some(m) = nameless
            .pointer_mut("/scenario/Mutant")
            .and_then(Value::as_object_mut)
        {
            m.remove("package");
        }
        assert!(mutant_counts(&[nameless]).is_err());
    }

    /// ADR-047 Amendment 1 (5): every test skipped for each mutant is a `#[cfg(feature = "kat")]` test function of
    /// `crates/secmp-proto/src/tr/tests.rs` (so it still runs in the `kat` step), and its name matches no other test
    /// function there (a libtest `--skip` filter is a substring match).
    #[test]
    fn mutants_skip_list_names_existing_tests() -> Result<()> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/secmp-proto/src/tr/tests.rs");
        let text = lf(&std::fs::read_to_string(path)?);
        let lines: Vec<&str> = text.lines().collect();
        assert!(!expect::MUTANT_SKIP_TESTS.is_empty());
        for (name, reason) in expect::MUTANT_SKIP_TESTS {
            assert!(!reason.is_empty(), "{name}");
            let decl = format!("fn {name}(");
            let at: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.trim_start().starts_with(&decl))
                .map(|(i, _)| i)
                .collect();
            let [at] = at.as_slice() else {
                bail!("{name}: {} declarations in tr/tests.rs", at.len());
            };
            // the attributes directly above the function
            let attrs: Vec<&str> = lines
                .get(..*at)
                .unwrap_or_default()
                .iter()
                .rev()
                .take_while(|l| l.trim_start().starts_with("#["))
                .map(|l| l.trim())
                .collect();
            assert!(attrs.contains(&"#[test]"), "{name}: {attrs:?}");
            assert!(
                attrs.contains(&"#[cfg(feature = \"kat\")]"),
                "{name}: {attrs:?}"
            );
            let matching = lines
                .iter()
                .filter(|l| l.trim_start().starts_with("fn ") && l.contains(*name))
                .count();
            assert_eq!(matching, 1, "{name} is a substring of another test name");
        }
        Ok(())
    }

    /// Write the result of shard `k` of `n` under `dir` as the `mutants-shard` job uploads it (`mutants-<k>-1/
    /// mutants.out/`): its verdict file and an `outcomes.json` with the baseline, `outcomes` and the run's own count
    /// `total`.
    fn write_shard(
        dir: &Path,
        (k, n): (usize, usize),
        verdict: &str,
        outcomes: &[Value],
        total: usize,
    ) -> Result<()> {
        let out = dir.join(format!("mutants-{k}-1")).join("mutants.out");
        std::fs::create_dir_all(&out)?;
        std::fs::write(
            out.join(MUTANTS_SHARD_VERDICT),
            serde_json::json!({"shard": format!("{k}/{n}"), "verdict": verdict, "detail": "d"})
                .to_string(),
        )?;
        let mut all = vec![serde_json::json!({"scenario": "Baseline", "summary": "Success"})];
        all.extend(outcomes.iter().cloned());
        std::fs::write(
            out.join("outcomes.json"),
            serde_json::json!({"outcomes": all, "total_mutants": total}).to_string(),
        )?;
        Ok(())
    }

    /// A mutant outcome with the name cargo-mutants prints (`crates/<package>/<file>:<line>:<col>: <description>`).
    fn named_mutant(name: &str, summary: &str) -> Value {
        let file = name.split_once(':').map_or(name, |(f, _)| f);
        let package = file
            .strip_prefix("crates/")
            .and_then(|r| r.split_once('/'))
            .map_or("?", |(p, _)| p);
        serde_json::json!({"scenario": {"Mutant": {"name": name, "package": package, "file": file}},
            "summary": summary})
    }

    /// An empty scratch directory for shard results, and one for the merged output, both under the temp dir.
    fn merge_dirs(label: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "secmp-xtask-mutants-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        (base.join("shards"), base.join("merged"))
    }

    /// `docs/mutants-accepted.md` as committed.
    fn accepted_survivors() -> Result<String> {
        Ok(lf(&std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/mutants-accepted.md"),
        )?))
    }

    /// ADR-047 Amendment 1 (2), with Amendment 2 (3): the merge needs exactly one result per shard, each with a PASS
    /// verdict of its own shard and a complete `outcomes.json`, and counts every package over all shards; a missing
    /// shard, a failed shard, an incomplete `outcomes.json` and a shard labelled for another run are failures naming
    /// the shard (re-pointed from an early error to the merged failures: every shard is read first).
    #[test]
    fn mutants_merge_needs_every_shard_with_a_pass_verdict() -> Result<()> {
        let (dir, _) = merge_dirs("needs");
        let crypto = mutant_outcomes("secmp-crypto", 3, 1, 0);
        let proto = mutant_outcomes("secmp-proto", 3, 1, 0);
        write_shard(&dir, (0, 2), "PASS", &crypto, 4)?;
        write_shard(&dir, (1, 2), "PASS", &proto, 4)?;
        let merged = merge_mutant_shards(&dir, 2)?;
        assert!(merged.failures.is_empty(), "{:?}", merged.failures);
        assert_eq!(merged.outcomes.len(), 8);
        let counts = mutant_counts(&merged.outcomes)?;
        assert_eq!(counts.get("secmp-crypto").map(|c| c.caught), Some(3));
        // a missing shard, a failed shard, a shard with an incomplete outcomes.json, a third shard
        let failures =
            |n: usize| -> Result<Vec<String>> { Ok(merge_mutant_shards(&dir, n)?.failures) };
        assert_eq!(
            failures(3)?,
            vec![
                "shard 0/3: verdict PASS for shard 0/2: d".to_owned(),
                "shard 1/3: verdict PASS for shard 1/2: d".to_owned(),
                "shard 2/3: 0 result directories (exactly one expected)".to_owned()
            ]
        );
        write_shard(&dir, (1, 2), "FAIL", &proto, 4)?;
        assert_eq!(
            failures(2)?,
            vec!["shard 1/2: verdict FAIL for shard 1/2: d".to_owned()]
        );
        write_shard(&dir, (1, 2), "PASS", &proto, 5)?;
        let found = failures(2)?;
        assert!(
            found.len() == 1 && found.iter().all(|f| f.contains("an incomplete run")),
            "{found:?}"
        );
        write_shard(&dir, (1, 2), "PASS", &proto, 4)?;
        write_shard(&dir, (0, 3), "PASS", &crypto, 4)?;
        assert_eq!(
            failures(2)?,
            vec!["shard 0/2: verdict PASS for shard 0/3: d".to_owned()],
            "shard 0 says 0/3"
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(merge_mutant_shards(&dir, 2).is_err(), "nothing downloaded");
        Ok(())
    }

    /// ADR-047 Amendment 2 (1): a package that caught fewer than half of its generated mutants fails the merge naming
    /// the package and its caught share (40 caught, 0 missed, 60 unviable: 40.0 %).
    #[test]
    fn mutants_merge_fails_when_the_caught_share_is_below_half() -> Result<()> {
        let (dir, out) = merge_dirs("below-half");
        write_shard(
            &dir,
            (0, 8),
            "PASS",
            &mutant_outcomes("secmp-crypto", 40, 60, 0),
            100,
        )?;
        write_shard(
            &dir,
            (1, 8),
            "PASS",
            &mutant_outcomes("secmp-proto", 80, 20, 0),
            100,
        )?;
        write_shard(
            &dir,
            (2, 8),
            "PASS",
            &mutant_outcomes("secmp-relay", 50, 10, 0),
            60,
        )?;
        for k in 3..8 {
            write_shard(&dir, (k, 8), "PASS", &[], 0)?;
        }
        let v = merge_verdict(&dir, 8, &accepted_survivors()?, &out)?;
        assert_eq!(
            v.failures,
            vec!["secmp-crypto: caught 40 of 100 mutants (40.0 %) is below 50 %".to_owned()]
        );
        let text = v.lines.join("; ");
        assert!(
            text.contains(
                "secmp-crypto: caught 40, missed 0, timeout 0, unviable 60 of 100 (caught 40.0 %, at least 50 %, \
                 unviable 60.0 %)"
            ),
            "{text}"
        );
        assert!(
            text.contains("FAIL secmp-crypto: caught 40 of 100 mutants (40.0 %) is below 50 %")
        );
        let _ = std::fs::remove_dir_all(dir.parent().unwrap_or(&dir));
        Ok(())
    }

    /// ADR-047 Amendment 2 (1), (2): the `secmp-crypto` tally of PR run 37127247911 — 168 caught, 1 missed (the
    /// accepted `SecretBytes` drop), 99 unviable — passes with the WARNING "unviable 36.9 % > 35 %"; the `secmp-proto`
    /// tally (727 caught, its 3 accepted equivalent mutants, 294 unviable: 28.7 %) passes without one (with a
    /// `secmp-relay` tally beside them since ADR-047 Amendment 3).
    #[test]
    fn mutants_merge_passes_the_crypto_tally_of_run_37127247911() -> Result<()> {
        let (dir, out) = merge_dirs("run-37127247911");
        let mut crypto = mutant_outcomes("secmp-crypto", 168, 99, 0);
        crypto.push(named_mutant(
            "crates/secmp-crypto/src/secret.rs:59:9: replace <impl Drop for SecretBytes<N>>::drop with ()",
            "MissedMutant",
        ));
        let mut proto = mutant_outcomes("secmp-proto", 727, 294, 0);
        for name in [
            "crates/secmp-proto/src/inv.rs:202:34: replace | with ^ in base64url_decode",
            "crates/secmp-proto/src/inv.rs:163:44: replace | with ^ in base64url_encode",
            "crates/secmp-proto/src/inv.rs:163:32: replace | with ^ in base64url_encode",
        ] {
            proto.push(named_mutant(name, "MissedMutant"));
        }
        write_shard(&dir, (0, 8), "PASS", &crypto, 268)?;
        write_shard(&dir, (1, 8), "PASS", &proto, 1024)?;
        write_shard(
            &dir,
            (2, 8),
            "PASS",
            &mutant_outcomes("secmp-relay", 50, 10, 0),
            60,
        )?;
        for k in 3..8 {
            write_shard(&dir, (k, 8), "PASS", &[], 0)?;
        }
        let v = merge_verdict(&dir, 8, &accepted_survivors()?, &out)?;
        assert!(v.failures.is_empty(), "{:?}", v.failures);
        let warnings: Vec<&String> = v
            .lines
            .iter()
            .filter(|l| l.starts_with("WARNING"))
            .collect();
        assert_eq!(
            warnings,
            vec![
                "WARNING secmp-crypto: unviable 36.9 % > 35 % (99 of 268 mutants, informative, ADR-047 Amendment 2)"
            ]
        );
        assert!(v.lines.contains(
            &"secmp-crypto: caught 168, missed 1, timeout 0, unviable 99 of 268 (caught 62.7 %, at least 50 %, \
              unviable 36.9 %)"
                .to_owned()
        ));
        assert!(v.lines.contains(
            &"survivors documented in docs/mutants-accepted.md: 4, undocumented: 0".to_owned()
        ));
        let summary = std::fs::read_to_string(out.join("summary.txt"))?;
        assert!(summary.contains("WARNING secmp-crypto: unviable 36.9 % > 35 %"));
        let _ = std::fs::remove_dir_all(dir.parent().unwrap_or(&dir));
        Ok(())
    }

    /// ADR-047 Amendment 2 (3): with shards 5 and 7 each failed on an unaccepted survivor (the two `Profile::eq`
    /// mutants of PR run 37127247911) and six passing, the merge reads every shard and both packages before it fails:
    /// its verdict text names both shards, both package tallies and both survivors with their package.
    #[test]
    fn mutants_merge_reports_every_shard_and_package_before_it_fails() -> Result<()> {
        let (dir, out) = merge_dirs("every-shard");
        let survivors = [
            (
                5,
                "crates/secmp-proto/src/wire/inv.rs:327:9: replace <impl PartialEq for Profile>::eq -> bool with true",
            ),
            (
                7,
                "crates/secmp-proto/src/wire/inv.rs:327:35: replace && with || in <impl PartialEq for Profile>::eq",
            ),
        ];
        for k in 0..8 {
            let mut outcomes = [
                mutant_outcomes("secmp-crypto", 20, 10, 0),
                mutant_outcomes("secmp-proto", 90, 30, 0),
                mutant_outcomes("secmp-relay", 10, 2, 0),
            ]
            .concat();
            let failed = survivors.iter().find(|(s, _)| *s == k);
            if let Some((_, name)) = failed {
                outcomes.push(named_mutant(name, "MissedMutant"));
            }
            let total = outcomes.len();
            write_shard(
                &dir,
                (k, 8),
                if failed.is_some() { "FAIL" } else { "PASS" },
                &outcomes,
                total,
            )?;
        }
        let v = merge_verdict(&dir, 8, &accepted_survivors()?, &out)?;
        let text = format!("mutants-merge: {}", v.lines.join("; "));
        for k in 0..8 {
            let state = if k == 5 || k == 7 { "FAIL" } else { "PASS" };
            assert!(
                text.contains(&format!("shard {k}/8: {state} — ")),
                "{k}: {text}"
            );
        }
        for needle in [
            "secmp-crypto: caught 160, missed 0, timeout 0, unviable 80 of 240 (caught 66.7 %",
            "secmp-proto: caught 720, missed 2, timeout 0, unviable 240 of 962 (caught 74.8 %",
            "FAIL shard 5/8: verdict FAIL for shard 5/8: d",
            "FAIL shard 7/8: verdict FAIL for shard 7/8: d",
            "FAIL secmp-proto: survivor not in docs/mutants-accepted.md: crates/secmp-proto/src/wire/inv.rs:327:9: \
             replace <impl PartialEq for Profile>::eq -> bool with true",
            "FAIL secmp-proto: survivor not in docs/mutants-accepted.md: crates/secmp-proto/src/wire/inv.rs:327:35: \
             replace && with || in <impl PartialEq for Profile>::eq",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert_eq!(v.failures.len(), 4, "{:?}", v.failures);
        let _ = std::fs::remove_dir_all(dir.parent().unwrap_or(&dir));
        Ok(())
    }

    /// A Kani log verifying `names`, with the summary line Kani prints.
    fn kani_log(names: &[&str], failures: usize) -> String {
        let harnesses: Vec<String> = names
            .iter()
            .map(|n| {
                format!(
                    "Checking harness {n}...\nVERIFICATION:- SUCCESSFUL\nVerification Time: 1.0s\n"
                )
            })
            .collect();
        let summary = format!(
            "Complete - {} successfully verified harnesses, {failures} failures, {} total.\n",
            names.len(),
            names.len().saturating_add(failures)
        );
        [harnesses.concat(), summary].concat()
    }

    /// M4 review C-15 (R-34): a cover that Kani reports as UNSATISFIABLE (or UNREACHABLE, or a summary with fewer
    /// satisfied than there are) fails the gate, naming the harness; SATISFIED covers pass and are listed per harness.
    #[test]
    fn kani_gate_fails_on_an_unsatisfiable_cover() -> Result<()> {
        let cover = |status: &str, satisfied: usize| {
            format!(
                "Checking harness kani_proofs::kani_commit_accept_atomic...\nCheck 1: kani_proofs::kani_commit_accept_atomic.assertion.1\n\t - Status: SUCCESS\nCheck 7: kani_proofs::kani_commit_accept_atomic.cover.1\n\t - Status: {status}\n\t - Description: \"a commit\"\n\nSUMMARY:\n ** 0 of 7 failed\n\n ** {satisfied} of 1 cover properties satisfied\n\nVERIFICATION:- SUCCESSFUL\nVerification Time: 1.0s\n"
            )
        };
        let mut good = kani_log(expect::KANI_HARNESSES, 0);
        good.push_str(&cover("SATISFIED", 1));
        assert_eq!(
            kani_covers(&good)?,
            vec!["kani_proofs::kani_commit_accept_atomic: 1 of 1 satisfied".to_owned()]
        );
        for (status, satisfied) in [("UNSATISFIABLE", 0), ("UNREACHABLE", 0)] {
            let bad = format!(
                "{}{}",
                kani_log(expect::KANI_HARNESSES, 0),
                cover(status, satisfied)
            );
            let got = kani_covers(&bad);
            assert!(
                got.as_ref()
                    .is_err_and(|e| e.0.contains("kani_proofs::kani_commit_accept_atomic")
                        && e.0.contains(status)),
                "{status}: {got:?}"
            );
        }
        // the summary alone, with a status line Kani did not print (terse output)
        let terse = "Checking harness kani_proofs::kani_accept_opk_delete_only_on_success...\n ** 0 of 1 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n";
        assert!(
            kani_covers(terse)
                .is_err_and(|e| e.0.contains("kani_accept_opk_delete_only_on_success"))
        );
        // a log without any cover is no failure of the parser; the gate fails it through `expect::KANI_COVERS`
        // (`kani_cover_pin_findings`, delta review VD1-5)
        let none = kani_covers(&kani_log(expect::KANI_HARNESSES, 0))?;
        assert!(none.is_empty());
        assert!(!kani_cover_pin_findings(&none).is_empty());
        Ok(())
    }

    /// M4 delta review VD1-5: the number of covers is pinned (`expect::KANI_COVERS`: as many as `kani_proofs.rs` has,
    /// each on a known harness); the committed Kani log matches it; a deleted or an added cover is a finding; a
    /// summary with Kani's `(K unreachable)` suffix fails the cover check.
    #[test]
    fn kani_cover_count_is_pinned() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut source = String::new();
        for file in [
            "crates/secmp-proto/src/kani_proofs.rs",
            "crates/secmp-relay/src/kani_proofs.rs",
        ] {
            source.push_str(&lf(&std::fs::read_to_string(root.join(file))?));
        }
        let pinned: usize = expect::KANI_COVERS.iter().map(|(_, m)| m).sum();
        assert_eq!(source.matches("kani::cover!(").count(), pinned);
        for (h, _) in expect::KANI_COVERS {
            assert!(expect::KANI_HARNESSES.contains(h), "{h}");
        }
        let mut log = lf(&std::fs::read_to_string(
            root.join("docs/reviews/M05-evidence/kani-xtask-step-ae10972.txt"),
        )?);
        // M5 Phase B: the committed runs of the relay harnesses (TEST-SPEC-M5 K-05…K-07)
        for h in [
            "kani_cmd_seq_monotone",
            "kani_executor_response_count",
            "kani_queue_eviction_bounds",
        ] {
            log.push_str(&lf(&std::fs::read_to_string(
                root.join(format!("docs/reviews/M05-evidence/kani-m5b-{h}.txt")),
            )?));
        }
        assert_eq!(
            kani_cover_pin_findings(&kani_covers(&log)?),
            Vec::<String>::new()
        );
        let summary = "** 1 of 1 cover properties satisfied";
        // a cover deleted: its harness prints no summary
        let deleted = log.replacen(summary, "", 1);
        assert_eq!(kani_cover_pin_findings(&kani_covers(&deleted)?).len(), 1);
        // a cover added: "2 of 2" is not the pinned "1 of 1"
        let added = log.replacen(summary, "** 2 of 2 cover properties satisfied", 1);
        assert_eq!(kani_cover_pin_findings(&kani_covers(&added)?).len(), 2);
        // the unreachable suffix, with and without a short count
        for line in [
            "** 1 of 2 cover properties satisfied (1 unreachable)",
            "** 1 of 1 cover properties satisfied (1 unreachable)",
        ] {
            let got = kani_covers(&log.replacen(summary, line, 1));
            assert!(
                got.as_ref().is_err_and(|e| e.0.contains("(1 unreachable)")),
                "{line}: {got:?}"
            );
        }
        Ok(())
    }

    /// M2 review C5: Kani must verify exactly the harnesses of `expect::KANI_HARNESSES`.
    #[test]
    fn kani_refuses_fifteen_harnesses() -> Result<()> {
        let all = expect::KANI_HARNESSES;
        // M5 Phase B: 30 + the three relay harnesses (TEST-SPEC-M5 K-05…K-07)
        assert_eq!(all.len(), 33);
        assert_eq!(kani_verified(&kani_log(all, 0))?.len(), 33);
        // a deleted harness: 18 verified, and Kani's own summary says 18 of 18
        let fifteen = all.get(1..).unwrap_or_default();
        assert!(kani_verified(&kani_log(fifteen, 0)).is_err());
        // a renamed harness, a failure, a harness counted twice, no summary
        let renamed: Vec<&str> = fifteen
            .iter()
            .copied()
            .chain(["kani_proofs::renamed"])
            .collect();
        assert!(kani_verified(&kani_log(&renamed, 0)).is_err());
        assert!(kani_verified(&kani_log(all, 1)).is_err());
        let twice: Vec<&str> = fifteen
            .iter()
            .copied()
            .chain(fifteen.first().copied())
            .collect();
        assert!(kani_verified(&kani_log(&twice, 0)).is_err());
        let no_summary = kani_log(all, 0).replace("Complete - ", "Done - ");
        assert!(kani_verified(&no_summary).is_err());
        Ok(())
    }

    /// M4 review C-6 (R-07): every fuzz target has a tracked seed corpus (`fuzz/corpus/<t>/` with at least one file),
    /// the directory the fuzz gate passes as libFuzzer's second corpus; without the `hx_outer` seeds the check names it.
    #[test]
    fn fuzz_corpus_exists_for_every_target() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let corpus = root.join("fuzz").join("corpus");
        assert_eq!(
            targets_without_corpus(&corpus, expect::FUZZ_TARGETS),
            Vec::<String>::new()
        );
        // every hx_outer seed is a padded `Outer` of exactly 12018 bytes
        let seeds: Vec<PathBuf> = std::fs::read_dir(corpus.join("hx_outer"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        assert!(!seeds.is_empty());
        for f in &seeds {
            assert_eq!(std::fs::metadata(f)?.len(), 12_018, "{}", f.display());
        }
        // a copy of the corpus layout without the hx_outer seeds fails naming hx_outer
        let dir =
            std::env::temp_dir().join(format!("secmp-xtask-fuzz-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for t in expect::FUZZ_TARGETS {
            std::fs::create_dir_all(dir.join(t))?;
            if *t != "hx_outer" {
                std::fs::write(dir.join(t).join("seed"), [0_u8])?;
            }
        }
        assert_eq!(
            targets_without_corpus(&dir, expect::FUZZ_TARGETS),
            vec!["hx_outer".to_owned()]
        );
        std::fs::remove_dir_all(dir.join("hx_outer"))?;
        assert_eq!(
            targets_without_corpus(&dir, expect::FUZZ_TARGETS),
            vec!["hx_outer".to_owned()]
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// M2 review C4: every fuzz target has a `-max_len`, and nothing else does.
    #[test]
    fn fuzz_max_len_covers_every_target() -> Result<()> {
        let targets: BTreeSet<&str> = expect::FUZZ_TARGETS.iter().copied().collect();
        let with_len: BTreeSet<&str> = expect::FUZZ_MAX_LEN.iter().map(|(t, _)| *t).collect();
        assert_eq!(targets, with_len);
        assert_eq!(expect::FUZZ_MAX_LEN.len(), expect::FUZZ_TARGETS.len());
        assert_eq!(fuzz_max_len("proto_cell")?, 65_644);
        assert!(fuzz_max_len("unknown").is_err());
        Ok(())
    }

    /// M2 review F7, F18: the exact `cargo fuzz run` arguments — the scratch corpus first (libFuzzer writes new
    /// inputs only there), the tracked corpus second, the time budget and the target's `-max_len`.
    #[test]
    fn fuzz_command_line() -> Result<()> {
        assert_eq!(
            fuzz_args("proto_cell", expect::FUZZ_SMOKE_SECONDS)?,
            [
                "fuzz",
                "run",
                "--fuzz-dir",
                "fuzz",
                "proto_cell",
                "target/fuzz-corpus/proto_cell",
                "fuzz/corpus/proto_cell",
                "--",
                "-max_total_time=120",
                "-max_len=65644",
                "-timeout=60",
            ]
        );
        for (t, max_len) in expect::FUZZ_MAX_LEN {
            let args = fuzz_args(t, 1200)?;
            assert_eq!(
                args.get(5..7),
                Some(
                    [
                        format!("target/fuzz-corpus/{t}"),
                        format!("fuzz/corpus/{t}")
                    ]
                    .as_slice()
                )
            );
            assert_eq!(
                args.get(8..),
                Some(
                    [
                        "-max_total_time=1200".to_owned(),
                        format!("-max_len={max_len}"),
                        "-timeout=60".to_owned()
                    ]
                    .as_slice()
                )
            );
        }
        assert!(fuzz_args("unknown", 120).is_err());
        Ok(())
    }

    /// The checks of `the_nightly_workflow` on one text of `fuzz-nightly.yml`. Line endings are normalised first: the
    /// Windows runner checks the repository out with CRLF (`core.autocrlf`), so `include_str!` holds `\r\n` there and a
    /// multi-line needle written with `\n` would never match (PR run 36800231503, `windows-native`).
    fn check_nightly(text: &str) {
        let nightly = text.replace("\r\n", "\n");
        assert!(workflow_findings("fuzz-nightly.yml", &nightly).is_empty());
        let files = vec![
            (
                expect::REQUIRED_WORKFLOW.to_owned(),
                lf(include_str!("../../.github/workflows/ci.yml")),
            ),
            (
                ".github/workflows/fuzz-nightly.yml".to_owned(),
                nightly.clone(),
            ),
        ];
        assert!(required_job_findings(&files).is_empty());
        assert_eq!(job_names(&nightly), vec!["fuzz-nightly".to_owned()]);
        for needle in [
            "on:\n  schedule:\n",
            "  workflow_dispatch:\n",
            "permissions:\n  contents: read\n",
            "SECMP_PROPTEST_SEED: ${{ github.run_id }}",
            "cargo nextest run --locked -p secmp-proto --features kat\n",
            "run: cargo xtask step --strict fuzz-nightly",
            "path: target/fuzz-corpus/",
            "path: fuzz/artifacts/",
        ] {
            assert!(nightly.contains(needle), "{needle}");
        }
        assert!(!nightly.contains("pull_request") && !nightly.contains("push:"));
        let timeout: Option<u64> = nightly
            .lines()
            .find_map(|l| l.trim().strip_prefix("timeout-minutes:"))
            .and_then(|m| m.trim().parse().ok());
        assert!(
            timeout
                .is_some_and(|m| m >= 300 && m.saturating_mul(60) > expect::FUZZ_NIGHTLY_SECONDS),
            "{timeout:?}"
        );
    }

    /// M2 review F2, F10: the committed `fuzz-nightly.yml` passes the workflow hygiene, is no required check (one job,
    /// `fuzz-nightly`), runs on a schedule and on dispatch only, runs the campaign step and the property tests with a
    /// fresh seed, and has the time for a 4 h campaign — with the checkout's line endings on every host: the file as
    /// compiled in, and the same file with CRLF line endings as a Windows checkout has it (M3 review C1).
    #[test]
    fn the_nightly_workflow() {
        let nightly = include_str!("../../.github/workflows/fuzz-nightly.yml");
        check_nightly(nightly);
        let crlf = nightly.replace("\r\n", "\n").replace('\n', "\r\n");
        assert!(crlf.contains("on:\r\n  schedule:\r\n"));
        check_nightly(&crlf);
    }

    /// M4 review C-4 (R-14): every job of `ci-dispatch.yml` runs exactly the `cargo xtask` gate lines of its `ci.yml`
    /// counterpart — `dispatch-full` the pinned `linux-full` line of `expect::REQUIRED_GATE_RUNS` (with the delegations
    /// to `ct`, `mutants` and `proverif-hx`), and each delegated job has its dispatch twin.
    #[test]
    fn dispatch_full_runs_the_linux_full_line() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let ci = lf(&std::fs::read_to_string(
            root.join(".github/workflows/ci.yml"),
        )?);
        let dispatch = lf(&std::fs::read_to_string(
            root.join(".github/workflows/ci-dispatch.yml"),
        )?);
        let gate_lines = |text: &str, job: &str| -> Vec<String> {
            yaml_jobs(text)
                .into_iter()
                .filter(|j| j.id == job)
                .flat_map(|j| j.steps.into_iter().flatten())
                .filter(|(k, v)| k == "run" && is_gate_run(v))
                .map(|(_, v)| v)
                .collect()
        };
        let pinned: Vec<String> = expect::REQUIRED_GATE_RUNS
            .iter()
            .find(|(j, _)| *j == "linux-full")
            .map(|(_, lines)| lines.iter().map(|l| (*l).to_owned()).collect())
            .unwrap_or_default();
        assert_eq!(pinned.len(), 1);
        assert_eq!(gate_lines(&dispatch, "dispatch-full"), pinned);
        for (twin, job) in [
            ("dispatch-fast", "linux-fast"),
            ("dispatch-windows", "windows-native"),
            ("dispatch-xwin", "xwin-cross"),
            ("dispatch-full", "linux-full"),
            ("dispatch-ct", "ct"),
            ("dispatch-mutants-shard", "mutants-shard"),
            ("dispatch-mutants", "mutants"),
            ("dispatch-proverif-hx", "proverif-hx"),
            ("dispatch-proverif-link", "proverif-link"),
        ] {
            let lines = gate_lines(&ci, job);
            assert!(!lines.is_empty(), "{job}: no gate line in ci.yml");
            assert_eq!(gate_lines(&dispatch, twin), lines, "{twin} vs {job}");
        }
        // every delegation of the linux-full line has its job in both workflows
        for line in &pinned {
            for d in line.split("--delegated ").skip(1) {
                let step = d.split_whitespace().next().unwrap_or_default();
                let job = match step {
                    "windows-native" => "windows-native",
                    "windows-cross" => "xwin-cross",
                    other => other,
                };
                assert!(
                    !gate_lines(&ci, job).is_empty(),
                    "{step}: no job {job} in ci.yml"
                );
            }
        }
        Ok(())
    }

    /// A package of `cargo metadata` with a library and the given test targets (name, required features).
    fn fake_package(name: &str, tests: &[(&str, &[&str])]) -> crate::meta::Package {
        let target = |n: &str, kind: &str, features: &[&str]| crate::meta::Target {
            name: n.to_owned(),
            kinds: vec![kind.to_owned()],
            src_path: PathBuf::from(format!("/w/{n}.rs")),
            required_features: features.iter().map(|f| (*f).to_owned()).collect(),
        };
        crate::meta::Package {
            id: format!("{name}#0.0.0"),
            name: name.to_owned(),
            manifest_path: PathBuf::from("/w/Cargo.toml"),
            targets: std::iter::once(target(name, "lib", &[]))
                .chain(tests.iter().map(|(n, f)| target(n, "test", f)))
                .collect(),
            features: BTreeSet::new(),
            kani_unstable: Vec::new(),
        }
    }

    /// M4 review C-4 (R-12): the test targets with `required-features` that Miri cannot build must be exactly the
    /// package's entries of `expect::MIRI_FEATURE_GATED` — an unlisted gated target, a listed target without
    /// `required-features` and a listed target that does not exist are refused; the real workspace matches the list.
    #[test]
    fn miri_feature_gated_targets_are_listed() -> Result<()> {
        let package = fake_package("p", &[("plain", &[]), ("gated", &["kat"])]);
        let reason = "required-features";
        assert_eq!(
            miri_test_targets(&package, &[("p", "gated", reason)])?,
            vec!["plain".to_owned()]
        );
        // a gated target nobody listed
        let got = miri_test_targets(&package, &[]);
        assert!(
            got.as_ref()
                .is_err_and(|e| e.0.contains("not listed: [\"gated\"]")),
            "{got:?}"
        );
        // a listed target that has no required-features, and one that does not exist
        assert!(
            miri_test_targets(&package, &[("p", "gated", reason), ("p", "plain", reason)]).is_err()
        );
        assert!(
            miri_test_targets(&package, &[("p", "gated", reason), ("p", "gone", reason)]).is_err()
        );
        // another package's entries do not count
        assert!(miri_test_targets(&package, &[("q", "gated", reason)]).is_err());
        // the workspace: every package of MIRI_PACKAGES matches, and every entry names one of them
        let ws = crate::meta::Workspace::load()?;
        for p in expect::MIRI_PACKAGES {
            let member = ws
                .member(p)
                .ok_or_else(|| Error(format!("{p} is not a workspace member")))?;
            miri_test_targets(member, expect::MIRI_FEATURE_GATED)?;
        }
        for (p, t, why) in expect::MIRI_FEATURE_GATED {
            assert!(expect::MIRI_PACKAGES.contains(p), "{p} {t}");
            assert!(!why.is_empty(), "{p} {t}");
        }
        Ok(())
    }

    /// M2 review F3: Miri runs per package, each with only its own skip filters; a `test-target:` entry leaves out
    /// that integration-test target (the rest by explicit selection, doctests in their own run) and must name an
    /// existing one; every entry of `expect.rs` names a Miri package and carries a reason.
    #[test]
    fn miri_runs_each_package_with_its_own_filters() -> Result<()> {
        let skip = [
            ("secmp-crypto", "mldsa::", "slow"),
            ("secmp-proto", "wire::cell::tests::x", "slow"),
            ("secmp-proto", "test-target:props", "slow"),
        ];
        let head = |extra: &[&str]| -> Vec<String> {
            [
                "miri",
                "test",
                "--locked",
                "--target",
                expect::MIRI_TARGET,
                "--package",
                "secmp-proto",
            ]
            .iter()
            .chain(extra)
            .map(|s| (*s).to_owned())
            .collect()
        };
        let tail = ["--", "--skip", "wire::cell::tests::x"].map(str::to_owned);
        let targets = ["a".to_owned(), "props".to_owned(), "b".to_owned()];
        assert_eq!(
            miri_runs("secmp-proto", &targets, true, &skip)?,
            vec![
                [
                    head(&["--lib", "--bins", "--test", "a", "--test", "b"]),
                    tail.to_vec()
                ]
                .concat(),
                [head(&["--doc"]), tail.to_vec()].concat(),
            ]
        );
        // without an excluded target: one run over the default targets
        let names_only = [("secmp-proto", "wire::cell::tests::x", "slow")];
        assert_eq!(
            miri_runs("secmp-proto", &targets, true, &names_only)?,
            vec![[head(&[]), tail.to_vec()].concat()]
        );
        // another package's filters do not apply; a missing test target is refused
        assert_eq!(
            miri_runs("secmp-sys-mem", &[], true, &skip)?
                .first()
                .and_then(|r| r.last())
                .map(String::as_str),
            Some("--")
        );
        assert!(miri_runs("secmp-proto", &["a".to_owned()], true, &skip).is_err());
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (p, f, reason) in expect::MIRI_SKIP.iter().chain(expect::MIRI_UNSUPPORTED) {
            assert!(expect::MIRI_PACKAGES.contains(p), "{p}");
            assert!(!f.is_empty() && !reason.is_empty(), "{p} {f}");
            if let Some(t) = f.strip_prefix(MIRI_TEST_TARGET) {
                let file = root
                    .join("crates")
                    .join(p)
                    .join("tests")
                    .join(format!("{t}.rs"));
                assert!(file.exists(), "{}", file.display());
            }
        }
        Ok(())
    }

    /// M2 review F2: the campaign's budget is shared equally by the targets, and never below the per-PR smoke.
    #[test]
    fn nightly_budget_per_target() -> Result<()> {
        assert_eq!(expect::FUZZ_NIGHTLY_SECONDS, 14_400);
        assert_eq!(
            nightly_seconds_per_target(expect::FUZZ_NIGHTLY_SECONDS, expect::FUZZ_TARGETS.len())?,
            // M5 Phase B: 29 targets (the two relay targets FZ-07, FZ-08), 496 s each
            14_400 / 29
        );
        assert_eq!(nightly_seconds_per_target(14_400, 14)?, 1028);
        assert!(nightly_seconds_per_target(14_400, 0).is_err());
        assert!(nightly_seconds_per_target(14_400, 121).is_err());
        assert_eq!(nightly_seconds_per_target(14_400, 120)?, 120);
        Ok(())
    }

    /// The M3 final ct report (`linux-full` dispatch 36840478213) as read, and with `site` and `precheck` written into
    /// every result as the bench writes them since M4 (M3 review R-45): `sites` lists (target, site, pre-check
    /// passed); every other target gets `null` for both.
    fn ct_report_with_sites(sites: &[(&str, &str, bool)]) -> Result<(String, String)> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/reviews/M03-evidence/ct-report-linux-dispatch-36840478213.json");
        let plain = std::fs::read_to_string(&path).map_err(|e| Error(e.to_string()))?;
        let mut v: Value = serde_json::from_str(&plain).map_err(|e| Error(e.to_string()))?;
        let results = v
            .get_mut("results")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| Error("ct report: no results".to_owned()))?;
        for r in results.iter_mut() {
            let name = r
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_owned();
            let claim = sites.iter().find(|(n, _, _)| *n == name);
            let r = r
                .as_object_mut()
                .ok_or_else(|| Error("ct report: a result is no object".to_owned()))?;
            r.insert(
                "site".to_owned(),
                claim.map_or(Value::Null, |(_, site, _)| Value::from(*site)),
            );
            r.insert(
                "precheck".to_owned(),
                claim.map_or(Value::Null, |(_, _, passed)| {
                    serde_json::json!({"check": "Err(Rejected) only: no reject-site tag on this path",
                        "passed": passed, "fixtures": 5, "expected": ["Err(Rejected)", "Err(Rejected)"],
                        "observed": ["Err(Rejected)", "Err(Rejected)"], "twin": null})
                }),
            );
        }
        Ok((plain, v.to_string()))
    }

    /// The M3 TR targets and the same-content control with a site each (all pre-checks passed).
    const M3_SITES: [(&str, &str, bool); 4] = [
        ("tr_decrypt_reject_hdr_key", "header: no key opened", true),
        ("tr_decrypt_reject_body_tag", "body MAC", true),
        ("tr_decrypt_reject_ct_pq", "kem constancy", true),
        ("same_content_control", "body MAC", true),
    ];

    /// M3 review R-45 (F19): the gate's report reader (`ctreport::ct_table`, unchanged) accepts the `site` and
    /// `precheck` fields of every result and reads the report exactly as without them.
    #[test]
    fn the_ct_reader_accepts_site_and_precheck() -> Result<()> {
        let (plain, with) = ct_report_with_sites(&M3_SITES)?;
        let (a, b) = (ctreport::ct_table(&plain)?, ctreport::ct_table(&with)?);
        assert_eq!(a.lines, b.lines);
        assert_eq!(a.failed, b.failed);
        assert_eq!(a.not_measurable, b.not_measurable);
        assert!(!b.lines.is_empty());
        Ok(())
    }

    /// M3 review R-45 (F19), ADR-045: each claimed site is appended to its target's verdict segment, which is one row
    /// of the step summary; every other line is unchanged.
    #[test]
    fn ct_sites_go_on_the_verdict_row() -> Result<()> {
        let (_, json) = ct_report_with_sites(&M3_SITES)?;
        let table = ctreport::ct_table(&json)?;
        let (lines, problems) = ct_site_lines(&json, &table.lines)?;
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(lines.len(), table.lines.len());
        let line = lines
            .iter()
            .find(|l| l.starts_with("tr_decrypt_reject_body_tag: PASS"))
            .ok_or_else(|| Error("no body-tag line".to_owned()))?;
        let (head, _) = line
            .split_once("; ")
            .ok_or_else(|| Error("one segment only".to_owned()))?;
        assert!(head.ends_with(" — site body MAC"), "{head}");
        let rows = crate::summary::step_rows("PASS", 1, &lines.join("; "));
        assert!(
            rows.iter()
                .any(|(_, r)| r.starts_with("tr_decrypt_reject_body_tag: PASS")
                    && r.ends_with(" — site body MAC"))
        );
        let changed = lines.iter().zip(&table.lines).filter(|(a, b)| a != b);
        assert_eq!(changed.count(), M3_SITES.len());
        Ok(())
    }

    /// M3 review R-45 (F19): a site without a passed pre-check, and a pre-checked target without a site, fail the gate.
    #[test]
    fn ct_sites_need_a_passed_precheck() -> Result<()> {
        let mut failed = M3_SITES;
        if let Some(body) = failed.get_mut(1) {
            body.2 = false;
        }
        let (plain, json) = ct_report_with_sites(&failed)?;
        let (_, problems) = ct_site_lines(&json, &[])?;
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems
                .iter()
                .all(|p| p.contains("tr_decrypt_reject_body_tag")
                    && p.contains("without a passed per-class pre-check"))
        );
        // the M3 report itself: four pre-checked targets without a site
        let (_, problems) = ct_site_lines(&plain, &[])?;
        assert_eq!(problems.len(), M3_SITES.len(), "{problems:?}");
        assert!(problems.iter().all(|p| p.contains("has no reject site")));
        Ok(())
    }

    /// M4 review R-63: a target whose claimed site is in no `KNOWN_SITES` entry fails the gate, naming target and
    /// site; every site in the list is a known site — accepted where `expect::CT_TARGET_SITES` binds it to the target,
    /// otherwise refused by that binding alone (M4 review R-47), never as unknown.
    #[test]
    fn ct_gate_rejects_unknown_site() -> Result<()> {
        let mut unknown = M3_SITES;
        if let Some(t) = unknown.get_mut(1) {
            t.1 = "body-MAC";
        }
        let (_, json) = ct_report_with_sites(&unknown)?;
        let (_, problems) = ct_site_lines(&json, &[])?;
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems
                .iter()
                .all(|p| p.contains("tr_decrypt_reject_body_tag")
                    && p.contains("\"body-MAC\"")
                    && p.contains("unknown reject site")),
            "{problems:?}"
        );
        // every known site is known (the pre-check passed, the site is listed): the bound "body MAC" is accepted, any
        // other is refused by the binding of `CT_TARGET_SITES` alone
        for site in expect::KNOWN_SITES {
            let mut ok = M3_SITES;
            if let Some(t) = ok.get_mut(1) {
                t.1 = *site;
            }
            let (_, json) = ct_report_with_sites(&ok)?;
            let (_, problems) = ct_site_lines(&json, &[])?;
            if *site == "body MAC" {
                assert!(problems.is_empty(), "{site}: {problems:?}");
            } else {
                assert!(
                    problems.len() == 1
                        && problems.iter().all(|p| p
                            .contains("tr_decrypt_reject_body_tag claims the reject site")
                            && p.contains("binds it to \"body MAC\"")),
                    "{site}: {problems:?}"
                );
            }
        }
        Ok(())
    }

    /// TEST-SPEC-M5 X-08 (M4 review R-47): `expect::CT_TARGET_SITES` binds each site-claiming ct target to its site —
    /// every entry is one target of `expect::CT_TARGETS` with a site of `expect::KNOWN_SITES`, and the claims of the
    /// committed M4 report (`b138a2b`, every TR/INV/HX target with its site) are exactly the bound ones; the gate
    /// (`ct_site_lines`) refuses a target re-aimed at another known site (naming target, claimed and bound site), a
    /// bound target without a site, and a site on a target that is bound to none (a LINK target, `msg_open_reject`).
    #[test]
    fn ct_target_sites_bind_each_target_to_its_site() -> Result<()> {
        let mut seen = BTreeSet::new();
        for (target, site) in expect::CT_TARGET_SITES {
            assert!(seen.insert(*target), "{target} listed twice");
            assert!(expect::CT_TARGETS.contains(target), "{target}");
            assert!(expect::KNOWN_SITES.contains(site), "{target}: {site}");
        }
        assert_eq!(expect::CT_TARGET_SITES.len(), 11);
        assert!(expect::CT_TARGET_SITES.contains(&("tr_decrypt_trial_open_position", "body MAC")));
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/reviews/M04-evidence/ct-report-local-b138a2b-scale10.json");
        let json = std::fs::read_to_string(&path).map_err(|e| Error(e.to_string()))?;
        let mut v: Value = serde_json::from_str(&json).map_err(|e| Error(e.to_string()))?;
        let (lines, problems) = ct_site_lines(&json, &[])?;
        assert!(problems.is_empty() && lines.is_empty(), "{problems:?}");
        let claimed: BTreeSet<(String, String)> = v
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|r| {
                let name = r.get("name")?.as_str()?;
                Some((name.to_owned(), r.get("site")?.as_str()?.to_owned()))
            })
            .collect();
        let bound: BTreeSet<(String, String)> = expect::CT_TARGET_SITES
            .iter()
            .filter(|(t, _)| *t != "tr_decrypt_trial_open_position")
            .map(|(t, s)| ((*t).to_owned(), (*s).to_owned()))
            .collect();
        assert_eq!(claimed, bound);
        // edit one result of the committed report and read it again
        let mut edited = |name: &str, site: Value| -> Result<Vec<String>> {
            let results = v
                .get_mut("results")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| Error("ct report: no results".to_owned()))?;
            let r = results
                .iter_mut()
                .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error(format!("ct report: no {name}")))?;
            let before = r.insert("site".to_owned(), site);
            let found = ct_site_lines(&v.to_string(), &[]).map(|(_, p)| p);
            if let Some(r) = v
                .get_mut("results")
                .and_then(Value::as_array_mut)
                .and_then(|rs| {
                    rs.iter_mut()
                        .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
                })
                .and_then(Value::as_object_mut)
            {
                r.insert("site".to_owned(), before.unwrap_or(Value::Null));
            }
            found
        };
        // re-aimed at another known site: refused by the binding alone
        let found = edited("tr_decrypt_reject_hdr_key", Value::from("body MAC"))?;
        assert_eq!(
            found,
            vec![
                "ct: tr_decrypt_reject_hdr_key claims the reject site \"body MAC\", but expect::CT_TARGET_SITES binds \
                 it to \"header: no key opened\" (M4 review R-47)"
                    .to_owned()
            ]
        );
        // a bound target without its site
        let found = edited("hx_accept_reject_inner", Value::Null)?;
        assert!(
            found.len() == 1
                && found
                    .iter()
                    .all(|p| p.contains("hx_accept_reject_inner has no reject site")),
            "{found:?}"
        );
        // a site on a target bound to none (its pre-check is also missing)
        let found = edited("msg_open_reject", Value::from("body MAC"))?;
        assert!(
            found.iter().any(|p| p
                == "ct: msg_open_reject claims the reject site \"body MAC\", but expect::CT_TARGET_SITES binds no \
                    site to it (M4 review R-47)"),
            "{found:?}"
        );
        // the restored report reads as committed
        let (_, problems) = ct_site_lines(&v.to_string(), &[])?;
        assert!(problems.is_empty(), "{problems:?}");
        Ok(())
    }

    /// M3 review R-45 (F19): a failed pre-check aborts the bench, which writes target, class, expected and observed
    /// outcome into `error`; the gate's reader refuses such a report with that text.
    #[test]
    fn a_failed_precheck_fails_the_gate() {
        let reason = "pre-check failed (M3 review R-45): target hx_accept_reject_inner, class 1 (inner_ct under K_id, \
                      its tag's last byte flipped (COM ok, tag fails)): expected Err(Rejected), site inner open, \
                      observed Err(Rejected), site inner checks (claimed site: inner open)";
        let report = serde_json::json!({ "error": reason }).to_string();
        assert!(
            matches!(ctreport::ct_table(&report), Err(Error(e)) if e.contains(reason)),
            "{report}"
        );
    }
}
