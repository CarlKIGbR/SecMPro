// SPDX-License-Identifier: AGPL-3.0-or-later
//! The individual gates of docs/06 §5. Each returns an [`Outcome`] or fails; the driver in `ci.rs` decides
//! what a skip means (`--strict` turns every skip into a failure).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::ci::{Ctx, Outcome};
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

pub(crate) fn nextest(_: &Ctx) -> Result<Outcome> {
    tools::require(tools::NEXTEST)?;
    Cmd::cargo()
        .args(["nextest", "run", "--workspace", "--locked"])
        .run()?;
    Ok(Outcome::Pass("cargo nextest run --workspace".into()))
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

pub(crate) fn kat(ctx: &Ctx) -> Result<Outcome> {
    let found: BTreeSet<String> = ctx
        .ws
        .members
        .iter()
        .filter(|p| p.features.contains("kat"))
        .map(|p| p.name.clone())
        .collect();
    same_set("KAT packages (feature `kat`)", &found, expect::KAT_PACKAGES)?;
    for p in &found {
        Cmd::cargo()
            .args([
                "nextest",
                "run",
                "--locked",
                "--package",
                p,
                "--features",
                "kat",
            ])
            .run()?;
    }
    // libcrux's build scripts compile its SIMD backends on aarch64 (NEON) and x86_64 (AVX2, chosen at run time),
    // so the run above tests the backend this host uses. A CPU without AVX2 runs the portable backend: the ML-KEM
    // KATs and the frozen vectors run again with the SIMD backends compiled out (own target directory, because
    // the build scripts do not declare the variables and Cargo would reuse a stale build).
    let portable_dir = ctx.root.join("target").join("kat-portable");
    Cmd::cargo()
        .args([
            "nextest",
            "run",
            "--locked",
            "--package",
            "secmp-crypto",
            "--features",
            "kat",
            "--test",
            "kat_mlkem",
            "--test",
            "vectors",
        ])
        .env("LIBCRUX_DISABLE_SIMD128", "1")
        .env("LIBCRUX_DISABLE_SIMD256", "1")
        .env("CARGO_TARGET_DIR", portable_dir.to_string_lossy())
        .run()?;
    Ok(Outcome::Pass(format!(
        "KAT/differential packages: {} (expected set matches); ML-KEM KATs and frozen vectors also with libcrux's portable backend",
        list(&found)
    )))
}

/// The `ct` report (`target/ct-report.json`, written by `crates/secmp-crypto/benches/ct.rs`) as the gate reads it
/// (ADR-038, ADR-041): one line per target, and the targets that fail or are not measurable on this runner.
#[derive(Debug, Default)]
pub(crate) struct CtTable {
    pub(crate) lines: Vec<String>,
    pub(crate) failed: Vec<String>,
    pub(crate) not_measurable: Vec<String>,
}

/// The verdicts a report may carry per target and whether each passes (ADR-041; `NOT_MEASURABLE` per ADR-038 (3)).
const CT_VERDICTS: &[(&str, bool)] = &[
    ("PASS", true),
    ("SUB_QUANTUM_SHIFT", true),
    ("FAIL", false),
    ("NOT_MEASURABLE", false),
    ("CONTROL_FAIL", false),
];

/// The run verdicts a report may carry (ADR-041 (3)).
const CT_RUN_VERDICTS: &[&str] = &["PASS", "FAIL", "CONTROL_FAIL"];

/// `max |t| = x (crop), batch median y ns, q_eff q ticks (source), realised r quanta` of one measurement object.
fn ct_measurement(m: &Value) -> String {
    let t = m
        .get("max_abs_t")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    let at = m.get("max_at").and_then(Value::as_str).unwrap_or("?");
    let median = m
        .get("median_ns")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    let q = m
        .get("q_eff_ticks")
        .and_then(Value::as_f64)
        .map_or_else(|| "?".to_owned(), |q| format!("{q:.1}"));
    let source = m.get("q_eff_source").and_then(Value::as_str).unwrap_or("?");
    let realised = m
        .get("realised_quanta")
        .and_then(Value::as_f64)
        .map_or_else(|| "?".to_owned(), |r| format!("{r:.1}"));
    format!(
        "max |t| = {t:.2} ({at}), batch median {median:.1} ns, q_eff {q} ticks ({source}), realised {realised} quanta"
    )
}

/// The report must echo exactly the parameters of `expect.rs` (the bench reads them from there).
fn ct_check_parameters(v: &Value) -> Result<()> {
    let th = v
        .get("thresholds")
        .ok_or_else(|| Error("ct report: no thresholds".to_owned()))?;
    let num = |k: &str| th.get(k).and_then(Value::as_f64).map(f64::to_bits);
    if num("pass") != Some(expect::CT_THRESHOLDS.to_bits())
        || num("max_resolution_fraction") != Some(expect::CT_RESOLUTION_MAX_FRACTION.to_bits())
        || th.get("max_batch").and_then(Value::as_u64) != Some(u64::from(expect::CT_MAX_BATCH))
        || num("batch_margin") != Some(expect::CT_BATCH_MARGIN.to_bits())
        || th.get("min_realised_quanta").and_then(Value::as_u64)
            != Some(expect::CT_MIN_REALISED_QUANTA)
        || num("effect_floor_quanta") != Some(expect::CT_EFFECT_FLOOR_QUANTA.to_bits())
        || num("aa_max_t") != Some(expect::CT_AA_MAX_T.to_bits())
    {
        bail!(
            "ct report: parameters {th} differ from expect::CT_THRESHOLDS {} / CT_RESOLUTION_MAX_FRACTION {} / \
             CT_MAX_BATCH {} / CT_BATCH_MARGIN {} / CT_MIN_REALISED_QUANTA {} / CT_EFFECT_FLOOR_QUANTA {} / \
             CT_AA_MAX_T {}",
            expect::CT_THRESHOLDS,
            expect::CT_RESOLUTION_MAX_FRACTION,
            expect::CT_MAX_BATCH,
            expect::CT_BATCH_MARGIN,
            expect::CT_MIN_REALISED_QUANTA,
            expect::CT_EFFECT_FLOOR_QUANTA,
            expect::CT_AA_MAX_T
        );
    }
    Ok(())
}

/// One target's line: verdict (with the deciding crop), `k`, calibration, both measurements and the A/A control.
fn ct_line(r: &Value) -> (String, String, bool) {
    let name = r.get("name").and_then(Value::as_str).unwrap_or("?");
    let verdict = r.get("verdict").and_then(Value::as_str).unwrap_or("?");
    let control = r.get("control").and_then(Value::as_bool).unwrap_or(false);
    let n = r.get("samples").and_then(Value::as_u64).unwrap_or(0);
    let k = r
        .get("k")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_owned(), |k| k.to_string());
    let calibration = r.get("calibration_median_ns").and_then(Value::as_f64);
    let ns = |x: Option<f64>| x.map_or_else(|| "?".to_owned(), |x| format!("{x:.1}"));
    let measurement = |key: &str, label: &str| {
        r.get(key)
            .filter(|m| !m.is_null())
            .map(|m| format!("; {label} {}", ct_measurement(m)))
            .unwrap_or_default()
    };
    let decisive = r
        .get("decisive_crop")
        .and_then(Value::as_str)
        .map(|c| format!(" at {c}"))
        .unwrap_or_default();
    let line = format!(
        "{name}: {verdict}{decisive} — k={k}, calibration median {} ns, {n} samples{}{}{}{}",
        ns(calibration),
        measurement("first", "first"),
        measurement("second", "second"),
        measurement("aa_control", "A/A"),
        if control {
            " (positive control, must be detected)"
        } else {
            ""
        }
    );
    let passes = CT_VERDICTS
        .iter()
        .find(|(v, _)| *v == verdict)
        .is_some_and(|(_, ok)| *ok);
    (
        line,
        format!("{name} (median {} ns)", ns(calibration)),
        passes,
    )
}

pub(crate) fn ct_table(json: &str) -> Result<CtTable> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("ct report: {e}")))?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        bail!("ct report: {e}");
    }
    ct_check_parameters(&v)?;
    let run_verdict = v
        .get("run_verdict")
        .and_then(Value::as_str)
        .filter(|rv| CT_RUN_VERDICTS.contains(rv))
        .ok_or_else(|| Error("ct report: no known run_verdict".to_owned()))?;
    let resolution = v
        .get("clock")
        .and_then(|c| c.get("q_eff_ns"))
        .and_then(Value::as_f64);
    let results = v
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| Error("ct report: no results".to_owned()))?;
    let mut table = CtTable::default();
    if results.is_empty() {
        table
            .failed
            .push("ct report: no target was measured".to_owned());
    }
    if run_verdict == "CONTROL_FAIL" {
        // ADR-041 (3): the harness or the runner is unsound; no target verdict counts
        let reason = v.get("run_reason").and_then(Value::as_str).unwrap_or("?");
        table.failed.push(format!("CONTROL_FAIL — {reason}"));
    }
    for r in results {
        let (line, not_measurable, passes) = ct_line(r);
        let verdict = r.get("verdict").and_then(Value::as_str).unwrap_or("?");
        if run_verdict != "CONTROL_FAIL" {
            if verdict == "NOT_MEASURABLE" {
                table.not_measurable.push(format!(
                    "{not_measurable}, effective quantum {} ns",
                    resolution.map_or_else(|| "?".to_owned(), |x| format!("{x:.1}"))
                ));
            } else if !passes {
                table.failed.push(line.clone());
            }
        }
        table.lines.push(line);
    }
    if run_verdict == "PASS" && !(table.failed.is_empty() && table.not_measurable.is_empty()) {
        table
            .failed
            .push("ct report: run verdict PASS with a failing target".to_owned());
    }
    Ok(table)
}

/// dudect-style constant-time tests (docs/06 §2, §4; ADR-038, ADR-041): `cargo bench --bench ct` in the release
/// profile, timed with the CPU counter; per target two measurements, FAIL only for a shift reproduced at the same
/// crop and sign (|t| > 4.5) of at least one effective quantum, a reproduced smaller shift reported as
/// `SUB_QUANTUM_SHIFT`; the positive control must be detected; a failing inline A/A control makes the run
/// `CONTROL_FAIL`; a target the runner's timer cannot resolve is NOT MEASURABLE. All but PASS and
/// `SUB_QUANTUM_SHIFT` fail the gate with their wording.
pub(crate) fn ct(ctx: &Ctx) -> Result<Outcome> {
    let report = ctx.root.join("target").join("ct-report.json");
    if report.exists() {
        std::fs::remove_file(&report)?;
    }
    let cap = Cmd::cargo()
        .args([
            "bench",
            "--locked",
            "--package",
            "secmp-crypto",
            "--features",
            "kat",
            "--bench",
            "ct",
        ])
        .capture()?;
    let json = std::fs::read_to_string(&report).map_err(|e| {
        say(cap.stderr.trim_end());
        Error(format!("ct: no report written ({e})"))
    })?;
    // the whole report first (clock, both measurements, per-crop t), so a CI log carries it even on failure
    say(&format!("  ct report: {}", json.trim_end()));
    let table = ct_table(&json)?;
    for l in &table.lines {
        say(&format!("  ct {l}"));
    }
    let mut problems = Vec::new();
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
    if !cap.success && problems.is_empty() {
        problems.push("ct: the bench failed without a failing target in its report".to_owned());
    }
    if !problems.is_empty() {
        bail!("{}", problems.join("; "));
    }
    Ok(Outcome::Pass(table.lines.join("; ")))
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

pub(crate) fn fuzz(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::FUZZ)?;
    tools::require_nightly(&[])?;
    let found = file_stems(&ctx.root.join("fuzz").join("fuzz_targets"), "rs")?;
    same_set("fuzz targets", &found, expect::FUZZ_TARGETS)?;
    for t in &found {
        Cmd::cargo_on(tools::NIGHTLY)
            .args([
                "fuzz",
                "run",
                "--fuzz-dir",
                "fuzz",
                t,
                "--",
                "-max_total_time=120",
            ])
            .dir(&ctx.root)
            .run()?;
    }
    Ok(Outcome::Pass(format!(
        "fuzz smoke, 120 s per target: {} (expected set matches)",
        list(&found)
    )))
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

pub(crate) fn coverage(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::LLVM_COV)?;
    tools::require(tools::NEXTEST)?;
    let out_path = ctx.root.join("target").join("llvm-cov-summary.json");
    Cmd::cargo()
        .args([
            "llvm-cov",
            "nextest",
            "--workspace",
            "--locked",
            "--json",
            "--summary-only",
            "--output-path",
        ])
        .arg(out_path.to_string_lossy())
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
/// `timeout.txt`) that no line of `docs/mutants-accepted.md` documents with both its path and its description
/// (line numbers are ignored, so an accepted survivor stays accepted when unrelated code moves).
pub(crate) fn undocumented_survivors(listing: &str, accepted: &str) -> Vec<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| {
            let mut parts = l.splitn(4, ':');
            let path = parts.next().unwrap_or_default();
            let desc = parts.nth(2).map(str::trim).unwrap_or_default();
            path.is_empty()
                || desc.is_empty()
                || !accepted
                    .lines()
                    .any(|a| a.contains(&format!("`{path}`")) && a.contains(&format!("`{desc}`")))
        })
        .map(str::to_owned)
        .collect()
}

pub(crate) fn mutants(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::MUTANTS)?;
    // With feature `kat` the external KATs and the frozen-vector test join the unit tests in killing mutants.
    let mut c = Cmd::cargo().args([
        "mutants",
        "--no-shuffle",
        "--output",
        "target",
        "--features",
        "secmp-crypto/kat",
    ]);
    for p in expect::MUTANT_PACKAGES {
        c = c.args(["--package", p]);
    }
    for f in expect::MUTANT_EXCLUDE_FILES {
        c = c.args(["--exclude", f]);
    }
    for re in expect::MUTANT_EXCLUDE_RE {
        c = c.args(["--exclude-re", re]);
    }
    let cap = c.dir(&ctx.root).capture()?;
    say(cap.stdout.trim_end());
    let out = ctx.root.join("target").join("mutants.out");
    let read = |name: &str| std::fs::read_to_string(out.join(name)).unwrap_or_default();
    let accepted = std::fs::read_to_string(ctx.root.join("docs").join("mutants-accepted.md"))?;
    let survivors = format!("{}\n{}", read("missed.txt"), read("timeout.txt"));
    let undocumented = undocumented_survivors(&survivors, &accepted);
    let documented = survivors
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
        .saturating_sub(undocumented.len());
    // cargo-mutants: 0 all caught, 2 missed mutants, 3 timeouts; anything else (baseline failure, usage) fails
    let only_survivors = matches!(cap.code, Some(0 | 2 | 3));
    if !only_survivors || !undocumented.is_empty() {
        say(cap.stderr.trim_end());
        for u in &undocumented {
            say(&format!("  UNDOCUMENTED SURVIVOR {u}"));
        }
        bail!(
            "cargo mutants (exit {:?}): {} undocumented survivor(s) (docs/mutants-accepted.md){}",
            cap.code,
            undocumented.len(),
            if only_survivors {
                ""
            } else {
                "; baseline or usage failure"
            }
        );
    }
    let summary = cap
        .stdout
        .lines()
        .rev()
        .find(|l| l.contains("mutants tested"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    Ok(Outcome::Pass(format!(
        "{}: {summary}; survivors documented in docs/mutants-accepted.md: {documented}",
        expect::MUTANT_PACKAGES.join(", ")
    )))
}

/// Miri in `ci-full`: the bounded scope, skipping the test modules of `expect::MIRI_SKIP` (docs/06 §4).
pub(crate) fn miri(ctx: &Ctx) -> Result<Outcome> {
    miri_with(ctx, expect::MIRI_SKIP)
}

/// `miri-full` (on demand; the weekly `miri-full` workflow, docs/06 §4, M1 review F3): the complete set, no skip
/// list.
pub(crate) fn miri_full(ctx: &Ctx) -> Result<Outcome> {
    miri_with(ctx, &[])
}

fn miri_with(ctx: &Ctx, skip: &[(&str, &str)]) -> Result<Outcome> {
    tools::require_nightly(&["miri", "rust-src"])?;
    Cmd::cargo_on(tools::NIGHTLY)
        .args(["miri", "setup", "--target", expect::MIRI_TARGET])
        .dir(&ctx.root)
        .run()?;
    // Miri cannot execute SIMD intrinsics: libcrux is built with its portable backend (own target directory,
    // because libcrux's build scripts do not declare these variables and Cargo would reuse a stale build).
    let mut c = Cmd::cargo_on(tools::NIGHTLY)
        .args(["miri", "test", "--locked", "--target", expect::MIRI_TARGET])
        .env("LIBCRUX_DISABLE_SIMD128", "1")
        .env("LIBCRUX_DISABLE_SIMD256", "1")
        .env(
            "CARGO_TARGET_DIR",
            ctx.root
                .join("target")
                .join("miri-portable")
                .to_string_lossy(),
        )
        .dir(&ctx.root);
    for p in expect::MIRI_PACKAGES {
        c = c.args(["--package", p]);
    }
    c = c.arg("--");
    for (filter, _) in skip {
        c = c.args(["--skip", filter]);
    }
    c.run()?;
    let skipped = if skip.is_empty() {
        "none (complete set)".to_owned()
    } else {
        skip.iter().map(|(f, _)| *f).collect::<Vec<_>>().join(", ")
    };
    Ok(Outcome::Pass(format!(
        "Miri ({}, interpreting {}, libcrux portable backend): {}; skipped test modules: {skipped}",
        tools::NIGHTLY,
        expect::MIRI_TARGET,
        expect::MIRI_PACKAGES.join(", "),
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
    for p in &packages {
        let mut c = Cmd::cargo().args(["kani", "--package", &p.name]);
        for feature in &p.kani_unstable {
            c = c.args(["-Z", feature]);
        }
        c.dir(&ctx.root).run()?;
    }
    Ok(Outcome::Pass(format!(
        "Kani {}: harness packages {} (expected set matches)",
        tools::KANI.version,
        list(&found)
    )))
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

fn proverif_cmd() -> Cmd {
    Cmd::new(std::env::var("SECMP_PROVERIF").unwrap_or_else(|_| "proverif".to_owned()))
}

pub(crate) fn proverif(ctx: &Ctx) -> Result<Outcome> {
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
    let fixture = ctx
        .root
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
    let models = file_stems(&ctx.root.join("formal"), "pv")?;
    same_set("ProVerif models", &models, expect::PROVERIF_MODELS)?;
    for m in &models {
        // M3+: each model's verdicts are compared with formal/CLAIMS.md (fixed by the reviewer).
        let path = ctx.root.join("formal").join(format!("{m}.pv"));
        let cap = proverif_cmd().arg(path.to_string_lossy()).capture()?;
        if !cap.success {
            bail!("ProVerif failed on formal/{m}.pv");
        }
        say(&format!(
            "  formal/{m}.pv: {:?}",
            proverif_results(&cap.stdout)
        ));
    }
    Ok(Outcome::Pass(format!(
        "ProVerif {} self-test [true, false] ok; models: {} (expected set matches)",
        tools::PROVERIF_VERSION,
        list(&models)
    )))
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

/// Step 12a: the frozen SecMP vectors equal the committed reference files of the independent `ref/` session
/// (ADR-026; CI compares with the committed `vectors/ref/*.json` and never runs the Python generator, M1 brief
/// Q-4). The Rust side is re-checked against the frozen files by the `kat` step (`tests/vectors.rs`).
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

/// Findings for one workflow file: forbidden triggers, actions not pinned to a full commit SHA, and
/// `continue-on-error` outside the jobs allowed by `expect::CONTINUE_ON_ERROR_JOBS`.
pub(crate) fn workflow_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut job: Option<String> = None;
    let mut in_jobs = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if line.starts_with("jobs:") {
            in_jobs = true;
        } else if !line.starts_with(' ') && !t.is_empty() {
            in_jobs = false;
        }
        if in_jobs
            && let Some(id) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
            && !id.starts_with(' ')
        {
            job = Some(id.to_owned());
        }
        for trigger in ["pull_request_target", "workflow_run"] {
            if t.contains(trigger) {
                out.push(format!("{name}: forbidden trigger `{trigger}`"));
            }
        }
        if let Some(u) = t
            .strip_prefix("uses:")
            .or_else(|| t.strip_prefix("- uses:"))
        {
            let u = u.trim();
            let pinned = u.split_once('@').is_some_and(|(_, r)| {
                let r = r.split_whitespace().next().unwrap_or_default();
                r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
            });
            if !u.starts_with("./") && !pinned {
                out.push(format!("{name}: action not pinned by commit SHA: {u}"));
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
        if t.starts_with("continue-on-error:") && !t.ends_with("false") {
            let ok = job
                .as_deref()
                .is_some_and(|j| expect::CONTINUE_ON_ERROR_JOBS.contains(&j));
            if !ok {
                out.push(format!(
                    "{name}: continue-on-error in job {job:?} is not allowed"
                ));
            }
        }
    }
    out
}

fn workflows(root: &Path) -> Result<String> {
    let dir = root.join(".github").join("workflows");
    let files = walk_files(&dir, &|p: &Path| {
        p.extension().is_some_and(|e| e == "yml" || e == "yaml")
    })?;
    let mut findings = Vec::new();
    for f in &files {
        findings.extend(workflow_findings(
            &rel(root, f),
            &std::fs::read_to_string(f)?,
        ));
    }
    for f in &findings {
        say(&format!("  FINDING {f}"));
    }
    if !findings.is_empty() {
        bail!("{} CI-hygiene finding(s)", findings.len());
    }
    Ok(format!(
        "workflows: {} files, triggers/SHA pins/continue-on-error ok",
        files.len()
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
            "| `crates/a/src/x.rs`: `replace <impl Drop for S>::drop with ()` | reason |\n";
        let listing = "crates/a/src/x.rs:59:9: replace <impl Drop for S>::drop with ()\n\
                       crates/a/src/x.rs:12:5: replace f -> bool with true\n\n";
        let u = undocumented_survivors(listing, accepted);
        assert_eq!(
            u,
            vec!["crates/a/src/x.rs:12:5: replace f -> bool with true".to_owned()]
        );
        // the line number does not matter, the file does
        assert!(
            undocumented_survivors(
                "crates/a/src/x.rs:99:1: replace <impl Drop for S>::drop with ()",
                accepted
            )
            .is_empty()
        );
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

    /// A report in the ADR-041 format with the given run verdict and results, the parameters of `expect.rs` and a
    /// 0.5 ns clock.
    fn ct_report(run_verdict: &str, results: &str) -> String {
        format!(
            r#"{{"thresholds":{{"pass":{},"max_resolution_fraction":{},"max_batch":{},"batch_margin":{},"min_realised_quanta":{},"effect_floor_quanta":{},"aa_max_t":{}}},"sign":"t < 0: class 0 faster","clock":{{"timer":"rdtscp","tick_ns":0.5,"resolution_ns":0.5,"q_eff_ns":0.5}},"run_verdict":"{run_verdict}","run_reason":null,"results":[{results}]}}"#,
            expect::CT_THRESHOLDS,
            expect::CT_RESOLUTION_MAX_FRACTION,
            expect::CT_MAX_BATCH,
            expect::CT_BATCH_MARGIN,
            expect::CT_MIN_REALISED_QUANTA,
            expect::CT_EFFECT_FLOOR_QUANTA,
            expect::CT_AA_MAX_T
        )
    }

    /// One target; `first: None` means no measurement (NOT MEASURABLE, `k` null).
    fn ct_target(
        name: &str,
        control: bool,
        verdict: &str,
        first: Option<f64>,
        second: Option<f64>,
    ) -> String {
        let m = |t: f64| {
            format!(
                r#"{{"max_abs_t":{t},"max_at":"p90","t":{{}},"crops":{{}},"q_eff_ticks":1.0,"q_eff_source":"clock","distinct":900,"median_ticks":6000,"median_ns":3000.0,"class_median_ticks":6000,"realised_quanta":6000.0}}"#
            )
        };
        let k = if first.is_some() { "2" } else { "null" };
        let decisive = if matches!(verdict, "FAIL" | "SUB_QUANTUM_SHIFT") {
            r#""p90""#
        } else {
            "null"
        };
        format!(
            r#"{{"name":"{name}","samples":10,"control":{control},"k":{k},"calibration_median_ticks":3000,"calibration_median_ns":1500.0,"verdict":"{verdict}","passed":false,"decisive_crop":{decisive},"aa_passed":true,"aa_control":{},"first":{},"second":{}}}"#,
            first.map_or_else(|| "null".to_owned(), |_| m(1.25)),
            first.map_or_else(|| "null".to_owned(), m),
            second.map_or_else(|| "null".to_owned(), m)
        )
    }

    #[test]
    fn ct_report_table() -> Result<()> {
        let ok = ct_report(
            "PASS",
            &[
                ct_target("control", true, "PASS", Some(99.0), None),
                ct_target("tag", false, "PASS", Some(1.25), Some(0.5)),
                ct_target("msg", false, "SUB_QUANTUM_SHIFT", Some(30.0), Some(25.0)),
            ]
            .join(","),
        );
        let t = ct_table(&ok)?;
        assert!(t.failed.is_empty() && t.not_measurable.is_empty(), "{t:?}");
        assert_eq!(t.lines.len(), 3);
        assert!(
            t.lines
                .iter()
                .any(|l| l.contains("positive control, must be detected"))
        );
        // k, the calibration median, both measurements (with q_eff and the realised quanta), the deciding crop and
        // the A/A control are printed
        assert!(
            t.lines.iter().any(|l| l.starts_with("msg: SUB_QUANTUM_SHIFT at p90 — k=2, calibration median 1500.0 ns")
                && l.contains("first max |t| = 30.00 (p90), batch median 3000.0 ns, q_eff 1.0 ticks (clock), realised 6000.0 quanta")
                && l.contains("second max |t| = 25.00 (p90)")
                && l.contains("A/A max |t| = 1.25 (p90)")),
            "{t:?}"
        );

        // FAIL fails the gate; so does a verdict ADR-041 withdrew and an unknown one (fail closed)
        for bad in ["FAIL", "INCONCLUSIVE→FAIL", "INCONCLUSIVE→PASS", "MAYBE"] {
            let t = ct_table(&ct_report(
                "FAIL",
                &ct_target("tag", false, bad, Some(30.0), Some(20.0)),
            ))?;
            assert_eq!(t.failed.len(), 1, "{bad}: {t:?}");
        }

        // NOT_MEASURABLE (k > max_batch: no measurement) is reported separately
        let t = ct_table(&ct_report(
            "FAIL",
            &ct_target("derive", false, "NOT_MEASURABLE", None, None),
        ))?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert_eq!(
            t.not_measurable,
            vec!["derive (median 1500.0 ns), effective quantum 0.5 ns".to_owned()]
        );
        assert!(t.lines.iter().any(|l| l.contains("k=-")), "{t:?}");

        // CONTROL_FAIL: the run fails with the reason, no target verdict counts
        let control_fail = ct_report(
            "CONTROL_FAIL",
            &[
                ct_target("control", true, "CONTROL_FAIL", Some(99.0), None),
                ct_target("tag", false, "CONTROL_FAIL", Some(1.0), Some(1.0)),
            ]
            .join(","),
        )
        .replacen(
            r#""run_reason":null"#,
            r#""run_reason":"inline A/A control above 4.5: tag |t| = 6.00 at p50""#,
            1,
        );
        let t = ct_table(&control_fail)?;
        assert_eq!(
            t.failed,
            vec!["CONTROL_FAIL — inline A/A control above 4.5: tag |t| = 6.00 at p50".to_owned()]
        );
        assert_eq!(t.lines.len(), 2);

        // a PASS run verdict next to a failing target is refused as inconsistent
        let t = ct_table(&ct_report(
            "PASS",
            &ct_target("tag", false, "FAIL", Some(30.0), Some(20.0)),
        ))?;
        assert_eq!(t.failed.len(), 2, "{t:?}");

        // parameters that differ from expect.rs are refused
        for (from, to) in [
            (r#""pass":4.5"#, r#""pass":10"#),
            (r#""max_batch":64"#, r#""max_batch":128"#),
            (
                r#""max_resolution_fraction":0.01"#,
                r#""max_resolution_fraction":0.1"#,
            ),
            (r#""batch_margin":1.1"#, r#""batch_margin":1"#),
            (r#""min_realised_quanta":80"#, r#""min_realised_quanta":40"#),
            (r#""effect_floor_quanta":1"#, r#""effect_floor_quanta":2"#),
            (r#""aa_max_t":4.5"#, r#""aa_max_t":9"#),
        ] {
            let tuned = ok.replacen(from, to, 1);
            assert_ne!(tuned, ok, "{from}");
            assert!(ct_table(&tuned).is_err(), "{from}");
        }
        let (without, _) = ok
            .split_once(r#""sign""#)
            .ok_or_else(|| Error("fixture".to_owned()))?;
        assert!(
            ct_table(&ok.replacen(without, "{", 1)).is_err(),
            "no thresholds"
        );
        // a missing or unknown run verdict is refused
        assert!(ct_table(&ok.replacen(r#""run_verdict":"PASS","#, "", 1)).is_err());
        assert!(
            ct_table(&ok.replacen(r#""run_verdict":"PASS""#, r#""run_verdict":"OK""#, 1)).is_err()
        );

        // an error report, an empty report, a malformed report
        assert!(ct_table(r#"{"error":"thresholds not readable"}"#).is_err());
        assert_eq!(
            ct_table(&ct_report("FAIL", ""))?.failed.len(),
            1,
            "an empty report never passes"
        );
        assert!(ct_table("{}").is_err());
        Ok(())
    }

    #[test]
    fn proverif_verdicts() {
        let out = "Verification summary:\nRESULT not attacker(s[]) is true.\nRESULT not attacker(p[]) is false.\nRESULT event(x) ==> event(y) cannot be proved.\n";
        assert_eq!(proverif_results(out), vec![Some(true), Some(false), None]);
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
}
