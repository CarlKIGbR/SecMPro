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

/// dudect-style constant-time tests (docs/06 §2, §4; ADR-038, ADR-041 with Amendment 1): `cargo bench --bench ct`
/// in the release profile, timed with the CPU counter; per target two measurements, FAIL only for a shift
/// reproduced at the same crop and sign (|t| > 4.5) that reaches the effect floor (one effective quantum, at least
/// 10 ns), a reproduced smaller shift reported as `SUB_FLOOR_SHIFT`; the positive control must be detected; a
/// failing inline A/A control or a sensitivity control (`min_leak_control`) below the floor makes the run
/// `CONTROL_FAIL`; a target the runner's timer cannot resolve is NOT MEASURABLE. All but PASS and
/// `SUB_FLOOR_SHIFT` fail the gate with their wording.
pub(crate) fn ct(ctx: &Ctx) -> Result<Outcome> {
    let report = ctx.root.join("target").join("ct-report.json");
    if report.exists() {
        std::fs::remove_file(&report)?;
    }
    // M2 review C3 (c): the full sample counts of expect.rs, whatever the caller's environment says
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
        .env_remove("SECMP_CT_SCALE")
        .capture()?;
    let json = std::fs::read_to_string(&report).map_err(|e| {
        say(cap.stderr.trim_end());
        Error(format!("ct: no report written ({e})"))
    })?;
    // the whole report first (clock, both measurements, per-crop t), so a CI log carries it even on failure
    say(&format!("  ct report: {}", json.trim_end()));
    let table = ctreport::ct_table(&json)?;
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
        let max_len = fuzz_max_len(t)?;
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
            .arg(format!("-max_len={max_len}"))
            .dir(&ctx.root)
            .run()?;
    }
    Ok(Outcome::Pass(format!(
        "fuzz smoke, 120 s per target, -max_len from expect::FUZZ_MAX_LEN: {} (expected set matches)",
        list(&found)
    )))
}

/// The libFuzzer `-max_len` of target `t` (`expect::FUZZ_MAX_LEN`, M2 review C4); a target without one is refused.
fn fuzz_max_len(t: &str) -> Result<usize> {
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
    let read = |name: &str| std::fs::read_to_string(out.join(name)).ok();
    let accepted = std::fs::read_to_string(ctx.root.join("docs").join("mutants-accepted.md"))?;
    let survivors = mutant_survivors(cap.code, read("missed.txt"), read("timeout.txt"))?;
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
    Ok(Outcome::Pass(format!(
        "Kani {}: harness packages {} (expected set matches); {}/{} harnesses verified (expect::KANI_HARNESSES): {}",
        tools::KANI.version,
        list(&found),
        verified.len(),
        expect::KANI_HARNESSES.len(),
        verified.join(", ")
    )))
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

/// The job ids of a workflow and the `name:` of each job (a check run carries the name, or the id without one).
fn job_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_jobs = false;
        }
        if !in_jobs {
            continue;
        }
        if let Some(id) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
            && !id.starts_with(' ')
        {
            out.push(id.to_owned());
        } else if let Some(name) = line.strip_prefix("    name:")
            && !line.starts_with("     ")
        {
            out.push(name.trim().trim_matches(['"', '\'']).to_owned());
        }
    }
    out
}

/// The job-level `if:` of every job of a workflow: (job id, the condition as written after `if:`, trimmed), `None`
/// for a job without one. Step-level conditions (deeper indentation) are not job conditions.
fn job_conditions(text: &str) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_jobs = false;
        }
        if !in_jobs {
            continue;
        }
        if let Some(id) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
            && !id.starts_with(' ')
        {
            out.push((id.to_owned(), None));
        } else if let Some(cond) = line.strip_prefix("    if:")
            && let Some((_, slot)) = out.last_mut()
        {
            *slot = Some(cond.trim().to_owned());
        }
    }
    out
}

/// M2 review C2: the required job names exist only in `expect::REQUIRED_WORKFLOW`, all of them, and that workflow
/// has no `workflow_dispatch` trigger (a dispatch would add `skipped` check runs under the required names, and
/// GitHub counts a skipped check as passing). F19 (external review EXT-1): the job-level `if:` of each required job
/// is exactly the one pinned in `expect::REQUIRED_JOB_CONDITIONS` (or absent where that says `None`), so no later
/// condition can skip a required check on a pull request while it reports green. `files`: (repository-relative
/// path, text).
pub(crate) fn required_job_findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
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
            for required in expect::REQUIRED_JOBS {
                if !jobs.iter().any(|j| j == required) {
                    out.push(format!("{name}: required job `{required}` missing"));
                }
            }
            let conditions = job_conditions(text);
            for (job, found) in &conditions {
                if !expect::REQUIRED_JOBS.contains(&job.as_str()) {
                    continue;
                }
                let pinned = expect::REQUIRED_JOB_CONDITIONS
                    .iter()
                    .find(|(j, _)| j == job)
                    .map(|(_, c)| *c);
                match pinned {
                    Some(pinned) if pinned == found.as_deref() => {}
                    Some(pinned) => out.push(format!(
                        "{name}: required job `{job}` has the condition {found:?}, pinned {pinned:?}"
                    )),
                    None => out.push(format!(
                        "{name}: required job `{job}` has no pinned condition in expect::REQUIRED_JOB_CONDITIONS"
                    )),
                }
            }
        } else {
            for j in jobs
                .iter()
                .filter(|j| expect::REQUIRED_JOBS.contains(&j.as_str()))
            {
                out.push(format!(
                    "{name}: job `{j}` uses a required-check name outside {}",
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

fn workflows(root: &Path) -> Result<String> {
    let dir = root.join(".github").join("workflows");
    let files = walk_files(&dir, &|p: &Path| {
        p.extension().is_some_and(|e| e == "yml" || e == "yaml")
    })?;
    let mut findings = Vec::new();
    let mut texts = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f)?;
        findings.extend(workflow_findings(&rel(root, f), &text));
        texts.push((rel(root, f), text));
    }
    findings.extend(required_job_findings(&texts));
    for f in &findings {
        say(&format!("  FINDING {f}"));
    }
    if !findings.is_empty() {
        bail!("{} CI-hygiene finding(s)", findings.len());
    }
    Ok(format!(
        "workflows: {} files, triggers/SHA pins/continue-on-error ok; required checks only in ci.yml, no dispatch there, job conditions as pinned",
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

    /// M2 review C2: the required job names only in ci.yml, all four there, and no dispatch trigger in ci.yml.
    #[test]
    fn required_checks_only_in_the_pull_request_workflow() {
        let ci = "on:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  linux-fast:\n    runs-on: x\n  windows-native:\n    runs-on: x\n  xwin-cross:\n    runs-on: x\n  linux-full:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n";
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
        assert_eq!(
            required_job_findings(&[("other.yml".to_owned(), dispatch.to_owned())]).len(),
            1
        );
    }

    /// F19 (external review EXT-1): a job-level `if:` on a required job other than the pinned one is refused — a
    /// new condition, a changed one, a removed pinned one; step-level conditions and other jobs are not affected.
    #[test]
    fn required_jobs_keep_their_pinned_conditions() {
        let ci = "on:\n  pull_request:\njobs:\n  linux-fast:\n    runs-on: x\n    steps:\n      - if: always()\n        run: x\n  windows-native:\n    runs-on: x\n  xwin-cross:\n    runs-on: x\n  linux-full:\n    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n    runs-on: x\n  extra:\n    if: false\n    runs-on: x\n";
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
        let changed = ci.replace("|| github.event_name == 'pull_request'", "");
        assert_eq!(required_job_findings(&files(&changed)).len(), 1);
        let removed = ci.replace(
            "    if: github.event_name == 'schedule' || github.event_name == 'pull_request'\n",
            "",
        );
        assert_eq!(required_job_findings(&files(&removed)).len(), 1);
        // the conditions as parsed
        let parsed = job_conditions(ci);
        assert_eq!(parsed.len(), 5);
        assert_eq!(parsed.first(), Some(&("linux-fast".to_owned(), None)));
        assert_eq!(
            parsed.get(4),
            Some(&("extra".to_owned(), Some("false".to_owned())))
        );
        // the real ci.yml keeps its pinned conditions
        let real = include_str!("../../.github/workflows/ci.yml");
        for (job, cond) in expect::REQUIRED_JOB_CONDITIONS {
            let found = job_conditions(real)
                .into_iter()
                .find(|(j, _)| j == job)
                .map(|(_, c)| c);
            assert_eq!(found, Some(cond.map(str::to_owned)), "{job}");
        }
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

    /// M2 review C5: Kani must verify exactly the harnesses of `expect::KANI_HARNESSES`.
    #[test]
    fn kani_refuses_fifteen_harnesses() -> Result<()> {
        let all = expect::KANI_HARNESSES;
        assert_eq!(all.len(), 16);
        assert_eq!(kani_verified(&kani_log(all, 0))?.len(), 16);
        // a deleted harness: 15 verified, and Kani's own summary says 15 of 15
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
}
