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
            "--locked",
            "--",
            "-D",
            "warnings",
        ])
        .run()?;
    Ok(Outcome::Pass(format!(
        "clippy -D warnings on {} ({} crates)",
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
    Ok(Outcome::Pass(format!(
        "KAT/differential packages: {} (expected set matches)",
        list(&found)
    )))
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

pub(crate) fn mutants(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::MUTANTS)?;
    let mut c = Cmd::cargo().args(["mutants", "--no-shuffle", "--output", "target"]);
    for p in expect::MUTANT_PACKAGES {
        c = c.args(["--package", p]);
    }
    let cap = c.dir(&ctx.root).capture()?;
    say(cap.stdout.trim_end());
    if !cap.success {
        say(cap.stderr.trim_end());
        bail!(
            "cargo mutants failed (exit {:?}): missed/timeout mutants or baseline failure",
            cap.code
        );
    }
    let summary = cap
        .stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .to_owned();
    Ok(Outcome::Pass(format!(
        "{}: {summary}",
        expect::MUTANT_PACKAGES.join(", ")
    )))
}

pub(crate) fn miri(ctx: &Ctx) -> Result<Outcome> {
    tools::require_nightly(&["miri", "rust-src"])?;
    Cmd::cargo_on(tools::NIGHTLY)
        .args(["miri", "setup"])
        .dir(&ctx.root)
        .run()?;
    let mut c = Cmd::cargo_on(tools::NIGHTLY)
        .args(["miri", "test", "--locked"])
        .dir(&ctx.root);
    for p in expect::MIRI_PACKAGES {
        c = c.args(["--package", p]);
    }
    c.run()?;
    Ok(Outcome::Pass(format!(
        "Miri ({}): {}",
        tools::NIGHTLY,
        expect::MIRI_PACKAGES.join(", ")
    )))
}

pub(crate) fn kani(ctx: &Ctx) -> Result<Outcome> {
    tools::require(tools::KANI)?;
    let mut found = BTreeSet::new();
    for p in &ctx.ws.members {
        let Some(dir) = p.manifest_path.parent() else {
            continue;
        };
        for f in walk_files(dir, &|x: &Path| x.extension().is_some_and(|e| e == "rs"))? {
            // spelled in two parts so that this file does not count as a harness
            if std::fs::read_to_string(&f)?.contains(concat!("#[kani", "::proof]")) {
                found.insert(p.name.clone());
            }
        }
    }
    same_set("Kani harness packages", &found, expect::KANI_PACKAGES)?;
    for p in &found {
        Cmd::cargo()
            .args(["kani", "--package", p])
            .dir(&ctx.root)
            .run()?;
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

pub(crate) fn ref_vectors(ctx: &Ctx) -> Result<Outcome> {
    let impl_files = walk_files(&ctx.root.join("ref"), &|p: &Path| {
        p.file_name().is_some_and(|n| n != "README.md")
    })?;
    if !impl_files.is_empty() {
        bail!("ref/ contains an implementation but `cargo xtask vectors` is still the M0 stub");
    }
    Ok(Outcome::Stub(
        "ref/ holds only its README; the cross-check starts in M1 with the separate reference session (OQ-17, ADR-026)".into(),
    ))
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
