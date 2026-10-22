// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask sbom` (docs/06 §5 step 13): CycloneDX SBOMs for every workspace crate and `cargo auditable`
//! release builds of the binaries, whose embedded dependency lists are read back with `cargo audit bin`.

use std::path::{Path, PathBuf};

use crate::expect;
use crate::tools;
use crate::util::{Cmd, Error, Result, bail, rel, say, walk_files};

/// Escape a string for a TOML basic string.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out
}

/// The host target triple (`rustc -vV`).
pub(crate) fn host_triple() -> Result<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let vv = Cmd::new(rustc).arg("-vV").read()?;
    vv.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| Error("rustc -vV printed no host line".to_owned()))
}

fn cargo_home() -> Result<PathBuf> {
    if let Ok(h) = std::env::var("CARGO_HOME") {
        return Ok(PathBuf::from(h));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| Error("no HOME".to_owned()))?;
    Ok(PathBuf::from(home).join(".cargo"))
}

/// `--config` argument that appends the release path remapping of docs/06 §6 to the target's rustflags
/// (Cargo merges config arrays, so the flags of `.cargo/config.toml` are kept).
pub(crate) fn remap_config(root: &Path, triple: &str) -> Result<String> {
    let flags = [
        format!("--remap-path-prefix={}=/secmpro", root.display()),
        format!("--remap-path-prefix={}=/cargo", cargo_home()?.display()),
    ];
    let list: Vec<String> = flags
        .iter()
        .map(|f| format!("\"{}\"", toml_str(f)))
        .collect();
    Ok(format!("target.{triple}.rustflags=[{}]", list.join(",")))
}

/// The number of `[[package]]` entries of a `Cargo.lock`.
fn lock_packages(lock: &str) -> u64 {
    lock.lines()
        .filter(|l| l.trim_end() == "[[package]]")
        .count()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// The `dependency-count` of `cargo audit --json bin` (the only per-binary figure that report carries: the package
/// names are not in it).
fn embedded_count(report: &str) -> Result<u64> {
    let v: serde_json::Value = serde_json::from_str(report)
        .map_err(|_| Error("`cargo audit --json bin` printed no JSON".to_owned()))?;
    v.get("lockfile")
        .and_then(|l| l.get("dependency-count"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error("`cargo audit --json bin`: no lockfile.dependency-count".to_owned()))
}

/// The embedded dependency list of `bin`: built with `cargo auditable` (`unaudited`: `cargo audit` said it was not, or the
/// list is empty — it then recovers a handful of names from panic messages) and no longer than `Cargo.lock`
/// (`embedded > locked`). A lower bound from a locally computed closure is platform- and resolver-dependent (run #178:
/// 78 embedded against 79 by `cargo tree` on the runner) and is not checked; names and versions need the `.dep-v0` section
/// (M7, ADR).
pub(crate) fn embedded_findings(
    bin: &str,
    embedded: u64,
    locked: u64,
    unaudited: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if unaudited || embedded == 0 {
        out.push(format!(
            "sbom: {bin} was not built with cargo auditable ({embedded} packages recovered)"
        ));
    }
    if embedded > locked {
        out.push(format!(
            "sbom: {bin} embeds {embedded} packages, more than the {locked} of Cargo.lock"
        ));
    }
    out
}

pub(crate) fn run(root: &Path) -> Result<String> {
    tools::require(tools::CYCLONEDX)?;
    tools::require(tools::AUDITABLE)?;
    tools::require(tools::AUDIT)?;
    let out_dir = root.join("target").join("sbom");
    std::fs::create_dir_all(&out_dir)?;
    Cmd::cargo()
        .args([
            "cyclonedx",
            "--all",
            "--format",
            "json",
            "--spec-version",
            "1.5",
        ])
        .dir(root)
        .run()?;
    // cargo-cyclonedx writes next to each manifest; collect them under target/sbom.
    let mut moved = 0_usize;
    for dir in ["crates", "xtask"] {
        for f in walk_files(&root.join(dir), &|p: &Path| {
            p.to_string_lossy().ends_with(".cdx.json")
        })? {
            let name = f
                .file_name()
                .ok_or_else(|| Error("SBOM without a file name".to_owned()))?;
            std::fs::rename(&f, out_dir.join(name))?;
            moved = moved.saturating_add(1);
        }
    }
    if moved == 0 {
        bail!("cargo cyclonedx produced no SBOM files");
    }
    let triple = host_triple()?;
    // OPEN-M6-C1-3: the step owns its target directory, so no test or other build can rewrite the binaries it reads back
    // (`relay_bin()` of the harness runs a plain `cargo build --release -p secmp-relay` into `target/release`, a binary
    // without audit data that `cargo audit bin` accepts with a warning), and it relinks every binary, so the embedded list
    // is the one of the current `Cargo.lock`.
    let target_dir = root.join("target").join("sbom-build");
    for bin in expect::BINARIES {
        Cmd::cargo()
            .args(["clean", "--release", "--package", bin])
            .args(["--target-dir", &target_dir.to_string_lossy()])
            .dir(root)
            .run()?;
    }
    let mut build = Cmd::cargo()
        .args(["auditable", "build", "--release", "--locked"])
        .args(["--target-dir", &target_dir.to_string_lossy()])
        .args(["--config", &remap_config(root, &triple)?]);
    for bin in expect::BINARIES {
        build = build.args(["--package", bin]);
    }
    build.dir(root).run()?;
    let locked = lock_packages(&std::fs::read_to_string(root.join("Cargo.lock"))?);
    let mut audited = Vec::new();
    for bin in expect::BINARIES {
        let exe = target_dir
            .join("release")
            .join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
        let audit = Cmd::cargo()
            .args(["audit", "--deny", "warnings", "--json", "bin"])
            .arg(exe.to_string_lossy())
            .capture()?;
        if !audit.success {
            bail!("cargo audit bin {bin}: {}", audit.stderr.trim());
        }
        let embedded = embedded_count(&audit.stdout)?;
        let unaudited = audit.stderr.contains("not built with 'cargo auditable'");
        let found = embedded_findings(bin, embedded, locked, unaudited);
        if !found.is_empty() {
            bail!("{}", found.join("; "));
        }
        audited.push(rel(root, &exe));
    }
    say(&format!("  SBOMs in {}", rel(root, &out_dir)));
    Ok(format!(
        "{moved} CycloneDX SBOMs in target/sbom; auditable release builds ({triple}, remapped paths) read back by `cargo audit bin`: {}",
        audited.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OPEN-M6-C1-3: a binary of the nested plain `cargo build --release -p secmp-relay` carries no audit data; `cargo audit
    /// bin` recovered 4 packages from it (container, 2026-10-22), said so on stderr and exited 0. Both signs are findings.
    #[test]
    fn unaudited_binary_fails() {
        let found = embedded_findings("secmp-relay", 4, 190, true);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found
                .iter()
                .all(|f| f.contains("not built with cargo auditable"))
        );
        let empty = embedded_findings("secmp-relay", 0, 190, false);
        assert_eq!(empty.len(), 1, "{empty:?}");
    }

    /// An embedded count above the packages of `Cargo.lock` is a finding (a list that does not belong to this lock).
    #[test]
    fn embedded_count_above_lock_fails() {
        let found = embedded_findings("secmp-relay", 191, 190, false);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found.iter().all(|f| f.contains("more than the 190")));
    }

    /// The auditable relay embeds 78 packages, within (0, lock]; the parsers read the figures of the real outputs.
    #[test]
    fn embedded_count_within_lock_passes() {
        assert!(embedded_findings("secmp-relay", 78, 190, false).is_empty());
        assert!(embedded_findings("secmp-relay", 190, 190, false).is_empty());
        let report = r#"{"lockfile":{"dependency-count":78},"vulnerabilities":{"found":false}}"#;
        assert_eq!(embedded_count(report).ok(), Some(78));
        assert!(embedded_count("not json").is_err());
        let lock = "[[package]]\nname = \"a\"\n\n[[package]]\nname = \"b\"\n";
        assert_eq!(lock_packages(lock), 2);
    }

    #[test]
    fn toml_escaping() {
        assert_eq!(toml_str(r"C:\a\b"), r"C:\\a\\b");
        assert_eq!(toml_str("a\"b"), "a\\\"b");
    }
}
