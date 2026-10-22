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

/// The number of distinct packages of a `cargo tree --prefix none --format "{p}"` listing (the repeat marker and the
/// proc-macro marker are not part of the package).
fn closure_count(tree: &str) -> u64 {
    let mut seen = std::collections::BTreeSet::new();
    for line in tree.lines() {
        let l = line.trim_end().trim_end_matches(" (*)");
        seen.insert(l.replace(" (proc-macro)", ""));
    }
    seen.remove("");
    seen.len().try_into().unwrap_or(u64::MAX)
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

/// The embedded dependency list of `bin` against the lock: at least the packages of the lock's closure of the binary
/// (`embedded < closure`: the binary was not built with `cargo auditable`, `cargo audit` then recovers a handful of
/// names from panic messages, or it is a stale or foreign binary) and at most the packages of the lock.
pub(crate) fn embedded_findings(
    bin: &str,
    embedded: u64,
    closure: u64,
    locked: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    if embedded < closure {
        out.push(format!(
            "sbom: {bin} embeds {embedded} packages, fewer than the {closure} of its closure in Cargo.lock (not built with cargo auditable, stale or foreign binary)"
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
        let report = Cmd::cargo()
            .args(["audit", "--deny", "warnings", "--json", "bin"])
            .arg(exe.to_string_lossy())
            .read()?;
        let embedded = embedded_count(&report)?;
        let tree = Cmd::cargo()
            .args(["tree", "--package", bin, "--edges", "normal,build"])
            .args(["--prefix", "none", "--locked", "--format", "{p}"])
            .dir(root)
            .read()?;
        let found = embedded_findings(bin, embedded, closure_count(&tree), locked);
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
    /// bin` recovered 4 packages from it (container, 2026-10-22) and exited 0. The embedded list is shorter than the lock's
    /// closure (57 packages for the relay) and the step fails.
    #[test]
    fn stale_embedded_package_fails() {
        let found = embedded_findings("secmp-relay", 4, 57, 190);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found.iter().all(|f| f.contains("secmp-relay embeds 4")));
        // more than the lock has is a finding too
        assert_eq!(embedded_findings("secmp-relay", 191, 57, 190).len(), 1);
    }

    /// The auditable relay of the same tree embeds 78 packages, between its closure (57) and the lock; the parsers read the
    /// figures of the real outputs.
    #[test]
    fn embedded_packages_match_lock_passes() {
        assert!(embedded_findings("secmp-relay", 78, 57, 190).is_empty());
        let report = r#"{"lockfile":{"dependency-count":78},"vulnerabilities":{"found":false}}"#;
        assert_eq!(embedded_count(report).ok(), Some(78));
        assert!(embedded_count("not json").is_err());
        let lock = "[[package]]\nname = \"a\"\n\n[[package]]\nname = \"b\"\n";
        assert_eq!(lock_packages(lock), 2);
        let tree = "secmp-relay v0.0.0 (/x)\nserde v1.0.0\nserde v1.0.0 (*)\nsyn v2.0.0 (proc-macro)\nsyn v2.0.0\n";
        assert_eq!(closure_count(tree), 3);
    }

    #[test]
    fn toml_escaping() {
        assert_eq!(toml_str(r"C:\a\b"), r"C:\\a\\b");
        assert_eq!(toml_str("a\"b"), "a\\\"b");
    }
}
