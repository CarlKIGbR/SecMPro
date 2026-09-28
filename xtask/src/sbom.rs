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
    let mut build = Cmd::cargo()
        .args(["auditable", "build", "--release", "--locked"])
        .args(["--config", &remap_config(root, &triple)?]);
    for bin in expect::BINARIES {
        build = build.args(["--package", bin]);
    }
    build.dir(root).run()?;
    let mut audited = Vec::new();
    for bin in expect::BINARIES {
        let exe = root
            .join("target")
            .join("release")
            .join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
        Cmd::cargo()
            .args(["audit", "bin", "--deny", "warnings"])
            .arg(exe.to_string_lossy())
            .run()?;
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

    #[test]
    fn toml_escaping() {
        assert_eq!(toml_str(r"C:\a\b"), r"C:\\a\\b");
        assert_eq!(toml_str("a\"b"), "a\\\"b");
    }
}
