// SPDX-License-Identifier: AGPL-3.0-or-later
//! Repository policy checks that the compiler and clippy cannot express on their own.
//!
//! * `forbid-unsafe`: every target root (lib, bin, test, bench, example) of every workspace crate except the
//!   two `secmp-sys-*` crates declares `#![forbid(unsafe_code)]` in its inner-attribute header (docs/06 §2).
//! * `lints-table`: every member manifest inherits `[lints] workspace = true` and declares no lints of its own.
//! * `lint-allows`: no attribute relaxes a lint unless sanctioned (`expect::LINT_ALLOWANCES`, docs/06 §2).
//! * `build-scripts`: no workspace crate has a build script (CLAUDE.md §1.9).
//! * `spdx`: every first-party source file starts with the AGPL-3.0-or-later SPDX header.
//! * `vet-closure`: no cargo-vet exemption covers a crate in the `secmp-crypto`/`secmp-proto` closure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::expect;
use crate::meta::Workspace;
use crate::util::{Result, bail, rel, say, walk_files};

pub(crate) const SPDX_RS: &str = "// SPDX-License-Identifier: AGPL-3.0-or-later";
pub(crate) const SPDX_HASH: &str = "# SPDX-License-Identifier: AGPL-3.0-or-later";
pub(crate) const SPDX_ML: &str = "(* SPDX-License-Identifier: AGPL-3.0-or-later *)";

/// True if `#![forbid(unsafe_code)]` appears in the inner-attribute header of `src`: the leading run of blank
/// lines, `//` comments (including `//!` docs) and single-line inner attributes. Anything else (an item, a
/// block comment, a multi-line attribute) ends the header, so an unusual layout fails closed.
pub(crate) fn header_forbids_unsafe(src: &str) -> bool {
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t.starts_with("#![") && t.ends_with(']') {
            let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            if compact == "#![forbid(unsafe_code)]" {
                return true;
            }
            continue;
        }
        return false;
    }
    false
}

fn check_forbid_unsafe(ws: &Workspace, findings: &mut Vec<String>) -> Result<usize> {
    let mut checked = 0_usize;
    for p in &ws.members {
        if expect::UNSAFE_ALLOWED.contains(&p.name.as_str()) {
            continue;
        }
        for t in &p.targets {
            let src = std::fs::read_to_string(&t.src_path)?;
            checked = checked.saturating_add(1);
            if !header_forbids_unsafe(&src) {
                findings.push(format!(
                    "forbid-unsafe: {} (crate {}, target {} [{}]) lacks #![forbid(unsafe_code)]",
                    rel(&ws.root, &t.src_path),
                    p.name,
                    t.name,
                    t.kinds.join(",")
                ));
            }
        }
    }
    Ok(checked)
}

/// True if a manifest inherits the workspace lints and declares none of its own.
pub(crate) fn manifest_lints_ok(manifest: &str) -> bool {
    let mut in_lints = false;
    let mut inherits = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            let header: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            if header.starts_with("[lints.") || header.starts_with("[package.lints") {
                return false;
            }
            in_lints = header == "[lints]";
            continue;
        }
        if in_lints && !t.is_empty() && !t.starts_with('#') {
            let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            if compact == "workspace=true" {
                inherits = true;
            } else {
                return false;
            }
        }
    }
    inherits
}

/// One lint-relaxing attribute found in a source file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Relaxation {
    pub(crate) lint: String,
    /// True for an inner attribute (`#![...]`) that appears before any item.
    pub(crate) file_top: bool,
}

/// Find `allow(...)`, `expect(...)` and `warn(...)` lint lists inside `#[...]`/`#![...]` attributes
/// (including `cfg_attr`). Brackets are matched across lines and `//` comments are skipped; block comments and
/// string literals are not parsed, so attribute-like text there is reported too (fails closed).
pub(crate) fn find_relaxations(src: &str) -> Vec<Relaxation> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut seen_item = false;
    let mut i = 0_usize;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i.saturating_add(1)).copied();
        if c == '#'
            && (next == Some('[')
                || (next == Some('!') && chars.get(i.saturating_add(2)) == Some(&'[')))
        {
            let inner = next == Some('!');
            let open = if inner {
                i.saturating_add(2)
            } else {
                i.saturating_add(1)
            };
            let mut depth = 0_usize;
            let mut j = open;
            while let Some(&cj) = chars.get(j) {
                if cj == '[' {
                    depth = depth.saturating_add(1);
                } else if cj == ']' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                j = j.saturating_add(1);
            }
            let body: String = chars
                .get(open..j.min(chars.len()))
                .unwrap_or_default()
                .iter()
                .collect();
            for lint in relaxed_lints(&body) {
                out.push(Relaxation {
                    lint,
                    file_top: inner && !seen_item,
                });
            }
            i = j.saturating_add(1);
            continue;
        }
        if !c.is_whitespace() && !is_comment_or_attr_start(&chars, i) {
            seen_item = true;
        }
        if c == '/' && next == Some('/') {
            // skip line comments so doc text does not mark the header as ended
            while let Some(&cc) = chars.get(i) {
                if cc == '\n' {
                    break;
                }
                i = i.saturating_add(1);
            }
            continue;
        }
        i = i.saturating_add(1);
    }
    out
}

fn is_comment_or_attr_start(chars: &[char], i: usize) -> bool {
    let c = chars.get(i).copied();
    let n = chars.get(i.saturating_add(1)).copied();
    (c == Some('/') && n == Some('/')) || c == Some('#')
}

fn relaxed_lints(attr_body: &str) -> Vec<String> {
    let compact: String = attr_body.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::new();
    for key in ["allow(", "expect(", "warn("] {
        let mut rest = compact.as_str();
        while let Some(pos) = rest.find(key) {
            let before = rest.get(..pos).and_then(|b| b.chars().last());
            let after = rest
                .get(pos.saturating_add(key.len())..)
                .unwrap_or_default();
            // `allow(` must not be the tail of a longer identifier
            if before.is_some_and(|b| b.is_alphanumeric() || b == '_') {
                rest = after;
                continue;
            }
            let list: String = after.chars().take_while(|&c| c != ')').collect();
            for lint in list.split(',') {
                if !lint.is_empty() && !lint.starts_with("reason=") {
                    out.push(lint.to_owned());
                }
            }
            rest = after;
        }
    }
    out
}

fn check_lint_allows(root: &Path, files: &[PathBuf], findings: &mut Vec<String>) -> Result<usize> {
    let mut count = 0_usize;
    for f in files {
        let path = rel(root, f);
        let src = std::fs::read_to_string(f)?;
        for r in find_relaxations(&src) {
            count = count.saturating_add(1);
            let test_file = path.contains("/tests/")
                || path.starts_with("tests/")
                || expect::TEST_FILE_PREFIXES
                    .iter()
                    .any(|p| path.starts_with(p));
            let by_rule =
                test_file && r.file_top && expect::TEST_FILE_ALLOWANCE.contains(&r.lint.as_str());
            let listed = expect::LINT_ALLOWANCES
                .iter()
                .any(|(p, l, _)| *p == path && *l == r.lint);
            if !(by_rule || listed) {
                findings.push(format!(
                    "lint-allows: {path} relaxes `{}` (not sanctioned by docs/06 §2)",
                    r.lint
                ));
            }
        }
    }
    Ok(count)
}

fn check_build_scripts(ws: &Workspace, findings: &mut Vec<String>) -> usize {
    for p in &ws.members {
        if p.targets
            .iter()
            .any(|t| t.kinds.iter().any(|k| k == "custom-build"))
        {
            findings.push(format!(
                "build-scripts: crate {} has a build script",
                p.name
            ));
        }
        if let Some(dir) = p.manifest_path.parent()
            && dir.join("build.rs").exists()
        {
            findings.push(format!(
                "build-scripts: {} exists",
                rel(&ws.root, &dir.join("build.rs"))
            ));
        }
    }
    ws.members.len()
}

/// First-party files that must carry the SPDX header, relative to `root`.
fn spdx_files(root: &Path) -> Result<Vec<(PathBuf, &'static str)>> {
    let mut out = Vec::new();
    for dir in [
        "crates", "xtask", "fuzz", "formal", "deploy", "ref", "vectors", ".cargo", ".github",
    ] {
        let d = root.join(dir);
        if !d.exists() {
            continue;
        }
        let pred = |p: &Path| {
            p.extension().is_some_and(|e| {
                ["rs", "toml", "yml", "yaml", "sh", "pv", "py", "service"]
                    .contains(&e.to_string_lossy().as_ref())
            })
        };
        for f in walk_files(&d, &pred)? {
            // fixtures are data that is fed to external tools verbatim
            if rel(root, &f).contains("/fixtures/") {
                continue;
            }
            let header = match f.extension().and_then(|e| e.to_str()) {
                Some("rs") => SPDX_RS,
                Some("pv") => SPDX_ML,
                _ => SPDX_HASH,
            };
            out.push((f, header));
        }
    }
    for f in [
        "Cargo.toml",
        "rust-toolchain.toml",
        "clippy.toml",
        "deny.toml",
        ".gitignore",
    ] {
        let p = root.join(f);
        if p.exists() {
            out.push((p, SPDX_HASH));
        }
    }
    Ok(out)
}

fn check_spdx(root: &Path, findings: &mut Vec<String>) -> Result<usize> {
    let files = spdx_files(root)?;
    for (f, header) in &files {
        let src = std::fs::read_to_string(f)?;
        let first = src.lines().next().unwrap_or_default().trim_end();
        if first != *header {
            findings.push(format!(
                "spdx: {} does not start with `{header}`",
                rel(root, f)
            ));
        }
    }
    Ok(files.len())
}

/// `[[exemptions.<name>]]` entries of `supply-chain/config.toml`: (crate name, has a tracked-exemption note).
pub(crate) fn vet_exemptions(config: &str) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    let mut in_exemption = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_exemption = false;
            if let Some(name) = t
                .strip_prefix("[[exemptions.")
                .and_then(|r| r.strip_suffix("]]"))
            {
                out.push((name.trim_matches('"').to_owned(), false));
                in_exemption = true;
            }
        } else if in_exemption
            && t.starts_with("notes")
            && t.contains("Tracked exemption")
            && let Some(last) = out.last_mut()
        {
            last.1 = true;
        }
    }
    out
}

/// `vet-closure`: zero exemptions in the `secmp-crypto`/`secmp-proto` closure (docs/06 §3).
pub(crate) fn check_vet_closure(ws: &Workspace) -> Result<String> {
    let config = std::fs::read_to_string(ws.root.join("supply-chain").join("config.toml"))?;
    let entries = vet_exemptions(&config);
    let untracked: Vec<&str> = entries
        .iter()
        .filter(|(_, noted)| !noted)
        .map(|(n, _)| n.as_str())
        .collect();
    if !untracked.is_empty() {
        bail!(
            "cargo-vet exemptions without a tracked-exemption note (supply-chain/README.md): {}",
            untracked.join(", ")
        );
    }
    let exempt: BTreeSet<String> = entries.into_iter().map(|(n, _)| n).collect();
    let mut closure = BTreeSet::new();
    for root in expect::ZERO_EXEMPTION_ROOTS {
        closure.extend(ws.external_closure(root)?);
    }
    let bad: Vec<String> = closure
        .iter()
        .filter(|(n, _)| exempt.contains(n))
        .map(|(n, v)| format!("{n} {v}"))
        .collect();
    if !bad.is_empty() {
        bail!(
            "cargo-vet exemptions inside the secmp-crypto/secmp-proto closure: {}",
            bad.join(", ")
        );
    }
    Ok(format!(
        "secmp-crypto/secmp-proto closure: {} external crates, 0 exempted; tracked exemptions elsewhere: {}",
        closure.len(),
        exempt.len()
    ))
}

/// Run every policy check; fail with the full list of findings.
pub(crate) fn run(ws: &Workspace) -> Result<String> {
    let mut findings = Vec::new();
    let roots = check_forbid_unsafe(ws, &mut findings)?;
    let mut manifests = 0_usize;
    for p in &ws.members {
        manifests = manifests.saturating_add(1);
        if !manifest_lints_ok(&std::fs::read_to_string(&p.manifest_path)?) {
            findings.push(format!(
                "lints-table: {} must contain exactly `[lints] workspace = true`",
                rel(&ws.root, &p.manifest_path)
            ));
        }
    }
    let rs_files: Vec<PathBuf> = ["crates", "xtask", "fuzz"]
        .iter()
        .map(|d| ws.root.join(d))
        .filter(|d| d.exists())
        .map(|d| walk_files(&d, &|p: &Path| p.extension().is_some_and(|e| e == "rs")))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let relaxations = check_lint_allows(&ws.root, &rs_files, &mut findings)?;
    let crates = check_build_scripts(ws, &mut findings);
    let spdx = check_spdx(&ws.root, &mut findings)?;
    let vet = check_vet_closure(ws);
    if let Err(e) = &vet {
        findings.push(format!("vet-closure: {e}"));
    }
    for f in &findings {
        say(&format!("  FINDING {f}"));
    }
    if !findings.is_empty() {
        bail!("{} policy finding(s)", findings.len());
    }
    Ok(format!(
        "forbid-unsafe: {roots} target roots; lints-table: {manifests} manifests; lint-allows: {relaxations} relaxing attributes \
         (all sanctioned); build-scripts: {crates} crates, none; spdx: {spdx} files; {}",
        vet.unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbid_header_detection() {
        assert!(header_forbids_unsafe(
            "// SPDX\n//! doc\n#![forbid(unsafe_code)]\nfn main() {}\n"
        ));
        assert!(header_forbids_unsafe(
            "#![deny(missing_docs)]\n#![forbid( unsafe_code )]\n"
        ));
        // after an item: not in the header
        assert!(!header_forbids_unsafe(
            "fn f() {}\n#![forbid(unsafe_code)]\n"
        ));
        // commented out
        assert!(!header_forbids_unsafe(
            "// #![forbid(unsafe_code)]\nfn main() {}\n"
        ));
        // inside a block comment: fails closed
        assert!(!header_forbids_unsafe("/*\n#![forbid(unsafe_code)]\n*/\n"));
        // weaker attribute
        assert!(!header_forbids_unsafe("#![deny(unsafe_code)]\n"));
        assert!(!header_forbids_unsafe(""));
    }

    #[test]
    fn manifest_lints_table() {
        assert!(manifest_lints_ok(
            "[package]\nname = \"x\"\n\n[lints]\nworkspace = true\n"
        ));
        assert!(!manifest_lints_ok("[package]\nname = \"x\"\n"));
        assert!(!manifest_lints_ok(
            "[lints]\nworkspace = true\n[lints.clippy]\nunwrap_used = \"allow\"\n"
        ));
        assert!(!manifest_lints_ok(
            "[lints.rust]\nunsafe_code = \"allow\"\n"
        ));
        assert!(!manifest_lints_ok("[lints]\nworkspace = false\n"));
    }

    /// Test inputs spell the attribute names in upper case and are lowered here, so that this file's own
    /// source contains no relaxing attribute for the `lint-allows` scan to find.
    fn src(s: &str) -> String {
        s.replace("ALLOW(", "allow(")
            .replace("EXPECT(", "expect(")
            .replace("WARN(", "warn(")
    }

    #[test]
    fn relaxations_are_found() {
        let lints = |s: &str| {
            find_relaxations(&src(s))
                .into_iter()
                .map(|r| r.lint)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            lints("#[ALLOW(clippy::unwrap_used)]\nfn f() {}"),
            vec!["clippy::unwrap_used"]
        );
        assert_eq!(
            lints("#[EXPECT(unsafe_code, reason = \"x\")]\nfn f() {}"),
            vec!["unsafe_code"]
        );
        assert_eq!(
            lints("#[cfg_attr(test, ALLOW(clippy::panic))]\nfn f() {}"),
            vec!["clippy::panic"]
        );
        assert_eq!(
            lints("#![WARN(\n  clippy::indexing_slicing,\n  missing_docs\n)]\n"),
            vec!["clippy::indexing_slicing", "missing_docs"]
        );
        assert_eq!(
            lints("#[deny(clippy::panic)]\n#[shALLOW(x)]\nfn f() {}"),
            Vec::<String>::new()
        );
        assert_eq!(
            lints("// #[ALLOW(clippy::panic)] in a comment is skipped\nfn f() {}"),
            Vec::<String>::new()
        );
        assert!(find_relaxations("#[derive(Debug)]\nstruct S;").is_empty());
    }

    #[test]
    fn file_top_is_tracked() {
        let r = find_relaxations(&src(
            "// SPDX\n//! doc\n#![ALLOW(clippy::unwrap_used)]\nfn f() {}\n",
        ));
        assert_eq!(
            r,
            vec![Relaxation {
                lint: "clippy::unwrap_used".into(),
                file_top: true
            }]
        );
        let r = find_relaxations(&src("fn f() {}\n#![ALLOW(clippy::unwrap_used)]\n"));
        assert_eq!(
            r,
            vec![Relaxation {
                lint: "clippy::unwrap_used".into(),
                file_top: false
            }]
        );
    }

    #[test]
    fn exemption_names() {
        let cfg = "[policy.x]\n\n[[exemptions.serde]]\nversion = \"1\"\n\n[[exemptions.\"weird-name\"]]\n";
        assert_eq!(
            vet_exemptions(cfg),
            vec![
                ("serde".to_owned(), false),
                ("weird-name".to_owned(), false)
            ]
        );
        let noted = "[[exemptions.a]]\nversion = \"1\"\nnotes = \"Tracked exemption: pulled by x\"\n\n[[exemptions.b]]\n";
        assert_eq!(
            vet_exemptions(noted),
            vec![("a".to_owned(), true), ("b".to_owned(), false)]
        );
    }
}
