// SPDX-License-Identifier: AGPL-3.0-or-later
//! Repository policy checks that the compiler and clippy cannot express on their own.
//!
//! * `unsafe-attrs`: the `unsafe_code` rules of docs/06 §2. Every target root (lib, bin, test, bench, example)
//!   declares `#![forbid(unsafe_code)]` in its inner-attribute header, except (a) the library root of
//!   `secmp-sys-mem`/`secmp-sys-desktop`, which declares `#![allow(unsafe_code)]` — the only relaxation of
//!   `unsafe_code` first-party code may contain, anywhere — and (b) the roots of `secmp-ui`, which declare
//!   `#![deny(unsafe_code)]` (or `forbid`) while the crate's own `.rs` files contain neither the token `unsafe`
//!   nor any relaxation of `unsafe_code` (ADR-033: only `slint!` expansions may carry one).
//! * `lints-table`: every member manifest inherits `[lints] workspace = true` and declares no lints of its own.
//! * `lint-allows`: no attribute relaxes a lint unless sanctioned (`expect::LINT_ALLOWANCES`, docs/06 §2);
//!   `unsafe_code` is owned by `unsafe-attrs`.
//! * `build-scripts`: no workspace crate has a build script (CLAUDE.md §1.9).
//! * `spdx`: every first-party source file starts with the AGPL-3.0-or-later SPDX header.
//! * `vet-closure`: no cargo-vet exemption covers a crate in the normal (shipped) `secmp-crypto`/`secmp-proto`
//!   closure (ADR-036), and every exemption carries a tracked-exemption note.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::expect;
use crate::meta::Workspace;
use crate::util::{Result, bail, rel, say, walk_files};

pub(crate) const SPDX_RS: &str = "// SPDX-License-Identifier: AGPL-3.0-or-later";
pub(crate) const SPDX_HASH: &str = "# SPDX-License-Identifier: AGPL-3.0-or-later";
pub(crate) const SPDX_ML: &str = "(* SPDX-License-Identifier: AGPL-3.0-or-later *)";

/// Library-like target kinds (`cargo metadata`): the crate root that `#![allow(unsafe_code)]` applies to.
const LIB_KINDS: &[&str] = &["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"];

const FORBID_UNSAFE: &str = "forbid(unsafe_code)";
const DENY_UNSAFE: &str = "deny(unsafe_code)";
/// The one sanctioned relaxation, compared with the whitespace-free attribute body. Messages build the
/// attribute from this constant, so this file itself contains no `unsafe_code` relaxation for the scan to find.
const ALLOW_UNSAFE: &str = "allow(unsafe_code)";

/// True if the inner attribute `#![<attr>]` appears in the inner-attribute header of `src`: the leading run of
/// blank lines, `//` comments (including `//!` docs) and single-line inner attributes. Anything else (an item, a
/// block comment, a multi-line attribute) ends the header, so an unusual layout fails closed. Whitespace inside
/// the attribute is ignored.
pub(crate) fn header_declares(src: &str, attr: &str) -> bool {
    let wanted = format!("#![{attr}]");
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t.starts_with("#![") && t.ends_with(']') {
            let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            if compact == wanted {
                return true;
            }
            continue;
        }
        return false;
    }
    false
}

/// How docs/06 §2 treats `unsafe_code` in one crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnsafeRule {
    /// Every crate not listed below: `#![forbid(unsafe_code)]` in every target root.
    Forbid,
    /// `expect::UNSAFE_ALLOWED`: `#![allow(unsafe_code)]` in the library root, `forbid` in every other root.
    SysAllow,
    /// `expect::UNSAFE_DENY_ONLY` (ADR-033): `#![deny(unsafe_code)]` or `forbid` in every root; no `unsafe`
    /// token and no relaxation of `unsafe_code` in the crate's own `.rs` files.
    UiDeny,
}

pub(crate) fn unsafe_rule(krate: &str) -> UnsafeRule {
    if expect::UNSAFE_ALLOWED.contains(&krate) {
        UnsafeRule::SysAllow
    } else if expect::UNSAFE_DENY_ONLY.contains(&krate) {
        UnsafeRule::UiDeny
    } else {
        UnsafeRule::Forbid
    }
}

/// One target root as the `unsafe-attrs` check sees it.
#[derive(Debug)]
pub(crate) struct Root {
    pub(crate) krate: String,
    /// Target name and kinds, for the message (e.g. `hello [test]`).
    pub(crate) target: String,
    /// Path relative to the workspace root.
    pub(crate) path: String,
    /// The library root of its crate (`LIB_KINDS`).
    pub(crate) lib: bool,
    pub(crate) src: String,
}

/// The header finding for one target root, if any.
pub(crate) fn root_finding(r: &Root) -> Option<String> {
    let (ok, wanted) = match unsafe_rule(&r.krate) {
        UnsafeRule::SysAllow if r.lib => (
            header_declares(&r.src, ALLOW_UNSAFE),
            format!("#![{ALLOW_UNSAFE}] (library root of a secmp-sys-* crate)"),
        ),
        UnsafeRule::Forbid | UnsafeRule::SysAllow => (
            header_declares(&r.src, FORBID_UNSAFE),
            format!("#![{FORBID_UNSAFE}]"),
        ),
        UnsafeRule::UiDeny => (
            header_declares(&r.src, DENY_UNSAFE) || header_declares(&r.src, FORBID_UNSAFE),
            format!("#![{DENY_UNSAFE}] (ADR-033)"),
        ),
    };
    (!ok).then(|| {
        format!(
            "unsafe-attrs: {} (crate {}, target {}) lacks {wanted} in its inner-attribute header",
            r.path, r.krate, r.target
        )
    })
}

/// 1-based numbers of the lines on which the keyword `unsafe` occurs as a whole token. The raw text is
/// scanned — comments and string literals count — so the check fails closed.
pub(crate) fn unsafe_token_lines(src: &str) -> Vec<usize> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let hit = line.match_indices("unsafe").any(|(i, m)| {
            let before = line.get(..i).and_then(|b| b.chars().last());
            let after = line
                .get(i.saturating_add(m.len())..)
                .and_then(|a| a.chars().next());
            !before.is_some_and(ident) && !after.is_some_and(ident)
        });
        if hit {
            out.push(n.saturating_add(1));
        }
    }
    out
}

/// `unsafe_code` findings for one first-party `.rs` file (`path` relative to the workspace root): every
/// relaxation of `unsafe_code` except the exact `#![allow(unsafe_code)]` at the top of a `SysAllow` library
/// root, and — in a `UiDeny` crate — every line holding the token `unsafe`.
pub(crate) fn unsafe_source_findings(
    path: &str,
    src: &str,
    sys_lib_root: bool,
    ui: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for r in find_relaxations(src) {
        if r.lint != "unsafe_code" {
            continue;
        }
        if sys_lib_root && r.file_top && r.attr == ALLOW_UNSAFE {
            continue;
        }
        out.push(format!(
            "unsafe-attrs: {path} relaxes `unsafe_code` with `{}` (docs/06 §2: only `#![{ALLOW_UNSAFE}]` at the \
             library root of secmp-sys-mem/secmp-sys-desktop{})",
            r.attr,
            if ui {
                "; secmp-ui tolerates only the one inside `slint!` expansions, ADR-033"
            } else {
                ""
            }
        ));
    }
    if ui {
        for n in unsafe_token_lines(src) {
            out.push(format!(
                "unsafe-attrs: {path}:{n} contains the token `unsafe` (secmp-ui, ADR-033; comments count too)"
            ));
        }
    }
    out
}

/// Counts for the `unsafe-attrs` summary line.
#[derive(Default)]
struct UnsafeCounts {
    forbid: usize,
    sys_allow: usize,
    ui_deny: usize,
    ui_files: usize,
}

fn check_unsafe_attrs(
    ws: &Workspace,
    rs_files: &[PathBuf],
    findings: &mut Vec<String>,
) -> Result<UnsafeCounts> {
    let mut counts = UnsafeCounts::default();
    for name in expect::UNSAFE_ALLOWED
        .iter()
        .chain(expect::UNSAFE_DENY_ONLY)
    {
        if ws.member(name).is_none() {
            findings.push(format!(
                "unsafe-attrs: {name} is listed in xtask/src/expect.rs but is not a workspace member"
            ));
        }
    }
    let mut sys_lib_roots = BTreeSet::new();
    let mut ui_dirs = Vec::new();
    for p in &ws.members {
        let rule = unsafe_rule(&p.name);
        if rule == UnsafeRule::UiDeny
            && let Some(dir) = p.manifest_path.parent()
        {
            ui_dirs.push(format!("{}/", rel(&ws.root, dir)));
        }
        let mut has_lib = false;
        for t in &p.targets {
            let lib = t.kinds.iter().any(|k| LIB_KINDS.contains(&k.as_str()));
            has_lib |= lib;
            let root = Root {
                krate: p.name.clone(),
                target: format!("{} [{}]", t.name, t.kinds.join(",")),
                path: rel(&ws.root, &t.src_path),
                lib,
                src: std::fs::read_to_string(&t.src_path)?,
            };
            match rule {
                UnsafeRule::SysAllow if lib => {
                    counts.sys_allow = counts.sys_allow.saturating_add(1);
                    sys_lib_roots.insert(root.path.clone());
                }
                UnsafeRule::UiDeny => counts.ui_deny = counts.ui_deny.saturating_add(1),
                UnsafeRule::Forbid | UnsafeRule::SysAllow => {
                    counts.forbid = counts.forbid.saturating_add(1);
                }
            }
            findings.extend(root_finding(&root));
        }
        if rule == UnsafeRule::SysAllow && !has_lib {
            findings.push(format!(
                "unsafe-attrs: crate {} has no library root to carry #![{ALLOW_UNSAFE}]",
                p.name
            ));
        }
    }
    for f in rs_files {
        let path = rel(&ws.root, f);
        let ui = ui_dirs.iter().any(|d| path.starts_with(d.as_str()));
        if ui {
            counts.ui_files = counts.ui_files.saturating_add(1);
        }
        let src = std::fs::read_to_string(f)?;
        findings.extend(unsafe_source_findings(
            &path,
            &src,
            sys_lib_roots.contains(&path),
            ui,
        ));
    }
    Ok(counts)
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
    /// The whole attribute body between the brackets, without whitespace (e.g. `allow(unsafe_code)`).
    pub(crate) attr: String,
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
            // `body` starts with the opening bracket
            let attr: String = body
                .chars()
                .skip(1)
                .filter(|c| !c.is_whitespace())
                .collect();
            for lint in relaxed_lints(&body) {
                out.push(Relaxation {
                    lint,
                    file_top: inner && !seen_item,
                    attr: attr.clone(),
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
            if r.lint == "unsafe_code" {
                // owned by `unsafe-attrs`, which sanctions exactly one form at exactly two crate roots
                continue;
            }
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

/// The normal (shipped) dependency closure of `secmp-crypto`/`secmp-proto` (ADR-036, docs/06 §3): normal edges
/// only (`cargo tree -e normal`), taken on every target of `expect::VET_CLOSURE_TARGETS` and united, so a crate
/// compiled for any shipped target or the development host is inside. Build- and dev-dependencies and
/// dependencies of other platforms or unset `cfg`s are outside and may be tracked exemptions.
pub(crate) fn zero_exemption_closure(ws: &Workspace) -> Result<BTreeSet<(String, String)>> {
    let mut closure = BTreeSet::new();
    for triple in expect::VET_CLOSURE_TARGETS {
        let graph = Workspace::load_for_platform(triple)?;
        for root in expect::ZERO_EXEMPTION_ROOTS {
            if ws.member(root).is_none() {
                bail!("zero-exemption root {root} is not a workspace member");
            }
            closure.extend(graph.external_closure(root, true)?);
        }
    }
    Ok(closure)
}

/// `vet-closure`: zero exemptions in the normal `secmp-crypto`/`secmp-proto` closure (docs/06 §3, ADR-036).
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
    let closure = zero_exemption_closure(ws)?;
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
        "secmp-crypto/secmp-proto normal closure ({}): {} external crates, 0 exempted; tracked exemptions elsewhere: {}",
        expect::VET_CLOSURE_TARGETS.join(", "),
        closure.len(),
        exempt.len()
    ))
}

/// Run every policy check; fail with the full list of findings.
pub(crate) fn run(ws: &Workspace) -> Result<String> {
    let mut findings = Vec::new();
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
    let unsafe_counts = check_unsafe_attrs(ws, &rs_files, &mut findings)?;
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
    let UnsafeCounts {
        forbid,
        sys_allow,
        ui_deny,
        ui_files,
    } = unsafe_counts;
    Ok(format!(
        "unsafe-attrs: {forbid} target roots forbid, {sys_allow} sys library roots allow, {ui_deny} secmp-ui roots deny, \
         {ui_files} secmp-ui files without `unsafe`; lints-table: {manifests} manifests; lint-allows: {relaxations} \
         relaxing attributes (all sanctioned); build-scripts: {crates} crates, none; spdx: {spdx} files; {}",
        vet.unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbid_header_detection() {
        let forbids = |s: &str| header_declares(s, FORBID_UNSAFE);
        assert!(forbids(
            "// SPDX\n//! doc\n#![forbid(unsafe_code)]\nfn main() {}\n"
        ));
        assert!(forbids(
            "#![deny(missing_docs)]\n#![forbid( unsafe_code )]\n"
        ));
        // after an item: not in the header
        assert!(!forbids("fn f() {}\n#![forbid(unsafe_code)]\n"));
        // commented out
        assert!(!forbids("// #![forbid(unsafe_code)]\nfn main() {}\n"));
        // inside a block comment: fails closed
        assert!(!forbids("/*\n#![forbid(unsafe_code)]\n*/\n"));
        // weaker attribute
        assert!(!forbids("#![deny(unsafe_code)]\n"));
        assert!(!forbids(""));
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
                file_top: true,
                attr: src("ALLOW(clippy::unwrap_used)"),
            }]
        );
        let r = find_relaxations(&src("fn f() {}\n#![ALLOW(clippy::unwrap_used)]\n"));
        assert_eq!(
            r,
            vec![Relaxation {
                lint: "clippy::unwrap_used".into(),
                file_top: false,
                attr: src("ALLOW(clippy::unwrap_used)"),
            }]
        );
    }

    const SYS: &str = "secmp-sys-mem";
    const UI: &str = "secmp-ui";
    const PLAIN: &str = "secmp-proto";
    const FORBID_SRC: &str = "// SPDX\n//! doc\n#![forbid(unsafe_code)]\n";
    const DENY_SRC: &str = "// SPDX\n//! doc\n#![deny(unsafe_code)]\n";

    fn root(krate: &str, lib: bool, text: &str) -> Root {
        Root {
            krate: krate.to_owned(),
            target: "x [lib]".to_owned(),
            path: format!("crates/{krate}/src/x.rs"),
            lib,
            src: src(text),
        }
    }

    #[test]
    fn rules_follow_expect_lists() {
        assert_eq!(unsafe_rule("secmp-sys-mem"), UnsafeRule::SysAllow);
        assert_eq!(unsafe_rule("secmp-sys-desktop"), UnsafeRule::SysAllow);
        assert_eq!(unsafe_rule("secmp-ui"), UnsafeRule::UiDeny);
        for c in [
            "secmp-crypto",
            "secmp-proto",
            "secmp-transport",
            "secmp-store",
            "secmp-client-core",
            "secmp-relay",
            "secmp-cli",
            "secmp-testkit",
            "xtask",
        ] {
            assert_eq!(unsafe_rule(c), UnsafeRule::Forbid, "{c}");
        }
    }

    /// Rule: every other crate carries `#![forbid(unsafe_code)]` in every target root.
    #[test]
    fn forbid_rule_rejects_weaker_or_missing_headers() {
        assert_eq!(root_finding(&root(PLAIN, true, FORBID_SRC)), None);
        assert_eq!(root_finding(&root(PLAIN, false, FORBID_SRC)), None);
        for bad in [
            DENY_SRC,
            "// SPDX\n#![ALLOW(unsafe_code)]\n",
            "// SPDX\nfn main() {}\n",
        ] {
            assert!(root_finding(&root(PLAIN, true, bad)).is_some(), "{bad}");
            assert!(root_finding(&root(PLAIN, false, bad)).is_some(), "{bad}");
        }
    }

    /// Rule: exactly the library roots of the two sys crates carry `#![allow(unsafe_code)]`.
    #[test]
    fn sys_rule_requires_allow_at_the_library_root_only() {
        let allow = "// SPDX\n//! doc\n#![ALLOW(unsafe_code)]\n";
        assert_eq!(root_finding(&root(SYS, true, allow)), None);
        // missing, or a different attribute, at the library root
        for bad in [
            FORBID_SRC,
            DENY_SRC,
            "// SPDX\n#![EXPECT(unsafe_code)]\n",
            "// SPDX\n#![cfg_attr(unix, ALLOW(unsafe_code))]\n",
            "// SPDX\nfn f() {}\n#![ALLOW(unsafe_code)]\n",
        ] {
            assert!(root_finding(&root(SYS, true, bad)).is_some(), "{bad}");
        }
        // integration tests, benches, examples and binaries of a sys crate still forbid
        assert_eq!(root_finding(&root(SYS, false, FORBID_SRC)), None);
        assert!(root_finding(&root(SYS, false, allow)).is_some());

        // sources: the exact form at the library root is the only sanctioned relaxation
        let lib = "crates/secmp-sys-mem/src/lib.rs";
        assert!(unsafe_source_findings(lib, &src(allow), true, false).is_empty());
        let not_root = "crates/secmp-sys-mem/src/ffi.rs";
        assert_eq!(
            unsafe_source_findings(not_root, &src(allow), false, false).len(),
            1
        );
        for bad in [
            "#![EXPECT(unsafe_code)]\n",
            "#![ALLOW(unsafe_code, reason = \"x\")]\n",
            "#![cfg_attr(unix, ALLOW(unsafe_code))]\n",
            "fn f() {}\n#[ALLOW(unsafe_code)]\nfn g() {}\n",
            "#![WARN(unsafe_code)]\n",
        ] {
            assert_eq!(
                unsafe_source_findings(lib, &src(bad), true, false).len(),
                1,
                "{bad}"
            );
        }
        // the same attribute in any other crate's root
        let other = "crates/secmp-crypto/src/lib.rs";
        assert_eq!(
            unsafe_source_findings(other, &src(allow), false, false).len(),
            1
        );
    }

    /// Rule: `secmp-ui` carries `#![deny(unsafe_code)]`, has no `unsafe` token and no hand-written relaxation.
    #[test]
    fn ui_rule_requires_deny_and_no_unsafe_token_or_relaxation() {
        assert_eq!(root_finding(&root(UI, false, DENY_SRC)), None);
        assert_eq!(root_finding(&root(UI, true, DENY_SRC)), None);
        // `forbid` is stronger and accepted (e.g. for integration tests that do not use `slint!`)
        assert_eq!(root_finding(&root(UI, false, FORBID_SRC)), None);
        assert!(root_finding(&root(UI, false, "// SPDX\nfn main() {}\n")).is_some());
        assert!(root_finding(&root(UI, false, "#![ALLOW(unsafe_code)]\n")).is_some());

        let path = "crates/secmp-ui/src/main.rs";
        let clean = "#![deny(unsafe_code)]\n//! no unsafe_code here\nfn main() {}\n";
        assert!(unsafe_source_findings(path, clean, false, true).is_empty());
        let token = "#![deny(unsafe_code)]\nfn main() {\n    unsafe { f() }\n}\n";
        let f = unsafe_source_findings(path, token, false, true);
        assert_eq!(f.len(), 1);
        assert!(f.iter().all(|m| m.contains("main.rs:3")), "{f:?}");
        // comments count too
        assert_eq!(
            unsafe_source_findings(path, "// an unsafe block\n", false, true).len(),
            1
        );
        for bad in [
            "#![ALLOW(unsafe_code)]\n",
            "#![EXPECT(unsafe_code)]\n",
            "fn f() {}\n#[ALLOW(unsafe_code)]\nfn g() {}\n",
            "#[EXPECT(unsafe_code, reason = \"slint\")]\nfn g() {}\n",
        ] {
            assert_eq!(
                unsafe_source_findings(path, &src(bad), false, true).len(),
                1,
                "{bad}"
            );
        }
        // the token rule applies to secmp-ui only
        assert!(
            unsafe_source_findings("crates/secmp-sys-mem/src/lib.rs", token, true, false)
                .is_empty()
        );
    }

    #[test]
    fn unsafe_token_boundaries() {
        assert_eq!(unsafe_token_lines("unsafe { x }"), vec![1]);
        assert_eq!(unsafe_token_lines("a\npub unsafe fn f()"), vec![2]);
        assert_eq!(unsafe_token_lines("x=\"unsafe\";"), vec![1]);
        assert_eq!(unsafe_token_lines("r#unsafe"), vec![1]);
        assert!(unsafe_token_lines("#![deny(unsafe_code)]").is_empty());
        assert!(unsafe_token_lines("not_unsafe unsafely Unsafe UNSAFE").is_empty());
        assert!(unsafe_token_lines("").is_empty());
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
