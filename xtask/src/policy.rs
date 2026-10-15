// SPDX-License-Identifier: AGPL-3.0-or-later
//! Repository policy checks that the compiler and clippy cannot express on their own.
//!
//! * `unsafe-attrs`: the `unsafe_code` rules of docs/06 §2. Every target root (lib, bin, test, bench, example)
//!   declares `#![forbid(unsafe_code)]` in its inner-attribute header, except (a) the library root of
//!   `secmp-sys-mem`/`secmp-sys-desktop`, which declares `#![allow(unsafe_code)]` — the only relaxation of
//!   `unsafe_code` first-party code may contain, anywhere — and (b) the roots of `secmp-ui`, which declare
//!   `#![deny(unsafe_code)]` (or `forbid`) while the crate's own `.rs` files contain neither the token `unsafe`
//!   nor any relaxation of `unsafe_code` (ADR-033: only `slint!` expansions may carry one), and (c) the one
//!   target root `expect::UNSAFE_EXEMPT_ROOT` (the constant-time bench, ADR-038), matched path-exactly, which
//!   declares `#![allow(unsafe_code)]` to read the CPU cycle counter.
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

/// True for exactly the target root that ADR-038 lets relax `unsafe_code` (`expect::UNSAFE_EXEMPT_ROOT`); `path`
/// is relative to the workspace root, as `rel` produces it.
pub(crate) fn unsafe_exempt_root(path: &str) -> bool {
    path == expect::UNSAFE_EXEMPT_ROOT
}

/// The header finding for one target root, if any.
pub(crate) fn root_finding(r: &Root) -> Option<String> {
    let (ok, wanted) = match unsafe_rule(&r.krate) {
        _ if unsafe_exempt_root(&r.path) => (
            header_declares(&r.src, ALLOW_UNSAFE),
            format!("#![{ALLOW_UNSAFE}] (the ADR-038 bench root)"),
        ),
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
/// relaxation of `unsafe_code` except the exact `#![allow(unsafe_code)]` at the top of a sanctioned root (the
/// library root of a `SysAllow` crate, or the ADR-038 bench root), and — in a `UiDeny` crate — every line
/// holding the token `unsafe`.
pub(crate) fn unsafe_source_findings(
    path: &str,
    src: &str,
    sanctioned_root: bool,
    ui: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for r in find_relaxations(src) {
        if r.lint != "unsafe_code" {
            continue;
        }
        if sanctioned_root && r.file_top && r.attr == ALLOW_UNSAFE {
            continue;
        }
        out.push(format!(
            "unsafe-attrs: {path} relaxes `unsafe_code` with `{}` (docs/06 §2: only `#![{ALLOW_UNSAFE}]` at the \
             library root of secmp-sys-mem/secmp-sys-desktop and at {} (ADR-038){})",
            r.attr,
            expect::UNSAFE_EXEMPT_ROOT,
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
    /// Target roots matching `expect::UNSAFE_EXEMPT_ROOT` (must be exactly one).
    exempt_allow: usize,
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
                _ if unsafe_exempt_root(&root.path) => {
                    counts.exempt_allow = counts.exempt_allow.saturating_add(1);
                }
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
            sys_lib_roots.contains(&path) || unsafe_exempt_root(&path),
            ui,
        ));
    }
    if counts.exempt_allow != 1 {
        findings.push(format!(
            "unsafe-attrs: expect::UNSAFE_EXEMPT_ROOT ({}) must name exactly one target root (ADR-038); it names {}",
            expect::UNSAFE_EXEMPT_ROOT,
            counts.exempt_allow
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

/// One `[[exemptions.<name>]]` entry of `supply-chain/config.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VetExemption {
    pub(crate) name: String,
    /// The `version` key (empty if the entry has none).
    pub(crate) version: String,
    /// The entry carries a tracked-exemption note.
    pub(crate) noted: bool,
    /// A `version` line whose value is neither a `"…"` nor a `'…'` string (after a trailing `#` comment is removed).
    pub(crate) bad_version_line: bool,
}

/// The `[[exemptions.<name>]]` entries of `supply-chain/config.toml`, in file order.
pub(crate) fn vet_exemptions(config: &str) -> Vec<VetExemption> {
    let mut out: Vec<VetExemption> = Vec::new();
    let mut in_exemption = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_exemption = false;
            if let Some(name) = t
                .strip_prefix("[[exemptions.")
                .and_then(|r| r.strip_suffix("]]"))
            {
                out.push(VetExemption {
                    name: name.trim_matches('"').to_owned(),
                    version: String::new(),
                    noted: false,
                    bad_version_line: false,
                });
                in_exemption = true;
            }
        } else if in_exemption && let Some(last) = out.last_mut() {
            if t.starts_with("notes") && t.contains("Tracked exemption") {
                last.noted = true;
            } else if is_key_line(t, "version") {
                // EXT2-2: fail closed — a version line that does not parse is a finding, never skipped
                match quoted_value(t, "version") {
                    Some(v) => last.version = v,
                    None => last.bad_version_line = true,
                }
            }
        }
    }
    out
}

/// A `MAJOR.MINOR.PATCH` version, optionally followed by `-pre` and/or `+build` (the form of `Cargo.lock` versions).
fn version_parses(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The line assigns `key` (`key = …`, any spacing).
fn is_key_line(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|r| r.trim_start().starts_with('='))
}

/// The string value of `key = "value"` or `key = 'value'` on a TOML line, with a trailing `# comment` after the
/// closing quote removed (EXT2-2); anything else (no quotes, unterminated, text after the value) is `None`.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let rest = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let body = rest.get(1..)?;
    let (value, after) = body.split_once(quote)?;
    let after = after.trim();
    if after.is_empty() || after.starts_with('#') {
        Some(value.to_owned())
    } else {
        None
    }
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

/// The `vet-closure` findings for a `supply-chain/config.toml` text and a closure: exemptions without a
/// tracked-exemption note, and exemptions of a package inside the closure. The closure is a set of (name, version)
/// packages (ADR-036 Amendment 1): another version of a closure crate's name, reachable only outside the closure, is
/// not a member and may carry a tracked exemption. Returns the findings and the number of exemption entries.
pub(crate) fn vet_closure_findings(
    config: &str,
    closure: &BTreeSet<(String, String)>,
) -> (Vec<String>, usize) {
    let entries = vet_exemptions(config);
    let mut findings = Vec::new();
    let untracked: Vec<&str> = entries
        .iter()
        .filter(|e| !e.noted)
        .map(|e| e.name.as_str())
        .collect();
    if !untracked.is_empty() {
        findings.push(format!(
            "cargo-vet exemptions without a tracked-exemption note (supply-chain/README.md): {}",
            untracked.join(", ")
        ));
    }
    for e in &entries {
        if e.bad_version_line {
            findings.push(format!(
                "vet exemption with an unparsable version line: {}",
                e.name
            ));
        } else if !version_parses(&e.version) {
            findings.push(format!("vet exemption without version: {}", e.name));
        } else if closure.contains(&(e.name.clone(), e.version.clone())) {
            findings.push(format!(
                "vet exemption inside the crypto/proto closure: {}@{}",
                e.name, e.version
            ));
        }
    }
    (findings, entries.len())
}

/// `vet-closure`: zero exemptions in the normal `secmp-crypto`/`secmp-proto` closure (docs/06 §3, ADR-036).
pub(crate) fn check_vet_closure(ws: &Workspace) -> Result<String> {
    let config = std::fs::read_to_string(ws.root.join("supply-chain").join("config.toml"))?;
    let closure = zero_exemption_closure(ws)?;
    let (findings, exempted) = vet_closure_findings(&config, &closure);
    if !findings.is_empty() {
        bail!("{}", findings.join("; "));
    }
    Ok(format!(
        "secmp-crypto/secmp-proto normal closure ({}): {} external crates, 0 exempted; tracked exemptions elsewhere: {exempted}",
        expect::VET_CLOSURE_TARGETS.join(", "),
        closure.len(),
    ))
}

/// The normal direct dependencies of the crates of `expect::NORMAL_DEPENDENCY_ALLOW` that their row does not list
/// (M5 review F-7, R-126, TEST-SPEC-M6 G-04), each as a finding naming the crate (package) and the dependency; a
/// listed crate that is not a workspace member is a finding too. Only normal edges count (`dev`- and
/// `build`-dependencies are not shipped); the edges are those of the workspace graph (`cargo metadata`).
pub(crate) fn normal_dependency_findings(ws: &Workspace) -> Vec<String> {
    let mut out = Vec::new();
    for (krate, allowed) in expect::NORMAL_DEPENDENCY_ALLOW {
        let Some(pkg) = ws.member(krate) else {
            out.push(format!(
                "normal-deps: {krate} is in expect::NORMAL_DEPENDENCY_ALLOW but not a workspace member"
            ));
            continue;
        };
        let mut deps: Vec<&str> = ws
            .edges
            .get(&pkg.id)
            .into_iter()
            .flatten()
            .filter(|(_, normal)| *normal)
            .filter_map(|(id, _)| ws.all.get(id))
            .map(|(name, _, _)| name.as_str())
            .collect();
        deps.sort_unstable();
        deps.dedup();
        for d in deps {
            if !allowed.contains(&d) {
                out.push(format!(
                    "normal-deps: package {krate} has the normal dependency {d}, which expect::NORMAL_DEPENDENCY_ALLOW does not list (a direct dependency needs its ADR line first, CLAUDE.md §1.9)"
                ));
            }
        }
    }
    out
}

/// The event names of the relay's closed event set (`secmp_relay::event::EVENT_NAMES` in `src`, the text of
/// `crates/secmp-relay/src/event.rs`), in order.
pub(crate) fn relay_event_names(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub const EVENT_NAMES") else {
        return Vec::new();
    };
    let body = src.get(start..).unwrap_or_default();
    // the list after `=` (the type `[&str; N]` comes first)
    let list = body
        .find('=')
        .and_then(|eq| body.get(eq..))
        .and_then(|b| b.find("];").and_then(|end| b.get(..end)))
        .unwrap_or_default();
    list.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// OPEN-M5-08 A: `expect::RELAY_TRACE_ALLOW` is exactly the relay's closed event set, in order — an event added to
/// the relay without the list (or the reverse) is a finding.
pub(crate) fn relay_event_findings(src: &str) -> Vec<String> {
    let names = relay_event_names(src);
    if names == expect::RELAY_TRACE_ALLOW {
        Vec::new()
    } else {
        vec![format!(
            "relay-events: secmp_relay::event::EVENT_NAMES {names:?} is not expect::RELAY_TRACE_ALLOW {:?}",
            expect::RELAY_TRACE_ALLOW
        )]
    }
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
    findings.extend(relay_event_findings(&std::fs::read_to_string(
        ws.root.join("crates/secmp-relay/src/event.rs"),
    )?));
    findings.extend(normal_dependency_findings(ws));
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
        exempt_allow,
    } = unsafe_counts;
    Ok(format!(
        "unsafe-attrs: {forbid} target roots forbid, {sys_allow} sys library roots allow, {exempt_allow} ADR-038 \
         bench root allows ({}), {ui_deny} secmp-ui roots deny, {ui_files} secmp-ui files without `unsafe`; \
         lints-table: {manifests} manifests; lint-allows: {relaxations} relaxing attributes (all sanctioned); \
         build-scripts: {crates} crates, none; spdx: {spdx} files; relay-events: {} names as \
         expect::RELAY_TRACE_ALLOW; normal-deps: {} crates within expect::NORMAL_DEPENDENCY_ALLOW; {}",
        expect::UNSAFE_EXEMPT_ROOT,
        expect::RELAY_TRACE_ALLOW.len(),
        expect::NORMAL_DEPENDENCY_ALLOW.len(),
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

    /// Rule (ADR-038, path moved by ADR-042): exactly `expect::UNSAFE_EXEMPT_ROOT` carries `#![allow(unsafe_code)]`
    /// besides the sys library roots; the match is on the exact relative path, nothing near it — the old path in
    /// `secmp-crypto` included.
    #[test]
    fn adr038_exemption_is_path_exact() {
        let exempt = expect::UNSAFE_EXEMPT_ROOT;
        assert_eq!(exempt, "crates/secmp-testkit/benches/ct.rs");
        assert!(unsafe_exempt_root(exempt));
        for near in [
            "crates/secmp-crypto/benches/ct.rs",
            "crates/secmp-testkit/benches/ct2.rs",
            "crates/secmp-testkit/benches/ct.rs.orig",
            "crates/secmp-testkit/benches/ct.rs/",
            "crates/secmp-testkit/benches/CT.rs",
            "crates/secmp-testkit/benches/ct/main.rs",
            "./crates/secmp-testkit/benches/ct.rs",
            "/crates/secmp-testkit/benches/ct.rs",
            "x/crates/secmp-testkit/benches/ct.rs",
            "crates\\secmp-testkit\\benches\\ct.rs",
            "crates/secmp-proto/benches/ct.rs",
            "crates/secmp-testkit/src/lib.rs",
            "crates/secmp-testkit/tests/ct.rs",
            "",
        ] {
            assert!(!unsafe_exempt_root(near), "{near}");
        }
        let allow = "// SPDX\n//! doc\n#![ALLOW(unsafe_code)]\n";
        let bench = |path: &str, text: &str| Root {
            krate: "secmp-testkit".to_owned(),
            target: "ct [bench]".to_owned(),
            path: path.to_owned(),
            lib: false,
            src: src(text),
        };
        // the exempt root must carry the allow; `forbid` there is a finding (the exemption is not optional)
        assert_eq!(root_finding(&bench(exempt, allow)), None);
        assert!(root_finding(&bench(exempt, FORBID_SRC)).is_some());
        assert!(root_finding(&bench(exempt, "// SPDX\n#![EXPECT(unsafe_code)]\n")).is_some());
        // any other bench root of the same crate still forbids
        let other = "crates/secmp-testkit/benches/other.rs";
        assert!(root_finding(&bench(other, allow)).is_some());
        assert_eq!(root_finding(&bench(other, FORBID_SRC)), None);
        // sources: only the exact form at the file top of the exempt root
        assert!(unsafe_source_findings(exempt, &src(allow), true, false).is_empty());
        for bad in [
            "#![EXPECT(unsafe_code)]\n",
            "#![ALLOW(unsafe_code, reason = \"x\")]\n",
            "fn f() {}\n#[ALLOW(unsafe_code)]\nfn g() {}\n",
        ] {
            assert_eq!(
                unsafe_source_findings(exempt, &src(bad), true, false).len(),
                1,
                "{bad}"
            );
        }
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
        let short = |c: &str| -> Vec<(String, String, bool)> {
            vet_exemptions(c)
                .into_iter()
                .map(|e| (e.name, e.version, e.noted))
                .collect()
        };
        assert_eq!(
            short(cfg),
            vec![
                ("serde".to_owned(), "1".to_owned(), false),
                ("weird-name".to_owned(), String::new(), false)
            ]
        );
        let noted = "[[exemptions.a]]\nversion = \"1\"\nnotes = \"Tracked exemption: pulled by x\"\n\n[[exemptions.b]]\n";
        assert_eq!(
            short(noted),
            vec![
                ("a".to_owned(), "1".to_owned(), true),
                ("b".to_owned(), String::new(), false)
            ]
        );
    }

    // ---- fixture-based negative tests (M0 review F1) -----------------------------------------------------

    /// A throw-away directory tree for the checks that walk the file system.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str, files: &[(&str, &str)]) -> Result<Self> {
            let root = std::env::temp_dir()
                .join(format!("secmp-xtask-fixture-{name}-{}", std::process::id()));
            if root.exists() {
                std::fs::remove_dir_all(&root)?;
            }
            for (path, text) in files {
                let p = root.join(path);
                if let Some(dir) = p.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                std::fs::write(&p, src(text))?;
            }
            Ok(Self(root))
        }

        fn files(&self, rel_paths: &[&str]) -> Vec<PathBuf> {
            rel_paths.iter().map(|p| self.0.join(p)).collect()
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SPDX: &str = "// SPDX-License-Identifier: AGPL-3.0-or-later\n";

    #[test]
    fn fixture_unsanctioned_lint_allowances() -> Result<()> {
        let tree = Tree::new(
            "lint-allows",
            &[
                // a relaxation in library code: never sanctioned
                (
                    "crates/x/src/lib.rs",
                    "#[ALLOW(clippy::unwrap_used)]\nfn f() {}\n",
                ),
                // the docs/06 §2 test allowance at the top of a test file: sanctioned by rule
                (
                    "crates/x/tests/t.rs",
                    "#![ALLOW(clippy::unwrap_used, clippy::expect_used)]\nfn g() {}\n",
                ),
                // the same lint, but not at the file top
                (
                    "crates/x/tests/u.rs",
                    "fn g() {}\n#[ALLOW(clippy::unwrap_used)]\nfn h() {}\n",
                ),
                // a lint outside the test allowance, at the top of a test file
                (
                    "crates/x/tests/v.rs",
                    "#![ALLOW(clippy::panic)]\nfn g() {}\n",
                ),
                // `expect` and `cfg_attr` forms count as relaxations too
                (
                    "crates/y/src/lib.rs",
                    "#[cfg_attr(test, EXPECT(clippy::indexing_slicing))]\nfn f() {}\n",
                ),
            ],
        )?;
        let files = tree.files(&[
            "crates/x/src/lib.rs",
            "crates/x/tests/t.rs",
            "crates/x/tests/u.rs",
            "crates/x/tests/v.rs",
            "crates/y/src/lib.rs",
        ]);
        let mut findings = Vec::new();
        let count = check_lint_allows(&tree.0, &files, &mut findings)?;
        assert_eq!(count, 6);
        assert_eq!(findings.len(), 4, "{findings:?}");
        for path in [
            "crates/x/src/lib.rs",
            "crates/x/tests/u.rs",
            "crates/x/tests/v.rs",
            "crates/y/src/lib.rs",
        ] {
            assert!(
                findings.iter().any(|f| f.contains(path)),
                "{path}: {findings:?}"
            );
        }
        assert!(!findings.iter().any(|f| f.contains("crates/x/tests/t.rs")));
        Ok(())
    }

    #[test]
    fn fixture_missing_or_wrong_spdx() -> Result<()> {
        let tree = Tree::new(
            "spdx",
            &[
                ("crates/a/src/good.rs", &format!("{SPDX}fn f() {{}}\n")),
                ("crates/a/src/missing.rs", "fn f() {}\n"),
                (
                    "crates/a/Cargo.toml",
                    "# SPDX-License-Identifier: MIT\n[package]\n",
                ),
                (
                    "formal/m.pv",
                    "(* SPDX-License-Identifier: AGPL-3.0-or-later *)\n",
                ),
                (".github/workflows/w.yml", "name: no header\n"),
                // fixtures are data for external tools and are not checked
                ("xtask/fixtures/data.rs", "no header\n"),
                ("Cargo.toml", "[workspace]\n"),
            ],
        )?;
        let mut findings = Vec::new();
        let n = check_spdx(&tree.0, &mut findings)?;
        assert_eq!(n, 6, "every candidate except the fixture");
        let mut bad: Vec<&str> = [
            "crates/a/src/missing.rs",
            "crates/a/Cargo.toml",
            ".github/workflows/w.yml",
            "Cargo.toml",
        ]
        .to_vec();
        bad.sort_unstable();
        assert_eq!(findings.len(), bad.len(), "{findings:?}");
        for path in bad {
            assert!(
                findings
                    .iter()
                    .any(|f| f.starts_with(&format!("spdx: {path} "))),
                "{path}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn fixture_build_scripts() -> Result<()> {
        let tree = Tree::new(
            "build-rs",
            &[
                ("crates/with-build/Cargo.toml", "[package]\n"),
                ("crates/with-build/build.rs", "fn main() {}\n"),
                ("crates/with-build/src/lib.rs", "\n"),
                ("crates/clean/Cargo.toml", "[package]\n"),
                ("crates/clean/src/lib.rs", "\n"),
            ],
        )?;
        let root = tree.0.to_string_lossy().replace('\\', "/");
        let json = format!(
            r#"{{"workspace_root": "{root}",
              "workspace_members": ["w#0", "c#0"],
              "packages": [
                {{"id": "w#0", "name": "with-build", "version": "0.0.0", "features": {{}},
                  "manifest_path": "{root}/crates/with-build/Cargo.toml",
                  "targets": [{{"name": "with-build", "kind": ["lib"], "src_path": "{root}/crates/with-build/src/lib.rs"}},
                              {{"name": "build-script-build", "kind": ["custom-build"], "src_path": "{root}/crates/with-build/build.rs"}}]}},
                {{"id": "c#0", "name": "clean", "version": "0.0.0", "features": {{}},
                  "manifest_path": "{root}/crates/clean/Cargo.toml",
                  "targets": [{{"name": "clean", "kind": ["lib"], "src_path": "{root}/crates/clean/src/lib.rs"}}]}}],
              "resolve": {{"nodes": [{{"id": "w#0", "deps": []}}, {{"id": "c#0", "deps": []}}]}}}}"#
        );
        let ws = Workspace::parse(&json)?;
        let mut findings = Vec::new();
        assert_eq!(check_build_scripts(&ws, &mut findings), 2);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|f| f.contains("crate with-build has a build script"))
        );
        assert!(
            findings
                .iter()
                .any(|f| f.contains("crates/with-build/build.rs exists"))
        );
        assert!(!findings.iter().any(|f| f.contains("clean")));
        Ok(())
    }

    /// The ADR-038 exemption (at its ADR-042 path) on a real directory tree and `cargo metadata`-shaped workspace: it
    /// covers the one bench root and nothing else — not another bench of the same crate, not the same file name in
    /// another crate (the bench's old path in `secmp-crypto`).
    #[test]
    fn fixture_adr038_unsafe_exemption() -> Result<()> {
        let allow = "#![ALLOW(unsafe_code)]\nfn main() {}\n";
        let forbid = "#![forbid(unsafe_code)]\nfn main() {}\n";
        let tree = Tree::new(
            "adr038",
            &[
                ("crates/secmp-testkit/src/lib.rs", forbid),
                ("crates/secmp-testkit/benches/ct.rs", allow),
                ("crates/secmp-testkit/benches/other.rs", allow),
                ("crates/secmp-crypto/src/lib.rs", forbid),
                ("crates/secmp-crypto/benches/ct.rs", allow),
            ],
        )?;
        let root = tree.0.to_string_lossy().replace('\\', "/");
        let metadata = |with_ct: bool| {
            let ct = if with_ct {
                format!(
                    r#"{{"name": "ct", "kind": ["bench"], "src_path": "{root}/crates/secmp-testkit/benches/ct.rs"}},"#
                )
            } else {
                String::new()
            };
            format!(
                r#"{{"workspace_root": "{root}",
                  "workspace_members": ["t#0", "c#0"],
                  "packages": [
                    {{"id": "t#0", "name": "secmp-testkit", "version": "0.0.0", "features": {{}},
                      "manifest_path": "{root}/crates/secmp-testkit/Cargo.toml",
                      "targets": [{{"name": "secmp_testkit", "kind": ["lib"], "src_path": "{root}/crates/secmp-testkit/src/lib.rs"}},
                                  {ct}
                                  {{"name": "other", "kind": ["bench"], "src_path": "{root}/crates/secmp-testkit/benches/other.rs"}}]}},
                    {{"id": "c#0", "name": "secmp-crypto", "version": "0.0.0", "features": {{}},
                      "manifest_path": "{root}/crates/secmp-crypto/Cargo.toml",
                      "targets": [{{"name": "secmp_crypto", "kind": ["lib"], "src_path": "{root}/crates/secmp-crypto/src/lib.rs"}},
                                  {{"name": "ct", "kind": ["bench"], "src_path": "{root}/crates/secmp-crypto/benches/ct.rs"}}]}}],
                  "resolve": {{"nodes": [{{"id": "t#0", "deps": []}}, {{"id": "c#0", "deps": []}}]}}}}"#
            )
        };
        let files = tree.files(&[
            "crates/secmp-testkit/src/lib.rs",
            "crates/secmp-testkit/benches/ct.rs",
            "crates/secmp-testkit/benches/other.rs",
            "crates/secmp-crypto/src/lib.rs",
            "crates/secmp-crypto/benches/ct.rs",
        ]);
        let about = |findings: &[String], path: &str| {
            findings
                .iter()
                .filter(|f| f.starts_with(&format!("unsafe-attrs: {path} ")))
                .count()
        };

        let ws = Workspace::parse(&metadata(true))?;
        let mut findings = Vec::new();
        let counts = check_unsafe_attrs(&ws, &files, &mut findings)?;
        assert_eq!(counts.exempt_allow, 1);
        assert_eq!(
            about(&findings, expect::UNSAFE_EXEMPT_ROOT),
            0,
            "{findings:?}"
        );
        // a root finding (header) and a source finding (relaxation) each
        assert_eq!(
            about(&findings, "crates/secmp-testkit/benches/other.rs"),
            2,
            "{findings:?}"
        );
        assert_eq!(
            about(&findings, "crates/secmp-crypto/benches/ct.rs"),
            2,
            "{findings:?}"
        );
        assert!(!findings.iter().any(|f| f.contains("must name exactly one")));

        // the exemption must point at an existing target root, or the check fails closed
        let ws = Workspace::parse(&metadata(false))?;
        let mut findings = Vec::new();
        assert_eq!(
            check_unsafe_attrs(&ws, &files, &mut findings)?.exempt_allow,
            0
        );
        assert!(
            findings
                .iter()
                .any(|f| f.contains("must name exactly one target root")),
            "{findings:?}"
        );
        Ok(())
    }

    /// A `cargo metadata` text of the workspace crates of `expect::NORMAL_DEPENDENCY_ALLOW` plus `secmp-crypto`,
    /// `secmp-proto`, `serde_json` and `tokio`, with the given `(from, to, kind)` edges (`kind` null = normal).
    fn metadata_fixture(edges: &[(&str, &str, &str)]) -> String {
        let names = [
            "secmp-relay",
            "secmp-transport",
            "secmp-client-core",
            "secmp-testkit",
            "secmp-crypto",
            "secmp-proto",
        ];
        let external = ["serde_json", "tokio"];
        let id = |n: &str| {
            if external.contains(&n) {
                format!("registry+x#{n}@1.0.0")
            } else {
                format!("path+file:///w/{n}#0.0.0")
            }
        };
        let package = |n: &&str| {
            format!(
                r#"{{"id": "{}", "name": "{n}", "version": "1.0.0", "manifest_path": "/w/{n}/Cargo.toml", "features": {{}}, "targets": []}}"#,
                id(n)
            )
        };
        let packages: Vec<String> = names
            .iter()
            .map(package)
            .chain(external.iter().map(package))
            .collect();
        let members: Vec<String> = names.iter().map(|n| format!("\"{}\"", id(n))).collect();
        let nodes: Vec<String> = names
            .iter()
            .chain(external.iter())
            .map(|n| {
                let deps: Vec<String> = edges
                    .iter()
                    .filter(|(from, _, _)| from == n)
                    .map(|(_, to, kind)| {
                        let kind = if *kind == "null" {
                            "null".to_owned()
                        } else {
                            format!("\"{kind}\"")
                        };
                        format!(
                            r#"{{"pkg": "{}", "dep_kinds": [{{"kind": {kind}, "target": null}}]}}"#,
                            id(to)
                        )
                    })
                    .collect();
                format!(r#"{{"id": "{}", "deps": [{}]}}"#, id(n), deps.join(","))
            })
            .collect();
        format!(
            r#"{{"workspace_root": "/w", "workspace_members": [{}], "packages": [{}], "resolve": {{"nodes": [{}]}}}}"#,
            members.join(","),
            packages.join(","),
            nodes.join(",")
        )
    }

    /// TEST-SPEC-M6 G-04 (M5 review F-7, R-126): the normal direct dependencies of `secmp-relay`, `secmp-transport`,
    /// `secmp-client-core` and `secmp-testkit` are within `expect::NORMAL_DEPENDENCY_ALLOW` (Phase A: workspace
    /// crates, plus the testkit's `serde_json`); a fixture with an unlisted crate is refused naming crate and package;
    /// dev- and build-dependencies are not shipped and do not count.
    /// Crate-name prefixes of the runtime and I/O crates that the sans-IO crates must not reach (ADR-051 Part 1.2,
    /// TEST-SPEC-M6 AD-12); an entry ending in `*` is a prefix, any other entry an exact name.
    pub(crate) const SANS_IO_FORBIDDEN: &[&str] = &[
        "tokio*",
        "mio",
        "socket2",
        "futures",
        "futures-*",
        "async-std",
        "smol",
        "rustls*",
        "arti-client",
        "tor-*",
    ];

    /// AD-12 findings: crates of `closure` (the normal closure of `secmp-crypto`/`secmp-proto`) matching
    /// `SANS_IO_FORBIDDEN`, and `async fn` in the given (path, text) sources of those two crates.
    pub(crate) fn sans_io_findings(
        closure: &BTreeSet<(String, String)>,
        sources: &[(String, String)],
    ) -> Vec<String> {
        let forbidden = |n: &str| {
            SANS_IO_FORBIDDEN.iter().any(|f| match f.strip_suffix('*') {
                Some(prefix) => n.starts_with(prefix),
                None => n == *f,
            })
        };
        let mut out: Vec<String> = closure
            .iter()
            .filter(|(n, _)| forbidden(n))
            .map(|(n, v)| {
                format!("sans-io: {n} {v} is in the normal closure of secmp-crypto/secmp-proto")
            })
            .collect();
        for (path, text) in sources {
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                if code.contains("async fn")
                    || code.contains("async move")
                    || code.contains("async {")
                {
                    out.push(format!(
                        "sans-io: {path}:{} has async code",
                        i.saturating_add(1)
                    ));
                }
            }
        }
        out
    }

    /// The ADR-051 Part 2 direct dependencies (normal and dev).
    const ADR051_DIRECT: &[&str] = &[
        "arti-client",
        "rustls",
        "tokio-rustls",
        "tokio",
        "aws-lc-rs",
        "turmoil",
    ];

    fn repo_file(rel_path: &str) -> Result<String> {
        Ok(std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(rel_path),
        )?)
    }

    /// (name, version) of every `[[package]]` of `Cargo.lock`.
    fn lock_packages() -> Result<BTreeSet<(String, String)>> {
        Ok(crate::cooldown::parse_lock(&repo_file("Cargo.lock")?)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect())
    }

    /// The `"…"` value of `key = "…"` inside an inline table line.
    fn inline_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let rest = line.split_once(&format!("{key} = \""))?.1;
        rest.split_once('"').map(|(v, _)| v)
    }

    /// TEST-SPEC-M6 X-02 (OPEN-M6-04 A): every `deny.toml` `skip` entry names `crate@version` of a crate that is in
    /// `Cargo.lock` in at least two versions, and a reason naming the direct dependency that pulls it (one of the
    /// workspace members' direct dependencies); no `skip-tree`; no entry twice. `cargo deny check bans` is the gate.
    #[test]
    fn deny_duplicate_skips_are_justified() -> Result<()> {
        let deny = repo_file("deny.toml")?;
        assert!(
            deny.contains("\nskip-tree = []\n"),
            "skip-tree must stay empty"
        );
        let skip = deny
            .split_once("\nskip = [\n")
            .and_then(|(_, r)| r.split_once("\n]\n"))
            .map(|(b, _)| b)
            .ok_or_else(|| crate::util::Error("deny.toml: no multi-line skip list".to_owned()))?;
        let lock = lock_packages()?;
        let ws = Workspace::load()?;
        let direct: BTreeSet<&str> = ws
            .members
            .iter()
            .flat_map(|m| ws.edges.get(&m.id).into_iter().flatten())
            .filter_map(|(id, _)| ws.all.get(id))
            .map(|(name, _, _)| name.as_str())
            .filter(|n| !n.starts_with("secmp-"))
            .collect();
        let mut seen = BTreeSet::new();
        let mut n = 0_usize;
        for line in skip.lines().filter(|l| l.trim_start().starts_with('{')) {
            n = n.saturating_add(1);
            let krate = inline_value(line, "crate").unwrap_or_default();
            let reason = inline_value(line, "reason").unwrap_or_default();
            let (name, version) = krate.split_once('@').unwrap_or_default();
            assert!(seen.insert(krate.to_owned()), "twice: {krate}");
            assert!(
                lock.contains(&(name.to_owned(), version.to_owned())),
                "{krate} not in Cargo.lock"
            );
            let versions = lock.iter().filter(|(l, _)| l == name).count();
            assert!(
                versions >= 2,
                "{krate}: only {versions} version in Cargo.lock"
            );
            let pulled = reason
                .strip_prefix("pulled by ")
                .and_then(|r| r.split_once(" ("))
                .map(|(by, _)| by)
                .unwrap_or_default();
            assert!(!pulled.is_empty(), "{krate}: reason {reason:?}");
            for by in pulled.split(", ") {
                assert!(
                    direct.contains(by),
                    "{krate}: {by} is not a direct dependency"
                );
            }
        }
        assert_eq!(n, 46);
        Ok(())
    }

    /// TEST-SPEC-M6 X-03 (OPEN-M6-02): the ADR-051 direct dependencies and the `tor-*`/`arti-*` crates carry no
    /// exemption — they are covered by the owner's records in `audits.toml` (trust or audit; read here, never written)
    /// — except `turmoil` (dev-only, a tracked exemption per the ADR-051 vet route); every exemption that cites ADR-051
    /// names one of the ADR-051 direct dependencies; `check_vet_closure` is tested by
    /// `vet_closure_of_this_workspace_has_no_exemptions`.
    #[test]
    fn vet_records_for_m6_closure() -> Result<()> {
        let config = repo_file("supply-chain/config.toml")?;
        let audits = repo_file("supply-chain/audits.toml")?;
        let notes: Vec<(String, String)> = {
            let mut out = Vec::new();
            let mut cur: Option<String> = None;
            for line in config.lines() {
                let t = line.trim();
                if let Some(n) = t
                    .strip_prefix("[[exemptions.")
                    .and_then(|r| r.strip_suffix("]]"))
                {
                    cur = Some(n.trim_matches('"').to_owned());
                } else if t.starts_with('[') {
                    cur = None;
                } else if let (Some(n), true) = (cur.as_ref(), t.starts_with("notes")) {
                    out.push((n.clone(), t.to_owned()));
                }
            }
            out
        };
        for e in vet_exemptions(&config) {
            let n = e.name.as_str();
            let owner = (ADR051_DIRECT.contains(&n) && n != "turmoil")
                || n.starts_with("tor-")
                || n.starts_with("arti-");
            assert!(!owner, "exemption for {n} {}", e.version);
        }
        for krate in [
            "arti-client",
            "rustls",
            "tokio-rustls",
            "tokio",
            "aws-lc-rs",
        ] {
            assert!(
                audits.contains(&format!("[[trusted.{krate}]]"))
                    || audits.contains(&format!("[[audits.{krate}]]")),
                "{krate}: no owner record"
            );
        }
        let mut cited = 0_usize;
        for (name, note) in &notes {
            if note.contains("ADR-051") && !ADR051_DIRECT.contains(&name.as_str()) {
                cited = cited.saturating_add(1);
                assert!(
                    ADR051_DIRECT.iter().any(|d| note.contains(d)),
                    "{name}: {note}"
                );
            }
        }
        assert!(cited > 100, "{cited} ADR-051 exemptions");
        Ok(())
    }

    /// TEST-SPEC-M6 X-04 (OPEN-M6-05 B): the license allowlist is unchanged and the exceptions are exactly Slint's and
    /// the two ADR-051 additions; `cargo deny check licenses` is the gate.
    #[test]
    fn licenses_cover_m6_closure() -> Result<()> {
        let deny = repo_file("deny.toml")?;
        let section = |start: &str| -> String {
            deny.split_once(start)
                .and_then(|(_, r)| r.split_once("\n]"))
                .map(|(b, _)| b.to_owned())
                .unwrap_or_default()
        };
        let allow: Vec<String> = section("\nallow = [\n")
            .lines()
            .filter_map(|l| inline_value(&format!("x = {}", l.trim()), "x").map(str::to_owned))
            .collect();
        assert_eq!(
            allow,
            [
                "MIT",
                "Apache-2.0",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "ISC",
                "Zlib",
                "Unicode-3.0",
                "Unicode-DFS-2016",
                "MPL-2.0"
            ]
        );
        let exceptions: Vec<(String, String)> = section("\nexceptions = [\n")
            .lines()
            .filter(|l| l.trim_start().starts_with('{'))
            .map(|l| {
                let lic = l
                    .split_once("allow = [\"")
                    .and_then(|(_, r)| r.split_once('"'))
                    .map(|(v, _)| v.to_owned())
                    .unwrap_or_default();
                (inline_value(l, "crate").unwrap_or_default().to_owned(), lic)
            })
            .collect();
        assert_eq!(
            exceptions,
            [
                ("slint".to_owned(), "GPL-3.0-only".to_owned()),
                ("async_executors".to_owned(), "Unlicense".to_owned()),
                ("notify".to_owned(), "CC0-1.0".to_owned()),
            ]
        );
        Ok(())
    }

    /// TEST-SPEC-M6 AD-12 (ADR-051 Part 1.2, docs/02 §3): the normal closure of `secmp-crypto` and `secmp-proto` on
    /// every target of `expect::VET_CLOSURE_TARGETS` contains none of `tokio`, `mio`, `socket2`, `futures-*`,
    /// `rustls*`, `arti-client`, `tor-*`, and their `src` has no `async` code; planted closures and sources are refused.
    #[test]
    fn crypto_and_proto_stay_sans_io() -> Result<()> {
        let ws = Workspace::load()?;
        let closure = zero_exemption_closure(&ws)?;
        assert!(!closure.is_empty());
        let mut sources = Vec::new();
        for krate in ["secmp-crypto", "secmp-proto"] {
            let src = ws.root.join("crates").join(krate).join("src");
            for f in walk_files(&src, &|p: &Path| p.extension().is_some_and(|e| e == "rs"))? {
                sources.push((rel(&ws.root, &f), std::fs::read_to_string(&f)?));
            }
        }
        assert!(sources.len() > 2, "{}", sources.len());
        let findings = sans_io_findings(&closure, &sources);
        assert!(findings.is_empty(), "{findings:?}");
        // the gate is not vacuous: planted crates and async code are refused, unrelated names pass
        let planted: BTreeSet<(String, String)> = [
            "tokio",
            "mio",
            "socket2",
            "futures-util",
            "rustls-webpki",
            "arti-client",
            "tor-proto",
            "tokio-rustls",
            "futures",
            "async-std",
            "smol",
            "zeroize",
            "subtle",
            "smolstr",
        ]
        .iter()
        .map(|n| ((*n).to_owned(), "1.0.0".to_owned()))
        .collect();
        let src = vec![(
            "x.rs".to_owned(),
            "fn a() {}\n// async fn in a comment\npub async fn b() {}\nlet f = async move { 1 };\n"
                .to_owned(),
        )];
        let found = sans_io_findings(&planted, &src);
        assert_eq!(found.len(), 13, "{found:?}");
        for bad in [
            "tokio 1",
            "mio",
            "socket2",
            "futures-util",
            "rustls-webpki",
            "arti-client",
            "tor-proto",
            "tokio-rustls",
            "futures 1",
            "async-std",
            "smol 1",
            "x.rs:3",
            "x.rs:4",
        ] {
            assert!(found.iter().any(|f| f.contains(bad)), "{bad}: {found:?}");
        }
        Ok(())
    }

    /// ADR-051 Amendment 1, WEISUNG M6-B-0: every `expect::AUDIT_IGNORES` id is in `deny.toml` `[advisories] ignore`
    /// with its reason as a comment, except the ids `cargo deny` never reports (`AUDIT_IGNORES_NOT_IN_DENY`), and
    /// `deny.toml` ignores nothing that `cargo audit` does not.
    /// `AUDIT_IGNORES` ids that `cargo deny` does not report (its per-target graph never compiles the crate), so they
    /// have no `deny.toml` `[advisories] ignore` entry.
    /// RUSTSEC-2025-0141 (ADR-051 Am. 1): lock-only, never compiled (cargo tree -i prints nothing).
    const AUDIT_IGNORES_NOT_IN_DENY: &[&str] = &["RUSTSEC-2026-0173", "RUSTSEC-2025-0141"];

    #[test]
    fn audit_ignores_match_deny_toml() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let deny = std::fs::read_to_string(root.join("deny.toml"))?;
        let section = deny
            .split_once("[advisories]")
            .and_then(|(_, rest)| rest.split_once("\nignore = ["))
            .and_then(|(_, rest)| rest.split_once("\n]"))
            .map(|(body, _)| body)
            .ok_or_else(|| {
                crate::util::Error("deny.toml: no multi-line [advisories] ignore list".to_owned())
            })?;
        let mut in_deny = Vec::new();
        for line in section.lines() {
            let t = line.trim();
            if let Some(id) = t
                .strip_prefix('"')
                .and_then(|r| r.split_once('"'))
                .map(|(id, _)| id)
            {
                let (_, reason) = t.split_once('#').unwrap_or_default();
                in_deny.push((id, reason.trim()));
            }
        }
        let mut want: Vec<(&str, &str)> = expect::AUDIT_IGNORES
            .iter()
            .filter(|(id, _)| !AUDIT_IGNORES_NOT_IN_DENY.contains(id))
            .copied()
            .collect();
        want.sort_unstable();
        in_deny.sort_unstable();
        assert_eq!(in_deny, want);
        for id in ["RUSTSEC-2023-0071", "RUSTSEC-2024-0436"] {
            assert!(in_deny.iter().any(|(d, _)| *d == id), "{id}");
        }
        for id in AUDIT_IGNORES_NOT_IN_DENY {
            assert!(expect::AUDIT_IGNORES.iter().any(|(a, _)| a == id), "{id}");
        }
        Ok(())
    }

    #[test]
    fn normal_dependencies_match_adr_allowlist() -> Result<()> {
        // the tree itself
        let findings = normal_dependency_findings(&Workspace::load()?);
        assert!(findings.is_empty(), "{findings:?}");
        // the allowlist's shape: workspace crates, plus exactly the third-party crates of the ADR-051 Part 2 table
        // (Amendment 1) and the testkit's serde_json (ADR-037)
        let adr051: &[(&str, &[&str])] = &[
            ("secmp-relay", &["aws-lc-rs", "rustls"]),
            (
                "secmp-transport",
                &[
                    "arti-client",
                    "aws-lc-rs",
                    "rustls",
                    "tokio",
                    "tokio-rustls",
                ],
            ),
            ("secmp-client-core", &["tokio"]),
            ("secmp-testkit", &["serde_json", "tokio"]),
        ];
        for (krate, allowed) in expect::NORMAL_DEPENDENCY_ALLOW {
            let third: Vec<&str> = allowed
                .iter()
                .copied()
                .filter(|d| !d.starts_with("secmp-"))
                .collect();
            let want = adr051
                .iter()
                .find(|(k, _)| k == krate)
                .map(|(_, d)| d.to_vec())
                .unwrap_or_default();
            assert_eq!(third, want, "{krate}");
        }
        // a fixture within the lists, with dev/build edges to tokio, passes
        let ok = metadata_fixture(&[
            ("secmp-relay", "secmp-crypto", "null"),
            ("secmp-relay", "secmp-proto", "null"),
            ("secmp-relay", "tokio", "dev"),
            ("secmp-transport", "secmp-proto", "null"),
            ("secmp-transport", "tokio", "build"),
            ("secmp-client-core", "secmp-transport", "null"),
            ("secmp-testkit", "serde_json", "null"),
            ("secmp-testkit", "tokio", "dev"),
        ]);
        assert_eq!(
            normal_dependency_findings(&Workspace::parse(&ok)?),
            Vec::<String>::new()
        );
        // an unlisted normal dependency is refused, naming package and crate
        let bad = metadata_fixture(&[
            ("secmp-relay", "secmp-crypto", "null"),
            ("secmp-relay", "tokio", "null"),
            ("secmp-transport", "serde_json", "null"),
            ("secmp-client-core", "secmp-relay", "null"),
        ]);
        let found = normal_dependency_findings(&Workspace::parse(&bad)?);
        assert_eq!(found.len(), 3, "{found:?}");
        for (package, dep) in [
            ("secmp-relay", "tokio"),
            ("secmp-transport", "serde_json"),
            ("secmp-client-core", "secmp-relay"),
        ] {
            assert!(
                found.iter().any(|f| f.contains(&format!(
                    "package {package} has the normal dependency {dep},"
                ))),
                "{package} {dep}: {found:?}"
            );
        }
        // a listed crate that is no workspace member is a finding
        let none = Workspace::parse(
            r#"{"workspace_root": "/w", "workspace_members": [], "packages": [], "resolve": {"nodes": []}}"#,
        )?;
        assert_eq!(
            normal_dependency_findings(&none).len(),
            expect::NORMAL_DEPENDENCY_ALLOW.len()
        );
        Ok(())
    }

    #[test]
    fn fixture_vet_exemptions() {
        let config = include_str!("../fixtures/policy/vet-config.toml");
        let closure: BTreeSet<(String, String)> = [("typenum", "1.20.1"), ("subtle", "2.6.1")]
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let (findings, exempted) = vet_closure_findings(config, &closure);
        assert_eq!(exempted, 3);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|f| f.contains("without a tracked-exemption note") && f.contains("crabgrind"))
        );
        assert!(
            findings
                .iter()
                .any(|f| f == "vet exemption inside the crypto/proto closure: typenum@1.20.1")
        );
        // outside the closure, correctly noted exemptions are fine
        let clean = config.replace(
            "[[exemptions.crabgrind]]",
            "[[exemptions.crabgrind]]\nnotes = \"Tracked exemption: x\"",
        );
        let empty = BTreeSet::new();
        assert!(vet_closure_findings(&clean, &empty).0.is_empty());
    }

    const TRACKED: &str =
        "notes = \"Tracked exemption (supply-chain/README.md): pulled by arti-client.\"";

    /// ADR-036 Amendment 1: an exemption for a (name, version) that is in the closure is a finding.
    #[test]
    fn vet_closure_exemption_for_closure_version_is_a_finding() {
        let closure: BTreeSet<(String, String)> = [("const-oid".to_owned(), "0.10.2".to_owned())]
            .into_iter()
            .collect();
        let config = format!(
            "[[exemptions.const-oid]]\nversion = \"0.10.2\"\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n"
        );
        let (findings, n) = vet_closure_findings(&config, &closure);
        assert_eq!(n, 1);
        assert_eq!(
            findings,
            vec!["vet exemption inside the crypto/proto closure: const-oid@0.10.2".to_owned()]
        );
    }

    /// WEISUNG M6-B-1 §0b (a): an exemption entry without a `version`, or with one that does not parse, is a finding.
    #[test]
    fn vet_closure_exemption_without_version_is_a_finding() {
        let empty = BTreeSet::new();
        let missing = format!("[[exemptions.libm]]\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n");
        let bad = format!(
            "[[exemptions.libm]]\nversion = \"0.2\"\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n"
        );
        for config in [missing, bad] {
            let (findings, n) = vet_closure_findings(&config, &empty);
            assert_eq!(n, 1);
            assert_eq!(
                findings,
                vec!["vet exemption without version: libm".to_owned()]
            );
        }
        for good in ["1.1.6+spec-1.1.0", "0.10.0-rc.19", "0.2.16"] {
            assert!(version_parses(good), "{good}");
        }
        for bad in ["", "1", "1.2", "1.2.x", "v1.2.3", "1..3"] {
            assert!(!version_parses(bad), "{bad}");
        }
    }

    /// EXT2-2 (Codex re-review): `version = "0.10.2" # owner note` is read as 0.10.2, so an exemption of a closure
    /// version with a trailing comment is still a finding.
    #[test]
    fn vet_closure_exemption_with_trailing_comment_is_parsed() {
        let closure: BTreeSet<(String, String)> = [("const-oid".to_owned(), "0.10.2".to_owned())]
            .into_iter()
            .collect();
        for line in [
            r#"version = "0.10.2""#,
            r#"version = "0.10.2" # owner note"#,
        ] {
            let config = format!(
                "[[exemptions.const-oid]]\n{line}\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n"
            );
            let e = vet_exemptions(&config);
            assert_eq!(
                e.first().map(|x| x.version.as_str()),
                Some("0.10.2"),
                "{line}"
            );
            assert_eq!(
                vet_closure_findings(&config, &closure).0,
                vec!["vet exemption inside the crypto/proto closure: const-oid@0.10.2".to_owned()],
                "{line}"
            );
        }
    }

    /// EXT2-2: a TOML literal string `version = '0.10.2'` is read like `"0.10.2"`.
    #[test]
    fn vet_closure_exemption_literal_string_version_is_parsed() {
        let closure: BTreeSet<(String, String)> = [("const-oid".to_owned(), "0.10.2".to_owned())]
            .into_iter()
            .collect();
        for line in [
            "version = '0.10.2'",
            "version = '0.10.2'   # note",
            "version='0.10.2'",
        ] {
            let config = format!(
                "[[exemptions.const-oid]]\n{line}\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n"
            );
            assert_eq!(
                vet_closure_findings(&config, &closure).0,
                vec!["vet exemption inside the crypto/proto closure: const-oid@0.10.2".to_owned()],
                "{line}"
            );
        }
    }

    /// EXT2-2: a `version` line that still does not parse is a finding naming the crate, never skipped.
    #[test]
    fn vet_closure_unparsable_version_line_is_a_finding() {
        let empty = BTreeSet::new();
        for line in [
            "version = 0.10.2",
            "version = \"0.10.2",
            "version = \"0.10.2\" trailing",
            "version = '0.10.2\"",
            "version =",
        ] {
            let config = format!(
                "[[exemptions.const-oid]]\n{line}\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n"
            );
            assert_eq!(
                vet_closure_findings(&config, &empty).0,
                vec!["vet exemption with an unparsable version line: const-oid".to_owned()],
                "{line}"
            );
        }
        // `versions = …` is another key, not a version line; the entry then has no version
        let other = format!("[[exemptions.x]]\nversions = \"1\"\n{TRACKED}\n");
        assert_eq!(
            vet_closure_findings(&other, &empty).0,
            vec!["vet exemption without version: x".to_owned()]
        );
    }

    /// ADR-036 Amendment 1: another version of a closure crate's name, outside the closure, may be exempted.
    #[test]
    fn vet_closure_other_version_of_closure_name_is_allowed() {
        let closure: BTreeSet<(String, String)> = [("const-oid".to_owned(), "0.10.2".to_owned())]
            .into_iter()
            .collect();
        let config = format!(
            "[[exemptions.const-oid]]\nversion = \"0.9.6\"\ncriteria = \"safe-to-deploy\"\n{TRACKED}\n"
        );
        let (findings, n) = vet_closure_findings(&config, &closure);
        assert_eq!(n, 1);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// The real tree: no exemption of `supply-chain/config.toml` names a (name, version) of the normal closure of
    /// `secmp-crypto`/`secmp-proto` on the three targets, and every exemption carries its tracked note.
    #[test]
    fn vet_closure_of_this_workspace_has_no_exemptions() -> Result<()> {
        let ws = Workspace::load()?;
        let summary = check_vet_closure(&ws)?;
        assert!(summary.contains(", 0 exempted;"), "{summary}");
        Ok(())
    }
}
