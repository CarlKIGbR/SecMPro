// SPDX-License-Identifier: AGPL-3.0-or-later
//! The source scans of `testscan` (test-only): the seed rules of the property tests (M4 review R-93, TEST-SPEC-M5
//! X-07) and the error codes of the doctest fences (M4 review R-92, TEST-SPEC-M5 X-06), with the tests
//! `pr_ci_runs_props_with_ci_run_seed` and `doctest_compile_fail_blocks_name_an_error_code`. The scanners read Rust
//! source text with comments and literals blanked ([`strip`]); they are an accident guard, not a parser.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use super::{DEFAULT_SEED_RANGE, PROPERTY_BINARIES, PROPERTY_PACKAGES, SEED_ENV};
use crate::expect;
use crate::util::{Error, Result, rel, walk_files};

/// The one helper that reads [`SEED_ENV`], relative to the workspace root.
pub(crate) const SEED_HELPER: &str = "crates/secmp-proto/tests/common/seed.rs";

/// The directories with first-party Rust sources (the workspace crates, `xtask`, the fuzz crate).
const RUST_SOURCE_DIRS: &[&str] = &["crates", "fuzz", "xtask"];

/// A function item of a Rust source file, read from the text with comments and literals blanked ([`strip`]).
#[derive(Debug)]
struct FnItem {
    name: String,
    /// Marked `#[test]` (or `#[<path>::test]`).
    test: bool,
    body: String,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Skip a string literal's rest after its opening quote (escapes honoured).
fn skip_string(it: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                it.next();
            }
            '"' => return,
            _ => {}
        }
    }
}

/// If `it` (just after an `r`) starts a raw string (`#`* then `"`), consume it and return true.
fn skip_raw_string(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    let mut look = it.clone();
    let mut hashes = 0_usize;
    while look.peek() == Some(&'#') {
        look.next();
        hashes = hashes.saturating_add(1);
    }
    if look.next() != Some('"') {
        return false;
    }
    *it = look;
    loop {
        match it.next() {
            None => return true,
            Some('"') => {
                let mut end = it.clone();
                let mut n = 0_usize;
                while n < hashes && end.peek() == Some(&'#') {
                    end.next();
                    n = n.saturating_add(1);
                }
                if n == hashes {
                    *it = end;
                    return true;
                }
            }
            Some(_) => {}
        }
    }
}

/// The source with comments removed and the contents of string, raw-string and char literals dropped (a string
/// becomes `""`, a char literal `''`), so braces and keywords inside them do not count; lifetimes are kept.
fn strip(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut it = src.chars().peekable();
    let mut prev_ident = false;
    while let Some(c) = it.next() {
        match c {
            '/' if it.peek() == Some(&'/') => {
                for c in it.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if it.peek() == Some(&'*') => {
                it.next();
                let mut depth = 1_usize;
                while depth > 0 {
                    match it.next() {
                        None => break,
                        Some('*') if it.peek() == Some(&'/') => {
                            it.next();
                            depth = depth.saturating_sub(1);
                        }
                        Some('/') if it.peek() == Some(&'*') => {
                            it.next();
                            depth = depth.saturating_add(1);
                        }
                        Some(_) => {}
                    }
                }
                out.push(' ');
            }
            '"' => {
                skip_string(&mut it);
                out.push_str("\"\"");
            }
            'r' if !prev_ident && skip_raw_string(&mut it) => out.push_str("\"\""),
            'b' if !prev_ident && it.peek() == Some(&'r') => {
                let mut after_r = it.clone();
                after_r.next();
                if skip_raw_string(&mut after_r) {
                    it = after_r;
                    out.push_str("\"\"");
                } else {
                    out.push('b');
                }
            }
            '\'' => {
                let mut look = it.clone();
                match (look.next(), look.next()) {
                    (Some('\\'), _) => {
                        it.next();
                        it.next();
                        for c in it.by_ref() {
                            if c == '\'' {
                                break;
                            }
                        }
                        out.push_str("''");
                    }
                    (Some(_), Some('\'')) => {
                        it.next();
                        it.next();
                        out.push_str("''");
                    }
                    _ => out.push('\''),
                }
            }
            _ => out.push(c),
        }
        prev_ident = out.as_bytes().last().is_some_and(|b| is_ident(*b));
    }
    out
}

/// Whether the attributes right before an item (the text before its `fn`, qualifiers already allowed for) hold
/// `#[test]` or `#[<path>::test]`.
fn marked_test(before: &str) -> bool {
    let mut rest = before.trim_end();
    for q in [
        "unsafe",
        "async",
        "const",
        "pub(crate)",
        "pub(super)",
        "pub",
    ] {
        if let Some(r) = rest.strip_suffix(q) {
            rest = r.trim_end();
        }
    }
    while let Some(inner) = rest.strip_suffix(']') {
        let mut depth = 0_usize;
        let mut open = None;
        for (i, b) in inner.bytes().enumerate().rev() {
            match b {
                b']' => depth = depth.saturating_add(1),
                b'[' if depth == 0 => {
                    open = Some(i);
                    break;
                }
                b'[' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        let Some(open) = open else {
            return false;
        };
        let attr = inner
            .get(open.saturating_add(1)..)
            .unwrap_or_default()
            .trim();
        if attr == "test" || attr.ends_with("::test") {
            return true;
        }
        let Some(head) = inner.get(..open).and_then(|h| h.strip_suffix('#')) else {
            return false;
        };
        rest = head.trim_end();
    }
    false
}

/// The function items of stripped source `code` (with or without a body; a declaration without one has an empty
/// body).
fn fn_items(code: &str) -> Vec<FnItem> {
    let bytes = code.as_bytes();
    let mut items = Vec::new();
    let mut from = 0_usize;
    while let Some(off) = code.get(from..).and_then(|s| s.find("fn ")) {
        let at = from.saturating_add(off);
        from = at.saturating_add(3);
        if at
            .checked_sub(1)
            .and_then(|p| bytes.get(p))
            .is_some_and(|b| is_ident(*b))
        {
            continue;
        }
        let after = code.get(from..).unwrap_or_default();
        let name: String = after
            .trim_start()
            .bytes()
            .take_while(|b| is_ident(*b))
            .map(char::from)
            .collect();
        if name.is_empty() {
            continue;
        }
        let test = marked_test(code.get(..at).unwrap_or_default());
        let body = fn_body(after).unwrap_or_default().to_owned();
        items.push(FnItem { name, test, body });
    }
    items
}

/// The body of the function whose signature starts `sig`: the text between the first `{` outside parentheses and
/// brackets and its matching `}`; `None` if a `;` comes first (no body).
fn fn_body(sig: &str) -> Option<&str> {
    let mut depth = 0_usize;
    let mut start = None;
    for (i, b) in sig.bytes().enumerate() {
        match (start, b) {
            (None, b'(' | b'[') | (Some(_), b'{') => depth = depth.saturating_add(1),
            (None, b')' | b']') => depth = depth.saturating_sub(1),
            (None, b';') if depth == 0 => return None,
            (None, b'{') if depth == 0 => {
                start = Some(i);
                depth = 1;
            }
            (Some(s), b'}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return sig.get(s.saturating_add(1)..i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether `body` calls a function named `name` (`name(` or `name::<` not preceded by an identifier character; a
/// method of the same name on another type counts too, which can only widen the seeded set).
fn calls(body: &str, name: &str) -> bool {
    let bytes = body.as_bytes();
    body.match_indices(name).any(|(i, _)| {
        let before_ok = i
            .checked_sub(1)
            .and_then(|p| bytes.get(p))
            .is_none_or(|b| !is_ident(*b));
        let rest = body.get(i.saturating_add(name.len())..).unwrap_or_default();
        before_ok && (rest.starts_with('(') || rest.starts_with("::<"))
    })
}

/// The functions of a file that reach the helper: those whose body calls `seed::master_seed`, and, transitively,
/// those that call one of them.
fn seeded_fns(items: &[FnItem]) -> BTreeSet<String> {
    let mut seeded: BTreeSet<String> = items
        .iter()
        .filter(|f| f.body.contains("seed::master_seed("))
        .map(|f| f.name.clone())
        .collect();
    loop {
        let more: Vec<String> = items
            .iter()
            .filter(|f| !seeded.contains(&f.name))
            .filter(|f| seeded.iter().any(|s| calls(&f.body, s)))
            .map(|f| f.name.clone())
            .collect();
        if more.is_empty() {
            return seeded;
        }
        seeded.extend(more);
    }
}

/// Lexically normalised `path` (`.` dropped, `..` pops a component).
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Whether `raw` (the file `file`) declares the helper as a module: a `#[path = "…"]` line resolving to
/// [`SEED_HELPER`] (relative to the file's directory), followed by `mod seed;`.
fn declares_helper(root: &Path, file: &Path, raw: &str) -> bool {
    let helper = normalise(&root.join(SEED_HELPER));
    let dir = file.parent().unwrap_or(root);
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines.windows(2).any(|w| {
        let (Some(attr), Some(next)) = (w.first(), w.get(1)) else {
            return false;
        };
        let target = attr
            .strip_prefix("#[path = \"")
            .and_then(|r| r.strip_suffix("\"]"));
        *next == "mod seed;" && target.is_some_and(|t| normalise(&dir.join(t)) == helper)
    })
}

/// The `DEFAULT_SEED` of stripped source `code`: the literal of `const DEFAULT_SEED: u64 = …;` (hex or decimal,
/// underscores allowed), `None` without one; a literal that does not parse is an error.
fn default_seed(code: &str) -> Result<Option<u64>> {
    let Some((_, rest)) = code.split_once("const DEFAULT_SEED: u64 =") else {
        return Ok(None);
    };
    let lit: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    let value = match lit.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => lit.parse().ok(),
    };
    value
        .map(Some)
        .ok_or_else(|| Error(format!("DEFAULT_SEED {lit:?} is not a u64 literal")))
}

/// The nextest binary id of a test function in `rel_path` (relative to the root): `<package>::<target>` for
/// `crates/<package>/tests/<target>.rs` and `crates/<package>/tests/<target>/…`, the package for any other file.
fn binary_id(rel_path: &str) -> String {
    let parts: Vec<&str> = rel_path.split('/').collect();
    match parts.as_slice() {
        ["crates", package, "tests", file] => {
            format!("{package}::{}", file.strip_suffix(".rs").unwrap_or(*file))
        }
        ["crates", package, "tests", dir, ..] => format!("{package}::{dir}"),
        ["crates", package, ..] => (*package).to_owned(),
        _ => rel_path.to_owned(),
    }
}

/// What [`scan_seeds`] found.
#[derive(Debug, Default)]
pub(crate) struct SeedScan {
    /// Every `#[test] fn prop_*`, as `binary_id::name`.
    pub(crate) props: BTreeSet<String>,
    /// Every test that reaches the helper, as `binary_id::name`.
    pub(crate) seeded_tests: BTreeSet<String>,
    /// Every `DEFAULT_SEED`, as (file, value).
    pub(crate) defaults: Vec<(String, u64)>,
    /// Every file that calls the helper, declared in it or in another file of its test binary.
    pub(crate) users: BTreeSet<String>,
    /// Violations of the seed rules (empty when the tree is right).
    pub(crate) findings: Vec<String>,
}

/// One Rust file of the scan.
struct Source {
    rel_path: String,
    raw: String,
    /// [`strip`] of `raw`.
    code: String,
    /// The test binary ([`binary_id`]).
    id: String,
    /// The file declares the helper ([`declares_helper`]).
    declares: bool,
}

/// The package of a `binary_id::name` or binary id.
fn package_of(id: &str) -> &str {
    id.split("::").next().unwrap_or(id)
}

/// The seed rules over every Rust file under `crates/` (M4 review R-93, TEST-SPEC-M5 X-07): (1) only [`SEED_HELPER`]
/// names the variable `"SECMP_PROPTEST_SEED"` as a literal; (2) a file with a `#[test] fn prop_*`, or with a seeded
/// generator (`seed_from_u64`, `SeedableRng`), calls `seed::master_seed`, and it or another file of its test binary
/// (e.g. the crate's `main.rs`) declares the helper; (3) every `prop_*` test reaches `seed::master_seed` through the
/// file's functions; (4) a file's `DEFAULT_SEED` lies in [`DEFAULT_SEED_RANGE`] and is the default it hands the helper;
/// (5) each binary of [`PROPERTY_BINARIES`] holds a test that reaches the helper; (6) every `prop_*` test and every
/// test that reaches the helper is in a package of [`PROPERTY_PACKAGES`], each of which is a KAT package
/// (`expect::KAT_PACKAGES`, so the kat step runs it with the CI run seed) and holds such a test.
pub(crate) fn scan_seeds(root: &Path) -> Result<SeedScan> {
    let helper = normalise(&root.join(SEED_HELPER));
    let mut scan = SeedScan::default();
    let text =
        std::fs::read_to_string(&helper).map_err(|e| Error(format!("{SEED_HELPER}: {e}")))?;
    if !text.contains("pub(crate) fn master_seed(default: u64) -> u64")
        || !text.contains("std::env::var(\"SECMP_PROPTEST_SEED\")")
    {
        scan.findings
            .push(format!("{SEED_HELPER}: not the reader of {SEED_ENV}"));
    }
    let mut sources = Vec::new();
    for file in walk_files(&root.join("crates"), &|p| {
        p.extension().is_some_and(|x| x == "rs")
    })? {
        if normalise(&file) == helper {
            continue;
        }
        let rel_path = rel(root, &file);
        let raw = std::fs::read_to_string(&file)?;
        sources.push(Source {
            id: binary_id(&rel_path),
            code: strip(&raw),
            declares: declares_helper(root, &file, &raw),
            rel_path,
            raw,
        });
    }
    let declaring: BTreeSet<String> = sources
        .iter()
        .filter(|s| s.declares)
        .map(|s| s.id.clone())
        .collect();
    for s in &sources {
        scan_file(s, declaring.contains(&s.id), &mut scan);
    }
    for b in PROPERTY_BINARIES {
        let prefix = format!("{b}::");
        if !scan.seeded_tests.iter().any(|t| t.starts_with(&prefix)) {
            scan.findings.push(format!(
                "PROPERTY_BINARIES: {b} holds no seeded test (stale entry)"
            ));
        }
    }
    let tests: BTreeSet<&String> = scan.props.iter().chain(&scan.seeded_tests).collect();
    for t in &tests {
        if !PROPERTY_PACKAGES.contains(&package_of(t)) {
            scan.findings.push(format!(
                "{t}: its package is not in PROPERTY_PACKAGES (no CI-seed pass)"
            ));
        }
    }
    for p in PROPERTY_PACKAGES {
        if !crate::expect::KAT_PACKAGES.contains(p) {
            scan.findings.push(format!(
                "PROPERTY_PACKAGES: {p} is not a KAT package (the kat step does not run it)"
            ));
        }
        if !tests.iter().any(|t| package_of(t) == *p) {
            scan.findings.push(format!(
                "PROPERTY_PACKAGES: {p} holds no property test (stale entry)"
            ));
        }
    }
    Ok(scan)
}

/// Rules (1)–(4) of [`scan_seeds`] on one file; `binary_declares`: some file of its test binary declares the helper.
fn scan_file(s: &Source, binary_declares: bool, scan: &mut SeedScan) {
    let rel_path = &s.rel_path;
    if s.raw.contains("\"SECMP_PROPTEST_SEED\"") {
        scan.findings.push(format!(
            "{rel_path}: names \"SECMP_PROPTEST_SEED\" itself; read it through {SEED_HELPER}"
        ));
    }
    let items = fn_items(&s.code);
    let seeded = seeded_fns(&items);
    let props: Vec<&FnItem> = items
        .iter()
        .filter(|f| f.test && f.name.starts_with("prop_"))
        .collect();
    let generator = s.code.contains("seed_from_u64(") || s.code.contains("SeedableRng");
    let uses = binary_declares && s.code.contains("seed::master_seed(");
    if uses {
        scan.users.insert(rel_path.clone());
    }
    if (generator || !props.is_empty()) && !uses {
        scan.findings.push(format!(
            "{rel_path}: seeded properties without the helper (`#[path = \"…/common/seed.rs\"] mod seed;` and `seed::master_seed(DEFAULT_SEED)`)"
        ));
    }
    for p in &props {
        scan.props.insert(format!("{}::{}", s.id, p.name));
        if !seeded.contains(&p.name) {
            scan.findings.push(format!(
                "{rel_path}: {} does not take its seed from seed::master_seed",
                p.name
            ));
        }
    }
    for f in items.iter().filter(|f| f.test && seeded.contains(&f.name)) {
        scan.seeded_tests.insert(format!("{}::{}", s.id, f.name));
    }
    match default_seed(&s.code) {
        Ok(None) => {}
        Err(e) => scan.findings.push(format!("{rel_path}: {e}")),
        Ok(Some(v)) => {
            if !DEFAULT_SEED_RANGE.contains(&v) {
                scan.findings.push(format!(
                    "{rel_path}: DEFAULT_SEED {v:#x} outside {:#x}..={:#x}",
                    DEFAULT_SEED_RANGE.start(),
                    DEFAULT_SEED_RANGE.end()
                ));
            }
            if !s.code.contains("seed::master_seed(DEFAULT_SEED)") {
                scan.findings.push(format!(
                    "{rel_path}: DEFAULT_SEED is not the default handed to seed::master_seed"
                ));
            }
            scan.defaults.push((rel_path.clone(), v));
        }
    }
}

/// The info string of a fenced code block opened on a doc-comment line (`///` or `//!`, fence of backticks or
/// tildes), if the line opens or closes one.
fn doc_fence_info(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let rest = t.strip_prefix("///").or_else(|| t.strip_prefix("//!"))?;
    let rest = rest.trim_start();
    rest.strip_prefix("```")
        .or_else(|| rest.strip_prefix("~~~"))
        .map(|r| r.trim_start_matches(['`', '~']))
}

/// Whether a code block's info string is `compile_fail` without an error code (`E` and four digits).
fn compile_fail_without_code(info: &str) -> bool {
    let attrs: Vec<&str> = info
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|a| !a.is_empty())
        .collect();
    let code = |a: &&str| {
        a.strip_prefix('E')
            .is_some_and(|d| d.len() == 4 && d.bytes().all(|b| b.is_ascii_digit()))
    };
    attrs.contains(&"compile_fail") && !attrs.iter().any(code)
}

/// Every `compile_fail` block without an error code in a doc comment of a first-party Rust file (M4 review R-92), as
/// `file:line`.
pub(crate) fn compile_fail_fences_without_code(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for dir in RUST_SOURCE_DIRS {
        let files = walk_files(&root.join(dir), &|p| {
            p.extension().is_some_and(|x| x == "rs")
        })?;
        for file in files {
            let text = std::fs::read_to_string(&file)?;
            for (n, line) in text.lines().enumerate() {
                if doc_fence_info(line).is_some_and(compile_fail_without_code) {
                    out.push(format!("{}:{}", rel(root, &file), n.saturating_add(1)));
                }
            }
        }
    }
    Ok(out)
}

/// A comparison site of a secret MAC, tag or token that must use a constant-time primitive (M5 review F-6, R-124,
/// TEST-SPEC-M6 G-03): the file (relative to the workspace root), the primitive the file must call, and the names of
/// the compared values.
pub(crate) struct CtSite {
    pub(crate) file: &'static str,
    pub(crate) primitive: &'static str,
    pub(crate) values: &'static [&'static str],
}

/// The four sites: `mac1` in the relay's handshake (`ct_eq`), `mac2` in the client's (`hmac_sha256_verify`), the
/// Q-command token in `ids.rs` (`hmac_sha256_verify`) and the tag of `hmac_sha256_verify` itself (`ct_eq`).
/// TEST-SPEC-M5 CT-01…04 are floor-only (the composed calls dwarf a `==`); this rule pins the comparison primitive.
pub(crate) const CT_SITES: &[CtSite] = &[
    CtSite {
        file: "crates/secmp-proto/src/link/relay.rs",
        primitive: "ct_eq",
        values: &["mac1"],
    },
    CtSite {
        file: "crates/secmp-proto/src/link/client.rs",
        primitive: "hmac_sha256_verify",
        values: &["mac2"],
    },
    CtSite {
        file: "crates/secmp-proto/src/link/ids.rs",
        primitive: "hmac_sha256_verify",
        values: &["received", "token"],
    },
    CtSite {
        file: "crates/secmp-crypto/src/mac.rs",
        primitive: "ct_eq",
        values: &["tag", "expected"],
    },
];

/// Whether `word` occurs in `text` bounded by non-identifier characters.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text.get(..i).and_then(|s| s.bytes().next_back());
        let after = text
            .get(i.saturating_add(word.len())..)
            .and_then(|s| s.bytes().next());
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Whether a line of stripped code has a `==` or `!=` operator (not `<=`, `>=`, `=>`, `===`).
fn has_equality_operator(line: &str) -> bool {
    let padded = format!(" {line} ");
    padded.as_bytes().windows(4).any(|w| match w {
        [p, b'=', b'=', n] => !matches!(p, b'=' | b'!' | b'<' | b'>') && *n != b'=',
        [_, b'!', b'=', n] => *n != b'=',
        _ => false,
    })
}

/// The findings for one site given the text of its file: the non-test part (up to the first `#[cfg(test)]`, with
/// comments and literals blanked) must call the site's primitive and compare none of its values with `==` or `!=`.
/// Each finding names the file (and the line for a comparison).
fn ct_site_findings(site: &CtSite, text: &str) -> Vec<String> {
    let code = strip(text);
    let code = code.split("#[cfg(test)]").next().unwrap_or_default();
    let mut out = Vec::new();
    let calls = code.match_indices(site.primitive).any(|(i, _)| {
        let before = code.get(..i).and_then(|s| s.bytes().next_back());
        let after = code
            .get(i.saturating_add(site.primitive.len())..)
            .and_then(|s| s.bytes().next());
        !before.is_some_and(is_ident) && after == Some(b'(')
    });
    if !calls {
        out.push(format!("{}: no call of {}", site.file, site.primitive));
    }
    for (n, line) in code.lines().enumerate() {
        if has_equality_operator(line) && site.values.iter().any(|v| has_word(line, v)) {
            out.push(format!(
                "{}:{}: `==`/`!=` on a secret value ({}); use {}",
                site.file,
                n.saturating_add(1),
                site.values.join("/"),
                site.primitive
            ));
        }
    }
    out
}

/// The findings of every site of [`CT_SITES`] under `root`.
pub(crate) fn ct_guard_findings(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for site in CT_SITES {
        let text = std::fs::read_to_string(root.join(site.file))
            .map_err(|e| Error(format!("{}: {e}", site.file)))?;
        out.extend(ct_site_findings(site, &text));
    }
    Ok(out)
}

/// Whether the code (comments and literals blanked) has an attribute naming `ignore` (`#[ignore]`,
/// `#[ignore = "…"]`, `#[cfg_attr(…, ignore)]`).
fn has_ignore_attribute(text: &str) -> bool {
    let code = strip(text);
    code.match_indices("#[").any(|(i, _)| {
        let body = code.get(i.saturating_add(2)..).unwrap_or_default();
        let mut depth = 1_usize;
        let mut end = body.len();
        for (j, c) in body.char_indices() {
            match c {
                '[' => depth = depth.saturating_add(1),
                ']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        has_word(body.get(..end).unwrap_or_default(), "ignore")
    })
}

/// The files of `files` (workspace-relative path, text) with an `ignore` attribute that `expect::IGNORE_ADR` does
/// not list (CLAUDE.md §6: no `#[ignore]` without an ADR; M5 review R-155).
fn ignore_findings(files: &[(String, String)], listed: &[&str]) -> Vec<String> {
    files
        .iter()
        .filter(|(path, text)| !listed.contains(&path.as_str()) && has_ignore_attribute(text))
        .map(|(path, _)| format!("{path}: #[ignore] without an ADR (expect::IGNORE_ADR)"))
        .collect()
}

/// [`ignore_findings`] over every first-party Rust file under `root`.
pub(crate) fn ignore_findings_in_tree(root: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for dir in RUST_SOURCE_DIRS {
        for file in walk_files(&root.join(dir), &|p| {
            p.extension().is_some_and(|x| x == "rs")
        })? {
            files.push((rel(root, &file), std::fs::read_to_string(&file)?));
        }
    }
    Ok(ignore_findings(&files, expect::IGNORE_ADR))
}

mod tests {
    use super::*;
    use crate::gates;

    /// TEST-SPEC-M6 G-03 (M5 review F-6, R-124): the four MAC/tag/token sites compare through `ct_eq` /
    /// `hmac_sha256_verify`, with no `==`/`!=` on the compared values; a fixture with `==` at one site is refused
    /// naming it, a fixture without the primitive too.
    #[test]
    fn ct_guard_sites_use_ct_eq() -> Result<()> {
        assert_eq!(CT_SITES.len(), 4);
        assert_eq!(ct_guard_findings(&root())?, Vec::<String>::new());
        // the shape of each real site passes; the same text with `==` is refused naming the site and line
        let good = "fn open() {\n    if !bool::from(mac1.ct_eq(&hs1.mac1)) { return; }\n    k.kid == hs1.kid;\n}\n\
                    #[cfg(test)]\nmod tests { fn t() { assert!(mac1 == other); } }\n";
        let relay = CT_SITES
            .first()
            .ok_or_else(|| Error("no site".to_owned()))?;
        assert_eq!(ct_site_findings(relay, good), Vec::<String>::new());
        let bad = good.replace("!bool::from(mac1.ct_eq(&hs1.mac1))", "mac1 != hs1.mac1");
        let found = ct_site_findings(relay, &bad);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("crates/secmp-proto/src/link/relay.rs:2: ")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|f| f.contains("no call of ct_eq")),
            "{found:?}"
        );
        // `==` in a comment or a string, on another value, or an operator like `<=`/`=>` is no finding
        let quiet = "fn f() {\n    // mac1 == x\n    let s = \"mac1 == x\";\n    let ok = ct_eq(a); if n <= mac1len { } match mac1 { _ => 1 };\n}\n";
        assert_eq!(ct_site_findings(relay, quiet), Vec::<String>::new());
        // the other three sites name their own file
        for site in CT_SITES.iter().skip(1) {
            let value = site.values.first().copied().unwrap_or("x");
            let text = format!(
                "fn f() {{ let _ = {}(a); if {value} == b {{ }} }}\n",
                site.primitive
            );
            let found = ct_site_findings(site, &text);
            assert_eq!(found.len(), 1, "{found:?}");
            assert!(found.iter().all(|f| f.starts_with(site.file)), "{found:?}");
        }
        Ok(())
    }

    /// TEST-SPEC-M6 G-10 (M5 review R-155, CLAUDE.md §6): no `#[ignore]` in a first-party Rust file unless
    /// `expect::IGNORE_ADR` lists the file (empty); the fixtures prove the detection and the listing.
    #[test]
    fn no_ignore_without_adr() -> Result<()> {
        assert!(expect::IGNORE_ADR.is_empty());
        assert_eq!(ignore_findings_in_tree(&root())?, Vec::<String>::new());
        let file = |path: &str, text: &str| vec![(path.to_owned(), text.to_owned())];
        for text in [
            "#[test]\n#[ignore]\nfn slow() {}\n",
            "#[test]\n#[ignore = \"slow\"]\nfn slow() {}\n",
            "#[cfg_attr(miri, ignore)]\nfn slow() {}\n",
        ] {
            let found = ignore_findings(&file("crates/x/tests/a.rs", text), &[]);
            assert_eq!(found.len(), 1, "{text}");
            assert!(
                found.iter().all(|f| f.starts_with("crates/x/tests/a.rs: ")),
                "{found:?}"
            );
            // listed with an ADR: accepted
            assert!(
                ignore_findings(&file("crates/x/tests/a.rs", text), &["crates/x/tests/a.rs"])
                    .is_empty()
            );
        }
        // mentions in comments, strings and unrelated attributes are no finding
        for text in [
            "// #[ignore]\nfn f() {}\n",
            "const S: &str = \"#[ignore]\";\n",
            "#[derive(Debug)]\n#[must_use]\nstruct Ignored;\n",
            "#[doc = \"ignore\"]\nfn f() {}\n",
            "#[test]\nfn ignore() {}\n",
        ] {
            assert!(
                ignore_findings(&file("crates/x/src/a.rs", text), &[]).is_empty(),
                "{text}"
            );
        }
        Ok(())
    }
    use crate::testscan::{
        NextestRun, ci_run_seed_from, kat_args, kat_runs, kat_seed_detail, nextest_detail,
        nextest_runs, property_filter,
    };

    fn root() -> PathBuf {
        normalise(&Path::new(env!("CARGO_MANIFEST_DIR")).join(".."))
    }

    /// The body of `pub(crate) fn <name>(<params>) -> Result<Outcome>` in `gates.rs` (line endings normalised).
    fn gate_body(name_and_params: &str) -> Result<String> {
        let gates_rs =
            std::fs::read_to_string(root().join("xtask/src/gates.rs"))?.replace("\r\n", "\n");
        gates_rs
            .split_once(&format!(
                "pub(crate) fn {name_and_params} -> Result<Outcome> {{"
            ))
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body.to_owned())
            .ok_or_else(|| Error(format!("gates.rs: no fn {name_and_params}")))
    }

    /// The invocations: the `nextest` step's two runs with the variable removed; the `kat` step's run of every KAT
    /// package with the variable removed and, with a CI run seed, of every property package filtered to its property
    /// tests with the variable set; the steps' code runs exactly these and names the seed in the verdict line.
    fn check_invocations() -> Result<()> {
        let plain =
            |args: Vec<&str>| -> Vec<String> { args.into_iter().map(str::to_owned).collect() };
        assert_eq!(
            nextest_runs(),
            vec![
                NextestRun {
                    args: plain(gates::nextest_args()),
                    seed: None
                },
                NextestRun {
                    args: plain(gates::nextest_nonkat_args()),
                    seed: None
                },
            ]
        );
        let packages: BTreeSet<String> = crate::expect::KAT_PACKAGES
            .iter()
            .map(|p| (*p).to_owned())
            .collect();
        let local = kat_runs(&packages, None)?;
        let defaults: Vec<NextestRun> = packages
            .iter()
            .map(|p| NextestRun {
                args: plain(vec![
                    "nextest",
                    "run",
                    "--locked",
                    "--package",
                    p.as_str(),
                    "--features",
                    "kat",
                ]),
                seed: None,
            })
            .collect();
        assert_eq!(local, defaults);
        let ci = kat_runs(&packages, Some(37_041_956_810))?;
        assert_eq!(ci.get(..defaults.len()), Some(defaults.as_slice()));
        let seeded: Vec<NextestRun> = PROPERTY_PACKAGES
            .iter()
            .map(|p| {
                let mut args = kat_args(p);
                args.extend(["-E".to_owned(), property_filter()]);
                NextestRun {
                    args,
                    seed: Some(37_041_956_810),
                }
            })
            .collect();
        assert_eq!(ci.get(defaults.len()..), Some(seeded.as_slice()));
        assert!(
            PROPERTY_PACKAGES.contains(&"secmp-relay")
                && PROPERTY_PACKAGES.contains(&"secmp-proto")
        );
        // a property package outside the KAT packages has no kat run: refused
        let mut fewer = packages.clone();
        fewer.remove("secmp-relay");
        assert!(kat_runs(&fewer, Some(1)).is_err());
        assert_eq!(kat_runs(&fewer, None)?.len(), fewer.len());
        for run in nextest_runs().iter().chain(&local) {
            let cmd = format!("{:?}", run.cmd());
            assert!(
                cmd.contains("removed: [\"SECMP_PROPTEST_SEED\"]") && cmd.contains("envs: []"),
                "{cmd}"
            );
        }
        let cmd = format!("{:?}", seeded.first().map(NextestRun::cmd));
        assert!(
            cmd.contains("envs: [(\"SECMP_PROPTEST_SEED\", \"37041956810\")]")
                && cmd.contains("removed: []"),
            "{cmd}"
        );
        assert_eq!(
            property_filter(),
            "test(/(^|::)prop_/) | binary_id(=secmp-proto::canonical) | binary_id(=secmp-proto::tr_properties)"
        );
        // the verdict line (ADR-045 summary rows) and the failure message carry the seed and the reproduction
        assert_eq!(
            seeded.first().map(NextestRun::reproduction).as_deref(),
            Some(
                "SECMP_PROPTEST_SEED=37041956810 cargo nextest run --locked --package secmp-proto --features kat -E 'test(/(^|::)prop_/) | binary_id(=secmp-proto::canonical) | binary_id(=secmp-proto::tr_properties)'"
            )
        );
        let detail = kat_seed_detail(Some(37_041_956_810));
        assert!(
            detail.contains("CI run seed SECMP_PROPTEST_SEED=37041956810"),
            "{detail}"
        );
        for run in &seeded {
            assert!(detail.contains(&run.reproduction()), "{detail}");
            assert!(!run.reproduction().contains("; "));
        }
        assert!(kat_seed_detail(None).contains("DEFAULT_SEED only"));
        assert!(nextest_detail().contains("SECMP_PROPTEST_SEED removed"));
        Ok(())
    }

    /// The gates run these invocations, the kat step with the seed of the environment.
    fn check_gate_code() -> Result<()> {
        let nextest = gate_body("nextest(_: &Ctx)")?;
        assert!(nextest.contains("testscan::nextest_runs()") && nextest.contains(".run()?"));
        assert!(nextest.contains("testscan::nextest_detail()"));
        assert!(
            !nextest.contains("Cmd::cargo()"),
            "gates::nextest runs nextest itself"
        );
        let kat = gate_body("kat(ctx: &Ctx)")?;
        for needle in [
            "testscan::ci_run_seed()?",
            "testscan::kat_runs(&found, ci_seed)?",
            "run.run()?",
            "testscan::kat_seed_detail(ci_seed)",
            ".env_remove(crate::testscan::SEED_ENV)",
        ] {
            assert!(kat.contains(needle), "gates::kat lacks {needle}");
        }
        // the only other nextest invocation of the kat step is the portable-backend rerun
        assert_eq!(kat.matches("Cmd::cargo()").count(), 1, "{kat}");
        Ok(())
    }

    /// The kat step runs in every pull-request run: `ci.yml` triggers on `pull_request`, `linux-fast` (no job condition)
    /// runs `ci-fast`, whose steps include `kat`, and `windows-native` (no job condition) runs the step by name.
    fn check_pr_jobs() -> Result<()> {
        let ci_yml = std::fs::read_to_string(root().join(crate::expect::REQUIRED_WORKFLOW))?
            .replace("\r\n", "\n");
        assert!(ci_yml.contains("on:\n  pull_request:\n"));
        let runs = |job: &str| {
            crate::expect::REQUIRED_GATE_RUNS
                .iter()
                .find(|(j, _)| *j == job)
                .map(|(_, lines)| *lines)
                .unwrap_or_default()
        };
        assert!(runs("linux-fast").contains(&"cargo xtask ci-fast --strict"));
        for step in ["nextest", "kat"] {
            assert!(
                runs("windows-native")
                    .iter()
                    .any(|l| l.split_whitespace().any(|w| w == step)),
                "{step}"
            );
        }
        for job in ["linux-fast", "windows-native"] {
            assert!(
                crate::expect::REQUIRED_JOB_CONDITIONS.contains(&(job, None)),
                "{job} runs on every event"
            );
        }
        let ci_rs = std::fs::read_to_string(root().join("xtask/src/ci.rs"))?.replace("\r\n", "\n");
        let fast = ci_rs
            .split_once("const FAST: &[Step] = &[")
            .and_then(|(_, rest)| rest.split_once("\n];\n"))
            .map(|(steps, _)| steps)
            .ok_or_else(|| Error("ci.rs: no FAST".to_owned()))?;
        assert!(fast.contains("id: \"nextest\"") && fast.contains("id: \"kat\""));
        Ok(())
    }

    /// The CI run seed: `None` outside GitHub Actions; in a run, the run id — the same for the same run (also across
    /// attempts and jobs), different for another run, never a `DEFAULT_SEED`; a missing, malformed or reserved run id
    /// fails.
    fn check_derivation(defaults: &[(String, u64)]) -> Result<()> {
        assert_eq!(ci_run_seed_from(None, Some("37041956810"))?, None);
        assert_eq!(ci_run_seed_from(Some("false"), Some("37041956810"))?, None);
        let a = ci_run_seed_from(Some("true"), Some("37041956810"))?;
        assert_eq!(a, Some(37_041_956_810));
        assert_eq!(ci_run_seed_from(Some("true"), Some(" 37041956810\n"))?, a);
        let b = ci_run_seed_from(Some("true"), Some("37041956811"))?;
        assert!(b.is_some() && b != a);
        for bad in [
            None,
            Some(""),
            Some("x1"),
            Some("-1"),
            Some("18446744073709551616"),
        ] {
            assert!(ci_run_seed_from(Some("true"), bad).is_err(), "{bad:?}");
        }
        let reserved = DEFAULT_SEED_RANGE.start().to_string();
        assert!(ci_run_seed_from(Some("true"), Some(&reserved)).is_err());
        assert!(defaults.len() >= 4, "{defaults:?}");
        for (file, v) in defaults {
            assert!(DEFAULT_SEED_RANGE.contains(v), "{file}");
            assert!(
                ci_run_seed_from(Some("true"), Some(&v.to_string())).is_err(),
                "{file}"
            );
            assert_ne!(a, Some(*v), "{file}");
        }
        Ok(())
    }

    /// M4 review R-93, TEST-SPEC-M5 X-07 [O-17]: pull-request runs execute every property test with its `DEFAULT_SEED`
    /// and again with a seed derived from the run. Proves (1) the invocations of the `nextest` step (variable removed)
    /// and of the `kat` step (every KAT package with the variable removed, then every property package filtered to
    /// its property tests with the CI run seed) and that the steps' code runs them, (2) that both steps run in every
    /// pull-request run, (3) the derivation (deterministic per run, distinct per run, never a `DEFAULT_SEED`), (4) by
    /// the source scan, that every `prop_*` test takes its seed from the one helper, that every property's package is
    /// a property package of the kat step, and that the CI-seed filter covers the seeded binaries.
    #[test]
    fn pr_ci_runs_props_with_ci_run_seed() -> Result<()> {
        check_invocations()?;
        check_gate_code()?;
        check_pr_jobs()?;
        let scan = scan_seeds(&root())?;
        assert!(scan.findings.is_empty(), "{:#?}", scan.findings);
        check_derivation(&scan.defaults)?;
        // the scan is not vacuous: the properties of TEST-SPEC-M4 (c) and M5 (d) — P-01…P-05, P-12 in secmp-proto,
        // P-06…P-11 in secmp-relay's kat-only `relay` crate — and the four seeded files of secmp-proto
        for p in [
            "secmp-proto::hx::prop_handshake_complementary_states",
            "secmp-proto::hx::prop_outer_unpad_total_12018",
            "secmp-proto::hx::prop_k_id_independent_of_iks_i_dh1_dh2",
            "secmp-proto::link::prop_link_handshake_agrees",
            "secmp-proto::link::prop_q_ids_are_derived",
            "secmp-relay::relay::prop_executor_response_shape_matches_d2",
            "secmp-relay::relay::prop_queue_store_matches_model",
            "secmp-relay::relay::prop_rejection_leaves_link_and_store_unchanged",
            "secmp-relay::relay::prop_response_count_independent_of_outcome",
            "secmp-relay::relay::prop_one_time_link_data_single_winner",
            "secmp-relay::relay::prop_cmd_seq_executes_iff_greater_than_last",
        ] {
            assert!(scan.props.contains(p), "{p}: {:#?}", scan.props);
            assert!(scan.seeded_tests.contains(p), "{p}");
        }
        assert!(scan.props.len() >= 18, "{:#?}", scan.props);
        for t in [
            "secmp-proto::canonical::records",
            "secmp-proto::tr_properties::random_interleavings_follow_spec_7_4_and_never_reuse_a_key",
        ] {
            assert!(scan.seeded_tests.contains(t), "{t}");
        }
        for f in [
            "crates/secmp-proto/tests/canonical.rs",
            "crates/secmp-proto/tests/tr_properties.rs",
            "crates/secmp-proto/tests/hx/props.rs",
            "crates/secmp-proto/tests/link/frames.rs",
        ] {
            assert!(scan.users.contains(f), "{f}: {:#?}", scan.users);
        }
        Ok(())
    }

    /// The scanner itself on fixtures: a property that draws its own seed, one that reaches the helper through two
    /// calls, a test in a comment or a string, and a reader of the variable outside the helper.
    #[test]
    fn the_seed_scanner_reads_items_and_calls() -> Result<()> {
        let src = concat!(
            "const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0009;\n",
            "fn master_seed() -> u64 { seed::master_seed(DEFAULT_SEED) }\n",
            "fn rng_for(t: u64) -> u64 { master_seed() ^ t }\n",
            "/// `fn prop_in_doc() {}`\n",
            "#[test]\nfn prop_good() { let s = \"} fn prop_fake() {\"; let c = '{'; let _ = rng_for(1); }\n",
            "#[test]\n#[cfg(feature = \"kat\")]\nfn prop_bad() { let _ = 7_u64.wrapping_mul(3); }\n",
            "fn helper<'a>(x: &'a str) -> &'a str { x }\n",
            "/* fn prop_block() { master_seed() } */\n",
            "#[test]\nfn plain() { let _ = r#\"master_seed()\"#; }\n",
        );
        let code = strip(src);
        assert!(
            !code.contains("prop_in_doc")
                && !code.contains("prop_fake")
                && !code.contains("prop_block")
        );
        let items = fn_items(&code);
        let names: Vec<(&str, bool)> = items.iter().map(|f| (f.name.as_str(), f.test)).collect();
        assert_eq!(
            names,
            vec![
                ("master_seed", false),
                ("rng_for", false),
                ("prop_good", true),
                ("prop_bad", true),
                ("helper", false),
                ("plain", true),
            ]
        );
        let seeded = seeded_fns(&items);
        let want: BTreeSet<String> = ["master_seed", "rng_for", "prop_good"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(seeded, want);
        assert_eq!(default_seed(&code)?, Some(0x5ec3_2d00_0000_0009));
        assert!(default_seed("const DEFAULT_SEED: u64 = 0xzz;").is_err());
        assert_eq!(default_seed("const OTHER: u64 = 1;")?, None);
        assert!(
            calls("a.rng_for(1)", "rng_for")
                && !calls("xrng_for(1)", "rng_for")
                && !calls("rng_for", "rng_for")
        );
        assert_eq!(
            binary_id("crates/secmp-proto/tests/hx/props.rs"),
            "secmp-proto::hx"
        );
        assert_eq!(
            binary_id("crates/secmp-proto/tests/canonical.rs"),
            "secmp-proto::canonical"
        );
        assert_eq!(binary_id("crates/secmp-relay/src/lib.rs"), "secmp-relay");
        let root = Path::new("/w");
        let file = Path::new("/w/crates/secmp-proto/tests/hx/props.rs");
        assert!(declares_helper(
            root,
            file,
            "#[path = \"../common/seed.rs\"]\nmod seed;\n"
        ));
        assert!(!declares_helper(
            root,
            file,
            "#[path = \"common/seed.rs\"]\nmod seed;\n"
        ));
        assert!(!declares_helper(
            root,
            file,
            "#[path = \"../common/seed.rs\"]\nmod other;\n"
        ));
        Ok(())
    }

    /// The seed rules on a fixture tree (a scratch directory): one compliant file, a compliant test crate whose
    /// `main.rs` declares the helper for its `props.rs`, and one file per broken rule — a property with its own seed
    /// source, a reader of the variable outside the helper, a `DEFAULT_SEED` outside the range and not handed to the
    /// helper — the properties outside `PROPERTY_PACKAGES`, and the stale `PROPERTY_PACKAGES` and `PROPERTY_BINARIES`
    /// entries; each is reported.
    #[test]
    fn the_seed_scan_flags_each_rule() -> Result<()> {
        let tree = std::env::temp_dir().join(format!("secmp-testscan-{}", std::process::id()));
        let write = |rel_path: &str, text: &str| -> Result<()> {
            let path = tree.join(rel_path);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, text)?;
            Ok(())
        };
        write(
            SEED_HELPER,
            "pub(crate) fn master_seed(default: u64) -> u64 {\n    let _ = std::env::var(\"SECMP_PROPTEST_SEED\");\n    default\n}\n",
        )?;
        let header = "#[path = \"../../secmp-proto/tests/common/seed.rs\"]\nmod seed;\n";
        write(
            "crates/a/tests/good.rs",
            &format!(
                "{header}const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0001;\nfn master_seed() -> u64 {{ seed::master_seed(DEFAULT_SEED) }}\n#[test]\nfn prop_ok() {{ let _ = master_seed(); }}\n"
            ),
        )?;
        write(
            "crates/a/tests/own.rs",
            "#[test]\nfn prop_own() { let _ = std::env::var(\"SECMP_PROPTEST_SEED\"); let _ = StdRng::seed_from_u64(1); }\n",
        )?;
        write(
            "crates/a/tests/range.rs",
            &format!(
                "{header}const DEFAULT_SEED: u64 = 7;\nfn s() -> u64 {{ seed::master_seed(7) }}\n#[test]\nfn prop_unreached() {{}}\n#[test]\nfn prop_r() {{ let _ = s(); }}\n"
            ),
        )?;
        // a test crate whose `main.rs` declares the helper and whose `props.rs` calls it (the `relay` layout)
        write(
            "crates/b/tests/bin/main.rs",
            "#[path = \"../../../secmp-proto/tests/common/seed.rs\"]\nmod seed;\nmod props;\n",
        )?;
        write(
            "crates/b/tests/bin/props.rs",
            "const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0002;\nfn m() -> u64 { crate::seed::master_seed(DEFAULT_SEED) }\n#[test]\nfn prop_via_main() { let _ = m(); }\n",
        )?;
        let scan = scan_seeds(&tree);
        std::fs::remove_dir_all(&tree)?;
        let scan = scan?;
        let want = [
            "a::good::prop_ok: its package is not in PROPERTY_PACKAGES (no CI-seed pass)",
            "a::own::prop_own: its package is not in PROPERTY_PACKAGES (no CI-seed pass)",
            "a::range::prop_r: its package is not in PROPERTY_PACKAGES (no CI-seed pass)",
            "a::range::prop_unreached: its package is not in PROPERTY_PACKAGES (no CI-seed pass)",
            "b::bin::prop_via_main: its package is not in PROPERTY_PACKAGES (no CI-seed pass)",
            "PROPERTY_PACKAGES: secmp-proto holds no property test (stale entry)",
            "PROPERTY_PACKAGES: secmp-relay holds no property test (stale entry)",
            "crates/a/tests/own.rs: names \"SECMP_PROPTEST_SEED\" itself; read it through crates/secmp-proto/tests/common/seed.rs",
            "crates/a/tests/own.rs: seeded properties without the helper (`#[path = \"…/common/seed.rs\"] mod seed;` and `seed::master_seed(DEFAULT_SEED)`)",
            "crates/a/tests/own.rs: prop_own does not take its seed from seed::master_seed",
            "crates/a/tests/range.rs: prop_unreached does not take its seed from seed::master_seed",
            "crates/a/tests/range.rs: DEFAULT_SEED 0x7 outside 0x5ec32d0000000000..=0x5ec32d00ffffffff",
            "crates/a/tests/range.rs: DEFAULT_SEED is not the default handed to seed::master_seed",
            "PROPERTY_BINARIES: secmp-proto::canonical holds no seeded test (stale entry)",
            "PROPERTY_BINARIES: secmp-proto::tr_properties holds no seeded test (stale entry)",
        ];
        let got: BTreeSet<&str> = scan.findings.iter().map(String::as_str).collect();
        assert_eq!(got, want.into_iter().collect::<BTreeSet<_>>());
        assert_eq!(scan.findings.len(), want.len());
        let props: Vec<&str> = scan.props.iter().map(String::as_str).collect();
        assert_eq!(
            props,
            vec![
                "a::good::prop_ok",
                "a::own::prop_own",
                "a::range::prop_r",
                "a::range::prop_unreached",
                "b::bin::prop_via_main"
            ]
        );
        assert_eq!(
            scan.users.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "crates/a/tests/good.rs",
                "crates/a/tests/range.rs",
                "crates/b/tests/bin/props.rs"
            ]
        );
        Ok(())
    }

    /// M4 review R-92, TEST-SPEC-M5 X-06: every `compile_fail` block in a doc comment of a first-party Rust file names
    /// its error code; the reader of the fences on fixtures (with and without a code, backticks and tildes, inner and
    /// outer doc comments, a fence mentioned in prose or in a plain comment).
    #[test]
    fn doctest_compile_fail_blocks_name_an_error_code() -> Result<()> {
        let fence = "```";
        let cases = [
            (format!("/// {fence}compile_fail"), true),
            (format!("    //! {fence}compile_fail,no_run"), true),
            ("/// ~~~compile_fail".to_owned(), true),
            (format!("/// {fence}compile_fail,E0624"), false),
            (format!("/// {fence}rust,compile_fail,E0277"), false),
            (format!("/// {fence}compile_fail,E06"), true),
            (format!("/// {fence}text"), false),
            (format!("/// {fence}"), false),
            (
                format!("/// a {fence}compile_fail mentioned in prose"),
                false,
            ),
            (format!("// {fence}compile_fail"), false),
        ];
        for (line, flagged) in &cases {
            assert_eq!(
                doc_fence_info(line).is_some_and(compile_fail_without_code),
                *flagged,
                "{line}"
            );
        }
        let missing = compile_fail_fences_without_code(&root())?;
        assert!(
            missing.is_empty(),
            "compile_fail blocks without an error code: {missing:?}"
        );
        Ok(())
    }
}
