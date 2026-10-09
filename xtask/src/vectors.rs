// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask vectors` and the reference cross-check (docs/06 §5 step 12a, ADR-026, `vectors/SCHEMA.md` §1).
//!
//! 1. The Rust generators write `vectors/rust/<suite>.json` (gitignored): the `secmp-crypto` example `gen-vectors`
//!    (feature `kat`) the M1 suites, the `secmp-proto` example `gen-encodings` the positive rows of `encodings`, the
//!    `secmp-proto` example `gen-tr` (feature `kat`) the complete `tr` suite (M3), the example `gen-hx` (feature
//!    `kat`) the complete `hx` suite (M4), the `secmp-relay` example `gen-link` (feature `kat`) the complete `link`
//!    suite (M5).
//! 2. Each file is compared **structurally** with the committed reference file `vectors/ref/<suite>.json`
//!    (written by the independent `ref/` session): both are parsed, `generator` is removed, the values must be
//!    equal — no case folding. Every byte-string field must match `^([0-9a-f]{2})*$`. For the suites of
//!    [`expect::VECTOR_POSITIVE_ONLY`] the comparison covers the header and the positive rows; the reference
//!    file's other rows must all be `decode` rows expecting `reject`, and the decoders must reject every one of
//!    them (the `secmp-proto` test `encodings_ref`, run here before the freeze).
//! 3. On agreement the reference file is frozen verbatim as `vectors/<suite>.json`. An existing frozen file is
//!    never overwritten: if it differs, the command fails (frozen vectors change only with a spec revision).
//!
//! CI step 12a (`check_frozen_against_ref`) re-checks every frozen file against its reference file without running
//! a generator: structurally, and byte for byte (M2 review F8; ADR-026 as amended: the frozen file is a verbatim
//! copy).
//!
//! A mismatch is reported with suite, case id, field and both values; the Rust side is never adjusted to match.

use std::path::Path;

use serde_json::Value;

use crate::expect;
use crate::util::{Cmd, Error, Result, bail, say};

/// Fields whose JSON strings are not byte strings (SCHEMA §1: labels, digit strings, `mode`, `op`, ids; schema 3:
/// the `encodings` inputs `structure` and `context`; schema 5: the `hx` invitation `uri`, an ASCII string).
const TEXT_FIELDS: &[&str] = &[
    "id",
    "op",
    "expect",
    "label",
    "mode",
    "half_a",
    "half_b",
    "safety_number",
    "suite",
    "spec",
    "generator",
    "structure",
    "context",
    "uri",
];

fn parse(path: &Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).map_err(|e| Error(format!("{}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| Error(format!("{}: {e}", path.display())))
}

fn without_generator(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(m) = v.as_object_mut() {
        m.remove("generator");
    }
    v
}

/// Structural differences between two vector files, as human-readable lines (empty: equal).
pub(crate) fn differences(ours: &Value, theirs: &Value) -> Vec<String> {
    let (a, b) = (without_generator(ours), without_generator(theirs));
    let mut out = Vec::new();
    diff("", &a, &b, &mut out);
    out
}

fn case_id(v: &Value) -> Option<&str> {
    v.get("id").and_then(Value::as_str)
}

/// A positive-only suite's reference file as the Rust generator writes it: the header and the positive (`encode`)
/// rows. The other rows must all be `decode` rows expecting `reject`; any other row is returned as a problem.
pub(crate) fn positive_view(reference: &Value) -> (Value, Vec<String>) {
    let mut view = reference.clone();
    let mut problems = Vec::new();
    if let Some(cases) = view.get_mut("cases").and_then(Value::as_array_mut) {
        cases.retain(|c| {
            let op = c.get("op").and_then(Value::as_str);
            if op == Some("encode") {
                return true;
            }
            if op != Some("decode") || c.get("expect").and_then(Value::as_str) != Some("reject") {
                problems.push(format!(
                    "{}: neither a positive row nor a rejecting decode row",
                    case_id(c).unwrap_or("?")
                ));
            }
            false
        });
    }
    (view, problems)
}

fn diff(path: &str, ours: &Value, theirs: &Value, out: &mut Vec<String>) {
    if ours == theirs {
        return;
    }
    match (ours, theirs) {
        (Value::Object(om), Value::Object(tm)) => {
            let keys: std::collections::BTreeSet<&String> = om.keys().chain(tm.keys()).collect();
            for key in keys {
                let sub = format!("{path}/{key}");
                match (om.get(key), tm.get(key)) {
                    (Some(ov), Some(tv)) => diff(&sub, ov, tv, out),
                    (ov, tv) => out.push(format!(
                        "{sub}: rust {} vs ref {}",
                        ov.map_or("<absent>".to_owned(), Value::to_string),
                        tv.map_or("<absent>".to_owned(), Value::to_string)
                    )),
                }
            }
        }
        (Value::Array(oa), Value::Array(ta)) => {
            if oa.len() != ta.len() {
                out.push(format!(
                    "{path}: rust has {} entries, ref {}",
                    oa.len(),
                    ta.len()
                ));
            }
            for (idx, (ov, tv)) in oa.iter().zip(ta).enumerate() {
                let label = case_id(ov).map_or_else(|| idx.to_string(), str::to_owned);
                diff(&format!("{path}[{label}]"), ov, tv, out);
            }
        }
        _ => out.push(format!("{path}: rust {ours} vs ref {theirs}")),
    }
}

/// Byte-string fields that are not lowercase hex (SCHEMA §1 validator).
pub(crate) fn hex_violations(doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let empty = Vec::new();
    for case in doc.get("cases").and_then(Value::as_array).unwrap_or(&empty) {
        for section in ["inputs", "outputs"] {
            let Some(fields) = case.get(section).and_then(Value::as_object) else {
                continue;
            };
            for (k, v) in fields {
                let Some(s) = v.as_str() else { continue };
                if TEXT_FIELDS.contains(&k.as_str()) {
                    continue;
                }
                let hex = s.len().is_multiple_of(2)
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if !hex {
                    out.push(format!(
                        "{}: {section}.{k} is not lowercase hex",
                        case_id(case).unwrap_or("?")
                    ));
                }
            }
        }
    }
    out
}

/// Step 1: the Rust generators write `rust_dir`; the decoders must reject every negative row of the
/// positive-only suites.
fn generate(rust_dir: &Path) -> Result<()> {
    Cmd::cargo()
        .args([
            "run",
            "--release",
            "--locked",
            "--quiet",
            "--package",
            "secmp-crypto",
            "--features",
            "kat",
            "--example",
            "gen-vectors",
            "--",
        ])
        .arg(rust_dir.to_string_lossy())
        .run()?;
    Cmd::cargo()
        .args([
            "run",
            "--release",
            "--locked",
            "--quiet",
            "--package",
            "secmp-proto",
            "--example",
            "gen-encodings",
            "--",
        ])
        .arg(rust_dir.to_string_lossy())
        .run()?;
    Cmd::cargo()
        .args([
            "run",
            "--release",
            "--locked",
            "--quiet",
            "--package",
            "secmp-proto",
            "--features",
            "kat",
            "--example",
            "gen-tr",
            "--",
        ])
        .arg(rust_dir.to_string_lossy())
        .run()?;
    Cmd::cargo()
        .args([
            "run",
            "--release",
            "--locked",
            "--quiet",
            "--package",
            "secmp-proto",
            "--features",
            "kat",
            "--example",
            "gen-hx",
            "--",
        ])
        .arg(rust_dir.to_string_lossy())
        .run()?;
    Cmd::cargo()
        .args([
            "run",
            "--release",
            "--locked",
            "--quiet",
            "--package",
            "secmp-relay",
            "--features",
            "kat",
            "--example",
            "gen-link",
            "--",
        ])
        .arg(rust_dir.to_string_lossy())
        .run()?;
    // the negative rows of the positive-only suites: every one rejected by the decoders
    Cmd::cargo()
        .args([
            "nextest",
            "run",
            "--locked",
            "--package",
            "secmp-proto",
            "--test",
            "encodings_ref",
        ])
        .run()?;
    Ok(())
}

/// `cargo xtask vectors`.
pub(crate) fn run(root: &Path) -> Result<()> {
    let rust_dir = root.join("vectors").join("rust");
    generate(&rust_dir)?;
    let mut problems = Vec::new();
    let mut open = Vec::new();
    for suite in expect::VECTOR_SUITES {
        let rust = parse(&rust_dir.join(format!("{suite}.json")))?;
        problems.extend(
            hex_violations(&rust)
                .into_iter()
                .map(|p| format!("{suite} (rust): {p}")),
        );
        let ref_path = root
            .join("vectors")
            .join("ref")
            .join(format!("{suite}.json"));
        if !ref_path.exists() {
            open.push(*suite);
            continue;
        }
        let reference = parse(&ref_path)?;
        problems.extend(
            hex_violations(&reference)
                .into_iter()
                .map(|p| format!("{suite} (ref): {p}")),
        );
        let reference = if expect::VECTOR_POSITIVE_ONLY.contains(suite) {
            let (view, shape) = positive_view(&reference);
            problems.extend(shape.into_iter().map(|p| format!("{suite} (ref): {p}")));
            view
        } else {
            reference
        };
        let diffs = differences(&rust, &reference);
        if !diffs.is_empty() {
            for d in &diffs {
                say(&format!("  MISMATCH {suite} {d}"));
            }
            problems.push(format!(
                "{suite}: {} difference(s), first: {}",
                diffs.len(),
                diffs.first().map_or("", String::as_str)
            ));
            continue;
        }
        let frozen = root.join("vectors").join(format!("{suite}.json"));
        let ref_bytes = std::fs::read(&ref_path)?;
        if frozen.exists() {
            if std::fs::read(&frozen)? == ref_bytes {
                say(&format!(
                    "  {suite}: agrees with ref; frozen file unchanged"
                ));
            } else {
                problems.push(format!(
                    "{suite}: frozen vectors/{suite}.json differs from the agreed file (frozen vectors change only with a spec revision)"
                ));
            }
        } else {
            std::fs::write(&frozen, &ref_bytes)?;
            say(&format!(
                "  {suite}: agrees with ref; frozen as vectors/{suite}.json"
            ));
        }
    }
    if !problems.is_empty() {
        bail!("vectors: {}", problems.join("; "));
    }
    if !open.is_empty() {
        bail!(
            "vectors: cross-check open, no reference file for: {} (vectors/ref/ is written by the ref/ session)",
            open.join(", ")
        );
    }
    say(&format!(
        "vectors: {} suites identical to vectors/ref (structural, SCHEMA §1; positive rows of {})",
        expect::VECTOR_SUITES.len(),
        expect::VECTOR_POSITIVE_ONLY.join(", ")
    ));
    Ok(())
}

/// ADR-026 as amended 2026-09-29 (M2 review F8): the frozen `vectors/<suite>.json` is a verbatim copy of
/// `vectors/ref/<suite>.json`. `None` if the two are byte-identical, else where they first differ.
pub(crate) fn byte_difference(frozen: &[u8], reference: &[u8]) -> Option<String> {
    if frozen == reference {
        return None;
    }
    let at = frozen
        .iter()
        .zip(reference)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| frozen.len().min(reference.len()));
    Some(format!(
        "not a verbatim copy of the reference file (ADR-026): first difference at byte {at} ({} vs {} bytes)",
        frozen.len(),
        reference.len()
    ))
}

/// One frozen suite against its reference file (step 12a): the frozen file validates (SCHEMA §1), equals the
/// reference structurally, and is byte-identical to it (M2 review F8). Returns the number of cases.
pub(crate) fn check_frozen_suite(suite: &str, frozen: &[u8], reference: &[u8]) -> Result<usize> {
    let parse_bytes = |what: &str, bytes: &[u8]| -> Result<Value> {
        serde_json::from_slice(bytes).map_err(|e| Error(format!("{suite} ({what}): {e}")))
    };
    let (frozen_doc, reference_doc) = (
        parse_bytes("frozen", frozen)?,
        parse_bytes("ref", reference)?,
    );
    let bad: Vec<String> = hex_violations(&frozen_doc)
        .into_iter()
        .chain(differences(&frozen_doc, &reference_doc))
        .chain(byte_difference(frozen, reference))
        .collect();
    if !bad.is_empty() {
        bail!("{suite}: {}", bad.join("; "));
    }
    Ok(frozen_doc
        .get("cases")
        .and_then(Value::as_array)
        .map_or(0, Vec::len))
}

/// ci-full step 12a: every frozen file equals its reference file structurally and byte for byte, both validate,
/// and exactly the expected suites exist in both directories; the reference files pending freeze
/// (`expect::VECTOR_REF_PENDING`) are checked for shape only.
pub(crate) fn check_frozen_against_ref(root: &Path) -> Result<String> {
    if let Some(both) = expect::VECTOR_REF_PENDING
        .iter()
        .find(|p| expect::VECTOR_SUITES.contains(p))
    {
        bail!("suite {both} is listed as frozen and as pending freeze");
    }
    let with_pending: Vec<&str> = expect::VECTOR_SUITES
        .iter()
        .chain(expect::VECTOR_REF_PENDING)
        .copied()
        .collect();
    for (dir, expected) in [
        ("vectors", expect::VECTOR_SUITES),
        ("vectors/ref", with_pending.as_slice()),
    ] {
        let found: std::collections::BTreeSet<String> = std::fs::read_dir(root.join(dir))?
            .filter_map(std::result::Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".json").map(str::to_owned)
            })
            .collect();
        crate::gates::same_set(&format!("{dir}/*.json"), &found, expected)?;
    }
    let mut pending = Vec::new();
    for suite in expect::VECTOR_REF_PENDING {
        let reference = parse(
            &root
                .join("vectors")
                .join("ref")
                .join(format!("{suite}.json")),
        )?;
        pending.push(format!(
            "{suite} ({} cases, reference only)",
            pending_cases(suite, &reference)?
        ));
    }
    let mut cases = 0_usize;
    for suite in expect::VECTOR_SUITES {
        let read = |path: std::path::PathBuf| {
            std::fs::read(&path).map_err(|e| Error(format!("{}: {e}", path.display())))
        };
        let frozen = read(root.join("vectors").join(format!("{suite}.json")))?;
        let reference = read(
            root.join("vectors")
                .join("ref")
                .join(format!("{suite}.json")),
        )?;
        cases = cases.saturating_add(check_frozen_suite(suite, &frozen, &reference)?);
    }
    Ok(format!(
        "{} frozen suites ({cases} cases) structurally and byte-identical to vectors/ref (ADR-026); pending freeze \
         (shape only): {}",
        expect::VECTOR_SUITES.len(),
        if pending.is_empty() {
            "none".to_owned()
        } else {
            pending.join(", ")
        }
    ))
}

/// The number of cases of a reference file pending freeze, after checking that it names `suite` and has cases.
fn pending_cases(suite: &str, reference: &Value) -> Result<usize> {
    if reference.get("suite").and_then(Value::as_str) != Some(suite) {
        bail!("vectors/ref/{suite}.json: `suite` is not {suite:?}");
    }
    match reference.get("cases").and_then(Value::as_array) {
        Some(cases) if !cases.is_empty() => Ok(cases.len()),
        _ => bail!("vectors/ref/{suite}.json: no cases"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(s: &str) -> Value {
        serde_json::from_str(s).unwrap_or(Value::Null)
    }

    #[test]
    fn structural_comparison_ignores_generator_only() {
        let rust = doc(
            r#"{"schema":2,"generator":"secmp-rust","cases":[{"id":"x-0001","inputs":{"k":"00"}}]}"#,
        );
        let reference = doc(
            r#"{"generator":"ref-python","schema":2,"cases":[{"id":"x-0001","inputs":{"k":"00"}}]}"#,
        );
        assert!(differences(&rust, &reference).is_empty());
        let changed = doc(r#"{"schema":2,"cases":[{"id":"x-0001","inputs":{"k":"01"}}]}"#);
        let found = differences(&rust, &changed);
        assert_eq!(found.len(), 1);
        assert!(
            found
                .first()
                .is_some_and(|l| l.contains("[x-0001]/inputs/k")),
            "{found:?}"
        );
        let empty = doc(r#"{"schema":2,"cases":[]}"#);
        assert!(!differences(&rust, &empty).is_empty());
        // no case folding: labels are compared exactly
        let upper = doc(r#"{"cases":[{"label":"SecMP-TR/1 rk"}]}"#);
        let lower = doc(r#"{"cases":[{"label":"secmp-tr/1 rk"}]}"#);
        assert!(!differences(&upper, &lower).is_empty());
    }

    #[test]
    fn hex_validator() {
        let ok = doc(
            r#"{"cases":[{"id":"a","op":"seal","inputs":{"k":"00ff","label":"SecMP-X","len":3},"outputs":{"safety_number":"0123"}}]}"#,
        );
        assert!(hex_violations(&ok).is_empty());
        let bad = doc(r#"{"cases":[{"id":"a","inputs":{"k":"00FF"},"outputs":{"c":"0"}}]}"#);
        assert_eq!(hex_violations(&bad).len(), 2);
    }

    #[test]
    fn positive_view_keeps_the_header_and_the_positive_rows() {
        let reference = doc(
            r#"{"schema":3,"suite":"encodings","cases":[{"id":"enc-0001","op":"encode","inputs":{}},
            {"id":"enc-0002","op":"decode","expect":"reject","inputs":{}}]}"#,
        );
        let (view, problems) = positive_view(&reference);
        assert!(problems.is_empty(), "{problems:?}");
        let rust = doc(
            r#"{"schema":3,"suite":"encodings","cases":[{"id":"enc-0001","op":"encode","inputs":{}}]}"#,
        );
        assert!(differences(&rust, &view).is_empty());
        // a row that is neither positive nor a rejecting decode row is a problem
        let odd = doc(r#"{"cases":[{"id":"enc-0003","op":"decode","inputs":{}}]}"#);
        assert_eq!(positive_view(&odd).1.len(), 1);
        // the header is still compared
        let other = doc(
            r#"{"schema":2,"suite":"encodings","cases":[{"id":"enc-0001","op":"encode","inputs":{}}]}"#,
        );
        assert!(!differences(&other, &view).is_empty());
    }

    #[test]
    fn pending_reference_files_must_name_their_suite_and_have_cases() {
        let ok = doc(r#"{"suite":"encodings","cases":[{"id":"enc-0001"},{"id":"enc-0002"}]}"#);
        assert_eq!(pending_cases("encodings", &ok).ok(), Some(2));
        let other = doc(r#"{"suite":"sas","cases":[{"id":"sas-0001"}]}"#);
        assert!(pending_cases("encodings", &other).is_err());
        let empty = doc(r#"{"suite":"encodings","cases":[]}"#);
        assert!(pending_cases("encodings", &empty).is_err());
        let missing = doc(r#"{"suite":"encodings"}"#);
        assert!(pending_cases("encodings", &missing).is_err());
    }

    /// M2 review F8: step 12a refuses a frozen file that is structurally equal to its reference file but not a
    /// verbatim copy of it (key order, whitespace, one byte); the structural comparison alone accepts each fixture,
    /// so it is the byte check that refuses them.
    #[test]
    fn step_12a_refuses_a_frozen_file_that_is_not_a_verbatim_copy() -> Result<()> {
        let reference =
            br#"{"schema":2,"suite":"x","cases":[{"id":"x-0001","inputs":{"k":"00","n":1}}]}
"#;
        assert_eq!(check_frozen_suite("x", reference, reference)?, 1);
        let reordered =
            br#"{"suite":"x","schema":2,"cases":[{"id":"x-0001","inputs":{"n":1,"k":"00"}}]}
"#;
        let spaced =
            br#"{"schema": 2,"suite":"x","cases":[{"id":"x-0001","inputs":{"k":"00","n":1}}]}
"#;
        let no_newline = reference.strip_suffix(b"\n").unwrap_or_default();
        let crlf = [no_newline, b"\r\n".as_slice()].concat();
        for (what, frozen) in [
            ("key order", reordered.as_slice()),
            ("whitespace", spaced.as_slice()),
            ("final newline", no_newline),
            ("one byte (LF -> CR LF)", crlf.as_slice()),
        ] {
            let (a, b): (Value, Value) = (
                serde_json::from_slice(frozen).map_err(|e| Error(e.to_string()))?,
                serde_json::from_slice(reference).map_err(|e| Error(e.to_string()))?,
            );
            assert!(differences(&a, &b).is_empty(), "{what}: structurally equal");
            let refused = check_frozen_suite("x", frozen, reference);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|e| e.0.contains("not a verbatim copy")),
                "{what}: {:?}",
                refused.map_err(|e| e.0)
            );
        }
        assert_eq!(
            byte_difference(b"abcd", b"abXd").as_deref(),
            Some(
                "not a verbatim copy of the reference file (ADR-026): first difference at byte 2 (4 vs 4 bytes)"
            )
        );
        assert!(
            byte_difference(b"abc", b"abcd")
                .is_some_and(|d| d.contains("at byte 3 (3 vs 4 bytes)"))
        );
        // a structural difference is still reported first, with the byte difference
        let changed =
            br#"{"schema":2,"suite":"x","cases":[{"id":"x-0001","inputs":{"k":"01","n":1}}]}
"#;
        assert!(
            check_frozen_suite("x", changed, reference)
                .is_err_and(|e| e.0.contains("[x-0001]/inputs/k") && e.0.contains("at byte 64"))
        );
        Ok(())
    }

    /// X-01 `vectors_step_12a_covers_twelve_suites` (TEST-SPEC-M5): step 12a compares the 12 frozen suites, `link`
    /// among them, nothing is pending freeze, and `link`'s frozen file is checked against its reference file (86
    /// cases, structurally and byte for byte) as part of the step's count.
    #[test]
    fn vectors_step_12a_covers_twelve_suites() -> Result<()> {
        assert_eq!(
            expect::VECTOR_SUITES.len(),
            12,
            "{:?}",
            expect::VECTOR_SUITES
        );
        assert!(expect::VECTOR_SUITES.contains(&"link"));
        assert!(
            expect::VECTOR_REF_PENDING.is_empty(),
            "{:?}",
            expect::VECTOR_REF_PENDING
        );
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let vectors = root.join("vectors");
        let (frozen, reference) = (
            std::fs::read(vectors.join("link.json"))?,
            std::fs::read(vectors.join("ref").join("link.json"))?,
        );
        assert_eq!(check_frozen_suite("link", &frozen, &reference)?, 86);
        // the step's total is the sum over the 12 suites, `link`'s 86 cases included
        let mut total = 0_usize;
        for suite in expect::VECTOR_SUITES {
            let doc = parse(&vectors.join(format!("{suite}.json")))?;
            total = total.saturating_add(
                doc.get("cases")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
            );
        }
        let summary = check_frozen_against_ref(&root)?;
        assert!(
            summary.starts_with(&format!("12 frozen suites ({total} cases)")),
            "{summary}"
        );
        assert!(
            summary.ends_with("pending freeze (shape only): none"),
            "{summary}"
        );
        Ok(())
    }

    #[test]
    fn the_committed_vector_files_match_the_expected_sets() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let summary = check_frozen_against_ref(&root);
        assert!(summary.is_ok(), "{summary:?}");
    }
}
