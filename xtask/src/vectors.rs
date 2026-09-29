// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask vectors` and the reference cross-check (docs/06 §5 step 12a, ADR-026, `vectors/SCHEMA.md` §1).
//!
//! 1. The Rust generator (`secmp-crypto` example `gen-vectors`, feature `kat`) writes `vectors/rust/<suite>.json`
//!    (gitignored).
//! 2. Each file is compared **structurally** with the committed reference file `vectors/ref/<suite>.json`
//!    (written by the independent `ref/` session): both are parsed, `generator` is removed, the values must be
//!    equal — no case folding. Every byte-string field must match `^([0-9a-f]{2})*$`.
//! 3. On agreement the reference file is frozen verbatim as `vectors/<suite>.json`. An existing frozen file is
//!    never overwritten: if it differs, the command fails (frozen vectors change only with a spec revision).
//!
//! A mismatch is reported with suite, case id, field and both values; the Rust side is never adjusted to match.

use std::path::Path;

use serde_json::Value;

use crate::expect;
use crate::util::{Cmd, Error, Result, bail, say};

/// Fields whose JSON strings are not byte strings (SCHEMA §1: labels, digit strings, `mode`, `op`, ids).
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

/// `cargo xtask vectors`.
pub(crate) fn run(root: &Path) -> Result<()> {
    let rust_dir = root.join("vectors").join("rust");
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
        "vectors: {} suites identical to vectors/ref (structural, SCHEMA §1)",
        expect::VECTOR_SUITES.len()
    ));
    Ok(())
}

/// ci-full step 12a: every frozen file equals its reference file structurally, both validate, and exactly the
/// expected suites exist in both directories.
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
        let frozen = parse(&root.join("vectors").join(format!("{suite}.json")))?;
        let reference = parse(
            &root
                .join("vectors")
                .join("ref")
                .join(format!("{suite}.json")),
        )?;
        let bad: Vec<String> = hex_violations(&frozen)
            .into_iter()
            .chain(differences(&frozen, &reference))
            .collect();
        if !bad.is_empty() {
            bail!("{suite}: {}", bad.join("; "));
        }
        cases = cases.saturating_add(
            frozen
                .get("cases")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        );
    }
    Ok(format!(
        "{} frozen suites ({cases} cases) structurally identical to vectors/ref (ADR-026); pending freeze: {}",
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

    #[test]
    fn the_committed_vector_files_match_the_expected_sets() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let summary = check_frozen_against_ref(&root);
        assert!(summary.is_ok(), "{summary:?}");
    }
}
