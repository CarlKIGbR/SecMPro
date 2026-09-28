// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Loaders for known-answer-test files: Wycheproof (`testGroups[].tests[]` with `tcId`, `result`, `flags`),
//! NIST ACVP internal projections (`testGroups[].tests[]` with `tcId`), and the SecMP vector files
//! (`vectors/SCHEMA.md`). Test data is trusted to be well-formed: a malformed file is a test failure, so the
//! accessors panic with the file position instead of returning errors.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The workspace `vectors/` directory.
#[must_use]
pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
}

/// Parse a JSON file below `vectors/`.
///
/// # Panics
/// If the file is missing or not JSON.
#[must_use]
pub fn load(rel: &str) -> Value {
    let path = vectors_dir().join(rel);
    let text = std::fs::read_to_string(&path).expect("vector file readable");
    serde_json::from_str(&text).expect("vector file is JSON")
}

/// Decode lowercase or uppercase hex.
///
/// # Panics
/// On odd length or a non-hex digit.
#[must_use]
#[track_caller]
pub fn hex(s: &str) -> Vec<u8> {
    decode_hex(s).expect("malformed test data: not hex")
}

/// Decode hex; `None` on odd length or a non-hex digit.
#[must_use]
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// Lowercase hex.
#[must_use]
pub fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

/// The string field `key` of `v`.
///
/// # Panics
/// If the field is missing or not a string.
#[must_use]
#[track_caller]
pub fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .expect("malformed test data: missing string field")
}

/// The string field `key` of `v`, if present (and a string).
#[must_use]
pub fn opt_str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// The hex field `key` of `v`, decoded.
///
/// # Panics
/// If the field is missing, not a string or not hex.
#[must_use]
#[track_caller]
pub fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    hex(str_field(v, key))
}

/// The unsigned integer field `key` of `v`.
///
/// # Panics
/// If the field is missing or not an unsigned integer.
#[must_use]
#[track_caller]
pub fn u64_field(v: &Value, key: &str) -> u64 {
    v.get(key)
        .and_then(Value::as_u64)
        .expect("malformed test data: missing integer field")
}

/// The boolean field `key` of `v`.
///
/// # Panics
/// If the field is missing or not a boolean.
#[must_use]
#[track_caller]
pub fn bool_field(v: &Value, key: &str) -> bool {
    v.get(key)
        .and_then(Value::as_bool)
        .expect("malformed test data: missing boolean field")
}

/// A Wycheproof verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// `"valid"`.
    Valid,
    /// `"acceptable"`: an implementation may accept or reject; the test states which.
    Acceptable,
    /// `"invalid"`.
    Invalid,
}

/// One Wycheproof test with its group.
#[derive(Debug)]
pub struct WycheproofCase<'a> {
    /// The enclosing `testGroups[]` entry (keys, parameters).
    pub group: &'a Value,
    /// The `tests[]` entry.
    pub test: &'a Value,
    /// `tcId`.
    pub tc_id: u64,
    /// `result`.
    pub verdict: Verdict,
    /// `flags`.
    pub flags: Vec<&'a str>,
}

impl WycheproofCase<'_> {
    /// Whether the test carries `flag`.
    #[must_use]
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.contains(&flag)
    }
}

/// All tests of a Wycheproof file, in file order.
///
/// # Panics
/// If the document does not have the Wycheproof shape.
#[must_use]
pub fn wycheproof_cases(doc: &Value) -> Vec<WycheproofCase<'_>> {
    let mut out = Vec::new();
    for group in array(doc, "testGroups") {
        for test in array(group, "tests") {
            let verdict = match str_field(test, "result") {
                "valid" => Some(Verdict::Valid),
                "acceptable" => Some(Verdict::Acceptable),
                "invalid" => Some(Verdict::Invalid),
                _ => None,
            }
            .expect("malformed test data: unknown Wycheproof result");
            let flags = test
                .get("flags")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            out.push(WycheproofCase {
                group,
                test,
                tc_id: u64_field(test, "tcId"),
                verdict,
                flags,
            });
        }
    }
    let declared = usize::try_from(u64_field(doc, "numberOfTests")).ok();
    (declared == Some(out.len()))
        .then_some(())
        .expect("malformed test data: numberOfTests does not match the tests found");
    out
}

/// All `(group, test)` pairs of an ACVP internal projection, in file order.
///
/// # Panics
/// If the document does not have the ACVP shape.
#[must_use]
pub fn acvp_cases(doc: &Value) -> Vec<(&Value, &Value)> {
    array(doc, "testGroups")
        .iter()
        .flat_map(|g| array(g, "tests").iter().map(move |t| (g, t)))
        .collect()
}

/// The array field `key` of `v`.
///
/// # Panics
/// If the field is missing or not an array.
#[must_use]
#[track_caller]
pub fn array<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v.get(key)
        .and_then(Value::as_array)
        .expect("malformed test data: missing array field")
}

/// Counts of executed and skipped cases, printed by the KAT tests so that the evidence shows what ran.
#[derive(Debug, Default)]
pub struct Tally {
    /// Cases whose expectation was checked.
    pub checked: usize,
    /// Cases not applicable to the API under test, with the reason.
    pub skipped: Vec<(u64, &'static str)>,
}

impl Tally {
    /// Record a checked case.
    pub fn check(&mut self) {
        self.checked = self.checked.saturating_add(1);
    }

    /// Record a skipped case.
    pub fn skip(&mut self, tc_id: u64, why: &'static str) {
        self.skipped.push((tc_id, why));
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self, what: &str) -> String {
        format!(
            "{what}: {} checked, {} skipped{}",
            self.checked,
            self.skipped.len(),
            self.skipped
                .first()
                .map(|(id, why)| format!(" (e.g. tcId {id}: {why})"))
                .unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_codec() {
        assert_eq!(hex("00ffA0"), vec![0, 255, 160]);
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(to_hex(&[1, 0xab]), "01ab");
        assert!(hex("").is_empty());
    }

    #[test]
    fn wycheproof_shape() {
        let doc: Value = serde_json::from_str(
            r#"{"numberOfTests": 3, "testGroups": [
                {"k": 1, "tests": [{"tcId": 1, "result": "valid", "flags": ["A"], "x": "0a"},
                                   {"tcId": 2, "result": "acceptable"}]},
                {"tests": [{"tcId": 3, "result": "invalid", "flags": []}]}]}"#,
        )
        .unwrap();
        let cases = wycheproof_cases(&doc);
        assert_eq!(cases.len(), 3);
        let first = cases.first().unwrap();
        assert_eq!(first.verdict, Verdict::Valid);
        assert!(first.has_flag("A"));
        assert!(!first.has_flag("B"));
        assert_eq!(hex_field(first.test, "x"), vec![10]);
        assert_eq!(u64_field(first.group, "k"), 1);
        assert_eq!(cases.get(1).map(|c| c.verdict), Some(Verdict::Acceptable));
        assert_eq!(
            cases.get(2).map(|c| (c.tc_id, c.verdict)),
            Some((3, Verdict::Invalid))
        );
    }

    #[test]
    #[should_panic(expected = "malformed test data")]
    fn wrong_count_is_malformed() {
        let doc: Value = serde_json::from_str(
            r#"{"numberOfTests": 2, "testGroups": [{"tests": [{"tcId": 1, "result": "nonsense"}]}]}"#,
        )
        .unwrap();
        let _ = wycheproof_cases(&doc);
    }

    #[test]
    fn acvp_shape_and_fields() {
        let doc: Value = serde_json::from_str(
            r#"{"testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "ok": true, "s": "x"}, {"tcId": 2}]}]}"#,
        )
        .unwrap();
        let cases = acvp_cases(&doc);
        assert_eq!(cases.len(), 2);
        let (g, t) = cases.first().copied().unwrap();
        assert_eq!(u64_field(g, "tgId"), 1);
        assert!(bool_field(t, "ok"));
        assert_eq!(opt_str_field(t, "s"), Some("x"));
        assert_eq!(opt_str_field(t, "nope"), None);
        assert_eq!(str_field(t, "s"), "x");
    }

    #[test]
    fn external_files_are_present() {
        let doc = load("external/wycheproof/x25519_test.json");
        assert!(!wycheproof_cases(&doc).is_empty());
        let doc = load("external/acvp/ML-KEM-keyGen-FIPS203.json");
        assert!(!acvp_cases(&doc).is_empty());
    }

    #[test]
    fn tally_summary() {
        let mut t = Tally::default();
        t.check();
        t.skip(7, "internal interface");
        assert_eq!(
            t.summary("x"),
            "x: 1 checked, 1 skipped (e.g. tcId 7: internal interface)"
        );
    }
}
