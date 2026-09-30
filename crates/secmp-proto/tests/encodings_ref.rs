// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The decoders and the Rust vector generator against the `encodings` vector file (`vectors/SCHEMA.md` §4.8,
//! `SCHEMA-4.8-encodings.md`):
//!
//! - every positive row decodes to exactly its `value` and re-encodes to exactly its bytes (a frame to the named
//!   command, whose name is part of the value); the D.6 rows (`Signed/*`) are encode-only;
//! - every negative row is rejected by the decoder itself with the crate's single error;
//! - the Rust generator (`tests/common/encodings.rs`, also run by `cargo xtask vectors`) reproduces every positive
//!   row, on every target.
//!
//! Reads the frozen `vectors/encodings.json` (ADR-026: a verbatim copy of the reference file), and the reference
//! file `vectors/ref/encodings.json` while the suite is not frozen yet.

#[path = "common/encodings.rs"]
mod encodings;

use serde_json::Value;

use secmp_proto::Error;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// `v[key]`, which must exist.
fn at<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).expect(key)
}

/// `v[key]` as a string, which must exist.
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    at(v, key).as_str().expect(key)
}

fn vector_file() -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("encodings.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("encodings.json")
    };
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_row_of_the_encodings_file() {
    let doc = vector_file();
    assert_eq!(text(&doc, "suite"), encodings::SUITE);
    let cases = at(&doc, "cases").as_array().unwrap();
    let (mut positives, mut signed, mut negatives) = (0_usize, 0_usize, 0_usize);
    for case in cases {
        let id = text(case, "id");
        let inputs = at(case, "inputs");
        let structure = text(inputs, "structure");
        let context = inputs.get("context").and_then(Value::as_str);
        let op = text(case, "op");
        assert!(op == "encode" || op == "decode", "{id}: op {op}");
        if op == "encode" {
            if structure.starts_with("Signed/") {
                assert!(encodings::decode(structure, context, &[]).is_none());
                signed = signed.saturating_add(1);
                continue;
            }
            let bytes = unhex(text(at(case, "outputs"), "bytes"));
            let decoded = encodings::decode(structure, context, &bytes)
                .expect("a decoder for every structure")
                .map_err(|e| format!("{id} {structure}: decode: {e}"))
                .unwrap();
            assert_eq!(
                &decoded.value,
                at(inputs, "value"),
                "{id} {structure}: decodes to exactly its value"
            );
            assert_eq!(
                decoded.again.ok(),
                Some(bytes),
                "{id} {structure}: re-encodes to exactly its bytes"
            );
            positives = positives.saturating_add(1);
        } else {
            assert_eq!(text(case, "expect"), "reject", "{id}");
            let bytes = unhex(text(inputs, "bytes"));
            let verdict = encodings::decode(structure, context, &bytes)
                .expect("a decoder for every structure");
            // the decoder itself must reject (not merely the re-encoding)
            assert_eq!(
                verdict.err(),
                Some(Error::Rejected),
                "{id} {structure} must be rejected by the decoder"
            );
            negatives = negatives.saturating_add(1);
        }
    }
    assert_eq!(
        (positives, signed, negatives),
        (78, 7, 547),
        "rows: decodable positives, encode-only positives, negatives"
    );
}

#[test]
fn the_rust_generator_reproduces_every_positive_row() {
    let file = vector_file();
    let ours = encodings::generate();
    for key in ["schema", "suite", "spec"] {
        assert_eq!(ours.get(key), file.get(key), "header {key}");
    }
    let listed: Vec<&Value> = at(&file, "cases")
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c.get("op").and_then(Value::as_str) == Some("encode"))
        .collect();
    let generated = at(&ours, "cases").as_array().unwrap();
    assert_eq!(generated.len(), listed.len(), "positive rows");
    for (g, l) in generated.iter().zip(listed) {
        assert_eq!(g, l, "case {}", text(l, "id"));
    }
}

#[test]
fn canonical_writer_is_stable() {
    // the Rust writer produces the canonical form of SCHEMA §1 (sorted keys, compact, ASCII, no newline)
    let doc = encodings::generate();
    let text = encodings::canonical(&doc);
    assert!(!text.ends_with('\n') && !text.contains(": ") && !text.contains(", "));
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), doc);
    assert_eq!(encodings::hex(&[0x0a, 0xff]), "0aff");
    assert_eq!(
        at(&doc, "cases").as_array().map(Vec::len),
        usize::try_from(encodings::POSITIVES).ok()
    );
}
