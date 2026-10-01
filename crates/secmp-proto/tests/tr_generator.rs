// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The Rust generator of the `tr` suite (`tests/common/tr.rs`, also run by `cargo xtask vectors` through the `gen-tr`
//! example) against the vector file (`vectors/SCHEMA.md` §4.9, `vectors/SCHEMA-4.9-tr.md`): every case, the file as
//! a whole (SCHEMA §1: `generator` removed), and the canonical bytes, on every target.
//!
//! Reads the frozen `vectors/tr.json` (ADR-026: a verbatim copy of the reference file), and the reference file
//! `vectors/ref/tr.json` while the suite is not frozen yet.

#[path = "common/tr.rs"]
mod tr;

use serde_json::Value;

fn vector_file() -> (Value, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("tr.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("tr.json")
    };
    let text = std::fs::read_to_string(path).unwrap();
    (serde_json::from_str(&text).unwrap(), text)
}

fn cases(doc: &Value) -> &Vec<Value> {
    doc.get("cases").and_then(Value::as_array).expect("cases")
}

fn without_generator(doc: &Value) -> Value {
    let mut doc = doc.clone();
    doc.as_object_mut().unwrap().remove("generator");
    doc
}

#[test]
fn the_rust_generator_reproduces_the_tr_file() {
    let (file, text) = vector_file();
    let ours = tr::generate();
    for key in ["schema", "suite", "spec"] {
        assert_eq!(ours.get(key), file.get(key), "header {key}");
    }
    assert_eq!(
        ours.get("generator").and_then(Value::as_str),
        Some("secmp-rust")
    );
    let (generated, listed) = (cases(&ours), cases(&file));
    assert_eq!(generated.len(), 96, "one case per event");
    assert_eq!(generated.len(), listed.len(), "cases");
    for (g, l) in generated.iter().zip(listed) {
        assert_eq!(
            g,
            l,
            "case {}",
            l.get("id").and_then(Value::as_str).unwrap_or("?")
        );
    }
    // the whole file (SCHEMA §1: structural, `generator` removed)
    assert_eq!(without_generator(&ours), without_generator(&file));
    // and byte for byte: the canonical writer with the file's `generator` reproduces the file
    let mut same_generator = ours;
    same_generator.as_object_mut().unwrap().insert(
        "generator".to_owned(),
        file.get("generator").unwrap().clone(),
    );
    assert!(
        tr::canonical(&same_generator) == text,
        "canonical bytes differ from the vector file"
    );
}
