// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Rust generator of the `hx` suite (`tests/common/hx_gen.rs`, also run by `cargo xtask vectors` through the
//! `gen-hx` example) against the vector file (`vectors/SCHEMA.md` §4.10, `vectors/SCHEMA-4.10-hx.md`): every case,
//! the file as a whole (SCHEMA §1: `generator` removed) and the canonical bytes, on every target.
//!
//! Reads the frozen `vectors/hx.json` (ADR-026: a verbatim copy of the reference file), and the reference file
//! `vectors/ref/hx.json` while the suite is not frozen yet.

use crate::hx_gen as hx;

use serde_json::Value;

fn vector_file() -> (Value, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("hx.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("hx.json")
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
fn the_rust_generator_reproduces_the_hx_file() {
    let (file, text) = vector_file();
    let ours = hx::generate();
    for key in ["schema", "suite", "spec"] {
        assert_eq!(ours.get(key), file.get(key), "header {key}");
    }
    assert_eq!(
        ours.get("generator").and_then(Value::as_str),
        Some("secmp-rust")
    );
    let (generated, listed) = (cases(&ours), cases(&file));
    assert_eq!(generated.len(), 30, "one case per step");
    assert_eq!(generated.len(), listed.len(), "cases");
    for (g, l) in generated.iter().zip(listed) {
        assert_eq!(
            g,
            l,
            "case {}",
            l.get("id").and_then(Value::as_str).unwrap_or("?")
        );
    }
    assert_eq!(without_generator(&ours), without_generator(&file));
    let mut same_generator = ours;
    same_generator.as_object_mut().unwrap().insert(
        "generator".to_owned(),
        file.get("generator").unwrap().clone(),
    );
    assert!(
        hx::canonical(&same_generator) == text,
        "canonical bytes differ from the vector file"
    );
}
