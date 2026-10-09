// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Rust generator of the `link` suite (`tests/common/link_gen.rs`, also run by `cargo xtask vectors` through the
//! `gen-link` example) against the reference file `vectors/ref/link.json` (TEST-SPEC-M5 V-22): every case, the file
//! as a whole (SCHEMA §1: `generator` removed) and the canonical bytes. Once the suite is frozen, the frozen
//! `vectors/link.json` must be a verbatim copy of the reference file (ADR-026), as step 12a checks.

use serde_json::Value;

#[path = "../common/link_gen.rs"]
mod link_gen;

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn reference_file() -> (Value, String) {
    let text = std::fs::read_to_string(root().join("ref").join("link.json")).unwrap();
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

/// V-22 `link_generator_reproduces_ref_file`: the generator writes the 86 cases of `vectors/link.json`; they equal
/// `vectors/ref/link.json` case by case, as a whole without `generator` (the comparison of step 12a), and in their
/// canonical bytes with the reference file's `generator`.
#[test]
fn link_generator_reproduces_ref_file() {
    let (file, text) = reference_file();
    let ours = link_gen::generate();
    for key in ["schema", "suite", "spec"] {
        assert_eq!(ours.get(key), file.get(key), "header {key}");
    }
    assert_eq!(
        ours.get("generator").and_then(Value::as_str),
        Some("secmp-rust"),
        "generator"
    );
    let (generated, listed) = (cases(&ours), cases(&file));
    assert_eq!(generated.len(), 86, "86 cases");
    assert_eq!(generated.len(), listed.len(), "cases");
    for (g, l) in generated.iter().zip(listed) {
        assert!(
            g == l,
            "case {} differs",
            l.get("id").and_then(Value::as_str).unwrap_or("?")
        );
    }
    assert!(
        without_generator(&ours) == without_generator(&file),
        "the file without generator"
    );
    let mut same_generator = ours;
    same_generator.as_object_mut().unwrap().insert(
        "generator".to_owned(),
        file.get("generator").unwrap().clone(),
    );
    assert!(
        link_gen::canonical(&same_generator) == text,
        "canonical bytes differ from the reference file"
    );
    let frozen = root().join("link.json");
    if frozen.exists() {
        assert!(
            std::fs::read(frozen).unwrap() == text.as_bytes(),
            "vectors/link.json is a verbatim copy of vectors/ref/link.json"
        );
    }
}
