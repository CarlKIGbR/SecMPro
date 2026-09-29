// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes the Rust side of the `encodings` vectors (`vectors/SCHEMA.md` §4.8: the positive rows 1–85) as
//! `<dir>/encodings.json` in the canonical form of SCHEMA §1. Run by `cargo xtask vectors` with
//! `<dir> = vectors/rust` (gitignored). Every decodable row is checked before writing: `decode(bytes)` gives the
//! listed value and re-encodes to the listed bytes. Exit status: failure if a row fails that check or the file
//! cannot be written.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::Value;

#[path = "../tests/common/encodings.rs"]
mod encodings;

/// `decode(bytes) = value` and `encode(decode(bytes)) = bytes` for a positive row (true for the encode-only
/// `Signed/*` rows, which have no decoder).
fn field<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a str> {
    v.and_then(|v| v.get(k)).and_then(Value::as_str)
}

fn round_trips(case: &Value) -> bool {
    let inputs = case.get("inputs");
    let (Some(structure), Some(bytes)) = (
        field(inputs, "structure"),
        field(case.get("outputs"), "bytes"),
    ) else {
        return false;
    };
    let Some(bytes) = unhex(bytes) else {
        return false;
    };
    match encodings::decode(structure, field(inputs, "context"), &bytes) {
        None => structure.starts_with("Signed/"),
        Some(Ok(d)) => {
            Some(&d.value) == inputs.and_then(|v| v.get("value")) && d.again.ok() == Some(bytes)
        }
        Some(Err(_)) => false,
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

fn main() -> ExitCode {
    let dir = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/rust"),
        PathBuf::from,
    );
    let doc = encodings::generate();
    let cases = doc.get("cases").and_then(Value::as_array);
    if !cases.is_some_and(|c| c.iter().all(round_trips)) {
        return ExitCode::FAILURE;
    }
    if std::fs::create_dir_all(&dir).is_err() {
        return ExitCode::FAILURE;
    }
    let path = dir.join(format!("{}.json", encodings::SUITE));
    if std::fs::write(path, encodings::canonical(&doc)).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
