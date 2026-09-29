// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes the Rust side of the SecMP test vectors (`vectors/SCHEMA.md` rev 2, M1 suites) as
//! `<dir>/<suite>.json` in the canonical form of SCHEMA §1. Run by `cargo xtask vectors` with
//! `<dir> = vectors/rust` (gitignored); requires feature `kat`. Exit status: failure if a file cannot be written
//! or a byte-string field is not lowercase hex.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../tests/common/vectors.rs"]
mod vectors;

fn main() -> ExitCode {
    let dir = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/rust"),
        PathBuf::from,
    );
    if std::fs::create_dir_all(&dir).is_err() {
        return ExitCode::FAILURE;
    }
    for suite in vectors::SUITES {
        let doc = vectors::generate(suite);
        if !vectors::validate(&doc).is_empty() {
            return ExitCode::FAILURE;
        }
        if std::fs::write(dir.join(format!("{suite}.json")), vectors::canonical(&doc)).is_err() {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
