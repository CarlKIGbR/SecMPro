// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes the Rust side of the `hx` vectors (`vectors/SCHEMA.md` §4.10, `vectors/SCHEMA-4.10-hx.md`: the SecMP-INV/HX
//! full run, 30 cases) as `<dir>/hx.json` in the canonical form of SCHEMA §1. Run by `cargo xtask vectors` with
//! `<dir> = vectors/rust` (gitignored). Needs feature `kat` (the derandomised ratchet entry points and the SCHEMA §2
//! streams). The generator reads no vector file; a failed check aborts the example. Exit status: failure if the
//! file cannot be written.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../tests/common/hx_gen.rs"]
mod hx;

fn main() -> ExitCode {
    let dir = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/rust"),
        PathBuf::from,
    );
    let doc = hx::generate();
    if std::fs::create_dir_all(&dir).is_err() {
        return ExitCode::FAILURE;
    }
    let path = dir.join(format!("{}.json", hx::SUITE));
    if std::fs::write(path, hx::canonical(&doc)).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
