// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes the Rust side of the `tr` vectors (`vectors/SCHEMA.md` §4.9, `vectors/SCHEMA-4.9-tr.md`: the 96 events of
//! the SecMP-TR transcript) as `<dir>/tr.json` in the canonical form of SCHEMA §1. Run by `cargo xtask vectors` with
//! `<dir> = vectors/rust` (gitignored). Needs feature `kat` (the derandomised ratchet entry points and the SCHEMA §2
//! streams). The generator reads no vector file and checks every SCHEMA-4.9 obligation while it runs; a failed check
//! aborts the example. Exit status: failure if the file cannot be written.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../tests/common/tr.rs"]
mod tr;

fn main() -> ExitCode {
    let dir = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/rust"),
        PathBuf::from,
    );
    let doc = tr::generate();
    if std::fs::create_dir_all(&dir).is_err() {
        return ExitCode::FAILURE;
    }
    let path = dir.join(format!("{}.json", tr::SUITE));
    if std::fs::write(path, tr::canonical(&doc)).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
