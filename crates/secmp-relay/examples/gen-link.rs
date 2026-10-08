// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes the Rust side of the `link` vectors (`vectors/SCHEMA.md` §4.11, `vectors/SCHEMA-4.11-link.md`: the
//! SecMP-LINK handshake and the SecMP-Q commands on one link, 86 cases) as `<dir>/link.json` in the canonical form of
//! SCHEMA §1. Run by `cargo xtask vectors` with `<dir> = vectors/rust` (gitignored). Needs feature `kat` (the
//! derandomised entry points, the stores' snapshot and the SCHEMA §2 streams). The generator reads no vector file; a
//! failed check aborts the example. Exit status: failure if the file cannot be written.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../tests/common/link_gen.rs"]
mod link_gen;

fn main() -> ExitCode {
    let dir = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/rust"),
        PathBuf::from,
    );
    let doc = link_gen::generate();
    if std::fs::create_dir_all(&dir).is_err() {
        return ExitCode::FAILURE;
    }
    let path = dir.join(format!("{}.json", link_gen::SUITE));
    if std::fs::write(path, link_gen::canonical(&doc)).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
