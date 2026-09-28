// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-cli` — the headless, scriptable SecMPro client.
//!
//! **Responsibility.** Profile, invitation, contact, send/tail and status commands with JSON-lines output for
//! integration/E2E tests and operations (M7). Output timestamps are a sanctioned `SystemTime::now` site
//! (docs/06 §2).
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-client-core` (and the crates below it); no key material
//! handling outside the core's API.
//!
//! **Status.** M0 skeleton — prints its name and version and exits (the M0 hello-world binary).
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::ExitCode;

/// M0 hello-world: print the package name and version, nothing else.
fn main() -> ExitCode {
    let banner = concat!(
        env!("CARGO_PKG_NAME"),
        " ",
        env!("CARGO_PKG_VERSION"),
        " (M0 skeleton: no functionality)"
    );
    match writeln!(std::io::stdout().lock(), "{banner}") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
