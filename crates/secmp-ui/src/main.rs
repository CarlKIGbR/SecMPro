// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-ui` — the desktop user interface binary: the window, `--probe` (the spike's checks) and `--version`.
//!
//! The Tor/direct choice is not made here: the application connects over Tor; direct mode is a setting of a later unit and
//! never the default (CLAUDE.md §1.5).
#![deny(unsafe_code)]

use std::io::Write as _;
use std::process::ExitCode;

use secmp_ui::{app, probe};

/// The package name and version, as the M0 skeleton printed them.
fn banner() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            let banner = format!("{} (M0 skeleton: no functionality)", banner());
            match writeln!(std::io::stdout().lock(), "{banner}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Some("--probe") => probe::run(),
        _ => app::run(&app::profile_root(), false),
    }
}
