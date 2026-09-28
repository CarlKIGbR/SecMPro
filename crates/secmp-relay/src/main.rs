// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-relay` binary entry point; see the library crate documentation for responsibility and
//! allowed dependencies.
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
