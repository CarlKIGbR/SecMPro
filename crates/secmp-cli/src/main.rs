// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `secmp-cli` binary: collects the arguments and exits with the code [`secmp_cli::run`] returns.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        // an argument that is not UTF-8 is a usage error, never a panic
        args.push(arg.into_string().unwrap_or_default());
    }
    ExitCode::from(secmp_cli::run(&args))
}
