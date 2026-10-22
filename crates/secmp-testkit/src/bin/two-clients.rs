// SPDX-License-Identifier: AGPL-3.0-or-later
//! `two-clients`: see `secmp_testkit::two_clients`. A test tool; it is not shipped (`required-features = ["harness"]`,
//! not in `expect::BINARIES`, not in the release SBOM).
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    ExitCode::from(secmp_testkit::two_clients::main_with(
        &args, &mut out, &mut err,
    ))
}
