// SPDX-License-Identifier: AGPL-3.0-or-later
//! M0 hello-world check for the `secmp-ui` binary: it starts, prints its banner and exits successfully on every
//! target (this is the binary `cargo xtask win-test` runs on Windows).
#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn prints_banner_and_exits_successfully() -> Result<(), String> {
    let out = Command::new(env!("CARGO_BIN_EXE_secmp-ui"))
        .output()
        .map_err(|e| format!("cannot start the binary: {e}"))?;
    if !out.status.success() {
        return Err(format!("unexpected exit status: {}", out.status));
    }
    let stdout = String::from_utf8(out.stdout).map_err(|e| format!("banner is not UTF-8: {e}"))?;
    let expected = concat!("secmp-ui ", env!("CARGO_PKG_VERSION"), " (");
    if !stdout.starts_with(expected) {
        return Err(format!("unexpected banner: {stdout:?}"));
    }
    Ok(())
}
