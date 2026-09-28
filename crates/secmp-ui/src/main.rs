// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-ui` — the desktop user interface (Slint, winit backend; ADR-013).
//!
//! **Responsibility.** Screens and screen-security behaviours (exclude-from-capture, blur on focus loss,
//! view-once reveal, watermark, clipboard policy, accessibility mode) together with `secmp-sys-desktop`
//! (docs/02 §4.5, docs/04). The UI never touches key material and never receives the store handle; it only
//! receives decrypted view models from the core `Api`.
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-client-core`, `secmp-sys-desktop`; `slint` (the single copyleft
//! licence exception, docs/06 §3), added with an ADR.
//!
//! **Unsafe code.** None. The crate declares `#![deny(unsafe_code)]` instead of `forbid`, because `slint!`
//! expansions carry a generated `allow(unsafe_code)` (E0453 under `forbid`; docs/06 §2 (b), ADR-033). `cargo
//! xtask policy` rejects the keyword and any hand-written relaxation of `unsafe_code` in this crate's sources.
//!
//! **Status.** M0 skeleton — prints its name and version and exits (no window yet; UI starts in M8).
#![deny(unsafe_code)]

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
