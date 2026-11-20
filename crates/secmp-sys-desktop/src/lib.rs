// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-sys-desktop` — desktop-only operating-system integration.
//!
//! **Responsibility.** `WDA_EXCLUDEFROMCAPTURE`/`DISPLAY_ONLY`, process DACL and mitigation policies, WER
//! exclusion, Recall input scope, Wayland/compositor probes and exclusion requests, OS keystores (DPAPI/CNG/TPM,
//! Secret Service/TPM2) and clipboard formats (docs/02 §3, docs/04 §1).
//!
//! **Unsafe code.** One of the only two crates that may contain `unsafe` (the other is `secmp-sys-mem`); it
//! carries `#![allow(unsafe_code)]` at the crate root instead of `#![forbid(unsafe_code)]` (docs/06 §2 (a),
//! checked by `cargo xtask policy`). Every `unsafe` block must have a `// SAFETY:` comment
//! (`clippy::undocumented_unsafe_blocks`), do one thing (`clippy::multiple_unsafe_ops_per_block`), and be
//! covered by a unit test and, where feasible, Miri (docs/06 §4).
//!
//! **Allowed dependencies** (docs/02 §3): no workspace crate; platform binding crates added with an ADR. Used only
//! by `secmp-ui`, `secmp-store` and `secmp-client-core` — never by `secmp-relay`.
//!
//! **Status.** M8 U1: Windows display affinity ([`set_exclude_from_capture`], [`display_affinity`]); the rest starts in M9.
#![allow(unsafe_code)]

use core::fmt;

/// The one error of the crate: an operating-system call refused or was given a handle it cannot use. It carries no
/// code, handle or detail (CLAUDE.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("desktop system call failed")
    }
}

impl std::error::Error for Error {}

#[cfg(windows)]
mod display_affinity {
    use core::ffi::c_void;

    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowDisplayAffinity, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
    };

    use super::Error;

    /// The window handle `hwnd` as the pointer the API takes; a zero or negative value is no handle.
    fn handle(hwnd: isize) -> Result<*mut c_void, Error> {
        if hwnd == 0 {
            return Err(Error);
        }
        let addr = usize::try_from(hwnd).map_err(|_| Error)?;
        Ok(core::ptr::with_exposed_provenance_mut::<c_void>(addr))
    }

    /// Exclude the window `hwnd` from screen capture (`WDA_EXCLUDEFROMCAPTURE`, docs/04).
    ///
    /// # Errors
    /// [`Error`] for a null or negative handle and when the call fails.
    pub fn set_exclude_from_capture(hwnd: isize) -> Result<(), Error> {
        let hwnd = handle(hwnd)?;
        // SAFETY: `SetWindowDisplayAffinity` only reads its two by-value arguments; a handle that is not a window of
        // this process makes it return 0, which is reported as the error below.
        let ok = unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) };
        if ok == 0 { Err(Error) } else { Ok(()) }
    }

    /// The display affinity of the window `hwnd` (`0x11` is `WDA_EXCLUDEFROMCAPTURE`).
    ///
    /// # Errors
    /// [`Error`] for a null or negative handle and when the call fails.
    pub fn display_affinity(hwnd: isize) -> Result<u32, Error> {
        let hwnd = handle(hwnd)?;
        let mut affinity: u32 = 0;
        // SAFETY: `affinity` is a live, writable `u32` for the duration of the call, which writes it only on success.
        let ok = unsafe { GetWindowDisplayAffinity(hwnd, &raw mut affinity) };
        if ok == 0 { Err(Error) } else { Ok(affinity) }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// T5: a null window is refused by both functions.
        #[test]
        fn capture_exclusion_rejects_null_window() {
            assert_eq!(set_exclude_from_capture(0), Err(Error));
            assert_eq!(display_affinity(0), Err(Error));
        }
    }
}

#[cfg(windows)]
pub use display_affinity::{display_affinity, set_exclude_from_capture};
