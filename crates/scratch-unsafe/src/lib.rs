// SPDX-License-Identifier: AGPL-3.0-or-later
//! M0 negative demonstration (removed after the run): `unsafe` outside `secmp-sys-*` must fail CI
//! (workspace `unsafe_code = "deny"` and the `forbid(unsafe_code)` grep).

/// Returns the first byte of `data` without a bounds check.
///
/// # Safety
/// `data` must not be empty.
#[must_use]
pub unsafe fn first_unchecked(data: &[u8]) -> u8 {
    // SAFETY: the caller guarantees that `data` is not empty.
    unsafe { *data.get_unchecked(0) }
}
