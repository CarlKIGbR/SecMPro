// SPDX-License-Identifier: AGPL-3.0-or-later
//! M0 negative demonstration (removed after the run): `unwrap()` must fail CI (`clippy::unwrap_used = "deny"`).
#![forbid(unsafe_code)]

/// Returns the first byte of `data`.
///
/// # Panics
/// Panics if `data` is empty.
#[must_use]
pub fn first(data: &[u8]) -> u8 {
    data.first().copied().unwrap()
}
