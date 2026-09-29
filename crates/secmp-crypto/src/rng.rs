// SPDX-License-Identifier: AGPL-3.0-or-later
//! The only randomness source: the operating system CSPRNG via `getrandom` (spec §3, CLAUDE.md §4).

use crate::error::{Error, Result};

/// Fill `buf` from the operating system CSPRNG.
///
/// # Errors
/// [`Error::Unavailable`] if the operating system cannot provide randomness.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() -> Result<()> {
        let (mut a, mut b) = ([0_u8; 32], [0_u8; 32]);
        fill(&mut a)?;
        fill(&mut b)?;
        // 2^-256 false-failure probability
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
        fill(&mut [])?;
        Ok(())
    }
}
