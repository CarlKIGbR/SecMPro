// SPDX-License-Identifier: AGPL-3.0-or-later
//! The single error type of `secmp-crypto` (docs/06 §2: one uniform error type per crate).

use core::fmt;

/// Why an operation of this crate failed.
///
/// Every failure caused by *input* — a wrong length, an invalid key, a failed MAC, tag, commitment or
/// signature, an all-zero Diffie-Hellman output, a refused label — is the one indistinguishable value
/// [`Error::Rejected`]: callers and attackers learn only *that* an input was rejected, never *why* (CLAUDE.md §4).
/// [`Error::Unavailable`] means the local environment could not provide a resource (the OS random number
/// generator or locked memory); it never depends on input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input was rejected (uniform for every input-dependent failure).
    Rejected,
    /// The operating system could not provide randomness or protected memory.
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "secmp-crypto: input rejected",
            Self::Unavailable => "secmp-crypto: randomness or protected memory unavailable",
        })
    }
}

impl std::error::Error for Error {}

impl From<secmp_sys_mem::Error> for Error {
    fn from(_: secmp_sys_mem::Error) -> Self {
        Self::Unavailable
    }
}

/// Shorthand used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_carries_no_detail() {
        assert_eq!(Error::Rejected.to_string(), "secmp-crypto: input rejected");
        assert_eq!(
            Error::Unavailable.to_string(),
            "secmp-crypto: randomness or protected memory unavailable"
        );
        let e: &dyn std::error::Error = &Error::Rejected;
        assert!(e.source().is_none());
    }

    #[test]
    fn locked_memory_failure_maps_to_unavailable() {
        // 2 MiB never fits in one page, so allocation fails on every platform.
        let e = secmp_sys_mem::SecretPage::<{ 1 << 21 }>::new().err();
        assert_eq!(e.map(Error::from), Some(Error::Unavailable));
    }
}
