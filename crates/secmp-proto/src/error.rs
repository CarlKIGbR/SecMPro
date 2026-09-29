// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one error of `secmp-proto` (docs/06 §2: one uniform error per crate).

use core::fmt;

/// Every malformed, inconsistent or non-canonical input — and every value that has no encoding — is
/// [`Error::Rejected`], with no detail: which rule failed is not observable (CLAUDE.md §4, spec §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input is not exactly one valid encoding (or the value cannot be encoded).
    Rejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rejected")
    }
}

impl std::error::Error for Error {}

impl From<secmp_crypto::Error> for Error {
    /// A key or signature refused by `secmp-crypto` is a malformed field.
    fn from(_: secmp_crypto::Error) -> Self {
        Self::Rejected
    }
}

/// `Result` with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_carries_no_detail() {
        assert_eq!(Error::Rejected.to_string(), "rejected");
        assert_eq!(
            Error::from(secmp_crypto::Error::Unavailable),
            Error::Rejected
        );
        assert_eq!(Error::from(secmp_crypto::Error::Rejected), Error::Rejected);
    }
}
