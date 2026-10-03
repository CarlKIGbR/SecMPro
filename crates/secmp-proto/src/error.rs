// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one error of `secmp-proto` (docs/06 §2: one uniform error per crate).

use core::fmt;

/// Every malformed, inconsistent or non-canonical input — and every value that has no encoding — is
/// [`Error::Rejected`], with no detail: which rule failed is not observable (CLAUDE.md §4, spec §4.1).
/// [`Error::Unavailable`] is the one other outcome (M2 review F4, M3 plan D1): the local environment could not
/// provide a resource; it never depends on input.
///
/// No wire decoder produces [`Error::Unavailable`]: the decoders call `secmp-crypto` only for the key and
/// signature checks of spec §4.1 (`X25519Public::from_bytes_checked`, `Ed25519VerifyingKey::from_bytes`,
/// `check_ed25519_signature_encoding`, `MlKem768Ek::from_bytes`, `MlKem1024Ek::from_bytes`) and to hold secret
/// fields (`SecretBytes::from_slice`, heap memory), all of which fail only with `Rejected`; a wire decoder never
/// allocates locked memory and never draws randomness. The `encodings` vector test asserts `Rejected` for every
/// negative row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input is not exactly one valid encoding (or the value cannot be encoded).
    Rejected,
    /// The local environment could not provide OS randomness or locked memory, or a store could not make a commit
    /// durable (`PrekeyStore::commit_accept`, M4 review C-12); never input-dependent; never produced by a wire
    /// decoder; the caller must neither send nor acknowledge — retry later.
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
        })
    }
}

impl std::error::Error for Error {}

impl From<secmp_crypto::Error> for Error {
    /// A key, signature or MAC refused by `secmp-crypto` is a rejected input; a missing resource (OS randomness,
    /// locked memory) stays [`Error::Unavailable`]. Any future kind of `secmp-crypto` (its error is
    /// `#[non_exhaustive]`) fails closed as a rejection.
    fn from(e: secmp_crypto::Error) -> Self {
        match e {
            secmp_crypto::Error::Unavailable => Self::Unavailable,
            _ => Self::Rejected,
        }
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
        assert_eq!(Error::Unavailable.to_string(), "unavailable");
        let e: &dyn std::error::Error = &Error::Unavailable;
        assert!(e.source().is_none());
    }

    /// `Rejected → Rejected`, `Unavailable → Unavailable` (M2 review F4: a missing resource is not a malformed
    /// input, so the caller does not acknowledge a cell it could not process).
    #[test]
    fn crypto_errors_keep_their_kind() {
        assert_eq!(Error::from(secmp_crypto::Error::Rejected), Error::Rejected);
        assert_eq!(
            Error::from(secmp_crypto::Error::Unavailable),
            Error::Unavailable
        );
    }
}
