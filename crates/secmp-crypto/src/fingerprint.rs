// SPDX-License-Identifier: AGPL-3.0-or-later
//! Identity fingerprints (spec §6.2): `fingerprint(iks) = SHA-256("SecMP-FP/1" ‖ encode(iks))` over the
//! 2017-byte encoded `IKSPublic { ver = 0x01, ik_ed25519[32], ik_mldsa65[1952], ik_dh[32] }`. The encoder and
//! decoder of `IKSPublic` belong to `secmp-proto` (M2); this module hashes the encoded bytes.

use core::fmt;

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::hash::sha256;
use crate::label::Label;

/// Length of an encoded `IKSPublic`.
pub const IKS_PUBLIC_LEN: usize = 2017;
/// Length of a fingerprint.
pub const FINGERPRINT_LEN: usize = 32;

/// The fingerprint of an identity key set. Compared in constant time; never printed.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    /// `SHA-256("SecMP-FP/1" ‖ encoded_iks)`.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `encoded_iks` is exactly 2017 bytes.
    pub fn of_encoded_iks(encoded_iks: &[u8]) -> Result<Self> {
        if encoded_iks.len() != IKS_PUBLIC_LEN {
            return Err(Error::Rejected);
        }
        Ok(Self(sha256(&[Label::Fp.as_bytes(), encoded_iks])))
    }

    /// A fingerprint received or stored as 32 bytes (e.g. `inviter_fp`).
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Rejected)?))
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Fingerprint {}

impl fmt::Debug for Fingerprint {
    /// Redacted: fingerprints never reach logs (docs/04 CS-2.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fingerprint(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_and_lengths() -> Result<()> {
        let iks = [0x01_u8; IKS_PUBLIC_LEN];
        let fp = Fingerprint::of_encoded_iks(&iks)?;
        assert_eq!(fp.as_bytes(), &sha256(&[b"SecMP-FP/1", &iks]));
        assert_eq!(Fingerprint::from_bytes(fp.as_bytes())?, fp);
        assert_ne!(Fingerprint::of_encoded_iks(&[0x02; IKS_PUBLIC_LEN])?, fp);
        assert_eq!(
            Fingerprint::of_encoded_iks(&[0; 2016]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            Fingerprint::from_bytes(&[0; 31]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(format!("{fp:?}"), "Fingerprint(..)");
        Ok(())
    }
}
