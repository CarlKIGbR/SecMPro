// SPDX-License-Identifier: AGPL-3.0-or-later
//! The randomness of SecMP-TR (spec §7.2–§7.4): X25519 and ML-KEM-768 key generation, ML-KEM-768 `Encaps` and the
//! header nonce (§7.3 `hdr_nonce = random 24 B`).
//!
//! [`Entropy`] is sealed. A shipped build has exactly one implementation, [`OsEntropy`] (the OS CSPRNG through
//! `secmp-crypto`, CLAUDE.md §4). Feature `kat` (vectors, tests, the constant-time bench; never in a shipped build)
//! adds [`FixedEntropy`], which reads a byte string in the order of `vectors/SCHEMA-4.9-tr.md`: an X25519 secret is
//! 32 raw bytes, an ML-KEM-768 key the 64-byte seed `d ‖ z` (`KeyGen_internal`), `Encaps` randomness `m` 32 bytes
//! (`Encaps_internal`), a nonce 24 bytes (`vectors/SCHEMA.md` §2).

use secmp_crypto::{MlKem768Ct, MlKem768Dk, MlKem768Ek, Nonce24, SecretBytes, X25519Secret};

use crate::error::Result;

mod sealed {
    /// Seals [`super::Entropy`]: no implementation outside this module.
    pub trait Sealed {}
}

/// The source of the ratchet's randomness (sealed; see the module documentation).
pub trait Entropy: sealed::Sealed {
    /// `X25519.keygen()` (§7.2 initiator, §7.4 `DHRatchet`).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness or locked memory is unavailable.
    fn x25519(&mut self) -> Result<X25519Secret>;

    /// `ML-KEM-768.keygen()`, held as its seed (§7.2, §7.4).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness or locked memory is unavailable.
    fn mlkem768(&mut self) -> Result<MlKem768Dk>;

    /// `ML-KEM-768.Encaps(ek)` → `(ct, ss)` (§7.2, §7.4).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness is unavailable.
    fn encaps(&mut self, ek: &MlKem768Ek) -> Result<(MlKem768Ct, SecretBytes<32>)>;

    /// A header nonce (§7.3).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness is unavailable.
    fn nonce(&mut self) -> Result<Nonce24>;
}

/// The operating system CSPRNG (the only [`Entropy`] of a shipped build).
pub struct OsEntropy;

impl sealed::Sealed for OsEntropy {}

impl Entropy for OsEntropy {
    fn x25519(&mut self) -> Result<X25519Secret> {
        Ok(X25519Secret::generate()?)
    }

    fn mlkem768(&mut self) -> Result<MlKem768Dk> {
        Ok(MlKem768Dk::generate()?)
    }

    fn encaps(&mut self, ek: &MlKem768Ek) -> Result<(MlKem768Ct, SecretBytes<32>)> {
        Ok(ek.encapsulate()?)
    }

    fn nonce(&mut self) -> Result<Nonce24> {
        Ok(Nonce24::random()?)
    }
}

/// Fixed randomness for the `tr` vectors, tests and the constant-time bench (feature `kat`, never in a shipped
/// build): the bytes are consumed front to back in the SCHEMA-4.9 order; running out is
/// [`crate::Error::Unavailable`] (the source, not the input, failed).
#[cfg(feature = "kat")]
pub struct FixedEntropy {
    bytes: secmp_crypto::Zeroizing<Vec<u8>>,
    at: usize,
}

#[cfg(feature = "kat")]
impl FixedEntropy {
    /// The randomness `bytes`, consumed front to back.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: secmp_crypto::Zeroizing::new(bytes.to_vec()),
            at: 0,
        }
    }

    /// The bytes not consumed yet.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    fn take<const N: usize>(&mut self) -> Result<secmp_crypto::Zeroizing<[u8; N]>> {
        let end = self
            .at
            .checked_add(N)
            .ok_or(crate::error::Error::Unavailable)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(crate::error::Error::Unavailable)?;
        let mut out = secmp_crypto::Zeroizing::new([0_u8; N]);
        out.copy_from_slice(slice);
        self.at = end;
        Ok(out)
    }
}

#[cfg(feature = "kat")]
impl sealed::Sealed for FixedEntropy {}

#[cfg(feature = "kat")]
impl Entropy for FixedEntropy {
    fn x25519(&mut self) -> Result<X25519Secret> {
        Ok(X25519Secret::from_bytes(self.take::<32>()?.as_slice())?)
    }

    fn mlkem768(&mut self) -> Result<MlKem768Dk> {
        Ok(MlKem768Dk::from_seed(self.take::<64>()?.as_slice())?)
    }

    fn encaps(&mut self, ek: &MlKem768Ek) -> Result<(MlKem768Ct, SecretBytes<32>)> {
        Ok(ek.encapsulate_kat(&*self.take::<32>()?))
    }

    fn nonce(&mut self) -> Result<Nonce24> {
        Ok(Nonce24::from_bytes_kat(*self.take::<24>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use secmp_crypto::ConstantTimeEq;

    #[test]
    fn os_entropy_draws_fresh_values() -> Result<()> {
        let mut e = OsEntropy;
        let a = e.x25519()?;
        let b = e.x25519()?;
        assert_ne!(a.public_key(), b.public_key());
        let dk = e.mlkem768()?;
        let (ct, ss) = e.encaps(&dk.encapsulation_key())?;
        assert!(bool::from(dk.decapsulate(&ct).ct_eq(&ss)));
        assert_ne!(e.nonce()?.as_bytes(), e.nonce()?.as_bytes());
        Ok(())
    }

    /// The SCHEMA-4.9 order and sizes; running out is `Unavailable`, never `Rejected`.
    #[cfg(feature = "kat")]
    #[test]
    fn fixed_entropy_reads_in_order() -> Result<()> {
        let bytes: Vec<u8> = (0..=255_u8).cycle().take(32 + 64 + 32 + 24).collect();
        let mut e = FixedEntropy::new(&bytes);
        assert_eq!(e.remaining(), 152);
        let x = e.x25519()?;
        assert_eq!(
            x.expose_secret().as_slice(),
            bytes.get(..32).unwrap_or_default()
        );
        let dk = e.mlkem768()?;
        assert_eq!(
            dk.expose_seed().as_slice(),
            bytes.get(32..96).unwrap_or_default()
        );
        let (ct, ss) = e.encaps(&dk.encapsulation_key())?;
        let mut m = [0_u8; 32];
        m.copy_from_slice(bytes.get(96..128).unwrap_or_default());
        let (ct2, ss2) = dk.encapsulation_key().encapsulate_kat(&m);
        assert_eq!(ct.as_bytes(), ct2.as_bytes());
        assert!(bool::from(ss.ct_eq(&ss2)));
        assert_eq!(
            e.nonce()?.as_bytes().as_slice(),
            bytes.get(128..).unwrap_or_default()
        );
        assert_eq!(e.remaining(), 0);
        assert_eq!(e.nonce().err(), Some(Error::Unavailable));
        assert_eq!(
            FixedEntropy::new(&[0; 31]).x25519().err(),
            Some(Error::Unavailable)
        );
        Ok(())
    }
}
