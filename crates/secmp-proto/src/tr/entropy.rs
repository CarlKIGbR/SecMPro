// SPDX-License-Identifier: AGPL-3.0-or-later
//! The randomness of SecMP-TR (spec §7.2–§7.4): X25519 and ML-KEM-768 key generation, ML-KEM-768 `Encaps` and the
//! header nonce (§7.3 `hdr_nonce = random 24 B`).
//!
//! [`Entropy`] is sealed. A shipped build has exactly one implementation, [`OsEntropy`] (the OS CSPRNG through
//! `secmp-crypto`, CLAUDE.md §4). Feature `kat` (vectors, tests, the constant-time bench; never in a shipped build)
//! adds [`FixedEntropy`], which reads a byte string in the order of `vectors/SCHEMA-4.9-tr.md`: an X25519 secret is
//! 32 raw bytes, an ML-KEM-768 key the 64-byte seed `d ‖ z` (`KeyGen_internal`), `Encaps` randomness `m` 32 bytes
//! (`Encaps_internal`), a nonce 24 bytes (`vectors/SCHEMA.md` §2).

use secmp_crypto::{
    HybridKem768Ciphertext, HybridKem768PublicKey, HybridKem1024Ciphertext, HybridKem1024PublicKey,
    HybridSignature, HybridSigningKey, Label, MlKem768Ct, MlKem768Dk, MlKem768Ek, MlKem1024Ct,
    MlKem1024Dk, MlKem1024Ek, Nonce24, SecretBytes, X25519Secret,
};

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

    /// `ML-KEM-1024.keygen()`, held as its seed (§6.1 signed and one-time prekeys; M4).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness or locked memory is unavailable.
    fn mlkem1024(&mut self) -> Result<MlKem1024Dk>;

    /// `ML-KEM-1024.Encaps(ek)` → `(ct, ss)` (§6.4; M4).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness is unavailable.
    fn encaps1024(&mut self, ek: &MlKem1024Ek) -> Result<(MlKem1024Ct, SecretBytes<32>)>;

    /// `N` random bytes held as a secret (identifiers, `link_key`, seeds, `init_id`; M4).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness or locked memory is unavailable.
    fn secret<const N: usize>(&mut self) -> Result<SecretBytes<N>>;

    /// A fresh `IK_sig` (Ed25519 ‖ ML-DSA-65; M4). The derandomised implementation reads the ML-DSA seed `ξ`
    /// (32 bytes), then the Ed25519 seed (32 bytes) (`vectors/SCHEMA-4.10-hx.md`, `keys-R`).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness or locked memory is unavailable.
    fn hybrid_signing_key(&mut self) -> Result<HybridSigningKey>;

    /// `HybridSign(key, label, msg)` with the ML-DSA hedge `rnd` from this source (§3.5; M4: the inviter signs
    /// bundles). The derandomised implementation reads `rnd` (32 bytes).
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if randomness is unavailable; [`crate::Error::Rejected`] if the message is
    /// refused by the signer.
    fn sign(&mut self, key: &HybridSigningKey, label: Label, msg: &[u8])
    -> Result<HybridSignature>;

    /// `HybridKEM-768.Encaps(pk)` → `(ct, ss)` (§3.2; the relay's HS2, §8.3 step 5). The derandomised
    /// implementation reads `sk_e` (32 bytes), then the ML-KEM randomness `m` (32 bytes) (`vectors/SCHEMA-4.11-link.md`,
    /// reading OPEN-1).
    ///
    /// # Errors
    /// [`crate::Error::Rejected`] if the X25519 output is all zero (a low-order `pk_dh`);
    /// [`crate::Error::Unavailable`] if randomness or locked memory is unavailable.
    fn hybrid_encaps768(
        &mut self,
        pk: &HybridKem768PublicKey,
    ) -> Result<(HybridKem768Ciphertext, SecretBytes<32>)>;

    /// `HybridKEM-1024.Encaps(pk)` → `(ct, ss)` (§3.2; the client's HS1, §8.3 step 2), drawn as
    /// [`Entropy::hybrid_encaps768`].
    ///
    /// # Errors
    /// As [`Entropy::hybrid_encaps768`].
    fn hybrid_encaps1024(
        &mut self,
        pk: &HybridKem1024PublicKey,
    ) -> Result<(HybridKem1024Ciphertext, SecretBytes<32>)>;
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

    fn mlkem1024(&mut self) -> Result<MlKem1024Dk> {
        Ok(MlKem1024Dk::generate()?)
    }

    fn encaps1024(&mut self, ek: &MlKem1024Ek) -> Result<(MlKem1024Ct, SecretBytes<32>)> {
        Ok(ek.encapsulate()?)
    }

    fn secret<const N: usize>(&mut self) -> Result<SecretBytes<N>> {
        Ok(SecretBytes::<N>::random()?)
    }

    fn hybrid_signing_key(&mut self) -> Result<HybridSigningKey> {
        Ok(HybridSigningKey::generate()?)
    }

    fn sign(
        &mut self,
        key: &HybridSigningKey,
        label: Label,
        msg: &[u8],
    ) -> Result<HybridSignature> {
        Ok(key.sign(label, msg)?)
    }

    fn hybrid_encaps768(
        &mut self,
        pk: &HybridKem768PublicKey,
    ) -> Result<(HybridKem768Ciphertext, SecretBytes<32>)> {
        Ok(pk.encapsulate()?)
    }

    fn hybrid_encaps1024(
        &mut self,
        pk: &HybridKem1024PublicKey,
    ) -> Result<(HybridKem1024Ciphertext, SecretBytes<32>)> {
        Ok(pk.encapsulate()?)
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

    fn mlkem1024(&mut self) -> Result<MlKem1024Dk> {
        Ok(MlKem1024Dk::from_seed(self.take::<64>()?.as_slice())?)
    }

    fn encaps1024(&mut self, ek: &MlKem1024Ek) -> Result<(MlKem1024Ct, SecretBytes<32>)> {
        Ok(ek.encapsulate_kat(&*self.take::<32>()?))
    }

    fn secret<const N: usize>(&mut self) -> Result<SecretBytes<N>> {
        Ok(SecretBytes::<N>::from_slice(self.take::<N>()?.as_slice())?)
    }

    fn hybrid_signing_key(&mut self) -> Result<HybridSigningKey> {
        let xi = self.take::<32>()?;
        let ed = self.take::<32>()?;
        Ok(HybridSigningKey::from_seeds(ed.as_slice(), xi.as_slice())?)
    }

    fn sign(
        &mut self,
        key: &HybridSigningKey,
        label: Label,
        msg: &[u8],
    ) -> Result<HybridSignature> {
        let rnd = self.take::<32>()?;
        Ok(key.sign_kat(label, msg, &rnd)?)
    }

    fn hybrid_encaps768(
        &mut self,
        pk: &HybridKem768PublicKey,
    ) -> Result<(HybridKem768Ciphertext, SecretBytes<32>)> {
        let sk_e = self.take::<32>()?;
        let m = self.take::<32>()?;
        Ok(pk.encapsulate_kat(&sk_e, &m)?)
    }

    fn hybrid_encaps1024(
        &mut self,
        pk: &HybridKem1024PublicKey,
    ) -> Result<(HybridKem1024Ciphertext, SecretBytes<32>)> {
        let sk_e = self.take::<32>()?;
        let m = self.take::<32>()?;
        Ok(pk.encapsulate_kat(&sk_e, &m)?)
    }
}

/// Test randomness (unit tests only, with or without feature `kat`): the OS source for the first `ok` draws, then
/// [`crate::Error::Unavailable`]; every draw is counted, so a test can assert that a path drew nothing (plan D2).
#[cfg(test)]
pub(crate) struct TestEntropy {
    /// Draws that succeed.
    ok: usize,
    /// Draws attempted so far (successful or not).
    pub(crate) calls: usize,
}

#[cfg(test)]
impl TestEntropy {
    /// `ok` successful draws, then `Unavailable`.
    pub(crate) const fn failing_after(ok: usize) -> Self {
        Self { ok, calls: 0 }
    }

    fn draw(&mut self) -> Result<()> {
        self.calls = self.calls.saturating_add(1);
        if self.calls > self.ok {
            Err(crate::error::Error::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
impl sealed::Sealed for TestEntropy {}

#[cfg(test)]
impl Entropy for TestEntropy {
    fn x25519(&mut self) -> Result<X25519Secret> {
        self.draw()?;
        OsEntropy.x25519()
    }

    fn mlkem768(&mut self) -> Result<MlKem768Dk> {
        self.draw()?;
        OsEntropy.mlkem768()
    }

    fn encaps(&mut self, ek: &MlKem768Ek) -> Result<(MlKem768Ct, SecretBytes<32>)> {
        self.draw()?;
        OsEntropy.encaps(ek)
    }

    fn nonce(&mut self) -> Result<Nonce24> {
        self.draw()?;
        OsEntropy.nonce()
    }

    fn mlkem1024(&mut self) -> Result<MlKem1024Dk> {
        self.draw()?;
        OsEntropy.mlkem1024()
    }

    fn encaps1024(&mut self, ek: &MlKem1024Ek) -> Result<(MlKem1024Ct, SecretBytes<32>)> {
        self.draw()?;
        OsEntropy.encaps1024(ek)
    }

    fn secret<const N: usize>(&mut self) -> Result<SecretBytes<N>> {
        self.draw()?;
        OsEntropy.secret::<N>()
    }

    fn hybrid_signing_key(&mut self) -> Result<HybridSigningKey> {
        self.draw()?;
        OsEntropy.hybrid_signing_key()
    }

    fn sign(
        &mut self,
        key: &HybridSigningKey,
        label: Label,
        msg: &[u8],
    ) -> Result<HybridSignature> {
        self.draw()?;
        OsEntropy.sign(key, label, msg)
    }

    fn hybrid_encaps768(
        &mut self,
        pk: &HybridKem768PublicKey,
    ) -> Result<(HybridKem768Ciphertext, SecretBytes<32>)> {
        self.draw()?;
        OsEntropy.hybrid_encaps768(pk)
    }

    fn hybrid_encaps1024(
        &mut self,
        pk: &HybridKem1024PublicKey,
    ) -> Result<(HybridKem1024Ciphertext, SecretBytes<32>)> {
        self.draw()?;
        OsEntropy.hybrid_encaps1024(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secmp_crypto::ConstantTimeEq;

    /// The test source: `ok` draws of any kind, then `Unavailable` for every kind; every call counted.
    #[test]
    fn test_entropy_fails_after_its_budget() -> Result<()> {
        use crate::error::Error;
        let mut e = TestEntropy::failing_after(4);
        let dk = e.mlkem768()?;
        e.encaps(&dk.encapsulation_key())?;
        e.x25519()?;
        e.nonce()?;
        assert_eq!(e.nonce().err(), Some(Error::Unavailable));
        assert_eq!(e.x25519().err(), Some(Error::Unavailable));
        assert_eq!(e.mlkem768().err(), Some(Error::Unavailable));
        assert_eq!(
            e.encaps(&dk.encapsulation_key()).err(),
            Some(Error::Unavailable)
        );
        assert_eq!(e.calls, 8);
        let mut none = TestEntropy::failing_after(0);
        assert_eq!(none.nonce().err(), Some(Error::Unavailable));
        assert_eq!(none.calls, 1);
        Ok(())
    }

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
        use crate::error::Error;
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
