// SPDX-License-Identifier: AGPL-3.0-or-later
//! ML-DSA-65 (FIPS 204; spec §3.5) via RustCrypto `ml-dsa` (ADR-023): **pure** ML-DSA (not HashML-DSA),
//! **hedged** with 32 bytes of OS randomness, keys from `KeyGen_internal(ξ)` with the 32-byte seed ξ held in
//! locked memory. Signing is FIPS 204 Algorithm 2: `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M`, then
//! `Sign_internal(sk, M', rnd)`; verification is Algorithm 3 with the same context.

use core::fmt;

use ml_dsa::{B32, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature, VerifyingKey};

use crate::error::{Error, Result};
use crate::secret::{LockedSecret, SecretBytes};

/// Length of the ML-DSA seed ξ.
pub const MLDSA_SEED_LEN: usize = 32;
/// Length of an ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature.
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Longest context string (FIPS 204: `len(ctx)` is one byte).
pub const MLDSA_MAX_CTX_LEN: usize = 255;

fn boxed<const N: usize>(bytes: &[u8]) -> Result<Box<[u8; N]>> {
    Ok(Box::new(bytes.try_into().map_err(|_| Error::Rejected)?))
}

/// An ML-DSA-65 signing key, held as its seed ξ in locked memory.
pub struct MlDsa65SigningKey(LockedSecret<MLDSA_SEED_LEN>);

impl MlDsa65SigningKey {
    /// A new random key.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if randomness or locked memory is unavailable.
    pub fn generate() -> Result<Self> {
        Ok(Self(LockedSecret::random()?))
    }

    /// The key with seed ξ (`KeyGen_internal(ξ)`).
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `seed` is 32 bytes long; [`Error::Unavailable`] if locked memory is
    /// unavailable.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self(LockedSecret::from_slice(seed)?))
    }

    /// The expanded key (zeroised on drop by `ml-dsa` with its `zeroize` feature).
    fn expanded(&self) -> ExpandedSigningKey<MlDsa65> {
        ExpandedSigningKey::from_seed(&B32::from(*self.0.expose_secret()))
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> MlDsa65VerifyingKey {
        let key = self.expanded().verifying_key();
        let mut bytes = Box::new([0; MLDSA65_PK_LEN]);
        bytes.copy_from_slice(&key.encode());
        MlDsa65VerifyingKey { bytes, key }
    }

    /// Pure, hedged ML-DSA-65 signature of `msg` under context `ctx`, with fresh randomness.
    ///
    /// # Errors
    /// [`Error::Rejected`] if `ctx` is longer than 255 bytes; [`Error::Unavailable`] if randomness is
    /// unavailable.
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<Box<[u8; MLDSA65_SIG_LEN]>> {
        let rnd = SecretBytes::<32>::random()?;
        self.sign_with(msg, ctx, rnd.expose_secret())
    }

    /// FIPS 204 Algorithm 2 with the given `rnd`.
    pub(crate) fn sign_with(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Box<[u8; MLDSA65_SIG_LEN]>> {
        let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::Rejected)?;
        // spec §3.5, FIPS 204 Alg. 2: M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M (pure ML-DSA), then Sign_internal(sk, M', rnd)
        let sig = self
            .expanded()
            .sign_internal(&[&[0x00], &[ctx_len], ctx, msg], &B32::from(*rnd));
        boxed(&sig.encode())
    }

    /// Signature with fixed `rnd`, for known-answer tests and vector generation (feature `kat`).
    ///
    /// # Errors
    /// [`Error::Rejected`] if `ctx` is longer than 255 bytes.
    #[cfg(feature = "kat")]
    pub fn sign_kat(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Box<[u8; MLDSA65_SIG_LEN]>> {
        self.sign_with(msg, ctx, rnd)
    }
}

/// An ML-DSA-65 verifying key.
#[derive(Clone, PartialEq)]
pub struct MlDsa65VerifyingKey {
    bytes: Box<[u8; MLDSA65_PK_LEN]>,
    key: VerifyingKey<MlDsa65>,
}

impl MlDsa65VerifyingKey {
    /// Import an encoded key (FIPS 204 `pkDecode`; every 1952-byte string decodes).
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 1952 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| Error::Rejected)?;
        Ok(Self {
            bytes: boxed(bytes)?,
            key: VerifyingKey::decode(&enc),
        })
    }

    /// The encoded key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLDSA65_PK_LEN] {
        &self.bytes
    }

    /// FIPS 204 Algorithm 3 (pure ML-DSA) under context `ctx`.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `sig` is a well-formed 3309-byte signature that verifies for `msg` and `ctx`.
    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        if ctx.len() > MLDSA_MAX_CTX_LEN {
            return Err(Error::Rejected);
        }
        let sig = Signature::<MlDsa65>::try_from(sig).map_err(|_| Error::Rejected)?;
        if self.key.verify_with_context(msg, ctx, &sig) {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }
}

impl fmt::Debug for MlDsa65VerifyingKey {
    /// Redacted: key bytes never reach logs (docs/04 CS-2.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsa65VerifyingKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_hedging() -> Result<()> {
        let key = MlDsa65SigningKey::generate()?;
        let vk = key.verifying_key();
        let s1 = key.sign(b"m", b"SecMP-HX/1 bundle")?;
        let s2 = key.sign(b"m", b"SecMP-HX/1 bundle")?;
        assert_ne!(s1, s2, "hedged: fresh rnd each time");
        vk.verify(b"m", b"SecMP-HX/1 bundle", s1.as_slice())?;
        vk.verify(b"m", b"SecMP-HX/1 bundle", s2.as_slice())?;
        // the same rnd gives the same signature
        let d1 = key.sign_with(b"m", b"", &[9; 32])?;
        let d2 = key.sign_with(b"m", b"", &[9; 32])?;
        assert_eq!(d1, d2);
        Ok(())
    }

    #[test]
    fn context_message_and_signature_are_bound() -> Result<()> {
        let key = MlDsa65SigningKey::from_seed(&[3; 32])?;
        let vk = key.verifying_key();
        let sig = key.sign(b"msg", b"ctx")?;
        assert_eq!(
            vk.verify(b"msg", b"ctx2", sig.as_slice()).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            vk.verify(b"msg!", b"ctx", sig.as_slice()).err(),
            Some(Error::Rejected)
        );
        let mut bad = *sig;
        bad[0] ^= 1;
        assert_eq!(vk.verify(b"msg", b"ctx", &bad).err(), Some(Error::Rejected));
        let short = sig.split_last().map_or(&[][..], |(_, rest)| rest);
        assert_eq!(
            vk.verify(b"msg", b"ctx", short).err(),
            Some(Error::Rejected)
        );
        let long_ctx = [0_u8; 256];
        assert_eq!(key.sign(b"msg", &long_ctx).err(), Some(Error::Rejected));
        assert_eq!(
            vk.verify(b"msg", &long_ctx, sig.as_slice()).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }

    #[test]
    fn seed_determines_key_and_import_round_trips() -> Result<()> {
        let a = MlDsa65SigningKey::from_seed(&[5; 32])?.verifying_key();
        let b = MlDsa65SigningKey::from_seed(&[5; 32])?.verifying_key();
        assert_eq!(a, b);
        let imported = MlDsa65VerifyingKey::from_bytes(a.as_bytes())?;
        assert_eq!(imported, a);
        assert_eq!(
            MlDsa65VerifyingKey::from_bytes(&[0; 1951]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            MlDsa65SigningKey::from_seed(&[0; 31]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(format!("{a:?}"), "MlDsa65VerifyingKey(..)");
        Ok(())
    }
}
