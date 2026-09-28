// SPDX-License-Identifier: AGPL-3.0-or-later
//! `HybridSign` (spec §3.5): Ed25519 ‖ ML-DSA-65 over a labelled digest.
//!
//! ```text
//! HybridSign(sk = (sk_ed, sk_mldsa), label, M):
//!     m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)
//!     return Ed25519.Sign(sk_ed, m) ‖ ML-DSA-65.Sign(sk_mldsa, m, ctx = label)
//! HybridVerify(pk, label, M, sig): both components MUST verify.
//! ```
//!
//! `label` must be one of the two HybridSign labels (`"SecMP-HX/1 bundle"`, `"SecMP-TR/1 keychange"`); every
//! other label is refused on signing and on verification. Ed25519 verification is strict (spec §3.5, see
//! [`crate::Ed25519VerifyingKey`]); ML-DSA-65 is pure and hedged. Verification evaluates both components before
//! deciding.

use core::fmt;

use crate::ed25519::{ED25519_PK_LEN, ED25519_SIG_LEN, Ed25519SigningKey, Ed25519VerifyingKey};
use crate::error::{Error, Result};
use crate::hash::sha256;
use crate::label::Label;
use crate::mldsa::{MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MlDsa65SigningKey, MlDsa65VerifyingKey};
use crate::secret::SecretBytes;

/// Length of a hybrid signature `sig_ed ‖ sig_mldsa`.
pub const HYBRID_SIG_LEN: usize = 3373;
const _: () = assert!(HYBRID_SIG_LEN == ED25519_SIG_LEN + MLDSA65_SIG_LEN);

/// `m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)`, only for the two HybridSign labels.
fn digest(label: Label, msg: &[u8]) -> Result<[u8; 32]> {
    if !label.is_hybrid_sign_label() {
        return Err(Error::Rejected);
    }
    Ok(sha256(&[
        Label::HybridSign.as_bytes(),
        label.as_bytes(),
        msg,
    ]))
}

/// The identity signing key `IK_sig` = (Ed25519, ML-DSA-65), both seeds in locked memory.
pub struct HybridSigningKey {
    ed: Ed25519SigningKey,
    mldsa: MlDsa65SigningKey,
}

impl HybridSigningKey {
    /// A new random key.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if randomness or locked memory is unavailable.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            ed: Ed25519SigningKey::generate()?,
            mldsa: MlDsa65SigningKey::generate()?,
        })
    }

    /// The key with the given Ed25519 seed and ML-DSA seed ξ (32 bytes each).
    ///
    /// # Errors
    /// [`Error::Rejected`] on a wrong seed length; [`Error::Unavailable`] if locked memory is unavailable.
    pub fn from_seeds(ed_seed: &[u8], mldsa_seed: &[u8]) -> Result<Self> {
        Ok(Self {
            ed: Ed25519SigningKey::from_seed(ed_seed)?,
            mldsa: MlDsa65SigningKey::from_seed(mldsa_seed)?,
        })
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed: self.ed.verifying_key(),
            mldsa: self.mldsa.verifying_key(),
        }
    }

    /// `HybridSign(sk, label, msg)` with fresh ML-DSA hedging randomness.
    ///
    /// # Errors
    /// [`Error::Rejected`] for a label other than the two HybridSign labels; [`Error::Unavailable`] if
    /// randomness is unavailable.
    pub fn sign(&self, label: Label, msg: &[u8]) -> Result<HybridSignature> {
        let rnd = SecretBytes::<32>::random()?;
        self.sign_with(label, msg, rnd.expose_secret())
    }

    fn sign_with(&self, label: Label, msg: &[u8], rnd: &[u8; 32]) -> Result<HybridSignature> {
        // spec §3.5: m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)
        let m = digest(label, msg)?;
        // Ed25519.Sign(sk_ed, m) ‖ ML-DSA-65.Sign(sk_mldsa, m, ctx = label)
        let ed = self.ed.sign(&m);
        let ml = self.mldsa.sign_with(&m, label.as_bytes(), rnd)?;
        let mut sig = Box::new([0; HYBRID_SIG_LEN]);
        let (a, b) = sig.split_at_mut(ED25519_SIG_LEN);
        a.copy_from_slice(&ed);
        b.copy_from_slice(ml.as_slice());
        Ok(HybridSignature(sig))
    }

    /// `HybridSign` with fixed ML-DSA randomness `rnd`, for known-answer tests and vectors (feature `kat`).
    ///
    /// # Errors
    /// [`Error::Rejected`] for a label other than the two HybridSign labels.
    #[cfg(feature = "kat")]
    pub fn sign_kat(&self, label: Label, msg: &[u8], rnd: &[u8; 32]) -> Result<HybridSignature> {
        self.sign_with(label, msg, rnd)
    }
}

/// The identity verifying key `(ik_ed25519, ik_mldsa65)`.
#[derive(Clone, PartialEq)]
pub struct HybridVerifyingKey {
    ed: Ed25519VerifyingKey,
    mldsa: MlDsa65VerifyingKey,
}

impl HybridVerifyingKey {
    /// Import both public keys (Ed25519 strict import rules, ML-DSA-65 length).
    ///
    /// # Errors
    /// [`Error::Rejected`] if either part is refused.
    pub fn from_bytes(ed: &[u8], mldsa: &[u8]) -> Result<Self> {
        Ok(Self {
            ed: Ed25519VerifyingKey::from_bytes(ed)?,
            mldsa: MlDsa65VerifyingKey::from_bytes(mldsa)?,
        })
    }

    /// The Ed25519 public key.
    #[must_use]
    pub fn ed25519(&self) -> &[u8; ED25519_PK_LEN] {
        self.ed.as_bytes()
    }

    /// The ML-DSA-65 public key.
    #[must_use]
    pub fn mldsa65(&self) -> &[u8; MLDSA65_PK_LEN] {
        self.mldsa.as_bytes()
    }

    /// `HybridVerify(pk, label, msg, sig)`: both components must verify.
    ///
    /// # Errors
    /// [`Error::Rejected`] for a label other than the two HybridSign labels, or if either component fails.
    pub fn verify(&self, label: Label, msg: &[u8], sig: &HybridSignature) -> Result<()> {
        let m = digest(label, msg)?;
        let (ed_sig, ml_sig) = sig.0.split_at(ED25519_SIG_LEN);
        let ed_ok = self.ed.verify(&m, ed_sig).is_ok();
        let ml_ok = self.mldsa.verify(&m, label.as_bytes(), ml_sig).is_ok();
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }
}

impl fmt::Debug for HybridVerifyingKey {
    /// Redacted: key bytes never reach logs (docs/04 CS-2.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridVerifyingKey(..)")
    }
}

/// A hybrid signature `sig_ed (64) ‖ sig_mldsa (3309)`.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature(Box<[u8; HYBRID_SIG_LEN]>);

impl HybridSignature {
    /// A signature of exactly 3373 bytes (its parts are checked when verifying).
    ///
    /// # Errors
    /// [`Error::Rejected`] on any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Box::new(
            bytes.try_into().map_err(|_| Error::Rejected)?,
        )))
    }

    /// The encoded signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HYBRID_SIG_LEN] {
        &self.0
    }
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSignature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Result<HybridSigningKey> {
        HybridSigningKey::from_seeds(&[1; 32], &[2; 32])
    }

    #[test]
    fn sign_and_verify_with_both_labels() -> Result<()> {
        let sk = key()?;
        let vk = sk.verifying_key();
        for label in [Label::HxBundle, Label::TrKeychange] {
            let sig = sk.sign(label, b"bundle bytes")?;
            vk.verify(label, b"bundle bytes", &sig)?;
            let again = HybridSignature::from_bytes(sig.as_bytes())?;
            vk.verify(label, b"bundle bytes", &again)?;
        }
        Ok(())
    }

    /// The composition recomputed from spec §3.5 with the component wrappers.
    #[test]
    fn matches_the_definition() -> Result<()> {
        let sk = key()?;
        let sig = sk.sign_with(Label::HxBundle, b"M", &[5; 32])?;
        let m = sha256(&[b"SecMP-HybridSign/1", b"SecMP-HX/1 bundle", b"M"]);
        let ed = Ed25519SigningKey::from_seed(&[1; 32])?.sign(&m);
        let ml = MlDsa65SigningKey::from_seed(&[2; 32])?.sign_with(
            &m,
            b"SecMP-HX/1 bundle",
            &[5; 32],
        )?;
        let (a, b) = sig.as_bytes().split_at(ED25519_SIG_LEN);
        assert_eq!(a, ed.as_slice());
        assert_eq!(b, ml.as_slice());
        Ok(())
    }

    #[test]
    fn other_labels_are_refused() -> Result<()> {
        let sk = key()?;
        let vk = sk.verifying_key();
        let sig = sk.sign(Label::HxBundle, b"x")?;
        for label in Label::ALL.into_iter().filter(|l| !l.is_hybrid_sign_label()) {
            assert_eq!(
                sk.sign(label, b"x").err(),
                Some(Error::Rejected),
                "{label:?}"
            );
            assert_eq!(
                vk.verify(label, b"x", &sig).err(),
                Some(Error::Rejected),
                "{label:?}"
            );
        }
        // the other HybridSign label does not verify either
        assert_eq!(
            vk.verify(Label::TrKeychange, b"x", &sig).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }

    #[test]
    fn either_component_failing_rejects() -> Result<()> {
        let sk = key()?;
        let vk = sk.verifying_key();
        let sig = sk.sign(Label::TrKeychange, b"m")?;
        for i in [0, 63, 64, HYBRID_SIG_LEN - 1] {
            let mut bad = *sig.as_bytes();
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            let bad = HybridSignature::from_bytes(&bad)?;
            assert_eq!(
                vk.verify(Label::TrKeychange, b"m", &bad).err(),
                Some(Error::Rejected),
                "{i}"
            );
        }
        assert_eq!(
            vk.verify(Label::TrKeychange, b"n", &sig).err(),
            Some(Error::Rejected)
        );
        let other = HybridSigningKey::generate()?.verifying_key();
        assert_eq!(
            other.verify(Label::TrKeychange, b"m", &sig).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }

    #[test]
    fn import_lengths_and_debug() -> Result<()> {
        let vk = key()?.verifying_key();
        let back = HybridVerifyingKey::from_bytes(vk.ed25519(), vk.mldsa65())?;
        assert_eq!(back, vk);
        assert_eq!(
            HybridVerifyingKey::from_bytes(&[0; 32], vk.mldsa65()).err(),
            Some(Error::Rejected),
            "small-order Ed25519 key"
        );
        assert_eq!(
            HybridVerifyingKey::from_bytes(vk.ed25519(), &[0; 10]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            HybridSignature::from_bytes(&[0; 3372]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            HybridSigningKey::from_seeds(&[0; 31], &[0; 32]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(format!("{vk:?}"), "HybridVerifyingKey(..)");
        let sig = key()?.sign(Label::HxBundle, b"")?;
        assert_eq!(format!("{sig:?}"), "HybridSignature(..)");
        Ok(())
    }
}
