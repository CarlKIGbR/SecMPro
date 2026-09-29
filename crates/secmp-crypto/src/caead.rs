// SPDX-License-Identifier: AGPL-3.0-or-later
//! `CAEAD` (spec §3.4): the committing XChaCha20-Poly1305 wrapper (UtC transform). `COM` commits to `(K, N)`
//! under a key separate from the encryption key:
//!
//! ```text
//! (K_enc ‖ COM) = HKDF-Expand(PRK = K, info = "SecMP-commit/1" ‖ N, L = 64)
//! C = XChaCha20-Poly1305.Seal(K_enc, N, AD, P)
//! return COM ‖ C                          ; COM 32 B, C includes the 16-byte tag; N is not part of the output
//! ```
//!
//! Opening recomputes `COM` and compares it in constant time; the AEAD is evaluated in every case, and the
//! plaintext is released only if both the commitment and the tag match. A commitment failure and a tag failure
//! therefore take the same path and return the same [`Error::Rejected`].

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::kdf::hkdf_expand;
use crate::label::Label;
use crate::nonce::Nonce24;
use crate::secret::SecretBytes;

/// Length of the commitment `COM`.
pub const COM_LEN: usize = 32;
/// Length of the Poly1305 tag inside `C`.
pub const AEAD_TAG_LEN: usize = 16;
/// Length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;

/// `(K_enc, COM)` of spec §3.4.
fn derive(k: &SecretBytes<32>, n: &[u8; NONCE_LEN]) -> Result<(XChaCha20Poly1305, [u8; COM_LEN])> {
    // (K_enc ‖ COM) = HKDF-Expand(PRK = K, info = "SecMP-commit/1" ‖ N, L = 64)
    let okm = hkdf_expand::<64>(k.expose_secret(), Label::Commit, &[n])?;
    let (k_enc, com) = okm
        .expose_secret()
        .split_first_chunk::<32>()
        .ok_or(Error::Rejected)?;
    let com: [u8; COM_LEN] = com.try_into().map_err(|_| Error::Rejected)?;
    Ok((XChaCha20Poly1305::new(k_enc.into()), com))
}

/// The `CAEAD` construction of spec §3.4.
pub struct Caead;

impl Caead {
    /// `CAEAD.Seal(K, N, AD, P)` → `COM ‖ C` (the nonce is consumed; transmit `nonce.as_bytes()` read before).
    ///
    /// # Errors
    /// [`Error::Rejected`] only if the AEAD refuses the length (more than 2^38 bytes).
    pub fn seal(k: &SecretBytes<32>, nonce: Nonce24, ad: &[u8], p: &[u8]) -> Result<Vec<u8>> {
        let n = nonce.into_bytes();
        let (aead, com) = derive(k, &n)?;
        let mut out =
            Vec::with_capacity(COM_LEN.saturating_add(p.len()).saturating_add(AEAD_TAG_LEN));
        out.extend_from_slice(&com);
        out.extend_from_slice(p);
        let body = out.get_mut(COM_LEN..).ok_or(Error::Rejected)?;
        // C = XChaCha20-Poly1305.Seal(K_enc, N, AD, P)
        let tag = aead
            .encrypt_inout_detached(&XNonce::from(n), ad, body.into())
            .map_err(|_| Error::Rejected)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// `CAEAD.Open(K, N, AD, COM ‖ C)`.
    ///
    /// # Errors
    /// [`Error::Rejected`] — uniformly — if the input is shorter than `COM` plus a tag, the commitment does
    /// not match, or the tag does not verify.
    pub fn open(
        k: &SecretBytes<32>,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        com_c: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (com, c) = com_c
            .split_first_chunk::<COM_LEN>()
            .ok_or(Error::Rejected)?;
        let tag_at = c.len().checked_sub(AEAD_TAG_LEN).ok_or(Error::Rejected)?;
        let (ct, tag) = c.split_at(tag_at);
        let (aead, expected) = derive(k, nonce)?;
        // recompute COM, constant-time compare
        let com_ok = expected.ct_eq(com);
        // then open (always evaluated, so both failures take the same path)
        let mut buf = Zeroizing::new(ct.to_vec());
        let tag = Tag::try_from(tag).map_err(|_| Error::Rejected)?;
        let tag_ok = aead
            .decrypt_inout_detached(&XNonce::from(*nonce), ad, buf.as_mut_slice().into(), &tag)
            .is_ok();
        // M1 review C4: combine both results as `Choice`s and branch once on the final verdict. A short-circuit
        // `bool::from(com_ok) && tag_ok` branches on `com_ok`, so a rejection took a different path depending on
        // whether the commitment matched — measurable (dudect |t| = 32 on x86_64 CI) and exactly what trial
        // decryption must not reveal (spec §6.5).
        let ok = com_ok & Choice::from(u8::from(tag_ok));
        if bool::from(ok) {
            Ok(buf)
        } else {
            buf.zeroize();
            Err(Error::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Result<SecretBytes<32>> {
        SecretBytes::from_slice(&[b; 32])
    }

    #[test]
    fn round_trip_and_layout() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Caead::seal(&key(1)?, n, b"ad", b"hello")?;
        assert_eq!(sealed.len(), COM_LEN + 5 + AEAD_TAG_LEN);
        assert_eq!(
            Caead::open(&key(1)?, &nb, b"ad", &sealed)?.as_slice(),
            b"hello"
        );
        // empty plaintext: COM ‖ tag
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Caead::seal(&key(1)?, n, b"", b"")?;
        assert_eq!(sealed.len(), COM_LEN + AEAD_TAG_LEN);
        assert!(Caead::open(&key(1)?, &nb, b"", &sealed)?.is_empty());
        Ok(())
    }

    /// The construction recomputed from its definition (HKDF-Expand split, plain XChaCha20-Poly1305, `COM ‖ C`).
    #[test]
    fn matches_the_definition() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Caead::seal(&key(9)?, n, b"assoc", b"payload")?;
        let okm = hkdf_expand::<64>(&[9; 32], Label::Commit, &[&nb])?;
        let (k_enc, com) = okm.expose_secret().split_at(32);
        let aead = XChaCha20Poly1305::new_from_slice(k_enc).map_err(|_| Error::Rejected)?;
        let mut buf = b"payload".to_vec();
        let tag = aead
            .encrypt_inout_detached(&XNonce::from(nb), b"assoc", buf.as_mut_slice().into())
            .map_err(|_| Error::Rejected)?;
        let mut expected = com.to_vec();
        expected.extend_from_slice(&buf);
        expected.extend_from_slice(&tag);
        assert_eq!(sealed, expected);
        Ok(())
    }

    #[test]
    fn every_failure_is_the_same_rejection() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Caead::seal(&key(2)?, n, b"ad", &[7; 16])?;
        let rej = Some(Error::Rejected);
        for i in [0, COM_LEN - 1, COM_LEN, sealed.len() - 1] {
            let mut bad = sealed.clone();
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            assert_eq!(
                Caead::open(&key(2)?, &nb, b"ad", &bad).err(),
                rej,
                "flip {i}"
            );
        }
        assert_eq!(Caead::open(&key(2)?, &nb, b"aD", &sealed).err(), rej, "AD");
        assert_eq!(Caead::open(&key(3)?, &nb, b"ad", &sealed).err(), rej, "key");
        let mut other = nb;
        other[0] ^= 1;
        assert_eq!(
            Caead::open(&key(2)?, &other, b"ad", &sealed).err(),
            rej,
            "nonce"
        );
        let short = sealed.split_last().map_or(&[][..], |(_, r)| r);
        assert_eq!(
            Caead::open(&key(2)?, &nb, b"ad", short).err(),
            rej,
            "truncated"
        );
        let tiny = sealed.get(..COM_LEN + 15).unwrap_or_default();
        assert_eq!(
            Caead::open(&key(2)?, &nb, b"ad", tiny).err(),
            rej,
            "shorter than a tag"
        );
        assert_eq!(
            Caead::open(&key(2)?, &nb, b"ad", sealed.get(..20).unwrap_or_default()).err(),
            rej,
            "shorter than COM"
        );
        Ok(())
    }

    /// A ciphertext that verifies under `K_enc` but carries a wrong `COM` is still rejected: the commitment is
    /// what binds `K` (the only way to reach this case is to tamper with `COM` alone).
    #[test]
    fn tag_valid_but_commitment_wrong() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let mut sealed = Caead::seal(&key(4)?, n, b"", b"x")?;
        if let Some(b) = sealed.get_mut(5) {
            *b ^= 0x80;
        }
        assert_eq!(
            Caead::open(&key(4)?, &nb, b"", &sealed).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }
}
