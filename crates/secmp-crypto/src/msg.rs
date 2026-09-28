// SPDX-License-Identifier: AGPL-3.0-or-later
//! `MsgEncrypt` (spec §3.3): Encrypt-then-MAC for end-to-end bodies — ChaCha20 (RFC 8439, block counter 0) and
//! HMAC-SHA-256 under keys derived from the single-use message key `MK`:
//!
//! ```text
//! (K_enc ‖ K_mac ‖ IV) = HKDF-SHA-256(salt = 0^32, IKM = MK, info = "SecMP-TR/1 msgkeys", L = 32+32+12)
//! C   = ChaCha20(K_enc, nonce = IV, counter = 0) XOR P
//! TAG = HMAC-SHA-256(K_mac, AD ‖ C)
//! return C ‖ TAG
//! ```
//!
//! Decryption recomputes the tag, compares it in constant time and only then decrypts. `|P| ≠ BODY_LEN` on
//! sealing and `|C ‖ TAG| ≠ BODY_LEN + 32` on opening are rejected with the same uniform error as a MAC failure.
//! Padding is not interpreted here (it is checked by the `Content` decoder, M2).

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::kdf::hkdf;
use crate::label::Label;
use crate::secret::SecretBytes;

/// Padded body length per cell (spec §4.2).
pub const BODY_LEN: usize = 1710;
/// HMAC-SHA-256 tag length.
pub const MSG_TAG_LEN: usize = 32;
/// Length of `C ‖ TAG`.
pub const MSG_SEALED_LEN: usize = 1742;
const _: () = assert!(MSG_SEALED_LEN == BODY_LEN + MSG_TAG_LEN);

/// The derived keys of one message key.
struct MsgKeys {
    okm: SecretBytes<76>,
}

impl MsgKeys {
    /// spec §3.3: `(K_enc ‖ K_mac ‖ IV) = HKDF-SHA-256(salt = 0^32, IKM = MK, info = "SecMP-TR/1 msgkeys", L = 76)`
    fn derive(mk: &SecretBytes<32>) -> Result<Self> {
        Ok(Self {
            okm: hkdf::<76>(&[0; 32], mk.expose_secret(), Label::TrMsgkeys, &[])?,
        })
    }

    fn parts(&self) -> Result<(&[u8; 32], &[u8; 32], &[u8; 12])> {
        let (k_enc, rest) = self
            .okm
            .expose_secret()
            .split_first_chunk::<32>()
            .ok_or(Error::Rejected)?;
        let (k_mac, iv) = rest.split_first_chunk::<32>().ok_or(Error::Rejected)?;
        let iv: &[u8; 12] = iv.try_into().map_err(|_| Error::Rejected)?;
        Ok((k_enc, k_mac, iv))
    }

    /// `C = ChaCha20(K_enc, nonce = IV, counter = 0) XOR buf`, in place.
    fn xor_keystream(&self, buf: &mut [u8]) -> Result<()> {
        let (k_enc, _, iv) = self.parts()?;
        let mut cipher = ChaCha20::new(k_enc.into(), iv.into());
        cipher.apply_keystream(buf);
        Ok(())
    }

    /// `TAG = HMAC-SHA-256(K_mac, AD ‖ C)`
    fn tag(&self, ad: &[u8], c: &[u8]) -> Result<[u8; MSG_TAG_LEN]> {
        let (_, k_mac, _) = self.parts()?;
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(k_mac).map_err(|_| Error::Rejected)?;
        mac.update(ad);
        mac.update(c);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// The `MsgEncrypt` construction of spec §3.3.
pub struct MsgEncrypt;

impl MsgEncrypt {
    /// Seal the padded body `p` under the single-use message key `mk` (consumed) with associated data `ad`;
    /// returns `C ‖ TAG` (1742 bytes).
    ///
    /// # Errors
    /// [`Error::Rejected`] if `p` is not exactly [`BODY_LEN`] bytes.
    pub fn seal(mk: SecretBytes<32>, ad: &[u8], p: &[u8]) -> Result<Vec<u8>> {
        if p.len() != BODY_LEN {
            return Err(Error::Rejected);
        }
        let keys = MsgKeys::derive(&mk)?;
        // MK is single-use (spec §3.3): consumed here, zeroised on drop
        drop(mk);
        let mut out = Vec::with_capacity(MSG_SEALED_LEN);
        out.extend_from_slice(p);
        keys.xor_keystream(&mut out)?;
        let tag = keys.tag(ad, &out)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open `C ‖ TAG`: the tag is recomputed and compared in constant time before anything is decrypted.
    ///
    /// # Errors
    /// [`Error::Rejected`] — uniformly — if `c_tag` is not exactly 1742 bytes or the tag does not match.
    pub fn open(mk: &SecretBytes<32>, ad: &[u8], c_tag: &[u8]) -> Result<SecretBytes<BODY_LEN>> {
        if c_tag.len() != MSG_SEALED_LEN {
            return Err(Error::Rejected);
        }
        let (c, tag) = c_tag.split_at(BODY_LEN);
        let keys = MsgKeys::derive(mk)?;
        let expected = keys.tag(ad, c)?;
        if !bool::from(expected.as_slice().ct_eq(tag)) {
            return Err(Error::Rejected);
        }
        let mut p = SecretBytes::<BODY_LEN>::zero();
        p.expose_secret_mut().copy_from_slice(c);
        keys.xor_keystream(p.expose_secret_mut())?;
        Ok(p)
    }

    /// The derived `(K_enc, K_mac, IV)` of `mk`, for the `msgencrypt` vector suite (feature `kat`).
    ///
    /// # Errors
    /// None in practice (the lengths are fixed); kept fallible like every derivation.
    #[cfg(feature = "kat")]
    pub fn derived_keys_kat(mk: &SecretBytes<32>) -> Result<([u8; 32], [u8; 32], [u8; 12])> {
        let keys = MsgKeys::derive(mk)?;
        let (k_enc, k_mac, iv) = keys.parts()?;
        Ok((*k_enc, *k_mac, *iv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(b: u8) -> Result<SecretBytes<32>> {
        SecretBytes::from_slice(&[b; 32])
    }

    #[test]
    fn round_trip() -> Result<()> {
        let body = [0x5a_u8; BODY_LEN];
        let sealed = MsgEncrypt::seal(mk(1)?, b"ad", &body)?;
        assert_eq!(sealed.len(), MSG_SEALED_LEN);
        assert_ne!(sealed.get(..BODY_LEN), Some(&body[..]));
        let opened = MsgEncrypt::open(&mk(1)?, b"ad", &sealed)?;
        assert_eq!(opened.expose_secret(), &body);
        Ok(())
    }

    /// The construction recomputed from its definition: HKDF split, ChaCha20 from block counter 0, HMAC over
    /// `AD ‖ C`.
    #[test]
    fn matches_the_definition() -> Result<()> {
        let body = [0x11_u8; BODY_LEN];
        let sealed = MsgEncrypt::seal(mk(7)?, b"header", &body)?;
        let okm = hkdf::<76>(&[0; 32], &[7; 32], Label::TrMsgkeys, &[])?;
        let (k_enc, rest) = okm.expose_secret().split_at(32);
        let (k_mac, iv) = rest.split_at(32);
        let mut c = body.to_vec();
        let mut ks = ChaCha20::new_from_slices(k_enc, iv).map_err(|_| Error::Rejected)?;
        ks.apply_keystream(&mut c);
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(k_mac).map_err(|_| Error::Rejected)?;
        mac.update(b"header");
        mac.update(&c);
        c.extend_from_slice(&mac.finalize().into_bytes());
        assert_eq!(sealed, c);
        Ok(())
    }

    #[test]
    fn every_failure_is_the_same_rejection() -> Result<()> {
        let body = [0_u8; BODY_LEN];
        let sealed = MsgEncrypt::seal(mk(2)?, b"ad", &body)?;
        let rej = Some(Error::Rejected);
        for i in [0, BODY_LEN - 1, BODY_LEN, MSG_SEALED_LEN - 1] {
            let mut bad = sealed.clone();
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            assert_eq!(
                MsgEncrypt::open(&mk(2)?, b"ad", &bad).err(),
                rej,
                "flip {i}"
            );
        }
        assert_eq!(
            MsgEncrypt::open(&mk(2)?, b"aD", &sealed).err(),
            rej,
            "wrong AD"
        );
        assert_eq!(
            MsgEncrypt::open(&mk(3)?, b"ad", &sealed).err(),
            rej,
            "wrong key"
        );
        let short = sealed.split_last().map_or(&[][..], |(_, r)| r);
        assert_eq!(
            MsgEncrypt::open(&mk(2)?, b"ad", short).err(),
            rej,
            "truncated"
        );
        let mut long = sealed.clone();
        long.push(0);
        assert_eq!(
            MsgEncrypt::open(&mk(2)?, b"ad", &long).err(),
            rej,
            "extended"
        );
        assert_eq!(MsgEncrypt::open(&mk(2)?, b"ad", &[]).err(), rej, "empty");
        assert_eq!(
            MsgEncrypt::seal(mk(2)?, b"ad", &body[1..]).err(),
            rej,
            "short body"
        );
        assert_eq!(
            MsgEncrypt::seal(mk(2)?, b"ad", &[0; BODY_LEN + 1]).err(),
            rej,
            "long body"
        );
        Ok(())
    }
}
