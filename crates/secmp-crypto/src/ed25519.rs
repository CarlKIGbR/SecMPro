// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 (RFC 8032, pure) with the strict verification rule of spec §3.5, defined by the spec and not by a
//! library: RFC 8032 §5.1.7 with the cofactorless equation `[S]B = R + [k]A`, and rejection of `S ≥ L`, of
//! non-canonical encodings of `A` or `R` (y-coordinate ≥ p), and of small-order `A` or `R` (order dividing 8,
//! including the identity).
//!
//! What `ed25519-dalek` 3.0.0 `verify_strict` does by itself (source read, M1): it rejects `S ≥ L`
//! (`Scalar::from_canonical_bytes`), small-order `A` and `R` (`is_small_order`), and — implicitly — a
//! non-canonical `R` (it compares the canonical encoding of the recomputed `R` with the received bytes), using
//! the cofactorless equation. It **accepts a non-canonical `A`**: `CompressedEdwardsY::decompress` reduces
//! y modulo p. Following the spec ("implementations whose library does less MUST add the missing checks on the
//! encoded bytes before verifying") every rule is checked here on the bytes first — `A` on import, `R` and `S`
//! before verification — and `verify_strict` runs afterwards.

use core::fmt;

use ed25519_dalek::Signer as _;

use crate::error::{Error, Result};
use crate::secret::LockedSecret;

/// Length of an Ed25519 public key.
pub const ED25519_PK_LEN: usize = 32;
/// Length of an Ed25519 seed (the RFC 8032 private key).
pub const ED25519_SEED_LEN: usize = 32;
/// Length of an Ed25519 signature `R ‖ S`.
pub const ED25519_SIG_LEN: usize = 64;

/// Byte-level encoding rules of spec §3.5.
mod strict {
    /// p = 2^255 − 19, little-endian.
    const P: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    /// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// The y-coordinates (little-endian, sign bit clear) of the eight points of order dividing 8: the
    /// identity (y = 1), the point of order 2 (y = p − 1), the two of order 4 (y = 0) and the four of order 8
    /// (two y values, each with both signs of x).
    const SMALL_ORDER_Y: [[u8; 32]; 5] = [
        [0; 32],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
    ];

    /// `a < b` for 32-byte little-endian integers (public values; not constant time).
    fn less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
        a.iter().rev().cmp(b.iter().rev()).is_lt()
    }

    /// The y-coordinate of an encoded point (sign bit of x cleared).
    fn y_of(enc: &[u8; 32]) -> [u8; 32] {
        let mut y = *enc;
        y[31] &= 0x7f;
        y
    }

    /// The encoding is canonical: y < p.
    pub(super) fn is_canonical_point(enc: &[u8; 32]) -> bool {
        less_than(&y_of(enc), &P)
    }

    /// The (canonical) encoding denotes a point of order dividing 8.
    pub(super) fn is_small_order(enc: &[u8; 32]) -> bool {
        SMALL_ORDER_Y.contains(&y_of(enc))
    }

    /// `S < L`.
    pub(super) fn is_canonical_scalar(s: &[u8; 32]) -> bool {
        less_than(s, &L)
    }

    /// An acceptable `A` or `R`: canonical and not of small order.
    pub(super) fn point_ok(enc: &[u8; 32]) -> bool {
        is_canonical_point(enc) && !is_small_order(enc)
    }

    /// The byte-level rules for a signature `R ‖ S`: `R` acceptable and `S < L`.
    pub(super) fn signature_ok(r: &[u8; 32], s: &[u8; 32]) -> bool {
        point_ok(r) && is_canonical_scalar(s)
    }

    #[cfg(test)]
    pub(super) const L_BYTES: [u8; 32] = L;
    #[cfg(test)]
    pub(super) const SMALL_ORDER: [[u8; 32]; 5] = SMALL_ORDER_Y;
}

/// An Ed25519 signing key, held as its 32-byte seed in locked memory.
pub struct Ed25519SigningKey(LockedSecret<ED25519_SEED_LEN>);

impl Ed25519SigningKey {
    /// A new random key.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if randomness or locked memory is unavailable.
    pub fn generate() -> Result<Self> {
        Ok(Self(LockedSecret::random()?))
    }

    /// The key with the given 32-byte seed.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `seed` is 32 bytes long; [`Error::Unavailable`] if locked memory is
    /// unavailable.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self(LockedSecret::from_slice(seed)?))
    }

    fn dalek(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(self.0.expose_secret())
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        let vk = self.dalek().verifying_key();
        Ed25519VerifyingKey {
            bytes: vk.to_bytes(),
            key: vk,
        }
    }

    /// Pure Ed25519 signature of `msg` (RFC 8032; deterministic).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; ED25519_SIG_LEN] {
        self.dalek().sign(msg).to_bytes()
    }
}

/// An Ed25519 verifying key that passed the import rules of spec §3.5 (canonical, not of small order).
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519VerifyingKey {
    bytes: [u8; ED25519_PK_LEN],
    key: ed25519_dalek::VerifyingKey,
}

impl Ed25519VerifyingKey {
    /// Import a public key `A`.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 32 bytes long, a canonical encoding (y < p), not of small order,
    /// and a point on the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; ED25519_PK_LEN] = bytes.try_into().map_err(|_| Error::Rejected)?;
        if !strict::point_ok(&bytes) {
            return Err(Error::Rejected);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Rejected)?;
        Ok(Self { bytes, key })
    }

    /// The encoded key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_PK_LEN] {
        &self.bytes
    }

    /// Strict verification of spec §3.5.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `sig` is 64 bytes, `R` is canonical and not of small order, `S < L`, and
    /// `[S]B = R + [k]A` holds.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let sig: [u8; ED25519_SIG_LEN] = sig.try_into().map_err(|_| Error::Rejected)?;
        let (r, s) = sig.split_at(32);
        let r: [u8; 32] = r.try_into().map_err(|_| Error::Rejected)?;
        let s: [u8; 32] = s.try_into().map_err(|_| Error::Rejected)?;
        if !strict::signature_ok(&r, &s) {
            return Err(Error::Rejected);
        }
        self.key
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| Error::Rejected)
    }
}

impl fmt::Debug for Ed25519VerifyingKey {
    /// Redacted: key bytes never reach logs (docs/04 CS-2.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519VerifyingKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex, unhex, unhex_n};

    /// RFC 8032 §7.1 tests 1–3.
    #[test]
    fn rfc8032_vectors() -> Result<()> {
        for (sk, pk, msg, sig) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ] {
            let key = Ed25519SigningKey::from_seed(&unhex_n::<32>(sk))?;
            let vk = key.verifying_key();
            assert_eq!(hex(vk.as_bytes()), pk);
            let msg = unhex(msg).unwrap_or_default();
            let s = key.sign(&msg);
            assert_eq!(hex(&s), sig);
            vk.verify(&msg, &s)?;
            assert_eq!(
                Ed25519VerifyingKey::from_bytes(&unhex_n::<32>(pk))?,
                vk,
                "import of an honest key"
            );
        }
        Ok(())
    }

    fn signed() -> Result<(Ed25519VerifyingKey, Vec<u8>, [u8; 64])> {
        let key = Ed25519SigningKey::generate()?;
        let msg = b"strict".to_vec();
        let sig = key.sign(&msg);
        Ok((key.verifying_key(), msg, sig))
    }

    #[test]
    fn wrong_message_signature_or_length() -> Result<()> {
        let (vk, msg, sig) = signed()?;
        vk.verify(&msg, &sig)?;
        assert_eq!(vk.verify(b"strict!", &sig).err(), Some(Error::Rejected));
        for i in [0, 31, 32, 63] {
            let mut bad = sig;
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            assert_eq!(
                vk.verify(&msg, &bad).err(),
                Some(Error::Rejected),
                "byte {i}"
            );
        }
        assert_eq!(vk.verify(&msg, &sig[..63]).err(), Some(Error::Rejected));
        assert_eq!(
            Ed25519VerifyingKey::from_bytes(&[1; 31]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            Ed25519SigningKey::from_seed(&[1; 33]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(format!("{vk:?}"), "Ed25519VerifyingKey(..)");
        Ok(())
    }

    /// `S + L` (vectors/SCHEMA.md §4.5 row 14) is rejected; `ed25519-dalek` alone rejects it as well.
    #[test]
    fn s_plus_l_is_rejected() -> Result<()> {
        let (vk, msg, sig) = signed()?;
        let mut s = [0_u8; 32];
        s.copy_from_slice(&sig[32..]);
        let mut carry = 0_u16;
        for (x, l) in s.iter_mut().zip(strict::L_BYTES) {
            let v = u16::from(*x).wrapping_add(u16::from(l)).wrapping_add(carry);
            *x = v.to_le_bytes()[0];
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "S + L < 2^256 for a canonical S");
        let mut bad = sig;
        bad[32..].copy_from_slice(&s);
        assert!(!strict::is_canonical_scalar(&s));
        assert_eq!(vk.verify(&msg, &bad).err(), Some(Error::Rejected));
        assert!(
            vk.key
                .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&bad))
                .is_err()
        );
        Ok(())
    }

    /// Small-order and non-canonical public keys (rows 15–16) are refused on import. `ed25519-dalek` would
    /// decompress the non-canonical ones (`VerifyingKey::from_bytes` succeeds): the byte-level check is needed.
    #[test]
    fn small_order_and_non_canonical_keys_are_refused() {
        // the identity, and y = 1 encoded as p + 1 (non-canonical)
        for enc in [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            assert_eq!(
                Ed25519VerifyingKey::from_bytes(&unhex_n::<32>(enc)).err(),
                Some(Error::Rejected),
                "{enc}"
            );
        }
        // every small-order y with both signs of x, where the encoding decodes at all
        for y in strict::SMALL_ORDER {
            for sign in [0x00, 0x80] {
                let mut enc = y;
                enc[31] |= sign;
                if let Ok(k) = ed25519_dalek::VerifyingKey::from_bytes(&enc) {
                    assert!(
                        k.is_weak(),
                        "dalek agrees that {} is small-order",
                        hex(&enc)
                    );
                }
                assert!(strict::is_small_order(&enc));
                assert_eq!(
                    Ed25519VerifyingKey::from_bytes(&enc).err(),
                    Some(Error::Rejected)
                );
            }
        }
        // non-canonical encodings y = p + t, t = 2..=18, of large-order points: dalek decompresses them
        let mut dalek_accepts = 0;
        for t in 2_u8..=18 {
            let mut enc = [0xff_u8; 32];
            enc[0] = 0xed_u8.wrapping_add(t);
            enc[31] = 0x7f;
            assert!(!strict::is_canonical_point(&enc));
            assert_eq!(
                Ed25519VerifyingKey::from_bytes(&enc).err(),
                Some(Error::Rejected)
            );
            if ed25519_dalek::VerifyingKey::from_bytes(&enc).is_ok_and(|k| !k.is_weak()) {
                dalek_accepts += 1;
            }
        }
        assert!(
            dalek_accepts > 0,
            "the gap in the library that the byte check closes"
        );
    }

    /// A signature whose `R` is small-order or non-canonical is rejected before the library runs.
    #[test]
    fn bad_r_is_rejected() -> Result<()> {
        let (vk, msg, sig) = signed()?;
        for r in [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let mut bad = sig;
            bad[..32].copy_from_slice(&unhex_n::<32>(r));
            assert_eq!(vk.verify(&msg, &bad).err(), Some(Error::Rejected));
        }
        Ok(())
    }

    #[test]
    fn canonical_edges() {
        let mut p_minus_1 = [0xff_u8; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        assert!(strict::is_canonical_point(&p_minus_1));
        let mut p = p_minus_1;
        p[0] = 0xed;
        assert!(!strict::is_canonical_point(&p));
        let mut l_minus_1 = strict::L_BYTES;
        l_minus_1[0] = 0xec;
        assert!(strict::is_canonical_scalar(&l_minus_1));
        assert!(!strict::is_canonical_scalar(&strict::L_BYTES));
        assert!(strict::is_canonical_scalar(&[0; 32]));
        // the most significant differing byte decides, not the first one
        let mut high = [0_u8; 32];
        high[31] = 1;
        let mut low = [0xff_u8; 32];
        low[31] = 0;
        assert!(strict::is_canonical_scalar(&low) && !strict::is_canonical_scalar(&[0xff; 32]));
        assert!(strict::is_canonical_point(&high) && strict::is_canonical_point(&low));
    }

    /// The byte-level signature rules on their own: `ed25519-dalek`'s `verify_strict` rejects the same inputs,
    /// so these checks (spec §3.5 "add the missing checks on the encoded bytes") are tested directly.
    #[test]
    fn signature_byte_rules() -> Result<()> {
        let (_, _, sig) = signed()?;
        let (r, s) = sig.split_at(32);
        let r: [u8; 32] = r.try_into().map_err(|_| Error::Rejected)?;
        let s: [u8; 32] = s.try_into().map_err(|_| Error::Rejected)?;
        assert!(strict::signature_ok(&r, &s));
        assert!(!strict::signature_ok(&r, &strict::L_BYTES), "S = L");
        let identity =
            unhex_n::<32>("0100000000000000000000000000000000000000000000000000000000000000");
        assert!(!strict::signature_ok(&identity, &s), "small-order R");
        let non_canonical =
            unhex_n::<32>("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(!strict::signature_ok(&non_canonical, &s), "R with y >= p");
        assert!(!strict::signature_ok(&identity, &strict::L_BYTES));
        Ok(())
    }
}
