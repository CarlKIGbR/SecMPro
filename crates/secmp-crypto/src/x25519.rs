// SPDX-License-Identifier: AGPL-3.0-or-later
//! X25519 (RFC 7748; spec §3 table). Inputs are handled exactly per RFC 7748 §5: the top bit of the received
//! u-coordinate is masked, non-canonical u is accepted and the scalar is clamped (all inside `x25519-dalek`).
//! **An all-zero output is rejected** — this covers every low-order input (CLAUDE.md §5). Public keys are the
//! 32 bytes as received; they are hashed and transmitted unchanged.

use core::fmt;

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};
use crate::secret::{LockedSecret, SecretBytes};

/// Length of X25519 public keys, secrets and shared secrets.
pub const X25519_LEN: usize = 32;

/// An X25519 secret (32 raw bytes, clamped inside X25519) in locked memory.
pub struct X25519Secret(LockedSecret<X25519_LEN>);

impl X25519Secret {
    /// A new random secret.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if randomness or locked memory is unavailable.
    pub fn generate() -> Result<Self> {
        Ok(Self(LockedSecret::random()?))
    }

    /// The secret with the given 32 raw bytes (e.g. from storage or a test vector).
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 32 bytes long; [`Error::Unavailable`] if locked memory is
    /// unavailable.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(LockedSecret::from_slice(bytes)?))
    }

    fn dalek(&self) -> StaticSecret {
        StaticSecret::from(*self.0.expose_secret())
    }

    /// The public key `X25519(secret, 9)`.
    #[must_use]
    pub fn public_key(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.dalek()).to_bytes())
    }

    /// `X25519(secret, peer)`.
    ///
    /// # Errors
    /// [`Error::Rejected`] if the result is all zero (a low-order `peer`), compared in constant time.
    pub fn diffie_hellman(&self, peer: &X25519Public) -> Result<SecretBytes<X25519_LEN>> {
        let shared = self.dalek().diffie_hellman(&PublicKey::from(peer.0));
        let out = SecretBytes::from_slice(shared.as_bytes())?;
        if bool::from(out.expose_secret().ct_eq(&[0; X25519_LEN])) {
            return Err(Error::Rejected);
        }
        Ok(out)
    }
}

/// An X25519 public key: the 32 bytes as received (RFC 7748: every 32-byte string is accepted as input).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X25519Public([u8; X25519_LEN]);

/// The low-order u-coordinates after RFC 7748 decoding with bit 255 cleared: 0, 1, p − 1, the two points of order
/// 8, and the non-canonical encodings p (≡ 0) and p + 1 (≡ 1) — every other reduced value is not of low order and
/// every other non-canonical value (u ≥ p + 2) reduces to 2 … 18, which are not low order either. With bit 255 set
/// or clear these are the 14 encodings of spec §4.1 decoder obligation (a) (`vectors/SCHEMA-4.8-encodings.md`
/// D-9). Little-endian.
const LOW_ORDER_MASKED: [[u8; X25519_LEN]; 7] = [
    // 0
    [0; 32],
    // 1
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // p − 1
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // order 8
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // order 8
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p (≡ 0)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (≡ 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

impl X25519Public {
    /// The public key with these 32 bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Rejected)?))
    }

    /// The public key with these 32 bytes, as a decoder receives it (spec §4.1 decoder obligation (a)): a
    /// low-order value — after RFC 7748 decoding (bit 255 masked, u reduced mod p) u ∈ {0, 1, p − 1, the two
    /// u-coordinates of order 8} — is refused; every other value, non-canonical u and bit 255 set included, is
    /// kept as received. A key refused here is exactly one whose X25519 output is all zero for every scalar, so
    /// the check at use ([`X25519Secret::diffie_hellman`]) stays in force and agrees with it.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 32 bytes long and not of low order.
    pub fn from_bytes_checked(bytes: &[u8]) -> Result<Self> {
        let key = Self::from_bytes(bytes)?;
        let mut masked = key.0;
        if let Some(top) = masked.last_mut() {
            *top &= 0x7f;
        }
        if LOW_ORDER_MASKED.contains(&masked) {
            return Err(Error::Rejected);
        }
        Ok(key)
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; X25519_LEN] {
        &self.0
    }
}

impl fmt::Debug for X25519Public {
    /// Redacted: key bytes never reach logs (docs/04 CS-2.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Public(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex, unhex_n};

    /// RFC 7748 §6.1.
    #[test]
    fn rfc7748_diffie_hellman() -> Result<()> {
        let a = X25519Secret::from_bytes(&unhex_n::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ))?;
        let b = X25519Secret::from_bytes(&unhex_n::<32>(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ))?;
        assert_eq!(
            hex(a.public_key().as_bytes()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(b.public_key().as_bytes()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let k1 = a.diffie_hellman(&b.public_key())?;
        let k2 = b.diffie_hellman(&a.public_key())?;
        assert_eq!(
            hex(k1.expose_secret()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        assert_eq!(k1.expose_secret(), k2.expose_secret());
        Ok(())
    }

    /// RFC 7748 §5.2 vector 2: the u-coordinate has its top bit set, which is masked (spec §3 table).
    #[test]
    fn rfc7748_top_bit_masked() -> Result<()> {
        let k = X25519Secret::from_bytes(&unhex_n::<32>(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        ))?;
        let u = X25519Public::from_bytes(&unhex_n::<32>(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        ))?;
        assert_eq!(
            hex(k.diffie_hellman(&u)?.expose_secret()),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
        Ok(())
    }

    /// Low-order inputs (u = 0, u = 1, the order-8 point, u = p − 1, and non-canonical u = p, p + 1)
    /// yield the all-zero output and are rejected.
    #[test]
    fn low_order_inputs_are_rejected() -> Result<()> {
        let k = X25519Secret::generate()?;
        for u in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let p = X25519Public::from_bytes(&unhex_n::<32>(u))?;
            assert_eq!(k.diffie_hellman(&p).err(), Some(Error::Rejected), "{u}");
        }
        Ok(())
    }

    /// Spec §4.1 decoder obligation (a): the 14 low-order encodings (the seven masked values of
    /// `LOW_ORDER_MASKED`, bit 255 clear and set) are refused at decode, and each of them is exactly an input
    /// whose X25519 output is all zero; everything else is kept as received.
    #[test]
    fn decode_refuses_exactly_the_low_order_encodings() -> Result<()> {
        let k = X25519Secret::generate()?;
        let mut refused = 0_usize;
        for masked in LOW_ORDER_MASKED {
            for top in [0x00_u8, 0x80] {
                let mut u = masked;
                u[31] |= top;
                assert_eq!(
                    X25519Public::from_bytes_checked(&u).err(),
                    Some(Error::Rejected)
                );
                let p = X25519Public::from_bytes(&u)?;
                assert_eq!(k.diffie_hellman(&p).err(), Some(Error::Rejected));
                refused = refused.saturating_add(1);
            }
        }
        assert_eq!(refused, 14);
        // accepted and kept as received: a real key, the same key with bit 255 set, u = 2, u = p + 2 (≡ 2),
        // u = 2^255 − 1 (≡ 18), u = 9
        let real = *k.public_key().as_bytes();
        let mut real_top = real;
        real_top[31] |= 0x80;
        for u in [
            real,
            real_top,
            unhex_n::<32>("0200000000000000000000000000000000000000000000000000000000000000"),
            unhex_n::<32>("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            unhex_n::<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            unhex_n::<32>("0900000000000000000000000000000000000000000000000000000000000000"),
        ] {
            let p = X25519Public::from_bytes_checked(&u)?;
            assert_eq!(p.as_bytes(), &u);
            assert!(k.diffie_hellman(&p).is_ok());
        }
        assert_eq!(
            X25519Public::from_bytes_checked(&real[..31]).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }

    #[test]
    fn lengths_and_debug() -> Result<()> {
        assert_eq!(
            X25519Public::from_bytes(&[0; 31]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            X25519Public::from_bytes(&[0; 33]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            X25519Secret::from_bytes(&[1; 31]).err(),
            Some(Error::Rejected)
        );
        let p = X25519Secret::generate()?.public_key();
        assert_eq!(format!("{p:?}"), "X25519Public(..)");
        Ok(())
    }
}
