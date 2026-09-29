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

impl X25519Public {
    /// The public key with these 32 bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `bytes` is 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Rejected)?))
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
