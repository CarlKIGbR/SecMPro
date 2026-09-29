// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every structure of spec Appendix D (rev 2.3, ADR-039), with the decoding contract of
//! `vectors/SCHEMA-4.8-encodings.md` (D-1 … D-13):
//!
//! - [`record`] D.1 records before the link handshake; [`frame`] D.2 frame plaintexts (requests and responses);
//!   [`inv`] D.3 invitation, relay reference, link data; [`hx`] D.4 handshake envelope; [`cell`] D.5 ratchet cell,
//!   header, content and bodies; [`signed`] D.6 the signed command messages (encode only).
//! - Values that App. D fixes (a `ver`, a reserved zero field, a record type, `total = 3`, `caps = 0`) are not
//!   fields of the Rust types: they are written by the encoder and checked by the decoder, so a value has exactly
//!   one encoding. Optional parts are `Option`s and presence bytes are derived from them (spec §4.1).
//! - Secret fields (`link_key`, `inv_send_seed`, `send_seed`) are `SecretBytes`; the structures holding them have
//!   no `Clone`, `PartialEq` or `Debug`.
//! - `Debug` is available on the other structures only in this crate's unit tests (docs/04 CS-2.5: ids, cells
//!   and keys never reach logs).

pub mod cell;
pub mod frame;
pub mod hx;
pub mod inv;
pub mod record;
pub mod signed;

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Error, Result};
use crate::sizes::PROTO_VER;

/// A 16-byte identifier (`rid`, `sid`, `ld_id`, `msg_id`, `init_id`, `sess_id`).
pub type Id = [u8; 16];

/// Check the `ver` byte (spec §4.1: every structure App. D gives a `ver` field checks it on decode).
pub(crate) fn read_ver(r: &mut Reader<'_>) -> Result<()> {
    r.expect(PROTO_VER)
}

/// Write the `ver` byte.
pub(crate) fn write_ver(w: &mut Writer) {
    w.u8(PROTO_VER);
}

/// A send period ∈ `PERIODS` = {10, 20, 40, 80} s (spec §4.2; `inv_period_s`, `RelayQueue.period_s`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Period {
    /// 10 s.
    S10,
    /// 20 s.
    S20,
    /// 40 s.
    S40,
    /// 80 s.
    S80,
}

impl Period {
    /// All periods, ascending.
    pub const ALL: [Self; 4] = [Self::S10, Self::S20, Self::S40, Self::S80];

    /// The period in seconds.
    #[must_use]
    pub const fn seconds(self) -> u16 {
        match self {
            Self::S10 => 10,
            Self::S20 => 20,
            Self::S40 => 40,
            Self::S80 => 80,
        }
    }

    /// The period of `seconds`.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless `seconds` ∈ `PERIODS`.
    pub fn from_seconds(seconds: u16) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.seconds() == seconds)
            .ok_or(Error::Rejected)
    }
}

impl Encode for Period {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.u16(self.seconds());
        Ok(())
    }
}

impl Decode for Period {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_seconds(r.u16()?)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared helpers of the unit tests: deterministic keys and the round-trip checks.

    use crate::codec::{Decode, Encode};
    use crate::error::Result;
    use crate::keys::{Ed25519Pk, Ed25519Sig, HybridSig, MlKem768Ek, MlKem1024Ek, X25519Pk};

    pub(crate) fn x25519(seed: u8) -> Result<X25519Pk> {
        X25519Pk::from_bytes(
            secmp_crypto::X25519Secret::from_bytes(&[seed; 32])?
                .public_key()
                .as_bytes(),
        )
    }

    pub(crate) fn ed25519(seed: u8) -> Result<Ed25519Pk> {
        Ed25519Pk::from_bytes(
            secmp_crypto::Ed25519SigningKey::from_seed(&[seed; 32])?
                .verifying_key()
                .as_bytes(),
        )
    }

    pub(crate) fn sig(seed: u8) -> Result<Ed25519Sig> {
        Ed25519Sig::from_bytes(&secmp_crypto::Ed25519SigningKey::from_seed(&[seed; 32])?.sign(b"x"))
    }

    pub(crate) fn hybrid_sig(seed: u8) -> Result<HybridSig> {
        let sk = secmp_crypto::HybridSigningKey::from_seeds(&[seed; 32], &[seed; 32])?;
        HybridSig::from_bytes(
            sk.sign(secmp_crypto::Label::HxBundle, b"x")?
                .as_bytes()
                .as_slice(),
        )
    }

    pub(crate) fn ek768(seed: u8) -> Result<MlKem768Ek> {
        MlKem768Ek::from_bytes(
            secmp_crypto::MlKem768Dk::from_seed(&[seed; 64])?
                .encapsulation_key()
                .as_bytes(),
        )
    }

    pub(crate) fn ek1024(seed: u8) -> Result<MlKem1024Ek> {
        MlKem1024Ek::from_bytes(
            secmp_crypto::MlKem1024Dk::from_seed(&[seed; 64])?
                .encapsulation_key()
                .as_bytes(),
        )
    }

    /// `decode(encode(x)) == x` and `encode(decode(b)) == b`; returns the encoding.
    pub(crate) fn round_trip<T: Encode + Decode + PartialEq + core::fmt::Debug>(
        x: &T,
    ) -> Result<Vec<u8>> {
        let bytes = x.encode()?;
        let back = T::decode(&bytes)?;
        assert_eq!(&back, x);
        assert_eq!(back.encode()?, bytes);
        Ok(bytes)
    }

    /// The same for types without `PartialEq` (secret fields): the encoding is injective, so equal encodings
    /// mean equal values.
    pub(crate) fn round_trip_bytes<T: Encode + Decode>(x: &T) -> Result<Vec<u8>> {
        let bytes = x.encode()?;
        assert_eq!(T::decode(&bytes)?.encode()?, bytes);
        Ok(bytes)
    }

    /// Every strict prefix and the input with one appended byte are rejected (D-1).
    pub(crate) fn exact_fit<T: Decode>(bytes: &[u8]) {
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(T::decode(&longer).is_err(), "trailing byte");
        for n in [0, 1, bytes.len() / 2, bytes.len().saturating_sub(1)] {
            if let Some(prefix) = bytes.get(..n)
                && n < bytes.len()
            {
                assert!(T::decode(prefix).is_err(), "prefix {n}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods() {
        for p in Period::ALL {
            assert_eq!(Period::from_seconds(p.seconds()), Ok(p));
            assert_eq!(Period::decode(&p.seconds().to_be_bytes()), Ok(p));
        }
        for s in [0_u16, 9, 11, 15, 30, 160, 0xffff] {
            assert_eq!(Period::from_seconds(s), Err(Error::Rejected));
        }
    }
}
