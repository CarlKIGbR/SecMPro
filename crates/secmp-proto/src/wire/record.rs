// SPDX-License-Identifier: AGPL-3.0-or-later
//! D.1 — records before the link handshake (spec §8.3): `Record = len u16 ‖ body`, where `len` covers the body
//! (the type byte included) and must be the record type's fixed body size (`SCHEMA-4.8` D-3). Each record decoder
//! expects its own type (D-6).

use crate::codec::{Decode, Encode, Reader, Writer, boxed};
use crate::error::{Error, Result};
use crate::keys::{Ed25519Pk, Ed25519Sig, MlKem768Ek, MlKem1024Ek, X25519Pk};
use crate::sizes::{
    HASH_LEN, HELLO_BODY_LEN, HS1_LEN, HS2_LEN, MLKEM768_CT_LEN, MLKEM1024_CT_LEN, PROTO_VER,
    RELAYINFO_LEN,
};
use crate::wire::{read_ver, write_ver};

/// Record type bytes (D.1).
pub mod record_type {
    /// `HELLO`.
    pub const HELLO: u8 = 0x01;
    /// `RELAYINFO`.
    pub const RELAYINFO: u8 = 0x02;
    /// `HS1`.
    pub const HS1: u8 = 0x03;
    /// `HS2`.
    pub const HS2: u8 = 0x04;
}

/// The `HELLO` magic.
const MAGIC: &[u8; 5] = b"SECMP";

/// The body of a record of `record_type` whose body (type byte included) is `body_len` bytes, positioned after
/// the type byte.
fn open_record<'a>(r: &mut Reader<'a>, record_type: u8, body_len: usize) -> Result<Reader<'a>> {
    let len = usize::from(r.u16()?);
    if len != body_len {
        return Err(Error::Rejected);
    }
    let mut body = Reader::new(r.take(len)?);
    body.expect(record_type)?;
    Ok(body)
}

/// Write `len ‖ type ‖ fields` for a body of `body_len` bytes (type byte included).
fn write_record(
    w: &mut Writer,
    record_type: u8,
    body_len: usize,
    fields: &impl Encode,
) -> Result<()> {
    let fields = fields.encode()?;
    // the fixed body size is the type byte plus the fields
    if Some(body_len) != fields.len().checked_add(1) {
        return Err(Error::Rejected);
    }
    w.u16(u16::try_from(body_len).map_err(|_| Error::Rejected)?);
    w.u8(record_type);
    w.bytes(&fields);
    Ok(())
}

/// `HELLO = 0x01 ‖ "SECMP" ‖ ver(0x01)` as a record (`len` = 7). It has no fields.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Hello;

struct HelloFields;

impl Encode for HelloFields {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(MAGIC);
        w.u8(PROTO_VER);
        Ok(())
    }
}

impl Encode for Hello {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_record(w, record_type::HELLO, HELLO_BODY_LEN, &HelloFields)
    }
}

impl Decode for Hello {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let mut body = open_record(r, record_type::HELLO, HELLO_BODY_LEN)?;
        if body.take(MAGIC.len())? != MAGIC {
            return Err(Error::Rejected);
        }
        read_ver(&mut body)?;
        body.finish()?;
        Ok(Self)
    }
}

/// `RelayInfoV1` (spec §8.2, D.1; 1741 B).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct RelayInfoV1 {
    /// The relay's long-term Ed25519 identity key.
    pub relay_sig_pk: Ed25519Pk,
    /// Key generation.
    pub kid: u32,
    /// Static X25519 key of generation `kid`.
    pub relay_dh_pk: X25519Pk,
    /// Static ML-KEM-1024 key of generation `kid`.
    pub relay_kem_ek: MlKem1024Ek,
    /// Access-key commitment (spec §9.6).
    pub akc: [u8; HASH_LEN],
    /// Unix seconds.
    pub valid_until: u64,
    /// `Ed25519(relay_sig, "SecMP-LINK/1 relayinfo" ‖ all preceding fields)` — verified at use.
    pub sig: Ed25519Sig,
}

impl Encode for RelayInfoV1 {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        self.relay_sig_pk.encode_to(w)?;
        w.u32(self.kid);
        self.relay_dh_pk.encode_to(w)?;
        self.relay_kem_ek.encode_to(w)?;
        w.bytes(&self.akc);
        w.u64(self.valid_until);
        self.sig.encode_to(w)
    }
}

impl Decode for RelayInfoV1 {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        Ok(Self {
            relay_sig_pk: Ed25519Pk::decode_from(r)?,
            kid: r.u32()?,
            relay_dh_pk: X25519Pk::decode_from(r)?,
            relay_kem_ek: MlKem1024Ek::decode_from(r)?,
            akc: r.array()?,
            valid_until: r.u64()?,
            sig: Ed25519Sig::decode_from(r)?,
        })
    }
}

impl RelayInfoV1 {
    /// The bytes the signature covers after the label: every field before `sig` (spec §8.2).
    ///
    /// # Errors
    /// None in practice (every field has a fixed width).
    pub fn signed_fields(&self) -> Result<Vec<u8>> {
        let all = self.encode()?;
        let n = RELAYINFO_LEN
            .checked_sub(crate::sizes::ED25519_SIG_LEN)
            .ok_or(Error::Rejected)?;
        Ok(all.get(..n).ok_or(Error::Rejected)?.to_vec())
    }
}

/// The `RELAYINFO` record: `0x02 ‖ RelayInfoV1` (`len` = 1742).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct RelayInfoRecord {
    /// The relay's info.
    pub relay_info: RelayInfoV1,
}

impl Encode for RelayInfoRecord {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let body_len = RELAYINFO_LEN.checked_add(1).ok_or(Error::Rejected)?;
        write_record(w, record_type::RELAYINFO, body_len, &self.relay_info)
    }
}

impl Decode for RelayInfoRecord {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let body_len = RELAYINFO_LEN.checked_add(1).ok_or(Error::Rejected)?;
        let mut body = open_record(r, record_type::RELAYINFO, body_len)?;
        let relay_info = RelayInfoV1::decode_from(&mut body)?;
        body.finish()?;
        Ok(Self { relay_info })
    }
}

/// `HS1 = 0x03 ‖ ver ‖ kid u32 ‖ e_c[32] ‖ ek_c[1184] ‖ pk_e1[32] ‖ ct_kem[1568] ‖ mac1[32]` (spec §8.3; `len` =
/// 2854).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Hs1 {
    /// The relay key generation the client encapsulates to.
    pub kid: u32,
    /// Client ephemeral X25519 key.
    pub e_c: X25519Pk,
    /// Client ephemeral ML-KEM-768 key.
    pub ek_c: MlKem768Ek,
    /// `HybridKEM-1024` ciphertext, X25519 part.
    pub pk_e1: X25519Pk,
    /// `HybridKEM-1024` ciphertext, ML-KEM part.
    pub ct_kem: Box<[u8; MLKEM1024_CT_LEN]>,
    /// Key confirmation.
    pub mac1: [u8; HASH_LEN],
}

struct Hs1Fields<'a>(&'a Hs1);

impl Encode for Hs1Fields<'_> {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let h = self.0;
        write_ver(w);
        w.u32(h.kid);
        h.e_c.encode_to(w)?;
        h.ek_c.encode_to(w)?;
        h.pk_e1.encode_to(w)?;
        w.bytes(h.ct_kem.as_slice());
        w.bytes(&h.mac1);
        Ok(())
    }
}

impl Encode for Hs1 {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let body_len = HS1_LEN.checked_add(1).ok_or(Error::Rejected)?;
        write_record(w, record_type::HS1, body_len, &Hs1Fields(self))
    }
}

impl Decode for Hs1 {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let body_len = HS1_LEN.checked_add(1).ok_or(Error::Rejected)?;
        let mut b = open_record(r, record_type::HS1, body_len)?;
        read_ver(&mut b)?;
        let value = Self {
            kid: b.u32()?,
            e_c: X25519Pk::decode_from(&mut b)?,
            ek_c: MlKem768Ek::decode_from(&mut b)?,
            pk_e1: X25519Pk::decode_from(&mut b)?,
            ct_kem: b.boxed()?,
            mac1: b.array()?,
        };
        b.finish()?;
        Ok(value)
    }
}

/// `HS2 = 0x04 ‖ ver ‖ e_r[32] ‖ ct_c[1088] ‖ mac2[32]` (spec §8.3; `len` = 1154).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Hs2 {
    /// Relay ephemeral X25519 key (the X25519 part of the `HybridKEM-768` ciphertext).
    pub e_r: X25519Pk,
    /// ML-KEM-768 ciphertext to `ek_c`.
    pub ct_c: Box<[u8; MLKEM768_CT_LEN]>,
    /// Key confirmation.
    pub mac2: [u8; HASH_LEN],
}

struct Hs2Fields<'a>(&'a Hs2);

impl Encode for Hs2Fields<'_> {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        self.0.e_r.encode_to(w)?;
        w.bytes(self.0.ct_c.as_slice());
        w.bytes(&self.0.mac2);
        Ok(())
    }
}

impl Encode for Hs2 {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let body_len = HS2_LEN.checked_add(1).ok_or(Error::Rejected)?;
        write_record(w, record_type::HS2, body_len, &Hs2Fields(self))
    }
}

impl Decode for Hs2 {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let body_len = HS2_LEN.checked_add(1).ok_or(Error::Rejected)?;
        let mut b = open_record(r, record_type::HS2, body_len)?;
        read_ver(&mut b)?;
        let value = Self {
            e_r: X25519Pk::decode_from(&mut b)?,
            ct_c: b.boxed()?,
            mac2: b.array()?,
        };
        b.finish()?;
        Ok(value)
    }
}

/// `Hs1.ct_kem` / `Hs2.ct_c` from a slice.
///
/// # Errors
/// [`Error::Rejected`] on a wrong length.
pub fn ciphertext<const N: usize>(bytes: &[u8]) -> Result<Box<[u8; N]>> {
    boxed(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testutil::{ed25519, ek768, ek1024, exact_fit, round_trip, sig, x25519};

    fn relay_info() -> Result<RelayInfoV1> {
        Ok(RelayInfoV1 {
            relay_sig_pk: ed25519(1)?,
            kid: 7,
            relay_dh_pk: x25519(2)?,
            relay_kem_ek: ek1024(3)?,
            akc: [4; 32],
            valid_until: u64::MAX,
            sig: sig(5)?,
        })
    }

    #[test]
    fn hello() -> Result<()> {
        let bytes = round_trip(&Hello)?;
        assert_eq!(*bytes, [0, 7, 1, b'S', b'E', b'C', b'M', b'P', 1]);
        exact_fit::<Hello>(&bytes);
        for bad in [
            [0, 6, 1, b'S', b'E', b'C', b'M', b'P', 1],
            [0, 7, 2, b'S', b'E', b'C', b'M', b'P', 1],
            [0, 7, 1, b's', b'E', b'C', b'M', b'P', 1],
            [0, 7, 1, b'S', b'E', b'C', b'M', b'P', 2],
        ] {
            assert_eq!(Hello::decode(&bad), Err(Error::Rejected));
        }
        Ok(())
    }

    #[test]
    fn relay_info_and_its_record() -> Result<()> {
        let info = relay_info()?;
        let bytes = round_trip(&info)?;
        assert_eq!(bytes.len(), RELAYINFO_LEN);
        exact_fit::<RelayInfoV1>(&bytes);
        assert_eq!(info.signed_fields()?.len(), 1677);
        let rec = round_trip(&RelayInfoRecord { relay_info: info })?;
        assert_eq!(rec.len(), 1744);
        assert_eq!(rec.get(..3), Some(&[0x06_u8, 0xce, 0x02][..]));
        exact_fit::<RelayInfoRecord>(&rec);
        // a HELLO record is not a RELAYINFO record
        assert!(RelayInfoRecord::decode(&Hello.encode()?).is_err());
        Ok(())
    }

    #[test]
    fn handshake_records() -> Result<()> {
        let hs1 = Hs1 {
            kid: u32::MAX,
            e_c: x25519(6)?,
            ek_c: ek768(7)?,
            pk_e1: x25519(8)?,
            ct_kem: ciphertext(&[9; MLKEM1024_CT_LEN])?,
            mac1: [10; 32],
        };
        let bytes = round_trip(&hs1)?;
        assert_eq!(bytes.len(), 2856);
        exact_fit::<Hs1>(&bytes);
        let hs2 = Hs2 {
            e_r: x25519(11)?,
            ct_c: ciphertext(&[12; MLKEM768_CT_LEN])?,
            mac2: [13; 32],
        };
        let bytes2 = round_trip(&hs2)?;
        assert_eq!(bytes2.len(), 1156);
        exact_fit::<Hs2>(&bytes2);
        assert!(Hs2::decode(&bytes).is_err() && Hs1::decode(&bytes2).is_err());
        assert!(ciphertext::<4>(&[1, 2, 3]).is_err());
        Ok(())
    }
}
