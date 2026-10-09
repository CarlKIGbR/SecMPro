// SPDX-License-Identifier: AGPL-3.0-or-later
//! D.4 — handshake envelope (spec §6.5):
//!
//! - `Outer = ver ‖ ek_I[32] ‖ spk_id u32 ‖ opk_id u32 ‖ ct_spk[1568] ‖ ct_opk[1568] ‖ inner_ct[6185]` (9362 B),
//!   padded to 12018 B.
//! - `inner_ct = N2[24] ‖ COM[32] ‖ ct[6113 + 16]` and `HandshakeCell = N_i[24] ‖ COM[32] ‖ ct[4024 + 16]` are
//!   opaque (length only).
//! - `Inner = IKSPublic ‖ first_msg[4096]` and `HandshakeCellPlaintext = init_id[16] ‖ i u8 (0..=2) ‖ total u8 (3)
//!   ‖ chunk[4006]` are the plaintexts inside them.

use crate::codec::{Decode, Encode, Reader, Writer, decode_padded, encode_padded};
use crate::error::{Error, Result};
use crate::keys::X25519Pk;
use crate::sizes::{
    COM_LEN, HANDSHAKE_CELL_CT_LEN, HANDSHAKE_CHUNK_LEN, HANDSHAKE_CHUNKS, INNER_CT_CT_LEN,
    MLKEM1024_CT_LEN, NONCE_LEN, OUTER_PADDED_LEN,
};
use crate::wire::cell::Cell;
use crate::wire::inv::IksPublic;
use crate::wire::{Id, read_ver, write_ver};

/// `inner_ct = N2[24] ‖ COM[32] ‖ ct[6129]` (6185 B).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct InnerCt {
    /// CAEAD nonce.
    pub n2: [u8; NONCE_LEN],
    /// CAEAD commitment.
    pub com: [u8; COM_LEN],
    /// Ciphertext of `Inner` with its tag.
    pub ct: Box<[u8; INNER_CT_CT_LEN]>,
}

impl Encode for InnerCt {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.n2);
        w.bytes(&self.com);
        w.bytes(self.ct.as_slice());
        Ok(())
    }
}

impl Decode for InnerCt {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            n2: r.array()?,
            com: r.array()?,
            ct: r.boxed()?,
        })
    }
}

/// `Outer` (spec §6.5), padded to 12018 bytes.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Outer {
    /// The initiator's ephemeral X25519 key.
    pub ek_i: X25519Pk,
    /// The responder's signed-prekey id.
    pub spk_id: u32,
    /// The responder's one-time-prekey id.
    pub opk_id: u32,
    /// ML-KEM-1024 ciphertext to `SPK_kem`.
    pub ct_spk: Box<[u8; MLKEM1024_CT_LEN]>,
    /// ML-KEM-1024 ciphertext to `OPK_kem`.
    pub ct_opk: Box<[u8; MLKEM1024_CT_LEN]>,
    /// The sealed `Inner`.
    pub inner_ct: InnerCt,
}

struct OuterFields<'a>(&'a Outer);

impl Encode for OuterFields<'_> {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let o = self.0;
        write_ver(w);
        o.ek_i.encode_to(w)?;
        w.u32(o.spk_id);
        w.u32(o.opk_id);
        w.bytes(o.ct_spk.as_slice());
        w.bytes(o.ct_opk.as_slice());
        o.inner_ct.encode_to(w)
    }
}

struct OuterDecoded(Outer);

impl Decode for OuterDecoded {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        Ok(Self(Outer {
            ek_i: X25519Pk::decode_from(r)?,
            spk_id: r.u32()?,
            opk_id: r.u32()?,
            ct_spk: r.boxed()?,
            ct_opk: r.boxed()?,
            inner_ct: InnerCt::decode_from(r)?,
        }))
    }
}

impl Encode for Outer {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&encode_padded(&OuterFields(self), OUTER_PADDED_LEN)?);
        Ok(())
    }
}

impl Decode for Outer {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(decode_padded::<OuterDecoded>(r.take(OUTER_PADDED_LEN)?, OUTER_PADDED_LEN)?.0)
    }
}

/// `Inner = IKSPublic ‖ first_msg` (6113 B): the initiator's identity and its first TR cell.
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Inner {
    /// `IKSPublic_I`.
    pub iks: IksPublic,
    /// The first SecMP-TR cell (Content type Handshake).
    pub first_msg: Cell,
}

impl Encode for Inner {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        self.iks.encode_to(w)?;
        self.first_msg.encode_to(w)
    }
}

impl Decode for Inner {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            iks: IksPublic::decode_from(r)?,
            first_msg: Cell::decode_from(r)?,
        })
    }
}

/// `HandshakeCell_i = N_i[24] ‖ COM[32] ‖ ct[4040]` (4096 B).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct HandshakeCell {
    /// CAEAD nonce.
    pub n: [u8; NONCE_LEN],
    /// CAEAD commitment.
    pub com: [u8; COM_LEN],
    /// Ciphertext of the plaintext with its tag.
    pub ct: Box<[u8; HANDSHAKE_CELL_CT_LEN]>,
}

impl Encode for HandshakeCell {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.n);
        w.bytes(&self.com);
        w.bytes(self.ct.as_slice());
        Ok(())
    }
}

impl Decode for HandshakeCell {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            n: r.array()?,
            com: r.array()?,
            ct: r.boxed()?,
        })
    }
}

/// `init_id[16] ‖ i u8 ‖ total u8 (= 3) ‖ chunk[4006]` (4024 B), the plaintext of a handshake cell. `total` is
/// always 3 and is not a field.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct HandshakeCellPlaintext {
    /// Groups the three chunks of one envelope.
    pub init_id: Id,
    /// Chunk index 0, 1 or 2.
    pub i: u8,
    /// `Padded[i·4006 .. (i+1)·4006]`.
    pub chunk: Box<[u8; HANDSHAKE_CHUNK_LEN]>,
}

impl Encode for HandshakeCellPlaintext {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        if self.i >= HANDSHAKE_CHUNKS {
            return Err(Error::Rejected);
        }
        w.bytes(&self.init_id);
        w.u8(self.i);
        w.u8(HANDSHAKE_CHUNKS);
        w.bytes(self.chunk.as_slice());
        Ok(())
    }
}

impl Decode for HandshakeCellPlaintext {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let init_id = r.array()?;
        let i = r.u8()?;
        if i >= HANDSHAKE_CHUNKS {
            return Err(Error::Rejected);
        }
        r.expect(HANDSHAKE_CHUNKS)?;
        Ok(Self {
            init_id,
            i,
            chunk: r.boxed()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sizes::{CELL_LEN, OUTER_LEN};
    use crate::wire::inv::tests::iks;
    use crate::wire::testutil::{exact_fit, round_trip, x25519};

    fn inner_ct() -> InnerCt {
        InnerCt {
            n2: [1; 24],
            com: [2; 32],
            ct: Box::new([3; INNER_CT_CT_LEN]),
        }
    }

    #[test]
    fn outer_is_padded_to_three_chunks() -> Result<()> {
        let o = Outer {
            ek_i: x25519(4)?,
            spk_id: u32::MAX,
            opk_id: 0,
            ct_spk: Box::new([5; MLKEM1024_CT_LEN]),
            ct_opk: Box::new([6; MLKEM1024_CT_LEN]),
            inner_ct: inner_ct(),
        };
        let bytes = round_trip(&o)?;
        assert_eq!(bytes.len(), OUTER_PADDED_LEN);
        assert_eq!(bytes.get(OUTER_LEN), Some(&0x80));
        exact_fit::<Outer>(&bytes);
        // the unpadded fields alone are not an Outer
        assert!(Outer::decode(bytes.get(..OUTER_LEN).unwrap_or_default()).is_err());
        Ok(())
    }

    #[test]
    fn opaque_and_inner_structures() -> Result<()> {
        assert_eq!(round_trip(&inner_ct())?.len(), crate::sizes::INNER_CT_LEN);
        let inner = Inner {
            iks: iks(7)?,
            first_msg: Cell::from_bytes(&[8; CELL_LEN])?,
        };
        let bytes = round_trip(&inner)?;
        assert_eq!(bytes.len(), crate::sizes::INNER_LEN);
        exact_fit::<Inner>(&bytes);
        let cell = HandshakeCell {
            n: [9; 24],
            com: [10; 32],
            ct: Box::new([11; HANDSHAKE_CELL_CT_LEN]),
        };
        assert_eq!(round_trip(&cell)?.len(), crate::sizes::HANDSHAKE_CELL_LEN);
        Ok(())
    }

    #[test]
    fn cell_plaintext_index_and_total() -> Result<()> {
        for i in 0..3 {
            let pt = HandshakeCellPlaintext {
                init_id: [12; 16],
                i,
                chunk: Box::new([13; HANDSHAKE_CHUNK_LEN]),
            };
            let bytes = round_trip(&pt)?;
            assert_eq!(bytes.len(), crate::sizes::HANDSHAKE_CELL_PT_LEN);
            exact_fit::<HandshakeCellPlaintext>(&bytes);
        }
        let bad = HandshakeCellPlaintext {
            init_id: [0; 16],
            i: 3,
            chunk: Box::new([0; HANDSHAKE_CHUNK_LEN]),
        };
        assert!(bad.encode().is_err());
        for (i, total) in [(3_u8, 3_u8), (0, 2), (0, 4), (0xff, 3)] {
            let mut w = Writer::new();
            w.bytes(&[0; 16]);
            w.u8(i);
            w.u8(total);
            w.bytes(&[0; HANDSHAKE_CHUNK_LEN]);
            assert!(HandshakeCellPlaintext::decode(&w.into_bytes()).is_err());
        }
        Ok(())
    }

    fn plaintext_bytes(i: u8, total: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&[0x11; 16]);
        w.u8(i);
        w.u8(total);
        w.bytes(&[0; HANDSHAKE_CHUNK_LEN]);
        w.into_bytes().to_vec()
    }

    /// V-3: `i` = `total` = 3 (an index outside 0..=2) is rejected by the decoder.
    #[test]
    fn cell_plaintext_decode_rejects_i_ge_total() {
        assert_eq!(
            HandshakeCellPlaintext::decode(&plaintext_bytes(3, 3)).err(),
            Some(Error::Rejected)
        );
        assert!(HandshakeCellPlaintext::decode(&plaintext_bytes(2, 3)).is_ok());
    }

    /// V-3: `total` ≠ 3 is rejected whatever `i` is.
    #[test]
    fn cell_plaintext_decode_rejects_total_ne_3() {
        for total in [0_u8, 2, 4, 0xff] {
            assert_eq!(
                HandshakeCellPlaintext::decode(&plaintext_bytes(0, total)).err(),
                Some(Error::Rejected)
            );
        }
    }
}
