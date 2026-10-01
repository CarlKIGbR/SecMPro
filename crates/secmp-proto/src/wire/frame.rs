// SPDX-License-Identifier: AGPL-3.0-or-later
//! D.2 — frame plaintext (spec §8.4, §9.2–9.4): `op u8 ‖ cmd_seq u32 ‖ fields ‖ pad`, ISO/IEC 7816-4 padded to
//! exactly 4336 bytes. Requests (client → relay) and responses (relay → client) have their own decoders; an
//! opcode of the other direction, the reserved `SKEY` (0x02) and every unknown opcode reject (`SCHEMA-4.8` D-6).
//! A `CELLR` is decoded in the context of the request it answers (D.2: "For FETCH, rid is zero on present 0/1").

use crate::codec::{Decode, Encode, Reader, Writer, pad, unpad};
use crate::error::{Error, Result};
use crate::keys::{Ed25519Pk, Ed25519Sig};
use crate::sizes::{
    BLOB_PART_LEN, CONT_DATA_LEN, ED25519_SIG_LEN, FETCH_MULTI_MAX, FRAME_PLAINTEXT_LEN, HASH_LEN,
};
use crate::wire::Id;
use crate::wire::cell::Cell;

/// The opcode table of D.2, complete: every opcode App. D lists, by direction.
pub mod opcode {
    /// `QUEUE_NEW`.
    pub const QUEUE_NEW: u8 = 0x01;
    /// `SKEY` — reserved for v1.1 mailboxes; a v1 decoder rejects it.
    pub const SKEY: u8 = 0x02;
    /// `SEND`.
    pub const SEND: u8 = 0x03;
    /// `FETCH`.
    pub const FETCH: u8 = 0x04;
    /// `FETCH_MULTI`.
    pub const FETCH_MULTI: u8 = 0x05;
    /// `QUEUE_DEL`.
    pub const QUEUE_DEL: u8 = 0x06;
    /// `LINK_PUT`.
    pub const LINK_PUT: u8 = 0x07;
    /// `LINK_GET`.
    pub const LINK_GET: u8 = 0x08;
    /// `PING`.
    pub const PING: u8 = 0x09;
    /// `CONT` (request direction).
    pub const CONT: u8 = 0x7f;
    /// `OK`.
    pub const OK: u8 = 0x80;
    /// `OK_QUEUE_NEW`.
    pub const OK_QUEUE_NEW: u8 = 0x81;
    /// `OK_SEND`.
    pub const OK_SEND: u8 = 0x82;
    /// `CELLR`.
    pub const CELLR: u8 = 0x83;
    /// `LINKR`.
    pub const LINKR: u8 = 0x84;
    /// `ERR`.
    pub const ERR: u8 = 0x8f;
    /// `CONT` (response direction).
    pub const RESPONSE_CONT: u8 = 0xff;

    /// Request opcodes with their App. D names (`SKEY` is listed and reserved).
    pub const REQUESTS: [(u8, &str); 10] = [
        (QUEUE_NEW, "QUEUE_NEW"),
        (SKEY, "SKEY"),
        (SEND, "SEND"),
        (FETCH, "FETCH"),
        (FETCH_MULTI, "FETCH_MULTI"),
        (QUEUE_DEL, "QUEUE_DEL"),
        (LINK_PUT, "LINK_PUT"),
        (LINK_GET, "LINK_GET"),
        (PING, "PING"),
        (CONT, "CONT"),
    ];

    /// Response opcodes with their App. D names.
    pub const RESPONSES: [(u8, &str); 7] = [
        (OK, "OK"),
        (OK_QUEUE_NEW, "OK_QUEUE_NEW"),
        (OK_SEND, "OK_SEND"),
        (CELLR, "CELLR"),
        (LINKR, "LINKR"),
        (ERR, "ERR"),
        (RESPONSE_CONT, "CONT"),
    ];
}

/// A `FETCH_MULTI` entry `rid[16] ‖ ack u64 ‖ sig[64]`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct FetchEntry {
    /// The queue.
    pub rid: Id,
    /// Cumulative acknowledgement (spec §9.3).
    pub ack: u64,
    /// By that queue's recv key over `"SecMP-Q/1 MFETCH" ‖ sess_id ‖ cmd_seq ‖ rid ‖ ack` (D.6) — verified by the
    /// relay.
    pub sig: Ed25519Sig,
}

/// `LINK_GET` mode (D.2): consume (signature all zero) or owner status (signed by `owner_pk`).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum LinkGetMode {
    /// `mode = 0`: `sig` is 64 zero bytes.
    Consume,
    /// `mode = 1`: `sig` by the owner key.
    OwnerStatus(Ed25519Sig),
}

/// The index of a continuation frame: `LINK_PUT` and `LINKR` are v1's only multi-frame messages, with CONT frames
/// 1 and 2 (D.2; `SCHEMA-4.8` D-8).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum ContIdx {
    /// The second frame of the message.
    One,
    /// The third frame of the message.
    Two,
}

impl ContIdx {
    const fn byte(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(Error::Rejected),
        }
    }
}

/// `CONT = idx u8 ‖ data[4100]` (both directions).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Cont {
    /// 1 or 2.
    pub idx: ContIdx,
    /// The next 4100 bytes of the blob.
    pub data: Box<[u8; CONT_DATA_LEN]>,
}

impl Cont {
    fn encode_to(&self, w: &mut Writer) {
        w.u8(self.idx.byte());
        w.bytes(self.data.as_slice());
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            idx: ContIdx::from_byte(r.u8()?)?,
            data: r.boxed()?,
        })
    }
}

/// A request command and its fields (D.2).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum RequestCmd {
    /// `0x01 QUEUE_NEW recv_pk[32] ‖ send_pk[32] ‖ token[32] ‖ sig[64]`.
    QueueNew {
        /// Recipient key.
        recv_pk: Ed25519Pk,
        /// Sender key.
        send_pk: Ed25519Pk,
        /// Access token (spec §9.6).
        token: [u8; HASH_LEN],
        /// By the recv key.
        sig: Ed25519Sig,
    },
    /// `0x03 SEND sid[16] ‖ cell[4096] ‖ sig[64]`.
    Send {
        /// The queue's sender id.
        sid: Id,
        /// The cell.
        cell: Cell,
        /// By the send key.
        sig: Ed25519Sig,
    },
    /// `0x04 FETCH rid[16] ‖ ack u64 ‖ sig[64]`.
    Fetch {
        /// The queue.
        rid: Id,
        /// Cumulative acknowledgement.
        ack: u64,
        /// By the recv key.
        sig: Ed25519Sig,
    },
    /// `0x05 FETCH_MULTI count u8 (1..=32) ‖ { rid ‖ ack ‖ sig } × count`.
    FetchMulti {
        /// 1..=32 entries.
        entries: Vec<FetchEntry>,
    },
    /// `0x06 QUEUE_DEL rid[16] ‖ sig[64]`.
    QueueDel {
        /// The queue.
        rid: Id,
        /// By the recv key.
        sig: Ed25519Sig,
    },
    /// `0x07 LINK_PUT ld_id[16] ‖ one_time u8 ‖ expires_bucket u32 ‖ owner_pk[32] ‖ token[32] ‖ sig[64] ‖
    /// blob_part[4160]` (frame 1 of 3).
    LinkPut {
        /// Link-data id.
        ld_id: Id,
        /// One-time link data.
        one_time: bool,
        /// Expiry hour bucket.
        expires_bucket: u32,
        /// Owner key for owner-status queries.
        owner_pk: Ed25519Pk,
        /// Access token.
        token: [u8; HASH_LEN],
        /// By the owner key, over the fields and `SHA-256(blob)`.
        sig: Ed25519Sig,
        /// The first 4160 bytes of the blob.
        blob_part: Box<[u8; BLOB_PART_LEN]>,
    },
    /// `0x08 LINK_GET ld_id[16] ‖ mode u8 ‖ sig[64]` (zeros when mode = 0).
    LinkGet {
        /// Link-data id.
        ld_id: Id,
        /// Consume or owner status.
        mode: LinkGetMode,
    },
    /// `0x09 PING` (no fields).
    Ping,
    /// `0x7F CONT idx u8 ‖ data`.
    Cont(Cont),
}

impl RequestCmd {
    /// The opcode.
    #[must_use]
    pub const fn op(&self) -> u8 {
        match self {
            Self::QueueNew { .. } => opcode::QUEUE_NEW,
            Self::Send { .. } => opcode::SEND,
            Self::Fetch { .. } => opcode::FETCH,
            Self::FetchMulti { .. } => opcode::FETCH_MULTI,
            Self::QueueDel { .. } => opcode::QUEUE_DEL,
            Self::LinkPut { .. } => opcode::LINK_PUT,
            Self::LinkGet { .. } => opcode::LINK_GET,
            Self::Ping => opcode::PING,
            Self::Cont(_) => opcode::CONT,
        }
    }

    fn encode_fields(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::QueueNew {
                recv_pk,
                send_pk,
                token,
                sig,
            } => {
                recv_pk.encode_to(w)?;
                send_pk.encode_to(w)?;
                w.bytes(token);
                sig.encode_to(w)?;
            }
            Self::Send { sid, cell, sig } => {
                w.bytes(sid);
                cell.encode_to(w)?;
                sig.encode_to(w)?;
            }
            Self::Fetch { rid, ack, sig } => {
                w.bytes(rid);
                w.u64(*ack);
                sig.encode_to(w)?;
            }
            Self::FetchMulti { entries } => {
                if entries.is_empty() || entries.len() > FETCH_MULTI_MAX {
                    return Err(Error::Rejected);
                }
                w.u8(u8::try_from(entries.len()).map_err(|_| Error::Rejected)?);
                for e in entries {
                    w.bytes(&e.rid);
                    w.u64(e.ack);
                    e.sig.encode_to(w)?;
                }
            }
            Self::QueueDel { rid, sig } => {
                w.bytes(rid);
                sig.encode_to(w)?;
            }
            Self::LinkPut {
                ld_id,
                one_time,
                expires_bucket,
                owner_pk,
                token,
                sig,
                blob_part,
            } => {
                w.bytes(ld_id);
                w.flag(*one_time);
                w.u32(*expires_bucket);
                owner_pk.encode_to(w)?;
                w.bytes(token);
                sig.encode_to(w)?;
                w.bytes(blob_part.as_slice());
            }
            Self::LinkGet { ld_id, mode } => {
                w.bytes(ld_id);
                match mode {
                    LinkGetMode::Consume => {
                        w.u8(0);
                        w.bytes(&[0; ED25519_SIG_LEN]);
                    }
                    LinkGetMode::OwnerStatus(sig) => {
                        w.u8(1);
                        sig.encode_to(w)?;
                    }
                }
            }
            Self::Ping => {}
            Self::Cont(c) => c.encode_to(w),
        }
        Ok(())
    }

    /// The fields of command `op` (after `op ‖ cmd_seq`); crate-visible for the Kani harnesses.
    pub(crate) fn decode_fields(op: u8, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match op {
            opcode::QUEUE_NEW => Self::QueueNew {
                recv_pk: Ed25519Pk::decode_from(r)?,
                send_pk: Ed25519Pk::decode_from(r)?,
                token: r.array()?,
                sig: Ed25519Sig::decode_from(r)?,
            },
            opcode::SEND => Self::Send {
                sid: r.array()?,
                cell: Cell::decode_from(r)?,
                sig: Ed25519Sig::decode_from(r)?,
            },
            opcode::FETCH => Self::Fetch {
                rid: r.array()?,
                ack: r.u64()?,
                sig: Ed25519Sig::decode_from(r)?,
            },
            opcode::FETCH_MULTI => {
                let count = usize::from(r.u8()?);
                if count == 0 || count > FETCH_MULTI_MAX {
                    return Err(Error::Rejected);
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(FetchEntry {
                        rid: r.array()?,
                        ack: r.u64()?,
                        sig: Ed25519Sig::decode_from(r)?,
                    });
                }
                Self::FetchMulti { entries }
            }
            opcode::QUEUE_DEL => Self::QueueDel {
                rid: r.array()?,
                sig: Ed25519Sig::decode_from(r)?,
            },
            opcode::LINK_PUT => Self::LinkPut {
                ld_id: r.array()?,
                one_time: r.flag()?,
                expires_bucket: r.u32()?,
                owner_pk: Ed25519Pk::decode_from(r)?,
                token: r.array()?,
                sig: Ed25519Sig::decode_from(r)?,
                blob_part: r.boxed()?,
            },
            opcode::LINK_GET => {
                let ld_id = r.array()?;
                let mode = match r.u8()? {
                    0 => {
                        // consume mode: the signature field is all zero (D.2, D-7)
                        if r.array::<ED25519_SIG_LEN>()? != [0; ED25519_SIG_LEN] {
                            return Err(Error::Rejected);
                        }
                        LinkGetMode::Consume
                    }
                    1 => LinkGetMode::OwnerStatus(Ed25519Sig::decode_from(r)?),
                    _ => return Err(Error::Rejected),
                };
                Self::LinkGet { ld_id, mode }
            }
            opcode::PING => Self::Ping,
            opcode::CONT => Self::Cont(Cont::decode_from(r)?),
            // SKEY (reserved in v1), response opcodes and unknown opcodes
            _ => return Err(Error::Rejected),
        })
    }
}

/// Kani stub (`crate::kani_proofs::request_frame`): the request command decoder as "consume any number of bytes,
/// then accept or reject" — the frame-level glue (outer size, `unpad`, `op`, `cmd_seq`, trailing bytes) is proven
/// with it, each command decoder by its own harness.
#[cfg(kani)]
pub(crate) mod kani_stubs {
    use super::{Error, Reader, RequestCmd, Result};

    pub(crate) fn request_decode_fields(_op: u8, r: &mut Reader<'_>) -> Result<RequestCmd> {
        let consumed: usize = kani::any();
        r.take(consumed)?;
        if kani::any() {
            Ok(RequestCmd::Ping)
        } else {
            Err(Error::Rejected)
        }
    }
}

/// A request frame plaintext.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Request {
    /// Per-link command sequence number (spec §9.2).
    pub cmd_seq: u32,
    /// The command.
    pub cmd: RequestCmd,
}

impl Encode for Request {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let mut fields = Writer::new();
        fields.u8(self.cmd.op());
        fields.u32(self.cmd_seq);
        self.cmd.encode_fields(&mut fields)?;
        w.bytes(&pad(&fields.into_bytes(), FRAME_PLAINTEXT_LEN)?);
        Ok(())
    }
}

impl Decode for Request {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let mut f = Reader::new(unpad(r.take(FRAME_PLAINTEXT_LEN)?, FRAME_PLAINTEXT_LEN)?);
        let op = f.u8()?;
        let cmd_seq = f.u32()?;
        let cmd = RequestCmd::decode_fields(op, &mut f)?;
        f.finish()?;
        Ok(Self { cmd_seq, cmd })
    }
}

/// `ERR` codes (D.2).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum ErrCode {
    /// 1 TOKEN.
    Token,
    /// 2 FULL.
    Full,
    /// 3 NOQUEUE.
    NoQueue,
    /// 4 AUTH.
    Auth,
    /// 5 EXISTS.
    Exists,
    /// 6 MALFORMED.
    Malformed,
    /// 7 RATE.
    Rate,
}

impl ErrCode {
    /// All codes, in order.
    pub const ALL: [Self; 7] = [
        Self::Token,
        Self::Full,
        Self::NoQueue,
        Self::Auth,
        Self::Exists,
        Self::Malformed,
        Self::Rate,
    ];

    /// The code byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Token => 1,
            Self::Full => 2,
            Self::NoQueue => 3,
            Self::Auth => 4,
            Self::Exists => 5,
            Self::Malformed => 6,
            Self::Rate => 7,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.byte() == b)
            .ok_or(Error::Rejected)
    }
}

/// The error kinds a `CELLR` reports for a listed queue (`present` 2–4).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum CellrError {
    /// 2 NOQUEUE.
    NoQueue,
    /// 3 AUTH.
    Auth,
    /// 4 MALFORMED.
    Malformed,
}

/// A `CELLR` response `present u8 ‖ rid[16] ‖ cell_id u64 ‖ cell[4096]` (D.2).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum Cellr {
    /// `present = 0`: a dummy — `rid` and `cell_id` zero, `cell` random.
    Dummy {
        /// Random bytes.
        cell: Cell,
    },
    /// `present = 1`: a stored cell; in answer to `FETCH`, `rid` is zero.
    Cell {
        /// The queue (`FETCH_MULTI`), zero (`FETCH`).
        rid: Id,
        /// Per-queue cell id.
        cell_id: u64,
        /// The cell.
        cell: Cell,
    },
    /// `present` 2–4: an error for a listed queue — `rid` set, `cell_id` zero, `cell` random.
    Error {
        /// Which error.
        error: CellrError,
        /// The queue.
        rid: Id,
        /// Random bytes.
        cell: Cell,
    },
}

/// The request a `CELLR` answers.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum CellrContext {
    /// In answer to `FETCH`: `rid` is zero on `present` 0 and 1.
    Fetch,
    /// In answer to `FETCH_MULTI`.
    FetchMulti,
}

impl Cellr {
    fn encode_fields(&self, w: &mut Writer) -> Result<()> {
        let (present, rid, cell_id, cell) = match self {
            Self::Dummy { cell } => (0, [0; 16], 0, cell),
            Self::Cell { rid, cell_id, cell } => (1, *rid, *cell_id, cell),
            Self::Error { error, rid, cell } => {
                let present = match error {
                    CellrError::NoQueue => 2,
                    CellrError::Auth => 3,
                    CellrError::Malformed => 4,
                };
                (present, *rid, 0, cell)
            }
        };
        w.u8(present);
        w.bytes(&rid);
        w.u64(cell_id);
        cell.encode_to(w)
    }

    fn decode_fields(r: &mut Reader<'_>, context: CellrContext) -> Result<Self> {
        let present = r.u8()?;
        let rid: Id = r.array()?;
        let cell_id = r.u64()?;
        let cell = Cell::decode_from(r)?;
        let error = |e| {
            if cell_id == 0 {
                Ok(Self::Error {
                    error: e,
                    rid,
                    cell: cell.clone(),
                })
            } else {
                Err(Error::Rejected)
            }
        };
        match present {
            0 if rid == [0; 16] && cell_id == 0 => Ok(Self::Dummy { cell }),
            1 if context == CellrContext::FetchMulti || rid == [0; 16] => {
                Ok(Self::Cell { rid, cell_id, cell })
            }
            2 => error(CellrError::NoQueue),
            3 => error(CellrError::Auth),
            4 => error(CellrError::Malformed),
            _ => Err(Error::Rejected),
        }
    }
}

/// A response command and its fields (D.2).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum ResponseCmd {
    /// `0x80 OK`.
    Ok,
    /// `0x81 OK_QUEUE_NEW rid[16] ‖ sid[16]`.
    OkQueueNew {
        /// Recipient id.
        rid: Id,
        /// Sender id.
        sid: Id,
    },
    /// `0x82 OK_SEND cell_id u64 ‖ evicted_present u8 ‖ evicted_id u64` (`evicted_id` 0 when absent).
    OkSend {
        /// The stored cell's id.
        cell_id: u64,
        /// The evicted cell's id, if any.
        evicted: Option<u64>,
    },
    /// `0x83 CELLR`.
    Cellr(Cellr),
    /// `0x84 LINKR present u8 ‖ consumed u8 ‖ blob_part[4160]` (frame 1 of 3).
    LinkR {
        /// The link data exists.
        present: bool,
        /// The link data was consumed.
        consumed: bool,
        /// The first 4160 bytes of the blob (a dummy blob when absent).
        blob_part: Box<[u8; BLOB_PART_LEN]>,
    },
    /// `0x8F ERR code u8`.
    Err(ErrCode),
    /// `0xFF CONT idx u8 ‖ data`.
    Cont(Cont),
}

impl ResponseCmd {
    /// The opcode.
    #[must_use]
    pub const fn op(&self) -> u8 {
        match self {
            Self::Ok => opcode::OK,
            Self::OkQueueNew { .. } => opcode::OK_QUEUE_NEW,
            Self::OkSend { .. } => opcode::OK_SEND,
            Self::Cellr(_) => opcode::CELLR,
            Self::LinkR { .. } => opcode::LINKR,
            Self::Err(_) => opcode::ERR,
            Self::Cont(_) => opcode::RESPONSE_CONT,
        }
    }

    fn encode_fields(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::Ok => {}
            Self::OkQueueNew { rid, sid } => {
                w.bytes(rid);
                w.bytes(sid);
            }
            Self::OkSend { cell_id, evicted } => {
                w.u64(*cell_id);
                w.flag(evicted.is_some());
                w.u64(evicted.unwrap_or(0));
            }
            Self::Cellr(c) => c.encode_fields(w)?,
            Self::LinkR {
                present,
                consumed,
                blob_part,
            } => {
                w.flag(*present);
                w.flag(*consumed);
                w.bytes(blob_part.as_slice());
            }
            Self::Err(code) => w.u8(code.byte()),
            Self::Cont(c) => c.encode_to(w),
        }
        Ok(())
    }

    fn decode_fields(op: u8, r: &mut Reader<'_>, context: CellrContext) -> Result<Self> {
        Ok(match op {
            opcode::OK => Self::Ok,
            opcode::OK_QUEUE_NEW => Self::OkQueueNew {
                rid: r.array()?,
                sid: r.array()?,
            },
            opcode::OK_SEND => {
                let cell_id = r.u64()?;
                let present = r.flag()?;
                let evicted_id = r.u64()?;
                // evicted_id is always present and MUST be 0 when evicted_present = 0 (D.2)
                let evicted = match (present, evicted_id) {
                    (false, 0) => None,
                    (false, _) => return Err(Error::Rejected),
                    (true, id) => Some(id),
                };
                Self::OkSend { cell_id, evicted }
            }
            opcode::CELLR => Self::Cellr(Cellr::decode_fields(r, context)?),
            opcode::LINKR => Self::LinkR {
                present: r.flag()?,
                consumed: r.flag()?,
                blob_part: r.boxed()?,
            },
            opcode::ERR => Self::Err(ErrCode::from_byte(r.u8()?)?),
            opcode::RESPONSE_CONT => Self::Cont(Cont::decode_from(r)?),
            // request opcodes and unknown opcodes
            _ => return Err(Error::Rejected),
        })
    }
}

/// A response frame plaintext.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Response {
    /// Echoes the request's `cmd_seq`.
    pub cmd_seq: u32,
    /// The response.
    pub cmd: ResponseCmd,
}

impl Encode for Response {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let mut fields = Writer::new();
        fields.u8(self.cmd.op());
        fields.u32(self.cmd_seq);
        self.cmd.encode_fields(&mut fields)?;
        w.bytes(&pad(&fields.into_bytes(), FRAME_PLAINTEXT_LEN)?);
        Ok(())
    }
}

impl Response {
    /// Decode a response frame plaintext; a `CELLR` is checked against the request it answers.
    ///
    /// # Errors
    /// [`Error::Rejected`] on any malformed input.
    pub fn decode(bytes: &[u8], context: CellrContext) -> Result<Self> {
        let mut f = Reader::new(unpad(bytes, FRAME_PLAINTEXT_LEN)?);
        let op = f.u8()?;
        let cmd_seq = f.u32()?;
        let cmd = ResponseCmd::decode_fields(op, &mut f, context)?;
        f.finish()?;
        Ok(Self { cmd_seq, cmd })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testutil::{ed25519, sig};

    fn cell(b: u8) -> Result<Cell> {
        Cell::from_bytes(&[b; crate::sizes::CELL_LEN])
    }

    fn requests() -> Result<Vec<Request>> {
        let cmds = vec![
            RequestCmd::QueueNew {
                recv_pk: ed25519(1)?,
                send_pk: ed25519(2)?,
                token: [3; 32],
                sig: sig(4)?,
            },
            RequestCmd::Send {
                sid: [5; 16],
                cell: cell(6)?,
                sig: sig(7)?,
            },
            RequestCmd::Fetch {
                rid: [8; 16],
                ack: u64::MAX,
                sig: sig(9)?,
            },
            RequestCmd::FetchMulti {
                entries: (0..32_u8)
                    .map(|i| {
                        Ok(FetchEntry {
                            rid: [i; 16],
                            ack: u64::from(i),
                            sig: sig(i)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            },
            RequestCmd::QueueDel {
                rid: [10; 16],
                sig: sig(11)?,
            },
            RequestCmd::LinkPut {
                ld_id: [12; 16],
                one_time: true,
                expires_bucket: u32::MAX,
                owner_pk: ed25519(13)?,
                token: [14; 32],
                sig: sig(15)?,
                blob_part: Box::new([16; BLOB_PART_LEN]),
            },
            RequestCmd::LinkGet {
                ld_id: [17; 16],
                mode: LinkGetMode::Consume,
            },
            RequestCmd::LinkGet {
                ld_id: [18; 16],
                mode: LinkGetMode::OwnerStatus(sig(19)?),
            },
            RequestCmd::Ping,
            RequestCmd::Cont(Cont {
                idx: ContIdx::Two,
                data: Box::new([20; CONT_DATA_LEN]),
            }),
        ];
        Ok(cmds
            .into_iter()
            .map(|cmd| Request {
                cmd_seq: 0xffff_fffe,
                cmd,
            })
            .collect())
    }

    #[test]
    fn every_request_round_trips_at_frame_size() -> Result<()> {
        for req in requests()? {
            let bytes = req.encode()?;
            assert_eq!(bytes.len(), FRAME_PLAINTEXT_LEN);
            assert_eq!(bytes.first(), Some(&req.cmd.op()));
            let back = Request::decode(&bytes)?;
            assert_eq!(back, req);
            assert_eq!(back.encode()?, bytes);
            // a request is never a response
            assert!(Response::decode(&bytes, CellrContext::FetchMulti).is_err());
        }
        Ok(())
    }

    fn responses() -> Result<Vec<(Response, CellrContext)>> {
        let fetch = CellrContext::Fetch;
        let multi = CellrContext::FetchMulti;
        let mut out = vec![
            (ResponseCmd::Ok, fetch),
            (
                ResponseCmd::OkQueueNew {
                    rid: [1; 16],
                    sid: [2; 16],
                },
                fetch,
            ),
            (
                ResponseCmd::OkSend {
                    cell_id: 3,
                    evicted: None,
                },
                fetch,
            ),
            (
                ResponseCmd::OkSend {
                    cell_id: u64::MAX,
                    evicted: Some(u64::MAX),
                },
                fetch,
            ),
            (
                ResponseCmd::OkSend {
                    cell_id: 4,
                    evicted: Some(0),
                },
                fetch,
            ),
            (ResponseCmd::Cellr(Cellr::Dummy { cell: cell(5)? }), fetch),
            (
                ResponseCmd::Cellr(Cellr::Cell {
                    rid: [0; 16],
                    cell_id: 6,
                    cell: cell(6)?,
                }),
                fetch,
            ),
            (
                ResponseCmd::Cellr(Cellr::Cell {
                    rid: [7; 16],
                    cell_id: 7,
                    cell: cell(7)?,
                }),
                multi,
            ),
            (
                ResponseCmd::LinkR {
                    present: true,
                    consumed: false,
                    blob_part: Box::new([9; BLOB_PART_LEN]),
                },
                fetch,
            ),
            (
                ResponseCmd::Cont(Cont {
                    idx: ContIdx::One,
                    data: Box::new([10; CONT_DATA_LEN]),
                }),
                fetch,
            ),
        ];
        for error in [CellrError::NoQueue, CellrError::Auth, CellrError::Malformed] {
            out.push((
                ResponseCmd::Cellr(Cellr::Error {
                    error,
                    rid: [8; 16],
                    cell: cell(8)?,
                }),
                multi,
            ));
        }
        for code in ErrCode::ALL {
            out.push((ResponseCmd::Err(code), fetch));
        }
        Ok(out
            .into_iter()
            .map(|(cmd, ctx)| (Response { cmd_seq: 0, cmd }, ctx))
            .collect())
    }

    #[test]
    fn every_response_round_trips_at_frame_size() -> Result<()> {
        for (resp, ctx) in responses()? {
            let bytes = resp.encode()?;
            assert_eq!(bytes.len(), FRAME_PLAINTEXT_LEN);
            let back = Response::decode(&bytes, ctx)?;
            assert_eq!(back, resp);
            assert_eq!(back.encode()?, bytes);
            assert!(Request::decode(&bytes).is_err());
        }
        Ok(())
    }

    #[test]
    fn cellr_context_and_zero_rules() -> Result<()> {
        let with_rid = Response {
            cmd_seq: 1,
            cmd: ResponseCmd::Cellr(Cellr::Cell {
                rid: [1; 16],
                cell_id: 1,
                cell: cell(1)?,
            }),
        }
        .encode()?;
        assert!(Response::decode(&with_rid, CellrContext::FetchMulti).is_ok());
        assert_eq!(
            Response::decode(&with_rid, CellrContext::Fetch),
            Err(Error::Rejected)
        );
        // present 0 with a rid or a cell_id; present 2 with a cell_id; present 5
        for (present, rid, cell_id) in [(0_u8, 1_u8, 0_u64), (0, 0, 1), (2, 1, 1), (5, 0, 0)] {
            let mut f = Writer::new();
            f.u8(opcode::CELLR);
            f.u32(1);
            f.u8(present);
            f.bytes(&[rid; 16]);
            f.u64(cell_id);
            f.bytes(&[0; crate::sizes::CELL_LEN]);
            let bytes = pad(&f.into_bytes(), FRAME_PLAINTEXT_LEN)?;
            for ctx in [CellrContext::Fetch, CellrContext::FetchMulti] {
                assert_eq!(Response::decode(&bytes, ctx), Err(Error::Rejected));
            }
        }
        Ok(())
    }

    #[test]
    fn reserved_and_foreign_opcodes_reject() -> Result<()> {
        for op in 0_u8..=255 {
            let mut f = Writer::new();
            f.u8(op);
            f.u32(0);
            let bytes = pad(&f.into_bytes(), FRAME_PLAINTEXT_LEN)?;
            // only PING and OK have no fields; everything else here is short, reserved or foreign
            assert_eq!(Request::decode(&bytes).is_ok(), op == opcode::PING, "{op}");
            assert_eq!(
                Response::decode(&bytes, CellrContext::Fetch).is_ok(),
                op == opcode::OK,
                "{op}"
            );
        }
        Ok(())
    }

    #[test]
    fn fetch_multi_count_and_link_get_rules() -> Result<()> {
        assert!(
            Request {
                cmd_seq: 0,
                cmd: RequestCmd::FetchMulti { entries: vec![] }
            }
            .encode()
            .is_err()
        );
        let mut too_many = Vec::new();
        for i in 0..33_u8 {
            too_many.push(FetchEntry {
                rid: [i; 16],
                ack: 0,
                sig: sig(i)?,
            });
        }
        assert!(
            Request {
                cmd_seq: 0,
                cmd: RequestCmd::FetchMulti { entries: too_many }
            }
            .encode()
            .is_err()
        );
        // the decoder refuses count 0 and count 33 on its own (independent of the encoder's check)
        for count in [0_u8, 33] {
            let mut f = Writer::new();
            f.u8(opcode::FETCH_MULTI);
            f.u32(0);
            f.u8(count);
            for i in 0..count {
                f.bytes(&[i; 16]);
                f.u64(0);
                f.bytes(sig(i)?.as_bytes());
            }
            let bytes = pad(&f.into_bytes(), FRAME_PLAINTEXT_LEN)?;
            assert_eq!(
                Request::decode(&bytes),
                Err(Error::Rejected),
                "count {count}"
            );
        }
        // LINK_GET mode 0 with a non-zero signature field, mode 2
        let mut f = Writer::new();
        f.u8(opcode::LINK_GET);
        f.u32(0);
        f.bytes(&[0; 16]);
        f.u8(0);
        f.bytes(sig(1)?.as_bytes());
        assert!(Request::decode(&pad(&f.into_bytes(), FRAME_PLAINTEXT_LEN)?).is_err());
        let mut f = Writer::new();
        f.u8(opcode::LINK_GET);
        f.u32(0);
        f.bytes(&[0; 16]);
        f.u8(2);
        f.bytes(sig(1)?.as_bytes());
        assert!(Request::decode(&pad(&f.into_bytes(), FRAME_PLAINTEXT_LEN)?).is_err());
        Ok(())
    }

    /// The opcode table equals the D.2 table of the spec text (review focus: opcode table complete).
    #[test]
    fn opcode_table_equals_appendix_d2() {
        const SPEC: &str = include_str!("../../../../docs/03-protocol-spec.md");
        let d2 = SPEC
            .split_once("### D.2")
            .and_then(|(_, rest)| rest.split_once("### D.3"))
            .map(|(d2, _)| d2)
            .unwrap_or_default();
        let (requests, responses) = d2.split_once("Response opcodes").unwrap_or_default();
        let parse = |text: &str| -> Vec<(u8, String)> {
            text.lines()
                .filter_map(|l| {
                    let l = l.trim_start();
                    let hex = l.strip_prefix("0x")?.get(..2)?;
                    let name = l.get(5..)?.split_whitespace().next()?;
                    Some((u8::from_str_radix(hex, 16).ok()?, name.to_owned()))
                })
                .collect()
        };
        let own = |t: &[(u8, &str)]| -> Vec<(u8, String)> {
            t.iter().map(|(o, n)| (*o, (*n).to_owned())).collect()
        };
        assert_eq!(parse(requests), own(&opcode::REQUESTS));
        assert_eq!(parse(responses), own(&opcode::RESPONSES));
    }
}
