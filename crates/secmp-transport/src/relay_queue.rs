// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`RelayQueueTransport`]: the [`QueueTransport`] of a SecMP relay (spec §12.1, §9.1–§9.6, D.2, D.6).
//!
//! Each method builds and signs the request of its command (D.6, with the link's `sess_id` and the command's own
//! `cmd_seq`), seals its frames, reads the response frames of D.2 and maps them to the trait's outcome. Everything
//! the relay answers is checked against the request (OPEN-M5-11 A): the opcode, the number and order of the frames,
//! the `cmd_seq` echo, the ids of `OK_QUEUE_NEW` (the client derives its own, §9.1), the layout of the `CELLR` and
//! `LINKR` frames; anything that does not fit is [`Error::Rejected`] and closes the link. A single `ERR` frame 6
//! (stale `cmd_seq`, malformed) or 7 (rate) may answer any command (ADR-048 (f), (p)).

use std::io::{Read, Write};

use secmp_crypto::{Ed25519SigningKey, SecretBytes};
use secmp_proto::codec::{Decode, Encode};
use secmp_proto::keys::Ed25519Sig;
use secmp_proto::link::cont::{AssembledResponse, LinkrAssembler, split_blob};
use secmp_proto::link::ids::{self, AccessKey};
use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH};
use secmp_proto::sizes::{FETCH_MULTI_MAX, HASH_LEN};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    Cellr, CellrContext, CellrError, ErrCode, FetchEntry, LinkGetMode as WireLinkGetMode, Request,
    RequestCmd, ResponseCmd,
};
use secmp_proto::wire::inv::LinkBlob;
use secmp_proto::wire::signed::{self, LinkPutFields};

use crate::caps::{QueueRef, RecvCap, SendCap, pk_of};
use crate::error::{Error, Result};
use crate::session::Session;

/// A per-queue cell id (spec §9.1).
pub type CellId = u64;
/// A link-data id (spec §9.4).
pub type LdId = Id;
/// An hour bucket (spec §4.2).
pub type Bucket = u32;
/// The access credential of the relay (spec §9.6): `QUEUE_NEW` and `LINK_PUT` carry a token derived from it for the
/// command (the transport computes it, so the key never reaches the relay).
pub type Token = AccessKey;

/// What a `SEND` returns (spec §9.3): the id of the stored cell and the id of the cell it evicted, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendOutcome {
    /// The stored cell's id.
    pub cell_id: CellId,
    /// The evicted cell's id, if the queue was full (spec §9.5).
    pub evicted: Option<CellId>,
}

/// What a `FETCH_MULTI` returns: the real cells of the queues that answered, and the queues that did not.
pub struct FetchMultiOutcome {
    /// `(queue, cell_id, cell)`, oldest first by arrival at the relay.
    pub cells: Vec<(QueueRef, CellId, Cell)>,
    /// A queue that answered with an error (`present` 2–4), in request order.
    pub errors: Vec<(QueueRef, Error)>,
}

/// The `LINK_GET` mode (spec §9.4).
pub enum LinkGetMode<'a> {
    /// Return the blob and delete a one-time entry.
    Consume,
    /// The status of the entry, signed by the owner key (the seed of `owner_pk`); never consumes.
    OwnerStatus(&'a SecretBytes<32>),
}

/// What a `LINK_GET` returns (spec §9.4).
pub struct LinkGetOutcome {
    /// The entry exists.
    pub present: bool,
    /// The entry was consumed (a one-time entry, already taken).
    pub consumed: bool,
    /// The blob, only for a consume that found the entry.
    pub blob: Option<LinkBlob>,
}

/// The operations the sessions need of a relay (spec §12.1), synchronous: a call returns when the relay has answered.
/// An asynchronous driver for the Tor and TLS providers (M6) builds on the same [`Session`].
pub trait QueueTransport {
    /// Create the queue of `recv` and `send` (idempotent: the same keys give the same capabilities; spec §9.1).
    ///
    /// # Errors
    /// [`Error::Token`], [`Error::Full`], [`Error::Auth`] (a known `recv_pk` with another `send_pk`), …
    fn create_queue(
        &mut self,
        recv: &SecretBytes<32>,
        send: &SecretBytes<32>,
        token: &Token,
    ) -> Result<(RecvCap, SendCap)>;

    /// `SEND` one cell.
    ///
    /// # Errors
    /// [`Error::NoQueue`], [`Error::Auth`], …
    fn send(&mut self, to: &SendCap, cell: &Cell) -> Result<SendOutcome>;

    /// `FETCH` with the cumulative `ack`: the real cells (at most `F` = 4), ascending; the relay's dummies are
    /// filtered.
    ///
    /// # Errors
    /// [`Error::NoQueue`], [`Error::Auth`], [`Error::Malformed`] (a stale `ack`), …
    fn fetch(&mut self, from: &RecvCap, ack: CellId) -> Result<Vec<(CellId, Cell)>>;

    /// `FETCH_MULTI` over 1 to 32 queues.
    ///
    /// # Errors
    /// [`Error::Invalid`] for 0 or more than 32 queues; link errors.
    fn fetch_multi(&mut self, from: &[(&RecvCap, CellId)]) -> Result<FetchMultiOutcome>;

    /// `QUEUE_DEL`.
    ///
    /// # Errors
    /// [`Error::NoQueue`], [`Error::Auth`].
    fn delete_queue(&mut self, q: &RecvCap) -> Result<()>;

    /// `LINK_PUT` (three frames).
    ///
    /// # Errors
    /// [`Error::Token`], [`Error::Full`], [`Error::Auth`], [`Error::Exists`], [`Error::Malformed`] (an
    /// `expires_bucket` out of range).
    fn put_link_data(
        &mut self,
        id: LdId,
        owner: &SecretBytes<32>,
        blob: &LinkBlob,
        one_time: bool,
        expires: Bucket,
        token: &Token,
    ) -> Result<()>;

    /// `LINK_GET`.
    ///
    /// # Errors
    /// Link errors; an absent or consumed entry is an outcome, not an error.
    fn get_link_data(&mut self, id: LdId, mode: LinkGetMode<'_>) -> Result<LinkGetOutcome>;
}

/// The transport to one relay over one link.
pub struct RelayQueueTransport<S> {
    session: Session<S>,
}

/// An `ERR` code a command's response may carry besides 6 and 7.
fn fits(code: ErrCode, allowed: &[ErrCode]) -> bool {
    matches!(code, ErrCode::Malformed | ErrCode::Rate) || allowed.contains(&code)
}

fn sig(bytes: &[u8]) -> Result<Ed25519Sig> {
    Ok(Ed25519Sig::from_bytes(bytes)?)
}

impl<S: Read + Write> RelayQueueTransport<S> {
    /// A transport over an established [`Session`].
    #[must_use]
    pub const fn new(session: Session<S>) -> Self {
        Self { session }
    }

    /// Connect: the SecMP-LINK handshake on `stream` (see [`Session::connect`]).
    ///
    /// # Errors
    /// As [`Session::connect`].
    pub fn connect(
        stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Self> {
        Ok(Self::new(Session::connect(
            stream, pinned_fp, access_key, now_unix, entropy,
        )?))
    }

    /// The link's session.
    #[must_use]
    pub const fn session(&self) -> &Session<S> {
        &self.session
    }

    /// The link's `sess_id`.
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        self.session.sess_id()
    }

    /// Whether the link is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.session.is_closed()
    }

    /// `PING` (spec §9.3): the relay answers `OK`.
    ///
    /// # Errors
    /// Link errors.
    pub fn ping(&mut self) -> Result<()> {
        let seq = self.session.next_cmd_seq()?;
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::Ping,
        }])?;
        self.expect_ok(seq, &[])
    }

    /// Read one frame that must be a single-frame response: its `ERR` code (if it fits the command) or its command.
    fn single(&mut self, seq: u32, allowed: &[ErrCode]) -> Result<ResponseCmd> {
        let response = self.session.receive(seq, CellrContext::Fetch)?;
        match response.cmd {
            ResponseCmd::Err(code) if fits(code, allowed) => Err(Error::from_code(code)),
            ResponseCmd::Err(_) => Err(self.session.reject()),
            other => Ok(other),
        }
    }

    /// A response that must be `OK`.
    fn expect_ok(&mut self, seq: u32, allowed: &[ErrCode]) -> Result<()> {
        match self.single(seq, allowed)? {
            ResponseCmd::Ok => Ok(()),
            _ => Err(self.session.reject()),
        }
    }

    /// The `cmd_seq` and the token of a command that carries one (spec §9.6).
    fn seq_and_token(&mut self, access: &AccessKey) -> Result<(u32, [u8; HASH_LEN])> {
        let seq = self.session.next_cmd_seq()?;
        let token = ids::token(access, self.session.sess_id(), seq)?;
        Ok((seq, token))
    }

    /// The `CELLR` frames after the first of a `FETCH` or `FETCH_MULTI`.
    fn more_cellr(
        &mut self,
        seq: u32,
        first: Cellr,
        total: usize,
        context: CellrContext,
    ) -> Result<Vec<Cellr>> {
        let mut frames = vec![first];
        while frames.len() < total {
            match self.session.receive(seq, context)?.cmd {
                ResponseCmd::Cellr(c) => frames.push(c),
                _ => return Err(self.session.reject()),
            }
        }
        Ok(frames)
    }

    /// The first frame of a `FETCH` / `FETCH_MULTI` response: a `CELLR`, or the single `ERR` 6 / 7.
    fn first_cellr(&mut self, seq: u32, context: CellrContext) -> Result<Cellr> {
        match self.session.receive(seq, context)?.cmd {
            ResponseCmd::Cellr(c) => Ok(c),
            ResponseCmd::Err(code) if fits(code, &[]) => Err(Error::from_code(code)),
            _ => Err(self.session.reject()),
        }
    }
}

impl<S: Read + Write> QueueTransport for RelayQueueTransport<S> {
    fn create_queue(
        &mut self,
        recv: &SecretBytes<32>,
        send: &SecretBytes<32>,
        token: &Token,
    ) -> Result<(RecvCap, SendCap)> {
        let recv_cap = RecvCap::from_seed(recv)?;
        let recv_pk = recv_cap.public_key()?;
        let send_pk = pk_of(send)?;
        let send_cap = SendCap::from_seed(&recv_pk, send)?;
        let (seq, token) = self.seq_and_token(token)?;
        let message = signed::queue_new(self.session.sess_id(), seq, &recv_pk, &send_pk, &token);
        let signature = sig(&recv_cap.key()?.sign(&message))?;
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::QueueNew {
                recv_pk,
                send_pk,
                token,
                sig: signature,
            },
        }])?;
        let allowed = [ErrCode::Token, ErrCode::Full, ErrCode::Auth];
        match self.single(seq, &allowed)? {
            // the ids are derived from the keys (spec §9.1): a relay that answers others is not ours
            ResponseCmd::OkQueueNew { rid, sid }
                if rid == *recv_cap.rid() && sid == *send_cap.sid() =>
            {
                Ok((recv_cap, send_cap))
            }
            _ => Err(self.session.reject()),
        }
    }

    fn send(&mut self, to: &SendCap, cell: &Cell) -> Result<SendOutcome> {
        let seq = self.session.next_cmd_seq()?;
        let message = signed::send(self.session.sess_id(), seq, to.sid(), cell);
        let signature = sig(&to.key()?.sign(&message))?;
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::Send {
                sid: *to.sid(),
                cell: cell.clone(),
                sig: signature,
            },
        }])?;
        match self.single(seq, &[ErrCode::NoQueue, ErrCode::Auth])? {
            ResponseCmd::OkSend { cell_id, evicted } if cell_id != 0 => {
                Ok(SendOutcome { cell_id, evicted })
            }
            _ => Err(self.session.reject()),
        }
    }

    fn fetch(&mut self, from: &RecvCap, ack: CellId) -> Result<Vec<(CellId, Cell)>> {
        let seq = self.session.next_cmd_seq()?;
        let message = signed::fetch(self.session.sess_id(), seq, from.rid(), ack);
        let signature = sig(&from.key()?.sign(&message))?;
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::Fetch {
                rid: *from.rid(),
                ack,
                sig: signature,
            },
        }])?;
        let first = self.first_cellr(seq, CellrContext::Fetch)?;
        let frames = self.more_cellr(seq, first, FETCH_BATCH, CellrContext::Fetch)?;
        if let Some(Cellr::Error { error, rid, .. }) = frames.first() {
            // an error frame is followed by dummies only, and names the requested queue (D.2)
            let rest_dummy = frames
                .iter()
                .skip(1)
                .all(|f| matches!(f, Cellr::Dummy { .. }));
            if !rest_dummy || rid != from.rid() {
                return Err(self.session.reject());
            }
            return Err(cellr_error(*error));
        }
        let mut cells = Vec::new();
        let mut previous = ack;
        let mut dummies = false;
        for frame in frames {
            match frame {
                // real cells ascend, all above the acknowledged id, and come before the dummies
                Cellr::Cell { cell_id, cell, .. } if !dummies && cell_id > previous => {
                    previous = cell_id;
                    cells.push((cell_id, cell));
                }
                Cellr::Dummy { .. } => dummies = true,
                _ => return Err(self.session.reject()),
            }
        }
        Ok(cells)
    }

    fn fetch_multi(&mut self, from: &[(&RecvCap, CellId)]) -> Result<FetchMultiOutcome> {
        if from.is_empty() || from.len() > FETCH_MULTI_MAX {
            return Err(Error::Invalid);
        }
        let seq = self.session.next_cmd_seq()?;
        let mut entries = Vec::with_capacity(from.len());
        for (cap, ack) in from {
            let message = signed::fetch_multi_entry(self.session.sess_id(), seq, cap.rid(), *ack);
            entries.push(FetchEntry {
                rid: *cap.rid(),
                ack: *ack,
                sig: sig(&cap.key()?.sign(&message))?,
            });
        }
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::FetchMulti { entries },
        }])?;
        let first = self.first_cellr(seq, CellrContext::FetchMulti)?;
        let frames = self.more_cellr(seq, first, FETCH_MULTI_BATCH, CellrContext::FetchMulti)?;
        // errors first (request order), then cells (per queue ascending, above its ack), then dummies
        let mut outcome = FetchMultiOutcome {
            cells: Vec::new(),
            errors: Vec::new(),
        };
        let mut stage = 0_u8;
        let mut next_entry = 0_usize;
        for frame in frames {
            match frame {
                Cellr::Error { error, rid, .. } if stage == 0 => {
                    let at = from
                        .iter()
                        .skip(next_entry)
                        .position(|(cap, _)| *cap.rid() == rid);
                    let Some(at) = at else {
                        return Err(self.session.reject());
                    };
                    next_entry = next_entry
                        .checked_add(at)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(Error::Rejected)?;
                    outcome
                        .errors
                        .push((QueueRef::from_rid(rid), cellr_error(error)));
                }
                Cellr::Cell { rid, cell_id, cell } if stage <= 1 => {
                    stage = 1;
                    // above the highest ack requested for this queue and above its previous cell
                    let floor = from
                        .iter()
                        .filter(|(cap, _)| *cap.rid() == rid)
                        .map(|(_, ack)| *ack)
                        .chain(
                            outcome
                                .cells
                                .iter()
                                .filter(|(q, _, _)| *q.rid() == rid)
                                .map(|(_, id, _)| *id),
                        )
                        .max();
                    match floor {
                        Some(floor) if cell_id > floor => {
                            outcome.cells.push((QueueRef::from_rid(rid), cell_id, cell));
                        }
                        _ => return Err(self.session.reject()),
                    }
                }
                Cellr::Dummy { .. } => stage = 2,
                _ => return Err(self.session.reject()),
            }
        }
        Ok(outcome)
    }

    fn delete_queue(&mut self, q: &RecvCap) -> Result<()> {
        let seq = self.session.next_cmd_seq()?;
        let message = signed::queue_del(self.session.sess_id(), seq, q.rid());
        let signature = sig(&q.key()?.sign(&message))?;
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::QueueDel {
                rid: *q.rid(),
                sig: signature,
            },
        }])?;
        self.expect_ok(seq, &[ErrCode::NoQueue, ErrCode::Auth])
    }

    fn put_link_data(
        &mut self,
        id: LdId,
        owner: &SecretBytes<32>,
        blob: &LinkBlob,
        one_time: bool,
        expires: Bucket,
        token: &Token,
    ) -> Result<()> {
        let (seq, token) = self.seq_and_token(token)?;
        let owner_pk = pk_of(owner)?;
        let fields = LinkPutFields {
            ld_id: &id,
            one_time,
            expires_bucket: expires,
            owner_pk: &owner_pk,
            token: &token,
        };
        let message = signed::link_put(self.session.sess_id(), seq, &fields, blob)?;
        let signature = sig(&Ed25519SigningKey::from_seed(owner.expose_secret())?.sign(&message))?;
        let (blob_part, one, two) = split_blob(&blob.encode()?)?;
        self.session.send(&[
            Request {
                cmd_seq: seq,
                cmd: RequestCmd::LinkPut {
                    ld_id: id,
                    one_time,
                    expires_bucket: expires,
                    owner_pk,
                    token,
                    sig: signature,
                    blob_part,
                },
            },
            Request {
                cmd_seq: seq,
                cmd: RequestCmd::Cont(one),
            },
            Request {
                cmd_seq: seq,
                cmd: RequestCmd::Cont(two),
            },
        ])?;
        self.expect_ok(
            seq,
            &[
                ErrCode::Token,
                ErrCode::Full,
                ErrCode::Auth,
                ErrCode::Exists,
            ],
        )
    }

    fn get_link_data(&mut self, id: LdId, mode: LinkGetMode<'_>) -> Result<LinkGetOutcome> {
        let seq = self.session.next_cmd_seq()?;
        let (wire_mode, consume) = match mode {
            LinkGetMode::Consume => (WireLinkGetMode::Consume, true),
            LinkGetMode::OwnerStatus(owner) => {
                let message = signed::link_get_owner_status(self.session.sess_id(), seq, &id);
                let key = Ed25519SigningKey::from_seed(owner.expose_secret())?;
                (
                    WireLinkGetMode::OwnerStatus(sig(&key.sign(&message))?),
                    false,
                )
            }
        };
        self.session.send(&[Request {
            cmd_seq: seq,
            cmd: RequestCmd::LinkGet {
                ld_id: id,
                mode: wire_mode,
            },
        }])?;
        let first = self.session.receive(seq, CellrContext::Fetch)?;
        if let ResponseCmd::Err(code) = first.cmd {
            return Err(if fits(code, &[]) {
                Error::from_code(code)
            } else {
                self.session.reject()
            });
        }
        let mut assembler = LinkrAssembler::new();
        let mut frame = first;
        let linkr = loop {
            match assembler.push(frame) {
                Ok(AssembledResponse::Pending) => {}
                Ok(AssembledResponse::Linkr(linkr)) => break linkr,
                Ok(AssembledResponse::Single(_)) | Err(_) => return Err(self.session.reject()),
            }
            frame = self.session.receive(seq, CellrContext::Fetch)?;
        };
        // {1, 1} is no state of §9.4
        if linkr.cmd_seq != seq || (linkr.present && linkr.consumed) {
            return Err(self.session.reject());
        }
        let blob = if consume && linkr.present {
            Some(LinkBlob::decode(&linkr.blob).map_err(|_| self.session.reject())?)
        } else {
            None
        };
        Ok(LinkGetOutcome {
            present: linkr.present,
            consumed: linkr.consumed,
            blob,
        })
    }
}

fn cellr_error(error: CellrError) -> Error {
    match error {
        CellrError::NoQueue => Error::NoQueue,
        CellrError::Auth => Error::Auth,
        CellrError::Malformed => Error::Malformed,
    }
}
