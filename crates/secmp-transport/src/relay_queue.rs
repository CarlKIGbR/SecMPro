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

use secmp_crypto::SecretBytes;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::sizes::HASH_LEN;
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::LinkBlob;

use crate::caps::{QueueRef, RecvCap, SendCap};
use crate::error::{Error, Result};
use crate::ops::{self, Exchange, LinkPut, QueueNewKeys, Step};
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
        self.run(ops::ping(seq))
    }

    /// Write the exchange's request frames and read its response (the sans-IO judgement is `ops`, shared with the
    /// asynchronous transport).
    fn run<T: TryFrom<ops::Out, Error = Error>>(&mut self, mut ex: Exchange<T>) -> Result<T> {
        self.session.send(ex.requests())?;
        loop {
            let response = self.session.receive(ex.seq(), ex.context())?;
            match ex.push(response) {
                Err(_) => return Err(self.session.reject()),
                Ok(Step::More) => {}
                Ok(Step::Done(outcome)) => return outcome,
            }
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
        let keys = QueueNewKeys::derive(recv, send)?;
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::create_queue(seq, self.session.sess_id(), keys, token)?;
        self.run(ex)
    }

    fn send(&mut self, to: &SendCap, cell: &Cell) -> Result<SendOutcome> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::send(seq, self.session.sess_id(), to, cell)?;
        self.run(ex)
    }

    fn fetch(&mut self, from: &RecvCap, ack: CellId) -> Result<Vec<(CellId, Cell)>> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::fetch(seq, self.session.sess_id(), from, ack)?;
        self.run(ex)
    }

    fn fetch_multi(&mut self, from: &[(&RecvCap, CellId)]) -> Result<FetchMultiOutcome> {
        if !ops::fetch_multi_len_ok(from) {
            return Err(Error::Invalid);
        }
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::fetch_multi(seq, self.session.sess_id(), from)?;
        self.run(ex)
    }

    fn delete_queue(&mut self, q: &RecvCap) -> Result<()> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::delete_queue(seq, self.session.sess_id(), q)?;
        self.run(ex)
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
        let seq = self.session.next_cmd_seq()?;
        let put = LinkPut {
            id,
            owner,
            blob,
            one_time,
            expires,
            access: token,
        };
        let ex = ops::put_link_data(seq, self.session.sess_id(), &put)?;
        self.run(ex)
    }

    fn get_link_data(&mut self, id: LdId, mode: LinkGetMode<'_>) -> Result<LinkGetOutcome> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::get_link_data(seq, self.session.sess_id(), id, &mode)?;
        self.run(ex)
    }
}
