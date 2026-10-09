// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`Channel`]: the sans-IO half of a SecMP-LINK session (spec §8.4, §10.1, §10.3, D.2) — the link keys and counters,
//! the `cmd_seq` sequence, **prepared** request frames and the **pipelined** responses.
//!
//! The scheduler prepares the frame of tick `k + 1` off the tick path ([`Channel::prepare`]: build, sign, pad, seal under
//! `k_c2r` at the next counter) and the tick only writes those bytes ([`Channel::begin_write`], then the caller's
//! I/O). Frames must be written in counter order ([`Error::OutOfOrder`] otherwise, nothing marked written). Several
//! requests may be outstanding; the response frames are matched to the requests in request order, and every frame is
//! checked against the request it answers (OPEN-M5-11 A): a frame that does not fit is [`Error::Rejected`] and closes
//! the channel.

use std::collections::VecDeque;

use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link::{self, FETCH_BATCH, FETCH_MULTI_BATCH, Link};
use secmp_proto::sizes::{FETCH_MULTI_MAX, FRAME_LEN, FRAME_PLAINTEXT_LEN};
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    Cellr, CellrContext, CellrError, ErrCode, FetchEntry, Request, RequestCmd, ResponseCmd,
};
use secmp_proto::wire::signed;

use crate::caps::{QueueRef, RecvCap, SendCap};
use crate::error::{Error, Result};
use crate::evicted::evicted_is_plausible;
use crate::relay_queue::{CellId, FetchMultiOutcome, SendOutcome};

/// Counting accessors of the harness build (`seal_calls`, `sign_calls`; TEST-SPEC-M6 "Conventions"): thread-local, read
/// before and after a unit.
#[cfg(feature = "harness")]
pub mod counters {
    use core::cell::Cell;

    thread_local! {
        static SEAL: Cell<u64> = const { Cell::new(0) };
        static SIGN: Cell<u64> = const { Cell::new(0) };
    }

    /// Frames sealed under `k_c2r` by [`super::Channel::prepare`] on this thread.
    #[must_use]
    pub fn seal_calls() -> u64 {
        SEAL.with(Cell::get)
    }

    /// Command signatures made by [`super::Channel::prepare`] on this thread.
    #[must_use]
    pub fn sign_calls() -> u64 {
        SIGN.with(Cell::get)
    }

    pub(super) fn bump_seal() {
        SEAL.with(|c| c.set(c.get().saturating_add(1)));
    }

    pub(super) fn bump_sign() {
        SIGN.with(|c| c.set(c.get().saturating_add(1)));
    }
}

#[cfg(not(feature = "harness"))]
mod counters {
    pub(super) const fn bump_seal() {}
    pub(super) const fn bump_sign() {}
}

/// The command a frame is prepared for.
pub enum Command<'a> {
    /// `PING`.
    Ping,
    /// `SEND` one cell.
    Send {
        /// The queue.
        to: &'a SendCap,
        /// The cell.
        cell: &'a Cell,
    },
    /// `FETCH` with the cumulative acknowledgement.
    Fetch {
        /// The queue.
        from: &'a RecvCap,
        /// The acknowledgement.
        ack: CellId,
    },
    /// `FETCH_MULTI` over 1 to 32 queues.
    FetchMulti {
        /// `(queue, ack)` in request order.
        from: &'a [(&'a RecvCap, CellId)],
    },
}

/// What a request expects back (kept until its response is complete).
#[derive(Clone)]
enum Expect {
    Ping,
    Send,
    Fetch { rid: Id, ack: CellId },
    FetchMulti { entries: Vec<(Id, CellId)> },
}

impl Expect {
    const fn context(&self) -> CellrContext {
        match self {
            Self::FetchMulti { .. } => CellrContext::FetchMulti,
            _ => CellrContext::Fetch,
        }
    }
}

/// One request, sealed and ready to write. Its bytes are `frames × 4352` ciphertext.
pub struct Prepared {
    bytes: Vec<u8>,
    first_counter: u64,
    seq: u32,
    expect: Expect,
}

impl Prepared {
    /// The sealed frame(s) to write.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `cmd_seq` of the request.
    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// The link counter of the first frame.
    #[must_use]
    pub const fn first_counter(&self) -> u64 {
        self.first_counter
    }
}

/// The outcome of one request. An `Err` inside is the relay's answer to the command (the link stays usable).
pub enum Outcome {
    /// `PING`.
    Ping(Result<()>),
    /// `SEND`.
    Send(Result<SendOutcome>),
    /// `FETCH`: the real cells above the acknowledgement, ascending.
    Fetch(Result<Vec<(CellId, Cell)>>),
    /// `FETCH_MULTI`.
    FetchMulti(Result<FetchMultiOutcome>),
}

/// A request whose response is complete.
pub struct Completed {
    /// The request's `cmd_seq`.
    pub seq: u32,
    /// What the relay answered.
    pub outcome: Outcome,
}

struct Pending {
    seq: u32,
    expect: Expect,
    frames: Vec<ResponseCmd>,
}

/// The sans-IO link session (see the module documentation).
pub struct Channel {
    link: Link,
    last_cmd_seq: u32,
    closed: bool,
    next_write: u64,
    pending: VecDeque<Pending>,
}

fn sig(bytes: &[u8]) -> Result<secmp_proto::keys::Ed25519Sig> {
    Ok(secmp_proto::keys::Ed25519Sig::from_bytes(bytes)?)
}

/// An `ERR` code a response may carry besides 6 and 7.
fn fits(code: ErrCode, allowed: &[ErrCode]) -> bool {
    matches!(code, ErrCode::Malformed | ErrCode::Rate) || allowed.contains(&code)
}

const fn cellr_error(error: CellrError) -> Error {
    match error {
        CellrError::NoQueue => Error::NoQueue,
        CellrError::Auth => Error::Auth,
        CellrError::Malformed => Error::Malformed,
    }
}

impl Channel {
    pub(crate) fn new(link: Link) -> Self {
        let next_write = link.send_counter().unwrap_or(0);
        Self {
            link,
            last_cmd_seq: 0,
            closed: false,
            next_write,
            pending: VecDeque::new(),
        }
    }

    /// The link's `sess_id`.
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        self.link.sess_id()
    }

    /// Whether the channel is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// The link state (tests only, feature `harness`).
    #[cfg(feature = "harness")]
    #[must_use]
    pub const fn link_kat(&self) -> &Link {
        &self.link
    }

    /// The link state, mutable (tests only, feature `harness`): the counter tests.
    #[cfg(feature = "harness")]
    pub const fn link_kat_mut(&mut self) -> &mut Link {
        &mut self.link
    }

    /// The next counter this side seals under; `None` once exhausted.
    #[must_use]
    pub const fn send_counter(&self) -> Option<u64> {
        self.link.send_counter()
    }

    /// Requests written whose response is not complete.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }

    pub(crate) const fn link_mut(&mut self) -> &mut Link {
        &mut self.link
    }

    pub(crate) const fn ensure_open(&self) -> Result<()> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    /// Mark the channel closed (the stream ended or failed).
    pub const fn close(&mut self) {
        self.closed = true;
    }

    /// A LINK-level failure: the channel is closed (spec §8.5).
    pub(crate) const fn reject(&mut self) -> Error {
        self.close();
        Error::Rejected
    }

    pub(crate) fn next_cmd_seq(&mut self) -> Result<u32> {
        self.ensure_open()?;
        let next = self
            .last_cmd_seq
            .checked_add(1)
            .ok_or(Error::NewLinkRequired)?;
        self.last_cmd_seq = next;
        Ok(next)
    }

    /// After frames were sealed and written directly (the blocking path): the write position follows the counter.
    pub(crate) fn synced(&mut self) {
        self.next_write = self.link.send_counter().unwrap_or(self.next_write);
    }

    /// Build, sign, pad and seal the request of `command` (spec §10.1: all of this happens off the tick path).
    ///
    /// # Errors
    /// [`Error::Closed`]; [`Error::NewLinkRequired`] (before anything is sealed) when the link has used its frames or
    /// its `cmd_seq` space; [`Error::Invalid`] for a `FETCH_MULTI` of 0 or more than 32 queues.
    pub fn prepare(&mut self, command: &Command<'_>) -> Result<Prepared> {
        self.ensure_open()?;
        let first_counter = self.link.send_counter().ok_or(Error::NewLinkRequired)?;
        let expect = match command {
            Command::Ping => Expect::Ping,
            Command::Send { .. } => Expect::Send,
            Command::Fetch { from, ack } => Expect::Fetch {
                rid: *from.rid(),
                ack: *ack,
            },
            Command::FetchMulti { from } => {
                if from.is_empty() || from.len() > FETCH_MULTI_MAX {
                    return Err(Error::Invalid);
                }
                Expect::FetchMulti {
                    entries: from.iter().map(|(c, a)| (*c.rid(), *a)).collect(),
                }
            }
        };
        let seq = self.next_cmd_seq()?;
        let request = self.build(seq, command)?;
        let padded = request.encode()?;
        let payload = unpad(&padded, FRAME_PLAINTEXT_LEN)?;
        counters::bump_seal();
        match self.link.seal(payload) {
            Ok(frame) => Ok(Prepared {
                bytes: frame.to_vec(),
                first_counter,
                seq,
                expect,
            }),
            Err(e) => {
                if !matches!(e, link::Error::NewLinkRequired) {
                    self.close();
                }
                Err(e.into())
            }
        }
    }

    fn build(&self, seq: u32, command: &Command<'_>) -> Result<Request> {
        let sess = self.link.sess_id();
        let cmd = match command {
            Command::Ping => RequestCmd::Ping,
            Command::Send { to, cell } => {
                let message = signed::send(sess, seq, to.sid(), cell);
                counters::bump_sign();
                RequestCmd::Send {
                    sid: *to.sid(),
                    cell: Cell::from_bytes(cell.as_bytes())?,
                    sig: sig(&to.key()?.sign(&message))?,
                }
            }
            Command::Fetch { from, ack } => {
                let message = signed::fetch(sess, seq, from.rid(), *ack);
                counters::bump_sign();
                RequestCmd::Fetch {
                    rid: *from.rid(),
                    ack: *ack,
                    sig: sig(&from.key()?.sign(&message))?,
                }
            }
            Command::FetchMulti { from } => {
                let mut entries = Vec::with_capacity(from.len());
                for (cap, ack) in *from {
                    let message = signed::fetch_multi_entry(sess, seq, cap.rid(), *ack);
                    counters::bump_sign();
                    entries.push(FetchEntry {
                        rid: *cap.rid(),
                        ack: *ack,
                        sig: sig(&cap.key()?.sign(&message))?,
                    });
                }
                RequestCmd::FetchMulti { entries }
            }
        };
        Ok(Request { cmd_seq: seq, cmd })
    }

    /// Declare `prepared` written: it must be the next frame in counter order, else [`Error::OutOfOrder`] and nothing
    /// changes. The caller writes `prepared.bytes()` right after (no crypto, no persistence on this path).
    ///
    /// # Errors
    /// [`Error::Closed`]; [`Error::OutOfOrder`].
    pub fn begin_write(&mut self, prepared: &Prepared) -> Result<()> {
        self.ensure_open()?;
        if prepared.first_counter != self.next_write {
            return Err(Error::OutOfOrder);
        }
        let frames = u64::try_from(prepared.bytes.len() / FRAME_LEN).map_err(|_| Error::Invalid)?;
        self.next_write = self
            .next_write
            .checked_add(frames)
            .ok_or(Error::NewLinkRequired)?;
        self.pending.push_back(Pending {
            seq: prepared.seq,
            expect: prepared.expect.clone(),
            frames: Vec::new(),
        });
        Ok(())
    }

    /// Take one received frame. `Ok(None)` while the oldest outstanding request still lacks frames.
    ///
    /// # Errors
    /// [`Error::Closed`]; [`Error::Rejected`] (the channel closes) for a frame that does not open, decode, echo the
    /// request's `cmd_seq`, or fit the request; an unsolicited frame is also [`Error::Rejected`].
    pub fn accept(&mut self, unit: &[u8]) -> Result<Option<Completed>> {
        self.ensure_open()?;
        let Some(front) = self.pending.front() else {
            return Err(self.reject());
        };
        let (seq, context) = (front.seq, front.expect.context());
        let Ok(response) = self.link.open_response(unit, context) else {
            return Err(self.reject());
        };
        if response.cmd_seq != seq {
            return Err(self.reject());
        }
        let Some(front) = self.pending.front_mut() else {
            return Err(self.reject());
        };
        front.frames.push(response.cmd);
        let need = match &front.expect {
            Expect::Ping | Expect::Send => 1,
            Expect::Fetch { .. } => match front.frames.first() {
                Some(ResponseCmd::Cellr(_)) => FETCH_BATCH,
                _ => 1,
            },
            Expect::FetchMulti { .. } => match front.frames.first() {
                Some(ResponseCmd::Cellr(_)) => FETCH_MULTI_BATCH,
                _ => 1,
            },
        };
        if front.frames.len() < need {
            return Ok(None);
        }
        let Some(done) = self.pending.pop_front() else {
            return Err(self.reject());
        };
        match Self::finish(done) {
            Ok(completed) => Ok(Some(completed)),
            Err(_) => Err(self.reject()),
        }
    }

    fn finish(done: Pending) -> Result<Completed> {
        let Pending {
            seq,
            expect,
            frames,
        } = done;
        let outcome = match expect {
            Expect::Ping => Outcome::Ping(
                single(frames, &[], |c| matches!(c, ResponseCmd::Ok))?.map(|_| ()),
            ),
            Expect::Send => Outcome::Send(
                match single(frames, &[ErrCode::NoQueue, ErrCode::Auth], |c| {
                    matches!(c, ResponseCmd::OkSend { .. })
                })? {
                    Err(e) => Err(e),
                    Ok(ResponseCmd::OkSend { cell_id, evicted })
                        if cell_id != 0 && evicted_is_plausible(cell_id, evicted) =>
                    {
                        Ok(SendOutcome { cell_id, evicted })
                    }
                    Ok(_) => return Err(Error::Rejected),
                },
            ),
            Expect::Fetch { rid, ack } => Outcome::Fetch(check_fetch(frames, &rid, ack)?),
            Expect::FetchMulti { entries } => {
                Outcome::FetchMulti(check_fetch_multi(frames, &entries)?)
            }
        };
        Ok(Completed { seq, outcome })
    }
}

/// A single-frame response: `Ok(Ok(cmd))`, the command's `ERR` as `Ok(Err(..))`, a misfit as the outer `Err`.
fn single(
    mut frames: Vec<ResponseCmd>,
    allowed: &[ErrCode],
    ok: impl Fn(&ResponseCmd) -> bool,
) -> Result<Result<ResponseCmd>> {
    let (Some(first), true) = (frames.pop(), frames.is_empty()) else {
        return Err(Error::Rejected);
    };
    match first {
        ResponseCmd::Err(code) if fits(code, allowed) => Ok(Err(Error::from_code(code))),
        ResponseCmd::Err(_) => Err(Error::Rejected),
        other if ok(&other) => Ok(Ok(other)),
        _ => Err(Error::Rejected),
    }
}

/// The frames of a `FETCH` response (D.2): a single `ERR` 6/7, an error `CELLR` followed by dummies and naming the
/// queue, or real cells above the acknowledgement in ascending order followed by dummies.
fn check_fetch(
    frames: Vec<ResponseCmd>,
    rid: &Id,
    ack: CellId,
) -> Result<Result<Vec<(CellId, Cell)>>> {
    if let [ResponseCmd::Err(code)] = frames.as_slice() {
        return if fits(*code, &[]) {
            Ok(Err(Error::from_code(*code)))
        } else {
            Err(Error::Rejected)
        };
    }
    if frames.len() != FETCH_BATCH {
        return Err(Error::Rejected);
    }
    let mut cells = Vec::new();
    let mut previous = ack;
    let mut dummies = false;
    let mut error: Option<Error> = None;
    for (at, frame) in frames.into_iter().enumerate() {
        let ResponseCmd::Cellr(c) = frame else {
            return Err(Error::Rejected);
        };
        match c {
            Cellr::Error { error: e, rid: r, .. } if at == 0 => {
                if r != *rid {
                    return Err(Error::Rejected);
                }
                error = Some(cellr_error(e));
            }
            Cellr::Dummy { .. } => dummies = true,
            Cellr::Cell { cell_id, cell, .. }
                if error.is_none() && !dummies && cell_id > previous =>
            {
                previous = cell_id;
                cells.push((cell_id, cell));
            }
            _ => return Err(Error::Rejected),
        }
    }
    Ok(error.map_or(Ok(cells), Err))
}

/// The frames of a `FETCH_MULTI` response: errors first (request order), then cells (per queue ascending, above its
/// acknowledgement), then dummies; or a single `ERR` 6/7.
fn check_fetch_multi(
    frames: Vec<ResponseCmd>,
    entries: &[(Id, CellId)],
) -> Result<Result<FetchMultiOutcome>> {
    if let [ResponseCmd::Err(code)] = frames.as_slice() {
        return if fits(*code, &[]) {
            Ok(Err(Error::from_code(*code)))
        } else {
            Err(Error::Rejected)
        };
    }
    if frames.len() != FETCH_MULTI_BATCH {
        return Err(Error::Rejected);
    }
    let mut outcome = FetchMultiOutcome {
        cells: Vec::new(),
        errors: Vec::new(),
    };
    let mut stage = 0_u8;
    let mut next_entry = 0_usize;
    for frame in frames {
        let ResponseCmd::Cellr(c) = frame else {
            return Err(Error::Rejected);
        };
        match c {
            Cellr::Error { error, rid, .. } if stage == 0 => {
                let at = entries
                    .iter()
                    .skip(next_entry)
                    .position(|(r, _)| *r == rid)
                    .ok_or(Error::Rejected)?;
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
                let floor = entries
                    .iter()
                    .filter(|(r, _)| *r == rid)
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
                    _ => return Err(Error::Rejected),
                }
            }
            Cellr::Dummy { .. } => stage = 2,
            _ => return Err(Error::Rejected),
        }
    }
    Ok(Ok(outcome))
}
