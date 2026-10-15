// SPDX-License-Identifier: AGPL-3.0-or-later
//! The commands of [`crate::QueueTransport`] as sans-IO exchanges (spec §12.1, §9.1–§9.6, D.2, D.6), shared by the
//! synchronous [`crate::RelayQueueTransport`] and the asynchronous [`crate::driver::AsyncRelayQueueTransport`], so that
//! both build the same requests and judge the same responses (TEST-SPEC-M6 AD-08).
//!
//! An exchange is built with the command's `cmd_seq` and the link's `sess_id` (it signs the request, D.6); the driver
//! seals and writes [`Exchange::requests`], then reads response frames under [`Exchange::context`] and feeds each one to
//! [`Exchange::push`] until it returns [`Step::Done`]. Everything the relay answers is checked against the request
//! (OPEN-M5-11 A): `push` returning `Err` is a LINK-level misfit — the driver closes the link ([`Error::Rejected`]);
//! `Done(Err(..))` is the relay's answer to the command, and the link stays usable. A single `ERR` frame 6 (stale
//! `cmd_seq`, malformed) or 7 (rate) may answer any command (ADR-048 (f), (p)).

use secmp_crypto::{Ed25519SigningKey, SecretBytes};
use secmp_proto::codec::{Decode, Encode};
use secmp_proto::keys::Ed25519Sig;
use secmp_proto::link::cont::{AssembledResponse, LinkrAssembler, split_blob};
use secmp_proto::link::ids::{self, AccessKey};
use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH};
use secmp_proto::sizes::{FETCH_MULTI_MAX, HASH_LEN};
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    Cellr, CellrContext, CellrError, ErrCode, FetchEntry, LinkGetMode as WireLinkGetMode, Request,
    RequestCmd, Response, ResponseCmd,
};
use secmp_proto::wire::inv::LinkBlob;
use secmp_proto::wire::signed::{self, LinkPutFields};

use crate::caps::{QueueRef, RecvCap, SendCap, pk_of};
use crate::error::{Error, Result};
use crate::evicted::evicted_is_plausible;
use crate::relay_queue::{
    Bucket, CellId, FetchMultiOutcome, LdId, LinkGetMode, LinkGetOutcome, SendOutcome,
};

/// Where an exchange stands after a response frame.
pub(crate) enum Step<T> {
    /// More frames belong to this response.
    More,
    /// The response is complete: the command's outcome (an `Err` here is the relay's answer, the link stays up).
    Done(Result<T>),
}

/// A link-level misfit (the caller closes the link).
const fn misfit<T>() -> Result<T> {
    Err(Error::Rejected)
}

/// An `ERR` code a command's response may carry besides 6 and 7.
fn fits(code: ErrCode, allowed: &[ErrCode]) -> bool {
    matches!(code, ErrCode::Malformed | ErrCode::Rate) || allowed.contains(&code)
}

fn sig(bytes: &[u8]) -> Result<Ed25519Sig> {
    Ok(Ed25519Sig::from_bytes(bytes)?)
}

const fn cellr_error(error: CellrError) -> Error {
    match error {
        CellrError::NoQueue => Error::NoQueue,
        CellrError::Auth => Error::Auth,
        CellrError::Malformed => Error::Malformed,
    }
}

/// One command's exchange (see the module documentation).
pub(crate) struct Exchange<T> {
    seq: u32,
    requests: Vec<Request>,
    context: CellrContext,
    judge: Judge,
    _out: core::marker::PhantomData<fn() -> T>,
}

/// How the response frames are judged.
enum Judge {
    /// A single frame that must be `OK`.
    Ok { allowed: &'static [ErrCode] },
    /// `OK_QUEUE_NEW` naming the ids the client derived (spec §9.1).
    QueueNew {
        rid: Id,
        sid: Id,
        caps: Option<(RecvCap, SendCap)>,
    },
    /// `OK_SEND`.
    Send,
    /// The `FETCH_BATCH` `CELLR` frames of a `FETCH`.
    Fetch {
        rid: Id,
        ack: CellId,
        frames: Vec<Cellr>,
    },
    /// The `FETCH_MULTI_BATCH` `CELLR` frames of a `FETCH_MULTI`.
    FetchMulti {
        entries: Vec<(Id, CellId)>,
        frames: Vec<Cellr>,
    },
    /// The `LINKR` frames of a `LINK_GET`.
    LinkGet {
        consume: bool,
        assembler: Option<LinkrAssembler>,
        first: bool,
    },
}

/// What a finished exchange returns (one variant per command).
pub(crate) enum Out {
    Unit,
    Caps(RecvCap, SendCap),
    Send(SendOutcome),
    Cells(Vec<(CellId, Cell)>),
    Multi(FetchMultiOutcome),
    Link(LinkGetOutcome),
}

impl<T> Exchange<T> {
    fn new(seq: u32, requests: Vec<Request>, context: CellrContext, judge: Judge) -> Self {
        Self {
            seq,
            requests,
            context,
            judge,
            _out: core::marker::PhantomData,
        }
    }

    /// The command's `cmd_seq` (every response frame must echo it, D.2).
    pub(crate) const fn seq(&self) -> u32 {
        self.seq
    }

    /// The request frames, in order (the frames of a multi-frame command repeat `cmd_seq`).
    pub(crate) fn requests(&self) -> &[Request] {
        &self.requests
    }

    /// The decoding context of the next response frame.
    pub(crate) const fn context(&self) -> CellrContext {
        self.context
    }
}

impl<T: TryFrom<Out, Error = Error>> Exchange<T> {
    /// Take one opened response frame.
    ///
    /// # Errors
    /// [`Error::Rejected`] if the frame does not echo `cmd_seq` or does not fit the request (the caller closes the
    /// link).
    pub(crate) fn push(&mut self, response: Response) -> Result<Step<T>> {
        if response.cmd_seq != self.seq {
            return misfit();
        }
        let out = match self.judge.push(response, self.seq)? {
            Step::More => return Ok(Step::More),
            Step::Done(Err(e)) => return Ok(Step::Done(Err(e))),
            Step::Done(Ok(out)) => out,
        };
        Ok(Step::Done(Ok(T::try_from(out)?)))
    }
}

impl Judge {
    /// A single-frame response's first check: `Ok(Ok(cmd))`, the command's `ERR` as `Ok(Err(..))`, a misfit `Err`.
    fn single(cmd: ResponseCmd, allowed: &[ErrCode]) -> Result<Result<ResponseCmd>> {
        match cmd {
            ResponseCmd::Err(code) if fits(code, allowed) => Ok(Err(Error::from_code(code))),
            ResponseCmd::Err(_) => misfit(),
            other => Ok(Ok(other)),
        }
    }

    fn push(&mut self, response: Response, seq: u32) -> Result<Step<Out>> {
        if let Self::LinkGet { .. } = self {
            return self.push_linkr(response, seq);
        }
        let cmd = response.cmd;
        match self {
            Self::Ok { allowed } => match Self::single(cmd, allowed)? {
                Err(e) => Ok(Step::Done(Err(e))),
                Ok(ResponseCmd::Ok) => Ok(Step::Done(Ok(Out::Unit))),
                Ok(_) => misfit(),
            },
            Self::QueueNew { rid, sid, caps } => {
                let allowed = [ErrCode::Token, ErrCode::Full, ErrCode::Auth];
                match Self::single(cmd, &allowed)? {
                    Err(e) => Ok(Step::Done(Err(e))),
                    // the ids are derived from the keys (spec §9.1): a relay that answers others is not ours
                    Ok(ResponseCmd::OkQueueNew { rid: r, sid: s }) if r == *rid && s == *sid => {
                        let (recv, send) = caps.take().ok_or(Error::Rejected)?;
                        Ok(Step::Done(Ok(Out::Caps(recv, send))))
                    }
                    Ok(_) => misfit(),
                }
            }
            Self::Send => match Self::single(cmd, &[ErrCode::NoQueue, ErrCode::Auth])? {
                Err(e) => Ok(Step::Done(Err(e))),
                Ok(ResponseCmd::OkSend { cell_id, evicted })
                    if cell_id != 0 && evicted_is_plausible(cell_id, evicted) =>
                {
                    Ok(Step::Done(Ok(Out::Send(SendOutcome { cell_id, evicted }))))
                }
                Ok(_) => misfit(),
            },
            Self::Fetch { rid, ack, frames } => {
                match cmd {
                    ResponseCmd::Cellr(c) => frames.push(c),
                    // only the first frame may be the single `ERR` 6 / 7
                    ResponseCmd::Err(code) if frames.is_empty() && fits(code, &[]) => {
                        return Ok(Step::Done(Err(Error::from_code(code))));
                    }
                    _ => return misfit(),
                }
                if frames.len() < FETCH_BATCH {
                    return Ok(Step::More);
                }
                let frames = core::mem::take(frames);
                Ok(Step::Done(check_fetch(frames, rid, *ack)?.map(Out::Cells)))
            }
            Self::FetchMulti { entries, frames } => {
                match cmd {
                    ResponseCmd::Cellr(c) => frames.push(c),
                    ResponseCmd::Err(code) if frames.is_empty() && fits(code, &[]) => {
                        return Ok(Step::Done(Err(Error::from_code(code))));
                    }
                    _ => return misfit(),
                }
                if frames.len() < FETCH_MULTI_BATCH {
                    return Ok(Step::More);
                }
                let frames = core::mem::take(frames);
                Ok(Step::Done(Ok(Out::Multi(check_fetch_multi(
                    frames, entries,
                )?))))
            }
            Self::LinkGet { .. } => misfit(),
        }
    }

    /// The frames of a `LINK_GET` response: a single `ERR` 6 / 7, or the three `LINKR` frames (D.2).
    fn push_linkr(&mut self, response: Response, seq: u32) -> Result<Step<Out>> {
        let Self::LinkGet {
            consume,
            assembler,
            first,
        } = self
        else {
            return misfit();
        };
        if *first {
            *first = false;
            if let ResponseCmd::Err(code) = response.cmd {
                return if fits(code, &[]) {
                    Ok(Step::Done(Err(Error::from_code(code))))
                } else {
                    misfit()
                };
            }
        }
        let Some(asm) = assembler.as_mut() else {
            return misfit();
        };
        let linkr = match asm.push(response) {
            Ok(AssembledResponse::Pending) => return Ok(Step::More),
            Ok(AssembledResponse::Linkr(linkr)) => linkr,
            Ok(AssembledResponse::Single(_)) | Err(_) => return misfit(),
        };
        // {1, 1} is no state of §9.4
        if linkr.cmd_seq != seq || (linkr.present && linkr.consumed) {
            return misfit();
        }
        let blob = if *consume && linkr.present {
            Some(LinkBlob::decode(&linkr.blob).map_err(|_| Error::Rejected)?)
        } else {
            None
        };
        Ok(Step::Done(Ok(Out::Link(LinkGetOutcome {
            present: linkr.present,
            consumed: linkr.consumed,
            blob,
        }))))
    }
}

/// The frames of a `FETCH` response (D.2): an error `CELLR` followed by dummies and naming the queue, or real cells
/// above the acknowledgement in ascending order followed by dummies.
fn check_fetch(frames: Vec<Cellr>, rid: &Id, ack: CellId) -> Result<Result<Vec<(CellId, Cell)>>> {
    if let Some(Cellr::Error { error, rid: r, .. }) = frames.first() {
        // an error frame is followed by dummies only, and names the requested queue
        let rest_dummy = frames
            .iter()
            .skip(1)
            .all(|f| matches!(f, Cellr::Dummy { .. }));
        if !rest_dummy || r != rid {
            return misfit();
        }
        return Ok(Err(cellr_error(*error)));
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
            _ => return misfit(),
        }
    }
    Ok(Ok(cells))
}

/// The frames of a `FETCH_MULTI` response: errors first (request order), then cells (per queue ascending, above its
/// acknowledgement), then dummies.
fn check_fetch_multi(frames: Vec<Cellr>, entries: &[(Id, CellId)]) -> Result<FetchMultiOutcome> {
    let mut outcome = FetchMultiOutcome {
        cells: Vec::new(),
        errors: Vec::new(),
    };
    let mut stage = 0_u8;
    let mut next_entry = 0_usize;
    for frame in frames {
        match frame {
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
                // the cells come from the queues that are not in error (D.2): one queue is never both
                if outcome.errors.iter().any(|(q, _)| *q.rid() == rid) {
                    return misfit();
                }
                // above the highest ack requested for this queue and above its previous cell
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
                    _ => return misfit(),
                }
            }
            Cellr::Dummy { .. } => stage = 2,
            _ => return misfit(),
        }
    }
    Ok(outcome)
}

// ---- the exchanges ------------------------------------------------------------------------------------------------

impl TryFrom<Out> for () {
    type Error = Error;
    fn try_from(out: Out) -> Result<Self> {
        match out {
            Out::Unit => Ok(()),
            _ => Err(Error::Rejected),
        }
    }
}

impl TryFrom<Out> for (RecvCap, SendCap) {
    type Error = Error;
    fn try_from(out: Out) -> Result<Self> {
        match out {
            Out::Caps(r, s) => Ok((r, s)),
            _ => Err(Error::Rejected),
        }
    }
}

impl TryFrom<Out> for SendOutcome {
    type Error = Error;
    fn try_from(out: Out) -> Result<Self> {
        match out {
            Out::Send(s) => Ok(s),
            _ => Err(Error::Rejected),
        }
    }
}

impl TryFrom<Out> for Vec<(CellId, Cell)> {
    type Error = Error;
    fn try_from(out: Out) -> Result<Self> {
        match out {
            Out::Cells(c) => Ok(c),
            _ => Err(Error::Rejected),
        }
    }
}

impl TryFrom<Out> for FetchMultiOutcome {
    type Error = Error;
    fn try_from(out: Out) -> Result<Self> {
        match out {
            Out::Multi(m) => Ok(m),
            _ => Err(Error::Rejected),
        }
    }
}

impl TryFrom<Out> for LinkGetOutcome {
    type Error = Error;
    fn try_from(out: Out) -> Result<Self> {
        match out {
            Out::Link(l) => Ok(l),
            _ => Err(Error::Rejected),
        }
    }
}

/// `PING` (spec §9.3).
pub(crate) fn ping(seq: u32) -> Exchange<()> {
    Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::Ping,
        }],
        CellrContext::Fetch,
        Judge::Ok { allowed: &[] },
    )
}

/// The token of a command that carries one (spec §9.6).
fn token_of(access: &AccessKey, sess: &Id, seq: u32) -> Result<[u8; HASH_LEN]> {
    Ok(ids::token(access, sess, seq)?)
}

/// The keys and capabilities of a `QUEUE_NEW`, derived before the command takes its `cmd_seq` (a seed that does not
/// derive costs no `cmd_seq`, as in M5).
pub(crate) struct QueueNewKeys {
    recv_cap: RecvCap,
    send_cap: SendCap,
    recv_pk: secmp_proto::keys::Ed25519Pk,
    send_pk: secmp_proto::keys::Ed25519Pk,
}

impl QueueNewKeys {
    /// Derive from the two seeds (spec §9.1).
    pub(crate) fn derive(recv: &SecretBytes<32>, send: &SecretBytes<32>) -> Result<Self> {
        let recv_cap = RecvCap::from_seed(recv)?;
        let recv_pk = recv_cap.public_key()?;
        let send_pk = pk_of(send)?;
        let send_cap = SendCap::from_seed(&recv_pk, send)?;
        Ok(Self {
            recv_cap,
            send_cap,
            recv_pk,
            send_pk,
        })
    }
}

/// `QUEUE_NEW` (spec §9.1): the client derives the capabilities from the keys and checks the ids the relay returns.
pub(crate) fn create_queue(
    seq: u32,
    sess: &Id,
    keys: QueueNewKeys,
    access: &AccessKey,
) -> Result<Exchange<(RecvCap, SendCap)>> {
    let QueueNewKeys {
        recv_cap,
        send_cap,
        recv_pk,
        send_pk,
    } = keys;
    let token = token_of(access, sess, seq)?;
    let message = signed::queue_new(sess, seq, &recv_pk, &send_pk, &token);
    let signature = sig(&recv_cap.key()?.sign(&message))?;
    let (rid, sid) = (*recv_cap.rid(), *send_cap.sid());
    Ok(Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::QueueNew {
                recv_pk,
                send_pk,
                token,
                sig: signature,
            },
        }],
        CellrContext::Fetch,
        Judge::QueueNew {
            rid,
            sid,
            caps: Some((recv_cap, send_cap)),
        },
    ))
}

/// `SEND` one cell.
pub(crate) fn send(
    seq: u32,
    sess: &Id,
    to: &SendCap,
    cell: &Cell,
) -> Result<Exchange<SendOutcome>> {
    let message = signed::send(sess, seq, to.sid(), cell);
    let signature = sig(&to.key()?.sign(&message))?;
    Ok(Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::Send {
                sid: *to.sid(),
                // the request's own copy, wiped when the request drops (a `Cell` has no `Clone`; M5 review C-4)
                cell: Cell::from_bytes(cell.as_bytes())?,
                sig: signature,
            },
        }],
        CellrContext::Fetch,
        Judge::Send,
    ))
}

/// `FETCH` with the cumulative acknowledgement.
pub(crate) fn fetch(
    seq: u32,
    sess: &Id,
    from: &RecvCap,
    ack: CellId,
) -> Result<Exchange<Vec<(CellId, Cell)>>> {
    let message = signed::fetch(sess, seq, from.rid(), ack);
    let signature = sig(&from.key()?.sign(&message))?;
    Ok(Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::Fetch {
                rid: *from.rid(),
                ack,
                sig: signature,
            },
        }],
        CellrContext::Fetch,
        Judge::Fetch {
            rid: *from.rid(),
            ack,
            frames: Vec::with_capacity(FETCH_BATCH),
        },
    ))
}

/// Whether `from` is a valid `FETCH_MULTI` list (1 to 32 queues); checked before a `cmd_seq` is taken.
pub(crate) fn fetch_multi_len_ok(from: &[(&RecvCap, CellId)]) -> bool {
    !from.is_empty() && from.len() <= FETCH_MULTI_MAX
}

/// `FETCH_MULTI` over 1 to 32 queues.
pub(crate) fn fetch_multi(
    seq: u32,
    sess: &Id,
    from: &[(&RecvCap, CellId)],
) -> Result<Exchange<FetchMultiOutcome>> {
    if !fetch_multi_len_ok(from) {
        return Err(Error::Invalid);
    }
    let mut entries = Vec::with_capacity(from.len());
    for (cap, ack) in from {
        let message = signed::fetch_multi_entry(sess, seq, cap.rid(), *ack);
        entries.push(FetchEntry {
            rid: *cap.rid(),
            ack: *ack,
            sig: sig(&cap.key()?.sign(&message))?,
        });
    }
    let expect = from.iter().map(|(c, a)| (*c.rid(), *a)).collect();
    Ok(Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::FetchMulti { entries },
        }],
        CellrContext::FetchMulti,
        Judge::FetchMulti {
            entries: expect,
            frames: Vec::with_capacity(FETCH_MULTI_BATCH),
        },
    ))
}

/// `QUEUE_DEL`.
pub(crate) fn delete_queue(seq: u32, sess: &Id, q: &RecvCap) -> Result<Exchange<()>> {
    let message = signed::queue_del(sess, seq, q.rid());
    let signature = sig(&q.key()?.sign(&message))?;
    Ok(Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::QueueDel {
                rid: *q.rid(),
                sig: signature,
            },
        }],
        CellrContext::Fetch,
        Judge::Ok {
            allowed: &[ErrCode::NoQueue, ErrCode::Auth],
        },
    ))
}

/// The fields of a `LINK_PUT` besides the link's own.
pub(crate) struct LinkPut<'a> {
    pub(crate) id: LdId,
    pub(crate) owner: &'a SecretBytes<32>,
    pub(crate) blob: &'a LinkBlob,
    pub(crate) one_time: bool,
    pub(crate) expires: Bucket,
    pub(crate) access: &'a AccessKey,
}

/// `LINK_PUT` (three frames).
pub(crate) fn put_link_data(seq: u32, sess: &Id, put: &LinkPut<'_>) -> Result<Exchange<()>> {
    let token = token_of(put.access, sess, seq)?;
    let owner_pk = pk_of(put.owner)?;
    let fields = LinkPutFields {
        ld_id: &put.id,
        one_time: put.one_time,
        expires_bucket: put.expires,
        owner_pk: &owner_pk,
        token: &token,
    };
    let message = signed::link_put(sess, seq, &fields, put.blob)?;
    let signature = sig(&Ed25519SigningKey::from_seed(put.owner.expose_secret())?.sign(&message))?;
    let (blob_part, one, two) = split_blob(&put.blob.encode()?)?;
    Ok(Exchange::new(
        seq,
        vec![
            Request {
                cmd_seq: seq,
                cmd: RequestCmd::LinkPut {
                    ld_id: put.id,
                    one_time: put.one_time,
                    expires_bucket: put.expires,
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
        ],
        CellrContext::Fetch,
        Judge::Ok {
            allowed: &[
                ErrCode::Token,
                ErrCode::Full,
                ErrCode::Auth,
                ErrCode::Exists,
            ],
        },
    ))
}

/// `LINK_GET`.
pub(crate) fn get_link_data(
    seq: u32,
    sess: &Id,
    id: LdId,
    mode: &LinkGetMode<'_>,
) -> Result<Exchange<LinkGetOutcome>> {
    let (wire_mode, consume) = match mode {
        LinkGetMode::Consume => (WireLinkGetMode::Consume, true),
        LinkGetMode::OwnerStatus(owner) => {
            let message = signed::link_get_owner_status(sess, seq, &id);
            let key = Ed25519SigningKey::from_seed(owner.expose_secret())?;
            (
                WireLinkGetMode::OwnerStatus(sig(&key.sign(&message))?),
                false,
            )
        }
    };
    Ok(Exchange::new(
        seq,
        vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::LinkGet {
                ld_id: id,
                mode: wire_mode,
            },
        }],
        CellrContext::Fetch,
        Judge::LinkGet {
            consume,
            assembler: Some(LinkrAssembler::new()),
            first: true,
        },
    ))
}
