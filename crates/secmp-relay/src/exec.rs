// SPDX-License-Identifier: AGPL-3.0-or-later
//! The semantics of the eight commands (spec §9.1–§9.7, D.2, D.6; ADR-048 (f)–(l), (o); readings OPEN-5…OPEN-12,
//! REF-M5 1–8, SQ-28): one function per command, each run under the relay's lock so that every command is atomic
//! (one-time consumption, §9.4: "the first consume wins").
//!
//! **Check order** (OPEN-M5-04 A = the reference's order): `QUEUE_NEW` token, signature, known `recv_pk` (identical:
//! `OK_QUEUE_NEW` without side effects; another `send_pk`: ERR 4), budget; `SEND` `sid`, signature; `FETCH` and each
//! `FETCH_MULTI` entry `rid`, signature, `ack`; `QUEUE_DEL` `rid`, signature; `LINK_PUT` token, signature,
//! `expires_bucket` range (ADR-048 (o)), `ld_id`, budget; owner-status `LINK_GET` entry and signature together.
//! Drain (OPEN-M5-09 A) answers `QUEUE_NEW` and `LINK_PUT` with ERR 2 at the budget step.
//!
//! Every signature is the strict Ed25519 verification of spec §3.5 over the D.6 message, which binds the link's
//! `sess_id` and the request's `cmd_seq` (§9.2); tokens are compared in constant time (§9.6). A command that fails
//! changes nothing in the store. The functions return a [`Plan`]; drawing the dummies and sealing are the
//! executor's (`crate::executor`).

use secmp_crypto::{Ed25519VerifyingKey, SecretBytes, sha256};
use secmp_proto::keys::{Ed25519Pk, Ed25519Sig};
use secmp_proto::link::cont::LinkPut;
use secmp_proto::link::ids::{self, AccessKey};
use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH, LINKDATA_TTL_HOURS};
use secmp_proto::sizes::{CELL_LEN, HASH_LEN, LINK_BLOB_LEN};
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{CellrError, ErrCode, FetchEntry, LinkGetMode, RequestCmd};
use secmp_proto::wire::signed::{self, LinkPutFields};

use crate::budget::{LINKDATA_BLOB_CHARGE, LINKDATA_RESERVATION, Pool, QUEUE_RESERVATION};
use crate::buf::{BlobBuf, CellBuf};
use crate::clock::HourBucket;
use crate::linkdata::Entry;
use crate::plan::{FetchMultiOutcome, FetchOutcome, Plan, plan_fetch, plan_fetch_multi};
use crate::relay::State;

/// A copy of a stored cell in a response (wiped when the response is sealed; [`crate::buf::CellCopy`]).
pub use crate::buf::CellCopy;
/// A copy of a stored blob in a response.
pub type BlobCopy = SecretBytes<LINK_BLOB_LEN>;
/// The relay's plans.
pub type RelayPlan = Plan<CellCopy, BlobCopy>;

/// A command the executor runs: a single-frame request, or an assembled `LINK_PUT`.
pub enum Command {
    /// A request of one frame (never `LINK_PUT` or `CONT`; those arrive assembled).
    Single(RequestCmd),
    /// A complete `LINK_PUT` (three frames).
    LinkPut(Box<LinkPut>),
}

/// A local abort: an exhausted counter (`cell_id`, `arrival`) or an internal invariant; the connection is closed
/// without an answer (`checked_add`, CLAUDE.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Abort;

/// What one command sees of its link and time.
pub struct Ctx<'a> {
    /// The link's `sess_id` (bound into every signature and token).
    pub sess_id: &'a Id,
    /// The request's `cmd_seq`.
    pub cmd_seq: u32,
    /// The current hour bucket.
    pub now: HourBucket,
    /// The relay access key (spec §9.6).
    pub access_key: &'a AccessKey,
    /// The relay is draining (OPEN-M5-09).
    pub draining: bool,
}

/// Strict Ed25519 verification (spec §3.5) of `sig` by `pk` over `msg`; a key the verifier refuses is a failure.
fn signed_by(pk: &Ed25519Pk, msg: &[u8], sig: &Ed25519Sig) -> bool {
    Ed25519VerifyingKey::from_bytes(pk.as_bytes())
        .is_ok_and(|vk| vk.verify(msg, sig.as_bytes()).is_ok())
}

/// The token check of spec §9.6: `HMAC-SHA-256(access_key, "SecMP-Q/1 token" ‖ sess_id ‖ cmd_seq)`, compared in
/// constant time.
fn token_ok(ctx: &Ctx<'_>, token: &[u8; HASH_LEN]) -> bool {
    ids::token_verify(ctx.access_key, ctx.sess_id, ctx.cmd_seq, token).is_ok_and(bool::from)
}

fn copy_cell(bytes: &[u8]) -> Result<CellCopy, Abort> {
    CellCopy::new(bytes).map_err(|_| Abort)
}

/// Run one command on the state.
///
/// # Errors
/// [`Abort`] on an exhausted counter or a broken internal invariant (the caller closes the link).
pub fn run(st: &mut State, ctx: &Ctx<'_>, command: Command) -> Result<RelayPlan, Abort> {
    match command {
        Command::LinkPut(put) => Ok(link_put(st, ctx, *put)),
        Command::Single(cmd) => match cmd {
            RequestCmd::QueueNew {
                recv_pk,
                send_pk,
                token,
                sig,
            } => queue_new(st, ctx, recv_pk, send_pk, &token, &sig),
            RequestCmd::Send { sid, cell, sig } => send(st, ctx, &sid, cell, &sig),
            RequestCmd::Fetch { rid, ack, sig } => fetch(st, ctx, &rid, ack, &sig),
            RequestCmd::FetchMulti { entries } => fetch_multi(st, ctx, &entries),
            RequestCmd::QueueDel { rid, sig } => Ok(queue_del(st, ctx, &rid, &sig)),
            RequestCmd::LinkGet { ld_id, mode } => link_get(st, ctx, &ld_id, &mode),
            RequestCmd::Ping => Ok(Plan::Ok),
            // the assembler hands these over only as `Command::LinkPut`, never as single frames
            RequestCmd::LinkPut { .. } | RequestCmd::Cont(_) => Err(Abort),
        },
    }
}

/// `QUEUE_NEW` (spec §9.1, §9.3, §9.7 items 4 and 8).
fn queue_new(
    st: &mut State,
    ctx: &Ctx<'_>,
    recv_pk: Ed25519Pk,
    send_pk: Ed25519Pk,
    token: &[u8; HASH_LEN],
    sig: &Ed25519Sig,
) -> Result<RelayPlan, Abort> {
    if !token_ok(ctx, token) {
        return Ok(Plan::Err(ErrCode::Token));
    }
    let msg = signed::queue_new(ctx.sess_id, ctx.cmd_seq, &recv_pk, &send_pk, token);
    if !signed_by(&recv_pk, &msg, sig) {
        return Ok(Plan::Err(ErrCode::Auth));
    }
    let rid = ids::rid(&recv_pk).map_err(|_| Abort)?;
    let sid = ids::sid(&recv_pk, &send_pk).map_err(|_| Abort)?;
    if let Some(q) = st.queues.get(&rid) {
        // §9.7 item 8: identical ⇒ OK_QUEUE_NEW without side effects; another send_pk ⇒ ERR_AUTH
        return Ok(if q.send_pk == send_pk {
            Plan::OkQueueNew { rid, sid }
        } else {
            Plan::Err(ErrCode::Auth)
        });
    }
    if st.queues.has_sid(&sid) {
        // a 128-bit sid collision with another queue: never two queues under one sid (fail closed)
        return Ok(Plan::Err(ErrCode::Auth));
    }
    if ctx.draining || st.budget.reserve(Pool::Queues, QUEUE_RESERVATION).is_err() {
        return Ok(Plan::Err(ErrCode::Full));
    }
    st.queues.insert(rid, sid, recv_pk, send_pk, ctx.now);
    Ok(Plan::OkQueueNew { rid, sid })
}

/// `SEND` (spec §9.3, §9.5): never refused for the budget (§9.7 item 4).
fn send(
    st: &mut State,
    ctx: &Ctx<'_>,
    sid: &Id,
    cell: Cell,
    sig: &Ed25519Sig,
) -> Result<RelayPlan, Abort> {
    let Some(rid) = st.queues.rid_of_sid(sid) else {
        return Ok(Plan::Err(ErrCode::NoQueue));
    };
    let send_pk = st.queues.get(&rid).ok_or(Abort)?.send_pk;
    let msg = signed::send(ctx.sess_id, ctx.cmd_seq, sid, &cell);
    if !signed_by(&send_pk, &msg, sig) {
        return Ok(Plan::Err(ErrCode::Auth));
    }
    let arrival = st.queues.take_arrival().ok_or(Abort)?;
    let q = st.queues.get_mut(&rid).ok_or(Abort)?;
    let (cell_id, evicted) = q
        .cells
        .push(arrival, ctx.now, CellBuf::new(cell))
        .map_err(|_| Abort)?;
    Ok(Plan::OkSend { cell_id, evicted })
}

/// The checks and the acknowledgement of one `FETCH` or `FETCH_MULTI` entry (spec §9.1, §9.3; OPEN-7, OPEN-8):
/// `None` if the entry is served (cells `≤ ack` deleted, `last_fetch_bucket` set), else its error.
fn check_and_ack(
    st: &mut State,
    ctx: &Ctx<'_>,
    rid: &Id,
    ack: u64,
    sig: &Ed25519Sig,
    msg: &[u8],
) -> Option<CellrError> {
    let Some(q) = st.queues.get_mut(rid) else {
        return Some(CellrError::NoQueue);
    };
    if !signed_by(&q.recv_pk, msg, sig) {
        return Some(CellrError::Auth);
    }
    if ack >= q.cells.next_cell_id() {
        // §9.1: a stale ack would delete every new cell; MALFORMED, nothing deleted
        return Some(CellrError::Malformed);
    }
    q.cells.ack(ack);
    q.last_fetch = Some(ctx.now);
    None
}

/// `FETCH` (spec §9.3, reading OPEN-7): exactly `F` `CELLR` frames.
fn fetch(
    st: &mut State,
    ctx: &Ctx<'_>,
    rid: &Id,
    ack: u64,
    sig: &Ed25519Sig,
) -> Result<RelayPlan, Abort> {
    let msg = signed::fetch(ctx.sess_id, ctx.cmd_seq, rid, ack);
    if let Some(error) = check_and_ack(st, ctx, rid, ack, sig, &msg) {
        return Ok(Plan::Fetch(plan_fetch(FetchOutcome::Error {
            error,
            rid: *rid,
        })));
    }
    let q = st.queues.get(rid).ok_or(Abort)?;
    let cells = q
        .cells
        .iter()
        .take(FETCH_BATCH)
        .map(|s| Ok((s.cell_id, copy_cell(s.buf.as_bytes())?)))
        .collect::<Result<Vec<_>, Abort>>()?;
    Ok(Plan::Fetch(plan_fetch(FetchOutcome::Cells(cells))))
}

/// `FETCH_MULTI` (spec §9.3, readings OPEN-8, SQ-28): each entry checked and acknowledged in request order; the
/// error frames first in request order, then the cells of the served queues oldest-first by `arrival` (a queue
/// listed twice is selected once), then dummies — exactly `F_M` frames.
fn fetch_multi(st: &mut State, ctx: &Ctx<'_>, entries: &[FetchEntry]) -> Result<RelayPlan, Abort> {
    let mut errors: Vec<(CellrError, Id)> = Vec::new();
    let mut served: Vec<Id> = Vec::new();
    for e in entries {
        let msg = signed::fetch_multi_entry(ctx.sess_id, ctx.cmd_seq, &e.rid, e.ack);
        match check_and_ack(st, ctx, &e.rid, e.ack, &e.sig, &msg) {
            Some(error) => errors.push((error, e.rid)),
            None => {
                if !served.contains(&e.rid) {
                    served.push(e.rid);
                }
            }
        }
    }
    let room = FETCH_MULTI_BATCH.saturating_sub(errors.len());
    let mut candidates: Vec<(u64, Id, u64, &[u8; CELL_LEN])> = Vec::new();
    for rid in &served {
        let q = st.queues.get(rid).ok_or(Abort)?;
        // a queue's cells are in arrival order: its first `room` cells are the only candidates
        candidates.extend(
            q.cells
                .iter()
                .take(room)
                .map(|s| (s.arrival, *rid, s.cell_id, s.buf.as_bytes())),
        );
    }
    candidates.sort_by_key(|c| c.0);
    let cells = candidates
        .into_iter()
        .take(room)
        .map(|(_, rid, cell_id, bytes)| Ok((rid, cell_id, copy_cell(bytes)?)))
        .collect::<Result<Vec<_>, Abort>>()?;
    Ok(Plan::FetchMulti(plan_fetch_multi(FetchMultiOutcome {
        errors,
        cells,
    })))
}

/// `QUEUE_DEL` (spec §9.3; reading OPEN-9): the queue and its cells are deleted (wiped) and its reservation
/// released.
fn queue_del(st: &mut State, ctx: &Ctx<'_>, rid: &Id, sig: &Ed25519Sig) -> RelayPlan {
    let Some(q) = st.queues.get(rid) else {
        return Plan::Err(ErrCode::NoQueue);
    };
    let msg = signed::queue_del(ctx.sess_id, ctx.cmd_seq, rid);
    if !signed_by(&q.recv_pk, &msg, sig) {
        return Plan::Err(ErrCode::Auth);
    }
    if st.queues.remove(rid) {
        st.budget.release(Pool::Queues, QUEUE_RESERVATION);
    }
    Plan::Ok
}

/// `LINK_PUT` (spec §9.3, §9.4; ADR-048 (o); readings OPEN-9, REF-M5 5): one answer after the third frame.
fn link_put(st: &mut State, ctx: &Ctx<'_>, put: LinkPut) -> RelayPlan {
    if !token_ok(ctx, &put.token) {
        return Plan::Err(ErrCode::Token);
    }
    let fields = LinkPutFields {
        ld_id: &put.ld_id,
        one_time: put.one_time,
        expires_bucket: put.expires_bucket,
        owner_pk: &put.owner_pk,
        token: &put.token,
    };
    // D.6: the signature covers SHA-256 of the whole 12360-byte blob
    let msg = signed::link_put_hashed(ctx.sess_id, ctx.cmd_seq, &fields, &sha256(&[&put.blob]));
    if !signed_by(&put.owner_pk, &msg, &put.sig) {
        return Plan::Err(ErrCode::Auth);
    }
    // ADR-048 (o): now_bucket ≤ expires_bucket ≤ now_bucket + LINKDATA_TTL, else MALFORMED, nothing stored
    let latest = ctx
        .now
        .plus(LINKDATA_TTL_HOURS)
        .unwrap_or(HourBucket(u32::MAX));
    let expires = HourBucket(put.expires_bucket);
    if expires < ctx.now || expires > latest {
        return Plan::Err(ErrCode::Malformed);
    }
    // an entry or a consumption marker: ERR_EXISTS until it expires (§9.4)
    if st.linkdata.get(&put.ld_id).is_some() {
        return Plan::Err(ErrCode::Exists);
    }
    if ctx.draining || !st.budget.fits(Pool::LinkData, LINKDATA_RESERVATION) {
        return Plan::Err(ErrCode::Full);
    }
    let Ok(blob) = BlobBuf::new(put.blob) else {
        // the assembler delivers exactly 12360 bytes; anything else is refused without storing
        return Plan::Err(ErrCode::Malformed);
    };
    if st
        .budget
        .reserve(Pool::LinkData, LINKDATA_RESERVATION)
        .is_err()
    {
        return Plan::Err(ErrCode::Full);
    }
    st.linkdata.insert(
        put.ld_id,
        Entry {
            one_time: put.one_time,
            expires,
            owner_pk: put.owner_pk,
            blob: Some(blob),
        },
    );
    Plan::Ok
}

/// `LINK_GET` (spec §9.3, §9.4; readings OPEN-10, OPEN-11, REF-M5 5–7): three frames in every case; consume mode
/// returns a stored blob (a one-time blob is then dropped, leaving its marker), owner status never consumes and
/// answers {0, 0} when the entry is absent or the signature does not verify.
fn link_get(
    st: &mut State,
    ctx: &Ctx<'_>,
    ld_id: &Id,
    mode: &LinkGetMode,
) -> Result<RelayPlan, Abort> {
    match mode {
        LinkGetMode::Consume => {
            let Some(e) = st.linkdata.get_mut(ld_id) else {
                return Ok(Plan::LinkR {
                    present: false,
                    consumed: false,
                    blob: None,
                });
            };
            let Some(stored) = &e.blob else {
                return Ok(Plan::LinkR {
                    present: false,
                    consumed: true,
                    blob: None,
                });
            };
            let copy = SecretBytes::from_slice(stored.as_bytes()).map_err(|_| Abort)?;
            if e.one_time {
                // §9.4: deleted atomically by the first consume (under the relay's lock); the marker remains
                e.blob = None;
                st.budget.release(Pool::LinkData, LINKDATA_BLOB_CHARGE);
            }
            Ok(Plan::LinkR {
                present: true,
                consumed: false,
                blob: Some(copy),
            })
        }
        LinkGetMode::OwnerStatus(sig) => {
            let msg = signed::link_get_owner_status(ctx.sess_id, ctx.cmd_seq, ld_id);
            let status = st
                .linkdata
                .get(ld_id)
                .filter(|e| signed_by(&e.owner_pk, &msg, sig))
                .map_or((false, false), |e| (e.present(), e.consumed()));
            Ok(Plan::LinkR {
                present: status.0,
                consumed: status.1,
                blob: None,
            })
        }
    }
}
