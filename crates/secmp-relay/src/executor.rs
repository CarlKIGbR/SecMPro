// SPDX-License-Identifier: AGPL-3.0-or-later
//! The executor of one link (spec §8.4–§8.5, §9.2, §9.7 items 6 and 7, D.2): every 4352-byte unit the client sends
//! after `HS2` goes through [`Executor::on_unit`].
//!
//! Per unit, in this order (a failure before the commit is the LINK-level rejection of §8.5: the connection is torn
//! down, nothing is emitted, and the frame counters, the recorded `cmd_seq` and the store are unchanged):
//!
//! 1. the frame layer opens the unit under the expected counter (strict `+1`) and checks the padding
//!    (`Link::open_unit`, no change yet);
//! 2. the plaintext is decoded: `SKEY` (0x02, the one reserved opcode that is answered, ERR 6) or a D.2 request
//!    (exact fit, the §4.1 decoder obligations); anything else is a rejection;
//! 3. multi-frame assembly (ADR-048 (f), SQ-27): while a `LINK_PUT` is pending only its next `CONT` continues it;
//!    any other frame — `SKEY` included — and an orphan `CONT` are rejections;
//! 4. the frame takes a token of the per-link rate; the receive counter is committed;
//! 5. the command is admitted (the pure functions `admit` and `answer`): `cmd_seq ≤ last` is stale (one ERR 6, not executed), a
//!    fresh one is recorded and, if one of its frames was over the rate, answered with one ERR 7 without being
//!    executed (ADR-048 (p)); a `LINK_PUT` is admitted at its first frame and answered after its third; `CONT`
//!    frames are exempt;
//! 6. the command runs atomically on the relay ([`crate::exec`]) and its [`Plan`] is rendered: dummies drawn in
//!    response-frame order (reading REF-M5 7), every frame padded to 4336 B and sealed to 4352 B under `k_r2c`, in
//!    request order, right after the request's last frame (D.2).

use secmp_crypto::SecretBytes;
use secmp_proto::Decode;
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link::cont::{Assembled, LinkPutAssembler, split_blob};
use secmp_proto::link::frame::Frame;
use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH, Link, Opened};
use secmp_proto::sizes::{CELL_LEN, FRAME_PLAINTEXT_LEN, LINK_BLOB_LEN};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    Cellr, ErrCode, Request, RequestCmd, Response, ResponseCmd, opcode,
};

use crate::clock::Now;
use crate::cmdseq::{Admit, CmdSeq};
use crate::exec::{Command, RelayPlan};
use crate::plan::{CellrPlan, Plan};
use crate::rate::{RateLimit, TokenBucket};
use crate::relay::Relay;

/// What a unit led to.
pub enum Outcome {
    /// The response frames, in order (exactly the D.2 count of the request).
    Respond(Vec<Frame>),
    /// The first or second frame of a `LINK_PUT`: nothing to answer yet.
    Pending,
    /// A LINK-level rejection or a local abort: emit nothing further and close the connection (spec §8.5).
    Teardown,
}

/// The rejection marker inside the executor.
pub(crate) struct Teardown;

/// How an admitted command is answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Executed.
    Run,
    /// `cmd_seq ≤ last`: one ERR 6 (spec §9.2).
    Stale,
    /// Over the per-link frame rate: one ERR 7 (spec §9.7 item 7).
    Rate,
}

/// A decoded frame.
enum Decoded {
    /// `SKEY` with its `cmd_seq` (nothing after it is parsed, reading REF-M5 2).
    Skey(u32),
    /// A D.2 request.
    Request(Request),
}

/// What the assembler made of the frame, with the command `C` it carries (generic for the Kani harness
/// `kani_cmd_seq_monotone`).
pub(crate) enum Step<C> {
    /// A single-frame request (`Some`) or `SKEY` (`None`) with its `cmd_seq`.
    Single(u32, Option<C>),
    /// Frame 1 of a `LINK_PUT` with its `cmd_seq`.
    PutStart(u32),
    /// `CONT` 1 of the pending `LINK_PUT`.
    PutCont,
    /// `CONT` 2: the assembled `LINK_PUT` with its `cmd_seq`.
    PutDone(u32, C),
}

/// Step 5, the admission (spec §9.2, ADR-048 (f), (p)): a stale `cmd_seq` first, then the rate.
fn verdict(seq: &mut CmdSeq, cmd_seq: u32, over_rate: bool) -> Verdict {
    match seq.admit(cmd_seq) {
        Admit::Stale => Verdict::Stale,
        Admit::Fresh if over_rate => Verdict::Rate,
        Admit::Fresh => Verdict::Run,
    }
}

/// Step 5 for one frame: `Some((cmd_seq, verdict, command))` when the command is answered now, `None` while a
/// `LINK_PUT` is pending. A `LINK_PUT` is admitted at its first frame; its `CONT` frames are **exempt** — they never
/// reach `seq` — and a frame over the rate turns its pending `Run` into `Rate` (ADR-048 (p)).
///
/// # Errors
/// [`Teardown`] for a completed `LINK_PUT` without an admission (the assembler rules it out).
pub(crate) fn admit<C>(
    seq: &mut CmdSeq,
    pending: &mut Option<Verdict>,
    step: Step<C>,
    over_rate: bool,
) -> Result<Option<(u32, Verdict, Option<C>)>, Teardown> {
    match step {
        Step::Single(cmd_seq, command) => {
            Ok(Some((cmd_seq, verdict(seq, cmd_seq, over_rate), command)))
        }
        Step::PutStart(cmd_seq) => {
            *pending = Some(verdict(seq, cmd_seq, over_rate));
            Ok(None)
        }
        Step::PutCont => {
            if over_rate && *pending == Some(Verdict::Run) {
                *pending = Some(Verdict::Rate);
            }
            Ok(None)
        }
        Step::PutDone(cmd_seq, command) => {
            let mut v = pending.take().ok_or(Teardown)?;
            if over_rate && v == Verdict::Run {
                v = Verdict::Rate;
            }
            Ok(Some((cmd_seq, v, Some(command))))
        }
    }
}

/// Step 6, what is executed: a fresh command runs; a stale `cmd_seq` (§9.2) and `SKEY`, reserved for v1.1 (§8.5,
/// D.2), are answered ERR 6 (`ERR_MALFORMED`), a command over the rate ERR 7 (§9.7 item 7) — none of them executed.
///
/// # Errors
/// The `ERR` code that answers a command that is not executed.
pub(crate) fn answer<C>(verdict: Verdict, command: Option<C>) -> Result<C, ErrCode> {
    match (verdict, command) {
        (Verdict::Run, Some(c)) => Ok(c),
        (Verdict::Stale, _) | (Verdict::Run, None) => Err(ErrCode::Malformed),
        (Verdict::Rate, _) => Err(ErrCode::Rate),
    }
}

fn decode(opened: &Opened) -> Result<Decoded, Teardown> {
    let payload = opened.payload();
    if payload.first() == Some(&opcode::SKEY) {
        // reading OPEN-6 / REF-M5 2: `op ‖ cmd_seq`, the rest of the payload is not parsed
        let seq = payload
            .get(1..5)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .ok_or(Teardown)?;
        return Ok(Decoded::Skey(u32::from_be_bytes(seq)));
    }
    Request::decode(opened.padded())
        .map(Decoded::Request)
        .map_err(|_| Teardown)
}

/// The relay's end of one link.
pub struct Executor {
    link: Link,
    seq: CmdSeq,
    put: LinkPutAssembler,
    /// The admission of the pending `LINK_PUT`.
    pending: Option<Verdict>,
    rate: Option<TokenBucket>,
}

impl Executor {
    /// The executor of a link established at `now`, with the per-link frame rate `rate` (`None`: unlimited).
    #[must_use]
    pub fn new(link: Link, rate: Option<RateLimit>, now: Now) -> Self {
        Self {
            link,
            seq: CmdSeq::new(),
            put: LinkPutAssembler::new(),
            pending: None,
            rate: rate.map(|r| TokenBucket::new(r, now.mono_ms)),
        }
    }

    /// The link (counters, `sess_id`).
    #[must_use]
    pub const fn link(&self) -> &Link {
        &self.link
    }

    /// The last recorded `cmd_seq` (`link_post.cmd_seq` of the vectors).
    #[must_use]
    pub const fn last_cmd_seq(&self) -> u32 {
        self.seq.last()
    }

    /// Process one unit received on the link.
    pub fn on_unit(
        &mut self,
        relay: &Relay,
        unit: &[u8],
        now: Now,
        entropy: &mut impl Entropy,
    ) -> Outcome {
        self.step(relay, unit, now, entropy)
            .unwrap_or(Outcome::Teardown)
    }

    fn step(
        &mut self,
        relay: &Relay,
        unit: &[u8],
        now: Now,
        entropy: &mut impl Entropy,
    ) -> Result<Outcome, Teardown> {
        // 1–3: nothing changes until every check of the unit has passed (spec §8.5)
        let opened = self.link.open_unit(unit).map_err(|_| Teardown)?;
        let step = match decode(&opened)? {
            Decoded::Skey(cmd_seq) => {
                if self.put.is_pending() {
                    // SQ-27: only the pending LINK_PUT's next CONT may follow
                    return Err(Teardown);
                }
                Step::Single(cmd_seq, None)
            }
            Decoded::Request(request) => {
                let starts_put = matches!(request.cmd, RequestCmd::LinkPut { .. });
                let cmd_seq = request.cmd_seq;
                match self.put.push(request).map_err(|_| Teardown)? {
                    Assembled::Single(r) => Step::Single(r.cmd_seq, Some(Command::Single(r.cmd))),
                    Assembled::Pending if starts_put => Step::PutStart(cmd_seq),
                    Assembled::Pending => Step::PutCont,
                    Assembled::Put(p) => Step::PutDone(p.cmd_seq, Command::LinkPut(p)),
                }
            }
        };
        // 4: the frame rate counts every request frame; then the counter moves (strict +1)
        let over_rate = self.rate.as_mut().is_some_and(|b| !b.take(now.mono_ms));
        self.link.commit(&opened).map_err(|_| Teardown)?;
        // 5: admission (CONT exempt)
        let Some((cmd_seq, verdict, command)) =
            admit(&mut self.seq, &mut self.pending, step, over_rate)?
        else {
            return Ok(Outcome::Pending);
        };
        // 6: execute and answer
        let plan: RelayPlan = match answer(verdict, command) {
            Err(code) => Plan::Err(code),
            Ok(c) => relay
                .execute(self.link.sess_id(), cmd_seq, now, c)
                .map_err(|_| Teardown)?,
        };
        let frames = self.render(plan, cmd_seq, entropy)?;
        Ok(Outcome::Respond(frames))
    }

    /// Draw the plan's randomness in frame order and seal its frames.
    fn render(
        &mut self,
        plan: RelayPlan,
        cmd_seq: u32,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<Frame>, Teardown> {
        let cmds: Vec<ResponseCmd> = match plan {
            Plan::Ok => vec![ResponseCmd::Ok],
            Plan::OkQueueNew { rid, sid } => vec![ResponseCmd::OkQueueNew { rid, sid }],
            Plan::OkSend { cell_id, evicted } => vec![ResponseCmd::OkSend { cell_id, evicted }],
            Plan::Err(code) => vec![ResponseCmd::Err(code)],
            Plan::Fetch(frames) => cellrs::<FETCH_BATCH>(*frames, entropy)?,
            Plan::FetchMulti(frames) => cellrs::<FETCH_MULTI_BATCH>(*frames, entropy)?,
            Plan::LinkR {
                present,
                consumed,
                blob,
            } => {
                let blob = match blob {
                    Some(b) => b,
                    // a dummy blob: 12360 random bytes (spec §9.3, reading OPEN-11)
                    None => entropy.secret::<LINK_BLOB_LEN>().map_err(|_| Teardown)?,
                };
                let (blob_part, one, two) =
                    split_blob(blob.expose_secret()).map_err(|_| Teardown)?;
                vec![
                    ResponseCmd::LinkR {
                        present,
                        consumed,
                        blob_part,
                    },
                    ResponseCmd::Cont(one),
                    ResponseCmd::Cont(two),
                ]
            }
        };
        cmds.into_iter()
            .map(|cmd| {
                let padded = Response { cmd_seq, cmd }.encode().map_err(|_| Teardown)?;
                let payload = unpad(&padded, FRAME_PLAINTEXT_LEN).map_err(|_| Teardown)?;
                self.link.seal(payload).map_err(|_| Teardown)
            })
            .collect()
    }
}

/// A random 4096-byte cell (a dummy, or the cell of an error frame).
fn random_cell(entropy: &mut impl Entropy) -> Result<Cell, Teardown> {
    let bytes: SecretBytes<CELL_LEN> = entropy.secret().map_err(|_| Teardown)?;
    Cell::from_bytes(bytes.expose_secret()).map_err(|_| Teardown)
}

/// The `CELLR` frames of a plan, drawing in frame order.
fn cellrs<const N: usize>(
    frames: [CellrPlan<crate::exec::CellCopy>; N],
    entropy: &mut impl Entropy,
) -> Result<Vec<ResponseCmd>, Teardown> {
    frames.into_iter().map(|f| cellr(f, entropy)).collect()
}

fn cellr(
    frame: CellrPlan<crate::exec::CellCopy>,
    entropy: &mut impl Entropy,
) -> Result<ResponseCmd, Teardown> {
    Ok(ResponseCmd::Cellr(match frame {
        CellrPlan::Dummy => Cellr::Dummy {
            cell: random_cell(entropy)?,
        },
        CellrPlan::Cell { rid, cell_id, cell } => Cellr::Cell {
            rid,
            cell_id,
            cell: Cell::from_bytes(cell.expose_secret()).map_err(|_| Teardown)?,
        },
        CellrPlan::Error { error, rid } => Cellr::Error {
            error,
            rid,
            cell: random_cell(entropy)?,
        },
    }))
}
