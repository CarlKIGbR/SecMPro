// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kani harnesses of the relay (TEST-SPEC-M5 (e) K-05 … K-07; `docs/06` §4), compiled only under `cargo kani`.
//!
//! - K-05 `kani_cmd_seq_monotone`: the admission of the executor (`executor::admit`, `executor::answer` over
//!   [`CmdSeq`]) on every sequence of five frames — single-frame requests, `SKEY`, `LINK_PUT` frame 1, its two
//!   `CONT`s, in any order, with any `cmd_seq` and any rate outcome: `last` never decreases and equals the maximum
//!   recorded; a stale `cmd_seq` is answered ERR 6 and nothing is executed; a `CONT` never touches `last` and
//!   completes the `LINK_PUT` with the verdict of its first frame (spec §9.2, ADR-048 (f), (p)).
//! - K-06 `kani_queue_eviction_bounds`: [`Cells`] at a capacity of 3 with a plain `u8` buffer, on a fixed operation
//!   pattern with symbolic acknowledgements (the bound: a free search over four operations gave no verdict in 25 min
//!   on this machine): three `SEND`s from empty (lengths 0, 1, 2), an acknowledgement of any `u64` on the full queue,
//!   a `SEND` at whatever length that left (0…3; at the capacity 3 the eviction), an acknowledgement of any `u64` (on
//!   a queue of 1…3 cells). Every `SEND`: at most 3 cells after it, at capacity the oldest evicted and reported, the
//!   next id, `next_cell_id` strictly increasing; every acknowledgement deletes exactly the ids `≤ ack` and keeps
//!   the order (spec §9.1, §9.3, §9.5). Negative control (M4 C-15): the same checks on a copy of `Cells::push`
//!   without the eviction fail (`docs/reviews/M05-evidence/kani-m5b-k06-negative-control.txt`, which holds the
//!   patch).
//! - K-07 `kani_executor_response_count` [SQ-26]: for every decoded request kind (the nine opcodes of D.2, `SKEY`
//!   included), every admission (any recorded `last`, any `cmd_seq`, any rate outcome per frame) and every store
//!   outcome the executor can plan for it — the crypto and the stores replaced by a free choice among the plans
//!   `crate::exec` returns for the command; a `FETCH` outcome is an error or 0, 1, 4 or 5 cells, a `FETCH_MULTI`
//!   outcome one of eight (errors, cells) shapes from (0, 0) to (9, 3), every field symbolic — the plan renders the
//!   D.2 frame count (`Plan::frame_count`); a stale `cmd_seq` and the rate limit give one frame; `plan_fetch` and
//!   `plan_fetch_multi` lay out their `CELLR` frames as readings OPEN-7, OPEN-8 and SQ-28 fix them (D.2 `:839`,
//!   §9.3 `:610`). The outcome lengths are concrete per case: symbolic lengths gave no verdict in 25 min.

use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH};
use secmp_proto::wire::frame::{CellrError, ErrCode, opcode};

use crate::cells::{Cells, IdsExhausted};
use crate::clock::HourBucket;
use crate::cmdseq::CmdSeq;
use crate::executor::{Step, Verdict, admit, answer};
use crate::plan::{CellrPlan, FetchMultiOutcome, FetchOutcome, Plan, plan_fetch, plan_fetch_multi};

// ---- K-05 --------------------------------------------------------------------------------------------------------

/// Frames per K-05 sequence: enough for a request that raises `last`, then a complete `LINK_PUT` and one more.
const K05_FRAMES: usize = 5;

/// What `executor::answer` must do with a verdict: execute a fresh command, answer the rest with one `ERR`.
fn check_answer(verdict: Verdict, command: Option<u8>) {
    let answered = answer(verdict, command);
    let want = match verdict {
        // spec §9.2: stale ⇒ ERR 6 (`ERR_MALFORMED`), nothing executed
        Verdict::Stale => Err(ErrCode::Malformed),
        // §9.7 item 7, ADR-048 (p): ERR 7, nothing executed
        Verdict::Rate => Err(ErrCode::Rate),
        // a fresh request runs; `SKEY` (no command) is answered ERR 6
        Verdict::Run => command.ok_or(ErrCode::Malformed),
    };
    assert!(answered == want);
}

/// K-05 (TEST-SPEC-M5 (e)): `last` never decreases; stale ⇒ ERR 6 and nothing executed; `CONT` exempt.
#[kani::proof]
#[kani::unwind(6)]
fn kani_cmd_seq_monotone() {
    assert!(ErrCode::Malformed.byte() == 6 && ErrCode::Rate.byte() == 7);
    let mut seq = CmdSeq::new();
    let mut pending: Option<Verdict> = None;
    // the spec's view of the pending LINK_PUT: the verdict its first frame got, ERR 7 once a frame was over the rate
    let mut ghost: Option<Verdict> = None;
    for _ in 0..K05_FRAMES {
        let before = seq.last();
        let kind: u8 = kani::any();
        let cmd_seq: u32 = kani::any();
        let command: Option<u8> = kani::any();
        let over_rate: bool = kani::any();
        let fresh = cmd_seq > before;
        let step = match kind % 4 {
            0 => Step::Single(cmd_seq, command),
            1 => Step::PutStart(cmd_seq),
            2 => Step::PutCont,
            _ => Step::PutDone(cmd_seq, command.unwrap_or(0)),
        };
        let result = admit(&mut seq, &mut pending, step, over_rate);
        assert!(seq.last() >= before);
        let expected = if !fresh {
            Verdict::Stale
        } else if over_rate {
            Verdict::Rate
        } else {
            Verdict::Run
        };
        match kind % 4 {
            0 => {
                // recorded iff greater than last: last = max(last, cmd_seq)
                assert!(seq.last() == if fresh { cmd_seq } else { before });
                let Ok(Some((s, v, c))) = result else {
                    panic!("a single-frame request is answered at once")
                };
                assert!(s == cmd_seq && v == expected && c == command);
                check_answer(v, c);
                kani::cover!(!fresh, "a stale request is answered ERR 6");
                kani::cover!(
                    fresh && !over_rate && command.is_some(),
                    "a fresh request is executed"
                );
            }
            1 => {
                assert!(seq.last() == if fresh { cmd_seq } else { before });
                assert!(matches!(result, Ok(None)));
                assert!(pending == Some(expected));
                ghost = Some(expected);
            }
            2 => {
                // exempt: a CONT never reaches `seq`, whatever its cmd_seq
                assert!(seq.last() == before);
                assert!(matches!(result, Ok(None)));
                if over_rate && ghost == Some(Verdict::Run) {
                    ghost = Some(Verdict::Rate);
                }
                assert!(pending == ghost);
            }
            _ => {
                assert!(seq.last() == before);
                match ghost.take() {
                    None => {
                        assert!(result.is_err());
                    }
                    Some(g) => {
                        let want = if over_rate && g == Verdict::Run {
                            Verdict::Rate
                        } else {
                            g
                        };
                        let Ok(Some((s, v, c))) = result else {
                            panic!("the third frame of a LINK_PUT is answered")
                        };
                        assert!(s == cmd_seq && v == want && c == Some(command.unwrap_or(0)));
                        check_answer(v, c);
                        kani::cover!(
                            v == Verdict::Run && cmd_seq <= before,
                            "a CONT whose cmd_seq is not above last completes a fresh LINK_PUT"
                        );
                        kani::cover!(
                            v == Verdict::Stale,
                            "a stale LINK_PUT is answered ERR 6 after its third frame"
                        );
                        kani::cover!(
                            v == Verdict::Rate,
                            "a LINK_PUT over the rate is answered ERR 7"
                        );
                    }
                }
                assert!(pending.is_none());
            }
        }
    }
}

// ---- K-06 --------------------------------------------------------------------------------------------------------

/// The capacity of the K-06 store.
const CAP: usize = 3;
/// The ids a check looks at (one more than the capacity, so that an overfull store is seen).
const SEEN: usize = 4;

/// What the K-06 checks need of one queue's cells; implemented by the real [`Cells`] (and, for the negative control
/// only, by a copy without the eviction).
trait Fifo {
    /// The first [`SEEN`] `cell_id`s, oldest first, and the number of stored cells.
    fn ids(&self) -> ([u64; SEEN], usize);
    /// `next_cell_id`.
    fn next_id(&self) -> u64;
    /// `SEND` (the arrival number and the buffer play no part in the properties: fixed values).
    fn store(&mut self) -> Result<(u64, Option<u64>), IdsExhausted>;
    /// The acknowledgement of `FETCH`.
    fn delete_to(&mut self, ack: u64) -> usize;
}

impl Fifo for Cells<u8, CAP> {
    fn ids(&self) -> ([u64; SEEN], usize) {
        let mut out = [0_u64; SEEN];
        let mut n = 0_usize;
        for s in self.iter() {
            if let Some(slot) = out.get_mut(n) {
                *slot = s.cell_id;
            }
            n = n.saturating_add(1);
        }
        (out, n)
    }

    fn next_id(&self) -> u64 {
        self.next_cell_id()
    }

    fn store(&mut self) -> Result<(u64, Option<u64>), IdsExhausted> {
        self.push(0, HourBucket(0), 0)
    }

    fn delete_to(&mut self, ack: u64) -> usize {
        self.ack(ack)
    }
}

/// What the checks saw of the store: the ids (oldest first), their number, `next_cell_id`.
#[derive(Clone, Copy)]
struct Seen {
    ids: [u64; SEEN],
    len: usize,
    next: u64,
}

impl Seen {
    fn of<F: Fifo>(c: &F) -> Self {
        let (ids, len) = c.ids();
        let s = Self {
            ids,
            len,
            next: c.next_id(),
        };
        // the store's invariant: ascending ids below next_cell_id
        for i in 0..SEEN {
            if i < s.len {
                assert!(s.ids[i] < s.next);
                if i > 0 {
                    assert!(s.ids[i - 1] < s.ids[i]);
                }
            }
        }
        s
    }
}

/// A `SEND` on `c`, checked against what was seen before it; returns what is seen after it. (The covers come before
/// the checks: a failed check ends the path, and the negative control must still reach every cover.)
fn checked_send<F: Fifo>(c: &mut F, before: Seen) -> Seen {
    kani::cover!(
        before.len == CAP,
        "a SEND at capacity evicts the oldest cell"
    );
    let Ok((cell_id, evicted)) = c.store() else {
        panic!("ids from 1 are not exhausted after a few cells")
    };
    let after = Seen::of(c);
    // §9.1: the next id, strictly increasing
    assert!(cell_id == before.next);
    assert!(after.next > before.next);
    assert!(after.len <= CAP);
    if before.len == CAP {
        // §9.5: the oldest is evicted and reported, the others move up, the new cell is last
        assert!(evicted == Some(before.ids[0]));
        assert!(after.len == CAP);
        for i in 0..CAP - 1 {
            assert!(after.ids[i] == before.ids[i + 1]);
        }
        assert!(after.ids[CAP - 1] == cell_id);
    } else {
        assert!(evicted.is_none());
        assert!(after.len == before.len + 1);
        for i in 0..CAP {
            if i < before.len {
                assert!(after.ids[i] == before.ids[i]);
            }
        }
        assert!(after.ids[before.len] == cell_id);
    }
    after
}

/// An acknowledgement of any `ack` on `c`, checked against what was seen before it; returns what is seen after it.
fn checked_ack<F: Fifo>(c: &mut F, before: Seen) -> Seen {
    let ack: u64 = kani::any();
    // §9.3: exactly the ids ≤ ack are deleted (cumulative), the rest keep their order
    let mut le = 0_usize;
    for i in 0..SEEN {
        if i < before.len && before.ids[i] <= ack {
            le += 1;
        }
    }
    kani::cover!(
        le > 0 && le < before.len,
        "an acknowledgement deletes some cells and keeps the newer ones"
    );
    kani::cover!(
        before.len == CAP && le == before.len,
        "an acknowledgement empties a full queue"
    );
    let deleted = c.delete_to(ack);
    let after = Seen::of(c);
    assert!(after.next == before.next);
    assert!(deleted == le);
    assert!(after.len == before.len - le);
    for i in 0..SEEN {
        if i < after.len {
            assert!(after.ids[i] > ack);
            assert!(after.ids[i] == before.ids[i + le]);
        }
    }
    after
}

/// The K-06 operation pattern on `c` (module documentation): three `SEND`s, an acknowledgement of any `u64`, a
/// `SEND`, an acknowledgement of any `u64`.
fn eviction_bounds<F: Fifo>(c: &mut F) {
    let mut seen = Seen::of(c);
    for _ in 0..CAP {
        seen = checked_send(c, seen);
    }
    seen = checked_ack(c, seen);
    seen = checked_send(c, seen);
    let _ = checked_ack(c, seen);
}

/// K-06 (TEST-SPEC-M5 (e)): the store logic at a capacity of 3.
#[kani::proof]
#[kani::unwind(5)]
fn kani_queue_eviction_bounds() {
    let mut c: Cells<u8, CAP> = Cells::new();
    eviction_bounds(&mut c);
}

// ---- K-07 --------------------------------------------------------------------------------------------------------

/// The D.2 response frame count of an executed request (TEST-SPEC-M5 Conventions, shape table).
const fn d2_count(op: u8) -> usize {
    match op {
        opcode::FETCH => FETCH_BATCH,
        opcode::FETCH_MULTI => FETCH_MULTI_BATCH,
        opcode::LINK_GET => 3,
        _ => 1,
    }
}

fn any_err() -> ErrCode {
    let i: usize = kani::any();
    kani::assume(i < ErrCode::ALL.len());
    ErrCode::ALL[i]
}

fn any_cellr_error() -> CellrError {
    match kani::any::<u8>() % 3 {
        0 => CellrError::NoQueue,
        1 => CellrError::Auth,
        _ => CellrError::Malformed,
    }
}

/// Whether every byte of `rid` is `t`, checked at the first and the last byte (a 16-byte `==` is a memcmp loop under
/// Kani).
fn rid_is(rid: &[u8; 16], t: u8) -> bool {
    rid[0] == t && rid[15] == t
}

/// The tag of entry `i` (`base | i` in every byte of its `rid`).
fn tag(i: usize, base: u8) -> u8 {
    base | u8::try_from(i).unwrap_or(0)
}

/// A `FETCH` outcome — an error (`n = None`) or `n` cells with ids 1… — through `plan_fetch`, its layout checked:
/// an error in frame 1 and dummies after it; else the first `F` cells with `rid` zero in order, then dummies.
fn fetch_case(n: Option<usize>) -> Plan<u8, u8> {
    let outcome = match n {
        None => FetchOutcome::Error {
            error: any_cellr_error(),
            rid: [0xee; 16],
        },
        Some(n) => {
            let mut cells = Vec::with_capacity(n);
            for i in 0..n {
                cells.push((u64::try_from(i).unwrap_or(0) + 1, kani::any::<u8>()));
            }
            FetchOutcome::Cells(cells)
        }
    };
    let frames = plan_fetch(outcome);
    let served = n.map_or(0, |n| n.min(FETCH_BATCH));
    for (i, f) in frames.iter().enumerate() {
        match f {
            CellrPlan::Error { rid, .. } => {
                assert!(n.is_none() && i == 0 && rid_is(rid, 0xee));
            }
            CellrPlan::Cell { rid, cell_id, .. } => {
                assert!(
                    i < served && rid_is(rid, 0) && *cell_id == u64::try_from(i).unwrap_or(0) + 1
                );
            }
            CellrPlan::Dummy => {
                assert!(if n.is_none() { i > 0 } else { i >= served });
            }
        }
    }
    kani::cover!(n == Some(FETCH_BATCH + 1), "FETCH with more cells than F");
    Plan::Fetch(frames)
}

/// A `FETCH_MULTI` outcome of `e` errors (in request order) and `c` cells (oldest first) through
/// `plan_fetch_multi`, its layout checked: the first `F_M` errors, then as many cells as fit, then dummies.
fn fetch_multi_case(e: usize, c: usize) -> Plan<u8, u8> {
    let mut errors = Vec::with_capacity(e);
    for i in 0..e {
        errors.push((any_cellr_error(), [tag(i, 0x00); 16]));
    }
    let mut cells = Vec::with_capacity(c);
    for i in 0..c {
        cells.push(([tag(i, 0x40); 16], kani::any::<u64>(), kani::any::<u8>()));
    }
    let frames = plan_fetch_multi(FetchMultiOutcome { errors, cells });
    let errs = e.min(FETCH_MULTI_BATCH);
    let served = c.min(FETCH_MULTI_BATCH - errs);
    for (i, f) in frames.iter().enumerate() {
        match f {
            // the errors first, in request order (the first F_M of them, SQ-28)
            CellrPlan::Error { rid, .. } => {
                assert!(i < errs && rid_is(rid, tag(i, 0x00)));
            }
            // then the cells, in the order given (oldest first by arrival), with their queue's rid
            CellrPlan::Cell { rid, .. } => {
                assert!(i >= errs && i < errs + served && rid_is(rid, tag(i - errs, 0x40)));
            }
            CellrPlan::Dummy => {
                assert!(i >= errs + served);
            }
        }
    }
    kani::cover!(
        e > FETCH_MULTI_BATCH,
        "FETCH_MULTI with more errors than F_M"
    );
    kani::cover!(
        e > 0 && c > 0 && errs + c > FETCH_MULTI_BATCH,
        "errors and cells compete for F_M"
    );
    Plan::FetchMulti(frames)
}

/// Every plan `crate::exec` returns for an executed command of kind `op` (the stores and the crypto replaced by a
/// free choice of the outcome; the `CELLR` outcomes one of the concrete shapes of the module documentation).
fn executed(op: u8) -> Plan<u8, u8> {
    match op {
        opcode::QUEUE_NEW => {
            if kani::any() {
                Plan::OkQueueNew {
                    rid: kani::any(),
                    sid: kani::any(),
                }
            } else {
                Plan::Err(any_err())
            }
        }
        opcode::SEND => {
            if kani::any() {
                Plan::OkSend {
                    cell_id: kani::any(),
                    evicted: kani::any(),
                }
            } else {
                Plan::Err(any_err())
            }
        }
        opcode::FETCH => match kani::any::<u8>() % 5 {
            0 => fetch_case(None),
            1 => fetch_case(Some(0)),
            2 => fetch_case(Some(1)),
            3 => fetch_case(Some(FETCH_BATCH)),
            _ => fetch_case(Some(FETCH_BATCH + 1)),
        },
        opcode::FETCH_MULTI => match kani::any::<u8>() % 8 {
            0 => fetch_multi_case(0, 0),
            1 => fetch_multi_case(0, 3),
            2 => fetch_multi_case(2, 3),
            3 => fetch_multi_case(6, 3),
            4 => fetch_multi_case(7, 3),
            5 => fetch_multi_case(8, 1),
            6 => fetch_multi_case(9, 0),
            _ => fetch_multi_case(9, 3),
        },
        opcode::QUEUE_DEL | opcode::LINK_PUT => {
            if kani::any() {
                Plan::Ok
            } else {
                Plan::Err(any_err())
            }
        }
        opcode::LINK_GET => Plan::LinkR {
            present: kani::any(),
            consumed: kani::any(),
            blob: kani::any(),
        },
        _ => Plan::Ok,
    }
}

/// K-07 (TEST-SPEC-M5 (e)) [SQ-26]: the D.2 count for every decoded request and store outcome; stale and rate ⇒ 1.
#[kani::proof]
#[kani::unwind(10)]
fn kani_executor_response_count() {
    let op: u8 = kani::any();
    kani::assume((opcode::QUEUE_NEW..=opcode::PING).contains(&op));
    // the admission: any recorded last, any cmd_seq, any rate outcome per request frame
    let mut seq = CmdSeq::new();
    let _ = seq.admit(kani::any());
    let mut pending = None;
    let cmd_seq: u32 = kani::any();
    let admitted = if op == opcode::LINK_PUT {
        let one = admit(
            &mut seq,
            &mut pending,
            Step::<u8>::PutStart(cmd_seq),
            kani::any(),
        );
        let two = admit(&mut seq, &mut pending, Step::<u8>::PutCont, kani::any());
        // nothing is answered after frames 1 and 2 (D.2 `:824`)
        assert!(matches!(one, Ok(None)) && matches!(two, Ok(None)));
        admit(
            &mut seq,
            &mut pending,
            Step::PutDone(cmd_seq, op),
            kani::any(),
        )
    } else {
        let command = (op != opcode::SKEY).then_some(op);
        admit(
            &mut seq,
            &mut pending,
            Step::Single(cmd_seq, command),
            kani::any(),
        )
    };
    let Ok(Some((answered_seq, verdict, command))) = admitted else {
        panic!("every request is answered after its last frame")
    };
    assert!(answered_seq == cmd_seq);
    let plan = match answer(verdict, command) {
        Err(code) => Plan::Err(code),
        Ok(kind) => executed(kind),
    };
    let expected = if verdict == Verdict::Run && op != opcode::SKEY {
        d2_count(op)
    } else {
        1
    };
    assert!(plan.frame_count() == expected);
    kani::cover!(
        verdict == Verdict::Stale && op == opcode::FETCH_MULTI,
        "a stale FETCH_MULTI is one frame"
    );
    kani::cover!(
        verdict == Verdict::Rate && op == opcode::LINK_PUT,
        "a LINK_PUT over the rate is one frame"
    );
    kani::cover!(
        verdict == Verdict::Run && op == opcode::LINK_GET,
        "an executed LINK_GET is three frames"
    );
}
