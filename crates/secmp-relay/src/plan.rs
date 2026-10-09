// SPDX-License-Identifier: AGPL-3.0-or-later
//! The response of a request before its randomness is drawn and its frames are sealed (spec §9.3, D.2).
//!
//! The executor turns a command's outcome into a [`Plan`]; the number of frames a plan renders is fixed by its
//! variant ([`Plan::frame_count`]): one frame for `OK`, `OK_QUEUE_NEW`, `OK_SEND` and `ERR`, exactly `F` `CELLR`
//! frames for `FETCH` and `F_M` for `FETCH_MULTI` (fixed-size arrays), and three for `LINKR` + two `CONT` — whatever
//! the outcome (D.2 `:839` "the exact number of frames the table specifies"; §9.3 "success and error frames are
//! indistinguishable on the wire"). The two exceptions of D.2 (a stale `cmd_seq`, the rate limit) are one `ERR`.
//!
//! [`plan_fetch`] and [`plan_fetch_multi`] fix the `CELLR` layout of reading OPEN-7/OPEN-8 and SQ-28: an error frame
//! first (`FETCH`: frame 1; `FETCH_MULTI`: every error in request order, at most `F_M`), then the cells, oldest first,
//! then dummies. The cell type `C` is generic so that the Kani harness `kani_executor_response_count` runs the same
//! functions with a plain stand-in.

use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH};
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{CellrContext, CellrError, ErrCode};

/// One `CELLR` frame to render.
pub enum CellrPlan<C> {
    /// `present = 0`: a dummy (rid and `cell_id` zero, a random cell drawn at rendering).
    Dummy,
    /// `present = 1`: a stored cell (`rid` zero in answer to `FETCH`).
    Cell {
        /// The queue (`FETCH_MULTI`), zero (`FETCH`).
        rid: Id,
        /// The cell's id.
        cell_id: u64,
        /// A copy of the cell.
        cell: C,
    },
    /// `present` 2–4: an error for a requested queue (`rid` set, `cell_id` zero, a random cell drawn at rendering).
    Error {
        /// Which error.
        error: CellrError,
        /// The requested `rid`.
        rid: Id,
    },
}

/// A planned response.
pub enum Plan<C, B> {
    /// `OK`.
    Ok,
    /// `OK_QUEUE_NEW { rid, sid }`.
    OkQueueNew {
        /// Recipient id.
        rid: Id,
        /// Sender id.
        sid: Id,
    },
    /// `OK_SEND { cell_id, evicted }`.
    OkSend {
        /// The stored cell's id.
        cell_id: u64,
        /// The evicted cell's id.
        evicted: Option<u64>,
    },
    /// `ERR code`.
    Err(ErrCode),
    /// The `F` `CELLR` frames of a `FETCH`.
    Fetch(Box<[CellrPlan<C>; FETCH_BATCH]>),
    /// The `F_M` `CELLR` frames of a `FETCH_MULTI`.
    FetchMulti(Box<[CellrPlan<C>; FETCH_MULTI_BATCH]>),
    /// `LINKR { present, consumed }` + two `CONT`: the stored blob, or a dummy blob (`None`) drawn at rendering.
    LinkR {
        /// The link data exists.
        present: bool,
        /// It was consumed.
        consumed: bool,
        /// A copy of the blob that is returned.
        blob: Option<B>,
    },
}

impl<C, B> Plan<C, B> {
    /// The number of frames the plan renders.
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        match self {
            Self::Ok | Self::OkQueueNew { .. } | Self::OkSend { .. } | Self::Err(_) => 1,
            Self::Fetch(_) => FETCH_BATCH,
            Self::FetchMulti(_) => FETCH_MULTI_BATCH,
            Self::LinkR { .. } => 3,
        }
    }

    /// The context a client decodes this plan's `CELLR` frames in.
    #[must_use]
    pub const fn context(&self) -> CellrContext {
        match self {
            Self::FetchMulti(_) => CellrContext::FetchMulti,
            _ => CellrContext::Fetch,
        }
    }
}

/// The outcome of a `FETCH` (spec §9.3).
pub enum FetchOutcome<C> {
    /// The requested queue is in error.
    Error {
        /// Which error.
        error: CellrError,
        /// The requested `rid`.
        rid: Id,
    },
    /// The oldest cells after the acknowledgement, ascending `cell_id` (at most `F` are used).
    Cells(Vec<(u64, C)>),
}

/// The outcome of a `FETCH_MULTI` (spec §9.3, OPEN-8, SQ-28).
pub struct FetchMultiOutcome<C> {
    /// The entries in error, in request order.
    pub errors: Vec<(CellrError, Id)>,
    /// The cells of the other queues, oldest first by arrival.
    pub cells: Vec<(Id, u64, C)>,
}

/// The `F` frames of a `FETCH`: on an error frame 1 carries it and frames 2…`F` are dummies; on success the cells
/// with `rid` zero, then dummies (reading OPEN-7).
#[must_use]
pub fn plan_fetch<C>(outcome: FetchOutcome<C>) -> Box<[CellrPlan<C>; FETCH_BATCH]> {
    let mut frames: Vec<CellrPlan<C>> = match outcome {
        FetchOutcome::Error { error, rid } => vec![CellrPlan::Error { error, rid }],
        FetchOutcome::Cells(cells) => cells
            .into_iter()
            .take(FETCH_BATCH)
            .map(|(cell_id, cell)| CellrPlan::Cell {
                rid: [0; 16],
                cell_id,
                cell,
            })
            .collect(),
    };
    let mut it = frames.drain(..);
    Box::new(core::array::from_fn(|_| {
        it.next().unwrap_or(CellrPlan::Dummy)
    }))
}

/// The `F_M` frames of a `FETCH_MULTI`: the error frames first in request order (the first `F_M` if more fail),
/// then the cells with their queue's `rid`, then dummies (reading OPEN-8, SQ-28).
#[must_use]
pub fn plan_fetch_multi<C>(
    outcome: FetchMultiOutcome<C>,
) -> Box<[CellrPlan<C>; FETCH_MULTI_BATCH]> {
    let mut frames: Vec<CellrPlan<C>> = outcome
        .errors
        .into_iter()
        .take(FETCH_MULTI_BATCH)
        .map(|(error, rid)| CellrPlan::Error { error, rid })
        .collect();
    let room = FETCH_MULTI_BATCH.saturating_sub(frames.len());
    frames.extend(
        outcome
            .cells
            .into_iter()
            .take(room)
            .map(|(rid, cell_id, cell)| CellrPlan::Cell { rid, cell_id, cell }),
    );
    let mut it = frames.drain(..);
    Box::new(core::array::from_fn(|_| {
        it.next().unwrap_or(CellrPlan::Dummy)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds<const N: usize>(frames: &[CellrPlan<u8>; N]) -> Vec<(u8, Id, u64)> {
        frames
            .iter()
            .map(|f| match f {
                CellrPlan::Dummy => (0, [0; 16], 0),
                CellrPlan::Cell { rid, cell_id, .. } => (1, *rid, *cell_id),
                CellrPlan::Error { error, rid } => (
                    match error {
                        CellrError::NoQueue => 2,
                        CellrError::Auth => 3,
                        CellrError::Malformed => 4,
                    },
                    *rid,
                    0,
                ),
            })
            .collect()
    }

    #[test]
    fn fetch_pads_with_dummies_and_puts_an_error_first() {
        let ok = plan_fetch(FetchOutcome::Cells(vec![(1, 0_u8), (2, 0)]));
        assert_eq!(
            kinds(&ok),
            vec![
                (1, [0; 16], 1),
                (1, [0; 16], 2),
                (0, [0; 16], 0),
                (0, [0; 16], 0)
            ]
        );
        let many = plan_fetch(FetchOutcome::Cells((1..=9).map(|i| (i, 0_u8)).collect()));
        assert_eq!(kinds(&many).len(), 4);
        let err = plan_fetch::<u8>(FetchOutcome::Error {
            error: CellrError::Auth,
            rid: [5; 16],
        });
        assert_eq!(
            kinds(&err),
            vec![
                (3, [5; 16], 0),
                (0, [0; 16], 0),
                (0, [0; 16], 0),
                (0, [0; 16], 0)
            ]
        );
    }

    #[test]
    fn fetch_multi_errors_first_then_cells_then_dummies() {
        let p = plan_fetch_multi(FetchMultiOutcome {
            errors: vec![(CellrError::NoQueue, [1; 16])],
            cells: vec![([2; 16], 7, 0_u8), ([3; 16], 1, 0)],
        });
        let k = kinds(&p);
        assert_eq!(k.first(), Some(&(2, [1; 16], 0)));
        assert_eq!(k.get(1), Some(&(1, [2; 16], 7)));
        assert_eq!(k.get(2), Some(&(1, [3; 16], 1)));
        assert_eq!(k.get(7), Some(&(0, [0; 16], 0)));
        // more errors than F_M: the first F_M in request order and nothing else (SQ-28)
        let errs: Vec<(CellrError, Id)> = (0..9_u8).map(|i| (CellrError::Auth, [i; 16])).collect();
        let p = plan_fetch_multi(FetchMultiOutcome {
            errors: errs,
            cells: vec![([9; 16], 1, 0_u8)],
        });
        let k = kinds(&p);
        assert_eq!(k.len(), 8);
        assert!(
            k.iter()
                .enumerate()
                .all(|(i, f)| f.0 == 3 && u8::try_from(i).is_ok_and(|i| f.1 == [i; 16]))
        );
    }

    #[test]
    fn frame_counts_follow_d2() {
        assert_eq!(Plan::<u8, u8>::Ok.frame_count(), 1);
        assert_eq!(Plan::<u8, u8>::Err(ErrCode::Rate).frame_count(), 1);
        assert_eq!(
            Plan::<u8, u8>::LinkR {
                present: false,
                consumed: false,
                blob: None
            }
            .frame_count(),
            3
        );
        let f: Plan<u8, u8> = Plan::Fetch(plan_fetch(FetchOutcome::Cells(Vec::new())));
        assert_eq!(f.frame_count(), 4);
        assert!(matches!(f.context(), CellrContext::Fetch));
        let m: Plan<u8, u8> = Plan::FetchMulti(plan_fetch_multi(FetchMultiOutcome {
            errors: Vec::new(),
            cells: Vec::new(),
        }));
        assert_eq!(m.frame_count(), 8);
        assert!(matches!(m.context(), CellrContext::FetchMulti));
    }
}
