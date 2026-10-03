// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pure decisions of spec §7.4, separated from the cryptography so that Kani can prove them (`kani_proofs`):
//!
//! - [`first_opened`] and [`decide`]: the header-key selection. The header is opened under *every* candidate key
//!   (the distinct header keys of `skipped` in first-seen order, `hk_r`, `nhk_r`), each result a `Choice`; these
//!   two functions reduce the results to the §7.4 case — a skipped key hit, the current chain, a DH step, or a
//!   rejection — with `Choice` arithmetic and one conversion to a branch, `decide`'s case code (docs/06 §9, review
//!   focus L3). The caller holds every cell-dependent result as a [`CellChoice`], which has no conversion to `bool`,
//!   and reaches them only through [`first_opened_cell`] and [`path`]; it reads `n` for the `(hk, n)` lookup from the
//!   header plaintext bytes `[38..42]` of every skipped candidate, selected with the one-hot `first` vector, and
//!   decodes headers only after `decide` (`ratchet::select_header`; M3 review C6/F1). So `decide`'s case code is the
//!   only conversion of a cell-dependent `Choice` to a branch up to and including `decide` (test
//!   `any_skipped_single_conversion`).
//! - [`skip_plan_within`]: the bounds of `skip_message_keys(until)` — which positions are derived and which are stored.
//! - [`evicted`]: how many earliest-inserted entries leave `skipped` after an insertion.

use secmp_crypto::{Choice, ConditionallySelectable};

use crate::error::{Error, Result};

/// Skipped message keys retained per receiving chain (spec §4.2 `SKIP_WINDOW`).
pub const SKIP_WINDOW: u32 = 256;
/// Largest chain fast-forward per received message (spec §4.2 `MAX_FF` = 2^20).
pub const MAX_FF: u32 = 1 << 20;
/// Total bound on `skipped` across chains (spec §4.2: 2 × `SKIP_WINDOW`).
pub const MAX_SKIPPED: usize = 512;
const _: () = assert!(MAX_SKIPPED == 2 * 256 && SKIP_WINDOW == 256 && MAX_FF == 1_048_576);

/// The case of spec §7.4 that decrypts a cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Path {
    /// Step 1: a skipped header key opened the header and `(hk, header.n)` is in `skipped`.
    Skipped,
    /// Step 2, `hk_r` opened the header: the current receiving chain (`step = false`).
    Chain,
    /// Step 2, `nhk_r` opened the header: a DH ratchet step (`step = true`).
    Step,
    /// No key opened the header (uniform rejection).
    Reject,
}

/// For the per-key results `opened` (the distinct skipped header keys, first-seen order), the one-hot selection of
/// the *first* key that opened: `first[i] = opened[i] ∧ ¬(opened[0] ∨ … ∨ opened[i−1])`, and whether any opened.
/// Constant work: every element is visited, nothing branches on a `Choice`.
pub(crate) fn first_opened(opened: &[Choice]) -> (Vec<Choice>, Choice) {
    let mut before = Choice::from(0);
    let first = opened
        .iter()
        .map(|&o| {
            let f = o & !before;
            before |= o;
            f
        })
        .collect();
    (first, before)
}

/// Spec §7.4 on the per-key results, in constant time up to the final conversion:
///
/// ```text
/// for hk in distinct_header_keys(skipped):                      ; any_skipped: some skipped key opened;
///     if header = Open(hk, …): if found: return skipped path   ; found: (hk, header.n) ∈ skipped for the FIRST
///                              else break                       ;        skipped key that opened
/// if Open(hk_r, …): chain  elif Open(nhk_r, …): step  else reject
/// ```
///
/// `current_opened`: `hk_r` opened the header; `next_opened`: `nhk_r` did. The four `Choice`s are combined with `&`, `|`, `!` into a case code, which is converted to a branch once.
pub(crate) fn decide(
    any_skipped: Choice,
    found: Choice,
    current_opened: Choice,
    next_opened: Choice,
) -> Path {
    let skipped = any_skipped & found;
    let chain = !skipped & current_opened;
    let step = !skipped & !current_opened & next_opened;
    let mut code = 0_u8;
    code.conditional_assign(&3, step);
    code.conditional_assign(&2, chain);
    code.conditional_assign(&1, skipped);
    match code {
        1 => Path::Skipped,
        2 => Path::Chain,
        3 => Path::Step,
        _ => Path::Reject,
    }
}

/// A cell-dependent `Choice` of the header selection (M3 review F1): a trial decryption's result, an element of the
/// one-hot `first` vector, `any_skipped`, a hit of the `(hk, n)` lookup. It has no conversion to `bool`, `u8` or
/// `Choice` and no `PartialEq`, and its field is private to this module, so the only branch on it is [`path`] —
/// [`decide`]'s case code. It is combined with `|=` and selects with [`CellChoice::assign`].
#[derive(Clone, Copy)]
pub(crate) struct CellChoice(Choice);

impl CellChoice {
    /// `dst = src` if set, else `dst` unchanged, in constant time (`ConditionallySelectable::conditional_assign`).
    pub(crate) fn assign<T: ConditionallySelectable>(self, dst: &mut T, src: &T) {
        dst.conditional_assign(src, self.0);
    }
}

impl From<Choice> for CellChoice {
    fn from(choice: Choice) -> Self {
        Self(choice)
    }
}

impl core::ops::BitOrAssign for CellChoice {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// [`first_opened`] on [`CellChoice`]s.
pub(crate) fn first_opened_cell(opened: &[CellChoice]) -> (Vec<CellChoice>, CellChoice) {
    #[cfg(test)]
    hook::selection();
    let choices: Vec<Choice> = opened.iter().map(|c| c.0).collect();
    let (first, any) = first_opened(&choices);
    (first.into_iter().map(CellChoice).collect(), CellChoice(any))
}

/// [`decide`] on [`CellChoice`]s: the one conversion of the header selection to a branch (docs/06 §9).
pub(crate) fn path(
    any_skipped: CellChoice,
    found: CellChoice,
    current_opened: CellChoice,
    next_opened: CellChoice,
) -> Path {
    #[cfg(test)]
    hook::conversion();
    decide(any_skipped.0, found.0, current_opened.0, next_opened.0)
}

/// Test hook of `any_skipped_single_conversion` (M3 review F1): per thread, the calls of [`first_opened_cell`] (the
/// selection on [`CellChoice`]s) and of [`path`] (the conversion to a branch).
#[cfg(test)]
pub(crate) mod hook {
    use core::cell::Cell;

    thread_local! {
        static COUNTS: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
    }

    pub(super) fn selection() {
        COUNTS.with(|c| {
            let (selections, conversions) = c.get();
            c.set((selections.saturating_add(1), conversions));
        });
    }

    pub(super) fn conversion() {
        COUNTS.with(|c| {
            let (selections, conversions) = c.get();
            c.set((selections, conversions.saturating_add(1)));
        });
    }

    /// `(selections, conversions)` on this thread since the last call; both are reset.
    pub(crate) fn take() -> (u32, u32) {
        COUNTS.with(|c| c.replace((0, 0)))
    }
}

/// The plan of `skip_message_keys(until)` on a receiving chain at `n_r` (spec §7.4):
///
/// ```text
/// if until < n_r: reject                     ; replay / stale counter
/// gap = until − n_r; if gap > MAX_FF: reject
/// while n_r < until: (ck_r, mk) = KDF_CK(ck_r); if until − n_r ≤ SKIP_WINDOW: store (hk_r, n_r) → mk; n_r += 1
/// ```
///
/// `steps` = `gap` chain steps are derived; the positions `store_from .. until` (at most `SKIP_WINDOW`) are the
/// ones stored, every earlier derived key is dropped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SkipPlan {
    /// Number of `KDF_CK` steps (`until − n_r`).
    pub(crate) steps: u32,
    /// The first stored position (`max(n_r, until − SKIP_WINDOW)`).
    pub(crate) store_from: u32,
}

/// See [`SkipPlan`]: [`skip_plan_within`] with the bound [`MAX_FF`] of §7.4, as the ratchet calls it (the tests and the
/// Kani harness `tr_skip_plan` check this instance). The case `ck_r = None` (no receiving chain: nothing to skip) is
/// the caller's.
///
/// # Errors
/// [`Error::Rejected`] if `until < n_r` or the gap exceeds [`MAX_FF`].
#[cfg(any(test, kani))]
pub(crate) fn skip_plan(n_r: u32, until: u32) -> Result<SkipPlan> {
    skip_plan_within(n_r, until, MAX_FF)
}

/// The bounds of `skip_message_keys(until)` on a chain at `n_r` ([`SkipPlan`]) with the fast-forward bound `max_ff`:
/// [`MAX_FF`] in §7.4 Decrypt, 0 for SecMP-HX's first message (ADR-044 (e), M4 review C-9), so that its `n ≠ 0` is
/// rejected before any chain step. The case `ck_r = None` (no receiving chain: nothing to skip) is the caller's.
///
/// # Errors
/// [`Error::Rejected`] if `until < n_r` or the gap exceeds `max_ff`.
pub(crate) fn skip_plan_within(n_r: u32, until: u32, max_ff: u32) -> Result<SkipPlan> {
    let steps = until.checked_sub(n_r).ok_or(Error::Rejected)?;
    if steps > max_ff {
        return Err(Error::Rejected);
    }
    Ok(SkipPlan {
        steps,
        store_from: until.saturating_sub(SKIP_WINDOW).max(n_r),
    })
}

/// The number of earliest-inserted entries to evict so that `len` entries (after an insertion) are at most
/// [`MAX_SKIPPED`] (spec §7.4 "evict earliest-inserted entries so |skipped| ≤ 2 × `SKIP_WINDOW`").
pub(crate) const fn evicted(len: usize) -> usize {
    len.saturating_sub(MAX_SKIPPED)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(b: bool) -> Choice {
        Choice::from(u8::from(b))
    }

    /// The sequential pseudocode of §7.4, literally.
    fn sequential(opened: &[bool], found: &[bool], hk_r: bool, nhk_r: bool) -> Path {
        for (o, f) in opened.iter().zip(found) {
            if *o {
                if *f {
                    return Path::Skipped;
                }
                break;
            }
        }
        if hk_r {
            Path::Chain
        } else if nhk_r {
            Path::Step
        } else {
            Path::Reject
        }
    }

    /// Exhaustive for up to 4 skipped header keys (the Kani harness `tr_header_selection` proves the same).
    #[test]
    fn constant_time_selection_equals_the_pseudocode() {
        for k in 0..=4_u32 {
            let len = usize::try_from(k).unwrap_or(0);
            for bits in 0..(1_u32 << (2 * k + 2)) {
                let bit = |i: u32| bits >> i & 1 == 1;
                let opened: Vec<bool> = (0..k).map(bit).collect();
                let found: Vec<bool> = (k..2 * k).map(bit).collect();
                let (hk_r, nhk_r) = (bit(2 * k), bit(2 * k + 1));
                let oc: Vec<Choice> = opened.iter().map(|b| c(*b)).collect();
                let (first, any) = first_opened(&oc);
                assert_eq!(first.len(), len);
                // one-hot: the lowest opened index, if any
                let lowest = opened.iter().position(|o| *o);
                for (i, f) in first.iter().enumerate() {
                    assert_eq!(bool::from(*f), Some(i) == lowest);
                }
                assert_eq!(bool::from(any), lowest.is_some());
                let mut found_first = Choice::from(0);
                for (f, x) in first.iter().zip(&found) {
                    found_first |= *f & c(*x);
                }
                assert_eq!(
                    decide(any, found_first, c(hk_r), c(nhk_r)),
                    sequential(&opened, &found, hk_r, nhk_r),
                    "k {k} bits {bits:b}"
                );
            }
        }
    }

    #[test]
    fn skip_plan_bounds() {
        assert_eq!(skip_plan(5, 4), Err(Error::Rejected), "replay");
        assert_eq!(
            skip_plan(5, 5),
            Ok(SkipPlan {
                steps: 0,
                store_from: 5
            })
        );
        assert_eq!(
            skip_plan(0, 3),
            Ok(SkipPlan {
                steps: 3,
                store_from: 0
            })
        );
        assert_eq!(
            skip_plan(1, 10_001),
            Ok(SkipPlan {
                steps: 10_000,
                store_from: 9_745
            })
        );
        assert_eq!(
            skip_plan(0, MAX_FF),
            Ok(SkipPlan {
                steps: MAX_FF,
                store_from: MAX_FF - SKIP_WINDOW
            })
        );
        assert_eq!(skip_plan(0, MAX_FF + 1), Err(Error::Rejected), "MAX_FF + 1");
        assert_eq!(skip_plan(1, MAX_FF + 2), Err(Error::Rejected), "N10");
        // the bound of SecMP-HX's first message (M4 review C-9): no fast-forward at all
        assert_eq!(
            skip_plan_within(0, 0, 0),
            Ok(SkipPlan {
                steps: 0,
                store_from: 0
            })
        );
        assert_eq!(
            skip_plan_within(0, 1, 0),
            Err(Error::Rejected),
            "n = 1, bound 0"
        );
        assert_eq!(skip_plan_within(0, 1 << 20, 0), Err(Error::Rejected));
        assert_eq!(skip_plan_within(3, 2, 0), Err(Error::Rejected), "replay");
        assert_eq!(skip_plan_within(0, 7, 7).map(|p| p.steps), Ok(7));
        assert_eq!(
            skip_plan(u32::MAX, u32::MAX),
            Ok(SkipPlan {
                steps: 0,
                store_from: u32::MAX
            })
        );
        assert_eq!(
            skip_plan(u32::MAX - 300, u32::MAX),
            Ok(SkipPlan {
                steps: 300,
                store_from: u32::MAX - 256
            })
        );
        assert_eq!(evicted(512), 0);
        assert_eq!(evicted(513), 1);
        assert_eq!(evicted(1024), 512);
        assert_eq!(evicted(0), 0);
    }
}
