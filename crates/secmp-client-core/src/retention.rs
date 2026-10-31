// SPDX-License-Identifier: AGPL-3.0-or-later
//! The cells an invitation queue retains between fetch rounds (review RT-1; `docs/03` §6.5; Q148, Q172): the newest
//! [`RETAIN_MAX`] = 24 of the cells that earlier rounds held and this round fetched, minus the cells that a complete group
//! spent. A pure function over cell ordinals (`cell_id`s): no codec type, no store, no `Vec`, so that it is built under
//! Kani (K7-01) and driven by the fuzzer (FZ-04).
//!
//! The 24 are the eight partial groups of three chunks that the responder holds while grouping
//! (`hx::responder::MAX_PARTIAL_GROUPS`); anything older is dropped, which is what keeps the retained set bounded when the
//! relay (or a thief of the invitation) fills the queue with cells that never classify.

/// The most cells retained: eight partial groups of three chunks.
pub const RETAIN_MAX: usize = 24;

/// Whether `id` is among `set`.
fn contains(set: &[u64], id: u64) -> bool {
    let mut found = false;
    for s in set {
        if *s == id {
            found = true;
        }
    }
    found
}

/// Offer `id` to the sorted `out[..len]`: kept if it is among the newest [`RETAIN_MAX`] seen so far; returns the new
/// length. A duplicate is not added twice. Every index is a loop counter over the whole array (no symbolic index), so
/// that the bounded model checker (K7-01) unrolls it cheaply.
fn offer(out: &mut [u64; RETAIN_MAX], len: usize, id: u64) -> usize {
    let mut dup = false;
    for (i, v) in out.iter().enumerate() {
        if i < len && *v == id {
            dup = true;
        }
    }
    if dup {
        return len;
    }
    let mut len = len;
    if len == RETAIN_MAX {
        // full: the smallest goes if `id` is newer than it, else `id` itself is the one dropped
        let oldest = out.first().copied().unwrap_or(u64::MAX);
        if id < oldest {
            return len;
        }
        for i in 1..RETAIN_MAX {
            let next = out.get(i).copied().unwrap_or(0);
            if let Some(slot) = out.get_mut(i.saturating_sub(1)) {
                *slot = next;
            }
        }
        len = RETAIN_MAX.saturating_sub(1);
    }
    // bubble `id` into its place in ascending order: each larger element moves on as the carried one
    let mut carry = id;
    for (i, slot) in out.iter_mut().enumerate() {
        if i < len && carry < *slot {
            core::mem::swap(slot, &mut carry);
        }
    }
    for (i, slot) in out.iter_mut().enumerate() {
        if i == len {
            *slot = carry;
        }
    }
    len.saturating_add(1)
}

/// The newest [`RETAIN_MAX`] of (`retained` ∪ `fetched`) \ `spent`, by cell id (Q148): written ascending to the front of
/// `out`; returns how many. Each id counts once, whichever of the two inputs holds it.
#[must_use]
pub fn retain(
    retained: &[u64],
    fetched: &[u64],
    spent: &[u64],
    out: &mut [u64; RETAIN_MAX],
) -> usize {
    let mut len = 0;
    for id in retained.iter().chain(fetched) {
        if !contains(spent, *id) {
            len = offer(out, len, *id);
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference: sort, dedup, drop spent, keep the newest 24.
    fn reference(retained: &[u64], fetched: &[u64], spent: &[u64]) -> Vec<u64> {
        let mut all: Vec<u64> = retained
            .iter()
            .chain(fetched)
            .copied()
            .filter(|i| !spent.contains(i))
            .collect();
        all.sort_unstable();
        all.dedup();
        let skip = all.len().saturating_sub(RETAIN_MAX);
        all.split_off(skip)
    }

    fn run(retained: &[u64], fetched: &[u64], spent: &[u64]) -> Vec<u64> {
        let mut out = [0_u64; RETAIN_MAX];
        let n = retain(retained, fetched, spent, &mut out);
        out.get(..n).unwrap_or(&[]).to_vec()
    }

    /// Q148: the newest 24 of (retained ∪ fetched) \ spent, ascending, each once.
    #[test]
    fn matches_the_reference() {
        let cases: [(Vec<u64>, Vec<u64>, Vec<u64>); 7] = [
            (vec![], vec![], vec![]),
            (vec![], (1..=10).collect(), vec![]),
            ((1..=24).collect(), (25..=30).collect(), vec![]),
            ((1..=24).collect(), (1..=24).collect(), vec![]),
            ((1..=24).collect(), (25..=60).collect(), vec![30, 31, 59, 2]),
            (vec![50, 3, 40], vec![3, 2, 99, 1], vec![99, 50]),
            (
                (1..=30).rev().collect(),
                (31..=34).collect(),
                (1..=30).collect(),
            ),
        ];
        for (retained, fetched, spent) in cases {
            assert_eq!(
                run(&retained, &fetched, &spent),
                reference(&retained, &fetched, &spent),
                "{retained:?} {fetched:?} {spent:?}"
            );
        }
    }

    /// Killers (mutants of `offer`): the id 0 is an id like another (the unused part of `out` is zeros); a full set drops
    /// an id older than all 24 and makes room for a newer one.
    #[test]
    fn zero_and_full_set() {
        assert_eq!(run(&[], &[0], &[]), [0]);
        assert_eq!(run(&[0], &[0, 5], &[]), [0, 5]);
        let full: Vec<u64> = (10..34).collect();
        assert_eq!(run(&full, &[9], &[]), full, "older than all 24: dropped");
        let mut newer: Vec<u64> = (11..34).collect();
        newer.push(40);
        assert_eq!(run(&full, &[40], &[]), newer);
        let mut gaps: Vec<u64> = (0..24).map(|i| i * 2 + 10).collect();
        let at = gaps.len();
        gaps.push(25);
        gaps.sort_unstable();
        let want: Vec<u64> = gaps.iter().copied().skip(1).collect();
        assert_eq!(at, 24);
        assert_eq!(run(&[], &gaps, &[]), want);
    }

    /// Never more than 24, whatever is offered, in any arrival order (a small deterministic sweep).
    #[test]
    fn never_more_than_24() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for round in 0..200_u64 {
            let mut next = || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            let n = usize::try_from(next() % 41).unwrap_or(0);
            let m = usize::try_from(next() % 41).unwrap_or(0);
            let retained: Vec<u64> = (0..n).map(|_| next() % 64).collect();
            let fetched: Vec<u64> = (0..m).map(|_| next() % 64).collect();
            let spent: Vec<u64> = (0..(round % 9)).map(|_| next() % 64).collect();
            let got = run(&retained, &fetched, &spent);
            assert!(got.len() <= RETAIN_MAX);
            assert_eq!(got, reference(&retained, &fetched, &spent), "{round}");
        }
    }
}
