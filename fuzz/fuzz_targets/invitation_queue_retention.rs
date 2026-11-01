// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 FZ-04 (RT-1, Q148, Q172): the cells an invitation queue retains between fetch rounds
//! (`secmp_client_core::retention::retain`) over arbitrary fetch rounds and `accept` outcomes — no crypto, no store: the
//! function sees cell ordinals only.
//!
//! Input: at most 16 rounds, each `n u8 ‖ id u16 × n ‖ k u8 ‖ idx u8 × k`: `n % 129` cells fetched (at most `FETCH`
//! = 128, ids as given, duplicates and any order included) and `k % 9` spent cells, `idx` choosing the spent id from
//! the round's union (the complete group an `accept` call spent). A short input stops the run.
//!
//! After every round: at most 24 ids are retained; they are the newest 24 of (retained ∪ fetched) \ spent, each once,
//! ascending (an independent sort-and-truncate oracle); and no spent id is among them — a spent group is never
//! retained. The retained ids are the next round's `retained`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_client_core::retention::{RETAIN_MAX, retain};

/// Rounds read from one input.
const ROUNDS: usize = 16;
/// The most cells one round fetches (`QUEUE_CAPACITY`).
const FETCH: usize = 128;
/// The most cells one `accept` call spends in a round of the model (a few groups of three).
const SPENT: usize = 8;

/// The first `n` bytes of `data`, and the rest.
fn split(data: &mut &[u8], n: usize) -> Option<Vec<u8>> {
    let (head, rest) = data.split_at_checked(n)?;
    *data = rest;
    Some(head.to_vec())
}

fuzz_target!(|input: &[u8]| {
    let mut data = input;
    let mut retained: Vec<u64> = Vec::new();
    for _ in 0..ROUNDS {
        let Some(n) = split(&mut data, 1).and_then(|b| b.first().copied()) else {
            return;
        };
        let n = usize::from(n) % (FETCH + 1);
        let Some(raw) = split(&mut data, n * 2) else {
            return;
        };
        let fetched: Vec<u64> = raw
            .chunks_exact(2)
            .map(|c| u64::from(u16::from_be_bytes([c[0], c[1]])))
            .collect();
        let Some(k) = split(&mut data, 1).and_then(|b| b.first().copied()) else {
            return;
        };
        let k = usize::from(k) % (SPENT + 1);
        let Some(idx) = split(&mut data, k) else {
            return;
        };

        let mut union: Vec<u64> = retained.iter().chain(&fetched).copied().collect();
        union.sort_unstable();
        union.dedup();
        let spent: Vec<u64> = if union.is_empty() {
            Vec::new()
        } else {
            idx.iter().map(|i| union[usize::from(*i) % union.len()]).collect()
        };

        let mut out = [0_u64; RETAIN_MAX];
        let m = retain(&retained, &fetched, &spent, &mut out);
        assert!(m <= RETAIN_MAX, "at most 24 retained");
        let got = &out[..m];

        let mut want: Vec<u64> = union.iter().copied().filter(|i| !spent.contains(i)).collect();
        let skip = want.len().saturating_sub(RETAIN_MAX);
        want.drain(..skip);
        assert_eq!(got, want.as_slice(), "the newest 24 of the unspent");
        assert!(got.iter().all(|i| !spent.contains(i)), "a spent cell is never retained");

        retained = got.to_vec();
    }
});
