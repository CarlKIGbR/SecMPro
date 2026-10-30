// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kani harnesses of the scheduler core (TEST-SPEC-M6 (j) K-01 … K-07; `docs/06` §4), compiled only under `cargo kani`.
//!
//! - K-01 `kani_balanced_rr_selects_due_or_ping`: the Balanced slot's choice (`pure::rr_select`).
//! - K-02 `kani_in_flight_bound`: the in-flight bound (`pure::Flight`), every event sequence of up to eight events.
//! - K-03 `kani_tick_time_checked`: `t_up + k·P` never wraps (`pure::tick_time`).
//! - K-04 `kani_uniform_draw_in_range`: one round of the rejection sampling (`timing::sample_round`).
//! - K-05 `kani_backoff_cap`: the cap of the reconnect back-off (`params::backoff_cap`).
//! - K-06 `kani_rate_bound_integer_form`: the integer rate bound equals the exact rational one (`params::rate_sum_ok`).
//! - K-07 `kani_evicted_range`: the plausibility rule of `OK_SEND`'s evicted id (`secmp_transport::evicted`).

use secmp_transport::evicted::evicted_is_plausible;

use crate::scheduler::core::pure::{
    Flight, complete_oldest, hand_out, ledger_admits, reserved_rr, rr_select, tick_time,
    unwritten_max,
};
use crate::scheduler::params::{backoff_cap, rate_sum_ok};
use crate::timing::{accept_ceiling, sample_with};

/// `PERIODS` in milliseconds.
const PERIODS: [u64; 4] = [10_000, 20_000, 40_000, 80_000];

fn any_period() -> u64 {
    let i: usize = kani::any();
    kani::assume(i < PERIODS.len());
    PERIODS[i]
}

fn due(last: Option<u64>, period: u64, slot: u64) -> bool {
    match last {
        None => true,
        Some(l) => slot - l >= period,
    }
}

/// K-01: with at most four queues, periods in `PERIODS` and any `last_send ≤ now`, the chosen queue is the first one
/// from the round-robin pointer that is due (`now − last ≥ P`, or never sent to); when none is due the slot is a `PING`.
#[kani::proof]
#[kani::unwind(6)]
fn kani_balanced_rr_selects_due_or_ping() {
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= 4);
    let slot: u64 = kani::any();
    let mut queues = [(None, 10_000_u64); 4];
    for q in queues.iter_mut() {
        let period = any_period();
        let last = if kani::any() {
            None
        } else {
            let l: u64 = kani::any();
            kani::assume(l <= slot);
            Some(l)
        };
        *q = (last, period);
    }
    let rr: usize = kani::any();
    kani::assume(rr < n);
    let table = &queues[..n];
    match rr_select(rr, table, slot) {
        Some(at) => {
            assert!(at < n);
            let (last, period) = table[at];
            assert!(due(last, period, slot));
            // nothing between the pointer and the choice is due
            let mut step = 0;
            while (rr + step) % n != at {
                let (l, p) = table[(rr + step) % n];
                assert!(!due(l, p, slot));
                step += 1;
            }
            kani::cover!(at != rr, "a later queue is chosen");
        }
        None => {
            // PING: nobody is due
            for (l, p) in table {
                assert!(!due(*l, *p, slot));
            }
            kani::cover!(true, "a ping slot");
        }
    }
}

/// K-02: over any sequence of up to eight events (tick, response, close) the number of outstanding ticks stays in
/// {0, 1, 2}; a tick at two outstanding is refused (the link is torn down before it writes) and changes nothing.
#[kani::proof]
#[kani::unwind(10)]
fn kani_in_flight_bound() {
    let mut flight = Flight::new(2);
    for _ in 0..8 {
        let event: u8 = kani::any();
        kani::assume(event < 3);
        match event {
            0 => {
                let before = flight.count();
                let written = flight.on_tick();
                if before >= 2 {
                    assert!(!written);
                    assert!(flight.count() == before);
                    kani::cover!(true, "a third tick is refused");
                } else {
                    assert!(written);
                    assert!(flight.count() == before + 1);
                }
            }
            1 => flight.on_response(),
            _ => flight = Flight::new(2),
        }
        assert!(flight.count() <= 2);
    }
}

/// K-03: `t_up + k·P` is computed with checked arithmetic: `Some` is exactly the sum (no wrap), `None` exactly when it
/// does not fit 64 bits.
#[kani::proof]
fn kani_tick_time_checked() {
    let t_up: u64 = kani::any();
    let k: u32 = kani::any();
    let period: u64 = kani::any();
    kani::assume(period <= 80_000);
    let exact = u128::from(t_up) + u128::from(k) * u128::from(period);
    match tick_time(t_up, k, period) {
        Some(v) => {
            assert!(u128::from(v) == exact);
            kani::cover!(v > 0, "a tick time");
        }
        None => {
            assert!(exact > u128::from(u64::MAX));
            kani::cover!(true, "an overflow is reported");
        }
    }
}

#[kani::proof]
fn kani_uniform_draw_in_range() {
    let a: u32 = kani::any();
    let b: u32 = kani::any();
    kani::assume(a <= b);
    let span = u64::from(b) - u64::from(a) + 1;
    let x: u64 = kani::any();
    let ceiling = accept_ceiling(span).unwrap();
    if let Some(v) = sample_with(x, u64::from(a), span, ceiling) {
        assert!(u64::from(a) <= v && v <= u64::from(b));
        kani::cover!(v == u64::from(b), "the top of the interval is reachable");
    }
    // the accepted draws are those below `ceiling`: more than half of them
    assert!(
        ceiling > u64::MAX / 2,
        "fewer than half of the draws are rejected"
    );
}

/// K-05: the cap of the n-th back-off, `min(180 000 · 2^(n−1), 3 600 000)`, never overflows for any n ≥ 1, lies between
/// the base and the cap, and does not decrease.
#[kani::proof]
fn kani_backoff_cap() {
    let n: u32 = kani::any();
    kani::assume(n >= 1);
    let c = backoff_cap(n, 180_000, 3_600_000);
    assert!(c >= 180_000 && c <= 3_600_000);
    if n < u32::MAX {
        assert!(backoff_cap(n + 1, 180_000, 3_600_000) >= c);
    }
    kani::cover!(c == 3_600_000, "the cap is reached");
    kani::cover!(c == 180_000, "the first delay");
}

/// K-06: for at most 32 queues with periods in `PERIODS`, `Σ 80 000/P ≤ 32` holds exactly when `Σ 1/P ≤ 0.4/s` (the
/// rational comparison: `5·Σ(L/P) ≤ 2·L` for the common denominator `L = 80 s`).
#[kani::proof]
#[kani::unwind(34)]
fn kani_rate_bound_integer_form() {
    let n: usize = kani::any();
    kani::assume(n <= 32);
    let mut periods = [0_u64; 32];
    // Σ over the queues of 80 s / P in whole seconds (8, 4, 2, 1)
    let mut weights = 0_u32;
    for slot in periods.iter_mut().take(n) {
        let i: usize = kani::any();
        kani::assume(i < PERIODS.len());
        *slot = PERIODS[i];
        weights += [8_u32, 4, 2, 1][i];
    }
    let integer = rate_sum_ok(periods[..n].iter().copied(), 80_000, 32);
    // exact rational: Σ 1/P_i ≤ 2/5 per second  ⇔  5 · Σ (80/P_i) ≤ 2 · 80
    let rational = 5 * weights <= 2 * 80;
    assert!(integer == rational);
    kani::cover!(integer, "a set within the bound");
    kani::cover!(!integer, "a set over the bound");
}

/// K-07: the evicted id of an `OK_SEND` that stored `cell_id` is accepted exactly for (0, 0) and (1, id) with
/// `1 ≤ id < cell_id`.
#[kani::proof]
fn kani_evicted_range() {
    let cell_id: u64 = kani::any();
    let present: bool = kani::any();
    let id: u64 = kani::any();
    // the decoder (D.2) turns (present, id) into an `Option`: (0, id ≠ 0) never reaches the rule
    kani::assume(present || id == 0);
    let evicted = if present { Some(id) } else { None };
    let accepted = evicted_is_plausible(cell_id, evicted);
    let expected = (!present && id == 0) || (present && id >= 1 && id < cell_id);
    assert!(accepted == expected);
    kani::cover!(accepted && present, "an eviction is accepted");
    kani::cover!(!accepted, "an implausible id is refused");
}

// ---- K-C1…K-C6 (BRIEF M6-C1 item 5, A′ ledger): the unwritten-frame ledger of a link and the round-robin rotation -----
//
// Scope (M7 for the rest): the harnesses run the extracted pure functions (`reserved_rr`, `hand_out`, `complete_oldest`,
// `ledger_admits`, `unwritten_max`; item 10b) on a symbolic ledger. They do not run the in-flight rule over real
// transitions, queue generations, the abstract persist contract or paired executions. An up link needs a `Channel`, which
// this crate cannot build under Kani, so `Scheduler` itself is out of reach (item 10b).

/// Symbolic ledger contents: up to four entries (`len`), each `None` (a `FETCH`) or the position a `SEND` commits (`< n`).
/// The array is the reference the harnesses compare against; no clone of a `Vec` is needed (a clone loop costs Kani tens
/// of gigabytes).
fn any_entries(n: usize) -> ([Option<usize>; 4], usize) {
    let len: usize = kani::any();
    kani::assume(len <= 4);
    let entries = [any_entry(n), any_entry(n), any_entry(n), any_entry(n)];
    (entries, len)
}

/// The ledger `Vec` holding the first `len` of `entries`, entry `i` with the frame id `i` (FINAL3 (e); pre-sized: no
/// reallocation under symbolic lengths).
fn ledger_of(entries: &[Option<usize>; 4], len: usize) -> Vec<(u8, Option<usize>)> {
    let mut ledger = Vec::with_capacity(8);
    for (i, e) in entries.iter().take(len).enumerate() {
        ledger.push((i as u8, *e));
    }
    ledger
}

/// The frame id of the oldest entry of `ledger` (the one the driver reports next), or an id never handed out.
fn oldest(ledger: &[(u8, Option<usize>)]) -> u8 {
    ledger.first().map_or(u8::MAX, |(f, _)| *f)
}

fn any_entry(n: usize) -> Option<usize> {
    if kani::any() {
        None
    } else {
        let v: usize = kani::any();
        kani::assume(v < n);
        Some(v)
    }
}

/// The last `Some` of the first `m` entries.
fn last_some_of_prefix(entries: &[Option<usize>], m: usize) -> Option<usize> {
    entries.iter().take(m).rev().find_map(|e| *e)
}

/// K-C1 (FIN2-1): the position handed to the next preparation is a function of the schedule only. With up to four handed-out
/// frames and any FIFO prefix of them reported written before the preparation, `reserved_rr` equals what it is with no
/// completion applied (the newest pending successor, else the committed position).
#[kani::proof]
#[kani::unwind(7)]
fn kani_reservation_is_schedule_only() {
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= 3);
    let committed: usize = kani::any();
    kani::assume(committed < n);
    let (entries, len) = any_entries(n);
    let mut ledger = ledger_of(&entries, len);
    let none_applied = reserved_rr(&ledger, committed);
    let mut rr = committed;
    let m: usize = kani::any();
    kani::assume(m <= len);
    for _ in 0..m {
        let frame = oldest(&ledger);
        assert!(complete_oldest(&mut ledger, &mut rr, &frame));
    }
    assert!(reserved_rr(&ledger, rr) == none_applied);
    assert!(none_applied < n);
    kani::cover!(m > 0 && m < len, "a partial completion prefix");
}

/// K-C2: reports complete frames in the order they were handed out: after `m` of them `rr` is the last `Some` among the
/// first `m` entries (unchanged if there is none), the later entries are untouched, and a report on an empty ledger is
/// refused (`false`) and changes nothing; so is a duplicate report of the frame just completed (FINAL3 (e), SC-05).
#[kani::proof]
#[kani::unwind(7)]
fn kani_frame_written_commits_fifo() {
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= 3);
    let committed: usize = kani::any();
    kani::assume(committed < n);
    let (entries, len) = any_entries(n);
    let mut live = ledger_of(&entries, len);
    let m: usize = kani::any();
    kani::assume(m <= 4);
    let mut rr = committed;
    let mut last: Option<u8> = None;
    for i in 0..m {
        let was_empty = live.is_empty();
        let before = rr;
        let frame = oldest(&live);
        let matched = complete_oldest(&mut live, &mut rr, &frame);
        assert!(matched == !was_empty);
        if was_empty {
            assert!(rr == before);
            assert!(i >= len);
        } else {
            last = Some(frame);
        }
    }
    // the duplicate report of the last completed frame: refused, nothing changes
    if let Some(frame) = last {
        let (before_len, before_rr) = (live.len(), rr);
        assert!(!complete_oldest(&mut live, &mut rr, &frame));
        assert!(live.len() == before_len && rr == before_rr);
    }
    assert!(rr == last_some_of_prefix(&entries[..len], m).unwrap_or(committed));
    assert!(live.len() == len.saturating_sub(m));
    for (a, b) in live.iter().zip(entries.iter().take(len).skip(m)) {
        assert!(a.1 == *b);
    }
    kani::cover!(rr != committed, "a commit moves the rotation");
}

/// K-C3 (A′): a teardown leaves the committed position where the completions put it. The position lives in the link, the
/// ledger in the up-state that `tear` replaces (`core::mem::replace(&mut link.state, …)`): after any number of completions
/// and a teardown the ledger is empty and `rr` is the value committed before it — what was handed out and never written
/// moves nothing.
#[kani::proof]
#[kani::unwind(7)]
fn kani_teardown_keeps_the_committed_rr() {
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= 3);
    let committed: usize = kani::any();
    kani::assume(committed < n);
    let (entries, len) = any_entries(n);
    let mut ledger = ledger_of(&entries, len);
    let m: usize = kani::any();
    kani::assume(m <= len);
    let mut rr = committed;
    for _ in 0..m {
        let frame = oldest(&ledger);
        assert!(complete_oldest(&mut ledger, &mut rr, &frame));
    }
    let committed_before_teardown = rr;
    // the teardown: the up-state, with its ledger, is dropped; the link keeps `rr`
    ledger.clear();
    assert!(ledger.is_empty());
    assert!(rr == committed_before_teardown);
    assert!(rr == last_some_of_prefix(&entries[..len], m).unwrap_or(committed));
    kani::cover!(m < len, "frames handed out and never written");
}

/// K-C4: a tick hands a prepared frame out without committing. One frame handed out: the ledger grows by exactly one entry
/// carrying the position the frame will commit, and `rr` is unchanged (Obtain → Tick → Commit order: the commit is
/// `complete_oldest`). `last_send` is set inline in `World::tick`, outside the extracted functions, and not covered here.
#[kani::proof]
#[kani::unwind(7)]
fn kani_tick_hands_out_without_commit() {
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= 3);
    let rr: usize = kani::any();
    kani::assume(rr < n);
    let (entries, len) = any_entries(n);
    kani::assume(len <= 3);
    let mut ledger = ledger_of(&entries, len);
    let old_len = ledger.len();
    let old_reserved = reserved_rr(&ledger, rr);
    let next_rr = any_entry(n);
    hand_out(&mut ledger, 7, next_rr);
    assert!(ledger.len() == old_len + 1);
    assert!(ledger.last() == Some(&(7, next_rr)));
    // nothing was committed by the hand-out: the next preparation is reserved against the new entry (a SEND), else
    // against what it was
    assert!(reserved_rr(&ledger, rr) == next_rr.unwrap_or(old_reserved));
    kani::cover!(next_rr.is_some(), "a SEND is handed out");
}

/// K-C5: the deadline arithmetic never wraps. The tick time `t_up + k·P` (`pure::tick_time`) is `Some` for every smaller `k`
/// whenever it is for `k` and is monotone in `k`; the `FETCH`-lead deadline `slot − lead` and the flush bound
/// `min(now + FLUSH_WAIT_MS, next_deadline − driver_jitter_ms)` — written inline in `prepare_link` and `Driver::flush_wait`
/// with saturating operations, here as the same expressions — never exceed the slot, the deadline or `now + 250`.
#[kani::proof]
fn kani_deadline_arithmetic_checked() {
    let t_up: u64 = kani::any();
    let k: u32 = kani::any();
    let period = any_period();
    if let Some(next) = k.checked_add(1)
        && let Some(later) = tick_time(t_up, next, period)
    {
        let now_k = tick_time(t_up, k, period);
        assert!(now_k.is_some());
        if let Some(earlier) = now_k {
            assert!(earlier <= later);
            assert!(later - earlier == period);
        }
        kani::cover!(period > 0, "a later tick exists");
    }
    let lead: u64 = kani::any();
    kani::assume(lead <= 1_000);
    let slot: u64 = kani::any();
    assert!(slot.saturating_sub(lead) <= slot);
    let now: u64 = kani::any();
    let next_deadline: u64 = kani::any();
    let jitter: u64 = kani::any();
    kani::assume(jitter <= 50);
    let flush = now
        .saturating_add(250)
        .min(next_deadline.saturating_sub(jitter));
    assert!(flush <= now.saturating_add(250));
    assert!(flush <= next_deadline);
}

/// K-C6 (item 11): the ledger never exceeds `unwritten_max`. Any sequence of up to `UNWRITTEN_MAX + 2` ticks with no
/// completion, each handing out one or two frames: a tick that `ledger_admits` refuses tears the link down (`Reason::InFlight`,
/// modelled as the stop) before it hands anything out, and the ledger length stays within the bound at every step.
#[kani::proof]
#[kani::unwind(8)]
fn kani_unwritten_bound() {
    // the default `max_in_flight` = 2: `UNWRITTEN_MAX` = 4, six ticks (a symbolic `max_in_flight` cost 14.8 GB)
    let max = unwritten_max(2);
    assert!(max == 4);
    let mut ledger: Vec<(u8, Option<usize>)> = Vec::with_capacity(8);
    let mut torn = false;
    for _ in 0..6 {
        let adding: usize = kani::any();
        kani::assume(adding >= 1 && adding <= 2);
        if ledger_admits(ledger.len(), adding, max) {
            hand_out(&mut ledger, 0, None);
            if adding == 2 {
                hand_out(&mut ledger, 1, None);
            }
        } else {
            assert!(ledger.len() + adding > max);
            torn = true;
            break;
        }
        assert!(ledger.len() <= max);
    }
    assert!(ledger.len() <= max);
    // max + 2 ticks of at least one frame each cannot all be admitted
    assert!(torn);
    kani::cover!(torn && ledger.len() == max, "the bound is reached exactly");
}
