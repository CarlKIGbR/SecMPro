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

use crate::scheduler::core::pure::{Flight, rr_select, tick_time};
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
