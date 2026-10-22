// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the latency simulations — SIM-06 `sim_latency_does_not_move_emission` and SIM-07
//! `sim_slow_link_in_flight_teardown` (TEST-SPEC-M6 (f)).

use std::collections::BTreeMap;
use std::time::Duration;

use secmp_client_core::scheduler::types::{LinkEvent, Reason};
use secmp_testkit::harness::{Dir, HarnessConfig, RelayLimits};

use crate::m6_sim::{Outcome, Spec, reconnect_delays, simulate};

/// The C2R frame times (the client's clock, ms) of each link of client `idx`, by slot.
fn frames(run: &Outcome, idx: usize) -> BTreeMap<u64, Vec<u64>> {
    let mut by_slot: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for u in run.observers.get(idx).unwrap().recorder().unwrap().units() {
        if u.dir == Dir::C2R && u.len == 4352 {
            by_slot.entry(u.slot).or_default().push(u.t_ms);
        }
    }
    by_slot
}

/// The scheduled links of client `idx` (the ones that lived long enough to write 100 frames), each as the absolute time of
/// its first frame and the frame times relative to it, in the order of the first frames: a link's tick `k` is at
/// `t_up + k·P` (§10.1, [O-12]), and `t_up` — the end of the handshake — is the one thing latency moves, so the offsets
/// from the first frame are what must not move.
fn schedules(run: &Outcome, idx: usize) -> Vec<(u64, Vec<u64>)> {
    let mut out: Vec<(u64, Vec<u64>)> = frames(run, idx)
        .into_values()
        .filter(|f| f.len() >= 100)
        .map(|f| {
            let first = *f.first().unwrap();
            (first, f.iter().map(|t| t.saturating_sub(first)).collect())
        })
        .collect();
    out.sort();
    out
}

fn spec(latency: Option<(Duration, Duration)>) -> Spec {
    Spec {
        messages: 20,
        interval_s: 120,
        end_s: 3 * 3_600,
        latency,
        ..Spec::default()
    }
}

/// SIM-06 `sim_latency_does_not_move_emission` (§10.1): message latency of 10…2 000 ms (round trip below `P`, so no
/// in-flight teardown) against 0 — the C2R emission series of every scheduled link are identical, tick for tick: the same
/// offsets from the link's first frame over the whole of the shorter series (the first frame itself moves with the
/// handshake, which latency lengthens, and the run is cut at one absolute time, so the link that came up later has up to
/// `⌈shift / P⌉` frames fewer); every gap is exactly `P` = 10 s in both runs; emission does not wait for a response.
/// (E), (K) in both runs.
#[test]
fn sim_latency_does_not_move_emission() {
    let base = simulate("lat-0", &spec(None), |_| {});
    let slow = simulate(
        "lat-2000",
        &spec(Some((
            Duration::from_millis(10),
            Duration::from_millis(2_000),
        ))),
        |_| {},
    );
    base.assert_e_and_k("SIM-06 (no latency)");
    slow.assert_e_and_k("SIM-06 (10…2000 ms)");
    for idx in 0..2 {
        let (a, b) = (schedules(&base, idx), schedules(&slow, idx));
        assert!(
            !a.is_empty(),
            "client {idx}: no scheduled link in the base run"
        );
        assert_eq!(
            a.len(),
            b.len(),
            "client {idx}: the number of scheduled links"
        );
        for ((first_x, x), (first_y, y)) in a.iter().zip(&b) {
            let n = x.len().min(y.len());
            let shift = first_x.abs_diff(*first_y);
            assert!(
                u64::try_from(x.len().abs_diff(y.len())).unwrap() <= shift.div_ceil(10_000),
                "client {idx}: {} frames against {} for a start {shift} ms apart",
                x.len(),
                y.len(),
            );
            assert!(n >= 100, "client {idx}: a common prefix of {n} frames");
            assert_eq!(
                x.get(..n),
                y.get(..n),
                "client {idx}: emission times moved with latency"
            );
            for (what, series) in [("base", x), ("latency", y)] {
                assert!(
                    series.windows(2).all(|w| w
                        .first()
                        .zip(w.last())
                        .is_some_and(|(a, b)| b.saturating_sub(*a) == 10_000)),
                    "client {idx}: a gap that is not P in the {what} run"
                );
            }
        }
        assert!(
            slow.observers
                .get(idx)
                .unwrap()
                .events()
                .iter()
                .all(|(_, e)| !matches!(e, LinkEvent::TornDown(_, Reason::InFlight))),
            "client {idx}: an in-flight teardown with a round trip below P"
        );
    }
}

/// SIM-07 `sim_slow_link_in_flight_teardown` (§10.3 `:678`), re-dictated by the reviewer (WEISUNG M6-C2-4): one-way
/// latency of 25 s with `P` = 10 s. A response comes 50 s after its request, more than `MAX_IN_FLIGHT · P` = 20 s, so no
/// response is ever read before the link is torn down and (E) is **not** asserted for this row. Asserted: every
/// scheduled link is `TornDown(InFlight)` exactly at its third tick (30.0 s after `Up`; no other teardown), after at most
/// two frames written, and `responses_read == 0` — no frame of a response was read on any scheduled link, the witness of
/// the mechanism; reconnect per LR-02 (`U[0, 180 s]`, matched to distinct connects); (K); no message delivered twice or
/// altered.
///
/// Two parameters of the rig (`Spec`/`WorldConfig`) are set for this row only, no default changes: the relay's
/// `HELLO`→`HS1` timeout is 300 s (default 30 s, OPEN-M5-02: a handshake over 25 s one way takes 75 s) and the drivers'
/// connect timeout is 600 s (default 120 s: TCP connect 50 s + handshake 100 s).
#[test]
fn sim_slow_link_in_flight_teardown() {
    let slow = Duration::from_secs(25);
    let spec = Spec {
        messages: 3,
        interval_s: 120,
        end_s: 8 * 3_600,
        latency: Some((slow, slow)),
        relay: HarnessConfig {
            limits: RelayLimits {
                hello_timeout_ms: 300_000,
                ..HarnessConfig::default().limits
            },
            ..HarnessConfig::default()
        },
        connect_timeout_ms: Some(600_000),
        ..Spec::default()
    };
    let run = simulate("slow-link", &spec, |_| {});
    for idx in 0..2 {
        let o = run.observers.get(idx).unwrap();
        let events = o.events();
        let ups: BTreeMap<u64, u64> = events
            .iter()
            .filter_map(|(t, e)| match e {
                LinkEvent::Up(l) => Some((l.0, *t)),
                _ => None,
            })
            .collect();
        let downs: Vec<(u64, u64, Reason)> = events
            .iter()
            .filter_map(|(t, e)| match e {
                LinkEvent::TornDown(l, why) => Some((l.0, *t, *why)),
                _ => None,
            })
            .collect();
        assert!(
            downs.len() >= 5,
            "client {idx}: {} teardowns in 8 h",
            downs.len()
        );
        for (link, t_down, why) in &downs {
            // a link that never came up (a failed connect) has no `Up`
            let Some(up) = ups.get(link) else { continue };
            assert_eq!(*why, Reason::InFlight, "client {idx}: link {link}");
            let dt = t_down.saturating_sub(*up);
            assert!(
                (30_000..=30_250).contains(&dt),
                "client {idx}: link {link} torn down {dt} ms after Up, not at the third tick (30 s)"
            );
        }
        // at most two frames per scheduled link, and none read
        let first_up = ups.values().min().copied().unwrap();
        let rec = o.recorder().unwrap().units();
        let responses_read = rec
            .iter()
            .filter(|u| u.dir == Dir::R2C && u.len == 4352 && u.t_ms >= first_up)
            .count();
        assert_eq!(
            responses_read, 0,
            "client {idx}: a response was read on a scheduled link"
        );
        let mut per_link: BTreeMap<u64, usize> = BTreeMap::new();
        for u in rec
            .iter()
            .filter(|u| u.dir == Dir::C2R && u.len == 4352 && u.t_ms >= first_up)
        {
            *per_link.entry(u.slot).or_default() += 1;
        }
        assert!(
            per_link.values().all(|n| *n <= 2),
            "client {idx}: a link wrote more than its first two ticks: {per_link:?}"
        );
        assert!(
            per_link.values().filter(|n| **n == 2).count() >= downs.len() / 2,
            "client {idx}: frames per link {per_link:?}"
        );
        // LR-02: the reconnect after each teardown, matched to distinct connects
        for (why, t, delay) in reconnect_delays(&events, &o.connects()) {
            if why == Reason::InFlight
                && let Some(delay) = delay
            {
                assert!(
                    delay <= 180_000 + 1_000,
                    "client {idx}: reconnect after {delay} ms at {t}"
                );
            }
        }
    }
    run.assert_k("SIM-07");
    run.assert_exact("SIM-07");
}
