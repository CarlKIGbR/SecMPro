// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the latency simulations — SIM-06 `sim_latency_does_not_move_emission` and SIM-07
//! `sim_slow_link_in_flight_teardown` (TEST-SPEC-M6 (f)).

use std::collections::BTreeMap;
use std::time::Duration;

use secmp_client_core::scheduler::types::{LinkEvent, Reason};
use secmp_testkit::harness::Dir;

use crate::m6_sim::{Outcome, Spec, simulate};

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

/// The scheduled links of client `idx` (the ones that lived long enough to write 100 frames), each as its frame times
/// relative to its own first frame, sorted: a link's tick `k` is at `t_up + k·P` (§10.1, [O-12]), and `t_up` — the end
/// of the handshake — is the one thing latency moves, so the offsets from the first frame are what must not move.
fn schedules(run: &Outcome, idx: usize) -> Vec<Vec<u64>> {
    let mut out: Vec<Vec<u64>> = frames(run, idx)
        .into_values()
        .filter(|f| f.len() >= 100)
        .map(|f| {
            let first = *f.first().unwrap();
            f.iter().map(|t| t.saturating_sub(first)).collect()
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
/// in-flight teardown) against 0 — the C2R emission times of every scheduled link are identical: the same offsets
/// from the link's first frame, tick for tick (the first frame itself moves with the handshake, which latency lengthens);
/// every frame gap is exactly `P` = 10 s; emission does not wait for a response. (E), (K) in both runs.
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
        for (x, y) in a.iter().zip(&b) {
            let n = x.len().min(y.len());
            // the lengths differ when latency reorders the timing draws that fix the lifetimes; the times do not
            assert!(n >= 100, "client {idx}: a common prefix of {n} frames");
            assert_eq!(
                x.get(..n),
                y.get(..n),
                "client {idx}: emission times moved with latency"
            );
            assert!(
                x.windows(2).all(|w| w
                    .first()
                    .zip(w.last())
                    .is_some_and(|(a, b)| b.saturating_sub(*a) == 10_000)),
                "client {idx}: a gap that is not P"
            );
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
