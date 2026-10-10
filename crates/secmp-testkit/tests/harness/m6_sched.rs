// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d1) the scheduler core on the virtual clock (S-01…S-32; spec §10, `docs/02` §4.4).

use secmp_client_core::scheduler::core::{LinkKind, SchedError};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::RelayId;
use secmp_testkit::harness::Dir;

use crate::m6_common::{FRAME, at, client, client_with, contact, driver, frames, frames_of};

/// The (only) link of `kind` of client `c`, once it is up.
fn the_link(sim: &secmp_testkit::harness::VirtualDriver, c: usize, kind: LinkKind) -> (u64, u64) {
    let infos = sim.client_ref(c).sched.links();
    let info = infos.iter().find(|l| l.kind == kind).unwrap();
    (info.id.unwrap().0, info.t_up.unwrap())
}

/// S-01: Strict opens one link per queue — two contacts and two pool queues give 6 links (2 send, 4 recv), each with
/// its own isolation key.
#[test]
fn strict_one_link_per_queue() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 11);
    let b = client(&mut sim, Mode::Strict, 12);
    let c = client(&mut sim, Mode::Strict, 13);
    contact(&mut sim, a, b, 10_000, 10_000);
    contact(&mut sim, a, c, 10_000, 10_000);
    let now = sim.now();
    sim.client(a).sched.manage_pool(now, RelayId(0)).unwrap();
    // the creations are control operations, 1…60 min out; their queues' links start ≤ 3 min later
    sim.run_until(3_600_000 + 200_000);
    let links = sim.client_ref(a).sched.links();
    let send = links.iter().filter(|l| l.kind == LinkKind::Send).count();
    let recv = links.iter().filter(|l| l.kind == LinkKind::Recv).count();
    assert_eq!((links.len(), send, recv), (6, 2, 4));
    // VD-6: the isolation keys of exactly these six links, pairwise distinct
    let current: std::collections::HashSet<u64> = links
        .iter()
        .map(|l| {
            let id = l.id.expect("connected");
            sim.client_ref(a)
                .connects
                .iter()
                .find(|(_, c, _)| *c == id)
                .map(|(_, _, k)| k.0)
                .expect("the connection's key")
        })
        .collect();
    assert_eq!(current.len(), 6, "six pairwise-distinct link keys");
    let ids: Vec<u64> = links.iter().filter_map(|l| l.id.map(|i| i.0)).collect();
    assert_eq!(ids.len(), 6, "all six are connected");
}

/// S-02: a Strict send link writes one `SEND` per period at `t_up + k·P`, 360 in an hour.
#[test]
fn strict_send_link_one_send_per_period() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 21);
    let b = client(&mut sim, Mode::Strict, 22);
    contact(&mut sim, a, b, 10_000, 80_000);
    sim.run_until(200_000);
    let (slot, t_up) = the_link(&sim, a, LinkKind::Send);
    sim.run_until(at(t_up, 360, 10_000));
    let sends = frames_of(&sim, a, Dir::C2R, slot);
    assert_eq!(sends.len(), 360);
    for (k, e) in sends.iter().enumerate() {
        assert_eq!(
            e.t_ms,
            at(t_up, u64::try_from(k).unwrap() + 1, 10_000),
            "tick {k}"
        );
        assert_eq!(e.len, FRAME);
    }
}

/// S-03: a Strict recv link writes one `FETCH` per period, each answered by 4 `CELLR`.
#[test]
fn strict_recv_link_one_fetch_per_period() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 31);
    let b = client(&mut sim, Mode::Strict, 32);
    contact(&mut sim, a, b, 80_000, 40_000);
    sim.run_until(200_000);
    let (slot, t_up) = the_link(&sim, a, LinkKind::Recv);
    sim.run_until(at(t_up, 90, 40_000));
    let fetches = frames_of(&sim, a, Dir::C2R, slot);
    let answers = frames_of(&sim, a, Dir::R2C, slot);
    assert_eq!(fetches.len(), 90);
    assert_eq!(answers.len(), 360, "four CELLR per FETCH");
}

/// S-04: the SEND counts per hour for the four periods.
#[test]
fn strict_counts_for_every_period() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 41);
    let b = client(&mut sim, Mode::Strict, 42);
    for p in [10_000, 20_000, 40_000, 80_000] {
        contact(&mut sim, a, b, p, 80_000);
    }
    sim.run_until(200_000);
    let links = sim.client_ref(a).sched.links();
    let sends: Vec<_> = links.iter().filter(|l| l.kind == LinkKind::Send).collect();
    assert_eq!(sends.len(), 4);
    let t0 = sends.iter().map(|l| l.t_up.unwrap()).max().unwrap();
    sim.run_until(at(t0, 1, 3_600_000));
    let mut counts = Vec::new();
    for (l, p) in sends.iter().zip([10_000_u64, 20_000, 40_000, 80_000]) {
        let t_up = l.t_up.unwrap();
        let n = frames_of(&sim, a, Dir::C2R, l.id.unwrap().0)
            .iter()
            .filter(|e| e.t_ms <= at(t_up, 1, 3_600_000))
            .count();
        counts.push((p, n));
    }
    // 3 600 s after each link's own t_up: 360, 180, 90, 45 (the run covers t0 + 3 600 s ≥ every link's)
    assert_eq!(
        counts.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
        vec![360, 180, 90, 45]
    );
}

/// S-05: a period outside `PERIODS` is refused, no link is made, nothing is drawn.
#[test]
fn period_outside_set_rejected() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 51);
    let b = client(&mut sim, Mode::Strict, 52);
    let (rc, sc, _, _) = sim.new_queue(b);
    let now = sim.now();
    for bad in [0, 15_000, 81_000, 65_535_000] {
        let draws = sim.client_ref(a).sched.timing_draws();
        let (sc2, rc2) = (
            secmp_transport::SendCap::from_bytes(&sc.to_bytes()).unwrap(),
            secmp_transport::RecvCap::from_bytes(&rc.to_bytes()).unwrap(),
        );
        let r = sim
            .client(a)
            .sched
            .add_send_queue(now, RelayId(0), sc2, bad);
        assert_eq!(r.err(), Some(SchedError::BadPeriod), "send {bad}");
        let r = sim
            .client(a)
            .sched
            .add_recv_queue(now, RelayId(0), rc2, bad);
        assert_eq!(r.err(), Some(SchedError::BadPeriod), "recv {bad}");
        assert_eq!(sim.client_ref(a).sched.timing_draws(), draws, "no draw");
    }
    assert!(sim.client_ref(a).sched.links().is_empty());
}

/// S-18: ticks sit at `t_up + k·P` however long the preparation takes; nothing is written at `t_up` itself.
#[test]
fn tick_anchor_after_hs2() {
    let mut sim = driver();
    let params = Params {
        phase_max_ms: 0,
        ..Params::default()
    };
    let a = client_with(&mut sim, Mode::Strict, params.clone(), 181);
    let b = client_with(&mut sim, Mode::Strict, params, 182);
    sim.run_until(12_345);
    contact(&mut sim, a, b, 10_000, 80_000);
    sim.run_until(12_345);
    let (slot, t_up) = the_link(&sim, a, LinkKind::Send);
    assert_eq!(t_up, 12_345);
    sim.run_until(at(t_up, 5, 10_000));
    let times: Vec<u64> = frames_of(&sim, a, Dir::C2R, slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert_eq!(times, vec![22_345, 32_345, 42_345, 52_345, 62_345]);
    assert!(
        frames(&sim, a, Dir::C2R)
            .iter()
            .all(|e| e.t_ms != 12_345 || e.len != FRAME)
    );
}
