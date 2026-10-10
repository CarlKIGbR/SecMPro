// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d5) rotation, reconnect and back-off (LR-01…LR-06; spec §8.4, §10.6 (1), M05-review F-1 M6 part).

use secmp_client_core::scheduler::core::{LinkKind, Scheduler};
use secmp_client_core::scheduler::outbox::{OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params, backoff_cap};
use secmp_client_core::scheduler::types::{LinkEvent, LinkId, Output, Reason, RelayId, Transport};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::Zeroizing;
use secmp_proto::wire::cell::AppKind;
use secmp_testkit::harness::Dir;

use crate::m6_common::{
    FRAME, client, client_with, contact, driver, frames, ks_uniform, run_until_link_up, send_only,
};
use crate::m6_sched_bal::{NoCells, fresh_recv_cap};

/// LR-01: a link whose send counter reaches `LINK_MAX_FRAMES` is replaced, never sealed past the bound.
#[test]
fn new_link_required_rotates() {
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 11);
    let bob = client(&mut sim, Mode::Strict, 12);
    send_only(&mut sim, alice, bob, 10_000);
    let (slot, t_up) = run_until_link_up(&mut sim, alice, LinkKind::Send);
    sim.run_until(t_up + 25_000);
    sim.set_send_counter(alice, LinkId(slot), (1 << 20) - 1);
    let t = sim.now();
    sim.run_until(t + 400_000);
    let c = sim.client_ref(alice);
    let torn = c
        .events
        .iter()
        .find(
            |(_, e)| matches!(e, LinkEvent::TornDown(id, Reason::NewLinkRequired) if id.0 == slot),
        )
        .expect("TornDown(NewLinkRequired)");
    let next = c
        .connects
        .iter()
        .find(|(at, id, _)| *at >= torn.0 && id.0 != slot)
        .expect("a new link");
    assert!(next.0 - torn.0 <= 180_000, "reconnect within U[0, 3 min]");
    let first_key = c.connects.iter().find(|(_, id, _)| id.0 == slot).unwrap().2;
    assert_ne!(next.2, first_key, "a new key");
    // the old link wrote at most one frame beyond the set counter
    let old: Vec<_> = frames(&sim, alice, Dir::C2R)
        .into_iter()
        .filter(|e| e.slot == slot && e.t_ms > t)
        .collect();
    assert!(
        old.len() <= 1,
        "{} frames after the counter was set",
        old.len()
    );
}

/// LR-02: after a failure the next attempt follows at `U[0, 180 s]`.
#[test]
fn reconnect_jitter_after_failure() {
    let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(0x1202));
    for n in 0..1000_u32 {
        sched
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(n), 80_000)
            .unwrap();
    }
    let t = 200_000;
    let outs = sched.poll(t, &mut NoCells).unwrap();
    let links: Vec<LinkId> = outs
        .iter()
        .filter_map(|o| {
            if let Output::Connect { link, .. } = o {
                Some(*link)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(links.len(), 1000);
    for link in links {
        sched.connect_failed(link, t, false).unwrap();
    }
    let delays: Vec<u64> = sched
        .links()
        .iter()
        .map(|l| l.starts_at.unwrap() - t)
        .collect();
    assert!(delays.iter().all(|d| *d <= 180_000));
    let (dstat, p) = ks_uniform(&delays, 0, 180_000);
    assert!(p >= 0.01, "KS D = {dstat}, p = {p}");

    // a real close: the relay restarts and the links come back at their own random offsets
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 21);
    let bob = client(&mut sim, Mode::Strict, 22);
    contact(&mut sim, alice, bob, 10_000, 40_000);
    sim.run_until(400_000);
    sim.restart_relay();
    let t_cut = 500_000;
    sim.run_until(t_cut + 200_000);
    let c = sim.client_ref(alice);
    let torn: Vec<u64> = c
        .events
        .iter()
        .filter(|(at, e)| *at >= 400_000 && matches!(e, LinkEvent::TornDown(_, Reason::Closed)))
        .map(|(at, _)| *at)
        .collect();
    assert!(!torn.is_empty());
    let back = c
        .connects
        .iter()
        .filter(|(at, _, _)| *at > *torn.first().unwrap())
        .count();
    assert!(back >= 1);
}

/// LR-03: consecutive closes before `RELAYINFO` back off exponentially up to the cap, and the count resets after an `HS2`.
#[test]
fn backoff_closed_before_relayinfo() {
    let caps: Vec<u64> = (1..=8)
        .map(|n| backoff_cap(n, 180_000, 3_600_000))
        .collect();
    assert_eq!(
        caps,
        [
            180_000, 360_000, 720_000, 1_440_000, 2_880_000, 3_600_000, 3_600_000, 3_600_000
        ]
    );
    let mut maxima = [0_u64; 8];
    for seed in 0..300_u64 {
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(seed));
        sched
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(1), 80_000)
            .unwrap();
        let mut now = sched.links().first().unwrap().starts_at.unwrap();
        for (n, cap) in caps.iter().enumerate() {
            let outs = sched.poll(now, &mut NoCells).unwrap();
            let link = outs
                .iter()
                .find_map(|o| {
                    if let Output::Connect { link, .. } = o {
                        Some(*link)
                    } else {
                        None
                    }
                })
                .unwrap();
            sched.connect_failed(link, now, true).unwrap();
            let info = *sched.links().first().unwrap();
            assert_eq!(info.closed_before, u32::try_from(n + 1).unwrap());
            let delay = info.starts_at.unwrap() - now;
            assert!(delay <= *cap, "n = {}: {delay} > {cap}", n + 1);
            let m = maxima.get_mut(n).unwrap();
            *m = (*m).max(delay);
            now = info.starts_at.unwrap();
        }
    }
    for (m, cap) in maxima.iter().zip(&caps) {
        assert!(
            *m * 10 > *cap * 9,
            "the delay reaches its cap: {m} of {cap}"
        );
    }

    // the exponent resets after an HS2
    let mut sim = driver();
    let alice = client(&mut sim, Mode::Strict, 31);
    let bob = client(&mut sim, Mode::Strict, 32);
    send_only(&mut sim, alice, bob, 10_000);
    sim.client(alice).opts.refuse_connections = true;
    while sim.client_ref(alice).refused < 3 {
        let next = sim.now() + 10_000;
        sim.run_until(next);
    }
    assert_eq!(
        sim.client_ref(alice)
            .sched
            .links()
            .first()
            .unwrap()
            .closed_before,
        3
    );
    sim.client(alice).opts.refuse_connections = false;
    let (_, _) = run_until_link_up(&mut sim, alice, LinkKind::Send);
    assert_eq!(
        sim.client_ref(alice)
            .sched
            .links()
            .first()
            .unwrap()
            .closed_before,
        0,
        "reset after HS2"
    );
}

/// LR-04: the back-off draws from the timing randomness only — an outbox full of messages changes no reconnect time.
#[test]
fn backoff_uses_timing_rng_only() {
    let run = |full: bool| {
        let mut sim = driver();
        let alice = client(&mut sim, Mode::Strict, 41);
        let bob = client(&mut sim, Mode::Strict, 42);
        let conv = send_only(&mut sim, alice, bob, 10_000);
        if full {
            let o = sim.client(alice).convs.get_mut(conv).unwrap().outbox_mut();
            for n in 0..50_u8 {
                o.enqueue(
                    OutMessage {
                        msg_id: [n; 16],
                        kind: AppKind::Text,
                        expire_after: 0,
                        payload: Zeroizing::new(vec![n; 100]),
                    },
                    0,
                );
            }
        }
        sim.client(alice).opts.refuse_connections = true;
        sim.run_until(20_000_000);
        sim.client_ref(alice)
            .connects
            .iter()
            .map(|(t, _, _)| *t)
            .collect::<Vec<u64>>()
    };
    let empty = run(false);
    let full = run(true);
    assert!(empty.len() >= 8);
    assert_eq!(empty, full);
}

/// LR-05: repeated failure never changes the transport — Tor stays Tor, direct stays direct.
#[test]
fn reconnect_never_changes_transport() {
    for (direct, want) in [(false, Transport::Tor), (true, Transport::Direct)] {
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(5));
        sched.set_direct(0, direct, &mut NoCells).unwrap();
        sched
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(1), 80_000)
            .unwrap();
        let mut seen = Vec::new();
        let mut now = sched.links().first().unwrap().starts_at.unwrap();
        for _ in 0..8 {
            let outs = sched.poll(now, &mut NoCells).unwrap();
            for o in outs {
                if let Output::Connect {
                    link, transport, ..
                } = o
                {
                    seen.push(transport);
                    sched.connect_failed(link, now, true).unwrap();
                }
            }
            now = sched.links().first().unwrap().starts_at.unwrap();
        }
        assert_eq!(seen.len(), 8);
        assert!(seen.iter().all(|t| *t == want), "{seen:?}");
    }
}

/// LR-06: across 100 rotations and reconnects no two `SEND`s of the queue are less than `P_q` apart.
#[test]
fn rotation_and_reconnect_keep_send_spacing() {
    let params = Params {
        lifetime_ms: (30_000, 60_000),
        phase_max_ms: 5_000,
        ..Params::default()
    };
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, params, 61);
    let bob = client(&mut sim, Mode::Strict, 62);
    send_only(&mut sim, alice, bob, 10_000);
    let mut t = 0;
    for round in 0..20_u64 {
        t += 300_000;
        sim.run_until(t);
        if round % 4 == 3 {
            sim.restart_relay();
        }
    }
    let rotations = sim
        .client_ref(alice)
        .events
        .iter()
        .filter(|(_, e)| matches!(e, LinkEvent::TornDown(_, Reason::Lifetime | Reason::Closed)))
        .count();
    assert!(rotations >= 100, "{rotations} rotations and reconnects");
    let mut sends: Vec<u64> = frames(&sim, alice, Dir::C2R)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    sends.sort_unstable();
    assert!(sends.len() > 300);
    for pair in sends.windows(2) {
        let (first, second) = (*pair.first().unwrap(), *pair.get(1).unwrap());
        assert!(second - first >= 10_000, "{first} then {second}");
    }
    assert!(frames(&sim, alice, Dir::C2R).iter().all(|e| e.len == FRAME));
}
