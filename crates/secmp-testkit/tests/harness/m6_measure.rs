// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (h) measurements on the virtual clock (MR-01, MR-02; spec §10.2, §9.5; `docs/07` M6).

use secmp_client_core::scheduler::core::LinkKind;
use secmp_client_core::scheduler::conversation::Conversation;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, MsgState, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{LinkEvent, QueueId, RelayId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::cell::AppKind;
use secmp_relay::Limits;
use secmp_testkit::harness::{Dir, EntropyPool, HarnessConfig, START_UNIX, VirtualDriver};

use crate::m6_activity::{Rig, Scenario};
use crate::m6_common::{FRAME, TestConv, client_with, run_until_link_up};

/// Bytes of one SecMP-LINK handshake on the wire: HELLO 9 + RELAYINFO 1 744 + HS1 2 856 + HS2 1 156 (D.1).
const HANDSHAKE: u64 = 5_765;

/// Frames a tick of this kind moves in both directions (D.2): `SEND`+`OK_SEND` 2, `FETCH`+4×`CELLR` 5, a slot 11.
fn frames_per_tick(kind: LinkKind) -> u64 {
    match kind {
        LinkKind::Send => 2,
        LinkKind::Recv => 5,
        LinkKind::Relay => 11,
    }
}

/// The ticks of a connection that was up from `up` and ended at `down` (exclusive; `end_inclusive`: it is still up at
/// the end of the run, whose last instant counts).
fn ticks(up: u64, down: u64, period: u64, end_inclusive: bool) -> u64 {
    let span = down.saturating_sub(up);
    if end_inclusive {
        span / period
    } else if span == 0 {
        0
    } else {
        (span - 1) / period
    }
}

struct Model {
    expected: u64,
    measured: u64,
    uptime_ms: u64,
}

/// The model against the capture, connection by connection; panics on the first connection whose bytes differ.
fn check_model(rig: &Rig, end: u64) -> Vec<(u64, LinkKind, u64, Model)> {
    let c = rig.sim.client_ref(rig.x);
    let mut out = Vec::new();
    for (_, id, _) in &c.connects {
        let Some(up) = c.events.iter().find(|(_, e)| matches!(e, LinkEvent::Up(i) if i == id)) else {
            continue;
        };
        let (kind, period) = *c.link_kinds.get(&id.0).unwrap();
        let down = c
            .events
            .iter()
            .find(|(_, e)| matches!(e, LinkEvent::TornDown(i, _) if i == id))
            .map(|(t, _)| *t);
        let (stop, inclusive) = down.map_or((end, true), |t| (t, false));
        let n = ticks(up.0, stop, period, inclusive);
        let expected = n * frames_per_tick(kind) * FRAME as u64 + HANDSHAKE;
        let measured: u64 = c
            .trace
            .iter()
            .filter(|e| e.slot == id.0)
            .map(|e| e.len as u64)
            .sum();
        assert_eq!(measured, expected, "connection {} ({kind:?}, P = {period}), {n} ticks", id.0);
        out.push((id.0, kind, period, Model { expected, measured, uptime_ms: stop - up.0 }));
    }
    out
}

fn bytes_per_day(model: &[(u64, LinkKind, u64, Model)], kinds: &[LinkKind], period: u64) -> (u64, u64) {
    let (mut bytes, mut up) = (0, 0);
    for (_, k, p, m) in model {
        if kinds.contains(k) && *p == period {
            bytes += m.measured - HANDSHAKE;
            up += m.uptime_ms;
        }
    }
    (bytes, up)
}

/// MR-01: the bandwidth model equals the capture — units × 4 352 B + 5 765 B per handshake, per connection — and its
/// steady-state numbers are the spec's.
#[test]
fn bandwidth_model_matches_capture() {
    // the constants of spec §10.2
    assert_eq!(7_u64 * 4352 * 86_400 / 10, 263_208_960, "Strict, per contact and day");
    assert_eq!(7_u64 * 4352 * 10 / 10, 30_464);
    assert_eq!(11_u64 * 4352 * 86_400 / 10, 413_614_080, "Balanced");
    assert_eq!(11_u64 * 4352 * 86_400 / 30, 137_871_360, "Low-bw");
    let hours = 24;
    let end = hours * 3_600_000;
    let cases = [
        ("Strict", Mode::Strict, vec![(10_000, 10_000)], LinkKind::Send, 10_000),
        ("Balanced", Mode::Balanced, vec![(10_000, 10_000); 4], LinkKind::Relay, 10_000),
        ("Low-bw", Mode::LowBw, vec![(40_000, 40_000); 5], LinkKind::Relay, 30_000),
    ];
    for (name, mode, contacts, kind, period) in cases {
        let sc = Scenario { mode, contacts, pool: true, seed: 0x3a00 };
        let mut rig = Rig::new(&sc, Params::default());
        rig.run(hours, None);
        let model = check_model(&rig, end);
        assert!(model.len() >= 2, "{name}: links");
        // the steady state: bytes while up per second against the spec's figure
        let kinds: &[LinkKind] = if mode == Mode::Strict {
            &[LinkKind::Send, LinkKind::Recv]
        } else {
            &[kind]
        };
        let (bytes, up_ms) = bytes_per_day(&model, kinds, period);
        let (bytes, up_ms) = if mode == Mode::Strict {
            // the contact's send link and its 10 s recv link: 7 frames per 10 s
            let (b, u) = bytes_per_day(&model, &[LinkKind::Send, LinkKind::Recv], period);
            (b, u / 2)
        } else {
            (bytes, up_ms)
        };
        let per_day = if mode == Mode::Strict {
            7 * 4352 * 86_400 / 10
        } else {
            11 * 4352 * 86_400 / (period / 1000)
        };
        // up_ms of all links of the kind; normalise to one link-day
        let links = if mode == Mode::Strict { 1 } else { 1 };
        let measured_rate = bytes as f64 / ((up_ms / links) as f64 / 1000.0);
        let spec_rate = per_day as f64 / 86_400.0;
        let err = (measured_rate - spec_rate).abs() / spec_rate;
        std::eprintln!("MR-01 {name}: {measured_rate:.1} B/s while up, spec {spec_rate:.1} B/s, error {err:.5}");
        assert!(err < 0.005, "{name}: {measured_rate} vs {spec_rate}");
    }
}

fn real(n: u8) -> OutMessage {
    OutMessage {
        msg_id: [n; 16],
        kind: AppKind::Text,
        expire_after: 0,
        payload: Zeroizing::new(vec![n; 200]),
    }
}

/// One drain case: `senders` clients send to one recipient at `period_ms` each; the recipient (in `mode`) is offline for
/// `hours`, then returns. Returns `(evictions, ticks of the recipient's link until every queue is acknowledged)`.
fn drain_case(mode: Mode, senders: usize, period_ms: u64, hours: u64, seed: u64) -> (u64, u64, u64) {
    let params = Params {
        lifetime_ms: (200 * 3_600_000, 200 * 3_600_000),
        ..Params::default()
    };
    let config = HarnessConfig {
        limits: Limits {
            link_age_ms: 200 * 3_600_000,
            link_idle_ms: 200 * 3_600_000,
            ..HarnessConfig::default().limits
        },
        ..HarnessConfig::default()
    };
    let mut sim = VirtualDriver::new(config);
    let bob = client_with(&mut sim, mode, params.clone(), seed);
    sim.client(bob).opts.refuse_connections = true;
    let mut pairs = Vec::new();
    for i in 0..senders {
        let tag = u32::try_from(i).unwrap();
        let alice = client_with(&mut sim, Mode::Strict, params.clone(), seed + 1 + u64::from(tag));
        let (rc_b, sc_b, rb, sb) = sim.new_queue(bob);
        let now = sim.now();
        let a_send = sim.client(alice).sched.add_send_queue(now, RelayId(0), sc_b, period_ms).unwrap();
        let b_recv = sim.client(bob).sched.add_recv_queue(now, RelayId(0), rc_b, period_ms).unwrap();
        sim.client(bob).material.queues.insert(b_recv.0, (rb, sb));
        let (state_a, state_b) = sim.ratchet_states(alice, bob);
        let key_a = sim.peer_key(alice);
        let key_b = sim.peer_key(bob);
        let mut conv_a: TestConv = Conversation::new(
            state_a,
            MemOutbox::new(),
            MemPersist::new(),
            EntropyPool::new("m6-mr2-a", tag),
            key_b,
            START_UNIX,
        );
        let mut conv_b: TestConv = Conversation::new(
            state_b,
            MemOutbox::new(),
            MemPersist::new(),
            EntropyPool::new("m6-mr2-b", tag),
            key_a,
            START_UNIX,
        );
        conv_a.bind(a_send, QueueId(u32::MAX));
        conv_b.bind(QueueId(u32::MAX - 1), b_recv);
        let ia = sim.client(alice).convs.add(conv_a);
        let ib = sim.client(bob).convs.add(conv_b);
        for n in 0..10_u8 {
            sim.client(alice).convs.get_mut(ia).unwrap().outbox_mut().enqueue(real(n), 0);
        }
        pairs.push((alice, ia, ib, b_recv));
    }
    let mut ups = Vec::new();
    for (alice, _, _, _) in &pairs {
        let (_, t) = run_until_link_up(&mut sim, *alice, LinkKind::Send);
        ups.push(t);
    }
    // the window ends `hours` after the latest link came up; each sender sent for as long as it was up
    let t_end = ups.iter().max().unwrap() + hours * 3_600_000;
    sim.run_until(t_end);
    let sent_each: Vec<u64> = pairs
        .iter()
        .map(|(a, _, _, _)| sim.client_ref(*a).gate.relayed_max)
        .collect();
    let evicted: u64 = pairs
        .iter()
        .map(|(a, _, _, _)| sim.client_ref(*a).gate.evicted_count)
        .sum();
    for (((alice, _, _, _), sent), up) in pairs.iter().zip(&sent_each).zip(&ups) {
        let expected_sent = (t_end - up) / period_ms;
        assert_eq!(*sent, expected_sent, "sender {alice}");
        assert!(*sent > 128);
    }
    assert_eq!(
        evicted,
        sent_each.iter().map(|s| s - 128).sum::<u64>(),
        "the relay evicts exactly the cells beyond the 128 it holds"
    );
    sim.client(bob).opts.refuse_connections = false;
    let (_, _) = run_until_link_up(
        &mut sim,
        bob,
        if mode == Mode::Strict { LinkKind::Recv } else { LinkKind::Relay },
    );
    // Strict recipients have one link per queue: one sender here
    let ticks = |sim: &VirtualDriver| {
        sim.client_ref(bob)
            .sched
            .links()
            .iter()
            .map(|l| u64::from(l.ticks))
            .max()
            .unwrap()
    };
    let mut guard = 0;
    loop {
        let next = sim.now() + period_ms.min(10_000);
        sim.run_until(next);
        let drained = pairs.iter().all(|(a, _, _, q)| {
            let newest = sim.client_ref(*a).gate.relayed_max;
            sim.client_ref(bob).sched.acked(*q).unwrap() + 1 >= newest
        });
        if drained {
            break;
        }
        guard += 1;
        assert!(guard < 100_000, "the queues do not drain");
    }
    let took = ticks(&sim);
    for (_, _, ib, _) in &pairs {
        let got = sim.client_ref(bob).convs.get(*ib).unwrap().received().len();
        assert_eq!(got, 10, "no real message lost");
    }
    for (alice, ia, _, _) in &pairs {
        let all_relayed = (0..10_u8)
            .filter_map(|n| sim.client_ref(*alice).convs.get(*ia).unwrap().outbox().state(&[n; 16]))
            .all(|s| matches!(s, MsgState::Relayed(_)));
        assert!(all_relayed);
    }
    (evicted, sent_each.iter().sum(), took)
}

/// MR-02: after the recipient was offline for 1 h or 24 h the relay has evicted exactly what the 128-cell queues could
/// not hold, the queue drains within the ticks the `F`/`F_M` arithmetic gives, and no real message is lost.
#[test]
fn drain_after_offline_virtual() {
    // Strict, P = 10 s: 1 h → 360 sends, 232 evicted; 24 h → 8 640 sends, 8 512 evicted; 45 recv ticks
    for (hours, sends, evicted) in [(1_u64, 360_u64, 232_u64), (24, 8_640, 8_512)] {
        let (e, s, ticks) = drain_case(Mode::Strict, 1, 10_000, hours, 0x7100 + hours);
        std::eprintln!("MR-02 Strict {hours} h: {s} sent, {e} evicted, drained in {ticks} recv ticks");
        assert_eq!((s, e), (sends, evicted), "{hours} h: sends and evictions");
        assert!(ticks <= 45, "Strict: {ticks} recv ticks");
    }
    // Balanced, four contacts at 10 s: empty within 130 slots
    let (e, s, slots) = drain_case(Mode::Balanced, 4, 10_000, 1, 0x7300);
    std::eprintln!("MR-02 Balanced 4 × 10 s: {s} sent, {e} evicted, drained in {slots} slots");
    assert!(slots <= 130, "Balanced: {slots} slots");
    // Low-bw, five contacts at 40 s, a day offline: empty within 153 slots
    let (e, s, slots) = drain_case(Mode::LowBw, 5, 40_000, 24, 0x7400);
    std::eprintln!("MR-02 Low-bw 5 × 40 s: {s} sent, {e} evicted, drained in {slots} slots");
    assert!(slots <= 153, "Low-bw: {slots} slots");
}
