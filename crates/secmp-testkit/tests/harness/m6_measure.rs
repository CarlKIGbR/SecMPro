// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (h) measurements on the virtual clock (MR-01, MR-02; spec §10.2, §9.5; `docs/07` M6).

use secmp_client_core::scheduler::conversation::Conversation;
use secmp_client_core::scheduler::core::LinkKind;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, MsgState, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{LinkEvent, QueueId, RelayId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::cell::AppKind;
use secmp_relay::Limits;
use secmp_testkit::harness::{EntropyPool, HarnessConfig, START_UNIX, VirtualDriver};

use crate::m6_activity::{Rig, Scenario};
use crate::m6_common::{FRAME, TestConv, client_with, evidence, run_until_link_up};

/// Bytes of one SecMP-LINK handshake on the wire: HELLO 9 + RELAYINFO 1 744 + HS1 2 856 + HS2 1 156 (D.1).
const HANDSHAKE: u64 = 5_765;

fn frame_bytes() -> u64 {
    u64::try_from(FRAME).unwrap()
}

/// Frames a tick of this kind moves in both directions (D.2): `SEND`+`OK_SEND` 2, `FETCH`+4×`CELLR` 5, a slot 11.
const fn frames_per_tick(kind: LinkKind) -> u64 {
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
    let counted = if end_inclusive {
        span
    } else {
        span.saturating_sub(1)
    };
    counted.checked_div(period).unwrap()
}

/// One connection of the run: what the capture holds.
struct Conn {
    kind: LinkKind,
    period: u64,
    measured: u64,
    uptime_ms: u64,
}

/// The model against the capture, connection by connection; fails on the first connection whose bytes differ.
fn check_model(rig: &Rig, end: u64) -> Vec<Conn> {
    let client = rig.sim.client_ref(rig.x);
    let mut out = Vec::new();
    for (_, id, _) in &client.connects {
        let Some(up) = client
            .events
            .iter()
            .find(|(_, e)| matches!(e, LinkEvent::Up(i) if i == id))
        else {
            continue;
        };
        let (kind, period) = *client.link_kinds.get(&id.0).unwrap();
        let down = client
            .events
            .iter()
            .find(|(_, e)| matches!(e, LinkEvent::TornDown(i, _) if i == id))
            .map(|(t, _)| *t);
        let (stop, inclusive) = down.map_or((end, true), |t| (t, false));
        let n = ticks(up.0, stop, period, inclusive);
        let expected = n
            .checked_mul(frames_per_tick(kind))
            .and_then(|f| f.checked_mul(frame_bytes()))
            .and_then(|b| b.checked_add(HANDSHAKE))
            .unwrap();
        let measured: u64 = client
            .trace
            .iter()
            .filter(|e| e.slot == id.0)
            .map(|e| u64::try_from(e.len).unwrap())
            .sum();
        assert_eq!(
            measured, expected,
            "connection {} ({kind:?}, P = {period}), {n} ticks",
            id.0
        );
        out.push(Conn {
            kind,
            period,
            measured,
            uptime_ms: stop.saturating_sub(up.0),
        });
    }
    out
}

fn as_f64(n: u64) -> f64 {
    f64::from(u32::try_from(n).unwrap())
}

/// Bytes per second while up of the connections of `kind` and `period` (the handshakes excluded).
fn rate_of(model: &[Conn], kind: LinkKind, period: u64) -> f64 {
    let (mut bytes, mut up_ms) = (0_u64, 0_u64);
    for c in model
        .iter()
        .filter(|c| c.kind == kind && c.period == period)
    {
        bytes = bytes.saturating_add(c.measured.saturating_sub(HANDSHAKE));
        up_ms = up_ms.saturating_add(c.uptime_ms);
    }
    as_f64(bytes) / (as_f64(up_ms) / 1000.0)
}

/// MR-01: the bandwidth model equals the capture — units × 4 352 B + 5 765 B per handshake, per connection — and its
/// steady-state numbers are the spec's.
#[test]
fn bandwidth_model_matches_capture() {
    // the constants of spec §10.2
    assert_eq!(
        7_u64 * 4352 * 86_400 / 10,
        263_208_960,
        "Strict, per contact and day"
    );
    assert_eq!(11_u64 * 4352 * 86_400 / 10, 413_614_080, "Balanced");
    assert_eq!(11_u64 * 4352 * 86_400 / 30, 137_871_360, "Low-bw");
    let hours = 24;
    let end = hours * 3_600_000;
    let mut lines = Vec::new();
    // (name, mode, contacts, steady-state links as (kind, period), the spec's bytes per day)
    let cases = [
        (
            "Strict",
            Mode::Strict,
            vec![(10_000, 10_000)],
            vec![(LinkKind::Send, 10_000_u64), (LinkKind::Recv, 10_000)],
            263_208_960_u64,
        ),
        (
            "Balanced",
            Mode::Balanced,
            vec![(10_000, 10_000); 4],
            vec![(LinkKind::Relay, 10_000)],
            413_614_080,
        ),
        (
            "Low-bw",
            Mode::LowBw,
            vec![(40_000, 40_000); 5],
            vec![(LinkKind::Relay, 30_000)],
            137_871_360,
        ),
    ];
    for (name, mode, contacts, links, per_day) in cases {
        let sc = Scenario {
            mode,
            contacts,
            pool: true,
            seed: 0x3a00,
        };
        let mut rig = Rig::new(&sc, Params::default());
        rig.run(hours, None);
        let model = check_model(&rig, end);
        assert!(model.len() >= 2, "{name}: links");
        // the steady state: the contact's links together, bytes per second while up
        let measured_rate: f64 = links
            .iter()
            .map(|(kind, period)| rate_of(&model, *kind, *period))
            .sum();
        let spec_rate = as_f64(per_day / 86_400);
        let exact = f64::from(u32::try_from(per_day).unwrap()) / 86_400.0;
        let err = (measured_rate - exact).abs() / exact;
        lines.push(format!(
            "{name}: {measured_rate:.1} B/s while up, spec {exact:.1} B/s ({spec_rate} B/s whole), error {err:.5}"
        ));
        assert!(err < 0.005, "{name}: {measured_rate} vs {exact}");
    }
    evidence("MR-01", &lines.join("\n"));
}

fn real(n: u8) -> OutMessage {
    OutMessage {
        msg_id: [n; 16],
        kind: AppKind::Text,
        expire_after: 0,
        payload: Zeroizing::new(vec![n; 200]),
    }
}

/// One sender of a drain case: its client, conversation index, and the recipient's conversation and queue.
struct Sender {
    client: usize,
    conv: usize,
    bob_conv: usize,
    bob_queue: QueueId,
}

fn add_sender(
    sim: &mut VirtualDriver,
    bob: usize,
    tag: u32,
    period_ms: u64,
    params: &Params,
    seed: u64,
) -> Sender {
    let alice = client_with(
        sim,
        Mode::Strict,
        params.clone(),
        seed.wrapping_add(1).wrapping_add(u64::from(tag)),
    );
    let (rc, sc, recv_seed, send_seed) = sim.new_queue(bob);
    let now = sim.now();
    let a_send = sim
        .client(alice)
        .sched
        .add_send_queue(now, RelayId(0), sc, period_ms)
        .unwrap();
    let b_recv = sim
        .client(bob)
        .sched
        .add_recv_queue(now, RelayId(0), rc, period_ms)
        .unwrap();
    sim.client(bob)
        .material
        .queues
        .insert(b_recv.0, (recv_seed, send_seed));
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
    let conv = sim.client(alice).convs.add(conv_a);
    let bob_conv = sim.client(bob).convs.add(conv_b);
    for n in 0..10_u8 {
        sim.client(alice)
            .convs
            .get_mut(conv)
            .unwrap()
            .outbox_mut()
            .enqueue(real(n), 0);
    }
    Sender {
        client: alice,
        conv,
        bob_conv,
        bob_queue: b_recv,
    }
}

/// The recipient returns; run until every queue is acknowledged. Returns the ticks of its busiest link.
fn return_and_drain(
    sim: &mut VirtualDriver,
    bob: usize,
    all: &[Sender],
    mode: Mode,
    period_ms: u64,
) -> u64 {
    sim.client(bob).opts.refuse_connections = false;
    let kind = if mode == Mode::Strict {
        LinkKind::Recv
    } else {
        LinkKind::Relay
    };
    run_until_link_up(sim, bob, kind);
    let mut guard = 0_u32;
    while !all.iter().all(|s| {
        let newest = sim.client_ref(s.client).gate.relayed_max;
        sim.client_ref(bob)
            .sched
            .acked(s.bob_queue)
            .unwrap()
            .saturating_add(1)
            >= newest
    }) {
        let next = sim.now().saturating_add(period_ms.min(10_000));
        sim.run_until(next);
        guard = guard.saturating_add(1);
        assert!(guard < 100_000, "the queues do not drain");
    }
    sim.client_ref(bob)
        .sched
        .links()
        .iter()
        .map(|l| u64::from(l.ticks))
        .max()
        .unwrap()
}

/// What one drain case found.
struct Drain {
    evicted: u64,
    sent: u64,
    ticks: u64,
}

/// One drain case: `senders` clients send to one recipient at `period_ms` each; the recipient (in `mode`) is offline for
/// `hours`, then returns. Reports the evictions and the ticks of the recipient's link until every queue is acknowledged.
fn drain_case(mode: Mode, senders: usize, period_ms: u64, hours: u64, seed: u64) -> Drain {
    let long = 200 * 3_600_000;
    let params = Params {
        lifetime_ms: (long, long),
        ..Params::default()
    };
    let config = HarnessConfig {
        limits: Limits {
            link_age_ms: long,
            link_idle_ms: long,
            ..HarnessConfig::default().limits
        },
        ..HarnessConfig::default()
    };
    let mut sim = VirtualDriver::new(config);
    let bob = client_with(&mut sim, mode, params.clone(), seed);
    sim.client(bob).opts.refuse_connections = true;
    let all: Vec<Sender> = (0..senders)
        .map(|i| {
            add_sender(
                &mut sim,
                bob,
                u32::try_from(i).unwrap(),
                period_ms,
                &params,
                seed,
            )
        })
        .collect();
    let ups: Vec<u64> = all
        .iter()
        .map(|s| run_until_link_up(&mut sim, s.client, LinkKind::Send).1)
        .collect();
    // the window ends `hours` after the latest link came up; each sender sent for as long as it was up
    let t_end = ups
        .iter()
        .max()
        .unwrap()
        .saturating_add(hours.saturating_mul(3_600_000));
    sim.run_until(t_end);
    let sent_each: Vec<u64> = all
        .iter()
        .map(|s| sim.client_ref(s.client).gate.relayed_max)
        .collect();
    let evicted: u64 = all
        .iter()
        .map(|s| sim.client_ref(s.client).gate.evicted_count)
        .sum();
    for ((s, sent), up) in all.iter().zip(&sent_each).zip(&ups) {
        let want = t_end.saturating_sub(*up).checked_div(period_ms).unwrap();
        assert_eq!(*sent, want, "sender {}", s.client);
        assert!(*sent > 128);
    }
    assert_eq!(
        evicted,
        sent_each.iter().map(|s| s.saturating_sub(128)).sum::<u64>(),
        "the relay evicts exactly the cells beyond the 128 it holds"
    );
    let took = return_and_drain(&mut sim, bob, &all, mode, period_ms);
    for s in &all {
        let got = sim
            .client_ref(bob)
            .convs
            .get(s.bob_conv)
            .unwrap()
            .received()
            .len();
        assert_eq!(got, 10, "no real message lost");
        let relayed = (0..10_u8)
            .filter_map(|n| {
                sim.client_ref(s.client)
                    .convs
                    .get(s.conv)
                    .unwrap()
                    .outbox()
                    .state(&[n; 16])
            })
            .all(|st| matches!(st, MsgState::Relayed(_)));
        assert!(relayed);
    }
    Drain {
        evicted,
        sent: sent_each.iter().sum(),
        ticks: took,
    }
}

/// MR-02: after the recipient was offline for 1 h or 24 h the relay has evicted exactly what the 128-cell queues could
/// not hold, the queue drains within the ticks the `F`/`F_M` arithmetic gives, and no real message is lost.
#[test]
fn drain_after_offline_virtual() {
    let mut lines = Vec::new();
    // Strict, P = 10 s: 1 h → 360 sends, 232 evicted; 24 h → 8 640 sends, 8 512 evicted; 45 recv ticks
    for (hours, sends, evicted) in [(1_u64, 360_u64, 232_u64), (24, 8_640, 8_512)] {
        let d = drain_case(
            Mode::Strict,
            1,
            10_000,
            hours,
            0x7100_u64.wrapping_add(hours),
        );
        lines.push(format!(
            "Strict {hours} h: {} sent, {} evicted, drained in {} recv ticks",
            d.sent, d.evicted, d.ticks
        ));
        assert_eq!(
            (d.sent, d.evicted),
            (sends, evicted),
            "{hours} h: sends and evictions"
        );
        assert!(d.ticks <= 45, "Strict: {} recv ticks", d.ticks);
    }
    // Balanced, four contacts at 10 s: empty within 130 slots
    let d = drain_case(Mode::Balanced, 4, 10_000, 1, 0x7300);
    lines.push(format!(
        "Balanced 4 x 10 s: {} sent, {} evicted, drained in {} slots",
        d.sent, d.evicted, d.ticks
    ));
    assert!(d.ticks <= 130, "Balanced: {} slots", d.ticks);
    // Low-bw, five contacts at 40 s, a day offline: empty within 153 slots
    let d = drain_case(Mode::LowBw, 5, 40_000, 24, 0x7400);
    lines.push(format!(
        "Low-bw 5 x 40 s: {} sent, {} evicted, drained in {} slots",
        d.sent, d.evicted, d.ticks
    ));
    assert!(d.ticks <= 153, "Low-bw: {} slots", d.ticks);
    evidence("MR-02", &lines.join("\n"));
}
