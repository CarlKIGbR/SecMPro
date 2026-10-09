// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d1) link lifetimes, the prepare/tick split, the in-flight bound (S-16…S-24; spec §10.1, §10.3, §10.6 (1)).

use secmp_client_core::scheduler::core::LinkKind;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{LinkEvent, Reason, RelayId};
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{Dir, Inspect, VirtualDriver};

use crate::m6_common::{
    FRAME, at, client, client_with, contact, driver, frames_of, ks_uniform, run_until_link_up,
};

fn the_link(sim: &VirtualDriver, c: usize, kind: LinkKind) -> (u64, u64) {
    let infos = sim.client_ref(c).sched.links();
    let info = infos.iter().find(|l| l.kind == kind).unwrap();
    (info.id.unwrap().0, info.t_up.unwrap())
}

/// S-16: link lifetimes are uniform on [6 h, 24 h].
#[test]
fn link_lifetime_uniform_6h_24h() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 161);
    let now = sim.now();
    for _ in 0..1000 {
        let (rc, _, _, _) = sim.new_queue(a);
        sim.client(a)
            .sched
            .add_recv_queue(now, RelayId(0), rc, 80_000)
            .unwrap();
    }
    sim.run_until(190_000);
    let lives: Vec<u64> = sim
        .client_ref(a)
        .sched
        .links()
        .iter()
        .map(|l| l.die_at.unwrap() - l.t_up.unwrap())
        .collect();
    assert_eq!(lives.len(), 1000);
    assert!(lives.iter().all(|l| (21_600_000..=86_400_000).contains(l)));
    let (dstat, p) = ks_uniform(&lives, 21_600_000, 86_400_000);
    assert!(p >= 0.01, "KS D = {dstat}, p = {p}");
}

/// S-17: at the end of its lifetime a link closes, and a fresh one (new key, new phase) takes over without two `SEND`s
/// within `P_q`.
#[test]
fn lifetime_end_reconnects_fresh() {
    let mut sim = driver();
    let params = Params {
        lifetime_ms: (21_600_000, 21_600_000),
        ..Params::default()
    };
    let a = client_with(&mut sim, Mode::Strict, params.clone(), 171);
    let b = client_with(&mut sim, Mode::Strict, params, 172);
    contact(&mut sim, a, b, 10_000, 80_000);
    sim.run_until(200_000);
    let (slot, t_up) = the_link(&sim, a, LinkKind::Send);
    let end = t_up + 21_600_000;
    sim.run_until(end + 200_000);
    let events = &sim.client_ref(a).events;
    let torn = events
        .iter()
        .find(|(_, e)| matches!(e, LinkEvent::TornDown(id, Reason::Lifetime) if id.0 == slot))
        .expect("lifetime teardown");
    assert_eq!(torn.0, end, "close at t_up + L");
    let old = frames_of(&sim, a, Dir::C2R, slot);
    assert!(
        old.iter().all(|e| e.t_ms < end),
        "no unit at or after the lifetime"
    );
    let connects = &sim.client_ref(a).connects;
    let first_key = connects.iter().find(|(_, id, _)| id.0 == slot).unwrap().2;
    let again = connects
        .iter()
        .find(|(t, id, k)| {
            *t >= end
                && id.0 != slot
                && *k != first_key
                && sim
                    .client_ref(a)
                    .sched
                    .links()
                    .iter()
                    .any(|l| l.id == Some(*id) && l.kind == LinkKind::Send)
        })
        .expect("a new send link with a new key");
    assert!(
        (end..=end + 180_000).contains(&again.0),
        "new phase within 3 min"
    );
    let new_slot = again.1.0;
    let new_sends = frames_of(&sim, a, Dir::C2R, new_slot);
    let last_old = old.last().unwrap().t_ms;
    let first_new = new_sends.first().unwrap().t_ms;
    assert!(
        first_new - last_old >= 10_000,
        "gap {}",
        first_new - last_old
    );
}

/// S-19: during a tick nothing is sealed, signed, encrypted or persisted — the tick writes the prepared 4 352 bytes.
#[test]
fn tick_writes_prebuilt_bytes_only() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 191);
    let b = client(&mut sim, Mode::Strict, 192);
    let c = contact(&mut sim, a, b, 10_000, 10_000);
    {
        use secmp_client_core::scheduler::outbox::{OutMessage, Outbox};
        let conv = sim.client(a).convs.get_mut(c.conv_a).unwrap();
        for n in 0..30_u8 {
            conv.outbox_mut().enqueue(
                OutMessage {
                    msg_id: [n; 16],
                    kind: secmp_proto::wire::cell::AppKind::Text,
                    expire_after: 0,
                    payload: secmp_crypto::Zeroizing::new(vec![n; 40]),
                },
                0,
            );
        }
    }
    sim.run_until(1_300_000);
    let audit = sim.client_ref(a).sched.tick_audit();
    assert!(audit.len() >= 100, "{} ticks audited", audit.len());
    for t in audit {
        assert_eq!(t.delta, [0, 0, 0, 0], "tick at {} did work", t.at);
        assert_eq!(t.bytes, FRAME);
    }
}

/// S-20: the frame of tick k+1 is prepared before tick k+1 — a `SEND` right after tick k, a `FETCH` when response k is
/// committed (or one `FETCH_LEAD` before the tick).
#[test]
fn next_frame_prepared_before_tick() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 201);
    let b = client(&mut sim, Mode::Strict, 202);
    contact(&mut sim, a, b, 10_000, 10_000);
    sim.run_until(1_300_000);
    let log = sim.client_ref(a).sched.prep_log();
    assert!(log.len() > 200);
    for r in log {
        assert!(r.at < r.tick_at, "{r:?} prepared at or after its tick");
        let expected = if r.tick == 1 {
            // prepared when the link came up
            r.at
        } else {
            r.tick_at - 10_000
        };
        assert_eq!(r.at, expected, "{r:?}");
    }
}

/// S-21: the `FETCH` of tick k+1 carries the acknowledgement committed from response k — or, if response k comes after
/// the lead, the one of response k−1; the re-fetched duplicates are dropped by `cell_id`.
#[test]
fn fetch_ack_uses_committed_state() {
    for (latency, lagging) in [(300_u64, false), (9_500, true)] {
        let mut sim = driver();
        let a = client(&mut sim, Mode::Strict, 211);
        let b = client(&mut sim, Mode::Strict, 212);
        let c = contact(&mut sim, a, b, 10_000, 10_000);
        sim.client(a).latency_ms = latency;
        sim.client(a).opts.inspect = Inspect::Requests;
        let (slot, t_up) = run_until_link_up(&mut sim, a, LinkKind::Recv);
        let mut acks_after_response: Vec<u64> = Vec::new();
        for k in 1..=14_u64 {
            sim.run_until(at(t_up, k, 10_000) + latency);
            acks_after_response.push(sim.client_ref(a).sched.acked(c.a_recv).unwrap());
        }
        sim.run_until(at(t_up, 15, 10_000));
        let fetch_acks: Vec<u64> = sim
            .client_ref(a)
            .requests
            .iter()
            .filter(|(_, s, r)| *s == slot && matches!(r.cmd, RequestCmd::Fetch { .. }))
            .map(|(_, _, r)| {
                if let RequestCmd::Fetch { ack, .. } = &r.cmd {
                    *ack
                } else {
                    0
                }
            })
            .collect();
        // fetch_acks[k] is the FETCH of tick k + 1; acks_after_response[k - 1] the state after response k
        for k in 3..14_usize {
            let behind = if lagging { 2 } else { 1 };
            let want = *acks_after_response.get(k - behind).unwrap();
            assert_eq!(
                *fetch_acks.get(k).unwrap(),
                want,
                "latency {latency}, FETCH of tick {}",
                k + 1
            );
        }
        let delivered = &sim.client_ref(a).gate.delivered;
        assert!(
            delivered.values().all(|n| *n == 1),
            "every cell delivered once"
        );
    }
}

/// S-22: a frame that is not ready at its tick is not written late: the tick writes nothing, the link goes down
/// (`Overrun`) and comes back at a random offset.
#[test]
fn prepare_overrun_tears_down() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 221);
    let b = client(&mut sim, Mode::Strict, 222);
    contact(&mut sim, a, b, 10_000, 80_000);
    let (slot, t_up) = run_until_link_up(&mut sim, a, LinkKind::Send);
    let t5 = at(t_up, 5, 10_000);
    sim.run_until(t5 - 1);
    sim.client(a).gate.block_prepare = true;
    sim.run_until(at(t_up, 7, 10_000));
    let sent: Vec<u64> = frames_of(&sim, a, Dir::C2R, slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert_eq!(
        sent.last().copied(),
        Some(t5),
        "tick 5 was prepared, tick 6 was not"
    );
    let t6 = at(t_up, 6, 10_000);
    assert!(!sent.contains(&t6), "no unit at tick 6");
    let torn = sim
        .client_ref(a)
        .events
        .iter()
        .find(|(_, e)| matches!(e, LinkEvent::TornDown(id, Reason::Overrun) if id.0 == slot))
        .expect("overrun");
    assert_eq!(torn.0, t6);
    assert_eq!(sim.client_ref(a).sched.overruns(), 1);
    sim.client(a).gate.block_prepare = false;
    sim.run_until(t6 + 200_000);
    let next = sim
        .client_ref(a)
        .connects
        .iter()
        .find(|(t, id, _)| *t >= t6 && id.0 != slot)
        .expect("reconnect");
    assert!((t6..=t6 + 180_000).contains(&next.0));
}

/// S-23: the in-flight bound — with the relay withholding answers, tick 3 tears the link down before it writes.
#[test]
fn in_flight_bound_two() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 231);
    let b = client(&mut sim, Mode::Strict, 232);
    contact(&mut sim, a, b, 10_000, 80_000);
    sim.client(a).opts.withhold = true;
    let (slot, t_up) = run_until_link_up(&mut sim, a, LinkKind::Send);
    let (t1, t2, t3) = (
        at(t_up, 1, 10_000),
        at(t_up, 2, 10_000),
        at(t_up, 3, 10_000),
    );
    sim.run_until(t1);
    assert_eq!(
        sim.client_ref(a)
            .sched
            .links()
            .iter()
            .find(|l| l.id.map(|i| i.0) == Some(slot))
            .unwrap()
            .in_flight,
        1
    );
    sim.run_until(t2);
    assert_eq!(
        sim.client_ref(a)
            .sched
            .links()
            .iter()
            .find(|l| l.id.map(|i| i.0) == Some(slot))
            .unwrap()
            .in_flight,
        2
    );
    sim.run_until(t3);
    let sent: Vec<u64> = frames_of(&sim, a, Dir::C2R, slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert_eq!(sent, vec![t1, t2], "0 bytes at tick 3");
    let torn = sim
        .client_ref(a)
        .events
        .iter()
        .find(|(_, e)| matches!(e, LinkEvent::TornDown(id, Reason::InFlight) if id.0 == slot))
        .expect("in-flight teardown");
    assert_eq!(torn.0, t3);
    sim.run_until(t3 + 200_000);
    let next = sim
        .client_ref(a)
        .connects
        .iter()
        .find(|(t, id, _)| *t >= t3 && id.0 != slot && *t <= t3 + 180_000);
    assert!(next.is_some(), "reconnect within 3 min");
}

/// S-24: the scheduler reads no UI state — no focus, visibility, window or typing identifier exists in `scheduler/`.
#[test]
fn scheduler_reads_no_ui_state() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../secmp-client-core/src/scheduler");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(files.len() >= 8);
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap().to_lowercase();
        for word in ["focus", "visible", "visibility", "window", "typing"] {
            assert!(!text.contains(word), "{} mentions `{word}`", f.display());
        }
    }
}
