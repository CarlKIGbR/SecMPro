// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 E2-02v, E2-05 and the virtual wait of E2-03 (Q292): store-backed parties on the `VirtualDriver` in Balanced
//! mode. E2-02v is E2-02 with the PC-05 digest check (every message key of every life distinct); E2-05 is the 24 h offline
//! run (spec §9.5: the relay evicts, the sender sends again; §7.4 note (a): the fast-forward of the receiver); E2-03 waits
//! for the 1–24 h overlap of a rotation and the `QUEUE_DEL` of the old queue (the CLI part is `m7_e2e`).

use std::collections::{BTreeMap, BTreeSet};

use secmp_client_core::api::{ContactId, Event, Request, Response};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{ControlKind, QueueId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{EntropyPool, Inspect, VirtualDriver};

use super::m6_common::evidence;
use super::m7_rotation::{SHORT_DRAWS, check_deleted, rotate, say};
use super::m7_world::{Party, contact_ids, driver, establish_seeded_mode, hub, open_hub};

/// `p`'s process dies and starts again from its profile in Balanced mode (`restart_party` restarts in Strict only).
fn restart(d: &mut VirtualDriver, p: &Party, epoch: u32) {
    d.client(p.idx).hub = None;
    let hub = open_hub(&p.name, &p.dir, &p.clock, epoch);
    d.restart_client(
        p.idx,
        Box::new(hub),
        (
            Mode::Balanced,
            Params::default(),
            900_u64.saturating_add(u64::from(epoch)),
        ),
    );
}

/// Push the `msg_id` of every message client `i` received from contact 1 since the last call, in order.
fn received(d: &mut VirtualDriver, i: usize, out: &mut Vec<[u8; 16]>) {
    for e in hub(d, i).core_mut().take_events() {
        if let Event::MessageReceived {
            contact, msg_id, ..
        } = e.event
            && contact == ContactId(1)
        {
            out.push(msg_id);
        }
    }
}

/// Queue `text` for contact 1 of client `i`.
fn send_text(d: &mut VirtualDriver, i: usize, text: &[u8]) -> [u8; 16] {
    let sent = hub(d, i)
        .core_mut()
        .handle(Request::Send {
            contact: ContactId(1),
            kind: 1,
            payload: Zeroizing::new(text.to_vec()),
            expire_after: 0,
        })
        .unwrap();
    match sent {
        Response::Sent(id) => id,
        _ => unreachable!("a Send is answered with Sent"),
    }
}

/// The text of the received message `msg_id` in the history of client `i`.
fn text_of(d: &mut VirtualDriver, i: usize, msg_id: [u8; 16]) -> Vec<u8> {
    let read = hub(d, i)
        .core_mut()
        .handle(Request::Message {
            contact: ContactId(1),
            msg_id,
        })
        .unwrap();
    match read {
        Response::Message {
            incoming, payload, ..
        } => {
            assert!(incoming, "a received message");
            payload.to_vec()
        }
        _ => unreachable!("a Message is answered with Message"),
    }
}

/// One side of E2-02v.
struct Side<'a> {
    party: &'a Party,
    /// The first letter of its texts.
    tag: char,
    /// The iterations at which its process dies.
    kills: [usize; 2],
    sent: Vec<[u8; 16]>,
    texts: Vec<Vec<u8>>,
    /// What it received, in order.
    got: Vec<[u8; 16]>,
    /// The message-key digests of the lives that ended.
    digests: Vec<[u8; 32]>,
    lives: u32,
}

impl<'a> Side<'a> {
    fn new(party: &'a Party, tag: char, kills: [usize; 2]) -> Self {
        Self {
            party,
            tag,
            kills,
            sent: Vec::new(),
            texts: Vec::new(),
            got: Vec::new(),
            digests: Vec::new(),
            lives: 0,
        }
    }
}

/// The text `i` of side `tag`: `<tag><i>-` padded with `x` to 8–64 bytes.
fn text_for(tag: char, i: usize) -> Vec<u8> {
    let mut t = format!("{tag}{i:03}-").into_bytes();
    let want = 8_usize.saturating_add(i.saturating_mul(7) % 57);
    while t.len() < want {
        t.push(b'x');
    }
    t
}

/// The two kill points of a side from the random bytes `r` at `at`: one in 1…249, one in 250…498.
fn kill_points(r: &[u8], at: usize) -> [usize; 2] {
    let v = |k: usize| usize::from(r.get(k).copied().unwrap_or(0));
    [
        1_usize.saturating_add(v(at) % 249),
        250_usize.saturating_add(v(at.saturating_add(1)) % 249),
    ]
}

/// Collect what both sides received.
fn gather(d: &mut VirtualDriver, sides: &mut [Side<'_>; 2]) {
    for s in sides.iter_mut() {
        received(d, s.party.idx, &mut s.got);
    }
}

/// Side `who` at iteration `i`: dies and starts again if `i` is a kill point, then sends its text `i`.
fn turn(d: &mut VirtualDriver, sides: &mut [Side<'_>; 2], who: usize, i: usize) {
    if sides.get(who).is_some_and(|s| s.kills.contains(&i)) {
        gather(d, sides);
        let s = sides.get_mut(who).unwrap();
        s.digests
            .extend(hub(d, s.party.idx).message_key_digests_kat(1));
        s.lives = s.lives.saturating_add(1);
        restart(d, s.party, s.lives);
    }
    let s = sides.get_mut(who).unwrap();
    let text = text_for(s.tag, i);
    s.sent.push(send_text(d, s.party.idx, &text));
    s.texts.push(text);
}

/// Every message of `from` arrived at `to` exactly once, in order, with its text.
fn check_side(d: &mut VirtualDriver, from: &Side<'_>, to: &Side<'_>) {
    assert!(
        from.sent == to.got,
        "side {}: {} sent, {} received, or out of order",
        from.tag,
        from.sent.len(),
        to.got.len()
    );
    for (n, (id, text)) in from.sent.iter().zip(&from.texts).enumerate() {
        assert!(
            text_of(d, to.party.idx, *id) == *text,
            "side {}: text {n} differs",
            from.tag
        );
    }
}

/// E2-02v [O-17] (TEST-SPEC-M7 E2-02; the PC-05 digest check): 500 single-cell messages each way in Balanced mode, each
/// side's process dies twice (seeded points) and starts again from its store; every message arrives once, in order, with
/// its text, and the message keys of all cells of both sides and all lives are pairwise distinct.
#[test]
fn five_hundred_single_cell_virtual() {
    const N: usize = 500;
    let mut d = driver();
    let world = establish_seeded_mode(&mut d, "e202v", 2, None, Mode::Balanced);
    for p in [&world.host, &world.guest] {
        d.client(p.idx).opts.inspect = Inspect::Off;
        assert_eq!(contact_ids(&mut d, p.idx), vec![1]);
    }
    let draws = EntropyPool::new("m7-e2e-02v", 0).bytes(4);
    let mut sides = [
        Side::new(&world.guest, 'a', kill_points(&draws, 0)),
        Side::new(&world.host, 'b', kill_points(&draws, 2)),
    ];
    for i in 0..N {
        for who in 0..2 {
            turn(&mut d, &mut sides, who, i);
        }
        let t = d.now();
        d.run_until(t.saturating_add(10_000));
        gather(&mut d, &mut sides);
    }
    let last = d.now();
    while sides.iter().any(|s| s.got.len() < N) && d.now() < last.saturating_add(7_200_000) {
        let t = d.now();
        d.run_until(t.saturating_add(60_000));
        gather(&mut d, &mut sides);
    }
    for s in &mut sides {
        s.digests
            .extend(hub(&mut d, s.party.idx).message_key_digests_kat(1));
    }
    let [guest_side, host_side] = &sides;
    check_side(&mut d, guest_side, host_side);
    check_side(&mut d, host_side, guest_side);
    assert!(
        guest_side.lives == 2 && host_side.lives == 2,
        "two restarts per side"
    );
    let all: Vec<[u8; 32]> = guest_side
        .digests
        .iter()
        .chain(&host_side.digests)
        .copied()
        .collect();
    let distinct: BTreeSet<[u8; 32]> = all.iter().copied().collect();
    assert_eq!(distinct.len(), all.len(), "a message key was used twice");
    assert!(all.len() > N.saturating_mul(2), "dummies are sealed too");
    for p in [&world.host, &world.guest] {
        assert_eq!(d.client_ref(p.idx).hub_errors, Vec::<String>::new());
    }
    evidence(
        "E2-02v",
        &format!(
            "{N} messages each way, Balanced; kill points a {:?}, b {:?}; virtual end {} ms; message-key digests {} total, {} distinct",
            guest_side.kills,
            host_side.kills,
            d.now(),
            all.len(),
            distinct.len()
        ),
    );
}

/// E2-05 [O-16, F25] (spec §9.5, §7.4 note (a)): the recipient is offline for 24 h (its links are refused) while the sender
/// sends a message every 10 minutes (144); the relay evicts. When it returns, all 144 real messages arrive exactly once;
/// the longest `KDF_CK` fast-forward of one cell is measured in steps (two HMAC-SHA-256 each), within `MAX_FF`.
#[test]
fn offline_24h_receives_every_real_message() {
    let mut d = driver();
    let world = establish_seeded_mode(&mut d, "e205", 2, None, Mode::Balanced);
    let (guest, host) = (world.guest.idx, world.host.idx);
    for i in [guest, host] {
        d.client(i).opts.inspect = Inspect::Off;
    }
    received(&mut d, host, &mut Vec::new());
    d.client(host).opts.refuse_connections = true;
    restart(&mut d, &world.host, 1);
    let t_off = d.now();
    let mut ids = Vec::new();
    for k in 0..144_u8 {
        ids.push(say(&mut d, guest, k));
        let at = 600_000_u64.saturating_mul(u64::from(k).saturating_add(1));
        d.run_until(t_off.saturating_add(at));
    }
    d.run_until(t_off.saturating_add(86_400_000));
    let evicted = d.client_ref(guest).gate.evicted_count;
    assert!(evicted > 0, "the relay evicted nothing in 24 h");
    assert!(d.client_ref(host).refused > 0, "no link was refused");
    d.client(host).gate.ff_max = 0;
    d.client(host).gate.ff_steps = 0;
    d.client(host).opts.refuse_connections = false;
    restart(&mut d, &world.host, 2);
    let t_back = d.now();
    let mut got = Vec::new();
    while got.len() < ids.len() && d.now() < t_back.saturating_add(10_800_000) {
        let t = d.now();
        d.run_until(t.saturating_add(60_000));
        received(&mut d, host, &mut got);
    }
    let mut seen: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for id in &got {
        *seen.entry(*id).or_insert(0) += 1;
    }
    for (k, id) in ids.iter().enumerate() {
        assert_eq!(seen.get(id), Some(&1), "message {k}");
    }
    assert_eq!(got.len(), ids.len(), "nothing else was delivered");
    let (ff_max, ff_steps) = (
        d.client_ref(host).gate.ff_max,
        d.client_ref(host).gate.ff_steps,
    );
    assert!(
        ff_max > 0 && ff_max <= secmp_proto::tr::MAX_FF,
        "ff_max {ff_max}"
    );
    for i in [guest, host] {
        assert_eq!(d.client_ref(i).hub_errors, Vec::<String>::new());
    }
    evidence(
        "E2-05-offline-24h",
        &format!(
            "evicted ids {evicted}; ff_max {ff_max} KDF_CK steps (the worst cell); ff_steps {ff_steps}; worst cell = {} HMAC-SHA-256 (two per KDF_CK, spec §7.4 note (a)); all {} messages after {} s of virtual time back online",
            u64::from(ff_max).saturating_mul(2),
            ids.len(),
            d.now().saturating_sub(t_back) / 1_000
        ),
    );
}

/// Whether the `QUEUE_DEL` of `queue` ran on client `i`.
fn queue_deleted(d: &VirtualDriver, i: usize, queue: QueueId) -> bool {
    d.client_ref(i)
        .controls_done
        .iter()
        .any(|(_, k)| matches!(k, ControlKind::QueueDel(q) if *q == queue))
}

/// E2-03, the 1–24 h wait (the CLI part is `m7_e2e`): 20 messages in flight when the recipient rotates; the old queue is
/// fetched through the overlap and deleted once, with the bounds of SE-03; every message arrives exactly once.
#[test]
fn rotation_with_overlap_virtual() {
    let mut d = driver();
    let world = establish_seeded_mode(&mut d, "e203v", 3, SHORT_DRAWS, Mode::Balanced);
    let (host, guest) = (world.host.idx, world.guest.idx);
    let mut got = Vec::new();
    received(&mut d, host, &mut got);
    got.clear();
    let ids: Vec<[u8; 16]> = (0..20_u8).map(|n| say(&mut d, guest, n)).collect();
    let old = rotate(&mut d, host, guest);
    let limit = old.t0.saturating_add(25 * 3_600_000);
    loop {
        let t = d.now();
        d.run_until(t.saturating_add(3_600_000));
        received(&mut d, host, &mut got);
        if queue_deleted(&d, host, old.queue) || d.now() >= limit {
            break;
        }
    }
    let (t_del, quiet) = check_deleted(&mut d, (host, guest), &old);
    let dels = d
        .client_ref(host)
        .control_requests
        .iter()
        .flat_map(|(_, _, reqs)| reqs.iter())
        .filter(|r| matches!(&r.cmd, RequestCmd::QueueDel { rid, .. } if *rid == old.rid))
        .count();
    assert_eq!(dels, 1, "one QUEUE_DEL request on the wire");
    let mut seen: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for id in &got {
        *seen.entry(*id).or_insert(0) += 1;
    }
    for (n, id) in ids.iter().enumerate() {
        assert_eq!(seen.get(id), Some(&1), "message {n}");
    }
    evidence(
        "E2-03-virtual",
        &format!(
            "rotation at {} ms; overlap deadline {} ms; QUEUE_DEL at {t_del} ms (quiet point {quiet} ms); 20 messages once each",
            old.t0, old.deadline_ms
        ),
    );
}
