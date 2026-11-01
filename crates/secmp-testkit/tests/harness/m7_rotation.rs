// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 SE-02, SE-03 (spec §10.6 (4), (5); `docs/02` §4.3): the rotation of a contact's recv-queue on the virtual
//! driver, over real stores. The recipient takes a pooled queue and announces it; the sender sends only dummies on the old
//! queue, sends again the real messages of the last `QUEUE_CAPACITY` cells on the new one; the recipient fetches the old
//! queue for `U[1 h, 24 h]` and deletes it only after a `FETCH` that found it empty.

use std::collections::BTreeMap;

use secmp_client_core::api::{ContactId, Event, Request, Response};
use secmp_client_core::scheduler::types::{ControlKind, QueueId};
use secmp_client_core::sessions::rotation::QueueSet;
use secmp_crypto::{Ed25519SigningKey, Zeroizing};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{CONTROL_SLOT_BASE, START_UNIX, VirtualDriver};
use secmp_testkit::ks::two_sample;

use super::m6_common::evidence;
use super::m7_world::{
    cells_on, driver, establish, establish_seeded, hub, restart_party, send_sid,
};

/// Queue a text for contact 1 of client `i`.
fn say(d: &mut VirtualDriver, i: usize, n: u8) -> [u8; 16] {
    let payload = Zeroizing::new(format!("message {n}").into_bytes());
    match hub(d, i)
        .core_mut()
        .handle(Request::Send {
            contact: ContactId(1),
            kind: 1,
            payload,
            expire_after: 0,
        })
        .unwrap()
    {
        Response::Sent(id) => id,
        _ => unreachable!("a Send is answered with Sent"),
    }
}

/// The real and dummy cells client `i` prepared for the queue `queue`.
fn prepared(d: &VirtualDriver, i: usize, queue: u32) -> (u64, u64) {
    d.client_ref(i)
        .gate
        .prepared
        .get(&queue)
        .copied()
        .unwrap_or((0, 0))
}

/// SE-02: the sender has sent 200 cells to the old queue, 12 real ones among the last 128 and 3 before them; the recipient's
/// `RouteUpdate` moves it to the new queue. From then on the old queue carries dummies only; the 12 are sent again on the
/// new queue (not the 3); the receiver delivers each message once.
#[test]
fn sender_resends_last_real_on_new_queue() {
    let mut d = driver();
    let s = establish(&mut d, "se02", 3);
    let (host, guest) = (s.host.idx, s.guest.idx);
    let old_sid = send_sid(&mut d, guest);
    let mut ids = Vec::new();
    // 200 cells on the old queue from here: 3 real early, 12 real among the last 128 at the moment of the switch
    let base = cells_on(&d, guest, old_sid);
    let mut t = d.now();
    let mut said = 0_u8;
    let rotated_at = loop {
        t += 10_000;
        d.run_until(t);
        let n = cells_on(&d, guest, old_sid).saturating_sub(base);
        match n {
            1..=3 if said < 3 => {
                ids.push(say(&mut d, guest, said));
                said += 1;
            }
            120..=131 if said < 15 && usize::from(said) == 3 + (n - 120) => {
                ids.push(say(&mut d, guest, said));
                said += 1;
            }
            _ => {}
        }
        if n >= 200 {
            break t;
        }
    };
    assert_eq!(ids.len(), 15);
    // the recipient rotates onto a pooled queue; its RouteUpdate reaches the sender within a few slots
    let rotated = hub(&mut d, host)
        .core_mut()
        .handle(Request::Rotate {
            contact: ContactId(1),
            relay: 1,
        })
        .unwrap();
    assert!(matches!(rotated, Response::Rotated(true)));
    let mut t = rotated_at;
    let new_sid = loop {
        t += 10_000;
        d.run_until(t);
        let current = send_sid(&mut d, guest);
        if current != old_sid {
            break current;
        }
        assert!(t < rotated_at + 600_000, "the sender never switched");
    };
    // the sender switched at some point in the last step: take stock, then run on
    let old_queue = {
        let hub = hub(&mut d, guest);
        hub.sends_of(ContactId(1)).expect("old send queue").0
    };
    let at_switch = prepared(&d, guest, old_queue.0);
    d.run_until(t + 1_200_000);
    let after = prepared(&d, guest, old_queue.0);
    assert_eq!(
        after.0, at_switch.0,
        "the old queue carried real cells after the switch"
    );
    assert!(after.1 > at_switch.1, "the old queue still carries dummies");
    let new_queue = hub(&mut d, guest).sends_of(ContactId(1)).unwrap().1;
    let (real, _) = prepared(&d, guest, new_queue.0);
    assert_eq!(
        real, 12,
        "the 12 real messages of the last 128 cells go again, not the 3 before them"
    );
    assert!(cells_on(&d, guest, new_sid) > 12);

    // the recipient delivers each message once
    let events = hub(&mut d, host).core_mut().take_events();
    let mut seen: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for e in events {
        if let Event::MessageReceived { msg_id, .. } = e.event {
            *seen.entry(msg_id).or_insert(0) += 1;
        }
    }
    for id in &ids {
        assert_eq!(seen.get(id), Some(&1), "message {id:?}");
    }
    assert_eq!(seen.len(), 15);
    let _ = QueueId(0);
}

/// `contacts.queues` of client `i`, decoded.
fn queue_set_of(d: &mut VirtualDriver, i: usize) -> QueueSet {
    let store = hub(d, i).profile_store();
    let bytes = store.lock().unwrap().contact_queues(1).unwrap().unwrap();
    QueueSet::decode(&bytes).unwrap()
}

/// The queue a rotation retired and what its retirement is measured against.
struct Retired {
    queue: QueueId,
    rid: [u8; 16],
    /// The sender id of the queue (the invitee's route before the switch).
    sid: [u8; 16],
    /// The end of the overlap, in virtual milliseconds.
    deadline_ms: u64,
    /// The time of the rotation.
    t0: u64,
}

/// The inviter rotates at the current time; returns the queue it retired.
fn rotate(d: &mut VirtualDriver, host: usize, guest: usize) -> Retired {
    let sid = send_sid(d, guest);
    let t0 = d.now();
    let started = hub(d, host)
        .core_mut()
        .handle(Request::Rotate {
            contact: ContactId(1),
            relay: 1,
        })
        .unwrap();
    assert!(matches!(started, Response::Rotated(true)));
    // the invitation queue (still in its own overlap), the queue just retired, the current one
    let set = queue_set_of(d, host);
    assert_eq!(set.entries.len(), 3);
    let old = set.entries.get(1).unwrap();
    let base = START_UNIX * 1_000;
    let deadline = old.retire_at_ms.unwrap();
    let from = base.saturating_add(t0);
    assert!(
        (from.saturating_add(3_600_000)..=from.saturating_add(86_401_000)).contains(&deadline),
        "deadline {deadline} for t0 {t0}"
    );
    let key = Ed25519SigningKey::from_seed(old.seed.expose_secret()).unwrap();
    let pk = Ed25519Pk::from_bytes(key.verifying_key().as_bytes()).unwrap();
    Retired {
        queue: QueueId(old.queue),
        rid: secmp_proto::link::ids::rid(&pk).unwrap(),
        sid,
        deadline_ms: deadline.saturating_sub(base),
        t0,
    }
}

/// The `QUEUE_DEL` of `old` ran once, on a control link of its own, never before the end of the overlap, nor before the
/// sender's last cell was fetched and an empty `FETCH` followed, and not later than `U[1 min, 60 min]` after that; the old
/// queue was fetched up to the deletion and not after; it left the queue set. Returns `(t_del, quiet)`.
fn check_deleted(
    d: &mut VirtualDriver,
    (host, guest): (usize, usize),
    old: &Retired,
) -> (u64, u64) {
    assert_eq!(d.client_ref(host).hub_errors, Vec::<String>::new());
    let dels: Vec<u64> = d
        .client_ref(host)
        .controls_done
        .iter()
        .filter(|(_, k)| matches!(k, ControlKind::QueueDel(q) if *q == old.queue))
        .map(|(t, _)| *t)
        .collect();
    assert_eq!(dels.len(), 1, "one QUEUE_DEL: {dels:?}");
    let t_del = *dels.first().unwrap();
    let started: Vec<_> = d
        .client_ref(host)
        .controls_started
        .iter()
        .filter(|(_, _, k)| matches!(k, ControlKind::QueueDel(q) if *q == old.queue))
        .collect();
    assert_eq!(started.len(), 1);
    let op = started.first().unwrap().1;
    assert!(d.client_ref(host).control_requests.iter().any(|(t, o, reqs)| {
        *t == t_del
            && *o == op
            && matches!(reqs.last().map(|r| &r.cmd), Some(RequestCmd::QueueDel { rid, .. }) if *rid == old.rid)
    }));
    let last_send = d
        .client_ref(guest)
        .requests
        .iter()
        .filter(|(_, slot, r)| {
            *slot < CONTROL_SLOT_BASE
                && matches!(&r.cmd, RequestCmd::Send { sid, .. } if *sid == old.sid)
        })
        .map(|(t, _, _)| *t)
        .max()
        .unwrap();
    let quiet = old.deadline_ms.max(last_send.saturating_add(10_000));
    assert!(
        t_del >= quiet.saturating_add(60_000),
        "QUEUE_DEL at {t_del} ms, quiet from {quiet} ms (deadline {}, last cell {last_send})",
        old.deadline_ms
    );
    assert!(
        t_del <= quiet.saturating_add(3_620_000),
        "QUEUE_DEL at {t_del} ms, quiet from {quiet} ms"
    );
    let fetches: Vec<u64> = d
        .client_ref(host)
        .requests
        .iter()
        .filter_map(|(t, slot, r)| match &r.cmd {
            RequestCmd::Fetch { rid, .. } if *rid == old.rid && *slot < CONTROL_SLOT_BASE => {
                Some(*t)
            }
            _ => None,
        })
        .collect();
    assert!(
        fetches.iter().any(|t| *t >= old.deadline_ms),
        "fetched through the overlap"
    );
    assert!(
        fetches.iter().all(|t| *t <= t_del),
        "not fetched after the deletion"
    );
    assert!(
        queue_set_of(d, host)
            .entries
            .iter()
            .all(|e| e.queue != old.queue.0)
    );
    (t_del, quiet)
}

/// The draws that decide how long the run is, chosen short: the inviter's second overlap draw (the queue retired here) is
/// 1.07 h, the invitee's (when it stops sending to the old queue) 1.08 h — both inside `U[1 h, 24 h]`, which is asserted.
const SHORT_DRAWS: Option<(u64, u64)> = Some((176, 234));

/// SE-03: the recipient rotates at `t0`. The old queue is fetched until its `QUEUE_DEL`, which runs on its own one-shot
/// link only after the end of the overlap `U[1 h, 24 h]`, after the sender stopped sending to it (an empty `FETCH`), and
/// `U[1 min, 60 min]` later; afterwards the queue is gone from the set, the scheduler and the relay.
#[test]
fn recipient_retires_old_queue() {
    let mut d = driver();
    let s = establish_seeded(&mut d, "se03", 3, SHORT_DRAWS);
    let old = rotate(&mut d, s.host.idx, s.guest.idx);
    d.run_until(old.t0 + 4 * 3_600_000);
    let (t_del, quiet) = check_deleted(&mut d, (s.host.idx, s.guest.idx), &old);
    evidence(
        "SE-03-queue-del",
        &format!(
            "rotation at {} ms; overlap deadline {} ms (+{} s); QUEUE_DEL at {t_del} ms (+{} s after the quiet point {quiet} ms)",
            old.t0,
            old.deadline_ms,
            (old.deadline_ms - old.t0) / 1000,
            (t_del - quiet) / 1000
        ),
    );
}

/// SE-03 and Q194 (the retirement deadline is stored with the queue and re-armed after a restart): the recipient's process
/// dies in the middle of the overlap and starts again from its store; the old queue is still fetched through the overlap
/// and deleted after it, with the same bounds.
#[test]
fn retirement_survives_restart() {
    let mut d = driver();
    let s = establish_seeded(&mut d, "se03r", 3, SHORT_DRAWS);
    let old = rotate(&mut d, s.host.idx, s.guest.idx);
    d.run_until(old.t0 + 20 * 60_000);
    restart_party(&mut d, &s.host, 1);
    d.run_until(old.t0 + 4 * 3_600_000);
    check_deleted(&mut d, (s.host.idx, s.guest.idx), &old);
}

/// SE-03, the draws (KS, p ≥ 0.01): the overlap `U[1 h, 24 h]` and the `QUEUE_DEL` delay `U[1 min, 60 min]` come from
/// `crate::timing`; 1 000 draws of each are not distinguishable from a reference uniform sample.
#[test]
fn retirement_delays_are_uniform() {
    use secmp_client_core::scheduler::params::Params;
    use secmp_client_core::sessions::rotation::OVERLAP_MS;
    use secmp_client_core::timing::TimingRng;

    // a reference uniform sample from an independent generator (SplitMix64)
    fn reference(seed: u64, lo: u64, hi: u64, n: usize) -> Vec<u64> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = x;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^= z >> 31;
                lo + z % (hi - lo + 1)
            })
            .collect()
    }
    let delay = Params::default().control_delay_ms;
    let mut report = Vec::new();
    for (name, (lo, hi)) in [("overlap", OVERLAP_MS), ("queue_del_delay", delay)] {
        // seeded: a fixed outcome (a test of a random p-value would fail one run in a hundred)
        let mut rng = TimingRng::seeded(0x5e03 + lo);
        let draws: Vec<u64> = (0..1_000).map(|_| rng.uniform(lo, hi).unwrap()).collect();
        assert!(draws.iter().all(|x| (lo..=hi).contains(x)));
        let ks = two_sample(&draws, &reference(0x5eed, lo, hi, 1_000)).unwrap();
        report.push(format!(
            "{name}: D = {:.4}, p = {:.4}, n = 1000",
            ks.d, ks.p
        ));
        assert!(ks.p >= 0.01, "{name}: p = {}", ks.p);
    }
    evidence("SE-03-ks", &report.join("\n"));
}

/// SE-04 on the virtual driver (§10.2): a client in Balanced mode whose recv-queues are at the rate bound — four queues at
/// 10 s, the ones in overlap included — does not start a rotation: `Rotated(false)` and `RotationDeferred`, nothing is
/// asked of the scheduler (no `hub_errors`, which a refused fifth queue would be), and the queues are as they were.
#[test]
fn rotation_deferred_at_the_rate_bound() {
    use secmp_client_core::api::Event;
    use secmp_client_core::scheduler::params::Mode;
    use secmp_proto::wire::Period;

    use super::m7_world::{add_party, add_party_period, invite_pair};

    let mut d = driver();
    let client = add_party_period(&mut d, "se04-x", 6, (Mode::Balanced, 31), Period::S10);
    let first = add_party(&mut d, "se04-p1", 3, 41);
    let second = add_party(&mut d, "se04-p2", 3, 42);
    invite_pair(&mut d, &client, &first);
    invite_pair(&mut d, &client, &second);
    let t = d.now();
    d.run_until(t + 600_000);
    // two contacts, each with its pool queue and the invitation queue in overlap: four recv-queues at 10 s
    let Response::Contacts(list) = hub(&mut d, client.idx)
        .core_mut()
        .handle(Request::Contacts)
        .unwrap()
    else {
        unreachable!("Contacts is answered with Contacts")
    };
    assert_eq!(list.len(), 2);
    let contact = list.first().unwrap().id;
    let before = hub(&mut d, client.idx)
        .profile_store()
        .lock()
        .unwrap()
        .contact_queues(contact.0)
        .unwrap()
        .unwrap()
        .to_vec();
    let answer = hub(&mut d, client.idx)
        .core_mut()
        .handle(Request::Rotate { contact, relay: 1 })
        .unwrap();
    assert!(matches!(answer, Response::Rotated(false)));
    let events: Vec<Event> = hub(&mut d, client.idx)
        .core_mut()
        .take_events()
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(
        events.contains(&Event::RotationDeferred(contact)),
        "{events:?}"
    );
    let t = d.now();
    d.run_until(t + 120_000);
    assert_eq!(d.client_ref(client.idx).hub_errors, Vec::<String>::new());
    let after = hub(&mut d, client.idx)
        .profile_store()
        .lock()
        .unwrap()
        .contact_queues(contact.0)
        .unwrap()
        .unwrap()
        .to_vec();
    assert_eq!(before, after, "the queues are as they were");
}
