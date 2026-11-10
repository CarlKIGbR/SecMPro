// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 SE-14 (§9.1 `docs/03:589,593`, §10.4 `:683`): the relay restarts and both clients restart from their stores
//! during the gap. The recipient re-creates its queues — the same ones — at `U[10 s, 5 min]`, its acknowledgement and cell
//! dedup start again; the sender, whose sends met `ERR_NOQUEUE`, sends what no receipt covers again; every message is
//! delivered once.

use std::collections::BTreeMap;

use secmp_client_core::api::{ContactId, Event, Request, Response};
use secmp_client_core::scheduler::types::{ControlKind, QueueId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{CONTROL_SLOT_BASE, Inspect, START_UNIX, VirtualDriver};

use super::m7_world::{add_party, driver, establish, hub, restart_party, rid_of};

/// Queue message `n` for contact 1 of client `i`.
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

/// The messages client `i`'s core announced since the last call.
fn received(d: &mut VirtualDriver, i: usize, into: &mut BTreeMap<[u8; 16], usize>) {
    for e in hub(d, i).core_mut().take_events() {
        if let Event::MessageReceived { msg_id, .. } = e.event {
            let n = into.entry(msg_id).or_insert(0_usize);
            *n = n.saturating_add(1);
        }
    }
}

/// `contacts.queues` of contact 1 of client `i`, as stored.
fn queues_of(d: &mut VirtualDriver, i: usize) -> Vec<u8> {
    hub(d, i)
        .profile_store()
        .lock()
        .unwrap()
        .contact_queues(1)
        .unwrap()
        .unwrap()
        .to_vec()
}

/// SE-14: three messages arrive; two more are sent while the recipient's answers are held back, so that they are still in
/// the relay when it restarts; then the relay and both clients restart. The recipient's `QUEUE_NEW` for its queue comes at
/// `U[10 s, 5 min]` after the restart and names the same queue; the sender, whose `SEND` met `ERR_NOQUEUE`, sends again
/// the messages no receipt covers (unverified contact: none); each of the five is delivered once.
#[test]
fn relay_restart_with_store() {
    let mut d = driver();
    let s = establish(&mut d, "se14", 3);
    let (host, guest) = (s.host.idx, s.guest.idx);
    let mut ids = Vec::new();
    let mut seen = BTreeMap::new();
    for n in 0..3 {
        ids.push(say(&mut d, guest, n));
    }
    let t = d.now() + 120_000;
    d.run_until(t);
    received(&mut d, host, &mut seen);
    assert_eq!(seen.len(), 3, "three delivered before the restart");

    // two more are in the relay (the recipient's answers are held back, nothing is acknowledged) when it restarts
    d.client(host).opts.withhold = true;
    for n in 3..5 {
        ids.push(say(&mut d, guest, n));
    }
    let t = d.now() + 60_000;
    d.run_until(t);
    received(&mut d, host, &mut seen);
    assert_eq!(seen.len(), 3);
    let queues_before = queues_of(&mut d, host);

    // the relay loses everything; both clients restart from their stores
    let t_restart = d.now();
    d.restart_relay();
    d.client(host).opts.withhold = false;
    restart_party(&mut d, &s.host, 1);
    restart_party(&mut d, &s.guest, 1);
    d.run_until(t_restart + 30 * 60_000);
    received(&mut d, host, &mut seen);
    assert_eq!(d.client_ref(host).hub_errors, Vec::<String>::new());
    assert_eq!(d.client_ref(guest).hub_errors, Vec::<String>::new());

    // the recipient re-created each queue — the same one — between 10 s and 5 min after the FETCH that found it gone
    let set = secmp_client_core::sessions::rotation::QueueSet::decode(&queues_before).unwrap();
    assert!(
        set.entries.iter().any(|e| e.retire_at_ms.is_some()),
        "an overlap entry before the restart (Q201 half)"
    );
    let mut created = 0;
    for (t, _, kind) in &d.client_ref(host).controls_started {
        let ControlKind::QueueNew(queue) = kind else {
            continue;
        };
        if *t < t_restart {
            continue;
        }
        let entry = set.entries.iter().find(|e| e.queue == queue.0).unwrap();
        assert!(
            entry.retire_at_ms.is_none(),
            "a queue in overlap, whose QUEUE_DEL waits, is not re-created (Q201)"
        );
        let rid = rid_of(entry.seed.expose_secret());
        let found_gone = d
            .client_ref(host)
            .requests
            .iter()
            .filter(|(at, slot, r)| {
                *at > t_restart
                    && *slot < CONTROL_SLOT_BASE
                    && matches!(&r.cmd, RequestCmd::Fetch { rid: fetched, .. } if *fetched == rid)
            })
            .map(|(at, _, _)| *at)
            .min()
            .expect("a FETCH of the queue after the restart");
        assert!(
            (found_gone + 10_000..=found_gone + 300_000 + 1_000).contains(t),
            "QUEUE_NEW {} ms after the FETCH that found the queue gone",
            t - found_gone
        );
        created += 1;
    }
    assert!(created > 0, "the recipient re-created a queue");
    recreated_once(&d, host, &set, t_restart);
    let queues_after = queues_of(&mut d, host);
    // the same current queue, from the store; the queue in overlap was not re-created: its retirement is complete (Q201)
    let mut expected =
        secmp_client_core::sessions::rotation::QueueSet::decode(&queues_before).unwrap();
    expected.entries.retain(|e| e.retire_at_ms.is_none());
    assert_eq!(
        expected.encode().unwrap().as_slice(),
        queues_after.as_slice(),
        "the same queues, from the store"
    );
    overlap_absent(&set, &queues_after);
    // the recipient fetches its queue again with the acknowledgement started over: a FETCH after the re-creation
    let fetched_after = d
        .client_ref(host)
        .requests
        .iter()
        .filter(|(t, slot, r)| {
            *t > t_restart
                && *slot < CONTROL_SLOT_BASE
                && matches!(
                    r.cmd,
                    RequestCmd::Fetch { .. } | RequestCmd::FetchMulti { .. }
                )
        })
        .count();
    assert!(fetched_after > 0);

    // every message exactly once: three before, two after (the three sent again are dedup'd by the history)
    for id in &ids {
        assert_eq!(seen.get(id), Some(&1), "message {id:?}");
    }
    assert_eq!(seen.len(), 5);
}

/// B4b-4: each queue of `before` that was in overlap is absent from the stored `queues_after` (its retirement completed).
fn overlap_absent(before: &secmp_client_core::sessions::rotation::QueueSet, queues_after: &[u8]) {
    let after = secmp_client_core::sessions::rotation::QueueSet::decode(queues_after).unwrap();
    for gone in before.entries.iter().filter(|e| e.retire_at_ms.is_some()) {
        assert!(
            after.entries.iter().all(|e| e.queue != gone.queue),
            "the queue in overlap is absent after the restart (its retirement completed)"
        );
    }
}

/// Q212 (6) (VERIFY-B4 P2 m-3): after the restart at `t_restart` each current queue of `set` is re-created exactly once,
/// and its first `FETCH` acknowledges nothing — the acknowledgement started over.
fn recreated_once(
    d: &VirtualDriver,
    host: usize,
    set: &secmp_client_core::sessions::rotation::QueueSet,
    t_restart: u64,
) {
    for entry in set.entries.iter().filter(|e| e.retire_at_ms.is_none()) {
        let news = d
            .client_ref(host)
            .controls_started
            .iter()
            .filter(|(t, _, k)| {
                *t >= t_restart && *k == ControlKind::QueueNew(QueueId(entry.queue))
            })
            .count();
        assert_eq!(news, 1, "one QUEUE_NEW for queue {}", entry.queue);
        let rid = rid_of(entry.seed.expose_secret());
        let first_ack = d
            .client_ref(host)
            .requests
            .iter()
            .filter(|(at, slot, _)| *at > t_restart && *slot < CONTROL_SLOT_BASE)
            .find_map(|(_, _, r)| match &r.cmd {
                RequestCmd::Fetch {
                    rid: fetched, ack, ..
                } if *fetched == rid => Some(*ack),
                _ => None,
            })
            .expect("a FETCH of the queue after the restart");
        assert_eq!(
            first_ack, 0,
            "the first FETCH after the restart acknowledges nothing"
        );
    }
}

/// Q214 (VERIFY-DELTA-B4b 2, C1-10): a queue whose stored entry has no sender seed is not re-created with a made-up one.
/// The host's current entry is rewritten with `send_seed = None` (a valid encoding), the host restarts from the store and
/// the relay loses its queues: no `QUEUE_NEW` for the queue is sent, the op fails, `hub_errors` names it.
#[test]
fn queue_new_without_sender_seed_fails_closed() {
    let mut d = driver();
    let s = establish(&mut d, "q214", 3);
    let host = s.host.idx;
    let t = d.now() + 60_000;
    d.run_until(t);
    let bytes = queues_of(&mut d, host);
    let mut set = secmp_client_core::sessions::rotation::QueueSet::decode(&bytes).unwrap();
    let entry = set
        .entries
        .iter_mut()
        .find(|e| e.retire_at_ms.is_none())
        .unwrap();
    entry.send_seed = None;
    let queue = QueueId(entry.queue);
    let encoded = set.encode().unwrap();
    hub(&mut d, host)
        .profile_store()
        .lock()
        .unwrap()
        .txn(|tx| secmp_store::contacts::put_contact_queues(tx, 1, encoded.as_slice()))
        .unwrap();

    let t_restart = d.now();
    d.restart_relay();
    restart_party(&mut d, &s.host, 1);
    d.run_until(t_restart + 30 * 60_000);
    let client = d.client_ref(host);
    assert!(
        !client
            .controls_done
            .iter()
            .any(|(_, k)| *k == ControlKind::QueueNew(queue)),
        "no QUEUE_NEW without a sender seed"
    );
    assert!(
        !client
            .control_requests
            .iter()
            .any(|(t, _, rs)| *t >= t_restart
                && rs
                    .iter()
                    .any(|r| matches!(r.cmd, RequestCmd::QueueNew { .. }))),
        "no QUEUE_NEW request"
    );
    let want = format!("QUEUE_NEW {}: no sender seed", queue.0);
    assert!(
        client.hub_errors.contains(&want),
        "hub_errors: {:?}",
        client.hub_errors
    );
}

/// B4b-6 / hub errors: the `QUEUE_DEL` of a retiring invitation queue runs on the relay, but the hub's write of it (the
/// delete of the stub row) is refused — a `TEMP` trigger on the hub's own connection, as `m7_crash.rs`. The failure is
/// not swallowed: it reaches `hub_errors`.
#[test]
fn queue_deleted_failure_reaches_hub_errors() {
    let mut d = driver();
    let p = add_party(&mut d, "qdfault", 2, 7);
    let issued = hub(&mut d, p.idx).invite(START_UNIX + 120).unwrap();
    let queue = hub(&mut d, p.idx)
        .invitation_queue(&issued.invitation.ld_id)
        .unwrap();
    hub(&mut d, p.idx)
        .profile_store()
        .lock()
        .unwrap()
        .connection_kat()
        .execute_batch(
            "CREATE TEMP TRIGGER fault BEFORE DELETE ON invitations \
             BEGIN SELECT RAISE(ABORT, 'fault'); END",
        )
        .unwrap();
    d.run_until(3 * 3_600_000);
    let client = d.client_ref(p.idx);
    assert!(
        client
            .controls_done
            .iter()
            .any(|(_, k)| *k == ControlKind::QueueDel(queue)),
        "the QUEUE_DEL ran on the relay"
    );
    assert!(
        !client.hub_errors.is_empty(),
        "the refused write of queue_deleted is reported"
    );
}

/// Hub errors: `Hub::pump` fails — the guest removes the contact, and the host's store refuses the state change that
/// `Core::pump` writes for the `ContactRemoved` control (`session_event` → `Contacts::on_control` → `UPDATE contacts`, a
/// `TEMP` trigger on the hub's own connection; a trigger on the `INSERT OR IGNORE` of the history would be overridden by
/// the statement's conflict policy) — and `hub_step` reports it in `hub_errors` instead of dropping it.
#[test]
fn hub_step_error_reaches_hub_errors() {
    let mut d = driver();
    let s = establish(&mut d, "sterr", 3);
    let (host, guest) = (s.host.idx, s.guest.idx);
    let t = d.now() + 60_000;
    d.run_until(t);
    assert_eq!(d.client_ref(host).hub_errors, Vec::<String>::new());
    hub(&mut d, host)
        .profile_store()
        .lock()
        .unwrap()
        .connection_kat()
        .execute_batch(
            "CREATE TEMP TRIGGER fault BEFORE UPDATE OF state ON contacts \
             BEGIN SELECT RAISE(ABORT, 'fault'); END",
        )
        .unwrap();
    hub(&mut d, guest)
        .core_mut()
        .handle(Request::Remove {
            contact: ContactId(1),
        })
        .unwrap();
    let t = d.now() + 120_000;
    d.run_until(t);
    assert!(
        !d.client_ref(host).hub_errors.is_empty(),
        "Hub::pump failed on the ContactRemoved control: {:?}",
        d.client_ref(host).hub_errors
    );
}

/// B4b-8: the `QUEUE_DEL` of an expired unused invitation's queue — re-armed after a restart in the Q194 form
/// `AfterEmptyFetch` (Q213) — meets `ERR_NOQUEUE` because the relay lost the queue immediately before the request (no
/// `FETCH` saw it gone, so this is not the `QueueGone` path of D-B32). The retirement is complete all the same: the op is
/// done, the stub row is gone, nothing is re-created, nothing is reported.
#[test]
fn queue_del_on_a_gone_queue_completes() {
    let mut d = driver();
    let p = add_party(&mut d, "qdgone", 2, 11);
    let issued = hub(&mut d, p.idx).invite(START_UNIX + 120).unwrap();
    let queue = hub(&mut d, p.idx)
        .invitation_queue(&issued.invitation.ld_id)
        .unwrap();
    // expired at 120 s and retired by the tick; the op waits for an empty FETCH and then 60 s at least: restart before it
    d.run_until(125_000);
    assert!(
        !d.client_ref(p.idx)
            .controls_done
            .iter()
            .any(|(_, k)| *k == ControlKind::QueueDel(queue)),
        "not deleted before the restart"
    );
    restart_party(&mut d, &p, 1);
    d.client(p.idx).opts.relay_drops_before_queue_del = true;
    d.client(p.idx).opts.inspect = Inspect::Requests;
    let recv = hub(&mut d, p.idx).queue_material(queue).unwrap().0;
    let rid = rid_of(recv.expose_secret());
    let t_restart = d.now();
    d.run_until(t_restart + 2 * 3_600_000);

    let client = d.client_ref(p.idx);
    let started: Vec<u64> = client
        .controls_started
        .iter()
        .filter(|(t, _, k)| *t >= t_restart && *k == ControlKind::QueueDel(queue))
        .map(|(t, _, _)| *t)
        .collect();
    assert_eq!(started.len(), 1, "one QUEUE_DEL after the restart");
    let start = *started.first().expect("one QUEUE_DEL");
    let first_fetch = client
        .requests
        .iter()
        .filter(|(at, slot, r)| {
            *at >= t_restart
                && *slot < CONTROL_SLOT_BASE
                && matches!(&r.cmd, RequestCmd::Fetch { rid: f, .. } if *f == rid)
        })
        .map(|(at, _, _)| *at)
        .min()
        .expect("a FETCH of the queue after the restart");
    assert!(
        start >= first_fetch + 60_000,
        "the QUEUE_DEL starts {} ms after the first empty FETCH",
        start.saturating_sub(first_fetch)
    );
    assert!(
        client
            .controls_done
            .iter()
            .any(|(_, k)| *k == ControlKind::QueueDel(queue)),
        "the QUEUE_DEL completed on ERR_NOQUEUE"
    );
    assert!(
        !client.control_requests.iter().any(|(_, _, rs)| rs
            .iter()
            .any(|r| matches!(r.cmd, RequestCmd::QueueNew { .. }))),
        "nothing is re-created"
    );
    assert_eq!(client.hub_errors, Vec::<String>::new());
    let rows = hub(&mut d, p.idx)
        .profile_store()
        .lock()
        .unwrap()
        .invitations()
        .unwrap()
        .len();
    assert_eq!(rows, 0, "the stub row is gone");
}
