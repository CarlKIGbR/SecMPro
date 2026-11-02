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
use secmp_testkit::harness::{CONTROL_SLOT_BASE, VirtualDriver};

use super::m7_world::{driver, establish, hub, restart_party, rid_of};

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
