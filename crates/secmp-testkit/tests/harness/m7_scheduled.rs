// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 IN-17 (D-C2-1, Q155): a full invitation through the scheduler — no scripted set-up link. The inviter's
//! `LINK_PUT`, the invitee's `LINK_GET` and the three handshake cells all run as the scheduler's operations on a virtual
//! clock, over a real profile store on each side; OPEN-M7-B-8 re-asserts IN-05 through the scheduler's own
//! acknowledgement.

use secmp_client_core::api::{Event, Request, Response};
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{CONTROL_SLOT_BASE, VirtualDriver};

use super::m6_common::evidence;
use super::m7_world::{driver, hub, start};

/// How many contacts `i` has.
fn contacts(d: &mut VirtualDriver, i: usize) -> usize {
    match hub(d, i).core_mut().handle(Request::Contacts).unwrap() {
        Response::Contacts(c) => c.len(),
        _ => usize::MAX,
    }
}

/// IN-17: the inviter issues an invitation and the invitee accepts it; the three handshake cells go out on scheduled `SEND`
/// slots of the invitation queue, the `LINK_PUT` and the `LINK_GET` on one-shot links, the inviter accepts and replies with a
/// route update; no link of the run is outside the schedule and none overran its tick.
#[test]
fn handshake_as_scheduled_ops() {
    let mut d = driver();
    let s = start(&mut d, "in17", 2);
    d.run_until(900_000);
    let mut lines = Vec::new();
    for p in [&s.host, &s.guest] {
        let c = d.client_ref(p.idx);
        assert_eq!(c.hub_errors, Vec::<String>::new(), "{}", p.name);
        assert_eq!(c.sched.overruns(), 0, "{} overran a tick", p.name);
        // every tick wrote bytes that existed: nothing was sealed or persisted inside a tick (S-19), whole frames only
        let audit = c.sched.tick_audit();
        assert!(!audit.is_empty());
        for t in audit {
            assert_eq!(
                (t.delta[2], t.delta[3]),
                (0, 0),
                "{} tick at {}",
                p.name,
                t.at
            );
            assert_eq!(t.bytes % 4352, 0);
        }
        let mut link_ids: Vec<u64> = audit.iter().map(|t| t.link.0).collect();
        link_ids.sort_unstable();
        link_ids.dedup();
        lines.push(format!(
            "{}: {} links, {} ticks, overruns {}, ticks that sealed or persisted 0",
            p.name,
            link_ids.len(),
            audit.len(),
            c.sched.overruns()
        ));
    }
    evidence("IN-17-tick-audit", &lines.join("\n"));
    // the invitee's first three SENDs to the invitation queue are the persisted handshake cells, byte for byte
    let sends: Vec<&Cell> = d
        .client_ref(s.guest.idx)
        .requests
        .iter()
        .filter_map(|(_, slot, r)| match &r.cmd {
            RequestCmd::Send { sid, cell, .. }
                if *sid == s.inv_sid && *slot < CONTROL_SLOT_BASE =>
            {
                Some(cell)
            }
            _ => None,
        })
        .collect();
    assert!(sends.len() >= 3, "{} sends", sends.len());
    for (sent, want) in sends.iter().zip(&s.handshake) {
        assert_eq!(sent.as_bytes(), want.as_slice());
    }
    // the inviter accepted: one contact; it replied, and the invitee has the reply (a route update)
    assert_eq!(contacts(&mut d, s.host.idx), 1);
    assert_eq!(contacts(&mut d, s.guest.idx), 1);
    let events: Vec<_> = hub(&mut d, s.guest.idx)
        .core_mut()
        .take_events()
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(
        events.iter().any(|e| matches!(e, Event::RoutesChanged(_))),
        "the first reply reached the invitee: {events:?}"
    );
}

/// OPEN-M7-B-8, IN-05 through the scheduler: the acknowledgement the scheduler sends for the invitation queue never covers
/// the last cell of the handshake group before the accept is committed — whenever the scheduler's acknowledgement of the
/// queue reaches cell 3, the inviter's contact is in its store — and it does reach it afterwards (the cells are acknowledged
/// through the scheduler's commit report, not by the structural order of `Round`).
#[test]
fn accept_commits_before_the_real_ack() {
    let mut d = driver();
    let s = start(&mut d, "in05", 2);
    let mut reached = None;
    let mut t = 31_000;
    while t < 600_000 {
        t += 500;
        d.run_until(t);
        let acked = d
            .client_ref(s.host.idx)
            .sched
            .acked(s.inv_queue)
            .unwrap_or(0);
        if acked >= 3 {
            assert_eq!(
                contacts(&mut d, s.host.idx),
                1,
                "the acknowledgement reached the group at {t} ms before the accept was committed"
            );
            reached.get_or_insert(t);
        } else {
            // before the group is complete nothing is accepted
            assert!(acked < 3);
        }
    }
    assert!(reached.is_some(), "the scheduler acknowledged the group");
}
