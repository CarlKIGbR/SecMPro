// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7-S2, review finding L1-2, Q297 (spec §9.4, §9.7 (1), §5.2, §10.6 (2)): the inviter's owner-status query is scheduled
//! and its answer reaches the hub. IN-18 / IN-19 at hub and scheduler level on the virtual driver with real stores: a link
//! data consumed by someone else is seen and reported at `expires`; a link data the relay lost is put again, identically;
//! the schedule of the queries does not depend on the user's calls.

use secmp_client_core::api::{ContactId, Event, Request, Response};
use secmp_client_core::invitations::uri_link_data;
use secmp_client_core::scheduler::control::When;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{ControlKind, RelayId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::frame::{LinkGetMode, RequestCmd};
use secmp_testkit::harness::{CONTROL_SLOT_BASE, Inspect, LinkMaterial, START_UNIX, VirtualDriver};

use super::m7_world::{add_party, contact_ids, driver, establish_seeded, hub};

/// The shortest delay of a control operation (§10.6 (2)), in milliseconds.
const MIN_MS: u64 = 60_000;
/// The longest delay of a control operation (§10.6 (2)), in milliseconds.
const MAX_MS: u64 = 3_600_000;
/// One driver step of slack on the longest delay, as `m7_scheduled`.
const SLACK_MS: u64 = 1_000;

/// The fields of a `LINK_PUT` that the owner chooses: `ld_id`, one-time, expiry bucket, owner key, blob part.
type PutFields = ([u8; 16], bool, u32, Vec<u8>, Vec<u8>);
/// The starts of the `LinkPut` / `LinkGetOwner` operations of a link data, and its owner-status answers.
type Chain = (Vec<(u64, ControlKind)>, Vec<(u64, bool, bool)>);

/// The times at which client `i` started a control operation of `kind`.
fn starts(d: &VirtualDriver, i: usize, kind: ControlKind) -> Vec<u64> {
    d.client_ref(i)
        .controls_started
        .iter()
        .filter(|(_, _, k)| *k == kind)
        .map(|(t, _, _)| *t)
        .collect()
}

/// Each time of `times` follows the one before it (the first: `from`) by `U[1 min, 60 min]` (plus a step of slack).
fn assert_delays(from: u64, times: &[u64]) {
    let mut prev = from;
    for t in times {
        let gap = t.saturating_sub(prev);
        assert!(
            (MIN_MS..=MAX_MS.saturating_add(SLACK_MS)).contains(&gap),
            "{gap} ms after the related operation at {prev}"
        );
        prev = *t;
    }
}

/// An idle client at the relay of the world, to consume someone else's link data.
fn thief(d: &mut VirtualDriver) -> usize {
    let i = d.add_client(Mode::Strict, Params::default(), 77);
    d.client(i).relay = RelayId(1);
    i
}

/// `thief` consumes the link data `(ld_id, n)` (a prompt `LINK_GET`, one second of virtual time).
fn steal(d: &mut VirtualDriver, thief: usize, (ld_id, n): ([u8; 16], u32)) {
    let now = d.now();
    let c = d.client(thief);
    c.links.insert(
        n,
        LinkMaterial {
            ld_id,
            owner_seed: [0; 32],
            blob: Vec::new(),
            one_time: true,
            expires_bucket: 0,
        },
    );
    c.sched
        .schedule_control(
            now,
            ControlKind::LinkGetConsume(n),
            RelayId(1),
            u64::from(n),
            When::Prompt,
        )
        .unwrap();
    d.run_until(now.saturating_add(1_000));
}

/// The `LINK_PUT`s client `i` sent, in order.
fn put_fields(d: &VirtualDriver, i: usize) -> Vec<PutFields> {
    d.client_ref(i)
        .control_requests
        .iter()
        .filter_map(|(_, _, rs)| match rs.first().map(|r| &r.cmd) {
            Some(RequestCmd::LinkPut {
                ld_id,
                one_time,
                expires_bucket,
                owner_pk,
                blob_part,
                ..
            }) => Some((
                *ld_id,
                *one_time,
                *expires_bucket,
                owner_pk.as_bytes().to_vec(),
                blob_part.to_vec(),
            )),
            _ => None,
        })
        .collect()
}

/// IN-18 end to end (§5.2, §9.4, §10.6 (2); L1-2): the inviter's owner-status query is scheduled, delayed `U[1 min, 60 min]`
/// from the `LINK_PUT`; another client consumes the link data; the next query sees `{0, 1}` and the chain stops; the
/// invitation is reported as used by someone else, once, at `expires`; no re-put, one command per one-shot link, nothing
/// of it on a slot of the schedule.
#[test]
fn owner_status_detects_foreign_consumption() {
    let mut d = driver();
    let host = add_party(&mut d, "s2a-host", 2, 21);
    let thief = thief(&mut d);
    d.client(host.idx).opts.inspect = Inspect::Requests;
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 3 * 3_600)
        .unwrap();
    let (ld_id, n) = uri_link_data(&issued.uri).unwrap();
    let mut elapsed = 0;
    while d.client_ref(host.idx).link_status.is_empty() {
        assert!(elapsed < 2 * MAX_MS, "no owner-status answer");
        elapsed += 10_000;
        d.run_until(elapsed);
    }
    steal(&mut d, thief, (ld_id, n));
    let last = d.client_ref(thief).link_consumed.last().copied().unwrap();
    assert_eq!((last.2, last.3, last.4), (true, false, true));
    d.run_until(3 * MAX_MS + 120_000);

    let cl = d.client_ref(host.idx);
    assert_eq!(cl.hub_errors, Vec::<String>::new());
    let answers: Vec<(bool, bool)> = cl
        .link_status
        .iter()
        .filter(|row| row.1 == n)
        .map(|row| (row.2, row.3))
        .collect();
    assert_eq!(answers, vec![(true, false), (false, true)]);
    let puts = starts(&d, host.idx, ControlKind::LinkPut(n));
    assert_eq!(puts.len(), 1, "no re-put");
    let queries = starts(&d, host.idx, ControlKind::LinkGetOwner(n));
    assert_eq!(queries.len(), 2);
    assert_delays(*puts.first().unwrap(), &queries);
    let owner_gets: Vec<usize> = cl
        .control_requests
        .iter()
        .filter(|(_, _, rs)| {
            matches!(
                rs.first().map(|r| &r.cmd),
                Some(RequestCmd::LinkGet { ld_id: got_ld, mode: LinkGetMode::OwnerStatus(_) }) if *got_ld == ld_id
            )
        })
        .map(|(_, _, rs)| rs.len())
        .collect();
    assert_eq!(owner_gets, vec![1, 1], "one command per one-shot link");
    assert!(
        !cl.requests.iter().any(|(_, slot, r)| {
            *slot < CONTROL_SLOT_BASE && matches!(r.cmd, RequestCmd::LinkGet { .. })
        }),
        "no LINK_GET on a slot of the schedule"
    );
    let events: Vec<Event> = hub(&mut d, host.idx)
        .core_mut()
        .take_events()
        .into_iter()
        .map(|ev| ev.event)
        .collect();
    let used = events
        .iter()
        .filter(|ev| matches!(ev, Event::InvitationUsedElsewhere))
        .count();
    assert_eq!(used, 1, "{events:?}");
}

/// IN-19 end to end (§9.7 (1); L1-2): the relay loses its state; the next owner-status query answers `{0, 0}`, the
/// identical `LINK_PUT` follows delayed `U[1 min, 60 min]`, exactly one query before it; the invitee then consumes it.
#[test]
fn owner_status_reputs_after_relay_loss() {
    let mut d = driver();
    let host = add_party(&mut d, "s2b-host", 2, 23);
    let guest = add_party(&mut d, "s2b-guest", 2, 24);
    d.client(host.idx).opts.inspect = Inspect::Requests;
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    let (ld_id, n) = uri_link_data(&issued.uri).unwrap();
    d.run_until(30_000);
    assert_eq!(starts(&d, host.idx, ControlKind::LinkPut(n)).len(), 1);
    d.restart_relay();
    let mut elapsed = d.now();
    let bound = elapsed.saturating_add(3 * MAX_MS);
    while starts(&d, host.idx, ControlKind::LinkPut(n)).len() < 2 {
        assert!(elapsed < bound, "no second LINK_PUT");
        elapsed = elapsed.saturating_add(60_000);
        d.run_until(elapsed);
    }

    let cl = d.client_ref(host.idx);
    assert_eq!(cl.hub_errors, Vec::<String>::new());
    let first = cl.link_status.iter().find(|row| row.1 == n).unwrap();
    assert_eq!((first.2, first.3), (false, false));
    let puts = starts(&d, host.idx, ControlKind::LinkPut(n));
    assert_eq!(puts.len(), 2);
    let (p0, p1) = (*puts.first().unwrap(), *puts.get(1).unwrap());
    let before: Vec<u64> = starts(&d, host.idx, ControlKind::LinkGetOwner(n))
        .into_iter()
        .filter(|due| *due < p1)
        .collect();
    assert_eq!(before.len(), 1, "one query before the second put");
    let q1 = *before.first().unwrap();
    assert_delays(p0, &[q1]);
    assert_delays(q1, &[p1]);
    let fields = put_fields(&d, host.idx);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields.first(), fields.get(1), "the identical LINK_PUT");

    let (ld, n_guest) = hub(&mut d, guest.idx).begin_accept(&issued.uri).unwrap();
    assert_eq!((ld, n_guest), (ld_id, n));
    d.client(guest.idx).links.insert(
        n_guest,
        LinkMaterial {
            ld_id: ld,
            owner_seed: [0; 32],
            blob: Vec::new(),
            one_time: true,
            expires_bucket: 0,
        },
    );
    let now = d.now();
    d.run_until(now.saturating_add(1_000));
    let gc = d.client_ref(guest.idx);
    assert_eq!(gc.hub_errors, Vec::<String>::new());
    let last = gc.link_consumed.last().copied().unwrap();
    assert_eq!((last.2, last.3, last.4), (true, false, true));
}

/// One run of the host of an established pair that issues an invitation (§10.1, §10.6 (2); CLAUDE.md §1.4): `active` makes
/// the user's calls (`send`, `contacts list`, `status`) every 5 minutes. The host's `LinkPut` / `LinkGetOwner` starts and the
/// answers of the link data, and the number of calls.
fn owner_chain_run(active: bool) -> (Chain, usize) {
    let mut d = driver();
    let pair = establish_seeded(&mut d, "s2c", 3, Some((61, 62)));
    let host = pair.host.idx;
    let contact = ContactId(*contact_ids(&mut d, host).first().unwrap());
    let issued = hub(&mut d, host).invite(START_UNIX + 3 * 3_600).unwrap();
    let (_, n) = uri_link_data(&issued.uri).unwrap();
    let mut calls: usize = 0;
    let mut at = d.now();
    while at < 3 * MAX_MS {
        at = at.saturating_add(300_000);
        d.run_until(at);
        if active {
            let core = hub(&mut d, host).core_mut();
            let sent = core
                .handle(Request::Send {
                    contact,
                    kind: 1,
                    payload: Zeroizing::new(format!("s2c {at}").into_bytes()),
                    expire_after: 0,
                })
                .unwrap();
            assert!(matches!(sent, Response::Sent(_)));
            assert!(matches!(
                core.handle(Request::Contacts).unwrap(),
                Response::Contacts(_)
            ));
            assert!(matches!(
                core.handle(Request::Settings).unwrap(),
                Response::Settings(_)
            ));
            calls = calls.saturating_add(3);
        }
    }
    let cl = d.client_ref(host);
    assert_eq!(cl.hub_errors, Vec::<String>::new());
    let starts: Vec<(u64, ControlKind)> = cl
        .controls_started
        .iter()
        .filter(|(_, _, kind)| matches!(kind, ControlKind::LinkPut(m) | ControlKind::LinkGetOwner(m) if *m == n))
        .map(|(when, _, kind)| (*when, *kind))
        .collect();
    let answers = cl
        .link_status
        .iter()
        .filter(|pair| pair.1 == n)
        .map(|pair| (pair.0, pair.2, pair.3))
        .collect();
    ((starts, answers), calls)
}

/// CLAUDE.md §1.4, spec §10.1 / §10.6 (2): the schedule of the owner-status queries and the answers are the same whether the
/// user calls `send`, `contacts list` and `status` all the time or not at all.
#[test]
fn owner_status_schedule_is_activity_independent() {
    let (idle, idle_calls) = owner_chain_run(false);
    let (active, active_calls) = owner_chain_run(true);
    assert_eq!(idle_calls, 0);
    assert!(active_calls >= 90, "{active_calls} calls");
    let queries = idle
        .0
        .iter()
        .filter(|(_, k)| matches!(k, ControlKind::LinkGetOwner(_)))
        .count();
    assert!(queries >= 2, "{queries} owner-status queries");
    assert_eq!(idle, active);
}
