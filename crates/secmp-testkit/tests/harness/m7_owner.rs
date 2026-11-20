// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7-S2, review finding L1-2, Q297 (spec §9.4, §9.7 (1), §5.2, §10.6 (2)): the inviter's owner-status query is scheduled
//! and its answer reaches the hub. IN-18 / IN-19 at hub and scheduler level on the virtual driver with real stores: a link
//! data consumed by someone else is seen and reported at `expires`; a link data the relay lost is put again, identically;
//! the schedule of the queries does not depend on the user's calls.

use secmp_client_core::api::{ContactId, Event, InviteReject, Request, Response};
use secmp_client_core::invitations::{OwnerStatus, uri_link_data};
use secmp_client_core::scheduler::control::When;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{ControlKind, RelayId};
use secmp_crypto::Zeroizing;
use secmp_proto::wire::frame::{LinkGetMode, RequestCmd};
use secmp_testkit::harness::{CONTROL_SLOT_BASE, Inspect, LinkMaterial, START_UNIX, VirtualDriver};
use secmp_transport::Error as TransportError;

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

/// Four hours of virtual time, in milliseconds.
const FOUR_HOURS_MS: u64 = 4 * 3_600_000;

/// S2-1, Q298 (§9.7 (1), §11.3): the relay loses its link data, the owner-status answer `{0, 0}` queues the re-put, and the
/// invitation is retired (identity rotation) before the re-put is due: no `LINK_PUT` command leaves, the operation completes
/// after at most one control-link start (a failed one would be retried for ever, CO-06), and the query queued with it ends the chain.
#[test]
fn owner_reput_is_not_sent_for_a_retired_invitation() {
    let mut d = driver();
    let host = add_party(&mut d, "s2d-host", 2, 27);
    d.client(host.idx).opts.inspect = Inspect::Requests;
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    let (_, n) = uri_link_data(&issued.uri).unwrap();
    d.run_until(30_000);
    d.restart_relay();
    let mut elapsed = d.now();
    while !d
        .client_ref(host.idx)
        .link_status
        .iter()
        .any(|row| row.1 == n)
    {
        assert!(elapsed < 3 * MAX_MS, "no owner-status answer");
        elapsed = elapsed.saturating_add(10_000);
        d.run_until(elapsed);
    }
    let answer = d
        .client_ref(host.idx)
        .link_status
        .iter()
        .find(|row| row.1 == n)
        .map(|row| (row.2, row.3));
    assert_eq!(answer, Some((false, false)));
    let puts_before = starts(&d, host.idx, ControlKind::LinkPut(n)).len();
    let queries_before = starts(&d, host.idx, ControlKind::LinkGetOwner(n)).len();
    let commands_before = put_fields(&d, host.idx).len();
    assert_eq!(puts_before, 1, "the re-put is queued, not started");

    // the invitation is retired before the re-put is due
    let rotated = hub(&mut d, host.idx)
        .core_mut()
        .handle(Request::RotateIdentity)
        .unwrap();
    assert!(matches!(rotated, Response::IdentityRotated(_)));
    let now = d.now();
    d.run_until(now.saturating_add(FOUR_HOURS_MS));

    assert_eq!(d.client_ref(host.idx).hub_errors, Vec::<String>::new());
    assert_eq!(put_fields(&d, host.idx).len(), commands_before);
    let puts_after = starts(&d, host.idx, ControlKind::LinkPut(n)).len();
    assert!(
        puts_after.saturating_sub(puts_before) <= 1,
        "{} LinkPut starts after the retirement",
        puts_after.saturating_sub(puts_before)
    );
    // the query queued with the re-put still runs once and ends without a command; its answer never reaches the hub, so the
    // chain does not continue (HB-55)
    let queries_after = starts(&d, host.idx, ControlKind::LinkGetOwner(n)).len();
    assert!(
        queries_after.saturating_sub(queries_before) <= 1,
        "{} owner-status starts after the retirement",
        queries_after.saturating_sub(queries_before)
    );
}

/// S2-1, Q298 (§9.7 (1)): the owner-status answer `{0, 0}` (injected through the hub, as the host's operation delivers it)
/// queues the re-put while the invitee's handshake is on its way; the handshake is accepted before the re-put is due (the
/// row is consumed): no `LINK_PUT` command leaves for this link data after it, the re-put completes after at most one
/// control-link start, and the contact exists on both sides.
#[test]
fn owner_reput_is_not_sent_after_the_handshake() {
    let mut d = driver();
    let host = add_party(&mut d, "s2e-host", 2, 25);
    let guest = add_party(&mut d, "s2e-guest", 2, 26);
    d.client(host.idx).opts.inspect = Inspect::Requests;
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    d.run_until(30_000);
    let (ld, n) = hub(&mut d, guest.idx).begin_accept(&issued.uri).unwrap();
    d.client(guest.idx).links.insert(
        n,
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
    let gone = OwnerStatus {
        present: false,
        consumed: false,
    };
    hub(&mut d, host.idx).owner_status(n, gone).unwrap();
    let puts_before = starts(&d, host.idx, ControlKind::LinkPut(n)).len();
    let commands_before = put_fields(&d, host.idx).len();
    assert_eq!(puts_before, 1);
    let mut elapsed = d.now();
    while contact_ids(&mut d, host.idx).is_empty() {
        assert!(elapsed < 3 * MAX_MS, "the handshake was not accepted");
        elapsed = elapsed.saturating_add(10_000);
        d.run_until(elapsed);
    }
    assert_eq!(
        starts(&d, host.idx, ControlKind::LinkPut(n)).len(),
        puts_before,
        "the handshake is accepted before the re-put is due"
    );
    d.run_until(elapsed.saturating_add(FOUR_HOURS_MS));

    assert_eq!(d.client_ref(host.idx).hub_errors, Vec::<String>::new());
    assert_eq!(put_fields(&d, host.idx).len(), commands_before);
    let puts_after = starts(&d, host.idx, ControlKind::LinkPut(n)).len();
    assert!(
        puts_after.saturating_sub(puts_before) <= 1,
        "{} LinkPut starts after the handshake",
        puts_after.saturating_sub(puts_before)
    );
    assert!(!contact_ids(&mut d, host.idx).is_empty());
    assert!(!contact_ids(&mut d, guest.idx).is_empty());
}

/// Q299 (F1-1; spec §9.4, §9.7 (1)): the relay still holds the link data when an owner-status answer `{0, 0}` (injected
/// through the hub, as the host's operation delivers it; the order of F1-1 (a)/(b)) queues the identical re-put; the relay
/// answers it `ERR_EXISTS`; the re-put completes once and is never retried over 4 h.
#[test]
fn owner_reput_answered_exists_is_not_retried() {
    let mut d = driver();
    let host = add_party(&mut d, "s3a-host", 2, 29);
    d.client(host.idx).opts.inspect = Inspect::Requests;
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    let (_, n) = uri_link_data(&issued.uri).unwrap();
    d.run_until(30_000);
    assert_eq!(
        starts(&d, host.idx, ControlKind::LinkPut(n)).len(),
        1,
        "the prompt put"
    );
    let done = |d: &VirtualDriver| {
        d.client_ref(host.idx)
            .controls_done
            .iter()
            .filter(|(_, k)| *k == ControlKind::LinkPut(n))
            .count()
    };
    assert_eq!(
        done(&d),
        1,
        "the prompt put completed: the relay holds the link data"
    );
    let gone = OwnerStatus {
        present: false,
        consumed: false,
    };
    hub(&mut d, host.idx).owner_status(n, gone).unwrap();
    let answers_before = d
        .client_ref(host.idx)
        .link_status
        .iter()
        .filter(|row| row.1 == n)
        .count();
    let now = d.now();
    d.run_until(now.saturating_add(FOUR_HOURS_MS));

    assert_eq!(d.client_ref(host.idx).hub_errors, Vec::<String>::new());
    assert_eq!(
        starts(&d, host.idx, ControlKind::LinkPut(n)).len(),
        2,
        "one re-put start, not retried"
    );
    assert_eq!(done(&d), 2, "the re-put answered ERR_EXISTS completed");
    let fields = put_fields(&d, host.idx);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields.first(), fields.get(1), "the identical LINK_PUT");
    let answers: Vec<(u64, u32, bool, bool)> = d
        .client_ref(host.idx)
        .link_status
        .iter()
        .filter(|row| row.1 == n)
        .skip(answers_before)
        .copied()
        .collect();
    assert!(
        !answers.is_empty(),
        "no owner-status answer after the injection"
    );
    assert!(
        answers.iter().all(|row| row.2 && !row.3),
        "{answers:?}: the relay still holds the link data"
    );
}

/// The least difference of consecutive times of `times` (`u64::MAX` for fewer than two).
fn min_gap(times: &[u64]) -> u64 {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    sorted
        .windows(2)
        .filter_map(|w| w.get(1).zip(w.first()).map(|(b, a)| b.saturating_sub(*a)))
        .min()
        .unwrap_or(u64::MAX)
}

/// Q300 (V-EXT3-4 new finding; spec §10.6 (2)): a re-put the relay answers `ERR_FULL` is queued again as a delayed
/// operation, so it does not push the start of the waiting owner-status query of the same link data out of reach: the
/// query runs, and no two of the two operations start less than a minute apart.
#[test]
fn answered_reput_does_not_starve_the_owner_query() {
    let mut d = driver();
    let host = add_party(&mut d, "s4b-host", 2, 31);
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    let (_, n) = uri_link_data(&issued.uri).unwrap();
    d.run_until(30_000);
    assert_eq!(starts(&d, host.idx, ControlKind::LinkPut(n)).len(), 1);
    d.client(host.idx).opts.answer_err = Some((ControlKind::LinkPut(n), TransportError::Full));
    let gone = OwnerStatus {
        present: false,
        consumed: false,
    };
    hub(&mut d, host.idx).owner_status(n, gone).unwrap();
    let now = d.now();
    d.run_until(now.saturating_add(FOUR_HOURS_MS));

    assert_eq!(d.client_ref(host.idx).hub_errors, Vec::<String>::new());
    let puts: Vec<u64> = starts(&d, host.idx, ControlKind::LinkPut(n))
        .into_iter()
        .filter(|t| *t >= now)
        .collect();
    assert!(
        (1..=20).contains(&puts.len()),
        "{} re-put starts in 4 h",
        puts.len()
    );
    let first = puts.first().copied().unwrap_or(u64::MAX);
    let queries: Vec<u64> = starts(&d, host.idx, ControlKind::LinkGetOwner(n))
        .into_iter()
        .filter(|t| *t >= now)
        .collect();
    assert!(
        queries.iter().any(|t| *t > first),
        "the owner query never ran after the first re-put: {queries:?}"
    );
    let all: Vec<u64> = puts.iter().chain(queries.iter()).copied().collect();
    let gap = min_gap(&all);
    assert!(gap >= MIN_MS, "min_gap {gap} ms over {} starts", all.len());
}

/// Q300 (Q297 at run time): an owner-status query the relay answers with an `ERR` is queued again; the answer
/// `{0, 1}` (consumed) reaches the hub before it runs again, so the second run ends without a link, and no re-put follows.
#[test]
fn answered_owner_query_ends_once_consumed_seen() {
    let mut d = driver();
    let host = add_party(&mut d, "s4c-host", 2, 33);
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    let (_, n) = uri_link_data(&issued.uri).unwrap();
    d.run_until(30_000);
    d.client(host.idx).opts.answer_err = Some((ControlKind::LinkGetOwner(n), TransportError::Rate));
    let mut elapsed = d.now();
    while starts(&d, host.idx, ControlKind::LinkGetOwner(n)).is_empty() {
        assert!(elapsed < 2 * MAX_MS, "no owner query started");
        elapsed = elapsed.saturating_add(MIN_MS);
        d.run_until(elapsed);
    }
    let before = d.client_ref(host.idx).controls_started.len();
    let rows: Vec<_> = d
        .client_ref(host.idx)
        .link_status
        .iter()
        .filter(|r| r.1 == n)
        .copied()
        .collect();
    let seen = OwnerStatus {
        present: false,
        consumed: true,
    };
    hub(&mut d, host.idx).owner_status(n, seen).unwrap();
    let now = d.now();
    d.run_until(now.saturating_add(FOUR_HOURS_MS));

    let c = d.client_ref(host.idx);
    assert_eq!(c.hub_errors, Vec::<String>::new());
    let later: Vec<_> = c
        .controls_started
        .iter()
        .skip(before)
        .filter(|(_, _, k)| *k == ControlKind::LinkGetOwner(n))
        .collect();
    assert_eq!(later.len(), 1, "{later:?}");
    // the operation keeps its id when it is queued again: only the entries from this run's start count
    let (start, op, _) = **later.first().unwrap();
    assert!(
        !c.trace
            .iter()
            .any(|e| e.slot == CONTROL_SLOT_BASE + op.0 && e.t_ms >= start),
        "the ended query opened no link"
    );
    let done = c
        .controls_done
        .iter()
        .filter(|(t, k)| *k == ControlKind::LinkGetOwner(n) && *t >= now)
        .count();
    assert_eq!(done, 1);
    let rows_after: Vec<_> = c.link_status.iter().filter(|r| r.1 == n).copied().collect();
    assert_eq!(rows_after, rows, "no new owner-status answer");
    let puts = starts(&d, host.idx, ControlKind::LinkPut(n))
        .into_iter()
        .filter(|t| *t >= now)
        .count();
    assert_eq!(puts, 0, "no re-put after the consumption was seen");
}

/// Q300: a consuming `LINK_GET` the relay answers with an `ERR` ends the accept once: one run, the invite fails as
/// invalid, no contact, nothing consumed.
#[test]
fn answered_consume_fails_the_accept_once() {
    let mut d = driver();
    let host = add_party(&mut d, "s4d-host", 2, 35);
    let guest = add_party(&mut d, "s4d-guest", 2, 36);
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 3_600)
        .unwrap();
    d.run_until(30_000);
    let (ld, n) = hub(&mut d, guest.idx).begin_accept(&issued.uri).unwrap();
    d.client(guest.idx).links.insert(
        n,
        LinkMaterial {
            ld_id: ld,
            owner_seed: [0; 32],
            blob: Vec::new(),
            one_time: true,
            expires_bucket: 0,
        },
    );
    d.client(guest.idx).opts.answer_err =
        Some((ControlKind::LinkGetConsume(n), TransportError::Rate));
    let now = d.now();
    d.run_until(now.saturating_add(FOUR_HOURS_MS));

    assert_eq!(d.client_ref(host.idx).hub_errors, Vec::<String>::new());
    assert_eq!(d.client_ref(guest.idx).hub_errors, Vec::<String>::new());
    assert_eq!(
        starts(&d, guest.idx, ControlKind::LinkGetConsume(n)).len(),
        1
    );
    let done = d
        .client_ref(guest.idx)
        .controls_done
        .iter()
        .filter(|(_, k)| *k == ControlKind::LinkGetConsume(n))
        .count();
    assert_eq!(done, 1);
    assert!(d.client_ref(guest.idx).link_consumed.is_empty());
    let events: Vec<Event> = hub(&mut d, guest.idx)
        .core_mut()
        .take_events()
        .into_iter()
        .map(|ev| ev.event)
        .collect();
    let failed = events
        .iter()
        .filter(|ev| matches!(ev, Event::InviteFailed(InviteReject::Invalid)))
        .count();
    assert_eq!(failed, 1, "{events:?}");
    assert!(contact_ids(&mut d, guest.idx).is_empty());
}

/// Q304 (EXT3b-4; V-EXT3b-34 T4-3): the relay answers every `LINK_PUT` of an invitation `ERR_FULL` from the issue on, so every owner-status answer is `{0, 0}`: over 24 h the put stays one operation (one chain), the owner query keeps running, and no two starts of the link data are less than a minute apart.
#[test]
fn absent_answers_keep_one_put_chain() {
    let mut d = driver();
    let host = add_party(&mut d, "s7a-host", 2, 37);
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 6 * 86_400)
        .unwrap();
    let (_, n) = uri_link_data(&issued.uri).unwrap();
    d.client(host.idx).opts.answer_err = Some((ControlKind::LinkPut(n), TransportError::Full));
    let start = d.now();
    d.run_until(start.saturating_add(24 * 3_600_000));
    let c = d.client_ref(host.idx);
    assert_eq!(c.hub_errors, Vec::<String>::new());
    let ops: std::collections::BTreeSet<u64> = c
        .controls_started
        .iter()
        .filter(|(_, _, k)| *k == ControlKind::LinkPut(n))
        .map(|(_, op, _)| op.0)
        .collect();
    assert_eq!(ops.len(), 1, "{} put operations", ops.len());
    let queries = starts(&d, host.idx, ControlKind::LinkGetOwner(n));
    assert!(
        queries.len() >= 16,
        "{} owner-status queries in 24 h",
        queries.len()
    );
    let all: Vec<u64> = starts(&d, host.idx, ControlKind::LinkPut(n))
        .into_iter()
        .chain(queries)
        .collect();
    let gap = min_gap(&all);
    assert!(gap >= MIN_MS, "min_gap {gap} ms over {} starts", all.len());
    let puts = starts(&d, host.idx, ControlKind::LinkPut(n));
    assert!(puts.len() >= 8, "{} put attempts in 24 h", puts.len());
    let last = puts.iter().copied().max().unwrap_or(0);
    assert!(
        last >= start.saturating_add(18 * 3_600_000),
        "the put chain still runs in the last 6 h: last start {last}"
    );
}
