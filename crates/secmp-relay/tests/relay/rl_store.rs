// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay obligations of the stores (TEST-SPEC-M5 (b5), spec §9.7): restart (RL-01, RL-21), the sweeper on a
//! virtual clock (RL-04 … RL-06, OPEN-M5-05 B), the `LINK_PUT` expiry range (RL-07, ADR-048 (o)), the memory budget
//! (RL-08, OPEN-M5-07 A), buffers that wipe on drop and on every delete path (RL-09, RL-10), hour buckets only
//! (RL-11) and the hasher of the maps (RL-18).
//!
//! The suite's `now` is bucket b = 472 222 (`fixture::NOW`); `at(h, ms)` is bucket b + h.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher as _;

use secmp_crypto::{
    Ed25519SigningKey, HybridKem1024SecretKey, MlKem1024Dk, SecretBytes, X25519Secret,
    ZeroizeOnDrop,
};
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{FETCH_BATCH, FETCH_MULTI_BATCH, QUEUE_CAPACITY};
use secmp_proto::tr::OsEntropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{Request, RequestCmd};
use secmp_relay::budget::{
    BudgetLimits, LINKDATA_BLOB_CHARGE, LINKDATA_OVERHEAD, LINKDATA_RESERVATION, QUEUE_RESERVATION,
};
use secmp_relay::buf::{BlobBuf, CellBuf, cell_copies_wiped_kat, live_buffers_kat};
use secmp_relay::cells::{Cells, Slot};
use secmp_relay::exec::{BlobCopy, CellCopy};
use secmp_relay::keys::{DEFAULT_VALIDITY_SECS, Generation, KeyFile};
use secmp_relay::linkdata::Entry;
use secmp_relay::queue::Queue;
use secmp_relay::relay::kat::StoreSnapshot;
use secmp_relay::{HourBucket, Limits};

use crate::fixture::{Client, EXPIRES, Key, at, now, rid_of, sid_of};
use crate::rl_util::{
    BLOB, CELL, Drive, V, Wire, add, code, distinct_bytes, flags, fresh_dir, identity, key_file,
    linkr, load, one_time, pair, presents, relay_sources, times, unlimited,
};

/// Bucket b of the suite's `now`.
const B: u32 = 472_222;

/// Bucket b + `h`.
fn bucket(h: u32) -> u32 {
    B.checked_add(h).unwrap()
}

/// RL-01 `relay_restart_loses_all_state`: a new relay instance from the same key file starts empty — no queue, no
/// link data, no reservation; FETCH answers `present` 2, SEND ERR 3, owner status {0, 0} (spec §9.7 item 1).
#[test]
fn relay_restart_loses_all_state() {
    let dir = fresh_dir("rl01");
    let path = key_file(&dir, DEFAULT_VALIDITY_SECS);
    let (recv, sender) = pair(1, 2);
    let owner = Key::of(3);
    let (ld_id, blob) = ([0x11; 16], distinct_bytes(1, BLOB));
    let put = one_time(&ld_id, EXPIRES, &owner, &blob);
    let cell = vec![7; CELL];
    let first_fp = {
        let relay = load(&path, Limits::vectors(), now());
        let (fp, access) = identity(&relay);
        let mut w = Wire::connect(&relay, fp, &access, now(), &mut OsEntropy, &mut OsEntropy);
        let qn = w.go(now(), &mut OsEntropy, |c, s| c.queue_new(s, &recv, &sender));
        assert_eq!(
            qn,
            vec![V::QueueNew(rid_of(&recv.pk), sid_of(&recv.pk, &sender.pk))]
        );
        let sent = w.go(now(), &mut OsEntropy, |c, s| {
            c.send(s, &recv, &sender, &cell)
        });
        assert_eq!(sent, vec![V::Send(1, None)]);
        assert_eq!(w.put(now(), &mut OsEntropy, &put), vec![V::Ok]);
        let snap = relay.snapshot_kat();
        assert_eq!(
            (snap.queues.len(), snap.linkdata.len()),
            (1, 1),
            "state before the restart"
        );
        fp
    };
    // the restart: a new process loads the same key file
    let relay = load(&path, Limits::vectors(), now());
    assert_eq!(
        relay.snapshot_kat(),
        StoreSnapshot::default(),
        "RL-01: store empty"
    );
    assert_eq!(relay.budget_used_kat(), (0, 0), "RL-01: no reservation");
    let (fp, access) = identity(&relay);
    assert_eq!(fp, first_fp, "RL-01: the same relay identity");
    let mut w = Wire::connect(&relay, fp, &access, now(), &mut OsEntropy, &mut OsEntropy);
    let fetched = w.go(now(), &mut OsEntropy, |c, s| c.fetch(s, &recv, 0));
    assert_eq!(
        presents(&fetched),
        vec![(2, 0), (0, 0), (0, 0), (0, 0)],
        "RL-01: FETCH present 2"
    );
    assert!(
        matches!(fetched.first(), Some(V::Cellr(2, rid, 0, _)) if *rid == rid_of(&recv.pk)),
        "RL-01: the error frame names the requested rid"
    );
    let sent = w.go(now(), &mut OsEntropy, |c, s| {
        c.send(s, &recv, &sender, &cell)
    });
    assert_eq!(sent, vec![V::Err(3)], "RL-01: SEND ERR 3");
    let status = w.go(now(), &mut OsEntropy, |c, s| {
        c.link_get_owner(s, &ld_id, &owner)
    });
    assert_eq!(
        flags(&status),
        (false, false),
        "RL-01: owner status {{0, 0}}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// RL-21 `relay_restart_identical_link_put_is_accepted`: after a restart the inviter's owner status of L reads
/// {0, 0}; the identical `LINK_PUT` (same `ld_id`, blob, `owner_pk`, `one_time`, `expires_bucket`; a fresh token
/// and signature on a new link) is OK and a consume then returns the blob (spec §9.7 item 1).
#[test]
fn relay_restart_identical_link_put_is_accepted() {
    let dir = fresh_dir("rl21");
    let path = key_file(&dir, DEFAULT_VALIDITY_SECS);
    let owner = Key::of(4);
    let (ld_id, blob) = ([0x21; 16], distinct_bytes(0x21, BLOB));
    let put = one_time(&ld_id, EXPIRES, &owner, &blob);
    let (first_sess, first_put) = {
        let relay = load(&path, Limits::vectors(), now());
        let (fp, access) = identity(&relay);
        let mut w = Wire::connect(&relay, fp, &access, now(), &mut OsEntropy, &mut OsEntropy);
        assert_eq!(
            w.put(now(), &mut OsEntropy, &put),
            vec![V::Ok],
            "RL-21: LINK_PUT L"
        );
        (w.client.sess_id(), w.client.link_put(1, &put))
    };
    let relay = load(&path, Limits::vectors(), now());
    let (fp, access) = identity(&relay);
    let mut w = Wire::connect(&relay, fp, &access, now(), &mut OsEntropy, &mut OsEntropy);
    assert_ne!(w.client.sess_id(), first_sess, "RL-21: a new link");
    let status = w.go(now(), &mut OsEntropy, |c, s| {
        c.link_get_owner(s, &ld_id, &owner)
    });
    assert_eq!(
        flags(&status),
        (false, false),
        "RL-21: owner status {{0, 0}} after the restart"
    );
    let again = w.client.link_put(2, &put);
    let head = |r: &[Request; 3]| match r.first().map(|f| &f.cmd) {
        Some(RequestCmd::LinkPut { token, sig, .. }) => Some((*token, *sig.as_bytes())),
        _ => None,
    };
    assert_ne!(
        head(&again),
        head(&first_put),
        "RL-21: fresh token and signature"
    );
    assert_eq!(
        w.put(now(), &mut OsEntropy, &put),
        vec![V::Ok],
        "RL-21: the identical LINK_PUT"
    );
    let got = w.go(now(), &mut OsEntropy, |_, s| {
        Client::link_get_consume(s, &ld_id)
    });
    assert_eq!(
        linkr(&got),
        (true, false, blob),
        "RL-21: a consume returns the blob"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// RL-04 `relay_sweeper_cell_ttl`: a cell that arrived in bucket b is retained at b + 168 and expired at b + 169
/// (`CELL_TTL` = 168 h; expired iff `now_bucket` > b + T, OPEN-M5-05 B) — by the periodic sweep (`tick`) and by the
/// sweep at the start of a command.
#[test]
fn relay_sweeper_cell_ttl() {
    let mut d = Drive::new(unlimited());
    let (recv, send) = pair(1, 2);
    d.go(at(0, 0), |c, s| c.queue_new(s, &recv, &send));
    let first = d.go(at(0, 0), |c, s| c.send(s, &recv, &send, &[1; CELL]));
    assert_eq!(first, vec![V::Send(1, None)], "cell 1 arrives in bucket b");
    let second = d.go(at(1, 0), |c, s| c.send(s, &recv, &send, &[2; CELL]));
    assert_eq!(
        second,
        vec![V::Send(2, None)],
        "cell 2 arrives in bucket b + 1"
    );
    d.b.relay.tick(at(168, 0));
    assert_eq!(d.cell_ids(), vec![1, 2], "RL-04: b + 168 retained");
    let served = d.go(at(168, 0), |c, s| c.fetch(s, &recv, 0));
    assert_eq!(
        presents(&served),
        vec![(1, 1), (1, 2), (0, 0), (0, 0)],
        "RL-04: b + 168 served"
    );
    // b + 169: the FETCH's own sweep runs before it is executed
    let served = d.go(at(169, 0), |c, s| c.fetch(s, &recv, 0));
    assert_eq!(
        presents(&served),
        vec![(1, 2), (0, 0), (0, 0), (0, 0)],
        "RL-04: b + 169 expired"
    );
    assert_eq!(
        d.cell_ids(),
        vec![2],
        "RL-04: only cell 1 expired at b + 169"
    );
    d.b.relay.tick(at(170, 0));
    assert_eq!(
        d.cell_ids(),
        Vec::<u64>::new(),
        "RL-04: cell 2 expired at (b + 1) + 169"
    );
    let served = d.go(at(170, 0), |c, s| c.fetch(s, &recv, 0));
    assert_eq!(presents(&served), vec![(0, 0); 4], "RL-04: dummies only");
}

/// RL-05 `relay_sweeper_queue_idle_ttl`: a queue without a non-error FETCH since its creation in bucket b is
/// retained at b + 720 and expired at b + 721 (`QUEUE_IDLE_TTL` = 720 h from `last_fetch_bucket`, else
/// `created_bucket`; reading R5-8); a non-error FETCH at b + 700 refreshes it, an error FETCH or a SEND does not.
#[test]
fn relay_sweeper_queue_idle_ttl() {
    let mut d = Drive::new(unlimited());
    let (idle, fetched, failed) = (pair(1, 2), pair(3, 4), pair(5, 6));
    for (r, s) in [&idle, &fetched, &failed] {
        let created = d.go(at(0, 0), |c, n| c.queue_new(n, r, s));
        assert_eq!(
            created,
            vec![V::QueueNew(rid_of(&r.pk), sid_of(&r.pk, &s.pk))]
        );
    }
    let ok = d.go(at(700, 0), |c, n| c.fetch(n, &fetched.0, 0));
    assert_eq!(
        presents(&ok),
        vec![(0, 0); 4],
        "a non-error FETCH at b + 700"
    );
    let bad = d.go(at(700, 0), |c, n| c.fetch(n, &failed.0, 1));
    assert_eq!(
        presents(&bad),
        vec![(4, 0), (0, 0), (0, 0), (0, 0)],
        "an error FETCH at b + 700"
    );
    let sent = d.go(at(710, 0), |c, n| c.send(n, &idle.0, &idle.1, &[9; CELL]));
    assert_eq!(sent, vec![V::Send(1, None)], "a SEND at b + 710");
    let rids = |d: &Drive| -> Vec<Id> {
        let mut v: Vec<Id> =
            d.b.relay
                .snapshot_kat()
                .queues
                .iter()
                .map(|q| q.rid)
                .collect();
        v.sort_unstable();
        v
    };
    let mut all = vec![
        rid_of(&idle.0.pk),
        rid_of(&fetched.0.pk),
        rid_of(&failed.0.pk),
    ];
    all.sort_unstable();
    d.b.relay.tick(at(720, 0));
    assert_eq!(rids(&d), all, "RL-05: b + 720 retained");
    d.b.relay.tick(at(721, 0));
    assert_eq!(
        rids(&d),
        vec![rid_of(&fetched.0.pk)],
        "RL-05: b + 721 expired, the fetched one refreshed"
    );
    assert_eq!(
        d.b.relay.budget_used_kat().0,
        QUEUE_RESERVATION,
        "RL-05: released"
    );
    let sent = d.go(at(721, 0), |c, n| c.send(n, &idle.0, &idle.1, &[9; CELL]));
    assert_eq!(sent, vec![V::Err(3)], "RL-05: the expired queue is gone");
    d.b.relay.tick(at(1420, 0));
    assert_eq!(
        rids(&d),
        vec![rid_of(&fetched.0.pk)],
        "RL-05: refreshed through (b + 700) + 720"
    );
    d.b.relay.tick(at(1421, 0));
    assert_eq!(
        rids(&d),
        Vec::<Id>::new(),
        "RL-05: expired at (b + 700) + 721"
    );
}

/// RL-06 `relay_sweeper_link_data_expiry_and_marker`: an entry and a consumption marker with `expires_bucket` e
/// are present in bucket e and gone ({0, 0}) in e + 1 (valid through `expires_bucket`, OPEN-M5-05 B; the marker
/// expires with the blob, §9.4); a `LINK_PUT` of the same `ld_id`s then is OK.
#[test]
fn relay_sweeper_link_data_expiry_and_marker() {
    let mut d = Drive::new(Limits::vectors());
    let owner = Key::of(7);
    let blob = distinct_bytes(6, BLOB);
    let (kept, consumed) = ([0x61; 16], [0x62; 16]);
    let e = bucket(10);
    assert_eq!(
        d.put(at(0, 0), &one_time(&kept, e, &owner, &blob)),
        vec![V::Ok]
    );
    assert_eq!(
        d.put(at(0, 0), &one_time(&consumed, e, &owner, &blob)),
        vec![V::Ok]
    );
    let got = d.go(at(0, 0), |_, s| Client::link_get_consume(s, &consumed));
    assert_eq!(
        linkr(&got),
        (true, false, blob.clone()),
        "the one-time blob is consumed"
    );
    // bucket e
    let st = d.go(at(10, 0), |c, s| c.link_get_owner(s, &kept, &owner));
    assert_eq!(
        flags(&st),
        (true, false),
        "RL-06: the entry is present in bucket e"
    );
    let st = d.go(at(10, 0), |c, s| c.link_get_owner(s, &consumed, &owner));
    assert_eq!(
        flags(&st),
        (false, true),
        "RL-06: the marker is present in bucket e"
    );
    let put = d.put(at(10, 0), &one_time(&consumed, e, &owner, &blob));
    assert_eq!(
        put,
        vec![V::Err(5)],
        "RL-06: the marker still holds its ld_id in bucket e"
    );
    // bucket e + 1
    let st = d.go(at(11, 0), |c, s| c.link_get_owner(s, &kept, &owner));
    assert_eq!(
        flags(&st),
        (false, false),
        "RL-06: the entry is gone in e + 1"
    );
    let st = d.go(at(11, 0), |c, s| c.link_get_owner(s, &consumed, &owner));
    assert_eq!(
        flags(&st),
        (false, false),
        "RL-06: the marker is gone in e + 1"
    );
    let got = d.go(at(11, 0), |_, s| Client::link_get_consume(s, &kept));
    assert_eq!(
        flags(&got),
        (false, false),
        "RL-06: nothing to consume in e + 1"
    );
    assert!(
        d.b.relay.snapshot_kat().linkdata.is_empty(),
        "RL-06: the store holds no link data"
    );
    assert_eq!(
        d.b.relay.budget_used_kat().1,
        0,
        "RL-06: the reservations are released"
    );
    let later = bucket(11 + 168);
    for ld_id in [&kept, &consumed] {
        let put = d.put(at(11, 0), &one_time(ld_id, later, &owner, &blob));
        assert_eq!(
            put,
            vec![V::Ok],
            "RL-06: LINK_PUT of the same ld_id after the expiry"
        );
    }
}

/// RL-07 `relay_link_put_expires_bucket_range`: `expires_bucket` = `now_bucket` − 1, `now_bucket`, `now_bucket` +
/// 720, `now_bucket` + 721 ⇒ ERR 6, OK, OK, ERR 6, each one frame after frame 3; nothing stored on ERR 6 (ADR-048 (o),
/// both bounds inclusive). The check runs after the token and the signature and before the `ld_id` lookup.
#[test]
fn relay_link_put_expires_bucket_range() {
    let mut d = Drive::new(Limits::vectors());
    let owner = Key::of(8);
    let blob = distinct_bytes(7, BLOB);
    let cases = [
        (B.checked_sub(1).unwrap(), V::Err(6)),
        (B, V::Ok),
        (bucket(720), V::Ok),
        (bucket(721), V::Err(6)),
    ];
    for (i, (expires, want)) in (0x70_u8..).zip(cases) {
        let ld_id = [i; 16];
        let before = d.b.digest();
        let put = d.put(now(), &one_time(&ld_id, expires, &owner, &blob));
        assert_eq!(put, vec![want.clone()], "RL-07: expires_bucket {expires}");
        let stored =
            d.b.relay
                .snapshot_kat()
                .linkdata
                .into_iter()
                .find(|e| e.ld_id == ld_id);
        if want == V::Ok {
            assert_eq!(
                stored.map(|e| e.expires_bucket),
                Some(expires),
                "RL-07: stored"
            );
        } else {
            assert_eq!(
                d.b.digest(),
                before,
                "RL-07: nothing stored on ERR 6 ({expires})"
            );
        }
    }
    range_check_order(&mut d, &owner, &blob);
}

/// ADR-048 (o) / OPEN-M5-04: token, signature, range, then `ld_id`.
fn range_check_order(d: &mut Drive, owner: &Key, blob: &[u8]) {
    let out = bucket(721);
    let fresh = [0x7f; 16];
    let token_flipped = d.put_with(now(), &one_time(&fresh, out, owner, blob), |_, _, one| {
        if let RequestCmd::LinkPut { token, .. } = &mut one.cmd
            && let Some(b) = token.first_mut()
        {
            *b ^= 1;
        }
    });
    assert_eq!(
        token_flipped,
        vec![V::Err(1)],
        "the token is checked before the range"
    );
    let foreign = Key::of(0x99);
    let wrong_signer = d.put_with(now(), &one_time(&fresh, out, owner, blob), |c, s, one| {
        let [other, _, _] = c.link_put(s, &one_time(&fresh, out, &foreign, blob));
        if let (RequestCmd::LinkPut { sig, .. }, RequestCmd::LinkPut { sig: theirs, .. }) =
            (&mut one.cmd, other.cmd)
        {
            *sig = theirs;
        }
    });
    assert_eq!(
        wrong_signer,
        vec![V::Err(4)],
        "the signature is checked before the range"
    );
    let taken = [0x71; 16];
    let existing = d.put(now(), &one_time(&taken, out, owner, blob));
    assert_eq!(
        existing,
        vec![V::Err(6)],
        "the range is checked before the ld_id lookup"
    );
    let existing = d.put(now(), &one_time(&taken, B, owner, blob));
    assert_eq!(
        existing,
        vec![V::Err(5)],
        "an in-range LINK_PUT of a stored ld_id is ERR 5"
    );
}

/// The queue keys of RL-08.
struct Queues {
    q1: (Key, Key),
    q2: (Key, Key),
    q3: (Key, Key),
    q4: (Key, Key),
}

/// RL-08 `relay_memory_budget_accounting`: allocations up to the limit of each pool; ERR 2 exactly when the next
/// reservation would exceed it (store unchanged); `QUEUE_DEL`, a consume and expiry release what was reserved, and a
/// released reservation is reusable; SEND is never ERR 2 (spec §9.7 item 4; OPEN-M5-07 A).
#[test]
fn relay_memory_budget_accounting() {
    let (rq, rl, oh) = (QUEUE_RESERVATION, LINKDATA_RESERVATION, LINKDATA_OVERHEAD);
    // the queue pool falls one byte short of a third queue; the link-data pool holds two entries and a marker
    let limits = Limits {
        budget: BudgetLimits {
            queue_bytes: Some(times(3, rq).checked_sub(1).unwrap()),
            linkdata_bytes: Some(add(times(2, rl), oh)),
        },
        ..Limits::vectors()
    };
    let mut d = Drive::new(limits);
    let k = Queues {
        q1: pair(1, 2),
        q2: pair(3, 4),
        q3: pair(5, 6),
        q4: pair(7, 8),
    };
    for (r, s) in [&k.q1, &k.q2] {
        assert!(
            created(&d.go(now(), |c, n| c.queue_new(n, r, s))),
            "a queue fits"
        );
    }
    assert_eq!(
        d.b.relay.budget_used_kat().0,
        times(2, rq),
        "two queue reservations"
    );
    let before = d.b.digest();
    let third = d.go(now(), |c, n| c.queue_new(n, &k.q3.0, &k.q3.1));
    assert_eq!(
        third,
        vec![V::Err(2)],
        "RL-08: a third queue would exceed the pool by one byte"
    );
    assert_eq!(d.b.digest(), before, "RL-08: store unchanged on ERR 2");
    budget_linkdata(&mut d);
    budget_send_and_release(&mut d, &k);
    budget_expiry(&mut d, &k);
}

/// Whether the answer is one `OK_QUEUE_NEW` frame.
fn created(frames: &[V]) -> bool {
    matches!(frames, [V::QueueNew(..)])
}

const L1: Id = [0x81; 16];
const L2: Id = [0x82; 16];
const L3: Id = [0x83; 16];
const L4: Id = [0x84; 16];

/// RL-08, the link-data pool: two entries fill it but for a marker's overhead; a consume releases the blob part.
fn budget_linkdata(d: &mut Drive) {
    let (rl, oh) = (LINKDATA_RESERVATION, LINKDATA_OVERHEAD);
    let owner = Key::of(9);
    let blob = distinct_bytes(8, BLOB);
    let e = bucket(10);
    for ld_id in [&L1, &L2] {
        assert_eq!(
            d.put(now(), &one_time(ld_id, e, &owner, &blob)),
            vec![V::Ok]
        );
    }
    assert_eq!(
        d.b.relay.budget_used_kat().1,
        times(2, rl),
        "two link-data reservations"
    );
    let before = d.b.digest();
    let third = d.put(now(), &one_time(&L3, e, &owner, &blob));
    assert_eq!(
        third,
        vec![V::Err(2)],
        "RL-08: a third entry would exceed the pool"
    );
    assert_eq!(d.b.digest(), before, "RL-08: store unchanged on ERR 2");
    let got = d.go(now(), |_, s| Client::link_get_consume(s, &L1));
    assert_eq!(flags(&got), (true, false));
    assert_eq!(
        d.b.relay.budget_used_kat().1,
        times(2, rl).checked_sub(LINKDATA_BLOB_CHARGE).unwrap(),
        "RL-08: a consume releases the blob, the marker keeps its overhead"
    );
    let third = d.put(now(), &one_time(&L3, e, &owner, &blob));
    assert_eq!(
        third,
        vec![V::Ok],
        "RL-08: the released bytes are reusable (the pool is now exactly full)"
    );
    assert_eq!(d.b.relay.budget_used_kat().1, add(times(2, rl), oh));
    let fourth = d.put(now(), &one_time(&L4, e, &owner, &blob));
    assert_eq!(fourth, vec![V::Err(2)], "RL-08: nothing fits a full pool");
}

/// RL-08: SEND with both pools full; `QUEUE_DEL` releases a reservation that a new queue reuses.
fn budget_send_and_release(d: &mut Drive, k: &Queues) {
    let rq = QUEUE_RESERVATION;
    let cell = vec![3; CELL];
    for id in 1..=130_u64 {
        let evicted = id.checked_sub(128).filter(|&x| x > 0);
        let sent = d.go(now(), |c, n| c.send(n, &k.q1.0, &k.q1.1, &cell));
        assert_eq!(
            sent,
            vec![V::Send(id, evicted)],
            "RL-08: SEND is never ERR 2 (cell {id})"
        );
    }
    assert_eq!(
        d.b.relay.budget_used_kat().0,
        times(2, rq),
        "RL-08: SEND reserves nothing"
    );
    assert_eq!(d.go(now(), |c, n| c.queue_del(n, &k.q1.0)), vec![V::Ok]);
    assert_eq!(
        d.b.relay.budget_used_kat().0,
        rq,
        "RL-08: QUEUE_DEL releases the reservation"
    );
    let reused = d.go(now(), |c, n| c.queue_new(n, &k.q3.0, &k.q3.1));
    assert!(
        created(&reused),
        "RL-08: the released reservation is reusable"
    );
    let full = d.go(now(), |c, n| c.queue_new(n, &k.q4.0, &k.q4.1));
    assert_eq!(full, vec![V::Err(2)], "RL-08: the pool is full again");
}

/// RL-08: expiry releases both pools.
fn budget_expiry(d: &mut Drive, k: &Queues) {
    let owner = Key::of(9);
    let blob = distinct_bytes(9, BLOB);
    d.b.relay.tick(at(11, 0));
    assert_eq!(
        d.b.relay.budget_used_kat().1,
        0,
        "RL-08: link-data expiry releases entries and markers"
    );
    let again = d.put(at(11, 0), &one_time(&L4, bucket(11 + 168), &owner, &blob));
    assert_eq!(
        again,
        vec![V::Ok],
        "RL-08: the expired reservations are reusable"
    );
    d.b.relay.tick(at(721, 0));
    assert_eq!(
        d.b.relay.budget_used_kat(),
        (0, 0),
        "RL-08: idle and link-data expiry release"
    );
    let fresh = d.go(at(721, 0), |c, n| c.queue_new(n, &k.q4.0, &k.q4.1));
    assert!(created(&fresh), "RL-08: a queue fits after the expiry");
    assert_eq!(d.b.relay.budget_used_kat().0, QUEUE_RESERVATION);
}

fn assert_zod<T: ZeroizeOnDrop>() {}

/// RL-09 `relay_storage_types_zeroize_on_drop`: the stored cell, the stored blob, the dummy buffers and the copies
/// a response is built from, the relay keys with every secret field type, the key file and the access key all
/// wipe their memory on drop (type-level, spec §9.7 item 5; M4 §E (E9)).
#[test]
fn relay_storage_types_zeroize_on_drop() {
    assert_zod::<CellBuf>();
    assert_zod::<BlobBuf>();
    assert_zod::<SecretBytes<4096>>();
    assert_zod::<SecretBytes<12_360>>();
    assert_zod::<CellCopy>();
    assert_zod::<BlobCopy>();
    assert_zod::<RelayKeys>();
    assert_zod::<Ed25519SigningKey>();
    assert_zod::<X25519Secret>();
    assert_zod::<MlKem1024Dk>();
    assert_zod::<HybridKem1024SecretKey>();
    assert_zod::<AccessKey>();
    assert_zod::<KeyFile>();
    assert_zod::<Generation>();
    // the stores keep exactly these buffer types
    let _: fn(&Queue) -> &Cells<CellBuf, QUEUE_CAPACITY> = |q| &q.cells;
    let _: fn(&Entry) -> &Option<BlobBuf> = |e| &e.blob;
    let _: fn(&Slot<CellBuf>) -> &CellBuf = |s| &s.buf;
}

/// The response copies of one `FETCH` / `FETCH_MULTI` (M5 review C-4, R-111): the request built by `build` is run,
/// and every copy of a stored cell its answer was built from is dropped — wiped — by the end of the request, one per
/// cell delivered (`present` 1). Returns the number of cells delivered.
fn copies_wiped_per_fetch(
    d: &mut Drive,
    what: &str,
    build: impl FnOnce(&Client, u32) -> Request,
) -> usize {
    let before = cell_copies_wiped_kat();
    let frames = d.go(now(), build);
    let delivered = presents(&frames).iter().filter(|(p, _)| *p == 1).count();
    assert_eq!(
        cell_copies_wiped_kat().checked_sub(before).unwrap(),
        u64::try_from(delivered).unwrap(),
        "RL-10: {what}: one wiped response copy per cell delivered"
    );
    delivered
}

/// RL-10 `relay_every_delete_path_drops_the_buffer`: ack, eviction, `QUEUE_DEL`, cell TTL, idle TTL, consume and
/// link-data expiry drop each stored buffer at once (the kat live-buffer counter falls by one per buffer); none is
/// left after the store drops (spec §9.7 item 5). The copies a `FETCH` or `FETCH_MULTI` answer is built from are
/// wiped by the end of the request, one per cell delivered (M5 review C-4, R-111; `copies_wiped_per_fetch`).
#[test]
fn relay_every_delete_path_drops_the_buffer() {
    let base = live_buffers_kat();
    {
        let mut d = Drive::new(unlimited());
        let live = || live_buffers_kat().checked_sub(base).unwrap();
        let (r, s) = pair(1, 2);
        let cell = vec![4; CELL];
        d.go(now(), |c, n| c.queue_new(n, &r, &s));
        for _ in 0..3 {
            d.go(now(), |c, n| c.send(n, &r, &s, &cell));
        }
        assert_eq!(live(), 3, "three stored cells");
        let delivered = copies_wiped_per_fetch(&mut d, "FETCH ack 1", |c, n| c.fetch(n, &r, 1));
        assert_eq!(delivered, 2, "cells 2 and 3");
        assert_eq!(live(), 2, "RL-10: ack drops one buffer");
        let delivered = copies_wiped_per_fetch(&mut d, "FETCH ack 3", |c, n| c.fetch(n, &r, 3));
        assert_eq!(delivered, 0, "an empty queue: dummies only");
        assert_eq!(
            live(),
            0,
            "RL-10: a cumulative ack drops one buffer per cell"
        );
        for _ in 0..QUEUE_CAPACITY {
            d.go(now(), |c, n| c.send(n, &r, &s, &cell));
        }
        assert_eq!(live(), 128);
        let sent = d.go(now(), |c, n| c.send(n, &r, &s, &cell));
        assert_eq!(sent, vec![V::Send(132, Some(4))]);
        assert_eq!(live(), 128, "RL-10: eviction drops the evicted buffer");
        let delivered =
            copies_wiped_per_fetch(&mut d, "FETCH of a full queue", |c, n| c.fetch(n, &r, 4));
        assert_eq!(delivered, FETCH_BATCH);
        let delivered = copies_wiped_per_fetch(&mut d, "FETCH_MULTI of a full queue", |c, n| {
            Client::fetch_multi(n, vec![c.fetch_entry(n, &r, 4)])
        });
        assert_eq!(delivered, FETCH_MULTI_BATCH);
        assert_eq!(live(), 128, "an ack of a deleted cell deletes nothing");
        d.go(now(), |c, n| c.queue_del(n, &r));
        assert_eq!(
            live(),
            0,
            "RL-10: QUEUE_DEL drops every buffer of the queue"
        );
        live_linkdata(&mut d, &live);
        live_ttl(&mut d, &live);
        let (r3, s3) = pair(5, 6);
        d.go(at(727, 0), |c, n| c.queue_new(n, &r3, &s3));
        d.go(at(727, 0), |c, n| c.send(n, &r3, &s3, &cell));
        let owner = Key::of(9);
        let blob = distinct_bytes(3, BLOB);
        d.put(at(727, 0), &one_time(&L3, bucket(727 + 10), &owner, &blob));
        assert_eq!(
            live(),
            2,
            "a cell and a blob are stored when the relay drops"
        );
    }
    assert_eq!(
        live_buffers_kat(),
        base,
        "RL-10: none left after the store drops"
    );
}

/// RL-10: consume and link-data expiry.
fn live_linkdata(d: &mut Drive, live: &dyn Fn() -> u64) {
    let owner = Key::of(9);
    let blob = distinct_bytes(2, BLOB);
    d.put(now(), &one_time(&L1, bucket(5), &owner, &blob));
    assert_eq!(live(), 1, "a stored blob");
    d.go(now(), |_, n| Client::link_get_consume(n, &L1));
    assert_eq!(live(), 0, "RL-10: a consume drops the one-time blob");
    d.put(now(), &one_time(&L2, bucket(5), &owner, &blob));
    assert_eq!(live(), 1, "a stored blob");
    d.b.relay.tick(at(6, 0));
    assert_eq!(live(), 0, "RL-10: link-data expiry drops the blob");
}

/// RL-10: cell TTL and idle TTL (a queue created in bucket b + 6).
fn live_ttl(d: &mut Drive, live: &dyn Fn() -> u64) {
    let (r, s) = pair(3, 4);
    let cell = vec![5; CELL];
    d.go(at(6, 0), |c, n| c.queue_new(n, &r, &s));
    d.go(at(6, 0), |c, n| c.send(n, &r, &s, &cell));
    d.go(at(6, 0), |c, n| c.send(n, &r, &s, &cell));
    assert_eq!(live(), 2);
    d.b.relay.tick(at(6 + 169, 0));
    assert_eq!(live(), 0, "RL-10: CELL_TTL drops both buffers");
    d.go(at(700, 0), |c, n| c.send(n, &r, &s, &cell));
    d.go(at(700, 0), |c, n| c.send(n, &r, &s, &cell));
    assert_eq!(live(), 2);
    d.b.relay.tick(at(6 + 721, 0));
    assert_eq!(live(), 0, "RL-10: QUEUE_IDLE_TTL drops the queue's buffers");
}

/// The `u32` of an hour bucket (the pattern is the type-level check: `HourBucket` is a `u32` newtype).
fn hour(b: HourBucket) -> u32 {
    let HourBucket(hours) = b;
    hours
}

/// RL-11 `relay_store_holds_hour_buckets_only`: every time field of the stores is an `HourBucket(u32)` — the
/// structs are destructured field by field, so a new field fails to compile (type-level) — and their values are the
/// buckets of the virtual clock; `SystemTime::now` occurs in `crates/secmp-relay/src` only once, in the bucket
/// function `clock::wall_clock_unix_secs` (spec §9.1; `docs/07:111`; `docs/06` §2).
#[test]
fn relay_store_holds_hour_buckets_only() {
    let mut d = Drive::new(Limits::vectors());
    let (r, s) = pair(1, 2);
    let owner = Key::of(3);
    let blob = distinct_bytes(4, BLOB);
    d.go(at(0, 0), |c, n| c.queue_new(n, &r, &s));
    d.go(at(2, 0), |c, n| c.send(n, &r, &s, &[1; CELL]));
    d.go(at(5, 0), |c, n| c.fetch(n, &r, 0));
    d.put(at(5, 0), &one_time(&L1, EXPIRES, &owner, &blob));
    let seen = d.b.relay.with_state_kat(|st| {
        let mut out = Vec::new();
        for (_, q) in st.queues.iter() {
            let Queue {
                recv_pk: _,
                send_pk: _,
                sid: _,
                cells,
                created,
                last_fetch,
            } = q;
            out.push(("created", hour(*created)));
            out.extend(last_fetch.iter().map(|b| ("last_fetch", hour(*b))));
            for slot in cells.iter() {
                let Slot {
                    cell_id: _,
                    arrival: _,
                    bucket,
                    buf: _,
                } = slot;
                out.push(("cell", hour(*bucket)));
            }
        }
        for (_, e) in st.linkdata.iter() {
            let Entry {
                one_time: _,
                expires,
                owner_pk: _,
                blob: _,
            } = e;
            out.push(("expires", hour(*expires)));
        }
        out
    });
    let want = vec![
        ("created", B),
        ("last_fetch", bucket(5)),
        ("cell", bucket(2)),
        ("expires", EXPIRES),
    ];
    assert_eq!(seen, Some(want), "RL-11: the buckets of the virtual clock");
    assert_eq!(size_of::<HourBucket>(), 4, "RL-11: an hour bucket is a u32");
    assert_eq!(
        system_time_sites(),
        vec![("clock.rs".to_owned(), "fn wall_clock_unix_secs".to_owned())]
    );
}

/// `(file, enclosing fn)` of every `SystemTime` in the code (comments excluded) of `crates/secmp-relay/src`.
fn system_time_sites() -> Vec<(String, String)> {
    let mut sites = Vec::new();
    for file in relay_sources() {
        let text = std::fs::read_to_string(&file).unwrap();
        let mut current_fn = String::new();
        for line in text.lines().map(code) {
            if let Some(at) = line.find("fn ") {
                let name: String = line
                    .get(at..)
                    .unwrap()
                    .chars()
                    .take_while(|c| *c != '(')
                    .collect();
                current_fn = name;
            }
            if line.contains("SystemTime") {
                let name = file.file_name().unwrap().to_string_lossy().into_owned();
                sites.push((name, current_fn.clone()));
            }
        }
    }
    sites
}

fn random_state<T>(_: &HashMap<Id, T, RandomState>) {}

/// RL-18 `relay_hash_maps_use_random_state`: the maps keyed by client-chosen or client-derived ids (`rid`, `sid`,
/// `ld_id`) are `HashMap<Id, _, RandomState>` (type-level), each with its own random keys; no other hash map exists
/// in the relay (`docs/06` §2 `:40`).
#[test]
fn relay_hash_maps_use_random_state() {
    let one = Drive::new(Limits::vectors());
    let two = Drive::new(Limits::vectors());
    let id: Id = [0x5c; 16];
    let hashes = |d: &Drive| {
        d.b.relay
            .with_state_kat(|st| {
                let (queues, sids) = st.queues.maps_kat();
                let linkdata = st.linkdata.map_kat();
                random_state(queues);
                random_state(sids);
                random_state(linkdata);
                [
                    queues.hasher().hash_one(id),
                    sids.hasher().hash_one(id),
                    linkdata.hasher().hash_one(id),
                ]
            })
            .unwrap()
    };
    let (h1, h2) = (hashes(&one), hashes(&two));
    let mut all: Vec<u64> = h1.iter().chain(&h2).copied().collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 6, "RL-18: six maps, six randomly keyed hashers");
    let mut with_maps: Vec<String> = relay_sources()
        .iter()
        .filter(|f| {
            let text = std::fs::read_to_string(f).unwrap();
            text.lines()
                .map(code)
                .any(|l| l.contains("HashMap") || l.contains("HashSet"))
        })
        .map(|f| f.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    with_maps.sort();
    assert_eq!(
        with_maps,
        vec!["linkdata.rs", "queue.rs"],
        "RL-18: the only hash maps are the stores'"
    );
}
