// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M5 (b4) Q-32 … Q-44: `LINK_PUT` and `LINK_GET` (spec §9.2, §9.3, §9.4, §9.7 item 4; D.2, D.6;
//! readings OPEN-9, OPEN-10, OPEN-11, ADR-048 (f), (h), (k), SQ-27, REF-M5 readings 5 and 6). Every answer goes
//! through [`assert_d2_shape`](crate::d2::assert_d2_shape); every error row also checks that the store is
//! unchanged. Q-42 runs four links against one relay from four threads.

use std::sync::Barrier;

use secmp_proto::tr::{FixedEntropy, OsEntropy};
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{Request, RequestCmd};
use secmp_relay::budget::LINKDATA_RESERVATION;
use secmp_relay::relay::kat::LinkDataSnapshot;
use secmp_relay::{Limits, Relay};

use crate::d2::{
    Expect, LinkR, OP_CONT, OP_LINK_GET, OP_SKEY, Peer, Reply, assert_teardown, blob, cmd,
    cmd_with, id16, limits, link_get_owner_req, link_put_req, msg_link_get, msg_link_put,
    relay_side, req_payload, run_consume, run_owner, run_put,
};
use crate::fixture::{
    Bench, Client, EXPIRES, Key, Put, RelayFx, at, flip, hex, lots, now, reference,
};

/// `ld_id`, owner key and blob of `link-0025` (P24).
fn case25() -> (Id, Key, Vec<u8>) {
    let c = reference().case(25);
    (
        c.input("ld_id").try_into().unwrap(),
        Key::from_seed(&c.input("owner_seed")),
        c.input("blob"),
    )
}

/// The link-data entries of the store.
fn entries(b: &Bench) -> Vec<LinkDataSnapshot> {
    b.relay.snapshot_kat().linkdata
}

/// The `LINKR` answer of a reply.
fn linkr(r: &Reply, case: &str) -> LinkR {
    let l = r.linkr();
    assert!(l.is_some(), "{case}: a LINKR answer");
    l.unwrap()
}

/// The entry of `ld_id`: (`one_time`, `present`, `consumed`).
fn entry_of(b: &Bench, ld_id: &Id) -> Option<(bool, bool, bool)> {
    entries(b)
        .into_iter()
        .find(|e| e.ld_id == *ld_id)
        .map(|e| (e.one_time, e.present, e.consumed))
}

/// Q-32 `q_link_put_three_frames_one_response`: `LINK_PUT` (P24) is three frames of 4314, 4106, 4106 B; nothing is
/// emitted after frames 1 and 2, OK after frame 3; the entry is {`one_time` 1, `expires_bucket`, present 1,
/// consumed 0} (D.2).
#[test]
fn q_link_put_three_frames_one_response() {
    let (ld_id, owner, data) = case25();
    let mut b = Bench::vectors();
    let p = Put {
        ld_id: &ld_id,
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let reqs = b.client.link_put(1, &p);
    let sizes: Vec<usize> = reqs.iter().map(|r| req_payload(r).len()).collect();
    assert_eq!(sizes, vec![4314, 4106, 4106], "Q-32: request payload sizes");
    let r = cmd(&mut b, "Q-32 P24", &reqs, Expect::D2);
    assert!(r.is_ok(), "Q-32: OK after frame 3");
    assert_eq!(
        entries(&b),
        vec![LinkDataSnapshot {
            ld_id,
            one_time: true,
            expires_bucket: EXPIRES,
            present: true,
            consumed: false
        }],
        "Q-32: the entry"
    );
}

/// Run a `LINK_PUT`; assert its ERR code after frame 3 and that the store is unchanged.
fn put_error(b: &mut Bench, case: &str, reqs: &[Request; 3], code: u8) {
    let digest = b.digest();
    let r = cmd(b, case, reqs, Expect::D2);
    assert_eq!(r.err(), Some(code), "{case}: ERR {code} after frame 3");
    assert_eq!(
        b.digest(),
        digest,
        "{case}: nothing stored, store unchanged"
    );
}

/// Q-33 `q_link_put_errors_answered_after_third_frame` [O-7]: a flipped token (E17) is ERR 1, a wrong signer (E18)
/// ERR 4, an existing `ld_id` (E2) ERR 5, a full link-data pool (OPEN-M5-07 A) ERR 2 — each one frame after frame 3
/// (D.2; reading OPEN-9). The vector budget never refuses link data.
#[test]
fn q_link_put_errors_answered_after_third_frame() {
    let (owner, data) = (Key::of(1), blob(1));
    let mut b = Bench::vectors();
    let sess = b.client.sess_id();
    let p = Put {
        ld_id: &[1; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let bad: [u8; 32] = flip(&b.client.token(1), 0).try_into().unwrap();
    let sig = owner.sign(&msg_link_put(&sess, 1, &p, &bad));
    put_error(
        &mut b,
        "Q-33 E17 token flip",
        &link_put_req(1, &p, bad, sig),
        1,
    );
    let tok = b.client.token(2);
    let sig = Key::of(0x66).sign(&msg_link_put(&sess, 2, &p, &tok));
    put_error(
        &mut b,
        "Q-33 E18 wrong signer",
        &link_put_req(2, &p, tok, sig),
        4,
    );
    assert!(run_put(&mut b, "Q-33 L", 3, &p).is_ok(), "Q-33: L stored");
    let again = b.client.link_put(4, &p);
    put_error(&mut b, "Q-33 E2 existing ld_id", &again, 5);
    for (q, ld) in (5_u32..).zip([[2_u8; 16], [3; 16], [4; 16]]) {
        let more = Put { ld_id: &ld, ..p };
        let r = run_put(&mut b, "Q-33 vector budget", q, &more);
        assert!(r.is_ok(), "Q-33: the vector budget accepts link data");
    }
    let mut full = Bench::new(limits(None, Some(LINKDATA_RESERVATION)));
    let r = run_put(&mut full, "Q-33 first entry", 1, &p);
    assert!(r.is_ok(), "Q-33: the pool takes one entry");
    let second = Put {
        ld_id: &[2; 16],
        ..p
    };
    let reqs = full.client.link_put(2, &second);
    put_error(&mut full, "Q-33 link-data pool full", &reqs, 2);
}

/// Q-34 `q_link_put_signature_covers_blob_hash`: a byte of `CONT` idx 2 flipped after signing is ERR 4 (D.6: the
/// signature covers SHA-256 of the whole blob).
#[test]
fn q_link_put_signature_covers_blob_hash() {
    let (owner, data) = (Key::of(1), blob(1));
    let mut b = Bench::vectors();
    let p = Put {
        ld_id: &[1; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    for (q, at_byte) in [(1_u32, 0_usize), (2, 4099)] {
        let mut reqs = b.client.link_put(q, &p);
        if let RequestCmd::Cont(c) = &mut reqs.get_mut(2).unwrap().cmd {
            *c.data.get_mut(at_byte).unwrap() ^= 1;
        }
        put_error(
            &mut b,
            &format!("Q-34 CONT 2 byte {at_byte} flipped"),
            &reqs,
            4,
        );
    }
    assert!(entries(&b).is_empty(), "Q-34: nothing stored");
}

/// The `LINK_PUT` of the Q-35 cases: `ld_id` [7; 16], owner `Key::of(7)`, `blob(7)`.
fn put7<'a>(owner: &'a Key, data: &'a [u8]) -> Put<'a> {
    Put {
        ld_id: &[7; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner,
        blob: data,
    }
}

/// A bench with the Q-35 `LINK_PUT` (`cmd_seq` 1) whose first `taken` frames went in (nothing answered); the
/// store digest before it, and the three requests.
fn put_pending(taken: usize) -> (Bench, [u8; 32], [Request; 3]) {
    let mut b = Bench::vectors();
    let digest = b.digest();
    let (owner, data) = (Key::of(7), blob(7));
    let reqs = b.client.link_put(1, &put7(&owner, &data));
    for (i, r) in reqs.iter().take(taken).enumerate() {
        assert!(b.go(r).is_pending(), "LINK_PUT frame {i}: nothing emitted");
    }
    (b, digest, reqs)
}

/// `req` tears the link down: nothing emitted or drawn, the relay side unchanged, nothing stored.
fn torn(b: &mut Bench, digest: [u8; 32], case: &str, req: &Request) {
    let before = relay_side(b);
    let mut entropy = lots();
    let left = entropy.remaining();
    assert!(
        b.run(req, now(), &mut entropy).is_teardown(),
        "{case}: teardown"
    );
    assert_eq!(entropy.remaining(), left, "{case}: nothing drawn");
    assert_eq!(relay_side(b), before, "{case}: relay side unchanged");
    assert_eq!(b.digest(), digest, "{case}: nothing stored");
}

/// A raw `CONT` payload `0x7F ‖ cmd_seq ‖ idx ‖ data` with `len` data bytes.
fn cont_raw(seq: u32, idx: u8, len: usize) -> Vec<u8> {
    let mut p = vec![OP_CONT];
    p.extend(seq.to_be_bytes());
    p.push(idx);
    p.extend(vec![0x33; len]);
    p
}

/// Q-35 `q_link_put_cont_violations_tear_down` [SQ-27]: while a `LINK_PUT` is pending, a `CONT` with another
/// `cmd_seq`, `idx` 2 first, `idx` 1 twice, `idx` 0 or 3, a `PING` or `SKEY` in between, and `CONT` data of 4099 or
/// 4101 B tear the link down (spec §9.2, D.2; ADR-048 (f)); EOF after frame 2 stores nothing; nothing is emitted.
#[test]
fn q_link_put_cont_violations_tear_down() {
    for taken in [1_usize, 2] {
        let (mut b, digest, reqs) = put_pending(taken);
        let req = Request {
            cmd_seq: 2,
            ..reqs.into_iter().nth(taken).unwrap()
        };
        torn(
            &mut b,
            digest,
            &format!("Q-35 CONT {taken} with another cmd_seq"),
            &req,
        );
        let (mut b, digest, _) = put_pending(taken);
        torn(
            &mut b,
            digest,
            &format!("Q-35 PING after frame {taken}"),
            &Client::ping(2),
        );
    }
    let (mut b, digest, reqs) = put_pending(1);
    torn(&mut b, digest, "Q-35 idx 2 first", reqs.get(2).unwrap());
    let (mut b, digest, reqs) = put_pending(2);
    torn(&mut b, digest, "Q-35 idx 1 twice", reqs.get(1).unwrap());
    for (taken, payload, name) in [
        (1, cont_raw(1, 0, 4100), "CONT idx 0"),
        (1, cont_raw(1, 3, 4100), "CONT idx 3"),
        (2, cont_raw(1, 3, 4100), "CONT idx 3 after CONT 1"),
        (1, vec![OP_SKEY, 0, 0, 0, 2], "SKEY after frame 1"),
        (2, vec![OP_SKEY, 0, 0, 0, 2], "SKEY after frame 2"),
        (1, cont_raw(1, 1, 4099), "CONT data 4099 B"),
        (1, cont_raw(1, 1, 4101), "CONT data 4101 B"),
    ] {
        let (mut b, digest, _) = put_pending(taken);
        assert_teardown(&mut b, &format!("Q-35 {name}"), &payload);
        assert_eq!(b.digest(), digest, "Q-35 {name}: nothing stored");
    }
    // EOF after frame 2: the connection ends (client and executor dropped); nothing was stored or emitted, and the
    // complete LINK_PUT of the same ld_id then succeeds on a new link
    let (b, digest, _) = put_pending(2);
    let Bench { relay, fx, .. } = b;
    assert_eq!(relay.store_digest_kat(), digest, "Q-35 EOF: nothing stored");
    let (owner, data) = (Key::of(7), blob(7));
    let mut peer = Peer::new(&relay, &fx, 0x35);
    let r = run_put(
        &mut peer.on(&relay),
        "Q-35 new link",
        1,
        &put7(&owner, &data),
    );
    assert!(r.is_ok(), "Q-35 EOF: the ld_id is free");
}

/// Q-36 `q_link_put_on_consumed_marker_is_exists` [R5-5]: a `LINK_PUT` on the `ld_id` of consumed one-time link data
/// before its expiry is ERR 5 (spec §9.4; ADR-048 (k)).
#[test]
fn q_link_put_on_consumed_marker_is_exists() {
    let (ld_id, owner, data) = case25();
    let mut b = Bench::vectors();
    let p = Put {
        ld_id: &ld_id,
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    assert!(
        run_put(&mut b, "Q-36 LINK_PUT", 1, &p).is_ok(),
        "Q-36: stored"
    );
    let consume = req_payload(&Client::link_get_consume(2, &ld_id));
    let r = cmd_with(
        &mut b,
        "Q-36 consume",
        &[consume],
        Expect::D2,
        at(1, 0),
        &mut lots(),
    );
    assert_eq!(linkr(&r, "Q-36").present, 1, "Q-36: consumed");
    assert_eq!(
        entry_of(&b, &ld_id),
        Some((true, false, true)),
        "Q-36: the marker"
    );
    let digest = b.digest();
    let again: Vec<Vec<u8>> = b.client.link_put(3, &p).iter().map(req_payload).collect();
    let r = cmd_with(
        &mut b,
        "Q-36 LINK_PUT on the marker",
        &again,
        Expect::D2,
        at(2, 0),
        &mut lots(),
    );
    assert_eq!(r.err(), Some(5), "Q-36: ERR 5 before the marker's expiry");
    assert_eq!(b.digest(), digest, "Q-36: store unchanged");
}

/// A bench holding P24's link data (one-time unless `one_time` is false); the next `cmd_seq` is 2.
fn with_link_data(one_time: bool) -> (Bench, Id, Key, Vec<u8>) {
    let (ld_id, owner, data) = case25();
    let mut b = Bench::vectors();
    let p = Put {
        ld_id: &ld_id,
        one_time,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    assert!(
        run_put(&mut b, "setup LINK_PUT", 1, &p).is_ok(),
        "setup: stored"
    );
    (b, ld_id, owner, data)
}

/// Q-37 `q_link_get_consume_one_time_returns_and_deletes`: consume (P26) answers `LINKR` {1, 0} + `CONT` + `CONT`
/// whose parts of 4160, 4100, 4100 B are the stored blob; the entry is then {0, 1} (spec §9.4; reading OPEN-11).
#[test]
fn q_link_get_consume_one_time_returns_and_deletes() {
    let (mut b, ld_id, _, data) = with_link_data(true);
    let r = run_consume(&mut b, "Q-37 P26", 2, &ld_id);
    let sizes: Vec<usize> = r.raw.iter().map(Vec::len).collect();
    assert_eq!(sizes, vec![4167, 4106, 4106], "Q-37: LINKR + CONT + CONT");
    let parts = [
        r.raw.first().and_then(|p| p.get(7..)),
        r.raw.get(1).and_then(|p| p.get(6..)),
        r.raw.get(2).and_then(|p| p.get(6..)),
    ];
    let lens: Vec<Option<usize>> = parts.iter().map(|p| p.map(<[u8]>::len)).collect();
    assert_eq!(
        lens,
        vec![Some(4160), Some(4100), Some(4100)],
        "Q-37: parts 4160/4100/4100"
    );
    let l = linkr(&r, "Q-37");
    assert_eq!((l.present, l.consumed), (1, 0), "Q-37: LINKR {{1, 0}}");
    assert_eq!(l.blob, data, "Q-37: the parts are the stored blob");
    assert_eq!(
        entry_of(&b, &ld_id),
        Some((true, false, true)),
        "Q-37: entry {{0, 1}}"
    );
}

/// Q-38 `q_link_get_consume_again_is_0_1`: a second consume (E19) answers `LINKR` {0, 1} with a dummy blob: the
/// 12360 bytes drawn (spec §9.4; reading OPEN-11).
#[test]
fn q_link_get_consume_again_is_0_1() {
    let (mut b, ld_id, _, data) = with_link_data(true);
    run_consume(&mut b, "Q-38 first consume", 2, &ld_id);
    let draws = blob(0x99);
    let mut entropy = FixedEntropy::new(&draws);
    let digest = b.digest();
    let payload = req_payload(&Client::link_get_consume(3, &ld_id));
    let r = cmd_with(
        &mut b,
        "Q-38 E19",
        &[payload],
        Expect::D2,
        now(),
        &mut entropy,
    );
    let l = linkr(&r, "Q-38");
    assert_eq!((l.present, l.consumed), (0, 1), "Q-38: LINKR {{0, 1}}");
    assert_eq!(l.blob, draws, "Q-38: a dummy blob of 12360 drawn bytes");
    assert_ne!(l.blob, data, "Q-38: not the stored blob");
    assert_eq!(entropy.remaining(), 0, "Q-38: 12360 bytes drawn");
    assert_eq!(b.digest(), digest, "Q-38: store unchanged");
}

/// Q-39 `q_link_get_unknown_is_0_0_with_fresh_dummy`: consume of an `ld_id` never stored (E20), twice, answers
/// {0, 0}; the 12360-B dummy blobs (OS randomness) differ between the calls (spec §9.3; reading OPEN-11).
#[test]
fn q_link_get_unknown_is_0_0_with_fresh_dummy() {
    let (mut b, _, _, _) = with_link_data(true);
    let digest = b.digest();
    let mut blobs = Vec::new();
    for q in [2, 3] {
        let payload = req_payload(&Client::link_get_consume(q, &[0x39; 16]));
        let r = cmd_with(
            &mut b,
            "Q-39 E20",
            &[payload],
            Expect::D2,
            now(),
            &mut OsEntropy,
        );
        let l = linkr(&r, "Q-39");
        assert_eq!((l.present, l.consumed), (0, 0), "Q-39: LINKR {{0, 0}}");
        assert_eq!(l.blob.len(), 12_360, "Q-39: a 12360-B dummy blob");
        blobs.push(l.blob);
    }
    assert_ne!(blobs.first(), blobs.get(1), "Q-39: fresh dummies differ");
    assert_eq!(b.digest(), digest, "Q-39: store unchanged");
}

/// Q-40 `q_link_get_owner_status_does_not_consume`: owner status (P25) {1, 0}; consume {1, 0} with the blob; owner
/// status (P27) {0, 1}; only the consume changes the entry (spec §9.4; ADR-048 (k)).
#[test]
fn q_link_get_owner_status_does_not_consume() {
    let (mut b, ld_id, owner, data) = with_link_data(true);
    let digest = b.digest();
    let l = linkr(
        &run_owner(&mut b, "Q-40 P25", 2, &ld_id, &owner),
        "Q-40 P25",
    );
    assert_eq!((l.present, l.consumed), (1, 0), "Q-40 P25: {{1, 0}}");
    assert_ne!(l.blob, data, "Q-40 P25: a dummy blob");
    assert_eq!(
        b.digest(),
        digest,
        "Q-40 P25: owner status consumes nothing"
    );
    let l = linkr(
        &run_consume(&mut b, "Q-40 consume", 3, &ld_id),
        "Q-40 consume",
    );
    assert_eq!(
        (l.present, l.consumed, &l.blob),
        (1, 0, &data),
        "Q-40: the consume returns the blob"
    );
    assert_eq!(
        entry_of(&b, &ld_id),
        Some((true, false, true)),
        "Q-40: consumed by the consume"
    );
    let digest = b.digest();
    let l = linkr(
        &run_owner(&mut b, "Q-40 P27", 4, &ld_id, &owner),
        "Q-40 P27",
    );
    assert_eq!((l.present, l.consumed), (0, 1), "Q-40 P27: {{0, 1}}");
    assert_eq!(b.digest(), digest, "Q-40 P27: store unchanged");
}

/// Q-41 `q_link_get_owner_status_bad_signature_is_0_0`: owner status signed by a wrong signer (E22), for an unknown
/// `ld_id`, or over another `cmd_seq` answers `LINKR` {0, 0} with a dummy blob, then two `CONT` (reading OPEN-10).
#[test]
fn q_link_get_owner_status_bad_signature_is_0_0() {
    let (mut b, ld_id, owner, data) = with_link_data(true);
    let sess = b.client.sess_id();
    let unknown: Id = [0x41; 16];
    let cases = [
        (
            "E22 wrong signer",
            2,
            ld_id,
            Key::of(0x66).sign(&msg_link_get(&sess, 2, &ld_id)),
        ),
        (
            "unknown ld_id",
            3,
            unknown,
            owner.sign(&msg_link_get(&sess, 3, &unknown)),
        ),
        (
            "over another cmd_seq",
            4,
            ld_id,
            owner.sign(&msg_link_get(&sess, 5, &ld_id)),
        ),
    ];
    for (name, q, ld, sig) in cases {
        let digest = b.digest();
        let r = cmd(
            &mut b,
            &format!("Q-41 {name}"),
            &[link_get_owner_req(q, ld, sig)],
            Expect::D2,
        );
        let l = linkr(&r, name);
        assert_eq!(
            (l.present, l.consumed),
            (0, 0),
            "Q-41 {name}: LINKR {{0, 0}}"
        );
        assert_ne!(l.blob, data, "Q-41 {name}: a dummy blob");
        assert_eq!(b.digest(), digest, "Q-41 {name}: store unchanged");
    }
}

/// The consumers consume `ld_id` at once, each from its own thread (the relay is shared, `Sync`).
fn race(relay: &Relay, consumers: &mut [Peer], seq: u32, ld_id: &Id) -> Vec<LinkR> {
    let barrier = Barrier::new(consumers.len());
    std::thread::scope(|s| {
        let handles: Vec<_> = consumers
            .iter_mut()
            .map(|peer| {
                let barrier = &barrier;
                s.spawn(move || {
                    let payload = req_payload(&Client::link_get_consume(seq, ld_id));
                    barrier.wait();
                    let mut on = peer.on(relay);
                    let r = cmd_with(
                        &mut on,
                        "Q-42 consume",
                        &[payload],
                        Expect::D2,
                        now(),
                        &mut OsEntropy,
                    );
                    linkr(&r, "Q-42 consume")
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// Q-42 `q_link_get_consume_is_atomic_single_winner`: four links (four handshakes against one relay, distinct
/// client draws) consume one one-time `ld_id` concurrently from four threads, 1000 times (a fresh `LINK_PUT` per
/// iteration): exactly one gets {1, 0, blob}, the others {0, 1} (spec §9.4 "atomically"; ADR-048 (k)).
#[test]
fn q_link_get_consume_is_atomic_single_winner() {
    let fx = RelayFx::case1();
    let relay = fx.relay(Limits::vectors());
    let mut putter = Peer::new(&relay, &fx, 0x10);
    let mut consumers: Vec<Peer> = (0x20_u8..0x24).map(|s| Peer::new(&relay, &fx, s)).collect();
    let mut sessions: Vec<Id> = consumers.iter().map(|p| p.client.sess_id()).collect();
    sessions.push(putter.client.sess_id());
    sessions.sort_unstable();
    sessions.dedup();
    assert_eq!(sessions.len(), 5, "Q-42: five distinct links");
    let owner = Key::of(0x42);
    for i in 0..1000_u32 {
        let seq = i.checked_add(1).unwrap();
        let ld_id = id16(&[b"Q-42", &i.to_be_bytes()]);
        let data = blob(u8::try_from(i & 0xff).unwrap());
        let p = Put {
            ld_id: &ld_id,
            one_time: true,
            expires_bucket: EXPIRES,
            owner: &owner,
            blob: &data,
        };
        let r = run_put(&mut putter.on(&relay), "Q-42 LINK_PUT", seq, &p);
        assert!(r.is_ok(), "Q-42 iteration {i}: stored");
        let results = race(&relay, &mut consumers, seq, &ld_id);
        let winners = results.iter().filter(|l| l.present == 1).count();
        assert_eq!(
            winners,
            1,
            "Q-42 iteration {i} ({}): exactly one winner",
            hex(&ld_id)
        );
        for l in &results {
            if l.present == 1 {
                assert_eq!(
                    (l.consumed, &l.blob),
                    (0, &data),
                    "Q-42 iteration {i}: the winner's blob"
                );
            } else {
                assert_eq!(
                    (l.present, l.consumed),
                    (0, 1),
                    "Q-42 iteration {i}: the others {{0, 1}}"
                );
            }
        }
    }
}

/// A raw `LINK_GET` payload `0x08 ‖ cmd_seq ‖ ld_id ‖ mode ‖ sig`.
fn link_get_raw(seq: u32, ld_id: &Id, mode: u8, sig: &[u8]) -> Vec<u8> {
    let mut p = vec![OP_LINK_GET];
    p.extend(seq.to_be_bytes());
    p.extend(ld_id);
    p.push(mode);
    p.extend(sig);
    p
}

/// Q-43 `q_link_get_mode_rules_tear_down`: `mode` 2, and `mode` 0 with a non-zero `sig`, tear the link down (D.2
/// "zeros when mode = 0"; REF-M2 reading 10); `mode` 0 with zeros and `mode` 1 are answered.
#[test]
fn q_link_get_mode_rules_tear_down() {
    let (_, ld_id, owner, _) = with_link_data(true);
    let sess = Bench::vectors().client.sess_id();
    let sig = *owner.sign(&msg_link_get(&sess, 2, &ld_id)).as_bytes();
    let mut one = [0_u8; 64];
    *one.last_mut().unwrap() = 1;
    for (name, payload) in [
        ("mode 2", link_get_raw(2, &ld_id, 2, &sig)),
        ("mode 0 with a signature", link_get_raw(2, &ld_id, 0, &sig)),
        (
            "mode 0 with one non-zero sig byte",
            link_get_raw(2, &ld_id, 0, &one),
        ),
    ] {
        let (mut b, _, _, _) = with_link_data(true);
        assert_teardown(&mut b, &format!("Q-43 {name}"), &payload);
    }
    let (mut b, _, _, _) = with_link_data(true);
    let r = cmd(
        &mut b,
        "Q-43 mode 1",
        &[link_get_owner_req(
            2,
            ld_id,
            owner.sign(&msg_link_get(&sess, 2, &ld_id)),
        )],
        Expect::D2,
    );
    assert_eq!(linkr(&r, "Q-43 mode 1").present, 1, "Q-43: mode 1 answered");
    let r = run_consume(&mut b, "Q-43 mode 0", 3, &ld_id);
    assert_eq!(linkr(&r, "Q-43 mode 0").present, 1, "Q-43: mode 0 answered");
}

/// Q-44 `q_link_get_not_one_time_is_kept` [R5-6]: link data with `one_time` 0 is returned {1, 0, blob} by two
/// consumes and kept (spec §9.4; ADR-048 (k)).
#[test]
fn q_link_get_not_one_time_is_kept() {
    let (mut b, ld_id, _, data) = with_link_data(false);
    let digest = b.digest();
    for q in [2, 3] {
        let l = linkr(
            &run_consume(&mut b, &format!("Q-44 consume {q}"), q, &ld_id),
            "Q-44",
        );
        assert_eq!(
            (l.present, l.consumed, &l.blob),
            (1, 0, &data),
            "Q-44: {{1, 0, blob}}"
        );
    }
    assert_eq!(
        entry_of(&b, &ld_id),
        Some((false, true, false)),
        "Q-44: the entry is kept"
    );
    assert_eq!(b.digest(), digest, "Q-44: store unchanged");
}
