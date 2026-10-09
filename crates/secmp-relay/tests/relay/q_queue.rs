// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M5 (b4) Q-01 … Q-07 and Q-28 … Q-31: `QUEUE_NEW` and `QUEUE_DEL` (spec §9.1, §9.3, §9.6, §9.7 items 4
//! and 8; D.2, D.6; readings OPEN-9, OPEN-12, OPEN-M5-04). Every answer goes through
//! [`assert_d2_shape`](crate::d2::assert_d2_shape); every error row also checks that the store is unchanged
//! (`Relay::store_digest_kat` before and after).

use secmp_proto::wire::Id;
use secmp_proto::wire::frame::Request;
use secmp_relay::budget::QUEUE_RESERVATION;
use secmp_relay::relay::kat::QueueSnapshot;

use crate::d2::{
    DUMMY, Expect, cell, cmd, d6, id16, msg_queue_del, msg_queue_new, queue_del_req, queue_new_req,
    req_payload, run_fetch, run_queue_del, run_queue_new, run_send,
};
use crate::fixture::{Bench, Key, flip, reference, rid_of, sid_of, token};

/// The keys of queue A (`link-0006`).
fn keys_a() -> (Key, Key) {
    let c = reference().case(6);
    (
        Key::from_seed(&c.input("recv_seed")),
        Key::from_seed(&c.input("send_seed")),
    )
}

/// `sess_id` with bit 0 of byte 0 flipped ("another link").
fn other_sess(sess: &Id) -> Id {
    flip(sess, 0).try_into().unwrap()
}

/// Q-01 `q_queue_new_creates_queue_with_derived_ids`: `QUEUE_NEW` with fresh keys (P6) answers `OK_QUEUE_NEW` with
/// `rid = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16]` and `sid = SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖
/// send_pk)[0..16]`; the queue is empty and its `next_cell_id` is 1.
#[test]
fn q_queue_new_creates_queue_with_derived_ids() {
    let (recv, send) = keys_a();
    let mut b = Bench::vectors();
    let r = run_queue_new(&mut b, "Q-01 P6", 1, &recv, &send);
    let rid = id16(&[b"SecMP-Q/1 rid", recv.pk.as_bytes()]);
    let sid = id16(&[b"SecMP-Q/1 sid", recv.pk.as_bytes(), send.pk.as_bytes()]);
    assert_eq!(
        r.ok_queue_new(),
        Some((rid, sid)),
        "Q-01: OK_QUEUE_NEW carries the derived ids"
    );
    let p6 = reference().case(6);
    assert_eq!(rid.to_vec(), p6.output("rid"), "Q-01: rid = link-0006 rid");
    assert_eq!(sid.to_vec(), p6.output("sid"), "Q-01: sid = link-0006 sid");
    assert_eq!(
        b.relay.snapshot_kat().queues,
        vec![QueueSnapshot {
            rid,
            sid,
            cell_ids: Vec::new(),
            next_cell_id: 1
        }],
        "Q-01: one empty queue with next_cell_id 1"
    );
}

/// The token and signature bytes of a `QUEUE_NEW` payload.
fn token_and_sig(r: &Request) -> Vec<u8> {
    req_payload(r).get(69..165).unwrap().to_vec()
}

/// Q-02 `q_queue_new_identical_is_idempotent`: an identical `QUEUE_NEW` (same keys) with a fresh token and signature
/// (P9) answers `OK_QUEUE_NEW` with the same ids and changes nothing in the store.
#[test]
fn q_queue_new_identical_is_idempotent() {
    let (recv, send) = keys_a();
    let mut b = Bench::vectors();
    let first = b.client.queue_new(1, &recv, &send);
    let first_bytes = token_and_sig(&first);
    let ids = cmd(&mut b, "Q-02 first", &[first], Expect::D2).ok_queue_new();
    assert!(ids.is_some(), "Q-02: the first QUEUE_NEW succeeds");
    // a stored cell, so that "without side effects" covers the cells too
    run_send(&mut b, "Q-02 SEND", 2, &recv, &send, &cell(7));
    let again = b.client.queue_new(3, &recv, &send);
    assert_ne!(
        first_bytes,
        token_and_sig(&again),
        "Q-02: fresh token and signature"
    );
    let digest = b.digest();
    let r = cmd(&mut b, "Q-02 P9", &[again], Expect::D2);
    assert_eq!(r.ok_queue_new(), ids, "Q-02: same ids");
    assert_eq!(b.digest(), digest, "Q-02: store unchanged");
}

/// Q-03 `q_queue_new_known_recv_pk_other_send_pk_is_auth`: B's recv key with a fresh send key (E6) is ERR 4.
#[test]
fn q_queue_new_known_recv_pk_other_send_pk_is_auth() {
    let mut b = Bench::vectors();
    let (recv_b, send_b) = (Key::of(3), Key::of(4));
    run_queue_new(&mut b, "Q-03 A", 1, &Key::of(1), &Key::of(2));
    run_queue_new(&mut b, "Q-03 B", 2, &recv_b, &send_b);
    let digest = b.digest();
    let r = run_queue_new(&mut b, "Q-03 E6", 3, &recv_b, &Key::of(5));
    assert_eq!(r.err(), Some(4), "Q-03 E6: ERR 4");
    assert_eq!(b.digest(), digest, "Q-03 E6: store unchanged");
}

/// Q-04 `q_queue_new_token_binding`: a token flipped at byte 0 (E3), the token of `cmd_seq` 1 (E4), a token over
/// `flip(sess_id, 0)` (E5) and a token under another access key are ERR 1 each (spec §9.6); each is signed as sent;
/// the honest token is accepted.
#[test]
fn q_queue_new_token_binding() {
    let mut b = Bench::vectors();
    let sess = b.client.sess_id();
    let access = b.fx.access_key.clone();
    let variants: [(&str, u32, [u8; 32]); 4] = [
        (
            "E3 flip(token, 0)",
            2,
            flip(&token(&access, &sess, 2), 0).try_into().unwrap(),
        ),
        ("E4 token of cmd_seq 1", 3, token(&access, &sess, 1)),
        (
            "E5 token over flip(sess_id, 0)",
            4,
            token(&access, &other_sess(&sess), 4),
        ),
        ("another access key", 5, token(&[0x5a; 32], &sess, 5)),
    ];
    for (i, (name, q, tok)) in (10_u8..).zip(variants) {
        let (recv, send) = (Key::of(i), Key::of(20));
        let sig = recv.sign(&msg_queue_new(&sess, q, &recv, &send, &tok));
        let digest = b.digest();
        let req = queue_new_req(q, &recv, &send, tok, sig);
        let r = cmd(&mut b, &format!("Q-04 {name}"), &[req], Expect::D2);
        assert_eq!(r.err(), Some(1), "Q-04 {name}: ERR 1");
        assert_eq!(b.digest(), digest, "Q-04 {name}: store unchanged");
    }
    let (recv, send) = (Key::of(30), Key::of(31));
    let tok = token(&access, &sess, 6);
    let sig = recv.sign(&msg_queue_new(&sess, 6, &recv, &send, &tok));
    let req = queue_new_req(6, &recv, &send, tok, sig);
    let r = cmd(&mut b, "Q-04 honest token", &[req], Expect::D2);
    assert!(
        r.ok_queue_new().is_some(),
        "Q-04: the honest token is accepted"
    );
}

/// Q-05 `q_queue_new_bad_signature_is_auth`: a `QUEUE_NEW` signed by the send key (E7), by an unrelated key, with
/// the label `"SecMP-Q/1 SEND"`, over another `cmd_seq` and over `flip(sess_id, 0)` is ERR 4 each (D.2, D.6;
/// reading OPEN-9); the token is honest.
#[test]
fn q_queue_new_bad_signature_is_auth() {
    let mut b = Bench::vectors();
    let sess = b.client.sess_id();
    for (i, name) in (40_u8..).zip([
        "E7 signed by the send key",
        "signed by an unrelated key",
        "label SecMP-Q/1 SEND",
        "over another cmd_seq",
        "over flip(sess_id, 0)",
    ]) {
        let (recv, send) = (Key::of(i), Key::of(i.checked_add(10).unwrap()));
        let q = u32::from(i);
        let tok = b.client.token(q);
        let fields: [&[u8]; 3] = [recv.pk.as_bytes(), send.pk.as_bytes(), &tok];
        let sig = match i {
            40 => send.sign(&msg_queue_new(&sess, q, &recv, &send, &tok)),
            41 => Key::of(99).sign(&msg_queue_new(&sess, q, &recv, &send, &tok)),
            42 => recv.sign(&d6("SEND", &sess, q, &fields)),
            43 => recv.sign(&msg_queue_new(
                &sess,
                q.checked_add(100).unwrap(),
                &recv,
                &send,
                &tok,
            )),
            _ => recv.sign(&msg_queue_new(&other_sess(&sess), q, &recv, &send, &tok)),
        };
        let digest = b.digest();
        let req = queue_new_req(q, &recv, &send, tok, sig);
        let r = cmd(&mut b, &format!("Q-05 {name}"), &[req], Expect::D2);
        assert_eq!(r.err(), Some(4), "Q-05 {name}: ERR 4");
        assert_eq!(b.digest(), digest, "Q-05 {name}: store unchanged");
    }
}

/// Q-06 `q_queue_new_budget_exceeded_is_full`: with the vector budget (two queue reservations) a third queue (E1) is
/// ERR 2 (spec §9.7 item 4; reading OPEN-12).
#[test]
fn q_queue_new_budget_exceeded_is_full() {
    let mut b = Bench::vectors();
    run_queue_new(&mut b, "Q-06 A", 1, &Key::of(1), &Key::of(2));
    run_queue_new(&mut b, "Q-06 B", 2, &Key::of(3), &Key::of(4));
    let full = QUEUE_RESERVATION.checked_mul(2).unwrap();
    assert_eq!(
        b.relay.budget_used_kat(),
        (full, 0),
        "Q-06: two reservations"
    );
    let digest = b.digest();
    let r = run_queue_new(&mut b, "Q-06 E1", 3, &Key::of(5), &Key::of(6));
    assert_eq!(r.err(), Some(2), "Q-06 E1: ERR 2");
    assert_eq!(b.digest(), digest, "Q-06 E1: store unchanged");
    assert_eq!(
        b.relay.snapshot_kat().queues.len(),
        2,
        "Q-06: no third queue"
    );
}

/// Q-07 `q_queue_new_identical_at_budget_is_ok` [O-4]: an identical `QUEUE_NEW` of an existing queue at the budget
/// limit answers `OK_QUEUE_NEW` (the budget check comes after the idempotency check, OPEN-M5-04).
#[test]
fn q_queue_new_identical_at_budget_is_ok() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    let ids = run_queue_new(&mut b, "Q-07 A", 1, &recv, &send).ok_queue_new();
    run_queue_new(&mut b, "Q-07 B", 2, &Key::of(3), &Key::of(4));
    let digest = b.digest();
    let r = run_queue_new(&mut b, "Q-07 identical A at the limit", 3, &recv, &send);
    assert_eq!(r.ok_queue_new(), ids, "Q-07: OK_QUEUE_NEW with A's ids");
    assert_eq!(
        ids,
        Some((rid_of(&recv.pk), sid_of(&recv.pk, &send.pk))),
        "Q-07: derived ids"
    );
    assert_eq!(b.digest(), digest, "Q-07: store unchanged");
}

/// Q-28 `q_queue_del_removes_queue`: `QUEUE_DEL` (P23) answers OK and removes the queue with its cells and its
/// reservation; then `SEND` is ERR 3 and `FETCH` answers `present` 2 (spec §9.3).
#[test]
fn q_queue_del_removes_queue() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    run_queue_new(&mut b, "Q-28 QUEUE_NEW", 1, &recv, &send);
    run_send(&mut b, "Q-28 SEND", 2, &recv, &send, &cell(1));
    assert_eq!(
        b.relay.budget_used_kat(),
        (QUEUE_RESERVATION, 0),
        "Q-28: reserved"
    );
    assert!(
        run_queue_del(&mut b, "Q-28 P23", 3, &recv).is_ok(),
        "Q-28: OK"
    );
    assert!(b.relay.snapshot_kat().queues.is_empty(), "Q-28: queue gone");
    assert_eq!(
        b.relay.budget_used_kat(),
        (0, 0),
        "Q-28: reservation released"
    );
    let r = run_send(&mut b, "Q-28 SEND after", 4, &recv, &send, &cell(2));
    assert_eq!(r.err(), Some(3), "Q-28: SEND ERR 3");
    let r = run_fetch(&mut b, "Q-28 FETCH after", 5, &recv, 0);
    let rid = rid_of(&recv.pk);
    assert_eq!(
        r.heads(),
        vec![(2, rid, 0), DUMMY, DUMMY, DUMMY],
        "Q-28: FETCH present 2"
    );
}

/// Q-29 `q_queue_del_unknown_rid_is_noqueue`: `QUEUE_DEL` of a `rid` never created is ERR 3 (reading OPEN-9).
#[test]
fn q_queue_del_unknown_rid_is_noqueue() {
    let mut b = Bench::vectors();
    run_queue_new(&mut b, "Q-29 A", 1, &Key::of(1), &Key::of(2));
    let digest = b.digest();
    let r = run_queue_del(&mut b, "Q-29 never created", 2, &Key::of(60));
    assert_eq!(r.err(), Some(3), "Q-29: ERR 3");
    assert_eq!(b.digest(), digest, "Q-29: store unchanged");
}

/// Q-30 `q_queue_del_bad_signature_is_auth`: `QUEUE_DEL` signed by the send key (E16) or with the label
/// `"SecMP-Q/1 FETCH"` is ERR 4 (reading OPEN-9).
#[test]
fn q_queue_del_bad_signature_is_auth() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    run_queue_new(&mut b, "Q-30 B", 1, &recv, &send);
    let sess = b.client.sess_id();
    let rid = rid_of(&recv.pk);
    let cases = [
        (
            "E16 signed by the send key",
            2,
            send.sign(&msg_queue_del(&sess, 2, &rid)),
        ),
        (
            "label SecMP-Q/1 FETCH",
            3,
            recv.sign(&d6("FETCH", &sess, 3, &[&rid])),
        ),
    ];
    for (name, q, sig) in cases {
        let digest = b.digest();
        let r = cmd(
            &mut b,
            &format!("Q-30 {name}"),
            &[queue_del_req(q, rid, sig)],
            Expect::D2,
        );
        assert_eq!(r.err(), Some(4), "Q-30 {name}: ERR 4");
        assert_eq!(b.digest(), digest, "Q-30 {name}: store unchanged");
    }
}

/// Q-31 `q_queue_del_then_recreate_is_fresh`: after `QUEUE_DEL`, the `QUEUE_NEW` with the same keys gives the same
/// `rid`/`sid`, no cells and `next_cell_id` 1 (spec §9.1).
#[test]
fn q_queue_del_then_recreate_is_fresh() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    let ids = run_queue_new(&mut b, "Q-31 QUEUE_NEW", 1, &recv, &send).ok_queue_new();
    run_send(&mut b, "Q-31 SEND 1", 2, &recv, &send, &cell(1));
    run_send(&mut b, "Q-31 SEND 2", 3, &recv, &send, &cell(2));
    assert!(
        run_queue_del(&mut b, "Q-31 QUEUE_DEL", 4, &recv).is_ok(),
        "Q-31: deleted"
    );
    let again = run_queue_new(&mut b, "Q-31 re-create", 5, &recv, &send).ok_queue_new();
    assert_eq!(again, ids, "Q-31: same rid and sid");
    let (rid, sid) = again.unwrap();
    assert_eq!(
        b.relay.snapshot_kat().queues,
        vec![QueueSnapshot {
            rid,
            sid,
            cell_ids: Vec::new(),
            next_cell_id: 1
        }],
        "Q-31: no cells, next_cell_id 1"
    );
    let r = run_send(&mut b, "Q-31 SEND after", 6, &recv, &send, &cell(3));
    assert_eq!(
        r.ok_send(),
        Some((1, 0, 0)),
        "Q-31: cell ids start at 1 again"
    );
}
