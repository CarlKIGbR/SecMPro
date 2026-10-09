// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M5 (b4) Q-08 … Q-27: `SEND`, `FETCH` and `FETCH_MULTI` (spec §9.1, §9.3, §9.5, §9.7 item 4; D.2, D.6;
//! readings OPEN-7, OPEN-8, ADR-048 (i), (j), (l), SQ-28). Every answer goes through
//! [`assert_d2_shape`](crate::d2::assert_d2_shape); every error row also checks that the store is unchanged.

use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Id;
use secmp_relay::budget::{LINKDATA_RESERVATION, QUEUE_RESERVATION};

use crate::d2::{
    CellR, DUMMY, Expect, OP_FETCH_MULTI, Reply, assert_teardown, blob, cell, cmd, cmd_with, d6,
    entry, fetch_req, limits, msg_fetch, msg_send, req_payload, run_fetch, run_fetch_multi,
    run_put, run_queue_del, run_queue_new, run_send, send_req,
};
use crate::fixture::{Bench, Client, EXPIRES, Key, Put, flip, now, reference, rid_of, sid_of};

/// `sess_id` with bit 0 of byte 0 flipped ("another link").
fn other_sess(sess: &Id) -> Id {
    flip(sess, 0).try_into().unwrap()
}

/// A bench with the queue `(recv, send)` holding `n` cells `cell(1)` … `cell(n)`; the next `cmd_seq` is `n + 2`.
fn with_cells(recv: &Key, send: &Key, n: u8) -> Bench {
    let mut b = Bench::vectors();
    run_queue_new(&mut b, "setup QUEUE_NEW", 1, recv, send);
    for i in 1..=n {
        let q = u32::from(i).checked_add(1).unwrap();
        run_send(&mut b, "setup SEND", q, recv, send, &cell(i));
    }
    b
}

/// The `cell_ids` and `next_cell_id` of the queue of `recv`.
fn queue_of(b: &Bench, recv: &Key) -> (Vec<u64>, u64) {
    let rid = rid_of(&recv.pk);
    let q = b
        .relay
        .snapshot_kat()
        .queues
        .into_iter()
        .find(|q| q.rid == rid);
    assert!(q.is_some(), "the queue exists");
    let q = q.unwrap();
    (q.cell_ids, q.next_cell_id)
}

/// `heads` followed by dummies up to `n` frames.
fn padded(heads: &[(u8, Id, u64)], n: usize) -> Vec<(u8, Id, u64)> {
    let mut v = heads.to_vec();
    v.resize(n, DUMMY);
    v
}

/// Q-08 `q_send_cell_ids_from_one`: `SEND`s to a fresh queue (P7, P10, P11) answer `OK_SEND` {1, 0, 0},
/// {2, 0, 0}, {3, 0, 0} (spec §9.1: `cell_id` per queue from 1).
#[test]
fn q_send_cell_ids_from_one() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 0);
    for (q, (n, want)) in (2_u32..).zip([(7, 1_u64), (10, 2), (11, 3)]) {
        let c = reference().case(n).input("cell");
        let r = run_send(&mut b, &format!("Q-08 P{n}"), q, &recv, &send, &c);
        assert_eq!(r.ok_send(), Some((want, 0, 0)), "Q-08 P{n}: OK_SEND");
    }
    assert_eq!(
        queue_of(&b, &recv),
        (vec![1, 2, 3], 4),
        "Q-08: cells 1, 2, 3"
    );
}

/// Q-09 `q_send_unknown_sid_is_noqueue`: `SEND` to a `sid` never created, and to the `sid` of a deleted queue
/// (E10), is ERR 3 (spec §9.3).
#[test]
fn q_send_unknown_sid_is_noqueue() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 1);
    let digest = b.digest();
    let r = run_send(
        &mut b,
        "Q-09 never created",
        3,
        &Key::of(7),
        &Key::of(8),
        &cell(9),
    );
    assert_eq!(r.err(), Some(3), "Q-09 never created: ERR 3");
    assert_eq!(b.digest(), digest, "Q-09 never created: store unchanged");
    let deleted = run_queue_del(&mut b, "Q-09 QUEUE_DEL", 4, &recv);
    assert!(deleted.is_ok(), "Q-09: deleted");
    let digest = b.digest();
    let r = run_send(&mut b, "Q-09 E10 deleted", 5, &recv, &send, &cell(9));
    assert_eq!(r.err(), Some(3), "Q-09 E10: ERR 3");
    assert_eq!(b.digest(), digest, "Q-09 E10: store unchanged");
}

/// Q-10 `q_send_bad_signature_is_auth`: `SEND` signed by the recv key (E8), over `flip(sess_id, 0)` (E9), over
/// another `cmd_seq`, or with the label `"SecMP-Q/1 FETCH"` is ERR 4 each (spec §9.3, D.6).
#[test]
fn q_send_bad_signature_is_auth() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 1);
    let sess = b.client.sess_id();
    let sid = sid_of(&recv.pk, &send.pk);
    let c = cell(5);
    let cases = [
        (
            "E8 signed by the recv key",
            3,
            recv.sign(&msg_send(&sess, 3, &sid, &c)),
        ),
        (
            "E9 over flip(sess_id, 0)",
            4,
            send.sign(&msg_send(&other_sess(&sess), 4, &sid, &c)),
        ),
        (
            "over another cmd_seq",
            5,
            send.sign(&msg_send(&sess, 6, &sid, &c)),
        ),
        (
            "label SecMP-Q/1 FETCH",
            7,
            send.sign(&d6("FETCH", &sess, 7, &[&sid, &c])),
        ),
    ];
    for (name, q, sig) in cases {
        let digest = b.digest();
        let req = send_req(q, sid, &c, sig);
        let r = cmd(&mut b, &format!("Q-10 {name}"), &[req], Expect::D2);
        assert_eq!(r.err(), Some(4), "Q-10 {name}: ERR 4");
        assert_eq!(b.digest(), digest, "Q-10 {name}: store unchanged");
    }
}

/// Q-11 `q_send_at_capacity_evicts_oldest`: 128 cells, then three `SEND`s answer {129, 1, 1}, {130, 1, 2},
/// {131, 1, 3}; the queue holds 4 … 131; `evicted_id` is 0 iff `evicted_present` is 0 (spec §9.5; ADR-048 (l)).
#[test]
fn q_send_at_capacity_evicts_oldest() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 0);
    let mut answers = Vec::new();
    for i in 1..=131_u32 {
        let q = i.checked_add(1).unwrap();
        let r = run_send(&mut b, &format!("Q-11 SEND {i}"), q, &recv, &send, &cell(3));
        answers.push(r.ok_send().unwrap());
    }
    for (i, (cell_id, present, evicted)) in (1_u64..).zip(answers.iter().copied()) {
        assert_eq!(cell_id, i, "Q-11: cell_id {i}");
        assert_eq!(
            present == 0,
            evicted == 0,
            "Q-11: evicted_id 0 iff evicted_present 0 ({i})"
        );
        if i <= 128 {
            assert_eq!(
                (present, evicted),
                (0, 0),
                "Q-11: no eviction below capacity ({i})"
            );
        }
    }
    assert_eq!(
        answers.get(128..),
        Some([(129, 1, 1), (130, 1, 2), (131, 1, 3)].as_slice()),
        "Q-11: the oldest is evicted and reported"
    );
    assert_eq!(
        queue_of(&b, &recv),
        ((4..=131).collect::<Vec<u64>>(), 132),
        "Q-11: the queue holds 4 … 131"
    );
}

/// Q-12 `q_send_accepted_when_budget_exhausted` [O-7]: with the queue pool and the link-data pool full
/// (OPEN-M5-07 A), `SEND` is still answered `OK_SEND`, at capacity too (spec §9.7 item 4).
#[test]
fn q_send_accepted_when_budget_exhausted() {
    let mut b = Bench::new(limits(Some(QUEUE_RESERVATION), Some(LINKDATA_RESERVATION)));
    let (recv, send) = (Key::of(1), Key::of(2));
    run_queue_new(&mut b, "Q-12 QUEUE_NEW", 1, &recv, &send);
    let (owner, data) = (Key::of(3), blob(1));
    let p = Put {
        ld_id: &[1; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    assert!(
        run_put(&mut b, "Q-12 LINK_PUT", 2, &p).is_ok(),
        "Q-12: link data stored"
    );
    assert_eq!(
        b.relay.budget_used_kat(),
        (QUEUE_RESERVATION, LINKDATA_RESERVATION),
        "Q-12: both pools full"
    );
    let r = run_queue_new(&mut b, "Q-12 queue pool full", 3, &Key::of(4), &Key::of(5));
    assert_eq!(r.err(), Some(2), "Q-12: QUEUE_NEW ERR 2");
    let p2 = Put {
        ld_id: &[2; 16],
        ..p
    };
    let r = run_put(&mut b, "Q-12 link-data pool full", 4, &p2);
    assert_eq!(r.err(), Some(2), "Q-12: LINK_PUT ERR 2");
    for i in 1..=129_u32 {
        let q = i.checked_add(4).unwrap();
        let r = run_send(&mut b, &format!("Q-12 SEND {i}"), q, &recv, &send, &cell(1));
        let want = if i == 129 {
            (129, 1, 1)
        } else {
            (u64::from(i), 0, 0)
        };
        assert_eq!(r.ok_send(), Some(want), "Q-12: SEND {i} OK_SEND");
    }
}

/// Q-13 `q_fetch_oldest_f_then_dummies`: three cells, `ack` 0 (P12): the present-1 cells 1, 2, 3 ascending with
/// `rid` 0, then one dummy {0, 0, 0} (spec §9.3; reading OPEN-7).
#[test]
fn q_fetch_oldest_f_then_dummies() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 3);
    let r = run_fetch(&mut b, "Q-13 P12", 5, &recv, 0);
    assert_eq!(
        r.heads(),
        padded(&[(1, [0; 16], 1), (1, [0; 16], 2), (1, [0; 16], 3)], 4),
        "Q-13: cells 1, 2, 3 then a dummy"
    );
    let cells: Vec<Vec<u8>> = r.cellrs().into_iter().take(3).map(|c| c.cell).collect();
    assert_eq!(
        cells,
        vec![cell(1), cell(2), cell(3)],
        "Q-13: the stored cells"
    );
}

/// The (`cell_id`, `cell`) pairs of the present-1 frames.
fn pairs(r: &Reply) -> Vec<(u64, Vec<u8>)> {
    r.cellrs()
        .into_iter()
        .filter(|c| c.present == 1)
        .map(|c| (c.cell_id, c.cell))
        .collect()
}

/// Q-14 `q_fetch_same_ack_is_idempotent`: a repeated `FETCH` with the same `ack` (P13) returns the same
/// (`cell_id`, `cell`) pairs (spec §9.3).
#[test]
fn q_fetch_same_ack_is_idempotent() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 3);
    let first = pairs(&run_fetch(&mut b, "Q-14 P12", 5, &recv, 0));
    let again = pairs(&run_fetch(&mut b, "Q-14 P13", 6, &recv, 0));
    assert_eq!(first.len(), 3, "Q-14: three cells");
    assert_eq!(first, again, "Q-14: identical (cell_id, cell) pairs");
}

/// Q-15 `q_fetch_cumulative_ack`: `ack` 2 (P14) deletes the cells ≤ 2 before the selection; `ack` 0 deletes
/// nothing (spec §9.3).
#[test]
fn q_fetch_cumulative_ack() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 3);
    run_fetch(&mut b, "Q-15 ack 0", 5, &recv, 0);
    assert_eq!(
        queue_of(&b, &recv),
        (vec![1, 2, 3], 4),
        "Q-15: ack 0 deletes nothing"
    );
    let only_3 = padded(&[(1, [0; 16], 3)], 4);
    let r = run_fetch(&mut b, "Q-15 P14 ack 2", 6, &recv, 2);
    assert_eq!(r.heads(), only_3, "Q-15: cell 3, then dummies");
    assert_eq!(
        queue_of(&b, &recv),
        (vec![3], 4),
        "Q-15: cells 1 and 2 deleted"
    );
    let r = run_fetch(&mut b, "Q-15 ack 0 again", 7, &recv, 0);
    assert_eq!(r.heads(), only_3, "Q-15: ack 0 keeps cell 3");
    assert_eq!(
        queue_of(&b, &recv),
        (vec![3], 4),
        "Q-15: ack 0 deletes nothing"
    );
}

/// Q-16 `q_fetch_ack_bounds`: `ack` = `next_cell_id` (E14) and `ack` = `u64::MAX` answer `present` 4 and delete
/// nothing; `ack` = `next_cell_id − 1` deletes every cell and answers `F` dummies (spec §9.1; reading OPEN-7).
#[test]
fn q_fetch_ack_bounds() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 3);
    let rid = rid_of(&recv.pk);
    for (q, ack) in [(5, 4), (6, u64::MAX)] {
        let digest = b.digest();
        let r = run_fetch(&mut b, &format!("Q-16 ack {ack}"), q, &recv, ack);
        assert_eq!(
            r.heads(),
            padded(&[(4, rid, 0)], 4),
            "Q-16 ack {ack}: present 4"
        );
        assert_eq!(
            b.digest(),
            digest,
            "Q-16 ack {ack}: nothing deleted, store unchanged"
        );
    }
    let r = run_fetch(&mut b, "Q-16 ack next_cell_id - 1", 7, &recv, 3);
    assert_eq!(r.heads(), vec![DUMMY; 4], "Q-16: F dummies");
    assert_eq!(
        queue_of(&b, &recv),
        (Vec::new(), 4),
        "Q-16: every cell deleted"
    );
}

/// Q-17 `q_fetch_unknown_rid_is_present_2`: `FETCH` of a deleted `rid` (E11), or of one never created, answers
/// `present` 2 in frame 1 (spec §9.3).
#[test]
fn q_fetch_unknown_rid_is_present_2() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 1);
    let deleted = run_queue_del(&mut b, "Q-17 QUEUE_DEL", 3, &recv);
    assert!(deleted.is_ok(), "Q-17: deleted");
    let never = Key::of(9);
    for (q, key, name) in [(4, &recv, "E11 deleted"), (5, &never, "never created")] {
        let digest = b.digest();
        let r = run_fetch(&mut b, &format!("Q-17 {name}"), q, key, 0);
        let want = padded(&[(2, rid_of(&key.pk), 0)], 4);
        assert_eq!(r.heads(), want, "Q-17 {name}: present 2");
        assert_eq!(b.digest(), digest, "Q-17 {name}: store unchanged");
    }
}

/// Q-18 `q_fetch_bad_signature_is_present_3`: `FETCH` signed by the send key (E12), over `flip(sess_id, 0)` (E13),
/// over another `cmd_seq`, or with the label `MFETCH` answers `present` 3 (spec §9.3, D.6).
#[test]
fn q_fetch_bad_signature_is_present_3() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 2);
    let sess = b.client.sess_id();
    let rid = rid_of(&recv.pk);
    let cases = [
        (
            "E12 signed by the send key",
            4,
            send.sign(&msg_fetch("FETCH", &sess, 4, &rid, 0)),
        ),
        (
            "E13 over flip(sess_id, 0)",
            5,
            recv.sign(&msg_fetch("FETCH", &other_sess(&sess), 5, &rid, 0)),
        ),
        (
            "over another cmd_seq",
            6,
            recv.sign(&msg_fetch("FETCH", &sess, 7, &rid, 0)),
        ),
        (
            "label MFETCH",
            8,
            recv.sign(&msg_fetch("MFETCH", &sess, 8, &rid, 0)),
        ),
    ];
    for (name, q, sig) in cases {
        let digest = b.digest();
        let r = cmd(
            &mut b,
            &format!("Q-18 {name}"),
            &[fetch_req(q, rid, 0, sig)],
            Expect::D2,
        );
        assert_eq!(
            r.heads(),
            padded(&[(3, rid, 0)], 4),
            "Q-18 {name}: present 3"
        );
        assert_eq!(b.digest(), digest, "Q-18 {name}: store unchanged");
    }
}

/// Q-19 `q_fetch_error_frame_layout`: for each error of Q-16 … Q-18, frame 1 carries the requested `rid`,
/// `cell_id` 0 and a random cell (the first 4096 bytes drawn), frames 2 … 4 are dummies {0, 0, 0} carrying the
/// next draws (reading OPEN-7; draw order REF-M5 reading 7).
#[test]
fn q_fetch_error_frame_layout() {
    let (recv, send, never) = (Key::of(1), Key::of(2), Key::of(9));
    let mut b = with_cells(&recv, &send, 2);
    let sess = b.client.sess_id();
    let (rid, unknown) = (rid_of(&recv.pk), rid_of(&never.pk));
    let cases = [
        ("present 2", 4, unknown, 0, &never, 2),
        ("present 3", 5, rid, 0, &send, 3),
        ("present 4", 6, rid, 3, &recv, 4),
    ];
    for (name, q, want_rid, ack, signer, present) in cases {
        let sig = signer.sign(&msg_fetch("FETCH", &sess, q, &want_rid, ack));
        let draws: Vec<u8> = [0xa1_u8, 0xb2, 0xc3, 0xd4]
            .into_iter()
            .flat_map(cell)
            .collect();
        let mut entropy = FixedEntropy::new(&draws);
        let payload = req_payload(&fetch_req(q, want_rid, ack, sig));
        let case = format!("Q-19 {name}");
        let r = cmd_with(&mut b, &case, &[payload], Expect::D2, now(), &mut entropy);
        let frames = r.cellrs();
        assert_eq!(
            frames.first().map(CellR::head),
            Some((present, want_rid, 0)),
            "{case}: frame 1 rid = the requested rid, cell_id 0"
        );
        assert_eq!(
            frames.first().map(|c| c.cell.clone()),
            Some(cell(0xa1)),
            "{case}: frame 1 cell drawn first"
        );
        for (f, x) in frames.iter().skip(1).zip([0xb2_u8, 0xc3, 0xd4]) {
            assert_eq!(
                (f.head(), &f.cell),
                (DUMMY, &cell(x)),
                "{case}: frames 2 … 4 are dummies"
            );
        }
        assert_eq!(entropy.remaining(), 0, "{case}: four cells drawn");
    }
}

/// Q-20 `q_fetch_after_recreate_old_ack_is_present_4`: after the queue is deleted and re-created with the same keys,
/// a `FETCH` with the old committed `ack` answers `present` 4 and deletes nothing (spec §9.1).
#[test]
fn q_fetch_after_recreate_old_ack_is_present_4() {
    let (recv, send) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&recv, &send, 3);
    let r = run_fetch(&mut b, "Q-20 FETCH", 5, &recv, 0);
    let committed = r.cellrs().iter().map(|c| c.cell_id).max().unwrap();
    assert_eq!(committed, 3, "Q-20: committed ack 3");
    let deleted = run_queue_del(&mut b, "Q-20 QUEUE_DEL", 6, &recv);
    assert!(deleted.is_ok(), "Q-20: deleted");
    run_queue_new(&mut b, "Q-20 re-create", 7, &recv, &send);
    run_send(&mut b, "Q-20 SEND", 8, &recv, &send, &cell(9));
    let digest = b.digest();
    let r = run_fetch(&mut b, "Q-20 old ack", 9, &recv, committed);
    let want = padded(&[(4, rid_of(&recv.pk), 0)], 4);
    assert_eq!(r.heads(), want, "Q-20: present 4");
    assert_eq!(b.digest(), digest, "Q-20: nothing deleted, store unchanged");
    assert_eq!(
        queue_of(&b, &recv),
        (vec![1], 2),
        "Q-20: the new cell is kept"
    );
}

/// Q-21 `q_fetch_multi_oldest_first_by_arrival`: entries [B `ack` 0, A `ack` 2] with arrival A3 < B1 < A4 (P18)
/// answer {1, A, 3}, {1, B, 1}, {1, A, 4} and five dummies; a present-1 frame carries its `rid` (reading OPEN-8).
#[test]
fn q_fetch_multi_oldest_first_by_arrival() {
    let (ra, sa, rb, sb) = (Key::of(1), Key::of(2), Key::of(3), Key::of(4));
    let mut b = with_cells(&ra, &sa, 3);
    run_queue_new(&mut b, "Q-21 B", 5, &rb, &sb);
    run_send(&mut b, "Q-21 B1", 6, &rb, &sb, &cell(0x11));
    run_send(&mut b, "Q-21 A4", 7, &ra, &sa, &cell(4));
    let r = run_fetch_multi(&mut b, "Q-21 P18", 8, &[(&rb, 0), (&ra, 2)]);
    let (a, bq) = (rid_of(&ra.pk), rid_of(&rb.pk));
    let want = padded(&[(1, a, 3), (1, bq, 1), (1, a, 4)], 8);
    assert_eq!(r.heads(), want, "Q-21: oldest first by arrival");
    let cells: Vec<Vec<u8>> = r.cellrs().into_iter().take(3).map(|c| c.cell).collect();
    assert_eq!(
        cells,
        vec![cell(3), cell(0x11), cell(4)],
        "Q-21: the stored cells"
    );
    assert_eq!(
        queue_of(&b, &ra),
        (vec![3, 4], 5),
        "Q-21: A's ack 2 applied"
    );
}

/// Three queues A, B, C on an unlimited-budget bench: A is deleted, B holds three cells and C two; B and C were
/// fetched once, so that a served entry with `ack` 0 changes nothing. The next `cmd_seq` is 20.
fn three_queues() -> (Bench, [(Key, Key); 3]) {
    let keys = [
        (Key::of(1), Key::of(2)),
        (Key::of(3), Key::of(4)),
        (Key::of(5), Key::of(6)),
    ];
    let mut b = Bench::new(limits(None, None));
    let mut q = 0_u32;
    let mut next = || {
        q = q.checked_add(1).unwrap();
        q
    };
    for (r, s) in &keys {
        run_queue_new(&mut b, "setup QUEUE_NEW", next(), r, s);
    }
    let [(ra, _), (rb, sb), (rc, sc)] = &keys;
    let deleted = run_queue_del(&mut b, "setup QUEUE_DEL A", next(), ra);
    assert!(deleted.is_ok(), "A deleted");
    for i in 1..=3_u8 {
        run_send(&mut b, "setup SEND B", next(), rb, sb, &cell(0x10 | i));
    }
    for i in 1..=2_u8 {
        run_send(&mut b, "setup SEND C", next(), rc, sc, &cell(0x20 | i));
    }
    run_fetch(&mut b, "setup FETCH B", next(), rb, 0);
    run_fetch(&mut b, "setup FETCH C", next(), rc, 0);
    assert!(next() < 20, "setup cmd_seq below 20");
    (b, keys)
}

/// Q-22 `q_fetch_multi_error_frames_first_in_request_order`: [A deleted, B] (E15) answers {2, A} then B's cells;
/// [B bad signature, A deleted, C] answers {3, B}, {2, A}, then C's cells (spec §9.3).
#[test]
fn q_fetch_multi_error_frames_first_in_request_order() {
    let (mut b, [(ra, _), (rb, sb), (rc, _)]) = three_queues();
    let (a, bq, c) = (rid_of(&ra.pk), rid_of(&rb.pk), rid_of(&rc.pk));
    let digest = b.digest();
    let r = run_fetch_multi(&mut b, "Q-22 E15", 20, &[(&ra, 0), (&rb, 0)]);
    let want = padded(&[(2, a, 0), (1, bq, 1), (1, bq, 2), (1, bq, 3)], 8);
    assert_eq!(r.heads(), want, "Q-22 E15: the error frame first");
    assert_eq!(b.digest(), digest, "Q-22 E15: store unchanged");
    let sess = b.client.sess_id();
    let bad = entry(bq, 0, sb.sign(&msg_fetch("MFETCH", &sess, 21, &bq, 0)));
    let entries = vec![
        bad,
        b.client.fetch_entry(21, &ra, 0),
        b.client.fetch_entry(21, &rc, 0),
    ];
    let req = Client::fetch_multi(21, entries);
    let r = cmd(&mut b, "Q-22 [B bad sig, A deleted, C]", &[req], Expect::D2);
    let want = padded(&[(3, bq, 0), (2, a, 0), (1, c, 1), (1, c, 2)], 8);
    assert_eq!(
        r.heads(),
        want,
        "Q-22: errors first in request order, then the cells"
    );
    assert_eq!(b.digest(), digest, "Q-22: store unchanged");
}

/// Q-23 `q_fetch_multi_per_entry_ack_semantics`: an entry's `ack` deletes before the selection; an entry with
/// `ack ≥ next_cell_id` answers `present` 4 for that entry and the others are served (reading OPEN-8).
#[test]
fn q_fetch_multi_per_entry_ack_semantics() {
    let (ra, sa, rb, sb) = (Key::of(1), Key::of(2), Key::of(3), Key::of(4));
    let mut b = with_cells(&ra, &sa, 3);
    run_queue_new(&mut b, "Q-23 B", 5, &rb, &sb);
    run_send(&mut b, "Q-23 B1", 6, &rb, &sb, &cell(0x11));
    run_send(&mut b, "Q-23 B2", 7, &rb, &sb, &cell(0x12));
    let (a, bq) = (rid_of(&ra.pk), rid_of(&rb.pk));
    let r = run_fetch_multi(&mut b, "Q-23 [A ack 2, B ack 0]", 8, &[(&ra, 2), (&rb, 0)]);
    let want = padded(&[(1, a, 3), (1, bq, 1), (1, bq, 2)], 8);
    assert_eq!(
        r.heads(),
        want,
        "Q-23: A's ack deletes before the selection"
    );
    assert_eq!(
        queue_of(&b, &ra),
        (vec![3], 4),
        "Q-23: A's cells 1 and 2 deleted"
    );
    let r = run_fetch_multi(
        &mut b,
        "Q-23 [A ack next_cell_id, B]",
        9,
        &[(&ra, 4), (&rb, 0)],
    );
    let want = padded(&[(4, a, 0), (1, bq, 1), (1, bq, 2)], 8);
    assert_eq!(r.heads(), want, "Q-23: present 4 for A, B served");
    assert_eq!(
        queue_of(&b, &ra),
        (vec![3], 4),
        "Q-23: nothing deleted from A"
    );
}

/// Q-24 `q_fetch_multi_signature_label_is_mfetch`: an entry signed with the label `"SecMP-Q/1 FETCH"` answers
/// `present` 3; with one entry dropped and `count` reduced the remaining entry still verifies (the count is not
/// signed; D.2, D.6; REF-M2 reading 13).
#[test]
fn q_fetch_multi_signature_label_is_mfetch() {
    let (ra, sa, rb, sb) = (Key::of(1), Key::of(2), Key::of(3), Key::of(4));
    let mut b = with_cells(&ra, &sa, 1);
    run_queue_new(&mut b, "Q-24 B", 3, &rb, &sb);
    run_send(&mut b, "Q-24 B1", 4, &rb, &sb, &cell(0x11));
    run_fetch(&mut b, "Q-24 FETCH B", 5, &rb, 0);
    let (sess, a, bq) = (b.client.sess_id(), rid_of(&ra.pk), rid_of(&rb.pk));
    let wrong = entry(a, 0, ra.sign(&msg_fetch("FETCH", &sess, 6, &a, 0)));
    let digest = b.digest();
    let req = Client::fetch_multi(6, vec![wrong]);
    let r = cmd(&mut b, "Q-24 label FETCH", &[req], Expect::D2);
    assert_eq!(
        r.heads(),
        padded(&[(3, a, 0)], 8),
        "Q-24: label FETCH is present 3"
    );
    assert_eq!(b.digest(), digest, "Q-24: store unchanged");
    // two entries signed for cmd_seq 7; only the second is sent, with count 1
    let [_, kept] = [
        b.client.fetch_entry(7, &ra, 0),
        b.client.fetch_entry(7, &rb, 0),
    ];
    let req = Client::fetch_multi(7, vec![kept]);
    let r = cmd(&mut b, "Q-24 one entry dropped", &[req], Expect::D2);
    assert_eq!(
        r.heads(),
        padded(&[(1, bq, 1)], 8),
        "Q-24: the remaining entry verifies"
    );
}

/// Q-25's bench, without a budget limit (three queues; the vector budget holds two): A holds cell 1, B is empty, C
/// holds cells 1 and 2. The next `cmd_seq` is 7.
fn q25_bench([(ra, sa), (rb, sb), (rc, sc)]: &[(Key, Key); 3]) -> Bench {
    let mut b = Bench::new(limits(None, None));
    run_queue_new(&mut b, "Q-25 A", 1, ra, sa);
    run_send(&mut b, "Q-25 A1", 2, ra, sa, &cell(1));
    run_queue_new(&mut b, "Q-25 B", 3, rb, sb);
    run_queue_new(&mut b, "Q-25 C", 4, rc, sc);
    run_send(&mut b, "Q-25 C1", 5, rc, sc, &cell(0x31));
    run_send(&mut b, "Q-25 C2", 6, rc, sc, &cell(0x32));
    b
}

/// Q-25 `q_fetch_multi_more_errors_than_f_m` [SQ-28]: ten entries — nine in error (`present` 2, 3 and 4), then a
/// valid one for queue C with `ack` 1 — answer exactly 8 frames: the first eight errors in request order, and only
/// their eight cells are drawn (ADR-048 (j)). The valid 10th entry is not reported, because the `F_M` cap cuts the
/// answer before it, but it is still checked and acknowledged: every entry has the `FETCH` ack semantics and the cap
/// limits only what is answered (spec §9.3 `FETCH_MULTI`; acking a cut entry is spec-conformant, M05 review H-10).
/// So C's cell 1 is deleted and the store changes by exactly what a lone `FETCH` of C with `ack` 1 changes on a twin
/// bench; a later `FETCH` of C no longer shows cell 1 (`q25_acked_but_unreported_entry_still_deletes`, M05 review
/// R-140/C-13).
#[test]
fn q_fetch_multi_more_errors_than_f_m() {
    let keys = [
        (Key::of(1), Key::of(2)),
        (Key::of(3), Key::of(4)),
        (Key::of(5), Key::of(6)),
    ];
    let [(ra, sa), (rb, _), (rc, _)] = &keys;
    let mut b = q25_bench(&keys);
    let sess = b.client.sess_id();
    let (a, bq) = (rid_of(&ra.pk), rid_of(&rb.pk));
    let unknown: Vec<Key> = (50_u8..57).map(Key::of).collect();
    let (first, rest) = unknown.split_first().unwrap();
    let mut entries = vec![
        b.client.fetch_entry(7, first, 0),
        entry(a, 0, sa.sign(&msg_fetch("MFETCH", &sess, 7, &a, 0))),
        b.client.fetch_entry(7, rb, 1),
    ];
    entries.extend(rest.iter().map(|k| b.client.fetch_entry(7, k, 0)));
    entries.push(b.client.fetch_entry(7, rc, 1));
    assert_eq!(
        entries.len(),
        10,
        "Q-25: ten entries, nine errors then a valid one"
    );
    let mut want = vec![(2, rid_of(&first.pk), 0), (3, a, 0), (4, bq, 0)];
    want.extend(rest.iter().take(5).map(|k| (2, rid_of(&k.pk), 0)));
    let mut entropy = FixedEntropy::new(&vec![0x5a; 32_768]);
    let digest = b.digest();
    assert_eq!(
        queue_of(&b, rc),
        (vec![1, 2], 3),
        "Q-25: C holds cells 1 and 2"
    );
    let payload = req_payload(&Client::fetch_multi(7, entries));
    let r = cmd_with(
        &mut b,
        "Q-25 nine errors and a valid entry",
        &[payload],
        Expect::D2,
        now(),
        &mut entropy,
    );
    assert_eq!(
        r.heads(),
        want,
        "Q-25: the first eight errors in request order (q25_acked_but_unreported_entry_still_deletes: C's entry \
         is not reported)"
    );
    assert_eq!(
        entropy.remaining(),
        0,
        "Q-25: eight cells drawn, nothing else"
    );
    assert_eq!(
        queue_of(&b, rc),
        (vec![2], 3),
        "Q-25 q25_acked_but_unreported_entry_still_deletes: C's cell 1 deleted by the unreported entry's ack, cell 2 \
         kept"
    );
    assert_eq!(
        (queue_of(&b, ra), queue_of(&b, rb)),
        ((vec![1], 2), (Vec::new(), 1)),
        "Q-25: A and B unchanged (their entries are errors)"
    );
    let mut twin = q25_bench(&keys);
    assert_eq!(
        twin.digest(),
        digest,
        "Q-25: the twin bench holds the same store"
    );
    // C's cell 2 alone; a FETCH's present-1 frame carries rid 0 (only FETCH_MULTI's carries its rid, OPEN-8)
    let only_2 = padded(&[(1, [0; 16], 2)], 4);
    let lone = run_fetch(&mut twin, "Q-25 twin: FETCH C ack 1", 7, rc, 1);
    assert_eq!(lone.heads(), only_2, "Q-25 twin: C ack 1 served");
    assert_eq!(
        b.digest(),
        twin.digest(),
        "Q-25 q25_acked_but_unreported_entry_still_deletes: the store changed by exactly C's ack 1 (= a lone FETCH \
         of C with ack 1 on the twin bench)"
    );
    let later = run_fetch(&mut b, "Q-25 FETCH C afterwards", 8, rc, 0);
    assert_eq!(
        later.heads(),
        only_2,
        "Q-25 q25_acked_but_unreported_entry_still_deletes: a later FETCH of C no longer shows cell 1"
    );
}

/// Q-26 `q_fetch_multi_repeated_rid` [SQ-28]: a `rid` listed twice with `ack` 1 then 2: the acks apply in request
/// order and no cell is returned twice (ADR-048 (j)).
#[test]
fn q_fetch_multi_repeated_rid() {
    let (ra, sa) = (Key::of(1), Key::of(2));
    let mut b = with_cells(&ra, &sa, 4);
    let a = rid_of(&ra.pk);
    let r = run_fetch_multi(&mut b, "Q-26 [A ack 1, A ack 2]", 6, &[(&ra, 1), (&ra, 2)]);
    assert_eq!(
        r.heads(),
        padded(&[(1, a, 3), (1, a, 4)], 8),
        "Q-26: cells 3 and 4 once"
    );
    let mut ids: Vec<u64> = r
        .cellrs()
        .iter()
        .filter(|c| c.present == 1)
        .map(|c| c.cell_id)
        .collect();
    let n = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), n, "Q-26: no cell returned twice");
    assert_eq!(
        queue_of(&b, &ra),
        (vec![3, 4], 5),
        "Q-26: both acks applied"
    );
}

/// Q-27 `q_fetch_multi_count_bounds_tear_down`: `count` 0 and 33 tear the link down (D.2 `count` 1..=32; reading
/// OPEN-6); `count` 1 and 32 are answered with `F_M` frames.
#[test]
fn q_fetch_multi_count_bounds_tear_down() {
    let keys: Vec<Key> = (60_u8..93).map(Key::of).collect();
    for n in [1_usize, 32] {
        let mut b = Bench::vectors();
        let entries = keys
            .iter()
            .take(n)
            .map(|k| b.client.fetch_entry(1, k, 0))
            .collect();
        let r = cmd(
            &mut b,
            &format!("Q-27 count {n}"),
            &[Client::fetch_multi(1, entries)],
            Expect::D2,
        );
        let errors = r.heads().iter().filter(|h| h.0 == 2).count();
        assert_eq!(
            errors,
            n.min(8),
            "Q-27 count {n}: one present-2 frame per entry, at most F_M"
        );
    }
    for n in [0_usize, 33] {
        let mut b = Bench::vectors();
        let mut payload = vec![OP_FETCH_MULTI];
        payload.extend(1_u32.to_be_bytes());
        payload.push(u8::try_from(n).unwrap());
        for k in keys.iter().take(n) {
            let e = b.client.fetch_entry(1, k, 0);
            payload.extend(e.rid);
            payload.extend(e.ack.to_be_bytes());
            payload.extend(e.sig.as_bytes());
        }
        assert_teardown(&mut b, &format!("Q-27 count {n}"), &payload);
    }
}
