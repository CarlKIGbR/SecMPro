// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M5 (b4) Q-45 … Q-52: `PING`, `SKEY` and `cmd_seq` (spec §8.5, §9.2, §9.3; D.2; readings OPEN-5,
//! OPEN-6, ADR-048 (f), SQ-26, REF-M5 reading 2). Every answer goes through
//! [`assert_d2_shape`](crate::d2::assert_d2_shape) — for a stale `cmd_seq` with its exception, exactly one ERR 6
//! frame ([`STALE`]); every error row also checks that the store is unchanged.

use secmp_proto::wire::frame::CellrContext;

use crate::d2::{
    Expect, OP_FETCH_MULTI, OP_SKEY, Reply, STALE, cell, cmd, cmd_raw, msg_send, run_consume,
    run_fetch, run_fetch_multi, run_owner, run_ping, run_put, run_queue_del, run_queue_new,
    run_send, send_req,
};
use crate::fixture::{Bench, Client, EXPIRES, Key, Put, decode_response, reference, sid_of};

/// Q-45 `q_ping_is_ok`: `PING` (P8) is answered `OK`, a 5-byte payload `0x80 ‖ cmd_seq` (spec §9.3).
#[test]
fn q_ping_is_ok() {
    let mut b = Bench::vectors();
    let r = run_ping(&mut b, "Q-45 P8", 3);
    assert_eq!(r.raw, vec![vec![0x80, 0, 0, 0, 3]], "Q-45: OK, 5 B");
    assert_eq!(
        r.raw,
        reference().case(8).output_list("resp"),
        "Q-45: = link-0008 resp"
    );
}

/// Q-46 `q_skey_is_err_6` [R5-2]: `0x02 ‖ cmd_seq` (E21), also with non-zero bytes before the padding, is answered
/// ERR 6 and its `cmd_seq` is recorded (spec §8.5, D.2; reading OPEN-6).
#[test]
fn q_skey_is_err_6() {
    let mut b = Bench::vectors();
    let digest = b.digest();
    let r = cmd_raw(
        &mut b,
        "Q-46 E21",
        &[vec![OP_SKEY, 0, 0, 0, 170]],
        Expect::D2,
    );
    assert_eq!(r.err(), Some(6), "Q-46 E21: ERR 6");
    assert_eq!(
        r.raw,
        reference().case(48).output_list("resp"),
        "Q-46: = link-0048 resp"
    );
    assert_eq!(b.exec.last_cmd_seq(), 170, "Q-46 E21: cmd_seq recorded");
    let skey = vec![OP_SKEY, 0, 0, 0, 171, 0x11, 0x22, 0x33];
    let r = cmd_raw(&mut b, "Q-46 bytes before the padding", &[skey], Expect::D2);
    assert_eq!(r.err(), Some(6), "Q-46 with bytes: ERR 6");
    assert_eq!(
        b.exec.last_cmd_seq(),
        171,
        "Q-46 with bytes: cmd_seq recorded"
    );
    let r = cmd(&mut b, "Q-46 PING 171", &[Client::ping(171)], STALE);
    assert_eq!(
        r.err(),
        Some(6),
        "Q-46: the recorded cmd_seq makes 171 stale"
    );
    assert_eq!(b.digest(), digest, "Q-46: store unchanged");
}

/// Q-47 `q_cmd_seq_gap_is_accepted`: `cmd_seq` 143 then 145 (P22) are both executed (spec §9.2: strictly
/// increasing, not necessarily + 1; ADR-048 (f)).
#[test]
fn q_cmd_seq_gap_is_accepted() {
    let mut b = Bench::vectors();
    assert!(run_ping(&mut b, "Q-47 143", 143).is_ok(), "Q-47: 143 OK");
    assert!(
        run_ping(&mut b, "Q-47 P22 145", 145).is_ok(),
        "Q-47: 145 OK"
    );
    assert_eq!(b.exec.last_cmd_seq(), 145, "Q-47: last = 145");
    let r = run_queue_new(&mut b, "Q-47 QUEUE_NEW 150", 150, &Key::of(1), &Key::of(2));
    assert!(
        r.ok_queue_new().is_some(),
        "Q-47: a command after a gap is executed"
    );
}

/// Q-48 `q_cmd_seq_not_increasing_is_err_6`: a `cmd_seq` equal to `last` (E23), lower, or 0 as the first request
/// (`last` = 0) is answered with one ERR 6 and not executed (spec §9.2; reading OPEN-5).
#[test]
fn q_cmd_seq_not_increasing_is_err_6() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    let digest = b.digest();
    let first = b.client.queue_new(0, &recv, &send);
    let r = cmd(&mut b, "Q-48 cmd_seq 0 first", &[first], STALE);
    assert_eq!(r.err(), Some(6), "Q-48 0 first: ERR 6");
    assert_eq!(b.digest(), digest, "Q-48 0 first: not executed");
    assert_eq!(b.exec.last_cmd_seq(), 0, "Q-48 0 first: last stays 0");
    run_queue_new(&mut b, "Q-48 QUEUE_NEW", 5, &recv, &send);
    run_send(&mut b, "Q-48 SEND", 6, &recv, &send, &cell(1));
    let digest = b.digest();
    let stale = [
        ("E23 equal SEND", b.client.send(6, &recv, &send, &cell(2))),
        ("lower SEND", b.client.send(4, &recv, &send, &cell(3))),
        (
            "lower QUEUE_NEW",
            b.client.queue_new(1, &Key::of(3), &Key::of(4)),
        ),
        ("E23 equal PING", Client::ping(6)),
    ];
    for (name, req) in stale {
        let r = cmd(&mut b, &format!("Q-48 {name}"), &[req], STALE);
        assert_eq!(r.err(), Some(6), "Q-48 {name}: ERR 6");
        assert_eq!(b.digest(), digest, "Q-48 {name}: nothing executed");
        assert_eq!(b.exec.last_cmd_seq(), 6, "Q-48 {name}: last stays 6");
    }
}

/// Q-49 `q_cmd_seq_recorded_whatever_the_outcome`: a `SEND` answered ERR 4 at `cmd_seq` 7 records 7, so a `PING`
/// with `cmd_seq` 7 is ERR 6 (reading OPEN-5).
#[test]
fn q_cmd_seq_recorded_whatever_the_outcome() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    run_queue_new(&mut b, "Q-49 QUEUE_NEW", 1, &recv, &send);
    let (sess, sid, c) = (b.client.sess_id(), sid_of(&recv.pk, &send.pk), cell(1));
    let req = send_req(7, sid, &c, recv.sign(&msg_send(&sess, 7, &sid, &c)));
    let r = cmd(&mut b, "Q-49 SEND ERR 4 at 7", &[req], Expect::D2);
    assert_eq!(r.err(), Some(4), "Q-49: ERR 4");
    assert_eq!(b.exec.last_cmd_seq(), 7, "Q-49: 7 recorded");
    let r = cmd(&mut b, "Q-49 PING 7", &[Client::ping(7)], STALE);
    assert_eq!(r.err(), Some(6), "Q-49: ERR 6");
}

/// Q-50 `q_cmd_seq_stale_multi_frame_commands` [SQ-26]: a stale `FETCH`, `FETCH_MULTI` and `LINK_GET` are answered
/// with one ERR 6 frame each, a stale `LINK_PUT` with one ERR 6 after its third frame; none is executed (spec
/// §9.2, D.2; ADR-048 (f)).
#[test]
fn q_cmd_seq_stale_multi_frame_commands() {
    let mut b = Bench::vectors();
    let (recv, send, owner) = (Key::of(1), Key::of(2), Key::of(3));
    let (data, fresh_data) = (crate::d2::blob(1), crate::d2::blob(2));
    run_queue_new(&mut b, "Q-50 QUEUE_NEW", 1, &recv, &send);
    run_send(&mut b, "Q-50 SEND 1", 2, &recv, &send, &cell(1));
    run_send(&mut b, "Q-50 SEND 2", 3, &recv, &send, &cell(2));
    let p = Put {
        ld_id: &[1; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    run_put(&mut b, "Q-50 LINK_PUT", 4, &p);
    run_ping(&mut b, "Q-50 PING 10", 10);
    let digest = b.digest();
    let fresh = Put {
        ld_id: &[2; 16],
        blob: &fresh_data,
        ..p
    };
    let entry = b.client.fetch_entry(9, &recv, 2);
    let commands: [(&str, Vec<_>); 5] = [
        ("FETCH", vec![b.client.fetch(9, &recv, 2)]),
        ("FETCH_MULTI", vec![Client::fetch_multi(8, vec![entry])]),
        (
            "LINK_GET consume",
            vec![Client::link_get_consume(7, &[1; 16])],
        ),
        (
            "LINK_GET owner",
            vec![b.client.link_get_owner(10, &[1; 16], &owner)],
        ),
        ("LINK_PUT", b.client.link_put(5, &fresh).to_vec()),
    ];
    for (name, reqs) in commands {
        let r = cmd(&mut b, &format!("Q-50 stale {name}"), &reqs, STALE);
        assert_eq!(r.err(), Some(6), "Q-50 stale {name}: one ERR 6");
        assert_eq!(b.digest(), digest, "Q-50 stale {name}: not executed");
        assert_eq!(
            b.exec.last_cmd_seq(),
            10,
            "Q-50 stale {name}: last stays 10"
        );
    }
    let r = run_fetch(&mut b, "Q-50 fresh FETCH", 11, &recv, 0);
    assert_eq!(
        r.heads().iter().filter(|h| h.0 == 1).count(),
        2,
        "Q-50: the cells are still there"
    );
}

/// Q-51 `q_cmd_seq_u32_max`: a request with `cmd_seq` 2^32 − 1 is executed; any request after it is ERR 6 (spec
/// §9.2; reading OPEN-5).
#[test]
fn q_cmd_seq_u32_max() {
    let mut b = Bench::vectors();
    let (recv, send) = (Key::of(1), Key::of(2));
    let r = run_queue_new(&mut b, "Q-51 QUEUE_NEW at 2^32 - 1", u32::MAX, &recv, &send);
    assert!(r.ok_queue_new().is_some(), "Q-51: executed");
    assert_eq!(b.exec.last_cmd_seq(), u32::MAX, "Q-51: last = 2^32 - 1");
    let digest = b.digest();
    let after = [
        ("PING 2^32 - 1", Client::ping(u32::MAX)),
        ("PING 0", Client::ping(0)),
        (
            "SEND 2^32 - 1",
            b.client.send(u32::MAX, &recv, &send, &cell(1)),
        ),
        (
            "FETCH 2^32 - 2",
            b.client.fetch(u32::MAX.checked_sub(1).unwrap(), &recv, 0),
        ),
    ];
    for (name, req) in after {
        let r = cmd(&mut b, &format!("Q-51 {name}"), &[req], STALE);
        assert_eq!(r.err(), Some(6), "Q-51 {name}: ERR 6");
        assert_eq!(b.digest(), digest, "Q-51 {name}: not executed");
    }
}

/// Every frame of `r` echoes `seq`: in the raw payload, in the client's decoding and in [`decode_response`].
fn echoes(r: &Reply, case: &str, seq: u32, op: u8) {
    let context = if op == OP_FETCH_MULTI {
        CellrContext::FetchMulti
    } else {
        CellrContext::Fetch
    };
    assert!(!r.raw.is_empty(), "{case}: frames");
    for (i, (p, resp)) in r.raw.iter().zip(&r.resp).enumerate() {
        assert_eq!(
            p.get(1..5),
            Some(seq.to_be_bytes().as_slice()),
            "{case}: frame {i} raw echo"
        );
        assert_eq!(resp.cmd_seq, seq, "{case}: frame {i} decoded echo");
        assert_eq!(
            decode_response(p, context).cmd_seq,
            seq,
            "{case}: frame {i} re-decoded echo"
        );
    }
}

/// Q-52 `q_response_echoes_cmd_seq`: every response kind — `OK_QUEUE_NEW`, `OK_SEND`, `CELLR` of `FETCH` and
/// `FETCH_MULTI`, `OK`, `LINKR` + `CONT`, `ERR` (also the stale one) — echoes the request's `cmd_seq` in every
/// frame (D.2).
#[test]
fn q_response_echoes_cmd_seq() {
    let mut b = Bench::vectors();
    let (recv, send, owner) = (Key::of(1), Key::of(2), Key::of(3));
    let data = crate::d2::blob(3);
    let p = Put {
        ld_id: &[1; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let seqs = [
        0x0000_0101_u32,
        0x0001_0203,
        0x00ff_0000,
        0x0100_0001,
        0x1234_5678,
        0x7fff_fffe,
        0x8000_0000,
        0xdead_beef,
        0xfeed_f00d,
        0xffff_fff0,
    ];
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9] = seqs;
    echoes(
        &run_queue_new(&mut b, "Q-52 OK_QUEUE_NEW", s0, &recv, &send),
        "Q-52 OK_QUEUE_NEW",
        s0,
        1,
    );
    echoes(
        &run_send(&mut b, "Q-52 OK_SEND", s1, &recv, &send, &cell(1)),
        "Q-52 OK_SEND",
        s1,
        3,
    );
    echoes(
        &run_fetch(&mut b, "Q-52 FETCH", s2, &recv, 0),
        "Q-52 FETCH",
        s2,
        4,
    );
    echoes(
        &run_fetch_multi(&mut b, "Q-52 FETCH_MULTI", s3, &[(&recv, 0)]),
        "Q-52 FETCH_MULTI",
        s3,
        5,
    );
    echoes(
        &run_put(&mut b, "Q-52 LINK_PUT", s4, &p),
        "Q-52 LINK_PUT",
        s4,
        7,
    );
    echoes(
        &run_owner(&mut b, "Q-52 LINK_GET owner", s5, &[1; 16], &owner),
        "Q-52 LINK_GET owner",
        s5,
        8,
    );
    echoes(
        &run_consume(&mut b, "Q-52 LINK_GET consume", s6, &[1; 16]),
        "Q-52 LINK_GET consume",
        s6,
        8,
    );
    echoes(
        &cmd_raw(
            &mut b,
            "Q-52 SKEY",
            &[[vec![OP_SKEY], s7.to_be_bytes().to_vec()].concat()],
            Expect::D2,
        ),
        "Q-52 ERR",
        s7,
        2,
    );
    echoes(
        &run_queue_del(&mut b, "Q-52 QUEUE_DEL", s8, &recv),
        "Q-52 OK",
        s8,
        6,
    );
    echoes(&run_ping(&mut b, "Q-52 PING", s9), "Q-52 PING", s9, 9);
    echoes(
        &cmd(&mut b, "Q-52 stale", &[Client::ping(s0)], STALE),
        "Q-52 stale ERR 6",
        s0,
        9,
    );
}
