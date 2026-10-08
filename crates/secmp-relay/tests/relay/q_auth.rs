// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M5 (b4) Q-53 … Q-56: tokens, the D.6 signed messages, the `sess_id` binding of every signed command,
//! and the strict Ed25519 decoder rules on requests (spec §3.5, §4.1 (b), §8.3, §9.2, §9.6; D.2, D.6; ADR-048 (g);
//! OPEN-M5-04; reading OPEN-6; REF-M5 reading 3). The token is recomputed from SHA-256 alone (RFC 2104) and the
//! signed messages by plain concatenation with the labels written out here. Every answer goes through
//! [`assert_d2_shape`](crate::d2::assert_d2_shape); every rejected command also checks that the store is unchanged.

use secmp_crypto::sha256;
use secmp_proto::keys::Ed25519Sig;
use secmp_proto::link::ids;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::Request;
use secmp_proto::wire::signed::{self, LinkPutFields};

use crate::d2::{
    Expect, Peer, Reply, assert_teardown, blob, bytes, cell, cmd, cmd_raw, entry, fetch_req,
    link_get_owner_req, link_put_req, queue_del_req, queue_new_req, req_payload, run_queue_new,
    send_req,
};
use crate::fixture::{Bench, Client, EXPIRES, Key, Put, hex, reference, rid_of, sid_of};

/// HMAC-SHA-256 by RFC 2104 from SHA-256 alone (block 64 B): `H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))`.
fn hmac_rfc2104(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0_u8; 64];
    k.get_mut(..key.len()).unwrap().copy_from_slice(key);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = sha256(&[&ipad, msg]);
    sha256(&[&opad, &inner])
}

/// The spec §9.6 token: `HMAC-SHA-256(key, "SecMP-Q/1 token" ‖ sess_id ‖ u32be(cmd_seq))`, a 35-byte input.
fn spec_token(key: &[u8], sess: &Id, seq: u32) -> [u8; 32] {
    let input = [b"SecMP-Q/1 token".as_slice(), sess, &seq.to_be_bytes()].concat();
    assert_eq!(input.len(), 35, "the token input is 35 B");
    hmac_rfc2104(key, &input)
}

/// A `QUEUE_NEW` of a fresh queue with this token, honestly signed over it.
fn queue_new_with(b: &Bench, seq: u32, n: u8, tok: [u8; 32]) -> Request {
    let (recv, send) = (Key::of(n), Key::of(n.wrapping_add(100)));
    let msg = msg(
        b"SecMP-Q/1 QUEUE_NEW",
        &b.client.sess_id(),
        seq,
        &[recv.pk.as_bytes(), send.pk.as_bytes(), &tok],
    );
    queue_new_req(seq, &recv, &send, tok, recv.sign(&msg))
}

/// Q-53 `q_token_matches_spec_hmac`: the token computed here from spec §9.6 equals the client's token (and the
/// vector's); only it is accepted — a token with a flipped byte, for another `cmd_seq`, over another `sess_id`,
/// under another key, or all zero is ERR 1 (spec §9.6; ADR-048 (g)).
#[test]
fn q_token_matches_spec_hmac() {
    let mut b = Bench::vectors();
    let (sess, key) = (b.client.sess_id(), b.fx.access_key.clone());
    for q in [1_u32, 2, 0xdead_beef, u32::MAX] {
        assert_eq!(
            spec_token(&key, &sess, q),
            b.client.token(q),
            "Q-53: = the client's token ({q})"
        );
        let proto = ids::token(&b.fx.access(), &sess, q).unwrap();
        assert_eq!(
            spec_token(&key, &sess, q),
            proto,
            "Q-53: = secmp-proto's token ({q})"
        );
    }
    assert_eq!(
        spec_token(&key, &sess, 1).to_vec(),
        reference().case(6).output("token"),
        "Q-53: = link-0006 token"
    );
    let mut other = sess;
    *other.first_mut().unwrap() ^= 1;
    let flipped = |q: u32, at: usize| {
        let mut t = spec_token(&key, &sess, q);
        *t.get_mut(at).unwrap() ^= 0x80;
        t
    };
    let wrong: [(&str, u32, [u8; 32]); 6] = [
        ("byte 0 flipped", 1, flipped(1, 0)),
        ("byte 31 flipped", 2, flipped(2, 31)),
        ("for another cmd_seq", 3, spec_token(&key, &sess, 4)),
        ("over another sess_id", 4, spec_token(&key, &other, 4)),
        ("under another key", 5, spec_token(&[0x77; 32], &sess, 5)),
        ("all zero", 6, [0; 32]),
    ];
    for (n, (name, q, tok)) in (1_u8..).zip(wrong) {
        let digest = b.digest();
        let req = queue_new_with(&b, q, n, tok);
        let r = cmd(&mut b, &format!("Q-53 {name}"), &[req], Expect::D2);
        assert_eq!(r.err(), Some(1), "Q-53 {name}: ERR 1");
        assert_eq!(b.digest(), digest, "Q-53 {name}: store unchanged");
    }
    let req = queue_new_with(&b, 7, 20, spec_token(&key, &sess, 7));
    let r = cmd(&mut b, "Q-53 spec token", &[req], Expect::D2);
    assert!(
        r.ok_queue_new().is_some(),
        "Q-53: the spec token is accepted"
    );
}

/// `label ‖ sess_id ‖ u32be(cmd_seq) ‖ fields`, the whole label written out (D.6).
fn msg(label: &[u8], sess: &Id, seq: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut m = [label, sess.as_slice(), &seq.to_be_bytes()].concat();
    for f in fields {
        m.extend_from_slice(f);
    }
    m
}

/// How the relay answered a probe: `Some(true)` accepted, `Some(false)` the command's answer to a signature that
/// does not verify, `None` anything else.
type Verdict = fn(&Reply) -> Option<bool>;

/// Sign two other messages (one byte more, one byte less) and then exactly `make_msg(seq)`: the two are refused
/// with the command's signature-failure answer and change nothing, the exact one is accepted. Returns the next
/// `cmd_seq`.
fn probe(
    b: &mut Bench,
    case: &str,
    seq: u32,
    make_msg: &dyn Fn(u32) -> Vec<u8>,
    make_req: &dyn Fn(u32, Ed25519Sig) -> Vec<Request>,
    signer: &Key,
    verdict: Verdict,
) -> u32 {
    let mut q = seq;
    for name in ["one byte appended", "last byte dropped"] {
        let mut m = make_msg(q);
        if name == "one byte appended" {
            m.push(0);
        } else {
            m.pop();
        }
        let digest = b.digest();
        let r = cmd(
            b,
            &format!("{case} over {name}"),
            &make_req(q, signer.sign(&m)),
            Expect::D2,
        );
        assert_eq!(verdict(&r), Some(false), "{case} over {name}: refused");
        assert_eq!(b.digest(), digest, "{case} over {name}: store unchanged");
        q = q.checked_add(1).unwrap();
    }
    let r = cmd(
        b,
        &format!("{case} exact"),
        &make_req(q, signer.sign(&make_msg(q))),
        Expect::D2,
    );
    assert_eq!(
        verdict(&r),
        Some(true),
        "{case}: a signature over exactly the D.6 message is accepted"
    );
    q.checked_add(1).unwrap()
}

/// An ERR 4 answer is the refusal; `ok` the acceptance.
fn err4_or(r: &Reply, ok: bool) -> Option<bool> {
    if ok {
        Some(true)
    } else if r.err() == Some(4) {
        Some(false)
    } else {
        None
    }
}

/// A `CELLR` answer whose frame 1 is `present` 3 is the refusal; one without any error frame the acceptance.
fn fetch_verdict(r: &Reply) -> Option<bool> {
    let heads = r.heads();
    match heads.first().map(|h| h.0) {
        Some(3) => Some(false),
        Some(0 | 1) => Some(true),
        _ => None,
    }
}

/// The `LINK_PUT` message of D.6 (one-time, [`EXPIRES`]) with `blob_field` where `SHA-256(blob)` goes.
fn link_put_msg(
    sess: &Id,
    seq: u32,
    ld: &Id,
    owner: &Key,
    token: &[u8; 32],
    blob_field: &[u8],
) -> Vec<u8> {
    msg(
        b"SecMP-Q/1 LINK_PUT",
        sess,
        seq,
        &[
            ld,
            &[1],
            &EXPIRES.to_be_bytes(),
            owner.pk.as_bytes(),
            token,
            blob_field,
        ],
    )
}

/// The keys and values of the Q-54 commands.
struct Values {
    recv: Key,
    send: Key,
    owner: Key,
    cell: Vec<u8>,
    data: Vec<u8>,
    ld: Id,
}

/// Q-54 `q_signed_bytes_match_d6`: for the seven signed commands the signed message, concatenated here
/// (`QUEUE_NEW` 135 B, `SEND` 4146, `FETCH` 59, `MFETCH` entry 60, `QUEUE_DEL` 55, `LINK_PUT` 155 with SHA-256 of
/// the 12360-B blob, `LINK_GET` 55), equals `secmp_proto::wire::signed`'s (what the relay verifies); a signature
/// over exactly it is accepted, over any other message refused (spec §9.2, D.6).
#[test]
fn q_signed_bytes_match_d6() {
    let mut bench = Bench::vectors();
    let v = Values {
        recv: Key::of(1),
        send: Key::of(2),
        owner: Key::of(3),
        cell: cell(9),
        data: blob(9),
        ld: [9; 16],
    };
    let (sess, tok) = (bench.client.sess_id(), bench.client.token(3));
    let (rid, sid) = (rid_of(&v.recv.pk), sid_of(&v.recv.pk, &v.send.pk));
    let (ack, hash) = (5_u64.to_be_bytes(), sha256(&[&v.data]));
    let fields = LinkPutFields {
        ld_id: &v.ld,
        one_time: true,
        expires_bucket: EXPIRES,
        owner_pk: &v.owner.pk,
        token: &tok,
    };
    let typed_cell = Cell::from_bytes(&v.cell).unwrap();
    let (recv_pk, send_pk) = (v.recv.pk.as_bytes(), v.send.pk.as_bytes());
    let cases: [(&str, Vec<u8>, usize, Vec<u8>); 7] = [
        (
            "QUEUE_NEW",
            msg(b"SecMP-Q/1 QUEUE_NEW", &sess, 3, &[recv_pk, send_pk, &tok]),
            135,
            signed::queue_new(&sess, 3, &v.recv.pk, &v.send.pk, &tok).to_vec(),
        ),
        (
            "SEND",
            msg(b"SecMP-Q/1 SEND", &sess, 3, &[&sid, &v.cell]),
            4146,
            signed::send(&sess, 3, &sid, &typed_cell).to_vec(),
        ),
        (
            "FETCH",
            msg(b"SecMP-Q/1 FETCH", &sess, 3, &[&rid, &ack]),
            59,
            signed::fetch(&sess, 3, &rid, 5).to_vec(),
        ),
        (
            "MFETCH entry",
            msg(b"SecMP-Q/1 MFETCH", &sess, 3, &[&rid, &ack]),
            60,
            signed::fetch_multi_entry(&sess, 3, &rid, 5).to_vec(),
        ),
        (
            "QUEUE_DEL",
            msg(b"SecMP-Q/1 QUEUE_DEL", &sess, 3, &[&rid]),
            55,
            signed::queue_del(&sess, 3, &rid).to_vec(),
        ),
        (
            "LINK_PUT",
            link_put_msg(&sess, 3, &v.ld, &v.owner, &tok, &hash),
            155,
            signed::link_put_hashed(&sess, 3, &fields, &hash).to_vec(),
        ),
        (
            "LINK_GET",
            msg(b"SecMP-Q/1 LINK_GET", &sess, 3, &[&v.ld, &[1]]),
            55,
            signed::link_get_owner_status(&sess, 3, &v.ld).to_vec(),
        ),
    ];
    for (name, mine, len, relays) in cases {
        assert_eq!(mine.len(), len, "Q-54 {name}: {len} B");
        assert_eq!(mine, relays, "Q-54 {name}: the message the relay verifies");
    }
    signatures_over_d6_are_verified(&mut bench, &v);
}

/// The behavioural half of Q-54: the relay accepts a signature over exactly the D.6 message and refuses one over
/// any other.
fn signatures_over_d6_are_verified(bench: &mut Bench, v: &Values) {
    let tokens: Vec<[u8; 32]> = (0..40).map(|q| bench.client.token(q)).collect();
    let seq = queue_signatures_verified(bench, v, &tokens);
    link_signatures_verified(bench, v, &tokens, seq);
}

/// Q-54 for `QUEUE_NEW`, `SEND`, `FETCH` and a `FETCH_MULTI` entry; the next `cmd_seq`.
fn queue_signatures_verified(bench: &mut Bench, v: &Values, tokens: &[[u8; 32]]) -> u32 {
    let (recv, send) = (&v.recv, &v.send);
    let sess = bench.client.sess_id();
    let (rid, sid, zero) = (
        rid_of(&recv.pk),
        sid_of(&recv.pk, &send.pk),
        0_u64.to_be_bytes(),
    );
    let tok = |q: u32| *tokens.get(usize::try_from(q).unwrap()).unwrap();
    let (recv_pk, send_pk) = (recv.pk.as_bytes(), send.pk.as_bytes());
    let seq = probe(
        bench,
        "Q-54 QUEUE_NEW",
        1,
        &|q| {
            msg(
                b"SecMP-Q/1 QUEUE_NEW",
                &sess,
                q,
                &[recv_pk, send_pk, &tok(q)],
            )
        },
        &|q, sig| vec![queue_new_req(q, recv, send, tok(q), sig)],
        recv,
        |reply| err4_or(reply, reply.ok_queue_new().is_some()),
    );
    let seq = probe(
        bench,
        "Q-54 SEND",
        seq,
        &|q| msg(b"SecMP-Q/1 SEND", &sess, q, &[&sid, &v.cell]),
        &|q, sig| vec![send_req(q, sid, &v.cell, sig)],
        send,
        |reply| err4_or(reply, reply.ok_send().is_some()),
    );
    let seq = probe(
        bench,
        "Q-54 FETCH",
        seq,
        &|q| msg(b"SecMP-Q/1 FETCH", &sess, q, &[&rid, &zero]),
        &|q, sig| vec![fetch_req(q, rid, 0, sig)],
        recv,
        fetch_verdict,
    );
    let seq = probe(
        bench,
        "Q-54 MFETCH",
        seq,
        &|q| msg(b"SecMP-Q/1 MFETCH", &sess, q, &[&rid, &zero]),
        &|q, sig| vec![Client::fetch_multi(q, vec![entry(rid, 0, sig)])],
        recv,
        fetch_verdict,
    );
    // the count is not signed: an entry signed over `… ‖ count ‖ rid ‖ ack` is refused
    let counted = recv.sign(&msg(b"SecMP-Q/1 MFETCH", &sess, seq, &[&[1], &rid, &zero]));
    let req = Client::fetch_multi(seq, vec![entry(rid, 0, counted)]);
    let reply = cmd(bench, "Q-54 MFETCH with count", &[req], Expect::D2);
    assert_eq!(
        fetch_verdict(&reply),
        Some(false),
        "Q-54: the count is not signed"
    );
    seq.checked_add(1).unwrap()
}

/// Q-54 for `LINK_PUT`, `LINK_GET` (owner status) and `QUEUE_DEL`, from `cmd_seq` `seq`.
fn link_signatures_verified(bench: &mut Bench, v: &Values, tokens: &[[u8; 32]], seq: u32) {
    let (recv, owner) = (&v.recv, &v.owner);
    let (sess, rid) = (bench.client.sess_id(), rid_of(&recv.pk));
    let tok = |q: u32| *tokens.get(usize::try_from(q).unwrap()).unwrap();
    let put = Put {
        ld_id: &v.ld,
        one_time: true,
        expires_bucket: EXPIRES,
        owner,
        blob: &v.data,
    };
    // the blob enters as its SHA-256: a signature over the blob itself is refused
    let over_blob = owner.sign(&link_put_msg(&sess, seq, &v.ld, owner, &tok(seq), &v.data));
    let reqs = link_put_req(seq, &put, tok(seq), over_blob);
    let reply = cmd(bench, "Q-54 LINK_PUT over the blob", &reqs, Expect::D2);
    assert_eq!(
        reply.err(),
        Some(4),
        "Q-54: LINK_PUT signs SHA-256(blob), not the blob"
    );
    let hash = sha256(&[&v.data]);
    let seq = probe(
        bench,
        "Q-54 LINK_PUT",
        seq.checked_add(1).unwrap(),
        &|q| link_put_msg(&sess, q, &v.ld, owner, &tok(q), &hash),
        &|q, sig| link_put_req(q, &put, tok(q), sig).to_vec(),
        owner,
        |reply| err4_or(reply, reply.is_ok()),
    );
    let seq = probe(
        bench,
        "Q-54 LINK_GET",
        seq,
        &|q| msg(b"SecMP-Q/1 LINK_GET", &sess, q, &[&v.ld, &[1]]),
        &|q, sig| vec![link_get_owner_req(q, v.ld, sig)],
        owner,
        |reply| reply.linkr().map(|l| l.present == 1),
    );
    probe(
        bench,
        "Q-54 QUEUE_DEL",
        seq,
        &|q| msg(b"SecMP-Q/1 QUEUE_DEL", &sess, q, &[&rid]),
        &|q, sig| vec![queue_del_req(q, rid, sig)],
        recv,
        |reply| err4_or(reply, reply.is_ok()),
    );
}

/// Run one command on link A; its request payloads (what a replay sends byte for byte) and its answer.
fn sent(b: &mut Bench, case: &str, reqs: &[Request]) -> (Vec<Vec<u8>>, Reply) {
    let r = cmd(b, case, reqs, Expect::D2);
    (reqs.iter().map(req_payload).collect(), r)
}

/// Q-55 `q_every_signed_command_is_bound_to_sess_id` [O-4]: every signed command of link A, replayed byte for byte
/// on a second link whose `last` is below the replayed `cmd_seq`, fails: ERR 1 for `QUEUE_NEW` and `LINK_PUT`
/// (after frame 3; the `sess_id`-bound token fails before the signature), ERR 4 for `SEND` and `QUEUE_DEL`,
/// `present` 3 for `FETCH` and each `FETCH_MULTI` entry, `LINKR` {0, 0} for owner status (spec §8.3, §9.2, §9.6;
/// OPEN-M5-04).
#[test]
fn q_every_signed_command_is_bound_to_sess_id() {
    let mut b = Bench::vectors();
    let (r1, s1, r2, s2, owner) = (Key::of(1), Key::of(2), Key::of(3), Key::of(4), Key::of(5));
    let data = blob(5);
    let p = Put {
        ld_id: &[5; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let (q1, q2) = (rid_of(&r1.pk), rid_of(&r2.pk));
    let reqs = [b.client.queue_new(1, &r1, &s1)];
    let (qn, r) = sent(&mut b, "Q-55 A QUEUE_NEW", &reqs);
    assert!(r.ok_queue_new().is_some(), "Q-55: link A QUEUE_NEW");
    let reqs = [b.client.send(2, &r1, &s1, &cell(1))];
    let (snd, r) = sent(&mut b, "Q-55 A SEND", &reqs);
    assert!(r.ok_send().is_some(), "Q-55: link A SEND");
    let reqs = [b.client.fetch(3, &r1, 0)];
    let (fet, _) = sent(&mut b, "Q-55 A FETCH", &reqs);
    run_queue_new(&mut b, "Q-55 A QUEUE_NEW 2", 4, &r2, &s2);
    let reqs = [Client::fetch_multi(
        5,
        vec![
            b.client.fetch_entry(5, &r1, 0),
            b.client.fetch_entry(5, &r2, 0),
        ],
    )];
    let (mf, _) = sent(&mut b, "Q-55 A FETCH_MULTI", &reqs);
    let reqs = b.client.link_put(6, &p);
    let (put, r) = sent(&mut b, "Q-55 A LINK_PUT", &reqs);
    assert!(r.is_ok(), "Q-55: link A LINK_PUT");
    let reqs = [b.client.link_get_owner(7, &[5; 16], &owner)];
    let (own, _) = sent(&mut b, "Q-55 A owner status", &reqs);
    let reqs = [b.client.queue_del(8, &r1)];
    let (del, r) = sent(&mut b, "Q-55 A QUEUE_DEL", &reqs);
    assert!(r.is_ok(), "Q-55: link A QUEUE_DEL");
    // re-created, so that the replayed QUEUE_DEL meets its queue
    run_queue_new(&mut b, "Q-55 A re-create", 9, &r1, &s1);
    let mut peer = Peer::new(&b.relay, &b.fx, 0x55);
    assert_ne!(
        peer.client.sess_id(),
        b.client.sess_id(),
        "Q-55: another link"
    );
    let digest = b.digest();
    let mut replay = |name: &str, payloads: &[Vec<u8>]| -> Reply {
        let seq = u32::from_be_bytes(bytes(payloads.first().unwrap(), 1));
        assert!(
            peer.exec.last_cmd_seq() < seq,
            "Q-55 {name}: last below the replayed cmd_seq"
        );
        let r = cmd_raw(
            &mut peer.on(&b.relay),
            &format!("Q-55 replayed {name}"),
            payloads,
            Expect::D2,
        );
        assert_eq!(b.digest(), digest, "Q-55 {name}: store unchanged");
        r
    };
    assert_eq!(
        replay("QUEUE_NEW", &qn).err(),
        Some(1),
        "Q-55 QUEUE_NEW: ERR 1"
    );
    assert_eq!(replay("SEND", &snd).err(), Some(4), "Q-55 SEND: ERR 4");
    assert_eq!(
        replay("FETCH", &fet).heads().first().copied(),
        Some((3, q1, 0)),
        "Q-55 FETCH: present 3"
    );
    let heads = replay("FETCH_MULTI", &mf).heads();
    assert_eq!(
        heads.get(..2),
        Some([(3, q1, 0), (3, q2, 0)].as_slice()),
        "Q-55 FETCH_MULTI: present 3 each"
    );
    assert_eq!(
        replay("LINK_PUT", &put).err(),
        Some(1),
        "Q-55 LINK_PUT: ERR 1 after frame 3"
    );
    let l = replay("owner status", &own).linkr().unwrap();
    assert_eq!(
        (l.present, l.consumed),
        (0, 0),
        "Q-55 owner status: LINKR {{0, 0}}"
    );
    assert_eq!(
        replay("QUEUE_DEL", &del).err(),
        Some(4),
        "Q-55 QUEUE_DEL: ERR 4"
    );
}

/// L = 2^252 + 27742317777372353535851937790883648493, little-endian (spec §3.5).
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `S + L` as 256-bit little-endian integers (`S < L`, so no carry leaves the 32 bytes).
fn s_plus_l(s: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut carry = false;
    for ((o, a), l) in out.iter_mut().zip(s).zip(L) {
        let (x, c1) = a.overflowing_add(l);
        let (x, c2) = x.overflowing_add(u8::from(carry));
        *o = x;
        carry = c1 || c2;
    }
    assert!(!carry, "S + L fits 32 bytes");
    out
}

/// `y` with the sign bit of x set.
fn signed_x(mut y: [u8; 32]) -> [u8; 32] {
    *y.last_mut().unwrap() |= 0x80;
    y
}

/// The eight encodings of the points of order dividing 8 (spec §3.5): the identity, the point of order 2, the two
/// of order 4, the four of order 8.
fn small_order() -> Vec<[u8; 32]> {
    let mut identity = [0_u8; 32];
    *identity.first_mut().unwrap() = 1;
    let mut order2 = [0xff_u8; 32];
    *order2.first_mut().unwrap() = 0xec;
    *order2.last_mut().unwrap() = 0x7f;
    let mut all = vec![identity, order2, [0; 32], signed_x([0; 32])];
    for y in ORDER_8_Y {
        all.extend([y, signed_x(y)]);
    }
    all
}

/// The two y-coordinates of the points of order 8 (little-endian, sign bit clear).
const ORDER_8_Y: [[u8; 32]; 2] = [
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
];

/// Encodings with y ≥ p = 2^255 − 19: y = p, p + 1, p + 3, 2^255 − 1, and p + 3 with the sign bit.
fn non_canonical() -> Vec<[u8; 32]> {
    let with_low = |b: u8| {
        let mut y = [0xff_u8; 32];
        *y.first_mut().unwrap() = b;
        *y.last_mut().unwrap() = 0x7f;
        y
    };
    vec![
        with_low(0xed),
        with_low(0xee),
        with_low(0xf0),
        with_low(0xff),
        signed_x(with_low(0xf0)),
    ]
}

/// `p` with `with` written at `at`.
fn replaced(p: &[u8], at: usize, with: &[u8]) -> Vec<u8> {
    let mut v = p.to_vec();
    v.get_mut(at..at.checked_add(with.len()).unwrap())
        .unwrap()
        .copy_from_slice(with);
    v
}

/// The signed commands of link A with the offset of their `sig` in the first payload (D.2): name, the request
/// payloads (three for `LINK_PUT`), offset.
fn signed_commands() -> Vec<(&'static str, Vec<Vec<u8>>, usize)> {
    let b = Bench::vectors();
    let (recv, send, owner, data) = (Key::of(1), Key::of(2), Key::of(3), blob(3));
    let p = Put {
        ld_id: &[3; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let one = |r: &Request| vec![req_payload(r)];
    vec![
        ("QUEUE_NEW", one(&b.client.queue_new(1, &recv, &send)), 101),
        ("SEND", one(&b.client.send(1, &recv, &send, &cell(1))), 4117),
        ("FETCH", one(&b.client.fetch(1, &recv, 0)), 29),
        (
            "FETCH_MULTI entry",
            one(&Client::fetch_multi(
                1,
                vec![b.client.fetch_entry(1, &recv, 0)],
            )),
            30,
        ),
        ("QUEUE_DEL", one(&b.client.queue_del(1, &recv)), 21),
        (
            "LINK_PUT",
            b.client.link_put(1, &p).iter().map(req_payload).collect(),
            90,
        ),
        (
            "LINK_GET owner status",
            one(&b.client.link_get_owner(1, &[3; 16], &owner)),
            22,
        ),
    ]
}

/// Q-56 `q_strict_ed25519_on_requests_tears_down`: a request whose `sig` has S + L, a small-order R or an R with
/// y ≥ p, or whose `recv_pk`, `send_pk` or `owner_pk` is of small order or has y ≥ p, is a decoder failure: the
/// link is torn down (spec §4.1 (b), §8.5; ADR-048 (g); reading OPEN-6; REF-M5 reading 3). The honest commands are
/// answered.
#[test]
fn q_strict_ed25519_on_requests_tears_down() {
    let commands = signed_commands();
    for (name, payloads, at) in &commands {
        cmd_raw(
            &mut Bench::vectors(),
            &format!("Q-56 {name} honest"),
            payloads,
            Expect::D2,
        );
        let first = payloads.first().unwrap();
        let s_at = at.checked_add(32).unwrap();
        let s = first.get(s_at..s_at.checked_add(32).unwrap()).unwrap();
        let mut bad = vec![(
            format!("{name} sig S + L"),
            replaced(first, s_at, &s_plus_l(s)),
        )];
        for r in small_order() {
            bad.push((
                format!("{name} sig R small-order {}", hex(&r)),
                replaced(first, *at, &r),
            ));
        }
        for r in non_canonical() {
            bad.push((
                format!("{name} sig R y >= p {}", hex(&r)),
                replaced(first, *at, &r),
            ));
        }
        for (case, payload) in bad {
            assert_teardown(&mut Bench::vectors(), &format!("Q-56 {case}"), &payload);
        }
    }
    for (name, i, at) in [
        ("QUEUE_NEW recv_pk", 0, 5),
        ("QUEUE_NEW send_pk", 0, 37),
        ("LINK_PUT owner_pk", 5, 26),
    ] {
        let first = commands.get(i).unwrap().1.first().unwrap();
        for k in small_order().into_iter().chain(non_canonical()) {
            assert_teardown(
                &mut Bench::vectors(),
                &format!("Q-56 {name} {}", hex(&k)),
                &replaced(first, at, &k),
            );
        }
    }
}
