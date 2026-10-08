// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M5 (b4) Q-57 … Q-60: the response shape over every command and outcome, request order under
//! pipelining, the response field rules, and the request decoder rules (spec §4.1, §9.3, §9.7 items 6 and 7, §10.3;
//! D.2; ADR-048 (f), SQ-26; REF-M2 reading 5; reading OPEN-6). Q-57 and Q-59 share one scenario that reaches every
//! outcome of every command; every answer in it goes through [`assert_d2_shape`](crate::d2::assert_d2_shape).

use std::collections::BTreeSet;

use secmp_proto::wire::Id;
use secmp_proto::wire::frame::Request;
use secmp_relay::Outcome;
use secmp_relay::budget::{LINKDATA_RESERVATION, QUEUE_RESERVATION};

use crate::d2::{
    CELLR, DUMMY, Expect, LINKR, OK_SEND, OP_FETCH, OP_FETCH_MULTI, OP_LINK_GET, OP_LINK_PUT,
    OP_PING, OP_QUEUE_DEL, OP_QUEUE_NEW, OP_SEND, OP_SKEY, Reply, STALE, Seq, assert_d2_shape,
    assert_teardown, be64, blob, byte, bytes, cell, cmd_raw, entry, feed, fetch_req, limits,
    link_get_owner_req, link_put_req, msg_fetch, msg_link_get, msg_link_put, msg_queue_del,
    msg_queue_new, msg_send, queue_del_req, queue_new_req, req_payload, run_queue_new, run_send,
    send_req,
};
use crate::fixture::{Bench, Client, EXPIRES, Key, Put, flip, lots, now, rid_of, sid_of};

/// The outcome labels of an answer (one per `CELLR` frame).
fn labels(r: &Reply) -> Vec<String> {
    if let Some(c) = r.err() {
        return vec![format!("ERR {c}")];
    }
    if r.is_ok() {
        return vec!["OK".to_owned()];
    }
    if r.ok_queue_new().is_some() {
        return vec!["OK_QUEUE_NEW".to_owned()];
    }
    if let Some((_, evicted, _)) = r.ok_send() {
        return vec![format!("OK_SEND evicted {evicted}")];
    }
    if let Some(l) = r.linkr() {
        return vec![format!("LINKR {}{}", l.present, l.consumed)];
    }
    r.heads()
        .iter()
        .map(|h| format!("present {}", h.0))
        .collect()
}

/// One answer of the scenario: the case, its request payloads and the answer.
struct Logged {
    case: String,
    payloads: Vec<Vec<u8>>,
    reply: Reply,
}

/// The scenario: a relay with two queue and two link-data reservations and no rate limits; every outcome seen,
/// per request opcode.
struct Scenario {
    b: Bench,
    s: Seq,
    seen: BTreeSet<(u8, String)>,
    log: Vec<Logged>,
}

impl Scenario {
    fn new() -> Self {
        let queues = QUEUE_RESERVATION.checked_mul(2);
        let linkdata = LINKDATA_RESERVATION.checked_mul(2);
        Self {
            b: Bench::new(limits(queues, linkdata)),
            s: Seq::default(),
            seen: BTreeSet::new(),
            log: Vec::new(),
        }
    }

    fn q(&mut self) -> u32 {
        self.s.fresh()
    }

    fn sess(&self) -> Id {
        self.b.client.sess_id()
    }

    /// Run a command (request payloads) with `expect`; its outcome must include `want`; record it.
    fn go(&mut self, case: &str, payloads: Vec<Vec<u8>>, expect: Expect, want: &str) {
        let op = byte(payloads.first().unwrap(), 0);
        let r = cmd_raw(&mut self.b, case, &payloads, expect);
        let mut got = labels(&r);
        if expect == STALE {
            got = vec!["stale".to_owned()];
        }
        assert!(
            got.iter().any(|l| l == want),
            "{case}: outcome {want} (got {got:?})"
        );
        self.seen.extend(got.into_iter().map(|l| (op, l)));
        self.log.push(Logged {
            case: case.to_owned(),
            payloads,
            reply: r,
        });
    }

    /// [`Scenario::go`] of requests.
    fn req(&mut self, case: &str, reqs: &[Request], want: &str) {
        self.go(
            case,
            reqs.iter().map(req_payload).collect(),
            Expect::D2,
            want,
        );
    }

    /// The whole scenario.
    fn full() -> Self {
        let mut sc = Self::new();
        sc.queue_new_and_send();
        sc.fetches();
        sc.link_puts();
        sc.link_gets();
        sc.queue_del_ping_skey();
        sc.eviction();
        sc.stale();
        sc
    }
}

/// Queue A = (1, 2), queue B = (3, 4); link data L = [1; 16] (owner 9).
fn keys() -> [Key; 5] {
    [Key::of(1), Key::of(2), Key::of(3), Key::of(4), Key::of(9)]
}

impl Scenario {
    fn queue_new_and_send(&mut self) {
        let [ra, sa, rb, sb, _] = keys();
        let q = self.q();
        let req = self.b.client.queue_new(q, &ra, &sa);
        self.req("Q-57 QUEUE_NEW OK", &[req], "OK_QUEUE_NEW");
        let q = self.q();
        let (r, s) = (Key::of(20), Key::of(21));
        let tok: [u8; 32] = flip(&self.b.client.token(q), 0).try_into().unwrap();
        let sig = r.sign(&msg_queue_new(&self.sess(), q, &r, &s, &tok));
        self.req(
            "Q-57 QUEUE_NEW ERR 1",
            &[queue_new_req(q, &r, &s, tok, sig)],
            "ERR 1",
        );
        let q = self.q();
        let req = self.b.client.queue_new(q, &ra, &Key::of(22));
        self.req("Q-57 QUEUE_NEW ERR 4", &[req], "ERR 4");
        let q = self.q();
        let req = self.b.client.queue_new(q, &rb, &sb);
        self.req("Q-57 QUEUE_NEW B", &[req], "OK_QUEUE_NEW");
        let q = self.q();
        let req = self.b.client.queue_new(q, &Key::of(23), &Key::of(24));
        self.req("Q-57 QUEUE_NEW ERR 2", &[req], "ERR 2");
        let q = self.q();
        let req = self.b.client.send(q, &ra, &sa, &cell(1));
        self.req("Q-57 SEND OK", &[req], "OK_SEND evicted 0");
        let q = self.q();
        let req = self.b.client.send(q, &Key::of(25), &Key::of(26), &cell(2));
        self.req("Q-57 SEND ERR 3", &[req], "ERR 3");
        let q = self.q();
        let sid = sid_of(&ra.pk, &sa.pk);
        let sig = ra.sign(&msg_send(&self.sess(), q, &sid, &cell(3)));
        self.req(
            "Q-57 SEND ERR 4",
            &[send_req(q, sid, &cell(3), sig)],
            "ERR 4",
        );
    }

    fn fetches(&mut self) {
        let [ra, sa, rb, _, _] = keys();
        let (a, sess) = (rid_of(&ra.pk), self.sess());
        let q = self.q();
        let req = self.b.client.fetch(q, &rb, 0);
        self.req("Q-57 FETCH empty", &[req], "present 0");
        let q = self.q();
        let req = self.b.client.fetch(q, &ra, 0);
        self.req("Q-57 FETCH cells", &[req], "present 1");
        let q = self.q();
        let req = self.b.client.fetch(q, &Key::of(27), 0);
        self.req("Q-57 FETCH present 2", &[req], "present 2");
        let q = self.q();
        let sig = sa.sign(&msg_fetch("FETCH", &sess, q, &a, 0));
        self.req(
            "Q-57 FETCH present 3",
            &[fetch_req(q, a, 0, sig)],
            "present 3",
        );
        let q = self.q();
        let req = self.b.client.fetch(q, &ra, 2);
        self.req("Q-57 FETCH present 4", &[req], "present 4");
        let q = self.q();
        let entries = vec![
            self.b.client.fetch_entry(q, &Key::of(27), 0),
            entry(a, 0, sa.sign(&msg_fetch("MFETCH", &sess, q, &a, 0))),
            self.b.client.fetch_entry(q, &rb, 1),
            self.b.client.fetch_entry(q, &ra, 0),
        ];
        let req = Client::fetch_multi(q, entries);
        self.req("Q-57 FETCH_MULTI present 0-4", &[req], "present 4");
    }

    fn link_puts(&mut self) {
        let [_, _, _, _, owner] = keys();
        let (data, sess) = (blob(1), self.sess());
        let p = Put {
            ld_id: &[1; 16],
            one_time: true,
            expires_bucket: EXPIRES,
            owner: &owner,
            blob: &data,
        };
        let q = self.q();
        let reqs = self.b.client.link_put(q, &p);
        self.req("Q-57 LINK_PUT OK", &reqs, "OK");
        let q = self.q();
        let bad: [u8; 32] = flip(&self.b.client.token(q), 0).try_into().unwrap();
        let sig = owner.sign(&msg_link_put(&sess, q, &p, &bad));
        self.req(
            "Q-57 LINK_PUT ERR 1",
            &link_put_req(q, &p, bad, sig),
            "ERR 1",
        );
        let q = self.q();
        let tok = self.b.client.token(q);
        let sig = Key::of(28).sign(&msg_link_put(&sess, q, &p, &tok));
        self.req(
            "Q-57 LINK_PUT ERR 4",
            &link_put_req(q, &p, tok, sig),
            "ERR 4",
        );
        let q = self.q();
        let reqs = self.b.client.link_put(q, &p);
        self.req("Q-57 LINK_PUT ERR 5", &reqs, "ERR 5");
        let late = Put {
            ld_id: &[2; 16],
            // now_bucket 472 222 + 721: past now_bucket + LINKDATA_TTL (ADR-048 (o))
            expires_bucket: 472_943,
            ..p
        };
        let q = self.q();
        let reqs = self.b.client.link_put(q, &late);
        self.req("Q-57 LINK_PUT ERR 6", &reqs, "ERR 6");
        let q = self.q();
        let reqs = self.b.client.link_put(
            q,
            &Put {
                ld_id: &[2; 16],
                ..p
            },
        );
        self.req("Q-57 LINK_PUT second", &reqs, "OK");
        let q = self.q();
        let reqs = self.b.client.link_put(
            q,
            &Put {
                ld_id: &[3; 16],
                ..p
            },
        );
        self.req("Q-57 LINK_PUT ERR 2", &reqs, "ERR 2");
    }

    fn link_gets(&mut self) {
        let [_, _, _, _, owner] = keys();
        let (ld, sess) = ([1_u8; 16], self.sess());
        let q = self.q();
        let req = self.b.client.link_get_owner(q, &ld, &owner);
        self.req("Q-57 owner status 10", &[req], "LINKR 10");
        let q = self.q();
        let sig = Key::of(29).sign(&msg_link_get(&sess, q, &ld));
        self.req(
            "Q-57 owner status 00",
            &[link_get_owner_req(q, ld, sig)],
            "LINKR 00",
        );
        let q = self.q();
        self.req(
            "Q-57 consume 10",
            &[Client::link_get_consume(q, &ld)],
            "LINKR 10",
        );
        let q = self.q();
        self.req(
            "Q-57 consume 01",
            &[Client::link_get_consume(q, &ld)],
            "LINKR 01",
        );
        let q = self.q();
        self.req(
            "Q-57 consume 00",
            &[Client::link_get_consume(q, &[9; 16])],
            "LINKR 00",
        );
        let q = self.q();
        let req = self.b.client.link_get_owner(q, &ld, &owner);
        self.req("Q-57 owner status 01", &[req], "LINKR 01");
    }

    fn queue_del_ping_skey(&mut self) {
        let [ra, sa, _, _, _] = keys();
        let (a, sess) = (rid_of(&ra.pk), self.sess());
        let q = self.q();
        let req = self.b.client.queue_del(q, &Key::of(30));
        self.req("Q-57 QUEUE_DEL ERR 3", &[req], "ERR 3");
        let q = self.q();
        let sig = sa.sign(&msg_queue_del(&sess, q, &a));
        self.req("Q-57 QUEUE_DEL ERR 4", &[queue_del_req(q, a, sig)], "ERR 4");
        let q = self.q();
        let req = self.b.client.queue_del(q, &ra);
        self.req("Q-57 QUEUE_DEL OK", &[req], "OK");
        let q = self.q();
        self.req("Q-57 PING", &[Client::ping(q)], "OK");
        let q = self.q();
        let skey = [vec![OP_SKEY], q.to_be_bytes().to_vec()].concat();
        self.go("Q-57 SKEY", vec![skey], Expect::D2, "ERR 6");
    }

    /// B is filled to capacity; the next SEND evicts.
    fn eviction(&mut self) {
        let [_, _, rb, sb, _] = keys();
        for i in 0..128 {
            let q = self.q();
            let r = run_send(
                &mut self.b,
                &format!("Q-57 fill B {i}"),
                q,
                &rb,
                &sb,
                &cell(4),
            );
            assert!(r.ok_send().is_some(), "Q-57 fill B {i}");
        }
        let q = self.q();
        let req = self.b.client.send(q, &rb, &sb, &cell(5));
        self.req("Q-57 SEND evicting", &[req], "OK_SEND evicted 1");
    }

    /// Every command again with `cmd_seq` 1 (stale): one ERR 6 frame each.
    fn stale(&mut self) {
        let [ra, sa, rb, _, owner] = keys();
        let data = blob(2);
        let p = Put {
            ld_id: &[4; 16],
            one_time: true,
            expires_bucket: EXPIRES,
            owner: &owner,
            blob: &data,
        };
        let c = &self.b.client;
        let commands: Vec<(&str, Vec<Request>)> = vec![
            (
                "QUEUE_NEW",
                vec![c.queue_new(1, &Key::of(31), &Key::of(32))],
            ),
            ("SEND", vec![c.send(1, &ra, &sa, &cell(6))]),
            ("FETCH", vec![c.fetch(1, &rb, 0)]),
            (
                "FETCH_MULTI",
                vec![Client::fetch_multi(1, vec![c.fetch_entry(1, &rb, 0)])],
            ),
            ("QUEUE_DEL", vec![c.queue_del(1, &rb)]),
            ("LINK_PUT", c.link_put(1, &p).to_vec()),
            ("LINK_GET", vec![Client::link_get_consume(1, &[2; 16])]),
            ("PING", vec![Client::ping(1)]),
        ];
        for (name, reqs) in commands {
            let payloads = reqs.iter().map(req_payload).collect();
            self.go(&format!("Q-57 stale {name}"), payloads, STALE, "stale");
        }
    }
}

/// The outcomes every command must have shown (TEST-SPEC-M5 Q-57: success, ERR 1–6, `present` 0–4, `LINKR`
/// {0, 0}/{0, 1}/{1, 0}, and the stale exception).
fn required() -> Vec<(u8, &'static str)> {
    let mut v = vec![
        (OP_QUEUE_NEW, "OK_QUEUE_NEW"),
        (OP_QUEUE_NEW, "ERR 1"),
        (OP_QUEUE_NEW, "ERR 2"),
        (OP_QUEUE_NEW, "ERR 4"),
        (OP_SKEY, "ERR 6"),
        (OP_SEND, "OK_SEND evicted 0"),
        (OP_SEND, "OK_SEND evicted 1"),
        (OP_SEND, "ERR 3"),
        (OP_SEND, "ERR 4"),
        (OP_QUEUE_DEL, "OK"),
        (OP_QUEUE_DEL, "ERR 3"),
        (OP_QUEUE_DEL, "ERR 4"),
        (OP_LINK_PUT, "OK"),
        (OP_LINK_PUT, "ERR 1"),
        (OP_LINK_PUT, "ERR 2"),
        (OP_LINK_PUT, "ERR 4"),
        (OP_LINK_PUT, "ERR 5"),
        (OP_LINK_PUT, "ERR 6"),
        (OP_LINK_GET, "LINKR 00"),
        (OP_LINK_GET, "LINKR 01"),
        (OP_LINK_GET, "LINKR 10"),
        (OP_PING, "OK"),
    ];
    for op in [OP_FETCH, OP_FETCH_MULTI] {
        for p in [
            "present 0",
            "present 1",
            "present 2",
            "present 3",
            "present 4",
        ] {
            v.push((op, p));
        }
    }
    for op in [
        OP_QUEUE_NEW,
        OP_SEND,
        OP_FETCH,
        OP_FETCH_MULTI,
        OP_QUEUE_DEL,
        OP_LINK_PUT,
        OP_LINK_GET,
        OP_PING,
    ] {
        v.push((op, "stale"));
    }
    v
}

/// Q-57 `q_every_response_is_d2_count_of_4352_byte_frames` [SQ-26]: every command × every reachable outcome
/// (success, ERR 1–6, `present` 0–4, `LINKR` {0, 0}/{0, 1}/{1, 0}) is answered with the D.2 count of 4352-byte
/// frames right after its last request frame — one ERR 6 for a stale `cmd_seq` (spec §9.3, §9.7 item 6, D.2;
/// ADR-048 (f)).
#[test]
fn q_every_response_is_d2_count_of_4352_byte_frames() {
    let sc = Scenario::full();
    for (op, outcome) in required() {
        assert!(
            sc.seen.contains(&(op, outcome.to_owned())),
            "Q-57: opcode {op:#04x} reached outcome {outcome}"
        );
    }
    for l in &sc.log {
        let op = byte(l.payloads.first().unwrap(), 0);
        let stale = l.case.contains("stale");
        let want = if stale { 1 } else { crate::d2::d2_count(op) };
        assert_eq!(l.reply.raw.len(), want, "{}: frame count", l.case);
    }
}

/// The `rid`s a `FETCH` or `FETCH_MULTI` request names.
fn requested_rids(payload: &[u8]) -> Vec<Id> {
    match byte(payload, 0) {
        OP_FETCH => vec![bytes(payload, 5)],
        OP_FETCH_MULTI => (0..usize::from(byte(payload, 5)))
            .map(|i| {
                bytes(
                    payload,
                    i.checked_mul(88).and_then(|o| o.checked_add(6)).unwrap(),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Q-59 `q_response_field_rules`: in every response the relay built in the Q-57 scenario, a `CELLR` with `present`
/// 0 has `rid` 0 and `cell_id` 0; `present` 2–4 the requested `rid` and `cell_id` 0; `present` 1 to `FETCH` `rid` 0
/// (to `FETCH_MULTI` a requested `rid`); `LINKR` flags are 0 or 1; `OK_SEND` `evicted_id` is 0 iff
/// `evicted_present` is 0 (D.2).
#[test]
fn q_response_field_rules() {
    let sc = Scenario::full();
    let mut variants: BTreeSet<&str> = BTreeSet::new();
    for l in &sc.log {
        let head = l.payloads.first().unwrap();
        let (op, rids) = (byte(head, 0), requested_rids(head));
        for p in &l.reply.raw {
            let case = &l.case;
            match byte(p, 0) {
                CELLR => {
                    let (present, rid, cell_id) = (byte(p, 5), bytes::<16>(p, 6), be64(p, 22));
                    let fits = match (present, op) {
                        (0, _) => rid == [0; 16] && cell_id == 0,
                        (1, OP_FETCH) => rid == [0; 16] && cell_id >= 1,
                        (1, _) => rids.contains(&rid) && cell_id >= 1,
                        (2..=4, _) => rids.contains(&rid) && cell_id == 0,
                        _ => false,
                    };
                    assert!(fits, "{case}: CELLR present {present} field rules");
                    variants.insert(match (present, op) {
                        (0, _) => "CELLR present 0",
                        (1, OP_FETCH) => "CELLR present 1 FETCH",
                        (1, _) => "CELLR present 1 FETCH_MULTI",
                        _ => "CELLR present 2-4",
                    });
                }
                LINKR => {
                    assert!(
                        byte(p, 5) <= 1 && byte(p, 6) <= 1,
                        "{case}: LINKR flags 0 or 1"
                    );
                    variants.insert("LINKR");
                }
                OK_SEND => {
                    let (present, evicted) = (byte(p, 13), be64(p, 14));
                    assert!(present <= 1, "{case}: evicted_present 0 or 1");
                    assert_eq!(
                        present == 0,
                        evicted == 0,
                        "{case}: evicted_id 0 iff evicted_present 0"
                    );
                    variants.insert(if present == 0 {
                        "OK_SEND 0"
                    } else {
                        "OK_SEND 1"
                    });
                }
                _ => {}
            }
        }
    }
    let all = [
        "CELLR present 0",
        "CELLR present 1 FETCH",
        "CELLR present 1 FETCH_MULTI",
        "CELLR present 2-4",
        "LINKR",
        "OK_SEND 0",
        "OK_SEND 1",
    ];
    assert_eq!(
        variants,
        all.into_iter().collect::<BTreeSet<_>>(),
        "Q-59: every response variant checked"
    );
}

/// Q-58 `q_responses_in_request_order_when_pipelined`: a `FETCH` and a `SEND` sealed back to back, and a three-frame
/// `LINK_PUT` followed by a `FETCH`, are answered in request order (D.2, spec §9.7 item 6, §10.3): the client opens
/// the answers at consecutive counters in that order, and the `FETCH` ran before the `SEND`.
#[test]
fn q_responses_in_request_order_when_pipelined() {
    let mut bench = Bench::vectors();
    let (recv, sender, owner, data) = (Key::of(1), Key::of(2), Key::of(3), blob(3));
    run_queue_new(&mut bench, "Q-58 QUEUE_NEW", 1, &recv, &sender);
    run_send(&mut bench, "Q-58 SEND 1", 2, &recv, &sender, &cell(1));
    let fetch = bench.client.fetch(3, &recv, 0);
    let push = bench.client.send(4, &recv, &sender, &cell(2));
    let frames = vec![bench.client.seal(&fetch), bench.client.seal(&push)];
    let mut outs = feed(&mut bench, &frames, now(), &mut lots()).into_iter();
    let first: Vec<Outcome> = outs.next().into_iter().collect();
    let fetched = assert_d2_shape(
        "Q-58 FETCH",
        &mut bench.client,
        OP_FETCH,
        3,
        first,
        Expect::D2,
    );
    let second: Vec<Outcome> = outs.next().into_iter().collect();
    let pushed = assert_d2_shape(
        "Q-58 SEND",
        &mut bench.client,
        OP_SEND,
        4,
        second,
        Expect::D2,
    );
    let only_1 = vec![(1, [0; 16], 1), DUMMY, DUMMY, DUMMY];
    assert_eq!(fetched.heads(), only_1, "Q-58: the FETCH ran first");
    assert_eq!(pushed.ok_send(), Some((2, 0, 0)), "Q-58: then the SEND");
    let put = Put {
        ld_id: &[1; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let reqs = bench.client.link_put(5, &put);
    let fetch = bench.client.fetch(6, &recv, 0);
    let frames: Vec<Vec<u8>> = reqs
        .iter()
        .chain([&fetch])
        .map(|req| bench.client.seal(req))
        .collect();
    let mut outs: Vec<Outcome> = feed(&mut bench, &frames, now(), &mut lots());
    let after = outs.split_off(3);
    let stored = assert_d2_shape(
        "Q-58 LINK_PUT",
        &mut bench.client,
        OP_LINK_PUT,
        5,
        outs,
        Expect::D2,
    );
    assert!(
        stored.is_ok(),
        "Q-58: LINK_PUT answered after its third frame"
    );
    let fetched = assert_d2_shape(
        "Q-58 FETCH after",
        &mut bench.client,
        OP_FETCH,
        6,
        after,
        Expect::D2,
    );
    let both = vec![(1, [0; 16], 1), (1, [0; 16], 2), DUMMY, DUMMY];
    assert_eq!(fetched.heads(), both, "Q-58: then the FETCH");
}

/// Q-60 `q_request_decoder_rules_tear_down`: `LINK_PUT` with `one_time` 2 or 0xFF, and `QUEUE_NEW`, `SEND`,
/// `FETCH`, `QUEUE_DEL`, `LINK_GET` and `PING` payloads with one extra non-zero byte after the last field (then
/// 0x80 and zeros), tear the link down (spec §4.1 boolean and consistency rules, §9.7 item 7; REF-M2 reading 5;
/// reading OPEN-6); the honest payloads are answered.
#[test]
fn q_request_decoder_rules_tear_down() {
    let b = Bench::vectors();
    let (recv, send, owner, data) = (Key::of(1), Key::of(2), Key::of(3), blob(3));
    let p = Put {
        ld_id: &[3; 16],
        one_time: true,
        expires_bucket: EXPIRES,
        owner: &owner,
        blob: &data,
    };
    let put: Vec<Vec<u8>> = b.client.link_put(1, &p).iter().map(req_payload).collect();
    cmd_raw(
        &mut Bench::vectors(),
        "Q-60 LINK_PUT honest",
        &put,
        Expect::D2,
    );
    for v in [2_u8, 0xff] {
        let mut frame1 = put.first().unwrap().clone();
        *frame1.get_mut(21).unwrap() = v;
        assert_teardown(
            &mut Bench::vectors(),
            &format!("Q-60 LINK_PUT one_time {v:#04x}"),
            &frame1,
        );
    }
    let singles = [
        ("QUEUE_NEW", b.client.queue_new(1, &recv, &send)),
        ("SEND", b.client.send(1, &recv, &send, &cell(1))),
        ("FETCH", b.client.fetch(1, &recv, 0)),
        ("QUEUE_DEL", b.client.queue_del(1, &recv)),
        ("LINK_GET consume", Client::link_get_consume(1, &[3; 16])),
        (
            "LINK_GET owner status",
            b.client.link_get_owner(1, &[3; 16], &owner),
        ),
        ("PING", Client::ping(1)),
    ];
    for (name, req) in singles {
        let payload = req_payload(&req);
        let honest = std::slice::from_ref(&payload);
        cmd_raw(
            &mut Bench::vectors(),
            &format!("Q-60 {name} honest"),
            honest,
            Expect::D2,
        );
        let mut extra = payload;
        extra.push(0x01);
        assert_teardown(
            &mut Bench::vectors(),
            &format!("Q-60 {name} + one byte"),
            &extra,
        );
    }
}
