// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-07 `relay_executor` (M5 Phase B; TEST-SPEC-M5 (f), [SQ-26]; `docs/07` "executor fuzz"): structured — the
//! fuzzer picks the commands and their fields, the harness signs, tokens and seals them honestly
//! (`common/relay_fixture.rs`) and hands the frames to the relay's executor of one link on a new, empty relay.
//!
//! Input: a configuration byte, then up to 160 commands (enough to fill a queue past its 128 cells), each an opcode
//! byte (modulo 10) and its fields (at most 27 bytes per command: `-max_len` 1 + 160 × 27 + 1):
//!
//! - configuration: bits 0–1 the queue budget (1–4 queues), bit 2 a link-data budget (bit 3: 1 or 2 entries; else
//!   unlimited), bit 4 a per-link frame rate (burst 1 + bits 5–7, 1 per second);
//! - `cmd_seq` byte of every request: below `0xe0` fresh (`last + 1 + (b & 3)`), else stale (`last − (b & 0x1f)`);
//! - key byte: recv key `k & 3`, send key `(k >> 2) & 3` (four pairs; mixed pairs are other queues or none),
//!   bit 6 a flipped token, bit 7 the wrong signer (or, for `LINK_GET` owner status, a signature over another
//!   `cmd_seq`);
//! - 0 `QUEUE_NEW` (seq, key) · 1 `SKEY` (seq) · 2 `SEND` (seq, key, cell fill byte) · 3 `FETCH` (seq, key, ack
//!   byte) · 4 `FETCH_MULTI` (seq, count byte → 1–12 entries of key and ack bytes) · 5 `QUEUE_DEL` (seq, key) ·
//!   6 `LINK_PUT` (seq, key: `ld_id` `k & 3`, owner bit 2, one-time bit 3; expiry byte → `bucket − 2 + 3e`; blob
//!   fill byte) · 7 `LINK_GET` (seq, key: `ld_id` `k & 3` or, with bit 4 and `k & 3 = 3`, an unknown one; owner
//!   status with bit 2, owner bit 3) · 8 `PING` (seq) · 9 the clock (bit 7: + `b & 0x7f` hours, the sweeper; else
//!   + 50 ms × b);
//! - ack byte: `0xff` `u64::MAX`, bit 7 `next_cell_id − (a & 0x7f)`, else `a`.
//!
//! Invariants (no panic): every honest frame is accepted (never a teardown); nothing is answered before a command's
//! last frame; the answer is exactly the D.2 count (one frame when stale — predicted from `last` — or over the
//! rate — predicted by a mirrored token bucket), every frame 4352 B, opening at the client's next counters and
//! echoing `cmd_seq`, of the response kinds D.2 allows; a stale or rate-limited command changes nothing; after
//! every command every queue holds at most 128 cells with strictly increasing ids below `next_cell_id`, its
//! `rid`/`sid` are derived from one of the pairs (spec §9.1), `next_cell_id` never decreases (until the sweeper or
//! a `QUEUE_DEL` removes the queue), `OK_SEND` reports the next id and evicts exactly at capacity, an
//! `OK_QUEUE_NEW` carries the derived ids, and the budget counters equal the stores' reservations.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::link::Link;
use secmp_proto::link::frame::Frame;
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{
    Cellr, CellrContext, FetchEntry, Request, RequestCmd, Response, ResponseCmd, opcode,
};
use secmp_relay::budget::{
    BudgetLimits, LINKDATA_OVERHEAD, LINKDATA_RESERVATION, QUEUE_RESERVATION,
};
use secmp_relay::rate::{RateLimit, TokenBucket};
use secmp_relay::relay::kat::StoreSnapshot;
use secmp_relay::{Executor, Limits, Outcome, Relay};

#[path = "../common/relay_fixture.rs"]
mod relay_fixture;

use relay_fixture::{Bytes, Client, Fixture, Put, at, ids_of, now_bucket, payload};

const MAX_COMMANDS: usize = 160;
const QUEUE_CAPACITY: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Run,
    Stale,
    Rate,
}

/// The D.2 response frame count of an executed request.
fn d2_count(op: u8) -> usize {
    match op {
        opcode::FETCH => 4,
        opcode::FETCH_MULTI => 8,
        opcode::LINK_GET => 3,
        _ => 1,
    }
}

/// The response kinds D.2 allows for request `op` (`verdict` not `Run`: one ERR 6 or ERR 7).
fn kinds_fit(op: u8, verdict: Verdict, r: &[Response]) -> bool {
    let ops: Vec<u8> = r.iter().map(|x| x.cmd.op()).collect();
    let err = match r {
        [
            Response {
                cmd: ResponseCmd::Err(c),
                ..
            },
        ] => Some(c.byte()),
        _ => None,
    };
    match verdict {
        Verdict::Stale => return err == Some(6),
        Verdict::Rate => return err == Some(7),
        Verdict::Run => {}
    }
    let one = |want: u8| ops == [want] || err.is_some();
    match op {
        opcode::QUEUE_NEW => one(opcode::OK_QUEUE_NEW),
        opcode::SEND => one(opcode::OK_SEND),
        opcode::QUEUE_DEL | opcode::LINK_PUT => one(opcode::OK),
        opcode::FETCH | opcode::FETCH_MULTI => ops.iter().all(|o| *o == opcode::CELLR),
        opcode::LINK_GET => ops == [opcode::LINKR, opcode::RESPONSE_CONT, opcode::RESPONSE_CONT],
        opcode::PING => ops == [opcode::OK],
        _ => err == Some(6),
    }
}

fn limits_of(config: u8) -> Limits {
    Limits {
        budget: BudgetLimits {
            queue_bytes: Some(QUEUE_RESERVATION * (1 + u64::from(config & 3))),
            linkdata_bytes: (config & 4 != 0)
                .then(|| LINKDATA_RESERVATION * (1 + u64::from((config >> 3) & 1))),
        },
        link_rate: (config & 0x10 != 0).then(|| RateLimit {
            burst: 1 + u32::from(config >> 5),
            per_sec: 1,
        }),
        ..Limits::vectors()
    }
}

fn cmd_seq(b: u8, last: u32) -> u32 {
    if b < 0xe0 {
        last.saturating_add(1 + u32::from(b & 3))
    } else {
        last.saturating_sub(u32::from(b & 0x1f))
    }
}

fn ack_of(a: u8, before: &StoreSnapshot, rid: &Id) -> u64 {
    let next = before
        .queues
        .iter()
        .find(|q| q.rid == *rid)
        .map_or(1, |q| q.next_cell_id);
    if a == 0xff {
        u64::MAX
    } else if a & 0x80 != 0 {
        next.saturating_sub(u64::from(a & 0x7f))
    } else {
        u64::from(a)
    }
}

/// What the harness knows about a command for the invariants.
#[derive(Default)]
struct Check {
    /// `SEND`: the target queue's `rid`.
    send_rid: Option<Id>,
    /// `QUEUE_NEW`: the derived ids of its keys.
    new_ids: Option<(Id, Id)>,
}

struct Session {
    relay: Relay,
    client: Link,
    exec: Executor,
    bucket: Option<TokenBucket>,
    hours: u64,
    mono: u64,
    /// The hour moved since the last executed command: its sweep may expire queues and link data.
    sweep: bool,
}

impl Session {
    fn step(&mut self, fx: &Fixture, b: &mut Bytes<'_>) {
        let op = b.u8() % 10;
        if op == 9 {
            let d = b.u8();
            if d & 0x80 != 0 {
                self.hours += u64::from(d & 0x7f);
                self.sweep = true;
            } else {
                self.mono += 50 * u64::from(d);
            }
            return;
        }
        let last = self.exec.last_cmd_seq();
        let seq = cmd_seq(b.u8(), last);
        let before = self.relay.snapshot_kat();
        let access = fx.access();
        let cl = Client {
            sess: *self.client.sess_id(),
            access: &access,
        };
        let (req_op, payloads, check) = build(fx, &cl, op, seq, b, &before, self.hours);
        let t = at(self.hours, self.mono);
        let mut over = false;
        let mut outcomes = Vec::new();
        for p in &payloads {
            // every request frame takes a token (executor step 4)
            if let Some(bucket) = self.bucket.as_mut() {
                over |= !bucket.take(self.mono);
            }
            let unit = self.client.seal(p).unwrap();
            outcomes.push(self.exec.on_unit(
                &self.relay,
                unit.as_slice(),
                t,
                &mut fx.answer_entropy(),
            ));
        }
        let verdict = if seq <= last {
            Verdict::Stale
        } else if over {
            Verdict::Rate
        } else {
            Verdict::Run
        };
        let resps = self.shape(req_op, verdict, seq, outcomes);
        let after = self.relay.snapshot_kat();
        self.invariants(fx, &before, &after, verdict, &resps, &check);
        if verdict == Verdict::Run {
            self.sweep = false;
        }
    }

    /// The D.2 shape of the answer (spec D.2 `:839`, §9.3 `:610`).
    fn shape(
        &mut self,
        op: u8,
        verdict: Verdict,
        seq: u32,
        outcomes: Vec<Outcome>,
    ) -> Vec<Response> {
        let n = outcomes.len();
        let mut frames: Vec<Frame> = Vec::new();
        for (i, o) in outcomes.into_iter().enumerate() {
            match o {
                Outcome::Teardown => {
                    panic!("an honest frame was rejected (op {op:#04x}, frame {i})")
                }
                Outcome::Pending => assert!(i + 1 < n, "the last frame of op {op:#04x} is pending"),
                Outcome::Respond(f) => {
                    assert!(i + 1 == n, "op {op:#04x} answered before its last frame");
                    frames = f;
                }
            }
        }
        let count = if verdict == Verdict::Run {
            d2_count(op)
        } else {
            1
        };
        assert_eq!(
            frames.len(),
            count,
            "op {op:#04x} {verdict:?}: D.2 frame count"
        );
        let context = if op == opcode::FETCH_MULTI {
            CellrContext::FetchMulti
        } else {
            CellrContext::Fetch
        };
        let resps: Vec<Response> = frames
            .iter()
            .map(|f| {
                assert_eq!(f.len(), 4352);
                let r = self.client.open_response(f.as_slice(), context).unwrap();
                assert_eq!(r.cmd_seq, seq, "cmd_seq echo");
                r
            })
            .collect();
        assert!(
            kinds_fit(op, verdict, &resps),
            "op {op:#04x} {verdict:?}: response kinds"
        );
        resps
    }

    fn invariants(
        &self,
        fx: &Fixture,
        before: &StoreSnapshot,
        after: &StoreSnapshot,
        verdict: Verdict,
        resps: &[Response],
        check: &Check,
    ) {
        if verdict != Verdict::Run {
            // not executed: nothing changes (spec §9.2, §9.7 item 7)
            assert_eq!(
                before, after,
                "a stale or rate-limited command changed the store"
            );
        }
        let derived: Vec<(Id, Id)> = fx
            .pairs
            .iter()
            .flat_map(|(r, _)| fx.pairs.iter().map(move |(_, s)| ids_of(r, s)))
            .collect();
        for q in &after.queues {
            assert!(q.cell_ids.len() <= QUEUE_CAPACITY, "more than 128 cells");
            assert!(q.next_cell_id >= 1);
            assert!(
                q.cell_ids.windows(2).all(|w| w[0] < w[1]),
                "ids not increasing"
            );
            assert!(q.cell_ids.iter().all(|i| *i >= 1 && *i < q.next_cell_id));
            assert!(
                derived.contains(&(q.rid, q.sid)),
                "a queue's ids are not derived from its keys"
            );
            if !self.sweep
                && let Some(p) = before.queues.iter().find(|p| p.rid == q.rid)
            {
                assert!(q.next_cell_id >= p.next_cell_id, "next_cell_id decreased");
            }
        }
        if let (
            Some(rid),
            [
                Response {
                    cmd: ResponseCmd::OkSend { cell_id, evicted },
                    ..
                },
            ],
        ) = (check.send_rid, resps)
            && !self.sweep
        {
            let q = before
                .queues
                .iter()
                .find(|q| q.rid == rid)
                .expect("OK_SEND to an existing queue");
            assert_eq!(*cell_id, q.next_cell_id, "OK_SEND cell_id");
            let full = q.cell_ids.len() == QUEUE_CAPACITY;
            assert_eq!(*evicted, full.then(|| q.cell_ids[0]), "OK_SEND eviction");
        }
        if let (
            Some(ids),
            [
                Response {
                    cmd: ResponseCmd::OkQueueNew { rid, sid },
                    ..
                },
            ],
        ) = (check.new_ids, resps)
        {
            assert_eq!((*rid, *sid), ids, "OK_QUEUE_NEW ids are derived");
        }
        for r in resps {
            if let ResponseCmd::Cellr(Cellr::Cell { cell_id, .. }) = &r.cmd {
                assert!(*cell_id >= 1);
            }
        }
        let (queues, linkdata) = self.relay.budget_used_kat();
        assert_eq!(
            queues,
            QUEUE_RESERVATION * after.queues.len() as u64,
            "queue pool"
        );
        let held: u64 = after
            .linkdata
            .iter()
            .map(|e| {
                if e.present {
                    LINKDATA_RESERVATION
                } else {
                    LINKDATA_OVERHEAD
                }
            })
            .sum();
        assert_eq!(linkdata, held, "link-data pool");
    }
}

/// The request frames of command `op` (module documentation) and what the invariants need to know.
fn build(
    fx: &Fixture,
    cl: &Client<'_>,
    op: u8,
    seq: u32,
    b: &mut Bytes<'_>,
    before: &StoreSnapshot,
    hours: u64,
) -> (u8, Vec<Vec<u8>>, Check) {
    let mut check = Check::default();
    let pair = |k: u8| {
        (
            &fx.pairs[usize::from(k & 3)].0,
            &fx.pairs[usize::from((k >> 2) & 3)].1,
        )
    };
    let token = |k: u8| {
        let mut t = cl.token(seq);
        if k & 0x40 != 0 {
            t[0] ^= 1;
        }
        t
    };
    let reqs = match op {
        0 => {
            let k = b.u8();
            let (recv, send) = pair(k);
            let signer = if k & 0x80 != 0 { send } else { recv };
            check.new_ids = Some(ids_of(recv, send));
            vec![cl.queue_new(seq, recv, send, token(k), signer)]
        }
        1 => {
            // SKEY: `op ‖ cmd_seq` (reading REF-M5 2), answered ERR 6; D.2 has no request type for it
            let p = [&[opcode::SKEY][..], &seq.to_be_bytes()].concat();
            return (opcode::SKEY, vec![p], check);
        }
        2 => {
            let k = b.u8();
            let (recv, send) = pair(k);
            let fill = b.u8();
            let signer = if k & 0x80 != 0 { recv } else { send };
            let (_, sid) = ids_of(recv, send);
            check.send_rid = before.queues.iter().find(|q| q.sid == sid).map(|q| q.rid);
            vec![cl.send(seq, recv, send, &[fill; 4096], signer)]
        }
        3 => {
            let k = b.u8();
            let (recv, send) = pair(k);
            let ack = ack_of(b.u8(), before, &ids_of(recv, send).0);
            let signer = if k & 0x80 != 0 { send } else { recv };
            vec![cl.fetch(seq, recv, ack, signer)]
        }
        4 => {
            let n = usize::from(b.u8() % 12) + 1;
            let entries: Vec<FetchEntry> = (0..n)
                .map(|_| {
                    let k = b.u8();
                    let (recv, send) = pair(k);
                    let ack = ack_of(b.u8(), before, &ids_of(recv, send).0);
                    let signer = if k & 0x80 != 0 { send } else { recv };
                    cl.entry(seq, recv, ack, signer)
                })
                .collect();
            vec![Request {
                cmd_seq: seq,
                cmd: RequestCmd::FetchMulti { entries },
            }]
        }
        5 => {
            let k = b.u8();
            let (recv, send) = pair(k);
            let signer = if k & 0x80 != 0 { send } else { recv };
            vec![cl.queue_del(seq, recv, signer)]
        }
        6 => {
            let k = b.u8();
            let owner = &fx.owners[usize::from((k >> 2) & 1)];
            let other = &fx.owners[usize::from(((k >> 2) & 1) ^ 1)];
            let bucket = now_bucket() + u32::try_from(hours).unwrap();
            let expires = (bucket - 2) + 3 * u32::from(b.u8());
            let blob = vec![b.u8(); 12_360];
            cl.link_put(
                seq,
                &Put {
                    ld_id: [k & 3; 16],
                    one_time: k & 0x08 != 0,
                    expires_bucket: expires,
                    owner,
                    token: token(k),
                    blob: &blob,
                    signer: if k & 0x80 != 0 { other } else { owner },
                },
            )
            .to_vec()
        }
        7 => {
            let k = b.u8();
            let ld = if k & 3 == 3 && k & 0x10 != 0 {
                [0xee; 16]
            } else {
                [k & 3; 16]
            };
            let owner = &fx.owners[usize::from((k >> 3) & 1)];
            let sig_seq = if k & 0x80 != 0 { seq ^ 1 } else { seq };
            vec![cl.link_get(seq, &ld, (k & 4 != 0).then_some((owner, sig_seq)))]
        }
        _ => vec![Request {
            cmd_seq: seq,
            cmd: RequestCmd::Ping,
        }],
    };
    (reqs[0].cmd.op(), reqs.iter().map(payload).collect(), check)
}

fuzz_target!(|data: &[u8]| {
    let fx = Fixture::get();
    let mut b = Bytes(data);
    let limits = limits_of(b.u8());
    let relay = fx.relay(limits);
    let (client, exec) = fx.link(&relay);
    let mut s = Session {
        relay,
        client,
        exec,
        bucket: limits.link_rate.map(|r| TokenBucket::new(r, 0)),
        hours: 0,
        mono: 0,
        sweep: false,
    };
    for _ in 0..MAX_COMMANDS {
        if b.is_empty() {
            break;
        }
        s.step(fx, &mut b);
    }
});
