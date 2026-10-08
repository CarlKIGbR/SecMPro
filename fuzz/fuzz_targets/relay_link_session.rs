// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-08 `relay_link_session` (M5 Phase B; TEST-SPEC-M5 (f), [SQ-27]): arbitrary frame plaintexts sealed honestly in
//! the fuzzer's order — `LINK_PUT` first frames and `CONT` frames among them, so every interleaving of the
//! multi-frame assembly is reachable — into a relay `Connection` after the honest handshake (`HELLO`, `RELAYINFO`,
//! `HS1`, `HS2` through the connection, `common/relay_fixture.rs`).
//!
//! Input: a configuration byte (bit 0 a per-link frame rate, burst 1 + bits 1–3), then up to 16 units, each a split
//! byte (bit 7: the unit arrives in two writes, cut at `(b & 0x7f) / 127` of its length), a kind byte (modulo 7) and
//! the kind's fields (at most 4339 bytes per unit, kind 0: `-max_len` 1 + 16 × 4339 + 1):
//!
//! - 0 an arbitrary plaintext: length `u16` (modulo 4336) and that many bytes, sealed by the client;
//! - 1 a `LINK_PUT` first frame: `cmd_seq` byte, `ld_id` byte, `one_time` byte (0, 1, or written raw), expiry byte
//!   (`bucket − 2 + 3e`), owner/token byte, blob fill byte — with the honest token and signature over
//!   `SHA-256(blob)` of the blob `[fill; 12360]`;
//! - 2 a `CONT`: `idx` byte (1, 2, or written raw), a byte whose bit 0 takes the `cmd_seq` of the last `LINK_PUT`
//!   begun (else the next `cmd_seq` byte), data fill byte (the blob verifies only with the `LINK_PUT`'s fill);
//! - 3 an honest single-frame request: kind byte (`PING`, `SKEY`, `FETCH`, `QUEUE_NEW`, `LINK_GET`), `cmd_seq`
//!   byte, key byte;
//! - 4 kind 3 with one plaintext byte xored (position `u16`, mask byte);
//! - 5 a unit the client did not seal: length `u16` (modulo 8705) of the fuzzer's bytes (at most 64, zero-padded);
//! - 6 an honest `PING` sealed under another counter: `cmd_seq` byte, distance byte (bit 7 backwards).
//!
//! The `cmd_seq` byte is fresh below `0xe0` (`last + 1 + (b & 3)`), else stale (`last − (b & 0x1f)`).
//!
//! Invariants (no panic): a write the relay answers emits whole 4352-byte frames that open at the client's next
//! counters; a teardown emits nothing, leaves the store (`store_digest_kat`) as it was before the unit, and the
//! closed connection answers nothing more.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::{self, Link};
use secmp_proto::wire::frame::{Cont, ContIdx, Request, RequestCmd};
use secmp_relay::rate::RateLimit;
use secmp_relay::{Connection, Limits, Now, Output};

#[path = "../common/relay_fixture.rs"]
mod relay_fixture;

use relay_fixture::{Bytes, Client, Fixture, NOW, Put, at, now_bucket, payload};

const MAX_UNITS: usize = 16;
const FRAME: usize = 4352;

fn seq_of(b: u8, last: u32) -> u32 {
    if b < 0xe0 {
        last.saturating_add(1 + u32::from(b & 3))
    } else {
        last.saturating_sub(u32::from(b & 0x1f))
    }
}

/// The harness's view of the link: the client's end, the recorded `cmd_seq`, the last `LINK_PUT` begun.
struct Session<'a> {
    fx: &'a Fixture,
    access: AccessKey,
    client: Link,
    last: u32,
    put_seq: Option<u32>,
}

impl Session<'_> {
    fn cl(&self) -> Client<'_> {
        Client {
            sess: *self.client.sess_id(),
            access: &self.access,
        }
    }

    /// The payload of an honest single-frame request (kind 3).
    fn honest(&self, b: &mut Bytes<'_>) -> Vec<u8> {
        let sub = b.u8() % 5;
        let seq = seq_of(b.u8(), self.last);
        let k = b.u8();
        let cl = self.cl();
        let (recv, send) = (&self.fx.pairs[usize::from(k & 3)].0, &self.fx.pairs[usize::from(k & 3)].1);
        match sub {
            0 => payload(&Request {
                cmd_seq: seq,
                cmd: RequestCmd::Ping,
            }),
            1 => [&[0x02][..], &seq.to_be_bytes()].concat(),
            2 => payload(&cl.fetch(seq, recv, 0, recv)),
            3 => payload(&cl.queue_new(seq, recv, send, cl.token(seq), recv)),
            _ => payload(&cl.link_get(seq, &[k; 16], None)),
        }
    }

    /// The unit of one input record (module documentation).
    fn unit(&mut self, b: &mut Bytes<'_>) -> Vec<u8> {
        let fx = self.fx;
        match b.u8() % 7 {
            0 => {
                let n = usize::from(b.u16()) % 4336;
                let p = b.take(n);
                self.client.seal(&p).unwrap().to_vec()
            }
            1 => {
                let seq = seq_of(b.u8(), self.last);
                let ld = b.u8();
                let one_time = b.u8();
                let expires = (now_bucket() - 2) + 3 * u32::from(b.u8());
                let k = b.u8();
                let fill = b.u8();
                let owner = &fx.owners[usize::from(k & 1)];
                let cl = self.cl();
                let mut token = cl.token(seq);
                if k & 0x40 != 0 {
                    token[0] ^= 1;
                }
                let blob = vec![fill; 12_360];
                let frames = cl.link_put(
                    seq,
                    &Put {
                        ld_id: [ld; 16],
                        one_time: one_time & 1 != 0,
                        expires_bucket: expires,
                        owner,
                        token,
                        blob: &blob,
                        signer: owner,
                    },
                );
                let mut p = payload(&frames[0]);
                if one_time > 1 {
                    // a boolean out of range (spec §4.1): a decoder rejection
                    p[21] = one_time;
                }
                self.put_seq = Some(seq);
                self.client.seal(&p).unwrap().to_vec()
            }
            2 => {
                let idx = b.u8();
                let mode = b.u8();
                let seq = match self.put_seq {
                    Some(s) if mode & 1 != 0 => s,
                    _ => seq_of(b.u8(), self.last),
                };
                let fill = b.u8();
                let req = Request {
                    cmd_seq: seq,
                    cmd: RequestCmd::Cont(Cont {
                        idx: if idx == 2 { ContIdx::Two } else { ContIdx::One },
                        data: Box::new([fill; 4100]),
                    }),
                };
                let mut p = payload(&req);
                if idx != 1 && idx != 2 {
                    p[5] = idx;
                }
                self.client.seal(&p).unwrap().to_vec()
            }
            3 => {
                let p = self.honest(b);
                self.client.seal(&p).unwrap().to_vec()
            }
            4 => {
                let mut p = self.honest(b);
                let at = usize::from(b.u16()) % p.len();
                p[at] ^= b.u8().max(1);
                self.client.seal(&p).unwrap().to_vec()
            }
            5 => {
                let len = usize::from(b.u16()) % (2 * FRAME + 1);
                let mut v = b.take(len.min(64));
                v.resize(len, 0);
                v
            }
            _ => {
                let seq = seq_of(b.u8(), self.last);
                let d = b.u8();
                let c = self.client.send_counter().unwrap();
                let distance = u64::from(d & 0x7f) + 1;
                let skewed = if d & 0x80 != 0 {
                    c.checked_sub(distance).unwrap_or(c + distance)
                } else {
                    c + distance
                };
                self.client.set_send_counter_kat(skewed);
                let p = payload(&Request {
                    cmd_seq: seq,
                    cmd: RequestCmd::Ping,
                });
                self.client.seal(&p).unwrap().to_vec()
            }
        }
    }
}

/// Write `unit` to the connection, in one write or (split bit) two.
fn deliver(conn: &mut Connection<'_>, fx: &Fixture, unit: &[u8], split: u8, t: Now) -> Output {
    if split & 0x80 == 0 || unit.len() < 2 {
        return conn.on_bytes(unit, t, &mut fx.answer_entropy());
    }
    let k = 1 + usize::from(split & 0x7f) * (unit.len() - 2) / 127;
    let first = conn.on_bytes(&unit[..k], t, &mut fx.answer_entropy());
    if first.close {
        return first;
    }
    let second = conn.on_bytes(&unit[k..], t, &mut fx.answer_entropy());
    Output {
        bytes: [first.bytes, second.bytes].concat(),
        close: second.close,
    }
}

fuzz_target!(|data: &[u8]| {
    let fx = Fixture::get();
    let mut b = Bytes(data);
    let config = b.u8();
    let limits = Limits {
        link_rate: (config & 1 != 0).then(|| RateLimit {
            burst: 1 + u32::from((config >> 1) & 7),
            per_sec: 1,
        }),
        ..Limits::vectors()
    };
    let relay = fx.relay(limits);
    let t = at(0, 0);
    let mut conn = Connection::accept(&relay, t).unwrap();
    let access = fx.access();
    let (hello, st) = link::client::start(fx.fp, Some(&access), NOW).unwrap();
    let info = conn.on_bytes(&hello, t, &mut fx.relay_entropy());
    assert!(!info.close, "RELAYINFO");
    let (hs1, wait) = st.on_relayinfo(&info.bytes, &mut fx.client_entropy()).unwrap();
    let hs2 = conn.on_bytes(&hs1, t, &mut fx.relay_entropy());
    assert!(!hs2.close, "HS2");
    let mut s = Session {
        fx,
        access,
        client: wait.on_hs2(&hs2.bytes).unwrap(),
        last: 0,
        put_seq: None,
    };
    for _ in 0..MAX_UNITS {
        if b.is_empty() {
            break;
        }
        let split = b.u8();
        let unit = s.unit(&mut b);
        let digest = relay.store_digest_kat();
        let out = deliver(&mut conn, fx, &unit, split, t);
        if out.close {
            // a teardown (spec §8.5): nothing emitted, the store as before the unit, and nothing after it
            assert!(out.bytes.is_empty(), "a teardown emitted {} bytes", out.bytes.len());
            assert_eq!(relay.store_digest_kat(), digest, "a teardown changed the store");
            let more = conn.on_bytes(&[0; FRAME], t, &mut fx.answer_entropy());
            assert!(more.close && more.bytes.is_empty(), "a closed connection answered");
            return;
        }
        assert_eq!(out.bytes.len() % FRAME, 0, "partial frames emitted");
        for f in out.bytes.chunks(FRAME) {
            assert!(s.client.open(f).is_ok(), "a relay frame does not open at the next counter");
        }
        s.last = conn.executor().map_or(s.last, |e| e.last_cmd_seq());
    }
});
