// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (c) prepared frames and pipelined responses (AD-01…AD-06; spec §10.1, §10.3, §8.4, D.2) against a scripted
//! relay: `Session::prepare` / `write_prepared` / `read_response` over a stream the test controls.

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::rc::Rc;

use secmp_crypto::SecretBytes;
use secmp_proto::wire::frame::{Cellr, ErrCode, Request, RequestCmd, Response, ResponseCmd};
use secmp_testkit::harness::EntropyPool;
use secmp_transport::channel::counters;
use secmp_transport::{
    Command, ConnectOutcome, Error, Outcome, RecvCap, SendCap, Session,
};

use crate::scripted::{self, Script, Scripted, cell, dummy, err};

/// A stream that counts the bytes written through it and optionally cuts what it reads into pieces.
#[derive(Clone)]
struct Tap<S> {
    inner: S,
    written: Rc<RefCell<usize>>,
    chunks: Rc<RefCell<Option<Sizes>>>,
}

struct Sizes(u64);

impl Sizes {
    fn next(&mut self) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        usize::try_from(self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % 4352)
            .unwrap()
            .saturating_add(1)
    }
}

impl<S> Tap<S> {
    fn new(inner: S, chunk_seed: Option<u64>) -> Self {
        Self {
            inner,
            written: Rc::new(RefCell::new(0)),
            chunks: Rc::new(RefCell::new(chunk_seed.map(|s| Sizes(s | 1)))),
        }
    }

    fn written(&self) -> usize {
        *self.written.borrow()
    }
}

impl<S: Read> Read for Tap<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = match self.chunks.borrow_mut().as_mut() {
            Some(s) => s.next().min(buf.len()),
            None => buf.len(),
        };
        let limit = limit.min(buf.len());
        self.inner.read(buf.get_mut(..limit).unwrap())
    }
}

impl<S: Write> Write for Tap<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut w = self.written.borrow_mut();
        *w = w.saturating_add(buf.len());
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct Peer {
    session: Session<Tap<Scripted>>,
    tap: Tap<Scripted>,
    relay: Scripted,
    send: SendCap,
    recv: RecvCap,
}

fn caps() -> (SendCap, RecvCap) {
    let recv_seed = SecretBytes::from_slice(&[0x41; 32]).unwrap();
    let recv = RecvCap::from_seed(&recv_seed).unwrap();
    let send = SendCap::from_route([0x42; 16], &SecretBytes::from_slice(&[0x43; 32]).unwrap())
        .unwrap();
    (send, recv)
}

fn peer(script: Script, chunk_seed: Option<u64>) -> Peer {
    let relay = Scripted::new(script);
    let id = scripted::identity();
    let tap = Tap::new(relay.clone(), chunk_seed);
    let mut entropy = EntropyPool::new("m6-channel-client", 0);
    let session = Session::connect(
        tap.clone(),
        id.fp,
        Some(&id.access),
        scripted::T0,
        entropy.get(),
    )
    .unwrap();
    let (send, recv) = caps();
    Peer {
        session,
        tap,
        relay,
        send,
        recv,
    }
}

/// The relay of the pipelining tests: `OK_SEND{cell_id: n}` for the n-th SEND, a FETCH answered with two real cells and
/// two dummies, `OK` for a PING.
fn friendly() -> Script {
    let mut sends = 0_u64;
    Box::new(move |request: &Request, _| match &request.cmd {
        RequestCmd::Send { .. } => {
            sends = sends.saturating_add(1);
            vec![Response {
                cmd_seq: request.cmd_seq,
                cmd: ResponseCmd::OkSend {
                    cell_id: sends,
                    evicted: None,
                },
            }]
        }
        RequestCmd::Fetch { .. } => {
            let seq = request.cmd_seq;
            let real = |id: u64| Response {
                cmd_seq: seq,
                cmd: ResponseCmd::Cellr(Cellr::Cell {
                    rid: [0; 16],
                    cell_id: id,
                    cell: cell(u8::try_from(id).unwrap()),
                }),
            };
            vec![real(1), real(2), dummy(seq), dummy(seq)]
        }
        RequestCmd::Ping => vec![scripted::ok(request.cmd_seq)],
        _ => vec![err(request.cmd_seq, ErrCode::Malformed)],
    })
}

/// AD-01: `prepare` seals (one seal, one signature, the counter moves, 4 352 B); `write_prepared` does no crypto and
/// writes exactly those bytes.
#[test]
fn prepare_seals_before_write() {
    let mut p = peer(friendly(), None);
    let c0 = p.session.channel().send_counter().unwrap();
    let (seal0, sign0) = (counters::seal_calls(), counters::sign_calls());
    let prepared = p
        .session
        .prepare(&Command::Send {
            to: &p.send,
            cell: &cell(7),
        })
        .unwrap();
    assert_eq!(counters::seal_calls() - seal0, 1);
    assert_eq!(counters::sign_calls() - sign0, 1);
    assert_eq!(p.session.channel().send_counter().unwrap() - c0, 1);
    assert_eq!(prepared.bytes().len(), 4352);
    let (seal1, sign1) = (counters::seal_calls(), counters::sign_calls());
    let before = p.tap.written();
    p.session.write_prepared(&prepared).unwrap();
    assert_eq!(
        (counters::seal_calls() - seal1, counters::sign_calls() - sign1),
        (0, 0),
        "no crypto on the write path"
    );
    assert_eq!(p.tap.written() - before, 4352);
    assert_eq!(p.relay.seen().len(), 1);
}

/// AD-02: frames leave in counter order; a later frame first is a local error that writes nothing.
#[test]
fn prepared_frames_written_in_counter_order() {
    let mut p = peer(friendly(), None);
    let a = p.session.prepare(&Command::Ping).unwrap();
    let b = p.session.prepare(&Command::Ping).unwrap();
    assert_eq!(b.first_counter(), a.first_counter() + 1);
    let before = p.tap.written();
    assert_eq!(p.session.write_prepared(&b).err(), Some(Error::OutOfOrder));
    assert_eq!(p.tap.written(), before, "0 bytes written");
    assert!(!p.session.is_closed());
    p.session.write_prepared(&a).unwrap();
    p.session.write_prepared(&b).unwrap();
    assert_eq!(p.tap.written() - before, 2 * 4352);
}

fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Ping(r) => format!("ping {:?}", r.as_ref().err()),
        Outcome::Send(r) => format!("send {:?}", r.as_ref().map(|o| (o.cell_id, o.evicted))),
        Outcome::Fetch(r) => format!(
            "fetch {:?}",
            r.as_ref()
                .map(|v| v.iter().map(|(id, _)| *id).collect::<Vec<_>>())
        ),
        Outcome::FetchMulti(_) => "fetch_multi".to_owned(),
    }
}

/// AD-03: a SEND and a FETCH outstanding together; the 1 + 4 response frames are matched in request order.
#[test]
fn pipelined_responses_matched_in_order() {
    let mut p = peer(friendly(), None);
    let send = p
        .session
        .prepare(&Command::Send {
            to: &p.send,
            cell: &cell(9),
        })
        .unwrap();
    let fetch = p
        .session
        .prepare(&Command::Fetch {
            from: &p.recv,
            ack: 0,
        })
        .unwrap();
    p.session.write_prepared(&send).unwrap();
    p.session.write_prepared(&fetch).unwrap();
    assert_eq!(p.session.channel().outstanding(), 2);
    let first = p.session.read_response().unwrap();
    let second = p.session.read_response().unwrap();
    assert_eq!((first.seq, second.seq), (send.seq(), fetch.seq()));
    assert_eq!(describe(&first.outcome), "send Ok((1, None))");
    assert_eq!(describe(&second.outcome), "fetch Ok([1, 2])");
    assert_eq!(p.session.channel().outstanding(), 0);
}

/// AD-04: a response that carries another request's `cmd_seq`, or an `OK_SEND` where a `FETCH` is due, is
/// `Rejected`; the link is closed and nothing is written after.
#[test]
fn pipelined_mismatch_closes_link() {
    // request 1 answered with request 2's cmd_seq
    let wrong_seq: Script = Box::new(|request: &Request, _| vec![scripted::ok(request.cmd_seq + 1)]);
    let mut p = peer(wrong_seq, None);
    let a = p.session.prepare(&Command::Ping).unwrap();
    p.session.write_prepared(&a).unwrap();
    assert_eq!(p.session.read_response().err(), Some(Error::Rejected));
    assert!(p.session.is_closed());
    let b = p.session.prepare(&Command::Ping).err();
    assert_eq!(b, Some(Error::Closed));

    // an OK_SEND where a FETCH's CELLR is due
    let wrong_kind: Script = Box::new(|request: &Request, _| {
        vec![Response {
            cmd_seq: request.cmd_seq,
            cmd: ResponseCmd::OkSend {
                cell_id: 3,
                evicted: None,
            },
        }]
    });
    let mut p = peer(wrong_kind, None);
    let f = p
        .session
        .prepare(&Command::Fetch {
            from: &p.recv,
            ack: 0,
        })
        .unwrap();
    p.session.write_prepared(&f).unwrap();
    assert_eq!(p.session.read_response().err(), Some(Error::Rejected));
    assert!(p.session.is_closed());
    let written = p.tap.written();
    assert_eq!(p.session.write_prepared(&f).err(), Some(Error::Closed));
    assert_eq!(p.tap.written(), written, "nothing written after");
}

/// AD-05: the responses are the same however the stream is cut (1…4 352 B pieces, seeded).
#[test]
fn frames_reassembled_from_any_chunking() {
    let run = |seed: Option<u64>| {
        let mut p = peer(friendly(), seed);
        let mut seen = Vec::new();
        for i in 0..6_u8 {
            let send = p
                .session
                .prepare(&Command::Send {
                    to: &p.send,
                    cell: &cell(i),
                })
                .unwrap();
            let fetch = p
                .session
                .prepare(&Command::Fetch {
                    from: &p.recv,
                    ack: 0,
                })
                .unwrap();
            p.session.write_prepared(&send).unwrap();
            p.session.write_prepared(&fetch).unwrap();
            seen.push(describe(&p.session.read_response().unwrap().outcome));
            seen.push(describe(&p.session.read_response().unwrap().outcome));
        }
        seen
    };
    let whole = run(None);
    for seed in [1_u64, 7, 99, 0xdead_beef] {
        assert_eq!(run(Some(seed)), whole, "chunk seed {seed}");
    }
}

/// A stream that is closed from the start: reads end at once, writes vanish.
struct Dead;

impl Read for Dead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for Dead {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// AD-06: a relay that closes after `HELLO` is `ClosedBeforeRelayInfo`; a `RELAYINFO` that fails verification is the
/// uniform `Rejected` (spec §8.5).
#[test]
fn closed_before_relayinfo_is_its_own_outcome() {
    let id = scripted::identity();
    let mut entropy = EntropyPool::new("m6-channel-client", 1);
    let outcome = Session::connect_outcome(Dead, id.fp, Some(&id.access), scripted::T0, entropy.get());
    assert!(matches!(outcome, ConnectOutcome::ClosedBeforeRelayInfo));

    let mut wrong = id.fp;
    wrong[0] ^= 1;
    let relay = Scripted::new(friendly());
    let outcome =
        Session::connect_outcome(relay, wrong, Some(&id.access), scripted::T0, entropy.get());
    assert!(matches!(outcome, ConnectOutcome::Failed(Error::Rejected)));
}
