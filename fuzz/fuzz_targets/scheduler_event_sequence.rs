// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-04 `scheduler_event_sequence` (M6 Phase A; TEST-SPEC-M6 (j)): arbitrary events against the sans-IO scheduler core
//! (`secmp_client_core::scheduler::core::Scheduler`) with honest links (the relay's end of the fixed handshake of
//! `common/link_fixture.rs`) and canned relay answers.
//!
//! Input: a mode byte (modulo 3), 8 seed bytes of the timing randomness, then up to 192 events of a tag byte (modulo
//! 10) and its arguments: 0 advance the clock by `u16` ms and poll; 1 jump the clock by `u32` modulo 24 h and poll; 2
//! answer the oldest request of link `b` (modulo the links); 3 the stream of link `b` ends; 4 add a send queue (period
//! byte modulo 4, relay byte modulo 2); 5 add a recv-queue; 6 remove queue `b`; 7 change the mode; 8 answer every
//! outstanding request of every link; 9 poll.
//!
//! Invariants: no panic; every connection's in-flight count stays at most 2; every write is whole 4352-byte frames that
//! open under the link's key as requests; no two `SEND`s to one queue are less than the queue's period apart.
#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{
    CellSource, CellToken, LinkId, Output, PreparedCell, QueueId, RelayId, SendFailure, SourceError,
};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::SecretBytes;
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link::Link;
use secmp_proto::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN};
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{Cellr, Request, RequestCmd, Response, ResponseCmd};
use secmp_transport::{Channel, RecvCap, SendCap};

#[path = "../common/link_fixture.rs"]
mod link_fixture;

use link_fixture::{Bytes, Fixture};

const MAX_EVENTS: usize = 192;
const PERIODS: [u64; 4] = [10_000, 20_000, 40_000, 80_000];

struct Src(u64);

impl CellSource for Src {
    fn prepare_cell(&mut self, _: QueueId, _: u64) -> Result<Option<PreparedCell>, SourceError> {
        self.0 += 1;
        Ok(Some(PreparedCell {
            cell: Cell::from_bytes(&[(self.0 & 0xff) as u8; 4096]).unwrap(),
            token: CellToken(self.0),
        }))
    }
    fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
    fn evicted(&mut self, _: QueueId, _: u64) {}
    fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
    fn discard(&mut self, _: QueueId, _: CellToken) {}
    fn queue_lost(&mut self, _: QueueId) {}
    fn deliver(&mut self, _: QueueId, _: u64, _: &Cell) -> Result<(), SourceError> {
        Ok(())
    }
}

/// The relay's end of a connection and the requests it has opened but not answered.
struct Peer {
    relay: Link,
    pending: Vec<Request>,
}

fn mode_of(b: u8) -> Mode {
    match b % 3 {
        0 => Mode::Strict,
        1 => Mode::Balanced,
        _ => Mode::LowBw,
    }
}

struct World {
    sched: Scheduler,
    src: Src,
    now: u64,
    peers: BTreeMap<LinkId, Peer>,
    /// `sid byte → period` and the time of the last `SEND` to it.
    periods: BTreeMap<u8, u64>,
    last_send: BTreeMap<u8, u64>,
    queues: Vec<QueueId>,
    next_sid: u8,
    next_cell_id: u64,
}

impl World {
    fn apply(&mut self, outs: Vec<Output>) {
        let mut work: std::collections::VecDeque<Output> = outs.into();
        while let Some(out) = work.pop_front() {
            match out {
                Output::Connect { link, .. } => {
                    let (client, relay) = Fixture::get().honest_links();
                    self.peers.insert(link, Peer { relay, pending: Vec::new() });
                    let more = self
                        .sched
                        .link_up(link, self.now, Channel::from_link_kat(client), &mut self.src)
                        .unwrap();
                    work.extend(more);
                }
                Output::Write { link, bytes } => {
                    assert!(!bytes.is_empty() && bytes.len() % FRAME_LEN == 0, "a write of {} bytes", bytes.len());
                    let peer = self.peers.get_mut(&link).expect("a write on a link that is not up");
                    for unit in bytes.chunks(FRAME_LEN) {
                        let request = peer.relay.open_request(unit).expect("the written frame opens as a request");
                        if let RequestCmd::Send { sid, .. } = &request.cmd {
                            let key = sid[0];
                            let period = self.periods[&key];
                            if let Some(last) = self.last_send.get(&key) {
                                assert!(
                                    self.now.saturating_sub(*last) >= period,
                                    "two SENDs {} ms apart on a queue of period {period}",
                                    self.now.saturating_sub(*last)
                                );
                            }
                            self.last_send.insert(key, self.now);
                        }
                        peer.pending.push(request);
                    }
                }
                Output::Close { link } => {
                    self.peers.remove(&link);
                }
                Output::Event(_) | Output::Control { .. } => {}
            }
        }
        for info in self.sched.links() {
            assert!(info.in_flight <= 2, "in-flight {}", info.in_flight);
        }
    }

    fn poll(&mut self) {
        let outs = self.sched.poll(self.now, &mut self.src).unwrap();
        self.apply(outs);
    }

    /// Answer the oldest outstanding request of `link` honestly.
    fn answer(&mut self, link: LinkId) {
        let Some(peer) = self.peers.get_mut(&link) else { return };
        if peer.pending.is_empty() {
            return;
        }
        let request = peer.pending.remove(0);
        let seq = request.cmd_seq;
        let responses: Vec<Response> = match &request.cmd {
            RequestCmd::Send { .. } => {
                self.next_cell_id += 1;
                vec![Response { cmd_seq: seq, cmd: ResponseCmd::OkSend { cell_id: self.next_cell_id, evicted: None } }]
            }
            RequestCmd::Fetch { .. } => (0..4).map(|_| dummy(seq)).collect(),
            RequestCmd::FetchMulti { .. } => (0..8).map(|_| dummy(seq)).collect(),
            _ => vec![Response { cmd_seq: seq, cmd: ResponseCmd::Ok }],
        };
        let mut units = Vec::new();
        for r in &responses {
            let padded = r.encode().unwrap();
            let payload = unpad(&padded, FRAME_PLAINTEXT_LEN).unwrap();
            units.push(peer.relay.seal(payload).unwrap());
        }
        for unit in units {
            let outs = self.sched.on_frame(link, self.now, &unit[..], &mut self.src).unwrap();
            self.apply(outs);
        }
    }

    fn link_at(&self, b: u8) -> Option<LinkId> {
        let ids: Vec<LinkId> = self.peers.keys().copied().collect();
        if ids.is_empty() {
            None
        } else {
            Some(ids[usize::from(b) % ids.len()])
        }
    }
}

fn dummy(seq: u32) -> Response {
    Response {
        cmd_seq: seq,
        cmd: ResponseCmd::Cellr(Cellr::Dummy { cell: Cell::from_bytes(&[0x11; 4096]).unwrap() }),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut b = Bytes(data);
    let mode = mode_of(b.u8());
    let seed = u64::from_be_bytes(b.take(8).try_into().unwrap());
    let mut w = World {
        sched: Scheduler::new(Params::default(), mode, TimingRng::seeded(seed)),
        src: Src(0),
        now: 0,
        peers: BTreeMap::new(),
        periods: BTreeMap::new(),
        last_send: BTreeMap::new(),
        queues: Vec::new(),
        next_sid: 0,
        next_cell_id: 0,
    };
    for _ in 0..MAX_EVENTS {
        if b.0.is_empty() {
            break;
        }
        match b.u8() % 10 {
            0 => {
                w.now += u64::from(b.u16());
                w.poll();
            }
            1 => {
                w.now += u64::from(b.u32()) % 86_400_000;
                w.poll();
            }
            2 => {
                if let Some(link) = w.link_at(b.u8()) {
                    w.answer(link);
                }
                w.poll();
            }
            3 => {
                if let Some(link) = w.link_at(b.u8()) {
                    w.peers.remove(&link);
                    let outs = w.sched.on_closed(link, w.now, &mut w.src).unwrap();
                    w.apply(outs);
                }
            }
            4 => {
                let period = PERIODS[usize::from(b.u8() % 4)];
                let relay = RelayId(u32::from(b.u8() % 2));
                w.next_sid = w.next_sid.wrapping_add(1);
                let sid_byte = w.next_sid;
                let cap = SendCap::from_route([sid_byte; 16], &SecretBytes::from_slice(&[sid_byte; 32]).unwrap()).unwrap();
                if let Ok(q) = w.sched.add_send_queue(w.now, relay, cap, period) {
                    w.periods.insert(sid_byte, period);
                    w.queues.push(q);
                }
            }
            5 => {
                let period = PERIODS[usize::from(b.u8() % 4)];
                let relay = RelayId(u32::from(b.u8() % 2));
                w.next_sid = w.next_sid.wrapping_add(1);
                let mut seed = [0u8; 32];
                seed[0] = w.next_sid;
                seed[1] = 0xee;
                let cap = RecvCap::from_seed(&SecretBytes::from_slice(&seed).unwrap()).unwrap();
                if let Ok(q) = w.sched.add_recv_queue(w.now, relay, cap, period) {
                    w.queues.push(q);
                }
            }
            6 => {
                if !w.queues.is_empty() {
                    let q = w.queues.remove(usize::from(b.u8()) % w.queues.len());
                    let outs = w.sched.remove_queue(w.now, q, &mut w.src).unwrap();
                    w.apply(outs);
                }
            }
            7 => {
                if let Ok(outs) = w.sched.set_mode(w.now, mode_of(b.u8()), &mut w.src) {
                    w.apply(outs);
                }
            }
            8 => {
                let links: Vec<LinkId> = w.peers.keys().copied().collect();
                for link in links {
                    for _ in 0..3 {
                        w.answer(link);
                    }
                }
                w.poll();
            }
            _ => w.poll(),
        }
    }
});
