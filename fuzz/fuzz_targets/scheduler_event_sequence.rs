// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-04 `scheduler_event_sequence` (M6 Phase A; TEST-SPEC-M6 (j); extended by M7 B-SC2, Q185): arbitrary events
//! against the sans-IO scheduler core (`secmp_client_core::scheduler::core::Scheduler`) with honest links (the relay's
//! end of the fixed handshake of `common/link_fixture.rs`), a relay whose every recv-queue holds the cells 1, 2, 3, …,
//! and a cell source that commits now, later, or not at all.
//!
//! Input: a mode byte (modulo 3), 8 seed bytes of the timing randomness, then up to 192 events of a tag byte (modulo
//! 12) and its arguments (at most 5 bytes per event): 0 advance the clock by `u16` ms and poll; 1 jump the clock by `u32`
//! modulo 24 h and poll; 2 answer the oldest request of link `b` (modulo the links) under the response mode byte `m` —
//! bit 0 reverses the cells, bit 1 drops one, bit 2 duplicates one, bits 3–4 modulo 3 give the cell source's answer for
//! this response (committed / pending / storage failure); 3 the stream of link `b` ends; 4 add a send queue (period byte
//! modulo 4, relay byte modulo 2); 5 add a recv-queue; 6 remove queue `b`; 7 change the mode; 8 answer every
//! outstanding request of every link honestly (mode 0); 9 poll; 10 the cell source commits the pending cell chosen by `b`
//! (`Scheduler::delivery_committed`); 11 report the oldest unreported frame of link `b` written (`frame_written`;
//! bit 0 of the argument byte reports it twice).
//!
//! A `FETCH` is answered with the lowest cells above its `ack` (at most 4, `FETCH_MULTI` at most 8 over its entries),
//! padded with dummies.
//!
//! Invariants: no panic; every connection's in-flight count stays at most 2; every write is whole 4352-byte frames that
//! open under the link's key as requests; no two `SEND`s to one queue are less than the queue's period apart; and
//! persist-before-ack (CLAUDE.md §1.7): every cell handed to the cell source with an id at or below the `ack` of the
//! latest `FETCH` of its queue the relay opened is committed.
#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use libfuzzer_sys::fuzz_target;
use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{
    CellSource, CellToken, Delivered, FrameId, LinkId, Output, PreparedCell, QueueId, RelayId, SendFailure,
    SourceError,
};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::SecretBytes;
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link::Link;
use secmp_proto::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN};
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{Cellr, Request, RequestCmd, Response, ResponseCmd};
use secmp_transport::{Channel, RecvCap, SendCap};

#[path = "../common/link_fixture.rs"]
mod link_fixture;

use link_fixture::{Bytes, Fixture};

const MAX_EVENTS: usize = 192;
const PERIODS: [u64; 4] = [10_000, 20_000, 40_000, 80_000];

/// The cell source: every slot gets a cell; a fetched cell is committed now, later or not at all (the response mode),
/// and the shadow of what was handed over and committed per queue.
#[derive(Default)]
struct Src {
    next: u64,
    /// The answer for cells not committed yet: 0 committed, 1 pending, 2 storage failure.
    answer: u8,
    handed: BTreeMap<QueueId, BTreeSet<u64>>,
    committed: BTreeMap<QueueId, BTreeSet<u64>>,
    pending: BTreeSet<(QueueId, u64)>,
}

impl CellSource for Src {
    fn prepare_cell(&mut self, _: QueueId, _: u64) -> Result<Option<PreparedCell>, SourceError> {
        self.next += 1;
        Ok(Some(PreparedCell::unpersisted_kat(
            Cell::from_bytes(&[(self.next & 0xff) as u8; 4096]).unwrap(),
            CellToken(self.next),
        )))
    }
    fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
    fn evicted(&mut self, _: QueueId, _: u64) {}
    fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
    fn discard(&mut self, _: QueueId, _: CellToken) {}
    fn queue_lost(&mut self, _: QueueId) {}
    fn deliver(&mut self, queue: QueueId, id: u64, _: &Cell) -> Result<Delivered, SourceError> {
        self.handed.entry(queue).or_default().insert(id);
        if self.committed.get(&queue).is_some_and(|c| c.contains(&id)) {
            return Ok(Delivered::Committed);
        }
        match self.answer {
            0 => {
                self.committed.entry(queue).or_default().insert(id);
                self.pending.remove(&(queue, id));
                Ok(Delivered::Committed)
            }
            1 => {
                self.pending.insert((queue, id));
                Ok(Delivered::Pending)
            }
            _ => Err(SourceError),
        }
    }
}

/// The relay's end of a connection, the requests it has opened but not answered, and the frames written to it that the
/// driver has not reported yet.
struct Peer {
    relay: Link,
    pending: Vec<Request>,
    unreported: Vec<FrameId>,
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
    /// The recv-queues by `rid`, and the `ack` of the latest `FETCH` of each the relay opened.
    rids: BTreeMap<Id, QueueId>,
    relay_ack: BTreeMap<QueueId, u64>,
}

impl World {
    fn apply(&mut self, outs: Vec<Output>) {
        let mut work: std::collections::VecDeque<Output> = outs.into();
        while let Some(out) = work.pop_front() {
            match out {
                Output::Connect { link, .. } => {
                    let (client, relay) = Fixture::get().honest_links();
                    self.peers.insert(link, Peer { relay, pending: Vec::new(), unreported: Vec::new() });
                    let more = self.sched.link_up(link, self.now, Channel::from_link_kat(client)).unwrap();
                    work.extend(more);
                    let more = self.sched.work(self.now, &mut self.src).unwrap();
                    work.extend(more);
                }
                Output::Write { link, bytes, frame, .. } => {
                    assert!(!bytes.is_empty() && bytes.len() % FRAME_LEN == 0, "a write of {} bytes", bytes.len());
                    let peer = self.peers.get_mut(&link).expect("a write on a link that is not up");
                    peer.unreported.push(frame);
                    for unit in bytes.chunks(FRAME_LEN) {
                        let request = peer.relay.open_request(unit).expect("the written frame opens as a request");
                        match &request.cmd {
                            RequestCmd::Send { sid, .. } => {
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
                            RequestCmd::Fetch { rid, ack, .. } => {
                                if let Some(q) = self.rids.get(rid) {
                                    self.relay_ack.insert(*q, *ack);
                                }
                            }
                            RequestCmd::FetchMulti { entries } => {
                                for e in entries {
                                    if let Some(q) = self.rids.get(&e.rid) {
                                        self.relay_ack.insert(*q, e.ack);
                                    }
                                }
                            }
                            _ => {}
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

    /// Persist-before-ack (CLAUDE.md §1.7): every handed cell at or below the acknowledgement the relay saw is committed.
    fn check_acks(&self) {
        for (queue, ack) in &self.relay_ack {
            let Some(handed) = self.src.handed.get(queue) else { continue };
            for id in handed.iter().filter(|id| **id <= *ack) {
                assert!(
                    self.src.committed.get(queue).is_some_and(|c| c.contains(id)),
                    "queue {queue:?}: id {id} acknowledged ({ack}) but not committed"
                );
            }
        }
    }

    fn poll(&mut self) {
        let outs = self.sched.poll(self.now, &mut self.src).unwrap();
        self.apply(outs);
    }

    /// The lowest cells above `ack`, at most `max`, as `(rid, cell id)`.
    fn lowest(rid: Id, ack: u64, max: u64) -> Vec<(Id, u64)> {
        (ack + 1..=ack + max).map(|id| (rid, id)).collect()
    }

    /// Answer the oldest outstanding request of `link` under the response mode `m` (0: honest).
    fn answer(&mut self, link: LinkId, m: u8) {
        let Some(peer) = self.peers.get_mut(&link) else { return };
        if peer.pending.is_empty() {
            return;
        }
        let request = peer.pending.remove(0);
        let seq = request.cmd_seq;
        let fetched: Option<(Vec<(Id, u64)>, usize)> = match &request.cmd {
            RequestCmd::Fetch { rid, ack, .. } => {
                Some((if self.rids.contains_key(rid) { Self::lowest([0; 16], *ack, 4) } else { Vec::new() }, 4))
            }
            RequestCmd::FetchMulti { entries } => {
                let mut out = Vec::new();
                for e in entries {
                    if out.len() < 8 && self.rids.contains_key(&e.rid) {
                        let room = (8 - out.len()) as u64;
                        out.extend(Self::lowest(e.rid, e.ack, room));
                    }
                }
                Some((out, 8))
            }
            _ => None,
        };
        let responses: Vec<Response> = match fetched {
            Some((mut cells, size)) => {
                if m & 1 != 0 {
                    cells.reverse();
                }
                if m & 2 != 0 && !cells.is_empty() {
                    cells.remove(cells.len() / 2);
                }
                if m & 4 != 0 && !cells.is_empty() && cells.len() < size {
                    cells.push(cells[0]);
                }
                let mut out: Vec<Response> = cells
                    .into_iter()
                    .map(|(rid, id)| Response {
                        cmd_seq: seq,
                        cmd: ResponseCmd::Cellr(Cellr::Cell {
                            rid,
                            cell_id: id,
                            cell: Cell::from_bytes(&[(id & 0xff) as u8; 4096]).unwrap(),
                        }),
                    })
                    .collect();
                while out.len() < size {
                    out.push(dummy(seq));
                }
                out
            }
            None => match &request.cmd {
                RequestCmd::Send { .. } => {
                    self.next_cell_id += 1;
                    vec![Response { cmd_seq: seq, cmd: ResponseCmd::OkSend { cell_id: self.next_cell_id, evicted: None } }]
                }
                _ => vec![Response { cmd_seq: seq, cmd: ResponseCmd::Ok }],
            },
        };
        let mut units = Vec::new();
        for r in &responses {
            let padded = r.encode().unwrap();
            let payload = unpad(&padded, FRAME_PLAINTEXT_LEN).unwrap();
            units.push(peer.relay.seal(payload).unwrap());
        }
        for unit in units {
            let outs = self.sched.on_frame(link, self.now, &unit[..]).unwrap();
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
        src: Src::default(),
        now: 0,
        peers: BTreeMap::new(),
        periods: BTreeMap::new(),
        last_send: BTreeMap::new(),
        queues: Vec::new(),
        next_sid: 0,
        next_cell_id: 0,
        rids: BTreeMap::new(),
        relay_ack: BTreeMap::new(),
    };
    for _ in 0..MAX_EVENTS {
        if b.0.is_empty() {
            break;
        }
        match b.u8() % 12 {
            0 => {
                w.now += u64::from(b.u16());
                w.poll();
            }
            1 => {
                w.now += u64::from(b.u32()) % 86_400_000;
                w.poll();
            }
            2 => {
                let link = w.link_at(b.u8());
                let m = b.u8();
                w.src.answer = ((m >> 3) & 3) % 3;
                if let Some(link) = link {
                    w.answer(link, m);
                }
                w.poll();
                w.src.answer = 0;
            }
            3 => {
                if let Some(link) = w.link_at(b.u8()) {
                    w.peers.remove(&link);
                    let outs = w.sched.on_closed(link, w.now).unwrap();
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
                let rid = *cap.queue().rid();
                if let Ok(q) = w.sched.add_recv_queue(w.now, relay, cap, period) {
                    w.queues.push(q);
                    w.rids.insert(rid, q);
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
                        w.answer(link, 0);
                    }
                }
                w.poll();
            }
            10 => {
                let pick = b.u8();
                let pending: Vec<(QueueId, u64)> = w.src.pending.iter().copied().collect();
                if !pending.is_empty() {
                    let (queue, id) = pending[usize::from(pick) % pending.len()];
                    w.src.pending.remove(&(queue, id));
                    w.src.committed.entry(queue).or_default().insert(id);
                    w.sched.delivery_committed(queue, id);
                }
                w.poll();
            }
            11 => {
                let link = w.link_at(b.u8());
                let twice = b.u8() & 1 != 0;
                if let Some(link) = link
                    && let Some(peer) = w.peers.get_mut(&link)
                    && !peer.unreported.is_empty()
                {
                    let frame = peer.unreported.remove(0);
                    let _ = w.sched.frame_written(link, frame);
                    if twice {
                        // a duplicate report: refused, nothing changes
                        let _ = w.sched.frame_written(link, frame);
                    }
                }
            }
            _ => w.poll(),
        }
        w.check_acks();
    }
});
