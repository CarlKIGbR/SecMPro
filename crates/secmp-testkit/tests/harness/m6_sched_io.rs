// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d1) the cell path of the scheduler: one path for real and dummy cells, persist-before-send / -ack, acknowledgement
//! of every delivered cell, response handling, queue re-creation (S-25…S-32; spec §7.5, §9.1, §9.3, §10.3).

use secmp_client_core::scheduler::conversation::{Conversation, Conversations, counters};
use secmp_client_core::scheduler::core::{LinkKind, Scheduler};
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, MsgState, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{
    Alert, CellSource, CellToken, ControlKind, LinkEvent, LinkId, Output, PreparedCell, QueueId,
    Reason, RelayId, SendFailure, SourceError,
};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::tr::{Entropy, FixedEntropy};
use secmp_proto::wire::cell::{AppKind, Cell};
use secmp_proto::wire::frame::{ErrCode, Request, RequestCmd, Response, ResponseCmd};
use secmp_testkit::harness::{Audit, Dir, EntropyPool, Inspect, START_UNIX, VirtualDriver, ratchet_pair};
use secmp_transport::{QueueTransport, RecvCap, RelayQueueTransport, SendCap, Session};

use crate::m6_common::{
    FRAME, client, contact, driver, frames, frames_of, half_contact, inject, run_until_link_up,
    send_only,
};
use crate::scripted::{self, Script, Scripted};

fn text(n: u8, len: usize) -> OutMessage {
    OutMessage {
        msg_id: [n; 16],
        kind: AppKind::Text,
        expire_after: 0,
        payload: Zeroizing::new(vec![n; len]),
    }
}

fn at(t_up: u64, k: u64, period: u64) -> u64 {
    t_up.checked_add(k.checked_mul(period).unwrap()).unwrap()
}

type TestConv = Conversation<MemOutbox, MemPersist, EntropyPool>;

/// A conversation over a fresh ratchet pair; the second state is the peer's, to open the cells.
fn conv_with_peer(tag: u32) -> (TestConv, secmp_proto::tr::RatchetState, EntropyPool) {
    let sk = SecretBytes::from_slice(&[7_u8; 32]).unwrap();
    let mut pool = EntropyPool::new("m6-io-pair", tag);
    let transcript: [u8; 32] = pool.bytes(32).try_into().unwrap();
    let mut ea = FixedEntropy::new(&pool.bytes(1 << 16));
    let mut eb = FixedEntropy::new(&pool.bytes(1 << 16));
    let (sender, receiver) = ratchet_pair(&sk, &transcript, &mut ea, &mut eb);
    let peer_key = pool.get().hybrid_signing_key().unwrap().verifying_key();
    let mut conv = Conversation::new(
        sender,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-io-conv", tag),
        peer_key,
        START_UNIX,
    );
    conv.bind(QueueId(0), QueueId(1));
    (conv, receiver, EntropyPool::new("m6-io-peer", tag))
}

fn content_type_of(cell: &Cell, peer: secmp_proto::tr::RatchetState, pool: &mut EntropyPool) -> (u8, secmp_proto::tr::RatchetState) {
    let opened = peer.decrypt_with(cell.as_bytes(), pool.get()).ok().unwrap();
    let ty = opened.plaintext().content().unwrap().body.content_type();
    let (state, _) = opened.commit(|_| Ok::<(), ()>(())).unwrap();
    (ty, state)
}

/// S-25: a dummy and a real message take the same path — one `encrypt` call site, both 4 096 B; Content types 0x00 and
/// 0x02; the frames carrying them are the same operation and size.
#[test]
fn real_and_dummy_share_one_path() {
    let (conv, peer, mut pool) = conv_with_peer(1);
    let mut convs = Conversations::new();
    let i = convs.add(conv);
    let before = counters::tr_encrypt_calls();
    let dummy = convs.prepare_cell(QueueId(0), 0).unwrap().unwrap();
    convs.get_mut(i).unwrap().outbox_mut().enqueue(text(1, 100), 0);
    let real = convs.prepare_cell(QueueId(0), 10_000).unwrap().unwrap();
    assert_eq!(counters::tr_encrypt_calls() - before, 2);
    assert_eq!(counters::encrypt_sites(), vec!["Conversation::seal"], "one call site");
    assert_eq!((dummy.cell.as_bytes().len(), real.cell.as_bytes().len()), (4096, 4096));
    let (t1, peer) = content_type_of(&dummy.cell, peer, &mut pool);
    let (t2, _) = content_type_of(&real.cell, peer, &mut pool);
    assert_eq!((t1, t2), (0x00, 0x02));

    // on the wire: the same request, the same size
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 251);
    let b = client(&mut d, Mode::Strict, 252);
    let c = contact(&mut d, a, b, 10_000, 80_000);
    d.client(a).opts.inspect = Inspect::Requests;
    d.run_until(300_000);
    d.client(a).convs.get_mut(c.conv_a).unwrap().outbox_mut().enqueue(text(2, 500), 300_000);
    d.run_until(600_000);
    let c2r = frames(&d, a, Dir::C2R);
    assert!(c2r.iter().all(|e| e.len == FRAME));
    let sends = d
        .client_ref(a)
        .requests
        .iter()
        .filter(|(_, _, r)| matches!(r.cmd, RequestCmd::Send { .. }))
        .count();
    assert!(sends > 20);
    assert_eq!(
        d.client_ref(b).convs.get(c.conv_b).unwrap().received().len(),
        1,
        "the real message arrived among the dummies"
    );
}

/// S-26: persist before send — encrypt, then persist, then seal, then write; when persisting fails no frame is built
/// and the message stays queued.
#[test]
fn persist_before_send_order() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 261);
    let b = client(&mut d, Mode::Strict, 262);
    let c = send_only(&mut d, a, b, 10_000);
    d.client(a).convs.get_mut(c).unwrap().outbox_mut().enqueue(text(1, 60), 0);
    d.run_until(400_000);
    let audit = d.client_ref(a).gate.audit.clone();
    let mut last_prepared: Option<[u64; 3]> = None;
    let mut checked = 0;
    for e in &audit {
        match *e {
            Audit::Prepared(p) => {
                assert_eq!(p[0], p[1], "every encrypt was persisted before the cell was released");
                if let Some(q) = last_prepared {
                    assert_eq!(p[0] - q[0], 1);
                }
                last_prepared = Some(p);
            }
            Audit::Wrote(seal) => {
                let p = last_prepared.expect("written after prepared");
                assert!(seal > p[2], "sealed after persisted, written after sealed");
                checked += 1;
            }
        }
    }
    assert!(checked > 10);

    // run 2: persist fails — no frame is prepared, the link goes down at the tick, the message stays queued
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 263);
    let b = client(&mut d, Mode::Strict, 264);
    let c = send_only(&mut d, a, b, 10_000);
    let (slot, t_up) = run_until_link_up(&mut d, a, LinkKind::Send);
    {
        let conv = d.client(a).convs.get_mut(c).unwrap();
        conv.persist_mut().set_failing(true);
        conv.outbox_mut().enqueue(text(9, 60), 0);
    }
    let _ = (slot, t_up);
    d.run_until(at(t_up, 3, 10_000));
    let torn = d
        .client_ref(a)
        .events
        .iter()
        .any(|(_, e)| matches!(e, LinkEvent::TornDown(_, Reason::Overrun)));
    assert!(torn, "no frame was prepared: overrun");
    let state = d.client_ref(a).convs.get(c).unwrap().outbox().state(&[9; 16]);
    assert_eq!(state, Some(MsgState::Queued));
}

/// S-27: persist before ack — a cell whose commit fails is not acknowledged and is fetched again; once the commit
/// succeeds the acknowledgement moves.
#[test]
fn persist_before_ack_order() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 271);
    let b = client(&mut d, Mode::Strict, 272);
    let h = half_contact(&mut d, a, b, 10_000);
    let real = {
        let conv = d.client(b).convs.get_mut(h.conv_b).unwrap();
        conv.outbox_mut().enqueue(text(5, 80), 0);
        conv.prepare_direct(0).unwrap().cell
    };
    d.client(a).convs.get_mut(h.conv_a).unwrap().persist_mut().set_failing(true);
    d.client(a).opts.inspect = Inspect::Requests;
    let id = inject(&mut d, b, &h, &real);
    let (slot, t_up) = run_until_link_up(&mut d, a, LinkKind::Recv);
    d.run_until(at(t_up, 4, 10_000));
    assert_eq!(d.client_ref(a).sched.acked(h.a_recv), Some(0), "no acknowledgement without a commit");
    let acks: Vec<u64> = fetch_acks(&d, a, slot);
    assert!(acks.iter().all(|a| *a == 0), "the next FETCHes carry the old ack: {acks:?}");
    assert!(d.client_ref(a).gate.delivered.get(&(h.a_recv.0, id)).copied().unwrap_or(0) >= 2, "fetched again");
    d.client(a).convs.get_mut(h.conv_a).unwrap().persist_mut().set_failing(false);
    d.run_until(at(t_up, 7, 10_000));
    assert_eq!(d.client_ref(a).sched.acked(h.a_recv), Some(id));
    assert_eq!(d.client_ref(a).convs.get(h.conv_a).unwrap().received().len(), 1);
}

fn fetch_acks(d: &VirtualDriver, c: usize, slot: u64) -> Vec<u64> {
    d.client_ref(c)
        .requests
        .iter()
        .filter(|(_, s, _)| *s == slot)
        .filter_map(|(_, _, r)| match &r.cmd {
            RequestCmd::Fetch { ack, .. } => Some(*ack),
            _ => None,
        })
        .collect()
}

/// S-28: a cell that does not decrypt is discarded, its decision is committed and the acknowledgement covers it; the
/// real cells around it are delivered.
#[test]
fn every_delivered_cell_is_acknowledged() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 281);
    let b = client(&mut d, Mode::Strict, 282);
    let h = half_contact(&mut d, a, b, 10_000);
    let (r1, r2) = {
        let conv = d.client(b).convs.get_mut(h.conv_b).unwrap();
        conv.outbox_mut().enqueue(text(1, 80), 0);
        let r1 = conv.prepare_direct(0).unwrap().cell;
        conv.outbox_mut().enqueue(text(2, 80), 0);
        let r2 = conv.prepare_direct(0).unwrap().cell;
        (r1, r2)
    };
    let id1 = inject(&mut d, b, &h, &r1);
    let garbage = Cell::from_bytes(&[0x33; 4096]).unwrap();
    let id2 = inject(&mut d, b, &h, &garbage);
    let id3 = inject(&mut d, b, &h, &r2);
    assert_eq!((id1, id2, id3), (1, 2, 3));
    let (_, t_up) = run_until_link_up(&mut d, a, LinkKind::Recv);
    d.run_until(at(t_up, 3, 10_000));
    let conv = d.client_ref(a).convs.get(h.conv_a).unwrap();
    assert_eq!(conv.received().len(), 2, "both real cells delivered");
    assert_eq!(conv.discarded(), 1);
    assert_eq!(d.client_ref(a).sched.acked(h.a_recv), Some(3), "the ack covers the discarded cell");
}

/// S-29: a cell delivered twice by the relay (a re-fetch with an older acknowledgement) is processed once.
#[test]
fn refetch_dedup_by_cell_id() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 291);
    let b = client(&mut d, Mode::Strict, 292);
    let h = half_contact(&mut d, a, b, 10_000);
    let real = {
        let conv = d.client(b).convs.get_mut(h.conv_b).unwrap();
        conv.outbox_mut().enqueue(text(3, 80), 0);
        conv.prepare_direct(0).unwrap().cell
    };
    let id = inject(&mut d, b, &h, &real);
    d.client(a).latency_ms = 9_500;
    d.client(a).opts.inspect = Inspect::Requests;
    let (slot, t_up) = run_until_link_up(&mut d, a, LinkKind::Recv);
    d.run_until(at(t_up, 5, 10_000));
    let acks = fetch_acks(&d, a, slot);
    assert!(acks.iter().filter(|a| **a == 0).count() >= 2, "the cell was asked for twice: {acks:?}");
    assert_eq!(d.client_ref(a).gate.delivered.get(&(h.a_recv.0, id)), Some(&1), "processed once");
    assert_eq!(d.client_ref(a).convs.get(h.conv_a).unwrap().received().len(), 1);
}

// ---- S-30: response handling against a scripted relay ---------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Relayed(u64, u64),
    Evicted(u64),
    Failed(SendFailure),
    Discard,
    Lost,
}

#[derive(Default)]
struct Fake {
    next: u64,
    calls: Vec<Call>,
}

impl CellSource for Fake {
    fn prepare_cell(&mut self, _: QueueId, _: u64) -> Result<Option<PreparedCell>, SourceError> {
        self.next += 1;
        Ok(Some(PreparedCell {
            cell: Cell::from_bytes(&[u8::try_from(self.next).unwrap(); 4096]).unwrap(),
            token: CellToken(self.next),
        }))
    }
    fn relayed(&mut self, _: QueueId, t: CellToken, id: u64) {
        self.calls.push(Call::Relayed(t.0, id));
    }
    fn evicted(&mut self, _: QueueId, id: u64) {
        self.calls.push(Call::Evicted(id));
    }
    fn send_failed(&mut self, _: QueueId, _: CellToken, why: SendFailure) {
        self.calls.push(Call::Failed(why));
    }
    fn discard(&mut self, _: QueueId, _: CellToken) {
        self.calls.push(Call::Discard);
    }
    fn queue_lost(&mut self, _: QueueId) {
        self.calls.push(Call::Lost);
    }
    fn deliver(&mut self, _: QueueId, _: u64, _: &Cell) -> Result<(), SourceError> {
        Ok(())
    }
}

/// The scheduler core driven by hand against a scripted relay.
struct Rig {
    sched: Scheduler,
    src: Fake,
    stream: Scripted,
    link: Option<LinkId>,
    writes: Vec<u64>,
    events: Vec<LinkEvent>,
    now: u64,
}

impl Rig {
    fn new(script: Script, mode: Mode) -> Self {
        let params = Params {
            phase_max_ms: 0,
            ..Params::default()
        };
        let mut sched = Scheduler::new(params, mode, TimingRng::seeded(3));
        let cap = SendCap::from_route([1; 16], &SecretBytes::from_slice(&[9; 32]).unwrap()).unwrap();
        sched.add_send_queue(0, RelayId(0), cap, 10_000).unwrap();
        Self {
            sched,
            src: Fake::default(),
            stream: Scripted::new(script),
            link: None,
            writes: Vec::new(),
            events: Vec::new(),
            now: 0,
        }
    }

    fn apply(&mut self, outs: Vec<Output>) {
        let mut queue: std::collections::VecDeque<Output> = outs.into();
        while let Some(o) = queue.pop_front() {
            match o {
                Output::Connect { link, .. } => {
                    let id = scripted::identity();
                    let mut entropy = EntropyPool::new("m6-rig-client", 0);
                    let session = Session::connect(
                        self.stream.clone(),
                        id.fp,
                        Some(&id.access),
                        scripted::T0,
                        entropy.get(),
                    )
                    .unwrap();
                    let (_s, chan) = session.into_parts();
                    self.link = Some(link);
                    let more = self.sched.link_up(link, self.now, chan, &mut self.src).unwrap();
                    queue.extend(more);
                }
                Output::Write { link, bytes } => {
                    self.writes.push(self.now);
                    std::io::Write::write_all(&mut self.stream, &bytes).unwrap();
                    loop {
                        let mut frame = vec![0_u8; FRAME];
                        let mut got = 0;
                        while got < FRAME {
                            let n = std::io::Read::read(&mut self.stream, &mut frame[got..]).unwrap();
                            if n == 0 {
                                break;
                            }
                            got += n;
                        }
                        if got < FRAME {
                            break;
                        }
                        let more = self.sched.on_frame(link, self.now, &frame, &mut self.src).unwrap();
                        queue.extend(more);
                    }
                }
                Output::Event(e) => self.events.push(e),
                Output::Close { .. } | Output::Control { .. } => {}
            }
        }
    }

    fn run_to(&mut self, t_end: u64) {
        loop {
            match self.sched.next_deadline() {
                Some(t) if t <= t_end => {
                    self.now = t.max(self.now);
                    let outs = self.sched.poll(self.now, &mut self.src).unwrap();
                    self.apply(outs);
                }
                _ => break,
            }
        }
        self.now = t_end;
    }
}

fn send_script() -> Script {
    Box::new(|request: &Request, n| {
        let seq = request.cmd_seq;
        let resp = match n {
            0 => ResponseCmd::OkSend { cell_id: 10, evicted: Some(5) },
            1 => ResponseCmd::OkSend { cell_id: 11, evicted: Some(6) },
            2 => ResponseCmd::Err(ErrCode::NoQueue),
            3 => ResponseCmd::Err(ErrCode::Auth),
            _ => ResponseCmd::Err(ErrCode::Rate),
        };
        vec![Response { cmd_seq: seq, cmd: resp }]
    })
}

/// S-30: `OK_SEND` with an evicted id, `ERR` 3, 4 and 7 each have their consequence, and none changes the tick
/// schedule.
#[test]
fn send_response_handling() {
    let mut rig = Rig::new(send_script(), Mode::Strict);
    rig.run_to(0);
    let t_up = 0;
    rig.run_to(at(t_up, 5, 10_000));
    assert_eq!(rig.writes, (1..=5).map(|k| k * 10_000).collect::<Vec<u64>>(), "schedule unchanged");
    assert_eq!(
        rig.src.calls,
        vec![
            Call::Relayed(1, 10),
            Call::Evicted(5),
            Call::Relayed(2, 11),
            Call::Evicted(6),
            Call::Failed(SendFailure::NoQueue),
            Call::Lost,
            Call::Failed(SendFailure::Auth),
            Call::Failed(SendFailure::Rate),
        ]
    );
    let q = QueueId(0);
    assert!(rig.sched.route_dead(q), "ERR 3 marks the route dead");
    assert!(rig.events.contains(&LinkEvent::RouteDead(q)));
    assert!(rig.events.contains(&LinkEvent::Alert(q, Alert::QueueAuth)));
    assert!(rig.events.contains(&LinkEvent::Alert(q, Alert::QueueRate)));
    assert!(!rig.events.iter().any(|e| matches!(e, LinkEvent::TornDown(..))), "no teardown");
}

/// S-31: a `FETCH` answered `present` 2 makes the recipient re-create the identical queue on a one-shot link after
/// `U[10 s, 5 min]`, with its acknowledgement reset; the recv link keeps its ticks.
#[test]
fn recv_noqueue_recreates_after_delay() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 311);
    let b = client(&mut d, Mode::Strict, 312);
    let c = contact(&mut d, a, b, 10_000, 10_000);
    let (slot, t_up) = run_until_link_up(&mut d, a, LinkKind::Recv);
    d.run_until(at(t_up, 40, 10_000));
    assert!(d.client_ref(a).sched.acked(c.a_recv).unwrap() > 0);
    // the relay loses the queue (QUEUE_DEL by its owner's key stands in for a restart that keeps the connections)
    let (recv_seed, send_seed) = *d.client_ref(a).material.queues.get(&c.a_recv.0).unwrap();
    {
        let access = d.harness().access_key();
        let fp = d.harness().relay_fp();
        let unix = d.harness().clock().unix();
        let stream = d.harness_mut().open_stream().unwrap();
        let mut t = RelayQueueTransport::connect(stream, fp, Some(&access), unix, d.client(a).entropy.get()).unwrap();
        t.delete_queue(&RecvCap::from_seed(&SecretBytes::from_slice(&recv_seed).unwrap()).unwrap()).unwrap();
    }
    let t_gone = d.now();
    d.run_until(at(t_up, 41, 10_000));
    let t_seen = at(t_up, 41, 10_000);
    assert_eq!(d.client_ref(a).sched.acked(c.a_recv), Some(0), "acknowledgement reset");
    d.run_until(t_seen + 320_000);
    let started: Vec<_> = d
        .client_ref(a)
        .controls_started
        .iter()
        .filter(|(_, _, k)| matches!(k, ControlKind::QueueNew(q) if *q == c.a_recv))
        .collect();
    assert_eq!(started.len(), 1, "one re-creation");
    let when = started.first().unwrap().0;
    assert!((t_seen + 10_000..=t_seen + 300_000).contains(&when), "t + U[10 s, 5 min]: {t_gone} {t_seen} {when}");
    // identical keys: the original sender capability works again, and the recv link has kept its ticks
    let sends = d.client_ref(a).material.queues.get(&c.a_recv.0).copied();
    assert_eq!(sends, Some((recv_seed, send_seed)));
    let ticks: Vec<u64> = frames_of(&d, a, Dir::C2R, slot).iter().map(|e| e.t_ms).collect();
    for (k, t) in ticks.iter().enumerate() {
        assert_eq!(*t, at(t_up, u64::try_from(k).unwrap() + 1, 10_000));
    }
    assert!(!d.client_ref(a).events.iter().any(|(_, e)| matches!(e, LinkEvent::TornDown(id, _) if id.0 == slot)));
    assert!(d.client_ref(a).sched.acked(c.a_recv).unwrap() > 0, "fetching again after the re-creation");
}

/// S-32: after `ERR_NOQUEUE` on a send queue the sender forgets its `cell_id → message` map; a later `evicted` id of the
/// re-created queue does not requeue a stale message.
#[test]
fn sender_noqueue_discards_cell_id_map() {
    let (conv, _peer, _) = conv_with_peer(32);
    let mut convs = Conversations::new();
    let i = convs.add(conv);
    for n in 0..7_u8 {
        convs.get_mut(i).unwrap().outbox_mut().enqueue(text(n, 30), 0);
        let p = convs.prepare_cell(QueueId(0), u64::from(n) * 10_000).unwrap().unwrap();
        convs.relayed(QueueId(0), p.token, u64::from(n) + 1);
    }
    assert_eq!(convs.get(i).unwrap().mapped_cells(), 7);
    convs.queue_lost(QueueId(0));
    assert_eq!(convs.get(i).unwrap().mapped_cells(), 0, "map empty");
    // the messages were relayed into a queue that is gone: queued again
    for n in 0..7_u8 {
        assert_eq!(convs.get(i).unwrap().outbox().state(&[n; 16]), Some(MsgState::Queued));
    }
    // take one message out again (relayed in the new queue), then a stale evicted id arrives: ignored
    let p = convs.prepare_cell(QueueId(0), 100_000).unwrap().unwrap();
    convs.relayed(QueueId(0), p.token, 20);
    assert_eq!(convs.get(i).unwrap().outbox().state(&[0; 16]), Some(MsgState::Relayed(20)));
    convs.evicted(QueueId(0), 3);
    assert_eq!(convs.get(i).unwrap().outbox().state(&[0; 16]), Some(MsgState::Relayed(20)), "stale id ignored");
}
