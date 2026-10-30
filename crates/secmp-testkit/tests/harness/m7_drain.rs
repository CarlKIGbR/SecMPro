// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7 B-SC: the drain of a recipient (OQ-20, OPEN-M7-08 A; spec §10.2 `docs/03:661-662`, §9.3; CLAUDE.md §1.7) —
//! TEST-SPEC-M7 SC-01, SC-02. The core hands every present cell of a response to the cell source at once and
//! acknowledges the highest committed prefix of what it fetched; the next `FETCH` carries the acknowledgement.

use std::collections::BTreeSet;

use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::params::Mode;
use secmp_client_core::scheduler::types::{
    CellSource, CellToken, Delivered, LinkId, Output, PreparedCell, QueueId, RelayId, SendFailure,
    SourceError,
};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::SecretBytes;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{Cellr, ErrCode, Request, RequestCmd, Response, ResponseCmd};
use secmp_testkit::harness::EntropyPool;
use secmp_transport::{RecvCap, Session};

use crate::m6_activity::Scenario;
use crate::m6_common::{FRAME, evidence};
use crate::m6_driver_io::no_phase;
use crate::m6_tokio::{AI_COSTS, Setup, TClient, TokioRig, runtime};
use crate::scripted::{self, Script, Scripted};

/// The period of the queue (Strict) and `T_BALANCED` (Balanced).
const P: u64 = 10_000;

/// `k` periods after `t0`, `into` milliseconds into the period.
fn at(t0: u64, k: u64, into: u64) -> u64 {
    t0.saturating_add(k.saturating_mul(P)).saturating_add(into)
}

/// One drain run, sampled in the middle of every period (the response of the period's tick is committed by then):
/// per period, the cells committed in it and the backlog before it (cells sent to the client and not yet committed).
struct Drain {
    per_period: Vec<(u64, u64)>,
    /// The first period after which nothing sent to the client is uncommitted.
    drained_after: Option<u64>,
}

/// The client under test receives a 128-cell backlog stored before its first `FETCH`; with `constant` its peer then sends
/// one cell per period (`k = 1`), at 7 s into the period, after the sample.
fn drain(mode: Mode, constant: bool, seed: u64) -> Drain {
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = Scenario {
            mode,
            contacts: vec![(P, P)],
            pool: false,
            seed,
        };
        let x = TClient::new(&setup, sc.mode, no_phase(), sc.seed, AI_COSTS, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        rig.quiet_peers();
        let t0 = rig.setup.now();
        rig.peer_cells(0, 0, 128, t0).await;
        let mut sent = 128_u64;
        let committed = |rig: &TokioRig| {
            u64::try_from(rig.x.convs.lock().unwrap().get(0).unwrap().received().len()).unwrap()
        };
        let (mut per_period, mut drained_after, mut before) = (Vec::new(), None, 0_u64);
        for k in 1..=80_u64 {
            rig.x.run_until(at(t0, k, 5_000)).await;
            let now = committed(&rig);
            per_period.push((now.saturating_sub(before), sent.saturating_sub(before)));
            before = now;
            if sent == now {
                drained_after = Some(k);
                break;
            }
            if constant {
                let t = at(t0, k, 7_000);
                rig.x.run_until(t).await;
                rig.peer_cells(0, sent, 1, t).await;
                sent = sent.saturating_add(1);
            }
        }
        assert_eq!(rig.x.sched.overruns(), 0);
        Drain {
            per_period,
            drained_after,
        }
    })
}

/// The assertions of SC-01 for one fixture: every response commits at least `min(F, backlog) − 1` cells (Strict: while
/// the backlog is at least `F`), and the backlog is 0 within `bound` periods.
fn check(name: &str, d: &Drain, f: u64, strict: bool, bound: u64) {
    let text = format!(
        "{name}: (committed in the period, backlog before it) per period: {:?}; drained after {:?} periods (bound {bound})",
        d.per_period, d.drained_after
    );
    evidence(&format!("SC-01-{name}"), &text);
    for (committed, backlog) in &d.per_period {
        let floor = if strict {
            if *backlog >= f {
                f.saturating_sub(1)
            } else {
                0
            }
        } else {
            f.min(*backlog).saturating_sub(1)
        };
        assert!(*committed >= floor, "{text}");
    }
    assert!(d.drained_after.is_some_and(|k| k <= bound), "{text}");
}

/// SC-01 [O-08] `drain_f_cells_per_response` (Q168): a 128-cell backlog, tokio driver, the AI costs (5 ms per received
/// cell). Strict (P = 10 s, F = 4): (a) peer silent — ≥ F − 1 committed per response while the backlog is ≥ F, backlog 0
/// within ⌈128/(F−1)⌉ + 2 = 45 periods; (b) peer at 1/P — backlog 0 within ⌈128/(F−2)⌉ + 2 = 66 periods. Balanced
/// (`F_M` = 8, `T_BALANCED` = 10 s, one contact, `P_q` = 10 s, k = 1): ≥ min(`F_M`, backlog) − 1 per `FETCH_MULTI` response;
/// silent: 0 within 21 slots; constant rate: 0 within 24 slots.
#[test]
fn drain_f_cells_per_response() {
    check(
        "strict-silent",
        &drain(Mode::Strict, false, 181),
        4,
        true,
        45,
    );
    check(
        "strict-constant",
        &drain(Mode::Strict, true, 182),
        4,
        true,
        66,
    );
    check(
        "balanced-silent",
        &drain(Mode::Balanced, false, 183),
        8,
        false,
        21,
    );
    check(
        "balanced-constant",
        &drain(Mode::Balanced, true, 184),
        8,
        false,
        24,
    );
}

// ---- SC-02: the acknowledgement is the highest committed prefix -----------------------------------------------------

/// A cell source whose decisions commit later: `deliver` answers `Pending` until the test reports the cell committed
/// (then `Committed`), as the driver's facade does with its worker.
#[derive(Default)]
struct Later {
    committed: BTreeSet<u64>,
    asked: Vec<u64>,
}

impl CellSource for Later {
    fn prepare_cell(&mut self, _: QueueId, _: u64) -> Result<Option<PreparedCell>, SourceError> {
        Ok(None)
    }
    fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
    fn evicted(&mut self, _: QueueId, _: u64) {}
    fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
    fn discard(&mut self, _: QueueId, _: CellToken) {}
    fn queue_lost(&mut self, _: QueueId) {}
    fn deliver(&mut self, _: QueueId, id: u64, _: &Cell) -> Result<Delivered, SourceError> {
        self.asked.push(id);
        Ok(if self.committed.contains(&id) {
            Delivered::Committed
        } else {
            Delivered::Pending
        })
    }
}

/// A scripted relay holding cells 1, 2, 3 of the queue: every `FETCH` is answered with the cells above its `ack` and
/// dummies up to F = 4.
fn three_cells() -> Script {
    Box::new(|request: &Request, _| match &request.cmd {
        RequestCmd::Fetch { ack, .. } => {
            let seq = request.cmd_seq;
            let mut out: Vec<Response> = (1..=3_u64)
                .filter(|id| id > ack)
                .map(|id| Response {
                    cmd_seq: seq,
                    cmd: ResponseCmd::Cellr(Cellr::Cell {
                        rid: [0; 16],
                        cell_id: id,
                        cell: scripted::cell(u8::try_from(id).unwrap()),
                    }),
                })
                .collect();
            while out.len() < 4 {
                out.push(scripted::dummy(seq));
            }
            out
        }
        _ => vec![scripted::err(request.cmd_seq, ErrCode::Malformed)],
    })
}

/// The core driven by hand against the scripted relay (as `m6_sched_io::Rig`, with the deferred cell source).
struct Rig {
    sched: Scheduler,
    src: Later,
    stream: Scripted,
    writes: Vec<u64>,
    now: u64,
}

impl Rig {
    fn apply(&mut self, outs: Vec<Output>) {
        let mut queue: std::collections::VecDeque<Output> = outs.into();
        while let Some(o) = queue.pop_front() {
            match o {
                Output::Connect { link, .. } => {
                    let id = scripted::identity();
                    let mut entropy = EntropyPool::new("m7-drain-client", 0);
                    let session = Session::connect(
                        self.stream.clone(),
                        id.fp,
                        Some(&id.access),
                        scripted::T0,
                        entropy.get(),
                    )
                    .unwrap();
                    let (_s, chan) = session.into_parts();
                    queue.extend(self.sched.link_up(link, self.now, chan).unwrap());
                    queue.extend(self.sched.work(self.now, &mut self.src).unwrap());
                }
                Output::Write { link, bytes, at } => self.write(link, &bytes, at, &mut queue),
                Output::Event(_) | Output::Close { .. } | Output::Control { .. } => {}
            }
        }
    }

    fn write(
        &mut self,
        link: LinkId,
        bytes: &[u8],
        at: u64,
        queue: &mut std::collections::VecDeque<Output>,
    ) {
        self.writes.push(at);
        std::io::Write::write_all(&mut self.stream, bytes).unwrap();
        self.sched.frame_written(link);
        loop {
            let mut frame = vec![0_u8; FRAME];
            let mut got = 0_usize;
            while got < FRAME {
                let n =
                    std::io::Read::read(&mut self.stream, frame.get_mut(got..).unwrap()).unwrap();
                if n == 0 {
                    break;
                }
                got = got.saturating_add(n);
            }
            if got < FRAME {
                break;
            }
            queue.extend(self.sched.on_frame(link, self.now, &frame).unwrap());
        }
        queue.extend(self.sched.work(self.now, &mut self.src).unwrap());
    }

    fn poll_at(&mut self, t: u64) {
        self.now = t;
        let outs = self.sched.poll_due(t).unwrap();
        self.apply(outs);
        let outs = self.sched.work(t, &mut self.src).unwrap();
        self.apply(outs);
        self.sched.prepared_until(t);
    }

    fn run_to(&mut self, t_end: u64) {
        while let Some(t) = self.sched.next_deadline().filter(|t| *t <= t_end) {
            self.poll_at(t.max(self.now));
        }
        self.now = t_end;
    }

    /// The worker finished cell `id` at `t` (an injected delay): the commit is reported, and the driver's next pass runs.
    fn commit_at(&mut self, q: QueueId, id: u64, t: u64) {
        self.run_to(t);
        self.src.committed.insert(id);
        self.sched.delivery_committed(q, id);
        self.poll_at(t);
    }

    fn fetch_acks(&self) -> Vec<u64> {
        self.stream
            .seen()
            .iter()
            .filter_map(|r| match &r.cmd {
                RequestCmd::Fetch { ack, .. } => Some(*ack),
                _ => None,
            })
            .collect()
    }
}

/// SC-02 [O-08] `ack_is_highest_committed_prefix` (CLAUDE.md §1.7): the first response carries cells 1, 2, 3, all handed
/// to the cell source at once; their commits complete in the order 1, 3, 2 at 12 s, 15 s and 25 s. The acknowledgement
/// is 1 after the first commit, stays 1 after 3 is committed, and is 3 only after 2 is committed; the `FETCH`es carry 0,
/// 1, 3 at their ticks (10 s, 20 s, 30 s) — commit latency moves no frame.
#[test]
fn ack_is_highest_committed_prefix() {
    let mut sched = Scheduler::new(no_phase(), Mode::Strict, TimingRng::seeded(5));
    let cap = RecvCap::from_seed(&SecretBytes::from_slice(&[0x21; 32]).unwrap()).unwrap();
    let q = sched.add_recv_queue(0, RelayId(0), cap, P).unwrap();
    let mut rig = Rig {
        sched,
        src: Later::default(),
        stream: Scripted::new(three_cells()),
        writes: Vec::new(),
        now: 0,
    };
    rig.run_to(10_000);
    assert_eq!(
        rig.src.asked,
        [1, 2, 3],
        "every cell of the response at once"
    );
    assert_eq!(rig.sched.acked(q), Some(0));
    let mut acks = Vec::new();
    rig.commit_at(q, 1, 12_000);
    acks.push(rig.sched.acked(q));
    rig.commit_at(q, 3, 15_000);
    acks.push(rig.sched.acked(q));
    rig.run_to(20_000);
    rig.commit_at(q, 2, 25_000);
    acks.push(rig.sched.acked(q));
    rig.run_to(30_000);
    let text = format!(
        "acknowledgement after the commits of 1, 3, 2: {acks:?}; FETCH acks: {:?}; ticks: {:?}; delivered: {:?}",
        rig.fetch_acks(),
        rig.writes,
        rig.src.asked
    );
    evidence("SC-02", &text);
    assert_eq!(acks, [Some(1), Some(1), Some(3)], "{text}");
    assert_eq!(rig.fetch_acks(), [0, 1, 3], "{text}");
    assert_eq!(rig.writes, [10_000, 20_000, 30_000], "{text}");
    // the second response (ack 1) carried 2 and 3 again: the pending 2 is handed over again (the facade dedups its
    // jobs), the committed 3 is not
    assert_eq!(rig.src.asked, [1, 2, 3, 2], "{text}");
}
