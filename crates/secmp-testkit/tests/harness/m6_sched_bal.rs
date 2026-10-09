// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d1) Balanced and Low-bw (S-06…S-15; spec §10.2).

use secmp_client_core::scheduler::core::{LinkKind, SchedError, Scheduler};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{
    CellSource, CellToken, LinkEvent, Output, PreparedCell, QueueId, Reason, RelayId, SendFailure,
    SourceError,
};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::SecretBytes;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{Dir, Inspect, VirtualDriver};
use secmp_transport::RecvCap;

use crate::m6_common::{client, contact, contact_on, driver, frames, frames_of, ks_uniform};

fn at(t_up: u64, k: u64, period: u64) -> u64 {
    t_up.checked_add(k.checked_mul(period).unwrap()).unwrap()
}

fn the_link(d: &VirtualDriver, c: usize, kind: LinkKind) -> (u64, u64) {
    let infos = d.client_ref(c).sched.links();
    let info = infos.iter().find(|l| l.kind == kind).unwrap();
    (info.id.unwrap().0, info.t_up.unwrap())
}

pub fn fresh_recv_cap(n: u32) -> RecvCap {
    let mut seed = [0_u8; 32];
    seed.get_mut(..4).unwrap().copy_from_slice(&n.to_be_bytes());
    RecvCap::from_seed(&SecretBytes::from_slice(&seed).unwrap()).unwrap()
}

/// A source for tests that never prepare a cell (no send queue is scheduled).
pub struct NoCells;

impl CellSource for NoCells {
    fn prepare_cell(&mut self, _: QueueId, _: u64) -> Result<Option<PreparedCell>, SourceError> {
        Ok(None)
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

/// S-06: Balanced opens one link per relay — three contacts on relay X, one on relay Y, two pool queues each: 2 links.
#[test]
fn balanced_one_link_per_relay() {
    let mut d = driver();
    let a = client(&mut d, Mode::Balanced, 61);
    let b = client(&mut d, Mode::Strict, 62);
    for _ in 0..3 {
        contact_on(&mut d, a, b, 80_000, 80_000, RelayId(0));
    }
    contact_on(&mut d, a, b, 80_000, 80_000, RelayId(1));
    let now = d.now();
    d.client(a).sched.manage_pool(now, RelayId(0)).unwrap();
    d.client(a).sched.manage_pool(now, RelayId(1)).unwrap();
    d.run_until(3_600_000 + 200_000);
    let links = d.client_ref(a).sched.links();
    assert_eq!(links.len(), 2, "one link per relay");
    assert!(links.iter().all(|l| l.kind == LinkKind::Relay));
    assert_eq!(d.client_ref(a).sched.pool_spares(RelayId(0)), 2);
    assert_eq!(d.client_ref(a).sched.pool_spares(RelayId(1)), 2);
}

/// S-07: a Balanced slot is `SEND`|`PING` then `FETCH_MULTI` (2 frames out), 1 then 8 frames back — 11 per slot.
#[test]
fn balanced_slot_frames() {
    let mut d = driver();
    let a = client(&mut d, Mode::Balanced, 71);
    let b = client(&mut d, Mode::Strict, 72);
    contact(&mut d, a, b, 10_000, 80_000);
    d.client(a).opts.inspect = Inspect::Requests;
    d.run_until(200_000);
    let (slot, t_up) = the_link(&d, a, LinkKind::Relay);
    let t3 = at(t_up, 3, 10_000);
    d.run_until(t3);
    let out: Vec<_> = frames_of(&d, a, Dir::C2R, slot)
        .into_iter()
        .filter(|e| e.t_ms == t3)
        .collect();
    let back: Vec<_> = frames_of(&d, a, Dir::R2C, slot)
        .into_iter()
        .filter(|e| e.t_ms == t3)
        .collect();
    assert_eq!((out.len(), back.len()), (2, 9), "11 frames per slot");
    let reqs: Vec<_> = d
        .client_ref(a)
        .requests
        .iter()
        .filter(|(t, s, _)| *t == t3 && *s == slot)
        .collect();
    assert_eq!(reqs.len(), 2);
    assert!(matches!(
        reqs.first().unwrap().2.cmd,
        RequestCmd::Send { .. } | RequestCmd::Ping
    ));
    assert!(matches!(
        reqs.get(1).unwrap().2.cmd,
        RequestCmd::FetchMulti { .. }
    ));
}

/// The queue each Balanced `SEND`/`PING` of ticks 1…n was prepared for (`-` for a ping).
fn send_sequence(d: &VirtualDriver, a: usize, names: &[(QueueId, char)], n: u32) -> String {
    let mut records: Vec<_> = d
        .client_ref(a)
        .sched
        .prep_log()
        .iter()
        .filter(|r| (r.kind == b'S' || r.kind == b'P') && r.tick >= 1 && r.tick <= n)
        .collect();
    records.sort_by_key(|r| r.tick);
    records
        .iter()
        .map(|r| match r.queue {
            Some(q) => names
                .iter()
                .find(|(id, _)| *id == q)
                .map_or('?', |(_, c)| *c),
            None => '-',
        })
        .collect()
}

/// S-08: the round-robin pointer and the "at least `P_q` ago" rule.
#[test]
fn balanced_round_robin_due_rule() {
    let mut d = driver();
    let a = client(&mut d, Mode::Balanced, 81);
    let b = client(&mut d, Mode::Strict, 82);
    let ca = contact(&mut d, a, b, 10_000, 80_000);
    let cb = contact(&mut d, a, b, 40_000, 80_000);
    let cc = contact(&mut d, a, b, 40_000, 80_000);
    d.run_until(200_000);
    let (_, t_up) = the_link(&d, a, LinkKind::Relay);
    d.run_until(at(t_up, 10, 10_000));
    let names = [(ca.a_send, 'A'), (cb.a_send, 'B'), (cc.a_send, 'C')];
    assert_eq!(send_sequence(&d, a, &names, 10), "ABCAABCAAB");
}

/// S-09: a single send queue at 20 s: `SEND`, `PING`, `SEND`, `PING`, `SEND`.
#[test]
fn balanced_ping_when_none_due() {
    let mut d = driver();
    let a = client(&mut d, Mode::Balanced, 91);
    let b = client(&mut d, Mode::Strict, 92);
    let ca = contact(&mut d, a, b, 20_000, 80_000);
    d.run_until(200_000);
    let (_, t_up) = the_link(&d, a, LinkKind::Relay);
    d.run_until(at(t_up, 5, 10_000));
    assert_eq!(send_sequence(&d, a, &[(ca.a_send, 'A')], 5), "A-A-A");
}

/// S-10: `FETCH_MULTI` lists every recv queue in creation order (3 contacts + 2 pool queues = 5), and a 33rd queue is
/// refused when it is added.
#[test]
fn balanced_fetch_multi_lists_all_recv_queues() {
    let mut d = driver();
    let a = client(&mut d, Mode::Balanced, 101);
    let b = client(&mut d, Mode::Strict, 102);
    let cs: Vec<_> = (0..3)
        .map(|_| contact(&mut d, a, b, 80_000, 80_000))
        .collect();
    let now = d.now();
    d.client(a).sched.manage_pool(now, RelayId(0)).unwrap();
    d.client(a).opts.inspect = Inspect::Requests;
    d.run_until(3_600_000 + 400_000);
    let sched = &d.client_ref(a).sched;
    let mut expected: Vec<_> = cs
        .iter()
        .map(|c| *sched.queue_ref(c.a_recv).unwrap().rid())
        .collect();
    // the pool queues join in the order their creation succeeded
    let pool_ids: Vec<u32> = d
        .client_ref(a)
        .controls_done
        .iter()
        .filter_map(|(_, k)| match k {
            secmp_client_core::scheduler::types::ControlKind::QueueNew(q) => Some(q.0),
            _ => None,
        })
        .collect();
    assert_eq!(pool_ids.len(), 2);
    expected.extend(
        pool_ids
            .into_iter()
            .map(|n| *sched.queue_ref(QueueId(n)).unwrap().rid()),
    );
    let last = d
        .client_ref(a)
        .requests
        .iter()
        .rev()
        .find_map(|(_, _, r)| {
            if let RequestCmd::FetchMulti { entries } = &r.cmd {
                Some(entries.iter().map(|e| e.rid).collect::<Vec<_>>())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(last, expected, "count 5, creation order");
    // the 33rd recv-queue: refused when it is added, nothing changes
    let mut s = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::seeded(5));
    for n in 0..32 {
        s.add_recv_queue(0, RelayId(0), fresh_recv_cap(n), 80_000)
            .unwrap();
    }
    let before = s.links().len();
    let r = s.add_recv_queue(0, RelayId(0), fresh_recv_cap(99), 80_000);
    assert_eq!(r.err(), Some(SchedError::TooManyQueues));
    assert_eq!(s.links().len(), before);
}

fn bound_result(mode: Mode, periods: &[u64]) -> Result<(), SchedError> {
    let mut s = Scheduler::new(Params::default(), mode, TimingRng::seeded(1));
    let mut last = Ok(());
    for (n, p) in periods.iter().enumerate() {
        last = s
            .add_recv_queue(0, RelayId(0), fresh_recv_cap(u32::try_from(n).unwrap()), *p)
            .map(|_| ());
    }
    last
}

/// S-11: the integer rate bound of Balanced.
#[test]
fn balanced_rate_bound_integer_form() {
    assert!(bound_result(Mode::Balanced, &[10_000; 4]).is_ok());
    assert_eq!(
        bound_result(Mode::Balanced, &[10_000; 5]),
        Err(SchedError::RateBound)
    );
    assert!(bound_result(Mode::Balanced, &[20_000; 8]).is_ok());
    assert!(bound_result(Mode::Balanced, &[40_000; 16]).is_ok());
    assert!(bound_result(Mode::Balanced, &[80_000; 32]).is_ok());
    let mut mixed = vec![10_000_u64; 4];
    mixed.push(80_000);
    assert_eq!(bound_result(Mode::Balanced, &mixed), Err(SchedError::RateBound));
}

/// S-12: Low-bw — the bound `Σ 240 000/P ≤ 32`, and 120 slots, 1 320 frames in an hour.
#[test]
fn lowbw_rate_bound_and_slot() {
    assert!(bound_result(Mode::LowBw, &[40_000; 5]).is_ok());
    assert_eq!(
        bound_result(Mode::LowBw, &[40_000; 6]),
        Err(SchedError::RateBound)
    );
    assert!(bound_result(Mode::LowBw, &[80_000; 10]).is_ok());
    assert_eq!(
        bound_result(Mode::LowBw, &[80_000; 11]),
        Err(SchedError::RateBound)
    );
    // 1 h at 30 s slots with five recv-queues at 40 s
    let mut d = driver();
    let a = client(&mut d, Mode::LowBw, 121);
    let now = d.now();
    for _ in 0..5 {
        let (rc, _, _, _) = d.new_queue(a);
        d.client(a)
            .sched
            .add_recv_queue(now, RelayId(0), rc, 40_000)
            .unwrap();
    }
    d.run_until(200_000);
    let (slot, t_up) = the_link(&d, a, LinkKind::Relay);
    d.run_until(at(t_up, 120, 30_000));
    let out = frames_of(&d, a, Dir::C2R, slot).len();
    let back = frames_of(&d, a, Dir::R2C, slot).len();
    assert_eq!((out, back, out + back), (240, 1080, 1320), "120 slots, 11 frames each");
}

/// S-13: direct mode implies Balanced.
#[test]
fn direct_mode_implies_balanced() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 131);
    let b = client(&mut d, Mode::Strict, 132);
    contact(&mut d, a, b, 10_000, 80_000);
    contact(&mut d, a, b, 10_000, 80_000);
    assert_eq!(d.client_ref(a).sched.links().len(), 4, "Strict: a link per queue");
    let now = d.now();
    d.client(a).sched.set_direct(now, true, &mut NoCells).unwrap();
    assert_eq!(d.client_ref(a).sched.effective_mode(), Mode::Balanced);
    assert_eq!(d.client_ref(a).sched.links().len(), 1, "one link per relay");
}

/// S-14: a mode change tears down every old link at once and starts the new ones at independent random offsets.
#[test]
fn mode_change_tears_down_all_links() {
    let mut d = driver();
    let a = client(&mut d, Mode::Strict, 141);
    let b = client(&mut d, Mode::Strict, 142);
    contact(&mut d, a, b, 10_000, 80_000);
    contact(&mut d, a, b, 10_000, 80_000);
    let t = 300_000;
    d.run_until(t);
    assert_eq!(d.client_ref(a).sched.links().len(), 4);
    let sent = frames(&d, a, Dir::C2R).len();
    let outs = d
        .client(a)
        .sched
        .set_mode(t, Mode::Balanced, &mut NoCells)
        .unwrap();
    let torn = outs
        .iter()
        .filter(|o| matches!(o, Output::Event(LinkEvent::TornDown(_, Reason::ModeChange))))
        .count();
    assert_eq!(torn, 4, "every old link: TornDown(ModeChange) at t");
    let closes = outs.iter().filter(|o| matches!(o, Output::Close { .. })).count();
    assert_eq!(closes, 4, "and closed");
    assert_eq!(frames(&d, a, Dir::C2R).len(), sent, "no unit after t");
    let after = d.client_ref(a).sched.links();
    assert_eq!(after.len(), 1);
    let start = after.first().unwrap().starts_at.unwrap();
    assert!((t..=t + 180_000).contains(&start), "new link starts within 3 min of t");
}

/// S-15: link phases are uniform on [0, 180 s] and drawn independently — one draw per link.
#[test]
fn link_phase_uniform_and_independent() {
    let mut s = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(0x5eed));
    for n in 0..1000_u32 {
        s.add_recv_queue(0, RelayId(0), fresh_recv_cap(n), 80_000)
            .unwrap();
    }
    let starts: Vec<u64> = s.links().iter().map(|l| l.starts_at.unwrap()).collect();
    assert_eq!(starts.len(), 1000);
    assert!(starts.iter().all(|t| *t <= 180_000));
    assert_eq!(s.timing_draws(), 1000, "1 000 distinct draw indices");
    let (dstat, p) = ks_uniform(&starts, 0, 180_000);
    assert!(p >= 0.01, "KS D = {dstat}, p = {p}");
}
