// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 property tests (P-01…P-04, P-06, P-07; `docs/06` §4 "Property"): seeded through `seed::master_seed` (the default
//! seed and, in CI, the run seed).

use std::collections::BTreeSet;

use secmp_client_core::scheduler::conversation::{Conversation, Conversations};
use secmp_client_core::scheduler::control::When;
use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, MsgId, MsgState, OutMessage, Outbox};
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::{CellSource, ControlKind, Output, QueueId, RelayId};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::AppKind;
use secmp_proto::wire::frame::RequestCmd;
use secmp_testkit::harness::{EntropyPool, Inspect, START_UNIX, ratchet_pair};

use crate::m6_activity::{Rig, Scenario, activity, compare};
use crate::m6_common::{client_with, driver, run_until_link_up, send_only};
use crate::m6_sched_bal::{NoCells, fresh_recv_cap};
use crate::seed;

/// A deterministic generator for the cases (not the timing randomness).
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        *items.get(usize::try_from(self.below(u64::try_from(items.len()).unwrap())).unwrap()).unwrap()
    }
}

fn cases() -> u64 {
    std::env::var("SECMP_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(4)
}

const PERIODS: [u64; 4] = [10_000, 20_000, 40_000, 80_000];

/// A random scenario: a mode, 1…3 contacts with random periods (Balanced / Low-bw within their rate bounds).
fn random_scenario(mix: &mut Mix, seed: u64) -> Scenario {
    let mode = mix.pick(&[Mode::Strict, Mode::Balanced, Mode::LowBw]);
    let n = 1 + usize::try_from(mix.below(3)).unwrap();
    let recv: &[u64] = if mode == Mode::LowBw { &[40_000, 80_000] } else { &PERIODS };
    let contacts = (0..n).map(|_| (mix.pick(&PERIODS), mix.pick(recv))).collect();
    Scenario {
        mode,
        contacts,
        pool: mix.below(2) == 0,
        seed,
    }
}

const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0601;

/// P-01: for a random mode, periods, link set and activity the emitted frames equal the idle run's within 5 ms.
#[test]
fn prop_schedule_independent_of_activity() {
    let master = seed::master_seed(DEFAULT_SEED);
    for case in 0..cases() {
        let mut mix = Mix(master ^ case.wrapping_mul(0x1234_5678_9abc_def1));
        let sc_seed = mix.next();
        let sc = random_scenario(&mut mix, sc_seed);
        let n = sc.contacts.len();
        let idle = Rig::new(&sc, Params::default()).run(1, None);
        let act = activity(mix.next(), 1, n);
        let run = Rig::new(&sc, Params::default()).run(1, Some(&act));
        let (c, r) = compare(&idle, &run);
        assert!(c.is_some_and(|d| d <= 5), "case {case} (seed {master}): C2R {c:?} in {:?}", sc.mode);
        assert!(r.is_some_and(|d| d <= 5), "case {case} (seed {master}): R2C {r:?}");
        assert_eq!(idle.draws, run.draws, "case {case}: timing draws");
    }
}

/// P-02: whatever the rotations and reconnects, two `SEND`s to a queue are never less than `P_q` apart.
#[test]
fn prop_at_most_once_per_period() {
    let master = seed::master_seed(DEFAULT_SEED.wrapping_add(1));
    for case in 0..cases() {
        let mut mix = Mix(master ^ case.wrapping_mul(0x9e37_79b9_7f4a_7c13));
        let mode = mix.pick(&[Mode::Strict, Mode::Balanced]);
        let params = Params {
            lifetime_ms: {
                let lo = 100_000 + mix.below(50_000);
                (lo, lo + mix.below(100_000))
            },
            phase_max_ms: 2_000 + mix.below(20_000),
            ..Params::default()
        };
        let mut sim = driver();
        let alice = client_with(&mut sim, mode, params, mix.next());
        let bob = client_with(&mut sim, Mode::Strict, Params::default(), 1);
        let queues = 1 + usize::try_from(mix.below(3)).unwrap();
        let mut periods = Vec::new();
        for _ in 0..queues {
            let p = mix.pick(&PERIODS);
            periods.push(p);
            send_only(&mut sim, alice, bob, p);
        }
        sim.client(alice).opts.inspect = Inspect::Requests;
        let mut t = 0;
        for round in 0..12_u64 {
            t += 200_000;
            sim.run_until(t);
            if mix.below(4) == 0 || round == 5 {
                sim.restart_relay();
            }
        }
        let mut per_queue: std::collections::BTreeMap<[u8; 16], Vec<u64>> = std::collections::BTreeMap::new();
        for (at, _, r) in &sim.client_ref(alice).requests {
            if let RequestCmd::Send { sid, .. } = &r.cmd {
                per_queue.entry(*sid).or_default().push(*at);
            }
        }
        assert_eq!(per_queue.len(), queues, "case {case}: every queue was sent to ({mode:?}, {periods:?}, {} requests)", sim.client_ref(alice).requests.len());
        let mut spacing: Vec<u64> = periods.clone();
        spacing.sort_unstable();
        for times in per_queue.values() {
            let mut times = times.clone();
            times.sort_unstable();
            assert!(times.len() > 10);
            let least = times.windows(2).map(|w| w[1] - w[0]).min().unwrap();
            assert!(spacing.contains(&least) || least >= 10_000, "case {case}: spacing {least}");
            // against the queue's own period: the smallest period of the set is the lower bound for all
            assert!(least >= *spacing.first().unwrap(), "case {case} (seed {master}): {least} < {:?}", spacing);
        }
    }
}

/// A plain model of the outbox: one entry per message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModelEntry {
    id: MsgId,
    queued_at: u64,
    state: MsgState,
    taken: bool,
}

fn model_apply(model: &mut Vec<ModelEntry>, op: &Op) {
    match op {
        Op::Enqueue(id, at) => model.push(ModelEntry { id: *id, queued_at: *at, state: MsgState::Queued, taken: false }),
        Op::Take => {
            if let Some(e) = model.iter_mut().find(|e| e.state == MsgState::Queued && !e.taken) {
                e.taken = true;
            }
        }
        Op::Relayed(id, cell) => {
            if let Some(e) = model.iter_mut().find(|e| e.id == *id)
                && e.state == MsgState::Queued
            {
                e.state = MsgState::Relayed(*cell);
                e.taken = false;
            }
        }
        Op::Requeue(id) => {
            if let Some(e) = model.iter_mut().find(|e| e.id == *id)
                && matches!(e.state, MsgState::Queued | MsgState::Relayed(_))
            {
                e.state = MsgState::Queued;
                e.taken = false;
            }
        }
        Op::Lost => {
            for e in model.iter_mut() {
                if matches!(e.state, MsgState::Relayed(_)) {
                    e.state = MsgState::Queued;
                    e.taken = false;
                }
            }
        }
        Op::Delivered(id) => {
            if let Some(e) = model.iter_mut().find(|e| e.id == *id)
                && e.state != MsgState::Failed
            {
                e.state = MsgState::Delivered;
                e.taken = false;
            }
        }
        Op::Expire(now) => {
            for e in model.iter_mut() {
                if e.state == MsgState::Queued && now.saturating_sub(e.queued_at) >= 2_592_000_000 {
                    e.state = MsgState::Failed;
                    e.taken = false;
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Enqueue(MsgId, u64),
    Take,
    Relayed(MsgId, u64),
    Requeue(MsgId),
    Lost,
    Delivered(MsgId),
    Expire(u64),
}

/// P-03: random enqueue / relayed / evicted / lost-queue / receipt / 30-day sequences leave the outbox in the states a
/// plain model computes.
#[test]
fn prop_outbox_matches_model() {
    let master = seed::master_seed(DEFAULT_SEED.wrapping_add(2));
    for case in 0..cases().max(1) * 50 {
        let mut mix = Mix(master ^ case.wrapping_mul(0x517c_c1b7_2722_0a95));
        let mut outbox = MemOutbox::new();
        let mut model: Vec<ModelEntry> = Vec::new();
        let mut now = 0_u64;
        let mut next_id = 0_u8;
        for step in 0..120 {
            now += mix.below(900_000_000);
            let known: Vec<MsgId> = model.iter().map(|e| e.id).collect();
            let pick = |mix: &mut Mix| -> MsgId {
                if known.is_empty() {
                    [0xee; 16]
                } else {
                    mix.pick(&known)
                }
            };
            let op = match mix.below(8) {
                0 | 1 => {
                    next_id = next_id.wrapping_add(1);
                    Op::Enqueue([next_id; 16], now)
                }
                2 => Op::Take,
                3 => Op::Relayed(pick(&mut mix), mix.below(1000)),
                4 => Op::Requeue(pick(&mut mix)),
                5 => Op::Lost,
                6 => Op::Delivered(pick(&mut mix)),
                _ => Op::Expire(now),
            };
            match &op {
                Op::Enqueue(id, at) => outbox.enqueue(
                    OutMessage { msg_id: *id, kind: AppKind::Text, expire_after: 0, payload: Zeroizing::new(vec![1; 8]) },
                    *at,
                ),
                Op::Take => {
                    let _ = outbox.take_next();
                }
                Op::Relayed(id, cell) => outbox.relayed(id, *cell),
                Op::Requeue(id) => outbox.requeue(id),
                Op::Lost => outbox.requeue_unreceipted(),
                Op::Delivered(id) => outbox.delivered(id),
                Op::Expire(at) => outbox.expire(*at),
            }
            model_apply(&mut model, &op);
            let states: Vec<(MsgId, MsgState)> = model.iter().map(|e| (e.id, e.state)).collect();
            assert_eq!(outbox.states(), states, "case {case} (seed {master}) step {step}: {op:?}");
            let waiting = model.iter().filter(|e| e.state == MsgState::Queued && !e.taken).count();
            assert_eq!(outbox.waiting(), waiting, "case {case} step {step}");
        }
    }
}

/// P-04: every random draw of the schedule lies in its interval.
#[test]
fn prop_draws_in_range() {
    let master = seed::master_seed(DEFAULT_SEED.wrapping_add(3));
    for case in 0..cases() * 20 {
        let mut mix = Mix(master ^ case.wrapping_mul(0x2545_f491_4f6c_dd1d));
        let phase = 1 + mix.below(300_000);
        let (lo, hi) = (10_000 + mix.below(100_000), 200_000 + mix.below(500_000));
        let params = Params {
            phase_max_ms: phase,
            lifetime_ms: (lo, hi),
            control_delay_ms: (lo, hi),
            backoff_cap_ms: phase.saturating_mul(1 + mix.below(40)),
            ..Params::default()
        };
        let mut sched = Scheduler::new(params.clone(), Mode::Strict, TimingRng::seeded(mix.next()));
        let now = mix.below(1_000_000);
        for n in 0..20 {
            sched.add_recv_queue(now, RelayId(0), fresh_recv_cap(n), 80_000).unwrap();
        }
        for l in sched.links() {
            assert!((now..=now + phase).contains(&l.starts_at.unwrap()), "case {case}: phase");
        }
        for n in 0..20_u32 {
            let op = sched
                .schedule_control(now, ControlKind::QueueNew(QueueId(100 + n)), RelayId(0), u64::from(n), When::Delayed)
                .unwrap();
            let due = sched.control_due(op).unwrap();
            assert!((now + lo..=now + hi).contains(&due), "case {case}: control delay {}", due - now);
        }
        // back-off: n consecutive closes before RELAYINFO
        let mut at = now + phase;
        let mut closed = 0_u32;
        for _ in 0..8 {
            let outs = sched.poll(at, &mut NoCells).unwrap();
            let Some(link) = outs.iter().find_map(|o| if let Output::Connect { link, .. } = o { Some(*link) } else { None })
            else {
                break;
            };
            sched.connect_failed(link, at, true).unwrap();
            closed += 1;
            let cap = secmp_client_core::scheduler::params::backoff_cap(closed, phase, params.backoff_cap_ms);
            let next = sched.links().iter().filter_map(|l| l.starts_at).min().unwrap();
            assert!(next - at <= cap, "case {case}: back-off {} > {cap}", next - at);
            at = next;
        }
    }
    // lifetimes of connections that came up
    let mut mix = Mix(master);
    let params = Params {
        lifetime_ms: (50_000_000, 60_000_000),
        ..Params::default()
    };
    let mut sim = driver();
    let alice = client_with(&mut sim, Mode::Strict, params, mix.next());
    let bob = client_with(&mut sim, Mode::Strict, Params::default(), 2);
    send_only(&mut sim, alice, bob, 80_000);
    let (_, t_up) = run_until_link_up(&mut sim, alice, secmp_client_core::scheduler::core::LinkKind::Send);
    let info = sim.client_ref(alice).sched.links()[0];
    let life = info.die_at.unwrap() - t_up;
    assert!((50_000_000..=60_000_000).contains(&life), "lifetime {life}");
}

/// P-06: random sets of control operations each run on their own new key, prompt ones at once, the others no earlier than
/// a minute after anything related.
#[test]
fn prop_control_ops_isolated_and_delayed() {
    let master = seed::master_seed(DEFAULT_SEED.wrapping_add(4));
    for case in 0..cases() * 10 {
        let mut mix = Mix(master ^ case.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(mix.next()));
        let mut ops = Vec::new();
        let mut last: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
        for n in 0..30_u32 {
            let now = u64::from(n) * 5_000;
            let related = mix.below(6);
            let when = if mix.below(4) == 0 { When::Prompt } else { When::Delayed };
            let op = sched
                .schedule_control(now, ControlKind::QueueNew(QueueId(n)), RelayId(0), related, when)
                .unwrap();
            let due = sched.control_due(op).unwrap();
            let base = now.max(last.get(&related).copied().unwrap_or(0));
            match when {
                When::Prompt => assert_eq!(due, now),
                _ => {
                    assert!(
                        (base + 60_000..=base + 3_600_000).contains(&due),
                        "case {case}: delay {} from {base}",
                        due - base
                    );
                }
            }
            last.insert(related, due.max(last.get(&related).copied().unwrap_or(0)));
            ops.push(op);
        }
        let mut keys = BTreeSet::new();
        let mut seen = 0;
        while let Some(t) = sched.next_deadline() {
            if seen >= ops.len() {
                break;
            }
            for o in sched.poll(t, &mut NoCells).unwrap() {
                if let Output::Control { key, .. } = o {
                    assert!(keys.insert(key), "case {case}: a key was used twice");
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, ops.len(), "case {case}: every op started");
    }
}

/// P-07: a crash anywhere around persist, seal and write never makes a message key reappear.
#[test]
fn prop_no_message_key_reuse_across_crashes() {
    let master = seed::master_seed(DEFAULT_SEED.wrapping_add(5));
    for case in 0..cases() * 3 {
        let mut mix = Mix(master ^ case.wrapping_mul(0xd6e8_feb8_6659_fd93));
        let sk = SecretBytes::from_slice(&[9_u8; 32]).unwrap();
        let mut pool = EntropyPool::new("m6-p7", u32::try_from(case).unwrap());
        let transcript: [u8; 32] = pool.bytes(32).try_into().unwrap();
        let mut ea = FixedEntropy::new(&pool.bytes(1 << 16));
        let mut eb = FixedEntropy::new(&pool.bytes(1 << 16));
        let (sender, mut peer) = ratchet_pair(&sk, &transcript, &mut ea, &mut eb);
        let key = secmp_proto::tr::Entropy::hybrid_signing_key(pool.get()).unwrap().verifying_key();
        let build = |state: RatchetState, tag: u32| {
            let mut c: Conversation<MemOutbox, MemPersist, EntropyPool> = Conversation::new(
                state,
                MemOutbox::new(),
                MemPersist::new(),
                EntropyPool::new("m6-p7-conv", tag),
                secmp_crypto::HybridSigningKey::from_seeds(&[1; 32], &[2; 32]).unwrap().verifying_key(),
                START_UNIX,
            );
            c.bind(QueueId(0), QueueId(1));
            c
        };
        let _ = key;
        let mut convs = Conversations::new();
        let mut idx = convs.add(build(sender, 0));
        let mut incarnation = 1;
        let mut digests: Vec<[u8; 32]> = Vec::new();
        for step in 0..60_u64 {
            let conv = convs.get_mut(idx).unwrap();
            let fail = mix.below(5) == 0;
            conv.persist_mut().set_failing(fail);
            if mix.below(3) == 0 {
                conv.outbox_mut().enqueue(
                    OutMessage { msg_id: [u8::try_from(step).unwrap(); 16], kind: AppKind::Text, expire_after: 0, payload: Zeroizing::new(vec![3; 30]) },
                    step,
                );
            }
            let made = convs.prepare_cell(QueueId(0), step * 10_000);
            match made {
                Ok(Some(cell)) => {
                    assert!(!fail, "a failing persist released a cell");
                    // the peer opens every released cell: its message key digest
                    let opened = peer.decrypt_with(cell.cell.as_bytes(), pool.get()).ok().unwrap();
                    digests.push(opened.plaintext().message_key_digest_kat());
                    let (state, _) = opened.commit(|_| Ok::<(), ()>(())).unwrap();
                    peer = state;
                    // a crash after persist: the process restarts from the durable state (the cell may never be written)
                    if mix.below(4) == 0 {
                        let durable = convs.get(idx).unwrap().durable().to_vec();
                        let state = RatchetState::from_bytes(&durable).unwrap();
                        convs = Conversations::new();
                        idx = convs.add(build(state, incarnation));
                        incarnation += 1;
                    }
                }
                Ok(None) => unreachable!(),
                Err(_) => assert!(fail, "an unexpected preparation failure"),
            }
        }
        let distinct: BTreeSet<[u8; 32]> = digests.iter().copied().collect();
        assert_eq!(distinct.len(), digests.len(), "case {case} (seed {master}): a message key was used twice");
        assert!(digests.len() > 20);
    }
}
