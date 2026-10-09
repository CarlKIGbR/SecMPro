// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 (d4) the outbox (OB-01…OB-08; spec §7.6, §9.5, §10.4, `docs/07` M6).

use secmp_client_core::scheduler::conversation::{Conversation, Conversations};
use secmp_client_core::scheduler::outbox::{MemOutbox, MemPersist, MsgState, OutMessage, Outbox};
use secmp_client_core::scheduler::params::Mode;
use secmp_client_core::scheduler::types::{CellSource, QueueId};
use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::tr::{Entropy, FixedEntropy};
use secmp_proto::wire::cell::AppKind;
use secmp_testkit::harness::{Dir, EntropyPool, START_UNIX, ratchet_pair};

use crate::m6_common::{client, contact, driver, max_dt};

type TestConv = Conversation<MemOutbox, MemPersist, EntropyPool>;

const A_SEND: QueueId = QueueId(0);
const A_RECV: QueueId = QueueId(1);
const B_SEND: QueueId = QueueId(2);
const B_RECV: QueueId = QueueId(3);

fn text(n: u8, len: usize) -> OutMessage {
    OutMessage {
        msg_id: [n; 16],
        kind: AppKind::Text,
        expire_after: 0,
        payload: Zeroizing::new(vec![n; len]),
    }
}

/// Two conversations of one ratchet pair in one cell source: `a` (initiator) sends on queue 0 and receives on 1, `b`
/// sends on 2 and receives on 3.
fn pair(tag: u32) -> (Conversations<MemOutbox, MemPersist, EntropyPool>, usize, usize) {
    let sk = SecretBytes::from_slice(&[7_u8; 32]).unwrap();
    let mut pool = EntropyPool::new("m6-ob-pair", tag);
    let transcript: [u8; 32] = pool.bytes(32).try_into().unwrap();
    let mut ea = FixedEntropy::new(&pool.bytes(1 << 16));
    let mut eb = FixedEntropy::new(&pool.bytes(1 << 16));
    let (sa, sb) = ratchet_pair(&sk, &transcript, &mut ea, &mut eb);
    let key_a = pool.get().hybrid_signing_key().unwrap().verifying_key();
    let key_b = pool.get().hybrid_signing_key().unwrap().verifying_key();
    let mut conv_a: TestConv = Conversation::new(
        sa,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-ob-a", tag),
        key_b,
        START_UNIX,
    );
    let mut conv_b: TestConv = Conversation::new(
        sb,
        MemOutbox::new(),
        MemPersist::new(),
        EntropyPool::new("m6-ob-b", tag),
        key_a,
        START_UNIX,
    );
    conv_a.bind(A_SEND, A_RECV);
    conv_b.bind(B_SEND, B_RECV);
    let mut convs = Conversations::new();
    let a = convs.add(conv_a);
    let b = convs.add(conv_b);
    (convs, a, b)
}

/// OB-01: queued → relayed(cell_id) → delivered (a receipt from the peer).
#[test]
fn outbox_states() {
    let (mut convs, a, b) = pair(1);
    let id = [1_u8; 16];
    convs.get_mut(a).unwrap().outbox_mut().enqueue(text(1, 50), 0);
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Queued));
    let cell = convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Queued), "not relayed yet");
    convs.relayed(A_SEND, cell.token, 9);
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Relayed(9)));
    convs.deliver(B_RECV, 9, &cell.cell).unwrap();
    assert_eq!(convs.get(b).unwrap().received().len(), 1);
    let receipt = convs.prepare_cell(B_SEND, 20_000).unwrap().unwrap();
    convs.deliver(A_RECV, 1, &receipt.cell).unwrap();
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Delivered));
}

/// OB-02: an evicted real cell is re-sent under a new key (new cell, new ratchet position, same `msg_id`); an evicted
/// dummy is forgotten.
#[test]
fn outbox_requeues_evicted_real_with_new_key() {
    let (mut convs, a, b) = pair(2);
    let id = [2_u8; 16];
    // a dummy first, then the real message
    let dummy = convs.prepare_cell(A_SEND, 0).unwrap().unwrap();
    convs.relayed(A_SEND, dummy.token, 8);
    convs.get_mut(a).unwrap().outbox_mut().enqueue(text(2, 50), 0);
    let first = convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    convs.relayed(A_SEND, first.token, 9);
    // the dummy is evicted: forgotten, the real message stays relayed
    convs.evicted(A_SEND, 8);
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Relayed(9)));
    // the real cell is evicted: queued again, sent at the next slot as a new cell
    convs.evicted(A_SEND, 9);
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Queued));
    let again = convs.prepare_cell(A_SEND, 20_000).unwrap().unwrap();
    assert_ne!(first.cell.as_bytes(), again.cell.as_bytes(), "new key, new bytes");
    convs.relayed(A_SEND, again.token, 10);
    assert_eq!(convs.get(a).unwrap().outbox().state(&id), Some(MsgState::Relayed(10)));
    // the receiver sees the same msg_id (the first copy was lost, the second delivers)
    convs.deliver(B_RECV, 10, &again.cell).unwrap();
    assert_eq!(convs.get(b).unwrap().received().first().unwrap().msg_id, id);
}

/// OB-03: a message never relayed within 30 days fails — exactly at 2 592 000 000 ms.
#[test]
fn outbox_failed_after_30_days() {
    let mut outbox = MemOutbox::new();
    outbox.enqueue(text(3, 10), 0);
    outbox.expire(2_591_999_000);
    assert_eq!(outbox.state(&[3; 16]), Some(MsgState::Queued));
    outbox.expire(2_592_000_000);
    assert_eq!(outbox.state(&[3; 16]), Some(MsgState::Failed));
    // a relayed message is never failed
    let mut outbox = MemOutbox::new();
    outbox.enqueue(text(4, 10), 0);
    outbox.relayed(&[4; 16], 1);
    outbox.expire(u64::MAX);
    assert_eq!(outbox.state(&[4; 16]), Some(MsgState::Relayed(1)));
}

/// OB-04: when the send queue was lost the relayed-but-unreceipted messages are sent again (new cells); the delivered
/// one is not.
#[test]
fn outbox_resends_unreceipted_after_restart() {
    let (mut convs, a, b) = pair(4);
    for n in 1..=3_u8 {
        convs.get_mut(a).unwrap().outbox_mut().enqueue(text(n, 40), 0);
        let cell = convs.prepare_cell(A_SEND, u64::from(n) * 10_000).unwrap().unwrap();
        convs.relayed(A_SEND, cell.token, u64::from(n));
    }
    convs.get_mut(a).unwrap().outbox_mut().delivered(&[1; 16]);
    convs.queue_lost(A_SEND);
    let states = |convs: &Conversations<MemOutbox, MemPersist, EntropyPool>| -> Vec<MsgState> {
        (1..=3_u8)
            .map(|n| convs.get(a).unwrap().outbox().state(&[n; 16]).unwrap())
            .collect()
    };
    assert_eq!(
        states(&convs),
        vec![MsgState::Delivered, MsgState::Queued, MsgState::Queued]
    );
    for slot in 0..2_u64 {
        let cell = convs.prepare_cell(A_SEND, 100_000 + slot * 10_000).unwrap().unwrap();
        convs.relayed(A_SEND, cell.token, 20 + slot);
        convs.deliver(B_RECV, 20 + slot, &cell.cell).unwrap();
    }
    let received: Vec<u8> = convs
        .get(b)
        .unwrap()
        .received()
        .iter()
        .map(|m| *m.msg_id.first().unwrap())
        .collect();
    assert_eq!(received, vec![2, 3], "only the unreceipted were sent again");
}

/// OB-05: a 65 535-byte message takes 40 consecutive cells (a Batch of 65 559 bytes, 40 fragments of the 65 560-byte
/// payload) and the tick times equal the idle run's.
#[test]
fn outbox_fragments_large_message() {
    assert_eq!(1 + 23 + 65_535, 65_559);
    assert_eq!((1 + 65_559_usize).div_ceil(1669), 40);
    let (mut convs, a, b) = pair(5);
    convs.get_mut(a).unwrap().outbox_mut().enqueue(text(5, 65_535), 0);
    let mut types = Vec::new();
    for slot in 0..41_u64 {
        let cell = convs.prepare_cell(A_SEND, slot * 10_000).unwrap().unwrap();
        convs.relayed(A_SEND, cell.token, slot + 1);
        convs.deliver(B_RECV, slot + 1, &cell.cell).unwrap();
        types.push(convs.get(b).unwrap().received().len());
    }
    assert_eq!(types.iter().position(|n| *n == 1), Some(39), "complete with the 40th cell");
    assert_eq!(convs.get(b).unwrap().received().first().unwrap().payload.len(), 65_535);
    assert_eq!(convs.get(a).unwrap().outbox().state(&[5; 16]), Some(MsgState::Relayed(40)));

    // on the clock: the fragments take the slots a dummy would have taken
    let run = |big: bool| {
        let mut sim = driver();
        let alice = client(&mut sim, Mode::Strict, 51);
        let bob = client(&mut sim, Mode::Strict, 52);
        let c = contact(&mut sim, alice, bob, 10_000, 80_000);
        if big {
            sim.client(alice).convs.get_mut(c.conv_a).unwrap().outbox_mut().enqueue(text(6, 65_535), 0);
        }
        sim.run_until(900_000);
        let got = sim.client_ref(bob).convs.get(c.conv_b).unwrap().received().len();
        (sim.scheduled(alice, Dir::C2R), got)
    };
    let (idle, none) = run(false);
    let (busy, one) = run(true);
    assert_eq!((none, one), (0, 1));
    assert_eq!(max_dt(&idle, &busy), Some(0), "fragmentation adds no frame and shifts no tick");
}

/// OB-06: three delivered messages are receipted by one `Receipt{delivered}` cell in a normal slot — no extra unit.
#[test]
fn receipts_ride_normal_slots() {
    let (mut convs, a, b) = pair(6);
    for n in 1..=3_u8 {
        convs.get_mut(a).unwrap().outbox_mut().enqueue(text(n, 40), 0);
        let cell = convs.prepare_cell(A_SEND, u64::from(n) * 10_000).unwrap().unwrap();
        convs.relayed(A_SEND, cell.token, u64::from(n));
        convs.deliver(B_RECV, u64::from(n), &cell.cell).unwrap();
    }
    assert_eq!(convs.get(b).unwrap().receipts_due(), 3);
    let receipt = convs.prepare_cell(B_SEND, 40_000).unwrap().unwrap();
    assert_eq!(convs.get(b).unwrap().receipts_due(), 0, "one cell takes all three");
    convs.deliver(A_RECV, 1, &receipt.cell).unwrap();
    for n in 1..=3_u8 {
        assert_eq!(convs.get(a).unwrap().outbox().state(&[n; 16]), Some(MsgState::Delivered));
    }

    // on the clock: the receiver's emissions are those of an idle receiver
    let run = |busy: bool| {
        let mut sim = driver();
        let alice = client(&mut sim, Mode::Strict, 61);
        let bob = client(&mut sim, Mode::Strict, 62);
        let c = contact(&mut sim, alice, bob, 40_000, 40_000);
        if busy {
            for n in 1..=3_u8 {
                sim.client(alice).convs.get_mut(c.conv_a).unwrap().outbox_mut().enqueue(text(n, 40), 0);
            }
        }
        sim.run_until(1_500_000);
        let states: Vec<_> = (1..=3_u8)
            .filter_map(|n| sim.client_ref(alice).convs.get(c.conv_a).unwrap().outbox().state(&[n; 16]))
            .collect();
        (sim.scheduled(bob, Dir::C2R), states)
    };
    let (idle, _) = run(false);
    let (busy, states) = run(true);
    assert!(states.iter().all(|s| *s == MsgState::Delivered), "{states:?}");
    assert_eq!(max_dt(&idle, &busy), Some(0));
}

/// OB-07: the scheduler sees the outbox only through its two traits — `secmp-client-core` has no store dependency.
#[test]
fn outbox_is_the_store_boundary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../secmp-client-core");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let deps = manifest.split("[dependencies]").nth(1).unwrap();
    assert!(!deps.contains("secmp-store"), "no store dependency in M6");
    fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, hits);
            } else if p.extension().is_some_and(|x| x == "rs")
                && std::fs::read_to_string(&p).unwrap().contains("secmp_store")
            {
                hits.push(p.display().to_string());
            }
        }
    }
    let mut hits = Vec::new();
    walk(&root.join("src"), &mut hits);
    assert!(hits.is_empty(), "{hits:?}");
}

/// OB-08: a message re-sent after an eviction and arriving twice reaches the application once.
#[test]
fn receiver_dedups_by_msg_id() {
    let (mut convs, a, b) = pair(8);
    convs.get_mut(a).unwrap().outbox_mut().enqueue(text(8, 40), 0);
    let first = convs.prepare_cell(A_SEND, 10_000).unwrap().unwrap();
    convs.relayed(A_SEND, first.token, 1);
    convs.evicted(A_SEND, 1);
    let second = convs.prepare_cell(A_SEND, 20_000).unwrap().unwrap();
    convs.relayed(A_SEND, second.token, 2);
    // both copies reach the receiver
    convs.deliver(B_RECV, 1, &first.cell).unwrap();
    convs.deliver(B_RECV, 2, &second.cell).unwrap();
    assert_eq!(convs.get(b).unwrap().received().len(), 1, "delivered once");
}
