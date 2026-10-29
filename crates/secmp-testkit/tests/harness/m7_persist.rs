// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7 persistence through the scheduler (TEST-SPEC-M7 PC-03, PC-04, PC-13): the conversations of the virtual driver
//! commit through a `MemPersist` whose mirror is the profile store (`StorePersist`, opened with the `kat` test key), so
//! every commit the scheduler waits for is a SQLCipher transaction.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use secmp_client_core::persist::{SharedStore, StorePersist, load_parts};
use secmp_client_core::scheduler::core::LinkKind;
use secmp_client_core::scheduler::outbox::{
    CommitParts, Outbox, Persist, PersistError, PersistKind,
};
use secmp_client_core::scheduler::params::Mode;
use secmp_client_core::scheduler::types::{CellSource, QueueId};
use secmp_proto::wire::frame::RequestCmd;
use secmp_store::Store;
use secmp_store::kat::{TempDir, TestKey};
use secmp_testkit::harness::{Audit, Inspect, VirtualDriver};

use crate::m6_common::{
    FRAME, at, client, contact, driver, half_contact, inject, run_until_link_up, seed_conversation,
    send_only,
};
use crate::m6_outbox::text;

/// The slot period of the runs.
const P: u64 = 10_000;

/// One event of the persist-before-send log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    /// A commit the store made durable.
    Commit(PersistKind),
    /// A write of `n` frames to the stream.
    Write(usize),
}

type Log = Arc<Mutex<Vec<Ev>>>;

/// The store's durability, logging every durable commit.
struct Logged {
    inner: StorePersist,
    log: Log,
}

impl Persist for Logged {
    fn commit(&mut self, kind: PersistKind, state: &[u8]) -> Result<(), PersistError> {
        self.inner.commit(kind, state)?;
        self.log.lock().unwrap().push(Ev::Commit(kind));
        Ok(())
    }

    fn commit_parts(
        &mut self,
        kind: PersistKind,
        parts: &CommitParts<'_>,
    ) -> Result<(), PersistError> {
        self.inner.commit_parts(kind, parts)?;
        self.log.lock().unwrap().push(Ev::Commit(kind));
        Ok(())
    }
}

/// The profile store in `dir`.
pub(crate) fn shared(dir: &Path) -> SharedStore {
    Arc::new(Mutex::new(Store::open(dir, &TestKey::db_key()).unwrap()))
}

/// Make conversation `conv` of client `client` commit to `store` (session `session`) before its in-memory copy.
fn store_back(
    sim: &mut VirtualDriver,
    client: usize,
    conv: usize,
    store: &SharedStore,
    session: i64,
    log: Option<&Log>,
) {
    let inner = StorePersist::open(Arc::clone(store), session).unwrap();
    let mirror: Box<dyn Persist + Send> = match log {
        Some(log) => Box::new(Logged {
            inner,
            log: Arc::clone(log),
        }),
        None => Box::new(inner),
    };
    sim.client(client)
        .convs
        .get_mut(conv)
        .unwrap()
        .persist_mut()
        .set_mirror(mirror);
}

/// The durable state of `session` as the store holds it.
fn durable(store: &SharedStore, session: i64) -> Vec<u8> {
    load_parts(store, session)
        .unwrap()
        .unwrap()
        .to_bytes()
        .unwrap()
        .to_vec()
}

/// PC-03 (§7.5 `docs/03:488`; review focus `docs/07:147`): 200 Strict slots of a store-backed conversation with real
/// messages among the dummies; in the log of durable commits and frame writes, every `SEND` frame is written after the
/// commit of the state that sealed its cell (the j-th `SEND` written follows at least j durable `Send` commits), and the
/// store holds the conversation's durable state at the end. That a `PreparedCell` exists only from a committed state is
/// the compile-fail doc test on `secmp_client_core::scheduler::types::PreparedCell` (`E0451`).
#[test]
fn persist_before_send_by_construction() {
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 731);
    let b = client(&mut sim, Mode::Strict, 732);
    let c = send_only(&mut sim, a, b, P);
    sim.client(a).opts.inspect = Inspect::Requests;
    let dir = TempDir::new("pc03").unwrap();
    let store = shared(dir.path());
    let log: Log = Arc::default();
    store_back(&mut sim, a, c, &store, 1, Some(&log));
    let hook = Arc::clone(&log);
    sim.client(a).after_write = Some(Box::new(move |_, bytes| {
        hook.lock().unwrap().push(Ev::Write(bytes.len() / FRAME));
    }));
    let (_, t_up) = run_until_link_up(&mut sim, a, LinkKind::Send);
    for k in 0..200_u64 {
        if k % 10 == 3 {
            let n = u8::try_from(k / 10).unwrap();
            let now = sim.now();
            sim.client(a)
                .convs
                .get_mut(c)
                .unwrap()
                .outbox_mut()
                .enqueue(text(n, 40), now);
        }
        sim.run_until(at(t_up, k.saturating_add(1), P));
    }
    let sends: Vec<bool> = sim
        .client_ref(a)
        .requests
        .iter()
        .map(|(_, _, r)| matches!(r.cmd, RequestCmd::Send { .. }))
        .collect();
    let events = log.lock().unwrap().clone();
    let (mut commits, mut frame, mut sent) = (0_usize, 0_usize, 0_usize);
    for e in &events {
        match *e {
            Ev::Commit(kind) => {
                assert_eq!(kind, PersistKind::Send, "a send-only conversation received");
                commits += 1;
            }
            Ev::Write(n) => {
                for _ in 0..n {
                    if *sends.get(frame).unwrap() {
                        sent += 1;
                        assert!(
                            commits >= sent,
                            "SEND frame {frame} written before the commit of its cell's state"
                        );
                    }
                    frame += 1;
                }
            }
        }
    }
    assert_eq!(frame, sends.len(), "every recorded frame was written once");
    assert!(sent >= 195, "{sent} SEND frames in 200 slots");
    // at most the frames prepared ahead (and not yet written) were committed beyond the frames written
    assert!(commits - sent <= 2, "{commits} commits, {sent} sends");
    let conv = sim.client_ref(a).convs.get(c).unwrap();
    assert_eq!(
        durable(&store, 1),
        conv.durable(),
        "the store holds the durable state"
    );
    assert_eq!(conv.outbox().waiting(), 0, "every real message was sent");
}

/// PC-04 (CLAUDE.md §1.7; §9.3 `docs/03:612`): 200 slots of a store-backed receiving conversation, cells injected at the
/// relay as the run goes; every `FETCH` the driver records (decoded from the frames written) acknowledges at most the
/// highest `cell_id` whose decision was committed to the store before the frame was sealed (the gate's `Decided` events
/// and the core's preparation log, both stamped with the thread's seal counter). Every injected cell is decided.
#[test]
fn persist_before_ack_by_construction() {
    let mut sim = driver();
    let x = client(&mut sim, Mode::Strict, 741);
    let y = client(&mut sim, Mode::Strict, 742);
    let half = half_contact(&mut sim, x, y, P);
    sim.client(x).opts.inspect = Inspect::Requests;
    let dir = TempDir::new("pc04").unwrap();
    let store = shared(dir.path());
    store_back(&mut sim, x, half.conv_a, &store, 1, None);
    let (_, t_up) = run_until_link_up(&mut sim, x, LinkKind::Recv);
    let mut injected = 0_u64;
    for k in 0..200_u64 {
        if k % 3 == 0 {
            for i in 0..=(k % 2) {
                let now = sim.now();
                if i == 0 && k % 6 == 0 {
                    let n = u8::try_from(k / 6).unwrap();
                    sim.client(y)
                        .convs
                        .get_mut(half.conv_b)
                        .unwrap()
                        .outbox_mut()
                        .enqueue(text(n, 40), now);
                }
                let cell = sim
                    .client(y)
                    .convs
                    .prepare_cell(QueueId(u32::MAX), now)
                    .unwrap()
                    .unwrap();
                inject(&mut sim, y, &half, &cell.cell);
                injected += 1;
            }
        }
        sim.run_until(at(t_up, k.saturating_add(1), P));
    }
    sim.run_until(at(t_up, 205, P));
    let c = sim.client_ref(x);
    let decided: Vec<[u64; 3]> = c
        .gate
        .audit
        .iter()
        .filter_map(|e| match *e {
            Audit::Decided(d) => Some(d),
            _ => None,
        })
        .collect();
    let mut seals: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for p in c.sched.prep_log() {
        if p.kind == b'F' || p.kind == b'M' {
            seals.entry(p.link.0).or_default().push(p.seal);
        }
    }
    let mut acks: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (_, slot, r) in &c.requests {
        let ack = match &r.cmd {
            RequestCmd::Fetch { ack, .. } => *ack,
            RequestCmd::FetchMulti { entries } => entries.iter().map(|e| e.ack).max().unwrap(),
            _ => continue,
        };
        acks.entry(*slot).or_default().push(ack);
    }
    let (mut checked, mut nonzero) = (0_u64, 0_u64);
    for (link, written) in &acks {
        let sealed = seals.get(link).unwrap();
        assert!(
            written.len() <= sealed.len(),
            "link {link}: more fetches written than prepared"
        );
        for (ack, seal) in written.iter().zip(sealed) {
            let allowed = decided
                .iter()
                .filter(|d| d[2] < *seal)
                .map(|d| d[1])
                .max()
                .unwrap_or(0);
            assert!(
                *ack <= allowed,
                "link {link}: ack {ack} above the highest cell committed before the seal ({allowed})"
            );
            checked += 1;
            nonzero += u64::from(*ack > 0);
        }
    }
    assert!(checked >= 195, "{checked} fetches checked");
    assert!(nonzero >= 150, "{nonzero} acknowledgements above 0");
    assert_eq!(
        u64::try_from(decided.len()).unwrap(),
        injected,
        "every injected cell was decided once"
    );
    let conv = c.convs.get(half.conv_a).unwrap();
    assert_eq!(
        durable(&store, 1),
        conv.durable(),
        "the store holds the durable state"
    );
    assert_eq!(conv.received().len(), 34, "the real messages arrived");
}

/// Write a line of evidence to `target/m7-evidence/<name>.txt` (the report quotes it; committed under
/// `docs/reviews/M07-evidence/`).
pub(crate) fn evidence(name: &str, text: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/m7-evidence");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{name}.txt")), format!("{text}\n")).unwrap();
}

/// PC-13 (M03 review F31; CS-3.7): 24 h of virtual Strict time, one contact, P = 10 s both ways, two profiles; the bytes
/// the store wrote (`kat::store_bytes_written`: the write-ahead log of every committed transaction, automatic
/// checkpoints off — a checkpoint writes each logged page to the database file at most once) per day and per slot, in
/// the evidence; per dummy slot (one cell: the sender's commit and the receiver's) at most 2 × (the fixed part of
/// `RatchetStateV1` + the outbox row of a message of one cell).
#[test]
fn write_amplification_measured() {
    secmp_store::kat::measure_writes(true);
    secmp_store::kat::reset_counters();
    let mut sim = driver();
    let a = client(&mut sim, Mode::Strict, 751);
    let b = client(&mut sim, Mode::Strict, 752);
    let c = contact(&mut sim, a, b, P, P);
    seed_conversation(&mut sim, a, b, &c);
    let (da, db) = (
        TempDir::new("pc13a").unwrap(),
        TempDir::new("pc13b").unwrap(),
    );
    let (sa, sb) = (shared(da.path()), shared(db.path()));
    store_back(&mut sim, a, c.conv_a, &sa, 1, None);
    store_back(&mut sim, b, c.conv_b, &sb, 1, None);
    let before = secmp_store::kat::store_bytes_written();
    let commits_before = secmp_store::kat::store_txn_commits();
    let start = sim.now();
    let day = 86_400_000_u64;
    sim.run_until(start.saturating_add(day));
    let bytes = secmp_store::kat::store_bytes_written() - before;
    let commits = secmp_store::kat::store_txn_commits() - commits_before;
    secmp_store::kat::measure_writes(false);
    let slots: u64 = [a, b]
        .iter()
        .map(|i| {
            let n = sim
                .client_ref(*i)
                .sched
                .prep_log()
                .iter()
                .filter(|p| p.kind == b'S')
                .count();
            u64::try_from(n).unwrap()
        })
        .sum();
    assert!(slots >= 2 * 8_600, "{slots} send slots in 24 h");
    let fixed = u64::try_from(load_parts(&sa, 1).unwrap().unwrap().fixed.len()).unwrap();
    // the outbox row of a message that fills one cell: a payload of at most one Content body (`BODY_LEN`) and the
    // other columns (`msg_id`, seven integers)
    let one_cell_payload = u64::try_from(secmp_proto::sizes::BODY_LEN).unwrap();
    let outbox_row = one_cell_payload + 16 + 8 * 7;
    let bound = 2 * (fixed + outbox_row);
    let per_slot = bytes / slots;
    let text = format!(
        "PC-13 write amplification (24 h virtual, Strict, one contact, P = 10 s, two profiles): bytes/day = {bytes}, \
         commits/day = {commits}, send slots/day = {slots}, bytes/dummy slot = {per_slot} (sender + receiver commit), \
         bound 2 × (fixed {fixed} + outbox row {outbox_row}) = {bound}"
    );
    evidence("pc-13-write-amplification", &text);
    assert!(per_slot <= bound, "{text}");
}
