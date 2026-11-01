// SPDX-License-Identifier: AGPL-3.0-or-later
//! PC-05 (acceptance `docs/07:145`; P-07 of M6; spec §7.5): crashes between persisting and sending, across two process
//! lives. Each run is two child processes of this test binary (`secmp_store::kat::run_child`) over two profiles on disk
//! (A and B, one SQLCipher store each, `kat` test key) and a relay of files: a queue per direction holds the cells
//! (`<cell_id>.cell`, written atomically) and the receiver's acknowledgement. The first life arms one crash point and
//! aborts there; the second reopens both profiles — ratchet state from the store (`StorePersist`), outbox from the store
//! (`StoreOutbox`: what was in flight is queued again), the delivered messages of the history as the dedup set — and
//! runs until every message has arrived.
//!
//! Each life appends, before a cell leaves for the relay, the SHA-256 of the message key that sealed it
//! (`message_key_digests_kat`) to a file, and, after a delivery, the `msg_id`s it delivered; the second life also records
//! the history it found at its start. The parent checks: every digest of both lives pairwise distinct (no message key
//! sealed two released cells), and every message delivered exactly once — none delivered in the second life that the
//! history of the first holds, none twice within a life, all 30 of each side in the end.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use secmp_client_core::outbox::StoreOutbox;
use secmp_client_core::persist::{SharedStore, StorePersist};
use secmp_client_core::scheduler::conversation::{Conversation, Conversations, EntropySource};
use secmp_client_core::scheduler::outbox::{Outbox, Persist, PersistKind};
use secmp_client_core::scheduler::types::{CellSource, QueueId};
use secmp_crypto::SecretBytes;
use secmp_proto::tr::{Entropy, FixedEntropy, RatchetState};
use secmp_proto::wire::cell::Cell;
use secmp_store::kat::{CrashAt, TempDir};
use secmp_testkit::harness::{EntropyPool, ratchet_pair};

use crate::m6_outbox::text;
use crate::m7_persist::{evidence, shared};

/// The test's name in this binary (the children re-enter it).
const TEST: &str = "m7_crash::crash_between_persist_and_send_no_key_reuse";
/// The child role.
const ROLE: &str = "pc05";
/// Real messages each way.
const MESSAGES: u8 = 30;
/// Seeds per crash point.
const SEEDS: u64 = 20;
/// The session (and contact) id of the peer in each profile.
const SESSION: i64 = 1;
/// The queue A sends on and B receives on, and the reverse (ids of the `Conversations`).
const AB: QueueId = QueueId(1);
const BA: QueueId = QueueId(2);

/// The crash points of the run (`k` of `MidTxn` from the seed).
fn point(index: u64, seed: u64) -> CrashAt {
    match index {
        0 => CrashAt::AfterCommitBeforeWrite,
        1 => CrashAt::AfterWriteBeforeOkSend,
        2 => CrashAt::MidTxn(u32::try_from(seed % 2).unwrap().saturating_add(1)),
        3 => CrashAt::AfterDecryptBeforeCommit,
        _ => CrashAt::AfterCommitBeforeAck,
    }
}

/// The entropy of a conversation.
struct Fixed(FixedEntropy);

impl EntropySource for Fixed {
    type E = FixedEntropy;

    fn entropy(&mut self) -> &mut FixedEntropy {
        &mut self.0
    }
}

type Convs = Conversations<StoreOutbox, StorePersist, Fixed>;

/// A queue of the file relay: cells by `cell_id`, the next id, the receiver's acknowledgement.
struct FileQueue(PathBuf);

impl FileQueue {
    fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn read_u64(&self, name: &str) -> u64 {
        std::fs::read_to_string(self.0.join(name)).map_or(0, |s| s.trim().parse().unwrap())
    }

    /// Write `bytes` to `name` atomically.
    fn write_atomic(&self, name: &str, bytes: &[u8]) {
        let tmp = self.0.join(format!("{name}.tmp"));
        std::fs::write(&tmp, bytes).unwrap();
        std::fs::rename(&tmp, self.0.join(name)).unwrap();
    }

    /// `SEND`: the cell is stored under the next `cell_id`, which is returned (`OK_SEND`).
    fn send(&self, cell: &Cell) -> u64 {
        let id = self.read_u64("next").saturating_add(1);
        self.write_atomic(&format!("{id:020}.cell"), cell.as_bytes());
        self.write_atomic("next", id.to_string().as_bytes());
        id
    }

    /// The cells above the acknowledgement, in order.
    fn fetch(&self) -> Vec<(u64, Cell)> {
        let ack = self.read_u64("ack");
        let mut out: Vec<(u64, Cell)> = std::fs::read_dir(&self.0)
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().into_string().unwrap();
                let id: u64 = name.strip_suffix(".cell")?.parse().ok()?;
                let bytes = std::fs::read(self.0.join(&name)).unwrap();
                (id > ack).then(|| (id, Cell::from_bytes(&bytes).unwrap()))
            })
            .collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }

    /// The acknowledgement `ack`: the cells at or below it are deleted.
    fn ack(&self, ack: u64) {
        self.write_atomic("ack", ack.to_string().as_bytes());
        for (id, ()) in self.fetch_all() {
            if id <= ack {
                std::fs::remove_file(self.0.join(format!("{id:020}.cell"))).unwrap();
            }
        }
    }

    fn fetch_all(&self) -> Vec<(u64, ())> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().into_string().unwrap();
                Some((name.strip_suffix(".cell")?.parse().ok()?, ()))
            })
            .collect()
    }

    fn is_empty(&self) -> bool {
        self.fetch().is_empty()
    }
}

/// Append `lines` to the file `path`.
fn append(path: &Path, lines: &[String]) {
    use std::io::Write as _;
    if lines.is_empty() {
        return;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    for l in lines {
        writeln!(f, "{l}").unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The lines of `path` (none if it does not exist).
fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map_or_else(|_| Vec::new(), |s| s.lines().map(str::to_owned).collect())
}

/// A deterministic byte stream (not random, not secret).
fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut pool = EntropyPool::new("m7-crash", u32::try_from(seed % 1_000_000).unwrap());
    pool.bytes(len)
}

/// One side of a life: its store, its conversation (index 0 of `convs`), what it sends on and receives on.
struct SideRun {
    store: SharedStore,
    convs: Convs,
    send: QueueId,
    recv: QueueId,
    /// Digests written to the file so far (of this life).
    digests_written: usize,
    /// Messages delivered in this life.
    received: Vec<[u8; 16]>,
}

/// Open side `name` (`a` initiator, `b` responder) of run `dir` in life `life`.
fn open_side(dir: &Path, name: &str, seed: u64, life: u64) -> SideRun {
    let store = shared(&dir.join(name));
    let initiator = name == "a";
    let mut persist = StorePersist::open(Arc::clone(&store), SESSION).unwrap();
    let mut outbox = StoreOutbox::open(Arc::clone(&store), SESSION).unwrap();
    let state = if let Some(parts) = persist.load().unwrap() {
        RatchetState::from_parts(&parts).unwrap()
    } else {
        // the first life: the pair from the seed, made durable, and the 30 messages queued
        let sk = SecretBytes::from_slice(&stream(seed, 32)).unwrap();
        let transcript: [u8; 32] = stream(seed.wrapping_add(1), 32).try_into().unwrap();
        let mut ea = FixedEntropy::new(&stream(seed.wrapping_add(2), 1 << 16));
        let mut eb = FixedEntropy::new(&stream(seed.wrapping_add(3), 1 << 16));
        let (a, b) = ratchet_pair(&sk, &transcript, &mut ea, &mut eb);
        let state = if initiator { a } else { b };
        persist
            .commit(PersistKind::Send, &state.to_bytes().unwrap())
            .unwrap();
        for n in 0..MESSAGES {
            let id = if initiator { n } else { n.wrapping_add(100) };
            outbox.enqueue(text(id, 24), 0);
        }
        state
    };
    let history = persist.delivered_ids().unwrap();
    let peer = FixedEntropy::new(&stream(seed.wrapping_add(4), 1 << 20))
        .hybrid_signing_key()
        .unwrap()
        .verifying_key();
    let source = Fixed(FixedEntropy::new(&stream(
        seed.wrapping_mul(10)
            .wrapping_add(life)
            .wrapping_add(if initiator { 5 } else { 6 }),
        1 << 21,
    )));
    let mut conv = Conversation::new(state, outbox, persist, source, peer, 0);
    let (send_q, recv_q) = if initiator { (AB, BA) } else { (BA, AB) };
    conv.bind(send_q, recv_q);
    conv.set_send_receipts(false);
    conv.seed_seen(history);
    let mut convs = Convs::new();
    convs.add(conv);
    SideRun {
        store,
        convs,
        send: send_q,
        recv: recv_q,
        digests_written: 0,
        received: Vec::new(),
    }
}

/// The ids the history of `side` holds (the messages it delivered so far, across lives).
fn history(side: &SideRun) -> Vec<[u8; 16]> {
    side.store.lock().unwrap().delivered_ids(SESSION).unwrap()
}

/// `side` sends what it has (if it can: the responder seals nothing before its first receive), each cell to `q`; the
/// relay stores the cell and `peer` fetches and decides it before `OK_SEND` reaches `side` (the answer's latency), so a
/// crash between the write and `OK_SEND` leaves a message the peer delivered that the sender sends again.
fn send_all(
    side: &mut SideRun,
    q: &FileQueue,
    digests: &Path,
    now: u64,
    peer: (&mut SideRun, &Path),
) {
    let (peer, received) = peer;
    while side.convs.pending_real(side.send) {
        let Ok(Some(prepared)) = side.convs.prepare_cell(side.send, now) else {
            // the responder before its first receive: its message waits
            return;
        };
        // the key that sealed the cell is recorded before the cell can leave
        let conv = side.convs.get(0).unwrap();
        let fresh: Vec<String> = conv
            .message_key_digests_kat()
            .get(side.digests_written..)
            .unwrap()
            .iter()
            .map(|d| hex(d))
            .collect();
        side.digests_written = conv.message_key_digests_kat().len();
        append(digests, &fresh);
        let id = q.send(&prepared.cell);
        receive_all(peer, q, received);
        secmp_store::kat::crash_point(CrashAt::AfterWriteBeforeOkSend);
        side.convs.relayed(side.send, prepared.token, id);
    }
}

/// `side` fetches the cells of `q`, decides each (committed) and acknowledges it.
fn receive_all(side: &mut SideRun, q: &FileQueue, received: &Path) {
    for (id, cell) in q.fetch() {
        side.convs.deliver(side.recv, id, &cell).unwrap();
        q.ack(id);
        let conv = side.convs.get(0).unwrap();
        let fresh: Vec<[u8; 16]> = conv
            .received()
            .get(side.received.len()..)
            .unwrap()
            .iter()
            .map(|m| m.msg_id)
            .collect();
        append(received, &fresh.iter().map(|m| hex(m)).collect::<Vec<_>>());
        side.received.extend(fresh);
    }
}

/// One process life of run `dir` (the child): `crash` armed, or none (the second life runs to the end).
fn life(dir: &Path, seed: u64, n: u64, crash: Option<(CrashAt, u32)>) {
    let mut a = open_side(dir, "a", seed, n);
    let mut b = open_side(dir, "b", seed, n);
    if n == 2 {
        append(
            &dir.join("history-a.txt"),
            &history(&a).iter().map(|m| hex(m)).collect::<Vec<_>>(),
        );
        append(
            &dir.join("history-b.txt"),
            &history(&b).iter().map(|m| hex(m)).collect::<Vec<_>>(),
        );
    }
    let (ab, ba) = (
        FileQueue::new(dir.join("relay/ab")),
        FileQueue::new(dir.join("relay/ba")),
    );
    if let Some((point, nth)) = crash {
        secmp_store::kat::arm_crash(point, nth);
    }
    let digests = dir.join(format!("digests-{n}.txt"));
    let mut settled = false;
    for round in 0..400_u64 {
        let now = round.saturating_mul(1_000);
        let (to_b, to_a) = (
            dir.join(format!("received-{n}-b.txt")),
            dir.join(format!("received-{n}-a.txt")),
        );
        // what a crash left at the relay is fetched first
        receive_all(&mut b, &ab, &to_b);
        receive_all(&mut a, &ba, &to_a);
        send_all(&mut a, &ab, &digests, now, (&mut b, &to_b));
        send_all(&mut b, &ba, &digests, now, (&mut a, &to_a));
        let quiet = !a.convs.pending_real(AB)
            && !b.convs.pending_real(BA)
            && ab.is_empty()
            && ba.is_empty();
        if quiet {
            settled = true;
            break;
        }
    }
    assert!(settled, "the run does not settle");
    assert!(crash.is_none(), "life 1 ended before its crash point fired");
}

/// The 30 ids side `name` sends.
fn sent_by(name: &str) -> BTreeSet<String> {
    (0..MESSAGES)
        .map(|n| {
            let id = if name == "a" { n } else { n.wrapping_add(100) };
            hex(&[id; 16])
        })
        .collect()
}

/// One run: crash point `index`, `seed`; returns (digests, distinct).
fn run(index: u64, seed: u64) -> (usize, usize) {
    let root = TempDir::new("pc05").unwrap();
    let dir = root.path();
    let nth = u32::try_from(seed.wrapping_mul(7) % 40)
        .unwrap()
        .saturating_add(1);
    let env = |life: &str| {
        let point_s = index.to_string();
        let seed_s = seed.to_string();
        let nth_s = nth.to_string();
        let life_s = life.to_owned();
        (point_s, seed_s, nth_s, life_s)
    };
    for l in ["1", "2"] {
        let (p, s, n, life_s) = env(l);
        let ok = secmp_store::kat::run_child(
            TEST,
            ROLE,
            &[
                ("SECMP_PC05_DIR", dir),
                ("SECMP_PC05_POINT", Path::new(&p)),
                ("SECMP_PC05_SEED", Path::new(&s)),
                ("SECMP_PC05_NTH", Path::new(&n)),
                ("SECMP_PC05_LIFE", Path::new(&life_s)),
            ],
        )
        .unwrap();
        let panic = std::fs::read_to_string(dir.join("panic.txt")).ok();
        assert_eq!(
            panic, None,
            "point {index} seed {seed} life {l}: the child panicked"
        );
        if l == "1" {
            assert!(
                !ok,
                "point {index} seed {seed}: life 1 aborts at its crash point"
            );
        } else {
            assert!(ok, "point {index} seed {seed}: life 2 runs to the end");
        }
    }
    let all: Vec<String> = [
        lines(&dir.join("digests-1.txt")),
        lines(&dir.join("digests-2.txt")),
    ]
    .concat();
    let distinct: BTreeSet<&String> = all.iter().collect();
    assert_eq!(
        distinct.len(),
        all.len(),
        "point {index} seed {seed}: a message key sealed two released cells"
    );
    for (me, peer) in [("a", "b"), ("b", "a")] {
        let h1: BTreeSet<String> = lines(&dir.join(format!("history-{me}.txt")))
            .into_iter()
            .collect();
        let r1 = lines(&dir.join(format!("received-1-{me}.txt")));
        let r2 = lines(&dir.join(format!("received-2-{me}.txt")));
        let r1_set: BTreeSet<&String> = r1.iter().collect();
        assert_eq!(
            r1_set.len(),
            r1.len(),
            "{me}: a message delivered twice in life 1"
        );
        let r2_set: BTreeSet<String> = r2.iter().cloned().collect();
        assert_eq!(
            r2_set.len(),
            r2.len(),
            "{me}: a message delivered twice in life 2"
        );
        assert!(
            r2_set.is_disjoint(&h1),
            "point {index} seed {seed}: {me} delivered again what its history held"
        );
        assert!(
            r1.iter().all(|m| h1.contains(m)),
            "point {index} seed {seed}: {me} delivered in life 1 what its history lost"
        );
        let union: BTreeSet<String> = h1.union(&r2_set).cloned().collect();
        assert_eq!(
            union,
            sent_by(peer),
            "point {index} seed {seed}: {me} got every message of {peer}"
        );
    }
    (all.len(), distinct.len())
}

/// PC-05 (`docs/07:145`): 5 crash points × 20 seeds, two profiles, 30 real messages each way per seed, a restart from
/// disk after each crash (see the module documentation).
#[test]
fn crash_between_persist_and_send_no_key_reuse() {
    if secmp_store::kat::child_role().as_deref() == Some(ROLE) {
        let var = |k: &str| std::env::var(k).unwrap();
        let dir = PathBuf::from(var("SECMP_PC05_DIR"));
        // a panic (not the abort of a crash point) leaves a mark the parent checks
        let mark = dir.join("panic.txt");
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = std::fs::write(&mark, info.to_string());
            default(info);
        }));
        let index: u64 = var("SECMP_PC05_POINT").parse().unwrap();
        let seed: u64 = var("SECMP_PC05_SEED").parse().unwrap();
        let nth: u32 = var("SECMP_PC05_NTH").parse().unwrap();
        let l: u64 = var("SECMP_PC05_LIFE").parse().unwrap();
        let crash = (l == 1).then(|| (point(index, seed), nth));
        life(&dir, seed, l, crash);
        return;
    }
    let names = [
        "AfterCommitBeforeWrite",
        "AfterWriteBeforeOkSend",
        "MidTxn(1|2)",
        "AfterDecryptBeforeCommit",
        "AfterCommitBeforeAck",
    ];
    let (mut total, mut distinct) = (0_usize, 0_usize);
    let mut rows = Vec::new();
    for (index, name) in (0..5_u64).zip(names) {
        let (mut t_point, mut d_point) = (0_usize, 0_usize);
        for seed in 0..SEEDS {
            let (t, d) = run(index, seed.wrapping_add(index.wrapping_mul(100)));
            t_point += t;
            d_point += d;
        }
        rows.push(format!(
            "  {name}: keys counted {t_point}, distinct {d_point}, duplicates {}",
            t_point - d_point
        ));
        total += t_point;
        distinct += d_point;
    }
    let text = format!(
        "PC-05 crash between persist and send (5 crash points x {SEEDS} seeds, two profiles, {MESSAGES} real messages each \
         way; SHA-256 digests of the message keys, never the keys): distinct/total = {distinct}/{total}, duplicates {}; \
         every message delivered exactly once\n{}",
        total - distinct,
        rows.join("\n")
    );
    evidence("pc-05-key-digests", &text);
    assert_eq!(distinct, total);
}
