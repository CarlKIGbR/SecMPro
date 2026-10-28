// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`StorePersist`]: the incremental, store-backed [`Persist`] of one session (CS-3.7 `docs/04:58`, `docs/02:102`;
//! OPEN-M7-14 A). The scheduler never sees it (OB-07, PC-12): it lives outside `scheduler/**` and reaches the scheduler
//! only as a `Persist`.
//!
//! **Incremental.** A commit writes the fixed part of `RatchetStateV1` (one row, rewritten per slot), inserts a row per
//! new skipped entry and deletes the row of every entry the step consumed or evicted — never the whole state. The entries
//! keep their insertion order through `ord` (the deque of §7.1 only appends at the back and removes anywhere). The
//! rows, the reassembly state, the trust and the delivered messages of one commit are one store transaction
//! (persist-before-send and -ack, CLAUDE.md §1.7; PC-09).
//!
//! **Crash points** (`kat`, TEST-SPEC-M7 Conventions): `AfterDecryptBeforeCommit` before a `Receive` commit,
//! `AfterCommitBeforeAck` after it, `AfterCommitBeforeWrite` after a `Send` commit; `MidTxn(k)` is the store's.

use std::sync::{Arc, Mutex};

use secmp_proto::tr::{RatchetParts, SKIPPED_KEY_LEN};
use secmp_store::Store;

pub use crate::scheduler::outbox::trust_code;
use crate::scheduler::outbox::{CommitParts, MsgId, Persist, PersistError, PersistKind};

/// A profile store shared by the sessions and the outbox of a client.
pub type SharedStore = Arc<Mutex<Store>>;

/// Row writes of a [`StorePersist`] (PC-07: incremental, never the whole state).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteCounts {
    /// Commits made durable.
    pub commits: u64,
    /// Writes of the fixed part (one per commit).
    pub fixed: u64,
    /// Skipped entries inserted.
    pub skipped_inserted: u64,
    /// Skipped entries deleted.
    pub skipped_deleted: u64,
}

/// The durable reassembly state and trust row of a session (each `None` before its first write).
pub type InboxTrust = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The store-backed durability of one session (see the module documentation).
pub struct StorePersist {
    store: SharedStore,
    session: i64,
    /// The stored skipped entries: `ord` and the entry's key `hk ‖ n`, in insertion order.
    entries: Vec<(i64, [u8; SKIPPED_KEY_LEN])>,
    next_ord: i64,
    counts: WriteCounts,
}

fn key_of(entry: &[u8]) -> Result<[u8; SKIPPED_KEY_LEN], PersistError> {
    entry
        .get(..SKIPPED_KEY_LEN)
        .and_then(|k| <[u8; SKIPPED_KEY_LEN]>::try_from(k).ok())
        .ok_or(PersistError)
}

impl StorePersist {
    /// The durability of `session` in `store`; the stored entries are read once.
    ///
    /// # Errors
    /// [`PersistError`] if the store cannot be read.
    pub fn open(store: SharedStore, session: i64) -> Result<Self, PersistError> {
        let entries = {
            let s = store.lock().map_err(|_| PersistError)?;
            match s.session_rows(session).map_err(|_| PersistError)? {
                Some(rows) => rows
                    .skipped
                    .iter()
                    .map(|(ord, e)| key_of(e).map(|k| (*ord, k)))
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            }
        };
        let next_ord = entries.last().map_or(0, |(o, _)| o.saturating_add(1));
        Ok(Self {
            store,
            session,
            entries,
            next_ord,
            counts: WriteCounts::default(),
        })
    }

    /// The durable state of the session, in its parts (`None` before its first commit).
    ///
    /// # Errors
    /// [`PersistError`] if the store cannot be read.
    pub fn load(&self) -> Result<Option<RatchetParts>, PersistError> {
        load_parts(&self.store, self.session)
    }

    /// The durable reassembly state and trust code of the session.
    ///
    /// # Errors
    /// [`PersistError`] if the store cannot be read.
    pub fn load_inbox_trust(&self) -> Result<InboxTrust, PersistError> {
        let s = self.store.lock().map_err(|_| PersistError)?;
        Ok(s.session_rows(self.session)
            .map_err(|_| PersistError)?
            .map_or((None, None), |r| (r.inbox, r.trust)))
    }

    /// The messages the history holds as delivered on this session (the dedup set after a restart).
    ///
    /// # Errors
    /// [`PersistError`] if the store cannot be read.
    pub fn delivered_ids(&self) -> Result<Vec<MsgId>, PersistError> {
        let s = self.store.lock().map_err(|_| PersistError)?;
        s.delivered_ids(self.session).map_err(|_| PersistError)
    }

    /// The row writes so far.
    #[must_use]
    pub const fn counts(&self) -> WriteCounts {
        self.counts
    }
}

/// The durable state of `session` in `store`, in its parts.
///
/// # Errors
/// [`PersistError`] if the store cannot be read.
pub fn load_parts(store: &SharedStore, session: i64) -> Result<Option<RatchetParts>, PersistError> {
    let s = store.lock().map_err(|_| PersistError)?;
    let Some(rows) = s.session_rows(session).map_err(|_| PersistError)? else {
        return Ok(None);
    };
    Ok(Some(RatchetParts {
        fixed: secmp_crypto::Zeroizing::new(rows.fixed),
        skipped: rows
            .skipped
            .into_iter()
            .map(|(_, e)| secmp_crypto::Zeroizing::new(e))
            .collect(),
    }))
}

impl Persist for StorePersist {
    fn commit(&mut self, kind: PersistKind, state: &[u8]) -> Result<(), PersistError> {
        let ratchet = RatchetParts::split(state).map_err(|_| PersistError)?;
        self.commit_parts(
            kind,
            &CommitParts {
                ratchet: &ratchet,
                inbox: None,
                trust: None,
                delivered: &[],
            },
        )
    }

    fn commit_parts(
        &mut self,
        kind: PersistKind,
        parts: &CommitParts<'_>,
    ) -> Result<(), PersistError> {
        #[cfg(feature = "kat")]
        if kind == PersistKind::Receive {
            secmp_store::kat::crash_point(secmp_store::kat::CrashAt::AfterDecryptBeforeCommit);
        }
        // the diff against the stored entries, by key (hk, n): deleted are the stored ones the new state lacks, inserted
        // the new ones the store lacks, in their order (always at the back of the deque)
        let new_keys: Vec<[u8; SKIPPED_KEY_LEN]> = parts
            .ratchet
            .skipped
            .iter()
            .map(|e| key_of(e))
            .collect::<Result<_, _>>()?;
        let deleted: Vec<i64> = self
            .entries
            .iter()
            .filter(|(_, k)| !new_keys.contains(k))
            .map(|(o, _)| *o)
            .collect();
        let mut inserted: Vec<(i64, usize)> = Vec::new();
        let mut ord = self.next_ord;
        for (i, k) in new_keys.iter().enumerate() {
            if !self.entries.iter().any(|(_, s)| s == k) {
                inserted.push((ord, i));
                ord = ord.checked_add(1).ok_or(PersistError)?;
            }
        }
        let session = self.session;
        {
            let mut s = self.store.lock().map_err(|_| PersistError)?;
            s.txn(|tx| {
                secmp_store::sessions::put_fixed(tx, session, &parts.ratchet.fixed)?;
                for o in &deleted {
                    secmp_store::sessions::delete_skipped(tx, session, *o)?;
                }
                for (o, i) in &inserted {
                    let entry = parts
                        .ratchet
                        .skipped
                        .get(*i)
                        .ok_or(secmp_store::Error::Unavailable)?;
                    secmp_store::sessions::insert_skipped(tx, session, *o, entry)?;
                }
                if let Some(inbox) = parts.inbox {
                    secmp_store::sessions::put_inbox(tx, session, inbox)?;
                }
                if let Some(trust) = parts.trust {
                    secmp_store::sessions::put_trust(tx, session, &[trust])?;
                }
                for m in parts.delivered {
                    match secmp_store::sessions::insert_delivered(
                        tx, session, &m.msg_id, m.kind, m.payload,
                    ) {
                        // a view-once is held in memory by the application, never written (CS-3.4)
                        Ok(()) | Err(secmp_store::Error::Unsupported) => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            })
            .map_err(|_| PersistError)?;
        }
        self.entries.retain(|(o, _)| !deleted.contains(o));
        for (o, i) in &inserted {
            if let Some(k) = new_keys.get(*i) {
                self.entries.push((*o, *k));
            }
        }
        self.next_ord = ord;
        self.counts.commits = self.counts.commits.saturating_add(1);
        self.counts.fixed = self.counts.fixed.saturating_add(1);
        self.counts.skipped_inserted = self
            .counts
            .skipped_inserted
            .saturating_add(u64::try_from(inserted.len()).unwrap_or(u64::MAX));
        self.counts.skipped_deleted = self
            .counts
            .skipped_deleted
            .saturating_add(u64::try_from(deleted.len()).unwrap_or(u64::MAX));
        #[cfg(feature = "kat")]
        secmp_store::kat::crash_point(match kind {
            PersistKind::Send => secmp_store::kat::CrashAt::AfterCommitBeforeWrite,
            PersistKind::Receive => secmp_store::kat::CrashAt::AfterCommitBeforeAck,
        });
        let _ = kind;
        Ok(())
    }
}

// the seed helper of the property tests (`xtask` seed rules; `prop_parts_reassemble_to_state`)
#[cfg(all(test, feature = "kat"))]
#[path = "../../secmp-proto/tests/common/seed.rs"]
mod seed;

#[cfg(test)]
mod tests {
    // The module is plain `cfg(test)`; the bodies need the `kat` test key and fixed entropy, so each test is gated inside
    // (a module under `cfg(all(test, feature))` is compiled out of the mutation gate's first run). The tests return
    // `Result`: an in-crate test module has no `unwrap` allowance.

    #[cfg(feature = "kat")]
    use super::*;
    #[cfg(feature = "kat")]
    use secmp_proto::tr::{Entropy as _, FixedEntropy, RatchetState};

    #[cfg(feature = "kat")]
    type R = Result<(), String>;

    /// `r` with its error as text.
    #[cfg(feature = "kat")]
    fn f<T, E: core::fmt::Debug>(r: Result<T, E>, what: &str) -> Result<T, String> {
        r.map_err(|e| format!("{what}: {e:?}"))
    }

    /// A deterministic byte stream for `FixedEntropy` (not random, not secret).
    #[cfg(feature = "kat")]
    fn stream(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(23) ^ 0x5851_f42d;
                x.to_be_bytes().first().copied().unwrap_or(0)
            })
            .collect()
    }

    /// The two sides of a session A → B from one shared secret, with the entropy of each.
    #[cfg(feature = "kat")]
    fn pair(seed: u64) -> Result<(RatchetState, FixedEntropy, RatchetState, FixedEntropy), String> {
        use secmp_crypto::SecretBytes;
        use secmp_proto::keys::{MlKem768Ek, X25519Pk};
        let base = seed.wrapping_mul(4);
        let mut responder = FixedEntropy::new(&stream(base.wrapping_add(2), 1 << 16));
        let mut initiator = FixedEntropy::new(&stream(base.wrapping_add(1), 1 << 16));
        let spk_dh = f(responder.x25519(), "x25519")?;
        let rpk_kem = f(responder.mlkem768(), "ml-kem")?;
        let spk = f(X25519Pk::from_bytes(spk_dh.public_key().as_bytes()), "spk")?;
        let ek = f(
            MlKem768Ek::from_bytes(rpk_kem.encapsulation_key().as_bytes()),
            "ek",
        )?;
        let sk = f(SecretBytes::from_slice(&[7_u8; 32]), "secret")?;
        let a = f(
            RatchetState::init_initiator_with(&sk, &[9_u8; 32], &spk, &ek, &mut initiator),
            "initiator",
        )?;
        let b = f(
            RatchetState::init_responder(&sk, &[9_u8; 32], spk_dh, rpk_kem),
            "responder",
        )?;
        let ea = FixedEntropy::new(&stream(base.wrapping_add(3), 1 << 22));
        let eb = FixedEntropy::new(&stream(base.wrapping_add(4), 1 << 22));
        Ok((a, ea, b, eb))
    }

    /// A content with one text message `n`.
    #[cfg(feature = "kat")]
    fn text(n: u8) -> secmp_proto::wire::cell::Content {
        use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody, Content, ContentBody};
        Content {
            seq: u64::from(n),
            ts: 0,
            body: ContentBody::Batch(BatchBody {
                messages: vec![AppMessage {
                    msg_id: [n; 16],
                    kind: AppKind::Text,
                    expire_after: 0,
                    payload: secmp_crypto::Zeroizing::new(vec![0x61; 32]),
                }],
            }),
        }
    }

    /// `state` seals `content` and commits the new state through `persist`: the new state and the cell.
    #[cfg(feature = "kat")]
    fn seal(
        state: RatchetState,
        content: &secmp_proto::wire::cell::Content,
        e: &mut FixedEntropy,
        persist: &mut dyn Persist,
    ) -> Result<(RatchetState, Vec<u8>), String> {
        let sealed = f(
            state.encrypt_with(content, e).map_err(|r| r.error()),
            "encrypt",
        )?;
        let (s, cell) = f(
            sealed.persist(|bytes| persist.commit(PersistKind::Send, bytes)),
            "persist",
        )?;
        Ok((s, cell.as_bytes().to_vec()))
    }

    /// `state` opens `cell` and commits the new state through `persist`.
    #[cfg(feature = "kat")]
    fn open(
        state: RatchetState,
        cell: &[u8],
        e: &mut FixedEntropy,
        persist: &mut dyn Persist,
    ) -> Result<RatchetState, String> {
        let opened = f(
            state.decrypt_with(cell, e).map_err(|r| r.error()),
            "decrypt",
        )?;
        let (s, _) = f(
            opened.commit(|bytes| persist.commit(PersistKind::Receive, bytes)),
            "commit",
        )?;
        Ok(s)
    }

    /// The profile store in `dir`, opened with the test key.
    #[cfg(feature = "kat")]
    fn shared(dir: &std::path::Path) -> Result<SharedStore, String> {
        let store = f(
            secmp_store::Store::open(dir, &secmp_store::kat::TestKey::db_key()),
            "open",
        )?;
        Ok(Arc::new(Mutex::new(store)))
    }

    /// The durable `RatchetStateV1` of `session`, rebuilt from its rows.
    #[cfg(feature = "kat")]
    fn durable(store: &SharedStore, session: i64) -> Result<Vec<u8>, String> {
        let parts = f(load_parts(store, session), "load")?.ok_or("no state")?;
        Ok(f(parts.to_bytes(), "join")?.to_vec())
    }

    /// `b - a` of two counters.
    #[cfg(feature = "kat")]
    fn delta(b: u64, a: u64) -> u64 {
        b.saturating_sub(a)
    }

    /// A sends `k` text cells, committing to `sink`: the new state and the cells.
    #[cfg(feature = "kat")]
    fn burst(
        mut a: RatchetState,
        ea: &mut FixedEntropy,
        sink: &mut dyn Persist,
        k: usize,
    ) -> Result<(RatchetState, Vec<Vec<u8>>), String> {
        let mut cells = Vec::with_capacity(k);
        for i in 0..k {
            let n = u8::try_from(i.checked_rem(200).unwrap_or(0)).map_err(|_| "n")?;
            let (next, cell) = seal(a, &text(n), ea, sink)?;
            a = next;
            cells.push(cell);
        }
        Ok((a, cells))
    }

    /// B's stored skipped rows (their `ord`s, in order).
    #[cfg(feature = "kat")]
    fn skipped_ords(store: &SharedStore, session: i64) -> Result<Vec<i64>, String> {
        let rows = f(f(store.lock(), "lock")?.session_rows(session), "rows")?.ok_or("no rows")?;
        Ok(rows.skipped.iter().map(|(o, _)| *o).collect())
    }

    /// PC-07 (CS-3.7 `docs/04:58`, `docs/02:102`; OPEN-M7-14 A): a dummy slot and a real slot write the fixed row once each
    /// and no skipped row (0/0); a receive that skips k = 10 inserts 10 skipped rows; an eviction of 3 skipped entries
    /// (a receive that skips 3 more at the bound of 512) deletes exactly the 3 earliest rows (−3, with its +3); three
    /// late cells consuming their entries delete 3 rows and insert none. Every commit writes the fixed row once — no
    /// commit rewrites the whole state — and the rows are the state byte for byte.
    #[test]
    #[cfg(feature = "kat")]
    fn incremental_rows_per_slot() -> R {
        let dir = f(secmp_store::kat::TempDir::new("pc07"), "dir")?;
        let store = shared(dir.path())?;
        let (a, mut ea, b, mut eb) = pair(7)?;
        let mut pa = f(StorePersist::open(Arc::clone(&store), 1), "persist A")?;
        let mut pb = f(StorePersist::open(Arc::clone(&store), 2), "persist B")?;
        let mut sink = crate::scheduler::outbox::MemPersist::new();
        // a dummy slot and a real slot of A
        let (a, _dummy) = seal(a, &secmp_proto::tr::content::dummy(), &mut ea, &mut pa)?;
        let one = WriteCounts {
            commits: 1,
            fixed: 1,
            skipped_inserted: 0,
            skipped_deleted: 0,
        };
        assert_eq!(pa.counts(), one, "dummy slot");
        let (a, real) = seal(a, &text(1), &mut ea, &mut pa)?;
        let two = WriteCounts {
            commits: 2,
            fixed: 2,
            skipped_inserted: 0,
            skipped_deleted: 0,
        };
        assert_eq!(pa.counts(), two, "real slot");
        // B receives the real cell (the dummy before it is one skipped entry), then the 11th of the next 11: k = 10
        let mut b = open(b, &real, &mut eb, &mut pb)?;
        let (mut a, mut late) = burst(a, &mut ea, &mut sink, 11)?;
        let last = late.pop().ok_or("no cell")?;
        let before = pb.counts();
        b = open(b, &last, &mut eb, &mut pb)?;
        let after = pb.counts();
        assert_eq!(delta(after.fixed, before.fixed), 1);
        assert_eq!(
            delta(after.skipped_inserted, before.skipped_inserted),
            10,
            "k = 10"
        );
        assert_eq!(delta(after.skipped_deleted, before.skipped_deleted), 0);
        assert_eq!(durable(&store, 2)?, f(b.to_bytes(), "bytes")?.to_vec());
        // fill `skipped` to its bound over two more chains (at most `SKIP_WINDOW` per receive): B replies, A answers on
        // a new chain and B receives the last cell of the burst
        for _ in 0..2 {
            let stored = skipped_ords(&store, 2)?.len();
            let gap = secmp_proto::tr::MAX_SKIPPED
                .saturating_sub(stored)
                .min(usize::try_from(secmp_proto::tr::SKIP_WINDOW).map_err(|_| "window")?);
            let (next, reply) = seal(b, &secmp_proto::tr::content::dummy(), &mut eb, &mut pb)?;
            b = next;
            a = open(a, &reply, &mut ea, &mut sink)?;
            let (next, cells) = burst(a, &mut ea, &mut sink, gap.saturating_add(1))?;
            a = next;
            b = open(b, cells.last().ok_or("no cell")?, &mut eb, &mut pb)?;
        }
        let full = skipped_ords(&store, 2)?;
        assert_eq!(full.len(), secmp_proto::tr::MAX_SKIPPED, "at the bound");
        // the eviction of 3: a receive that skips 3 more on the current chain
        let (next, cells) = burst(a, &mut ea, &mut sink, 4)?;
        let _a = next;
        let before = pb.counts();
        b = open(b, cells.last().ok_or("no cell")?, &mut eb, &mut pb)?;
        let after = pb.counts();
        assert_eq!(delta(after.fixed, before.fixed), 1);
        assert_eq!(delta(after.skipped_inserted, before.skipped_inserted), 3);
        assert_eq!(
            delta(after.skipped_deleted, before.skipped_deleted),
            3,
            "eviction: −3"
        );
        let now = skipped_ords(&store, 2)?;
        assert_eq!(now.len(), secmp_proto::tr::MAX_SKIPPED);
        assert_eq!(
            now.get(..509),
            full.get(3..),
            "the 3 earliest rows left, the others stayed"
        );
        assert_eq!(durable(&store, 2)?, f(b.to_bytes(), "bytes")?.to_vec());
        // three late cells of the first chain consume their entries: −3, nothing inserted
        // (the dummy and late[0..2] were the earliest, evicted above)
        for cell in late.iter().skip(4).take(3) {
            b = open(b, cell, &mut eb, &mut pb)?;
        }
        let end = pb.counts();
        assert_eq!(delta(end.fixed, after.fixed), 3);
        assert_eq!(delta(end.skipped_inserted, after.skipped_inserted), 0);
        assert_eq!(delta(end.skipped_deleted, after.skipped_deleted), 3);
        assert_eq!(durable(&store, 2)?, f(b.to_bytes(), "bytes")?.to_vec());
        assert_eq!(
            pb.counts().fixed,
            pb.counts().commits,
            "one fixed write per commit"
        );
        Ok(())
    }

    /// A deterministic generator of the property (seeded from the master seed).
    #[cfg(feature = "kat")]
    struct Mix(u64);

    #[cfg(feature = "kat")]
    impl Mix {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33).checked_rem(n.max(1)).unwrap_or(0)
        }
    }

    /// The default seed of this file's property (`xtask` seed rules).
    #[cfg(feature = "kat")]
    const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0701;

    /// PC-08 (`RatchetStateV1`, frozen layout; OPEN-M7-14 A): seeded TR runs of 300 messages with skips, late deliveries
    /// and replies (DH steps, so entries of older chains); after every commit the state rebuilt from the rows is the
    /// state's `to_bytes` byte for byte, on both sides.
    #[test]
    #[cfg(feature = "kat")]
    fn prop_parts_reassemble_to_state() -> R {
        let master = super::seed::master_seed(DEFAULT_SEED);
        for case in 0..2_u64 {
            let mut mix = Mix(master ^ case.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let dir = f(secmp_store::kat::TempDir::new("pc08"), "dir")?;
            let store = shared(dir.path())?;
            let (mut a, mut ea, mut b, mut eb) = pair(case.wrapping_add(80))?;
            let mut pa = f(StorePersist::open(Arc::clone(&store), 1), "persist A")?;
            let mut pb = f(StorePersist::open(Arc::clone(&store), 2), "persist B")?;
            let mut pending: Vec<Vec<u8>> = Vec::new();
            let mut sent = 0_u32;
            let mut n = 0_u8;
            // the responder sends only after its first receive (§7.2)
            let mut b_received = false;
            while sent < 300 {
                match mix.below(10) {
                    0..=5 => {
                        for _ in 0..=mix.below(4) {
                            n = n.wrapping_add(1);
                            let (s, cell) = seal(a, &text(n), &mut ea, &mut pa)?;
                            a = s;
                            assert_eq!(durable(&store, 1)?, f(a.to_bytes(), "a")?.to_vec());
                            pending.push(cell);
                            sent = sent.saturating_add(1);
                        }
                    }
                    6..=8 if !pending.is_empty() => {
                        let len = f(u64::try_from(pending.len()), "len")?;
                        let i = f(usize::try_from(mix.below(len)), "index")?;
                        let cell = pending.remove(i);
                        b = open(b, &cell, &mut eb, &mut pb)?;
                        b_received = true;
                        assert_eq!(
                            durable(&store, 2)?,
                            f(b.to_bytes(), "b")?.to_vec(),
                            "case {case}"
                        );
                    }
                    9 if b_received => {
                        // B replies; A's next cell starts a new chain and the undelivered cells of the old one arrive late
                        let (s, cell) =
                            seal(b, &secmp_proto::tr::content::dummy(), &mut eb, &mut pb)?;
                        b = s;
                        assert_eq!(
                            durable(&store, 2)?,
                            f(b.to_bytes(), "b")?.to_vec(),
                            "case {case}"
                        );
                        a = open(a, &cell, &mut ea, &mut pa)?;
                        assert_eq!(durable(&store, 1)?, f(a.to_bytes(), "a")?.to_vec());
                        // inside the skip window
                        if pending.len() > 40 {
                            pending.drain(..20);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// PC-06 (P-03 of M6; spec §10.4): seeded random sequences of enqueue, send (`take_next`), `OK_SEND` (`relayed`),
    /// eviction (`requeue`), `NOQUEUE` (`requeue_unreceipted`), receipt (`delivered`), 30-day expiry and restart on a
    /// `StoreOutbox` — whose restart reopens the store — and on the model `MemOutbox`: after every step the `MsgState` of
    /// every id is the same, and so is the number waiting.
    #[test]
    #[cfg(feature = "kat")]
    fn prop_store_matches_mem_model() -> R {
        use crate::outbox::StoreOutbox;
        use crate::scheduler::outbox::{FAIL_AFTER_MS, MemOutbox, OutMessage, Outbox};
        use secmp_proto::wire::cell::AppKind;
        let master = super::seed::master_seed(DEFAULT_SEED);
        for case in 0..3_u64 {
            let mut mix = Mix(master ^ case.wrapping_add(1).wrapping_mul(0xa076_1d64_78bd_642f));
            let dir = f(secmp_store::kat::TempDir::new("pc06"), "dir")?;
            let mut store_o = f(StoreOutbox::open(shared(dir.path())?, 3), "open")?;
            let mut model = MemOutbox::new();
            let mut ids: Vec<[u8; 16]> = Vec::new();
            let mut taken: Vec<[u8; 16]> = Vec::new();
            let mut now = 0_u64;
            let mut cell = 0_u64;
            for step in 0..150_u32 {
                now = now.saturating_add(mix.below(3_600_000));
                let pick = |mix: &mut Mix, from: &[[u8; 16]]| -> Option<[u8; 16]> {
                    let len = u64::try_from(from.len()).ok()?;
                    from.get(usize::try_from(mix.below(len)).ok()?).copied()
                };
                match mix.below(9) {
                    0 | 1 => {
                        let n = u8::try_from(ids.len().checked_rem(250).unwrap_or(0))
                            .map_err(|_| "n")?;
                        let id = [n, 0x5a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                        let message = || OutMessage {
                            msg_id: id,
                            kind: AppKind::Text,
                            expire_after: 0,
                            payload: secmp_crypto::Zeroizing::new(vec![n; 4]),
                        };
                        store_o.enqueue(message(), now);
                        model.enqueue(message(), now);
                        ids.push(id);
                    }
                    2 => {
                        let a = store_o.take_next().map(|m| m.msg_id);
                        let b = model.take_next().map(|m| m.msg_id);
                        assert_eq!(a, b, "case {case} step {step}: take_next");
                        taken.extend(a);
                    }
                    3 => {
                        if let Some(id) = pick(&mut mix, &taken) {
                            cell = cell.saturating_add(1);
                            store_o.relayed(&id, cell);
                            model.relayed(&id, cell);
                        }
                    }
                    4 => {
                        if let Some(id) = pick(&mut mix, &ids) {
                            store_o.requeue(&id);
                            model.requeue(&id);
                        }
                    }
                    5 => {
                        store_o.requeue_unreceipted();
                        model.requeue_unreceipted();
                    }
                    6 => {
                        if let Some(id) = pick(&mut mix, &ids) {
                            store_o.delivered(&id);
                            model.delivered(&id);
                        }
                    }
                    7 => {
                        now = now.saturating_add(
                            FAIL_AFTER_MS.saturating_sub(mix.below(2 * 86_400_000)),
                        );
                        store_o.expire(now);
                        model.expire(now);
                    }
                    _ => {
                        // the process restarts: the store outbox is reopened from disk
                        drop(store_o);
                        store_o = f(StoreOutbox::open(shared(dir.path())?, 3), "reopen")?;
                        model.restart();
                        taken.clear();
                    }
                }
                for id in &ids {
                    assert_eq!(
                        store_o.state(id),
                        model.state(id),
                        "case {case} step {step}"
                    );
                }
                assert_eq!(
                    store_o.waiting(),
                    model.waiting(),
                    "case {case} step {step}"
                );
                assert_eq!(store_o.write_errors(), 0);
            }
        }
        Ok(())
    }

    /// The child of PC-01: commit S0, then S1 (`Send`), record SHA-256(S1) next to the profile, abort.
    #[cfg(feature = "kat")]
    fn durable_child(dir: &std::path::Path) -> R {
        let store = shared(dir)?;
        let (a, mut ea, _, _) = pair(1)?;
        let mut pa = f(StorePersist::open(Arc::clone(&store), 1), "persist")?;
        f(
            pa.commit(PersistKind::Send, &f(a.to_bytes(), "s0")?),
            "commit S0",
        )?;
        let sealed = f(
            a.encrypt_with(&secmp_proto::tr::content::dummy(), &mut ea)
                .map_err(|r| r.error()),
            "encrypt",
        )?;
        let mut s1 = Vec::new();
        f(
            sealed.persist(|bytes| {
                s1 = bytes.to_vec();
                pa.commit(PersistKind::Send, bytes)
            }),
            "commit S1",
        )?;
        f(
            std::fs::write(dir.join("s1.digest"), secmp_crypto::sha256(&[&s1])),
            "digest",
        )?;
        std::process::abort()
    }

    /// PC-01 (the `Persist` contract, `scheduler/outbox.rs`): `commit(Send, S1)` returns `Ok` in a child that aborts right
    /// after it; the reopened store holds S1 (SHA-256 equal).
    #[test]
    #[cfg(feature = "kat")]
    fn store_persist_is_durable() -> R {
        if secmp_store::kat::child_role().as_deref() == Some("pc01") {
            let dir = std::env::var_os("SECMP_STORE_DIR").ok_or("no dir")?;
            return durable_child(std::path::Path::new(&dir));
        }
        let root = f(secmp_store::kat::TempDir::new("pc01"), "dir")?;
        let ok = f(
            secmp_store::kat::run_child(
                "persist::tests::store_persist_is_durable",
                "pc01",
                &[("SECMP_STORE_DIR", root.path())],
            ),
            "child",
        )?;
        assert!(!ok, "the child aborts");
        let want = f(std::fs::read(root.path().join("s1.digest")), "digest file")?;
        let store = shared(root.path())?;
        assert_eq!(
            secmp_crypto::sha256(&[&durable(&store, 1)?]).as_slice(),
            want.as_slice()
        );
        Ok(())
    }

    /// The entropy source of a test conversation.
    #[cfg(feature = "kat")]
    struct Fixed(FixedEntropy);

    #[cfg(feature = "kat")]
    impl crate::scheduler::conversation::EntropySource for Fixed {
        type E = FixedEntropy;

        fn entropy(&mut self) -> &mut FixedEntropy {
            &mut self.0
        }
    }

    /// PC-02 (`scheduler/outbox.rs`, the `Persist` contract): `FailAt(k)` for the statement of a `Send` commit and for
    /// every statement of a `Receive` commit gives `PersistError`; the durable state stays the previous one, no cell is
    /// released (no frame) and the received cell is not decided (no acknowledgement); after the failure the same cell is
    /// decided.
    #[test]
    #[cfg(feature = "kat")]
    fn failed_commit_changes_nothing() -> R {
        use crate::scheduler::conversation::{Conversation, Conversations};
        use crate::scheduler::outbox::MemOutbox;
        use crate::scheduler::types::{CellSource, QueueId};
        let dir = f(secmp_store::kat::TempDir::new("pc02"), "dir")?;
        let store = shared(dir.path())?;
        let (a, ea, b, eb) = pair(2)?;
        let peer = f(
            FixedEntropy::new(&stream(5, 1 << 20)).hybrid_signing_key(),
            "peer key",
        )?
        .verifying_key();
        let mut pa = f(StorePersist::open(Arc::clone(&store), 1), "persist A")?;
        f(
            pa.commit(PersistKind::Send, &f(a.to_bytes(), "a")?),
            "seed A",
        )?;
        let mut pb = f(StorePersist::open(Arc::clone(&store), 2), "persist B")?;
        f(
            pb.commit(PersistKind::Receive, &f(b.to_bytes(), "b")?),
            "seed B",
        )?;
        let mut convs: Conversations<MemOutbox, StorePersist, Fixed> = Conversations::new();
        let mut ca = Conversation::new(a, MemOutbox::new(), pa, Fixed(ea), peer.clone(), 0);
        ca.bind(QueueId(1), QueueId(9));
        let mut cb = Conversation::new(b, MemOutbox::new(), pb, Fixed(eb), peer, 0);
        cb.bind(QueueId(8), QueueId(1));
        convs.add(ca);
        convs.add(cb);
        // a `Send` commit of a fresh chain: one statement (the fixed part)
        let before = durable(&store, 1)?;
        secmp_store::kat::fail_at(secmp_store::kat::FailAt(1));
        assert!(
            convs.prepare_cell(QueueId(1), 0).is_err(),
            "no cell is released"
        );
        assert_eq!(durable(&store, 1)?, before, "send: the previous state");
        let mut cells = Vec::new();
        for _ in 0..3 {
            let p = f(convs.prepare_cell(QueueId(1), 0), "prepare")?.ok_or("no cell")?;
            cells.push(p.cell);
        }
        // B receives the third first: the fixed part and two skipped entries, three statements
        let third = cells.pop().ok_or("no cell")?;
        for k in 1..=3_u32 {
            let before = durable(&store, 2)?;
            secmp_store::kat::fail_at(secmp_store::kat::FailAt(k));
            assert!(
                convs.deliver(QueueId(1), 3, &third).is_err(),
                "statement {k}: not decided, not acknowledged"
            );
            assert_eq!(
                durable(&store, 2)?,
                before,
                "receive, statement {k}: the previous state"
            );
        }
        f(convs.deliver(QueueId(1), 3, &third), "deliver")?;
        let rows = f(f(store.lock(), "lock")?.session_rows(2), "rows")?.ok_or("no rows")?;
        assert_eq!(rows.skipped.len(), 2, "decided after the failures");
        Ok(())
    }

    /// The new state of PC-09's receive (written by the parent).
    #[cfg(feature = "kat")]
    const NEW_STATE: &str = "new.state";

    /// The child of PC-09: the receive commit of the new (ratchet, inbox, trust), with the crash `k` armed (`k` ≤ 5:
    /// after statement `k`, before the commit point; 6: after the commit, before the acknowledgement).
    #[cfg(feature = "kat")]
    fn atomic_child(dir: &std::path::Path, k: u32) -> R {
        let store = shared(dir)?;
        let mut pb = f(StorePersist::open(Arc::clone(&store), 2), "persist")?;
        let new = f(std::fs::read(dir.join(NEW_STATE)), "new state")?;
        let ratchet = f(RatchetParts::split(&new), "split")?;
        let point = if k <= 5 {
            secmp_store::kat::CrashAt::MidTxn(k)
        } else {
            secmp_store::kat::CrashAt::AfterCommitBeforeAck
        };
        secmp_store::kat::arm_crash(point, 1);
        f(
            pb.commit_parts(
                PersistKind::Receive,
                &CommitParts {
                    ratchet: &ratchet,
                    inbox: Some(b"inbox-new"),
                    trust: Some(trust_code(secmp_proto::tr::content::Trust::Frozen)),
                    delivered: &[],
                },
            ),
            "commit",
        )?;
        Ok(())
    }

    /// PC-09 (M03 review F29, R-36): the receive commit that freezes the session — the new ratchet state with two new
    /// skipped entries, the reassembly state and the trust `Frozen`, five statements of one transaction — crashed after
    /// statement k (k = 1…5, before the commit point) leaves all three old after reopen; crashed after the commit, all
    /// three new; never a mix.
    #[test]
    #[cfg(feature = "kat")]
    fn ratchet_inbox_trust_one_commit() -> R {
        if secmp_store::kat::child_role().as_deref() == Some("pc09") {
            let dir = std::env::var_os("SECMP_STORE_DIR").ok_or("no dir")?;
            let k = f(
                f(std::env::var("SECMP_PC09_K"), "no k")?.parse::<u32>(),
                "k",
            )?;
            return atomic_child(std::path::Path::new(&dir), k);
        }
        let (a, mut ea, b, mut eb) = pair(9)?;
        let mut sink = crate::scheduler::outbox::MemPersist::new();
        let (a, _c1) = seal(a, &text(1), &mut ea, &mut sink)?;
        let (a, _c2) = seal(a, &text(2), &mut ea, &mut sink)?;
        let (_a, c3) = seal(a, &text(3), &mut ea, &mut sink)?;
        let old_state = f(b.to_bytes(), "old")?.to_vec();
        let new_state = f(open(b, &c3, &mut eb, &mut sink)?.to_bytes(), "new")?.to_vec();
        let frozen = vec![trust_code(secmp_proto::tr::content::Trust::Frozen)];
        let verified = vec![trust_code(secmp_proto::tr::content::Trust::Verified)];
        for k in 1..=6_u32 {
            let root = f(secmp_store::kat::TempDir::new("pc09"), "dir")?;
            {
                let store = shared(root.path())?;
                let mut pb = f(StorePersist::open(Arc::clone(&store), 2), "persist")?;
                let ratchet = f(RatchetParts::split(&old_state), "split")?;
                f(
                    pb.commit_parts(
                        PersistKind::Receive,
                        &CommitParts {
                            ratchet: &ratchet,
                            inbox: Some(b"inbox-old"),
                            trust: Some(trust_code(secmp_proto::tr::content::Trust::Verified)),
                            delivered: &[],
                        },
                    ),
                    "old",
                )?;
            }
            f(
                std::fs::write(root.path().join(NEW_STATE), &new_state),
                "write",
            )?;
            let k_text = k.to_string();
            let ok = f(
                secmp_store::kat::run_child(
                    "persist::tests::ratchet_inbox_trust_one_commit",
                    "pc09",
                    &[
                        ("SECMP_STORE_DIR", root.path()),
                        ("SECMP_PC09_K", std::path::Path::new(&k_text)),
                    ],
                ),
                "child",
            )?;
            assert!(!ok, "k = {k}: the child aborts");
            let store = shared(root.path())?;
            let pb = f(StorePersist::open(Arc::clone(&store), 2), "reopen")?;
            let state = durable(&store, 2)?;
            let (inbox, trust) = f(pb.load_inbox_trust(), "inbox/trust")?;
            let all_new = state == new_state
                && inbox.as_deref() == Some(b"inbox-new".as_slice())
                && trust.as_ref() == Some(&frozen);
            let all_old = state == old_state
                && inbox.as_deref() == Some(b"inbox-old".as_slice())
                && trust.as_ref() == Some(&verified);
            if k <= 5 {
                assert!(all_old, "k = {k}: all three old");
            } else {
                assert!(all_new, "after the commit: all three new");
            }
        }
        Ok(())
    }
}
