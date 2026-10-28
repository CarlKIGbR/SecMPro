// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test-only parts of the store (feature `kat` and the unit tests; never in a shipped build, ST-09): the fixed test key,
//! temporary profile directories, failure and crash injection, the counting accessors and the forensic scan of the
//! Conventions of TEST-SPEC-M7.
//!
//! **No key hierarchy.** [`TestKey`] is a fixed 32-byte constant applied as the SQLCipher raw key. It is the only way to
//! obtain a [`DbKey`] in M7 Phase A step A-3; the passphrase wrap and the key derivation of ADR-053 are A-4.
//!
//! **Injection** is thread-local: [`fail_at`] arms the k-th SQL statement of the next transaction of this thread to fail,
//! [`arm_crash`] makes the n-th occurrence of a [`CrashAt`] point call `std::process::abort` (the test runs that part in
//! a child process, [`child_role`], and the parent reopens the profile from disk).

use std::cell::Cell;
use std::path::{Path, PathBuf};

use crate::store::DbKey;

/// The fixed raw key of the test profiles: 32 bytes, applied as `PRAGMA key = "x'…'"`.
pub struct TestKey;

/// The bytes of the test key.
const TEST_KEY: [u8; 32] = [
    0x5e, 0xc3, 0x2d, 0x07, 0x51, 0x70, 0x7e, 0x5a, 0x0a, 0x13, 0x26, 0x39, 0x4c, 0x5f, 0x72, 0x85,
    0x98, 0xab, 0xbe, 0xd1, 0xe4, 0xf7, 0x0b, 0x1e, 0x31, 0x44, 0x57, 0x6a, 0x7d, 0x90, 0xa3, 0xb6,
];

impl TestKey {
    /// The key of every test profile.
    #[must_use]
    pub fn db_key() -> DbKey {
        DbKey::from_bytes(TEST_KEY)
    }

    /// The test key with its last bit flipped (ST-04: a key differing in one bit).
    #[must_use]
    pub fn one_bit_off() -> DbKey {
        let mut k = TEST_KEY;
        if let Some(last) = k.last_mut() {
            *last ^= 1;
        }
        DbKey::from_bytes(k)
    }
}

/// A fresh directory under `target/secmp-store-tests/`, removed on drop.
pub struct TempDir {
    path: PathBuf,
    remove: bool,
}

thread_local! {
    static DIR_SEQ: Cell<u64> = const { Cell::new(0) };
}

impl TempDir {
    /// A new empty directory named after `label`, the process and a per-thread counter.
    ///
    /// # Errors
    /// If the directory cannot be created.
    pub fn new(label: &str) -> std::io::Result<Self> {
        let n = DIR_SEQ.with(|c| {
            let n = c.get();
            c.set(n.saturating_add(1));
            n
        });
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/secmp-store-tests")
            .join(format!("{label}-{}-{n}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir_all(&path)?;
        Ok(Self { path, remove: true })
    }

    /// An existing directory that is kept on drop (a child process works in its parent's directory).
    #[must_use]
    pub const fn keep(path: PathBuf) -> Self {
        Self {
            path,
            remove: false,
        }
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.remove {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// The crash points of the Conventions (TEST-SPEC-M7): `MidTxn(k)` is inside a store transaction (after its k-th
/// statement); the others are the client's points around a commit, a frame write and an acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashAt {
    /// After the `Send` commit, before the frame with the cell is written.
    AfterCommitBeforeWrite,
    /// After the frame is written, before `OK_SEND` reaches the outbox.
    AfterWriteBeforeOkSend,
    /// Inside a store transaction, after its k-th statement (1-based) — after the last one, before the commit point.
    MidTxn(u32),
    /// After a received cell is decrypted, before its decision is committed.
    AfterDecryptBeforeCommit,
    /// After the decision is committed, before the cell is acknowledged.
    AfterCommitBeforeAck,
}

/// A failure injection: the k-th SQL statement (1-based) of the next transaction returns an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailAt(pub u32);

thread_local! {
    static FAIL: Cell<Option<u32>> = const { Cell::new(None) };
    static CRASH: Cell<Option<(CrashAt, u32)>> = const { Cell::new(None) };
    static CRASH_SEEN: Cell<u32> = const { Cell::new(0) };
    static TXN_COMMITS: Cell<u64> = const { Cell::new(0) };
    static BYTES_WRITTEN: Cell<u64> = const { Cell::new(0) };
    static MIGRATION_STATEMENTS: Cell<u64> = const { Cell::new(0) };
    static MEASURE_WRITES: Cell<bool> = const { Cell::new(false) };
}

/// Arm `f` for the next transaction of this thread (cleared when that transaction ends).
pub fn fail_at(f: FailAt) {
    FAIL.with(|c| c.set(Some(f.0)));
}

/// Make the `nth` (1-based) occurrence of `point` on this thread abort the process.
pub fn arm_crash(point: CrashAt, nth: u32) {
    CRASH_SEEN.with(|c| c.set(0));
    CRASH.with(|c| c.set(Some((point, nth))));
}

/// A crash point: aborts the process if this is the armed occurrence of `point`.
pub fn crash_point(point: CrashAt) {
    let armed = CRASH.with(Cell::get);
    let Some((p, nth)) = armed else {
        return;
    };
    let same = match (p, point) {
        (CrashAt::MidTxn(a), CrashAt::MidTxn(b)) => a == b,
        (a, b) => a == b,
    };
    if !same {
        return;
    }
    let seen = CRASH_SEEN.with(|c| {
        let n = c.get().saturating_add(1);
        c.set(n);
        n
    });
    if seen == nth {
        std::process::abort();
    }
}

/// Called by the transaction executor before its `k`-th statement: `true` if the statement must fail.
pub(crate) fn statement_fails(k: u32) -> bool {
    crash_point_mid_txn(k.saturating_sub(1));
    FAIL.with(|c| c.get() == Some(k))
}

/// The crash point after the `k`-th statement of a transaction (`k` = 0: none yet).
fn crash_point_mid_txn(k: u32) {
    if k > 0 {
        crash_point(CrashAt::MidTxn(k));
    }
}

/// Called by the executor when a transaction ends (committed or not): the failure injection is one-shot.
pub(crate) fn transaction_ended(statements: u32, committed: bool) {
    crash_point_mid_txn(statements);
    FAIL.with(|c| c.set(None));
    if committed {
        TXN_COMMITS.with(|c| c.set(c.get().saturating_add(1)));
    }
}

/// Committed store transactions on this thread.
#[must_use]
pub fn store_txn_commits() -> u64 {
    TXN_COMMITS.with(Cell::get)
}

/// Bytes appended to the write-ahead log by committed transactions on this thread, measured when
/// [`measure_writes`] was on at open (automatic checkpoints are then off, so the log only grows; every page of the log is
/// written to the database file at most once by a checkpoint).
#[must_use]
pub fn store_bytes_written() -> u64 {
    BYTES_WRITTEN.with(Cell::get)
}

pub(crate) fn add_bytes_written(n: u64) {
    BYTES_WRITTEN.with(|c| c.set(c.get().saturating_add(n)));
}

/// Statements run by migrations on this thread.
#[must_use]
pub fn migration_statements() -> u64 {
    MIGRATION_STATEMENTS.with(Cell::get)
}

pub(crate) fn add_migration_statements(n: u64) {
    MIGRATION_STATEMENTS.with(|c| c.set(c.get().saturating_add(n)));
}

/// Profiles opened after this call on this thread measure their log writes ([`store_bytes_written`]).
pub fn measure_writes(on: bool) {
    MEASURE_WRITES.with(|c| c.set(on));
}

pub(crate) fn measuring() -> bool {
    MEASURE_WRITES.with(Cell::get)
}

/// Reset the counters of this thread.
pub fn reset_counters() {
    TXN_COMMITS.with(|c| c.set(0));
    BYTES_WRITTEN.with(|c| c.set(0));
    MIGRATION_STATEMENTS.with(|c| c.set(0));
}

/// The environment variable that selects the role of a re-entered test binary (the Conventions' child process).
pub const CHILD_ROLE: &str = "SECMP_STORE_CHILD";

/// The role this process was started in, if it is a child.
#[must_use]
pub fn child_role() -> Option<String> {
    std::env::var(CHILD_ROLE).ok().filter(|r| !r.is_empty())
}

/// Run the test `test` of this test binary again in a child process with `CHILD_ROLE` = `role` and the extra
/// environment `env`; returns whether the child exited successfully (an aborted child returns `false`).
///
/// # Errors
/// If the child cannot be started.
pub fn run_child(test: &str, role: &str, env: &[(&str, &Path)]) -> std::io::Result<bool> {
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args([test, "--exact", "--test-threads", "1"])
        .env(CHILD_ROLE, role);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(out.success())
}

/// One finding of [`scan_dir`]: a file and what was found in it.
#[derive(Debug, PartialEq, Eq)]
pub struct ScanHit {
    /// The file (relative to the scanned directory).
    pub file: PathBuf,
    /// The index of the needle that matched.
    pub needle: usize,
    /// `true`: as raw bytes; `false`: inside a printable run (`strings`-like, ≥ 4 bytes).
    pub raw: bool,
}

/// The forensic scan of the Conventions (FO-01a): every file under `dir`, recursively; a needle is a hit when it occurs
/// as raw bytes, or when a substring of it of at least `min_sub` bytes occurs inside a printable ASCII run of at least
/// 4 bytes (the `strings` view). Returns the hits and the number of files and bytes scanned.
///
/// # Errors
/// If a file cannot be read.
pub fn scan_dir(
    dir: &Path,
    needles: &[&[u8]],
    min_sub: usize,
) -> std::io::Result<(Vec<ScanHit>, u64, u64)> {
    let mut hits = Vec::new();
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let data = std::fs::read(&path)?;
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
            let rel = path.strip_prefix(dir).unwrap_or(&path).to_path_buf();
            for (i, n) in needles.iter().enumerate() {
                if contains(&data, n) {
                    hits.push(ScanHit {
                        file: rel.clone(),
                        needle: i,
                        raw: true,
                    });
                } else if printable_runs(&data).any(|run| substring_hit(run, n, min_sub)) {
                    hits.push(ScanHit {
                        file: rel.clone(),
                        needle: i,
                        raw: false,
                    });
                }
            }
        }
    }
    Ok((hits, files, bytes))
}

/// Whether `needle` occurs in `hay`.
#[must_use]
pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// The printable ASCII runs of at least 4 bytes.
fn printable_runs(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|b| !(0x20..0x7f).contains(b))
        .filter(|r| r.len() >= 4)
}

/// Whether some substring of `needle` of `min_sub` bytes (or the whole needle if shorter) occurs in `run`.
fn substring_hit(run: &[u8], needle: &[u8], min_sub: usize) -> bool {
    let w = min_sub.min(needle.len());
    w > 0 && needle.windows(w).any(|s| contains(run, s))
}
