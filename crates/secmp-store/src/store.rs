// SPDX-License-Identifier: AGPL-3.0-or-later
//! The profile store: one SQLCipher database per profile directory (CS-3.1, `docs/04:52`; `docs/02` §4.2).
//!
//! **Opening** (`open_connection`, the only place a connection is made): `SQLITE_DBCONFIG_DEFENSIVE` before any
//! statement (ST-20, ADR-055 item 7), `cipher_memory_security = ON` before the key is given, the raw key (one statement
//! from a zeroizing buffer, [`DbKey::key_statement`]), a read of `sqlite_master` that
//! decides the key (every failure there is the uniform [`Error::Unlock`]), the SQLCipher version check against
//! [`SQLCIPHER_MIN`], then `journal_mode = WAL`, `temp_store = MEMORY` (no temp files, `docs/02:102`) and
//! `secure_delete = ON` (CS-3.4) and `synchronous = FULL` (Q-A14). The profile directory holds `profile.db`, its `-wal` and `-shm`, and `lock`, which an
//! open store holds locked (one writer per profile).
//!
//! **Transactions.** Every write goes through [`Store::txn`]: one `BEGIN IMMEDIATE … COMMIT`, every statement through
//! [`Tx`]; an error anywhere rolls the whole transaction back and is [`Error::Unavailable`] (nothing changed).
//!
//! **Keys.** A [`DbKey`] is the SQLCipher raw key. In M7 Phase A step A-3 it can be obtained only from the test key of
//! the `kat` module; the key hierarchy of ADR-053 (passphrase wrap, derived database key) is A-4.

use std::fs::File;
use std::path::{Path, PathBuf};

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, Params, Row};
use secmp_crypto::Zeroizing;

use crate::error::{Error, Result};

/// The file name of the database inside a profile directory.
pub const DB_FILE: &str = "profile.db";
/// The lock file of a profile directory (held while a store is open).
pub const LOCK_FILE: &str = "lock";

/// The oldest bundled SQLCipher this store accepts (CS-3.1 "refuses older-than-pinned"; ADR-055 item 4, Q119): the
/// version `libsqlite3-sys` 0.37.0 bundles, the one the graph can hold beside Arti (`links = "sqlite3"`).
pub const SQLCIPHER_MIN: (u32, u32, u32) = (4, 10, 0);

/// The SQLCipher raw key of a profile, zeroized on drop. No `Clone`, `Debug` or `PartialEq`.
pub struct DbKey(Zeroizing<[u8; 32]>);

impl DbKey {
    /// A key from its bytes: test-only in A-3 (the shipped constructor is ADR-053's derivation, A-4).
    #[cfg(any(test, feature = "kat"))]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// `x'<64 hex digits>'`, the raw-key form of `PRAGMA key`, in a zeroizing buffer.
    fn pragma_value(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(67));
        s.push_str("x'");
        for b in self.0.iter() {
            s.push(hex_digit(b >> 4));
            s.push(hex_digit(b & 0x0f));
        }
        s.push('\'');
        s
    }

    /// `PRAGMA key = "x'<64 hex digits>'"` (82 bytes), built in one zeroizing buffer of exactly that capacity, so no
    /// reallocation leaves a copy of the key behind.
    pub(crate) fn key_statement(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(82));
        s.push_str("PRAGMA key = \"");
        s.push_str(&self.pragma_value());
        s.push('"');
        s
    }
}

/// One step of `open_connection` in the `kat` step log ([`crate::kat::open_steps`]; a static tag, never SQL or a key).
#[cfg(any(test, feature = "kat"))]
fn step(tag: &'static str) {
    crate::kat::note_open_step(tag);
}

#[cfg(not(any(test, feature = "kat")))]
const fn step(_tag: &'static str) {}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0'.wrapping_add(n)),
        _ => char::from(b'a'.wrapping_add(n.wrapping_sub(10))),
    }
}

/// Accept a `PRAGMA cipher_version` value if its leading `MAJOR.MINOR.PATCH` is at least [`SQLCIPHER_MIN`] (the pragma
/// of the bundled build reads `4.10.0 community`).
///
/// # Errors
/// [`Error::Unsupported`] for an older or unreadable version.
pub fn check_cipher_version(version: &str) -> Result<()> {
    let lead = version.split_whitespace().next().unwrap_or_default();
    let mut parts = lead.split('.').map(str::parse::<u32>);
    let (Some(Ok(a)), Some(Ok(b)), Some(Ok(c)), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Unsupported);
    };
    if (a, b, c) >= SQLCIPHER_MIN {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}

/// An open profile (see the module documentation).
pub struct Store {
    pub(crate) conn: Connection,
    dir: PathBuf,
    _lock: File,
    /// View-once messages, in memory only (CS-3.4, ST-17).
    pub(crate) view_once: crate::messages::ViewOnceHolder,
    /// The size of the write-ahead log after the last commit (`kat::measure_writes`).
    #[cfg(any(test, feature = "kat"))]
    wal_size: Option<u64>,
}

/// Open (or create) the database at `path` with `key` (`None`: no key — the `kat` test of ST-04 only) and apply the
/// settings of the module documentation.
fn open_connection(path: &Path, key: Option<&DbKey>) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        .union(OpenFlags::SQLITE_OPEN_CREATE)
        .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
    #[cfg(any(test, feature = "kat"))]
    crate::kat::clear_open_steps();
    let conn = Connection::open_with_flags(path, flags).map_err(|_| Error::Unavailable)?;
    // ST-20 (ADR-055 item 7): before any statement
    let on = conn
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| Error::Unavailable)?;
    if !on {
        return Err(Error::Unavailable);
    }
    step("defensive");
    // V1-F3: SQLCipher's memory security is on before the key reaches it
    conn.execute_batch("PRAGMA cipher_memory_security = ON")
        .map_err(|_| Error::Unlock)?;
    step("cipher_memory_security");
    if let Some(k) = key {
        conn.execute_batch(&k.key_statement())
            .map_err(|_| Error::Unlock)?;
        step("key");
    }
    // the key is decided by the first read of the schema: SQLCipher allocates and checks only then
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|_| Error::Unlock)?;
    step("check_key");
    let version: String = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .map_err(|_| Error::Unsupported)?;
    check_cipher_version(&version)?;
    step("cipher_version");
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .map_err(|_| Error::Unavailable)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::Unavailable);
    }
    step("journal_mode");
    conn.pragma_update(None, "temp_store", 2)
        .map_err(|_| Error::Unavailable)?;
    step("temp_store");
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|_| Error::Unavailable)?;
    step("secure_delete");
    // V1-F13 (Q-A14): every commit is on disk before it returns (persist-before-send/ack)
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|_| Error::Unavailable)?;
    step("synchronous");
    #[cfg(any(test, feature = "kat"))]
    if crate::kat::measuring() {
        conn.pragma_update(None, "wal_autocheckpoint", 0)
            .map_err(|_| Error::Unavailable)?;
    }
    Ok(conn)
}

impl Store {
    /// Open the profile in `dir` (created, with its schema, if the directory holds none) with `key`.
    ///
    /// # Errors
    /// [`Error::Unlock`] for a wrong key or a file that is no profile; [`Error::Unsupported`] for an older SQLCipher;
    /// [`Error::TooNew`] for a newer schema (the file is not touched); [`Error::Unavailable`] if the directory cannot be
    /// used, another store holds it, or a migration statement failed (nothing changed).
    pub fn open(dir: &Path, key: &DbKey) -> Result<Self> {
        Self::open_with(dir, Some(key))
    }

    /// [`Store::open`] without a key (ST-04: a keyed profile must not open).
    ///
    /// # Errors
    /// As [`Store::open`].
    #[cfg(any(test, feature = "kat"))]
    pub fn open_unkeyed_kat(dir: &Path) -> Result<Self> {
        Self::open_with(dir, None)
    }

    /// [`Store::open`] without running the migration (ST-15 reads the version a failed migration left).
    ///
    /// # Errors
    /// As [`Store::open`], without `TooNew`.
    #[cfg(any(test, feature = "kat"))]
    pub fn open_without_migration_kat(dir: &Path, key: &DbKey) -> Result<Self> {
        Self::open_inner(dir, Some(key), false)
    }

    fn open_with(dir: &Path, key: Option<&DbKey>) -> Result<Self> {
        Self::open_inner(dir, key, true)
    }

    fn open_inner(dir: &Path, key: Option<&DbKey>, migrate: bool) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|_| Error::Unavailable)?;
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(LOCK_FILE))
            .map_err(|_| Error::Unavailable)?;
        {
            // `kat`: no child of a test is between `fork` and `exec` holding a copy of a released lock
            #[cfg(any(test, feature = "kat"))]
            let _spawning = crate::kat::spawn_guard();
            lock.try_lock().map_err(|_| Error::Unavailable)?;
        }
        let conn = open_connection(&dir.join(DB_FILE), key)?;
        let mut store = Self {
            conn,
            dir: dir.to_path_buf(),
            _lock: lock,
            view_once: crate::messages::ViewOnceHolder::default(),
            #[cfg(any(test, feature = "kat"))]
            wal_size: None,
        };
        if migrate {
            crate::migrate::migrate(&mut store)?;
        }
        #[cfg(any(test, feature = "kat"))]
        {
            store.wal_size = store.measured_wal_size();
        }
        Ok(store)
    }

    /// The profile directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Run `f` in one transaction (`BEGIN IMMEDIATE`); commit if it returns `Ok`, roll back otherwise.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a statement or the commit fails (the transaction is rolled back), or `f`'s error.
    pub fn txn<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let (result, statements) = {
            let tx = self
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| Error::Unavailable)?;
            let mut t = Tx { tx, statements: 0 };
            let out = f(&mut t);
            let Tx { tx, statements } = t;
            // `kat::CrashAt::MidTxn(k)` after the last statement: before the commit point
            #[cfg(any(test, feature = "kat"))]
            if out.is_ok() && statements > 0 {
                crate::kat::crash_point(crate::kat::CrashAt::MidTxn(statements));
            }
            let result = match out {
                Ok(v) => tx.commit().map(|()| v).map_err(|_| Error::Unavailable),
                Err(e) => {
                    let _ = tx.rollback();
                    Err(e)
                }
            };
            (result, statements)
        };
        #[cfg(any(test, feature = "kat"))]
        crate::kat::transaction_ended(result.is_ok());
        let _ = statements;
        #[cfg(any(test, feature = "kat"))]
        if result.is_ok() {
            self.note_commit();
        }
        result
    }

    /// One statement outside a transaction is never needed: every write is a [`Store::txn`]. Reads use this.
    pub(crate) fn query_row<T, P: Params>(
        &self,
        sql: &str,
        params: P,
        f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>> {
        match self.conn.query_row(sql, params, f) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(_) => Err(Error::Unavailable),
        }
    }

    /// The size of the write-ahead log when writes are measured (`kat::measure_writes`).
    #[cfg(any(test, feature = "kat"))]
    fn measured_wal_size(&self) -> Option<u64> {
        crate::kat::measuring().then(|| {
            let wal = self.dir.join(format!("{DB_FILE}-wal"));
            std::fs::metadata(wal).map_or(0, |m| m.len())
        })
    }

    /// Add the log bytes of the last commit to `kat::store_bytes_written`.
    #[cfg(any(test, feature = "kat"))]
    fn note_commit(&mut self) {
        if let (Some(before), Some(after)) = (self.wal_size, self.measured_wal_size()) {
            crate::kat::add_bytes_written(after.saturating_sub(before));
            self.wal_size = Some(after);
        }
    }

    /// The connection (the tests read pragmas and raw pages through it).
    #[cfg(any(test, feature = "kat"))]
    #[must_use]
    pub const fn connection_kat(&self) -> &Connection {
        &self.conn
    }
}

/// A transaction of [`Store::txn`]: every statement is counted (failure and crash injection, `kat`).
pub struct Tx<'a> {
    tx: rusqlite::Transaction<'a>,
    statements: u32,
}

impl Tx<'_> {
    /// Count the next statement; `true` if the failure injection makes it fail (`kat`; never otherwise).
    fn next_statement_fails(&mut self) -> bool {
        self.statements = self.statements.saturating_add(1);
        #[cfg(any(test, feature = "kat"))]
        return crate::kat::statement_fails(self.statements);
        #[cfg(not(any(test, feature = "kat")))]
        false
    }

    /// Execute one statement.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if it fails.
    pub fn exec<P: Params>(&mut self, sql: &str, params: P) -> Result<usize> {
        if self.next_statement_fails() {
            return Err(Error::Unavailable);
        }
        self.tx.execute(sql, params).map_err(|_| Error::Unavailable)
    }

    /// Read one row (`None` without one).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the query fails.
    pub fn query_row<T, P: Params>(
        &mut self,
        sql: &str,
        params: P,
        f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>> {
        if self.next_statement_fails() {
            return Err(Error::Unavailable);
        }
        match self.tx.query_row(sql, params, f) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(_) => Err(Error::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{TempDir, TestKey};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    fn pragma(store: &Store, name: &str) -> core::result::Result<String, rusqlite::Error> {
        store
            .connection_kat()
            .query_row(&format!("PRAGMA {name}"), [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .map(|v| match v {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
    }

    /// ST-01 (CS-3.1, `docs/02:102`): a new profile, one `SELECT 1`, then each pragma read back.
    #[test]
    fn create_sets_pragmas() -> R {
        let dir = TempDir::new("st01")?;
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        let one: i64 = store
            .connection_kat()
            .query_row("SELECT 1", [], |r| r.get(0))?;
        assert_eq!(one, 1);
        assert_eq!(pragma(&store, "cipher_memory_security")?, "1");
        assert_eq!(pragma(&store, "temp_store")?, "2");
        assert_eq!(pragma(&store, "journal_mode")?, "wal");
        assert_eq!(pragma(&store, "secure_delete")?, "1");
        assert_eq!(pragma(&store, "synchronous")?, "2");
        Ok(())
    }

    /// ST-02 (CS-3.1, ADR-055 item 4, Q119): below the pin refused, the pin and above accepted; the pin is 4.10.0 and
    /// the bundled SQLCipher reports it (`4.10.0 community`).
    #[test]
    fn refuses_older_cipher_version() -> R {
        assert_eq!(check_cipher_version("4.9.4"), Err(Error::Unsupported));
        assert_eq!(check_cipher_version("4.10.0"), Ok(()));
        assert_eq!(check_cipher_version("4.10.1"), Ok(()));
        assert_eq!(check_cipher_version("4.10.0 community"), Ok(()));
        assert_eq!(check_cipher_version("3.99.99"), Err(Error::Unsupported));
        assert_eq!(check_cipher_version("4.10"), Err(Error::Unsupported));
        assert_eq!(check_cipher_version(""), Err(Error::Unsupported));
        assert_eq!(SQLCIPHER_MIN, (4, 10, 0));
        let dir = TempDir::new("st02")?;
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        let v = pragma(&store, "cipher_version")?;
        assert_eq!(v.split_whitespace().next(), Some("4.10.0"), "{v}");
        Ok(())
    }

    /// The child of ST-03: the work, with `TMPDIR` pointing at an empty directory (set by the parent on the child's
    /// environment; edition 2024 makes `set_var` unsafe).
    fn no_temp_files_child(dir: &Path) -> R {
        let mut store = Store::open(dir, &TestKey::db_key())?;
        store.txn(|tx| {
            for i in 0..2000_i64 {
                tx.exec(
                    "INSERT INTO messages (contact_id, msg_id, direction, kind, ts_ms, expire_at_ms, payload) \
                     VALUES (1, ?1, 0, 1, ?1, NULL, ?2)",
                    rusqlite::params![i, vec![0x61_u8; 64]],
                )?;
            }
            Ok(())
        })?;
        let sorted: i64 = store.connection_kat().query_row(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10000) \
             SELECT count(*) FROM (SELECT x FROM c ORDER BY (x * 7919) % 10007)",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(sorted, 10000);
        store.connection_kat().execute_batch("VACUUM")?;
        spill(&store)?;
        Ok(())
    }

    /// A temporary table of 20 000 rows of 512 random bytes in one transaction (≈ 10 MB, beyond the page cache); on Linux,
    /// the descriptors of the process that point into `TMPDIR` while the table exists: 0 (`temp_store = MEMORY`).
    fn spill(store: &Store) -> R {
        let conn = store.connection_kat();
        conn.execute_batch(
            "CREATE TEMP TABLE spill(x BLOB); \
             WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 20000) \
             INSERT INTO spill SELECT randomblob(512) FROM c",
        )?;
        #[cfg(target_os = "linux")]
        {
            let tmp = std::fs::canonicalize(std::env::var_os("TMPDIR").ok_or("no TMPDIR")?)?;
            assert_eq!(
                fds_into(&tmp)?,
                0,
                "a descriptor into TMPDIR while the temp table exists"
            );
        }
        conn.execute_batch("DROP TABLE spill")?;
        Ok(())
    }

    /// The descriptors of this process whose target lies under `dir` (an unlinked file shows as `… (deleted)`).
    #[cfg(target_os = "linux")]
    fn fds_into(dir: &Path) -> std::io::Result<usize> {
        let mut n = 0_usize;
        for entry in std::fs::read_dir("/proc/self/fd")? {
            let Ok(entry) = entry else { continue };
            if std::fs::read_link(entry.path()).is_ok_and(|t| t.starts_with(dir)) {
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// The control child of ST-03 (Linux): the same temporary table after `PRAGMA temp_store = FILE` opens a temp file
    /// in `TMPDIR` (SQLite unlinks it at once; the descriptor stays).
    #[cfg(target_os = "linux")]
    fn temp_file_control_child(dir: &Path) -> R {
        let store = Store::open(dir, &TestKey::db_key())?;
        let conn = store.connection_kat();
        conn.execute_batch(
            "PRAGMA temp_store = FILE; CREATE TEMP TABLE spill(x BLOB); \
             WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 20000) \
             INSERT INTO spill SELECT randomblob(512) FROM c",
        )?;
        let tmp = std::fs::canonicalize(std::env::var_os("TMPDIR").ok_or("no TMPDIR")?)?;
        let open = fds_into(&tmp)?;
        std::fs::write(dir.join("control-fds"), open.to_string())?;
        assert!(open >= 1, "control: no temp file descriptor in TMPDIR");
        Ok(())
    }

    /// ST-03 (`docs/02:102`, temp files forbidden): in a child process with `TMPDIR` an empty directory, 2 000 inserts,
    /// an `ORDER BY` over 10 000 rows and a `VACUUM` leave `TMPDIR` empty; the profile directory holds exactly
    /// `profile.db`, `profile.db-wal`, `profile.db-shm`, `lock`.
    #[test]
    fn no_temp_files_anywhere() -> R {
        if crate::kat::child_role().as_deref() == Some("st03") {
            let dir = std::env::var_os("SECMP_STORE_DIR").ok_or("no dir")?;
            return no_temp_files_child(Path::new(&dir));
        }
        #[cfg(target_os = "linux")]
        if crate::kat::child_role().as_deref() == Some("st03-control") {
            let dir = std::env::var_os("SECMP_STORE_DIR").ok_or("no dir")?;
            return temp_file_control_child(Path::new(&dir));
        }
        let root = TempDir::new("st03")?;
        let tmp = root.path().join("tmp");
        let profile = root.path().join("profile");
        std::fs::create_dir_all(&tmp)?;
        let ok = crate::kat::run_child(
            "store::tests::no_temp_files_anywhere",
            "st03",
            &[
                ("TMPDIR", &tmp),
                ("TMP", &tmp),
                ("TEMP", &tmp),
                ("SECMP_STORE_DIR", &profile),
            ],
        )?;
        assert!(ok, "the child failed");
        assert_eq!(std::fs::read_dir(&tmp)?.count(), 0, "TMPDIR is not empty");
        // the child did the work (its rows are there); the store is closed: reopen it so that the -wal and -shm files
        // exist as during use
        assert!(profile.join(DB_FILE).exists(), "the child ran");
        let store = Store::open(&profile, &TestKey::db_key())?;
        let n: i64 =
            store
                .connection_kat()
                .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        assert_eq!(n, 2000);
        let mut names: Vec<String> = std::fs::read_dir(&profile)?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["lock", "profile.db", "profile.db-shm", "profile.db-wal"]
        );
        assert_eq!(std::fs::read_dir(&tmp)?.count(), 0);
        drop(store);
        // the control (Q-A16): with `temp_store = FILE` the same table does open a file in TMPDIR
        #[cfg(target_os = "linux")]
        {
            let control_tmp = root.path().join("tmp-control");
            let control = root.path().join("profile-control");
            std::fs::create_dir_all(&control_tmp)?;
            std::fs::create_dir_all(&control)?;
            let ok = crate::kat::run_child(
                "store::tests::no_temp_files_anywhere",
                "st03-control",
                &[
                    ("TMPDIR", &control_tmp),
                    ("TMP", &control_tmp),
                    ("TEMP", &control_tmp),
                    ("SECMP_STORE_DIR", &control),
                ],
            )?;
            let fds = std::fs::read_to_string(control.join("control-fds")).unwrap_or_default();
            assert!(
                ok,
                "the control child failed (descriptors into TMPDIR: {fds:?})"
            );
        }
        Ok(())
    }

    /// ST-04 (CS-3.1): the profile does not open without a key or with a key one bit off, both the uniform `Unlock`,
    /// and the file's SHA-256 is unchanged.
    #[test]
    fn wrong_key_cannot_open() -> R {
        let dir = TempDir::new("st04")?;
        drop(Store::open(dir.path(), &TestKey::db_key())?);
        let db = dir.path().join(DB_FILE);
        let before = secmp_crypto::sha256(&[&std::fs::read(&db)?]);
        assert_eq!(
            Store::open_unkeyed_kat(dir.path()).err(),
            Some(Error::Unlock)
        );
        assert_eq!(
            Store::open(dir.path(), &TestKey::one_bit_off()).err(),
            Some(Error::Unlock)
        );
        assert_eq!(secmp_crypto::sha256(&[&std::fs::read(&db)?]), before);
        assert!(Store::open(dir.path(), &TestKey::db_key()).is_ok());
        Ok(())
    }
    /// V1-F3 (CLAUDE.md §1.6): `cipher_memory_security` is on before the key is given, the key is one statement in an
    /// 82-byte zeroizing buffer (`PRAGMA key = "x'<64 hex>'"`), and the open runs its steps in the documented order;
    /// without a key the same steps without `key`. The step log holds static tags only.
    #[test]
    fn key_pragma_order_and_zeroizing() -> R {
        let dir = TempDir::new("open-steps")?;
        let all = [
            "defensive",
            "cipher_memory_security",
            "key",
            "check_key",
            "cipher_version",
            "journal_mode",
            "temp_store",
            "secure_delete",
            "synchronous",
        ];
        drop(Store::open(dir.path(), &TestKey::db_key())?);
        assert_eq!(crate::kat::open_steps(), all);
        let plain = TempDir::new("open-steps-plain")?;
        drop(Store::open_unkeyed_kat(plain.path())?);
        let unkeyed: Vec<&str> = all.iter().copied().filter(|s| *s != "key").collect();
        assert_eq!(crate::kat::open_steps(), unkeyed);
        let s: Zeroizing<String> = TestKey::db_key().key_statement();
        assert_eq!(s.len(), 82);
        assert!(s.starts_with("PRAGMA key = \"x'") && s.ends_with("'\""));
        assert_eq!(s.capacity(), 82, "built in place, no reallocation");
        Ok(())
    }

    /// G7-13 extra test: `PRAGMA key` gets the raw key as `x'<64 lowercase hex>'`, high nibble first, every digit
    /// value; the one-bit-off key of ST-04 differs from the test key in exactly one bit.
    #[test]
    fn raw_key_pragma_value() -> R {
        let mut bytes = [0_u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i.wrapping_mul(0x11).wrapping_add(0x0f) & 0xff)?;
        }
        let want = bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(
            *DbKey::from_bytes(bytes).pragma_value(),
            format!("x'{want}'")
        );
        assert_eq!(
            *DbKey::from_bytes([0xa5; 32]).pragma_value(),
            format!("x'{}'", "a5".repeat(32))
        );
        let (a, b) = (TestKey::db_key(), TestKey::one_bit_off());
        let bits: u32 =
            a.0.iter()
                .zip(b.0.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum();
        assert_eq!(bits, 1);
        Ok(())
    }

    /// A row of `t` in `store`.
    fn count(store: &Store) -> rusqlite::Result<i64> {
        store.connection_kat().query_row(
            "SELECT count(*) FROM settings WHERE key LIKE 'crash-%'",
            [],
            |r| r.get(0),
        )
    }

    /// One write of the crash test (`key` = `crash-<n>`).
    fn put(tx: &mut Tx<'_>, n: u32) -> Result<()> {
        tx.exec(
            "INSERT INTO settings (key, value) VALUES (?1, x'00')",
            rusqlite::params![format!("crash-{n}")],
        )?;
        Ok(())
    }

    /// The child of [`crash_points_fire_where_armed`]: the scenario `role`, then a mark file (reached only without an
    /// abort).
    fn crash_child(role: &str, dir: &Path) -> R {
        use crate::kat::{CrashAt, arm_crash};
        let mut store = Store::open(dir, &TestKey::db_key())?;
        match role {
            // MidTxn(0) is no point: an empty transaction and a one-statement one run to the end
            "mid0" => {
                arm_crash(CrashAt::MidTxn(0), 1);
                store.txn(|_| Ok(()))?;
                store.txn(|tx| put(tx, 1))?;
            }
            // after the first of two statements
            "midfirst" => {
                arm_crash(CrashAt::MidTxn(1), 1);
                store.txn(|tx| {
                    put(tx, 1)?;
                    put(tx, 2)
                })?;
            }
            // after the last statement: before the commit point
            "midlast" => {
                arm_crash(CrashAt::MidTxn(1), 1);
                store.txn(|tx| put(tx, 1))?;
            }
            // a transaction that fails after its statement does not reach the commit point (no crash there)
            "midfail" => {
                arm_crash(CrashAt::MidTxn(1), 1);
                let failed: Result<()> = store.txn(|tx| {
                    put(tx, 1)?;
                    Err(Error::Unavailable)
                });
                assert_eq!(failed, Err(Error::Unavailable));
            }
            // the second occurrence: the first transaction commits
            "nth2" => {
                arm_crash(CrashAt::MidTxn(1), 2);
                store.txn(|tx| put(tx, 1))?;
                store.txn(|tx| put(tx, 2))?;
            }
            // another point armed: none of the store's fires
            _ => {
                arm_crash(CrashAt::AfterCommitBeforeAck, 1);
                store.txn(|tx| put(tx, 1))?;
                crate::kat::crash_point(CrashAt::AfterCommitBeforeWrite);
            }
        }
        std::fs::write(dir.join("mark"), b"ran to the end")?;
        Ok(())
    }

    /// G7-13 extra test (the `kat` crash points of the Conventions; PC-09's `MidTxn(k)` after the last statement): in a
    /// child, `MidTxn(k)` aborts after statement k — also after the last one, before the commit point — at its armed
    /// occurrence; `MidTxn(0)`, a failed transaction and another point never abort. After reopen exactly the committed
    /// rows are there.
    #[test]
    fn crash_points_fire_where_armed() -> R {
        if let Some(role) = crate::kat::child_role() {
            let dir = std::env::var_os("SECMP_STORE_DIR").ok_or("no dir")?;
            return crash_child(&role, Path::new(&dir));
        }
        for (role, aborts, rows) in [
            ("mid0", false, 1),
            ("midfirst", true, 0),
            ("midlast", true, 0),
            ("midfail", false, 0),
            ("nth2", true, 1),
            ("other", false, 1),
        ] {
            let root = TempDir::new("crash")?;
            let ok = crate::kat::run_child(
                "store::tests::crash_points_fire_where_armed",
                role,
                &[("SECMP_STORE_DIR", root.path())],
            )?;
            assert_eq!(!ok, aborts, "{role}: aborted");
            assert_eq!(
                root.path().join("mark").exists(),
                !aborts,
                "{role}: ran to the end"
            );
            let store = Store::open(root.path(), &TestKey::db_key())?;
            assert_eq!(count(&store)?, rows, "{role}: rows after reopen");
        }
        Ok(())
    }

    /// G7-13 extra test (PC-13's counters): with `measure_writes` on at open, each committed transaction adds the log
    /// bytes it appended — at least one page frame — and counts one commit; a failed one adds neither; with it off at
    /// open nothing is measured.
    #[test]
    fn write_measurement_counts_committed_log_bytes() -> R {
        use crate::kat::{measure_writes, reset_counters, store_bytes_written, store_txn_commits};
        let dir = TempDir::new("measure")?;
        measure_writes(true);
        reset_counters();
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let (b0, c0) = (store_bytes_written(), store_txn_commits());
        store.txn(|tx| put(tx, 1))?;
        let (b1, c1) = (store_bytes_written(), store_txn_commits());
        assert_eq!(c1.saturating_sub(c0), 1);
        assert!(b1.saturating_sub(b0) >= 4_096 + 24, "{b0} → {b1}");
        let _ = store.txn(|tx| {
            put(tx, 2)?;
            Err::<(), _>(Error::Unavailable)
        });
        assert_eq!((store_bytes_written(), store_txn_commits()), (b1, c1));
        store.txn(|tx| put(tx, 3))?;
        let b3 = store_bytes_written();
        assert!(b3.saturating_sub(b1) >= 4_096 + 24);
        let wal = std::fs::metadata(dir.path().join("profile.db-wal"))?.len();
        assert!(
            b3 <= wal,
            "the measured bytes are in the log ({b3} of {wal})"
        );
        drop(store);
        measure_writes(false);
        reset_counters();
        let other = TempDir::new("measure-off")?;
        let mut store = Store::open(other.path(), &TestKey::db_key())?;
        let c = store_txn_commits();
        store.txn(|tx| put(tx, 1))?;
        assert_eq!(store_bytes_written(), 0, "not measured");
        assert_eq!(
            store_txn_commits().saturating_sub(c),
            1,
            "commits are always counted"
        );
        Ok(())
    }

    /// G7-13 extra test: `Tx::query_row` returns the row, `None` without one, and an error for a bad statement.
    #[test]
    fn tx_query_row_reads_inside_the_transaction() -> R {
        let dir = TempDir::new("query")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let (got, none, bad) = store.txn(|tx| {
            put(tx, 5)?;
            let got = tx.query_row("SELECT key FROM settings WHERE key = 'crash-5'", [], |r| {
                r.get::<_, String>(0)
            })?;
            let none = tx.query_row("SELECT key FROM settings WHERE key = 'nope'", [], |r| {
                r.get::<_, String>(0)
            })?;
            let bad = tx.query_row("SELECT nope FROM nowhere", [], |r| r.get::<_, String>(0));
            Ok((got, none, bad))
        })?;
        assert_eq!(got.as_deref(), Some("crash-5"));
        assert_eq!(none, None);
        assert_eq!(bad, Err(Error::Unavailable));
        Ok(())
    }
}
