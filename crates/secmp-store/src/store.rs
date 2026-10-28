// SPDX-License-Identifier: AGPL-3.0-or-later
//! The profile store: one SQLCipher database per profile directory (CS-3.1, `docs/04:52`; `docs/02` §4.2).
//!
//! **Opening** (`open_connection`, the only place a connection is made): `SQLITE_DBCONFIG_DEFENSIVE` before any
//! statement (ST-20, ADR-055 item 7), the raw key, `cipher_memory_security = ON`, a read of `sqlite_master` that
//! decides the key (every failure there is the uniform [`Error::Unlock`]), the SQLCipher version check against
//! [`SQLCIPHER_MIN`], then `journal_mode = WAL`, `temp_store = MEMORY` (no temp files, `docs/02:102`) and
//! `secure_delete = ON` (CS-3.4). The profile directory holds `profile.db`, its `-wal` and `-shm`, and `lock`, which an
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
}

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
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).map_err(|_| Error::Unavailable)?;
    // ST-20 (ADR-055 item 7): before any statement
    let on = conn
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| Error::Unavailable)?;
    if !on {
        return Err(Error::Unavailable);
    }
    if let Some(k) = key {
        conn.pragma_update(None, "key", k.pragma_value().as_str())
            .map_err(|_| Error::Unlock)?;
    }
    conn.pragma_update(None, "cipher_memory_security", "ON")
        .map_err(|_| Error::Unlock)?;
    // the key is decided by the first read of the schema: SQLCipher allocates and checks only then
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|_| Error::Unlock)?;
    let version: String = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .map_err(|_| Error::Unsupported)?;
    check_cipher_version(&version)?;
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .map_err(|_| Error::Unavailable)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::Unavailable);
    }
    conn.pragma_update(None, "temp_store", 2)
        .map_err(|_| Error::Unavailable)?;
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|_| Error::Unavailable)?;
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
        lock.try_lock().map_err(|_| Error::Unavailable)?;
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
        crate::kat::transaction_ended(statements, result.is_ok());
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
        let root = TempDir::new("st03")?;
        let tmp = root.path().join("tmp");
        let profile = root.path().join("profile");
        std::fs::create_dir_all(&tmp)?;
        let ok = crate::kat::run_child(
            "store::tests::no_temp_files_anywhere",
            "st03",
            &[("TMPDIR", &tmp), ("SECMP_STORE_DIR", &profile)],
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
}
