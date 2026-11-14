// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema migrations (deliverable "migrations", `docs/07:140`). The version lives in `meta.schema_version`; a profile
//! without `meta` is version 0. Opening migrates an older profile to [`CURRENT`] in one transaction (all statements or
//! none), runs nothing for a current one, and refuses a newer one with [`Error::TooNew`] before any write.

use rusqlite::params;

use crate::error::{Error, Result};
use crate::store::Store;

/// The schema version this build writes.
pub const CURRENT: u32 = 1;

/// The statements that take a profile from version 0 to [`CURRENT`]: the schema of [`crate::schema::V1`], then the
/// version row.
#[must_use]
pub fn v0_to_current() -> Vec<&'static str> {
    let mut s: Vec<&'static str> = crate::schema::V1.to_vec();
    s.push("INSERT INTO meta (key, value) VALUES ('schema_version', ?1)");
    s
}

/// The schema version of the open profile (0 without `meta`).
///
/// # Errors
/// [`Error::Unavailable`] if it cannot be read.
pub fn schema_version(store: &Store) -> Result<u32> {
    let has_meta = store
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |r| r.get::<_, i64>(0),
        )?
        .unwrap_or(0);
    if has_meta == 0 {
        return Ok(0);
    }
    let v = store.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |r| r.get::<_, i64>(0),
    )?;
    Ok(v.and_then(|v| u32::try_from(v).ok()).unwrap_or(0))
}

/// Bring the profile to [`CURRENT`] (see the module documentation).
///
/// # Errors
/// [`Error::TooNew`] for a newer profile (nothing written); [`Error::Unavailable`] if a statement fails (rolled back).
pub fn migrate(store: &mut Store) -> Result<()> {
    let v = schema_version(store)?;
    if v > CURRENT {
        return Err(Error::TooNew);
    }
    if v == CURRENT {
        return Ok(());
    }
    let statements = v0_to_current();
    store.txn(|tx| {
        for sql in &statements {
            if sql.contains("?1") {
                tx.exec(sql, params![i64::from(CURRENT)])?;
            } else {
                tx.exec(sql, [])?;
            }
        }
        Ok(())
    })?;
    #[cfg(any(test, feature = "kat"))]
    crate::kat::add_migration_statements(u64::try_from(statements.len()).unwrap_or(u64::MAX));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{FailAt, TempDir, TestKey, fail_at, migration_statements, reset_counters};
    use crate::store::DB_FILE;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// ST-14 (deliverable "migrations"): an empty directory becomes version [`CURRENT`]; reopening runs no statement; a
    /// profile whose `meta.schema_version` is `CURRENT + 1` is refused with `TooNew` and its file is unchanged.
    #[test]
    fn fresh_reopen_and_too_new() -> R {
        let dir = TempDir::new("st14")?;
        reset_counters();
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(schema_version(&store)?, CURRENT);
        assert_eq!(
            migration_statements(),
            u64::try_from(v0_to_current().len())?
        );
        drop(store);
        reset_counters();
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(
            migration_statements(),
            0,
            "a current profile runs no migration"
        );
        store.connection_kat().execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            params![i64::from(CURRENT) + 1],
        )?;
        drop(store);
        let db = dir.path().join(DB_FILE);
        let before = secmp_crypto::sha256(&[&std::fs::read(&db)?]);
        assert_eq!(
            Store::open(dir.path(), &TestKey::db_key()).err(),
            Some(Error::TooNew)
        );
        assert_eq!(secmp_crypto::sha256(&[&std::fs::read(&db)?]), before);
        Ok(())
    }

    /// ST-15 (SQLite transaction semantics): a failure at any statement k of the v0 → current migration is
    /// `Unavailable`, the schema version is unchanged (0), and the next open migrates fully.
    #[test]
    fn migration_is_atomic() -> R {
        let n = u32::try_from(v0_to_current().len())?;
        assert!(n >= 11);
        for k in 1..=n {
            let dir = TempDir::new("st15")?;
            fail_at(FailAt(k));
            assert_eq!(
                Store::open(dir.path(), &TestKey::db_key()).err(),
                Some(Error::Unavailable),
                "statement {k}"
            );
            // nothing of the migration is there: version 0, no table at all
            let raw = Store::open_without_migration_kat(dir.path(), &TestKey::db_key())?;
            assert_eq!(schema_version(&raw)?, 0, "statement {k}: version unchanged");
            let none: i64 = raw.connection_kat().query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(none, 0, "statement {k}: no table survived the rollback");
            drop(raw);
            let store = Store::open(dir.path(), &TestKey::db_key())?;
            assert_eq!(
                schema_version(&store)?,
                CURRENT,
                "statement {k}: the reopen migrates"
            );
            let tables: i64 = store.connection_kat().query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(tables, i64::try_from(crate::schema::TABLES.len())?);
        }
        Ok(())
    }
}
