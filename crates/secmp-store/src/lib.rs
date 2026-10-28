// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-store` — the encrypted local profile store.
//!
//! **Responsibility.** One encrypted database per profile (rusqlite + SQLCipher with vendored OpenSSL, ADR-055),
//! master-key wrapping (docs/04 §3, ADR-053 — M7 Phase A step A-4), migrations, outbox tables, incremental ratchet
//! persistence (persist-before-send, persist-before-ack), secure delete, and backup export/import without ratchet state
//! (CS-3.5). Schema per docs/02 §4.2.
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-proto`, `secmp-crypto`, `secmp-sys-desktop` (OS keystores);
//! `rusqlite` with bundled SQLCipher/OpenSSL (exempt from the "only `secmp-crypto`" rule, never used for SecMP
//! constructions), added with ADR-055.
//!
//! **Status.** M7 Phase A step A-3: the store with the `kat`-only test key ([`kat::TestKey`]); no shipped constructor
//! of a [`DbKey`] exists until A-4.
#![forbid(unsafe_code)]

pub mod delete;
mod error;
pub mod messages;
pub mod migrate;
pub mod schema;
pub mod store;

#[cfg(any(test, feature = "kat"))]
pub mod kat;

pub use error::{Error, Result};
pub use store::{DbKey, SQLCIPHER_MIN, Store, Tx, check_cipher_version};

#[cfg(test)]
mod tests {
    use crate::kat::{TempDir, TestKey};
    use crate::store::Store;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// The schema as `sqlite_master` lists it.
    fn schema(store: &Store) -> rusqlite::Result<Vec<(String, String)>> {
        let mut stmt = store
            .connection_kat()
            .prepare("SELECT name, coalesce(sql, '') FROM sqlite_master ORDER BY name")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// ST-20 (Q128; ADR-055 item 7): every connection the store opens — on a new and on an existing profile — has
    /// `SQLITE_DBCONFIG_DEFENSIVE` on; with `writable_schema` asked for, a direct write to `sqlite_master` is refused and
    /// the schema is unchanged.
    #[test]
    fn open_sets_defensive_mode() -> R {
        let dir = TempDir::new("st20")?;
        for round in ["new", "existing"] {
            let store = Store::open(dir.path(), &TestKey::db_key())?;
            let conn = store.connection_kat();
            assert!(
                conn.db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?,
                "{round}"
            );
            let before = schema(&store)?;
            let _ = conn.execute_batch("PRAGMA writable_schema = ON");
            let write = conn.execute(
                "UPDATE sqlite_master SET sql = 'CREATE TABLE settings (x)' WHERE name = 'settings'",
                [],
            );
            assert!(
                write.is_err(),
                "{round}: the sqlite_master write was accepted"
            );
            let insert = conn.execute(
                "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', 'evil', 'evil', 0, 'CREATE TABLE evil (x)')",
                [],
            );
            assert!(
                insert.is_err(),
                "{round}: the sqlite_master insert was accepted"
            );
            assert_eq!(schema(&store)?, before, "{round}");
        }
        Ok(())
    }
}
