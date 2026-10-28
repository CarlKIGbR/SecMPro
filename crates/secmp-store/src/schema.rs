// SPDX-License-Identifier: AGPL-3.0-or-later
//! The schema of a profile (`docs/02` §4.2 `:90-100`): the nine tables of the data model plus `meta` (the schema version
//! and the store's own markers). Version 1 is created by [`crate::migrate`].
//!
//! `sessions` holds the ratchet state of a session incrementally (CS-3.7, `docs/02:102`; OPEN-M7-14 A): one row per
//! part, keyed `(session_id, part, ord)` — part 0 the fixed part of `RatchetStateV1` (one row, rewritten per slot), part 1
//! one row per skipped entry (`hk ‖ n ‖ mk`, `ord` = insertion order), part 2 the reassembly state (`Inbox`), part 3 the
//! trust. Secret columns are sealed record by record in A-4 (ADR-053 item 5); in A-3 they lie inside the SQLCipher file
//! only.

/// The tables of a profile, in creation order.
pub const TABLES: [&str; 10] = [
    "identity",
    "prekeys",
    "relays",
    "contacts",
    "sessions",
    "outbox",
    "messages",
    "invitations",
    "settings",
    "meta",
];

/// The `sessions` parts.
pub mod part {
    /// The fixed part of `RatchetStateV1` (everything before the skipped entries).
    pub const FIXED: i64 = 0;
    /// One skipped entry.
    pub const SKIPPED: i64 = 1;
    /// The reassembly state.
    pub const INBOX: i64 = 2;
    /// The trust.
    pub const TRUST: i64 = 3;
}

/// The statements of schema version 1.
pub const V1: &[&str] = &[
    "CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL)",
    "CREATE TABLE identity (id INTEGER PRIMARY KEY, secret BLOB NOT NULL, fingerprint BLOB NOT NULL, created_ms INTEGER NOT NULL)",
    "CREATE TABLE prekeys (kind INTEGER NOT NULL, id INTEGER NOT NULL, secret BLOB NOT NULL, expires_ms INTEGER, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (kind, id))",
    "CREATE TABLE relays (id INTEGER PRIMARY KEY, relay_ref BLOB NOT NULL, access_key BLOB)",
    "CREATE TABLE contacts (id INTEGER PRIMARY KEY, iks BLOB NOT NULL, fingerprint BLOB NOT NULL, display_name TEXT, verified INTEGER NOT NULL DEFAULT 0, routes BLOB, queues BLOB, state INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE sessions (session_id INTEGER NOT NULL, part INTEGER NOT NULL, ord INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (session_id, part, ord))",
    "CREATE TABLE outbox (msg_id BLOB PRIMARY KEY NOT NULL, contact_id INTEGER NOT NULL, seq INTEGER NOT NULL, kind INTEGER NOT NULL, expire_after INTEGER NOT NULL, payload BLOB NOT NULL, queued_ms INTEGER NOT NULL, first_relayed_ms INTEGER, state INTEGER NOT NULL, cell_id INTEGER)",
    "CREATE TABLE messages (id INTEGER PRIMARY KEY, contact_id INTEGER NOT NULL, msg_id BLOB NOT NULL, direction INTEGER NOT NULL, kind INTEGER NOT NULL, ts_ms INTEGER NOT NULL, expire_at_ms INTEGER, payload BLOB NOT NULL, UNIQUE (contact_id, direction, msg_id))",
    "CREATE TABLE invitations (ld_id BLOB PRIMARY KEY NOT NULL, record BLOB NOT NULL, expires_ms INTEGER NOT NULL, status INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL)",
];

#[cfg(test)]
mod tests {
    use crate::kat::{TempDir, TestKey};
    use crate::store::Store;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// ST-13 (`docs/02:90-100`): the tables of a new profile are exactly the nine of the data model and `meta`; the
    /// skipped-key rows live in `sessions` (part discriminator in the key), so there is no tenth table for them.
    #[test]
    fn tables_match_docs_02() -> R {
        let dir = TempDir::new("st13")?;
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        let mut stmt = store
            .connection_kat()
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
        let mut names: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        names.retain(|n| !n.starts_with("sqlite_"));
        let mut want: Vec<String> = super::TABLES.iter().map(|t| (*t).to_owned()).collect();
        want.sort();
        assert_eq!(names, want);
        let sessions_sql: String = store.connection_kat().query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'sessions'",
            [],
            |r| r.get(0),
        )?;
        assert!(sessions_sql.contains("PRIMARY KEY (session_id, part, ord)"));
        Ok(())
    }
}
