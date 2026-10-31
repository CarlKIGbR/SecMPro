// SPDX-License-Identifier: AGPL-3.0-or-later
//! The schema of a profile (`docs/02` §4.2 `:90-100`): the nine tables of the data model plus `meta` (the schema version
//! and the store's own markers). Version 1 is created by [`crate::migrate`].
//!
//! `sessions` holds the ratchet state of a session incrementally (CS-3.7, `docs/02:102`; OPEN-M7-14 A): one row per
//! part, keyed `(session_id, part, ord)` — part 0 the fixed part of `RatchetStateV1` (one row, rewritten per slot), part 1
//! one row per skipped entry (`hk ‖ n ‖ mk`, `ord` = insertion order), part 2 the reassembly state (`Inbox`), part 3 the
//! trust; `skey` holds the key `hk ‖ n` of a skipped entry apart, so that listing the keys opens no message key.
//!
//! The secret columns (Q139: `identity.secret`, `prekeys.secret`, `sessions.data`, `sessions.skey`, `outbox.payload`,
//! `invitations.record`, `relays.access_key`) are sealed record by record ([`crate::seal`], ADR-053 item 5) inside the
//! SQLCipher file; `messages` lies inside the SQLCipher file only.

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
    "CREATE TABLE contacts (id INTEGER PRIMARY KEY, iks BLOB NOT NULL, fingerprint BLOB NOT NULL, display_name TEXT, verified INTEGER NOT NULL DEFAULT 0, routes BLOB, queues BLOB, state INTEGER NOT NULL DEFAULT 0, profile BLOB)",
    "CREATE TABLE sessions (session_id INTEGER NOT NULL, part INTEGER NOT NULL, ord INTEGER NOT NULL, data BLOB NOT NULL, skey BLOB, PRIMARY KEY (session_id, part, ord))",
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

    /// A plaintext of `n` bytes that names its column (a canary: printable, unique per site).
    fn canary(site: &str, n: usize) -> Vec<u8> {
        site.bytes()
            .chain(b"-canary-".iter().copied())
            .cycle()
            .take(n)
            .collect()
    }

    /// One secret column of one row: (table, column, `WHERE` clause, plaintext).
    type Site = (&'static str, &'static str, String, Vec<u8>);

    /// A populated profile (identity, three prekey generations, two contacts, two sessions, the outbox, one invitation,
    /// a relay access key); the secret columns written, with their plaintexts.
    fn populate(store: &mut Store) -> core::result::Result<Vec<Site>, Box<dyn std::error::Error>> {
        use crate::contacts::{Contact, put_contact};
        use crate::outbox::{OutboxRow, state};
        use crate::profile::{insert_invitation, insert_prekey, put_identity, put_relay};
        use crate::sessions::{insert_skipped, put_fixed, put_inbox, put_trust};

        let mut want: Vec<Site> = Vec::new();
        store.txn(|tx| {
            let identity = canary("identity.secret", 97);
            put_identity(tx, 1, &identity, b"own fingerprint", 1)?;
            want.push(("identity", "secret", "id = 1".into(), identity));
            for (kind, id) in (1..=3_i64).flat_map(|g| (1..=3_i64).map(move |k| (k, g))) {
                let s = canary(&format!("prekeys.secret.{kind}.{id}"), 64);
                insert_prekey(tx, kind, id, &s, None)?;
                want.push((
                    "prekeys",
                    "secret",
                    format!("kind = {kind} AND id = {id}"),
                    s,
                ));
            }
            let access = canary("relays.access_key", 32);
            put_relay(tx, 1, b"relay ref", Some(&access))?;
            want.push(("relays", "access_key", "id = 1".into(), access));
            for id in 1..=2 {
                let contact = Contact {
                    id,
                    iks: b"peer iks",
                    fingerprint: b"peer fingerprint",
                    display_name: Some("peer"),
                    verified: id == 1,
                    routes: None,
                    queues: None,
                    state: 0,
                    profile: Some(b"peer profile"),
                };
                put_contact(tx, &contact)?;
            }
            let invitation = canary("invitations.record", 120);
            insert_invitation(tx, &[5; 16], &invitation, 1)?;
            let ld = "ld_id = x'05050505050505050505050505050505'";
            want.push(("invitations", "record", ld.into(), invitation));
            for s in 1..=2_i64 {
                let fixed = canary(&format!("sessions.data.fixed.{s}"), 300);
                let skipped = canary(&format!("sessions.data.skipped.{s}"), 36 + 32);
                let inbox = canary(&format!("sessions.data.inbox.{s}"), 50);
                put_fixed(tx, s, &fixed)?;
                insert_skipped(tx, s, 0, &skipped)?;
                put_inbox(tx, s, &inbox)?;
                put_trust(tx, s, &[1])?;
                let row = |p: i64| format!("session_id = {s} AND part = {p}");
                let skey = skipped.get(..36).unwrap_or_default().to_vec();
                want.push(("sessions", "data", row(0), fixed));
                want.push(("sessions", "data", row(1), skipped));
                want.push(("sessions", "skey", row(1), skey));
                want.push(("sessions", "data", row(2), inbox));
            }
            Ok(())
        })?;
        let payload = canary("outbox.payload", 200);
        let row = OutboxRow {
            msg_id: [9; 16],
            seq: 0,
            kind: 1,
            expire_after: 0,
            payload: secmp_crypto::Zeroizing::new(payload.clone()),
            queued_ms: 1,
            first_relayed_ms: None,
            state: state::QUEUED,
            cell_id: None,
        };
        store.outbox_insert(1, &row)?;
        let msg = "msg_id = x'09090909090909090909090909090909'";
        want.push(("outbox", "payload", msg.into(), payload));
        Ok(want)
    }

    /// ST-12 (CS-3.3; ADR-053 item 5, Q139): after a populated profile ([`populate`]) the raw bytes of every secret column,
    /// read with the SQLCipher key, are its plaintext plus 72 bytes long and do not contain the plaintext.
    #[test]
    fn secret_columns_are_sealed() -> R {
        use crate::kat::contains;
        use crate::seal::SEAL_OVERHEAD;

        let dir = TempDir::new("st12")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let want = populate(&mut store)?;
        let columns: std::collections::BTreeSet<(&str, &str)> =
            want.iter().map(|(t, c, _, _)| (*t, *c)).collect();
        assert_eq!(columns.len(), 7, "the seven columns of Q139");
        for (table, column, cond, plain) in &want {
            let raw: Vec<u8> = store.connection_kat().query_row(
                &format!("SELECT {column} FROM {table} WHERE {cond}"),
                [],
                |r| r.get(0),
            )?;
            let site = format!("{table}.{column} [{cond}]");
            assert_eq!(raw.len(), plain.len() + SEAL_OVERHEAD, "{site}");
            assert!(!contains(&raw, plain), "{site}: plaintext inside");
            assert!(
                !contains(&raw, plain.get(..8).ok_or("prefix")?),
                "{site}: plaintext prefix inside"
            );
        }
        Ok(())
    }
}
