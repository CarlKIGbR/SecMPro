// SPDX-License-Identifier: AGPL-3.0-or-later
//! The rows of an incrementally persisted session (CS-3.7 `docs/04:58`, `docs/02:102`; OPEN-M7-14 A): `sessions` keyed
//! `(session_id, part, ord)` — the fixed part of `RatchetStateV1` (one row, rewritten per slot), one row per skipped
//! entry (`ord` = insertion order), the reassembly state and the trust ([`crate::schema::part`]). The writes are statements
//! of the caller's transaction ([`crate::Tx`]): the client commits a ratchet step, its skipped entries, its reassembly
//! and trust state and the messages it delivered in one transaction (persist-before-send/ack, PC-09).

use rusqlite::params;
use secmp_crypto::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::Table;
use crate::schema::part;
use crate::seal::{KeyPart, row_key};
use crate::store::{Store, Tx};

/// The length of the key `hk ‖ n` at the front of a skipped entry (`secmp_proto::tr::SKIPPED_KEY_LEN`).
pub const SKIPPED_KEY_LEN: i64 = 36;

/// The rows of a session as stored (every part a secret or a secret's container: zeroized on drop, CLAUDE.md §1.6).
pub struct SessionRows {
    /// The fixed part.
    pub fixed: Zeroizing<Vec<u8>>,
    /// The skipped entries with their `ord`, in insertion order.
    pub skipped: Vec<(i64, Zeroizing<Vec<u8>>)>,
    /// The reassembly state, if any.
    pub inbox: Option<Zeroizing<Vec<u8>>>,
    /// The trust, if any.
    pub trust: Option<Zeroizing<Vec<u8>>>,
}

/// The reassembly state and the trust of a session (each `None` before its first write).
pub type InboxTrust = (Option<Zeroizing<Vec<u8>>>, Option<Zeroizing<Vec<u8>>>);

/// `row_key` of a `sessions` row: (`session_id`, `part`, `ord`), 24 bytes (ADR-053 item 5, Am. 1).
fn session_row(session: i64, p: i64, ord: i64) -> Result<Vec<u8>> {
    row_key(&[KeyPart::Int(session), KeyPart::Int(p), KeyPart::Int(ord)])
}

fn put(tx: &mut Tx<'_>, session: i64, p: i64, ord: i64, data: &[u8]) -> Result<()> {
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(
        Table::Sessions,
        "data",
        &session_row(session, p, ord)?,
        data,
    )?;
    tx.exec(
        "INSERT INTO sessions (session_id, part, ord, data) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (session_id, part, ord) DO UPDATE SET data = excluded.data",
        params![session, p, ord, sealed],
    )?;
    Ok(())
}

/// Write the fixed part.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_fixed(tx: &mut Tx<'_>, session: i64, fixed: &[u8]) -> Result<()> {
    put(tx, session, part::FIXED, 0, fixed)
}

/// Insert one skipped entry at `ord`: the whole entry sealed in `data`, its key `hk ‖ n` (the first [`SKIPPED_KEY_LEN`]
/// bytes) sealed in `skey`.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails (also if `ord` is taken).
pub fn insert_skipped(tx: &mut Tx<'_>, session: i64, ord: i64, entry: &[u8]) -> Result<()> {
    let rk = session_row(session, part::SKIPPED, ord)?;
    let key_len = usize::try_from(SKIPPED_KEY_LEN).map_err(|_| Error::Unavailable)?;
    let key = entry.get(..key_len).unwrap_or(entry);
    // spec §3.4; ADR-053 item 5
    let data = tx.seal(Table::Sessions, "data", &rk, entry)?;
    // spec §3.4; ADR-053 item 5
    let skey = tx.seal(Table::Sessions, "skey", &rk, key)?;
    tx.exec(
        "INSERT INTO sessions (session_id, part, ord, data, skey) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![session, part::SKIPPED, ord, data, skey],
    )?;
    Ok(())
}

/// Delete the skipped entry at `ord`.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such row.
pub fn delete_skipped(tx: &mut Tx<'_>, session: i64, ord: i64) -> Result<()> {
    let n = tx.exec(
        "DELETE FROM sessions WHERE session_id = ?1 AND part = ?2 AND ord = ?3",
        params![session, part::SKIPPED, ord],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Write the reassembly state.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_inbox(tx: &mut Tx<'_>, session: i64, inbox: &[u8]) -> Result<()> {
    put(tx, session, part::INBOX, 0, inbox)
}

/// Write the trust.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_trust(tx: &mut Tx<'_>, session: i64, trust: &[u8]) -> Result<()> {
    put(tx, session, part::TRUST, 0, trust)
}

/// Record a delivered message in the history (`INSERT OR IGNORE`: a message delivered again is kept once), received at
/// `ts_ms` (Unix ms) and expiring `expire_after` seconds later (0: never; V1-F4).
///
/// # Errors
/// [`Error::Unsupported`] for a view-once (never written, CS-3.4); [`Error::Unavailable`] if the statement fails or the
/// time does not fit the column.
pub fn insert_delivered(
    tx: &mut Tx<'_>,
    contact_id: i64,
    msg_id: &[u8; 16],
    kind: u8,
    payload: &[u8],
    ts_ms: u64,
    expire_after: u32,
) -> Result<()> {
    if kind == crate::messages::KIND_VIEW_ONCE {
        return Err(Error::Unsupported);
    }
    let ts = i64::try_from(ts_ms).map_err(|_| Error::Unavailable)?;
    let expire_at = crate::messages::expire_at(ts_ms, expire_after)?;
    tx.exec(
        "INSERT OR IGNORE INTO messages (contact_id, msg_id, direction, kind, ts_ms, expire_at_ms, payload) \
         VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6)",
        params![contact_id, msg_id.as_slice(), i64::from(kind), ts, expire_at, payload],
    )?;
    Ok(())
}

impl Store {
    /// The rows of `session` (`None` if it has no fixed part).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a read fails.
    pub fn session_rows(&self, session: i64) -> Result<Option<SessionRows>> {
        let Some((_, fixed)) = self.read_part(session, part::FIXED)?.into_iter().next() else {
            return Ok(None);
        };
        let skipped = self.read_part(session, part::SKIPPED)?;
        #[cfg(any(test, feature = "kat"))]
        crate::kat::note_session_secret_bytes(
            skipped
                .iter()
                .fold(fixed.len(), |n, (_, e)| n.saturating_add(e.len())),
        );
        let (inbox, trust) = self.inbox_trust(session)?;
        Ok(Some(SessionRows {
            fixed,
            skipped,
            inbox,
            trust,
        }))
    }

    /// The rows of one part of `session`, in `ord` order, opened.
    fn read_part(&self, session: i64, p: i64) -> Result<Vec<(i64, Zeroizing<Vec<u8>>)>> {
        self.read_rows(
            "SELECT ord, data FROM sessions WHERE session_id = ?1 AND part = ?2 ORDER BY ord",
            session,
            p,
            "data",
        )
    }

    /// The sealed `column` of the rows `sql` selects (`ord`, `column`), each opened under its row (ADR-053 item 5).
    fn read_rows(
        &self,
        sql: &str,
        session: i64,
        p: i64,
        column: &str,
    ) -> Result<Vec<(i64, Zeroizing<Vec<u8>>)>> {
        let mut stmt = self.conn.prepare(sql).map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map(params![session, p], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
            })
            .map_err(|_| Error::Unavailable)?;
        let mut out = Vec::new();
        for row in rows {
            let (ord, sealed) = row.map_err(|_| Error::Unavailable)?;
            let sealed = sealed.ok_or(Error::Unavailable)?;
            let rk = session_row(session, p, ord)?;
            // spec §3.4; ADR-053 item 5
            out.push((
                ord,
                self.open_record(Table::Sessions, column, &rk, &sealed)?,
            ));
        }
        Ok(out)
    }

    /// The keys `hk ‖ n` of the skipped entries of `session` with their `ord`, in insertion order — the sealed `skey`
    /// column only (the first [`SKIPPED_KEY_LEN`] bytes of each entry): no message key is opened (V1-F2).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a read or an open fails.
    pub fn skipped_keys(&self, session: i64) -> Result<Vec<(i64, Zeroizing<Vec<u8>>)>> {
        self.read_rows(
            "SELECT ord, skey FROM sessions WHERE session_id = ?1 AND part = ?2 ORDER BY ord",
            session,
            part::SKIPPED,
            "skey",
        )
    }

    /// The reassembly state and the trust of `session` (the INBOX and TRUST parts only).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a read fails.
    pub fn inbox_trust(&self, session: i64) -> Result<InboxTrust> {
        let inbox = self.read_part(session, part::INBOX)?.into_iter().next();
        let trust = self.read_part(session, part::TRUST)?.into_iter().next();
        Ok((inbox.map(|(_, d)| d), trust.map(|(_, d)| d)))
    }

    /// The `msg_id`s the history holds as received from `contact_id` (the dedup set after a restart).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn delivered_ids(&self, contact_id: i64) -> Result<Vec<[u8; 16]>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT msg_id FROM messages WHERE contact_id = ?1 AND direction = 0 ORDER BY id",
            )
            .map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map(params![contact_id], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|_| Error::Unavailable)?;
        let mut out = Vec::new();
        for r in rows {
            let v = r.map_err(|_| Error::Unavailable)?;
            out.push(<[u8; 16]>::try_from(v.as_slice()).map_err(|_| Error::Unavailable)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{TempDir, TestKey};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// The rows of a session as written (G7-13 extra test, store half of PC-07/PC-09): the fixed part, the skipped entries
    /// by `ord` in order, the reassembly state and the trust; an `ord` is taken once; deleting an entry removes exactly it,
    /// deleting a missing one fails; a second session is apart; nothing before the first fixed part.
    #[test]
    fn session_rows_round_trip() -> R {
        let dir = TempDir::new("sessions")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        assert!(store.session_rows(7)?.is_none(), "no fixed part yet");
        store.txn(|tx| {
            put_fixed(tx, 7, b"fixed-1")?;
            insert_skipped(tx, 7, 0, b"entry-0")?;
            insert_skipped(tx, 7, 1, b"entry-1")?;
            insert_skipped(tx, 7, 2, b"entry-2")?;
            put_inbox(tx, 7, b"inbox")?;
            put_trust(tx, 7, &[3])?;
            put_fixed(tx, 8, b"other")
        })?;
        assert_eq!(
            store.txn(|tx| insert_skipped(tx, 7, 1, b"again")),
            Err(Error::Unavailable),
            "an ord is taken once"
        );
        store.txn(|tx| {
            put_fixed(tx, 7, b"fixed-2")?;
            delete_skipped(tx, 7, 1)
        })?;
        assert_eq!(
            store.txn(|tx| delete_skipped(tx, 7, 1)),
            Err(Error::Unavailable),
            "no such row"
        );
        let rows = store.session_rows(7)?.ok_or("rows")?;
        assert_eq!(rows.fixed.as_slice(), b"fixed-2");
        let skipped: Vec<(i64, &[u8])> = rows
            .skipped
            .iter()
            .map(|(o, e)| (*o, e.as_slice()))
            .collect();
        assert_eq!(
            skipped,
            vec![(0, b"entry-0".as_slice()), (2, b"entry-2".as_slice())]
        );
        assert_eq!(
            rows.inbox.as_deref().map(Vec::as_slice),
            Some(b"inbox".as_slice())
        );
        assert_eq!(
            rows.trust.as_deref().map(Vec::as_slice),
            Some([3_u8].as_slice())
        );
        let other = store.session_rows(8)?.ok_or("rows")?;
        assert_eq!(other.fixed.as_slice(), b"other");
        assert!(other.skipped.is_empty() && other.inbox.is_none() && other.trust.is_none());
        Ok(())
    }

    /// The delivered history of a session (G7-13 extra test, store half of PC-05): ids in delivery order, a message
    /// delivered again is kept once, a view-once is never written (`Unsupported`), another contact's are apart.
    #[test]
    fn delivered_history_dedups() -> R {
        let dir = TempDir::new("delivered")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| {
            insert_delivered(tx, 1, &[2; 16], 1, b"two", 0, 0)?;
            insert_delivered(tx, 1, &[1; 16], 1, b"one", 0, 0)?;
            insert_delivered(tx, 1, &[2; 16], 1, b"two again", 0, 0)?;
            insert_delivered(tx, 9, &[5; 16], 1, b"other", 0, 0)
        })?;
        assert_eq!(
            store.txn(|tx| insert_delivered(
                tx,
                1,
                &[4; 16],
                crate::messages::KIND_VIEW_ONCE,
                b"vo",
                0,
                0
            )),
            Err(Error::Unsupported)
        );
        assert_eq!(store.delivered_ids(1)?, vec![[2; 16], [1; 16]]);
        assert_eq!(store.delivered_ids(9)?, vec![[5; 16]]);
        assert!(store.delivered_ids(3)?.is_empty());
        Ok(())
    }

    /// V1-F2 (CLAUDE.md §1.6): reading the stored keys of the skipped entries and the inbox/trust reads no message key
    /// and no fixed part — `skipped_keys` returns only the 36-byte prefix `hk ‖ n` of each entry; `session_rows` (the
    /// control) reads the fixed part and every whole entry.
    #[test]
    fn open_reads_no_message_keys() -> R {
        use crate::kat::{reset_counters, session_secret_bytes_read};
        use secmp_proto::tr::{SKIPPED_ENTRY_LEN, SKIPPED_KEY_LEN as PROTO_KEY_LEN};
        assert_eq!(usize::try_from(SKIPPED_KEY_LEN)?, PROTO_KEY_LEN);
        let dir = TempDir::new("no-mk")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let entries: Vec<Vec<u8>> = (1..=3_u8).map(|n| vec![n; SKIPPED_ENTRY_LEN]).collect();
        let fixed = vec![0x42_u8; 100];
        store.txn(|tx| {
            put_fixed(tx, 4, &fixed)?;
            for (ord, e) in (0_i64..).zip(&entries) {
                insert_skipped(tx, 4, ord, e)?;
            }
            put_inbox(tx, 4, b"inbox")?;
            put_trust(tx, 4, &[1])
        })?;
        reset_counters();
        let keys = store.skipped_keys(4)?;
        assert_eq!(keys.len(), 3);
        for ((ord, k), (want_ord, e)) in keys.iter().zip((0_i64..).zip(&entries)) {
            assert_eq!(*ord, want_ord);
            assert_eq!(k.len(), PROTO_KEY_LEN);
            assert_eq!(Some(k.as_slice()), e.get(..PROTO_KEY_LEN));
        }
        assert_eq!(session_secret_bytes_read(), 0);
        let (inbox, trust) = store.inbox_trust(4)?;
        assert_eq!(
            inbox.as_deref().map(Vec::as_slice),
            Some(b"inbox".as_slice())
        );
        assert_eq!(trust.as_deref().map(Vec::as_slice), Some([1_u8].as_slice()));
        assert_eq!(session_secret_bytes_read(), 0);
        let rows = store.session_rows(4)?.ok_or("rows")?;
        assert_eq!(rows.skipped.len(), 3);
        assert_eq!(
            session_secret_bytes_read(),
            u64::try_from(fixed.len() + 3 * SKIPPED_ENTRY_LEN)?
        );
        Ok(())
    }

    /// V1-F4 (dictated): a delivered message is stored with its receive time and its `expire_after`, and expires.
    #[test]
    fn delivered_message_expires() -> R {
        let dir = TempDir::new("delivered-expiry")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let now = 1_000_000_u64;
        store.txn(|tx| insert_delivered(tx, 6, &[7; 16], 1, b"soon gone", now, 86_400))?;
        assert_eq!(store.expire_messages(now + 86_400_000 - 1)?, 0);
        assert!(store.has_message(6, &[7; 16])?);
        assert_eq!(store.expire_messages(now + 86_400_000 + 1)?, 1);
        assert!(!store.has_message(6, &[7; 16])?);
        Ok(())
    }
}
