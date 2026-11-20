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
/// [`Error::Unavailable`] if the entry is shorter than [`SKIPPED_KEY_LEN`] (malformed; nothing is written) or the
/// statement fails (also if `ord` is taken).
pub fn insert_skipped(tx: &mut Tx<'_>, session: i64, ord: i64, entry: &[u8]) -> Result<()> {
    let rk = session_row(session, part::SKIPPED, ord)?;
    let key_len = usize::try_from(SKIPPED_KEY_LEN).map_err(|_| Error::Unavailable)?;
    // Q175: an entry shorter than its key is malformed
    let key = entry.get(..key_len).ok_or(Error::Unavailable)?;
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

/// Write the three handshake cells of an initiator (`PersistedCells` encoding, 3 × 4096 B; Q150): sealed, until the first
/// decrypted reply.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_handshake(tx: &mut Tx<'_>, session: i64, cells: &[u8]) -> Result<()> {
    put(tx, session, part::HANDSHAKE, 0, cells)
}

/// Delete the handshake cells of `session` (the first reply was decrypted); no row is not an error.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn delete_handshake(tx: &mut Tx<'_>, session: i64) -> Result<()> {
    tx.exec(
        "DELETE FROM sessions WHERE session_id = ?1 AND part = ?2",
        params![session, part::HANDSHAKE],
    )?;
    Ok(())
}

/// Write the contact's identity before the last accepted `KeyChange` (`IKSPublic` encoding; ADR-058): sealed like every
/// `sessions` row, one row (ord 0), replaced by the next accepted `KeyChange`.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_previous_identity(tx: &mut Tx<'_>, session: i64, iks: &[u8]) -> Result<()> {
    put(tx, session, part::PREVIOUS_IDENTITY, 0, iks)
}

/// Write a pending control content of `session` (Q210 c): sealed, at the next `ord` of the CONTROL part; returns that
/// `ord`. The client's encoding is opaque here.
///
/// # Errors
/// [`Error::Unavailable`] if a statement fails.
pub fn insert_pending_control(tx: &mut Tx<'_>, session: i64, content: &[u8]) -> Result<i64> {
    let ord = tx
        .query_row(
            "SELECT COALESCE(MAX(ord) + 1, 0) FROM sessions WHERE session_id = ?1 AND part = ?2",
            params![session, part::CONTROL],
            |r| r.get::<_, i64>(0),
        )?
        .ok_or(Error::Unavailable)?;
    put(tx, session, part::CONTROL, ord, content)?;
    Ok(ord)
}

/// Delete the pending control content at `ord` of `session` (every cell of its current attempt has its `OK_SEND`,
/// Q222; or a newer `RouteUpdate` retired it, Q224).
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such row.
pub fn delete_pending_control(tx: &mut Tx<'_>, session: i64, ord: i64) -> Result<()> {
    let n = tx.exec(
        "DELETE FROM sessions WHERE session_id = ?1 AND part = ?2 AND ord = ?3",
        params![session, part::CONTROL, ord],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// The trust codes of the TRUST part's first byte (`secmp-client-core`'s `trust_code` maps its trusts onto them; a test
/// there pins the equality). The store compares only [`TRUST_FROZEN`].
pub const TRUST_UNVERIFIED: u8 = 0;
/// See [`TRUST_UNVERIFIED`].
pub const TRUST_VERIFIED: u8 = 1;
/// See [`TRUST_UNVERIFIED`].
pub const TRUST_KEY_CHANGED: u8 = 2;
/// See [`TRUST_UNVERIFIED`]: a stored `Frozen` is left only by a new session (a fresh invitation, spec §7.8; Q205).
pub const TRUST_FROZEN: u8 = 3;
/// The block byte of the TRUST part: none.
pub const BLOCK_NONE: u8 = 0;
/// The block byte: the contact was removed (`Control{1}`, either side).
pub const BLOCK_REMOVED: u8 = 1;
/// The block byte: a session reset was asked for (`Control{2}`, either side).
pub const BLOCK_RESET: u8 = 2;

/// The TRUST part of a session, strictly decoded: `trust code u8 ‖ block u8` (Q210 b), nothing else.
///
/// # Errors
/// [`Error::Unavailable`] for any other length or an unknown code.
pub fn trust_row(row: &[u8]) -> Result<(u8, u8)> {
    match *row {
        [
            code @ TRUST_UNVERIFIED..=TRUST_FROZEN,
            block @ BLOCK_NONE..=BLOCK_RESET,
        ] => Ok((code, block)),
        _ => Err(Error::Unavailable),
    }
}

/// The raw TRUST row writer: only through [`update_trust`] and [`init_trust`], which check the stored row.
pub(crate) fn put_trust(tx: &mut Tx<'_>, session: i64, trust: &[u8]) -> Result<()> {
    put(tx, session, part::TRUST, 0, trust)
}

/// The stored TRUST part of `session`, read inside the transaction (`None` without one).
fn stored_trust(tx: &mut Tx<'_>, session: i64) -> Result<Option<(u8, u8)>> {
    let sealed = tx.query_row(
        "SELECT data FROM sessions WHERE session_id = ?1 AND part = ?2 AND ord = 0",
        params![session, part::TRUST],
        |r| r.get::<_, Vec<u8>>(0),
    )?;
    let Some(sealed) = sealed else {
        return Ok(None);
    };
    // spec §3.4; ADR-053 item 5
    let row = tx.open(
        Table::Sessions,
        "data",
        &session_row(session, part::TRUST, 0)?,
        &sealed,
    )?;
    trust_row(&row).map(Some)
}

/// Write the trust `code` and/or set the block of `session` (Q205, Q210 b) — the one guarded trust writer: the stored row
/// is read in the same transaction; a trust other than [`TRUST_FROZEN`] over a stored `Frozen` is refused and nothing is
/// written (only a new session leaves `Frozen`); a trust write keeps the stored block and is never refused because of it;
/// a block is set, never cleared ([`BLOCK_NONE`] is refused).
///
/// # Errors
/// [`Error::Unavailable`] for a refused write, an unknown code, a stored row that does not decode or a failed statement.
pub fn update_trust(
    tx: &mut Tx<'_>,
    session: i64,
    code: Option<u8>,
    block: Option<u8>,
) -> Result<()> {
    if code.is_some_and(|c| c > TRUST_FROZEN)
        || block.is_some_and(|b| b == BLOCK_NONE || b > BLOCK_RESET)
    {
        return Err(Error::Unavailable);
    }
    let (stored_code, stored_block) =
        stored_trust(tx, session)?.unwrap_or((TRUST_UNVERIFIED, BLOCK_NONE));
    let present = trust_after(stored_code, code)?;
    put_trust(tx, session, &[present, block.unwrap_or(stored_block)])
}

/// The trust to write: `code` unless it would leave a stored `Frozen`.
fn trust_after(stored: u8, code: Option<u8>) -> Result<u8> {
    match code {
        Some(c) if stored == TRUST_FROZEN && c != TRUST_FROZEN => Err(Error::Unavailable),
        Some(c) => Ok(c),
        None => Ok(stored),
    }
}

/// The trust of a new session (the accept of an invitation): `code` and no block, on a session without a TRUST row.
///
/// # Errors
/// [`Error::Unavailable`] if the session has a TRUST row already, for an unknown code or a failed statement.
pub fn init_trust(tx: &mut Tx<'_>, session: i64, code: u8) -> Result<()> {
    if code > TRUST_FROZEN || stored_trust(tx, session)?.is_some() {
        return Err(Error::Unavailable);
    }
    put_trust(tx, session, &[code, BLOCK_NONE])
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

    /// The handshake cells of `session`, if its first reply has not been decrypted yet.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a read fails.
    pub fn handshake(&self, session: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .read_part(session, part::HANDSHAKE)?
            .into_iter()
            .next()
            .map(|(_, d)| d))
    }

    /// The pending control contents of `session` with their `ord`, in order (Q210 c).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a read or an open fails.
    pub fn pending_controls(&self, session: i64) -> Result<Vec<(i64, Zeroizing<Vec<u8>>)>> {
        self.read_part(session, part::CONTROL)
    }

    /// The contact's identity before the last accepted `KeyChange` of `session` (ADR-058); `None` before the first one.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a read or an open fails.
    pub fn previous_identity(&self, session: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .read_part(session, part::PREVIOUS_IDENTITY)?
            .into_iter()
            .next()
            .map(|(_, d)| d))
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

    /// ADR-058: the previous identity of a session is one sealed row (part 6, ord 0) — absent at first, written, replaced
    /// by the next write, apart per session, and not in the clear in `sessions.data`.
    #[test]
    fn previous_identity_round_trip() -> R {
        let dir = TempDir::new("previous-identity")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        assert!(store.previous_identity(4)?.is_none());
        store.txn(|tx| put_previous_identity(tx, 4, b"iks-a"))?;
        assert_eq!(
            store.previous_identity(4)?.as_deref().map(Vec::as_slice),
            Some(&b"iks-a"[..])
        );
        store.txn(|tx| put_previous_identity(tx, 4, b"iks-b"))?;
        assert_eq!(
            store.previous_identity(4)?.as_deref().map(Vec::as_slice),
            Some(&b"iks-b"[..])
        );
        let rows: i64 = store.connection_kat().query_row(
            "SELECT count(*) FROM sessions WHERE session_id = 4 AND part = 6",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(rows, 1, "one row");
        assert!(store.previous_identity(5)?.is_none(), "another session");
        let raw: Vec<u8> = store.connection_kat().query_row(
            "SELECT data FROM sessions WHERE session_id = 4 AND part = 6 AND ord = 0",
            [],
            |r| r.get(0),
        )?;
        assert_ne!(raw.as_slice(), b"iks-b", "sealed");
        Ok(())
    }

    /// Q175 (A4-1-09): a skipped entry shorter than its key (`SKIPPED_KEY_LEN` = 36 B) is malformed — the uniform
    /// `Unavailable`, nothing written; a 36-byte entry is stored.
    #[test]
    fn short_skipped_entry_refused() -> R {
        let dir = TempDir::new("short-skipped")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| put_fixed(tx, 9, b"fixed"))?;
        assert_eq!(
            store.txn(|tx| insert_skipped(tx, 9, 0, &[b'e'; 35])),
            Err(Error::Unavailable)
        );
        let rows = store.session_rows(9)?.ok_or("rows")?;
        assert!(rows.skipped.is_empty(), "nothing written");
        store.txn(|tx| insert_skipped(tx, 9, 0, &[b'e'; 36]))?;
        let rows = store.session_rows(9)?.ok_or("rows")?;
        assert_eq!(rows.skipped.len(), 1);
        Ok(())
    }

    /// Q210 c: the pending control contents of a session — sealed rows of the CONTROL part at increasing `ord`s, read in
    /// order, each deleted once (a missing one is `Unavailable`); another session's are apart.
    #[test]
    fn pending_controls_round_trip() -> R {
        let dir = TempDir::new("pending-controls")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let (a, b) = store.txn(|tx| {
            let a = insert_pending_control(tx, 4, b"route update")?;
            let b = insert_pending_control(tx, 4, b"control")?;
            insert_pending_control(tx, 5, b"other")?;
            Ok((a, b))
        })?;
        assert_eq!((a, b), (0, 1));
        let rows: Vec<(i64, Vec<u8>)> = store
            .pending_controls(4)?
            .into_iter()
            .map(|(o, d)| (o, d.to_vec()))
            .collect();
        assert_eq!(
            rows,
            vec![(0, b"route update".to_vec()), (1, b"control".to_vec())]
        );
        store.txn(|tx| delete_pending_control(tx, 4, 0))?;
        assert_eq!(
            store.txn(|tx| delete_pending_control(tx, 4, 0)),
            Err(Error::Unavailable),
            "once"
        );
        assert_eq!(store.txn(|tx| insert_pending_control(tx, 4, b"next"))?, 2);
        assert_eq!(store.pending_controls(5)?.len(), 1);
        assert_eq!(store.pending_controls(6)?.len(), 0);
        Ok(())
    }

    /// Q205, Q210 b: the one guarded trust writer. A new session's trust goes onto a session without a row (a second
    /// `init_trust` is refused); a trust write keeps the block; a block is set, never cleared, and never refuses a trust;
    /// nothing but `Frozen` is written over a stored `Frozen` (nothing written); the row is `code ‖ block`, decoded
    /// strictly.
    #[test]
    fn trust_writer_keeps_frozen_and_block() -> R {
        let dir = TempDir::new("trust-guard")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let row_of = |store: &Store, session: i64| -> core::result::Result<Vec<u8>, Error> {
            Ok(store
                .inbox_trust(session)?
                .1
                .map(|t| t.to_vec())
                .unwrap_or_default())
        };
        let row = |store: &Store| row_of(store, 5);
        store.txn(|tx| init_trust(tx, 5, TRUST_UNVERIFIED))?;
        assert_eq!(row(&store)?, [TRUST_UNVERIFIED, BLOCK_NONE]);
        assert_eq!(
            store.txn(|tx| init_trust(tx, 5, TRUST_UNVERIFIED)),
            Err(Error::Unavailable),
            "a session with a trust row is not new"
        );
        store.txn(|tx| update_trust(tx, 5, None, Some(BLOCK_RESET)))?;
        store.txn(|tx| update_trust(tx, 5, Some(TRUST_VERIFIED), None))?;
        assert_eq!(
            row(&store)?,
            [TRUST_VERIFIED, BLOCK_RESET],
            "the block stays"
        );
        assert_eq!(
            store.txn(|tx| update_trust(tx, 5, None, Some(BLOCK_NONE))),
            Err(Error::Unavailable),
            "a block is never cleared"
        );
        store.txn(|tx| update_trust(tx, 5, Some(TRUST_FROZEN), Some(BLOCK_REMOVED)))?;
        for code in [TRUST_UNVERIFIED, TRUST_VERIFIED, TRUST_KEY_CHANGED] {
            assert_eq!(
                store.txn(|tx| update_trust(tx, 5, Some(code), None)),
                Err(Error::Unavailable),
                "{code} over Frozen"
            );
        }
        store.txn(|tx| update_trust(tx, 5, Some(TRUST_FROZEN), None))?;
        store.txn(|tx| update_trust(tx, 5, None, Some(BLOCK_RESET)))?;
        assert_eq!(row(&store)?, [TRUST_FROZEN, BLOCK_RESET], "still frozen");
        for bad in [
            &[][..],
            &[TRUST_FROZEN],
            &[4, 0],
            &[0, 3],
            &[TRUST_FROZEN, BLOCK_NONE, 0],
        ] {
            assert_eq!(trust_row(bad), Err(Error::Unavailable), "{bad:?}");
        }
        assert_eq!(
            store.txn(|tx| update_trust(tx, 5, Some(4), None)),
            Err(Error::Unavailable)
        );
        // B-4c killer (`init_trust`): every known code starts a session, an unknown one none
        store.txn(|tx| init_trust(tx, 7, TRUST_FROZEN))?;
        assert_eq!(row_of(&store, 7)?, [TRUST_FROZEN, BLOCK_NONE]);
        assert_eq!(
            store.txn(|tx| init_trust(tx, 8, 4)),
            Err(Error::Unavailable)
        );
        // a raw row that does not decode is refused by the guard, nothing is written over it
        store.txn(|tx| put_trust(tx, 6, &[TRUST_VERIFIED]))?;
        assert_eq!(
            store.txn(|tx| update_trust(tx, 6, Some(TRUST_VERIFIED), None)),
            Err(Error::Unavailable)
        );
        Ok(())
    }

    /// The rows of a session as written (G7-13 extra test, store half of PC-07/PC-09): the fixed part, the skipped entries
    /// by `ord` in order, the reassembly state and the trust; an `ord` is taken once; deleting an entry removes exactly it,
    /// deleting a missing one fails; a second session is apart; nothing before the first fixed part.
    #[test]
    fn session_rows_round_trip() -> R {
        let dir = TempDir::new("sessions")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        // Q175: every skipped entry is at least `SKIPPED_KEY_LEN` (36) bytes: 36 × `e`, then its ordinal
        let entry = |n: u8| [&[b'e'; 36][..], &[n]].concat();
        assert!(store.session_rows(7)?.is_none(), "no fixed part yet");
        store.txn(|tx| {
            put_fixed(tx, 7, b"fixed-1")?;
            insert_skipped(tx, 7, 0, &entry(0))?;
            insert_skipped(tx, 7, 1, &entry(1))?;
            insert_skipped(tx, 7, 2, &entry(2))?;
            put_inbox(tx, 7, b"inbox")?;
            put_trust(tx, 7, &[3])?;
            put_fixed(tx, 8, b"other")
        })?;
        assert_eq!(
            store.txn(|tx| insert_skipped(tx, 7, 1, &[b'a'; 36])),
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
            vec![(0, entry(0).as_slice()), (2, entry(2).as_slice())]
        );
        let keys: Vec<(i64, Vec<u8>)> = store
            .skipped_keys(7)?
            .into_iter()
            .map(|(o, k)| (o, k.to_vec()))
            .collect();
        assert_eq!(keys, vec![(0, vec![b'e'; 36]), (2, vec![b'e'; 36])]);
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

    /// Killer (A-4 mutant, `session_row`): a sealed part copied to another row of `sessions` does not open there (the row
    /// key `(session_id, part, ord)` is in the record's AD, ADR-053 item 5).
    #[test]
    fn sealed_part_bound_to_its_row() -> R {
        let dir = TempDir::new("sessions-row")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| {
            put_fixed(tx, 7, b"fixed-7")?;
            put_fixed(tx, 8, b"fixed-8")
        })?;
        store.connection_kat().execute(
            "UPDATE sessions SET data = (SELECT data FROM sessions WHERE session_id = 7) WHERE session_id = 8",
            [],
        )?;
        assert!(store.session_rows(7)?.is_some());
        assert_eq!(store.session_rows(8).err(), Some(Error::Unavailable));
        Ok(())
    }

    /// B-4 (killers of `put_handshake`, `delete_handshake`, `Store::handshake`; Q150): the persisted handshake cells of an
    /// initiator read back until deleted; another session has none; deleting none is no error; the fixed part is not touched.
    #[test]
    fn handshake_cells_round_trip() -> R {
        let dir = TempDir::new("handshake-cells")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        assert!(store.handshake(4)?.is_none());
        store.txn(|tx| {
            put_fixed(tx, 4, b"fixed")?;
            put_handshake(tx, 4, b"three cells")
        })?;
        assert_eq!(
            store.handshake(4)?.map(|z| z.to_vec()),
            Some(b"three cells".to_vec())
        );
        assert!(store.handshake(5)?.is_none(), "another session has none");
        store.txn(|tx| delete_handshake(tx, 5))?;
        assert!(
            store.handshake(4)?.is_some(),
            "deleting another session's none"
        );
        store.txn(|tx| delete_handshake(tx, 4))?;
        assert!(store.handshake(4)?.is_none());
        assert_eq!(
            store.session_rows(4)?.ok_or("rows")?.fixed.to_vec(),
            b"fixed".to_vec()
        );
        Ok(())
    }
}
