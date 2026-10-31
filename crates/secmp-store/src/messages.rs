// SPDX-License-Identifier: AGPL-3.0-or-later
//! The conversation history (`messages`, `docs/02:96`), its expiry (§7.6 `expire_after`, CS-3.4) and view-once messages
//! (CS-1.14, CS-3.4, OPEN-M7-27 A as revised by Q125): a view-once (kind 3) is **never written** — not to `messages`, not
//! to `outbox`. A received one is held in memory until it has been revealed and 20 s have passed; a queued one to send is
//! held in memory too, and only its `msg_id` is kept in `meta` (`view_once_pending`), so that after a restart the store
//! can report it lost ([`Store::take_view_once_lost`]; the `Api` event `ViewOnceLost` is Phase B).

use rusqlite::params;
use secmp_crypto::Zeroizing;

use crate::error::{Error, Result};
use crate::store::Store;

/// `AppMessage.kind` of a view-once text (spec §7.6).
pub const KIND_VIEW_ONCE: u8 = 3;

/// How long a revealed view-once stays readable (CS-1.14: 20 s after reveal).
pub const VIEW_ONCE_REVEAL_MS: u64 = 20_000;

/// Who sent a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Received.
    In,
    /// Sent.
    Out,
}

/// How long the history is kept (OPEN-M7-09: the `docs/09` default is to keep it, user-settable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Keep forever (the default).
    Keep,
    /// Delete messages older than this many days.
    Days(u32),
}

/// A message to keep in the history.
pub struct NewMessage<'a> {
    /// The contact.
    pub contact_id: i64,
    /// Its `msg_id`.
    pub msg_id: [u8; 16],
    /// In or out.
    pub direction: Direction,
    /// `AppMessage.kind`.
    pub kind: u8,
    /// When (milliseconds of the store's clock).
    pub ts_ms: u64,
    /// `expire_after` in seconds (0: never).
    pub expire_after: u32,
    /// The payload.
    pub payload: &'a [u8],
}

/// A held view-once message.
struct Held {
    msg_id: [u8; 16],
    payload: Zeroizing<Vec<u8>>,
    revealed_at: Option<u64>,
    outgoing: bool,
}

/// The in-memory view-once messages of an open store.
#[derive(Default)]
pub struct ViewOnceHolder {
    held: Vec<Held>,
}

impl ViewOnceHolder {
    fn sweep(&mut self, now_ms: u64) {
        self.held.retain(|h| {
            h.revealed_at
                .is_none_or(|t| now_ms < t.saturating_add(VIEW_ONCE_REVEAL_MS))
        });
    }
}

/// The `expire_at_ms` of a message stored at `ts_ms` with `expire_after` seconds (`None`: 0, never expires) — shared by
/// the history writes of sent and of delivered messages.
///
/// # Errors
/// [`Error::Unavailable`] if the time does not fit the column.
pub fn expire_at(ts_ms: u64, expire_after: u32) -> Result<Option<i64>> {
    if expire_after == 0 {
        return Ok(None);
    }
    i64_of(ts_ms.saturating_add(u64::from(expire_after).saturating_mul(1000))).map(Some)
}

fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::Unavailable)
}

impl Store {
    /// Keep a message in the history (one transaction). A view-once is refused: it never reaches the disk.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for kind 3; [`Error::Unavailable`] if the write fails.
    pub fn insert_message(&mut self, m: &NewMessage<'_>) -> Result<()> {
        if m.kind == KIND_VIEW_ONCE {
            return Err(Error::Unsupported);
        }
        let ts = i64_of(m.ts_ms)?;
        let expire_at = expire_at(m.ts_ms, m.expire_after)?;
        let direction: i64 = match m.direction {
            Direction::In => 0,
            Direction::Out => 1,
        };
        self.txn(|tx| {
            tx.exec(
                "INSERT OR IGNORE INTO messages (contact_id, msg_id, direction, kind, ts_ms, expire_at_ms, payload) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![m.contact_id, m.msg_id.as_slice(), direction, i64::from(m.kind), ts, expire_at, m.payload],
            )?;
            Ok(())
        })
    }

    /// Whether the history holds the message.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn has_message(&self, contact_id: i64, msg_id: &[u8; 16]) -> Result<bool> {
        Ok(self
            .query_row(
                "SELECT count(*) FROM messages WHERE contact_id = ?1 AND msg_id = ?2",
                params![contact_id, msg_id.as_slice()],
                |r| r.get::<_, i64>(0),
            )?
            .unwrap_or(0)
            > 0)
    }

    /// Delete every message whose `expire_after` has run out at `now_ms` (§7.6); returns how many.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the write fails.
    pub fn expire_messages(&mut self, now_ms: u64) -> Result<usize> {
        let now = i64_of(now_ms)?;
        self.txn(|tx| {
            tx.exec(
                "DELETE FROM messages WHERE expire_at_ms IS NOT NULL AND expire_at_ms <= ?1",
                params![now],
            )
        })
    }

    /// The retention setting (default [`Retention::Keep`], OPEN-M7-09).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn retention(&self) -> Result<Retention> {
        let v = self.query_row(
            "SELECT value FROM settings WHERE key = 'retention_days'",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        Ok(match v.and_then(|d| u32::try_from(d).ok()) {
            Some(d) if d > 0 => Retention::Days(d),
            _ => Retention::Keep,
        })
    }

    /// Hold a received view-once message in memory (never written).
    pub fn hold_received_view_once(&mut self, msg_id: [u8; 16], payload: &[u8]) {
        self.view_once.held.push(Held {
            msg_id,
            payload: Zeroizing::new(payload.to_vec()),
            revealed_at: None,
            outgoing: false,
        });
    }

    /// Reveal a held view-once at `now_ms`: its payload, readable until `now_ms + 20 s` (the first reveal starts the
    /// clock).
    pub fn reveal_view_once(
        &mut self,
        msg_id: &[u8; 16],
        now_ms: u64,
    ) -> Option<Zeroizing<Vec<u8>>> {
        self.view_once.sweep(now_ms);
        let h = self
            .view_once
            .held
            .iter_mut()
            .find(|h| h.msg_id == *msg_id && !h.outgoing)?;
        h.revealed_at.get_or_insert(now_ms);
        Some(Zeroizing::new(h.payload.to_vec()))
    }

    /// Whether a received view-once is still held at `now_ms`.
    pub fn view_once_held(&mut self, msg_id: &[u8; 16], now_ms: u64) -> bool {
        self.view_once.sweep(now_ms);
        self.view_once
            .held
            .iter()
            .any(|h| h.msg_id == *msg_id && !h.outgoing)
    }

    /// Queue a view-once to send: the payload in memory, its `msg_id` (id only) in `meta.view_once_pending`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the id cannot be recorded (nothing is held then).
    pub fn queue_view_once(&mut self, msg_id: [u8; 16], payload: &[u8]) -> Result<()> {
        let mut ids = self.pending_view_once_ids()?;
        ids.extend_from_slice(&msg_id);
        self.write_pending_view_once(&ids)?;
        self.view_once.held.push(Held {
            msg_id,
            payload: Zeroizing::new(payload.to_vec()),
            revealed_at: None,
            outgoing: true,
        });
        Ok(())
    }

    /// The payload of a queued outgoing view-once (for its cell).
    #[must_use]
    pub fn outgoing_view_once(&self, msg_id: &[u8; 16]) -> Option<Zeroizing<Vec<u8>>> {
        self.view_once
            .held
            .iter()
            .find(|h| h.msg_id == *msg_id && h.outgoing)
            .map(|h| Zeroizing::new(h.payload.to_vec()))
    }

    /// The `msg_id`s of the view-once messages queued to send by an earlier run and lost with it (their payload was in
    /// memory only); the record is cleared. A restart reports each once.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the record cannot be read or cleared.
    pub fn take_view_once_lost(&mut self) -> Result<Vec<[u8; 16]>> {
        let ids = self.pending_view_once_ids()?;
        let held: Vec<[u8; 16]> = self
            .view_once
            .held
            .iter()
            .filter(|h| h.outgoing)
            .map(|h| h.msg_id)
            .collect();
        let mut lost = Vec::new();
        let mut keep = Vec::new();
        for id in ids.as_chunks::<16>().0 {
            let id = *id;
            if held.contains(&id) {
                keep.extend_from_slice(&id);
            } else {
                lost.push(id);
            }
        }
        self.write_pending_view_once(&keep)?;
        Ok(lost)
    }

    fn pending_view_once_ids(&self) -> Result<Vec<u8>> {
        Ok(self
            .query_row(
                "SELECT value FROM meta WHERE key = 'view_once_pending'",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )?
            .unwrap_or_default())
    }

    fn write_pending_view_once(&mut self, ids: &[u8]) -> Result<()> {
        self.txn(|tx| {
            tx.exec(
                "INSERT INTO meta (key, value) VALUES ('view_once_pending', ?1) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![ids],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{TempDir, TestKey, scan_dir};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    fn rows(store: &Store, table: &str) -> rusqlite::Result<i64> {
        store
            .connection_kat()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
    }

    /// ST-17 (CS-3.4, CS-1.14; OPEN-M7-27 A / Q125) — the store half: a received view-once (kind 3) with a canary is
    /// held in memory until revealed + 20 s; one queued to send leaves only its id; neither reaches `messages` or
    /// `outbox` (the history refuses kind 3); after close neither canary is in any file of the profile directory (raw
    /// bytes and printable runs) nor in the decrypted pages (`sqlcipher_export`); after a restart the unsent one is
    /// reported lost (`take_view_once_lost`). The `Api` event `ViewOnceLost` is Phase B.
    #[test]
    fn view_once_never_written() -> R {
        let dir = TempDir::new("st17")?;
        let inbound: &[u8] = b"CANARY-MSG-1f2e3d4c5b6a7980 view-once in";
        let outbound: &[u8] = b"CANARY-MSG-0a1b2c3d4e5f6071 view-once out";
        let (rid, sid) = ([0x31_u8; 16], [0x32_u8; 16]);
        {
            let mut store = Store::open(dir.path(), &TestKey::db_key())?;
            store.hold_received_view_once(rid, inbound);
            assert_eq!(
                store.insert_message(&NewMessage {
                    contact_id: 1,
                    msg_id: rid,
                    direction: Direction::In,
                    kind: KIND_VIEW_ONCE,
                    ts_ms: 1_000,
                    expire_after: 0,
                    payload: inbound,
                }),
                Err(Error::Unsupported)
            );
            store.queue_view_once(sid, outbound)?;
            assert!(store.outgoing_view_once(&sid).is_some());
            // held until revealed + 20 s
            assert!(store.view_once_held(&rid, 5_000));
            assert_eq!(
                store
                    .reveal_view_once(&rid, 10_000)
                    .as_deref()
                    .map(Vec::as_slice),
                Some(inbound)
            );
            assert!(store.view_once_held(&rid, 10_000 + VIEW_ONCE_REVEAL_MS - 1));
            assert!(!store.view_once_held(&rid, 10_000 + VIEW_ONCE_REVEAL_MS));
            assert!(store.reveal_view_once(&rid, 40_000).is_none());
            assert_eq!(rows(&store, "messages")?, 0);
            assert_eq!(rows(&store, "outbox")?, 0);
            // decrypted pages: the logical content exported to a plaintext copy
            let export = TempDir::new("st17-export")?;
            let plain = export.path().join("plain.db");
            store.connection_kat().execute(
                "ATTACH DATABASE ?1 AS plain KEY ''",
                params![plain.to_string_lossy()],
            )?;
            store
                .connection_kat()
                .query_row("SELECT sqlcipher_export('plain')", [], |_| Ok(()))?;
            store
                .connection_kat()
                .execute_batch("DETACH DATABASE plain")?;
            let pages = std::fs::read(&plain)?;
            assert!(pages.starts_with(b"SQLite format 3\0"), "a plaintext copy");
            for c in [inbound, outbound] {
                assert!(!crate::kat::contains(&pages, c));
            }
        }
        let (hits, files, _bytes) = scan_dir(dir.path(), &[inbound, outbound], 8)?;
        assert!(files >= 2);
        assert!(hits.is_empty(), "{hits:?}");
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(store.take_view_once_lost()?, vec![sid]);
        assert!(store.take_view_once_lost()?.is_empty(), "reported once");
        assert!(
            store.outgoing_view_once(&sid).is_none(),
            "gone after the restart"
        );
        assert!(!store.view_once_held(&rid, 0));
        Ok(())
    }

    /// ST-18 (CS-3.4; §7.6 `expire_after`; OPEN-M7-09): a message with `expire_after` = 60 is present at +59 s and gone at
    /// +61 s; the default retention is to keep.
    #[test]
    fn expire_after_deletes() -> R {
        let dir = TempDir::new("st18")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(store.retention()?, Retention::Keep);
        let id = [0x18_u8; 16];
        store.insert_message(&NewMessage {
            contact_id: 7,
            msg_id: id,
            direction: Direction::In,
            kind: 1,
            ts_ms: 0,
            expire_after: 60,
            payload: b"expiring",
        })?;
        assert_eq!(store.expire_messages(59_000)?, 0);
        assert!(store.has_message(7, &id)?);
        assert_eq!(store.expire_messages(61_000)?, 1);
        assert!(!store.has_message(7, &id)?);
        Ok(())
    }

    /// G7-13 extra test (OPEN-M7-09): `retention_days` > 0 is `Days`, 0 is `Keep`, as is no setting.
    #[test]
    fn retention_setting_days_or_keep() -> R {
        let dir = TempDir::new("retention")?;
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(store.retention()?, Retention::Keep);
        let set = |d: i64| {
            store.connection_kat().execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('retention_days', ?1)",
                rusqlite::params![d],
            )
        };
        set(7)?;
        assert_eq!(store.retention()?, Retention::Days(7));
        set(1)?;
        assert_eq!(store.retention()?, Retention::Days(1));
        set(0)?;
        assert_eq!(store.retention()?, Retention::Keep);
        Ok(())
    }

    /// G7-13 extra test (CS-3.4): a received and an outgoing view-once are held apart by id and direction — revealing,
    /// holding and the outgoing payload each find only their own.
    #[test]
    fn view_once_lookups_by_id_and_direction() -> R {
        let dir = TempDir::new("view-once")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let (received, outgoing) = ([0x51_u8; 16], [0x52_u8; 16]);
        store.hold_received_view_once(received, b"in");
        store.queue_view_once(outgoing, b"out")?;
        assert_eq!(
            store.reveal_view_once(&outgoing, 0),
            None,
            "an outgoing one is not revealed"
        );
        assert!(!store.view_once_held(&outgoing, 0), "nor held as received");
        assert!(!store.view_once_held(&[0x53; 16], 0));
        assert_eq!(
            store.outgoing_view_once(&received),
            None,
            "a received one is not sent"
        );
        assert_eq!(
            store
                .outgoing_view_once(&outgoing)
                .as_deref()
                .map(Vec::as_slice),
            Some(b"out".as_slice())
        );
        assert_eq!(
            store
                .reveal_view_once(&received, 0)
                .as_deref()
                .map(Vec::as_slice),
            Some(b"in".as_slice())
        );
        assert!(store.view_once_held(&received, 0));
        Ok(())
    }
}
