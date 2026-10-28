// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real deletion (CS-3.4, `docs/04:55`: "real delete + `secure_delete`"): a deleted message's row is removed in one
//! transaction; with `secure_delete = ON` (set at every open, [`crate::store`]) SQLite overwrites the freed content with
//! zeros, in the log and, after a checkpoint, in the database file.

use rusqlite::params;

use crate::error::Result;
use crate::store::Store;

impl Store {
    /// Delete a message of the history; returns whether it existed.
    ///
    /// # Errors
    /// [`crate::Error::Unavailable`] if the write fails.
    pub fn delete_message(&mut self, contact_id: i64, msg_id: &[u8; 16]) -> Result<bool> {
        let n = self.txn(|tx| {
            tx.exec(
                "DELETE FROM messages WHERE contact_id = ?1 AND msg_id = ?2",
                params![contact_id, msg_id.as_slice()],
            )
        })?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::kat::{TempDir, TestKey, contains};
    use crate::messages::{Direction, NewMessage};
    use crate::store::Store;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// ST-16 (CS-3.4): a message with a canary is stored, deleted, the log checkpointed (`TRUNCATE`); the canary is in
    /// no decrypted page image, and `secure_delete` reads back 1. This SQLCipher build has no `sqlite_dbpage` (not
    /// compiled in: `libsqlite3-sys` 0.37.0 sets no `SQLITE_ENABLE_DBPAGE_VTAB`), so the page images are those of a
    /// `sqlcipher_export` to a plaintext copy, read page by page; the encrypted files are scanned too.
    #[test]
    fn secure_delete_removes_message() -> R {
        let dir = TempDir::new("st16")?;
        let canary: &[u8] = b"CANARY-MSG-a5a5c3c3e1e1f0f0 to be deleted";
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let has_dbpage: i64 = store.connection_kat().query_row(
            "SELECT count(*) FROM pragma_module_list WHERE name = 'sqlite_dbpage'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(
            has_dbpage, 0,
            "sqlite_dbpage is compiled in: use it instead (report the path)"
        );
        let id = [0x16_u8; 16];
        store.insert_message(&NewMessage {
            contact_id: 3,
            msg_id: id,
            direction: Direction::Out,
            kind: 1,
            ts_ms: 1,
            expire_after: 0,
            payload: canary,
        })?;
        // the positive control: before the delete the canary is in the decrypted pages
        let before = TempDir::new("st16-before")?;
        let plain_before = before.path().join("plain.db");
        store.connection_kat().execute(
            "ATTACH DATABASE ?1 AS plain KEY ''",
            rusqlite::params![plain_before.to_string_lossy()],
        )?;
        store
            .connection_kat()
            .query_row("SELECT sqlcipher_export('plain')", [], |_| Ok(()))?;
        store
            .connection_kat()
            .execute_batch("DETACH DATABASE plain")?;
        assert!(
            contains(&std::fs::read(&plain_before)?, canary),
            "control: the canary is stored"
        );
        assert!(store.delete_message(3, &id)?);
        let (_busy, _log, _done): (i64, i64, i64) =
            store
                .connection_kat()
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        let secure: i64 = store
            .connection_kat()
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))?;
        assert_eq!(secure, 1);
        let export = TempDir::new("st16-export")?;
        let plain = export.path().join("plain.db");
        store.connection_kat().execute(
            "ATTACH DATABASE ?1 AS plain KEY ''",
            rusqlite::params![plain.to_string_lossy()],
        )?;
        store
            .connection_kat()
            .query_row("SELECT sqlcipher_export('plain')", [], |_| Ok(()))?;
        store
            .connection_kat()
            .execute_batch("DETACH DATABASE plain")?;
        let image = std::fs::read(&plain)?;
        assert!(image.starts_with(b"SQLite format 3\0"));
        let page = usize::from(u16::from_be_bytes([
            image.get(16).copied().unwrap_or(0x10),
            image.get(17).copied().unwrap_or(0),
        ]));
        assert!(page >= 512);
        assert!(image.chunks(page).all(|p| !contains(p, canary)));
        assert!(!contains(&image, canary));
        for f in ["profile.db", "profile.db-wal"] {
            let bytes = std::fs::read(dir.path().join(f)).unwrap_or_default();
            assert!(!contains(&bytes, canary), "{f}");
        }
        Ok(())
    }
}
