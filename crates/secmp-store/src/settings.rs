// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `settings` rows (`docs/02:100`; OPEN-M7-09, OQ-10): key/value, no secret, inside the SQLCipher file only (Q139).
//! `retention_days` is an SQLite INTEGER (EXT1-3, Q177; read by [`crate::Store::retention`]); the other settings are
//! one byte each. The writes are statements of the caller's transaction ([`crate::Tx`]).

use rusqlite::params;

use crate::error::{Error, Result};
use crate::messages::Retention;
use crate::store::{Store, Tx};

/// The scheduler mode: 0 Strict, 1 Balanced, 2 Low-bandwidth (spec §10.2).
pub const KEY_MODE: &str = "mode";
/// Delivery receipts: 0 off, 1 for verified contacts only (the default), 2 for every contact (spec §10.4).
pub const KEY_RECEIPTS_DELIVERED: &str = "receipts_delivered";
/// Read receipts: 0 off (the default), 1 on.
pub const KEY_RECEIPTS_READ: &str = "receipts_read";

/// The one-byte settings, in the order of the keys above.
pub const BYTE_KEYS: [&str; 3] = [KEY_MODE, KEY_RECEIPTS_DELIVERED, KEY_RECEIPTS_READ];

/// Write the one-byte setting `key` (one of [`BYTE_KEYS`]).
///
/// # Errors
/// [`Error::Unavailable`] for another key or if the statement fails.
pub fn put_byte(tx: &mut Tx<'_>, key: &str, value: u8) -> Result<()> {
    if !BYTE_KEYS.contains(&key) {
        return Err(Error::Unavailable);
    }
    tx.exec(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, vec![value]],
    )?;
    Ok(())
}

/// Write the retention (`retention_days` as an INTEGER; [`Retention::Keep`] deletes the row).
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_retention(tx: &mut Tx<'_>, retention: Retention) -> Result<()> {
    match retention {
        Retention::Keep => {
            tx.exec(
                "DELETE FROM settings WHERE key = ?1",
                params!["retention_days"],
            )?;
        }
        Retention::Days(d) => {
            tx.exec(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params!["retention_days", i64::from(d)],
            )?;
        }
    }
    Ok(())
}

impl Store {
    /// The one-byte setting `key` (`None`: never set).
    ///
    /// # Errors
    /// [`Error::Unavailable`] for a key that is not one of [`BYTE_KEYS`], a value that is not one byte, or if the read
    /// fails.
    pub fn setting_byte(&self, key: &str) -> Result<Option<u8>> {
        if !BYTE_KEYS.contains(&key) {
            return Err(Error::Unavailable);
        }
        let v = self.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, Vec<u8>>(0),
        )?;
        match v.as_deref() {
            None => Ok(None),
            Some([b]) => Ok(Some(*b)),
            Some(_) => Err(Error::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{TempDir, TestKey};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// The settings round-trip: a byte setting and the retention survive a reopen; a key outside [`BYTE_KEYS`] and a value
    /// that is not one byte are the uniform `Unavailable`; `Keep` deletes the retention row.
    #[test]
    fn settings_round_trip() -> R {
        let dir = TempDir::new("settings-rt")?;
        {
            let mut store = Store::open(dir.path(), &TestKey::db_key())?;
            assert_eq!(store.setting_byte(KEY_MODE)?, None);
            assert_eq!(store.retention()?, Retention::Keep);
            store.txn(|tx| {
                put_byte(tx, KEY_MODE, 1)?;
                put_retention(tx, Retention::Days(7))
            })?;
            assert_eq!(
                store.txn(|tx| put_byte(tx, "theme", 1)),
                Err(Error::Unavailable)
            );
            assert_eq!(store.setting_byte("theme").err(), Some(Error::Unavailable));
        }
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(store.setting_byte(KEY_MODE)?, Some(1));
        assert_eq!(store.retention()?, Retention::Days(7));
        store
            .connection_kat()
            .execute("UPDATE settings SET value = x'0102' WHERE key = 'mode'", [])?;
        assert_eq!(store.setting_byte(KEY_MODE).err(), Some(Error::Unavailable));
        store.txn(|tx| put_retention(tx, Retention::Keep))?;
        assert_eq!(store.retention()?, Retention::Keep);
        Ok(())
    }

    /// Every byte key is in the backup's exclusion list (A4-1-04: a key is in exactly one list).
    #[test]
    fn byte_keys_are_excluded_from_backups() {
        for key in BYTE_KEYS {
            assert!(
                crate::backup::BACKUP_SETTINGS_EXCLUDED.contains(&key),
                "{key}"
            );
            assert!(!crate::backup::BACKUP_SETTINGS_KEYS.contains(&key), "{key}");
        }
    }
}
