// SPDX-License-Identifier: AGPL-3.0-or-later
//! The settings (`docs/02:100`; OPEN-M7-09, OQ-10): the scheduler mode, the history retention and the receipts. Key/value
//! rows of the `settings` table, no secret (Q139). The defaults of a fresh profile are the safe ones: Strict, keep the
//! history, delivery receipts for verified contacts only, read receipts off.

use secmp_store::messages::Retention as StoredRetention;
use secmp_store::settings::{
    KEY_MODE, KEY_RECEIPTS_DELIVERED, KEY_RECEIPTS_READ, put_byte, put_retention,
};

use crate::api::Error;
use crate::persist::SharedStore;
use crate::scheduler::params::Mode;

/// Whom the client sends delivery receipts to (spec §10.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveredReceipts {
    /// Nobody.
    Off,
    /// Verified contacts only (the default).
    VerifiedOnly,
    /// Every contact.
    All,
}

/// How long the history is kept (the `Api` names no store type; this is the settings' own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Keep forever (the default).
    Keep,
    /// Delete messages older than this many days.
    Days(u32),
}

impl From<StoredRetention> for Retention {
    fn from(r: StoredRetention) -> Self {
        match r {
            StoredRetention::Keep => Self::Keep,
            StoredRetention::Days(d) => Self::Days(d),
        }
    }
}

impl From<Retention> for StoredRetention {
    fn from(r: Retention) -> Self {
        match r {
            Retention::Keep => Self::Keep,
            Retention::Days(d) => Self::Days(d),
        }
    }
}

/// The settings of a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The scheduler mode.
    pub mode: Mode,
    /// How long the history is kept.
    pub retention: Retention,
    /// Delivery receipts.
    pub delivered_receipts: DeliveredReceipts,
    /// Read receipts.
    pub read_receipts: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Strict,
            retention: Retention::Keep,
            delivered_receipts: DeliveredReceipts::VerifiedOnly,
            read_receipts: false,
        }
    }
}

const fn mode_code(m: Mode) -> u8 {
    match m {
        Mode::Strict => 0,
        Mode::Balanced => 1,
        Mode::LowBw => 2,
    }
}

const fn delivered_code(d: DeliveredReceipts) -> u8 {
    match d {
        DeliveredReceipts::Off => 0,
        DeliveredReceipts::VerifiedOnly => 1,
        DeliveredReceipts::All => 2,
    }
}

impl Settings {
    /// The settings of the profile in `store` (a value never set is the default).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or holds a value no build writes.
    pub fn load(store: &SharedStore) -> Result<Self, Error> {
        let s = store.lock().map_err(|_| Error::Unavailable)?;
        let mode = match s.setting_byte(KEY_MODE)? {
            None | Some(0) => Mode::Strict,
            Some(1) => Mode::Balanced,
            Some(2) => Mode::LowBw,
            Some(_) => return Err(Error::Unavailable),
        };
        let delivered_receipts = match s.setting_byte(KEY_RECEIPTS_DELIVERED)? {
            Some(0) => DeliveredReceipts::Off,
            None | Some(1) => DeliveredReceipts::VerifiedOnly,
            Some(2) => DeliveredReceipts::All,
            Some(_) => return Err(Error::Unavailable),
        };
        let read_receipts = match s.setting_byte(KEY_RECEIPTS_READ)? {
            None | Some(0) => false,
            Some(1) => true,
            Some(_) => return Err(Error::Unavailable),
        };
        Ok(Self {
            mode,
            retention: s.retention()?.into(),
            delivered_receipts,
            read_receipts,
        })
    }

    /// Write all four settings in one store transaction.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be written (nothing is changed).
    pub fn save(&self, store: &SharedStore) -> Result<(), Error> {
        let mut s = store.lock().map_err(|_| Error::Unavailable)?;
        s.txn(|tx| {
            put_byte(tx, KEY_MODE, mode_code(self.mode))?;
            put_byte(
                tx,
                KEY_RECEIPTS_DELIVERED,
                delivered_code(self.delivered_receipts),
            )?;
            put_byte(tx, KEY_RECEIPTS_READ, u8::from(self.read_receipts))?;
            put_retention(tx, self.retention.into())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "kat")]
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "kat")]
    use secmp_store::Store;
    #[cfg(feature = "kat")]
    use secmp_store::kat::{TempDir, TestKey};

    #[cfg(feature = "kat")]
    use super::*;

    #[cfg(feature = "kat")]
    type R = Result<(), Box<dyn std::error::Error>>;

    /// PR-09 [O-09] (OQ-10; `docs/02:100`): a fresh profile has the defaults — Strict, keep forever, delivery receipts for
    /// verified contacts, read receipts off; Balanced and 7 days survive a reopen (and so does each other change).
    #[cfg(feature = "kat")]
    #[test]
    fn defaults_and_roundtrip() -> R {
        let dir = TempDir::new("pr09")?;
        {
            let store: SharedStore =
                Arc::new(Mutex::new(Store::open(dir.path(), &TestKey::db_key())?));
            let fresh = Settings::load(&store)?;
            assert_eq!(fresh.mode, Mode::Strict);
            assert_eq!(fresh.retention, Retention::Keep);
            assert_eq!(fresh.delivered_receipts, DeliveredReceipts::VerifiedOnly);
            assert!(!fresh.read_receipts);
            assert_eq!(fresh, Settings::default());
            Settings {
                mode: Mode::Balanced,
                retention: Retention::Days(7),
                delivered_receipts: DeliveredReceipts::All,
                read_receipts: true,
            }
            .save(&store)?;
        }
        let store: SharedStore = Arc::new(Mutex::new(Store::open(dir.path(), &TestKey::db_key())?));
        let back = Settings::load(&store)?;
        assert_eq!(back.mode, Mode::Balanced);
        assert_eq!(back.retention, Retention::Days(7));
        assert_eq!(back.delivered_receipts, DeliveredReceipts::All);
        assert!(back.read_receipts);
        for m in [Mode::Strict, Mode::Balanced, Mode::LowBw] {
            Settings { mode: m, ..back }.save(&store)?;
            assert_eq!(Settings::load(&store)?.mode, m);
        }
        for d in [DeliveredReceipts::Off, DeliveredReceipts::VerifiedOnly] {
            Settings {
                delivered_receipts: d,
                retention: Retention::Keep,
                ..back
            }
            .save(&store)?;
            let l = Settings::load(&store)?;
            assert_eq!((l.delivered_receipts, l.retention), (d, Retention::Keep));
        }
        Ok(())
    }

    /// A value no build writes is the uniform `Unavailable`, not a default.
    #[cfg(feature = "kat")]
    #[test]
    fn unknown_value_is_unavailable() -> R {
        let dir = TempDir::new("pr09-bad")?;
        let store: SharedStore = Arc::new(Mutex::new(Store::open(dir.path(), &TestKey::db_key())?));
        for key in ["mode", "receipts_delivered", "receipts_read"] {
            store.lock().map_err(|_| "lock")?.connection_kat().execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, x'09')",
                [key],
            )?;
            assert_eq!(
                Settings::load(&store).err(),
                Some(Error::Unavailable),
                "{key}"
            );
            store
                .lock()
                .map_err(|_| "lock")?
                .connection_kat()
                .execute("DELETE FROM settings", [])?;
        }
        Ok(())
    }
}
