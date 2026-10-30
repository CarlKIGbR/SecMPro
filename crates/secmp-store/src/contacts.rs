// SPDX-License-Identifier: AGPL-3.0-or-later
//! The contact rows (`docs/02:95`): the peer's `IKSPublic`, its fingerprint, the user's own name for it
//! (`display_name`), the verified flag, routes, queues, the state and the peer's `Profile` (D.3; Q143). No column is
//! secret: `contacts` lies inside the SQLCipher file only (Q139). The writes are statements of the caller's
//! transaction ([`crate::Tx`]).

use rusqlite::params;

use crate::error::{Error, Result};
use crate::store::{Store, Tx};

/// The state of a contact with a session (or one being set up).
pub const STATE_ACTIVE: i64 = 0;
/// The state of a restored contact (CS-3.5; Q142): no session, the contact must be re-invited before anything is sent.
pub const STATE_REINVITE_REQUIRED: i64 = 1;

/// One contact row.
pub struct Contact<'a> {
    /// The row id.
    pub id: i64,
    /// The peer's `IKSPublic`.
    pub iks: &'a [u8],
    /// The peer's fingerprint.
    pub fingerprint: &'a [u8],
    /// The user's own name for the contact.
    pub display_name: Option<&'a str>,
    /// The verified flag.
    pub verified: bool,
    /// The routes.
    pub routes: Option<&'a [u8]>,
    /// The queues.
    pub queues: Option<&'a [u8]>,
    /// The state ([`STATE_ACTIVE`], [`STATE_REINVITE_REQUIRED`]).
    pub state: i64,
    /// The peer's `Profile` (D.3 encoding; Q143).
    pub profile: Option<&'a [u8]>,
}

/// A contact row as read back: its id, its `IKSPublic`, the verified flag, the user's name for it, the state and the
/// peer's `Profile`.
pub struct StoredContact {
    /// The row id.
    pub id: i64,
    /// The peer's `IKSPublic`.
    pub iks: Vec<u8>,
    /// The verified flag.
    pub verified: bool,
    /// The user's own name for the contact.
    pub display_name: Option<String>,
    /// The state.
    pub state: i64,
    /// The peer's `Profile` (D.3 encoding).
    pub profile: Option<Vec<u8>>,
}

/// Write a contact row.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_contact(tx: &mut Tx<'_>, c: &Contact<'_>) -> Result<()> {
    tx.exec(
        "INSERT INTO contacts (id, iks, fingerprint, display_name, verified, routes, queues, state, profile) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
         ON CONFLICT (id) DO UPDATE SET iks = excluded.iks, fingerprint = excluded.fingerprint, \
         display_name = excluded.display_name, verified = excluded.verified, routes = excluded.routes, \
         queues = excluded.queues, state = excluded.state, profile = excluded.profile",
        params![
            c.id,
            c.iks,
            c.fingerprint,
            c.display_name,
            i64::from(c.verified),
            c.routes,
            c.queues,
            c.state,
            c.profile
        ],
    )?;
    Ok(())
}

impl Store {
    /// Every contact, by id.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn contacts(&self) -> Result<Vec<StoredContact>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, iks, verified, display_name, state, profile FROM contacts ORDER BY id",
            )
            .map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredContact {
                    id: r.get(0)?,
                    iks: r.get(1)?,
                    verified: r.get::<_, i64>(2)? != 0,
                    display_name: r.get(3)?,
                    state: r.get(4)?,
                    profile: r.get(5)?,
                })
            })
            .map_err(|_| Error::Unavailable)?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(|_| Error::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::kat::{TempDir, TestKey};
    use crate::store::Store;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// A4-1-07: a failing read of `contacts` is the uniform `Unavailable` (the table renamed away under the store).
    #[test]
    fn contacts_read_failure_is_unavailable() -> R {
        let dir = TempDir::new("contacts-fail")?;
        let store = Store::open(dir.path(), &TestKey::db_key())?;
        assert_eq!(store.contacts()?.len(), 0);
        store
            .connection_kat()
            .execute_batch("ALTER TABLE contacts RENAME TO c2")?;
        assert_eq!(store.contacts().err(), Some(Error::Unavailable));
        Ok(())
    }
}
