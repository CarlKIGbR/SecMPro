// SPDX-License-Identifier: AGPL-3.0-or-later
//! The contact rows (`docs/02:95`): the peer's `IKSPublic`, its fingerprint, the user's own name for it
//! (`display_name`), the verified flag, routes, queues, the state and the peer's `Profile` (D.3; Q143). `routes` and
//! `queues` hold queue capabilities (sender seeds) and are sealed per record (Q151, ADR-053 item 5: `contacts` (`id`));
//! the other columns lie inside the SQLCipher file only (Q139). The writes are statements of the caller's transaction
//! ([`crate::Tx`]).

use rusqlite::params;
use secmp_crypto::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::Table;
use crate::seal::{KeyPart, row_key};
use crate::store::{Store, Tx};

/// The state of a contact with a session (or one being set up).
pub const STATE_ACTIVE: i64 = 0;
/// The state of a restored contact (CS-3.5; Q142): no session, the contact must be re-invited before anything is sent.
pub const STATE_REINVITE_REQUIRED: i64 = 1;
/// The state of a contact that sent `Control{ContactRemoved}` (spec §7.6 code 1): no real message is sent to it.
pub const STATE_REMOVED: i64 = 2;

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
    /// The state ([`STATE_ACTIVE`], [`STATE_REINVITE_REQUIRED`], [`STATE_REMOVED`]).
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
    /// The peer's fingerprint.
    pub fingerprint: Vec<u8>,
    /// The verified flag.
    pub verified: bool,
    /// The user's own name for the contact.
    pub display_name: Option<String>,
    /// The state.
    pub state: i64,
    /// The peer's `Profile` (D.3 encoding).
    pub profile: Option<Vec<u8>>,
}

/// Write a contact row; `routes` and `queues` are sealed (Q151).
///
/// # Errors
/// [`Error::Unavailable`] if a seal or the statement fails.
pub fn put_contact(tx: &mut Tx<'_>, c: &Contact<'_>) -> Result<()> {
    let rk = row_key(&[KeyPart::Int(c.id)])?;
    // spec §3.4; ADR-053 item 5
    let routes = c
        .routes
        .map(|r| tx.seal(Table::Contacts, "routes", &rk, r))
        .transpose()?;
    // spec §3.4; ADR-053 item 5
    let queues = c
        .queues
        .map(|q| tx.seal(Table::Contacts, "queues", &rk, q))
        .transpose()?;
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
            routes,
            queues,
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
                "SELECT id, iks, fingerprint, verified, display_name, state, profile FROM contacts ORDER BY id",
            )
            .map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredContact {
                    id: r.get(0)?,
                    iks: r.get(1)?,
                    fingerprint: r.get(2)?,
                    verified: r.get::<_, i64>(3)? != 0,
                    display_name: r.get(4)?,
                    state: r.get(5)?,
                    profile: r.get(6)?,
                })
            })
            .map_err(|_| Error::Unavailable)?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(|_| Error::Unavailable)
    }

    /// The sealed column `column` (`routes` or `queues`) of contact `id` (`None`: no row or no value).
    fn contact_sealed(&self, id: i64, column: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let sql = if column == "routes" {
            "SELECT routes FROM contacts WHERE id = ?1"
        } else {
            "SELECT queues FROM contacts WHERE id = ?1"
        };
        let sealed = self
            .query_row(sql, params![id], |r| r.get::<_, Option<Vec<u8>>>(0))?
            .flatten();
        let rk = row_key(&[KeyPart::Int(id)])?;
        // spec §3.4; ADR-053 item 5
        sealed
            .map(|s| self.open_record(Table::Contacts, column, &rk, &s))
            .transpose()
    }

    /// The routes of contact `id` (the peer's reply routes, Q151).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn contact_routes(&self, id: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.contact_sealed(id, "routes")
    }

    /// The queues of contact `id` (Q151).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn contact_queues(&self, id: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.contact_sealed(id, "queues")
    }
}

/// Replace the routes of contact `id` (sealed, Q151) as a statement of the caller's transaction.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails or there is no such contact.
pub fn put_contact_routes(tx: &mut Tx<'_>, id: i64, routes: &[u8]) -> Result<()> {
    let rk = row_key(&[KeyPart::Int(id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(Table::Contacts, "routes", &rk, routes)?;
    let n = tx.exec(
        "UPDATE contacts SET routes = ?2 WHERE id = ?1",
        params![id, sealed],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Replace the queues of contact `id` (sealed, Q151) as a statement of the caller's transaction.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails or there is no such contact.
pub fn put_contact_queues(tx: &mut Tx<'_>, id: i64, queues: &[u8]) -> Result<()> {
    let rk = row_key(&[KeyPart::Int(id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(Table::Contacts, "queues", &rk, queues)?;
    let n = tx.exec(
        "UPDATE contacts SET queues = ?2 WHERE id = ?1",
        params![id, sealed],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Set the state of contact `id`.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such contact.
pub fn set_contact_state(tx: &mut Tx<'_>, id: i64, state: i64) -> Result<()> {
    let n = tx.exec(
        "UPDATE contacts SET state = ?2 WHERE id = ?1",
        params![id, state],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Replace the identity of contact `id` after an accepted key change (spec §7.7): the new `IKSPublic` and its
/// fingerprint; the contact is unverified again.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such contact.
pub fn put_contact_identity(
    tx: &mut Tx<'_>,
    id: i64,
    iks: &[u8],
    fingerprint: &[u8],
) -> Result<()> {
    let n = tx.exec(
        "UPDATE contacts SET iks = ?2, fingerprint = ?3, verified = 0 WHERE id = ?1",
        params![id, iks, fingerprint],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Set the verified flag of contact `id`.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such contact.
pub fn set_contact_verified(tx: &mut Tx<'_>, id: i64, verified: bool) -> Result<()> {
    let n = tx.exec(
        "UPDATE contacts SET verified = ?2 WHERE id = ?1",
        params![id, i64::from(verified)],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// The next free contact id (`max(id) + 1`, 1 for the first).
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or the id space is exhausted.
pub fn next_contact_id(tx: &mut Tx<'_>) -> Result<i64> {
    let max = tx
        .query_row("SELECT max(id) FROM contacts", [], |r| {
            r.get::<_, Option<i64>>(0)
        })?
        .flatten()
        .unwrap_or(0);
    max.checked_add(1).ok_or(Error::Unavailable)
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::kat::{TempDir, TestKey};
    use crate::store::Store;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// Q151 (extra test): `routes` and `queues` are sealed per record — they read back as written, are 72 bytes longer in
    /// the file and do not contain their plaintext, a record moved to another contact does not open; the state and the
    /// verified flag are updated in place; the next id follows the largest.
    #[test]
    fn routes_and_queues_are_sealed() -> R {
        use super::{
            Contact, STATE_ACTIVE, STATE_REMOVED, next_contact_id, put_contact, set_contact_state,
            set_contact_verified,
        };
        use crate::kat::contains;
        use crate::seal::SEAL_OVERHEAD;

        let dir = TempDir::new("contacts-sealed")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        let routes = b"routes canary: a sender capability".to_vec();
        let queues = b"queues canary: a recipient seed".to_vec();
        assert_eq!(store.txn(next_contact_id)?, 1);
        store.txn(|tx| {
            for id in [1, 2] {
                put_contact(
                    tx,
                    &Contact {
                        id,
                        iks: b"iks",
                        fingerprint: b"fp",
                        display_name: Some("peer"),
                        verified: false,
                        routes: Some(&routes),
                        queues: (id == 1).then_some(queues.as_slice()),
                        state: STATE_ACTIVE,
                        profile: None,
                    },
                )?;
            }
            Ok(())
        })?;
        assert_eq!(store.txn(next_contact_id)?, 3);
        let read = |v: Option<secmp_crypto::Zeroizing<Vec<u8>>>| v.map(|z| z.to_vec());
        assert_eq!(read(store.contact_routes(1)?), Some(routes.clone()));
        assert_eq!(read(store.contact_queues(1)?), Some(queues.clone()));
        assert_eq!(read(store.contact_queues(2)?), None);
        assert_eq!(read(store.contact_routes(9)?), None);
        for (column, plain) in [("routes", &routes), ("queues", &queues)] {
            let raw: Vec<u8> = store.connection_kat().query_row(
                &format!("SELECT {column} FROM contacts WHERE id = 1"),
                [],
                |r| r.get(0),
            )?;
            assert_eq!(raw.len(), plain.len() + SEAL_OVERHEAD, "{column}");
            assert!(!contains(&raw, plain), "{column}: plaintext inside");
        }
        store.connection_kat().execute(
            "UPDATE contacts SET routes = (SELECT routes FROM contacts WHERE id = 1) WHERE id = 2",
            [],
        )?;
        assert_eq!(
            store.contact_routes(2).err(),
            Some(Error::Unavailable),
            "moved to another row"
        );

        store.txn(|tx| {
            set_contact_state(tx, 1, STATE_REMOVED)?;
            set_contact_verified(tx, 1, true)
        })?;
        let all = store.contacts()?;
        assert_eq!(all.len(), 2);
        assert!(
            all.first()
                .is_some_and(|c| c.verified && c.state == STATE_REMOVED)
        );
        assert!(
            all.get(1)
                .is_some_and(|c| !c.verified && c.state == STATE_ACTIVE)
        );
        assert_eq!(
            all.first().map(|c| c.fingerprint.clone()),
            Some(b"fp".to_vec())
        );
        assert_eq!(
            store.txn(|tx| set_contact_state(tx, 9, 0)),
            Err(Error::Unavailable)
        );
        assert_eq!(
            store.txn(|tx| set_contact_verified(tx, 9, true)),
            Err(Error::Unavailable)
        );
        Ok(())
    }

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

    /// B-4 (killers of `put_contact_routes`, `put_contact_queues`, `put_contact_identity`): the updates of a contact row are
    /// statements of the caller's transaction; the sealed columns read back through their getters, the identity through the
    /// list; an unknown contact is the uniform error and another contact's row is not touched.
    #[test]
    fn contact_row_updates() -> R {
        use super::{
            Contact, STATE_ACTIVE, put_contact, put_contact_identity, put_contact_queues,
            put_contact_routes,
        };

        let dir = TempDir::new("contacts-updates")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| {
            for id in [1, 2] {
                put_contact(
                    tx,
                    &Contact {
                        id,
                        iks: b"iks-old",
                        fingerprint: b"fp-old",
                        display_name: None,
                        verified: false,
                        routes: Some(b"routes-old"),
                        queues: Some(b"queues-old"),
                        state: STATE_ACTIVE,
                        profile: None,
                    },
                )?;
            }
            Ok(())
        })?;
        store.txn(|tx| {
            put_contact_routes(tx, 1, b"routes-new")?;
            put_contact_queues(tx, 1, b"queues-new")?;
            put_contact_identity(tx, 1, b"iks-new", b"fp-new")
        })?;
        let read = |v: Option<secmp_crypto::Zeroizing<Vec<u8>>>| v.map(|z| z.to_vec());
        assert_eq!(read(store.contact_routes(1)?), Some(b"routes-new".to_vec()));
        assert_eq!(read(store.contact_queues(1)?), Some(b"queues-new".to_vec()));
        let rows = store.contacts()?;
        let first = rows.first().ok_or("row 1")?;
        assert_eq!(
            (first.iks.clone(), first.fingerprint.clone()),
            (b"iks-new".to_vec(), b"fp-new".to_vec())
        );
        // the other contact is as it was
        let second = rows.get(1).ok_or("row 2")?;
        assert_eq!(
            (second.iks.clone(), second.fingerprint.clone()),
            (b"iks-old".to_vec(), b"fp-old".to_vec())
        );
        assert_eq!(read(store.contact_routes(2)?), Some(b"routes-old".to_vec()));
        assert_eq!(read(store.contact_queues(2)?), Some(b"queues-old".to_vec()));
        // an unknown contact
        assert_eq!(
            store.txn(|tx| put_contact_routes(tx, 9, b"x")),
            Err(Error::Unavailable)
        );
        assert_eq!(
            store.txn(|tx| put_contact_queues(tx, 9, b"x")),
            Err(Error::Unavailable)
        );
        assert_eq!(
            store.txn(|tx| put_contact_identity(tx, 9, b"x", b"y")),
            Err(Error::Unavailable)
        );
        Ok(())
    }
}
