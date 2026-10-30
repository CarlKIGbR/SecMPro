// SPDX-License-Identifier: AGPL-3.0-or-later
//! The rows of the identity, the prekeys, the relays and the invitations (`docs/02` §4.2 `:90-100`; the contacts:
//! [`crate::contacts`]). The secret column of each (Q139: `identity.secret`, `prekeys.secret`, `relays.access_key`,
//! `invitations.record`) is sealed per record ([`crate::seal`], ADR-053 item 5) under its row: `identity` (`id`),
//! `prekeys` (`kind`, `id`), `relays` (`id`), `invitations` (`ld_id`). The writes are statements of the caller's
//! transaction ([`crate::Tx`]).

use rusqlite::params;
use secmp_crypto::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::Table;
use crate::seal::{KeyPart, row_key};
use crate::store::{Store, Tx};

fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::Unavailable)
}

/// Write the identity row `id`: `secret` sealed (the identity section, Q143).
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails.
pub fn put_identity(
    tx: &mut Tx<'_>,
    id: i64,
    secret: &[u8],
    fingerprint: &[u8],
    created_ms: u64,
) -> Result<()> {
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(
        Table::Identity,
        "secret",
        &row_key(&[KeyPart::Int(id)])?,
        secret,
    )?;
    tx.exec(
        "INSERT INTO identity (id, secret, fingerprint, created_ms) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (id) DO UPDATE SET secret = excluded.secret, fingerprint = excluded.fingerprint, \
         created_ms = excluded.created_ms",
        params![id, sealed, fingerprint, i64_of(created_ms)?],
    )?;
    Ok(())
}

/// Insert the prekey (`kind`, `id`): `secret` sealed.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails (also if the prekey exists).
pub fn insert_prekey(
    tx: &mut Tx<'_>,
    kind: i64,
    id: i64,
    secret: &[u8],
    expires_ms: Option<u64>,
) -> Result<()> {
    let rk = row_key(&[KeyPart::Int(kind), KeyPart::Int(id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(Table::Prekeys, "secret", &rk, secret)?;
    let expires = expires_ms.map(i64_of).transpose()?;
    tx.exec(
        "INSERT INTO prekeys (kind, id, secret, expires_ms) VALUES (?1, ?2, ?3, ?4)",
        params![kind, id, sealed, expires],
    )?;
    Ok(())
}

/// Write the relay row `id`: `access_key` sealed.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails.
pub fn put_relay(
    tx: &mut Tx<'_>,
    id: i64,
    relay_ref: &[u8],
    access_key: Option<&[u8]>,
) -> Result<()> {
    let rk = row_key(&[KeyPart::Int(id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = access_key
        .map(|k| tx.seal(Table::Relays, "access_key", &rk, k))
        .transpose()?;
    tx.exec(
        "INSERT INTO relays (id, relay_ref, access_key) VALUES (?1, ?2, ?3) \
         ON CONFLICT (id) DO UPDATE SET relay_ref = excluded.relay_ref, access_key = excluded.access_key",
        params![id, relay_ref, sealed],
    )?;
    Ok(())
}

/// Insert the invitation `ld_id`: `record` sealed.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails (also if it exists).
pub fn insert_invitation(
    tx: &mut Tx<'_>,
    ld_id: &[u8],
    record: &[u8],
    expires_ms: u64,
) -> Result<()> {
    let rk = row_key(&[KeyPart::Bytes(ld_id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(Table::Invitations, "record", &rk, record)?;
    tx.exec(
        "INSERT INTO invitations (ld_id, record, expires_ms) VALUES (?1, ?2, ?3)",
        params![ld_id, sealed, i64_of(expires_ms)?],
    )?;
    Ok(())
}

impl Store {
    /// The one sealed column `sql` selects (`None`: no row or a NULL column), opened under (`table`, `column`, `rk`).
    fn read_sealed<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
        (table, column, rk): (Table, &str, &[u8]),
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let sealed = match self
            .conn
            .query_row(sql, params, |r| r.get::<_, Option<Vec<u8>>>(0))
        {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(_) => return Err(Error::Unavailable),
        };
        // spec §3.4; ADR-053 item 5
        sealed
            .map(|s| self.open_record(table, column, rk, &s))
            .transpose()
    }

    /// The identity section of the identity row `id`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn identity_secret(&self, id: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let rk = row_key(&[KeyPart::Int(id)])?;
        self.read_sealed(
            "SELECT secret FROM identity WHERE id = ?1",
            params![id],
            (Table::Identity, "secret", &rk),
        )
    }

    /// The secret of the prekey (`kind`, `id`).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn prekey_secret(&self, kind: i64, id: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let rk = row_key(&[KeyPart::Int(kind), KeyPart::Int(id)])?;
        self.read_sealed(
            "SELECT secret FROM prekeys WHERE kind = ?1 AND id = ?2",
            params![kind, id],
            (Table::Prekeys, "secret", &rk),
        )
    }

    /// The access key of the relay row `id`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn relay_access_key(&self, id: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let rk = row_key(&[KeyPart::Int(id)])?;
        self.read_sealed(
            "SELECT access_key FROM relays WHERE id = ?1",
            params![id],
            (Table::Relays, "access_key", &rk),
        )
    }

    /// The record of the invitation `ld_id`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn invitation_record(&self, ld_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let rk = row_key(&[KeyPart::Bytes(ld_id)])?;
        self.read_sealed(
            "SELECT record FROM invitations WHERE ld_id = ?1",
            params![ld_id],
            (Table::Invitations, "record", &rk),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{TempDir, TestKey};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// The profile rows round-trip (extra test): each sealed column reads back as written, a missing row is `None`, a
    /// record copied to another row does not open (the uniform error).
    #[test]
    fn profile_rows_round_trip() -> R {
        let dir = TempDir::new("profile-rows")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| {
            put_identity(tx, 1, b"identity section", b"fp", 5)?;
            insert_prekey(tx, 1, 7, b"spk seed", Some(9))?;
            insert_prekey(tx, 2, 7, b"opk seed", None)?;
            put_relay(tx, 3, b"relay", Some(b"access"))?;
            put_relay(tx, 4, b"relay without key", None)?;
            insert_invitation(tx, &[5; 16], b"invitation record", 100)
        })?;
        let read = |v: Option<Zeroizing<Vec<u8>>>| v.map(|z| z.to_vec());
        assert_eq!(
            read(store.identity_secret(1)?),
            Some(b"identity section".to_vec())
        );
        assert_eq!(read(store.prekey_secret(1, 7)?), Some(b"spk seed".to_vec()));
        assert_eq!(read(store.prekey_secret(2, 7)?), Some(b"opk seed".to_vec()));
        assert_eq!(read(store.relay_access_key(3)?), Some(b"access".to_vec()));
        assert_eq!(read(store.relay_access_key(4)?), None);
        assert_eq!(
            read(store.invitation_record(&[5; 16])?),
            Some(b"invitation record".to_vec())
        );
        assert_eq!(read(store.identity_secret(2)?), None);
        store.connection_kat().execute(
            "UPDATE prekeys SET secret = (SELECT secret FROM prekeys WHERE kind = 1 AND id = 7) WHERE kind = 2",
            [],
        )?;
        assert_eq!(store.prekey_secret(2, 7).err(), Some(Error::Unavailable));
        Ok(())
    }

    /// Killer (A-4 mutant, `i64_of`): the times are stored as given, and a time beyond `i64` is refused.
    #[test]
    fn times_stored_as_given() -> R {
        let dir = TempDir::new("profile-times")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| {
            put_identity(tx, 1, b"s", b"fp", 5)?;
            insert_prekey(tx, 1, 1, b"s", Some(9))?;
            insert_invitation(tx, &[5; 16], b"r", 11)
        })?;
        let read = |sql: &str| -> core::result::Result<i64, Box<dyn std::error::Error>> {
            Ok(store.connection_kat().query_row(sql, [], |r| r.get(0))?)
        };
        assert_eq!(read("SELECT created_ms FROM identity")?, 5);
        assert_eq!(read("SELECT expires_ms FROM prekeys")?, 9);
        assert_eq!(read("SELECT expires_ms FROM invitations")?, 11);
        assert_eq!(
            store.txn(|tx| put_identity(tx, 2, b"s", b"fp", u64::MAX)),
            Err(Error::Unavailable)
        );
        Ok(())
    }
}
