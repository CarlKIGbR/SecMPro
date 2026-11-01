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

/// The `kind` of a signed-prekey row of `prekeys` (§6.1: `SPK_dh`, `SPK_kem` and `RPK_kem` in one secret).
pub const KIND_SPK: i64 = 1;
/// The `kind` of a one-time-prekey row of `prekeys`.
pub const KIND_OPK: i64 = 2;

/// The `status` of an invitation not yet used (`invitations.status`).
pub const INVITATION_OPEN: i64 = 0;
/// The `status` of an invitation whose handshake was accepted (§5.2 "until the invitation is consumed").
pub const INVITATION_CONSUMED: i64 = 1;

/// Set the counter `key` of `meta` (a public value, e.g. `opk_next`: the next one-time prekey id, never reused, OPEN-M7-B-10)
/// as a statement of the caller's transaction.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails.
pub fn put_meta_u32(tx: &mut Tx<'_>, key: &str, value: u32) -> Result<()> {
    tx.exec(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value.to_be_bytes().to_vec()],
    )?;
    Ok(())
}

/// Delete the prekey (`kind`, `id`); with `secure_delete` on, its pages are overwritten.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such row.
pub fn delete_prekey(tx: &mut Tx<'_>, kind: i64, id: i64) -> Result<()> {
    let n = tx.exec(
        "DELETE FROM prekeys WHERE kind = ?1 AND id = ?2",
        params![kind, id],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Set the status of the invitation `ld_id`.
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such row.
pub fn set_invitation_status(tx: &mut Tx<'_>, ld_id: &[u8], status: i64) -> Result<()> {
    let n = tx.exec(
        "UPDATE invitations SET status = ?2 WHERE ld_id = ?1",
        params![ld_id, status],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Delete the invitation `ld_id` (its record, its status and its retained cells).
///
/// # Errors
/// [`Error::Unavailable`] if the statement fails or there is no such row.
pub fn delete_invitation(tx: &mut Tx<'_>, ld_id: &[u8]) -> Result<()> {
    let n = tx.exec("DELETE FROM invitations WHERE ld_id = ?1", params![ld_id])?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Write the cells that invitation `ld_id` retains between fetch rounds (Q149): sealed (`invitations.retained`), or
/// cleared with `None`.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails or there is no such invitation.
pub fn put_invitation_retained(
    tx: &mut Tx<'_>,
    ld_id: &[u8],
    retained: Option<&[u8]>,
) -> Result<()> {
    let rk = row_key(&[KeyPart::Bytes(ld_id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = retained
        .map(|r| tx.seal(Table::Invitations, "retained", &rk, r))
        .transpose()?;
    let n = tx.exec(
        "UPDATE invitations SET retained = ?2 WHERE ld_id = ?1",
        params![ld_id, sealed],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Write the spare-queue pool of the relay row `id` (Q151): sealed (`relays.pool`), or cleared with `None`.
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails or there is no such relay.
pub fn put_relay_pool(tx: &mut Tx<'_>, id: i64, pool: Option<&[u8]>) -> Result<()> {
    let rk = row_key(&[KeyPart::Int(id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = pool
        .map(|p| tx.seal(Table::Relays, "pool", &rk, p))
        .transpose()?;
    let n = tx.exec(
        "UPDATE relays SET pool = ?2 WHERE id = ?1",
        params![id, sealed],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Replace the sealed record of the invitation `ld_id` (`invitations.record`).
///
/// # Errors
/// [`Error::Unavailable`] if the seal or the statement fails or there is no such invitation.
pub fn put_invitation_record(tx: &mut Tx<'_>, ld_id: &[u8], record: &[u8]) -> Result<()> {
    let rk = row_key(&[KeyPart::Bytes(ld_id)])?;
    // spec §3.4; ADR-053 item 5
    let sealed = tx.seal(Table::Invitations, "record", &rk, record)?;
    let n = tx.exec(
        "UPDATE invitations SET record = ?2 WHERE ld_id = ?1",
        params![ld_id, sealed],
    )?;
    if n == 1 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// A prekey row as listed (never its secret).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrekeyRow {
    /// The prekey id (`spk_id`, `opk_id`).
    pub id: i64,
    /// Unix ms at which it expires (`None`: single use, no time).
    pub expires_ms: Option<u64>,
}

/// An invitation row as listed (never its record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRow {
    /// The link-data id.
    pub ld_id: Vec<u8>,
    /// Unix ms at which it expires.
    pub expires_ms: u64,
    /// [`INVITATION_OPEN`] or [`INVITATION_CONSUMED`].
    pub status: i64,
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

    /// The spare-queue pool of the relay row `id`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn relay_pool(&self, id: i64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let rk = row_key(&[KeyPart::Int(id)])?;
        self.read_sealed(
            "SELECT pool FROM relays WHERE id = ?1",
            params![id],
            (Table::Relays, "pool", &rk),
        )
    }

    /// The cells invitation `ld_id` retains.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read or the open fails.
    pub fn invitation_retained(&self, ld_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let rk = row_key(&[KeyPart::Bytes(ld_id)])?;
        self.read_sealed(
            "SELECT retained FROM invitations WHERE ld_id = ?1",
            params![ld_id],
            (Table::Invitations, "retained", &rk),
        )
    }

    /// The rows of `prekeys` of `kind`, by id.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn prekeys(&self, kind: i64) -> Result<Vec<PrekeyRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, expires_ms FROM prekeys WHERE kind = ?1 ORDER BY id")
            .map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map(params![kind], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .map_err(|_| Error::Unavailable)?;
        rows.map(|r| {
            let (id, expires) = r.map_err(|_| Error::Unavailable)?;
            let expires_ms = expires
                .map(|e| u64::try_from(e).map_err(|_| Error::Unavailable))
                .transpose()?;
            Ok(PrekeyRow { id, expires_ms })
        })
        .collect()
    }

    /// The invitations, by `ld_id`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn invitations(&self) -> Result<Vec<InvitationRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ld_id, expires_ms, status FROM invitations ORDER BY ld_id")
            .map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| Error::Unavailable)?;
        rows.map(|r| {
            let (ld_id, expires, status) = r.map_err(|_| Error::Unavailable)?;
            Ok(InvitationRow {
                ld_id,
                expires_ms: u64::try_from(expires).map_err(|_| Error::Unavailable)?,
                status,
            })
        })
        .collect()
    }

    /// The relay reference of the relay row `id` (a public value: the `RelayRef` of spec §5.3).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn relay_ref(&self, id: i64) -> Result<Option<Vec<u8>>> {
        self.query_row(
            "SELECT relay_ref FROM relays WHERE id = ?1",
            params![id],
            |r| r.get::<_, Vec<u8>>(0),
        )
    }

    /// The fingerprint column of the identity row `id` (a public value).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn identity_fingerprint(&self, id: i64) -> Result<Option<Vec<u8>>> {
        self.query_row(
            "SELECT fingerprint FROM identity WHERE id = ?1",
            params![id],
            |r| r.get::<_, Vec<u8>>(0),
        )
    }

    /// The counter `key` of `meta` ([`put_meta_u32`]); `None` if it was never set or is not four bytes.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn meta_u32(&self, key: &str) -> Result<Option<u32>> {
        let raw = self.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        Ok(raw
            .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
            .map(u32::from_be_bytes))
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

    /// B-1…B-2 rows (extra test): the prekeys list by id with their expiry; a prekey is deleted once (a second delete and a
    /// delete of a missing row are the uniform error); an invitation's status, its sealed record and its sealed retained
    /// cells are updated in place and read back, a cleared column reads `None`; the relay pool is sealed like the access
    /// key; the lists carry no secret.
    #[test]
    fn lifecycle_rows() -> R {
        let dir = TempDir::new("profile-lifecycle")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| {
            insert_prekey(tx, KIND_SPK, 2, b"spk 2", Some(2000))?;
            insert_prekey(tx, KIND_SPK, 1, b"spk 1", Some(1000))?;
            insert_prekey(tx, KIND_OPK, 1, b"opk 1", None)?;
            put_relay(tx, 3, b"relay ref", None)?;
            insert_invitation(tx, &[5; 16], b"record", 100)?;
            insert_invitation(tx, &[4; 16], b"other", 200)
        })?;
        assert_eq!(
            store.prekeys(KIND_SPK)?,
            [
                PrekeyRow {
                    id: 1,
                    expires_ms: Some(1000)
                },
                PrekeyRow {
                    id: 2,
                    expires_ms: Some(2000)
                }
            ]
        );
        assert_eq!(
            store.prekeys(KIND_OPK)?,
            [PrekeyRow {
                id: 1,
                expires_ms: None
            }]
        );
        assert_eq!(store.relay_ref(3)?, Some(b"relay ref".to_vec()));
        assert_eq!(store.relay_ref(4)?, None);
        let rows = store.invitations()?;
        assert_eq!(
            rows,
            [
                InvitationRow {
                    ld_id: vec![4; 16],
                    expires_ms: 200,
                    status: INVITATION_OPEN
                },
                InvitationRow {
                    ld_id: vec![5; 16],
                    expires_ms: 100,
                    status: INVITATION_OPEN
                }
            ]
        );

        store.txn(|tx| {
            delete_prekey(tx, KIND_SPK, 1)?;
            set_invitation_status(tx, &[5; 16], INVITATION_CONSUMED)?;
            put_invitation_retained(tx, &[5; 16], Some(b"cells"))?;
            put_invitation_record(tx, &[4; 16], b"replaced record")?;
            put_relay_pool(tx, 3, Some(b"pool"))
        })?;
        assert_eq!(store.prekeys(KIND_SPK)?.len(), 1);
        assert_eq!(
            store
                .invitations()?
                .iter()
                .map(|r| r.status)
                .collect::<Vec<_>>(),
            [INVITATION_OPEN, INVITATION_CONSUMED]
        );
        let read = |v: Option<Zeroizing<Vec<u8>>>| v.map(|z| z.to_vec());
        assert_eq!(
            read(store.invitation_retained(&[5; 16])?),
            Some(b"cells".to_vec())
        );
        assert_eq!(read(store.invitation_retained(&[4; 16])?), None);
        assert_eq!(
            read(store.invitation_record(&[4; 16])?),
            Some(b"replaced record".to_vec())
        );
        assert_eq!(read(store.relay_pool(3)?), Some(b"pool".to_vec()));
        store.txn(|tx| {
            put_invitation_retained(tx, &[5; 16], None)?;
            put_relay_pool(tx, 3, None)
        })?;
        assert_eq!(read(store.invitation_retained(&[5; 16])?), None);
        assert_eq!(read(store.relay_pool(3)?), None);

        // a missing row, or a second delete, is the uniform error and changes nothing
        for failing in [
            store.txn(|tx| delete_prekey(tx, KIND_SPK, 1)),
            store.txn(|tx| delete_prekey(tx, KIND_OPK, 9)),
            store.txn(|tx| set_invitation_status(tx, &[9; 16], INVITATION_CONSUMED)),
            store.txn(|tx| delete_invitation(tx, &[9; 16])),
            store.txn(|tx| put_invitation_retained(tx, &[9; 16], Some(b"x"))),
            store.txn(|tx| put_invitation_record(tx, &[9; 16], b"x")),
            store.txn(|tx| put_relay_pool(tx, 9, Some(b"x"))),
        ] {
            assert_eq!(failing, Err(Error::Unavailable));
        }
        store.txn(|tx| delete_invitation(tx, &[5; 16]))?;
        assert_eq!(store.invitations()?.len(), 1);
        assert_eq!(
            store.txn(|tx| delete_invitation(tx, &[5; 16])),
            Err(Error::Unavailable)
        );
        Ok(())
    }

    /// Killer (mutant of `identity_fingerprint`): the public fingerprint column reads back as written; a missing row is `None`.
    #[test]
    fn identity_fingerprint_column() -> R {
        let dir = TempDir::new("profile-fp")?;
        let mut store = Store::open(dir.path(), &TestKey::db_key())?;
        store.txn(|tx| put_identity(tx, 1, b"identity section", b"fingerprint bytes", 5))?;
        assert_eq!(
            store.identity_fingerprint(1)?,
            Some(b"fingerprint bytes".to_vec())
        );
        assert_eq!(store.identity_fingerprint(2)?, None);
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
