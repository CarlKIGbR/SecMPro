// SPDX-License-Identifier: AGPL-3.0-or-later
//! The record seal of a secret column (CS-3.3 `docs/04:54`; ADR-053 item 5 and Amendment 1, accepted 2026-10-29, Q144):
//!
//! ```text
//! rec = N(24) ‖ CAEAD.Seal(K_t, N, AD = "SecMP-STORE/1 <table>" ‖ col_len u8 ‖ column name (ASCII) ‖ row_key, record)
//! ```
//!
//! (72 bytes of overhead: `N` 24, `COM` 32, tag 16). `row_key` (item 5; Am. 1 for a composite key): each part of the
//! primary key in column order, an integer as u64 big-endian, a byte string as `len u8 ‖ bytes`; a negative integer is not
//! encodable. A record moved to another table, row or column does not open; every failure is the one
//! [`Error::Unavailable`] (no distinction between a wrong place, a bad commitment and a bad tag).

use secmp_crypto::{Caead, LockedSecret, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::Table;

/// The overhead of a sealed record: `N` (24) ‖ `COM` (32) ‖ … ‖ tag (16).
pub const SEAL_OVERHEAD: usize = 24 + 32 + 16;
const _: () = assert!(SEAL_OVERHEAD == 72);

/// One part of a primary key.
#[derive(Clone, Copy, Debug)]
pub enum KeyPart<'a> {
    /// An integer column.
    Int(i64),
    /// A byte-string column (at most 255 bytes).
    Bytes(&'a [u8]),
}

/// `row_key` of a primary key (ADR-053 item 5; Amendment 1: the parts concatenated in primary-key column order).
///
/// # Errors
/// [`Error::Unavailable`] for a negative integer part or a byte string longer than 255 bytes.
pub fn row_key(parts: &[KeyPart<'_>]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for p in parts {
        match p {
            KeyPart::Int(v) => {
                let v = u64::try_from(*v).map_err(|_| Error::Unavailable)?;
                out.extend_from_slice(&v.to_be_bytes());
            }
            KeyPart::Bytes(b) => {
                out.push(u8::try_from(b.len()).map_err(|_| Error::Unavailable)?);
                out.extend_from_slice(b);
            }
        }
    }
    Ok(out)
}

/// `"SecMP-STORE/1 <table>" ‖ col_len u8 ‖ column ‖ row_key` (ADR-053 item 5).
fn ad(table: Table, column: &str, row_key: &[u8]) -> Result<Vec<u8>> {
    let len = u8::try_from(column.len()).map_err(|_| Error::Unavailable)?;
    Ok([table.label().as_bytes(), &[len], column.as_bytes(), row_key].concat())
}

/// Seal `record` for (`table`, `column`, `row_key`) under `key` (= `K_table`) with a fresh nonce.
///
/// # Errors
/// [`Error::Unavailable`] if randomness is unavailable or a length does not fit.
pub(crate) fn seal(
    key: &LockedSecret<32>,
    table: Table,
    column: &str,
    row_key: &[u8],
    record: &[u8],
) -> Result<Vec<u8>> {
    let nonce = crate::rand::nonce()?;
    let n = *nonce.as_bytes();
    // spec §3.4; ADR-053 item 5
    let sealed = Caead::seal_locked(key, nonce, &ad(table, column, row_key)?, record)
        .map_err(|_| Error::Unavailable)?;
    Ok([&n[..], &sealed].concat())
}

/// Open a record sealed for (`table`, `column`, `row_key`) under `key`.
///
/// # Errors
/// [`Error::Unavailable`] — uniformly — if the record is shorter than the overhead, belongs to another table, column or
/// row, or its commitment or tag does not verify.
pub(crate) fn open(
    key: &LockedSecret<32>,
    table: Table,
    column: &str,
    row_key: &[u8],
    rec: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let (n, sealed) = rec.split_first_chunk::<24>().ok_or(Error::Unavailable)?;
    // spec §3.4; ADR-053 item 5
    Caead::open_locked(key, n, &ad(table, column, row_key)?, sealed).map_err(|_| Error::Unavailable)
}

/// [`seal`] under the table keys of `kat::TEST_MK` (feature `kat`: the fuzz target `store_record_open`).
///
/// # Errors
/// As [`seal`].
#[cfg(feature = "kat")]
pub fn seal_kat(table: Table, column: &str, row_key: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    let mk =
        LockedSecret::<32>::from_slice(&crate::kat::TEST_MK).map_err(|_| Error::Unavailable)?;
    let keys = crate::keys::TableKeys::derive(&mk)?;
    seal(keys.get(table), table, column, row_key, record)
}

/// [`open`] under the table keys of `kat::TEST_MK` (feature `kat`: the fuzz target `store_record_open`).
///
/// # Errors
/// As [`open`].
#[cfg(feature = "kat")]
pub fn open_kat(
    table: Table,
    column: &str,
    row_key: &[u8],
    rec: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mk =
        LockedSecret::<32>::from_slice(&crate::kat::TEST_MK).map_err(|_| Error::Unavailable)?;
    let keys = crate::keys::TableKeys::derive(&mk)?;
    open(keys.get(table), table, column, row_key, rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::TableKeys;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// ST-11 (CS-3.3; ADR-053 item 5, Am. 1): a record sealed for (`sessions`, `data`, row (7, 0, 0)) opens only there —
    /// as row (8, 0, 0), in `outbox` row `[7; 16]`, in the column `skey` of the same row, with a flipped `COM` and with a
    /// flipped tag it is the one uniform error.
    #[test]
    fn record_bound_to_table_and_row() -> R {
        let mk = LockedSecret::<32>::from_slice(&crate::kat::TEST_MK)?;
        let keys = TableKeys::derive(&mk)?;
        let row7 = row_key(&[KeyPart::Int(7), KeyPart::Int(0), KeyPart::Int(0)])?;
        let row8 = row_key(&[KeyPart::Int(8), KeyPart::Int(0), KeyPart::Int(0)])?;
        let outbox7 = row_key(&[KeyPart::Bytes(&[7; 16])])?;
        assert_eq!((row7.len(), outbox7.len()), (24, 17));
        let sk = keys.get(Table::Sessions);
        let rec = seal(sk, Table::Sessions, "data", &row7, b"ratchet state")?;
        assert_eq!(rec.len(), b"ratchet state".len() + SEAL_OVERHEAD);
        assert_eq!(
            open(sk, Table::Sessions, "data", &row7, &rec)?.as_slice(),
            b"ratchet state"
        );
        let flip = |at: usize| {
            let mut r = rec.clone();
            if let Some(x) = r.get_mut(at) {
                *x ^= 1;
            }
            r
        };
        let outbox_key = keys.get(Table::Outbox);
        let failures = [
            (
                "another row",
                open(sk, Table::Sessions, "data", &row8, &rec).err(),
            ),
            (
                "another table",
                open(outbox_key, Table::Outbox, "data", &outbox7, &rec).err(),
            ),
            (
                "another column",
                open(sk, Table::Sessions, "skey", &row7, &rec).err(),
            ),
            (
                "flipped COM",
                open(sk, Table::Sessions, "data", &row7, &flip(24)).err(),
            ),
            (
                "flipped tag",
                open(sk, Table::Sessions, "data", &row7, &flip(rec.len() - 1)).err(),
            ),
        ];
        for (name, err) in failures {
            assert_eq!(err, Some(Error::Unavailable), "{name}");
        }
        assert_eq!(
            row_key(&[KeyPart::Int(-1)]),
            Err(Error::Unavailable),
            "a negative part"
        );
        Ok(())
    }

    /// Killers (A-4 mutants, the `kat` entry points of the fuzz target `store_record_open`): `seal_kat` seals under the
    /// table keys of `kat::TEST_MK` — [`open`] under those keys gives the record back — and `open_kat` opens it there and
    /// not under another column.
    #[test]
    #[cfg(feature = "kat")]
    fn fuzz_entry_points_round_trip() -> R {
        let mk = LockedSecret::<32>::from_slice(&crate::kat::TEST_MK)?;
        let keys = TableKeys::derive(&mk)?;
        let row = row_key(&[KeyPart::Int(7)])?;
        let rec = seal_kat(Table::Identity, "secret", &row, b"identity section")?;
        assert_eq!(rec.len(), 16 + SEAL_OVERHEAD);
        let key = keys.get(Table::Identity);
        assert_eq!(
            open(key, Table::Identity, "secret", &row, &rec)?.as_slice(),
            b"identity section"
        );
        assert_eq!(
            open_kat(Table::Identity, "secret", &row, &rec)?.as_slice(),
            b"identity section"
        );
        assert_eq!(
            open_kat(Table::Identity, "other", &row, &rec).err(),
            Some(Error::Unavailable)
        );
        Ok(())
    }

    /// `N(24) ‖ rest` of a raw sealed column, opened under `K_t` — `HKDF(0^32, TEST_MK, label)`, derived here
    /// independently of `keys.rs` — with the hand-written `ad` (hex); the record must give `want`.
    fn open_vector(
        table: Table,
        raw: &[u8],
        ad_hex: &str,
        want: &[u8],
    ) -> core::result::Result<(), Box<dyn std::error::Error>> {
        let k = secmp_crypto::hkdf::<32>(&[0; 32], &crate::kat::TEST_MK, table.label(), &[])?;
        let k = LockedSecret::<32>::from_slice(k.expose_secret())?;
        let ad = ad_hex
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(core::str::from_utf8(c)?, 16).map_err(Into::into))
            .collect::<core::result::Result<Vec<u8>, Box<dyn std::error::Error>>>()?;
        let (n, rest) = raw.split_first_chunk::<24>().ok_or("short record")?;
        assert_eq!(Caead::open_locked(&k, n, &ad, rest)?.as_slice(), want);
        Ok(())
    }

    /// The raw bytes of the one column `sql` selects.
    fn raw(
        store: &crate::store::Store,
        sql: &str,
    ) -> core::result::Result<Vec<u8>, rusqlite::Error> {
        store.connection_kat().query_row(sql, [], |r| r.get(0))
    }

    /// A4-1-03 `prekeys` (kind 1, id 2): the AD spelled out, `row_key` = two u64 big-endian.
    #[test]
    fn ad_vector_prekeys() -> R {
        let dir = crate::kat::TempDir::new("adv-prekeys")?;
        let mut store = crate::store::Store::open(dir.path(), &crate::kat::TestKey::db_key())?;
        store.txn(|tx| crate::profile::insert_prekey(tx, 1, 2, b"prekey seed", None))?;
        let rec = raw(&store, "SELECT secret FROM prekeys")?;
        open_vector(
            Table::Prekeys,
            &rec,
            concat!(
                "5365634d502d53544f52452f3120",
                "7072656b657973",
                "06",
                "736563726574",
                "0000000000000001",
                "0000000000000002"
            ),
            b"prekey seed",
        )
    }

    /// A4-1-03 `sessions` (session 4, part 1 = skipped, ord 0): `data` and `skey`, the AD spelled out.
    #[test]
    fn ad_vector_sessions() -> R {
        let dir = crate::kat::TempDir::new("adv-sessions")?;
        let mut store = crate::store::Store::open(dir.path(), &crate::kat::TestKey::db_key())?;
        let entry = [&[b'k'; 36][..], b"message key"].concat();
        store.txn(|tx| crate::sessions::insert_skipped(tx, 4, 0, &entry))?;
        let data = raw(&store, "SELECT data FROM sessions")?;
        open_vector(
            Table::Sessions,
            &data,
            concat!(
                "5365634d502d53544f52452f3120",
                "73657373696f6e73",
                "04",
                "64617461",
                "0000000000000004",
                "0000000000000001",
                "0000000000000000"
            ),
            &entry,
        )?;
        let skey = raw(&store, "SELECT skey FROM sessions")?;
        open_vector(
            Table::Sessions,
            &skey,
            concat!(
                "5365634d502d53544f52452f3120",
                "73657373696f6e73",
                "04",
                "736b6579",
                "0000000000000004",
                "0000000000000001",
                "0000000000000000"
            ),
            &[b'k'; 36],
        )
    }

    /// A4-1-03 `identity` (id 1): the AD spelled out.
    #[test]
    fn ad_vector_identity() -> R {
        let dir = crate::kat::TempDir::new("adv-identity")?;
        let mut store = crate::store::Store::open(dir.path(), &crate::kat::TestKey::db_key())?;
        store.txn(|tx| crate::profile::put_identity(tx, 1, b"identity section", b"fp", 5))?;
        let rec = raw(&store, "SELECT secret FROM identity")?;
        open_vector(
            Table::Identity,
            &rec,
            concat!(
                "5365634d502d53544f52452f3120",
                "6964656e74697479",
                "06",
                "736563726574",
                "0000000000000001"
            ),
            b"identity section",
        )
    }

    /// A4-1-03 `relays` (id 1, column `access_key`): the AD spelled out.
    #[test]
    fn ad_vector_relays() -> R {
        let dir = crate::kat::TempDir::new("adv-relays")?;
        let mut store = crate::store::Store::open(dir.path(), &crate::kat::TestKey::db_key())?;
        store.txn(|tx| crate::profile::put_relay(tx, 1, b"relay", Some(b"access key")))?;
        let rec = raw(&store, "SELECT access_key FROM relays")?;
        open_vector(
            Table::Relays,
            &rec,
            concat!(
                "5365634d502d53544f52452f3120",
                "72656c617973",
                "0a",
                "6163636573735f6b6579",
                "0000000000000001"
            ),
            b"access key",
        )
    }

    /// A4-1-03 `invitations` (`ld_id` = 16 × 0x05): the AD spelled out, `row_key` = `len u8 ‖ bytes`.
    #[test]
    fn ad_vector_invitations() -> R {
        let dir = crate::kat::TempDir::new("adv-invitations")?;
        let mut store = crate::store::Store::open(dir.path(), &crate::kat::TestKey::db_key())?;
        store
            .txn(|tx| crate::profile::insert_invitation(tx, &[5; 16], b"invitation record", 100))?;
        let rec = raw(&store, "SELECT record FROM invitations")?;
        open_vector(
            Table::Invitations,
            &rec,
            concat!(
                "5365634d502d53544f52452f3120",
                "696e7669746174696f6e73",
                "06",
                "7265636f7264",
                "10",
                "05050505050505050505050505050505"
            ),
            b"invitation record",
        )
    }

    /// A4-1-03 `outbox` (`msg_id` = 16 × 0x09, column `payload`): the AD spelled out.
    #[test]
    fn ad_vector_outbox() -> R {
        let dir = crate::kat::TempDir::new("adv-outbox")?;
        let mut store = crate::store::Store::open(dir.path(), &crate::kat::TestKey::db_key())?;
        let row = crate::outbox::OutboxRow {
            msg_id: [9; 16],
            seq: 1,
            kind: 0,
            expire_after: 0,
            payload: Zeroizing::new(b"outbox payload".to_vec()),
            queued_ms: 5,
            first_relayed_ms: None,
            state: crate::outbox::state::QUEUED,
            cell_id: None,
        };
        store.outbox_insert(1, &row)?;
        let rec = raw(&store, "SELECT payload FROM outbox")?;
        open_vector(
            Table::Outbox,
            &rec,
            concat!(
                "5365634d502d53544f52452f3120",
                "6f7574626f78",
                "07",
                "7061796c6f6164",
                "10",
                "09090909090909090909090909090909"
            ),
            b"outbox payload",
        )
    }
}
