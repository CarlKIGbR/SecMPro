// SPDX-License-Identifier: AGPL-3.0-or-later
//! The rows of the outbox (`docs/02:95`; spec §9.5, §10.4): one row per queued message of a contact, with its state
//! (`queued`, `relayed` with the `cell_id` of its last cell, `delivered`, `failed`), when it was queued and when it was
//! first relayed. The client's `StoreOutbox` keeps the order of the scheduler (enqueue order, `seq`) and writes every
//! transition through these functions, one transaction each.

use rusqlite::params;

use crate::error::{Error, Result};
use crate::store::Store;

/// The state codes of the `state` column.
pub mod state {
    /// Waiting (or being sent).
    pub const QUEUED: i64 = 0;
    /// `OK_SEND` stored its last cell under `cell_id`.
    pub const RELAYED: i64 = 1;
    /// A receipt arrived.
    pub const DELIVERED: i64 = 2;
    /// Never relayed within 30 days.
    pub const FAILED: i64 = 3;
}

/// One outbox row.
pub struct OutboxRow {
    /// Its `msg_id`.
    pub msg_id: [u8; 16],
    /// The enqueue order.
    pub seq: i64,
    /// `AppMessage.kind`.
    pub kind: u8,
    /// `expire_after` (seconds).
    pub expire_after: u32,
    /// The payload.
    pub payload: Vec<u8>,
    /// When it was queued.
    pub queued_ms: u64,
    /// When it was first relayed.
    pub first_relayed_ms: Option<u64>,
    /// [`state`].
    pub state: i64,
    /// The `cell_id` of a relayed message.
    pub cell_id: Option<u64>,
}

fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::Unavailable)
}

fn u64_of(v: i64) -> rusqlite::Result<u64> {
    u64::try_from(v).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, v))
}

impl Store {
    /// Insert a queued message.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for a view-once (memory only, CS-3.4); [`Error::Unavailable`] if the write fails.
    pub fn outbox_insert(&mut self, contact_id: i64, row: &OutboxRow) -> Result<()> {
        if row.kind == crate::messages::KIND_VIEW_ONCE {
            return Err(Error::Unsupported);
        }
        let queued = i64_of(row.queued_ms)?;
        self.txn(|tx| {
            tx.exec(
                "INSERT INTO outbox (msg_id, contact_id, seq, kind, expire_after, payload, queued_ms, first_relayed_ms, state, cell_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL)",
                params![
                    row.msg_id.as_slice(),
                    contact_id,
                    row.seq,
                    i64::from(row.kind),
                    i64::from(row.expire_after),
                    row.payload,
                    queued,
                    state::QUEUED
                ],
            )?;
            Ok(())
        })
    }

    /// Set the state of a message (and its `cell_id` / first-relayed time).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the write fails.
    pub fn outbox_set_state(
        &mut self,
        msg_id: &[u8; 16],
        new_state: i64,
        cell_id: Option<u64>,
        first_relayed_ms: Option<u64>,
    ) -> Result<()> {
        let cell = cell_id.map(i64_of).transpose()?;
        let first = first_relayed_ms.map(i64_of).transpose()?;
        self.txn(|tx| {
            tx.exec(
                "UPDATE outbox SET state = ?2, cell_id = ?3, first_relayed_ms = coalesce(first_relayed_ms, ?4) \
                 WHERE msg_id = ?1",
                params![msg_id.as_slice(), new_state, cell, first],
            )?;
            Ok(())
        })
    }

    /// The outbox of `contact_id`, in enqueue order.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the read fails.
    pub fn outbox_rows(&self, contact_id: i64) -> Result<Vec<OutboxRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT msg_id, seq, kind, expire_after, payload, queued_ms, first_relayed_ms, state, cell_id \
                 FROM outbox WHERE contact_id = ?1 ORDER BY seq",
            )
            .map_err(|_| Error::Unavailable)?;
        let rows = stmt
            .query_map(params![contact_id], |r| {
                let id: Vec<u8> = r.get(0)?;
                let msg_id = <[u8; 16]>::try_from(id.as_slice()).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "msg_id".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                let kind: i64 = r.get(2)?;
                let expire_after: i64 = r.get(3)?;
                Ok(OutboxRow {
                    msg_id,
                    seq: r.get(1)?,
                    kind: u8::try_from(kind)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, kind))?,
                    expire_after: u32::try_from(expire_after)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, expire_after))?,
                    payload: r.get(4)?,
                    queued_ms: u64_of(r.get(5)?)?,
                    first_relayed_ms: r.get::<_, Option<i64>>(6)?.map(u64_of).transpose()?,
                    state: r.get(7)?,
                    cell_id: r.get::<_, Option<i64>>(8)?.map(u64_of).transpose()?,
                })
            })
            .map_err(|_| Error::Unavailable)?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(|_| Error::Unavailable)
    }
}
