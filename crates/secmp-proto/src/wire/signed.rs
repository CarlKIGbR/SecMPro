// SPDX-License-Identifier: AGPL-3.0-or-later
//! D.6 — the messages the command signatures cover (spec §9.2): `"SecMP-Q/1 " ‖ CMD_LABEL ‖ sess_id[16] ‖
//! cmd_seq u32 ‖ <fields in D.2 order, excluding sig and the blob parts; SHA-256(blob) for LINK_PUT>`, where the
//! label is the Appendix A label of the command (`MFETCH` for `FETCH_MULTI`). Encode only: a signed message is
//! computed by both sides and never parsed.

use secmp_crypto::Label;

use crate::codec::{Encode, Writer};
use crate::error::Result;
use crate::keys::Ed25519Pk;
use crate::sizes::HASH_LEN;
use crate::wire::Id;
use crate::wire::cell::Cell;
use crate::wire::inv::LinkBlob;

fn message(label: Label, sess_id: &Id, cmd_seq: u32) -> Writer {
    let mut w = Writer::new();
    w.bytes(label.as_bytes());
    w.bytes(sess_id);
    w.u32(cmd_seq);
    w
}

/// `QUEUE_NEW`: `… ‖ recv_pk ‖ send_pk ‖ token`, signed by the recv key.
#[must_use]
pub fn queue_new(
    sess_id: &Id,
    cmd_seq: u32,
    recv_pk: &Ed25519Pk,
    send_pk: &Ed25519Pk,
    token: &[u8; HASH_LEN],
) -> Vec<u8> {
    let mut w = message(Label::QQueueNew, sess_id, cmd_seq);
    w.bytes(recv_pk.as_bytes());
    w.bytes(send_pk.as_bytes());
    w.bytes(token);
    w.into_vec()
}

/// `SEND`: `… ‖ sid ‖ cell`, signed by the send key.
#[must_use]
pub fn send(sess_id: &Id, cmd_seq: u32, sid: &Id, cell: &Cell) -> Vec<u8> {
    let mut w = message(Label::QSend, sess_id, cmd_seq);
    w.bytes(sid);
    w.bytes(cell.as_bytes());
    w.into_vec()
}

/// `FETCH`: `… ‖ rid ‖ ack`, signed by the recv key.
#[must_use]
pub fn fetch(sess_id: &Id, cmd_seq: u32, rid: &Id, ack: u64) -> Vec<u8> {
    let mut w = message(Label::QFetch, sess_id, cmd_seq);
    w.bytes(rid);
    w.u64(ack);
    w.into_vec()
}

/// One `FETCH_MULTI` entry: label `MFETCH`, `… ‖ rid ‖ ack`, signed by that queue's recv key.
#[must_use]
pub fn fetch_multi_entry(sess_id: &Id, cmd_seq: u32, rid: &Id, ack: u64) -> Vec<u8> {
    let mut w = message(Label::QMfetch, sess_id, cmd_seq);
    w.bytes(rid);
    w.u64(ack);
    w.into_vec()
}

/// `QUEUE_DEL`: `… ‖ rid`, signed by the recv key.
#[must_use]
pub fn queue_del(sess_id: &Id, cmd_seq: u32, rid: &Id) -> Vec<u8> {
    let mut w = message(Label::QQueueDel, sess_id, cmd_seq);
    w.bytes(rid);
    w.into_vec()
}

/// The `LINK_PUT` fields its signature covers besides the blob hash.
pub struct LinkPutFields<'a> {
    /// Link-data id.
    pub ld_id: &'a Id,
    /// One-time link data.
    pub one_time: bool,
    /// Expiry hour bucket.
    pub expires_bucket: u32,
    /// Owner key.
    pub owner_pk: &'a Ed25519Pk,
    /// Access token.
    pub token: &'a [u8; HASH_LEN],
}

/// `LINK_PUT`: `… ‖ ld_id ‖ one_time ‖ expires_bucket ‖ owner_pk ‖ token ‖ SHA-256(blob)`, signed by the owner
/// key.
///
/// # Errors
/// None in practice (a `LinkBlob` always encodes).
pub fn link_put(
    sess_id: &Id,
    cmd_seq: u32,
    fields: &LinkPutFields<'_>,
    blob: &LinkBlob,
) -> Result<Vec<u8>> {
    let mut w = message(Label::QLinkPut, sess_id, cmd_seq);
    w.bytes(fields.ld_id);
    w.flag(fields.one_time);
    w.u32(fields.expires_bucket);
    w.bytes(fields.owner_pk.as_bytes());
    w.bytes(fields.token);
    w.bytes(&secmp_crypto::sha256(&[&blob.encode()?]));
    Ok(w.into_vec())
}

/// `LINK_GET` in owner-status mode (the only signed mode): `… ‖ ld_id ‖ mode (0x01)`, signed by the owner key.
#[must_use]
pub fn link_get_owner_status(sess_id: &Id, cmd_seq: u32, ld_id: &Id) -> Vec<u8> {
    let mut w = message(Label::QLinkGet, sess_id, cmd_seq);
    w.bytes(ld_id);
    w.u8(1);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sizes::{CELL_LEN, COM_LEN, LINK_BLOB_CT_LEN};
    use crate::wire::testutil::ed25519;

    /// The message lengths of `SCHEMA-4.8` rows 79–85 and their label prefixes.
    #[test]
    fn lengths_and_labels() -> Result<()> {
        let s = [1_u8; 16];
        let pk = ed25519(2)?;
        let blob = LinkBlob::from_parts(&[3; 24], &[4; COM_LEN + LINK_BLOB_CT_LEN])?;
        let cell = Cell::from_bytes(&[5; CELL_LEN])?;
        let cases: [(Vec<u8>, &[u8], usize); 7] = [
            (
                queue_new(&s, 1, &pk, &pk, &[6; 32]),
                b"SecMP-Q/1 QUEUE_NEW",
                135,
            ),
            (send(&s, 1, &s, &cell), b"SecMP-Q/1 SEND", 4146),
            (fetch(&s, 1, &s, 7), b"SecMP-Q/1 FETCH", 59),
            (fetch_multi_entry(&s, 1, &s, 7), b"SecMP-Q/1 MFETCH", 60),
            (queue_del(&s, 1, &s), b"SecMP-Q/1 QUEUE_DEL", 55),
            (
                link_put(
                    &s,
                    1,
                    &LinkPutFields {
                        ld_id: &s,
                        one_time: true,
                        expires_bucket: 8,
                        owner_pk: &pk,
                        token: &[9; 32],
                    },
                    &blob,
                )?,
                b"SecMP-Q/1 LINK_PUT",
                155,
            ),
            (link_get_owner_status(&s, 1, &s), b"SecMP-Q/1 LINK_GET", 55),
        ];
        for (msg, label, len) in cases {
            assert_eq!(msg.len(), len);
            assert!(msg.starts_with(label));
            assert_eq!(
                msg.get(label.len()..label.len().saturating_add(16)),
                Some(&s[..])
            );
        }
        Ok(())
    }
}
