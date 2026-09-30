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
    w.into_bytes().to_vec()
}

/// `SEND`: `… ‖ sid ‖ cell`, signed by the send key.
#[must_use]
pub fn send(sess_id: &Id, cmd_seq: u32, sid: &Id, cell: &Cell) -> Vec<u8> {
    let mut w = message(Label::QSend, sess_id, cmd_seq);
    w.bytes(sid);
    w.bytes(cell.as_bytes());
    w.into_bytes().to_vec()
}

/// `FETCH`: `… ‖ rid ‖ ack`, signed by the recv key.
#[must_use]
pub fn fetch(sess_id: &Id, cmd_seq: u32, rid: &Id, ack: u64) -> Vec<u8> {
    let mut w = message(Label::QFetch, sess_id, cmd_seq);
    w.bytes(rid);
    w.u64(ack);
    w.into_bytes().to_vec()
}

/// One `FETCH_MULTI` entry: label `MFETCH`, `… ‖ rid ‖ ack`, signed by that queue's recv key.
#[must_use]
pub fn fetch_multi_entry(sess_id: &Id, cmd_seq: u32, rid: &Id, ack: u64) -> Vec<u8> {
    let mut w = message(Label::QMfetch, sess_id, cmd_seq);
    w.bytes(rid);
    w.u64(ack);
    w.into_bytes().to_vec()
}

/// `QUEUE_DEL`: `… ‖ rid`, signed by the recv key.
#[must_use]
pub fn queue_del(sess_id: &Id, cmd_seq: u32, rid: &Id) -> Vec<u8> {
    let mut w = message(Label::QQueueDel, sess_id, cmd_seq);
    w.bytes(rid);
    w.into_bytes().to_vec()
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
    Ok(w.into_bytes().to_vec())
}

/// `LINK_GET` in owner-status mode (the only signed mode): `… ‖ ld_id ‖ mode (0x01)`, signed by the owner key.
#[must_use]
pub fn link_get_owner_status(sess_id: &Id, cmd_seq: u32, ld_id: &Id) -> Vec<u8> {
    let mut w = message(Label::QLinkGet, sess_id, cmd_seq);
    w.bytes(ld_id);
    w.u8(1);
    w.into_bytes().to_vec()
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

    /// The full messages, field by field in D.2 order (spec §9.2, D.6), with distinct field values.
    #[test]
    fn exact_contents() -> Result<()> {
        let sess = [0x11_u8; 16];
        let seq = 0x0102_0304_u32.to_be_bytes();
        let id = [0x22_u8; 16];
        let (recv, send_pk) = (ed25519(3)?, ed25519(4)?);
        let cell = Cell::from_bytes(&[0x33; CELL_LEN])?;
        let blob = LinkBlob::from_parts(&[0x44; 24], &[0x55; COM_LEN + LINK_BLOB_CT_LEN])?;
        let ack = 0x0a0b_0c0d_0e0f_1011_u64.to_be_bytes();
        let cat = |parts: &[&[u8]]| parts.concat();
        assert_eq!(
            queue_new(&sess, 0x0102_0304, &recv, &send_pk, &[0x66; 32]),
            cat(&[
                b"SecMP-Q/1 QUEUE_NEW",
                &sess,
                &seq,
                recv.as_bytes(),
                send_pk.as_bytes(),
                &[0x66; 32]
            ])
        );
        assert_eq!(
            send(&sess, 0x0102_0304, &id, &cell),
            cat(&[b"SecMP-Q/1 SEND", &sess, &seq, &id, cell.as_bytes()])
        );
        assert_eq!(
            fetch(&sess, 0x0102_0304, &id, 0x0a0b_0c0d_0e0f_1011),
            cat(&[b"SecMP-Q/1 FETCH", &sess, &seq, &id, &ack])
        );
        assert_eq!(
            fetch_multi_entry(&sess, 0x0102_0304, &id, 0x0a0b_0c0d_0e0f_1011),
            cat(&[b"SecMP-Q/1 MFETCH", &sess, &seq, &id, &ack])
        );
        assert_eq!(
            queue_del(&sess, 0x0102_0304, &id),
            cat(&[b"SecMP-Q/1 QUEUE_DEL", &sess, &seq, &id])
        );
        for one_time in [false, true] {
            let fields = LinkPutFields {
                ld_id: &id,
                one_time,
                expires_bucket: 0x0708_090a,
                owner_pk: &recv,
                token: &[0x77; 32],
            };
            assert_eq!(
                link_put(&sess, 0x0102_0304, &fields, &blob)?,
                cat(&[
                    b"SecMP-Q/1 LINK_PUT",
                    &sess,
                    &seq,
                    &id,
                    &[u8::from(one_time)],
                    &[7, 8, 9, 10],
                    recv.as_bytes(),
                    &[0x77; 32],
                    &secmp_crypto::sha256(&[&blob.encode()?])
                ])
            );
        }
        assert_eq!(
            link_get_owner_status(&sess, 0x0102_0304, &id),
            cat(&[b"SecMP-Q/1 LINK_GET", &sess, &seq, &id, &[1]])
        );
        Ok(())
    }
}
