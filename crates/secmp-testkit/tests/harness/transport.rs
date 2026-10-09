// SPDX-License-Identifier: AGPL-3.0-or-later
//! Client transport `secmp-transport::RelayQueueTransport` (TEST-SPEC-M5 (b6), T-01…T-09, T-11; spec §12.1) against
//! the Phase B relay in process, and against a scripted relay where the relay must misbehave.

use secmp_crypto::{ConstantTimeEq, Label, SecretBytes, hmac_sha256};
use secmp_proto::Encode;
use secmp_proto::wire::frame::{
    Cellr, CellrError, Cont, ContIdx, ErrCode, LinkGetMode as WireMode, RequestCmd, Response,
    ResponseCmd,
};
use secmp_transport::{Error, LinkGetMode, QueueRef, QueueTransport, RecvCap, SendCap};

use crate::fixture::{blob, rig, scripted as scripted_transport};
use crate::scripted::{self, cell, dummy, err, ok};

/// T-01: `create_queue` is idempotent — the same keys give the same capabilities (spec §9.1).
#[test]
fn transport_create_queue_idempotent() {
    let mut r = rig();
    let a = r.a;
    let (recv, send) = r.seeds(a);
    let token = r.h.access_key();
    let (t, _) = r.link(a);
    let (r1, s1) = t.create_queue(&recv, &send, &token).unwrap();
    let (r2, s2) = t.create_queue(&recv, &send, &token).unwrap();
    assert!(
        bool::from(r1.ct_eq(&r2) & s1.ct_eq(&s2)),
        "same (RecvCap, SendCap)"
    );
    // another queue gives other capabilities
    let (recv_b, send_b) = r.seeds(a);
    let (t, _) = r.link(a);
    let (r3, s3) = t.create_queue(&recv_b, &send_b, &token).unwrap();
    assert!(bool::from(!r3.ct_eq(&r1) & !s3.ct_eq(&s1)));
    // a known recv key with another send key is ERR_AUTH (spec §9.7 item 8)
    let other_send = SecretBytes::from_slice(&[0x77; 32]).unwrap();
    assert_eq!(
        t.create_queue(&recv, &other_send, &token).err(),
        Some(Error::Auth)
    );
}

/// T-02: `OK_SEND` with and without eviction, `ERR` 3 and `ERR` 4 map to `Ok{cell_id, evicted}`, `NoQueue`, `Auth`.
#[test]
fn transport_send_outcome_mapping() {
    let mut r = rig();
    let a = r.a;
    let (recv, send) = r.seeds(a);
    let token = r.h.access_key();
    let (t, _) = r.link(a);
    let (_recv_cap, send_cap) = t.create_queue(&recv, &send, &token).unwrap();
    let first = t.send(&send_cap, &cell(1)).unwrap();
    assert_eq!((first.cell_id, first.evicted), (1, None));
    for i in 2..=128_u8 {
        assert_eq!(t.send(&send_cap, &cell(i)).unwrap().evicted, None);
    }
    let full = t.send(&send_cap, &cell(129)).unwrap();
    assert_eq!((full.cell_id, full.evicted), (129, Some(1)), "eviction");
    // a queue that does not exist: ERR_NOQUEUE
    let (ghost_recv, ghost_send): (SecretBytes<32>, SecretBytes<32>) = (
        SecretBytes::from_slice(&[0x21; 32]).unwrap(),
        SecretBytes::from_slice(&[0x22; 32]).unwrap(),
    );
    let ghost = SendCap::from_seed(
        &secmp_proto::keys::Ed25519Pk::from_bytes(
            secmp_crypto::Ed25519SigningKey::from_seed(ghost_recv.expose_secret())
                .unwrap()
                .verifying_key()
                .as_bytes(),
        )
        .unwrap(),
        &ghost_send,
    )
    .unwrap();
    assert_eq!(t.send(&ghost, &cell(1)).err(), Some(Error::NoQueue));
    // the right queue but a wrong sender key: ERR_AUTH
    let forged = SendCap::from_route(
        {
            let bytes = send_cap.to_bytes();
            let mut sid = [0_u8; 16];
            sid.copy_from_slice(bytes.get(1..17).unwrap());
            sid
        },
        &SecretBytes::from_slice(&[0x33; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(t.send(&forged, &cell(1)).err(), Some(Error::Auth));
    // the link survived every error outcome
    assert!(!t.is_closed());
    assert_eq!(t.send(&send_cap, &cell(130)).unwrap().cell_id, 130);
}

/// T-03: `fetch` returns the real cells only (at most F = 4, ascending); the errors are mapped.
#[test]
fn transport_fetch_returns_real_cells_only() {
    let mut r = rig();
    let a = r.a;
    let (recv, send) = r.seeds(a);
    let token = r.h.access_key();
    let extra: Vec<_> = (0..4).map(|_| r.seeds(a)).collect();
    let (t, _) = r.link(a);
    let (recv_cap, send_cap) = t.create_queue(&recv, &send, &token).unwrap();
    assert!(
        t.fetch(&recv_cap, 0).unwrap().is_empty(),
        "no cell, only dummies"
    );
    for count in 1..=6_u8 {
        t.send(&send_cap, &cell(count)).unwrap();
    }
    let first = t.fetch(&recv_cap, 0).unwrap();
    let ids: Vec<u64> = first.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![1, 2, 3, 4], "at most F real cells, ascending");
    assert_eq!(first.first().unwrap().1.as_bytes(), cell(1).as_bytes());
    let second = t.fetch(&recv_cap, 4).unwrap();
    let ids: Vec<u64> = second.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![5, 6], "the rest, dummies filtered");
    assert!(
        t.fetch(&recv_cap, 6).unwrap().is_empty(),
        "all acknowledged"
    );
    // 1 to 4 stored cells on fresh queues: exactly those, then dummies
    for (count, (recv, send)) in (1..=4_u8).zip(&extra) {
        let (recv_cap, send_cap) = t.create_queue(recv, send, &token).unwrap();
        for i in 0..count {
            t.send(&send_cap, &cell(0xc0_u8.saturating_add(i))).unwrap();
        }
        assert_eq!(t.fetch(&recv_cap, 0).unwrap().len(), usize::from(count));
    }
    // present 4 (MALFORMED): an acknowledgement beyond the queue's last id
    assert_eq!(t.fetch(&recv_cap, 7).err(), Some(Error::Malformed));
    // present 2 (NOQUEUE)
    t.delete_queue(&recv_cap).unwrap();
    assert_eq!(t.fetch(&recv_cap, 0).err(), Some(Error::NoQueue));
    assert!(!t.is_closed());
}

/// T-03 (present 3) and the single `ERR` frames of a `FETCH`: a scripted relay answers what the in-process relay
/// cannot be made to (AUTH for a derived `rid`).
#[test]
fn transport_fetch_maps_auth_and_single_error_frames() {
    let rid_of = |req: &secmp_proto::wire::frame::Request| match &req.cmd {
        RequestCmd::Fetch { rid, .. } => *rid,
        _ => unreachable!("a FETCH"),
    };
    let (mut t, _relay, _id) = scripted_transport(Box::new(move |req, n| {
        let seq = req.cmd_seq;
        match n {
            0 => vec![
                Response {
                    cmd_seq: seq,
                    cmd: ResponseCmd::Cellr(Cellr::Error {
                        error: CellrError::Auth,
                        rid: rid_of(req),
                        cell: cell(0x44),
                    }),
                },
                dummy(seq),
                dummy(seq),
                dummy(seq),
            ],
            1 => vec![err(seq, ErrCode::Rate)],
            _ => vec![err(seq, ErrCode::Malformed)],
        }
    }));
    let recv = RecvCap::from_seed(&SecretBytes::from_slice(&[9; 32]).unwrap()).unwrap();
    assert_eq!(t.fetch(&recv, 0).err(), Some(Error::Auth));
    assert_eq!(
        t.fetch(&recv, 0).err(),
        Some(Error::Rate),
        "one ERR 7 frame"
    );
    assert_eq!(
        t.fetch(&recv, 0).err(),
        Some(Error::Malformed),
        "one ERR 6 frame"
    );
    assert!(!t.is_closed());
}

/// T-04: `fetch_multi` returns the cells with their `QueueRef` and the per-queue error.
#[test]
fn transport_fetch_multi_maps_queue_refs() {
    let mut r = rig();
    let a = r.a;
    let token = r.h.access_key();
    let (ra, sa) = r.seeds(a);
    let (rb, sb) = r.seeds(a);
    let (t, _) = r.link(a);
    let (recv_a, send_a) = t.create_queue(&ra, &sa, &token).unwrap();
    let (recv_b, send_b) = t.create_queue(&rb, &sb, &token).unwrap();
    t.send(&send_a, &cell(0xa1)).unwrap();
    t.send(&send_b, &cell(0xb1)).unwrap();
    t.send(&send_a, &cell(0xa2)).unwrap();
    t.delete_queue(&recv_b).unwrap();
    let outcome = t.fetch_multi(&[(&recv_b, 0), (&recv_a, 0)]).unwrap();
    let cells: Vec<(QueueRef, u64)> = outcome.cells.iter().map(|(q, id, _)| (*q, *id)).collect();
    assert_eq!(cells, vec![(recv_a.queue(), 1), (recv_a.queue(), 2)]);
    assert_eq!(
        outcome.errors.len(),
        1,
        "the deleted queue answered with an error"
    );
    assert!(
        outcome
            .errors
            .first()
            .is_some_and(|(q, e)| *q == recv_b.queue() && *e == Error::NoQueue)
    );
    // 0 and more than 32 queues cannot be requested
    assert_eq!(t.fetch_multi(&[]).err(), Some(Error::Invalid));
    let many: Vec<(&RecvCap, u64)> = (0..33).map(|_| (&recv_a, 0)).collect();
    assert_eq!(t.fetch_multi(&many).err(), Some(Error::Invalid));
    assert!(!t.is_closed());
}

/// T-05: `delete_queue`, then `fetch` is `NoQueue`.
#[test]
fn transport_delete_queue() {
    let mut r = rig();
    let a = r.a;
    let (recv, send) = r.seeds(a);
    let token = r.h.access_key();
    let (t, _) = r.link(a);
    let (recv_cap, send_cap) = t.create_queue(&recv, &send, &token).unwrap();
    t.send(&send_cap, &cell(1)).unwrap();
    t.delete_queue(&recv_cap).unwrap();
    assert_eq!(t.fetch(&recv_cap, 0).err(), Some(Error::NoQueue));
    assert_eq!(t.send(&send_cap, &cell(2)).err(), Some(Error::NoQueue));
    assert_eq!(t.delete_queue(&recv_cap).err(), Some(Error::NoQueue));
}

/// T-06: `put_link_data` (three frames), `get_link_data` consume and owner status.
#[test]
fn transport_put_and_get_link_data() {
    let mut r = rig();
    let a = r.a;
    let token = r.h.access_key();
    let (owner, _) = r.seeds(a);
    let bucket = secmp_relay::HourBucket::from_unix_secs(r.h.clock().unix() + 86_400).0;
    let (t, _) = r.link(a);
    let stored = blob(0x5c);
    let id = [0x42; 16];
    t.put_link_data(id, &owner, &stored, true, bucket, &token)
        .unwrap();
    // an existing id is ERR_EXISTS
    assert_eq!(
        t.put_link_data(id, &owner, &blob(0x5d), true, bucket, &token)
            .err(),
        Some(Error::Exists)
    );
    // owner status does not consume
    let status = t
        .get_link_data(id, LinkGetMode::OwnerStatus(&owner))
        .unwrap();
    assert!(status.present && !status.consumed && status.blob.is_none());
    // consume returns the blob
    let got = t.get_link_data(id, LinkGetMode::Consume).unwrap();
    assert!(got.present && !got.consumed);
    assert_eq!(
        got.blob.unwrap().encode().unwrap().as_slice(),
        stored.encode().unwrap().as_slice()
    );
    // consumed: {0, 1}, no blob; owner status says so too
    let again = t.get_link_data(id, LinkGetMode::Consume).unwrap();
    assert!(!again.present && again.consumed && again.blob.is_none());
    let status = t
        .get_link_data(id, LinkGetMode::OwnerStatus(&owner))
        .unwrap();
    assert!(!status.present && status.consumed);
    // unknown: {0, 0}
    let unknown = t.get_link_data([0x43; 16], LinkGetMode::Consume).unwrap();
    assert!(!unknown.present && !unknown.consumed && unknown.blob.is_none());
    // a wrong owner key: owner status {0, 0} (spec §9.4: the relay does not reveal the entry)
    let wrong = SecretBytes::from_slice(&[0x66; 32]).unwrap();
    t.put_link_data([0x44; 16], &owner, &stored, false, bucket, &token)
        .unwrap();
    let hidden = t
        .get_link_data([0x44; 16], LinkGetMode::OwnerStatus(&wrong))
        .unwrap();
    assert!(!hidden.present && !hidden.consumed);
}

/// T-07: `cmd_seq` starts at 1 and increases by 1 per command; the `CONT` frames of a `LINK_PUT` repeat it.
#[test]
fn transport_cmd_seq_starts_at_1_strictly_increasing() {
    let (mut t, relay, id) = scripted_transport(Box::new(|req, n| {
        let seq = req.cmd_seq;
        match &req.cmd {
            RequestCmd::Cont(c) if c.idx == ContIdx::Two => vec![ok(seq)],
            RequestCmd::Cont(_) | RequestCmd::LinkPut { .. } => vec![],
            RequestCmd::Ping | RequestCmd::QueueDel { .. } => vec![ok(seq)],
            _ => unreachable!("unexpected request {n}"),
        }
    }));
    let owner = SecretBytes::from_slice(&[1; 32]).unwrap();
    t.ping().unwrap();
    t.put_link_data([1; 16], &owner, &blob(1), true, 5, &id.access)
        .unwrap();
    t.ping().unwrap();
    t.delete_queue(&RecvCap::from_seed(&SecretBytes::from_slice(&[2; 32]).unwrap()).unwrap())
        .unwrap();
    t.ping().unwrap();
    let seqs: Vec<u32> = relay.seen().iter().map(|q| q.cmd_seq).collect();
    assert_eq!(
        seqs,
        vec![1, 2, 2, 2, 3, 4, 5],
        "CONT frames repeat the command's cmd_seq"
    );
}

/// T-08: the token of `QUEUE_NEW` and `LINK_PUT` is over this link's `sess_id` and the command's own `cmd_seq`.
#[test]
fn transport_token_per_command() {
    let (mut t, relay, id) = scripted_transport(Box::new(|req, _| {
        let seq = req.cmd_seq;
        match &req.cmd {
            RequestCmd::QueueNew {
                recv_pk, send_pk, ..
            } => vec![Response {
                cmd_seq: seq,
                cmd: ResponseCmd::OkQueueNew {
                    rid: secmp_proto::link::ids::rid(recv_pk).unwrap(),
                    sid: secmp_proto::link::ids::sid(recv_pk, send_pk).unwrap(),
                },
            }],
            RequestCmd::Cont(c) if c.idx == ContIdx::Two => vec![ok(seq)],
            RequestCmd::Cont(_) | RequestCmd::LinkPut { .. } => vec![],
            _ => unreachable!("unexpected request"),
        }
    }));
    let (recv, send) = (
        SecretBytes::from_slice(&[3; 32]).unwrap(),
        SecretBytes::from_slice(&[4; 32]).unwrap(),
    );
    t.create_queue(&recv, &send, &id.access).unwrap();
    t.put_link_data([5; 16], &send, &blob(2), false, 9, &id.access)
        .unwrap();
    t.create_queue(&recv, &send, &id.access).unwrap();
    let sess_id = relay.sess_id();
    let expected = |seq: u32| {
        hmac_sha256(
            id.access.expose_secret(),
            Label::QToken,
            &[&sess_id, &seq.to_be_bytes()],
        )
        .unwrap()
    };
    let mut tokens = Vec::new();
    for req in relay.seen() {
        match req.cmd {
            RequestCmd::QueueNew { token, .. } | RequestCmd::LinkPut { token, .. } => {
                assert_eq!(token, expected(req.cmd_seq), "cmd_seq {}", req.cmd_seq);
                tokens.push(token);
            }
            _ => {}
        }
    }
    assert_eq!(tokens.len(), 3);
    assert!(
        tokens.windows(2).all(|w| w.first() != w.get(1)),
        "a token per command"
    );
}

fn is_rejected_and_closed<S: std::io::Read + std::io::Write>(
    t: &mut secmp_transport::RelayQueueTransport<S>,
    result: Result<(), Error>,
    what: &str,
) {
    assert_eq!(result.err(), Some(Error::Rejected), "{what}");
    assert!(t.is_closed(), "{what}: link closed");
    assert_eq!(t.ping().err(), Some(Error::Closed), "{what}: later calls");
}

/// T-09 (OPEN-M5-11 A): an authenticated response that does not fit its request is a LINK-level `Rejected`.
#[test]
fn transport_rejects_bad_response_shape() {
    let seed = |b: u8| SecretBytes::from_slice(&[b; 32]).unwrap();
    let recv = RecvCap::from_seed(&seed(7)).unwrap();
    let key = seed(8);

    // wrong op: OK to a FETCH
    let (mut t, _r, _id) = scripted_transport(Box::new(|req, _| vec![ok(req.cmd_seq)]));
    let r = t.fetch(&recv, 0).map(|_| ());
    is_rejected_and_closed(&mut t, r, "OK for FETCH");

    // wrong cmd_seq echo
    let (mut t, _r, _id) = scripted_transport(Box::new(|req, _| vec![ok(req.cmd_seq + 1)]));
    let r = t.delete_queue(&recv);
    is_rejected_and_closed(&mut t, r, "cmd_seq echo");

    // wrong ERR code for the command (ERR 5 EXISTS for a QUEUE_DEL)
    let (mut t, _r, _id) =
        scripted_transport(Box::new(|req, _| vec![err(req.cmd_seq, ErrCode::Exists)]));
    let r = t.delete_queue(&recv);
    is_rejected_and_closed(&mut t, r, "ERR 5 for QUEUE_DEL");

    // OK_QUEUE_NEW with ids other than the derived ones
    let (mut t, _r, id) = scripted_transport(Box::new(|req, _| {
        vec![Response {
            cmd_seq: req.cmd_seq,
            cmd: ResponseCmd::OkQueueNew {
                rid: [1; 16],
                sid: [2; 16],
            },
        }]
    }));
    let r = t.create_queue(&key, &key, &id.access).map(|_| ());
    is_rejected_and_closed(&mut t, r, "OK_QUEUE_NEW ids");

    // wrong order in a FETCH: a real cell after a dummy
    let (mut t, _r, _id) = scripted_transport(Box::new(|req, _| {
        let seq = req.cmd_seq;
        vec![dummy(seq), cellr(seq, 1), dummy(seq), dummy(seq)]
    }));
    let r = t.fetch(&recv, 0).map(|_| ());
    is_rejected_and_closed(&mut t, r, "a cell after a dummy");

    // wrong count: five frames for a FETCH — the fifth is read as the answer to the next command
    let (mut t, _r, _id) = scripted_transport(Box::new(|req, _| {
        let seq = req.cmd_seq;
        if matches!(req.cmd, RequestCmd::Fetch { .. }) {
            vec![dummy(seq), dummy(seq), dummy(seq), dummy(seq), dummy(seq)]
        } else {
            vec![ok(seq)]
        }
    }));
    assert!(t.fetch(&recv, 0).unwrap().is_empty());
    let r = t.ping();
    is_rejected_and_closed(&mut t, r, "a fifth frame");

    // a LINKR whose continuation has the wrong index
    let (mut t, _r, _id) = scripted_transport(Box::new(|req, _| {
        let seq = req.cmd_seq;
        let part = Box::new([0_u8; 4160]);
        let cont = |idx| Response {
            cmd_seq: seq,
            cmd: ResponseCmd::Cont(Cont {
                idx,
                data: Box::new([0; 4100]),
            }),
        };
        vec![
            Response {
                cmd_seq: seq,
                cmd: ResponseCmd::LinkR {
                    present: true,
                    consumed: false,
                    blob_part: part.into(),
                },
            },
            cont(ContIdx::Two),
            cont(ContIdx::One),
        ]
    }));
    let r = t.get_link_data([9; 16], LinkGetMode::Consume).map(|_| ());
    is_rejected_and_closed(&mut t, r, "CONT order of a LINKR");

    // control: the same scripted relay, honest, is accepted
    let (mut t, _r, _id) = scripted_transport(Box::new(|req, _| vec![ok(req.cmd_seq)]));
    t.delete_queue(&recv).unwrap();
    let _ = WireMode::Consume;
}

fn cellr(seq: u32, id: u64) -> Response {
    scripted::cellr(
        seq,
        Cellr::Cell {
            rid: [0; 16],
            cell_id: id,
            cell: cell(0x55),
        },
    )
}

/// T-11: capabilities are opaque, serialise and restore equal, and work after the restore.
#[test]
fn transport_caps_are_opaque_and_roundtrip() {
    let mut r = rig();
    let a = r.a;
    let (recv, send) = r.seeds(a);
    let token = r.h.access_key();
    let (t, _) = r.link(a);
    let (recv_cap, send_cap) = t.create_queue(&recv, &send, &token).unwrap();
    let recv_bytes = recv_cap.to_bytes();
    let send_bytes = send_cap.to_bytes();
    assert_eq!((recv_bytes.len(), send_bytes.len()), (49, 49));
    let recv_back = RecvCap::from_bytes(&recv_bytes).unwrap();
    let send_back = SendCap::from_bytes(&send_bytes).unwrap();
    assert!(
        bool::from(recv_back.ct_eq(&recv_cap) & send_back.ct_eq(&send_cap)),
        "equal after restore"
    );
    // usable after restore
    assert_eq!(t.send(&send_back, &cell(9)).unwrap().cell_id, 1);
    let got = t.fetch(&recv_back, 0).unwrap();
    assert_eq!(got.len(), 1);
    // the Debug output names no id or key
    assert_eq!(
        format!("{recv_cap:?} {send_cap:?}"),
        "RecvCap(..) SendCap(..)"
    );
    // damaged serialisations are refused
    assert_eq!(
        RecvCap::from_bytes(recv_bytes.get(..48).unwrap()).err(),
        Some(Error::Invalid)
    );
    let mut wrong_version = recv_bytes.to_vec();
    *wrong_version.first_mut().unwrap() = 2;
    assert_eq!(
        RecvCap::from_bytes(&wrong_version).err(),
        Some(Error::Invalid)
    );
    let mut wrong_rid = recv_bytes.to_vec();
    *wrong_rid.get_mut(1).unwrap() ^= 1;
    assert_eq!(
        RecvCap::from_bytes(&wrong_rid).err(),
        Some(Error::Invalid),
        "rid is derived"
    );
}
