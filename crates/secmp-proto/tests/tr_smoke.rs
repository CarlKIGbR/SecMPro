// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Smoke test of SecMP-TR through the public API: a session, both directions, steps, out of order.

use secmp_crypto::{MlKem768Dk, SecretBytes, X25519Secret};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::dummy;
use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody, Cell, Content, ContentBody};

fn pair() -> (RatchetState, RatchetState) {
    let sk = SecretBytes::<32>::random().unwrap();
    let sb = [7_u8; 32];
    let spk = X25519Secret::generate().unwrap();
    let rpk = MlKem768Dk::generate().unwrap();
    let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes()).unwrap();
    let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).unwrap();
    let a = RatchetState::init_initiator(&sk, &sb, &spk_pub, &rpk_ek).unwrap();
    let b = RatchetState::init_responder(&sk, &sb, spk, rpk).unwrap();
    (a, b)
}

fn text(seq: u64, s: &str) -> Content {
    Content {
        seq,
        ts: 0,
        body: ContentBody::Batch(BatchBody {
            messages: vec![AppMessage {
                msg_id: [1; 16],
                kind: AppKind::Text,
                expire_after: 0,
                payload: secmp_crypto::Zeroizing::new(s.as_bytes().to_vec()),
            }],
        }),
    }
}

fn send(s: RatchetState, c: &Content) -> (RatchetState, Cell) {
    s.encrypt(c)
        .ok()
        .unwrap()
        .persist(|_| Ok::<(), ()>(()))
        .unwrap()
}

fn recv(s: RatchetState, cell: &Cell) -> (RatchetState, u64) {
    let (s, pt) = s
        .decrypt(cell.as_bytes())
        .ok()
        .unwrap()
        .commit(|_| Ok::<(), ()>(()))
        .unwrap();
    (s, pt.content().unwrap().seq)
}

#[test]
fn both_directions_steps_and_reordering() {
    let (a, b) = pair();
    let (a, c1) = send(a, &text(1, "one"));
    let (a, c2) = send(a, &dummy());
    let (a, c3) = send(a, &text(3, "three"));
    let (b, s3) = recv(b, &c3);
    assert_eq!(s3, 3);
    let (b, s1) = recv(b, &c1);
    assert_eq!(s1, 1);
    let (b, s2) = recv(b, &c2);
    assert_eq!(s2, 0);
    // replay is rejected, state unchanged
    let before = b.to_bytes().unwrap();
    let refused = b.decrypt(c1.as_bytes()).err().unwrap();
    assert_eq!(refused.error(), secmp_proto::Error::Rejected);
    let b = refused.into_state();
    assert_eq!(*b.to_bytes().unwrap(), *before);
    let (b, r1) = send(b, &text(10, "reply"));
    let (a, t) = recv(a, &r1);
    assert_eq!(t, 10);
    let (a, c4) = send(a, &text(4, "four"));
    let (b, s4) = recv(b, &c4);
    assert_eq!(s4, 4);
    // state round trip
    let a = RatchetState::from_bytes(&a.to_bytes().unwrap()).unwrap();
    let b = RatchetState::from_bytes(&b.to_bytes().unwrap()).unwrap();
    let (b, r2) = send(b, &text(11, "again"));
    let (_, t) = recv(a, &r2);
    assert_eq!(t, 11);
    drop(b);
}
