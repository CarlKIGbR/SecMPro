// SPDX-License-Identifier: AGPL-3.0-or-later
//! RH-01…RH-15: the relay handshake (spec §8.2–§8.3) (TEST-SPEC-M5 (b); `docs/reviews/M05-planning/TEST-SPEC-M5.md`).

use crate::fixture;

use fixture::{
    LOW_ORDER_8, NOW, RelayFx, VALID_UNTIL, at, ck1_mac1, client_entropy, expand_keys, flip, from,
    h0_of, h1, h2, honest_hs1_parts, honest_links, hs1_record, patch, reference, relay_answer,
    relay_draws, relay_entropy, ri, unhex,
};
use secmp_crypto::{
    Ed25519VerifyingKey, HybridKem768PublicKey, Label, MlKem768Ek, X25519Public, hkdf_extract,
    hmac_sha256, sha256,
};
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, Error};
use secmp_proto::tr::FixedEntropy;

fn hello() -> Vec<u8> {
    unhex("0007015345434d5001")
}

/// What the relay is fed, and where in the connection.
#[derive(Clone, Copy)]
enum Stage {
    /// The record arrives as the first record of the connection.
    Hello,
    /// A valid HELLO was answered; the record arrives in place of `HS1`.
    Hs1,
}

#[derive(Clone, Copy)]
enum Statics {
    Honest,
    Other,
}

struct Sc {
    label: String,
    stage: Stage,
    statics: Statics,
    rec: Vec<u8>,
}

fn sc(label: impl Into<String>, stage: Stage, rec: Vec<u8>) -> Sc {
    Sc {
        label: label.into(),
        stage,
        statics: Statics::Honest,
        rec,
    }
}

fn other_keys(fx: &RelayFx) -> RelayKeys {
    let c = reference().case(64);
    fx.keys_with_static(&c.input("other_dh_sk"), &c.input("other_kem_seed"))
}

fn rec_hs1() -> Vec<u8> {
    reference().case(3).output("rec_hs1")
}

/// Drive one connection; returns the verdict and the number of draw bytes left in the entropy (64 at the start).
fn run(keys: &RelayKeys, s: &Sc) -> (link::Result<()>, usize) {
    let mut ent = relay_entropy();
    let st = link::relay::accept(keys);
    let res = match s.stage {
        Stage::Hello => st.on_hello(&s.rec, VALID_UNTIL).map(|_| ()),
        Stage::Hs1 => {
            let (_, st) = st.on_hello(&hello(), VALID_UNTIL).unwrap();
            st.on_hs1(&s.rec, &mut ent).map(|_| ())
        }
    };
    (res, ent.remaining())
}

fn assert_teardown(keys: &RelayKeys, other: &RelayKeys, s: &Sc) {
    let k = match s.statics {
        Statics::Honest => keys,
        Statics::Other => other,
    };
    let (res, left) = run(k, s);
    assert_eq!(res, Err(Error::Rejected), "{}: teardown", s.label);
    assert_eq!(left, 64, "{}: no RNG draw", s.label);
}

fn low_order() -> Vec<[u8; 32]> {
    let ff30 = "ff".repeat(30);
    let hexes = [
        "00".repeat(32),
        format!("01{}", "00".repeat(31)),
        format!("ec{ff30}7f"),
        fixture::hex(&LOW_ORDER_8),
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157".to_owned(),
        format!("ed{ff30}7f"),
        format!("ee{ff30}7f"),
    ];
    let mut out = Vec::new();
    for h in hexes {
        let u: [u8; 32] = unhex(&h).try_into().unwrap();
        out.push(u);
        let mut hi = u;
        *hi.get_mut(31).unwrap() |= 0x80;
        out.push(hi);
    }
    out
}

/// An `HS1` record with the honest fields of link-0003, `mutate` applied to them, and `mac1` re-computed from the
/// honest `ss1` (so that the MAC does not fire: the check under test is the only one that can).
fn remac(fx: &RelayFx, mutate: impl FnOnce(&mut fixture::Hs1Parts)) -> Vec<u8> {
    let mut parts = honest_hs1_parts(fx);
    mutate(&mut parts);
    let (_ck1, mac1) = ck1_mac1(&h0_of(&parts), &reference().case(3).output("ss1"));
    hs1_record(&parts, &mac1, 1)
}

/// The fields of another honest `HS1` (other draws), to be spliced into the honest record.
fn other_parts(fx: &RelayFx) -> fixture::Hs1Parts {
    let (_rec, _ss1, parts, _ck1) =
        fixture::compose_hs1(fx, &[0x11; 32], &[0x22; 64], &[0x33; 32], &[0x44; 32], 1);
    parts
}

/// The teardown scenarios of group `n` (RH-0n).
fn scenarios(fx: &RelayFx, n: u8) -> Vec<Sc> {
    let rec = rec_hs1();
    let mut v = Vec::new();
    match n {
        1 => {
            let h = hello();
            assert_eq!(reference().case(60).input("rec_hello"), flip(&h, 3));
            v.push(sc("len 6", Stage::Hello, patch(&h, 0, &[0, 6])));
            v.push(sc("len 8", Stage::Hello, patch(&h, 0, &[0, 8])));
            v.push(sc("len 0", Stage::Hello, patch(&h, 0, &[0, 0])));
            v.push(sc("truncated", Stage::Hello, at(&h, 0, 8).to_vec()));
            v.push(sc("trailing", Stage::Hello, [h.clone(), vec![0]].concat()));
            v.push(sc("empty", Stage::Hello, Vec::new()));
            v.push(sc("magic RECMP (H1)", Stage::Hello, flip(&h, 3)));
            v.push(sc(
                "magic RECMP (vector)",
                Stage::Hello,
                reference().case(60).input("rec_hello"),
            ));
            v.push(sc("magic SECMQ", Stage::Hello, patch(&h, 7, b"Q")));
            v.push(sc("magic secmp", Stage::Hello, patch(&h, 3, b"secmp")));
            v.push(sc("ver 0", Stage::Hello, patch(&h, 8, &[0])));
            v.push(sc("ver 2", Stage::Hello, patch(&h, 8, &[2])));
            v.push(sc("type 2", Stage::Hello, patch(&h, 2, &[2])));
        }
        3 => v.push(sc("HS1 first", Stage::Hello, rec)),
        4 => v.push(sc("second HELLO", Stage::Hs1, hello())),
        5 => {
            assert_eq!(
                reference().case(68).input("rec_hs1"),
                patch(&rec, h1::VER, &[2])
            );
            let short = reference().case(69).input("rec_hs1");
            assert_eq!(short.len(), 2855);
            assert_eq!(at(&short, 0, 2), [0x0b, 0x25]);
            v.push(sc("S9 short, len 2853", Stage::Hs1, short));
            v.push(sc(
                "full, len 2853",
                Stage::Hs1,
                patch(&rec, 0, &[0x0b, 0x25]),
            ));
            v.push(sc(
                "full, len 2855",
                Stage::Hs1,
                patch(&rec, 0, &[0x0b, 0x27]),
            ));
            v.push(sc(
                "trailing byte",
                Stage::Hs1,
                [rec.clone(), vec![0]].concat(),
            ));
            for t in [0_u8, 1, 2, 4] {
                v.push(sc(format!("type {t}"), Stage::Hs1, patch(&rec, 2, &[t])));
            }
            for ver in [0_u8, 2, 0xff] {
                v.push(sc(
                    format!("ver {ver}"),
                    Stage::Hs1,
                    patch(&rec, h1::VER, &[ver]),
                ));
            }
        }
        _ => return scenarios_b(fx, n),
    }
    assert!(!v.is_empty());
    v
}

/// Groups 6 to 11 of [`scenarios`].
fn scenarios_b(fx: &RelayFx, n: u8) -> Vec<Sc> {
    let rec = rec_hs1();
    let mut v = Vec::new();
    match n {
        6 => {
            for (i, u) in low_order().iter().enumerate() {
                v.push(sc(
                    format!("e_c low-order #{i}"),
                    Stage::Hs1,
                    remac(fx, |p| p.e_c = u.to_vec()),
                ));
                // pk_e1 sits in h0 too; ss1 is the honest one (the relay's Decaps never gets that far: the decoder
                // refuses the point first)
                v.push(sc(
                    format!("pk_e1 low-order #{i}"),
                    Stage::Hs1,
                    remac(fx, |p| p.pk_e1 = u.to_vec()),
                ));
                v.push(sc(
                    format!("e_c low-order, stale mac #{i}"),
                    Stage::Hs1,
                    patch(&rec, h1::E_C, u),
                ));
                v.push(sc(
                    format!("pk_e1 low-order, stale mac #{i}"),
                    Stage::Hs1,
                    patch(&rec, h1::PK_E1, u),
                ));
            }
            v.push(sc(
                "S5 vector",
                Stage::Hs1,
                reference().case(65).input("rec_hs1"),
            ));
            v.push(sc(
                "S6 vector",
                Stage::Hs1,
                reference().case(66).input("rec_hs1"),
            ));
        }
        7 => {
            v.push(sc(
                "ek_c ff ff ff, re-MACed",
                Stage::Hs1,
                remac(fx, |p| {
                    p.ek_c.get_mut(..3).unwrap().copy_from_slice(&[0xff; 3]);
                }),
            ));
            v.push(sc(
                "ek_c ff ff ff, stale mac",
                Stage::Hs1,
                patch(&rec, h1::EK_C, &[0xff; 3]),
            ));
            v.push(sc(
                "S7 vector",
                Stage::Hs1,
                reference().case(67).input("rec_hs1"),
            ));
        }
        8 => {
            for off in [0_usize, 15, 31] {
                v.push(sc(
                    format!("mac1 byte {off}"),
                    Stage::Hs1,
                    flip(&rec, fixture::add(h1::MAC1, off)),
                ));
            }
            v.push(sc(
                "S1 vector",
                Stage::Hs1,
                reference().case(61).input("rec_hs1"),
            ));
        }
        _ => return scenarios_c(fx, n),
    }
    assert!(!v.is_empty());
    v
}

/// Groups 9 to 11 of [`scenarios`].
fn scenarios_c(fx: &RelayFx, n: u8) -> Vec<Sc> {
    let rec = rec_hs1();
    let mut v = Vec::new();
    match n {
        9 => {
            let o = other_parts(fx);
            v.push(sc("e_c other", Stage::Hs1, patch(&rec, h1::E_C, &o.e_c)));
            v.push(sc("ek_c other", Stage::Hs1, patch(&rec, h1::EK_C, &o.ek_c)));
            v.push(sc(
                "pk_e1 other",
                Stage::Hs1,
                patch(&rec, h1::PK_E1, &o.pk_e1),
            ));
            v.push(sc("ct_kem byte 0 (S2)", Stage::Hs1, flip(&rec, h1::CT_KEM)));
            v.push(sc(
                "ct_kem byte 1567",
                Stage::Hs1,
                flip(&rec, fixture::add(h1::CT_KEM, 1567)),
            ));
            v.push(sc(
                "S2 vector",
                Stage::Hs1,
                reference().case(62).input("rec_hs1"),
            ));
        }
        10 => {
            for kid in [0_u32, 2, u32::MAX] {
                v.push(sc(
                    format!("kid {kid}, mac1 valid for that kid"),
                    Stage::Hs1,
                    remac(fx, |p| p.kid = kid),
                ));
                v.push(sc(
                    format!("kid {kid}, stale mac"),
                    Stage::Hs1,
                    patch(&rec, h1::KID, &kid.to_be_bytes()),
                ));
            }
            v.push(sc(
                "S3 vector",
                Stage::Hs1,
                reference().case(63).input("rec_hs1"),
            ));
        }
        11 => {
            v.push(Sc {
                label: "honest HS1 to a relay with another static pair".into(),
                stage: Stage::Hs1,
                statics: Statics::Other,
                rec: rec.clone(),
            });
            v.push(sc(
                "S4 vector",
                Stage::Hs1,
                reference().case(64).input("rec_hs1"),
            ));
        }
        _ => unreachable!(),
    }
    assert!(!v.is_empty());
    v
}

fn expect_group(n: u8) {
    let fx = RelayFx::case1();
    let keys = fx.keys();
    let other = other_keys(&fx);
    for s in scenarios(&fx, n) {
        assert_teardown(&keys, &other, &s);
    }
}

#[test]
fn relay_hello_shape_tears_down() {
    expect_group(1);
    // control: the honest HELLO is answered
    let fx = RelayFx::case1();
    let keys = fx.keys();
    assert!(
        link::relay::accept(&keys)
            .on_hello(&hello(), VALID_UNTIL)
            .is_ok()
    );
}

#[test]
fn relay_answers_every_hello_with_current_relayinfo() {
    let fx = RelayFx::case1();
    for (kid, keys) in [(1_u32, fx.keys()), (2, fx.keys_with_kid(2))] {
        for conn in 0..3 {
            let (rec, _st) = link::relay::accept(&keys)
                .on_hello(&hello(), VALID_UNTIL)
                .unwrap();
            assert_eq!(rec.len(), ri::LEN, "kid {kid} conn {conn}");
            assert_eq!(at(&rec, ri::KID, 4), kid.to_be_bytes());
            let signed = [Label::LinkRelayinfo.as_bytes(), at(&rec, 3, 1677)].concat();
            Ed25519VerifyingKey::from_bytes(at(&rec, ri::SIG_PK, 32))
                .unwrap()
                .verify(&signed, at(&rec, ri::SIG, 64))
                .unwrap();
            if kid == 1 {
                assert_eq!(rec, fx.rec_relayinfo);
            }
        }
    }
    assert_eq!(NOW, 1_700_000_100);
}

#[test]
fn relay_hs1_before_hello_tears_down() {
    expect_group(3);
}

#[test]
fn relay_second_hello_tears_down() {
    expect_group(4);
}

#[test]
fn relay_hs1_record_shape_tears_down() {
    expect_group(5);
}

#[test]
fn relay_hs1_low_order_points_tear_down() {
    expect_group(6);
}

#[test]
fn relay_hs1_ek_c_modulus_tears_down() {
    expect_group(7);
}

#[test]
fn relay_hs1_mac1_flip_tears_down_without_draw() {
    expect_group(8);
}

#[test]
fn relay_hs1_field_tamper_tears_down() {
    expect_group(9);
}

#[test]
fn relay_hs1_unknown_kid_tears_down() {
    expect_group(10);
    // control: the same re-MAC construction with kid 1 is the honest record and is answered
    let fx = RelayFx::case1();
    assert_eq!(remac(&fx, |_| {}), rec_hs1());
    let keys = fx.keys();
    let ok = sc("control", Stage::Hs1, remac(&fx, |p| p.kid = 1));
    let (res, left) = run(&keys, &ok);
    assert_eq!(res, Ok(()));
    assert_eq!(left, 0);
}

#[test]
fn relay_hs1_wrong_static_key_tears_down() {
    expect_group(11);
    // control: the HS1 encapsulated to the other pair is answered by the relay that holds that pair
    let fx = RelayFx::case1();
    let other = other_keys(&fx);
    let s = sc("control", Stage::Hs1, reference().case(64).input("rec_hs1"));
    let (res, left) = run(&other, &s);
    assert_eq!(res, Ok(()));
    assert_eq!(left, 0);
}

#[test]
fn relay_hs1_replay_answers_new_handshake() {
    let fx = RelayFx::case1();
    let c3 = reference().case(3);
    let c4 = reference().case(4);
    let c70 = reference().case(70);
    let rec = c3.output("rec_hs1");
    assert_eq!(c70.input("rec_hs1"), rec);
    let keys = fx.keys();
    // first connection (link A)
    let (hs2_a, link_a) = relay_answer(&fx, &rec).unwrap();
    assert_eq!(hs2_a, c4.output("rec_hs2"));
    // second connection: same HS1, fresh relay draws (case 70)
    let (_, st) = link::relay::accept(&keys)
        .on_hello(&hello(), VALID_UNTIL)
        .unwrap();
    let mut ent = FixedEntropy::new(&relay_draws(c70));
    let (hs2_b, link_b) = st.on_hs1(&rec, &mut ent).unwrap();
    assert_eq!(ent.remaining(), 0);
    assert_eq!(hs2_b, c70.output("rec_hs2"));
    assert_ne!(hs2_a, hs2_b);
    assert_ne!(at(&hs2_a, h2::E_R, 32), at(&hs2_b, h2::E_R, 32));
    assert_ne!(at(&hs2_a, h2::CT_C, 1088), at(&hs2_b, h2::CT_C, 1088));
    assert_eq!(
        link_b.sess_id().as_slice(),
        c70.output("sess_id").as_slice()
    );
    assert_ne!(link_a.sess_id(), link_b.sess_id());
    // P6's request frame (counter 0): opens on link A, fails on the new link
    let frame = c70.input("frame");
    assert_eq!(frame.len(), 4352);
    assert!(link_a.open_unit(&frame).is_ok());
    assert_eq!(link_b.open_unit(&frame).err(), Some(Error::Rejected));
    assert_eq!(link_b.recv_counter(), Some(0));
}

#[test]
fn relay_hs2_matches_independent_derivation() {
    let fx = RelayFx::case1();
    let c3 = reference().case(3);
    let c4 = reference().case(4);
    let parts = honest_hs1_parts(&fx);
    let h0 = h0_of(&parts);
    let (ck1, mac1) = ck1_mac1(&h0, &c3.output("ss1"));
    // ss2 = HybridKEM-768.Encaps((e_c, ek_c)) with the draws of link-0004
    let pk_c = HybridKem768PublicKey::new(
        X25519Public::from_bytes_checked(&parts.e_c).unwrap(),
        MlKem768Ek::from_bytes(&parts.ek_c).unwrap(),
    );
    let sk_er: [u8; 32] = c4.input("sk_er").try_into().unwrap();
    let m2: [u8; 32] = c4.input("m2").try_into().unwrap();
    let (ct2, ss2) = pk_c.encapsulate_kat(&sk_er, &m2).unwrap();
    let e_r = ct2.pk_e().as_bytes().to_vec();
    let ct_c = ct2.ct().as_bytes().to_vec();
    let pre = [
        h0.to_vec(),
        mac1.to_vec(),
        e_r.clone(),
        sha256(&[&ct_c]).to_vec(),
    ]
    .concat();
    assert_eq!(pre.len(), 128);
    let h1v = sha256(&[&pre]);
    let ikm = [
        ck1.expose_secret().as_slice(),
        ss2.expose_secret().as_slice(),
    ]
    .concat();
    assert_eq!(ikm.len(), 64);
    let ck2 = hkdf_extract(&h1v, &ikm).unwrap();
    let mac2 = hmac_sha256(ck2.expose_secret(), Label::LinkHs2, &[]).unwrap();
    let (k_c2r, k_r2c, sess) = expand_keys(&ck2);

    let (rec, link_r) = relay_answer(&fx, &rec_hs1()).unwrap();
    // record layout: len 2 ‖ type 1 ‖ body (ver 0, e_r 1, ct_c 33, mac2 1121, end 1153)
    assert_eq!(rec.len(), h2::LEN);
    assert_eq!(at(&rec, 0, 2), 1154_u16.to_be_bytes());
    assert_eq!(at(&rec, 2, 1), [4]);
    let body = from(&rec, 3);
    assert_eq!(body.len(), 1153);
    assert_eq!(at(body, 0, 1), [1]);
    assert_eq!(at(body, 1, 32), e_r.as_slice());
    assert_eq!(at(body, 33, 1088), ct_c.as_slice());
    assert_eq!(at(body, 1121, 32), mac2.as_slice());
    assert_eq!(h2::E_R, 4);
    assert_eq!(h2::CT_C, 36);
    assert_eq!(h2::MAC2, 1124);
    assert_eq!(rec, c4.output("rec_hs2"));

    let t = link_r.trace_kat();
    assert_eq!(t.ss2.as_slice(), ss2.expose_secret().as_slice());
    assert_eq!(t.h1.as_slice(), h1v.as_slice());
    assert_eq!(t.ck2.as_slice(), ck2.expose_secret().as_slice());
    assert_eq!(t.mac2.as_slice(), mac2.as_slice());
    assert_eq!(t.k_c2r.as_slice(), k_c2r.as_slice());
    assert_eq!(t.k_r2c.as_slice(), k_r2c.as_slice());
    assert_eq!(t.sess_id.as_slice(), sess.as_slice());
    assert_eq!(t.ck1.as_slice(), ck1.expose_secret().as_slice());
    assert_eq!(t.h0.as_slice(), h0.as_slice());
    // split 32/32/16 of the 80-byte expansion
    assert_eq!((k_c2r.len(), k_r2c.len(), sess.len()), (32, 32, 16));
    // the relay sends with k_r2c and receives with k_c2r
    let (k_send, k_recv) = link_r.keys_kat();
    assert_eq!(k_send.as_slice(), k_r2c.as_slice());
    assert_eq!(k_recv.as_slice(), k_c2r.as_slice());
}

#[test]
fn relay_bytes_after_hs2_are_frames() {
    let (_client, mut relay) = honest_links();
    let rec = rec_hs1();
    assert_eq!(rec.len(), 2856);
    assert_eq!(relay.open_unit(&rec).err(), Some(Error::Rejected));
    assert_eq!(
        relay.aead_open_attempts_kat(),
        0,
        "length check before the AEAD"
    );
    let zeros = vec![0_u8; 4352];
    assert_eq!(relay.open_unit(&zeros).err(), Some(Error::Rejected));
    assert_eq!(
        relay.aead_open_attempts_kat(),
        1,
        "a 4352-byte unit is opened"
    );
    assert_eq!(relay.open(&rec).err(), Some(Error::Rejected));
    assert_eq!(relay.open(&zeros).err(), Some(Error::Rejected));
    assert_eq!(relay.recv_counter(), Some(0));
    assert_eq!(relay.send_counter(), Some(0));
}

// The relay of this phase has no store (the queue store arrives in Phase B), so "no store entry" is vacuous here;
// what a rejected connection could leave behind is the relay keys, which are compared byte for byte.
#[test]
fn relay_handshake_rejection_keeps_no_state() {
    let fx = RelayFx::case1();
    let keys = fx.keys();
    let other = other_keys(&fx);
    let info_before = keys.relay_info_record(VALID_UNTIL).unwrap();
    assert_eq!(info_before, fx.rec_relayinfo);
    let (fp, akc) = (keys.fp(), keys.akc());
    let fresh = |what: &str| {
        // relay keys unchanged ...
        assert_eq!(
            keys.relay_info_record(VALID_UNTIL).unwrap(),
            info_before,
            "{what}"
        );
        assert_eq!((keys.fp(), keys.akc(), keys.kid()), (fp, akc, 1), "{what}");
        // ... and a new connection on the same keys completes the honest handshake byte-exactly
        let (info, st) = link::relay::accept(&keys)
            .on_hello(&hello(), VALID_UNTIL)
            .unwrap();
        assert_eq!(info, fx.rec_relayinfo, "{what}");
        let (hs2, relay_link) = st.on_hs1(&rec_hs1(), &mut relay_entropy()).unwrap();
        assert_eq!(hs2, reference().case(4).output("rec_hs2"), "{what}");
        assert_eq!(relay_link.recv_counter(), Some(0));
    };
    fresh("before any rejection");
    for n in [1_u8, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        for s in scenarios(&fx, n) {
            assert_teardown(&keys, &other, &s);
            fresh(&format!("after RH-{n:02} {}", s.label));
        }
    }
    // RH-14: after HS2 a wrong-length record and a zero unit; the relay keys are still intact
    let (_c, mut relay) = honest_links();
    assert!(relay.open(&rec_hs1()).is_err());
    assert!(relay.open(&vec![0_u8; 4352]).is_err());
    assert_eq!(relay.recv_counter(), Some(0));
    fresh("after RH-14");
    assert_eq!(client_entropy().remaining(), 160);
}
