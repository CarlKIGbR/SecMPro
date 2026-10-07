// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replay of the handshake groups of the frozen `link` suite (`vectors/SCHEMA-4.11-link.md`) through
//! `secmp_proto::link` (TEST-SPEC-M5 (a): V-01…V-05, V-17…V-19, V-21). Every assertion message names its case id.
//! The command groups (V-06…V-16, V-20, V-22) are Phase B.

use secmp_proto::Encode;
use secmp_proto::link::{self, Error};
use secmp_proto::tr::FixedEntropy;

use crate::fixture::{
    NOW, RelayFx, VALID_UNTIL, add, at, client_draws, client_entropy, flip, from, h1, hex,
    honest_links, patch, reference, relay_draws, ri, unhex,
};

const HELLO: &str = "0007015345434d5001";

fn id_of(n: usize) -> String {
    format!("link-{n:04}")
}

/// V-01 `link_vectors_relay_keys`: case 0001.
#[test]
fn link_vectors_relay_keys() {
    let fx = RelayFx::case1();
    let c = reference().case(1);
    let id = id_of(1);
    let keys = fx.keys();
    assert_eq!(
        keys.sig_pk().as_bytes().to_vec(),
        c.output("relay_sig_pk"),
        "{id} relay_sig_pk"
    );
    assert_eq!(keys.fp().to_vec(), c.output("relay_fp"), "{id} relay_fp");
    assert_eq!(keys.akc().to_vec(), c.output("akc"), "{id} akc");
    let info = keys.relay_info(VALID_UNTIL).unwrap();
    let info_bytes = info.encode().unwrap();
    assert_eq!(info_bytes.len(), 1741, "{id} relayinfo length");
    assert_eq!(info_bytes.to_vec(), c.output("relayinfo"), "{id} relayinfo");
    assert_eq!(
        info.relay_dh_pk.as_bytes().to_vec(),
        c.output("relay_dh_pk"),
        "{id} relay_dh_pk"
    );
    assert_eq!(
        info.relay_kem_ek.as_bytes().len(),
        1568,
        "{id} relay_kem_ek length"
    );
    assert_eq!(
        info.relay_kem_ek.as_bytes().to_vec(),
        c.output("relay_kem_ek"),
        "{id} relay_kem_ek"
    );
    let rec = keys.relay_info_record(VALID_UNTIL).unwrap();
    assert_eq!(rec.len(), 1744, "{id} rec_relayinfo length");
    assert_eq!(rec, c.output("rec_relayinfo"), "{id} rec_relayinfo");
}

/// V-02 `link_vectors_relayinfo_accept`: cases 0002 and 0059.
#[test]
fn link_vectors_relayinfo_accept() {
    let fx = RelayFx::case1();
    let access = fx.access();
    // 0002: the client emits HELLO and accepts case 1's RelayInfo
    let c2 = reference().case(2);
    let (hello, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    assert_eq!(
        hex(&hello),
        hex(&c2.output("rec_hello")),
        "link-0002 rec_hello"
    );
    assert_eq!(hex(&hello), HELLO, "link-0002 rec_hello literal");
    assert_eq!(c2.accept(), Some(true), "link-0002 accept in the file");
    assert!(
        st.on_relayinfo(&fx.rec_relayinfo, &mut client_entropy())
            .is_ok(),
        "link-0002 accept"
    );
    // 0059: valid_until − now = 5 184 000 exactly, re-signed
    let c59 = reference().case(59);
    let rec = c59.input("rec_relayinfo");
    assert_eq!(
        c59.manipulation(),
        "relayinfo-valid-60d",
        "link-0059 manipulation"
    );
    assert_eq!(c59.accept(), Some(true), "link-0059 accept in the file");
    let (_h, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    assert!(
        st.on_relayinfo(&rec, &mut client_entropy()).is_ok(),
        "link-0059 accept"
    );
    let boundary = fx.resigned(|r| {
        *r = patch(r, ri::VALID_UNTIL, &(NOW + 5_184_000).to_be_bytes());
    });
    assert_eq!(boundary, rec, "link-0059 re-signed bytes");
}

/// V-03 `link_vectors_hs1`: case 0003.
#[test]
fn link_vectors_hs1() {
    let fx = RelayFx::case1();
    let c = reference().case(3);
    let id = id_of(3);
    let access = fx.access();
    // draws in the order e_c_sk 32, ek_c_seed 64, sk_e1 32, m1 32
    assert_eq!(
        [32, 64, 32, 32],
        [
            c.input("e_c_sk").len(),
            c.input("ek_c_seed").len(),
            c.input("sk_e1").len(),
            c.input("m1").len()
        ],
        "{id} draw sizes"
    );
    let draws = client_draws(c);
    let mut entropy = FixedEntropy::new(&draws);
    let (_h, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    let (rec, wait) = st.on_relayinfo(&fx.rec_relayinfo, &mut entropy).unwrap();
    assert_eq!(entropy.remaining(), 0, "{id} draws consumed exactly");
    assert_eq!(rec.len(), 2856, "{id} rec_hs1 length");
    assert_eq!(rec, c.output("rec_hs1"), "{id} rec_hs1");
    assert_eq!(from(&rec, 3), c.output("hs1"), "{id} hs1");
    assert_eq!(at(&rec, h1::E_C, 32), c.output("e_c"), "{id} e_c");
    assert_eq!(at(&rec, h1::EK_C, 1184), c.output("ek_c"), "{id} ek_c");
    assert_eq!(at(&rec, h1::PK_E1, 32), c.output("pk_e1"), "{id} pk_e1");
    assert_eq!(
        at(&rec, h1::CT_KEM, 1568),
        c.output("ct_kem"),
        "{id} ct_kem"
    );
    let t = wait.trace_kat();
    assert_eq!(t.ss1.to_vec(), c.output("ss1"), "{id} ss1");
    assert_eq!(t.h0.to_vec(), c.output("h0"), "{id} h0");
    assert_eq!(t.ck1.to_vec(), c.output("ck1"), "{id} ck1");
    assert_eq!(t.mac1.to_vec(), c.output("mac1"), "{id} mac1");
    assert_eq!(
        from(&rec, h1::MAC1),
        c.output("mac1"),
        "{id} mac1 in the record"
    );
}

/// V-04 `link_vectors_hs2`: case 0004.
#[test]
fn link_vectors_hs2() {
    let fx = RelayFx::case1();
    let c = reference().case(4);
    let id = id_of(4);
    let rec_hs1 = reference().case(3).output("rec_hs1");
    let draws = relay_draws(c);
    // mac1 verifies before the relay draws: a flipped mac1 leaves the draws untouched
    let keys = fx.keys();
    let (info, st) = link::relay::accept(&keys)
        .on_hello(&unhex(HELLO), VALID_UNTIL)
        .unwrap();
    assert_eq!(info, fx.rec_relayinfo, "{id} RELAYINFO per HELLO");
    let mut entropy = FixedEntropy::new(&draws);
    let (rec_hs2, relay_link) = st.on_hs1(&rec_hs1, &mut entropy).unwrap();
    assert_eq!(entropy.remaining(), 0, "{id} sk_er, m2 consumed");
    assert_eq!(rec_hs2.len(), 1156, "{id} rec_hs2 length");
    assert_eq!(rec_hs2, c.output("rec_hs2"), "{id} rec_hs2");
    assert_eq!(from(&rec_hs2, 3), c.output("hs2"), "{id} hs2");
    let t = relay_link.trace_kat();
    for (name, got) in [
        ("ss1", t.ss1.to_vec()),
        ("h0", t.h0.to_vec()),
        ("ck1", t.ck1.to_vec()),
        ("ss2", t.ss2.to_vec()),
        ("h1", t.h1.to_vec()),
        ("ck2", t.ck2.to_vec()),
        ("mac2", t.mac2.to_vec()),
        ("k_c2r", t.k_c2r.to_vec()),
        ("k_r2c", t.k_r2c.to_vec()),
        ("sess_id", t.sess_id.to_vec()),
    ] {
        assert_eq!(got, c.output(name), "{id} {name}");
    }
    // ss1, h0, ck1 equal link-0003's
    let c3 = reference().case(3);
    for name in ["ss1", "h0", "ck1"] {
        assert_eq!(c.output(name), c3.output(name), "{id} {name} = link-0003");
    }
    assert_eq!(relay_link.send_counter(), Some(0), "{id} r2c");
    assert_eq!(relay_link.recv_counter(), Some(0), "{id} c2r");
    assert_eq!(
        relay_link.sess_id().to_vec(),
        c.output("sess_id"),
        "{id} sess_id"
    );
    // the draws only after mac1: a flipped mac1 is a teardown with the source untouched
    let mut untouched = FixedEntropy::new(&draws);
    let (_i, st) = link::relay::accept(&keys)
        .on_hello(&unhex(HELLO), VALID_UNTIL)
        .unwrap();
    let bad = flip(&rec_hs1, h1::MAC1);
    assert!(
        matches!(st.on_hs1(&bad, &mut untouched), Err(Error::Rejected)),
        "{id} mac1 flip"
    );
    assert_eq!(
        untouched.remaining(),
        draws.len(),
        "{id} no draw before mac1 verifies"
    );
}

/// V-05 `link_vectors_hs2_accept`: case 0005.
#[test]
fn link_vectors_hs2_accept() {
    let c = reference().case(5);
    let id = id_of(5);
    let (client, relay) = honest_links();
    let t = client.trace_kat();
    for (name, got) in [
        ("ss2", t.ss2.to_vec()),
        ("h1", t.h1.to_vec()),
        ("ck2", t.ck2.to_vec()),
        ("k_c2r", t.k_c2r.to_vec()),
        ("k_r2c", t.k_r2c.to_vec()),
        ("sess_id", t.sess_id.to_vec()),
    ] {
        assert_eq!(got, c.output(name), "{id} {name}");
        assert_eq!(
            got,
            reference().case(4).output(name),
            "{id} {name} = link-0004"
        );
    }
    assert_eq!(client.sess_id(), relay.sess_id(), "{id} sess_id both sides");
    let (ks, kr) = client.keys_kat();
    let (rs, rr) = relay.keys_kat();
    assert_eq!((ks, kr), (rr, rs), "{id} direction keys agree");
    assert_ne!(ks, kr, "{id} k_c2r != k_r2c");
    assert_eq!(client.send_counter(), Some(0), "{id} c2r");
    assert_eq!(client.recv_counter(), Some(0), "{id} r2c");
    assert_eq!(
        c.at_pointer("/outputs/link_post/cmd_seq")
            .and_then(serde_json::Value::as_u64),
        Some(0),
        "{id} link_post cmd_seq"
    );
}

fn reject_label(c: &crate::fixture::Case) -> String {
    format!("{} ({})", c.id, c.manipulation())
}

/// V-17 `link_vectors_relayinfo_reject`: cases 0052–0058, all rejected by the client with nothing emitted.
#[test]
fn link_vectors_relayinfo_reject() {
    let fx = RelayFx::case1();
    let access = fx.access();
    for n in 52..=58 {
        let c = reference().case(n);
        let who = reject_label(c);
        assert_eq!(c.op, "relayinfo-reject", "{who} op");
        assert!(c.expects_reject(), "{who} expect");
        let rec = c.input("rec_relayinfo");
        let pinned: [u8; 32] = if c.inputs.contains_key("relay_fp") {
            c.input("relay_fp").try_into().unwrap()
        } else {
            fx.relay_fp
        };
        let (_h, st) = link::client::start(pinned, Some(&access), NOW).unwrap();
        let mut entropy = FixedEntropy::new(&client_draws(reference().case(3)));
        let r = st.on_relayinfo(&rec, &mut entropy);
        assert!(matches!(r, Err(Error::Rejected)), "{who}: client rejects");
        assert_eq!(entropy.remaining(), 160, "{who}: nothing drawn");
    }
}

/// V-18 `link_vectors_hs1_reject`: cases 0060–0070.
#[test]
fn link_vectors_hs1_reject() {
    let fx = RelayFx::case1();
    for n in 60..=70 {
        let c = reference().case(n);
        let who = reject_label(c);
        assert_eq!(c.op, "hs1-reject", "{who} op");
        let keys = fx.keys();
        let at = link::relay::accept(&keys);
        if n == 60 {
            // H1: a HELLO with the magic "RECMP"
            assert!(
                at.on_hello(&c.input("rec_hello"), VALID_UNTIL).is_err(),
                "{who}: relay rejects HELLO"
            );
            continue;
        }
        let (_info, st) = at.on_hello(&unhex(HELLO), VALID_UNTIL).unwrap();
        let rec = c.input("rec_hs1");
        let draws = if n == 70 {
            [c.input("sk_er"), c.input("m2")].concat()
        } else {
            vec![0x5a; 64]
        };
        let mut entropy = FixedEntropy::new(&draws);
        if n == 64 {
            // S4: an honest HS1 to another static pair: the relay of case 1 does not hold those keys
            let r = st.on_hs1(&rec, &mut entropy);
            assert!(matches!(r, Err(Error::Rejected)), "{who}: relay rejects");
            assert_eq!(entropy.remaining(), 64, "{who}: no draw");
        } else if n == 70 {
            // S10: a replayed HS1 is answered as a new handshake with a new sess_id; the old frame fails
            let (rec_hs2, mut link) = st.on_hs1(&rec, &mut entropy).unwrap();
            assert_eq!(rec_hs2, c.output("rec_hs2"), "{who}: rec_hs2");
            assert_eq!(
                link.sess_id().to_vec(),
                c.output("sess_id"),
                "{who}: sess_id"
            );
            assert_ne!(
                link.sess_id().to_vec(),
                reference().case(4).output("sess_id"),
                "{who}: new link"
            );
            let frame = c.input("frame");
            assert!(
                matches!(link.open(&frame), Err(Error::Rejected)),
                "{who}: P6's frame fails"
            );
            assert_eq!(link.recv_counter(), Some(0), "{who}: counter unchanged");
        } else {
            let r = st.on_hs1(&rec, &mut entropy);
            assert!(matches!(r, Err(Error::Rejected)), "{who}: relay rejects");
            assert_eq!(entropy.remaining(), 64, "{who}: no draw");
        }
    }
}

/// V-19 `link_vectors_hs2_reject`: cases 0071–0074, against the client state of case 0003.
#[test]
fn link_vectors_hs2_reject() {
    let fx = RelayFx::case1();
    let access = fx.access();
    for n in 71..=74 {
        let c = reference().case(n);
        let who = reject_label(c);
        assert_eq!(c.op, "hs2-reject", "{who} op");
        let (_h, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
        let (_rec, wait) = st
            .on_relayinfo(&fx.rec_relayinfo, &mut client_entropy())
            .unwrap();
        let r = wait.on_hs2(&c.input("rec_hs2"));
        assert!(matches!(r, Err(Error::Rejected)), "{who}: client rejects");
    }
}

/// V-21 `link_vectors_file_shape`: the file itself.
#[test]
fn link_vectors_file_shape() {
    use std::collections::BTreeMap;
    let r = reference();
    assert_eq!(
        r.header
            .pointer("/suite")
            .and_then(serde_json::Value::as_str),
        Some("link")
    );
    assert_eq!(
        r.header
            .pointer("/schema")
            .and_then(serde_json::Value::as_u64),
        Some(6)
    );
    assert_eq!(r.cases.len(), 86);
    for (i, c) in r.cases.iter().enumerate() {
        assert_eq!(c.id, format!("link-{:04}", add(i, 1)), "contiguous ids");
    }
    let mut parties: BTreeMap<String, usize> = BTreeMap::new();
    for c in &r.cases {
        *parties.entry(c.party().to_owned()).or_default() += 1;
    }
    assert_eq!(parties.get("R"), Some(&23), "party R");
    assert_eq!(parties.get("C"), Some(&17), "party C");
    assert_eq!(parties.get("CR"), Some(&46), "party CR");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let bytes = std::fs::read(root.join("ref").join("link.json")).unwrap();
    assert_eq!(bytes.len(), 2_818_910, "size of vectors/ref/link.json");
    assert_eq!(
        hex(&secmp_crypto::sha256(&[&bytes])),
        "dd77bb7c96d298f9cc188d4eadbd950605ccca2a250169708cdc573a73264c77",
        "sha256 of vectors/ref/link.json"
    );
    let mut ops: BTreeMap<String, usize> = BTreeMap::new();
    for c in &r.cases {
        *ops.entry(c.op.clone()).or_default() += 1;
    }
    // op counts of `ref-link-cases-index.txt`, grouped as the file groups them
    let n = |op: &str| *ops.get(op).unwrap_or(&0);
    assert_eq!(
        add(n("relayinfo-reject"), n("relayinfo-accept")),
        9,
        "RelayInfo cases (0002, I1–I7, I8)"
    );
    assert_eq!(n("hs1-reject"), 11, "hs1-reject");
    assert_eq!(n("hs2-reject"), 4, "hs2-reject");
    assert_eq!(n("frame-reject"), 12, "frame-reject");
    assert_eq!(n("relay-keys"), 1);
    assert_eq!(add(add(n("hs1"), n("hs2")), n("hs2-accept")), 3);
}
