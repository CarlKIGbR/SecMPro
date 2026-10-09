// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The `tr` vector suite (`vectors/SCHEMA.md` §4.9, `vectors/SCHEMA-4.9-tr.md`) replayed against SecMP-TR: the 96
//! events in order with both parties' states — every `state_pre`/`state_post` digest, every `cell`, every
//! `content`, every rejection with the uniform error and a byte-identical state.
//!
//! `StateDigestV1` is the suite's comparison construct (SCHEMA-4.9), not the persistence format: it is computed in
//! the test crate (`tests/common/tr_digest.rs`, shared with the generator) by parsing the documented
//! `RatchetStateV1` encoding field by field.
//!
//! Reads the frozen `vectors/tr.json` (ADR-026: a verbatim copy of the reference file), and the reference file
//! `vectors/ref/tr.json` while the suite is not frozen yet.

#[path = "common/tr_digest.rs"]
mod tr_digest;

use std::collections::HashMap;

use serde_json::Value;

use secmp_crypto::{HybridSigningKey, MlKem768Dk, SecretBytes, X25519Secret};
use secmp_proto::codec::{pad, unpad};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::sizes::BODY_LEN;
use secmp_proto::tr::content::{Delivery, Inbox, Trust, dummy};
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::Content;
use secmp_proto::{Decode, Encode, Error};

use tr_digest::{digest, hex};

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).expect(key)
}

fn bytes(v: &Value, key: &str) -> Vec<u8> {
    unhex(text(v, key))
}

fn vector_file() -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("tr.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("tr.json")
    };
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The typed Content of an unpadded encoding (the vector's `content`), which must re-encode to it.
fn content_of(unpadded: &[u8]) -> Content {
    let padded = pad(unpadded, BODY_LEN).unwrap();
    let c = Content::decode(&padded).unwrap();
    assert_eq!(*c.encode().unwrap(), *padded, "canonical content");
    c
}

fn entropy(inputs: &Value, keys: &[&str]) -> FixedEntropy {
    let mut all = Vec::new();
    for k in keys {
        if let Some(v) = inputs.get(*k).and_then(Value::as_str) {
            all.extend(unhex(v));
        }
    }
    FixedEntropy::new(&all)
}

#[derive(Default)]
struct Parties {
    a: Option<RatchetState>,
    b: Option<RatchetState>,
}

impl Parties {
    fn take(&mut self, party: &str) -> RatchetState {
        if party == "A" {
            self.a.take().unwrap()
        } else {
            assert_eq!(party, "B");
            self.b.take().unwrap()
        }
    }

    fn put(&mut self, party: &str, s: RatchetState) {
        match party {
            "A" => self.a = Some(s),
            _ => self.b = Some(s),
        }
    }
}

type Cells = HashMap<String, Vec<u8>>;

fn init(p: &mut Parties, id: &str, inputs: &Value, outputs: &Value) {
    let sk = SecretBytes::<32>::from_slice(&bytes(inputs, "sk")).unwrap();
    let sb: [u8; 32] = bytes(inputs, "sb").try_into().unwrap();
    let spk = X25519Secret::from_bytes(&bytes(inputs, "spk_dh_sk")).unwrap();
    let rpk = MlKem768Dk::from_seed(&bytes(inputs, "rpk_kem_seed")).unwrap();
    let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes()).unwrap();
    let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).unwrap();
    let mut e = entropy(inputs, &["dh_s_sk", "kem_s_seed", "m"]);
    let a = RatchetState::init_initiator_with(&sk, &sb, &spk_pub, &rpk_ek, &mut e).unwrap();
    assert_eq!(e.remaining(), 0, "{id}");
    let b = RatchetState::init_responder(&sk, &sb, spk, rpk).unwrap();
    assert_eq!(digest(&a), text(outputs, "state_post_A"), "{id} A");
    assert_eq!(digest(&b), text(outputs, "state_post_B"), "{id} B");
    p.a = Some(a);
    p.b = Some(b);
}

fn send(
    st: RatchetState,
    id: &str,
    inputs: &Value,
    outputs: &Value,
    cells: &mut Cells,
) -> RatchetState {
    let content = content_of(&bytes(inputs, "content"));
    let mut e = entropy(inputs, &["hdr_nonce"]);
    let (st, cell) = st
        .encrypt_with(&content, &mut e)
        .ok()
        .unwrap()
        .persist(|_| Ok::<(), ()>(()))
        .unwrap();
    assert_eq!(e.remaining(), 0, "{id}");
    assert_eq!(hex(cell.as_bytes()), text(outputs, "cell"), "{id} cell");
    cells.insert(id.to_owned(), cell.as_bytes().to_vec());
    st
}

/// The receive side of the `KeyChange` fragments (m18-m21, tr-0049..0052): B's inbox, its trust in A, A's old `IK_sig`
/// (from the seeds in tr-0049's inputs) and what each fragment delivered (M3 review F14).
struct KeyChangeRx {
    inbox: Inbox,
    trust: Trust,
    old_ik: Option<secmp_crypto::HybridVerifyingKey>,
    delivered: Vec<&'static str>,
    new_iks: Option<secmp_proto::wire::inv::IksPublic>,
}

fn recv(
    st: RatchetState,
    id: &str,
    case: &Value,
    cells: &Cells,
    rx: &mut KeyChangeRx,
) -> RatchetState {
    let (inputs, outputs) = (case.get("inputs").unwrap(), case.get("outputs").unwrap());
    let cell = cells.get(text(case, "from")).unwrap();
    let mut e = entropy(inputs, &["dh_sk", "kem_seed", "m"]);
    let opened = st
        .decrypt_with(cell, &mut e)
        .map_err(|r| r.error())
        .expect(id);
    let content = unpad(opened.plaintext().as_bytes(), BODY_LEN)
        .unwrap()
        .to_vec();
    assert_eq!(hex(&content), text(outputs, "content"), "{id} content");
    if matches!(
        text(case, "from"),
        "tr-0049" | "tr-0050" | "tr-0051" | "tr-0052"
    ) {
        let old = rx
            .old_ik
            .as_ref()
            .expect("tr-0049 carries the old IK_sig seeds");
        match rx.inbox.receive(opened.plaintext(), old, &mut rx.trust) {
            Delivery::Partial => rx.delivered.push("Partial"),
            Delivery::KeyChange(iks) => {
                rx.delivered.push("KeyChange");
                rx.new_iks = Some(iks);
            }
            _ => rx.delivered.push("other"),
        }
    }
    let (st, _) = opened.commit(|_| Ok::<(), ()>(())).unwrap();
    assert_eq!(e.remaining(), 0, "{id}: DH-step randomness used exactly");
    st
}

fn advance(mut st: RatchetState, case: &Value, inputs: &Value) -> RatchetState {
    let count = case.get("count").and_then(Value::as_u64).unwrap();
    let nonces = bytes(inputs, "hdr_nonces");
    assert_eq!(
        Some(nonces.len()),
        usize::try_from(count).unwrap().checked_mul(24)
    );
    for nonce in nonces.chunks(24) {
        let mut e = FixedEntropy::new(nonce);
        st = st
            .encrypt_with(&dummy(), &mut e)
            .ok()
            .unwrap()
            .persist(|_| Ok::<(), ()>(()))
            .unwrap()
            .0;
    }
    st
}

fn reject(st: RatchetState, id: &str, case: &Value) -> RatchetState {
    let (inputs, outputs) = (case.get("inputs").unwrap(), case.get("outputs").unwrap());
    assert_eq!(text(case, "expect"), "reject", "{id}");
    assert_eq!(
        text(outputs, "state_pre"),
        text(outputs, "state_post"),
        "{id}"
    );
    let before = st.to_bytes().unwrap().to_vec();
    let mut e = entropy(inputs, &["dh_sk", "kem_seed", "m"]);
    let supplied = e.remaining();
    let refused = st
        .decrypt_with(&bytes(inputs, "cell"), &mut e)
        .err()
        .expect(id);
    assert_eq!(refused.error(), Error::Rejected, "{id}: the uniform error");
    // a rejection draws no randomness (plan D2; M3 review C4): N1 lists the step randomness, none of it is used
    assert_eq!(e.remaining(), supplied, "{id}: a rejection drew randomness");
    let st = refused.into_state();
    assert_eq!(
        *st.to_bytes().unwrap(),
        before,
        "{id}: state byte-identical"
    );
    st
}

#[test]
fn every_event_of_the_tr_file() {
    let doc = vector_file();
    assert_eq!(text(&doc, "suite"), "tr");
    assert_eq!(doc.get("schema").and_then(Value::as_u64), Some(4));
    assert_eq!(text(&doc, "spec"), "SecMP/1 rev 2.3");
    let cases = doc.get("cases").and_then(Value::as_array).unwrap();
    assert_eq!(cases.len(), 96);
    let mut p = Parties::default();
    let mut cells = Cells::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut rx = KeyChangeRx {
        inbox: Inbox::new(),
        trust: Trust::Verified,
        old_ik: None,
        delivered: Vec::new(),
        new_iks: None,
    };
    for case in cases {
        let id = text(case, "id");
        let op = text(case, "op");
        if id == "tr-0049" {
            let i = case.get("inputs").unwrap();
            let sk = HybridSigningKey::from_seeds(
                &bytes(i, "old_ik_ed_seed"),
                &bytes(i, "old_ik_mldsa_xi"),
            )
            .unwrap();
            rx.old_ik = Some(sk.verifying_key());
        }
        *counts.entry(op.to_owned()).or_default() += 1;
        let inputs = case.get("inputs").unwrap();
        let outputs = case.get("outputs").unwrap();
        if op == "init" {
            init(&mut p, id, inputs, outputs);
            continue;
        }
        let party = text(case, "party");
        let st = p.take(party);
        assert_eq!(digest(&st), text(outputs, "state_pre"), "{id} pre");
        let st = match op {
            "send" => send(st, id, inputs, outputs, &mut cells),
            "recv" => recv(st, id, case, &cells, &mut rx),
            "advance" => advance(st, case, inputs),
            _ => {
                assert_eq!(op, "recv-reject", "{id}");
                reject(st, id, case)
            }
        };
        assert_eq!(digest(&st), text(outputs, "state_post"), "{id} post");
        p.put(party, st);
    }
    let expected = [
        ("init", 1),
        ("send", 40),
        ("recv", 40),
        ("advance", 2),
        ("recv-reject", 13),
    ];
    for (op, n) in expected {
        assert_eq!(counts.get(op).copied(), Some(n), "{op}");
    }
    // F14: the vector KeyChange (signed by the Python reference under the old key) reassembles from tr-0049..0052,
    // verifies, and moves the trust to KeyChanged
    assert_eq!(
        rx.delivered,
        ["Partial", "Partial", "Partial", "KeyChange"],
        "the four KeyChange fragments"
    );
    assert_eq!(rx.trust, Trust::KeyChanged);
    assert_eq!(rx.inbox.partials(), 0);
    assert!(rx.new_iks.is_some());
}

/// G-03 `tr_vectors_f14_new_iks_equals_vector_iks` (R-55, M3 review F14): the `new_iks` the receiver delivers from the
/// four `KeyChange` fragments is byte-equal to the `IKSPublic` that the seeds of tr-0049 define.
#[test]
fn tr_vectors_f14_new_iks_equals_vector_iks() {
    let doc = vector_file();
    let cases = doc.get("cases").and_then(Value::as_array).unwrap();
    let mut p = Parties::default();
    let mut cells = Cells::new();
    let mut rx = KeyChangeRx {
        inbox: Inbox::new(),
        trust: Trust::Verified,
        old_ik: None,
        delivered: Vec::new(),
        new_iks: None,
    };
    let mut vector_iks: Option<Vec<u8>> = None;
    for case in cases {
        let id = text(case, "id");
        let op = text(case, "op");
        let inputs = case.get("inputs").unwrap();
        let outputs = case.get("outputs").unwrap();
        if id == "tr-0049" {
            let sk = HybridSigningKey::from_seeds(
                &bytes(inputs, "old_ik_ed_seed"),
                &bytes(inputs, "old_ik_mldsa_xi"),
            )
            .unwrap();
            rx.old_ik = Some(sk.verifying_key());
            let new = HybridSigningKey::from_seeds(
                &bytes(inputs, "new_ik_ed_seed"),
                &bytes(inputs, "new_ik_mldsa_xi"),
            )
            .unwrap()
            .verifying_key();
            let new_dh = X25519Secret::from_bytes(&bytes(inputs, "new_ik_dh_sk")).unwrap();
            vector_iks = Some(
                [
                    &[1_u8][..],
                    new.ed25519().as_slice(),
                    new.mldsa65().as_slice(),
                    new_dh.public_key().as_bytes().as_slice(),
                ]
                .concat(),
            );
        }
        if op == "init" {
            init(&mut p, id, inputs, outputs);
            continue;
        }
        let party = text(case, "party");
        let st = p.take(party);
        let st = match op {
            "send" => send(st, id, inputs, outputs, &mut cells),
            "recv" => recv(st, id, case, &cells, &mut rx),
            "advance" => advance(st, case, inputs),
            _ => reject(st, id, case),
        };
        p.put(party, st);
    }
    let delivered = rx.new_iks.expect("the KeyChange was delivered");
    assert_eq!(
        delivered.encode().unwrap().to_vec(),
        vector_iks.expect("tr-0049 carries the new identity seeds"),
        "new_iks = the vector's IKSPublic"
    );
}
