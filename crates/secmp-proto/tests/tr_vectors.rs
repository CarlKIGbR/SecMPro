// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "kat")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The `tr` vector suite (`vectors/SCHEMA.md` §4.9, `vectors/SCHEMA-4.9-tr.md`) replayed against SecMP-TR: the 96
//! events in order with both parties' states — every `state_pre`/`state_post` digest, every `cell`, every
//! `content`, every rejection with the uniform error and a byte-identical state.
//!
//! `StateDigestV1` is the suite's comparison construct (SCHEMA-4.9), not the persistence format: it is computed
//! here, in the test crate, by parsing the documented `RatchetStateV1` encoding field by field.
//!
//! Reads the frozen `vectors/tr.json` (ADR-026: a verbatim copy of the reference file), and the reference file
//! `vectors/ref/tr.json` while the suite is not frozen yet.

use std::collections::HashMap;

use serde_json::Value;

use secmp_crypto::{MlKem768Dk, SecretBytes, X25519Secret, sha256};
use secmp_proto::codec::{pad, unpad};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::sizes::BODY_LEN;
use secmp_proto::tr::content::dummy;
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::Content;
use secmp_proto::{Decode, Encode, Error};

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
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

/// A cursor over the `RatchetStateV1` encoding.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }

    /// `opt(x)`: the presence byte and, if present, `n` bytes — returned as written (the digest's `opt` is the same).
    fn opt(&mut self, n: usize) -> Vec<u8> {
        let flag = self.take(1).first().copied().unwrap();
        assert!(flag <= 1, "presence byte");
        let mut out = vec![flag];
        if flag == 1 {
            out.extend_from_slice(self.take(n));
        }
        out
    }
}

/// `StateDigestV1` (SCHEMA-4.9): SHA-256 of `"SecMP-TR/1 state-digest" ‖ sb ‖ rk ‖ dh_s.sk ‖ opt(dh_r) ‖
/// kem_s.seed ‖ opt(kem_r) ‖ opt(last_ct_r) ‖ opt(ct_s) ‖ opt(ck_s) ‖ opt(ck_r) ‖ opt(hk_s) ‖ opt(hk_r) ‖
/// opt(nhk_s) ‖ opt(nhk_r) ‖ u32(n_s) ‖ u32(n_r) ‖ u32(pn) ‖ u32(|skipped|) ‖ (hk ‖ u32(n) ‖ mk)*`, read from the
/// state's `RatchetStateV1` encoding.
fn digest(state: &RatchetState) -> String {
    let encoded = state.to_bytes().unwrap();
    let mut f = Fields(&encoded);
    assert_eq!(f.take(1), [1], "RatchetStateV1 format byte");
    let mut pre = b"SecMP-TR/1 state-digest".to_vec();
    pre.extend_from_slice(f.take(32)); // sb
    pre.extend_from_slice(f.take(32)); // rk
    pre.extend_from_slice(f.take(32)); // dh_s.sk
    pre.extend(f.opt(32)); // dh_r
    pre.extend_from_slice(f.take(64)); // kem_s seed
    pre.extend(f.opt(1184)); // kem_r
    pre.extend(f.opt(1088)); // last_ct_r
    pre.extend(f.opt(1088)); // ct_s
    for _ in 0..6 {
        pre.extend(f.opt(32)); // ck_s, ck_r, hk_s, hk_r, nhk_s, nhk_r
    }
    pre.extend_from_slice(f.take(12)); // n_s, n_r, pn
    let count = u16::from_be_bytes(f.take(2).try_into().unwrap());
    pre.extend_from_slice(&u32::from(count).to_be_bytes());
    for _ in 0..count {
        pre.extend_from_slice(f.take(68)); // hk ‖ n ‖ mk
    }
    assert!(f.0.is_empty(), "RatchetStateV1 fully consumed");
    hex(&sha256(&[&pre]))
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

fn recv(st: RatchetState, id: &str, case: &Value, cells: &Cells) -> RatchetState {
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
    let refused = st
        .decrypt_with(&bytes(inputs, "cell"), &mut e)
        .err()
        .expect(id);
    assert_eq!(refused.error(), Error::Rejected, "{id}: the uniform error");
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
    for case in cases {
        let id = text(case, "id");
        let op = text(case, "op");
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
            "recv" => recv(st, id, case, &cells),
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
}
