// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The SecMP vector generator of `vectors/SCHEMA.md` revision 2 (M1 suites), written from the schema alone.
//! Shared by the `gen-vectors` example (which writes `vectors/rust/<suite>.json`) and the `vectors` test (which
//! re-checks the frozen files on every target). Feature `kat` (fixed randomness).
//!
//! Inputs: `seed_i = SHA-256("SecMP-vectors/1" ‖ suite name ‖ u32be(i))`, `stream_i = SHAKE-256(seed_i)` consumed
//! front to back in the order of the suite's input list; lengths, labels, `len`, `mode`, `op` and manipulations
//! come from the case tables (SCHEMA §2, §4). A negative row "derived from row r" draws from its **own**
//! stream with row r's shape (reviewer-confirmed reading 1, `docs/reviews/ref-spec-questions-M1.md`).

use serde_json::{Map, Value, json};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use secmp_crypto::{
    Caead, Ed25519SigningKey, Error, Fingerprint, HybridKem768Ciphertext, HybridKem768PublicKey,
    HybridKem768SecretKey, HybridKem1024Ciphertext, HybridKem1024PublicKey, HybridKem1024SecretKey,
    HybridSignature, HybridSigningKey, HybridVerifyingKey, Label, MlDsa65SigningKey, MlKem768Ct,
    MlKem768Dk, MlKem768Ek, MlKem1024Ct, MlKem1024Dk, MlKem1024Ek, MsgEncrypt, Nonce24,
    SafetyNumber, SecretBytes, X25519Public, X25519Secret, hkdf_kat, sha256,
};

/// Every M1 suite: (suite name, file name).
pub const SUITES: [&str; 8] = [
    "hkdf-labels",
    "caead",
    "msgencrypt",
    "hybridkem-768",
    "hybridkem-1024",
    "hybridsign",
    "fingerprint",
    "sas",
];

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The per-case input stream of SCHEMA §2.
pub struct Stream(sha3::Shake256Reader);

impl Stream {
    /// `stream_i` of `suite`.
    pub fn new(suite: &str, i: u32) -> Self {
        let seed = sha256(&[
            Label::Vectors.as_bytes(),
            suite.as_bytes(),
            &i.to_be_bytes(),
        ]);
        let mut h = Shake256::default();
        h.update(&seed);
        Self(h.finalize_xof())
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0; n];
        self.0.read(&mut out);
        out
    }

    /// The next `N` bytes as an array.
    pub fn arr<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.0.read(&mut out);
        out
    }
}

/// flip(field, k): XOR byte k (negative: from the end) with 0x01.
pub fn flip(v: &[u8], k: isize) -> Vec<u8> {
    let mut out = v.to_vec();
    let idx = if k >= 0 {
        usize::try_from(k).unwrap()
    } else {
        v.len().checked_sub(k.unsigned_abs()).unwrap()
    };
    *out.get_mut(idx).unwrap() ^= 0x01;
    out
}

/// drop-last(field).
pub fn drop_last(v: &[u8]) -> Vec<u8> {
    v.split_last().map(|(_, r)| r.to_vec()).unwrap_or_default()
}

/// append-zero(field).
pub fn append_zero(v: &[u8]) -> Vec<u8> {
    let mut out = v.to_vec();
    out.push(0);
    out
}

/// A manipulation of `(k, n, ad, com, c)` (caead).
type CaeadManip = fn(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>);
/// A manipulation of `(mk, ad, c_tag)` (msgencrypt).
type MsgManip = fn(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>);
/// A manipulation of `(pk_e, ct_kem)` or `(ek_kem, pk_dh)` (hybridkem).
type KemManip = fn(&mut Vec<u8>, &mut Vec<u8>);
/// A manipulation of `(pk_ed, pk_mldsa, label, msg, sig)` (hybridsign).
type SignManip = fn(&mut Vec<u8>, &mut Vec<u8>, &mut &'static str, &mut Vec<u8>, &mut Vec<u8>);

fn id(tag: &str, i: u32) -> String {
    format!("{tag}-{i:04}")
}

fn case(tag: &str, i: u32, op: &str, inputs: Value) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("id".to_owned(), Value::String(id(tag, i)));
    m.insert("op".to_owned(), Value::String(op.to_owned()));
    m.insert("inputs".to_owned(), inputs);
    m
}

fn positive(tag: &str, i: u32, op: &str, inputs: Value, outputs: Value) -> Value {
    let mut m = case(tag, i, op, inputs);
    m.insert("outputs".to_owned(), outputs);
    Value::Object(m)
}

fn reject(tag: &str, i: u32, op: &str, inputs: Value) -> Value {
    let mut m = case(tag, i, op, inputs);
    m.insert("expect".to_owned(), Value::String("reject".to_owned()));
    Value::Object(m)
}

fn file(suite: &str, cases: Vec<Value>) -> Value {
    let mut m = Map::new();
    m.insert("schema".to_owned(), json!(2));
    m.insert("suite".to_owned(), Value::String(suite.to_owned()));
    m.insert(
        "spec".to_owned(),
        Value::String("SecMP/1 rev 2.2".to_owned()),
    );
    m.insert(
        "generator".to_owned(),
        Value::String("secmp-rust".to_owned()),
    );
    m.insert("cases".to_owned(), Value::Array(cases));
    Value::Object(m)
}

/// The suite `name` as a JSON document.
pub fn generate(name: &str) -> Value {
    match name {
        "hkdf-labels" => hkdf_labels(),
        "caead" => caead(),
        "msgencrypt" => msgencrypt(),
        "hybridkem-768" => hybridkem768(),
        "hybridkem-1024" => hybridkem1024(),
        "hybridsign" => hybridsign(),
        "fingerprint" => fingerprint(),
        "sas" => sas(),
        other => panic_unknown(other),
    }
}

fn panic_unknown(name: &str) -> Value {
    assert_eq!(name, "a known suite");
    Value::Null
}

/// Canonical serialisation (SCHEMA §1): keys sorted at every level (`serde_json`'s default map is ordered),
/// separators `,`/`:` without spaces, ASCII only, no trailing newline.
pub fn canonical(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap();
    assert!(s.is_ascii(), "vector files are ASCII");
    s
}

// ---- 4.1 hkdf-labels ------------------------------------------------------------------------------------

fn hkdf_labels() -> Value {
    const SUITE: &str = "hkdf-labels";
    // (mode, label, salt, ikm, extra_info, len)
    let rows: [(&str, Label, usize, usize, usize, usize); 12] = [
        ("extract-expand", Label::InvLinkdata, 16, 32, 0, 32),
        ("extract-expand", Label::HxSk, 32, 224, 32, 32),
        ("extract-expand", Label::HxIdkey, 16, 160, 0, 32),
        ("extract-expand", Label::HxInitkey, 16, 32, 0, 32),
        ("extract-expand", Label::TrInit, 32, 32, 0, 96),
        ("extract-expand", Label::TrRk, 32, 64, 0, 96),
        ("extract-expand", Label::TrMsgkeys, 32, 32, 0, 76),
        ("expand", Label::Commit, 0, 32, 24, 64),
        ("expand", Label::LinkKeys, 0, 32, 0, 80),
        ("extract-expand", Label::TrMsgkeys, 0, 32, 0, 76),
        ("extract-expand", Label::HxSk, 32, 32, 100, 8160),
        ("extract-expand", Label::TrRk, 32, 0, 0, 1),
    ];
    let mut cases = Vec::new();
    for (i, (mode, label, salt_len, ikm_len, extra_len, len)) in (1_u32..).zip(rows) {
        let mut s = Stream::new(SUITE, i);
        let salt = s.take(salt_len);
        let ikm = s.take(ikm_len);
        let extra = s.take(extra_len);
        let okm = hkdf_kat(&salt, &ikm, label, &extra, len, mode == "expand").unwrap();
        cases.push(positive(
            "hkdf",
            i,
            "derive",
            json!({
                "mode": mode, "label": label.as_str(), "len": len,
                "salt": hex(&salt), "ikm": hex(&ikm), "extra_info": hex(&extra),
            }),
            json!({ "okm": hex(&okm) }),
        ));
    }
    file(SUITE, cases)
}

// ---- 4.2 caead ------------------------------------------------------------------------------------------

fn caead_seal(k: &[u8], n: &[u8], ad: &[u8], p: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = SecretBytes::<32>::from_slice(k).unwrap();
    let nonce = Nonce24::from_bytes_kat(n.try_into().unwrap());
    let sealed = Caead::seal(&key, nonce, ad, p).unwrap();
    let (com, c) = sealed.split_at(32);
    (com.to_vec(), c.to_vec())
}

fn caead_open_rejects(k: &[u8], n: &[u8], ad: &[u8], com: &[u8], c: &[u8]) -> bool {
    let key = SecretBytes::<32>::from_slice(k).unwrap();
    Caead::open(&key, n.try_into().unwrap(), ad, &[com, c].concat()).err() == Some(Error::Rejected)
}

fn caead() -> Value {
    const SUITE: &str = "caead";
    let shapes: [(usize, usize); 8] = [
        (0, 0),
        (16, 1),
        (21, 16),
        (32, 255),
        (64, 256),
        (128, 1024),
        (256, 4006),
        (1024, 12288),
    ];
    let mut cases = Vec::new();
    for (i, (ad_len, p_len)) in (1_u32..).zip(shapes) {
        let mut st = Stream::new(SUITE, i);
        let (key, nonce, ad, pt) = (st.take(32), st.take(24), st.take(ad_len), st.take(p_len));
        let (com, ct) = caead_seal(&key, &nonce, &ad, &pt);
        let sk = SecretBytes::<32>::from_slice(&key).unwrap();
        let opened = Caead::open(
            &sk,
            nonce.as_slice().try_into().unwrap(),
            &ad,
            &[com.clone(), ct.clone()].concat(),
        )
        .unwrap();
        assert_eq!(opened.as_slice(), pt.as_slice());
        cases.push(positive(
            "caead",
            i,
            "seal",
            json!({ "k": hex(&key), "n": hex(&nonce), "ad": hex(&ad), "p": hex(&pt) }),
            json!({ "com": hex(&com), "c": hex(&ct) }),
        ));
    }
    // (row shape, manipulation)
    let negatives: [(usize, CaeadManip); 9] = [
        (3, |_, _, _, _, c| *c = flip(c, 0)),
        (3, |_, _, _, _, c| *c = flip(c, -1)),
        (3, |_, _, _, com, _| *com = flip(com, 0)),
        (3, |_, _, _, _, c| *c = drop_last(c)),
        (3, |_, _, _, _, c| c.truncate(15)),
        (3, |_, _, ad, _, _| *ad = flip(ad, 0)),
        (3, |_, n, _, _, _| *n = flip(n, 0)),
        (3, |k, _, _, _, _| *k = flip(k, 0)),
        (1, |_, _, _, _, c| *c = flip(c, 0)),
    ];
    for (i, (row, manip)) in (9_u32..).zip(negatives) {
        let (ad_len, p_len) = *shapes.get(row.checked_sub(1).unwrap()).unwrap();
        let mut st = Stream::new(SUITE, i);
        let (mut key, mut nonce, mut ad, pt) =
            (st.take(32), st.take(24), st.take(ad_len), st.take(p_len));
        let (mut com, mut ct) = caead_seal(&key, &nonce, &ad, &pt);
        manip(&mut key, &mut nonce, &mut ad, &mut com, &mut ct);
        assert!(
            caead_open_rejects(&key, &nonce, &ad, &com, &ct),
            "caead case {i}"
        );
        cases.push(reject(
            "caead",
            i,
            "open",
            json!({ "k": hex(&key), "n": hex(&nonce), "ad": hex(&ad), "com": hex(&com), "c": hex(&ct) }),
        ));
    }
    file(SUITE, cases)
}

// ---- 4.3 msgencrypt ------------------------------------------------------------------------------------

/// `BODY_LEN` (spec §4.2) and one byte less (SCHEMA §4.3 row 16).
const BODY: usize = 1710;
const BODY_SHORT: usize = 1709;

fn msgencrypt() -> Value {
    const SUITE: &str = "msgencrypt";
    let ad_lens: [usize; 8] = [0, 1, 32, 64, 128, 1024, 2401, 4096];
    let mut cases = Vec::new();
    for (i, ad_len) in (1_u32..).zip(ad_lens) {
        let mut s = Stream::new(SUITE, i);
        let (mk, ad, p) = (s.take(32), s.take(ad_len), s.take(BODY));
        let key = SecretBytes::<32>::from_slice(&mk).unwrap();
        let (k_enc, k_mac, iv) = MsgEncrypt::derived_keys_kat(&key).unwrap();
        let c_tag = MsgEncrypt::seal(SecretBytes::from_slice(&mk).unwrap(), &ad, &p).unwrap();
        assert_eq!(
            MsgEncrypt::open(&key, &ad, &c_tag)
                .unwrap()
                .expose_secret()
                .as_slice(),
            p.as_slice()
        );
        cases.push(positive(
            "msgenc",
            i,
            "seal",
            json!({ "mk": hex(&mk), "ad": hex(&ad), "p": hex(&p) }),
            json!({ "k_enc": hex(&k_enc), "k_mac": hex(&k_mac), "iv": hex(&iv), "c_tag": hex(&c_tag) }),
        ));
    }
    let negatives: [MsgManip; 7] = [
        |_, _, ct| *ct = flip(ct, 0),
        |_, _, ct| *ct = flip(ct, -1),
        |_, _, ct| *ct = drop_last(ct),
        |_, _, ct| *ct = append_zero(ct),
        |_, ad, _| *ad = flip(ad, 0),
        |mk, _, _| *mk = flip(mk, 0),
        |_, _, ct| ct.clear(),
    ];
    for (i, manip) in (9_u32..).zip(negatives) {
        // derived from row 3 (ad 32)
        let mut s = Stream::new(SUITE, i);
        let (mut mk, mut ad, p) = (s.take(32), s.take(32), s.take(BODY));
        let mut c_tag = MsgEncrypt::seal(SecretBytes::from_slice(&mk).unwrap(), &ad, &p).unwrap();
        manip(&mut mk, &mut ad, &mut c_tag);
        let key = SecretBytes::<32>::from_slice(&mk).unwrap();
        assert_eq!(
            MsgEncrypt::open(&key, &ad, &c_tag).err(),
            Some(Error::Rejected),
            "msgencrypt case {i}"
        );
        cases.push(reject(
            "msgenc",
            i,
            "open",
            json!({ "mk": hex(&mk), "ad": hex(&ad), "c_tag": hex(&c_tag) }),
        ));
    }
    // row 16: a 1709-byte body on the seal side (shape of row 1: ad 0)
    let mut s = Stream::new(SUITE, 16);
    let (mk, ad, p) = (s.take(32), s.take(0), s.take(BODY_SHORT));
    assert_eq!(
        MsgEncrypt::seal(SecretBytes::from_slice(&mk).unwrap(), &ad, &p).err(),
        Some(Error::Rejected)
    );
    cases.push(reject(
        "msgenc",
        16,
        "seal",
        json!({ "mk": hex(&mk), "ad": hex(&ad), "p": hex(&p) }),
    ));
    file(SUITE, cases)
}

// ---- 4.4 hybridkem -------------------------------------------------------------------------------------

/// The order-8 point of SCHEMA §4.4 row 16.
const ORDER8: &str = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800";

macro_rules! hybridkem_suite {
    ($fn:ident, $suite:literal, $tag:literal, $sk:ident, $pk:ident, $ct:ident, $dk:ident, $ek:ident, $kct:ident) => {
        fn $fn() -> Value {
            const SUITE: &str = $suite;
            let honest = |s: &mut Stream| {
                let (dk_seed, sk_dh, m, sk_e) = (s.take(64), s.take(32), s.arr::<32>(), s.arr::<32>());
                let sk = $sk::from_parts(X25519Secret::from_bytes(&sk_dh).unwrap(), $dk::from_seed(&dk_seed).unwrap());
                let pk = sk.public_key();
                let (ct, ss) = pk.encapsulate_kat(&sk_e, &m).unwrap();
                (dk_seed, sk_dh, m, sk_e, sk, pk, ct, ss)
            };
            let mut cases = Vec::new();
            for i in 1_u32..=8 {
                let (dk_seed, sk_dh, m, sk_e, sk, pk, ct, ss) = honest(&mut Stream::new(SUITE, i));
                assert_eq!(sk.decapsulate(&ct).unwrap().expose_secret(), ss.expose_secret(), "{} case {i}", SUITE);
                cases.push(positive(
                    $tag,
                    i,
                    "encaps",
                    json!({ "dk_seed": hex(&dk_seed), "sk_dh": hex(&sk_dh), "m": hex(&m), "sk_e": hex(&sk_e) }),
                    json!({
                        "ek_kem": hex(pk.ek().as_bytes()), "pk_dh": hex(pk.pk_dh().as_bytes()),
                        "ct_kem": hex(ct.ct().as_bytes()), "pk_e": hex(ct.pk_e().as_bytes()),
                        "ss": hex(ss.expose_secret()),
                    }),
                ));
            }
            // decapsulation rows 9..=16: (manipulation of (pk_e, ct_kem), rejected?)
            let decaps: [(KemManip, bool); 8] = [
                (|_, _| {}, false),
                (|_, ct| *ct = flip(ct, 0), false),
                (|_, ct| *ct = flip(ct, -1), false),
                (|e, _| *e = flip(e, 0), false),
                (|_, ct| *ct = drop_last(ct), true),
                (|e, _| *e = vec![0; 32], true),
                (|e, _| { *e = vec![0; 32]; *e.get_mut(0).unwrap() = 1; }, true),
                (|e, _| *e = secmp_testkit::kat::hex(ORDER8), true),
            ];
            for (i, (manip, rejected)) in (9_u32..).zip(decaps) {
                let (dk_seed, sk_dh, _, _, sk, _, ct, _) = honest(&mut Stream::new(SUITE, i));
                let mut pk_e = ct.pk_e().as_bytes().to_vec();
                let mut ct_kem = ct.ct().as_bytes().to_vec();
                manip(&mut pk_e, &mut ct_kem);
                let inputs = json!({
                    "dk_seed": hex(&dk_seed), "sk_dh": hex(&sk_dh), "pk_e": hex(&pk_e), "ct_kem": hex(&ct_kem),
                });
                let outcome = $kct::from_bytes(&ct_kem).and_then(|c| {
                    let manipulated = $ct::new(X25519Public::from_bytes(&pk_e)?, c);
                    sk.decapsulate(&manipulated)
                });
                if rejected {
                    assert_eq!(outcome.err(), Some(Error::Rejected), "{} case {i}", SUITE);
                    cases.push(reject($tag, i, "decaps", inputs));
                } else {
                    let ss = outcome.unwrap();
                    cases.push(positive($tag, i, "decaps", inputs, json!({ "ss": hex(ss.expose_secret()) })));
                }
            }
            // encapsulation-side rows 17..=19
            let encaps_to: [KemManip; 3] = [
                |ek, _| ek.get_mut(..3).unwrap().copy_from_slice(&[0xff; 3]),
                |ek, _| *ek = drop_last(ek),
                |_, pk_dh| *pk_dh = vec![0; 32],
            ];
            for (i, manip) in (17_u32..).zip(encaps_to) {
                let (_, _, m, sk_e, _, pk, _, _) = honest(&mut Stream::new(SUITE, i));
                let mut ek = pk.ek().as_bytes().to_vec();
                let mut pk_dh = pk.pk_dh().as_bytes().to_vec();
                manip(&mut ek, &mut pk_dh);
                let outcome = $ek::from_bytes(&ek).and_then(|ek| {
                    $pk::new(X25519Public::from_bytes(&pk_dh)?, ek).encapsulate_kat(&sk_e, &m).map(|_| ())
                });
                assert_eq!(outcome.err(), Some(Error::Rejected), "{} case {i}", SUITE);
                cases.push(reject(
                    $tag,
                    i,
                    "encaps-to",
                    json!({ "ek_kem": hex(&ek), "pk_dh": hex(&pk_dh), "m": hex(&m), "sk_e": hex(&sk_e) }),
                ));
            }
            file(SUITE, cases)
        }
    };
}

hybridkem_suite!(
    hybridkem768,
    "hybridkem-768",
    "hk768",
    HybridKem768SecretKey,
    HybridKem768PublicKey,
    HybridKem768Ciphertext,
    MlKem768Dk,
    MlKem768Ek,
    MlKem768Ct
);
hybridkem_suite!(
    hybridkem1024,
    "hybridkem-1024",
    "hk1024",
    HybridKem1024SecretKey,
    HybridKem1024PublicKey,
    HybridKem1024Ciphertext,
    MlKem1024Dk,
    MlKem1024Ek,
    MlKem1024Ct
);

// ---- 4.5 hybridsign ------------------------------------------------------------------------------------

/// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `S + L` on the bytes 32..64 of a signature (little-endian addition).
fn s_plus_l(sig: &[u8]) -> Vec<u8> {
    let mut out = sig.to_vec();
    let mut carry = 0_u16;
    for (b, l) in out.get_mut(32..64).unwrap().iter_mut().zip(L_LE) {
        let v = u16::from(*b).wrapping_add(u16::from(l)).wrapping_add(carry);
        *b = v.to_le_bytes()[0];
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    out
}

fn hybridsign() -> Value {
    const SUITE: &str = "hybridsign";
    let rows: [(Label, usize); 8] = [
        (Label::HxBundle, 0),
        (Label::TrKeychange, 1),
        (Label::HxBundle, 32),
        (Label::TrKeychange, 32),
        (Label::HxBundle, 100),
        (Label::TrKeychange, 1024),
        (Label::HxBundle, 4434),
        (Label::TrKeychange, 4096),
    ];
    let sign = |s: &mut Stream, label: Label, msg_len: usize| {
        let (ed_seed, mldsa_seed, rnd, msg) =
            (s.take(32), s.take(32), s.arr::<32>(), s.take(msg_len));
        let key = HybridSigningKey::from_seeds(&ed_seed, &mldsa_seed).unwrap();
        let sig = key.sign_kat(label, &msg, &rnd).unwrap();
        (ed_seed, mldsa_seed, rnd, msg, key.verifying_key(), sig)
    };
    let mut cases = Vec::new();
    for (i, (label, msg_len)) in (1_u32..).zip(rows) {
        let (ed_seed, mldsa_seed, rnd, msg, vk, sig) =
            sign(&mut Stream::new(SUITE, i), label, msg_len);
        let verify = vk.verify(label, &msg, &sig).is_ok();
        assert!(verify);
        cases.push(positive(
            "hsig",
            i,
            "sign",
            json!({
                "ed_seed": hex(&ed_seed), "mldsa_seed": hex(&mldsa_seed), "rnd": hex(&rnd),
                "msg": hex(&msg), "label": label.as_str(),
            }),
            json!({
                "pk_ed": hex(vk.ed25519()), "pk_mldsa": hex(vk.mldsa65()), "sig": hex(sig.as_bytes()),
                "verify": verify,
            }),
        ));
    }
    // negatives 9..=17, derived from row 3 (HX bundle, msg 32)
    let negatives: [SignManip; 9] = [
        |_, _, _, _, sig| *sig = flip(sig, 0),
        |_, _, _, _, sig| *sig = flip(sig, 64),
        |_, _, label, _, _| *label = Label::TrKeychange.as_str(),
        |_, _, label, _, _| *label = Label::TrRk.as_str(),
        |_, _, _, _, sig| *sig = drop_last(sig),
        |_, _, _, _, sig| *sig = s_plus_l(sig),
        |pk_ed, _, _, _, _| {
            *pk_ed = vec![0; 32];
            *pk_ed.get_mut(0).unwrap() = 1;
        },
        |pk_ed, _, _, _, _| {
            *pk_ed = vec![0xff; 32];
            *pk_ed.get_mut(0).unwrap() = 0xee;
            *pk_ed.get_mut(31).unwrap() = 0x7f;
        },
        |_, _, _, msg, _| *msg = flip(msg, 0),
    ];
    for (i, manip) in (9_u32..).zip(negatives) {
        let (_, _, _, mut msg, vk, sig) = sign(&mut Stream::new(SUITE, i), Label::HxBundle, 32);
        let mut pk_ed = vk.ed25519().to_vec();
        let mut pk_mldsa = vk.mldsa65().to_vec();
        let mut label = Label::HxBundle.as_str();
        let mut sig = sig.as_bytes().to_vec();
        manip(&mut pk_ed, &mut pk_mldsa, &mut label, &mut msg, &mut sig);
        let outcome = HybridVerifyingKey::from_bytes(&pk_ed, &pk_mldsa).and_then(|vk| {
            let label = Label::from_ascii(label).ok_or(Error::Rejected)?;
            vk.verify(label, &msg, &HybridSignature::from_bytes(&sig)?)
        });
        assert_eq!(outcome.err(), Some(Error::Rejected), "hybridsign case {i}");
        cases.push(reject(
            "hsig",
            i,
            "verify",
            json!({
                "pk_ed": hex(&pk_ed), "pk_mldsa": hex(&pk_mldsa), "label": label,
                "msg": hex(&msg), "sig": hex(&sig),
            }),
        ));
    }
    file(SUITE, cases)
}

// ---- 4.6 fingerprint -----------------------------------------------------------------------------------

fn fingerprint() -> Value {
    const SUITE: &str = "fingerprint";
    let mut cases = Vec::new();
    for i in 1_u32..=8 {
        let mut s = Stream::new(SUITE, i);
        let (ed_seed, mldsa_seed, dh_seed) = (s.take(32), s.take(32), s.take(32));
        let ed = Ed25519SigningKey::from_seed(&ed_seed)
            .unwrap()
            .verifying_key();
        let ml = MlDsa65SigningKey::from_seed(&mldsa_seed)
            .unwrap()
            .verifying_key();
        let dh = X25519Secret::from_bytes(&dh_seed).unwrap().public_key();
        // IKSPublic { ver = 0x01, ik_ed25519, ik_mldsa65, ik_dh } (spec §6.2, D.3)
        let iks: Vec<u8> = [&[0x01][..], ed.as_bytes(), ml.as_bytes(), dh.as_bytes()].concat();
        assert_eq!(iks.len(), 2017);
        let fp = Fingerprint::of_encoded_iks(&iks).unwrap();
        cases.push(positive(
            "fp",
            i,
            "fp",
            json!({ "ed_seed": hex(&ed_seed), "mldsa_seed": hex(&mldsa_seed), "dh_seed": hex(&dh_seed) }),
            json!({ "iks": hex(&iks), "fp": hex(fp.as_bytes()) }),
        ));
    }
    file(SUITE, cases)
}

// ---- 4.7 sas -------------------------------------------------------------------------------------------

fn sas_case(i: u32, fp_a: &[u8], fp_b: &[u8]) -> Value {
    let a = Fingerprint::from_bytes(fp_a).unwrap();
    let b = Fingerprint::from_bytes(fp_b).unwrap();
    positive(
        "sas",
        i,
        "sas",
        json!({ "fp_a": hex(fp_a), "fp_b": hex(fp_b) }),
        json!({
            "half_a": SafetyNumber::half_kat(&a), "half_b": SafetyNumber::half_kat(&b),
            "safety_number": SafetyNumber::new(&a, &b).as_str(),
        }),
    )
}

fn sas() -> Value {
    const SUITE: &str = "sas";
    let mut cases = Vec::new();
    let mut row1 = (Vec::new(), Vec::new());
    for i in 1_u32..=8 {
        let mut s = Stream::new(SUITE, i);
        let (fp_a, fp_b) = (s.take(32), s.take(32));
        cases.push(sas_case(i, &fp_a, &fp_b));
        if i == 1 {
            row1 = (fp_a, fp_b);
        }
    }
    let fp_9 = Stream::new(SUITE, 9).take(32);
    cases.push(sas_case(9, &fp_9, &fp_9));
    // row 10: row 1 with fp_a and fp_b swapped (same safety number)
    let swapped = sas_case(10, &row1.1, &row1.0);
    let first = cases
        .first()
        .and_then(|c| c.pointer("/outputs/safety_number"))
        .cloned();
    assert_eq!(swapped.pointer("/outputs/safety_number").cloned(), first);
    cases.push(swapped);
    file(SUITE, cases)
}

/// Every byte-string field must be lowercase hex (SCHEMA §1 validator); labels, digit strings, `mode`, `op`,
/// `id`, `expect` are the non-hex strings.
pub fn validate(doc: &Value) -> Vec<String> {
    const TEXT: [&str; 10] = [
        "id",
        "op",
        "expect",
        "label",
        "mode",
        "half_a",
        "half_b",
        "safety_number",
        "suite",
        "spec",
    ];
    let mut bad = Vec::new();
    for case in doc
        .get("cases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for section in ["inputs", "outputs"] {
            for (k, v) in case
                .get(section)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                if let Some(s) = v.as_str()
                    && !TEXT.contains(&k.as_str())
                    && !(s.len().is_multiple_of(2)
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                {
                    bad.push(format!(
                        "{}: {section}.{k} is not lowercase hex",
                        case.get("id").unwrap_or(&Value::Null)
                    ));
                }
            }
        }
    }
    bad
}
