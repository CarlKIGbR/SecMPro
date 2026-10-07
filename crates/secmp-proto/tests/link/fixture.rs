// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared fixture of the LINK tests: the reference file, the relay of case `link-0001`, the draws of the honest
//! handshake (cases 3 and 4), an independent composition of the handshake of spec §8.3 (written from the spec and
//! `vectors/SCHEMA-4.11-link.md` with `secmp-crypto` primitives, not with `secmp_proto::link`), and the byte layouts
//! of the records of D.1.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use secmp_crypto::{
    Ed25519SigningKey, HybridKem768SecretKey, HybridKem1024PublicKey, Label, MlKem768Dk,
    MlKem1024Dk, MlKem1024Ek, SecretBytes, X25519Public, X25519Secret, hkdf_expand, hkdf_extract,
    hmac_sha256, sha256,
};
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, Link};
use secmp_proto::tr::FixedEntropy;
use serde_json::Value;

/// `now` of the suite (`vectors/SCHEMA-4.11-link.md`, constants).
pub const NOW: u64 = 1_700_000_100;
/// `valid_until` of the relay of case 1.
pub const VALID_UNTIL: u64 = 1_702_592_000;
/// The order-8 point of the suite.
pub const LOW_ORDER_8: [u8; 32] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];

pub fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

pub fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v[at] ^= 1;
    v
}

/// `bytes` with `new` written at `at`.
pub fn patch(bytes: &[u8], at: usize, new: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v[at..at + new.len()].copy_from_slice(new);
    v
}

/// The frozen file when it exists, else the reference file (as the `hx` tests do).
fn link_file() -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("link.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("link.json")
    };
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// One case of the file.
pub struct Case {
    pub id: String,
    pub op: String,
    pub inputs: BTreeMap<String, Value>,
    pub outputs: BTreeMap<String, Value>,
    pub raw: Value,
}

impl Case {
    fn new(v: &Value) -> Self {
        let map = |key: &str| -> BTreeMap<String, Value> {
            v.get(key)
                .and_then(Value::as_object)
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default()
        };
        Self {
            id: v["id"].as_str().unwrap().to_owned(),
            op: v["op"].as_str().unwrap().to_owned(),
            inputs: map("inputs"),
            outputs: map("outputs"),
            raw: v.clone(),
        }
    }

    pub fn input(&self, name: &str) -> Vec<u8> {
        unhex(
            self.inputs
                .get(name)
                .unwrap_or_else(|| panic!("{}: no input {name}", self.id))
                .as_str()
                .unwrap(),
        )
    }

    pub fn output(&self, name: &str) -> Vec<u8> {
        unhex(
            self.outputs
                .get(name)
                .unwrap_or_else(|| panic!("{}: no output {name}", self.id))
                .as_str()
                .unwrap(),
        )
    }

    pub fn manipulation(&self) -> &str {
        self.raw["manipulation"].as_str().unwrap_or("")
    }
}

/// The file, parsed once.
pub struct Ref {
    pub header: Value,
    pub cases: Vec<Case>,
}

impl Ref {
    /// The case `link-00nn`.
    pub fn case(&self, n: usize) -> &Case {
        let c = &self.cases[n - 1];
        assert_eq!(c.id, format!("link-{n:04}"));
        c
    }
}

pub fn reference() -> &'static Ref {
    static REF: OnceLock<Ref> = OnceLock::new();
    REF.get_or_init(|| {
        let v = link_file();
        let cases = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(Case::new)
            .collect();
        Ref { header: v, cases }
    })
}

/// The relay of `link-0001`: its secrets as bytes, and constructors for the library types.
pub struct RelayFx {
    pub sig_seed: Vec<u8>,
    pub dh_sk: Vec<u8>,
    pub kem_seed: Vec<u8>,
    pub access_key: Vec<u8>,
    pub kid: u32,
    pub rec_relayinfo: Vec<u8>,
    pub relay_fp: [u8; 32],
    pub relay_dh_pk: Vec<u8>,
    pub relay_kem_ek: Vec<u8>,
    pub akc: [u8; 32],
}

impl RelayFx {
    /// The relay of case 1.
    pub fn case1() -> Self {
        let c = reference().case(1);
        Self {
            sig_seed: c.input("relay_sig_seed"),
            dh_sk: c.input("relay_dh_sk"),
            kem_seed: c.input("relay_kem_seed"),
            access_key: c.input("relay_access_key"),
            kid: 1,
            rec_relayinfo: c.output("rec_relayinfo"),
            relay_fp: c.output("relay_fp").try_into().unwrap(),
            relay_dh_pk: c.output("relay_dh_pk"),
            relay_kem_ek: c.output("relay_kem_ek"),
            akc: c.output("akc").try_into().unwrap(),
        }
    }

    pub fn access(&self) -> AccessKey {
        SecretBytes::from_slice(&self.access_key).unwrap()
    }

    /// The library's relay keys of generation `kid` with these secrets.
    pub fn keys(&self) -> RelayKeys {
        self.keys_with_kid(self.kid)
    }

    pub fn keys_with_kid(&self, kid: u32) -> RelayKeys {
        RelayKeys::new(
            Ed25519SigningKey::from_seed(&self.sig_seed).unwrap(),
            X25519Secret::from_bytes(&self.dh_sk).unwrap(),
            MlKem1024Dk::from_seed(&self.kem_seed).unwrap(),
            self.access(),
            kid,
        )
        .unwrap()
    }

    /// Another static pair (same signing identity), for the wrong-static-key tests.
    pub fn keys_with_static(&self, dh_sk: &[u8], kem_seed: &[u8]) -> RelayKeys {
        RelayKeys::new(
            Ed25519SigningKey::from_seed(&self.sig_seed).unwrap(),
            X25519Secret::from_bytes(dh_sk).unwrap(),
            MlKem1024Dk::from_seed(kem_seed).unwrap(),
            self.access(),
            self.kid,
        )
        .unwrap()
    }

    /// `rec_relayinfo` with `f` applied to the record, then re-signed under `relay_sig` (the suite's re-signed
    /// manipulations).
    pub fn resigned(&self, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut rec = self.rec_relayinfo.clone();
        f(&mut rec);
        let signed = [Label::LinkRelayinfo.as_bytes(), &rec[3..3 + 1677]].concat();
        let sig = Ed25519SigningKey::from_seed(&self.sig_seed)
            .unwrap()
            .sign(&signed);
        rec[3 + 1677..].copy_from_slice(&sig);
        rec
    }
}

/// Offsets inside a `RELAYINFO` record (D.1): `len` 2, type 1, then the body.
pub mod ri {
    pub const VER: usize = 3;
    pub const SIG_PK: usize = 4;
    pub const KID: usize = 36;
    pub const DH_PK: usize = 40;
    pub const KEM_EK: usize = 72;
    pub const AKC: usize = 1640;
    pub const VALID_UNTIL: usize = 1672;
    pub const SIG: usize = 1680;
    pub const LEN: usize = 1744;
}

/// Offsets inside an `HS1` record (2856 B).
pub mod h1 {
    pub const VER: usize = 3;
    pub const KID: usize = 4;
    pub const E_C: usize = 8;
    pub const EK_C: usize = 40;
    pub const PK_E1: usize = 1224;
    pub const CT_KEM: usize = 1256;
    pub const MAC1: usize = 2824;
    pub const LEN: usize = 2856;
}

/// Offsets inside an `HS2` record (1156 B).
pub mod h2 {
    pub const VER: usize = 3;
    pub const E_R: usize = 4;
    pub const CT_C: usize = 36;
    pub const MAC2: usize = 1124;
    pub const LEN: usize = 1156;
}

/// The draws of `link-0003` in stream order: `e_c_sk`, `ek_c_seed`, `sk_e1`, `m1`.
pub fn client_draws(case: &Case) -> Vec<u8> {
    [
        case.input("e_c_sk"),
        case.input("ek_c_seed"),
        case.input("sk_e1"),
        case.input("m1"),
    ]
    .concat()
}

/// The draws of `link-0004`: `sk_er`, `m2`.
pub fn relay_draws(case: &Case) -> Vec<u8> {
    [case.input("sk_er"), case.input("m2")].concat()
}

pub fn client_entropy() -> FixedEntropy {
    FixedEntropy::new(&client_draws(reference().case(3)))
}

pub fn relay_entropy() -> FixedEntropy {
    FixedEntropy::new(&relay_draws(reference().case(4)))
}

/// Run the client up to `HS1` with the honest `link-0003` draws; returns the `HS1` record and the awaiting state.
pub fn client_hs1(
    fx: &RelayFx,
    rec_relayinfo: &[u8],
    access_key: Option<&AccessKey>,
) -> link::Result<(Vec<u8>, link::client::AwaitHs2)> {
    let (_hello, st) = link::client::start(fx.relay_fp, access_key, NOW).unwrap();
    st.on_relayinfo(rec_relayinfo, &mut client_entropy())
}

/// The honest handshake of `link-0001`…`link-0005`: the client's and the relay's end of link A.
pub fn honest_links() -> (Link, Link) {
    let fx = RelayFx::case1();
    let access = fx.access();
    let (_hello, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    let (rec_hs1, wait) = st
        .on_relayinfo(&fx.rec_relayinfo, &mut client_entropy())
        .unwrap();
    let keys = fx.keys();
    let (info, st) = link::relay::accept(&keys)
        .on_hello(&unhex("0007015345434d5001"), VALID_UNTIL)
        .unwrap();
    assert_eq!(info, fx.rec_relayinfo);
    let (rec_hs2, relay_link) = st.on_hs1(&rec_hs1, &mut relay_entropy()).unwrap();
    let client_link = wait.on_hs2(&rec_hs2).unwrap();
    (client_link, relay_link)
}

/// The honest `HS2` record and relay link for a given `HS1` record (the relay of case 1, draws of case 4).
pub fn relay_answer(fx: &RelayFx, rec_hs1: &[u8]) -> link::Result<(Vec<u8>, Link)> {
    let keys = fx.keys();
    let (_info, st) = link::relay::accept(&keys)
        .on_hello(&unhex("0007015345434d5001"), VALID_UNTIL)
        .unwrap();
    st.on_hs1(rec_hs1, &mut relay_entropy())
}

// ---------------------------------------------------------------------------------------------------------------
// An independent composition of spec §8.3, from raw bytes and `secmp-crypto` primitives.

/// The values of an `HS1` that `h0` and `mac1` depend on.
pub struct Hs1Parts {
    pub kid: u32,
    pub relay_fp: [u8; 32],
    pub e_c: Vec<u8>,
    pub ek_c: Vec<u8>,
    pub pk_e1: Vec<u8>,
    pub ct_kem: Vec<u8>,
}

/// `h0 = SHA-256("SecMP-LINK/1 h0" ‖ ver ‖ u32be(kid) ‖ relay_fp ‖ e_c ‖ SHA-256(ek_c) ‖ pk_e1 ‖ SHA-256(ct_kem))`,
/// a preimage of 180 B (spec §8.3).
pub fn h0_of(p: &Hs1Parts) -> [u8; 32] {
    let pre = [
        Label::LinkH0.as_bytes().to_vec(),
        vec![1],
        p.kid.to_be_bytes().to_vec(),
        p.relay_fp.to_vec(),
        p.e_c.clone(),
        sha256(&[&p.ek_c]).to_vec(),
        p.pk_e1.clone(),
        sha256(&[&p.ct_kem]).to_vec(),
    ]
    .concat();
    assert_eq!(pre.len(), 15 + 1 + 4 + 32 + 32 + 32 + 32 + 32);
    sha256(&[&pre])
}

/// `(ck1, mac1)` for `h0` and `ss1`.
pub fn ck1_mac1(h0: &[u8; 32], ss1: &[u8]) -> (SecretBytes<32>, [u8; 32]) {
    let ck1 = hkdf_extract(h0, ss1).unwrap();
    let mac1 = hmac_sha256(ck1.expose_secret(), Label::LinkHs1, &[]).unwrap();
    (ck1, mac1)
}

/// An `HS1` record with these fields and this `mac1` (the 2856-byte layout of D.1).
pub fn hs1_record(p: &Hs1Parts, mac1: &[u8; 32], ver: u8) -> Vec<u8> {
    let body = [
        vec![3, ver],
        p.kid.to_be_bytes().to_vec(),
        p.e_c.clone(),
        p.ek_c.clone(),
        p.pk_e1.clone(),
        p.ct_kem.clone(),
        mac1.to_vec(),
    ]
    .concat();
    let mut rec = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    rec.extend_from_slice(&body);
    rec
}

/// The fields of an honest `HS1` as the reference computes them, taken from the record of `link-0003`.
pub fn honest_hs1_parts(fx: &RelayFx) -> Hs1Parts {
    let c = reference().case(3);
    Hs1Parts {
        kid: fx.kid,
        relay_fp: fx.relay_fp,
        e_c: c.output("e_c"),
        ek_c: c.output("ek_c"),
        pk_e1: c.output("pk_e1"),
        ct_kem: c.output("ct_kem"),
    }
}

/// A complete honest `HS1` for `parts` encapsulating to the relay of `fx` with these draws (the client side of
/// §8.3, composed here): returns the record and `ss1`.
pub fn compose_hs1(
    fx: &RelayFx,
    e_c_sk: &[u8],
    ek_c_seed: &[u8],
    sk_e1: &[u8],
    m1: &[u8],
    kid: u32,
) -> (Vec<u8>, SecretBytes<32>, Hs1Parts, SecretBytes<32>) {
    let relay_pk = HybridKem1024PublicKey::new(
        X25519Public::from_bytes_checked(&fx.relay_dh_pk).unwrap(),
        MlKem1024Ek::from_bytes(&fx.relay_kem_ek).unwrap(),
    );
    let (ct, ss1) = relay_pk
        .encapsulate_kat(sk_e1.try_into().unwrap(), m1.try_into().unwrap())
        .unwrap();
    let e_c_secret = X25519Secret::from_bytes(e_c_sk).unwrap();
    let dk_c = MlKem768Dk::from_seed(ek_c_seed).unwrap();
    let kem_c = HybridKem768SecretKey::from_parts(e_c_secret, dk_c);
    let pk_c = kem_c.public_key();
    let parts = Hs1Parts {
        kid,
        relay_fp: fx.relay_fp,
        e_c: pk_c.pk_dh().as_bytes().to_vec(),
        ek_c: pk_c.ek().as_bytes().to_vec(),
        pk_e1: ct.pk_e().as_bytes().to_vec(),
        ct_kem: ct.ct().as_bytes().to_vec(),
    };
    let h0 = h0_of(&parts);
    let (ck1, mac1) = ck1_mac1(&h0, ss1.expose_secret());
    let rec = hs1_record(&parts, &mac1, 1);
    (rec, ss1, parts, ck1)
}

/// `(k_c2r, k_r2c, sess_id)` from `ck2` (spec §8.3).
pub fn expand_keys(ck2: &SecretBytes<32>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let okm = hkdf_expand::<80>(ck2.expose_secret(), Label::LinkKeys, &[]).unwrap();
    let b = okm.expose_secret();
    (b[..32].to_vec(), b[32..64].to_vec(), b[64..].to_vec())
}
