// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The Rust generator of the `hx` vector suite (`vectors/SCHEMA.md` §4.10, `vectors/SCHEMA-4.10-hx.md`), written
//! from the SCHEMA text and the spec; it reads no vector file and uses no `hx`/`inv`/`prekeys` code of the
//! library (the independent construction of `hx_harness.rs`).
//!
//! [`generate`] builds the 37 cases: 10 positive (keys-R, keys-I, invite, linkdata, invitee-accept, initiate,
//! respond, respond-garbage, and A1, A2), 9 `invitee-reject` (V1–V9) and 18 `respond-reject` (R1–R18), in the
//! SCHEMA order (positives, V1–V8, R1–R12, V9, R13, then A1, R14–R18, A2). Case *i* draws from its own SCHEMA §2 stream (suite `hx`,
//! index *i*): the stream-derived values in the order the SCHEMA lists them, then the derived ones.
//!
//! Shared by the `gen-hx` example (which writes `vectors/rust/hx.json` for `cargo xtask vectors`) and the
//! `hx_generator` test.

use std::slice::SliceIndex;

use serde_json::{Map, Value, json};

use secmp_crypto::{
    Caead, Ed25519SigningKey, Label, MlKem768Dk, MlKem1024Ct, MlKem1024Dk, SecretBytes,
    VectorStream, X25519Public, X25519Secret, sha3_256, sha256,
};
use secmp_proto::Encode;
use secmp_proto::codec::{pad, unpad};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::sizes::BODY_LEN;
use secmp_proto::tr::RatchetState;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{
    AppKind, AppMessage, BatchBody, Content, ContentBody, RelayQueue, RouteDescriptor,
};
use secmp_proto::wire::inv::{Onion, Profile, RelayRef};

#[path = "hx_harness.rs"]
pub mod harness;
#[path = "tr_digest.rs"]
pub mod tr_digest;

use harness::{
    AgreeIn, Agreement, CREATED, EXPIRES, IKS_LEN, INNER_LEN, Identity, LOW_ORDER_8, NOW,
    OFF_CT_OPK, OFF_CT_SPK, OFF_EK, OFF_INNER_CT, OFF_OPK_ID, OFF_SPK_ID, OPK_ID, OUTER_LEN,
    PADDED_LEN, Prekeys, SPK_ID, agree, blob, bundle_bytes, cell_plaintext, cell_raw, cells,
    chunk_of, fixed, handshake_content, hex, identity, inner_ct, k_id, k_inv, k_ld, linkdata_bytes,
    outer, profile_bytes, sk, snapshot, tr_initiator, tr_responder, transcript, unpadded_content,
};
use tr_digest::digest;

/// The suite name (SCHEMA §3).
pub const SUITE: &str = "hx";

fn case_id(i: u32) -> String {
    format!("hx-{i:04}")
}

/// The canonical bytes of a vector file: the compact JSON with sorted keys (ASCII).
pub fn canonical(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap();
    assert!(s.is_ascii(), "vector files are ASCII");
    s
}

struct Stream {
    s: VectorStream,
    inputs: Map<String, Value>,
    /// Every byte drawn, in stream order.
    drawn: Vec<u8>,
}

impl Stream {
    fn new(i: u32) -> Self {
        Self {
            s: VectorStream::new(SUITE, i),
            inputs: Map::new(),
            drawn: Vec::new(),
        }
    }

    fn draw(&mut self, name: &str, n: usize) -> Vec<u8> {
        let v = self.s.take(n);
        self.drawn.extend_from_slice(&v);
        self.list(name, &v);
        v
    }

    fn arr<const N: usize>(&mut self, name: &str) -> [u8; N] {
        self.draw(name, N).try_into().unwrap()
    }

    /// Lists input `name` (a derived input is listed after the case's stream draws).
    fn list(&mut self, name: &str, v: &[u8]) {
        let fresh = self.inputs.insert(name.to_owned(), json!(hex(v))).is_none();
        assert!(fresh, "input {name} listed twice");
    }

    fn list_value(&mut self, name: &str, v: Value) {
        let fresh = self.inputs.insert(name.to_owned(), v).is_none();
        assert!(fresh, "input {name} listed twice");
    }

    fn dh_step(&mut self) -> Vec<u8> {
        self.dh_step_named("dh_sk", "kem_seed", "m")
    }

    /// A DH-step draw (`dh_sk` ‖ `kem_seed` ‖ `m`) under the given input names (A1's second step: `_2`).
    fn dh_step_named(&mut self, dh_sk: &str, kem_seed: &str, m: &str) -> Vec<u8> {
        [
            self.draw(dh_sk, 32),
            self.draw(kem_seed, 64),
            self.draw(m, 32),
        ]
        .concat()
    }

    fn finish(self, i: u32, op: &str, party: &str, rest: Vec<(&str, Value)>) -> Value {
        let mut case = Map::new();
        case.insert("id".into(), json!(case_id(i)));
        case.insert("op".into(), json!(op));
        case.insert("party".into(), json!(party));
        case.insert("inputs".into(), Value::Object(self.inputs));
        for (k, v) in rest {
            case.insert(k.into(), v);
        }
        Value::Object(case)
    }
}

fn hex_array(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| json!(hex(b))).collect())
}

/// `onion = PUBKEY ‖ SHA3-256(".onion checksum" ‖ PUBKEY ‖ 0x03)[0..2] ‖ 0x03` (Tor rend-spec-v3 §6).
fn onion(pubkey: &[u8; 32]) -> Vec<u8> {
    let sum = sha3_256(&[b".onion checksum", pubkey, &[3]]);
    [pubkey.as_slice(), &sum[..2], &[3]].concat()
}

/// `InvitationV1` (§5.2) bytes, 241 B.
pub struct Invitation {
    pub relay_fp: [u8; 32],
    pub onion_pubkey: [u8; 32],
    pub akc: [u8; 32],
    pub ld_id: [u8; 16],
    pub link_key: [u8; 32],
    pub inviter_fp: [u8; 32],
    /// Derived (§9.1, ADR-048 (m)): SHA-256("SecMP-Q/1 sid" ‖ `invq_recv_pk` ‖ `inv_send_pk`)[0..16].
    pub inv_sid: [u8; 16],
    pub inv_send_seed: [u8; 32],
    /// The Ed25519 seed of the invitation queue's recipient key (§5.2) and of the link-data owner key.
    pub invq_recv_seed: [u8; 32],
    pub owner_seed: [u8; 32],
}

/// The Ed25519 public key of `seed`.
fn ed25519_pk(seed: &[u8; 32]) -> [u8; 32] {
    *Ed25519SigningKey::from_seed(seed)
        .unwrap()
        .verifying_key()
        .as_bytes()
}

impl Invitation {
    pub fn encode(&self, ver: u8, kind: u8, expires: u64) -> Vec<u8> {
        let mut b = vec![ver, kind, 0x01];
        b.extend_from_slice(&self.relay_fp);
        b.extend_from_slice(&onion(&self.onion_pubkey));
        b.extend_from_slice(&self.akc);
        b.push(0); // direct_present
        b.extend_from_slice(&self.ld_id);
        b.extend_from_slice(&self.link_key);
        b.extend_from_slice(&self.inviter_fp);
        b.extend_from_slice(&self.inv_sid);
        b.extend_from_slice(&self.inv_send_seed);
        b.extend_from_slice(&20_u16.to_be_bytes());
        b.extend_from_slice(&expires.to_be_bytes());
        assert_eq!(b.len(), 241);
        b
    }
}

fn uri(invitation: &[u8]) -> String {
    format!(
        "secmp://i/{}",
        secmp_proto::inv::base64url_encode(invitation).as_str()
    )
}

fn flip_last_bit(mut b: Vec<u8>, at: usize) -> Vec<u8> {
    *byte_mut(&mut b, at) ^= 1;
    b
}

/// `b[at]` for a mutable byte; the generator's offsets are constants, so a miss is a bug in the generator.
fn byte_mut(b: &mut [u8], at: usize) -> &mut u8 {
    b.get_mut(at).unwrap()
}

/// `&b[r]`.
fn sl<R: SliceIndex<[u8], Output = [u8]>>(b: &[u8], r: R) -> &[u8] {
    b.get(r).unwrap()
}

/// `&mut b[r]`.
fn sl_mut<R: SliceIndex<[u8], Output = [u8]>>(b: &mut [u8], r: R) -> &mut [u8] {
    b.get_mut(r).unwrap()
}

/// The relay queue of the Handshake's route as the §4.8 row `rd_relayqueue`: `relay_fp` 32, `onion_seed` 32
/// (→ `onion` from the Ed25519 public key of the seed), `akc` 32, no `direct`, `sid` 16, `send_seed` 32, `period_s` 20.
fn relay_queue(s: &mut Stream) -> RouteDescriptor {
    let relay_fp = s.arr::<32>("relay_fp");
    let onion_key = Ed25519SigningKey::from_seed(&s.draw("onion_seed", 32)).unwrap();
    let onion_pk = Ed25519Pk::from_bytes(onion_key.verifying_key().as_bytes()).unwrap();
    let relay = RelayRef {
        relay_fp,
        onion: Onion::from_pubkey(onion_pk.as_bytes()),
        akc: s.arr("akc"),
        direct: None,
    };
    RouteDescriptor::RelayQueue(RelayQueue {
        relay,
        sid: s.arr("sid"),
        send_seed: SecretBytes::from_slice(&s.draw("send_seed", 32)).unwrap(),
        period_s: Period::S20,
    })
}

fn case1() -> (Base1, Value) {
    let mut s = Stream::new(1);
    let xi = s.draw("ik_mldsa_xi", 32);
    let ed = s.draw("ik_ed_seed", 32);
    let dh = s.draw("ik_dh_sk", 32);
    let r = identity(&xi, &ed, &dh);
    let keys = Prekeys {
        spk_dh: X25519Secret::from_bytes(&s.draw("spk_dh_sk", 32)).unwrap(),
        spk_kem: MlKem1024Dk::from_seed(&s.draw("spk_kem_seed", 64)).unwrap(),
        rpk_kem: MlKem768Dk::from_seed(&s.draw("rpk_kem_seed", 64)).unwrap(),
        opk_dh: X25519Secret::from_bytes(&s.draw("opk_dh_sk", 32)).unwrap(),
        opk_kem: MlKem1024Dk::from_seed(&s.draw("opk_kem_seed", 64)).unwrap(),
    };
    let rnd: [u8; 32] = s.arr("rnd");
    let bundle = bundle_bytes(&r, &keys, EXPIRES, 1, &rnd);
    let outputs = json!({
        "iks": hex(&r.iks_bytes),
        "fp": hex(&r.fp),
        "bundle": hex(&bundle),
        "opks_post": [OPK_ID],
    });
    let seed = s.drawn.clone();
    let case = s.finish(1, "keys-R", "R", vec![("outputs", outputs)]);
    (
        Base1 {
            r,
            keys,
            bundle,
            seed,
        },
        case,
    )
}

struct Base1 {
    r: Identity,
    keys: Prekeys,
    bundle: Vec<u8>,
    seed: Vec<u8>,
}

fn case2() -> (Identity, Vec<u8>, Value) {
    let mut s = Stream::new(2);
    let xi = s.draw("ik_mldsa_xi", 32);
    let ed = s.draw("ik_ed_seed", 32);
    let dh = s.draw("ik_dh_sk", 32);
    let i = identity(&xi, &ed, &dh);
    let outputs = json!({"iks": hex(&i.iks_bytes), "fp": hex(&i.fp)});
    let seed = s.drawn.clone();
    let case = s.finish(2, "keys-I", "I", vec![("outputs", outputs)]);
    (i, seed, case)
}

fn case3(r: &Identity) -> (Invitation, Vec<u8>, String, Value) {
    let mut s = Stream::new(3);
    let relay_fp = s.arr("relay_fp");
    let onion_pubkey = s.arr("onion_pubkey");
    let akc = s.arr("akc");
    let ld_id = s.arr("ld_id");
    let link_key = s.arr("link_key");
    // OPEN-M5-14 B: the 16 bytes formerly drawn for `inv_sid` are drawn at their old place and discarded
    let _discarded: [u8; 16] = s.arr("inv_sid_discarded");
    let inv_send_seed = s.arr("inv_send_seed");
    let invq_recv_seed = s.arr("invq_recv_seed");
    let owner_seed = s.arr("owner_seed");
    let invq_recv_pk = ed25519_pk(&invq_recv_seed);
    let inv_sid: [u8; 16] = sha256(&[
        Label::QSid.as_bytes(),
        &invq_recv_pk,
        &ed25519_pk(&inv_send_seed),
    ])[..16]
        .try_into()
        .unwrap();
    let inv = Invitation {
        relay_fp,
        onion_pubkey,
        akc,
        ld_id,
        link_key,
        inv_sid,
        inv_send_seed,
        invq_recv_seed,
        owner_seed,
        inviter_fp: r.fp,
    };
    let encoded = inv.encode(1, 1, EXPIRES);
    let text = uri(&encoded);
    assert_eq!(text.len(), 332);
    let outputs = json!({
        "invitation": hex(&encoded),
        "uri": text,
        "inv_sid": hex(&inv_sid),
        "invq_recv_pk": hex(&ed25519_pk(&inv.invq_recv_seed)),
        "owner_pk": hex(&ed25519_pk(&inv.owner_seed)),
    });
    let case = s.finish(3, "invite", "R", vec![("outputs", outputs)]);
    (inv, encoded, text, case)
}

fn case4(b1: &Base1, inv: &Invitation) -> (Vec<u8>, Vec<u8>, SecretBytes<32>, Value) {
    let mut s = Stream::new(4);
    let n = s.draw("n", 24);
    let k = k_ld(&inv.ld_id, &inv.link_key);
    let linkdata = linkdata_bytes(
        &b1.r.iks_bytes,
        &b1.bundle,
        &profile_bytes("bob", None),
        CREATED,
    );
    assert_eq!(linkdata.len(), 9806);
    let sealed = blob(&k, &inv.ld_id, &n, &linkdata);
    let outputs =
        json!({"k_ld": hex(k.expose_secret()), "linkdata": hex(&linkdata), "blob": hex(&sealed)});
    let case = s.finish(4, "linkdata", "R", vec![("outputs", outputs)]);
    (linkdata, sealed, k, case)
}

fn case5(inv: &Invitation, k: &SecretBytes<32>) -> (SecretBytes<32>, Value) {
    let s = Stream::new(5);
    let k_inv_value = k_inv(&inv.ld_id, &inv.link_key);
    let outputs = json!({
        "k_ld": hex(k.expose_secret()),
        "k_inv": hex(k_inv_value.expose_secret()),
        "accept": true,
    });
    (
        k_inv_value,
        s.finish(5, "invitee-accept", "I", vec![("outputs", outputs)]),
    )
}

/// The stream draws of case 6 (`initiate`), in SCHEMA order.
struct Draws6 {
    ek_sk: Vec<u8>,
    m_signed: [u8; 32],
    m_onetime: [u8; 32],
    dh_s_sk: Vec<u8>,
    kem_s_seed: Vec<u8>,
    m_tr: Vec<u8>,
    avatar: [u8; 32],
    route: RouteDescriptor,
    hdr_nonce: Vec<u8>,
    inner_nonce: Vec<u8>,
    init_id: [u8; 16],
    cell_nonces: [Vec<u8>; 3],
}

fn draws6(s: &mut Stream) -> Draws6 {
    Draws6 {
        ek_sk: s.draw("ek_sk", 32),
        m_signed: s.arr("m_spk"),
        m_onetime: s.arr("m_opk"),
        dh_s_sk: s.draw("dh_s_sk", 32),
        kem_s_seed: s.draw("kem_s_seed", 64),
        m_tr: s.draw("m_tr", 32),
        avatar: s.arr("avatar_sha256"),
        route: relay_queue(s),
        hdr_nonce: s.draw("hdr_nonce", 24),
        inner_nonce: s.draw("inner_nonce", 24),
        init_id: s.arr("init_id"),
        cell_nonces: [
            s.draw("cell_nonce_0", 24),
            s.draw("cell_nonce_1", 24),
            s.draw("cell_nonce_2", 24),
        ],
    }
}

/// The randomness of `Initiator::start` in the library's draw order (`ek_sk` ... `cell_nonce_2`).
fn entropy6(d: &Draws6) -> Vec<u8> {
    [
        d.ek_sk.as_slice(),
        &d.m_signed,
        &d.m_onetime,
        &d.dh_s_sk,
        &d.kem_s_seed,
        &d.m_tr,
        &d.hdr_nonce,
        &d.inner_nonce,
        &d.init_id,
        &d.cell_nonces[0],
        &d.cell_nonces[1],
        &d.cell_nonces[2],
    ]
    .concat()
}

/// The `outputs` of case 6.
fn outputs6(
    b6: &Base6,
    k_inv_value: &SecretBytes<32>,
    inner_ct_bytes: &[u8],
    state: &RatchetState,
) -> Value {
    let a = &b6.a;
    json!({
        "ek_pk": hex(&a.ek_pk),
        "dh1": hex(&a.dh[0]), "dh2": hex(&a.dh[1]), "dh3": hex(&a.dh[2]), "dh4": hex(&a.dh[3]),
        "ct_spk": hex(&a.ct_spk), "ss_spk": hex(&a.ss_spk),
        "ct_opk": hex(&a.ct_opk), "ss_opk": hex(&a.ss_opk),
        "transcript": hex(&a.transcript),
        "sk": hex(a.sk.expose_secret()),
        "k_id": hex(a.k_id.expose_secret()),
        "k_inv": hex(k_inv_value.expose_secret()),
        "content": hex(&b6.content),
        "first_msg": hex(&b6.first_msg),
        "inner_ct": hex(inner_ct_bytes),
        "outer": hex(&b6.outer),
        "cell_0": hex(&b6.cells[0]), "cell_1": hex(&b6.cells[1]), "cell_2": hex(&b6.cells[2]),
        "state_post_I": digest(state),
    })
}

/// Case 6 (`initiate`): §6.4, §6.5, §7.2 initiator, §7.3 Encrypt of the Handshake Content.
fn case6(b: &Base0) -> (Base6, Value) {
    let mut s = Stream::new(6);
    let d = draws6(&mut s);
    let route_encoded = d.route.encode().unwrap().to_vec();
    let entropy = entropy6(&d);
    let a = agree(&AgreeIn {
        i: b.i,
        r: b.r,
        keys: b.keys,
        ld_id: &b.inv.ld_id,
        link_key: &b.inv.link_key,
        ek_sk: &d.ek_sk,
        m_spk: &d.m_signed,
        m_opk: &d.m_onetime,
    });
    let k_inv_value = k_inv(&b.inv.ld_id, &b.inv.link_key);
    let state = tr_initiator(&a, b.keys, &d.dh_s_sk, &d.kem_s_seed, &d.m_tr);
    let i_after_init = snapshot(&state);
    let content = handshake_content(
        Profile::new("alice", Some(d.avatar)).unwrap(),
        vec![d.route],
        1,
        1_700_000_001,
    );
    let content_bytes = unpadded_content(&content);
    assert_eq!(content_bytes.len(), 219);
    let (state, cell) = state
        .encrypt_with(&content, &mut fixed(&[&d.hdr_nonce]))
        .map_err(|r| r.error())
        .unwrap()
        .persist(|_| Ok::<(), ()>(()))
        .unwrap();
    let first_msg = cell.as_bytes().to_vec();
    let inner = [b.i.iks_bytes.as_slice(), &first_msg].concat();
    let inner_ct_bytes = inner_ct(&a.k_id, &b.inv.ld_id, &d.inner_nonce, &inner);
    let outer_bytes = outer(
        &a.ek_pk,
        SPK_ID,
        OPK_ID,
        &a.ct_spk,
        &a.ct_opk,
        &inner_ct_bytes,
    );
    let cells_bytes = cells(
        &k_inv_value,
        &b.inv.ld_id,
        &d.init_id,
        [&d.cell_nonces[0], &d.cell_nonces[1], &d.cell_nonces[2]],
        &outer_bytes,
    );
    let b6 = Base6 {
        a,
        first_msg,
        inner,
        outer: outer_bytes,
        init_id: d.init_id,
        cells: cells_bytes,
        content: content_bytes,
        i_after_init,
        entropy,
        route: route_encoded,
        avatar: d.avatar,
    };
    let outputs = outputs6(&b6, &k_inv_value, &inner_ct_bytes, &state);
    let case = s.finish(6, "initiate", "I", vec![("outputs", outputs)]);
    (b6, case)
}

struct Base0<'a> {
    r: &'a Identity,
    i: &'a Identity,
    keys: &'a Prekeys,
    inv: &'a Invitation,
}

/// Case 6 and what the negative cases build on.
pub struct Base6 {
    pub a: Agreement,
    pub first_msg: Vec<u8>,
    pub inner: Vec<u8>,
    pub outer: Vec<u8>,
    pub init_id: [u8; 16],
    pub cells: [Vec<u8>; 3],
    pub content: Vec<u8>,
    pub i_after_init: RatchetState,
    /// The randomness of `Initiator::start` in the library's draw order (`ek_sk` … `cell_nonce_2`).
    pub entropy: Vec<u8>,
    /// The Handshake's route, encoded (155 B), and the profile's avatar hash.
    pub route: Vec<u8>,
    pub avatar: [u8; 32],
}

/// R's processing of an honest group (§6.5, §6.6 steps 1–4) from `fetched`, with the DH-step randomness `step`.
struct Responded {
    transcript: [u8; 32],
    sk: SecretBytes<32>,
    k_id: SecretBytes<32>,
    peer_iks: Vec<u8>,
    content: Vec<u8>,
    profile: Vec<u8>,
    routes: Vec<Vec<u8>>,
    state_digest: String,
}

/// Trial-opens every fetched cell (those that do not open are ignored), reassembles the three chunks and
/// unpads them to the unpadded `Outer`.
fn reassemble(b: &Base0, fetched: &[Vec<u8>]) -> Vec<u8> {
    let k_inv_value = k_inv(&b.inv.ld_id, &b.inv.link_key);
    let ad = [Label::HxInitcell.as_bytes(), b.inv.ld_id.as_slice()].concat();
    let mut chunks: [Option<Vec<u8>>; 3] = [None, None, None];
    for cell in fetched {
        let (n, rest) = cell.split_at(24);
        let Ok(pt) = Caead::open(&k_inv_value, n.try_into().unwrap(), &ad, rest) else {
            continue;
        };
        // plaintext: init_id (16) || i || total || chunk
        let (Some(&idx), Some(&total)) = (pt.get(16), pt.get(17)) else {
            continue;
        };
        if pt.len() != 4024 || total != 3 || idx > 2 {
            continue;
        }
        let Some(slot) = chunks.get_mut(usize::from(idx)) else {
            continue;
        };
        if slot.is_none() {
            *slot = Some(sl(&pt, 18..).to_vec());
        }
    }
    let padded: Vec<u8> = chunks.into_iter().flat_map(|c| c.unwrap()).collect();
    let outer_bytes = unpad(&padded, PADDED_LEN).unwrap().to_vec();
    assert_eq!(outer_bytes.len(), OUTER_LEN);
    outer_bytes
}

fn respond(b: &Base0, fetched: &[Vec<u8>], step: &[u8]) -> Responded {
    let outer_bytes = reassemble(b, fetched);
    let ek = sl(&outer_bytes, OFF_EK..OFF_EK + 32);
    let ct_signed = sl(&outer_bytes, OFF_CT_SPK..OFF_CT_OPK);
    let ct_onetime = sl(&outer_bytes, OFF_CT_OPK..OFF_INNER_CT);
    let inner_ct_bytes = sl(&outer_bytes, OFF_INNER_CT..);
    let ek_pub = X25519Public::from_bytes(ek).unwrap();
    let dh3 = b.keys.spk_dh.diffie_hellman(&ek_pub).unwrap();
    let dh4 = b.keys.opk_dh.diffie_hellman(&ek_pub).unwrap();
    let ss_signed = b
        .keys
        .spk_kem
        .decapsulate(&MlKem1024Ct::from_bytes(ct_signed).unwrap());
    let ss_onetime = b
        .keys
        .opk_kem
        .decapsulate(&MlKem1024Ct::from_bytes(ct_onetime).unwrap());
    let k_id_value = k_id(
        &b.inv.ld_id,
        &b.inv.link_key,
        dh3.expose_secret(),
        ss_signed.expose_secret(),
        dh4.expose_secret(),
        ss_onetime.expose_secret(),
    );
    let ad_inner = [Label::HxInner.as_bytes(), b.inv.ld_id.as_slice()].concat();
    let (n2, rest) = inner_ct_bytes.split_at(24);
    let inner = Caead::open(&k_id_value, n2.try_into().unwrap(), &ad_inner, rest).unwrap();
    let (iks_i, first_msg) = inner.split_at(IKS_LEN);
    let iks_i_pub = X25519Public::from_bytes(sl(iks_i, IKS_LEN - 32..)).unwrap();
    let dh1 = b.keys.spk_dh.diffie_hellman(&iks_i_pub).unwrap();
    let dh2 = b.r.dh.diffie_hellman(&ek_pub).unwrap();
    let tr = transcript([
        &b.r.iks_bytes,
        &SPK_ID.to_be_bytes(),
        b.keys.spk_dh.public_key().as_bytes(),
        b.keys.spk_kem.encapsulation_key().as_bytes(),
        b.keys.rpk_kem.encapsulation_key().as_bytes(),
        &OPK_ID.to_be_bytes(),
        b.keys.opk_dh.public_key().as_bytes(),
        b.keys.opk_kem.encapsulation_key().as_bytes(),
        iks_i,
        ek,
        ct_signed,
        ct_onetime,
        &b.inv.ld_id,
    ]);
    let sk_value = sk(
        [
            dh1.expose_secret(),
            dh2.expose_secret(),
            dh3.expose_secret(),
            dh4.expose_secret(),
            ss_signed.expose_secret(),
            ss_onetime.expose_secret(),
        ],
        &tr,
    );
    let state = tr_responder(&sk_value, &tr, b.keys);
    let mut e = fixed(&[step]);
    let (state, plaintext) = state
        .decrypt_with(first_msg, &mut e)
        .map_err(|r| r.error())
        .unwrap()
        .commit(|_| Ok::<(), ()>(()))
        .unwrap();
    assert_eq!(
        e.remaining(),
        0,
        "R's DH step draws exactly the step randomness"
    );
    let content = plaintext.content().unwrap();
    let handshake = match &content.body {
        ContentBody::Handshake(h) => Some(h),
        _ => None,
    }
    .expect("the first message is a Handshake");
    Responded {
        transcript: tr,
        sk: sk_value,
        k_id: k_id_value,
        peer_iks: iks_i.to_vec(),
        content: unpad(plaintext.as_bytes(), BODY_LEN).unwrap().to_vec(),
        profile: handshake.profile.encode().unwrap().to_vec(),
        routes: handshake
            .routes
            .iter()
            .map(|r| r.encode().unwrap().to_vec())
            .collect(),
        state_digest: digest(&state),
    }
}

fn responded_outputs(r: &Responded) -> Value {
    json!({
        "transcript": hex(&r.transcript),
        "sk": hex(r.sk.expose_secret()),
        "k_id": hex(r.k_id.expose_secret()),
        "peer_iks": hex(&r.peer_iks),
        "content": hex(&r.content),
        "profile": hex(&r.profile),
        "routes": hex_array(&r.routes),
        "state_post_R": r.state_digest,
        "opks_post": [],
    })
}

fn case7(b: &Base0, b6: &Base6) -> Value {
    let mut s = Stream::new(7);
    let step = s.dh_step();
    let fetched: Vec<Vec<u8>> = b6.cells.to_vec();
    s.list_value("fetched", hex_array(&fetched));
    let outputs = responded_outputs(&respond(b, &fetched, &step));
    s.finish(7, "respond", "R", vec![("outputs", outputs)])
}

fn case8(b: &Base0, b6: &Base6) -> Value {
    let mut s = Stream::new(8);
    let g1 = s.draw("g1", 4096);
    let g2 = s.draw("g2", 4096);
    let step = s.dh_step();
    let fetched = vec![
        g1,
        b6.cells[0].clone(),
        g2,
        b6.cells[1].clone(),
        b6.cells[2].clone(),
    ];
    s.list_value("fetched", hex_array(&fetched));
    let outputs = responded_outputs(&respond(b, &fetched, &step));
    s.finish(8, "respond-garbage", "R", vec![("outputs", outputs)])
}

// ---- invitee-reject -----------------------------------------------------------------------------------------

fn reject_i(s: Stream, i: u32, manipulation: &str) -> Value {
    s.finish(
        i,
        "invitee-reject",
        "I",
        vec![
            ("manipulation", json!(manipulation)),
            ("expect", json!("reject")),
        ],
    )
}

struct Pos<'a> {
    base: &'a Base0<'a>,
    bundle: &'a [u8],
    linkdata: &'a [u8],
    invitation: &'a [u8],
}

fn v_invitation(p: &Pos<'_>, i: u32, manipulation: &str, mutated: &[u8]) -> Value {
    let mut s = Stream::new(i);
    s.list("invitation", mutated);
    s.list_value("uri", json!(uri(mutated)));
    let _ = p;
    reject_i(s, i, manipulation)
}

fn seal_linkdata(p: &Pos<'_>, n: &[u8], linkdata: &[u8]) -> Vec<u8> {
    let k = k_ld(&p.base.inv.ld_id, &p.base.inv.link_key);
    blob(&k, &p.base.inv.ld_id, n, linkdata)
}

/// V4–V7, V9: a `LinkDataV1` variant, sealed under the case 3 `K_ld` with the stream's `n`.
fn v_linkdata(
    p: &Pos<'_>,
    i: u32,
    manipulation: &str,
    mut s: Stream,
    n: &[u8],
    linkdata: &[u8],
) -> Value {
    let sealed = seal_linkdata(p, n, linkdata);
    s.list("linkdata", linkdata);
    s.list("blob", &sealed);
    reject_i(s, i, manipulation)
}

fn v_cases(p: &Pos<'_>) -> Vec<(u32, Value)> {
    let bundle_end = 1 + IKS_LEN + 7775;
    // the first byte of `bundle.sig` (the Ed25519 `R`), inside the unpadded LinkDataV1
    let sig_at = bundle_end - 3373;
    let mut out = Vec::new();

    // V1 expired: `expires` := now − 1
    let mut inv = p.invitation.to_vec();
    inv.truncate(233);
    inv.extend_from_slice(&(NOW - 1).to_be_bytes());
    out.push((9, v_invitation(p, 9, "inv-expired", &inv)));
    // V2 kind := 0x02, V3 ver := 0x02
    let mut inv = p.invitation.to_vec();
    *byte_mut(&mut inv, 1) = 2;
    out.push((10, v_invitation(p, 10, "inv-kind-multi", &inv)));
    let mut inv = p.invitation.to_vec();
    *byte_mut(&mut inv, 0) = 2;
    out.push((11, v_invitation(p, 11, "inv-ver", &inv)));

    // V4 fingerprint mismatch: a fresh IKS, bundle unchanged
    let mut s = Stream::new(12);
    let xi = s.draw("ik_mldsa_xi", 32);
    let ed = s.draw("ik_ed_seed", 32);
    let dh = s.draw("ik_dh_sk", 32);
    let n = s.draw("n", 24);
    let fresh = identity(&xi, &ed, &dh);
    let linkdata = linkdata_bytes(
        &fresh.iks_bytes,
        p.bundle,
        &profile_bytes("bob", None),
        CREATED,
    );
    out.push((12, v_linkdata(p, 12, "ld-fp-mismatch", s, &n, &linkdata)));

    // V5 bad signature (ML-DSA part): bit 0 of the last byte of `bundle.sig`
    let mut s = Stream::new(13);
    let n = s.draw("n", 24);
    let linkdata = flip_last_bit(p.linkdata.to_vec(), bundle_end - 1);
    out.push((13, v_linkdata(p, 13, "ld-bad-sig", s, &n, &linkdata)));

    // V6 bundle expired: spk_expiry := now − 1, re-signed
    let mut s = Stream::new(14);
    let rnd: [u8; 32] = s.arr("rnd");
    let n = s.draw("n", 24);
    let bundle = bundle_bytes(p.base.r, p.base.keys, NOW - 1, 1, &rnd);
    let linkdata = linkdata_bytes(
        &p.base.r.iks_bytes,
        &bundle,
        &profile_bytes("bob", None),
        CREATED,
    );
    out.push((14, v_linkdata(p, 14, "ld-bundle-expired", s, &n, &linkdata)));

    // V7 opk_present := 0x00, re-signed
    let mut s = Stream::new(15);
    let rnd: [u8; 32] = s.arr("rnd");
    let n = s.draw("n", 24);
    let bundle = bundle_bytes(p.base.r, p.base.keys, EXPIRES, 0, &rnd);
    let linkdata = linkdata_bytes(
        &p.base.r.iks_bytes,
        &bundle,
        &profile_bytes("bob", None),
        CREATED,
    );
    out.push((15, v_linkdata(p, 15, "ld-opk-absent", s, &n, &linkdata)));

    // V8 wrong key: K_ld of link_key with bit 0 of byte 0 flipped
    let mut s = Stream::new(16);
    let n = s.draw("n", 24);
    let mut wrong = p.base.inv.link_key;
    wrong[0] ^= 1;
    let sealed = blob(
        &k_ld(&p.base.inv.ld_id, &wrong),
        &p.base.inv.ld_id,
        &n,
        p.linkdata,
    );
    s.list("blob", &sealed);
    out.push((16, reject_i(s, 16, "ld-wrong-key")));

    // V9 bad signature (Ed25519 part): bit 0 of byte 0 of `bundle.sig`
    let mut s = Stream::new(29);
    let n = s.draw("n", 24);
    let linkdata = flip_last_bit(p.linkdata.to_vec(), sig_at);
    out.push((29, v_linkdata(p, 29, "ld-bad-sig-ed", s, &n, &linkdata)));
    out
}

// ---- respond-reject -------------------------------------------------------------------------------------------

struct Re<'a> {
    base: &'a Base0<'a>,
    b6: &'a Base6,
}

fn reject_r(
    mut s: Stream,
    i: u32,
    manipulation: &str,
    fetched: &[Vec<u8>],
    opks_post: &[u32],
) -> Value {
    s.list_value("fetched", hex_array(fetched));
    s.finish(
        i,
        "respond-reject",
        "R",
        vec![
            ("manipulation", json!(manipulation)),
            ("expect", json!("reject")),
            ("outputs", json!({"opks_post": opks_post})),
        ],
    )
}

/// Re-seal draws: `init_id` 16, `cell_nonce_0..2` 24 each, then the three cells of `outer`.
fn reseal(re: &Re<'_>, s: &mut Stream, outer: &[u8]) -> Vec<Vec<u8>> {
    let init_id: [u8; 16] = s.arr("init_id");
    let n0 = s.draw("cell_nonce_0", 24);
    let n1 = s.draw("cell_nonce_1", 24);
    let n2 = s.draw("cell_nonce_2", 24);
    let k = k_inv(&re.base.inv.ld_id, &re.base.inv.link_key);
    cells(&k, &re.base.inv.ld_id, &init_id, [&n0, &n1, &n2], outer).to_vec()
}

/// A case that changes `Outer`: stream = re-seal draws; `outer` is listed after them.
fn outer_case(re: &Re<'_>, i: u32, manipulation: &str, mutate: impl FnOnce(&mut Vec<u8>)) -> Value {
    let mut s = Stream::new(i);
    let mut outer = re.b6.outer.clone();
    mutate(&mut outer);
    let fetched = {
        // the draws come first: init_id, nonces
        let cells = reseal(re, &mut s, &outer);
        s.list("outer", &outer);
        cells
    };
    reject_r(s, i, manipulation, &fetched, &[OPK_ID])
}

/// A case that changes `Inner` (and so `inner_ct` and `Outer`): stream = `inner_nonce`, the re-seal draws,
/// optionally the DH-step draws; `inner` and `outer` are listed after them.
fn inner_case(re: &Re<'_>, i: u32, manipulation: &str, with_step: bool, inner: &[u8]) -> Value {
    let mut s = Stream::new(i);
    let inner_nonce = s.draw("inner_nonce", 24);
    let a = &re.b6.a;
    let ict = inner_ct(&a.k_id, &re.base.inv.ld_id, &inner_nonce, inner);
    let outer_bytes = outer(&a.ek_pk, SPK_ID, OPK_ID, &a.ct_spk, &a.ct_opk, &ict);
    let fetched = reseal(re, &mut s, &outer_bytes);
    if with_step {
        let _ = s.dh_step();
    }
    s.list("inner", inner);
    s.list("outer", &outer_bytes);
    reject_r(s, i, manipulation, &fetched, &[OPK_ID])
}

/// R9 / R13: a different first message encrypted from I's post-init state with `hdr_nonce`.
fn first_msg_case(
    re: &Re<'_>,
    i: u32,
    manipulation: &str,
    pre: impl FnOnce(&mut Stream) -> Vec<u8>,
) -> Value {
    let mut s = Stream::new(i);
    // the Content's own draws (R13: msg_id, payload) come first; `pre` returns the padded body
    let padded_body = pre(&mut s);
    let hdr_nonce = s.draw("hdr_nonce", 24);
    let inner_nonce = s.draw("inner_nonce", 24);
    let state = snapshot(&re.b6.i_after_init);
    let cell = state
        .encrypt_padded_kat(&padded_body, &mut fixed(&[&hdr_nonce]))
        .map_err(|r| r.error())
        .unwrap()
        .persist(|_| Ok::<(), ()>(()))
        .unwrap()
        .1;
    let inner = [re.base.i.iks_bytes.as_slice(), cell.as_bytes()].concat();
    let a = &re.b6.a;
    let ict = inner_ct(&a.k_id, &re.base.inv.ld_id, &inner_nonce, &inner);
    let outer_bytes = outer(&a.ek_pk, SPK_ID, OPK_ID, &a.ct_spk, &a.ct_opk, &ict);
    let fetched = reseal(re, &mut s, &outer_bytes);
    let _ = s.dh_step();
    let content = unpad(&padded_body, BODY_LEN).unwrap().to_vec();
    s.list("content", &content);
    s.list("inner", &inner);
    s.list("outer", &outer_bytes);
    reject_r(s, i, manipulation, &fetched, &[OPK_ID])
}

/// R15 / R16 / R18: the first message is a cell built by `build` (which draws its own `hdr_nonce`s, and returns
/// the cell and the unpadded Content); stream = `build`'s draws, `inner_nonce`, the re-seal draws, the DH step.
fn first_msg_cell_case(
    re: &Re<'_>,
    i: u32,
    manipulation: &str,
    build: impl FnOnce(&mut Stream) -> (Vec<u8>, Vec<u8>),
) -> Value {
    let mut s = Stream::new(i);
    let (cell, content) = build(&mut s);
    let inner_nonce = s.draw("inner_nonce", 24);
    let inner = [re.base.i.iks_bytes.as_slice(), &cell].concat();
    let a = &re.b6.a;
    let ict = inner_ct(&a.k_id, &re.base.inv.ld_id, &inner_nonce, &inner);
    let outer_bytes = outer(&a.ek_pk, SPK_ID, OPK_ID, &a.ct_spk, &a.ct_opk, &ict);
    let fetched = reseal(re, &mut s, &outer_bytes);
    let _ = s.dh_step();
    s.list("content", &content);
    s.list("inner", &inner);
    s.list("outer", &outer_bytes);
    reject_r(s, i, manipulation, &fetched, &[OPK_ID])
}

/// Encrypts the padded `body` from `state` with `hdr_nonce`; returns the new state and the cell.
fn encrypt_padded(state: RatchetState, body: &[u8], hdr_nonce: &[u8]) -> (RatchetState, Vec<u8>) {
    let (state, cell) = state
        .encrypt_padded_kat(body, &mut fixed(&[hdr_nonce]))
        .map_err(|r| r.error())
        .unwrap()
        .persist(|_| Ok::<(), ()>(()))
        .unwrap();
    (state, cell.as_bytes().to_vec())
}

/// `RatchetStateV1` from its fields (the inverse of `tr_digest::fields`).
fn encode_state(f: &tr_digest::StateFields) -> Vec<u8> {
    fn put_opt(out: &mut Vec<u8>, x: Option<&Vec<u8>>) {
        match x {
            None => out.push(0),
            Some(x) => {
                out.push(1);
                out.extend_from_slice(x);
            }
        }
    }
    let mut out = vec![1];
    out.extend_from_slice(&f.sb_rk_dh_s);
    put_opt(&mut out, f.dh_r.as_ref());
    out.extend_from_slice(&f.kem_s_seed);
    for x in f.kem.iter().chain(&f.keys) {
        put_opt(&mut out, x.as_ref());
    }
    for n in [f.n_s, f.n_r, f.pn] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(&u16::try_from(f.skipped.len()).unwrap().to_be_bytes());
    for e in &f.skipped {
        out.extend_from_slice(e);
    }
    out
}

/// `state` with `pn` := 1. A state with `pn` ≠ 0 is only reachable after receiving a DH step, so the serialisation
/// is rebuilt with a receiving chain; the sending half, which seals the cell, is the honest one (SCHEMA-4.10 R16).
fn with_pn_one(state: &RatchetState) -> RatchetState {
    let mut f = tr_digest::fields(state);
    f.pn = 1;
    f.keys[1] = Some(vec![1; 32]);
    f.keys[3] = Some(vec![2; 32]);
    f.kem[1] = Some(vec![3; 1088]);
    RatchetState::from_bytes(&encode_state(&f)).unwrap()
}

fn r_cases(re: &Re<'_>) -> Vec<(u32, Value)> {
    let b6 = re.b6;
    let mut out = Vec::new();
    // R1 opk-unknown: opk_id := 43; R2 spk-unknown: spk_id := 8
    out.push((
        17,
        outer_case(re, 17, "opk-unknown", |o| {
            sl_mut(o, OFF_OPK_ID..OFF_OPK_ID + 4).copy_from_slice(&43_u32.to_be_bytes());
        }),
    ));
    out.push((
        18,
        outer_case(re, 18, "spk-unknown", |o| {
            sl_mut(o, OFF_SPK_ID..OFF_SPK_ID + 4).copy_from_slice(&8_u32.to_be_bytes());
        }),
    ));
    // R3 replay: case 6's cells again, to R after case 7
    let s = Stream::new(19);
    out.push((19, reject_r(s, 19, "replay", &b6.cells, &[])));
    // R4 zero-ek
    out.push((
        20,
        outer_case(re, 20, "zero-ek", |o| {
            sl_mut(o, OFF_EK..OFF_EK + 32).fill(0);
        }),
    ));
    // R5 low-order ik_dh in Inner
    let mut inner = b6.inner.clone();
    sl_mut(&mut inner, IKS_LEN - 32..IKS_LEN).copy_from_slice(&LOW_ORDER_8);
    out.push((21, inner_case(re, 21, "low-order-ik-dh", false, &inner)));
    // R6 tampered chunk: cell_1 with bit 0 of its last byte flipped
    let s = Stream::new(22);
    let mut fetched = b6.cells.clone();
    fetched[1] = flip_last_bit(fetched[1].clone(), 4095);
    out.push((22, reject_r(s, 22, "tampered-chunk", &fetched, &[OPK_ID])));
    // R7 inner-tag-flip
    out.push((
        23,
        outer_case(re, 23, "inner-tag-flip", |o| {
            *o.last_mut().unwrap() ^= 1;
        }),
    ));
    // R8 first-msg-flip: bit 0 of the last byte of first_msg in Inner
    let inner = flip_last_bit(b6.inner.clone(), INNER_LEN - 1);
    out.push((24, inner_case(re, 24, "first-msg-flip", true, &inner)));
    // R9 caps-nonzero: caps := 1 in case 6's Content
    out.push((
        25,
        first_msg_case(re, 25, "caps-nonzero", |_| {
            let mut content = b6.content.clone();
            // ver 1, type 1, seq 8, ts 8, body_len 2, Profile (39), then caps u32
            *byte_mut(&mut content, 20 + 39 + 3) = 1;
            pad(&content, BODY_LEN).unwrap().to_vec()
        }),
    ));
    // R10 ct-spk-flip
    out.push((
        26,
        outer_case(re, 26, "ct-spk-flip", |o| *byte_mut(o, OFF_CT_SPK) ^= 1),
    ));
    // R11 total-not-3: cell_0 re-sealed with total := 2
    let mut s = Stream::new(27);
    let n0 = s.draw("cell_nonce_0", 24);
    let k = k_inv(&re.base.inv.ld_id, &re.base.inv.link_key);
    let mut fetched = b6.cells.clone();
    fetched[0] = cell_raw(
        &k,
        &re.base.inv.ld_id,
        &n0,
        &cell_plaintext(&b6.init_id, 0, 2, &chunk_of(&b6.outer, 0)),
    );
    out.push((27, reject_r(s, 27, "total-not-3", &fetched, &[OPK_ID])));
    // R12 idx-dup: cell_1 re-sealed with i := 0
    let mut s = Stream::new(28);
    let n1 = s.draw("cell_nonce_1", 24);
    let mut fetched = b6.cells.clone();
    fetched[1] = cell_raw(
        &k,
        &re.base.inv.ld_id,
        &n1,
        &cell_plaintext(&b6.init_id, 0, 3, &chunk_of(&b6.outer, 1)),
    );
    out.push((28, reject_r(s, 28, "idx-dup", &fetched, &[OPK_ID])));
    // R13 first-msg-not-handshake: a Batch of one AppMessage
    out.push((
        30,
        first_msg_case(re, 30, "first-msg-not-handshake", |s| {
            let msg_id: [u8; 16] = s.arr("msg_id");
            let payload = s.draw("payload", 8);
            let content = Content {
                seq: 1,
                ts: 1_700_000_001,
                body: ContentBody::Batch(BatchBody {
                    messages: vec![AppMessage {
                        msg_id,
                        kind: AppKind::Text,
                        expire_after: 0,
                        payload: secmp_crypto::Zeroizing::new(payload),
                    }],
                }),
            };
            content.encode().unwrap().to_vec()
        }),
    ));
    out
}

/// R14 … R18 (`hx-0032` … `hx-0036`, Weisung REF-M5-2).
fn r_cases_rev25(re: &Re<'_>) -> Vec<(u32, Value)> {
    let b6 = re.b6;
    let k = k_inv(&re.base.inv.ld_id, &re.base.inv.link_key);
    let mut out = Vec::new();
    // R14 no-reform (rev 2.5): a differing chunk 1 first, then the honest cells twice
    let mut s = Stream::new(32);
    let n1 = s.draw("cell_nonce_1", 24);
    let mut chunk = chunk_of(&b6.outer, 1);
    *byte_mut(&mut chunk, 0) ^= 1;
    let differing = cell_raw(
        &k,
        &re.base.inv.ld_id,
        &n1,
        &cell_plaintext(&b6.init_id, 1, 3, &chunk),
    );
    let mut fetched = vec![differing];
    fetched.extend(b6.cells.clone());
    fetched.extend(b6.cells.clone());
    out.push((32, reject_r(s, 32, "no-reform", &fetched, &[OPK_ID])));
    // R15 first-msg-n: case 6's Content as I's second message (one message encrypted first and discarded)
    out.push((
        33,
        first_msg_cell_case(re, 33, "first-msg-n", |s| {
            let hdr_nonce_0 = s.draw("hdr_nonce_0", 24);
            let hdr_nonce = s.draw("hdr_nonce", 24);
            let body = pad(&b6.content, BODY_LEN).unwrap().to_vec();
            let (state, _discarded) =
                encrypt_padded(snapshot(&b6.i_after_init), &body, &hdr_nonce_0);
            let (_, cell) = encrypt_padded(state, &body, &hdr_nonce);
            (cell, b6.content.clone())
        }),
    ));
    // R16 first-msg-pn: case 6's Content with pn := 1 in the header
    out.push((
        34,
        first_msg_cell_case(re, 34, "first-msg-pn", |s| {
            let hdr_nonce = s.draw("hdr_nonce", 24);
            let body = pad(&b6.content, BODY_LEN).unwrap().to_vec();
            let (_, cell) = encrypt_padded(with_pn_one(&b6.i_after_init), &body, &hdr_nonce);
            (cell, b6.content.clone())
        }),
    ));
    // R17 reflection: IKSPublic_I := IKSPublic_R in Inner, case 6's first_msg
    let inner = [re.base.r.iks_bytes.as_slice(), &b6.first_msg].concat();
    out.push((35, inner_case(re, 35, "reflection", false, &inner)));
    // R18 no-known-route: the route replaced by a RouteDescriptor of kind 0x7F
    out.push((
        36,
        first_msg_cell_case(re, 36, "no-known-route", |s| {
            let blob = s.draw("route_blob", 16);
            let hdr_nonce = s.draw("hdr_nonce", 24);
            let content = handshake_content(
                Profile::new("alice", Some(b6.avatar)).unwrap(),
                vec![RouteDescriptor::Unknown {
                    kind: 0x7F,
                    blob: secmp_crypto::Zeroizing::new(blob),
                }],
                1,
                1_700_000_001,
            );
            let (_, cell) = encrypt_padded(
                snapshot(&b6.i_after_init),
                &content.encode().unwrap(),
                &hdr_nonce,
            );
            (cell, unpadded_content(&content))
        }),
    ));
    out
}

/// A1 (`hx-0031`, `respond-later-group`): a complete group that R rejects (case 8's R8 construction under a fresh
/// `init_id`), then case 6's cells, accepted with the second step's draws.
fn case31(base: &Base0, b6: &Base6) -> Value {
    let mut s = Stream::new(31);
    let inner_nonce = s.draw("inner_nonce", 24);
    let inner = flip_last_bit(b6.inner.clone(), INNER_LEN - 1);
    let ict = inner_ct(&b6.a.k_id, &base.inv.ld_id, &inner_nonce, &inner);
    let outer_bytes = outer(
        &b6.a.ek_pk,
        SPK_ID,
        OPK_ID,
        &b6.a.ct_spk,
        &b6.a.ct_opk,
        &ict,
    );
    let init_id: [u8; 16] = s.arr("init_id");
    let n0 = s.draw("cell_nonce_0", 24);
    let n1 = s.draw("cell_nonce_1", 24);
    let n2 = s.draw("cell_nonce_2", 24);
    let k = k_inv(&base.inv.ld_id, &base.inv.link_key);
    let rejected = cells(&k, &base.inv.ld_id, &init_id, [&n0, &n1, &n2], &outer_bytes);
    let _first_step = s.dh_step();
    let step = s.dh_step_named("dh_sk_2", "kem_seed_2", "m_2");
    s.list("inner", &inner);
    s.list("outer", &outer_bytes);
    let fetched: Vec<Vec<u8>> = rejected.into_iter().chain(b6.cells.clone()).collect();
    s.list_value("fetched", hex_array(&fetched));
    let outputs = responded_outputs(&respond(base, &b6.cells, &step));
    s.finish(31, "respond-later-group", "R", vec![("outputs", outputs)])
}

/// A2 (`hx-0037`, `respond-retained-spk`): R holds SPK generation 8 (from the case's own stream) next to SPK 7
/// of cases 1–4; case 6's cells name SPK 7 and are accepted.
fn case37(base: &Base0, b6: &Base6) -> Value {
    let mut s = Stream::new(37);
    let _spk_dh_sk = s.draw("spk_dh_sk", 32);
    let _spk_kem_seed = s.draw("spk_kem_seed", 64);
    let _rpk_kem_seed = s.draw("rpk_kem_seed", 64);
    let step = s.dh_step();
    let fetched: Vec<Vec<u8>> = b6.cells.to_vec();
    s.list_value("fetched", hex_array(&fetched));
    let outputs = responded_outputs(&respond(base, &fetched, &step));
    s.finish(37, "respond-retained-spk", "R", vec![("outputs", outputs)])
}

/// The values through case 6 and case 7's randomness: the scenario the negative tests build on.
pub struct World {
    pub r: Identity,
    pub i: Identity,
    pub keys: Prekeys,
    /// The stream of case 1 (`ik_mldsa_xi` … `rnd`) and of case 2, in draw order: the entropy of
    /// `IdentityKeys::generate` (and, for R, the prekeys and the bundle signature).
    pub r_seed: Vec<u8>,
    pub i_seed: Vec<u8>,
    pub bundle: Vec<u8>,
    pub inv: Invitation,
    pub invitation: Vec<u8>,
    pub uri: String,
    pub linkdata: Vec<u8>,
    pub blob: Vec<u8>,
    pub k_ld: SecretBytes<32>,
    pub k_inv: SecretBytes<32>,
    pub b6: Base6,
    /// Case 7's DH-step randomness (`dh_sk` ‖ `kem_seed` ‖ `m`).
    pub step: Vec<u8>,
    cases: Vec<(u32, Value)>,
}

/// Cases 1–8 and everything the later cases build on.
pub fn world() -> World {
    let (b1, case1) = case1();
    let (i, i_seed, case2) = case2();
    let (inv, invitation, uri_text, case3) = case3(&b1.r);
    let (linkdata, sealed_blob, k_ld_value, case4) = case4(&b1, &inv);
    let (k_inv_value, case5) = case5(&inv, &k_ld_value);
    let base0 = Base0 {
        r: &b1.r,
        i: &i,
        keys: &b1.keys,
        inv: &inv,
    };
    let (b6, case6) = case6(&base0);
    let case7 = case7(&base0, &b6);
    let case8 = case8(&base0, &b6);
    let step = Stream::new(7).dh_step();
    let positives = vec![
        (1, case1),
        (2, case2),
        (3, case3),
        (4, case4),
        (5, case5),
        (6, case6),
        (7, case7),
        (8, case8),
    ];
    World {
        r: b1.r,
        i,
        keys: b1.keys,
        r_seed: b1.seed,
        i_seed,
        bundle: b1.bundle,
        inv,
        invitation,
        uri: uri_text,
        linkdata,
        blob: sealed_blob,
        k_ld: k_ld_value,
        k_inv: k_inv_value,
        b6,
        step,
        cases: positives,
    }
}

/// Cross-checks the values `world()` hands to the tests against the ones the cases were built from.
fn check_world(w: &World) {
    assert_eq!(w.r_seed.len(), 384);
    assert_eq!(w.i_seed.len(), 96);
    assert_eq!(w.uri, uri(&w.invitation));
    assert_eq!(
        hex(w.k_ld.expose_secret()),
        hex(k_ld(&w.inv.ld_id, &w.inv.link_key).expose_secret())
    );
    assert_eq!(
        hex(w.k_inv.expose_secret()),
        hex(k_inv(&w.inv.ld_id, &w.inv.link_key).expose_secret())
    );
    assert!(w.blob.len() > w.linkdata.len());
    assert_eq!(w.step.len(), 128);
    assert_eq!(w.b6.entropy.len(), 360);
    assert_eq!(w.b6.route.len(), 155);
    assert_eq!(w.b6.first_msg.len(), 4096);
    assert!(w.b6.content.windows(32).any(|c| c == w.b6.avatar));
}

/// The complete `hx` file (the Rust side of `cargo xtask vectors`).
pub fn generate() -> Value {
    let w = world();
    check_world(&w);
    let base0 = Base0 {
        r: &w.r,
        i: &w.i,
        keys: &w.keys,
        inv: &w.inv,
    };
    let pos = Pos {
        base: &base0,
        bundle: &w.bundle,
        linkdata: &w.linkdata,
        invitation: &w.invitation,
    };
    let mut numbered: Vec<(u32, Value)> = w.cases.clone();
    numbered.extend(v_cases(&pos));
    numbered.extend(r_cases(&Re {
        base: &base0,
        b6: &w.b6,
    }));
    numbered.extend(r_cases_rev25(&Re {
        base: &base0,
        b6: &w.b6,
    }));
    numbered.push((31, case31(&base0, &w.b6)));
    numbered.push((37, case37(&base0, &w.b6)));
    // SCHEMA order: positives, V1–V8 (9–16), R1–R12 (17–28), V9 (29), R13 (30), A1 (31), R14–R18 (32–36), A2 (37)
    numbered.sort_by_key(|(i, _)| *i);
    let cases: Vec<Value> = numbered.into_iter().map(|(_, c)| c).collect();
    assert_eq!(cases.len(), 37);
    json!({
        "schema": 5,
        "suite": SUITE,
        "spec": "SecMP/1 rev 2.6",
        "generator": "secmp-rust",
        "cases": cases,
    })
}
