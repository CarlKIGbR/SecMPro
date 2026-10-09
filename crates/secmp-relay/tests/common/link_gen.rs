// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The Rust generator of the `link` vector suite (`vectors/SCHEMA.md` §1–§2, §4.11; `vectors/SCHEMA-4.11-link.md`):
//! one handshake and one link ("link A") between a client C and the relay R, 86 cases. It reads no vector file.
//! Case *i* draws from its own SCHEMA §2 stream (suite `link`, index *i*) in the order of the case tables — the
//! client's draws, then the relay's in response-frame order — and every output is what the code under test computes:
//! the relay (`secmp_relay::Relay` and `Executor` with `FixedEntropy`; `secmp_relay::Connection` and the responder of
//! `secmp_proto::link::relay` for the handshakes it rejects) and the client of `secmp_proto::link`.
//!
//! The requests are written here from D.2, D.6 and spec §9.6 with `secmp-crypto` primitives (the signed messages and
//! the tokens are recomputed, not taken from `secmp_proto::wire::signed`), with the manipulations of the SCHEMA
//! tables; the manipulated frames of the `frame-reject` group are sealed here (spec §8.4) under the keys of link A.
//!
//! [`generate`] builds the cases in the SCHEMA order: `link-0001` … `link-0050` (the handshake, then the positives
//! and the command-error cases E1–E23 of link A in event order), X1 (`link-0051`), the `RELAYINFO` cases I1–I8, then
//! `hs1-reject` (H1, S1–S10), `hs2-reject` (T1–T4) and `frame-reject` (F1–F12). Shared by the `gen-link` example
//! (which writes `vectors/rust/link.json` for `cargo xtask vectors`) and the relay test
//! `link_generator_reproduces_ref_file` (TEST-SPEC-M5 V-22).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::slice::SliceIndex;

use secmp_crypto::{
    Aead, Ed25519SigningKey, Label, MlKem1024Dk, Nonce24, SecretBytes, VectorStream, X25519Secret,
    hkdf_extract, hmac_sha256, sha256,
};
use secmp_proto::codec::{pad, unpad};
use secmp_proto::keys::{Ed25519Pk, Ed25519Sig};
use secmp_proto::link::cont::split_blob;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, HandshakeTrace, Link};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    CellrContext, FetchEntry, LinkGetMode, Request, RequestCmd, Response, opcode,
};
use secmp_proto::wire::record::{Hs1, Hs2};
use secmp_proto::{Decode, Encode};
use secmp_relay::event::NullSink;
use secmp_relay::relay::kat::StoreSnapshot;
use secmp_relay::{Connection, Executor, KeyRing, Limits, Now, Outcome, Relay};
use serde_json::{Map, Value, json};

/// The suite name (SCHEMA §3).
pub const SUITE: &str = "link";

/// `now` (constants): hour bucket 472 222.
const NOW: u64 = 1_700_000_100;
/// `valid_until` of the relay's `RelayInfoV1` (constants: `now` + 2 591 900 s).
const VALID_UNTIL: u64 = 1_702_592_000;
/// One day in seconds; the client accepts `valid_until − now` ≤ 60 days (reading OPEN-4).
const DAY: u64 = 86_400;
/// The relay's only key generation (constants).
const KID: u32 = 1;
/// `expires_bucket` of every `LINK_PUT` (constants: 472 222 + 168).
const EXPIRES: u32 = 472_390;
/// A frame and its plaintext (spec §4.2, §8.4).
const FRAME: usize = 4352;
const PLAIN: usize = 4336;
/// A cell, a link-data blob, a client `CONT`'s `data` (spec §4.2, D.2).
const CELL: usize = 4096;
const BLOB: usize = 12_360;
const CONT_DATA: usize = 4100;
/// The `HELLO` record `len` (7) ‖ 0x01 ‖ `"SECMP"` ‖ `ver` (D.1).
const HELLO: [u8; 9] = [0x00, 0x07, 0x01, b'S', b'E', b'C', b'M', b'P', 0x01];
/// The order-8 point (constants; SCHEMA §4.4 row 16).
const LOW_ORDER_8: [u8; 32] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];
/// `send-fill`: 127 `SEND`s fill queue B (one cell before) to `QUEUE_CAPACITY` 128.
const FILL: u32 = 127;
/// The relay's dummy-cell draws of a response, by index.
const DUMMY: [&str; 5] = ["dummy_0", "dummy_1", "dummy_2", "dummy_3", "dummy_4"];

/// Offsets in the `RELAYINFO` record (D.1: `len` 2, type 1, then `RelayInfoV1`, 1744 B).
mod ri {
    pub const VER: usize = 3;
    pub const DH_PK: usize = 40;
    pub const AKC: usize = 1640;
    pub const VALID_UNTIL: usize = 1672;
    pub const SIG: usize = 1680;
}

/// Offsets in the `HS1` record (2856 B).
mod h1 {
    pub const VER: usize = 3;
    pub const KID: usize = 4;
    pub const E_C: usize = 8;
    pub const EK_C: usize = 40;
    pub const PK_E1: usize = 1224;
    pub const CT_KEM: usize = 1256;
    pub const MAC1: usize = 2824;
    pub const LEN: usize = 2856;
}

/// Offsets in the `HS2` record (1156 B).
mod h2 {
    pub const VER: usize = 3;
    pub const E_R: usize = 4;
    pub const CT_C: usize = 36;
    pub const MAC2: usize = 1124;
}

// ---------------------------------------------------------------------------------------------------------------
// Bytes and JSON.

fn hex(b: &[u8]) -> String {
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

fn hex_list(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| json!(hex(b))).collect())
}

fn case_id(i: u32) -> String {
    format!("link-{i:04}")
}

/// The canonical bytes of a vector file (SCHEMA §1): compact JSON, keys sorted, ASCII.
pub fn canonical(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap();
    assert!(s.is_ascii(), "vector files are ASCII");
    s
}

/// `&b[r]`; the generator's offsets are constants, so a miss is a bug in the generator.
fn sl<R: SliceIndex<[u8], Output = [u8]>>(b: &[u8], r: R) -> &[u8] {
    b.get(r).unwrap()
}

fn first(items: &[Vec<u8>]) -> &[u8] {
    items.first().unwrap()
}

/// SCHEMA §4 flip(`bytes`, `at`): byte `at` XOR 0x01.
fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut v = bytes.to_vec();
    *v.get_mut(at).unwrap() ^= 1;
    v
}

/// `bytes` with `new` written at `at`.
fn patch(bytes: &[u8], at: usize, new: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.get_mut(at..at.checked_add(new.len()).unwrap())
        .unwrap()
        .copy_from_slice(new);
    v
}

fn id16(b: &[u8]) -> Id {
    b.try_into().unwrap()
}

fn arr32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}

const fn now() -> Now {
    Now {
        unix_secs: NOW,
        mono_ms: 0,
    }
}

/// The SCHEMA §2 stream of one case and the inputs it lists.
struct Stream {
    s: VectorStream,
    inputs: Map<String, Value>,
}

impl Stream {
    fn new(i: u32) -> Self {
        Self {
            s: VectorStream::new(SUITE, i),
            inputs: Map::new(),
        }
    }

    /// The next `n` stream bytes, listed as input `name`.
    fn draw(&mut self, name: &str, n: usize) -> Vec<u8> {
        let v = self.s.take(n);
        self.list(name, &v);
        v
    }

    /// An Ed25519 key from a 32-byte seed of the stream (SCHEMA §2).
    fn key(&mut self, name: &str) -> Key {
        Key::from_seed(&self.draw(name, 32))
    }

    /// Lists the *derived* input `name` (after the case's draws; the order of the JSON keys is canonical anyway).
    fn list(&mut self, name: &str, v: &[u8]) {
        let fresh = self.inputs.insert(name.to_owned(), json!(hex(v))).is_none();
        assert!(fresh, "input {name} listed twice");
    }
}

/// The `outputs` of a case.
#[derive(Default)]
struct Out(Map<String, Value>);

impl Out {
    fn b(&mut self, name: &str, v: &[u8]) {
        self.v(name, json!(hex(v)));
    }

    fn v(&mut self, name: &str, v: Value) {
        let fresh = self.0.insert(name.to_owned(), v).is_none();
        assert!(fresh, "output {name} listed twice");
    }

    fn done(self) -> Value {
        Value::Object(self.0)
    }
}

/// One case (SCHEMA §1, `"schema": 6`): `id`, `op`, `party`, `from` (every case but `link-0001` and X1), `inputs`,
/// then the case's other fields.
fn make_case(
    i: u32,
    op: &str,
    party: &str,
    from: Option<u32>,
    inputs: Map<String, Value>,
    rest: Vec<(&str, Value)>,
) -> (u32, Value) {
    let mut c = Map::new();
    c.insert("id".to_owned(), json!(case_id(i)));
    c.insert("op".to_owned(), json!(op));
    c.insert("party".to_owned(), json!(party));
    if let Some(f) = from {
        c.insert("from".to_owned(), json!(case_id(f)));
    }
    c.insert("inputs".to_owned(), Value::Object(inputs));
    for (k, v) in rest {
        let fresh = c.insert(k.to_owned(), v).is_none();
        assert!(fresh, "{}: field {k} twice", case_id(i));
    }
    (i, Value::Object(c))
}

/// `manipulation` and `"expect": "reject"`.
fn rejected(manipulation: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("manipulation", json!(manipulation)),
        ("expect", json!("reject")),
    ]
}

/// `link_post` {`c2r`, `r2c`, `cmd_seq`}: the next frame counter in each direction and the relay's last recorded
/// `cmd_seq` (reading OPEN-5).
fn link_post((c2r, r2c, cmd_seq): (u64, u64, u32)) -> Value {
    json!({"c2r": c2r, "r2c": r2c, "cmd_seq": cmd_seq})
}

/// `store_post` {`queues` ascending by `rid`, `linkdata` ascending by `ld_id`}.
fn store_post(snap: &StoreSnapshot) -> Value {
    assert!(
        snap.queues
            .windows(2)
            .all(|w| w.first().map(|q| q.rid) < w.get(1).map(|q| q.rid))
    );
    assert!(
        snap.linkdata
            .windows(2)
            .all(|w| w.first().map(|e| e.ld_id) < w.get(1).map(|e| e.ld_id))
    );
    let queues: Vec<Value> = snap
        .queues
        .iter()
        .map(|q| {
            json!({"rid": hex(&q.rid), "sid": hex(&q.sid), "cell_ids": q.cell_ids,
                "next_cell_id": q.next_cell_id})
        })
        .collect();
    let linkdata: Vec<Value> = snap
        .linkdata
        .iter()
        .map(|e| {
            json!({"ld_id": hex(&e.ld_id), "one_time": u8::from(e.one_time),
                "expires_bucket": e.expires_bucket, "present": u8::from(e.present),
                "consumed": u8::from(e.consumed)})
        })
        .collect();
    json!({"queues": queues, "linkdata": linkdata})
}

// ---------------------------------------------------------------------------------------------------------------
// Keys, signed messages (D.6), tokens (§9.6) and requests (D.2).

/// An Ed25519 key from its seed.
struct Key {
    sk: Ed25519SigningKey,
    pk: Ed25519Pk,
}

impl Key {
    fn from_seed(seed: &[u8]) -> Self {
        let sk = Ed25519SigningKey::from_seed(seed).unwrap();
        let pk = Ed25519Pk::from_bytes(sk.verifying_key().as_bytes()).unwrap();
        Self { sk, pk }
    }

    fn sign(&self, msg: &[u8]) -> Ed25519Sig {
        Ed25519Sig::from_bytes(&self.sk.sign(msg)).unwrap()
    }
}

/// D.6: `"SecMP-Q/1 <CMD>" ‖ sess_id ‖ u32be(cmd_seq) ‖ fields`.
fn signed(label: Label, sess: &Id, seq: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut m = [label.as_bytes(), sess, &seq.to_be_bytes()].concat();
    for f in fields {
        m.extend_from_slice(f);
    }
    m
}

/// spec §9.6: `HMAC-SHA-256(relay_access_key, "SecMP-Q/1 token" ‖ sess_id ‖ u32be(cmd_seq))`.
fn token(access: &[u8], sess: &Id, seq: u32) -> [u8; 32] {
    hmac_sha256(access, Label::QToken, &[sess, &seq.to_be_bytes()]).unwrap()
}

/// spec §9.1: `rid = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16]`.
fn rid_of(recv: &Ed25519Pk) -> Id {
    id16(sl(
        &sha256(&[Label::QRid.as_bytes(), recv.as_bytes()]),
        ..16,
    ))
}

/// spec §9.1: `sid = SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]`.
fn sid_of(recv: &Ed25519Pk, send: &Ed25519Pk) -> Id {
    id16(sl(
        &sha256(&[Label::QSid.as_bytes(), recv.as_bytes(), send.as_bytes()]),
        ..16,
    ))
}

fn flip_id(id: &Id) -> Id {
    id16(&flip(id, 0))
}

/// `QUEUE_NEW recv_pk ‖ send_pk ‖ token ‖ sig`, `sig` by `signer` over the fields as sent (D.6).
fn queue_new(
    sess: &Id,
    seq: u32,
    (recv, send): (&Ed25519Pk, &Ed25519Pk),
    token: [u8; 32],
    signer: &Key,
) -> Request {
    let msg = signed(
        Label::QQueueNew,
        sess,
        seq,
        &[recv.as_bytes(), send.as_bytes(), &token],
    );
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::QueueNew {
            recv_pk: *recv,
            send_pk: *send,
            token,
            sig: signer.sign(&msg),
        },
    }
}

/// `SEND sid ‖ cell ‖ sig` (D.6: signed over `sid ‖ cell`).
fn send(sess: &Id, seq: u32, sid: Id, cell: &[u8], signer: &Key) -> Request {
    let msg = signed(Label::QSend, sess, seq, &[&sid, cell]);
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::Send {
            sid,
            cell: Cell::from_bytes(cell).unwrap(),
            sig: signer.sign(&msg),
        },
    }
}

/// `FETCH rid ‖ ack ‖ sig` (D.6: signed over `rid ‖ u64be(ack)`).
fn fetch(sess: &Id, seq: u32, rid: Id, ack: u64, signer: &Key) -> Request {
    let msg = signed(Label::QFetch, sess, seq, &[&rid, &ack.to_be_bytes()]);
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::Fetch {
            rid,
            ack,
            sig: signer.sign(&msg),
        },
    }
}

/// One `FETCH_MULTI` entry (D.6: `"SecMP-Q/1 MFETCH"`, signed over `rid ‖ u64be(ack)`; the count is not signed).
fn entry(sess: &Id, seq: u32, rid: Id, ack: u64, signer: &Key) -> FetchEntry {
    let msg = signed(Label::QMfetch, sess, seq, &[&rid, &ack.to_be_bytes()]);
    FetchEntry {
        rid,
        ack,
        sig: signer.sign(&msg),
    }
}

/// `QUEUE_DEL rid ‖ sig` (D.6: signed over `rid`).
fn queue_del(sess: &Id, seq: u32, rid: Id, signer: &Key) -> Request {
    let msg = signed(Label::QQueueDel, sess, seq, &[&rid]);
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::QueueDel {
            rid,
            sig: signer.sign(&msg),
        },
    }
}

/// The fields of a `LINK_PUT` (`one_time` 1 and `expires_bucket` 472 390 in every case of the suite).
struct Put<'a> {
    ld_id: &'a Id,
    owner_pk: &'a Ed25519Pk,
    token: [u8; 32],
    signer: &'a Key,
    blob: &'a [u8],
}

/// The three frames of a `LINK_PUT` (spec §9.3, D.2): the head fields with `blob[0..4160]`, then CONT 1 and CONT 2;
/// `sig` over `ld_id ‖ one_time ‖ u32be(expires_bucket) ‖ owner_pk ‖ token ‖ SHA-256(blob)` (D.6).
fn link_put(sess: &Id, seq: u32, p: &Put<'_>) -> [Request; 3] {
    let msg = signed(
        Label::QLinkPut,
        sess,
        seq,
        &[
            p.ld_id,
            &[1],
            &EXPIRES.to_be_bytes(),
            p.owner_pk.as_bytes(),
            &p.token,
            &sha256(&[p.blob]),
        ],
    );
    let (blob_part, one, two) = split_blob(p.blob).unwrap();
    [
        Request {
            cmd_seq: seq,
            cmd: RequestCmd::LinkPut {
                ld_id: *p.ld_id,
                one_time: true,
                expires_bucket: EXPIRES,
                owner_pk: *p.owner_pk,
                token: p.token,
                sig: p.signer.sign(&msg),
                blob_part,
            },
        },
        Request {
            cmd_seq: seq,
            cmd: RequestCmd::Cont(one),
        },
        Request {
            cmd_seq: seq,
            cmd: RequestCmd::Cont(two),
        },
    ]
}

/// `LINK_GET` in owner-status mode (D.6: signed over `ld_id ‖ mode`).
fn link_get_owner(sess: &Id, seq: u32, ld_id: &Id, signer: &Key) -> Request {
    let msg = signed(Label::QLinkGet, sess, seq, &[ld_id, &[1]]);
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::LinkGet {
            ld_id: *ld_id,
            mode: LinkGetMode::OwnerStatus(signer.sign(&msg)),
        },
    }
}

/// `LINK_GET` in consume mode (`sig` = 0^64).
const fn link_get_consume(seq: u32, ld_id: &Id) -> Request {
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::LinkGet {
            ld_id: *ld_id,
            mode: LinkGetMode::Consume,
        },
    }
}

const fn ping(seq: u32) -> Request {
    Request {
        cmd_seq: seq,
        cmd: RequestCmd::Ping,
    }
}

/// The unpadded payload `op ‖ cmd_seq ‖ fields` of a request (the frame layer pads it, spec §4.1).
fn payload(req: &Request) -> Vec<u8> {
    unpad(&req.encode().unwrap(), PLAIN).unwrap().to_vec()
}

fn payloads(reqs: &[Request]) -> Vec<Vec<u8>> {
    reqs.iter().map(payload).collect()
}

/// The `sig` of a signed request.
fn sig_of(req: &Request) -> Vec<u8> {
    match &req.cmd {
        RequestCmd::QueueNew { sig, .. }
        | RequestCmd::Send { sig, .. }
        | RequestCmd::Fetch { sig, .. }
        | RequestCmd::QueueDel { sig, .. }
        | RequestCmd::LinkPut { sig, .. }
        | RequestCmd::LinkGet {
            mode: LinkGetMode::OwnerStatus(sig),
            ..
        } => Some(sig.as_bytes().to_vec()),
        _ => None,
    }
    .expect("a signed request")
}

/// The derived `token` and `sig` of a `QUEUE_NEW` or `LINK_PUT`.
fn token_and_sig(req: &Request) -> [(&'static str, Vec<u8>); 2] {
    let token = match &req.cmd {
        RequestCmd::QueueNew { token, .. } | RequestCmd::LinkPut { token, .. } => {
            Some(token.to_vec())
        }
        _ => None,
    }
    .expect("a request with a token");
    [("token", token), ("sig", sig_of(req))]
}

/// `pad(payload, 4336)` (spec §4.1).
fn padded(payload: &[u8]) -> Vec<u8> {
    pad(payload, PLAIN).unwrap().to_vec()
}

/// spec §8.4: `XChaCha20-Poly1305.Seal(k_dir, 0^16 ‖ u64be(counter), ad, plaintext)`.
fn seal(key: &[u8; 32], counter: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    Aead::seal(
        &SecretBytes::from_slice(key).unwrap(),
        Nonce24::from_link_counter(counter),
        ad,
        plaintext,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// The relay, the handshake and the link.

/// The relay secrets of `link-0001`.
struct Secrets {
    sig_seed: Vec<u8>,
    dh_sk: Vec<u8>,
    kem_seed: Vec<u8>,
    access_key: Vec<u8>,
}

impl Secrets {
    fn access(&self) -> AccessKey {
        SecretBytes::from_slice(&self.access_key).unwrap()
    }

    /// `relay_sig` with the static pair (`dh_sk`, `kem_seed`) as generation `kid` 1, and the access key.
    fn keys_with(&self, dh_sk: &[u8], kem_seed: &[u8]) -> RelayKeys {
        RelayKeys::new(
            Ed25519SigningKey::from_seed(&self.sig_seed).unwrap(),
            X25519Secret::from_bytes(dh_sk).unwrap(),
            MlKem1024Dk::from_seed(kem_seed).unwrap(),
            self.access(),
            KID,
        )
        .unwrap()
    }

    fn keys(&self) -> RelayKeys {
        self.keys_with(&self.dh_sk, &self.kem_seed)
    }

    /// The relay of the suite: `kid` 1 valid until `valid_until`, the vector limits (a budget of two queues, link
    /// data unlimited, no rate limits; reading OPEN-12), empty.
    fn relay(&self) -> Relay {
        let ring = KeyRing::new(vec![(self.keys(), VALID_UNTIL)]).unwrap();
        Relay::new(ring, Limits::vectors(), Box::new(NullSink), now())
    }

    /// A `RELAYINFO` record re-signed under `relay_sig`: `sig` = Ed25519(`"SecMP-LINK/1 relayinfo"` ‖ the 1677
    /// bytes of `RelayInfoV1` before `sig`) (spec §8.2).
    fn resign(&self, rec: &[u8]) -> Vec<u8> {
        let msg = [Label::LinkRelayinfo.as_bytes(), sl(rec, ri::VER..ri::SIG)].concat();
        let sig = Ed25519SigningKey::from_seed(&self.sig_seed)
            .unwrap()
            .sign(&msg);
        patch(rec, ri::SIG, &sig)
    }
}

/// What the handshake (`link-0001` … `link-0005`) produced: the base of the reject cases and of the replays of
/// link A.
struct Hs {
    secrets: Secrets,
    relay_fp: [u8; 32],
    rec_relayinfo: Vec<u8>,
    /// `link-0003`'s draws `e_c_sk ‖ ek_c_seed ‖ sk_e1 ‖ m1`.
    client_draws: Vec<u8>,
    rec_hs1: Vec<u8>,
    /// `link-0004`'s draws `sk_er ‖ m2`.
    relay_draws: Vec<u8>,
    rec_hs2: Vec<u8>,
    k_c2r: [u8; 32],
    k_r2c: [u8; 32],
    sess_id: Id,
}

/// The relay, the client's end of the link and the relay's executor of it.
struct Bench {
    relay: Relay,
    client: Link,
    exec: Executor,
}

/// One round trip: the request payloads and frames, the response payloads and frames, and how many response frames
/// followed each request frame.
#[derive(Default)]
struct Exchange {
    req: Vec<Vec<u8>>,
    req_frames: Vec<Vec<u8>>,
    resp: Vec<Vec<u8>>,
    resp_frames: Vec<Vec<u8>>,
    per_unit: Vec<usize>,
}

impl Bench {
    /// C seals each payload (spec §8.4), R opens, executes and answers with `draws` as its randomness (all of them
    /// consumed), C opens and decodes every response frame (a `CELLR` with its request as context).
    fn exchange(&mut self, reqs: &[Vec<u8>], draws: &[u8]) -> Exchange {
        let context = if reqs.first().and_then(|p| p.first()) == Some(&opcode::FETCH_MULTI) {
            CellrContext::FetchMulti
        } else {
            CellrContext::Fetch
        };
        let mut entropy = FixedEntropy::new(draws);
        let mut x = Exchange::default();
        for p in reqs {
            let frame = self.client.seal(p).unwrap().to_vec();
            assert_eq!(frame.len(), FRAME, "request frame length");
            let outcome = self.exec.on_unit(&self.relay, &frame, now(), &mut entropy);
            assert!(
                !matches!(outcome, Outcome::Teardown),
                "teardown on an honest frame"
            );
            let frames: Vec<Vec<u8>> = match outcome {
                Outcome::Respond(f) => f.iter().map(|b| b.to_vec()).collect(),
                Outcome::Pending | Outcome::Teardown => Vec::new(),
            };
            for f in &frames {
                assert_eq!(f.len(), FRAME, "response frame length");
                let opened = self.client.open_unit(f).unwrap();
                assert_eq!(opened.padded().len(), PLAIN, "response plaintext length");
                assert!(Response::decode(opened.padded(), context).is_ok());
                x.resp.push(opened.payload().to_vec());
                self.client.commit(&opened).unwrap();
            }
            x.req.push(p.clone());
            x.req_frames.push(frame);
            x.per_unit.push(frames.len());
            x.resp_frames.extend(frames);
        }
        assert_eq!(entropy.remaining(), 0, "the relay's draws consumed exactly");
        x
    }

    /// (`c2r`, `r2c`, `cmd_seq`) on the relay's side; the client's counters agree.
    fn post(&self) -> (u64, u64, u32) {
        let l = self.exec.link();
        let (c2r, r2c) = (l.recv_counter().unwrap(), l.send_counter().unwrap());
        assert_eq!(
            (self.client.send_counter(), self.client.recv_counter()),
            (Some(c2r), Some(r2c)),
            "both sides' counters agree"
        );
        (c2r, r2c, self.exec.last_cmd_seq())
    }
}

/// A handshake from scratch: the relay of case 1 answers `HELLO` with `RELAYINFO` and `HS1` with `HS2`
/// (`relay_draws`); the client checks `RELAYINFO`, sends `HS1` (`client_draws`) and accepts `HS2`.
struct Connected {
    bench: Bench,
    hello: Vec<u8>,
    rec_relayinfo: Vec<u8>,
    rec_hs1: Vec<u8>,
    /// The client's values after `HS1`.
    hs1_trace: HandshakeTrace,
    rec_hs2: Vec<u8>,
}

fn connect(
    secrets: &Secrets,
    relay_fp: [u8; 32],
    client_draws: &[u8],
    relay_draws: &[u8],
) -> Connected {
    let relay = secrets.relay();
    let access = secrets.access();
    let (hello, st) = link::client::start(relay_fp, Some(&access), NOW).unwrap();
    let (rec_relayinfo, st_r) = link::relay::accept_ring(relay.keys().ring())
        .on_hello(&hello, VALID_UNTIL)
        .unwrap();
    let mut ce = FixedEntropy::new(client_draws);
    let (rec_hs1, wait) = st.on_relayinfo(&rec_relayinfo, &mut ce).unwrap();
    assert_eq!(ce.remaining(), 0, "the client's draws consumed exactly");
    let hs1_trace = wait.trace_kat().clone();
    let mut re = FixedEntropy::new(relay_draws);
    let (rec_hs2, relay_link) = st_r.on_hs1(&rec_hs1, &mut re).unwrap();
    assert_eq!(re.remaining(), 0, "the relay's draws consumed exactly");
    let client = wait.on_hs2(&rec_hs2).unwrap();
    let exec = Executor::new(relay_link, relay.limits().link_rate, now());
    Connected {
        bench: Bench {
            relay,
            client,
            exec,
        },
        hello,
        rec_relayinfo,
        rec_hs1,
        hs1_trace,
        rec_hs2,
    }
}

/// Link A after `link-0008` (R expects `c2r` 3, C expects `r2c` 3, `last` 3): the handshake and P6–P8 replayed.
fn at_case_8(hs: &Hs, ex: &BTreeMap<u32, Exchange>) -> Bench {
    let c = connect(&hs.secrets, hs.relay_fp, &hs.client_draws, &hs.relay_draws);
    assert_eq!(c.rec_hs2, hs.rec_hs2);
    let mut b = c.bench;
    for n in 6..=8 {
        let x = ex.get(&n).unwrap();
        let again = b.exchange(&x.req, &[]);
        assert_eq!(again.req_frames, x.req_frames, "{} replayed", case_id(n));
        assert_eq!(again.resp_frames, x.resp_frames, "{} replayed", case_id(n));
    }
    assert_eq!(b.post(), (3, 3, 3));
    b
}

// ---------------------------------------------------------------------------------------------------------------
// P1–P5: the relay's keys and the handshake.

/// P1 `link-0001` `relay-keys` (spec §8.2, D.1).
fn relay_keys() -> (Secrets, [u8; 32], Vec<u8>, (u32, Value)) {
    let mut s = Stream::new(1);
    let secrets = Secrets {
        sig_seed: s.draw("relay_sig_seed", 32),
        dh_sk: s.draw("relay_dh_sk", 32),
        kem_seed: s.draw("relay_kem_seed", 64),
        access_key: s.draw("relay_access_key", 32),
    };
    let keys = secrets.keys();
    let info = keys.relay_info(VALID_UNTIL).unwrap();
    let relayinfo = info.encode().unwrap().to_vec();
    let rec = keys.relay_info_record(VALID_UNTIL).unwrap();
    assert_eq!((relayinfo.len(), rec.len()), (1741, 1744));
    // len (1742) ‖ 0x02 ‖ RelayInfoV1 (D.1)
    assert_eq!(sl(&rec, ..3), [0x06, 0xce, 0x02]);
    assert_eq!(sl(&rec, 3..), relayinfo.as_slice());
    let sig_pk = keys.sig_pk().as_bytes();
    // relay_fp = SHA-256("SecMP-LINK/1 relay-fp" ‖ relay_sig_pk); akc = SHA-256("SecMP-Q/1 akc" ‖ key) (§8.2, §5.3)
    let relay_fp = sha256(&[Label::LinkRelayFp.as_bytes(), sig_pk]);
    assert_eq!(keys.fp(), relay_fp);
    assert_eq!(
        keys.akc(),
        sha256(&[Label::QAkc.as_bytes(), &secrets.access_key])
    );
    assert_eq!(secrets.resign(&rec), rec, "Ed25519 is deterministic");
    let mut o = Out::default();
    o.b("relay_sig_pk", sig_pk);
    o.b("relay_fp", &relay_fp);
    o.b("relay_dh_pk", info.relay_dh_pk.as_bytes());
    o.b("relay_kem_ek", info.relay_kem_ek.as_bytes());
    o.b("akc", &info.akc);
    o.b("relayinfo", &relayinfo);
    o.b("rec_relayinfo", &rec);
    let case = make_case(
        1,
        "relay-keys",
        "R",
        None,
        s.inputs,
        vec![("outputs", o.done())],
    );
    (secrets, relay_fp, rec, case)
}

/// The key schedule of spec §8.3 recomputed from the records and the shared secrets of `t`.
fn check_schedule(t: &HandshakeTrace, relay_fp: &[u8; 32], rec_hs1: &[u8], rec_hs2: &[u8]) {
    let hs1 = Hs1::decode(rec_hs1).unwrap();
    let hs2 = Hs2::decode(rec_hs2).unwrap();
    // h0 = SHA-256("SecMP-LINK/1 h0" ‖ 0x01 ‖ u32be(kid) ‖ relay_fp ‖ e_c ‖ SHA-256(ek_c) ‖ pk_e1 ‖ SHA-256(ct_kem))
    let h0 = sha256(&[
        Label::LinkH0.as_bytes(),
        &[1],
        &KID.to_be_bytes(),
        relay_fp,
        hs1.e_c.as_bytes(),
        &sha256(&[hs1.ek_c.as_bytes()]),
        hs1.pk_e1.as_bytes(),
        &sha256(&[hs1.ct_kem.as_slice()]),
    ]);
    assert_eq!(t.h0, h0, "h0");
    let ck1 = hkdf_extract(&h0, &t.ss1).unwrap();
    assert_eq!(*ck1.expose_secret(), t.ck1, "ck1");
    let mac1 = hmac_sha256(ck1.expose_secret(), Label::LinkHs1, &[]).unwrap();
    assert_eq!((mac1, hs1.mac1), (t.mac1, t.mac1), "mac1");
    // h1 = SHA-256(h0 ‖ mac1 ‖ e_r ‖ SHA-256(ct_c)); ck2 = HKDF-Extract(h1, ck1 ‖ ss2)
    let h1 = sha256(&[
        &h0,
        &mac1,
        hs2.e_r.as_bytes(),
        &sha256(&[hs2.ct_c.as_slice()]),
    ]);
    assert_eq!(t.h1, h1, "h1");
    let ck2 = hkdf_extract(&h1, &[t.ck1, t.ss2].concat()).unwrap();
    assert_eq!(*ck2.expose_secret(), t.ck2, "ck2");
    let mac2 = hmac_sha256(ck2.expose_secret(), Label::LinkHs2, &[]).unwrap();
    assert_eq!((mac2, hs2.mac2), (t.mac2, t.mac2), "mac2");
}

/// A handshake step: `from` is the preceding step.
fn step(i: u32, op: &str, party: &str, inputs: Map<String, Value>, o: Out) -> (u32, Value) {
    make_case(
        i,
        op,
        party,
        i.checked_sub(1),
        inputs,
        vec![("outputs", o.done())],
    )
}

/// P3's outputs: the fields of `HS1`, the client's `ss1`, `h0`, `ck1`, `mac1`, the record (spec §8.3).
fn hs1_outputs(c: &Connected) -> Out {
    let hs1 = Hs1::decode(&c.rec_hs1).unwrap();
    assert_eq!((c.rec_hs1.len(), hs1.kid), (h1::LEN, KID));
    let t = &c.hs1_trace;
    let mut o = Out::default();
    o.b("e_c", hs1.e_c.as_bytes());
    o.b("ek_c", hs1.ek_c.as_bytes());
    o.b("pk_e1", hs1.pk_e1.as_bytes());
    o.b("ct_kem", hs1.ct_kem.as_slice());
    for (name, v) in [
        ("ss1", t.ss1),
        ("h0", t.h0),
        ("ck1", t.ck1),
        ("mac1", t.mac1),
    ] {
        o.b(name, &v);
    }
    o.b("hs1", sl(&c.rec_hs1, 3..));
    o.b("rec_hs1", &c.rec_hs1);
    o
}

/// P4's outputs: the relay's values (`rt`) — `ss1`, `h0`, `ck1` equal the client's of P3 (asserted) — the fields of
/// `HS2`, the record, the link keys and `link_post`.
fn hs2_outputs(c: &Connected, rt: &HandshakeTrace, relay_fp: &[u8; 32]) -> Out {
    let t = &c.hs1_trace;
    assert_eq!(
        (rt.ss1, rt.h0, rt.ck1),
        (t.ss1, t.h0, t.ck1),
        "ss1, h0, ck1 = link-0003"
    );
    check_schedule(rt, relay_fp, &c.rec_hs1, &c.rec_hs2);
    let hs2 = Hs2::decode(&c.rec_hs2).unwrap();
    let mut o = Out::default();
    for (name, v) in [("ss1", rt.ss1), ("h0", rt.h0), ("ck1", rt.ck1)] {
        o.b(name, &v);
    }
    o.b("e_r", hs2.e_r.as_bytes());
    o.b("ct_c", hs2.ct_c.as_slice());
    for (name, v) in [
        ("ss2", rt.ss2),
        ("h1", rt.h1),
        ("ck2", rt.ck2),
        ("mac2", rt.mac2),
    ] {
        o.b(name, &v);
    }
    o.b("hs2", sl(&c.rec_hs2, 3..));
    o.b("rec_hs2", &c.rec_hs2);
    o.b("k_c2r", &rt.k_c2r);
    o.b("k_r2c", &rt.k_r2c);
    o.b("sess_id", &rt.sess_id);
    o.v("link_post", link_post(c.bench.post()));
    o
}

/// P5's outputs: the client's values (`ct`), byte-equal to the relay's (asserted), and `link_post`.
fn hs2_accept_outputs(c: &Connected, ct: &HandshakeTrace, rt: &HandshakeTrace) -> Out {
    let six = |t: &HandshakeTrace| (t.ss2, t.h1, t.ck2, t.k_c2r, t.k_r2c, t.sess_id, t.mac2);
    assert_eq!(six(ct), six(rt), "the six values (and mac2) = link-0004");
    let mut o = Out::default();
    for (name, v) in [
        ("ss2", ct.ss2),
        ("h1", ct.h1),
        ("ck2", ct.ck2),
        ("k_c2r", ct.k_c2r),
        ("k_r2c", ct.k_r2c),
    ] {
        o.b(name, &v);
    }
    o.b("sess_id", &ct.sess_id);
    o.v("link_post", link_post(c.bench.post()));
    o
}

/// P2–P5 (`link-0002` … `link-0005`): `HELLO` and the client's `RELAYINFO` check, `HS1`, `HS2`, the client's
/// acceptance. Returns the handshake, link A, and the four cases.
fn handshake(
    secrets: Secrets,
    relay_fp: [u8; 32],
    rec_relayinfo: &[u8],
) -> (Hs, Bench, Vec<(u32, Value)>) {
    // reading OPEN-1: C draws e_c_sk, ek_c_seed, sk_e1, m1; R draws sk_er, m2
    let mut s3 = Stream::new(3);
    let client_draws = [
        s3.draw("e_c_sk", 32),
        s3.draw("ek_c_seed", 64),
        s3.draw("sk_e1", 32),
        s3.draw("m1", 32),
    ]
    .concat();
    let mut s4 = Stream::new(4);
    let relay_draws = [s4.draw("sk_er", 32), s4.draw("m2", 32)].concat();
    let c = connect(&secrets, relay_fp, &client_draws, &relay_draws);
    assert_eq!(c.hello, HELLO, "rec_hello");
    assert_eq!(c.rec_relayinfo, rec_relayinfo, "RELAYINFO of case 1");
    let rt = c.bench.exec.link().trace_kat().clone();
    let ct = c.bench.client.trace_kat().clone();
    // P2: the client accepted case 1's RELAYINFO (it answered with HS1)
    let mut o = Out::default();
    o.b("rec_hello", &c.hello);
    o.v("accept", json!(true));
    let cases = vec![
        step(2, "relayinfo-accept", "C", Map::new(), o),
        step(3, "hs1", "C", s3.inputs, hs1_outputs(&c)),
        step(4, "hs2", "R", s4.inputs, hs2_outputs(&c, &rt, &relay_fp)),
        step(
            5,
            "hs2-accept",
            "C",
            Map::new(),
            hs2_accept_outputs(&c, &ct, &rt),
        ),
    ];
    let hs = Hs {
        secrets,
        relay_fp,
        rec_relayinfo: c.rec_relayinfo,
        client_draws,
        rec_hs1: c.rec_hs1,
        relay_draws,
        rec_hs2: c.rec_hs2,
        k_c2r: ct.k_c2r,
        k_r2c: ct.k_r2c,
        sess_id: ct.sess_id,
    };
    (hs, c.bench, cases)
}

// ---------------------------------------------------------------------------------------------------------------
// Link A: `link-0006` … `link-0050`.

/// The case-level fields of a link-A case.
struct Cmd {
    i: u32,
    op: &'static str,
    seq: u32,
    manipulation: Option<&'static str>,
}

/// A positive case.
const fn pos(i: u32, op: &'static str, seq: u32) -> Cmd {
    Cmd {
        i,
        op,
        seq,
        manipulation: None,
    }
}

/// A command-error case (`manipulation` and `outputs`, no `expect`).
const fn err(i: u32, op: &'static str, seq: u32, manipulation: &'static str) -> Cmd {
    Cmd {
        i,
        op,
        seq,
        manipulation: Some(manipulation),
    }
}

/// The relay's draws of a response: `k` dummy cells.
fn dummies(k: usize) -> Vec<(&'static str, usize)> {
    DUMMY.iter().take(k).map(|n| (*n, CELL)).collect()
}

/// A `FETCH` error: the error frame's `cell_r`, then three dummies (reading OPEN-7).
fn fetch_error_draws() -> Vec<(&'static str, usize)> {
    [("cell_r", CELL)].into_iter().chain(dummies(3)).collect()
}

/// Queue A (`link-0006`'s keys) or B (`link-0015`'s): (recv key, send key).
type Queue = (Key, Key);

fn pks(q: &Queue) -> (&Ed25519Pk, &Ed25519Pk) {
    (&q.0.pk, &q.1.pk)
}

/// The run on link A.
struct Run {
    b: Bench,
    access: Vec<u8>,
    sess: Id,
    prev: u32,
    cases: Vec<(u32, Value)>,
    ex: BTreeMap<u32, Exchange>,
}

impl Run {
    fn token(&self, seq: u32) -> [u8; 32] {
        token(&self.access, &self.sess, seq)
    }

    /// One link-A case: the relay's draws (after the client's, which the caller has drawn), the round trip, the
    /// outputs (`derived`, `req`, `req_frames`, `resp`, `resp_frames`, `link_post`, `store_post`).
    fn command(
        &mut self,
        c: &Cmd,
        mut s: Stream,
        reqs: &[Vec<u8>],
        relay: &[(&str, usize)],
        derived: &[(&str, Vec<u8>)],
    ) {
        let draws: Vec<u8> = relay
            .iter()
            .flat_map(|&(name, n)| s.draw(name, n))
            .collect();
        let seq = reqs
            .first()
            .and_then(|p| p.get(1..5))
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()));
        assert_eq!(
            seq,
            Some(c.seq),
            "{}: cmd_seq of the first request frame",
            case_id(c.i)
        );
        let x = self.b.exchange(reqs, &draws);
        let mut o = Out::default();
        for (name, v) in derived {
            o.b(name, v);
        }
        o.v("req", hex_list(&x.req));
        o.v("req_frames", hex_list(&x.req_frames));
        o.v("resp", hex_list(&x.resp));
        o.v("resp_frames", hex_list(&x.resp_frames));
        o.v("link_post", link_post(self.b.post()));
        o.v("store_post", store_post(&self.b.relay.snapshot_kat()));
        let mut rest = vec![("cmd_seq", json!(c.seq)), ("outputs", o.done())];
        if let Some(m) = c.manipulation {
            rest.push(("manipulation", json!(m)));
        }
        self.cases
            .push(make_case(c.i, c.op, "CR", Some(self.prev), s.inputs, rest));
        self.prev = c.i;
        self.ex.insert(c.i, x);
    }

    /// P6–P8: `QUEUE_NEW` of queue A, `SEND`, `PING` — frames 1–3 each way (reading OPEN-13).
    fn first_frames(&mut self) -> Queue {
        let mut s = Stream::new(6);
        let a = (s.key("recv_seed"), s.key("send_seed"));
        s.list("recv_pk", a.0.pk.as_bytes());
        s.list("send_pk", a.1.pk.as_bytes());
        let req = queue_new(&self.sess, 1, pks(&a), self.token(1), &a.0);
        let derived = [
            ("rid", rid_of(&a.0.pk).to_vec()),
            ("sid", sid_of(&a.0.pk, &a.1.pk).to_vec()),
        ];
        let derived: Vec<(&str, Vec<u8>)> =
            derived.into_iter().chain(token_and_sig(&req)).collect();
        self.command(&pos(6, "queue-new", 1), s, &[payload(&req)], &[], &derived);
        self.send(&pos(7, "send", 2), &a, &a.1);
        self.command(
            &pos(8, "ping", 3),
            Stream::new(8),
            &[payload(&ping(3))],
            &[],
            &[],
        );
        a
    }

    /// A `SEND` of a stream cell to `q`'s `sid`, signed by `signer`; a positive case lists `sig`.
    fn send(&mut self, c: &Cmd, q: &Queue, signer: &Key) {
        let mut s = Stream::new(c.i);
        let cell = s.draw("cell", CELL);
        let req = send(&self.sess, c.seq, sid_of(&q.0.pk, &q.1.pk), &cell, signer);
        let derived = if c.manipulation.is_none() {
            vec![("sig", sig_of(&req))]
        } else {
            Vec::new()
        };
        self.command(c, s, &[payload(&req)], &[], &derived);
    }

    /// A positive `FETCH` of `q` with `ack` and `k` dummy draws.
    fn fetch(&mut self, c: &Cmd, q: &Queue, ack: u64, k: usize) {
        let req = fetch(&self.sess, c.seq, rid_of(&q.0.pk), ack, &q.0);
        self.command(
            c,
            Stream::new(c.i),
            &[payload(&req)],
            &dummies(k),
            &[("sig", sig_of(&req))],
        );
    }

    /// P9–P14: the identical `QUEUE_NEW`, two `SEND`s, `FETCH` with `ack` 0 twice (idempotence), then 2.
    fn queue_a(&mut self, a: &Queue) {
        let mut s = Stream::new(9);
        s.list("recv_pk", a.0.pk.as_bytes());
        s.list("send_pk", a.1.pk.as_bytes());
        let req = queue_new(&self.sess, 4, pks(a), self.token(4), &a.0);
        self.command(
            &pos(9, "queue-new", 4),
            s,
            &[payload(&req)],
            &[],
            &token_and_sig(&req),
        );
        self.send(&pos(10, "send", 5), a, &a.1);
        self.send(&pos(11, "send", 6), a, &a.1);
        self.fetch(&pos(12, "fetch", 7), a, 0, 1);
        self.fetch(&pos(13, "fetch", 8), a, 0, 1);
        // FETCH idempotence: the (cell_id, cell) of the three present-1 CELLRs equal link-0012's
        let cells = |n: u32| -> Vec<Vec<u8>> {
            let x = self.ex.get(&n).unwrap();
            x.resp.iter().take(3).map(|p| sl(p, 5..).to_vec()).collect()
        };
        assert_eq!(cells(13), cells(12), "link-0013 = link-0012");
        self.fetch(&pos(14, "fetch", 9), a, 2, 3);
    }

    /// P15–P21 with E1: queue B, a third queue refused (ERR 2), `SEND`s to B and A, `FETCH_MULTI`, the fill of B,
    /// the eviction, the `FETCH` of B.
    fn queue_b(&mut self, a: &Queue) -> Queue {
        let mut s = Stream::new(15);
        let b = (s.key("recv_seed"), s.key("send_seed"));
        s.list("recv_pk", b.0.pk.as_bytes());
        s.list("send_pk", b.1.pk.as_bytes());
        let req = queue_new(&self.sess, 10, pks(&b), self.token(10), &b.0);
        let derived = [
            ("rid", rid_of(&b.0.pk).to_vec()),
            ("sid", sid_of(&b.0.pk, &b.1.pk).to_vec()),
        ];
        let derived: Vec<(&str, Vec<u8>)> =
            derived.into_iter().chain(token_and_sig(&req)).collect();
        self.command(
            &pos(15, "queue-new", 10),
            s,
            &[payload(&req)],
            &[],
            &derived,
        );
        // E1: an honest QUEUE_NEW of a fresh third queue (reading OPEN-12)
        let mut s = Stream::new(16);
        let third = (s.key("recv_seed"), s.key("send_seed"));
        let req = queue_new(&self.sess, 11, pks(&third), self.token(11), &third.0);
        self.command(
            &err(16, "queue-new", 11, "queue-new-full"),
            s,
            &[payload(&req)],
            &[],
            &[],
        );
        self.send(&pos(17, "send", 12), &b, &b.1);
        self.send(&pos(18, "send", 13), a, &a.1);
        // P18: FETCH_MULTI [B ack 0, A ack 2]; sig_0, sig_1 in entry order (reading OPEN-8)
        let entries = vec![
            entry(&self.sess, 14, rid_of(&b.0.pk), 0, &b.0),
            entry(&self.sess, 14, rid_of(&a.0.pk), 2, &a.0),
        ];
        let derived: Vec<(&str, Vec<u8>)> = ["sig_0", "sig_1"]
            .into_iter()
            .zip(&entries)
            .map(|(name, e)| (name, e.sig.as_bytes().to_vec()))
            .collect();
        let req = Request {
            cmd_seq: 14,
            cmd: RequestCmd::FetchMulti { entries },
        };
        self.command(
            &pos(19, "fetch-multi", 14),
            Stream::new(19),
            &[payload(&req)],
            &dummies(5),
            &derived,
        );
        self.fill(&b);
        self.send(&pos(21, "send", 142), &b, &b.1);
        self.fetch(&pos(22, "fetch", 143), &b, 0, 0);
        b
    }

    /// P19 `link-0020` `send-fill`: 127 `SEND`s of `fill_cell` to B.
    fn fill(&mut self, b: &Queue) {
        let mut s = Stream::new(20);
        let cell = s.draw("fill_cell", CELL);
        let sid = sid_of(&b.0.pk, &b.1.pk);
        let mut frames = Vec::new();
        let mut last = Vec::new();
        for k in 0..FILL {
            let seq = 15_u32.checked_add(k).unwrap();
            let x = self
                .b
                .exchange(&[payload(&send(&self.sess, seq, sid, &cell, &b.1))], &[]);
            assert_eq!(x.resp_frames.len(), 1);
            frames.extend(x.req_frames.concat());
            frames.extend(x.resp_frames.concat());
            last = x.resp.concat();
        }
        assert_eq!(frames.len(), FRAME.checked_mul(254).unwrap());
        let mut o = Out::default();
        o.b("frames_sha256", &sha256(&[&frames]));
        o.b("resp_last", &last);
        o.v("link_post", link_post(self.b.post()));
        o.v("store_post", store_post(&self.b.relay.snapshot_kat()));
        let rest = vec![
            ("cmd_seq", json!(15)),
            ("count", json!(FILL)),
            ("outputs", o.done()),
        ];
        self.cases.push(make_case(
            20,
            "send-fill",
            "CR",
            Some(self.prev),
            s.inputs,
            rest,
        ));
        self.prev = 20;
    }

    /// P22–P27 with E2: the `cmd_seq` gap, `QUEUE_DEL` of A, `LINK_PUT` of L (and again: ERR 5), owner status,
    /// consumption, owner status after it. Returns L's owner and `ld_id`.
    fn link_data(&mut self, a: &Queue) -> (Key, Id) {
        self.command(
            &pos(23, "ping", 145),
            Stream::new(23),
            &[payload(&ping(145))],
            &[],
            &[],
        );
        let req = queue_del(&self.sess, 146, rid_of(&a.0.pk), &a.0);
        self.command(
            &pos(24, "queue-del", 146),
            Stream::new(24),
            &[payload(&req)],
            &[],
            &[("sig", sig_of(&req))],
        );
        let mut s = Stream::new(25);
        let ld = id16(&s.draw("ld_id", 16));
        let owner = s.key("owner_seed");
        let blob = s.draw("blob", BLOB);
        s.list("owner_pk", owner.pk.as_bytes());
        let put = |seq: u32, token: [u8; 32]| {
            let p = Put {
                ld_id: &ld,
                owner_pk: &owner.pk,
                token,
                signer: &owner,
                blob: &blob,
            };
            link_put(&self.sess, seq, &p)
        };
        let p24 = put(147, self.token(147));
        let e2 = put(148, self.token(148));
        let derived = token_and_sig(p24.first().unwrap());
        self.command(&pos(25, "link-put", 147), s, &payloads(&p24), &[], &derived);
        self.command(
            &err(26, "link-put", 148, "link-put-exists"),
            Stream::new(26),
            &payloads(&e2),
            &[],
            &[],
        );
        let blob_draw = [("dummy_blob", BLOB)];
        let req = link_get_owner(&self.sess, 149, &ld, &owner);
        self.command(
            &pos(27, "link-get", 149),
            Stream::new(27),
            &[payload(&req)],
            &blob_draw,
            &[("sig", sig_of(&req))],
        );
        let req = link_get_consume(150, &ld);
        self.command(
            &pos(28, "link-get", 150),
            Stream::new(28),
            &[payload(&req)],
            &[],
            &[],
        );
        // the consuming call returns P24's blob: 4160 + 4100 + 4100 bytes after the LINKR and CONT heads
        let x = self.ex.get(&28).unwrap();
        let parts: Vec<u8> = x
            .resp
            .iter()
            .zip([7, 6, 6])
            .flat_map(|(p, head)| sl(p, head..).to_vec())
            .collect();
        assert_eq!(parts, blob, "link-0028 returns the blob");
        let req = link_get_owner(&self.sess, 151, &ld, &owner);
        self.command(
            &pos(29, "link-get", 151),
            Stream::new(29),
            &[payload(&req)],
            &blob_draw,
            &[("sig", sig_of(&req))],
        );
        (owner, ld)
    }

    /// E3–E7: `QUEUE_NEW` with a flipped, replayed or foreign token, a known `recv_pk` with another `send_pk`, and
    /// the wrong signer.
    fn queue_new_errors(&mut self, b: &Queue) {
        let other = flip_id(&self.sess);
        let rows: [(u32, u32, &'static str); 3] = [
            (30, 152, "token-flip"),
            (31, 153, "token-replayed"),
            (32, 154, "token-other-link"),
        ];
        for (i, seq, manipulation) in rows {
            let mut s = Stream::new(i);
            let q = (s.key("recv_seed"), s.key("send_seed"));
            let token = match i {
                30 => arr32(&flip(&self.token(seq), 0)),
                // P6's token, made for cmd_seq 1
                31 => self.token(1),
                _ => token(&self.access, &other, seq),
            };
            let req = queue_new(&self.sess, seq, pks(&q), token, &q.0);
            self.command(
                &err(i, "queue-new", seq, manipulation),
                s,
                &[payload(&req)],
                &[],
                &[],
            );
        }
        // E6: B's recv key with a fresh send key
        let mut s = Stream::new(33);
        let fresh = s.key("send_seed");
        s.list("recv_pk", b.0.pk.as_bytes());
        let req = queue_new(&self.sess, 155, (&b.0.pk, &fresh.pk), self.token(155), &b.0);
        self.command(
            &err(33, "queue-new", 155, "send-pk-differs"),
            s,
            &[payload(&req)],
            &[],
            &[],
        );
        // E7: signed by the send key
        let mut s = Stream::new(34);
        let q = (s.key("recv_seed"), s.key("send_seed"));
        let req = queue_new(&self.sess, 156, pks(&q), self.token(156), &q.1);
        self.command(
            &err(34, "queue-new", 156, "wrong-signer"),
            s,
            &[payload(&req)],
            &[],
            &[],
        );
    }

    /// E8–E16: `SEND`, `FETCH`, `FETCH_MULTI` and `QUEUE_DEL` errors.
    fn queue_errors(&mut self, a: &Queue, b: &Queue) {
        self.send(&err(35, "send", 157, "wrong-signer"), b, &b.0);
        // E9: B's send key over flip(sess_id, 0)
        let other = flip_id(&self.sess);
        let mut s = Stream::new(36);
        let cell = s.draw("cell", CELL);
        let req = send(&other, 158, sid_of(&b.0.pk, &b.1.pk), &cell, &b.1);
        self.command(
            &err(36, "send", 158, "sess-id-other-link"),
            s,
            &[payload(&req)],
            &[],
            &[],
        );
        // E10: A was deleted in P23
        self.send(&err(37, "send", 159, "unknown-sid"), a, &a.1);
        let (rid_a, rid_b) = (rid_of(&a.0.pk), rid_of(&b.0.pk));
        let rows: [(u32, u32, &'static str, Request); 4] = [
            (
                38,
                160,
                "unknown-rid",
                fetch(&self.sess, 160, rid_a, 0, &a.0),
            ),
            (
                39,
                161,
                "wrong-signer",
                fetch(&self.sess, 161, rid_b, 0, &b.1),
            ),
            (
                40,
                162,
                "sess-id-other-link",
                fetch(&other, 162, rid_b, 0, &b.0),
            ),
            // ack 130 = B's next_cell_id
            (
                41,
                163,
                "stale-ack",
                fetch(&self.sess, 163, rid_b, 130, &b.0),
            ),
        ];
        for (i, seq, manipulation, req) in rows {
            self.command(
                &err(i, "fetch", seq, manipulation),
                Stream::new(i),
                &[payload(&req)],
                &fetch_error_draws(),
                &[],
            );
        }
        // E15: entries [A ack 0, B ack 0]; the error frame carries cell_r (reading OPEN-8)
        let req = Request {
            cmd_seq: 164,
            cmd: RequestCmd::FetchMulti {
                entries: vec![
                    entry(&self.sess, 164, rid_a, 0, &a.0),
                    entry(&self.sess, 164, rid_b, 0, &b.0),
                ],
            },
        };
        let c = err(42, "fetch-multi", 164, "one-queue-unknown");
        self.command(
            &c,
            Stream::new(42),
            &[payload(&req)],
            &[("cell_r", CELL)],
            &[],
        );
        let req = queue_del(&self.sess, 165, rid_b, &b.1);
        self.command(
            &err(43, "queue-del", 165, "wrong-signer"),
            Stream::new(43),
            &[payload(&req)],
            &[],
            &[],
        );
    }

    /// E17–E23: `LINK_PUT`, `LINK_GET`, `SKEY` and `cmd_seq` errors.
    fn link_errors(&mut self, l_owner: &Key, l: &Id) {
        // E17: a fresh entry with a flipped token, signed as sent
        let mut s = Stream::new(44);
        let ld = id16(&s.draw("ld_id", 16));
        let owner = s.key("owner_seed");
        let blob = s.draw("blob", BLOB);
        let p = Put {
            ld_id: &ld,
            owner_pk: &owner.pk,
            token: arr32(&flip(&self.token(166), 0)),
            signer: &owner,
            blob: &blob,
        };
        let put = link_put(&self.sess, 166, &p);
        self.command(
            &err(44, "link-put", 166, "token-flip"),
            s,
            &payloads(&put),
            &[],
            &[],
        );
        // E18: owner_pk of owner_seed, signed by signer_seed
        let mut s = Stream::new(45);
        let ld = id16(&s.draw("ld_id", 16));
        let owner = s.key("owner_seed");
        let signer = s.key("signer_seed");
        let blob = s.draw("blob", BLOB);
        let p = Put {
            ld_id: &ld,
            owner_pk: &owner.pk,
            token: self.token(167),
            signer: &signer,
            blob: &blob,
        };
        let put = link_put(&self.sess, 167, &p);
        self.command(
            &err(45, "link-put", 167, "wrong-signer"),
            s,
            &payloads(&put),
            &[],
            &[],
        );
        let blob_draw = [("dummy_blob", BLOB)];
        // E19: consume L again
        let req = link_get_consume(168, l);
        self.command(
            &err(46, "link-get", 168, "consume-again"),
            Stream::new(46),
            &[payload(&req)],
            &blob_draw,
            &[],
        );
        // E20: an ld_id that was never stored
        let mut s = Stream::new(47);
        let unknown = id16(&s.draw("ld_id", 16));
        let req = link_get_consume(169, &unknown);
        self.command(
            &err(47, "link-get", 169, "unknown-ld-id"),
            s,
            &[payload(&req)],
            &blob_draw,
            &[],
        );
        // E21: SKEY = 0x02 ‖ cmd_seq (D.2; reading OPEN-6)
        let skey = [&[opcode::SKEY][..], &170_u32.to_be_bytes()].concat();
        self.command(
            &err(48, "skey", 170, "reserved-opcode"),
            Stream::new(48),
            &[skey],
            &[],
            &[],
        );
        // E22: owner status on L signed by signer_seed (reading OPEN-10)
        let mut s = Stream::new(49);
        let signer = s.key("signer_seed");
        let req = link_get_owner(&self.sess, 171, l, &signer);
        assert_ne!(
            sig_of(&req),
            sig_of(&link_get_owner(&self.sess, 171, l, l_owner))
        );
        self.command(
            &err(49, "link-get", 171, "owner-wrong-signer"),
            s,
            &[payload(&req)],
            &blob_draw,
            &[],
        );
        // E23: PING 172 (OK), then PING 172 again (ERR 6; reading OPEN-5)
        let reqs = payloads(&[ping(172), ping(172)]);
        self.command(
            &err(50, "ping", 172, "cmd-seq-replayed"),
            Stream::new(50),
            &reqs,
            &[],
            &[],
        );
    }
}

/// `link-0006` … `link-0050` in event order on link A.
fn link_a(b: Bench, hs: &Hs) -> Run {
    let mut run = Run {
        b,
        access: hs.secrets.access_key.clone(),
        sess: hs.sess_id,
        prev: 5,
        cases: Vec::new(),
        ex: BTreeMap::new(),
    };
    let a = run.first_frames();
    run.queue_a(&a);
    let b = run.queue_b(&a);
    let (owner, ld) = run.link_data(&a);
    run.queue_new_errors(&b);
    run.queue_errors(&a, &b);
    run.link_errors(&owner, &ld);
    assert_eq!(run.prev, 50);
    run
}

// ---------------------------------------------------------------------------------------------------------------
// X1 and the reject groups.

/// X1 `link-0051`: the response frame counts of a success and the errors of the same command; items 2–4 of the
/// byte-level test (position after the command's last request frame, 4352-B frames, 4336-B plaintexts) for every
/// link-A case.
fn indist(ex: &BTreeMap<u32, Exchange>) -> (u32, Value) {
    const GROUPS: [&[u32]; 7] = [
        &[7, 35, 37],
        &[12, 38, 41],
        &[19, 42],
        &[6, 16, 30, 33],
        &[25, 26, 44],
        &[27, 28, 29, 46, 47, 49],
        &[8, 48],
    ];
    for (n, x) in ex {
        let op = x.req.first().and_then(|p| p.first()).copied().unwrap();
        // the D.2 frame count of the command, right after its last request frame (LINK_PUT: after the third)
        let count = match op {
            opcode::FETCH => 4,
            opcode::FETCH_MULTI => 8,
            opcode::LINK_GET => 3,
            _ => 1,
        };
        let expected = if op == opcode::LINK_PUT {
            vec![0, 0, 1]
        } else {
            vec![count; x.req.len()]
        };
        assert_eq!(
            x.per_unit,
            expected,
            "{}: response position and count",
            case_id(*n)
        );
        assert!(
            x.req_frames
                .iter()
                .chain(&x.resp_frames)
                .all(|f| f.len() == FRAME)
        );
    }
    let counts: Vec<Vec<usize>> = GROUPS
        .iter()
        .map(|g| {
            g.iter()
                .map(|n| ex.get(n).unwrap().resp_frames.len())
                .collect()
        })
        .collect();
    let literal: Vec<Vec<usize>> = vec![
        vec![1, 1, 1],
        vec![4, 4, 4],
        vec![8, 8],
        vec![1, 1, 1, 1],
        vec![1, 1, 1],
        vec![3, 3, 3, 3, 3, 3],
        vec![1, 1],
    ];
    assert_eq!(counts, literal, "link-0051 resp_counts");
    let ids: Vec<Vec<String>> = GROUPS
        .iter()
        .map(|g| g.iter().map(|n| case_id(*n)).collect())
        .collect();
    let mut o = Out::default();
    o.v("resp_counts", json!(counts));
    o.v("frame_len", json!(FRAME));
    make_case(
        51,
        "indist",
        "CR",
        None,
        Map::new(),
        vec![("cases", json!(ids)), ("outputs", o.done())],
    )
}

/// The client (pinning `pinned`, holding the access key) refuses `record` with the uniform error before it draws
/// anything (reading OPEN-2).
fn client_rejects_relayinfo(hs: &Hs, pinned: [u8; 32], record: &[u8]) {
    let access = hs.secrets.access();
    let (_hello, st) = link::client::start(pinned, Some(&access), NOW).unwrap();
    let r = st.on_relayinfo(record, &mut FixedEntropy::new(&[]));
    assert_eq!(r.err(), Some(link::Error::Rejected), "RELAYINFO rejected");
}

/// I1–I8 (`link-0052` … `link-0059`): the client of case 1's pin and access key against a manipulated `RELAYINFO`.
fn relayinfo_cases(hs: &Hs) -> Vec<(u32, Value)> {
    let honest = &hs.rec_relayinfo;
    let re = |rec: Vec<u8>| hs.secrets.resign(&rec);
    let at = |secs: u64| -> Vec<u8> { re(patch(honest, ri::VALID_UNTIL, &secs.to_be_bytes())) };
    let expired = NOW.checked_sub(1).unwrap();
    let too_long = NOW.checked_add(DAY.checked_mul(61).unwrap()).unwrap();
    let sixty = NOW.checked_add(DAY.checked_mul(60).unwrap()).unwrap();
    assert_eq!((too_long, sixty), (1_705_270_500, 1_705_184_100));
    let rows: [(u32, &str, Vec<u8>); 6] = [
        // the low byte of S: S stays < L, the decoder accepts and the verification fails
        (
            52,
            "ri-sig-flip",
            flip(honest, ri::SIG.checked_add(32).unwrap()),
        ),
        (54, "ri-expired", at(expired)),
        (55, "ri-akc-mismatch", re(flip(honest, ri::AKC))),
        (56, "ri-ver", re(patch(honest, ri::VER, &[2]))),
        (
            57,
            "ri-dh-low-order",
            re(patch(honest, ri::DH_PK, &LOW_ORDER_8)),
        ),
        (58, "relayinfo-valid-too-long", at(too_long)),
    ];
    let mut cases = Vec::new();
    for (i, manipulation, rec) in rows {
        client_rejects_relayinfo(hs, hs.relay_fp, &rec);
        let mut s = Stream::new(i);
        s.list("rec_relayinfo", &rec);
        cases.push(make_case(
            i,
            "relayinfo-reject",
            "C",
            Some(1),
            s.inputs,
            rejected(manipulation),
        ));
    }
    // I2: the honest RELAYINFO against the pin flip(relay_fp, 0)
    let pinned = arr32(&flip(&hs.relay_fp, 0));
    client_rejects_relayinfo(hs, pinned, honest);
    let mut s = Stream::new(53);
    s.list("relay_fp", &pinned);
    s.list("rec_relayinfo", honest);
    cases.push(make_case(
        53,
        "relayinfo-reject",
        "C",
        Some(1),
        s.inputs,
        rejected("ri-fp-mismatch"),
    ));
    // I8: valid_until − now = 60 days exactly is accepted
    let rec = at(sixty);
    let access = hs.secrets.access();
    let (_hello, st) = link::client::start(hs.relay_fp, Some(&access), NOW).unwrap();
    let accept = st
        .on_relayinfo(&rec, &mut FixedEntropy::new(&hs.client_draws))
        .is_ok();
    assert!(accept, "link-0059 accepted");
    let mut s = Stream::new(59);
    s.list("rec_relayinfo", &rec);
    let mut o = Out::default();
    o.v("accept", json!(accept));
    let rest = vec![
        ("manipulation", json!("relayinfo-valid-60d")),
        ("outputs", o.done()),
    ];
    cases.push(make_case(
        59,
        "relayinfo-accept",
        "C",
        Some(1),
        s.inputs,
        rest,
    ));
    cases
}

/// The relay of case 1 refuses `record` as its `HS1`: the responder with the uniform error and no draw (reading
/// OPEN-2), and the relay's connection closes with nothing emitted after `RELAYINFO`.
fn relay_rejects_hs1(hs: &Hs, record: &[u8]) {
    let keys = hs.secrets.keys();
    let (_info, st) = link::relay::accept(&keys)
        .on_hello(&HELLO, VALID_UNTIL)
        .unwrap();
    let r = st.on_hs1(record, &mut FixedEntropy::new(&[]));
    assert_eq!(r.err(), Some(link::Error::Rejected), "HS1 rejected");
    let relay = hs.secrets.relay();
    let mut conn = Connection::accept(&relay, now()).unwrap();
    let out = conn.on_bytes(&HELLO, now(), &mut FixedEntropy::new(&[]));
    assert_eq!(
        (out.bytes.as_slice(), out.close),
        (hs.rec_relayinfo.as_slice(), false)
    );
    let out = conn.on_bytes(record, now(), &mut FixedEntropy::new(&[]));
    assert!(out.bytes.is_empty() && out.close, "closed, nothing emitted");
}

/// H1 and S1–S10 (`link-0060` … `link-0070`): the relay (state of case 1) against manipulated `HELLO`/`HS1` records.
fn hs1_cases(hs: &Hs, p6_frame: &[u8]) -> Vec<(u32, Value)> {
    let mut cases = Vec::new();
    // H1: the magic reads "RECMP"
    let hello = flip(&HELLO, 3);
    let keys = hs.secrets.keys();
    let r = link::relay::accept(&keys).on_hello(&hello, VALID_UNTIL);
    assert_eq!(r.err(), Some(link::Error::Rejected), "HELLO rejected");
    let relay = hs.secrets.relay();
    let mut conn = Connection::accept(&relay, now()).unwrap();
    let out = conn.on_bytes(&hello, now(), &mut FixedEntropy::new(&[]));
    assert!(
        out.bytes.is_empty() && out.close,
        "HELLO: closed, nothing emitted"
    );
    let mut s = Stream::new(60);
    s.list("rec_hello", &hello);
    cases.push(make_case(
        60,
        "hs1-reject",
        "R",
        Some(1),
        s.inputs,
        rejected("hello-magic"),
    ));
    let honest = &hs.rec_hs1;
    let rows: [(u32, &str, Vec<u8>); 8] = [
        (61, "mac1-flip", flip(honest, h1::MAC1)),
        (62, "ct-kem-flip", flip(honest, h1::CT_KEM)),
        (
            63,
            "kid-unknown",
            patch(honest, h1::KID, &2_u32.to_be_bytes()),
        ),
        (
            65,
            "pk-e1-low-order",
            patch(honest, h1::PK_E1, &LOW_ORDER_8),
        ),
        (66, "e-c-zero", patch(honest, h1::E_C, &[0; 32])),
        (67, "ek-c-modulus", patch(honest, h1::EK_C, &[0xff; 3])),
        (68, "hs1-ver", patch(honest, h1::VER, &[2])),
        // the last body byte dropped and len := 2853
        (
            69,
            "hs1-short",
            [
                &2853_u16.to_be_bytes()[..],
                sl(honest, 2..h1::LEN.checked_sub(1).unwrap()),
            ]
            .concat(),
        ),
    ];
    for (i, manipulation, rec) in rows {
        relay_rejects_hs1(hs, &rec);
        let mut s = Stream::new(i);
        s.list("rec_hs1", &rec);
        cases.push(make_case(
            i,
            "hs1-reject",
            "R",
            Some(1),
            s.inputs,
            rejected(manipulation),
        ));
    }
    cases.push(wrong_static_key(hs));
    cases.push(hs1_replay(hs, p6_frame));
    cases
}

/// S4 `link-0064`: an honest `HS1` with `kid` 1 from a client that encapsulated to another static pair (the
/// `RELAYINFO` of `relay_sig` with `other_dh`, `other_kem`), with `mac1` from that `ss1`.
fn wrong_static_key(hs: &Hs) -> (u32, Value) {
    let mut s = Stream::new(64);
    let other_dh = s.draw("other_dh_sk", 32);
    let other_kem = s.draw("other_kem_seed", 64);
    let draws = [
        s.draw("e_c_sk", 32),
        s.draw("ek_c_seed", 64),
        s.draw("sk_e1", 32),
        s.draw("m1", 32),
    ]
    .concat();
    let info = hs
        .secrets
        .keys_with(&other_dh, &other_kem)
        .relay_info_record(VALID_UNTIL)
        .unwrap();
    let access = hs.secrets.access();
    let (_hello, st) = link::client::start(hs.relay_fp, Some(&access), NOW).unwrap();
    let mut e = FixedEntropy::new(&draws);
    let (rec, _) = st.on_relayinfo(&info, &mut e).unwrap();
    assert_eq!((e.remaining(), Hs1::decode(&rec).unwrap().kid), (0, KID));
    relay_rejects_hs1(hs, &rec);
    s.list("rec_hs1", &rec);
    make_case(
        64,
        "hs1-reject",
        "R",
        Some(1),
        s.inputs,
        rejected("wrong-static-key"),
    )
}

/// S10 `link-0070`: P3's `HS1` on a new connection is answered as a new handshake (reading OPEN-3); P6's request
/// frame (counter 0) then fails under the new `k_c2r`.
fn hs1_replay(hs: &Hs, p6_frame: &[u8]) -> (u32, Value) {
    let mut s = Stream::new(70);
    let draws = [s.draw("sk_er", 32), s.draw("m2", 32)].concat();
    let relay = hs.secrets.relay();
    let mut conn = Connection::accept(&relay, now()).unwrap();
    let out = conn.on_bytes(&HELLO, now(), &mut FixedEntropy::new(&[]));
    assert_eq!(out.bytes, hs.rec_relayinfo);
    let mut e = FixedEntropy::new(&draws);
    let out = conn.on_bytes(&hs.rec_hs1, now(), &mut e);
    assert!(!out.close && e.remaining() == 0);
    let rec_hs2 = out.bytes;
    let sess_id = *conn.executor().unwrap().link().sess_id();
    assert!(sess_id != hs.sess_id && rec_hs2 != hs.rec_hs2, "a new link");
    let out = conn.on_bytes(p6_frame, now(), &mut FixedEntropy::new(&[]));
    assert!(
        out.bytes.is_empty() && out.close,
        "P6's frame: closed, nothing emitted"
    );
    // the responder agrees, and its link refuses the frame with the uniform error
    let keys = hs.secrets.keys();
    let (_info, st) = link::relay::accept(&keys)
        .on_hello(&HELLO, VALID_UNTIL)
        .unwrap();
    let (again, mut l) = st
        .on_hs1(&hs.rec_hs1, &mut FixedEntropy::new(&draws))
        .unwrap();
    assert_eq!(again, rec_hs2);
    assert!(matches!(l.open(p6_frame), Err(link::Error::Rejected)));
    assert_eq!(l.recv_counter(), Some(0));
    s.list("rec_hs1", &hs.rec_hs1);
    s.list("frame", p6_frame);
    let mut o = Out::default();
    o.b("rec_hs2", &rec_hs2);
    o.b("sess_id", &sess_id);
    let mut rest = rejected("hs1-replay");
    rest.push(("outputs", o.done()));
    make_case(70, "hs1-reject", "R", Some(1), s.inputs, rest)
}

/// T1–T4 (`link-0071` … `link-0074`): the client of case 3 against a manipulated `HS2`.
fn hs2_cases(hs: &Hs) -> Vec<(u32, Value)> {
    let honest = &hs.rec_hs2;
    let rows: [(u32, &str, Vec<u8>); 4] = [
        (71, "mac2-flip", flip(honest, h2::MAC2)),
        // implicit rejection: C's ss2 differs, so mac2 fails
        (72, "ct-c-flip", flip(honest, h2::CT_C)),
        (73, "e-r-low-order", patch(honest, h2::E_R, &LOW_ORDER_8)),
        (74, "hs2-ver", patch(honest, h2::VER, &[2])),
    ];
    let access = hs.secrets.access();
    rows.into_iter()
        .map(|(i, manipulation, rec)| {
            let (_hello, st) = link::client::start(hs.relay_fp, Some(&access), NOW).unwrap();
            let (_hs1, wait) = st
                .on_relayinfo(&hs.rec_relayinfo, &mut FixedEntropy::new(&hs.client_draws))
                .unwrap();
            assert_eq!(
                wait.on_hs2(&rec).err(),
                Some(link::Error::Rejected),
                "HS2 rejected"
            );
            let mut s = Stream::new(i);
            s.list("rec_hs2", &rec);
            make_case(
                i,
                "hs2-reject",
                "C",
                Some(3),
                s.inputs,
                rejected(manipulation),
            )
        })
        .collect()
}

/// F1–F12 (`link-0075` … `link-0086`): one unit at the state of `link-0008`; the receiver rejects it with the
/// uniform LINK-level error and its counters, `cmd_seq` and store are unchanged (readings OPEN-2, OPEN-6).
fn frame_cases(hs: &Hs, ex: &BTreeMap<u32, Exchange>) -> Vec<(u32, Value)> {
    let (x8, x9) = (ex.get(&8).unwrap(), ex.get(&9).unwrap());
    let (req9, req9_frame) = (first(&x9.req), first(&x9.req_frames));
    let (resp9, resp9_frame) = (first(&x9.resp), first(&x9.resp_frames));
    let ad = [Label::LinkFrame.as_bytes(), &hs.sess_id].concat();
    let ad_other = [Label::LinkFrame.as_bytes(), &flip_id(&hs.sess_id)].concat();
    let c2r = |counter: u64, ad: &[u8], plaintext: &[u8]| seal(&hs.k_c2r, counter, ad, plaintext);
    let r2c = |counter: u64, plaintext: &[u8]| seal(&hs.k_r2c, counter, &ad, plaintext);
    assert_eq!(
        c2r(3, &ad, &padded(req9)),
        req9_frame,
        "link-0009's request frame"
    );
    assert_eq!(
        r2c(3, &padded(resp9)),
        resp9_frame,
        "link-0009's response frame"
    );
    let mut s84 = Stream::new(84);
    let data = s84.draw("data", CONT_DATA);
    // CONT {idx 1, data} with cmd_seq 3 (0x7F ‖ cmd_seq ‖ idx ‖ data, D.2)
    let orphan = [
        &[opcode::CONT][..],
        &3_u32.to_be_bytes(),
        &[1],
        data.as_slice(),
    ]
    .concat();
    // a PING plaintext with cmd_seq 4 and 0x00 for the 0x80 marker
    let bad_pad = [&[opcode::PING][..], &4_u32.to_be_bytes(), &[0; 4331]].concat();
    let unknown_op = [&[0x0a][..], &4_u32.to_be_bytes()].concat();
    let rows: [(u32, &str, &str, Vec<u8>); 12] = [
        (75, "R", "ctr-skip", c2r(4, &ad, &padded(req9))),
        (76, "R", "ctr-replay", first(&x8.req_frames).to_vec()),
        (
            77,
            "R",
            "tag-flip",
            flip(req9_frame, FRAME.checked_sub(1).unwrap()),
        ),
        (
            78,
            "R",
            "short",
            sl(req9_frame, ..FRAME.checked_sub(1).unwrap()).to_vec(),
        ),
        (79, "R", "long", [req9_frame, &[0]].concat()),
        (80, "R", "reflected", resp9_frame.to_vec()),
        (81, "R", "ad-other-link", c2r(3, &ad_other, &padded(req9))),
        (82, "C", "resp-ctr-skip", r2c(4, &padded(resp9))),
        (
            83,
            "C",
            "resp-tag-flip",
            flip(resp9_frame, FRAME.checked_sub(1).unwrap()),
        ),
        (84, "R", "cont-orphan", c2r(3, &ad, &padded(&orphan))),
        (85, "R", "pt-bad-pad", c2r(3, &ad, &bad_pad)),
        (86, "R", "pt-unknown-op", c2r(3, &ad, &padded(&unknown_op))),
    ];
    let mut s84 = Some(s84);
    rows.into_iter()
        .map(|(i, party, manipulation, frame)| {
            let mut b = at_case_8(hs, ex);
            let digest = b.relay.store_digest_kat();
            if party == "R" {
                let outcome = b
                    .exec
                    .on_unit(&b.relay, &frame, now(), &mut FixedEntropy::new(&[]));
                assert!(
                    matches!(outcome, Outcome::Teardown),
                    "{}: teardown",
                    case_id(i)
                );
            } else {
                let r = b.client.open_unit(&frame);
                assert!(
                    matches!(r, Err(link::Error::Rejected)),
                    "{}: rejected",
                    case_id(i)
                );
            }
            let post = b.post();
            assert_eq!(post, (3, 3, 3), "{}: unchanged", case_id(i));
            assert_eq!(
                b.relay.store_digest_kat(),
                digest,
                "{}: store unchanged",
                case_id(i)
            );
            let mut s = if i == 84 {
                s84.take().unwrap()
            } else {
                Stream::new(i)
            };
            s.list("frame", &frame);
            let mut o = Out::default();
            o.v("link_post", link_post(post));
            let mut rest = rejected(manipulation);
            rest.push(("outputs", o.done()));
            make_case(i, "frame-reject", party, Some(8), s.inputs, rest)
        })
        .collect()
}

/// The complete `link` file (the Rust side of `cargo xtask vectors`).
pub fn generate() -> Value {
    let (secrets, relay_fp, rec_relayinfo, relay_case) = relay_keys();
    let (hs, bench, handshake_cases) = handshake(secrets, relay_fp, &rec_relayinfo);
    let run = link_a(bench, &hs);
    let mut numbered = vec![relay_case];
    numbered.extend(handshake_cases);
    numbered.push(indist(&run.ex));
    numbered.extend(relayinfo_cases(&hs));
    let p6_frame = first(&run.ex.get(&6).unwrap().req_frames).to_vec();
    numbered.extend(hs1_cases(&hs, &p6_frame));
    numbered.extend(hs2_cases(&hs));
    numbered.extend(frame_cases(&hs, &run.ex));
    numbered.extend(run.cases);
    numbered.sort_by_key(|(i, _)| *i);
    let ids: Vec<u32> = numbered.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        ids,
        (1..=86).collect::<Vec<u32>>(),
        "86 cases, ids contiguous"
    );
    let cases: Vec<Value> = numbered.into_iter().map(|(_, c)| c).collect();
    let rejects = cases
        .iter()
        .filter(|c| c.get("expect").and_then(Value::as_str) == Some("reject"))
        .count();
    assert_eq!(rejects, 34, "34 cases carry expect: reject");
    json!({
        "schema": 6,
        "suite": SUITE,
        "spec": "SecMP/1 rev 2.3",
        "generator": "secmp-rust",
        "cases": cases,
    })
}
