// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared fixture of the relay tests: the `link` vector file, the relay of `link-0001`, the honest handshake of
//! `link-0003`/`link-0004` (link A), and a client that builds, signs and seals D.2 requests and opens the relay's
//! responses. The request builders are written from spec §9.2, §9.6 and D.6 with `secmp-crypto` primitives (the
//! signed messages and tokens are recomputed here, not taken from `secmp_proto::wire::signed`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use secmp_crypto::{
    Ed25519SigningKey, Label, MlKem1024Dk, SecretBytes, X25519Secret, hmac_sha256, sha256,
};
use secmp_proto::codec::unpad;
use secmp_proto::keys::{Ed25519Pk, Ed25519Sig};
use secmp_proto::link::cont::split_blob;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, Link};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    CellrContext, FetchEntry, LinkGetMode, Request, RequestCmd, Response,
};
use secmp_proto::{Decode, Encode};
use secmp_relay::event::NullSink;
use secmp_relay::{Executor, KeyRing, Limits, Now, Outcome, Relay};
use serde_json::Value;

/// `now` of the suite (`vectors/SCHEMA-4.11-link.md`, constants): bucket 472 222.
pub const NOW: u64 = 1_700_000_100;
/// `valid_until` of the relay of case 1.
pub const VALID_UNTIL: u64 = 1_702_592_000;
/// The `HELLO` record (D.1).
pub const HELLO: [u8; 9] = [0x00, 0x07, 0x01, 0x53, 0x45, 0x43, 0x4d, 0x50, 0x01];
/// Frame and plaintext sizes (spec §4.2).
pub const FRAME: usize = 4352;
pub const PLAIN: usize = 4336;

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

/// `bytes` with bit 0 of the byte at `at` flipped.
pub fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut v = bytes.to_vec();
    *v.get_mut(at).unwrap() ^= 1;
    v
}

/// The suite time at `mono_ms` on the monotonic clock.
pub const fn now() -> Now {
    Now {
        unix_secs: NOW,
        mono_ms: 0,
    }
}

/// The suite's wall clock shifted by `hours` and the monotonic clock at `mono_ms`.
pub fn at(hours: u64, mono_ms: u64) -> Now {
    Now {
        unix_secs: NOW.checked_add(hours.checked_mul(3600).unwrap()).unwrap(),
        mono_ms,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The vector file.

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
    pub raw: Value,
    pub inputs: BTreeMap<String, Value>,
    pub outputs: BTreeMap<String, Value>,
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
            id: v.get("id").unwrap().as_str().unwrap().to_owned(),
            raw: v.clone(),
            inputs: map("inputs"),
            outputs: map("outputs"),
        }
    }

    pub fn op(&self) -> &str {
        self.raw.get("op").and_then(Value::as_str).unwrap()
    }

    pub fn input(&self, name: &str) -> Vec<u8> {
        let v = self.inputs.get(name);
        assert!(v.is_some(), "{}: no input {name}", self.id);
        unhex(v.unwrap().as_str().unwrap())
    }

    pub fn has_input(&self, name: &str) -> bool {
        self.inputs.contains_key(name)
    }

    pub fn output(&self, name: &str) -> Vec<u8> {
        let v = self.outputs.get(name);
        assert!(v.is_some(), "{}: no output {name}", self.id);
        unhex(v.unwrap().as_str().unwrap())
    }

    pub fn has_output(&self, name: &str) -> bool {
        self.outputs.contains_key(name)
    }

    /// An array of byte strings in `outputs`.
    pub fn output_list(&self, name: &str) -> Vec<Vec<u8>> {
        assert!(
            self.outputs.contains_key(name),
            "{}: no output list {name}",
            self.id
        );
        self.outputs
            .get(name)
            .and_then(Value::as_array)
            .expect("an output list")
            .iter()
            .map(|v| unhex(v.as_str().unwrap()))
            .collect()
    }

    pub fn cmd_seq(&self) -> u32 {
        u32::try_from(self.raw.get("cmd_seq").and_then(Value::as_u64).unwrap()).unwrap()
    }

    pub fn manipulation(&self) -> &str {
        self.raw
            .get("manipulation")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    pub fn party(&self) -> &str {
        self.raw.get("party").and_then(Value::as_str).unwrap()
    }

    /// `link_post` as (`c2r`, `r2c`, `cmd_seq`).
    pub fn link_post(&self) -> (u64, u64, u32) {
        let lp = self.outputs.get("link_post").unwrap();
        let n = |k: &str| lp.get(k).and_then(Value::as_u64).unwrap();
        (n("c2r"), n("r2c"), u32::try_from(n("cmd_seq")).unwrap())
    }
}

/// The parsed file.
pub struct Ref {
    pub header: Value,
    pub cases: Vec<Case>,
}

impl Ref {
    /// The case `link-00nn`.
    pub fn case(&self, n: usize) -> &Case {
        let c = self.cases.get(n.checked_sub(1).unwrap()).unwrap();
        assert_eq!(c.id, format!("link-{n:04}"));
        c
    }
}

pub fn reference() -> &'static Ref {
    static REF: OnceLock<Ref> = OnceLock::new();
    REF.get_or_init(|| {
        let v = link_file();
        let cases = v
            .get("cases")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(Case::new)
            .collect();
        Ref { header: v, cases }
    })
}

// ---------------------------------------------------------------------------------------------------------------
// The relay of case 1 and link A.

/// The relay secrets of `link-0001`.
pub struct RelayFx {
    pub sig_seed: Vec<u8>,
    pub dh_sk: Vec<u8>,
    pub kem_seed: Vec<u8>,
    pub access_key: Vec<u8>,
    pub relay_fp: [u8; 32],
}

impl RelayFx {
    pub fn case1() -> Self {
        let c = reference().case(1);
        Self {
            sig_seed: c.input("relay_sig_seed"),
            dh_sk: c.input("relay_dh_sk"),
            kem_seed: c.input("relay_kem_seed"),
            access_key: c.input("relay_access_key"),
            relay_fp: c.output("relay_fp").try_into().unwrap(),
        }
    }

    pub fn access(&self) -> AccessKey {
        SecretBytes::from_slice(&self.access_key).unwrap()
    }

    pub fn keys(&self, kid: u32) -> RelayKeys {
        RelayKeys::new(
            Ed25519SigningKey::from_seed(&self.sig_seed).unwrap(),
            X25519Secret::from_bytes(&self.dh_sk).unwrap(),
            MlKem1024Dk::from_seed(&self.kem_seed).unwrap(),
            self.access(),
            kid,
        )
        .unwrap()
    }

    /// The relay of the suite: kid 1, valid until [`VALID_UNTIL`], `limits`.
    pub fn relay(&self, limits: Limits) -> Relay {
        let ring = KeyRing::new(vec![(self.keys(1), VALID_UNTIL)]).unwrap();
        Relay::new(ring, limits, Box::new(NullSink), now())
    }
}

/// The draws of `link-0003` (client) and `link-0004` (relay).
pub fn client_entropy() -> FixedEntropy {
    let c = reference().case(3);
    FixedEntropy::new(
        &[
            c.input("e_c_sk"),
            c.input("ek_c_seed"),
            c.input("sk_e1"),
            c.input("m1"),
        ]
        .concat(),
    )
}

pub fn relay_hs_entropy() -> FixedEntropy {
    let c = reference().case(4);
    FixedEntropy::new(&[c.input("sk_er"), c.input("m2")].concat())
}

/// The honest handshake of the suite against `relay`: the client's end of link A and the relay's executor.
pub fn link_a(relay: &Relay, fx: &RelayFx) -> (Link, Executor) {
    let access = fx.access();
    let (hello, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    let (info, st_r) = link::relay::accept_ring(relay.keys().ring())
        .on_hello(&hello, VALID_UNTIL)
        .unwrap();
    let (hs1, wait) = st.on_relayinfo(&info, &mut client_entropy()).unwrap();
    let (hs2, relay_link) = st_r.on_hs1(&hs1, &mut relay_hs_entropy()).unwrap();
    let client = wait.on_hs2(&hs2).unwrap();
    (
        client,
        Executor::new(relay_link, relay.limits().link_rate, now()),
    )
}

/// A relay, its link A and a client on it: the common start of the executor tests.
pub struct Bench {
    pub fx: RelayFx,
    pub relay: Relay,
    pub client: Client,
    pub exec: Executor,
}

impl Bench {
    pub fn new(limits: Limits) -> Self {
        let fx = RelayFx::case1();
        let relay = fx.relay(limits);
        let (link, exec) = link_a(&relay, &fx);
        let client = Client::new(link, fx.access());
        Self {
            fx,
            relay,
            client,
            exec,
        }
    }

    /// The vector configuration (budget of two queues, no rate limits).
    pub fn vectors() -> Self {
        Self::new(Limits::vectors())
    }

    /// Feed one unit to the executor.
    pub fn unit(&mut self, unit: &[u8], t: Now, entropy: &mut FixedEntropy) -> Outcome {
        self.exec.on_unit(&self.relay, unit, t, entropy)
    }

    /// Seal `req` with the client, run it, and open every response frame (context from the request).
    pub fn run(&mut self, req: &Request, t: Now, entropy: &mut FixedEntropy) -> Answer {
        let frame = self.client.seal(req);
        let context = context_of(&req.cmd);
        match self.unit(&frame, t, entropy) {
            Outcome::Respond(frames) => Answer::Frames(
                frames
                    .iter()
                    .map(|f| self.client.open(f.as_slice(), context))
                    .collect(),
            ),
            Outcome::Pending => Answer::Pending,
            Outcome::Teardown => Answer::Teardown,
        }
    }

    /// Run `req` with plenty of OS-independent random draws available.
    pub fn go(&mut self, req: &Request) -> Answer {
        self.run(req, now(), &mut lots())
    }

    /// `QueueStore` ‖ `LinkDataStore` ‖ budget digest (TEST-SPEC "store unchanged").
    pub fn digest(&self) -> [u8; 32] {
        self.relay.store_digest_kat()
    }

    /// (`c2r`, `r2c`, `cmd_seq`) on the relay's side.
    pub fn link_post(&self) -> (u64, u64, u32) {
        let l = self.exec.link();
        (
            l.recv_counter().unwrap(),
            l.send_counter().unwrap(),
            self.exec.last_cmd_seq(),
        )
    }
}

/// Entropy with `n` × 12360 recognisable bytes: enough for any response (the draws of the relay are dummies).
pub fn lots() -> FixedEntropy {
    let bytes: Vec<u8> = (0..400_000_u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    FixedEntropy::new(&bytes)
}

/// What a request produced.
pub enum Answer {
    Frames(Vec<Response>),
    Pending,
    Teardown,
}

impl Answer {
    pub fn frames(self) -> Vec<Response> {
        match self {
            Self::Frames(f) => Some(f),
            Self::Pending | Self::Teardown => None,
        }
        .expect("response frames, not pending or a teardown")
    }

    pub const fn is_teardown(&self) -> bool {
        matches!(self, Self::Teardown)
    }

    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

pub const fn context_of(cmd: &RequestCmd) -> CellrContext {
    match cmd {
        RequestCmd::FetchMulti { .. } => CellrContext::FetchMulti,
        _ => CellrContext::Fetch,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The client side: keys, signed messages (D.6), tokens (§9.6), requests (D.2).

/// An Ed25519 key from a seed.
pub struct Key {
    pub sk: Ed25519SigningKey,
    pub pk: Ed25519Pk,
}

impl Key {
    pub fn from_seed(seed: &[u8]) -> Self {
        let sk = Ed25519SigningKey::from_seed(seed).unwrap();
        let pk = Ed25519Pk::from_bytes(sk.verifying_key().as_bytes()).unwrap();
        Self { sk, pk }
    }

    /// A key from a one-byte pattern (tests).
    pub fn of(b: u8) -> Self {
        Self::from_seed(&[b; 32])
    }

    pub fn sign(&self, msg: &[u8]) -> Ed25519Sig {
        Ed25519Sig::from_bytes(&self.sk.sign(msg)).unwrap()
    }
}

/// `"SecMP-Q/1 " ‖ CMD_LABEL ‖ sess_id ‖ u32be(cmd_seq) ‖ fields` (D.6).
pub fn signed_msg(label: Label, sess_id: &Id, cmd_seq: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut m = [label.as_bytes(), sess_id, &cmd_seq.to_be_bytes()].concat();
    for f in fields {
        m.extend_from_slice(f);
    }
    m
}

/// `HMAC-SHA-256(access_key, "SecMP-Q/1 token" ‖ sess_id ‖ u32be(cmd_seq))` (spec §9.6).
pub fn token(access: &[u8], sess_id: &Id, cmd_seq: u32) -> [u8; 32] {
    hmac_sha256(access, Label::QToken, &[sess_id, &cmd_seq.to_be_bytes()]).unwrap()
}

/// `rid = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16]` (spec §9.1).
pub fn rid_of(recv: &Ed25519Pk) -> Id {
    sha256(&[Label::QRid.as_bytes(), recv.as_bytes()])
        .first_chunk::<16>()
        .copied()
        .unwrap()
}

/// `sid = SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]` (spec §9.1).
pub fn sid_of(recv: &Ed25519Pk, send: &Ed25519Pk) -> Id {
    sha256(&[Label::QSid.as_bytes(), recv.as_bytes(), send.as_bytes()])
        .first_chunk::<16>()
        .copied()
        .unwrap()
}

/// The client of link A.
pub struct Client {
    pub link: Link,
    pub access: AccessKey,
}

impl Client {
    pub const fn new(link: Link, access: AccessKey) -> Self {
        Self { link, access }
    }

    pub fn sess_id(&self) -> Id {
        *self.link.sess_id()
    }

    /// Seal a request (padded by the frame layer).
    pub fn seal(&mut self, req: &Request) -> Vec<u8> {
        let padded = req.encode().unwrap();
        self.seal_payload(unpad(&padded, PLAIN).unwrap())
    }

    /// Seal raw payload bytes `op ‖ cmd_seq ‖ fields` (the frame layer pads them).
    pub fn seal_payload(&mut self, payload: &[u8]) -> Vec<u8> {
        self.link.seal(payload).unwrap().to_vec()
    }

    /// Open and decode one response frame.
    pub fn open(&mut self, frame: &[u8], context: CellrContext) -> Response {
        self.link.open_response(frame, context).unwrap()
    }

    pub fn token(&self, cmd_seq: u32) -> [u8; 32] {
        token(self.access.expose_secret(), &self.sess_id(), cmd_seq)
    }

    pub fn queue_new(&self, cmd_seq: u32, recv: &Key, send: &Key) -> Request {
        let token = self.token(cmd_seq);
        let msg = signed_msg(
            Label::QQueueNew,
            &self.sess_id(),
            cmd_seq,
            &[recv.pk.as_bytes(), send.pk.as_bytes(), &token],
        );
        Request {
            cmd_seq,
            cmd: RequestCmd::QueueNew {
                recv_pk: recv.pk,
                send_pk: send.pk,
                token,
                sig: recv.sign(&msg),
            },
        }
    }

    pub fn send(&self, cmd_seq: u32, recv: &Key, send: &Key, cell: &[u8]) -> Request {
        let sid = sid_of(&recv.pk, &send.pk);
        let msg = signed_msg(Label::QSend, &self.sess_id(), cmd_seq, &[&sid, cell]);
        Request {
            cmd_seq,
            cmd: RequestCmd::Send {
                sid,
                cell: Cell::from_bytes(cell).unwrap(),
                sig: send.sign(&msg),
            },
        }
    }

    pub fn fetch(&self, cmd_seq: u32, recv: &Key, ack: u64) -> Request {
        let rid = rid_of(&recv.pk);
        let msg = signed_msg(
            Label::QFetch,
            &self.sess_id(),
            cmd_seq,
            &[&rid, &ack.to_be_bytes()],
        );
        Request {
            cmd_seq,
            cmd: RequestCmd::Fetch {
                rid,
                ack,
                sig: recv.sign(&msg),
            },
        }
    }

    pub fn fetch_entry(&self, cmd_seq: u32, recv: &Key, ack: u64) -> FetchEntry {
        let rid = rid_of(&recv.pk);
        let msg = signed_msg(
            Label::QMfetch,
            &self.sess_id(),
            cmd_seq,
            &[&rid, &ack.to_be_bytes()],
        );
        FetchEntry {
            rid,
            ack,
            sig: recv.sign(&msg),
        }
    }

    pub const fn fetch_multi(cmd_seq: u32, entries: Vec<FetchEntry>) -> Request {
        Request {
            cmd_seq,
            cmd: RequestCmd::FetchMulti { entries },
        }
    }

    pub fn queue_del(&self, cmd_seq: u32, recv: &Key) -> Request {
        let rid = rid_of(&recv.pk);
        let msg = signed_msg(Label::QQueueDel, &self.sess_id(), cmd_seq, &[&rid]);
        Request {
            cmd_seq,
            cmd: RequestCmd::QueueDel {
                rid,
                sig: recv.sign(&msg),
            },
        }
    }

    /// The three frames of a `LINK_PUT` (frame 1 with the head fields and `blob[0..4160]`, then two CONT).
    pub fn link_put(&self, cmd_seq: u32, p: &Put<'_>) -> [Request; 3] {
        let token = self.token(cmd_seq);
        let hash = sha256(&[p.blob]);
        let msg = signed_msg(
            Label::QLinkPut,
            &self.sess_id(),
            cmd_seq,
            &[
                p.ld_id,
                &[u8::from(p.one_time)],
                &p.expires_bucket.to_be_bytes(),
                p.owner.pk.as_bytes(),
                &token,
                &hash,
            ],
        );
        let (blob_part, one, two) = split_blob(p.blob).unwrap();
        [
            Request {
                cmd_seq,
                cmd: RequestCmd::LinkPut {
                    ld_id: *p.ld_id,
                    one_time: p.one_time,
                    expires_bucket: p.expires_bucket,
                    owner_pk: p.owner.pk,
                    token,
                    sig: p.owner.sign(&msg),
                    blob_part,
                },
            },
            Request {
                cmd_seq,
                cmd: RequestCmd::Cont(one),
            },
            Request {
                cmd_seq,
                cmd: RequestCmd::Cont(two),
            },
        ]
    }

    pub const fn link_get_consume(cmd_seq: u32, ld_id: &Id) -> Request {
        Request {
            cmd_seq,
            cmd: RequestCmd::LinkGet {
                ld_id: *ld_id,
                mode: LinkGetMode::Consume,
            },
        }
    }

    pub fn link_get_owner(&self, cmd_seq: u32, ld_id: &Id, owner: &Key) -> Request {
        let msg = signed_msg(Label::QLinkGet, &self.sess_id(), cmd_seq, &[ld_id, &[1]]);
        Request {
            cmd_seq,
            cmd: RequestCmd::LinkGet {
                ld_id: *ld_id,
                mode: LinkGetMode::OwnerStatus(owner.sign(&msg)),
            },
        }
    }

    pub const fn ping(cmd_seq: u32) -> Request {
        Request {
            cmd_seq,
            cmd: RequestCmd::Ping,
        }
    }
}

/// The fields of a `LINK_PUT`.
pub struct Put<'a> {
    pub ld_id: &'a Id,
    pub one_time: bool,
    pub expires_bucket: u32,
    pub owner: &'a Key,
    pub blob: &'a [u8],
}

/// The suite's `expires_bucket` (472 222 + 168).
pub const EXPIRES: u32 = 472_390;

/// Decode a response payload (unpadded `op ‖ cmd_seq ‖ fields`) in `context`.
pub fn decode_response(payload: &[u8], context: CellrContext) -> Response {
    Response::decode(&secmp_proto::codec::pad(payload, PLAIN).unwrap(), context).unwrap()
}

/// Encode a response to its unpadded payload.
pub fn payload_of(resp: &Response) -> Vec<u8> {
    unpad(&resp.encode().unwrap(), PLAIN).unwrap().to_vec()
}

/// Decode a request payload.
pub fn decode_request(payload: &[u8]) -> Request {
    Request::decode(&secmp_proto::codec::pad(payload, PLAIN).unwrap()).unwrap()
}
