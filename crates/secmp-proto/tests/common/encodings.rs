// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The `encodings` vectors of `vectors/SCHEMA.md` §4.8 (`SCHEMA-4.8-encodings.md`), written from the schema and
//! spec App. D alone:
//!
//! - [`generate`]: the positive rows 1–85. Every row draws from its own SCHEMA §2 stream
//!   ([`secmp_crypto::VectorStream`]) in the order of the table "Stream order per structure", builds the typed
//!   value (keys derived from stream seeds with the M1 primitives, signatures computed), and lists `value` (the
//!   structure's fields, SCHEMA §1 `"schema": 3`) and `bytes` (this crate's encoding).
//! - [`decode`]: the decoder of a structure name, with the decoded value in the same representation, so a test can
//!   check `decode(bytes) = value` as well as `encode(decode(bytes)) = bytes`.
//!
//! The negative rows 86–632 are the reference file's; M2 cross-generates the positives (docs/07 M2 deliverables)
//! and every negative must be rejected by the decoders (`tests/encodings_ref.rs`).
//!
//! Shared by the `gen-encodings` example (which writes `vectors/rust/encodings.json`), the `vectors` test (which
//! re-checks the frozen file on every target) and the `encodings_ref` test.

use std::num::NonZeroU16;

use serde_json::{Map, Value, json};

use secmp_crypto::{
    Ed25519SigningKey, Fingerprint, HybridSigningKey, Label, SecretBytes, VectorStream,
    X25519Secret,
};
use secmp_proto::keys::{Ed25519Pk, Ed25519Sig, HybridSig, MlKem768Ek, MlKem1024Ek, X25519Pk};
use secmp_proto::sizes::{BLOB_PART_LEN, CELL_LEN, CONT_DATA_LEN, MLDSA65_PK_LEN};
use secmp_proto::wire::cell::{
    AppKind, AppMessage, BatchBody, Cell, Content, ContentBody, ControlBody, ControlCode, Fragment,
    FragmentPayload, HandshakeBody, HeaderV1, KeyChangeBody, ReceiptBody, ReceiptKind, RelayQueue,
    RouteDescriptor, RouteUpdateBody,
};
use secmp_proto::wire::frame::{
    Cellr, CellrContext, CellrError, Cont, ContIdx, ErrCode, FetchEntry, LinkGetMode, Request,
    RequestCmd, Response, ResponseCmd, opcode,
};
use secmp_proto::wire::hx::{HandshakeCell, HandshakeCellPlaintext, Inner, InnerCt, Outer};
use secmp_proto::wire::inv::{
    Direct, Host, IksPublic, InvitationV1, LinkBlob, LinkDataV1, Onion, PrekeyBundle, Profile,
    RelayRef,
};
use secmp_proto::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord, RelayInfoV1};
use secmp_proto::wire::signed::{self, LinkPutFields};
use secmp_proto::wire::{Id, Period};
use secmp_proto::{Decode, Encode, Error};

/// The suite name (SCHEMA §3).
pub const SUITE: &str = "encodings";
/// The positive rows of the case table.
pub const POSITIVES: u32 = 85;

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn h(b: &[u8]) -> Value {
    Value::String(hex(b))
}

/// Canonical serialisation (SCHEMA §1): keys sorted at every level, compact, ASCII only, no trailing newline.
pub fn canonical(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap();
    assert!(s.is_ascii(), "vector files are ASCII");
    s
}

/// The file header and the positive rows (the Rust side of `cargo xtask vectors`).
pub fn generate() -> Value {
    let cases: Vec<Value> = (1..=POSITIVES).map(positive).collect();
    json!({
        "schema": 3,
        "suite": SUITE,
        "spec": "SecMP/1 rev 2.3",
        "generator": "secmp-rust",
        "cases": cases,
    })
}

// ---- the value representation (SCHEMA §1, SCHEMA-4.8 "Value representation") ----------------------------

fn obj(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn name_of(table: &[(u8, &'static str)], op: u8) -> &'static str {
    table
        .iter()
        .find(|(o, _)| *o == op)
        .map_or("?", |(_, n)| *n)
}

fn encoded<T: Encode>(x: &T) -> Vec<u8> {
    x.encode().unwrap()
}

/// `len` and `type` of a record: the body length after the 2-byte `len`, and the byte after it.
fn record_head(bytes: &[u8]) -> (usize, u8) {
    (bytes.len().saturating_sub(2), *bytes.get(2).unwrap())
}

fn hello_json(x: Hello) -> Value {
    let b = encoded(&x);
    let (len, ty) = record_head(&b);
    json!({"len": len, "type": ty, "magic": h(b.get(3..8).unwrap()), "ver": b.get(8).unwrap()})
}

fn relay_info_json(x: &RelayInfoV1) -> Value {
    json!({
        "ver": 1,
        "relay_sig_pk": h(x.relay_sig_pk.as_bytes()),
        "kid": x.kid,
        "relay_dh_pk": h(x.relay_dh_pk.as_bytes()),
        "relay_kem_ek": h(x.relay_kem_ek.as_bytes()),
        "akc": h(&x.akc),
        "valid_until": x.valid_until,
        "sig": h(x.sig.as_bytes()),
    })
}

fn relay_info_record_json(x: &RelayInfoRecord) -> Value {
    let (len, ty) = record_head(&encoded(x));
    json!({"len": len, "type": ty, "relay_info": relay_info_json(&x.relay_info)})
}

fn hs1_json(x: &Hs1) -> Value {
    let (len, ty) = record_head(&encoded(x));
    json!({
        "len": len, "type": ty, "ver": 1, "kid": x.kid, "e_c": h(x.e_c.as_bytes()),
        "ek_c": h(x.ek_c.as_bytes()), "pk_e1": h(x.pk_e1.as_bytes()), "ct_kem": h(&*x.ct_kem),
        "mac1": h(&x.mac1),
    })
}

fn hs2_json(x: &Hs2) -> Value {
    let (len, ty) = record_head(&encoded(x));
    json!({
        "len": len, "type": ty, "ver": 1, "e_r": h(x.e_r.as_bytes()), "ct_c": h(&*x.ct_c),
        "mac2": h(&x.mac2),
    })
}

fn cont_json(c: &Cont) -> Map<String, Value> {
    let idx = match c.idx {
        ContIdx::One => 1,
        ContIdx::Two => 2,
    };
    obj(vec![("idx", json!(idx)), ("data", h(&*c.data))])
}

fn request_json(r: &Request) -> Value {
    let mut m = match &r.cmd {
        RequestCmd::QueueNew {
            recv_pk,
            send_pk,
            token,
            sig,
        } => obj(vec![
            ("recv_pk", h(recv_pk.as_bytes())),
            ("send_pk", h(send_pk.as_bytes())),
            ("token", h(token)),
            ("sig", h(sig.as_bytes())),
        ]),
        RequestCmd::Send { sid, cell, sig } => obj(vec![
            ("sid", h(sid)),
            ("cell", h(cell.as_bytes())),
            ("sig", h(sig.as_bytes())),
        ]),
        RequestCmd::Fetch { rid, ack, sig } => obj(vec![
            ("rid", h(rid)),
            ("ack", json!(ack)),
            ("sig", h(sig.as_bytes())),
        ]),
        RequestCmd::FetchMulti { entries } => {
            let list: Vec<Value> = entries
                .iter()
                .map(|e| json!({"rid": h(&e.rid), "ack": e.ack, "sig": h(e.sig.as_bytes())}))
                .collect();
            obj(vec![
                ("count", json!(entries.len())),
                ("entries", Value::Array(list)),
            ])
        }
        RequestCmd::QueueDel { rid, sig } => obj(vec![("rid", h(rid)), ("sig", h(sig.as_bytes()))]),
        RequestCmd::LinkPut {
            ld_id,
            one_time,
            expires_bucket,
            owner_pk,
            token,
            sig,
            blob_part,
        } => obj(vec![
            ("ld_id", h(ld_id)),
            ("one_time", json!(u8::from(*one_time))),
            ("expires_bucket", json!(expires_bucket)),
            ("owner_pk", h(owner_pk.as_bytes())),
            ("token", h(token)),
            ("sig", h(sig.as_bytes())),
            ("blob_part", h(&**blob_part)),
        ]),
        RequestCmd::LinkGet { ld_id, mode } => {
            let (mode, sig) = match mode {
                LinkGetMode::Consume => ("consume", [0; 64]),
                LinkGetMode::OwnerStatus(sig) => ("owner-status", *sig.as_bytes()),
            };
            obj(vec![
                ("ld_id", h(ld_id)),
                ("mode", json!(mode)),
                ("sig", h(&sig)),
            ])
        }
        RequestCmd::Ping => Map::new(),
        RequestCmd::Cont(c) => cont_json(c),
    };
    m.insert(
        "op".to_owned(),
        json!(name_of(&opcode::REQUESTS, r.cmd.op())),
    );
    m.insert("cmd_seq".to_owned(), json!(r.cmd_seq));
    Value::Object(m)
}

fn response_json(r: &Response) -> Value {
    let mut m = match &r.cmd {
        ResponseCmd::Ok => Map::new(),
        ResponseCmd::OkQueueNew { rid, sid } => obj(vec![("rid", h(rid)), ("sid", h(sid))]),
        ResponseCmd::OkSend { cell_id, evicted } => obj(vec![
            ("cell_id", json!(cell_id)),
            ("evicted_present", json!(u8::from(evicted.is_some()))),
            ("evicted_id", json!(evicted.unwrap_or(0))),
        ]),
        ResponseCmd::Cellr(c) => {
            let (present, rid, cell_id, cell) = match c {
                Cellr::Dummy { cell } => (0_u8, [0; 16], 0, cell),
                Cellr::Cell { rid, cell_id, cell } => (1, *rid, *cell_id, cell),
                Cellr::Error { error, rid, cell } => {
                    let present = match error {
                        CellrError::NoQueue => 2,
                        CellrError::Auth => 3,
                        CellrError::Malformed => 4,
                    };
                    (present, *rid, 0, cell)
                }
            };
            obj(vec![
                ("present", json!(present)),
                ("rid", h(&rid)),
                ("cell_id", json!(cell_id)),
                ("cell", h(cell.as_bytes())),
            ])
        }
        ResponseCmd::LinkR {
            present,
            consumed,
            blob_part,
        } => obj(vec![
            ("present", json!(u8::from(*present))),
            ("consumed", json!(u8::from(*consumed))),
            ("blob_part", h(&**blob_part)),
        ]),
        ResponseCmd::Err(code) => obj(vec![("code", json!(code.byte()))]),
        ResponseCmd::Cont(c) => cont_json(c),
    };
    m.insert(
        "op".to_owned(),
        json!(name_of(&opcode::RESPONSES, r.cmd.op())),
    );
    m.insert("cmd_seq".to_owned(), json!(r.cmd_seq));
    Value::Object(m)
}

fn relay_ref_json(r: &RelayRef) -> Value {
    let mut m = obj(vec![
        ("ver", json!(1)),
        ("relay_fp", h(&r.relay_fp)),
        ("onion", h(r.onion.as_bytes())),
        ("akc", h(&r.akc)),
        ("direct_present", json!(u8::from(r.direct.is_some()))),
    ]);
    if let Some(d) = &r.direct {
        m.insert("host_len".to_owned(), json!(d.host.as_bytes().len()));
        m.insert("host".to_owned(), h(d.host.as_bytes()));
        m.insert("port".to_owned(), json!(d.port.get()));
        m.insert("spki_sha256".to_owned(), h(&d.spki_sha256));
    }
    Value::Object(m)
}

fn invitation_json(x: &InvitationV1) -> Value {
    json!({
        "ver": 1,
        "kind": 1,
        "relay": relay_ref_json(&x.relay),
        "ld_id": h(&x.ld_id),
        "link_key": h(x.link_key.expose_secret()),
        "inviter_fp": h(&x.inviter_fp),
        "inv_sid": h(&x.inv_sid),
        "inv_send_seed": h(x.inv_send_seed.expose_secret()),
        "inv_period_s": x.inv_period_s.seconds(),
        "expires": x.expires,
    })
}

fn profile_json(p: &Profile) -> Value {
    let name = p.name().as_bytes();
    let mut m = obj(vec![
        ("name_len", json!(name.len())),
        ("name", h(name)),
        ("avatar_present", json!(u8::from(p.avatar_sha256.is_some()))),
    ]);
    if let Some(a) = &p.avatar_sha256 {
        m.insert("avatar_sha256".to_owned(), h(a));
    }
    Value::Object(m)
}

fn iks_json(x: &IksPublic) -> Value {
    json!({
        "ver": 1,
        "ik_ed25519": h(x.ik_ed25519.as_bytes()),
        "ik_mldsa65": h(&*x.ik_mldsa65),
        "ik_dh": h(x.ik_dh.as_bytes()),
    })
}

fn bundle_json(x: &PrekeyBundle) -> Value {
    json!({
        "ver": 1,
        "spk_id": x.spk_id,
        "spk_dh": h(x.spk_dh.as_bytes()),
        "spk_kem": h(x.spk_kem.as_bytes()),
        "rpk_kem": h(x.rpk_kem.as_bytes()),
        "spk_expiry": x.spk_expiry,
        "opk_present": 1,
        "opk_id": x.opk_id,
        "opk_dh": h(x.opk_dh.as_bytes()),
        "opk_kem": h(x.opk_kem.as_bytes()),
        "sig": h(x.sig.as_bytes()),
    })
}

fn link_data_json(x: &LinkDataV1) -> Value {
    json!({
        "ver": 1,
        "inviter_iks": iks_json(&x.inviter_iks),
        "bundle": bundle_json(&x.bundle),
        "profile": profile_json(&x.profile),
        "created": x.created,
    })
}

fn link_blob_json(x: &LinkBlob) -> Value {
    json!({"N": h(&x.n), "COM": h(&x.com), "ct": h(&*x.ct)})
}

fn inner_ct_json(x: &InnerCt) -> Value {
    json!({"N2": h(&x.n2), "COM": h(&x.com), "ct": h(&*x.ct)})
}

fn outer_json(x: &Outer) -> Value {
    json!({
        "ver": 1,
        "ek_I": h(x.ek_i.as_bytes()),
        "spk_id": x.spk_id,
        "opk_id": x.opk_id,
        "ct_spk": h(&*x.ct_spk),
        "ct_opk": h(&*x.ct_opk),
        "inner_ct": h(&encoded(&x.inner_ct)),
    })
}

fn inner_json(x: &Inner) -> Value {
    json!({"iks": iks_json(&x.iks), "first_msg": h(x.first_msg.as_bytes())})
}

fn handshake_cell_json(x: &HandshakeCell) -> Value {
    json!({"N_i": h(&x.n), "COM": h(&x.com), "ct": h(&*x.ct)})
}

fn handshake_pt_json(x: &HandshakeCellPlaintext) -> Value {
    json!({"init_id": h(&x.init_id), "i": x.i, "total": 3, "chunk": h(&*x.chunk)})
}

fn cell_json(x: &Cell) -> Value {
    let p = x.parts().unwrap();
    json!({"hdr_nonce": h(p.hdr_nonce), "hdr_ct": h(p.hdr_ct), "body_ct": h(p.body_ct), "tag": h(p.tag)})
}

fn header_json(x: &HeaderV1) -> Value {
    json!({
        "ver": 1,
        "flags": 0,
        "dh_pk": h(x.dh_pk.as_bytes()),
        "pn": x.pn,
        "n": x.n,
        "ek_pq": h(x.ek_pq.as_bytes()),
        "ct_pq": h(&*x.ct_pq),
    })
}

fn app_message_json(x: &AppMessage) -> Value {
    json!({
        "msg_id": h(&x.msg_id),
        "kind": x.kind.byte(),
        "expire_after": x.expire_after,
        "payload_len": x.payload.len(),
        "payload": h(&x.payload),
    })
}

fn batch_json(x: &BatchBody) -> Value {
    let list: Vec<Value> = x.messages.iter().map(app_message_json).collect();
    json!({"count": x.messages.len(), "messages": list})
}

fn fragment_json(x: &Fragment) -> Value {
    json!({"msg_id": h(&x.msg_id), "idx": x.idx, "total": x.total, "chunk": h(&x.chunk)})
}

fn relay_queue_json(x: &RelayQueue) -> Value {
    json!({
        "relay": relay_ref_json(&x.relay),
        "sid": h(&x.sid),
        "send_seed": h(x.send_seed.expose_secret()),
        "period_s": x.period_s.seconds(),
    })
}

fn route_json(x: &RouteDescriptor) -> Value {
    let (kind, blob, len) = match x {
        RouteDescriptor::RelayQueue(q) => (1, relay_queue_json(q), encoded(q).len()),
        RouteDescriptor::Unknown { kind, blob } => (*kind, h(blob), blob.len()),
    };
    json!({"ver": 1, "kind": kind, "len": len, "blob": blob})
}

fn routes_json(routes: &[RouteDescriptor]) -> Value {
    Value::Array(routes.iter().map(route_json).collect())
}

fn route_update_json(x: &RouteUpdateBody) -> Value {
    json!({"count": x.routes.len(), "routes": routes_json(&x.routes)})
}

fn handshake_body_json(x: &HandshakeBody) -> Value {
    json!({
        "profile": profile_json(&x.profile),
        "caps": 0,
        "route_count": x.routes.len(),
        "routes": routes_json(&x.routes),
    })
}

fn key_change_json(x: &KeyChangeBody) -> Value {
    json!({"iks": iks_json(&x.iks), "sig": h(x.sig.as_bytes())})
}

fn receipt_json(x: &ReceiptBody) -> Value {
    let kind = match x.kind {
        ReceiptKind::Delivered => 1,
        ReceiptKind::Read => 2,
    };
    let ids: Vec<Value> = x.msg_ids.iter().map(|m| h(m)).collect();
    json!({"kind": kind, "count": x.msg_ids.len(), "msg_ids": ids})
}

fn control_json(x: &ControlBody) -> Value {
    let code = match x.code {
        ControlCode::ContactRemoved => 1,
        ControlCode::SessionResetRequest => 2,
    };
    json!({"code": code, "arg_len": x.arg.len(), "arg": h(&x.arg)})
}

/// A Content body's value and encoded length (`""` and 0 for a Dummy).
fn content_body_json(x: &ContentBody) -> (Value, usize) {
    match x {
        ContentBody::Dummy => (json!(""), 0),
        ContentBody::Handshake(b) => (handshake_body_json(b), encoded(b).len()),
        ContentBody::Batch(b) => (batch_json(b), encoded(b).len()),
        ContentBody::Fragment(b) => (fragment_json(b), encoded(b).len()),
        ContentBody::RouteUpdate(b) => (route_update_json(b), encoded(b).len()),
        ContentBody::Receipt(b) => (receipt_json(b), encoded(b).len()),
        ContentBody::Control(b) => (control_json(b), encoded(b).len()),
    }
}

fn content_json(x: &Content) -> Value {
    let (body, len) = content_body_json(&x.body);
    json!({
        "ver": 1,
        "seq": x.seq,
        "ts": x.ts,
        "type": x.body.content_type(),
        "body_len": len,
        "body": body,
    })
}

fn fragment_payload_json(x: &FragmentPayload) -> Value {
    let (ty, body) = match x {
        FragmentPayload::Batch(b) => (0x02, batch_json(b)),
        FragmentPayload::RouteUpdate(b) => (0x04, route_update_json(b)),
        FragmentPayload::KeyChange(b) => (0x05, key_change_json(b)),
        FragmentPayload::Receipt(b) => (0x06, receipt_json(b)),
        FragmentPayload::Control(b) => (0x07, control_json(b)),
    };
    json!({"inner_type": ty, "inner_body": body})
}

// ---- decoding by structure name --------------------------------------------------------------------------

/// A successful decode: the value and the re-encoding.
pub struct Decoded {
    /// The decoded value in the representation of SCHEMA §1.
    pub value: Value,
    /// `encode(decode(bytes))`.
    pub again: Result<Vec<u8>, Error>,
}

fn via<T: Decode + Encode>(bytes: &[u8], json: fn(&T) -> Value) -> Result<Decoded, Error> {
    T::decode(bytes).map(|x| Decoded {
        value: json(&x),
        again: x.encode(),
    })
}

/// `structure` (a SCHEMA-4.8 structure name) decoded from `bytes`: the decoder's verdict, and on success the value
/// and the re-encoding. `None`: no decoder for this name (the `Signed/*` rows are encode-only).
pub fn decode(
    structure: &str,
    context: Option<&str>,
    bytes: &[u8],
) -> Option<Result<Decoded, Error>> {
    if structure.starts_with("Request/") {
        return Some(via::<Request>(bytes, request_json));
    }
    if structure.starts_with("Response/") {
        let ctx = match context {
            Some("FETCH_MULTI") => CellrContext::FetchMulti,
            // FETCH, and every non-CELLR response (the context only matters for CELLR)
            _ => CellrContext::Fetch,
        };
        return Some(Response::decode(bytes, ctx).map(|x| Decoded {
            value: response_json(&x),
            again: x.encode(),
        }));
    }
    Some(match structure {
        "Record/HELLO" => via::<Hello>(bytes, |x| hello_json(*x)),
        "Record/RELAYINFO" => via::<RelayInfoRecord>(bytes, relay_info_record_json),
        "Record/HS1" => via::<Hs1>(bytes, hs1_json),
        "Record/HS2" => via::<Hs2>(bytes, hs2_json),
        "RelayInfoV1" => via::<RelayInfoV1>(bytes, relay_info_json),
        "RelayRef" => via::<RelayRef>(bytes, relay_ref_json),
        "InvitationV1" => via::<InvitationV1>(bytes, invitation_json),
        "Profile" => via::<Profile>(bytes, profile_json),
        "LinkDataV1" => via::<LinkDataV1>(bytes, link_data_json),
        "LinkBlob" => via::<LinkBlob>(bytes, link_blob_json),
        "IKSPublic" => via::<IksPublic>(bytes, iks_json),
        "PrekeyBundle" => via::<PrekeyBundle>(bytes, bundle_json),
        "Outer" => via::<Outer>(bytes, outer_json),
        "inner_ct" => via::<InnerCt>(bytes, inner_ct_json),
        "Inner" => via::<Inner>(bytes, inner_json),
        "HandshakeCell" => via::<HandshakeCell>(bytes, handshake_cell_json),
        "HandshakeCellPlaintext" => via::<HandshakeCellPlaintext>(bytes, handshake_pt_json),
        "Cell" => via::<Cell>(bytes, cell_json),
        "HeaderV1" => via::<HeaderV1>(bytes, header_json),
        "Content" => via::<Content>(bytes, content_json),
        "AppMessage" => via::<AppMessage>(bytes, app_message_json),
        "BatchBody" => via::<BatchBody>(bytes, batch_json),
        "Fragment" => via::<Fragment>(bytes, fragment_json),
        "FragmentPayload" => via::<FragmentPayload>(bytes, fragment_payload_json),
        "RouteDescriptor" => via::<RouteDescriptor>(bytes, route_json),
        "RelayQueue" => via::<RelayQueue>(bytes, relay_queue_json),
        "RouteUpdateBody" => via::<RouteUpdateBody>(bytes, route_update_json),
        "HandshakeBody" => via::<HandshakeBody>(bytes, handshake_body_json),
        "KeyChangeBody" => via::<KeyChangeBody>(bytes, key_change_json),
        "ReceiptBody" => via::<ReceiptBody>(bytes, receipt_json),
        "ControlBody" => via::<ControlBody>(bytes, control_json),
        _ => return None,
    })
}

// ---- the stream (SCHEMA §2) and the derived keys ----------------------------------------------------------

/// A row's stream with the derivations of SCHEMA-4.8 "Input derivation".
struct In(VectorStream);

impl In {
    fn new(i: u32) -> Self {
        Self(VectorStream::new(SUITE, i))
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        self.0.take(n)
    }

    fn arr<const N: usize>(&mut self) -> [u8; N] {
        self.0.arr()
    }

    fn boxed<const N: usize>(&mut self) -> Box<[u8; N]> {
        self.take(N).into_boxed_slice().try_into().unwrap()
    }

    /// A free integer: w stream bytes, big-endian.
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.arr())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.arr())
    }

    fn secret(&mut self) -> SecretBytes<32> {
        SecretBytes::from_slice(&self.arr::<32>()).unwrap()
    }

    /// X25519 secret 32 → X25519(sk, 9).
    fn x25519(&mut self) -> X25519Pk {
        let sk = X25519Secret::from_bytes(&self.arr::<32>()).unwrap();
        X25519Pk::from_bytes(sk.public_key().as_bytes()).unwrap()
    }

    /// Ed25519 seed 32 → the signing key and its public key.
    fn ed25519(&mut self) -> (Ed25519SigningKey, Ed25519Pk) {
        let sk = Ed25519SigningKey::from_seed(&self.arr::<32>()).unwrap();
        let pk = Ed25519Pk::from_bytes(sk.verifying_key().as_bytes()).unwrap();
        (sk, pk)
    }

    /// ML-KEM-768 seed `d ‖ z` 64 → `ek`.
    fn ek768(&mut self) -> MlKem768Ek {
        let dk = secmp_crypto::MlKem768Dk::from_seed(&self.arr::<64>()).unwrap();
        MlKem768Ek::from_bytes(dk.encapsulation_key().as_bytes()).unwrap()
    }

    /// ML-KEM-1024 seed `d ‖ z` 64 → `ek`.
    fn ek1024(&mut self) -> MlKem1024Ek {
        let dk = secmp_crypto::MlKem1024Dk::from_seed(&self.arr::<64>()).unwrap();
        MlKem1024Ek::from_bytes(dk.encapsulation_key().as_bytes()).unwrap()
    }

    /// "Text of k stream bytes": the lowercase hex of k stream bytes as ASCII.
    fn text(&mut self, k: usize) -> String {
        hex(&self.take(k))
    }

    fn cell(&mut self) -> Cell {
        Cell::from_bytes(&self.take(CELL_LEN)).unwrap()
    }

    /// `IKSPublic` order: `ed_seed` 32 → `ik_ed25519`; `mldsa_seed` 32 → `ik_mldsa65` (`KeyGen_internal(ξ)`); `dh_sk` 32
    /// → `ik_dh`. Returns the signing key of the identity as well.
    fn iks(&mut self) -> (IksPublic, HybridSigningKey) {
        let ed = self.arr::<32>();
        let mldsa = self.arr::<32>();
        let key = HybridSigningKey::from_seeds(&ed, &mldsa).unwrap();
        let vk = key.verifying_key();
        let mut ik_mldsa65 = Box::new([0_u8; MLDSA65_PK_LEN]);
        ik_mldsa65.copy_from_slice(vk.mldsa65());
        let iks = IksPublic {
            ik_ed25519: Ed25519Pk::from_bytes(vk.ed25519()).unwrap(),
            ik_mldsa65,
            ik_dh: self.x25519(),
        };
        (iks, key)
    }

    /// `RelayRef` order: `relay_fp` 32; `onion_seed` 32 → `onion` (PUBKEY = the Ed25519 public key); `akc` 32; with
    /// `direct` (host and port from the table): `spki_sha256` 32.
    fn relay_ref(&mut self, direct: Option<(&[u8], u16)>) -> RelayRef {
        let relay_fp = self.arr();
        let (_, onion_pk) = self.ed25519();
        let onion = Onion::from_pubkey(onion_pk.as_bytes());
        let akc = self.arr();
        let direct = direct.map(|(host, port)| Direct {
            host: Host::from_bytes(host).unwrap(),
            port: NonZeroU16::new(port).unwrap(),
            spki_sha256: self.arr(),
        });
        RelayRef {
            relay_fp,
            onion,
            akc,
            direct,
        }
    }

    /// `RelayQueue` order: `relay`; `sid` 16; `send_seed` 32 (`period_s` from the table).
    fn relay_queue(&mut self, direct: Option<(&[u8], u16)>, period_s: u16) -> RelayQueue {
        RelayQueue {
            relay: self.relay_ref(direct),
            sid: self.arr(),
            send_seed: self.secret(),
            period_s: Period::from_seconds(period_s).unwrap(),
        }
    }

    /// `Profile` order: `name` (text of k stream bytes); `avatar_sha256` 32 if present.
    fn profile(&mut self, name_bytes: usize, avatar: bool) -> Profile {
        let name = self.text(name_bytes);
        let avatar = avatar.then(|| self.arr());
        Profile::new(&name, avatar).unwrap()
    }

    /// `AppMessage` order: `msg_id` 16; `expire_after` 4; `payload` = text of k stream bytes.
    fn app_message(&mut self, kind: AppKind, text_bytes: usize) -> AppMessage {
        AppMessage {
            msg_id: self.arr(),
            expire_after: self.u32(),
            kind,
            payload: self.text(text_bytes).into_bytes(),
        }
    }

    /// `PrekeyBundle` order up to the signer: `spk_id` 4; `spk_dh_sk` 32; `spk_kem_seed` 64 (ML-KEM-1024);
    /// `rpk_kem_seed` 64 (ML-KEM-768); `spk_expiry` 8; `opk_id` 4; `opk_dh_sk` 32; `opk_kem_seed` 64 (ML-KEM-1024).
    /// The signature is added by [`sign_bundle`] (a placeholder until then).
    fn bundle_fields(&mut self) -> PrekeyBundle {
        PrekeyBundle {
            spk_id: self.u32(),
            spk_dh: self.x25519(),
            spk_kem: self.ek1024(),
            rpk_kem: self.ek768(),
            spk_expiry: self.u64(),
            opk_id: self.u32(),
            opk_dh: self.x25519(),
            opk_kem: self.ek1024(),
            sig: placeholder_sig(),
        }
    }

    /// `KeyChangeBody` order: `iks` (the new identity); `old_ed_seed` 32; `old_mldsa_seed` 32; rnd 32; `sig` =
    /// HybridSign(old, `"SecMP-TR/1 keychange"`, fingerprint(iks)) (spec §7.6).
    fn key_change(&mut self) -> KeyChangeBody {
        let (iks, _) = self.iks();
        let old = HybridSigningKey::from_seeds(&self.arr::<32>(), &self.arr::<32>()).unwrap();
        let rnd = self.arr::<32>();
        let fp = Fingerprint::of_encoded_iks(&encoded(&iks)).unwrap();
        let sig = old
            .sign_kat(Label::TrKeychange, fp.as_bytes(), &rnd)
            .unwrap();
        KeyChangeBody {
            iks,
            sig: HybridSig::from_bytes(sig.as_bytes().as_slice()).unwrap(),
        }
    }
}

/// A well-formed `HybridSig` (from a fixed key, no stream input) that fills the field until the real signature is
/// computed over the fields before it; never listed.
fn placeholder_sig() -> HybridSig {
    let key = HybridSigningKey::from_seeds(&[0; 32], &[0; 32]).unwrap();
    let sig = key.sign_kat(Label::HxBundle, b"", &[0; 32]).unwrap();
    HybridSig::from_bytes(sig.as_bytes().as_slice()).unwrap()
}

/// `sig` = HybridSign(signer, `"SecMP-HX/1 bundle"`, the fields before `sig` ‖ the signer's `ik_dh`) (spec §6.3;
/// ML-DSA hedged with `rnd`).
fn sign_bundle(
    bundle: &mut PrekeyBundle,
    signer: &HybridSigningKey,
    signer_ik_dh: &X25519Pk,
    rnd: &[u8; 32],
) {
    let mut msg = bundle.signed_fields().unwrap();
    msg.extend_from_slice(signer_ik_dh.as_bytes());
    let sig = signer.sign_kat(Label::HxBundle, &msg, rnd).unwrap();
    bundle.sig = HybridSig::from_bytes(sig.as_bytes().as_slice()).unwrap();
}

fn ed_sig(key: &Ed25519SigningKey, msg: &[u8]) -> Ed25519Sig {
    Ed25519Sig::from_bytes(&key.sign(msg)).unwrap()
}

// ---- the rows ----------------------------------------------------------------------------------------------

const HOST: &[u8] = b"relay.example.org";
const DIRECT: Option<(&[u8], u16)> = Some((HOST, 443));

/// The 253-byte host of row 33: 63 × `a`, `.`, 63 × `b`, `.`, 63 × `c`, `.`, 61 × `d`.
fn max_host() -> Vec<u8> {
    let mut v = Vec::new();
    for (c, n) in [(b'a', 63), (b'b', 63), (b'c', 63), (b'd', 61)] {
        if !v.is_empty() {
            v.push(b'.');
        }
        v.extend(std::iter::repeat_n(c, n));
    }
    v
}

fn row(i: u32, structure: &str, context: Option<&str>, value: Value, bytes: &[u8]) -> Value {
    let mut inputs = obj(vec![("structure", json!(structure)), ("value", value)]);
    if let Some(c) = context {
        inputs.insert("context".to_owned(), json!(c));
    }
    json!({
        "id": format!("enc-{i:04}"),
        "op": "encode",
        "inputs": inputs,
        "outputs": {"bytes": hex(bytes)},
    })
}

fn row_of<T: Encode>(i: u32, structure: &str, x: &T, json: fn(&T) -> Value) -> Value {
    row(i, structure, None, json(x), &encoded(x))
}

/// A request frame row.
fn req(i: u32, name: &str, cmd_seq: u32, cmd: RequestCmd) -> Value {
    let r = Request { cmd_seq, cmd };
    row_of(i, &format!("Request/{name}"), &r, request_json)
}

/// A response frame row (`context` for CELLR).
fn resp(i: u32, name: &str, context: Option<&str>, cmd_seq: u32, cmd: ResponseCmd) -> Value {
    let r = Response { cmd_seq, cmd };
    row(
        i,
        &format!("Response/{name}"),
        context,
        response_json(&r),
        &encoded(&r),
    )
}

/// A `Signed/*` row: the value is the listed inputs, the bytes the D.6 message.
fn signed_row(i: u32, name: &str, value: Value, bytes: &[u8]) -> Value {
    row(i, &format!("Signed/{name}"), None, value, bytes)
}

/// `RelayInfoV1` order: `relay_sig_seed` 32 → `relay_sig_pk`; `kid` 4; `relay_dh_sk` 32 → `relay_dh_pk`;
/// `relay_kem_seed` 64 → `relay_kem_ek` (ML-KEM-1024); `akc` 32; `valid_until` 8; `sig` = Ed25519.Sign(`relay_sig_seed`,
/// `"SecMP-LINK/1 relayinfo"` ‖ the 1677 bytes before `sig`) (§8.2). `maxima`: kid and `valid_until` at their maxima
/// (not drawn).
fn relay_info(s: &mut In, maxima: bool) -> RelayInfoV1 {
    let (sk, relay_sig_pk) = s.ed25519();
    let kid = if maxima { u32::MAX } else { s.u32() };
    let relay_dh_pk = s.x25519();
    let relay_kem_ek = s.ek1024();
    let akc = s.arr();
    let valid_until = if maxima { u64::MAX } else { s.u64() };
    let mut info = RelayInfoV1 {
        relay_sig_pk,
        kid,
        relay_dh_pk,
        relay_kem_ek,
        akc,
        valid_until,
        sig: ed_sig(&sk, b""),
    };
    let mut msg = Label::LinkRelayinfo.as_bytes().to_vec();
    msg.extend(info.signed_fields().unwrap());
    info.sig = ed_sig(&sk, &msg);
    info
}

/// `Request/FETCH`: `cmd_seq` 4; `rid` 16; `ack` 8; `sess_id` 16; `recv_seed` 32; `sig` (maxima: `cmd_seq` and ack).
fn fetch_row(i: u32, s: &mut In, maxima: bool) -> Value {
    let cmd_seq = if maxima { u32::MAX } else { s.u32() };
    let rid: Id = s.arr();
    let ack = if maxima { u64::MAX } else { s.u64() };
    let sess_id: Id = s.arr();
    let (sk, _) = s.ed25519();
    let sig = ed_sig(&sk, &signed::fetch(&sess_id, cmd_seq, &rid, ack));
    req(i, "FETCH", cmd_seq, RequestCmd::Fetch { rid, ack, sig })
}

/// `Request/FETCH_MULTI`: `cmd_seq` 4; per entry `rid` 16, `ack` 8; `sess_id` 16; per entry `recv_seed` 32; each
/// entry's `sig` over its own `MFETCH` message.
fn fetch_multi_row(i: u32, s: &mut In, count: usize) -> Value {
    let cmd_seq = s.u32();
    let queues: Vec<(Id, u64)> = (0..count).map(|_| (s.arr(), s.u64())).collect();
    let sess_id: Id = s.arr();
    let entries = queues
        .into_iter()
        .map(|(rid, ack)| {
            let (sk, _) = s.ed25519();
            let sig = ed_sig(
                &sk,
                &signed::fetch_multi_entry(&sess_id, cmd_seq, &rid, ack),
            );
            FetchEntry { rid, ack, sig }
        })
        .collect();
    req(
        i,
        "FETCH_MULTI",
        cmd_seq,
        RequestCmd::FetchMulti { entries },
    )
}

/// `Response/OK_SEND`: `cmd_seq` 4; `cell_id` 8; `evicted_id` 8 if present (maxima: all three, nothing drawn).
fn ok_send_row(i: u32, s: &mut In, evicted: bool, maxima: bool) -> Value {
    let (cmd_seq, cell_id, evicted) = if maxima {
        (u32::MAX, u64::MAX, Some(u64::MAX))
    } else {
        let cmd_seq = s.u32();
        let cell_id = s.u64();
        (cmd_seq, cell_id, evicted.then(|| s.u64()))
    };
    resp(
        i,
        "OK_SEND",
        None,
        cmd_seq,
        ResponseCmd::OkSend { cell_id, evicted },
    )
}

/// `InvitationV1` order: `relay`; `ld_id` 16; `link_key` 32; `inviter_fp` 32; `inv_sid` 16; `inv_send_seed` 32;
/// `expires` 8 (not drawn at its maximum).
fn invitation(
    s: &mut In,
    direct: Option<(&[u8], u16)>,
    period_s: u16,
    max_expires: bool,
) -> InvitationV1 {
    InvitationV1 {
        relay: s.relay_ref(direct),
        ld_id: s.arr(),
        link_key: s.secret(),
        inviter_fp: s.arr(),
        inv_sid: s.arr(),
        inv_send_seed: s.secret(),
        inv_period_s: Period::from_seconds(period_s).unwrap(),
        expires: if max_expires { u64::MAX } else { s.u64() },
    }
}

/// `HeaderV1` order: `dh_sk` 32 → `dh_pk`; `pn` 4; `n` 4; `ek_pq_seed` 64 → `ek_pq` (ML-KEM-768); `ct_pq` 1088.
fn header(s: &mut In, maxima: bool) -> HeaderV1 {
    let dh_pk = s.x25519();
    let (pn, n) = if maxima {
        (u32::MAX, u32::MAX)
    } else {
        (s.u32(), s.u32())
    };
    HeaderV1 {
        dh_pk,
        pn,
        n,
        ek_pq: s.ek768(),
        ct_pq: s.boxed(),
    }
}

/// A `Content` row: `seq` 8; `ts` 8 (both at their maxima: not drawn); then the body in its own order.
fn content_row(i: u32, s: &mut In, maxima: bool, body: fn(&mut In) -> ContentBody) -> Value {
    let (seq, ts) = if maxima {
        (u64::MAX, u64::MAX)
    } else {
        (s.u64(), s.u64())
    };
    let c = Content {
        seq,
        ts,
        body: body(s),
    };
    row_of(i, "Content", &c, content_json)
}

/// `Fragment` order: `msg_id` 16; `chunk` (length from the table).
fn fragment(s: &mut In, idx: u16, total: u16, chunk: usize) -> Fragment {
    Fragment {
        msg_id: s.arr(),
        idx,
        total,
        chunk: s.take(chunk),
    }
}

fn receipt(s: &mut In, kind: ReceiptKind, count: usize) -> ReceiptBody {
    ReceiptBody {
        kind,
        msg_ids: (0..count).map(|_| s.arr()).collect(),
    }
}

fn control_row(i: u32, s: &mut In, code: ControlCode, arg: usize) -> Value {
    let c = ControlBody {
        code,
        arg: s.take(arg),
    };
    row_of(i, "ControlBody", &c, control_json)
}

fn route_unknown(s: &mut In, kind: u8, n: usize) -> RouteDescriptor {
    RouteDescriptor::Unknown {
        kind,
        blob: s.take(n),
    }
}

/// Positive row `i` of the case table.
fn positive(i: u32) -> Value {
    let s = &mut In::new(i);
    match i {
        1..=6 => records(i, s),
        7..=18 => requests(i, s),
        19..=30 => responses(i, s),
        31..=43 => invitation_rows(i, s),
        44..=59 => envelope_and_content(i, s),
        60..=78 => bodies(i, s),
        _ => signed_positive(i, s),
    }
}

/// A row number outside its group (a generator error).
fn not_in_group(i: u32) -> Value {
    assert!(i == 0, "row {i} is not a positive row of this group");
    Value::Null
}

/// Rows 1–6 (D.1).
fn records(i: u32, s: &mut In) -> Value {
    match i {
        1 => row_of(i, "Record/HELLO", &Hello, |x| hello_json(*x)),
        2 => {
            let r = RelayInfoRecord {
                relay_info: relay_info(s, false),
            };
            row_of(i, "Record/RELAYINFO", &r, relay_info_record_json)
        }
        3 | 4 => row_of(i, "RelayInfoV1", &relay_info(s, i == 4), relay_info_json),
        5 => {
            let r = Hs1 {
                kid: s.u32(),
                e_c: s.x25519(),
                ek_c: s.ek768(),
                pk_e1: s.x25519(),
                ct_kem: s.boxed(),
                mac1: s.arr(),
            };
            row_of(i, "Record/HS1", &r, hs1_json)
        }
        6 => {
            let r = Hs2 {
                e_r: s.x25519(),
                ct_c: s.boxed(),
                mac2: s.arr(),
            };
            row_of(i, "Record/HS2", &r, hs2_json)
        }
        _ => not_in_group(i),
    }
}

/// Rows 7–18 (D.2 requests).
fn requests(i: u32, s: &mut In) -> Value {
    match i {
        7 => {
            let cmd_seq = s.u32();
            let (recv, recv_pk) = s.ed25519();
            let (_, send_pk) = s.ed25519();
            let token = s.arr();
            let sess_id: Id = s.arr();
            let sig = ed_sig(
                &recv,
                &signed::queue_new(&sess_id, cmd_seq, &recv_pk, &send_pk, &token),
            );
            let cmd = RequestCmd::QueueNew {
                recv_pk,
                send_pk,
                token,
                sig,
            };
            req(i, "QUEUE_NEW", cmd_seq, cmd)
        }
        8 => {
            let cmd_seq = s.u32();
            let sid: Id = s.arr();
            let cell = s.cell();
            let sess_id: Id = s.arr();
            let (sk, _) = s.ed25519();
            let sig = ed_sig(&sk, &signed::send(&sess_id, cmd_seq, &sid, &cell));
            req(i, "SEND", cmd_seq, RequestCmd::Send { sid, cell, sig })
        }
        9 | 10 => fetch_row(i, s, i == 10),
        11 => fetch_multi_row(i, s, 3),
        12 => fetch_multi_row(i, s, 32),
        13 => {
            let cmd_seq = s.u32();
            let rid: Id = s.arr();
            let sess_id: Id = s.arr();
            let (sk, _) = s.ed25519();
            let sig = ed_sig(&sk, &signed::queue_del(&sess_id, cmd_seq, &rid));
            req(i, "QUEUE_DEL", cmd_seq, RequestCmd::QueueDel { rid, sig })
        }
        14 => link_put_row(i, s),
        15 => {
            let cmd_seq = s.u32();
            let ld_id = s.arr();
            let cmd = RequestCmd::LinkGet {
                ld_id,
                mode: LinkGetMode::Consume,
            };
            req(i, "LINK_GET", cmd_seq, cmd)
        }
        16 => {
            let cmd_seq = s.u32();
            let ld_id: Id = s.arr();
            let sess_id: Id = s.arr();
            let (sk, _) = s.ed25519();
            let sig = ed_sig(
                &sk,
                &signed::link_get_owner_status(&sess_id, cmd_seq, &ld_id),
            );
            let cmd = RequestCmd::LinkGet {
                ld_id,
                mode: LinkGetMode::OwnerStatus(sig),
            };
            req(i, "LINK_GET", cmd_seq, cmd)
        }
        17 => req(i, "PING", s.u32(), RequestCmd::Ping),
        18 => {
            let cmd_seq = s.u32();
            let cont = Cont {
                idx: ContIdx::Two,
                data: s.boxed::<CONT_DATA_LEN>(),
            };
            req(i, "CONT", cmd_seq, RequestCmd::Cont(cont))
        }
        _ => not_in_group(i),
    }
}

/// `Request/LINK_PUT` (`one_time` 1): `cmd_seq` 4; `ld_id` 16; `expires_bucket` 4; `owner_seed` 32 → `owner_pk`;
/// `token` 32; blob 12360 (`blob_part` = its first 4160 bytes); `sess_id` 16; `sig` by `owner_seed`, with
/// SHA-256(blob).
fn link_put_row(i: u32, s: &mut In) -> Value {
    let cmd_seq = s.u32();
    let ld_id: Id = s.arr();
    let expires_bucket = s.u32();
    let (owner, owner_pk) = s.ed25519();
    let token = s.arr();
    let blob_bytes = s.take(secmp_proto::sizes::LINK_BLOB_LEN);
    let (n, com_ct) = blob_bytes.split_at(secmp_proto::sizes::NONCE_LEN);
    let blob = LinkBlob::from_parts(n, com_ct).unwrap();
    let sess_id: Id = s.arr();
    let fields = LinkPutFields {
        ld_id: &ld_id,
        one_time: true,
        expires_bucket,
        owner_pk: &owner_pk,
        token: &token,
    };
    let sig = ed_sig(
        &owner,
        &signed::link_put(&sess_id, cmd_seq, &fields, &blob).unwrap(),
    );
    let mut blob_part = Box::new([0_u8; BLOB_PART_LEN]);
    blob_part.copy_from_slice(blob_bytes.get(..BLOB_PART_LEN).unwrap());
    let cmd = RequestCmd::LinkPut {
        ld_id,
        one_time: true,
        expires_bucket,
        owner_pk,
        token,
        sig,
        blob_part,
    };
    req(i, "LINK_PUT", cmd_seq, cmd)
}

/// Rows 19–30 (D.2 responses).
fn responses(i: u32, s: &mut In) -> Value {
    match i {
        19 => resp(i, "OK", None, s.u32(), ResponseCmd::Ok),
        20 => {
            let cmd_seq = s.u32();
            let cmd = ResponseCmd::OkQueueNew {
                rid: s.arr(),
                sid: s.arr(),
            };
            resp(i, "OK_QUEUE_NEW", None, cmd_seq, cmd)
        }
        21 => ok_send_row(i, s, false, false),
        22 => ok_send_row(i, s, true, false),
        23 => ok_send_row(i, s, true, true),
        24 => {
            let cmd_seq = s.u32();
            let cell_id = s.u64();
            let c = Cellr::Cell {
                rid: [0; 16],
                cell_id,
                cell: s.cell(),
            };
            resp(i, "CELLR", Some("FETCH"), cmd_seq, ResponseCmd::Cellr(c))
        }
        25 => {
            let cmd_seq = s.u32();
            let c = Cellr::Dummy { cell: s.cell() };
            resp(i, "CELLR", Some("FETCH"), cmd_seq, ResponseCmd::Cellr(c))
        }
        26 => {
            let cmd_seq = s.u32();
            let rid = s.arr();
            let cell_id = s.u64();
            let c = Cellr::Cell {
                rid,
                cell_id,
                cell: s.cell(),
            };
            resp(
                i,
                "CELLR",
                Some("FETCH_MULTI"),
                cmd_seq,
                ResponseCmd::Cellr(c),
            )
        }
        27 => {
            let cmd_seq = s.u32();
            let rid = s.arr();
            let c = Cellr::Error {
                error: CellrError::Auth,
                rid,
                cell: s.cell(),
            };
            resp(
                i,
                "CELLR",
                Some("FETCH_MULTI"),
                cmd_seq,
                ResponseCmd::Cellr(c),
            )
        }
        28 => {
            let cmd_seq = s.u32();
            let cmd = ResponseCmd::LinkR {
                present: true,
                consumed: false,
                blob_part: s.boxed::<BLOB_PART_LEN>(),
            };
            resp(i, "LINKR", None, cmd_seq, cmd)
        }
        29 => resp(i, "ERR", None, s.u32(), ResponseCmd::Err(ErrCode::Rate)),
        30 => {
            let cmd_seq = s.u32();
            let cont = Cont {
                idx: ContIdx::One,
                data: s.boxed::<CONT_DATA_LEN>(),
            };
            resp(i, "CONT", None, cmd_seq, ResponseCmd::Cont(cont))
        }
        _ => not_in_group(i),
    }
}

/// Rows 31–43 (D.3).
fn invitation_rows(i: u32, s: &mut In) -> Value {
    match i {
        31 => row_of(i, "RelayRef", &s.relay_ref(None), relay_ref_json),
        32 => row_of(i, "RelayRef", &s.relay_ref(DIRECT), relay_ref_json),
        33 => {
            let host = max_host();
            let r = s.relay_ref(Some((&host, u16::MAX)));
            row_of(i, "RelayRef", &r, relay_ref_json)
        }
        34 => row_of(
            i,
            "InvitationV1",
            &invitation(s, None, 40, false),
            invitation_json,
        ),
        35 => row_of(
            i,
            "InvitationV1",
            &invitation(s, DIRECT, 10, false),
            invitation_json,
        ),
        36 => row_of(
            i,
            "InvitationV1",
            &invitation(s, None, 80, true),
            invitation_json,
        ),
        37 => row_of(i, "Profile", &s.profile(32, true), profile_json),
        38 => {
            let p = Profile::new("Zoë Ångström 李雷 🙂", None).unwrap();
            row_of(i, "Profile", &p, profile_json)
        }
        39 => {
            // bundle signed by inviter_iks: no signer seeds drawn
            let (inviter_iks, inviter) = s.iks();
            let mut bundle = s.bundle_fields();
            let rnd = s.arr();
            sign_bundle(&mut bundle, &inviter, &inviter_iks.ik_dh, &rnd);
            let ld = LinkDataV1 {
                inviter_iks,
                bundle,
                profile: s.profile(8, true),
                created: s.u64(),
            };
            row_of(i, "LinkDataV1", &ld, link_data_json)
        }
        40 => {
            let b = LinkBlob {
                n: s.arr(),
                com: s.arr(),
                ct: s.boxed(),
            };
            row_of(i, "LinkBlob", &b, link_blob_json)
        }
        41 => row_of(i, "IKSPublic", &s.iks().0, iks_json),
        42 => {
            // ik_dh with bit 255 set (§3: accepted, kept as received)
            let (mut iks, _) = s.iks();
            let mut dh = *iks.ik_dh.as_bytes();
            if let Some(last) = dh.last_mut() {
                *last |= 0x80;
            }
            iks.ik_dh = X25519Pk::from_bytes(&dh).unwrap();
            row_of(i, "IKSPublic", &iks, iks_json)
        }
        43 => {
            // standalone: the signer IKS comes from the stream after the bundle fields
            let mut bundle = s.bundle_fields();
            let (signer_iks, signer) = s.iks();
            let rnd = s.arr();
            sign_bundle(&mut bundle, &signer, &signer_iks.ik_dh, &rnd);
            row_of(i, "PrekeyBundle", &bundle, bundle_json)
        }
        _ => not_in_group(i),
    }
}

/// Rows 44–59 (D.4, and D.5 `Cell`, `HeaderV1`, `Content`).
fn envelope_and_content(i: u32, s: &mut In) -> Value {
    match i {
        44 => {
            let o = Outer {
                ek_i: s.x25519(),
                spk_id: s.u32(),
                opk_id: s.u32(),
                ct_spk: s.boxed(),
                ct_opk: s.boxed(),
                inner_ct: InnerCt::decode(&s.take(secmp_proto::sizes::INNER_CT_LEN)).unwrap(),
            };
            row_of(i, "Outer", &o, outer_json)
        }
        45 => {
            let c = InnerCt {
                n2: s.arr(),
                com: s.arr(),
                ct: s.boxed(),
            };
            row_of(i, "inner_ct", &c, inner_ct_json)
        }
        46 => {
            let x = Inner {
                iks: s.iks().0,
                first_msg: s.cell(),
            };
            row_of(i, "Inner", &x, inner_json)
        }
        47 => {
            let c = HandshakeCell {
                n: s.arr(),
                com: s.arr(),
                ct: s.boxed(),
            };
            row_of(i, "HandshakeCell", &c, handshake_cell_json)
        }
        48 => {
            let p = HandshakeCellPlaintext {
                init_id: s.arr(),
                i: 2,
                chunk: s.boxed(),
            };
            row_of(i, "HandshakeCellPlaintext", &p, handshake_pt_json)
        }
        49 => row_of(i, "Cell", &s.cell(), cell_json),
        50 | 51 => row_of(i, "HeaderV1", &header(s, i == 51), header_json),
        52 => content_row(i, s, false, |_| ContentBody::Dummy),
        53 => content_row(i, s, false, |s| {
            ContentBody::Handshake(HandshakeBody {
                profile: s.profile(8, false),
                routes: vec![RouteDescriptor::RelayQueue(s.relay_queue(None, 20))],
            })
        }),
        54 => content_row(i, s, false, |s| {
            ContentBody::Batch(BatchBody {
                messages: vec![
                    s.app_message(AppKind::Text, 20),
                    s.app_message(AppKind::ViewOnceText, 12),
                ],
            })
        }),
        55 => content_row(i, s, false, |s| {
            ContentBody::Fragment(fragment(s, 1, 3, 1669))
        }),
        56 => content_row(i, s, false, |s| {
            ContentBody::RouteUpdate(RouteUpdateBody {
                routes: vec![RouteDescriptor::RelayQueue(s.relay_queue(DIRECT, 40))],
            })
        }),
        57 => content_row(i, s, false, |s| {
            ContentBody::Receipt(receipt(s, ReceiptKind::Read, 4))
        }),
        58 => content_row(i, s, false, |_| {
            ContentBody::Control(ControlBody {
                code: ControlCode::SessionResetRequest,
                arg: vec![],
            })
        }),
        59 => content_row(i, s, true, |_| ContentBody::Dummy),
        _ => not_in_group(i),
    }
}

/// Rows 60–78 (the D.5 bodies).
fn bodies(i: u32, s: &mut In) -> Value {
    match i {
        60 => row_of(
            i,
            "AppMessage",
            &s.app_message(AppKind::Text, 50),
            app_message_json,
        ),
        61 => {
            let m = AppMessage {
                msg_id: s.arr(),
                kind: AppKind::AttachmentInline,
                expire_after: u32::MAX,
                payload: s.take(65_535),
            };
            row_of(i, "AppMessage", &m, app_message_json)
        }
        62 => {
            let b = BatchBody {
                messages: vec![
                    s.app_message(AppKind::Text, 30),
                    s.app_message(AppKind::ViewOnceText, 5),
                ],
            };
            row_of(i, "BatchBody", &b, batch_json)
        }
        63 => row_of(i, "Fragment", &fragment(s, 1, 2, 100), fragment_json),
        64 => row_of(i, "Fragment", &fragment(s, 0, 2, 100), fragment_json),
        65 => row_of(i, "Fragment", &fragment(s, 63, 64, 1669), fragment_json),
        66 => {
            let p = FragmentPayload::KeyChange(s.key_change());
            row_of(i, "FragmentPayload", &p, fragment_payload_json)
        }
        67 => {
            let r = RouteDescriptor::RelayQueue(s.relay_queue(None, 20));
            row_of(i, "RouteDescriptor", &r, route_json)
        }
        68 => row_of(
            i,
            "RouteDescriptor",
            &route_unknown(s, 0x7e, 24),
            route_json,
        ),
        69 => row_of(
            i,
            "RouteDescriptor",
            &route_unknown(s, 0x7e, 65_535),
            route_json,
        ),
        70 => row_of(
            i,
            "RelayQueue",
            &s.relay_queue(DIRECT, 80),
            relay_queue_json,
        ),
        71 => {
            let b = RouteUpdateBody {
                routes: vec![
                    RouteDescriptor::RelayQueue(s.relay_queue(None, 80)),
                    RouteDescriptor::RelayQueue(s.relay_queue(DIRECT, 10)),
                ],
            };
            row_of(i, "RouteUpdateBody", &b, route_update_json)
        }
        72 => {
            let profile = s.profile(4, true);
            let b = HandshakeBody {
                profile,
                routes: vec![
                    RouteDescriptor::RelayQueue(s.relay_queue(DIRECT, 10)),
                    route_unknown(s, 0x10, 40),
                ],
            };
            row_of(i, "HandshakeBody", &b, handshake_body_json)
        }
        73 => row_of(i, "KeyChangeBody", &s.key_change(), key_change_json),
        74 => row_of(
            i,
            "ReceiptBody",
            &receipt(s, ReceiptKind::Delivered, 5),
            receipt_json,
        ),
        75 => row_of(
            i,
            "ReceiptBody",
            &receipt(s, ReceiptKind::Read, 255),
            receipt_json,
        ),
        76 => control_row(i, s, ControlCode::ContactRemoved, 0),
        77 => control_row(i, s, ControlCode::SessionResetRequest, 16),
        78 => control_row(i, s, ControlCode::ContactRemoved, 65_535),
        _ => not_in_group(i),
    }
}

/// Rows 79–85, `Signed/*`: `sess_id` 16; `cmd_seq` 4; the signed D.2 fields in order (Ed25519 keys from 32-byte
/// seeds); `LINK_PUT`: `blob` 12360.
fn signed_positive(i: u32, s: &mut In) -> Value {
    let sess_id: Id = s.arr();
    let cmd_seq = s.u32();
    let head = |m: Value| {
        let mut m = m;
        if let Some(o) = m.as_object_mut() {
            o.insert("sess_id".to_owned(), h(&sess_id));
            o.insert("cmd_seq".to_owned(), json!(cmd_seq));
        }
        m
    };
    match i {
        79 => {
            let (_, recv_pk) = s.ed25519();
            let (_, send_pk) = s.ed25519();
            let token = s.arr();
            let bytes = signed::queue_new(&sess_id, cmd_seq, &recv_pk, &send_pk, &token);
            let v = json!({"recv_pk": h(recv_pk.as_bytes()), "send_pk": h(send_pk.as_bytes()), "token": h(&token)});
            signed_row(i, "QUEUE_NEW", head(v), &bytes)
        }
        80 => {
            let sid: Id = s.arr();
            let cell = s.cell();
            let bytes = signed::send(&sess_id, cmd_seq, &sid, &cell);
            let v = json!({"sid": h(&sid), "cell": h(cell.as_bytes())});
            signed_row(i, "SEND", head(v), &bytes)
        }
        81 | 82 => {
            let rid: Id = s.arr();
            let ack = s.u64();
            let v = json!({"rid": h(&rid), "ack": ack});
            if i == 81 {
                signed_row(
                    i,
                    "FETCH",
                    head(v),
                    &signed::fetch(&sess_id, cmd_seq, &rid, ack),
                )
            } else {
                let bytes = signed::fetch_multi_entry(&sess_id, cmd_seq, &rid, ack);
                signed_row(i, "FETCH_MULTI", head(v), &bytes)
            }
        }
        83 => {
            let rid: Id = s.arr();
            let bytes = signed::queue_del(&sess_id, cmd_seq, &rid);
            signed_row(i, "QUEUE_DEL", head(json!({"rid": h(&rid)})), &bytes)
        }
        84 => {
            let ld_id: Id = s.arr();
            let expires_bucket = s.u32();
            let (_, owner_pk) = s.ed25519();
            let token = s.arr();
            let blob_bytes = s.take(secmp_proto::sizes::LINK_BLOB_LEN);
            let (n, com_ct) = blob_bytes.split_at(secmp_proto::sizes::NONCE_LEN);
            let blob = LinkBlob::from_parts(n, com_ct).unwrap();
            let fields = LinkPutFields {
                ld_id: &ld_id,
                one_time: true,
                expires_bucket,
                owner_pk: &owner_pk,
                token: &token,
            };
            let bytes = signed::link_put(&sess_id, cmd_seq, &fields, &blob).unwrap();
            let v = json!({
                "ld_id": h(&ld_id), "one_time": 1, "expires_bucket": expires_bucket,
                "owner_pk": h(owner_pk.as_bytes()), "token": h(&token), "blob": h(&blob_bytes),
            });
            signed_row(i, "LINK_PUT", head(v), &bytes)
        }
        _ => {
            assert_eq!(i, 85, "row {i} is not a positive row");
            let ld_id: Id = s.arr();
            let bytes = signed::link_get_owner_status(&sess_id, cmd_seq, &ld_id);
            let v = json!({"ld_id": h(&ld_id), "mode": "owner-status"});
            signed_row(i, "LINK_GET", head(v), &bytes)
        }
    }
}
