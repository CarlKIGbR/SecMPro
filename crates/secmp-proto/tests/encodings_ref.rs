// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The decoders against the `encodings` vector file (`vectors/SCHEMA.md` §4.8, `SCHEMA-4.8-encodings.md`): every
//! positive row decodes and re-encodes to exactly its bytes (and a frame decodes to the named command); every
//! negative row is rejected with the crate's single error. The D.6 rows (`Signed/*`) are encode-only and are
//! checked by the vector generator (plan step 10), not here.
//!
//! Reads the reference file `vectors/ref/encodings.json` until the suite is frozen (plan step 10), then the
//! frozen `vectors/encodings.json`.

use serde_json::Value;

use secmp_proto::wire::cell::{
    AppMessage, BatchBody, Cell, Content, ControlBody, Fragment, FragmentPayload, HandshakeBody,
    HeaderV1, KeyChangeBody, ReceiptBody, RelayQueue, RouteDescriptor, RouteUpdateBody,
};
use secmp_proto::wire::frame::{CellrContext, Request, Response, opcode};
use secmp_proto::wire::hx::{HandshakeCell, HandshakeCellPlaintext, Inner, InnerCt, Outer};
use secmp_proto::wire::inv::{
    IksPublic, InvitationV1, LinkBlob, LinkDataV1, PrekeyBundle, Profile, RelayRef,
};
use secmp_proto::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord, RelayInfoV1};
use secmp_proto::{Decode, Encode, Error};

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// `v[key]`, which must exist.
fn at<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).expect(key)
}

/// `v[key]` as a string, which must exist.
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    at(v, key).as_str().expect(key)
}

/// Decode then re-encode.
fn again<T: Decode + Encode>(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    T::decode(bytes)?.encode()
}

/// The D.2 name of an opcode in a direction table.
fn name_of(table: &[(u8, &'static str)], op: u8) -> &'static str {
    table
        .iter()
        .find(|(o, _)| *o == op)
        .map_or("?", |(_, n)| *n)
}

/// The outcome of decoding and re-encoding one row: the re-encoding (or the error) and, for a frame, the D.2
/// name of the decoded command.
type Outcome = (Result<Vec<u8>, Error>, Option<&'static str>);

/// `structure` decoded from `bytes` and encoded again. `None`: no decoder for this structure name (a test error,
/// never counted as a rejection).
fn decode_encode(structure: &str, context: Option<&str>, bytes: &[u8]) -> Option<Outcome> {
    if structure.starts_with("Request/") {
        return Some(match Request::decode(bytes) {
            Ok(r) => (r.encode(), Some(name_of(&opcode::REQUESTS, r.cmd.op()))),
            Err(e) => (Err(e), None),
        });
    }
    if structure.starts_with("Response/") {
        let ctx = match context {
            Some("FETCH_MULTI") => CellrContext::FetchMulti,
            // FETCH, and every non-CELLR response (the context only matters for CELLR)
            _ => CellrContext::Fetch,
        };
        return Some(match Response::decode(bytes, ctx) {
            Ok(r) => (r.encode(), Some(name_of(&opcode::RESPONSES, r.cmd.op()))),
            Err(e) => (Err(e), None),
        });
    }
    let result = match structure {
        "Record/HELLO" => again::<Hello>(bytes),
        "Record/RELAYINFO" => again::<RelayInfoRecord>(bytes),
        "Record/HS1" => again::<Hs1>(bytes),
        "Record/HS2" => again::<Hs2>(bytes),
        "RelayInfoV1" => again::<RelayInfoV1>(bytes),
        "RelayRef" => again::<RelayRef>(bytes),
        "InvitationV1" => again::<InvitationV1>(bytes),
        "Profile" => again::<Profile>(bytes),
        "LinkDataV1" => again::<LinkDataV1>(bytes),
        "LinkBlob" => again::<LinkBlob>(bytes),
        "IKSPublic" => again::<IksPublic>(bytes),
        "PrekeyBundle" => again::<PrekeyBundle>(bytes),
        "Outer" => again::<Outer>(bytes),
        "inner_ct" => again::<InnerCt>(bytes),
        "Inner" => again::<Inner>(bytes),
        "HandshakeCell" => again::<HandshakeCell>(bytes),
        "HandshakeCellPlaintext" => again::<HandshakeCellPlaintext>(bytes),
        "Cell" => again::<Cell>(bytes),
        "HeaderV1" => again::<HeaderV1>(bytes),
        "Content" => again::<Content>(bytes),
        "AppMessage" => again::<AppMessage>(bytes),
        "BatchBody" => again::<BatchBody>(bytes),
        "Fragment" => again::<Fragment>(bytes),
        "FragmentPayload" => again::<FragmentPayload>(bytes),
        "RouteDescriptor" => again::<RouteDescriptor>(bytes),
        "RelayQueue" => again::<RelayQueue>(bytes),
        "RouteUpdateBody" => again::<RouteUpdateBody>(bytes),
        "HandshakeBody" => again::<HandshakeBody>(bytes),
        "KeyChangeBody" => again::<KeyChangeBody>(bytes),
        "ReceiptBody" => again::<ReceiptBody>(bytes),
        "ControlBody" => again::<ControlBody>(bytes),
        _ => return None,
    };
    Some((result, None))
}

fn vector_file() -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("encodings.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("encodings.json")
    };
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_row_of_the_encodings_file() {
    let doc = vector_file();
    assert_eq!(text(&doc, "suite"), "encodings");
    let cases = at(&doc, "cases").as_array().unwrap();
    let (mut positives, mut signed, mut negatives) = (0_usize, 0_usize, 0_usize);
    for case in cases {
        let id = text(case, "id");
        let inputs = at(case, "inputs");
        let structure = text(inputs, "structure");
        let context = inputs.get("context").and_then(Value::as_str);
        let op = text(case, "op");
        assert!(op == "encode" || op == "decode", "{id}: op {op}");
        if op == "encode" {
            if structure.starts_with("Signed/") {
                signed = signed.saturating_add(1);
                continue;
            }
            let bytes = unhex(text(at(case, "outputs"), "bytes"));
            let (again, name) =
                decode_encode(structure, context, &bytes).expect("a decoder for every structure");
            assert_eq!(again.as_deref(), Ok(&bytes[..]), "{id} {structure}");
            if let Some(name) = name {
                assert_eq!(
                    Some(name),
                    structure.split_once('/').map(|(_, n)| n),
                    "{id}: decoded as another command"
                );
            }
            positives = positives.saturating_add(1);
        } else {
            assert_eq!(text(case, "expect"), "reject", "{id}");
            let bytes = unhex(text(inputs, "bytes"));
            let (again, _) =
                decode_encode(structure, context, &bytes).expect("a decoder for every structure");
            assert_eq!(
                again.err(),
                Some(Error::Rejected),
                "{id} {structure} must be rejected"
            );
            negatives = negatives.saturating_add(1);
        }
    }
    assert_eq!(
        (positives, signed, negatives),
        (78, 7, 547),
        "rows: decodable positives, encode-only positives, negatives"
    );
}
