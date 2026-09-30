// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kani harnesses (docs/06 §4 "Model checking": the cell and frame parsers never panic and accept exact fits only;
//! docs/07 M2: `Cell`, `Frame`, `HeaderV1` and frame-plaintext parsing). Run by `cargo kani --package secmp-proto`
//! (ci-full step 9).
//!
//! Every harness decodes symbolic input, so a proof covers every byte string it allows: the decoder does not panic
//! (Kani checks every panic, arithmetic overflow and out-of-bounds access on the way) and accepts only the exact
//! size. `cell`, `header_v1_reencodes` and `padding` also prove that an accepted input re-encodes to itself (lengths
//! compared, then the bytes at one symbolic index, which stands for every index).
//!
//! The Frame (4352 B) is the AEAD seal of a padded 4336-byte plaintext (spec §8.3): parsing a frame is `unpad`, then
//! the command decoder of the direction. `padding` proves `pad`/`unpad` (size-generic code) for every size up to
//! [`PAD_SIZES`]. The frame harnesses decode 4335-, 4336- and 4337-byte plaintexts through
//! `codec::kani_stubs::unpad`, which over-approximates `unpad` (any proper prefix, or a rejection), so every field
//! string shorter than 4336 bytes is covered: no panic and exact fit at 4336 bytes. `response_frame` covers every
//! response opcode at once (and checks the decoded opcode). The request side is split, because CBMC does not prune
//! the other opcodes' arms of a symbolic opcode and the `FETCH_MULTI` loop over symbolic input then did not finish
//! in 7 minutes (measured 2026-09-29): `request_frame` proves the frame-level glue with the command decoder stubbed,
//! and one harness per request opcode proves `RequestCmd::decode_fields` with that opcode concrete (the decoded
//! command has that opcode). Unknown request and response opcodes are rejected for all 256 values by the unit test
//! `wire::frame::tests::reserved_and_foreign_opcodes_reject`. Bounds, each measured: the `unpad` scan (a symbolic
//! 4336-byte marker scan does not finish in CI time); `FETCH_MULTI` entry counts up to [`FETCH_MULTI_KANI`] and
//! above 32 (the entry loop runs the same code for each entry; counts up to 32 are covered by the `frames` property
//! test, the `proto_frames` fuzz target and the 32-entry vector row); the frames' re-encoding property (with it
//! CBMC's solver exceeded 7 minutes; covered by the same tests).
//!
//! Key and signature fields use `keys::kani_stubs` (a nondeterministic accept/reject in place of the `secmp-crypto`
//! check); X25519 fields keep the real low-order check (byte comparisons only). Harnesses with a loop whose bound
//! depends on the input carry `#[kani::unwind]`; Kani then also proves the bound sufficient (unwinding assertions).

use crate::codec::{Decode, Encode, Reader, pad, unpad};
use crate::sizes::{CELL_LEN, FRAME_PLAINTEXT_LEN, HEADER_LEN};
use crate::wire::cell::{Cell, HeaderV1};
use crate::wire::frame::{CellrContext, Request, RequestCmd, Response, opcode};

/// The padding harness covers every `size` in `0..=PAD_SIZES`.
const PAD_SIZES: usize = 32;

/// `FETCH_MULTI` entry counts covered by `request_fetch_multi`: 0 ..= this bound, and every count above 32.
const FETCH_MULTI_KANI: u8 = 8;

/// `a` and `b` are the same bytes: equal lengths, and equal at an arbitrary index.
fn same_bytes(a: &[u8], b: &[u8]) {
    assert!(a.len() == b.len());
    let j: usize = kani::any();
    kani::assume(j < a.len());
    assert!(a.get(j) == b.get(j));
}

/// An accepted value re-encodes to exactly its input.
fn reencodes_to(encoded: crate::Result<Vec<u8>>, input: &[u8]) {
    assert!(encoded.is_ok());
    if let Ok(e) = encoded {
        same_bytes(&e, input);
    }
}

/// `Cell` (D.5, opaque 4096 bytes): every input of 0…4097 bytes; accepted iff exactly 4096 bytes long.
#[kani::proof]
fn cell() {
    let bytes: [u8; CELL_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= CELL_LEN + 1);
    let input = bytes.get(..len).unwrap_or_default();
    match Cell::decode(input) {
        Ok(c) => {
            assert!(len == CELL_LEN);
            reencodes_to(c.encode(), input);
        }
        Err(_) => assert!(len != CELL_LEN),
    }
}

/// `HeaderV1` (D.5, 2314 bytes): every input of 0…2315 bytes; accepted only at exactly 2314 bytes with `ver` = 1
/// and `flags` = 0. The re-encoding property is `header_v1_reencodes` (one harness with both did not fit a CI
/// runner's memory: the runner was shut down at 54 M clauses, run 36642147335).
#[kani::proof]
#[kani::stub(
    crate::keys::MlKem768Ek::from_bytes,
    crate::keys::kani_stubs::mlkem768_ek
)]
fn header_v1() {
    let bytes: [u8; HEADER_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= HEADER_LEN + 1);
    let input = bytes.get(..len).unwrap_or_default();
    if HeaderV1::decode(input).is_ok() {
        assert!(len == HEADER_LEN);
        assert!(input.first() == Some(&1));
        assert!(input.get(1) == Some(&0));
    }
}

/// `HeaderV1` of exactly 2314 bytes (every other length is rejected, `header_v1`): an accepted input re-encodes to
/// itself.
#[kani::proof]
#[kani::stub(
    crate::keys::MlKem768Ek::from_bytes,
    crate::keys::kani_stubs::mlkem768_ek
)]
fn header_v1_reencodes() {
    let bytes: [u8; HEADER_LEN] = kani::any();
    if let Ok(h) = HeaderV1::decode(&bytes) {
        reencodes_to(h.encode(), &bytes);
    }
}

/// ISO/IEC 7816-4 padding (spec §4.1), for every `size` ≤ [`PAD_SIZES`] and every input of that size: whatever
/// `unpad` accepts is exactly `pad` of the fields it returns, and `pad` of any fields shorter than `size` is
/// accepted by `unpad` with exactly those fields (one padded form per field string).
#[kani::proof]
#[kani::unwind(34)] // the marker scan and the field compare: at most PAD_SIZES + 1 steps
fn padding() {
    let bytes: [u8; PAD_SIZES] = kani::any();
    let size: usize = kani::any();
    kani::assume(size <= PAD_SIZES);
    let input = bytes.get(..size).unwrap_or_default();
    if let Ok(fields) = unpad(input, size) {
        reencodes_to(pad(fields, size), input);
    }
    let n: usize = kani::any();
    kani::assume(n <= size);
    let fields = bytes.get(..n).unwrap_or_default();
    match pad(fields, size) {
        Ok(p) => {
            assert!(n < size);
            assert!(unpad(&p, size) == Ok(fields));
        }
        Err(_) => assert!(n == size),
    }
}

/// A frame plaintext length the harnesses try: one byte short, exact, or one byte long.
fn frame_len() -> usize {
    let len: usize = kani::any();
    kani::assume(len >= FRAME_PLAINTEXT_LEN.saturating_sub(1));
    kani::assume(len <= FRAME_PLAINTEXT_LEN.saturating_add(1));
    len
}

/// The frame-level glue of a request: plaintexts of 4335, 4336 or 4337 bytes, every opcode and `cmd_seq`, every
/// field string shorter than 4336 bytes, the command decoder stubbed (consumes any number of bytes, then accepts or
/// rejects): no panic; accepted only at exactly 4336 bytes.
#[kani::proof]
#[kani::stub(crate::codec::unpad, crate::codec::kani_stubs::unpad)]
#[kani::stub(
    crate::wire::frame::RequestCmd::decode_fields,
    crate::wire::frame::kani_stubs::request_decode_fields
)]
fn request_frame() {
    let bytes: [u8; FRAME_PLAINTEXT_LEN + 1] = kani::any();
    let len = frame_len();
    let input = bytes.get(..len).unwrap_or_default();
    if Request::decode(input).is_ok() {
        assert!(len == FRAME_PLAINTEXT_LEN);
    }
}

/// The command decoder of opcode `op` on every field string that fits a frame (after `op ‖ cmd_seq`): no panic; a
/// decoded command has opcode `op`.
fn request_fields(op: u8, count_bound: bool) {
    let bytes: [u8; FRAME_PLAINTEXT_LEN] = kani::any();
    if count_bound {
        // FETCH_MULTI: the entry count is the first field byte
        let count = bytes.first().copied().unwrap_or_default();
        kani::assume(count <= FETCH_MULTI_KANI || count > 32);
    }
    let n: usize = kani::any();
    kani::assume(n <= FRAME_PLAINTEXT_LEN.saturating_sub(6));
    let mut r = Reader::new(bytes.get(..n).unwrap_or_default());
    if let Ok(cmd) = RequestCmd::decode_fields(op, &mut r) {
        assert!(cmd.op() == op);
    }
}

/// One harness per request opcode, the opcode concrete (stubs: the Ed25519 key and signature checks).
macro_rules! request_harness {
    ($name:ident, $op:expr) => {
        #[kani::proof]
        #[kani::stub(
            crate::keys::Ed25519Pk::from_bytes,
            crate::keys::kani_stubs::ed25519_pk
        )]
        #[kani::stub(
            crate::keys::Ed25519Sig::from_bytes,
            crate::keys::kani_stubs::ed25519_sig
        )]
        #[kani::unwind(66)] // the 64-byte zero-signature compare of LINK_GET
        fn $name() {
            request_fields($op, false);
        }
    };
}

request_harness!(request_queue_new, opcode::QUEUE_NEW);
request_harness!(request_skey, opcode::SKEY);
request_harness!(request_send, opcode::SEND);
request_harness!(request_fetch, opcode::FETCH);
request_harness!(request_queue_del, opcode::QUEUE_DEL);
request_harness!(request_link_put, opcode::LINK_PUT);
request_harness!(request_link_get, opcode::LINK_GET);
request_harness!(request_ping, opcode::PING);
request_harness!(request_cont, opcode::CONT);

/// `FETCH_MULTI` as the other request harnesses, for an entry `count` of at most [`FETCH_MULTI_KANI`] or above
/// the maximum 32 (the rejection branch); see the module documentation for the bound.
#[kani::proof]
#[kani::stub(
    crate::keys::Ed25519Sig::from_bytes,
    crate::keys::kani_stubs::ed25519_sig
)]
#[kani::unwind(10)] // FETCH_MULTI_KANI + 2
fn request_fetch_multi() {
    request_fields(opcode::FETCH_MULTI, true);
}

/// A response frame plaintext of 4335, 4336 or 4337 bytes (every opcode, both `CELLR` contexts, every field string
/// shorter than 4336 bytes): no panic; accepted only at exactly 4336 bytes; a decoded command has the opcode it was
/// read from.
#[kani::proof]
#[kani::stub(crate::codec::unpad, crate::codec::kani_stubs::unpad)]
fn response_frame() {
    let bytes: [u8; FRAME_PLAINTEXT_LEN + 1] = kani::any();
    let context = if kani::any() {
        CellrContext::Fetch
    } else {
        CellrContext::FetchMulti
    };
    let len = frame_len();
    let input = bytes.get(..len).unwrap_or_default();
    if let Ok(r) = Response::decode(input, context) {
        assert!(len == FRAME_PLAINTEXT_LEN);
        assert!(bytes.first() == Some(&r.cmd.op()));
    }
}
