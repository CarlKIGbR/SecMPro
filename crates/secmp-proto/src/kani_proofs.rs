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
//!
//! M3 (plan step 9): the pure decisions of SecMP-TR decryption (`tr::select`, spec §7.4) — `tr_header_selection`
//! (the constant-time header-key selection equals the sequential pseudocode), `tr_skip_plan` (the bounds of
//! `skip_message_keys`) and `tr_eviction` (the bound on `skipped`). They run on the real `subtle::Choice` (re-exported
//! by `secmp-crypto`): its optimisation barrier is a volatile read, which Kani executes as a read, so nothing is
//! stubbed.

use secmp_crypto::Choice;

use crate::codec::{Decode, Encode, Reader, pad, unpad};
use crate::sizes::{CELL_LEN, FRAME_PLAINTEXT_LEN, HEADER_LEN};
use crate::tr::select::{self, MAX_FF, MAX_SKIPPED, Path, SKIP_WINDOW};
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
fn reencodes_to(encoded: crate::Result<crate::codec::Zeroizing<Vec<u8>>>, input: &[u8]) {
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

/// `tr_header_selection` covers every number of distinct skipped header keys `k` in `0..=TR_SKIPPED_KEYS`.
const TR_SKIPPED_KEYS: usize = 4;

fn choice(b: bool) -> Choice {
    Choice::from(u8::from(b))
}

/// Spec §7.4 steps 1–2 as written, sequentially: the reference `tr_header_selection` compares with.
/// `opened[i]`: the i-th distinct skipped header key (first-seen order) opened the header; `found[i]`: `(hk_i,
/// header.n)` is in `skipped`; `current`/`next`: `hk_r`/`nhk_r` opened the header.
fn sequential_path(opened: &[bool], found: &[bool], current: bool, next: bool) -> Path {
    for (o, f) in opened.iter().zip(found) {
        if *o {
            if *f {
                return Path::Skipped;
            }
            break;
        }
    }
    if current {
        Path::Chain
    } else if next {
        Path::Step
    } else {
        Path::Reject
    }
}

/// The constant-time header-key selection (plan D3): for every `k ≤ TR_SKIPPED_KEYS` distinct skipped header keys
/// and every combination of per-key results (opened, found), of `hk_r` and `nhk_r` opening, and of the lookup's value
/// when no skipped key opened (`RatchetState::open` then looks up the all-zero key with `n` = 0, which may match):
/// [`select::first_opened`] is one-hot on the lowest opened index (so the `conditional_assign` loop of `open` selects
/// exactly that key's header and key) and says whether any opened, and [`select::decide`] on the lookup of the
/// selected key equals the sequential pseudocode.
#[kani::proof]
#[kani::unwind(6)] // TR_SKIPPED_KEYS + 2
fn tr_header_selection() {
    let opened_all: [bool; TR_SKIPPED_KEYS] = kani::any();
    let found_all: [bool; TR_SKIPPED_KEYS] = kani::any();
    let k: usize = kani::any();
    kani::assume(k <= TR_SKIPPED_KEYS);
    let opened = opened_all.get(..k).unwrap_or_default();
    let found = found_all.get(..k).unwrap_or_default();
    let results: Vec<Choice> = opened.iter().map(|o| choice(*o)).collect();
    let (first, any) = select::first_opened(&results);
    assert!(first.len() == k);
    let lowest = opened.iter().position(|o| *o);
    for (i, f) in first.iter().enumerate() {
        assert!(bool::from(*f) == (Some(i) == lowest));
    }
    assert!(bool::from(any) == lowest.is_some());
    // the lookup of `open`: of the selected (first opened) key; arbitrary if none opened
    let mut found_first = Choice::from(0);
    for (f, x) in first.iter().zip(found) {
        found_first |= *f & choice(*x);
    }
    let spurious: bool = kani::any();
    found_first |= !any & choice(spurious);
    let current: bool = kani::any();
    let next: bool = kani::any();
    assert!(
        select::decide(any, found_first, choice(current), choice(next))
            == sequential_path(opened, found, current, next)
    );
}

/// `skip_message_keys(until)` on a chain at `n_r` (spec §7.4), for every `n_r` and `until`: [`select::skip_plan`]
/// rejects exactly when `until < n_r` or the gap exceeds `MAX_FF`; otherwise it derives `until − n_r` keys (the
/// position counter of `derive_skipped` reaches `until` without overflow), stores from `max(n_r, until −
/// SKIP_WINDOW)`, i.e. exactly the last `min(gap, SKIP_WINDOW)` positions, and a position `p` in `n_r .. until` is
/// stored iff `until − p ≤ SKIP_WINDOW`.
#[kani::proof]
fn tr_skip_plan() {
    let n_r: u32 = kani::any();
    let until: u32 = kani::any();
    let gap = until.checked_sub(n_r);
    match select::skip_plan(n_r, until) {
        Err(_) => assert!(gap.is_none_or(|g| g > MAX_FF)),
        Ok(plan) => {
            assert!(gap == Some(plan.steps) && plan.steps <= MAX_FF);
            assert!(n_r.checked_add(plan.steps) == Some(until));
            assert!(plan.store_from == until.saturating_sub(SKIP_WINDOW).max(n_r));
            assert!(n_r <= plan.store_from && plan.store_from <= until);
            let stored = until.checked_sub(plan.store_from);
            assert!(stored == Some(plan.steps.min(SKIP_WINDOW)));
            let p: u32 = kani::any();
            if n_r <= p && p < until {
                let distance = until.checked_sub(p);
                assert!((p >= plan.store_from) == distance.is_some_and(|d| d <= SKIP_WINDOW));
            }
        }
    }
}

/// The bound on `skipped` (spec §7.4 "evict earliest-inserted entries so |skipped| ≤ 2 × `SKIP_WINDOW`"), for every
/// length: [`select::evicted`] never exceeds the length (`drain(..evicted)` in `RatchetState::apply` stays in
/// bounds), leaves at most `MAX_SKIPPED` entries, evicts nothing up to `MAX_SKIPPED` and exactly `len − MAX_SKIPPED`
/// above. And the lengths `apply` produces — at most `MAX_SKIPPED` before, at most one entry removed (step 1), at
/// most `2 × SKIP_WINDOW` inserted (two `skip_message_keys` calls on a DH step, each storing at most `SKIP_WINDOW`,
/// `tr_skip_plan`) — are at most `2 × MAX_SKIPPED` and computed without overflow. Which entries leave is the front of
/// the insertion-ordered `VecDeque` (`drain(..n)`); the `tr` vector tr-0070 and the property tests check it.
#[kani::proof]
fn tr_eviction() {
    let len: usize = kani::any();
    let evicted = select::evicted(len);
    let kept = len.checked_sub(evicted);
    assert!(kept.is_some_and(|k| k <= MAX_SKIPPED));
    if len <= MAX_SKIPPED {
        assert!(evicted == 0);
    } else {
        assert!(len.checked_sub(MAX_SKIPPED) == Some(evicted));
        assert!(kept == Some(MAX_SKIPPED));
    }
    let window = usize::try_from(SKIP_WINDOW).unwrap_or(usize::MAX);
    let before: usize = kani::any();
    let removed: usize = kani::any();
    let added: usize = kani::any();
    kani::assume(before <= MAX_SKIPPED && removed <= 1 && removed <= before);
    kani::assume(added <= window.saturating_mul(2));
    let after = before
        .checked_sub(removed)
        .and_then(|b| b.checked_add(added));
    assert!(after.is_some_and(|a| a <= MAX_SKIPPED.saturating_mul(2)));
}

// ---- M4: SecMP-HX (spec §6.5, §6.6; ADR-044 (c)) --------------------------------------------------------------------

use crate::error::{Error, Result};
use crate::hx::responder::{Groups, MAX_PARTIAL_GROUPS, drive, insert};
use crate::prekeys::{OpkSecrets, PrekeyStore, SpkGeneration};
use crate::sizes::{
    HANDSHAKE_CELL_PT_LEN, HANDSHAKE_CHUNK_LEN, HANDSHAKE_CHUNKS, OUTER_PADDED_LEN,
};
use crate::wire::hx::{HandshakeCellPlaintext, Outer};

/// K1, a check of the chunking constants and their tiling — not a property of the initiator's split or the responder's
/// join, which it does not call (M4 review C-15, R-32): `HANDSHAKE_CHUNKS × HANDSHAKE_CHUNK_LEN` = 3 × 4006 = 12018
/// (§6.5); for every chunk index `i` < 3, `i · 4006 + 4006` does not overflow and does not exceed 12018; `as_chunks`
/// tiles a 12018-byte array exactly (no remainder); and for every byte index `j`, `(j / 4006) · 4006 + j % 4006 = j`
/// with `j / 4006` < 3 (Euclid's identity on these constants). The split and the join are exercised by the tests and
/// the vectors.
#[kani::proof]
fn kani_hx_chunk_bounds() {
    assert!(usize::from(HANDSHAKE_CHUNKS) * HANDSHAKE_CHUNK_LEN == OUTER_PADDED_LEN);
    let i: u8 = kani::any();
    kani::assume(i < HANDSHAKE_CHUNKS);
    let start = usize::from(i).checked_mul(HANDSHAKE_CHUNK_LEN);
    let end = start.and_then(|s| s.checked_add(HANDSHAKE_CHUNK_LEN));
    assert!(start.is_some() && end.is_some_and(|e| e <= OUTER_PADDED_LEN));
    let padded = [0_u8; OUTER_PADDED_LEN];
    let (chunks, rest) = padded.as_chunks::<HANDSHAKE_CHUNK_LEN>();
    assert!(chunks.len() == usize::from(HANDSHAKE_CHUNKS) && rest.is_empty());
    let j: usize = kani::any();
    kani::assume(j < OUTER_PADDED_LEN);
    let (chunk, offset) = (j / HANDSHAKE_CHUNK_LEN, j % HANDSHAKE_CHUNK_LEN);
    assert!(chunk < usize::from(HANDSHAKE_CHUNKS));
    assert!(chunk * HANDSHAKE_CHUNK_LEN + offset == j);
}

/// `Outer` (D.4) on every 12018-byte input and its neighbours, with the ISO/IEC 7816-4 scan stubbed by an
/// over-approximation (any proper prefix, or a rejection; `unpad` itself is proven by `padding`): the decoder never
/// panics, and accepts only an input of exactly 12018 bytes.
#[kani::proof]
#[kani::stub(crate::codec::unpad, crate::codec::kani_stubs::unpad)]
fn kani_outer_unpad_total() {
    let bytes: [u8; OUTER_PADDED_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= OUTER_PADDED_LEN + 1);
    let input = bytes.get(..len).unwrap_or_default();
    if Outer::decode(input).is_ok() {
        assert!(len == OUTER_PADDED_LEN);
    }
}

/// `kani_hx_grouping` bound (WEISUNG M4-3 fallback): at the production bound [`MAX_PARTIAL_GROUPS`] = 8 with 9 ids
/// and 10 inserts, Kani gave no result within 30 minutes, twice (M4 report §11). The same code runs here with 3
/// slots, 4 distinct ids (one more than the slots, so a new id with every slot held — eviction — is reachable) and at
/// most 6 inserts.
const GROUPING_SLOTS: usize = 3;
const GROUPING_IDS: usize = GROUPING_SLOTS + 1;
const GROUPING_STEPS: usize = 6;
const _: () = assert!(GROUPING_SLOTS < MAX_PARTIAL_GROUPS);

/// The slots of `groups` as values, oldest first: `(init_id, chunks)` of each held group.
fn slots<const N: usize>(groups: &Groups<u8, u8, N>) -> [Option<(u8, [Option<u8>; 3])>; N] {
    core::array::from_fn(|k| groups.get(k).map(|g| (g.init_id, g.chunks)))
}

/// The model's removal of entry `p` of the first `held` entries of `order`, the later ones moving down one place (an
/// element loop: with `copy_within`, i.e. `ptr::copy` over a symbolic count, Kani reported a counterexample that
/// the same inputs do not reproduce natively or under Kani with concrete values; M4 report §11).
fn drop_at(order: &mut [usize], p: usize, held: usize) {
    for j in p..held.saturating_sub(1) {
        order[j] = order[j + 1];
    }
}

/// The grouping of §6.5 with ADR-044 (c) over `N` slots, on every sequence of at most `steps` chunks
/// `(init_id, i, chunk_tag)` with `init_id` one of `IDS` distinct symbolic ids, `i` ≤ 2 and a symbolic tag, against
/// an independent model (the held ids in arrival order, and per id the first-seen tag of each `i`). A group that
/// completes is removed from the slots by the function `drive` removes it with (`Groups::remove`). After every
/// insert: the slots hold exactly the model's groups in arrival order, each with the model's chunks (at most one
/// group per id, at most 3 chunks, the first-seen tag per `i`), and at most `N` groups; `insert` answers with a
/// group exactly when the model has seen `i` = 0, 1 and 2 for that id, and that group carries the first-seen tags;
/// a duplicate `(init_id, i)`, identical or differing, leaves the slots unchanged; a new id with `N` groups held
/// evicts the model's oldest id (the one that arrived first, not the implementation's slot 0).
fn grouping<const N: usize, const IDS: usize>(steps: usize) {
    let ids: [u8; IDS] = kani::any();
    for a in 0..IDS {
        for b in 0..a {
            kani::assume(ids[a] != ids[b]);
        }
    }
    // the model: the held ids (indices into `ids`), oldest first, and per id the first-seen tag of each `i`
    let mut order = [0_usize; N];
    let mut held = 0_usize;
    let mut seen = [[None::<u8>; 3]; IDS];
    let mut groups: Groups<u8, u8, N> = Groups::new();
    for _ in 0..steps {
        let w: usize = kani::any();
        kani::assume(w < IDS);
        let i: usize = kani::any();
        kani::assume(i <= 2);
        let tag: u8 = kani::any();
        let id = ids[w];
        let before = slots(&groups);

        // the model's step
        let known = order[..held].contains(&w);
        let duplicate = known && seen[w][i].is_some();
        let mut evicted = None;
        if !known {
            if held == N {
                let oldest = order[0];
                seen[oldest] = [None; 3];
                drop_at(&mut order, 0, held);
                held -= 1;
                evicted = Some(ids[oldest]);
            }
            order[held] = w;
            held += 1;
        }
        if seen[w][i].is_none() {
            seen[w][i] = Some(tag);
        }
        let chunks = seen[w];
        let complete = chunks.iter().all(Option::is_some);

        // the implementation's step
        let done = insert(&mut groups, id, i, tag);
        assert!(done.is_some() == complete);
        if duplicate {
            assert!(slots(&groups) == before);
        }
        if let Some(e) = evicted {
            assert!(slots(&groups).iter().all(|s| s.is_none_or(|(x, _)| x != e)));
        }
        if let Some(at) = done {
            // the responder's next step (`drive`): the completed group leaves the slots
            let group = groups.remove_completed(at);
            assert!(group.is_some_and(|g| g.init_id == id && g.chunks == chunks));
            let p = order[..held].iter().position(|x| *x == w).unwrap_or(held);
            drop_at(&mut order, p, held);
            held -= 1;
            seen[w] = [None; 3];
        }

        // the slots are the model
        assert!(groups.len() == held && held <= N);
        let now = slots(&groups);
        for k in 0..N {
            let expected = (k < held).then(|| (ids[order[k]], seen[order[k]]));
            assert!(now[k] == expected);
        }
        assert!(
            now.iter()
                .filter(|s| s.is_some_and(|(x, _)| x == id))
                .count()
                <= 1
        );
    }
}

/// K3: [`grouping`] with [`GROUPING_SLOTS`] slots, [`GROUPING_IDS`] ids and up to [`GROUPING_STEPS`] inserts (the
/// bound and why it is not the production 8: [`GROUPING_SLOTS`]).
#[kani::proof]
#[kani::unwind(7)] // GROUPING_STEPS + 1; the other loops run over at most GROUPING_IDS or GROUPING_SLOTS
fn kani_hx_grouping() {
    let steps: usize = kani::any();
    kani::assume(steps <= GROUPING_STEPS);
    grouping::<GROUPING_SLOTS, GROUPING_IDS>(steps);
}

/// A prekey store without keys that keeps the contract of [`PrekeyStore::commit_accept`]: the OPK and the record are
/// removed together (`Ok`), or nothing changes (`Err(Rejected)`: either is absent; `Err(Unavailable)`: the commit
/// could not be made durable, M4 review C-12).
/// It counts the calls and keeps their arguments. (On the real `MemoryPrekeyStore`, which Kani runs since
/// `secmp-sys-mem` has a `cfg(kani)` heap backend, this harness gave no verdict in 30 minutes, with or without the
/// K4b stubs; K4b proves `commit_accept` on the real store. M4 report §11.2.)
struct ContractStore {
    opk_present: bool,
    record_present: bool,
    durable: bool,
    commits: u8,
    committed_with: Option<(u32, [u8; 16])>,
}

impl PrekeyStore for ContractStore {
    fn spk(&self, _spk_id: u32) -> Option<&SpkGeneration> {
        None
    }

    fn opk(&self, _opk_id: u32) -> Option<&OpkSecrets> {
        None
    }

    fn delete_opk(&mut self, _opk_id: u32) -> Result<()> {
        Err(Error::Rejected)
    }

    fn commit_accept(&mut self, opk_id: u32, ld_id: &[u8; 16]) -> Result<()> {
        self.commits = self.commits.saturating_add(1);
        self.committed_with = Some((opk_id, *ld_id));
        if !(self.opk_present && self.record_present) {
            Err(Error::Rejected)
        } else if self.durable {
            self.opk_present = false;
            self.record_present = false;
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
}

/// `kani_accept_opk_delete_only_on_success`: chunks per run (two complete groups fit).
const DRIVE_CHUNKS: usize = 6;

/// `drive` (the only caller of `commit_accept`; group bound 8, as in production) with the cryptographic steps of
/// §6.6 replaced by a nondeterministic outcome per step, over every sequence of at most 6 chunks of 3 init_ids,
/// every `opk_id`/`ld_id` and every store state (OPK and record present or not, commit durable or not): only
/// complete groups are processed; `commit_accept` is called (once, with the record's `opk_id` and `ld_id`) **if and
/// only if** a processed group passed every step, and no group is processed after that; every processing sees the
/// store untouched, so a rejected complete group leaves it as it was and a later group can still commit (the cover
/// property: a first group rejected, a group of another init_id committed); `Ok` ⇔ that commit succeeded, and then
/// the OPK and the record are gone; every `Err` leaves the store as it was; `Unavailable` comes from a step (then no
/// commit was attempted) or from the one commit, which could not be made durable (M4 review C-12).
#[kani::proof]
#[kani::unwind(10)] // DRIVE_CHUNKS + 1 items; the 8 slots; 4 steps
fn kani_accept_opk_delete_only_on_success() {
    let opk_present: bool = kani::any();
    let record_present: bool = kani::any();
    let mut store = ContractStore {
        opk_present,
        record_present,
        durable: kani::any(),
        commits: 0,
        committed_with: None,
    };
    let opk_id: u32 = kani::any();
    let ld_id: [u8; 16] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= DRIVE_CHUNKS);
    let items: [(u8, usize, ()); DRIVE_CHUNKS] = core::array::from_fn(|_| {
        let id: u8 = kani::any();
        kani::assume(id <= 2);
        let i: usize = kani::any();
        kani::assume(i < 3);
        (id, i, ())
    });
    // per call of `process`: the calls so far, the init_id of the first, the call that passed every step, and
    // whether a step was `Unavailable`
    let calls = core::cell::Cell::new(0_u8);
    let first_id = core::cell::Cell::new(None::<u8>);
    let accepted = core::cell::Cell::new(None::<(u8, u8)>);
    let unavailable = core::cell::Cell::new(false);
    let result = drive(
        items.into_iter().take(n),
        &mut store,
        opk_id,
        &ld_id,
        |group, store| {
            assert!(group.complete());
            assert!(accepted.get().is_none() && !unavailable.get());
            assert!(store.commits == 0);
            assert!(store.opk_present == opk_present && store.record_present == record_present);
            let call = calls.get();
            calls.set(call.saturating_add(1));
            if call == 0 {
                first_id.set(Some(group.init_id));
            }
            // the steps of §6.6 (outer decode, id checks, K_id, inner open, transcript, TR decrypt, Content checks):
            // each succeeds or fails, arbitrarily
            for _ in 0..4 {
                if kani::any() {
                    let e = if kani::any() {
                        Error::Rejected
                    } else {
                        unavailable.set(true);
                        Error::Unavailable
                    };
                    return Err(e);
                }
            }
            accepted.set(Some((call, group.init_id)));
            Ok(call)
        },
    );
    assert!(store.commits <= 1);
    assert!((store.commits == 1) == accepted.get().is_some());
    if let Some((o, l)) = store.committed_with {
        // the record's `opk_id` and `ld_id` (one symbolic index stands for every index: no 16-byte `memcmp` loop)
        assert!(o == opk_id);
        same_bytes(&l, &ld_id);
    }
    let ok = result.is_ok();
    match result {
        Ok(call) => {
            assert!(accepted.get().is_some_and(|(c, _)| c == call));
            assert!(opk_present && record_present && store.durable);
            assert!(!store.opk_present && !store.record_present);
        }
        Err(e) => {
            assert!(store.opk_present == opk_present && store.record_present == record_present);
            if e == Error::Unavailable {
                assert!(
                    (unavailable.get() && store.commits == 0)
                        || (store.commits == 1
                            && accepted.get().is_some()
                            && opk_present
                            && record_present
                            && !store.durable)
                );
            } else {
                assert!(e == Error::Rejected);
            }
        }
    }
    kani::cover!(
        ok && calls.get() == 2
            && accepted
                .get()
                .is_some_and(|(c, id)| c == 1 && first_id.get() != Some(id)),
        "a rejected complete group, then a group of another init_id commits"
    );
}

// ---- K4b: `commit_accept` on the real `MemoryPrekeyStore` (WEISUNG M4-8) --------------------------------------------
//
// The store's secrets live in `secmp-sys-mem` pages, which run on that crate's heap backend under Kani (`cfg(kani)`,
// the Miri backend). Four stubs, none in the store's logic: the OS randomness, zeroize's `asm!` barrier, zeroize's
// per-element wipe loop and the `memcmp` model of `[u8; 16] ==`. The last two are loops of 64 and 16 steps; as
// `#[kani::unwind]` bounds every loop of a harness, they would make CBMC unroll each loop over the store's vectors
// 64 or 16 times (no verdict in 30 minutes; M4 report §11.2).

use crate::prekeys::{InvitationRecord, MemoryPrekeyStore};
use crate::tr::OsEntropy;
use core::cmp::PartialEq; // named by the stub path below: Kani resolves neither the prelude nor `core::cmp::PartialEq`

/// The draws of [`kani_fill`] so far.
static KANI_DRAWS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);

/// `secmp-crypto`'s operating-system randomness under Kani, which does not execute `getentropy`/`getrandom`: draw
/// `d` (1, 2, …) is the byte `d` repeated (a draw of the store is at most 64 bytes, an ML-KEM seed). Different keys
/// get different bytes, so the harness can tell them apart by their first byte; the bytes are concrete because the
/// store never reads them.
fn kani_fill(buf: &mut [u8]) -> secmp_crypto::Result<()> {
    let d = KANI_DRAWS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let bytes = [d; 64];
    let src = bytes
        .get(..buf.len())
        .ok_or(secmp_crypto::Error::Unavailable)?;
    buf.copy_from_slice(src);
    Ok(())
}

/// zeroize's optimisation barrier is an inline `asm!` comment, which Kani does not execute.
fn kani_no_barrier<T: ?Sized>(_val: &T) {}

/// zeroize's wipe of a fixed-size array (one volatile write per element) as one assignment of the same zeros. The
/// wipe itself is checked by Miri and the `secmp-sys-mem` unit tests.
fn kani_zeroize_array<Z: Default + Copy, const N: usize>(a: &mut [Z; N]) {
    *a = [Z::default(); N];
}

/// Element `k` of `a` and `b` is equal (or both arrays are shorter).
fn kani_eq_at<T: PartialEq<U>, U>(a: &[T], b: &[U], k: usize) -> bool {
    match (a.get(k), b.get(k)) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

/// Array equality `[T; N] == [U; N]` without a loop: a 16-byte array as one `u128` comparison, any other array of
/// at most 16 elements as the conjunction of the element comparisons (asserted: a larger array fails the proof).
fn kani_array_eq<T: PartialEq<U> + 'static, U: 'static, const N: usize>(
    a: &[T; N],
    b: &[U; N],
) -> bool {
    let (x, y): (&dyn core::any::Any, &dyn core::any::Any) = (a, b);
    if let (Some(x), Some(y)) = (x.downcast_ref::<[u8; 16]>(), y.downcast_ref::<[u8; 16]>()) {
        return u128::from_ne_bytes(*x) == u128::from_ne_bytes(*y);
    }
    assert!(N <= 16);
    kani_eq_at(a, b, 0)
        & kani_eq_at(a, b, 1)
        & kani_eq_at(a, b, 2)
        & kani_eq_at(a, b, 3)
        & kani_eq_at(a, b, 4)
        & kani_eq_at(a, b, 5)
        & kani_eq_at(a, b, 6)
        & kani_eq_at(a, b, 7)
        & kani_eq_at(a, b, 8)
        & kani_eq_at(a, b, 9)
        & kani_eq_at(a, b, 10)
        & kani_eq_at(a, b, 11)
        & kani_eq_at(a, b, 12)
        & kani_eq_at(a, b, 13)
        & kani_eq_at(a, b, 14)
        & kani_eq_at(a, b, 15)
}

/// The first byte of a held OPK's `OPK_dh`: it names the key ([`kani_fill`]).
fn kani_opk_tag(store: &MemoryPrekeyStore, id: u32) -> Option<u8> {
    store.opk(id).map(|o| o.dh_secret().expose_secret()[0])
}

/// A held record's `spk_id`, `opk_id`, `expires` and the first byte of its link key.
fn kani_record_tag(store: &MemoryPrekeyStore, ld_id: &[u8; 16]) -> Option<(u32, u32, u64, u8)> {
    store
        .record(ld_id)
        .map(|r| (r.spk_id, r.opk_id, r.expires, r.link_key.expose_secret()[0]))
}

/// [`kani_commit_accept_atomic`] on one store: SPK generation 1 (arbitrary `created`), OPKs 1 and 2, the record
/// `[1; 16]` naming OPK `named` (arbitrary `expires`), then `delete_opk(delete)` unless `delete` is 0.
fn kani_commit_on(named: u32, delete: u32) {
    let mut store = MemoryPrekeyStore::starting_at(1, 1);
    assert!(store.create_spk(kani::any(), &mut OsEntropy) == Ok(1));
    assert!(store.issue_opk(&mut OsEntropy) == Ok(1));
    assert!(store.issue_opk(&mut OsEntropy) == Ok(2));
    let link_key = secmp_crypto::SecretBytes::from_slice(&[0xa5; 32]);
    assert!(link_key.is_ok());
    if let Ok(link_key) = link_key {
        let record = InvitationRecord {
            ld_id: [1; 16],
            link_key,
            spk_id: 1,
            opk_id: named,
            expires: kani::any(),
        };
        assert!(store.add_record(record).is_ok());
    }
    if delete != 0 {
        assert!(store.delete_opk(delete).is_ok());
    }

    let opk_id: u32 = kani::any();
    let ld_id: [u8; 16] = kani::any();
    // one arbitrary id of each kind stands for every id
    let (probe_opk, probe_ld): (u32, [u8; 16]) = (kani::any(), kani::any());
    let held = |k: u32| (k == 1 || k == 2) && k != delete;
    let opks_before = [kani_opk_tag(&store, 1), kani_opk_tag(&store, 2)];
    let record_before = kani_record_tag(&store, &[1; 16]);
    let spk_before = store.spk(1).map(|g| g.dh_secret().expose_secret()[0]);
    let probe_opk_before = kani_opk_tag(&store, probe_opk);
    let probe_ld_before = kani_record_tag(&store, &probe_ld);
    assert!(spk_before.is_some() && record_before.is_some());

    let result = store.commit_accept(opk_id, &ld_id);

    let ok = result.is_ok();
    // Ok <=> both are held and the record names exactly `opk_id` (R-64)
    assert!(ok == (held(opk_id) && ld_id == [1; 16] && opk_id == named));
    assert!(ok || result == Err(Error::Rejected));
    for (k, before) in (1..=2_u32).zip(opks_before) {
        assert!(before.is_some() == held(k));
        let after = kani_opk_tag(&store, k);
        if ok && k == opk_id {
            assert!(after.is_none());
        } else {
            assert!(after == before);
        }
    }
    let record_after = kani_record_tag(&store, &[1; 16]);
    assert!(if ok {
        record_after.is_none()
    } else {
        record_after == record_before
    });
    assert!(store.spk(1).map(|g| g.dh_secret().expose_secret()[0]) == spk_before);
    let opk_after = kani_opk_tag(&store, probe_opk);
    assert!(if ok && probe_opk == opk_id {
        opk_after.is_none()
    } else {
        opk_after == probe_opk_before
    });
    let ld_after = kani_record_tag(&store, &probe_ld);
    assert!(if ok && probe_ld == ld_id {
        ld_after.is_none()
    } else {
        ld_after == probe_ld_before
    });
    kani::cover!(ok, "a commit");
    // the store's drop is not part of the property
    core::mem::forget(store);
}

/// K4b: [`PrekeyStore::commit_accept`] of the real [`MemoryPrekeyStore`] is atomic, for every `(opk_id, ld_id)` on
/// two stores of SPK generation 1, OPKs 1 and 2 and one record: the record names OPK 1; or it names OPK 2, which is
/// then deleted (a record whose OPK is gone). No panic; `Ok` exactly when the OPK `opk_id` and the record `ld_id`
/// are both held, and then both are gone; otherwise `Err(Rejected)`. Every other OPK, the record if not consumed
/// and the SPK generation are unchanged (the first secret byte names the key, [`kani_fill`]), and an arbitrary probe
/// id of each kind — present after exactly as before unless it is the removed one, with the same tag — shows that
/// nothing else is removed, changed or added. Bound (WEISUNG M4-3 asked for every store of ≤ 2 OPKs and ≤ 2 records
/// with arbitrary ids; M4 report §11.2): no proof with a second record or a symbolic store finished in 9–30 minutes.
#[kani::proof]
#[kani::stub(secmp_crypto::rng::fill, kani_fill)]
#[kani::stub(zeroize::optimization_barrier, kani_no_barrier)]
#[kani::stub(<[u8; 64] as zeroize::Zeroize>::zeroize, kani_zeroize_array)]
#[kani::stub(<[u8; 16] as PartialEq<[u8; 16]>>::eq, kani_array_eq)]
#[kani::unwind(3)] // the vectors hold at most 2 entries
fn kani_commit_accept_atomic() {
    kani_commit_on(1, 0);
    kani_commit_on(2, 2);
}

/// `HandshakeCellPlaintext` (D.4) on every input of 4023…4025 bytes (the exact size and its neighbours): the decoder
/// never panics; an accepted input has exactly 4024 bytes with `i` ≤ 2 and `total` = 3, and re-encodes to itself.
#[kani::proof]
#[kani::unwind(4010)]
fn kani_cell_plaintext_decode_total() {
    let bytes: [u8; HANDSHAKE_CELL_PT_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len >= HANDSHAKE_CELL_PT_LEN - 1 && len <= HANDSHAKE_CELL_PT_LEN + 1);
    let input = bytes.get(..len).unwrap_or_default();
    if let Ok(p) = HandshakeCellPlaintext::decode(input) {
        assert!(len == HANDSHAKE_CELL_PT_LEN);
        assert!(p.i < HANDSHAKE_CHUNKS);
        assert!(input.get(17) == Some(&HANDSHAKE_CHUNKS));
        reencodes_to(p.encode(), input);
    }
}

// ---- M5: SecMP-LINK (spec §8.4, §9.2, §9.3; ADR-048) ----------------------------------------------------------------

use crate::link::cont::{BLOB_OFFSETS, Input, State, Step, step};
use crate::link::frame::{Link, MAX_PAYLOAD_LEN, kani_stubs::sealed_counter};
use crate::link::{Error as LinkError, LINK_MAX_FRAMES};
use crate::sizes::{BLOB_PART_LEN, CONT_DATA_LEN, FRAME_LEN, LINK_BLOB_LEN};

/// K-01 reaches the marker scan only within this many trailing bytes (a symbolic 4336-byte scan does not finish, see the
/// module documentation; `padding` proves the size-generic code for every size up to [`PAD_SIZES`]).
const SCAN_WINDOW: usize = 32;

/// K-01. The frame padding at the real size 4336 (spec §4.1, §8.4). (a) `pad` of any payload of any length n (symbolic
/// content): Ok exactly for n <= 4335 (`MAX_PAYLOAD_LEN`), the result is 4336 bytes, the marker is at index n, the
/// payload precedes it (one symbolic index) and every byte after it is zero (one symbolic index). (b) `unpad` of any
/// 4336-byte buffer whose last [`SCAN_WINDOW`] bytes are not all zero (the marker is then found within the window) is
/// total, and what it accepts re-encodes: `pad` of the returned fields is the buffer. (c) `unpad` inverts `pad` for every
/// payload that ends within the window (n >= 4336 - [`SCAN_WINDOW`]). Bound: the scan over a longer all-zero tail (the
/// scan loop is the size-generic code of `padding`, proven for every size up to 32; a symbolic 4336-byte scan did not
/// finish in 30 minutes, measured 2026-10-07, and in the M2 measurement).
#[kani::proof]
#[kani::unwind(40)] // the marker scan within the window, plus the window test
fn kani_frame_pad_total() {
    let bytes: [u8; FRAME_PLAINTEXT_LEN] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= FRAME_PLAINTEXT_LEN);
    let payload = bytes.get(..n).unwrap_or_default();
    // (a)
    match pad(payload, FRAME_PLAINTEXT_LEN) {
        Ok(p) => {
            assert!(n <= MAX_PAYLOAD_LEN);
            assert!(p.len() == FRAME_PLAINTEXT_LEN);
            assert!(p.get(n) == Some(&0x80));
            let j: usize = kani::any();
            kani::assume(j < n);
            assert!(p.get(j) == payload.get(j));
            let k: usize = kani::any();
            kani::assume(k > n && k < FRAME_PLAINTEXT_LEN);
            assert!(p.get(k) == Some(&0));
            // (c)
            if n >= FRAME_PLAINTEXT_LEN.saturating_sub(SCAN_WINDOW) {
                match unpad(&p, FRAME_PLAINTEXT_LEN) {
                    Ok(fields) => same_bytes(fields, payload),
                    Err(_) => assert!(false),
                }
            }
        }
        Err(_) => assert!(n == FRAME_PLAINTEXT_LEN),
    }
    // (b)
    let tail = bytes
        .get(FRAME_PLAINTEXT_LEN.saturating_sub(SCAN_WINDOW)..)
        .unwrap_or_default();
    kani::assume(tail.iter().any(|b| *b != 0));
    if let Ok(fields) = unpad(&bytes, FRAME_PLAINTEXT_LEN) {
        assert!(fields.len() < FRAME_PLAINTEXT_LEN);
        reencodes_to(pad(fields, FRAME_PLAINTEXT_LEN), &bytes);
    }
}

/// A 4352-byte unit with a symbolic counter record: the stand-in `Aead` opens it iff its record equals the expected
/// counter, so a fresh symbolic unit is accepted or rejected at the solver's choice (the covers show both occur).
fn symbolic_unit() -> Box<[u8; FRAME_LEN]> {
    Box::new(kani::any())
}

/// K-02. Strict `+1` on receive (spec §8.4): `Link::open` over three symbolic units (4352 bytes with a symbolic
/// counter record) from a symbolic receive counter. Stubbed: the AEAD (`link::frame::kani_stubs::Aead`: open succeeds
/// iff the nonce's counter equals the counter sealed into the unit) and `codec::unpad` (any proper prefix, or a
/// rejection, so a unit can open and still be rejected by the padding check). Per step: on success the unit's sealed
/// counter was the expected one and the receive counter is `checked_add(1)` of it (`None` after `u64::MAX`); on any
/// failure the receive counter is unchanged and the send counter never moves; `open_unit` alone never changes the
/// link. Bound: three receives from one symbolic counter (each step runs the same code); the wrong-length branch is
/// in `kani_link_counter_checked_add`.
#[kani::proof]
#[kani::stub(crate::codec::unpad, crate::codec::kani_stubs::unpad)]
#[kani::unwind(4)]
fn kani_link_counter_strict_plus_one() {
    let start: u64 = kani::any();
    let send: u64 = kani::any();
    let Some(mut link) = Link::kani_new(Some(send), Some(start), None) else {
        return;
    };
    let mut accepted = false;
    let mut rejected = false;
    for _ in 0..3 {
        let unit = symbolic_unit();
        let before = link.recv_counter();
        // a read-only open leaves the link as it was
        let _ = link.open_unit(unit.as_slice());
        assert!(link.recv_counter() == before);
        match link.open(unit.as_slice()) {
            Ok(opened) => {
                accepted = true;
                assert!(before == Some(opened.counter()));
                assert!(sealed_counter(unit.as_slice()) == before);
                assert!(link.recv_counter() == opened.counter().checked_add(1));
            }
            Err(_) => {
                rejected = true;
                assert!(link.recv_counter() == before);
            }
        }
        assert!(link.send_counter() == Some(send));
    }
    kani::cover!(accepted, "a unit opens and the counter advances");
    kani::cover!(rejected, "a unit is rejected and the counter stays");
    core::mem::forget(link);
}

/// K-03. Checked counters and the `LINK_MAX_FRAMES` check (spec §4.2, §8.4, ADR-048 OPEN-M5-03). Stubbed: as
/// `kani_link_counter_strict_plus_one` (the AEAD stand-in; `unpad`). (a) The client's `seal` over every pair of
/// counters (`None` = exhausted included) and the empty payload: `NewLinkRequired` exactly when either counter is at
/// or beyond [`LINK_MAX_FRAMES`], otherwise `CounterOverflow` for an exhausted send counter and success for the rest;
/// nothing moves on an error and success moves the send counter by `checked_add(1)`. (b) The relay (no limit) seals
/// at every send counter including `u64::MAX`, after which the counter is exhausted and the next seal is
/// `CounterOverflow` with the counter still exhausted (no wrap to 0); the same for opening at `u64::MAX`; a payload of
/// 4336 bytes is `PayloadTooLong` and moves nothing; a unit of another length is rejected without moving a counter.
#[kani::proof]
#[kani::stub(crate::codec::unpad, crate::codec::kani_stubs::unpad)]
fn kani_link_counter_checked_add() {
    // (a) the client
    let send: Option<u64> = kani::any();
    let recv: Option<u64> = kani::any();
    let Some(mut client) = Link::kani_new(send, recv, Some(LINK_MAX_FRAMES)) else {
        return;
    };
    let reached = |c: Option<u64>| c.is_some_and(|v| v >= LINK_MAX_FRAMES);
    match client.seal(&[]) {
        Err(LinkError::NewLinkRequired) => {
            assert!(reached(send) || reached(recv));
            assert!(client.send_counter() == send && client.recv_counter() == recv);
        }
        Err(LinkError::CounterOverflow) => {
            assert!(send.is_none() && !reached(recv));
            assert!(client.send_counter() == send && client.recv_counter() == recv);
        }
        Err(_) => assert!(false),
        Ok(frame) => {
            assert!(!reached(send) && !reached(recv));
            assert!(sealed_counter(frame.as_slice()) == send);
            assert!(client.send_counter() == send.and_then(|v| v.checked_add(1)));
            assert!(client.recv_counter() == recv);
        }
    }
    core::mem::forget(client);
    // (b) the relay at the end of the counter space
    let Some(mut relay) = Link::kani_new(Some(u64::MAX), Some(u64::MAX), None) else {
        return;
    };
    let too_long = [0_u8; MAX_PAYLOAD_LEN + 1];
    assert!(matches!(
        relay.seal(&too_long),
        Err(LinkError::PayloadTooLong)
    ));
    assert!(relay.send_counter() == Some(u64::MAX));
    assert!(relay.seal(&[]).is_ok());
    assert!(relay.send_counter().is_none());
    assert!(matches!(relay.seal(&[]), Err(LinkError::CounterOverflow)));
    assert!(relay.send_counter().is_none());
    // a unit sealed under the last counter opens once; afterwards the receive counter is exhausted
    let unit = symbolic_unit();
    if relay.open(unit.as_slice()).is_ok() {
        assert!(sealed_counter(unit.as_slice()) == Some(u64::MAX));
        assert!(relay.recv_counter().is_none());
    }
    if relay.recv_counter().is_none() {
        assert!(matches!(
            relay.open(unit.as_slice()),
            Err(LinkError::CounterOverflow)
        ));
        assert!(relay.recv_counter().is_none());
    }
    // a unit of another length is rejected without touching the counters
    let before = relay.recv_counter();
    if before.is_some() {
        assert!(matches!(
            relay.open(unit.get(..FRAME_LEN - 1).unwrap_or_default()),
            Err(LinkError::Rejected)
        ));
        assert!(relay.recv_counter() == before);
    }
    core::mem::forget(relay);
}

/// One frame the continuation harness feeds: `LINK_PUT` (a start), `CONT` with `idx` 0 ..= 3, or any other
/// request; `cmd_seq` is any `u32` (the dictated set {1, 2} is a subset).
fn symbolic_input() -> Input {
    let cmd_seq: u32 = kani::any();
    let kind: u8 = kani::any();
    match kind {
        0 => Input::Start { cmd_seq },
        1..=4 => Input::Cont {
            cmd_seq,
            idx: kind.saturating_sub(1),
        },
        _ => Input::Other,
    }
}

/// K-04 [SQ-27]. Continuation (spec §9.2, §9.3; ADR-048 (f)): over every sequence of up to 5 frames from the idle
/// state (each `LINK_PUT`, `CONT` with `idx` 0 ..= 3 or another request, any `cmd_seq`), [`step`] completes exactly on
/// `LINK_PUT(s)`, `CONT(s, 1)`, `CONT(s, 2)` in three consecutive frames that start in the idle state, and rejects every
/// other order: a rejection happens iff the state is pending and the frame is not the next `CONT` of the pending
/// `cmd_seq`, or the state is idle and the frame is a `CONT`. The sequence stops at the first rejection (the
/// assembler resets and the link closes). And the blob layout: the three parts start at 0, 4160, 8260 and tile 12360
/// = [`LINK_BLOB_LEN`] without gap or overlap. Bound: 5 frames (a complete message plus a frame before it and one
/// after); the transition has no history beyond its state.
#[kani::proof]
#[kani::unwind(7)]
fn kani_cont_assembly() {
    assert!(BLOB_OFFSETS.first() == Some(&0));
    assert!(BLOB_OFFSETS.get(1) == Some(&4160));
    assert!(BLOB_OFFSETS.get(2) == Some(&8260));
    assert!(BLOB_OFFSETS.get(1) == Some(&BLOB_PART_LEN));
    assert!(BLOB_OFFSETS.get(2) == Some(&(BLOB_PART_LEN + CONT_DATA_LEN)));
    assert!(BLOB_PART_LEN + 2 * CONT_DATA_LEN == 12_360);
    assert!(BLOB_PART_LEN + 2 * CONT_DATA_LEN == LINK_BLOB_LEN);
    let mut state = State::Idle;
    let mut history = [Input::Other; 5];
    let mut completed = false;
    for i in 0..5_usize {
        let input = symbolic_input();
        if let Some(slot) = history.get_mut(i) {
            *slot = input;
        }
        let expected_ok = match (state, input) {
            (State::Idle, Input::Cont { .. }) => false,
            (State::Idle, _) => true,
            (State::AwaitOne { cmd_seq }, Input::Cont { cmd_seq: s, idx }) => {
                s == cmd_seq && idx == 1
            }
            (State::AwaitTwo { cmd_seq }, Input::Cont { cmd_seq: s, idx }) => {
                s == cmd_seq && idx == 2
            }
            (_, _) => false,
        };
        let Some((next, taken)) = step(state, input) else {
            assert!(!expected_ok);
            return;
        };
        assert!(expected_ok);
        if taken == Step::Complete {
            completed = true;
            // exactly the three-frame message, started from idle
            let (a, b, c) = (
                i.checked_sub(2).and_then(|k| history.get(k)),
                i.checked_sub(1).and_then(|k| history.get(k)),
                history.get(i),
            );
            let ok = match (a, b, c) {
                (
                    Some(Input::Start { cmd_seq: s0 }),
                    Some(Input::Cont {
                        cmd_seq: s1,
                        idx: 1,
                    }),
                    Some(Input::Cont {
                        cmd_seq: s2,
                        idx: 2,
                    }),
                ) => s0 == s1 && s1 == s2,
                _ => false,
            };
            assert!(ok);
            assert!(next == State::Idle);
        }
        match (state, input) {
            (State::Idle, Input::Start { cmd_seq }) => {
                assert!(taken == Step::Began && next == State::AwaitOne { cmd_seq });
            }
            (State::Idle, Input::Other) => assert!(taken == Step::Single && next == State::Idle),
            (State::AwaitOne { cmd_seq }, _) => {
                assert!(taken == Step::Continued && next == State::AwaitTwo { cmd_seq });
            }
            (State::AwaitTwo { .. }, _) => assert!(taken == Step::Complete),
            (State::Idle, Input::Cont { .. }) => assert!(false),
        }
        state = next;
    }
    kani::cover!(completed, "a three-frame message completes");
}

/// K-08. Both D.2 frame-plaintext decoders over the same arbitrary plaintext of 4335, 4336 or 4337 bytes (the exact
/// size and its neighbours; every field string shorter than 4336 bytes through the `unpad` over-approximation of
/// `request_frame`/`response_frame`, with `RequestCmd::decode_fields` stubbed as in `request_frame`; the per-opcode
/// request harnesses and `response_frame` prove the field decoders): neither panics; each accepts only at exactly
/// 4336 bytes; an accepted request or response carries the `cmd_seq` of bytes 1 ..= 4 (the layout `op ‖ cmd_seq ‖
/// fields`); an accepted response has the opcode of byte 0, which is one of the seven response opcodes of D.2 and
/// no request opcode (so a request frame is never taken for a response), for both `CELLR` contexts.
#[kani::proof]
#[kani::stub(crate::codec::unpad, crate::codec::kani_stubs::unpad)]
#[kani::stub(
    crate::wire::frame::RequestCmd::decode_fields,
    crate::wire::frame::kani_stubs::request_decode_fields
)]
fn kani_q_frame_plaintext_exact_fit() {
    let bytes: [u8; FRAME_PLAINTEXT_LEN + 1] = kani::any();
    let len = frame_len();
    let input = bytes.get(..len).unwrap_or_default();
    let cmd_seq = bytes
        .get(1..5)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes);
    if let Ok(req) = Request::decode(input) {
        assert!(len == FRAME_PLAINTEXT_LEN);
        assert!(Some(req.cmd_seq) == cmd_seq);
    }
    let context = if kani::any() {
        CellrContext::Fetch
    } else {
        CellrContext::FetchMulti
    };
    if let Ok(resp) = Response::decode(input, context) {
        let op = resp.cmd.op();
        assert!(len == FRAME_PLAINTEXT_LEN);
        assert!(Some(resp.cmd_seq) == cmd_seq);
        assert!(bytes.first() == Some(&op));
        assert!(opcode::RESPONSES.iter().any(|(o, _)| *o == op));
        assert!(!opcode::REQUESTS.iter().any(|(o, _)| *o == op));
    }
}
