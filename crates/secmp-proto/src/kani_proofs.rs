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
use crate::hx::responder::{Groups, drive, insert};
use crate::prekeys::{OpkSecrets, PrekeyStore, SpkGeneration};
use crate::sizes::{
    HANDSHAKE_CELL_PT_LEN, HANDSHAKE_CHUNK_LEN, HANDSHAKE_CHUNKS, OUTER_PADDED_LEN,
};
use crate::wire::hx::{HandshakeCellPlaintext, Outer};

/// The three chunks of `Padded` (§6.5: 3 × 4006 = 12018): for every chunk index `i` < 3, `i · 4006 + 4006` does not
/// overflow and does not exceed 12018, the chunks tile `Padded` exactly (`as_chunks` leaves no remainder), and
/// splitting and joining is the identity at every byte index (the chunk `j / 4006` at offset `j % 4006` is byte `j`).
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

/// The grouping of §6.5 with ADR-044 (c) over the fixed-array `Groups` (no `Vec`), on every sequence of at most 4
/// chunks `(init_id, i)` over 3 init_ids with a symbolic `u8` payload and a bound of `N` = 2 partial groups (the
/// logic is the same for every `N`; the production bound `MAX_PARTIAL_GROUPS` = 8 is tested by
/// `group_partial_store_bound_8_evicts_oldest`): at most `N` groups are stored, never more than the chunks seen; at
/// most one group per init_id; `insert` answers with a group index exactly when that group is complete (chunks 0, 1
/// and 2); a duplicate `(init_id, i)` never replaces the stored chunk (first-seen wins); a chunk of a new init_id
/// with `N` groups held evicts exactly the oldest; an index of 3 or more changes nothing.
#[kani::proof]
#[kani::unwind(6)]
fn kani_hx_grouping() {
    const N: usize = 2;
    let mut groups: Groups<u8, u8, N> = Groups::new();
    let steps: usize = kani::any();
    kani::assume(steps <= 4);
    for step in 0..steps {
        let id: u8 = kani::any();
        kani::assume(id <= 2);
        let i: usize = kani::any();
        kani::assume(i <= 3);
        let value: u8 = kani::any();
        let find = |g: &Groups<u8, u8, N>, id: u8| {
            (0..g.len()).find(|k| g.get(*k).is_some_and(|x| x.init_id == id))
        };
        let known = find(&groups, id);
        let old = known
            .and_then(|k| groups.get(k))
            .and_then(|g| g.chunks.get(i).copied().flatten());
        let held = groups.len();
        let oldest = groups.get(0).map(|g| g.init_id);
        let done = insert(&mut groups, id, i, value);
        assert!(groups.len() <= N && groups.len() <= step + 1);
        if i >= 3 {
            assert!(done.is_none() && groups.len() == held);
            continue;
        }
        let at = find(&groups, id);
        assert!(at.is_some());
        let at = at.unwrap_or(0);
        let count = (0..groups.len())
            .filter(|k| groups.get(*k).is_some_and(|x| x.init_id == id))
            .count();
        assert!(count == 1);
        let group = groups.get(at);
        assert!(group.is_some_and(|g| done == g.complete().then_some(at)));
        let stored = group.and_then(|g| g.chunks.get(i).copied().flatten());
        assert!(stored == Some(old.unwrap_or(value)));
        if known.is_none() && held >= N {
            assert!(groups.len() == N);
            assert!(oldest.is_some_and(|o| find(&groups, o).is_none()));
        }
    }
}

/// A prekey store that only counts: no keys; `commit_accept` records the call and either commits (the OPK flag goes
/// false) or fails and keeps the OPK.
struct CountingStore {
    opk_present: bool,
    commits: u8,
    fail_commit: bool,
}

impl PrekeyStore for CountingStore {
    fn spk(&self, _spk_id: u32) -> Option<&SpkGeneration> {
        None
    }

    fn opk(&self, _opk_id: u32) -> Option<&OpkSecrets> {
        None
    }

    fn delete_opk(&mut self, _opk_id: u32) -> Result<()> {
        Err(Error::Rejected)
    }

    fn commit_accept(&mut self, _opk_id: u32, _ld_id: &[u8; 16]) -> Result<()> {
        self.commits = self.commits.saturating_add(1);
        if self.fail_commit {
            Err(Error::Rejected)
        } else {
            self.opk_present = false;
            Ok(())
        }
    }
}

/// `drive` (the only caller of `commit_accept`) with the cryptographic steps replaced by a nondeterministic outcome
/// per step, over every sequence of at most 4 chunks of 3 init_ids (group bound 8, as in production): the commit is
/// called at most once, only after the processing of a group succeeded; `Ok` leaves the OPK committed; every `Err`
/// leaves it in place (a failed commit keeps it by the store's contract); `Unavailable` never commits.
#[kani::proof]
#[kani::unwind(10)]
fn kani_accept_opk_delete_only_on_success() {
    let mut store = CountingStore {
        opk_present: true,
        commits: 0,
        fail_commit: kani::any(),
    };
    let n: usize = kani::any();
    kani::assume(n <= 4);
    let items: [(u8, usize, ()); 4] = core::array::from_fn(|_| {
        let id: u8 = kani::any();
        kani::assume(id <= 2);
        let i: usize = kani::any();
        kani::assume(i < 3);
        (id, i, ())
    });
    let processed_ok = core::cell::Cell::new(false);
    let result = drive(
        items.into_iter().take(n),
        &mut store,
        42,
        &[0; 16],
        |_group, _store| {
            // the steps of §6.6 (outer decode, id checks, K_id, inner open, transcript, TR decrypt, Content checks):
            // each succeeds or fails, arbitrarily
            for _ in 0..4 {
                if kani::any() {
                    return Err(if kani::any() {
                        Error::Rejected
                    } else {
                        Error::Unavailable
                    });
                }
            }
            processed_ok.set(true);
            Ok(())
        },
    );
    assert!(store.commits <= 1);
    if store.commits == 1 {
        assert!(processed_ok.get());
    }
    match result {
        Ok(()) => assert!(store.commits == 1 && !store.fail_commit && !store.opk_present),
        Err(e) => {
            assert!(store.opk_present);
            if e == Error::Unavailable {
                assert!(store.commits == 0);
            }
        }
    }
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
