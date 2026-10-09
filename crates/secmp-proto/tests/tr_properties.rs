// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! SecMP-TR property tests (docs/07 M3 "Property tests"; M3 plan step 8; docs/06 §4 "Property"), on generators
//! built from `rand` (ADR-040).
//!
//! **Model.** Two parties, A (initiator, `init_initiator_with`) and B (responder, `init_responder`), with `SK`,
//! `sb`, `SPK_dh_R` and `RPK_kem_R` drawn from the run's RNG; *all* of the ratchet's randomness comes from
//! `FixedEntropy` filled from the same RNG, so a seed reproduces a run exactly. A network holds each party's cells
//! in flight. Random events (weights in [`World::random_event`]): send a real Batch or a `content::dummy()` from
//! either party (from one without a sending chain — B before its first receive — the refusal is checked instead);
//! deliver an in-flight cell (the oldest, the newest or any: reordering); deliver an already delivered cell again
//! (duplicate / replay); drop a cell; a *gap* (`k` cells of the sender that are all dropped, `k` in
//! `1..=SMALL_GAP_MAX`, one gap in `MEDIUM_GAP_ONE_IN` of `MEDIUM_GAP`; see "Long gaps"); a tampered cell (a bit
//! flipped, truncated, extended, or reflected to its own sender); persist-and-reload a party. Scheduled once in two
//! of every [`BIG_GAP_PERIOD`] sessions ([`World::big_gap`]): a gap of `MAX_FF` positions probed on both sides of the
//! bound — the receiver meets a gap of `MAX_FF + d` (`d` in 1..=3; rejected), then exactly `MAX_FF` (accepted), and
//! then the rejected cell again (accepted: the gap has closed) — on `n` in one session and on `pn` (the first cell
//! of the sender's next chain after a DH step) in the other.
//!
//! Every delivery is predicted by a position-level model of spec §7.4 ([`Model`]) that tracks, per party, the
//! chains (A's `0, 1, 2, …`, B's `1, 2, …`), `n_s`, `n_r`, `pn` and `skipped` as `(chain, n)` in insertion order.
//! **The deliveries the test expects to succeed** are exactly the ones §7.4 guarantees, and every other one must be
//! rejected:
//! - (late) the cell's `(chain, n)` is in the modelled `skipped`: it was jumped over by an accepted later cell of its
//!   chain (or, for the old chain, by a step message's `pn`) while `until − n ≤ SKIP_WINDOW`, it has not been
//!   consumed, and it has not been evicted (earliest-inserted first, total ≤ `MAX_SKIPPED` = 2 × `SKIP_WINDOW`);
//! - (fresh) the cell is on the current receiving chain with `n_r ≤ n ≤ n_r + MAX_FF` (in order, or ahead);
//! - (step) the cell is on the peer's next chain, `n ≤ MAX_FF`, and — if there is a receiving chain —
//!   `pn − n_r ≤ MAX_FF`.
//!
//! The model is itself checked against the implementation after every event: `n_s`, `n_r`, `pn`, the presence of
//! the sending and receiving chains and the whole `skipped` list (header keys mapped back to chains) are read from
//! the `RatchetStateV1` encoding (layout documented in `tr/state.rs`), and `hk_s`/`hk_r` must be the header keys of
//! the modelled chains, a new sending chain's `hk_s` the receiver's `nhk_r`.
//!
//! **Properties** (checked after every event; the seed as `SECMP_PROPTEST_SEED=<n>`, the session and the event
//! index are in every assertion message): (1) no panic (each event runs under `catch_unwind`); (2) every message
//! key is used for sealing at most once across both parties and the whole run (`Sealed::message_key_digest_kat`,
//! all distinct), and every accepted decryption's key (`Plaintext::message_key_digest_kat`) is the sealing key of
//! that very cell, which is accepted at most once; (3) the decrypted padded Content equals the sent Content's
//! encoding; (4) every rejection is `Error::Rejected`, leaves `to_bytes()` byte-identical and draws no randomness;
//! an accepted cell draws the DH step's randomness exactly when it is a step; (5) after every event, both parties'
//! states encode, and every encoding not checked before decodes (`from_bytes`) and re-encodes to the same bytes
//! (an encoding identical to the one checked last is not decoded again: decoding is deterministic); the bytes
//! handed to `persist`/`commit` are the new state's encoding; a party continues with the decoded state at random;
//! (6) the model's prediction (above) is the outcome of every delivery, including the big gaps' probes.
//!
//! **Long gaps.** A gap of more than `ENCRYPTED_GAP_MAX` cells is applied to the sender's state directly —
//! `ck_s ← KDF_CK^k(ck_s)`, `n_s += k` in the persistence encoding, then `from_bytes` — which is byte-identical to
//! `k` encryptions whose cells are dropped (`encrypt` changes nothing else; test
//! [`advancing_the_sending_chain_equals_encrypting_and_dropping`]); encrypting 2^20 cells would not fit the budget.
//!
//! **Seeds and budget.** The master seed is [`DEFAULT_SEED`], or the decimal `u64` in `SECMP_PROPTEST_SEED` if set
//! and not empty (read by the shared `common/seed.rs`, as in `canonical.rs`); `SECMP_PROPTEST_CASES` (decimal)
//! replaces the number of sessions [`DEFAULT_CASES`]. The default run takes about a minute in the debug profile;
//! each of its two `MAX_FF` gaps costs 2^20 chain steps at the sender and 2^20 at the receiver (about 10 µs each in
//! debug). The seed and the counters are in every assertion message; the test reads no clock (docs/06 §4).

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use secmp_crypto::{MlKem768Dk, SecretBytes, X25519Secret, Zeroizing, kdf_ck};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::tr::content::dummy;
use secmp_proto::tr::{FixedEntropy, MAX_FF, MAX_SKIPPED, RatchetState, SKIP_WINDOW};
use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody, Content, ContentBody};
use secmp_proto::{Encode, Error};

/// The master seed when `SECMP_PROPTEST_SEED` is not set.
const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0003;
/// Sessions in the default run (`SECMP_PROPTEST_CASES` overrides).
const DEFAULT_CASES: u32 = 6;
/// Random events per session.
const EVENTS_PER_CASE: u32 = 400;
/// Most gaps are `1..=SMALL_GAP_MAX` cells (across the `SKIP_WINDOW` boundary).
const SMALL_GAP_MAX: u32 = 300;
/// The occasional long gap.
const MEDIUM_GAP: u32 = 10_000;
/// One gap in `MEDIUM_GAP_ONE_IN` is `MEDIUM_GAP` long.
const MEDIUM_GAP_ONE_IN: u32 = 10;
/// Gaps up to this length are encrypted cell by cell (every message key tracked); longer ones advance the sending
/// chain in the state encoding (module documentation, "Long gaps"; an `encrypt` costs about 1.7 ms in the debug
/// profile, a chain step about 10 µs).
const ENCRYPTED_GAP_MAX: u32 = 32;
/// `MAX_FF` gaps ([`World::big_gap`]): of every `BIG_GAP_PERIOD` consecutive sessions, the first carries one on `n`
/// and the second one on `pn`; the default run ([`DEFAULT_CASES`]) has exactly these two.
const BIG_GAP_PERIOD: u32 = 6;
/// A scheduled big gap runs at a random event index in this range (on `pn`: at the first index from there on at
/// which a direction allows it).
const BIG_GAP_EVENTS: core::ops::Range<u32> = 100..250;
/// A `decrypt` gets 128 bytes: a DH step's sending half draws an X25519 secret (32), an ML-KEM-768 seed (64) and the
/// `Encaps` randomness (32) (SCHEMA-4.9 order); every other outcome draws nothing. `init_initiator_with` draws the
/// same three.
const STEP_ENTROPY: usize = 128;
/// The header nonce of one `encrypt`.
const NONCE_ENTROPY: usize = 24;
/// After an event that changed a party's encoding, the party continues with probability 1/`RELOAD_ONE_IN` with the
/// state decoded from it (besides the explicit reload events).
const RELOAD_ONE_IN: u32 = 4;
/// Separates the per-session RNG streams.
const CASE_STREAM: u64 = 0x9e37_79b9_7f4a_7c15;

/// A decimal number from the environment variable `name`, if set and not empty (an unparsable value fails).
fn env_number<T: core::str::FromStr>(name: &str) -> Option<T>
where
    T::Err: core::fmt::Display,
{
    let raw = match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => return None,
        other => other.map_err(|e| format!("{name}: {e}")).unwrap(),
    };
    if raw.trim().is_empty() {
        return None;
    }
    Some(
        raw.trim()
            .parse()
            .map_err(|e| format!("{name}={raw:?} is not a decimal number: {e}"))
            .unwrap(),
    )
}

/// The one reader of `SECMP_PROPTEST_SEED` (M4 review R-93, TEST-SPEC-M5 X-07).
#[path = "common/seed.rs"]
mod seed;

/// The master seed of this run: `SECMP_PROPTEST_SEED` (decimal `u64`) if set and not empty, else [`DEFAULT_SEED`].
fn master_seed() -> u64 {
    seed::master_seed(DEFAULT_SEED)
}

/// A party.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Who {
    A,
    B,
}

impl Who {
    const fn peer(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// How §7.4 decrypts a cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Path {
    /// Step 1: `(hk, n)` found in `skipped` (at this index).
    Skipped(usize),
    /// The current receiving chain.
    Chain,
    /// A DH step onto the peer's next chain.
    Step,
}

/// Why §7.4 rejects a cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Why {
    /// Its position is behind the chain (or on an older chain) and not in `skipped`.
    Stale,
    /// A gap beyond `MAX_FF` (on `n`, or on `pn` for a step).
    TooFar,
    /// A chain the receiver cannot know yet (never happens: the model is wrong).
    Unknown,
}

/// The positions of one party's ratchet (spec §7.1) as §7.4 moves them.
#[derive(Default)]
struct Model {
    /// The index of the own sending chain (A: `0, 1, …`; B: `1, 2, …`).
    send_chain: Option<u32>,
    n_s: u32,
    pn: u32,
    /// The index of the peer's chain being received.
    recv_chain: Option<u32>,
    n_r: u32,
    /// `(chain, n)` of every stored skipped key, in insertion order.
    skipped: VecDeque<(u32, u32)>,
    /// The peer's first chain (A's is 0, B's is 1).
    peer_first: u32,
}

impl Model {
    /// The peer chain that the next header key `nhk_r` opens.
    fn next_recv(&self) -> u32 {
        self.recv_chain
            .map_or(self.peer_first, |c| c.checked_add(1).unwrap())
    }

    /// Spec §7.4 on positions: the outcome of delivering the cell at `(chain, n)` carrying `pn`.
    fn predict(&self, chain: u32, n: u32, pn: u32) -> Result<Path, Why> {
        // 1. skipped keys (the header keys of distinct chains are distinct)
        if let Some(at) = self.skipped.iter().position(|e| *e == (chain, n)) {
            return Ok(Path::Skipped(at));
        }
        // 2. hk_r: skip_message_keys(n) on the current chain
        if self.recv_chain == Some(chain) {
            let gap = n.checked_sub(self.n_r).ok_or(Why::Stale)?;
            return if gap > MAX_FF {
                Err(Why::TooFar)
            } else {
                Ok(Path::Chain)
            };
        }
        // nhk_r: skip_message_keys(pn) on the old chain (if any), DHRatchet, skip_message_keys(n) from 0
        if chain == self.next_recv() {
            if self.recv_chain.is_some() {
                let old_gap = pn.checked_sub(self.n_r).ok_or(Why::Stale)?;
                if old_gap > MAX_FF {
                    return Err(Why::TooFar);
                }
            }
            return if n > MAX_FF {
                Err(Why::TooFar)
            } else {
                Ok(Path::Step)
            };
        }
        if chain < self.next_recv() {
            Err(Why::Stale)
        } else {
            Err(Why::Unknown)
        }
    }

    /// `skipped.insert((chain, p))` for `max(from, until − SKIP_WINDOW) ≤ p < until`.
    fn store(&mut self, chain: u32, from: u32, until: u32) {
        for p in until.saturating_sub(SKIP_WINDOW).max(from)..until {
            self.skipped.push_back((chain, p));
        }
    }

    /// Apply an accepted cell; returns the number of evicted entries.
    fn accept(&mut self, path: Path, chain: u32, n: u32, pn: u32) -> usize {
        match path {
            Path::Skipped(at) => {
                assert!(self.skipped.remove(at).is_some());
                return 0;
            }
            Path::Chain => self.store(chain, self.n_r, n),
            Path::Step => {
                if let Some(old) = self.recv_chain {
                    self.store(old, self.n_r, pn);
                }
                self.store(chain, 0, n);
                self.recv_chain = Some(chain);
                // DHRatchet: pn = n_s; n_s = 0; a new sending chain
                self.pn = self.n_s;
                self.n_s = 0;
                self.send_chain = Some(self.send_chain.map_or(1, |c| c.checked_add(1).unwrap()));
            }
        }
        self.n_r = n.checked_add(1).unwrap();
        let evict = self.skipped.len().saturating_sub(MAX_SKIPPED);
        self.skipped.drain(..evict);
        evict
    }
}

/// The fields of a `RatchetStateV1` encoding (`tr/state.rs`) that the model predicts, and two offsets.
struct View {
    has_send: bool,
    has_recv: bool,
    /// Offset of the `ck_s` value.
    ck_s_at: Option<usize>,
    /// Offset of `n_s` (followed by `n_r`, `pn`).
    counters_at: usize,
    n_s: u32,
    n_r: u32,
    pn: u32,
    /// `(hk, n)` of every skipped entry, in order.
    skipped: Vec<([u8; 32], u32)>,
}

/// A cursor over an encoding.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let end = self.at.checked_add(n).unwrap();
        let out = self.bytes.get(self.at..end).unwrap();
        self.at = end;
        out
    }

    /// `opt(x)`: the offset of `x` if present.
    fn opt(&mut self, n: usize) -> Option<usize> {
        let flag = self.take(1).first().copied().unwrap();
        assert!(flag <= 1, "presence byte");
        if flag == 1 {
            let at = self.at;
            self.take(n);
            Some(at)
        } else {
            None
        }
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
}

/// Parse `RatchetStateV1`: `fmt ‖ sb ‖ rk ‖ dh_s.sk ‖ opt(dh_r) ‖ kem_s.seed ‖ opt(kem_r) ‖ opt(last_ct_r) ‖
/// opt(ct_s) ‖ opt(ck_s) ‖ opt(ck_r) ‖ opt(hk_s) ‖ opt(hk_r) ‖ opt(nhk_s) ‖ opt(nhk_r) ‖ n_s ‖ n_r ‖ pn ‖ count u16
/// ‖ {hk ‖ n ‖ mk} × count`.
fn view(bytes: &[u8]) -> View {
    let mut c = Cursor { bytes, at: 0 };
    assert_eq!(c.take(1), [1], "format byte");
    c.take(96); // sb, rk, dh_s.sk
    c.opt(32); // dh_r
    c.take(64); // kem_s seed
    c.opt(1184); // kem_r
    c.opt(1088); // last_ct_r
    c.opt(1088); // ct_s
    let ck_s_at = c.opt(32);
    let ck_r = c.opt(32);
    for _ in 0..4 {
        c.opt(32); // hk_s, hk_r, nhk_s, nhk_r
    }
    let counters_at = c.at;
    let (n_s, n_r, pn) = (c.u32(), c.u32(), c.u32());
    let count = u16::from_be_bytes(c.take(2).try_into().unwrap());
    let skipped = (0..count)
        .map(|_| {
            let hk: [u8; 32] = c.take(32).try_into().unwrap();
            let n = c.u32();
            c.take(32); // mk
            (hk, n)
        })
        .collect();
    assert_eq!(c.at, bytes.len(), "RatchetStateV1 fully consumed");
    View {
        has_send: ck_s_at.is_some(),
        has_recv: ck_r.is_some(),
        ck_s_at,
        counters_at,
        n_s,
        n_r,
        pn,
        skipped,
    }
}

/// The state after `k` encryptions whose cells are all dropped: `ck_s ← KDF_CK^k(ck_s)`, `n_s += k` (§7.3 changes
/// nothing else), applied to the encoding and decoded.
fn advance_sending_chain(state: &RatchetState, k: u32) -> RatchetState {
    let mut bytes = state.to_bytes().unwrap();
    let v = view(&bytes);
    let at = v.ck_s_at.unwrap();
    let end = at.checked_add(32).unwrap();
    let mut ck = SecretBytes::<32>::from_slice(bytes.get(at..end).unwrap()).unwrap();
    for _ in 0..k {
        ck = kdf_ck(&ck).unwrap().0;
    }
    bytes
        .get_mut(at..end)
        .unwrap()
        .copy_from_slice(ck.expose_secret());
    let n_s_end = v.counters_at.checked_add(4).unwrap();
    bytes
        .get_mut(v.counters_at..n_s_end)
        .unwrap()
        .copy_from_slice(&v.n_s.checked_add(k).unwrap().to_be_bytes());
    RatchetState::from_bytes(&bytes).unwrap()
}

/// A cell sent in the current session.
struct SentCell {
    from: Who,
    chain: u32,
    n: u32,
    pn: u32,
    /// SHA-256 of its message key.
    mk: [u8; 32],
    /// The padded Content it carries.
    padded: Zeroizing<Vec<u8>>,
    bytes: Vec<u8>,
    accepted: bool,
    delivered: bool,
}

struct Party {
    state: Option<RatchetState>,
    model: Model,
    /// Ids of this party's cells in flight, in send order.
    in_flight: Vec<usize>,
    /// Ids of this party's cells delivered at least once.
    delivered: Vec<usize>,
    /// The application sequence of real messages.
    seq: u64,
    /// The encoding that passed the round trip last (empty: none yet).
    checked: Zeroizing<Vec<u8>>,
}

impl Party {
    fn new(state: RatchetState, model: Model) -> Self {
        Self {
            state: Some(state),
            model,
            in_flight: Vec::new(),
            delivered: Vec::new(),
            seq: 0,
            checked: Zeroizing::new(Vec::new()),
        }
    }
}

/// Counters of the run (reported; the non-vacuity checks use them).
#[derive(Default, Debug)]
struct Stats {
    events: u64,
    sealed: u64,
    gap_cells_encrypted: u64,
    gap_positions_fast: u64,
    deliveries: u64,
    accepted_in_order: u64,
    accepted_ahead: u64,
    accepted_step: u64,
    accepted_late: u64,
    rejected_replay: u64,
    rejected_stale: u64,
    rejected_too_far: u64,
    rejected_tampered: u64,
    refused_encrypt: u64,
    reloads: u64,
    round_trips: u64,
    evicted: u64,
    max_skipped: usize,
    max_in_flight: usize,
    /// Scheduled `MAX_FF` gaps (each: rejected at `MAX_FF + d`, accepted at `MAX_FF`), on `n` and on `pn`.
    big_gaps: u64,
    big_gaps_on_n: u64,
    big_gaps_on_pn: u64,
}

struct World {
    seed: u64,
    case: u32,
    event: u32,
    what: String,
    rng: StdRng,
    a: Party,
    b: Party,
    cells: Vec<SentCell>,
    /// Every message key digest used for sealing, across both parties and the whole run.
    sealed: HashSet<[u8; 32]>,
    /// Header key → (owner, chain) and back, for the current session.
    hk_chain: HashMap<[u8; 32], (Who, u32)>,
    chain_hk: HashMap<(Who, u32), [u8; 32]>,
    stats: Stats,
}

fn must<T>(r: Result<T, Error>, ctx: &str) -> T {
    assert!(r.is_ok(), "{ctx}: {:?}", r.as_ref().err());
    r.unwrap()
}

impl World {
    fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let (a, b) = Self::session(&mut rng);
        Self {
            seed,
            case: 0,
            event: 0,
            what: String::new(),
            rng,
            a,
            b,
            cells: Vec::new(),
            sealed: HashSet::new(),
            hk_chain: HashMap::new(),
            chain_hk: HashMap::new(),
            stats: Stats::default(),
        }
    }

    /// `(A, B)` of a fresh session (spec §7.2) with every key and all randomness from `rng`.
    fn session(rng: &mut StdRng) -> (Party, Party) {
        let mut bytes = |n: usize| {
            let mut v = vec![0_u8; n];
            rng.fill(v.as_mut_slice());
            v
        };
        let sk = SecretBytes::<32>::from_slice(&bytes(32)).unwrap();
        let sb: [u8; 32] = bytes(32).try_into().unwrap();
        let spk = X25519Secret::from_bytes(&bytes(32)).unwrap();
        let rpk = MlKem768Dk::from_seed(&bytes(64)).unwrap();
        let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes()).unwrap();
        let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).unwrap();
        let mut e = FixedEntropy::new(&bytes(STEP_ENTROPY));
        let a = RatchetState::init_initiator_with(&sk, &sb, &spk_pub, &rpk_ek, &mut e).unwrap();
        assert_eq!(e.remaining(), 0, "init_initiator draws dh_s, kem_s, m");
        let b = RatchetState::init_responder(&sk, &sb, spk, rpk).unwrap();
        let a_model = Model {
            send_chain: Some(0),
            peer_first: 1,
            ..Model::default()
        };
        (Party::new(a, a_model), Party::new(b, Model::default()))
    }

    fn start_case(&mut self, case: u32) {
        self.case = case;
        self.event = 0;
        "init".clone_into(&mut self.what);
        self.rng = StdRng::seed_from_u64(self.seed ^ u64::from(case).wrapping_mul(CASE_STREAM));
        let (a, b) = Self::session(&mut self.rng);
        self.a = a;
        self.b = b;
        self.cells.clear();
        self.hk_chain.clear();
        self.chain_hk.clear();
        self.record_send_chain(Who::A);
    }

    /// The prefix of every assertion message.
    fn ctx(&self) -> String {
        format!(
            "case {} event {} [{}] (SECMP_PROPTEST_SEED={})",
            self.case, self.event, self.what, self.seed
        )
    }

    const fn party(&self, who: Who) -> &Party {
        match who {
            Who::A => &self.a,
            Who::B => &self.b,
        }
    }

    const fn party_mut(&mut self, who: Who) -> &mut Party {
        match who {
            Who::A => &mut self.a,
            Who::B => &mut self.b,
        }
    }

    fn state(&self, who: Who) -> &RatchetState {
        self.party(who).state.as_ref().unwrap()
    }

    fn take_state(&mut self, who: Who) -> RatchetState {
        self.party_mut(who).state.take().unwrap()
    }

    fn put_state(&mut self, who: Who, state: RatchetState) {
        self.party_mut(who).state = Some(state);
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0_u8; n];
        self.rng.fill(v.as_mut_slice());
        v
    }

    fn one_in(&mut self, n: u32) -> bool {
        self.rng.random_ratio(1, n)
    }

    /// A uniformly chosen element of `v` (which is not empty).
    fn pick(&mut self, v: &[usize]) -> (usize, usize) {
        let i = self.rng.random_range(0..v.len());
        (i, *v.get(i).unwrap())
    }

    /// Record the header key of `who`'s (new) sending chain; it must be the peer's `nhk_r` (spec §7.2, §7.4) and
    /// differ from every header key so far.
    fn record_send_chain(&mut self, who: Who) {
        let ctx = self.ctx();
        let chain = self.party(who).model.send_chain.unwrap();
        let hk = *self.state(who).hk_s_kat().unwrap().expose_secret();
        let peer_next = self.state(who.peer()).receiving_header_keys_kat().1;
        assert_eq!(
            peer_next.map(|k| *k.expose_secret()),
            Some(hk),
            "{ctx}: {who:?}'s chain {chain} is opened by the peer's nhk_r"
        );
        assert!(
            self.hk_chain.insert(hk, (who, chain)).is_none(),
            "{ctx}: header keys are distinct"
        );
        self.chain_hk.insert((who, chain), hk);
    }

    /// A random real Content (a Batch of 1–3 messages) with the next application sequence number.
    fn real_content(&mut self, from: Who) -> Content {
        let count = self.rng.random_range(1..=3_usize);
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.rng.random_range(0..=500_usize);
            let kind_at = self.rng.random_range(0..AppKind::ALL.len());
            messages.push(AppMessage {
                msg_id: self.bytes(16).try_into().unwrap(),
                kind: AppKind::ALL.get(kind_at).copied().unwrap(),
                expire_after: self.rng.random(),
                payload: Zeroizing::new(self.bytes(len)),
            });
        }
        let party = self.party_mut(from);
        party.seq = party.seq.checked_add(1).unwrap();
        let seq = party.seq;
        Content {
            seq,
            ts: self.rng.random(),
            body: ContentBody::Batch(BatchBody { messages }),
        }
    }

    /// `encrypt` from `from` (which has a sending chain): checks the nonce use, the message key's uniqueness and the
    /// persisted bytes; advances the model. Returns the cell, its position and its key digest.
    fn encrypt(&mut self, from: Who, content: &Content) -> (Vec<u8>, u32, u32, u32, [u8; 32]) {
        let ctx = self.ctx();
        let nonce = self.bytes(NONCE_ENTROPY);
        let state = self.take_state(from);
        let mut e = FixedEntropy::new(&nonce);
        let sealed = must(
            state.encrypt_with(content, &mut e).map_err(|r| r.error()),
            &ctx,
        );
        assert_eq!(e.remaining(), 0, "{ctx}: encrypt draws one nonce");
        let mk = sealed.message_key_digest_kat();
        assert!(
            self.sealed.insert(mk),
            "{ctx}: a message key was used for sealing twice"
        );
        self.stats.sealed = self.stats.sealed.checked_add(1).unwrap();
        let mut persisted = Zeroizing::new(Vec::new());
        let (state, cell) = sealed
            .persist(|b| {
                persisted.extend_from_slice(b);
                Ok::<(), ()>(())
            })
            .unwrap();
        assert_eq!(
            *persisted,
            *must(state.to_bytes(), &ctx),
            "{ctx}: persist-before-send hands out the new state"
        );
        self.put_state(from, state);
        let m = &mut self.party_mut(from).model;
        let (chain, n, pn) = (m.send_chain.unwrap(), m.n_s, m.pn);
        m.n_s = m.n_s.checked_add(1).unwrap();
        (cell.as_bytes().to_vec(), chain, n, pn, mk)
    }

    /// Send a real or dummy Content from `from`; returns the id of the cell (now in flight). From a party without
    /// a sending chain the refusal is checked and the other party sends instead.
    fn send(&mut self, from: Who, real: bool) -> usize {
        let from = if self.party(from).model.send_chain.is_some() {
            from
        } else {
            self.check_refused_encrypt(from);
            from.peer()
        };
        let content = if real {
            self.real_content(from)
        } else {
            dummy()
        };
        let padded = must(content.encode(), &self.ctx());
        let (bytes, chain, n, pn, mk) = self.encrypt(from, &content);
        let id = self.cells.len();
        self.cells.push(SentCell {
            from,
            chain,
            n,
            pn,
            mk,
            padded,
            bytes,
            accepted: false,
            delivered: false,
        });
        let party = self.party_mut(from);
        party.in_flight.push(id);
        let in_flight = party.in_flight.len();
        self.stats.max_in_flight = self.stats.max_in_flight.max(in_flight);
        id
    }

    /// A party without a sending chain cannot encrypt: `Rejected`, state unchanged, no randomness drawn.
    fn check_refused_encrypt(&mut self, who: Who) {
        let ctx = self.ctx();
        let nonce = self.bytes(NONCE_ENTROPY);
        let state = self.take_state(who);
        let before = must(state.to_bytes(), &ctx);
        let mut e = FixedEntropy::new(&nonce);
        let refused = state.encrypt_with(&dummy(), &mut e);
        assert!(refused.is_err(), "{ctx}: encrypt without a sending chain");
        let refused = refused.err().unwrap();
        assert_eq!(refused.error(), Error::Rejected, "{ctx}");
        let state = refused.into_state();
        assert_eq!(*must(state.to_bytes(), &ctx), *before, "{ctx}: unchanged");
        assert_eq!(e.remaining(), NONCE_ENTROPY, "{ctx}: no randomness drawn");
        self.put_state(who, state);
        self.stats.refused_encrypt = self.stats.refused_encrypt.checked_add(1).unwrap();
    }

    /// `decrypt` at `to`. Accepted: the padded plaintext, its key digest and the unused randomness, after checking
    /// the committed bytes. Rejected (`None`): checks the uniform error, the unchanged state and that no randomness
    /// was drawn.
    fn decrypt(&mut self, to: Who, cell: &[u8]) -> Option<(Zeroizing<Vec<u8>>, [u8; 32], usize)> {
        let ctx = self.ctx();
        let randomness = self.bytes(STEP_ENTROPY);
        let state = self.take_state(to);
        let before = must(state.to_bytes(), &ctx);
        let mut e = FixedEntropy::new(&randomness);
        match state.decrypt_with(cell, &mut e) {
            Ok(opened) => {
                let padded = Zeroizing::new(opened.plaintext().as_bytes().to_vec());
                let mk = opened.plaintext().message_key_digest_kat();
                let mut committed = Zeroizing::new(Vec::new());
                let (state, plaintext) = opened
                    .commit(|b| {
                        committed.extend_from_slice(b);
                        Ok::<(), ()>(())
                    })
                    .unwrap();
                assert_eq!(plaintext.message_key_digest_kat(), mk, "{ctx}");
                assert_eq!(
                    *committed,
                    *must(state.to_bytes(), &ctx),
                    "{ctx}: persist-before-ack hands out the new state"
                );
                self.put_state(to, state);
                Some((padded, mk, e.remaining()))
            }
            Err(refused) => {
                assert_eq!(refused.error(), Error::Rejected, "{ctx}: the uniform error");
                let state = refused.into_state();
                assert_eq!(
                    *must(state.to_bytes(), &ctx),
                    *before,
                    "{ctx}: a rejection leaves the state byte-identical"
                );
                assert_eq!(
                    e.remaining(),
                    STEP_ENTROPY,
                    "{ctx}: a rejection draws no randomness"
                );
                self.put_state(to, state);
                None
            }
        }
    }

    /// Deliver cell `id` to its recipient: the outcome must be the model's prediction, and an accepted cell must
    /// yield its own message key (once) and its own Content.
    fn deliver(&mut self, id: usize) -> bool {
        let cell = self.cells.get(id).unwrap();
        let (from, chain, n, pn) = (cell.from, cell.chain, cell.n, cell.pn);
        let (was_accepted, bytes) = (cell.accepted, cell.bytes.clone());
        let to = from.peer();
        self.what = format!(
            "deliver {from:?}→{to:?} cell {id} (chain {chain}, n {n}, pn {pn}){}",
            if cell.delivered { " again" } else { "" }
        );
        let m = &self.party(to).model;
        let note = format!(
            "{}: receiver chain {:?} n_r {} next {} |skipped| {}",
            self.ctx(),
            m.recv_chain,
            m.n_r,
            m.next_recv(),
            m.skipped.len()
        );
        let predicted = m.predict(chain, n, pn);
        assert_ne!(predicted, Err(Why::Unknown), "{note}");
        let outcome = self.decrypt(to, &bytes);
        self.stats.deliveries = self.stats.deliveries.checked_add(1).unwrap();
        let cell = self.cells.get_mut(id).unwrap();
        if !cell.delivered {
            cell.delivered = true;
            self.party_mut(from).delivered.push(id);
        }
        assert_eq!(
            predicted.is_ok(),
            outcome.is_some(),
            "{note}: predicted {predicted:?}, accepted {}",
            outcome.is_some()
        );
        match (predicted, outcome) {
            (Ok(path), Some(opened)) => {
                self.accepted(id, path, &opened, &note);
                true
            }
            (Err(why), _) => {
                let counter = if was_accepted {
                    &mut self.stats.rejected_replay
                } else if why == Why::TooFar {
                    &mut self.stats.rejected_too_far
                } else {
                    &mut self.stats.rejected_stale
                };
                *counter = counter.checked_add(1).unwrap();
                false
            }
            (Ok(_), None) => false,
        }
    }

    /// The checks and bookkeeping of an accepted delivery; `opened` is `(padded Content, key digest, unused
    /// randomness)`.
    fn accepted(
        &mut self,
        id: usize,
        path: Path,
        opened: &(Zeroizing<Vec<u8>>, [u8; 32], usize),
        note: &str,
    ) {
        let (padded, key, unused) = opened;
        let cell = self.cells.get_mut(id).unwrap();
        assert!(!cell.accepted, "{note}: a cell was accepted twice");
        cell.accepted = true;
        assert_eq!(*key, cell.mk, "{note}: opened with its own sealing key");
        assert_eq!(**padded, *cell.padded, "{note}: the sent Content");
        let (from, chain, n, pn) = (cell.from, cell.chain, cell.n, cell.pn);
        let expected_unused = if path == Path::Step { 0 } else { STEP_ENTROPY };
        assert_eq!(*unused, expected_unused, "{note}: step randomness");
        let to = from.peer();
        let n_r = self.party(to).model.n_r;
        let counter = match path {
            Path::Skipped(_) => &mut self.stats.accepted_late,
            Path::Step => &mut self.stats.accepted_step,
            Path::Chain if n == n_r => &mut self.stats.accepted_in_order,
            Path::Chain => &mut self.stats.accepted_ahead,
        };
        *counter = counter.checked_add(1).unwrap();
        let evicted = self.party_mut(to).model.accept(path, chain, n, pn);
        self.stats.evicted = self
            .stats
            .evicted
            .checked_add(u64::try_from(evicted).unwrap())
            .unwrap();
        let len = self.party(to).model.skipped.len();
        self.stats.max_skipped = self.stats.max_skipped.max(len);
        if path == Path::Step {
            self.record_send_chain(to);
        }
    }

    /// A random party with a sending chain (A always has one).
    fn sender(&mut self) -> Who {
        if self.party(Who::B).model.send_chain.is_some() && self.rng.random_bool(0.5) {
            Who::B
        } else {
            Who::A
        }
    }

    /// A random party whose list `which` is not empty.
    fn with_cells(&mut self, which: fn(&Party) -> &Vec<usize>) -> Option<Who> {
        let candidates: Vec<Who> = [Who::A, Who::B]
            .into_iter()
            .filter(|w| !which(self.party(*w)).is_empty())
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let i = self.rng.random_range(0..candidates.len());
        candidates.get(i).copied()
    }

    /// `k` positions of `from`'s sending chain whose cells are all dropped.
    fn drop_positions(&mut self, from: Who, k: u32) {
        if k <= ENCRYPTED_GAP_MAX {
            for _ in 0..k {
                let content = if self.one_in(4) {
                    self.real_content(from)
                } else {
                    dummy()
                };
                self.encrypt(from, &content);
            }
            self.stats.gap_cells_encrypted = self
                .stats
                .gap_cells_encrypted
                .checked_add(u64::from(k))
                .unwrap();
        } else {
            let state = self.take_state(from);
            let advanced = advance_sending_chain(&state, k);
            drop(state);
            self.put_state(from, advanced);
            let m = &mut self.party_mut(from).model;
            m.n_s = m.n_s.checked_add(k).unwrap();
            self.stats.gap_positions_fast = self
                .stats
                .gap_positions_fast
                .checked_add(u64::from(k))
                .unwrap();
        }
    }

    /// One random event (percent weights).
    fn random_event(&mut self) {
        let who = if self.rng.random_bool(0.5) {
            Who::A
        } else {
            Who::B
        };
        match self.rng.random_range(0..100_u32) {
            0..=21 => {
                self.what = format!("send real from {who:?}");
                self.send(who, true);
            }
            22..=39 => {
                self.what = format!("send dummy from {who:?}");
                self.send(who, false);
            }
            40..=71 => self.deliver_event(),
            72..=77 => self.duplicate_event(),
            78..=84 => self.drop_event(),
            85..=88 => self.gap_event(),
            89..=92 => self.tamper_event(),
            _ => self.reload_event(who),
        }
    }

    /// Deliver an in-flight cell: the oldest (1/2), the newest (1/5) or any (reordering).
    fn deliver_event(&mut self) {
        let Some(from) = self.with_cells(|p| &p.in_flight) else {
            "send real from A (nothing in flight)".clone_into(&mut self.what);
            self.send(Who::A, true);
            return;
        };
        let len = self.party(from).in_flight.len();
        let i = match self.rng.random_range(0..10_u32) {
            0..=4 => 0,
            5 | 6 => len.checked_sub(1).unwrap(),
            _ => self.rng.random_range(0..len),
        };
        let id = self.party_mut(from).in_flight.remove(i);
        self.deliver(id);
    }

    /// Deliver an already delivered cell again (duplicate / replay).
    fn duplicate_event(&mut self) {
        let Some(from) = self.with_cells(|p| &p.delivered) else {
            return self.deliver_event();
        };
        let delivered = self.party(from).delivered.clone();
        let (_, id) = self.pick(&delivered);
        self.deliver(id);
    }

    /// Drop an in-flight cell.
    fn drop_event(&mut self) {
        let Some(from) = self.with_cells(|p| &p.in_flight) else {
            return self.deliver_event();
        };
        let in_flight = self.party(from).in_flight.clone();
        let (i, id) = self.pick(&in_flight);
        self.what = format!("drop cell {id}");
        self.party_mut(from).in_flight.remove(i);
    }

    /// A gap: `1..=SMALL_GAP_MAX` cells, or `MEDIUM_GAP`, encrypted and dropped.
    fn gap_event(&mut self) {
        let from = self.sender();
        let k = if self.one_in(MEDIUM_GAP_ONE_IN) {
            MEDIUM_GAP
        } else {
            self.rng.random_range(1..=SMALL_GAP_MAX)
        };
        self.what = format!("gap of {k} from {from:?}");
        self.drop_positions(from, k);
    }

    /// A sent cell with one bit flipped, truncated, extended, or reflected to its sender: always rejected.
    fn tamper_event(&mut self) {
        if self.cells.is_empty() {
            return self.deliver_event();
        }
        let id = self.rng.random_range(0..self.cells.len());
        let (from, mut bytes) = {
            let c = self.cells.get(id).unwrap();
            (c.from, c.bytes.clone())
        };
        let mut to = from.peer();
        let how = match self.rng.random_range(0..10_u32) {
            0 => {
                let len = self.rng.random_range(0..bytes.len());
                bytes.truncate(len);
                "truncated"
            }
            1 => {
                bytes.push(self.rng.random());
                "extended"
            }
            2 => {
                to = from;
                "reflected"
            }
            _ => {
                let bit = self
                    .rng
                    .random_range(0..bytes.len().checked_mul(8).unwrap());
                let mask = 1_u8
                    .checked_shl(u32::try_from(bit.checked_rem(8).unwrap()).unwrap())
                    .unwrap();
                *bytes.get_mut(bit.checked_div(8).unwrap()).unwrap() ^= mask;
                "bit flipped"
            }
        };
        self.what = format!("cell {id} {how}, to {to:?}");
        let outcome = self.decrypt(to, &bytes);
        assert!(outcome.is_none(), "{}: rejected", self.ctx());
        self.stats.rejected_tampered = self.stats.rejected_tampered.checked_add(1).unwrap();
    }

    /// Persist and reload `who`.
    fn reload_event(&mut self, who: Who) {
        self.what = format!("reload {who:?}");
        let ctx = self.ctx();
        let state = self.take_state(who);
        let bytes = must(state.to_bytes(), &ctx);
        drop(state);
        self.put_state(who, must(RatchetState::from_bytes(&bytes), &ctx));
        self.stats.reloads = self.stats.reloads.checked_add(1).unwrap();
    }

    /// Property (5) for both parties — decoded and re-encoded unless the encoding is the one checked last (decoding
    /// is deterministic), and continued with the decoded state at random — then the model check.
    fn after_event(&mut self) {
        for who in [Who::A, Who::B] {
            let ctx = self.ctx();
            let state = self.take_state(who);
            let bytes = must(state.to_bytes(), &ctx);
            if *self.party(who).checked == *bytes {
                self.put_state(who, state);
                self.check_model(who, &bytes);
                continue;
            }
            let decoded = must(RatchetState::from_bytes(&bytes), &ctx);
            assert_eq!(
                *must(decoded.to_bytes(), &ctx),
                *bytes,
                "{ctx}: {who:?} decodes and re-encodes to the same bytes"
            );
            self.stats.round_trips = self.stats.round_trips.checked_add(1).unwrap();
            if self.one_in(RELOAD_ONE_IN) {
                drop(state);
                self.put_state(who, decoded);
                self.stats.reloads = self.stats.reloads.checked_add(1).unwrap();
            } else {
                drop(decoded);
                self.put_state(who, state);
            }
            self.check_model(who, &bytes);
            self.party_mut(who).checked = bytes;
        }
    }

    /// The state's positions, `skipped` and header keys equal the model's.
    fn check_model(&self, who: Who, bytes: &[u8]) {
        let ctx = self.ctx();
        let v = view(bytes);
        let m = &self.party(who).model;
        assert_eq!(
            (v.has_send, v.has_recv),
            (m.send_chain.is_some(), m.recv_chain.is_some()),
            "{ctx}: {who:?} (sending, receiving) chain present"
        );
        assert_eq!(
            (v.n_s, v.n_r, v.pn),
            (m.n_s, m.n_r, m.pn),
            "{ctx}: {who:?} (n_s, n_r, pn)"
        );
        let skipped: Vec<(u32, u32)> = v
            .skipped
            .iter()
            .map(|(hk, n)| {
                let owner = self.hk_chain.get(hk).copied();
                assert_eq!(
                    owner.map(|o| o.0),
                    Some(who.peer()),
                    "{ctx}: {who:?} skipped entry under a header key of the peer"
                );
                (owner.unwrap().1, *n)
            })
            .collect();
        let first_difference = skipped.iter().zip(&m.skipped).position(|(x, y)| x != y);
        assert!(
            skipped.len() == m.skipped.len() && first_difference.is_none(),
            "{ctx}: {who:?} skipped ({} entries) differs from the model ({} entries), first at {first_difference:?}",
            skipped.len(),
            m.skipped.len()
        );
        let state = self.state(who);
        let hk_s = state.hk_s_kat().map(|k| *k.expose_secret());
        let chain_key = |owner: Who, chain: Option<u32>| {
            chain.and_then(|c| self.chain_hk.get(&(owner, c)).copied())
        };
        assert_eq!(hk_s, chain_key(who, m.send_chain), "{ctx}: {who:?} hk_s");
        let hk_r = state
            .receiving_header_keys_kat()
            .0
            .map(|k| *k.expose_secret());
        assert_eq!(
            hk_r,
            chain_key(who.peer(), m.recv_chain),
            "{ctx}: {who:?} hk_r"
        );
    }

    /// Seal a real cell from `from` (which has a sending chain) and keep it out of the network.
    fn hold(&mut self, from: Who) -> usize {
        let id = self.send(from, true);
        assert_eq!(self.party_mut(from).in_flight.pop(), Some(id));
        id
    }

    /// Deliver `id` and require the outcome `accepted` (the model predicted it as well).
    fn expect(&mut self, id: usize, accepted: bool, what: &str, label: &str) {
        let got = self.deliver(id);
        assert_eq!(got, accepted, "{}: {what}: {label}", self.ctx());
    }

    /// A gap of `MAX_FF` positions from a random sender to its peer, probed on both sides of the bound (spec §7.4
    /// `if gap > MAX_FF: reject`) with one chain derivation, on `n` or — if the sender can step at once — on `pn`.
    /// The receiver's gap is `MAX_FF + d` (`d` in 1..=3) for the first probe, which is rejected, then exactly
    /// `MAX_FF`, which is accepted (2^20 chain steps at the receiver); the rejected probe is accepted afterwards,
    /// once the gap has closed (a rejection changed nothing).
    fn big_gap(&mut self, on_pn: bool) {
        let d = self.rng.random_range(1..=3_u32);
        let candidates = self.big_gap_senders(on_pn);
        let from = *candidates
            .get(self.rng.random_range(0..candidates.len()))
            .unwrap();
        let to = from.peer();
        let (s, r) = (&self.party(from).model, &self.party(to).model);
        // the receiver's position on the sender's current chain (0 if it has not reached that chain yet)
        let base = if r.recv_chain == s.send_chain {
            r.n_r
        } else {
            0
        };
        let ahead = s.n_s.checked_sub(base).unwrap();
        let what = format!(
            "big gap {from:?}→{to:?} on {}, MAX_FF + {d} then MAX_FF",
            if on_pn { "pn" } else { "n" }
        );
        self.what.clone_from(&what);
        if on_pn {
            self.big_gap_on_pn(from, d, &what);
        } else {
            // at_bound at base + MAX_FF, beyond at base + MAX_FF + d
            self.drop_positions(from, MAX_FF.checked_sub(ahead).unwrap());
            let at_bound = self.hold(from);
            self.drop_positions(from, d.checked_sub(1).unwrap());
            let beyond = self.hold(from);
            self.expect(beyond, false, &what, "gap MAX_FF + d on n: rejected");
            self.expect(at_bound, true, &what, "gap MAX_FF on n: accepted");
            self.expect(
                beyond,
                true,
                &what,
                "the rejected cell after the gap closed",
            );
        }
        self.stats.big_gaps = self.stats.big_gaps.checked_add(1).unwrap();
        let counter = if on_pn {
            &mut self.stats.big_gaps_on_pn
        } else {
            &mut self.stats.big_gaps_on_n
        };
        *counter = counter.checked_add(1).unwrap();
    }

    /// The parties that can send a big gap: any with a sending chain on `n`; on `pn` one whose peer receives its
    /// current chain and whose next receiving chain is the peer's current sending chain (a reply makes it step).
    fn big_gap_senders(&self, on_pn: bool) -> Vec<Who> {
        [Who::A, Who::B]
            .into_iter()
            .filter(|who| {
                let (s, r) = (&self.party(*who).model, &self.party(who.peer()).model);
                s.send_chain.is_some()
                    && (!on_pn
                        || (r.recv_chain == s.send_chain
                            && r.send_chain
                                .is_some_and(|c| s.predict(c, r.n_s, r.pn) == Ok(Path::Step))))
            })
            .collect()
    }

    /// The `pn` variant of [`World::big_gap`]: the receiver takes the chain's next cell (at `q`), the sender holds
    /// the cell at `q + d` and drops `MAX_FF` positions, the receiver's reply makes the sender step (`pn = q + d + 1 +
    /// MAX_FF`), and its first cell on the new chain meets `pn − n_r = MAX_FF + d` (rejected), then — after the held
    /// cell raised `n_r` to `q + d + 1` — exactly `MAX_FF` (accepted).
    fn big_gap_on_pn(&mut self, from: Who, d: u32, what: &str) {
        let to = from.peer();
        let next = self.hold(from);
        self.expect(next, true, what, "the chain's next cell");
        self.drop_positions(from, d.checked_sub(1).unwrap());
        let closer = self.hold(from);
        self.drop_positions(from, MAX_FF);
        let reply = self.hold(to);
        self.expect(reply, true, what, "the reply: the sender steps");
        let probe = self.hold(from);
        self.expect(probe, false, what, "gap MAX_FF + d on pn: rejected");
        self.expect(
            closer,
            true,
            what,
            "the old chain's cell that narrows the gap",
        );
        self.expect(probe, true, what, "gap MAX_FF on pn: accepted");
    }

    /// One session: `EVENTS_PER_CASE` events; in the sessions [`BIG_GAP_PERIOD`] names, one of them is a big gap
    /// (on `pn`: at the first event from a random index in `BIG_GAP_EVENTS` on at which a direction allows it);
    /// after every event property (5) and the model check.
    fn run_case(&mut self, case: u32) {
        self.start_case(case);
        // the pending big gap: Some(on_pn)
        let mut big = match case.checked_rem(BIG_GAP_PERIOD).unwrap() {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
        let big_from = self.rng.random_range(BIG_GAP_EVENTS);
        for event in 0..EVENTS_PER_CASE {
            self.event = event;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                match big {
                    Some(on_pn) if event >= big_from && !self.big_gap_senders(on_pn).is_empty() => {
                        self.big_gap(on_pn);
                        big = None;
                    }
                    _ => self.random_event(),
                }
                self.after_event();
            }));
            assert!(
                outcome.is_ok(),
                "{}: panicked (the message is above)",
                self.ctx()
            );
            self.stats.events = self.stats.events.checked_add(1).unwrap();
        }
    }
}

/// The M3 property criterion: random interleavings with drops, duplicates, reorders and gaps up to and beyond
/// `MAX_FF` never reuse a message key, never panic, round-trip through serialisation after every event, reject
/// without changing the state, and decrypt exactly what §7.4 guarantees (module documentation).
#[test]
fn random_interleavings_follow_spec_7_4_and_never_reuse_a_key() {
    let seed = master_seed();
    let cases = env_number("SECMP_PROPTEST_CASES").unwrap_or(DEFAULT_CASES);
    let mut w = World::new(seed);
    for case in 0..cases {
        w.run_case(case);
    }
    let s = &w.stats;
    let ctx = format!("SECMP_PROPTEST_SEED={seed}, {cases} cases: {s:?}");
    assert_eq!(
        u64::try_from(w.sealed.len()).unwrap(),
        s.sealed,
        "{ctx}: every sealing key distinct"
    );
    // every scheduled MAX_FF gap ran (each asserted: rejected at MAX_FF + d, accepted at MAX_FF)
    let scheduled = |phase: u32| {
        u64::try_from(
            (0..cases)
                .filter(|c| c.checked_rem(BIG_GAP_PERIOD) == Some(phase))
                .count(),
        )
        .unwrap()
    };
    assert_eq!(
        (s.big_gaps_on_n, s.big_gaps_on_pn),
        (scheduled(0), scheduled(1)),
        "{ctx}: scheduled MAX_FF gaps on (n, pn) that ran"
    );
    // not vacuous: every kind of outcome occurred (a full-length run)
    if cases >= DEFAULT_CASES {
        for (what, n) in [
            ("in order", s.accepted_in_order),
            ("ahead", s.accepted_ahead),
            ("step", s.accepted_step),
            ("late within the window", s.accepted_late),
            ("replay", s.rejected_replay),
            ("stale (outside the window, evicted)", s.rejected_stale),
            ("beyond MAX_FF", s.rejected_too_far),
            ("tampered", s.rejected_tampered),
            ("evictions", s.evicted),
            ("reloads", s.reloads),
            ("long gaps", s.gap_positions_fast),
        ] {
            assert!(n > 0, "{ctx}: no {what}");
        }
        assert_eq!(
            s.max_skipped, MAX_SKIPPED,
            "{ctx}: skipped reached its bound"
        );
    }
}

/// The long-gap shortcut is exact: `advance_sending_chain(s, k)` encodes byte-identically to `k` encryptions with
/// their cells dropped — for the initiator and for a responder with a receiving chain and skipped keys.
#[test]
fn advancing_the_sending_chain_equals_encrypting_and_dropping() {
    let mut w = World::new(master_seed() ^ 1);
    w.start_case(0);
    for _ in 0..3 {
        w.send(Who::A, false);
    }
    let last = w.party_mut(Who::A).in_flight.pop().unwrap();
    assert!(w.deliver(last), "{}", w.ctx());
    for who in [Who::A, Who::B] {
        for k in [1, 2, 3, 257] {
            let state = w.take_state(who);
            let advanced = advance_sending_chain(&state, k);
            let mut state = state;
            for _ in 0..k {
                let nonce = w.bytes(NONCE_ENTROPY);
                state = state
                    .encrypt_with(&dummy(), &mut FixedEntropy::new(&nonce))
                    .ok()
                    .unwrap()
                    .persist(|_| Ok::<(), ()>(()))
                    .unwrap()
                    .0;
            }
            assert_eq!(
                *advanced.to_bytes().unwrap(),
                *state.to_bytes().unwrap(),
                "{who:?} k {k} (SECMP_PROPTEST_SEED={})",
                w.seed
            );
            w.put_state(who, state);
        }
    }
}
