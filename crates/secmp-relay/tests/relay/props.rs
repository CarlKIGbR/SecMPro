// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's property tests (TEST-SPEC-M5 (d) P-06 … P-11): seeded `rand` generators as in
//! `secmp-proto/tests/link/frames.rs`. The master seed comes from the one helper `common/seed.rs` of `secmp-proto`
//! (`SECMP_PROPTEST_SEED` if set, else [`DEFAULT_SEED`]; M4 review R-93, TEST-SPEC-M5 X-07), the case counts from
//! `SECMP_PROPTEST_CASES`; every assertion message names the seed, ready to re-run, and the case.
//!
//! - P-06 `prop_executor_response_shape_matches_d2` [SQ-26]: random request sequences, honestly signed over random
//!   fields, with random command-level faults, stale `cmd_seq`s and a random per-link rate ⇒ `assert_d2_shape` per
//!   request (the stale and rate exceptions predicted from the relay's `last` and a mirrored token bucket).
//! - P-07 `prop_queue_store_matches_model`: random `QUEUE_NEW`/`SEND`/`FETCH`/`FETCH_MULTI`/`QUEUE_DEL` ⇒ the same
//!   responses and queue states as a plain model (a `VecDeque` of at most 128 cells, ids from 1, the oldest evicted,
//!   cumulative ack, oldest-first by arrival across queues, the vector budget of two queues).
//! - P-08 `prop_rejection_leaves_link_and_store_unchanged`: a random mutation of the next valid unit (ciphertext,
//!   length, counter, direction, padding, decoder rules, multi-frame assembly, a random plaintext byte) or of a
//!   `HELLO`/`HS1` record that the relay rejects ⇒ frame counters, `last`, the store digest unchanged, nothing
//!   emitted, no random draw.
//! - P-09 `prop_response_count_independent_of_outcome`: every command with honest and faulted fields and random
//!   requests ⇒ per command one frame count and one list of frame lengths whatever the outcome (at least two
//!   outcomes seen per command that has several), and one 4352-byte frame for every stale or rate-limited command.
//! - P-10 `prop_one_time_link_data_single_winner`: random interleavings of consume and owner-status `LINK_GET`s on
//!   one-time link data from several links ⇒ exactly one consume per entry returns the blob; the others and the
//!   owner status see it consumed.
//! - P-11 `prop_cmd_seq_executes_iff_greater_than_last`: random `cmd_seq` sequences over `PING`, `SKEY`, `QUEUE_NEW`
//!   and `LINK_PUT` ⇒ executed iff greater than `last`; `last` is the maximum recorded after every frame (`CONT`
//!   frames exempt).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::OnceLock;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use secmp_crypto::{Aead, Label, Nonce24, SecretBytes, sha256};
use secmp_proto::Encode;
use secmp_proto::codec::{pad, unpad};
use secmp_proto::keys::Ed25519Sig;
use secmp_proto::link;
use secmp_proto::link::frame::Frame;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{
    Cellr, CellrError, Cont, ContIdx, LinkGetMode, Request, RequestCmd, Response, ResponseCmd,
    opcode,
};
use secmp_relay::budget::QUEUE_RESERVATION;
use secmp_relay::rate::{RateLimit, TokenBucket};
use secmp_relay::relay::kat::QueueSnapshot;
use secmp_relay::{Connection, Executor, Limits, Outcome, Relay};

use crate::d2::{self, Expect};
use crate::fixture::{
    Bench, Client, EXPIRES, FRAME, HELLO, Key, NOW, PLAIN, Put, RelayFx, VALID_UNTIL, at, flip,
    now, rid_of, sid_of,
};

// ---------------------------------------------------------------------------------------------------------------
// Seeds and generators.

/// The master seed when `SECMP_PROPTEST_SEED` is not set.
const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0006;

/// The one reader of `SECMP_PROPTEST_SEED` (M4 review R-93, TEST-SPEC-M5 X-07).
#[path = "../../../secmp-proto/tests/common/seed.rs"]
mod seed;

/// The master seed of this run: `SECMP_PROPTEST_SEED` (decimal `u64`) if set and not empty, else [`DEFAULT_SEED`].
fn master_seed() -> u64 {
    seed::master_seed(DEFAULT_SEED)
}

/// `SECMP_PROPTEST_CASES` if set and not empty, else `default`.
fn cases(default: u32) -> u32 {
    std::env::var("SECMP_PROPTEST_CASES")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map_or(default, |v| {
            v.trim()
                .parse()
                .expect("SECMP_PROPTEST_CASES is a decimal u32")
        })
}

fn bytes(rng: &mut StdRng, n: usize) -> Vec<u8> {
    let mut v = vec![0_u8; n];
    rng.fill(v.as_mut_slice());
    v
}

fn id(rng: &mut StdRng) -> Id {
    let mut v = [0_u8; 16];
    rng.fill(&mut v[..]);
    v
}

fn pick<'a, T>(rng: &mut StdRng, v: &'a [T]) -> &'a T {
    v.get(rng.random_range(0..v.len())).unwrap()
}

fn one_in(rng: &mut StdRng, n: u32) -> bool {
    rng.random_range(0..n) == 0
}

/// A non-zero xor mask.
fn mask(rng: &mut StdRng) -> u8 {
    rng.random_range(1..=u8::MAX)
}

/// Fisher–Yates with the seeded generator.
fn shuffle<T>(v: &mut [T], rng: &mut StdRng) {
    for i in (1..v.len()).rev() {
        v.swap(i, rng.random_range(0..=i));
    }
}

/// Enough relay draws for any one response (eight random cells, or a dummy blob).
fn draws() -> FixedEntropy {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    FixedEntropy::new(BYTES.get_or_init(|| {
        (0..40_000_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect()
    }))
}

/// The unpadded payload `op ‖ cmd_seq ‖ fields` of a request.
fn payload(req: &Request) -> Vec<u8> {
    unpad(&req.encode().unwrap(), PLAIN).unwrap().to_vec()
}

/// `SKEY ‖ cmd_seq` (D.2, reading REF-M5 2).
fn skey(cmd_seq: u32) -> Vec<u8> {
    [&[opcode::SKEY][..], &cmd_seq.to_be_bytes()].concat()
}

/// The hour bucket of the suite's `now` (472 222).
fn now_bucket() -> u32 {
    u32::try_from(NOW / 3600).unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// Requests, links and the D.2 shape.

/// The request kinds of D.2 (`SKEY` included).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    QueueNew,
    Skey,
    Send,
    Fetch,
    FetchMulti,
    QueueDel,
    LinkPut,
    LinkGet,
    Ping,
}

const OPS: [Op; 9] = [
    Op::QueueNew,
    Op::Skey,
    Op::Send,
    Op::Fetch,
    Op::FetchMulti,
    Op::QueueDel,
    Op::LinkPut,
    Op::LinkGet,
    Op::Ping,
];

impl Op {
    /// The D.2 response frames of an executed request (TEST-SPEC-M5 Conventions, shape table).
    const fn frames(self) -> usize {
        match self {
            Self::Fetch => 4,
            Self::FetchMulti => 8,
            Self::LinkGet => 3,
            Self::QueueNew
            | Self::Skey
            | Self::Send
            | Self::QueueDel
            | Self::LinkPut
            | Self::Ping => 1,
        }
    }

    /// The request opcode (D.2).
    const fn byte(self) -> u8 {
        match self {
            Self::QueueNew => opcode::QUEUE_NEW,
            Self::Skey => opcode::SKEY,
            Self::Send => opcode::SEND,
            Self::Fetch => opcode::FETCH,
            Self::FetchMulti => opcode::FETCH_MULTI,
            Self::QueueDel => opcode::QUEUE_DEL,
            Self::LinkPut => opcode::LINK_PUT,
            Self::LinkGet => opcode::LINK_GET,
            Self::Ping => opcode::PING,
        }
    }

    /// Whether the command has more than one outcome (P-09's non-vacuity).
    const fn has_outcomes(self) -> bool {
        !matches!(self, Self::Skey | Self::Ping)
    }
}

/// How the relay admits a request (spec §9.2, §9.7 item 7; ADR-048 (f), (p)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Run,
    Stale,
    Rate,
}

impl Admission {
    /// What `d2::assert_d2_shape` expects: the D.2 count, or exactly one ERR 6 (stale) or ERR 7 (rate) frame.
    const fn expect(self) -> Expect {
        match self {
            Self::Run => Expect::D2,
            Self::Stale => Expect::Single(6),
            Self::Rate => Expect::Single(7),
        }
    }
}

const fn present(c: &Cellr) -> u8 {
    match c {
        Cellr::Dummy { .. } => 0,
        Cellr::Cell { .. } => 1,
        Cellr::Error { error, .. } => match error {
            CellrError::NoQueue => 2,
            CellrError::Auth => 3,
            CellrError::Malformed => 4,
        },
    }
}

/// Seal `payloads` with `client` and hand them to `exec`, frame `i` at monotonic time `times[i]` (0 if absent), with
/// enough draws for any answer; the executor's outcomes in order.
fn feed_at(
    client: &mut Client,
    exec: &mut Executor,
    relay: &Relay,
    payloads: &[Vec<u8>],
    times: &[u64],
) -> Vec<Outcome> {
    payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let unit = client.seal_payload(p);
            let t = at(0, times.get(i).copied().unwrap_or(0));
            exec.on_unit(relay, &unit, t, &mut draws())
        })
        .collect()
}

/// `assert_d2_shape` (TEST-SPEC-M5 Conventions; `d2::assert_d2_shape`) of the outcomes of `op`'s frames with
/// `cmd_seq`, admitted as `adm`; the decoded responses.
fn shape(
    ctx: &str,
    client: &mut Client,
    op: Op,
    cmd_seq: u32,
    outcomes: Vec<Outcome>,
    adm: Admission,
) -> Vec<Response> {
    d2::assert_d2_shape(ctx, client, op.byte(), cmd_seq, outcomes, adm.expect()).resp
}

/// Run one honest request on `b` at time 0 and check its D.2 shape (admitted, no rate limit).
fn run(b: &mut Bench, ctx: &str, op: Op, payloads: &[Vec<u8>], cmd_seq: u32) -> Vec<Response> {
    let outcomes = feed_at(&mut b.client, &mut b.exec, &b.relay, payloads, &[]);
    shape(ctx, &mut b.client, op, cmd_seq, outcomes, Admission::Run)
}

/// The next fresh `cmd_seq` of `exec`'s link.
fn fresh(exec: &Executor) -> u32 {
    exec.last_cmd_seq().checked_add(1).unwrap()
}

/// A second link to `relay` with random handshake draws: the client and the relay's executor.
fn open_link(relay: &Relay, fx: &RelayFx, rng: &mut StdRng) -> (Client, Executor) {
    let access = fx.access();
    let (hello, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    let (info, st_r) = link::relay::accept_ring(relay.keys().ring())
        .on_hello(&hello, VALID_UNTIL)
        .unwrap();
    let (hs1, wait) = st
        .on_relayinfo(&info, &mut FixedEntropy::new(&bytes(rng, 160)))
        .unwrap();
    let (hs2, relay_link) = st_r
        .on_hs1(&hs1, &mut FixedEntropy::new(&bytes(rng, 64)))
        .unwrap();
    let client = wait.on_hs2(&hs2).unwrap();
    (
        Client::new(client, fx.access()),
        Executor::new(relay_link, relay.limits().link_rate, now()),
    )
}

// ---------------------------------------------------------------------------------------------------------------
// The random requests of P-06 and P-09.

/// The keys and ids random requests draw from: three queue key pairs, two link-data owners, three `ld_id`s.
struct Pool {
    pairs: Vec<(Key, Key)>,
    owners: Vec<Key>,
    ld_ids: Vec<Id>,
}

impl Pool {
    fn new(rng: &mut StdRng) -> Self {
        let mut key = || Key::from_seed(&bytes(rng, 32));
        let pairs = vec![(key(), key()), (key(), key()), (key(), key())];
        let owners = vec![key(), key()];
        let ld_ids = vec![id(rng), id(rng), id(rng)];
        Self {
            pairs,
            owners,
            ld_ids,
        }
    }

    /// Pair `tame`, or a random pair (one in four with another pair's sender key).
    fn pair(&self, rng: &mut StdRng, tame: Option<usize>) -> (&Key, &Key) {
        let i = tame.unwrap_or_else(|| rng.random_range(0..self.pairs.len()));
        let p = self.pairs.get(i).unwrap();
        let send = if tame.is_none() && one_in(rng, 4) {
            &pick(rng, &self.pairs).1
        } else {
            &p.1
        };
        (&p.0, send)
    }
}

/// An `ack` for the queue of `recv` as the relay holds it: 0, a stored id, the newest id, `next_cell_id` (one too
/// many), `u64::MAX`, or a random value up to `next_cell_id`.
fn ack_for(relay: &Relay, recv: &Key, rng: &mut StdRng) -> u64 {
    let rid = rid_of(&recv.pk);
    let q = relay
        .snapshot_kat()
        .queues
        .into_iter()
        .find(|q| q.rid == rid);
    let next = q.as_ref().map_or(1, |q| q.next_cell_id);
    let ids = q.map(|q| q.cell_ids).unwrap_or_default();
    match rng.random_range(0..6) {
        0 => 0,
        1 if !ids.is_empty() => *pick(rng, &ids),
        2 => next.saturating_sub(1),
        3 => next,
        4 => u64::MAX,
        _ => rng.random_range(0..=next),
    }
}

/// The signature field of a signed command (a `FETCH_MULTI`'s first entry).
fn sig_mut(cmd: &mut RequestCmd) -> Option<&mut Ed25519Sig> {
    match cmd {
        RequestCmd::QueueNew { sig, .. }
        | RequestCmd::Send { sig, .. }
        | RequestCmd::Fetch { sig, .. }
        | RequestCmd::QueueDel { sig, .. }
        | RequestCmd::LinkPut { sig, .. }
        | RequestCmd::LinkGet {
            mode: LinkGetMode::OwnerStatus(sig),
            ..
        } => Some(sig),
        RequestCmd::FetchMulti { entries } => entries.first_mut().map(|e| &mut e.sig),
        _ => None,
    }
}

/// `req` with the signature of `other`, the same command signed over another `cmd_seq`: an encoding the decoder
/// accepts and the verification refuses (spec §9.2, D.6).
fn swap_sig(req: &mut Request, mut other: Request) {
    let sig = sig_mut(&mut other.cmd).copied();
    if let (Some(dst), Some(sig)) = (sig_mut(&mut req.cmd), sig) {
        *dst = sig;
    }
}

/// Flip byte 0 of the token of `QUEUE_NEW` or `LINK_PUT` (the token is checked first, spec §9.6).
fn flip_token(req: &mut Request) {
    if let RequestCmd::QueueNew { token, .. } | RequestCmd::LinkPut { token, .. } = &mut req.cmd {
        *token.first_mut().unwrap() ^= 1;
    }
}

/// One request of a random sequence: its kind, `cmd_seq` and the payloads of its frames (three for `LINK_PUT`).
struct Planned {
    op: Op,
    cmd_seq: u32,
    payloads: Vec<Vec<u8>>,
}

/// A random request of kind `op` with `cmd_seq` on `b`'s link, honestly signed over random fields; with `fault`, one
/// command-level fault of its kind (a flipped token, a signature over another `cmd_seq`, an `expires_bucket` out of
/// range) — always answered, never a LINK-level rejection. `tame` aims the honest request at existing state: queue
/// pair `tame` (`QUEUE_DEL`: pair 2, which is never created), the first `ld_id`, a fresh `ld_id` for `LINK_PUT`.
fn planned(
    rng: &mut StdRng,
    pool: &Pool,
    b: &Bench,
    op: Op,
    cmd_seq: u32,
    fault: bool,
    tame: Option<usize>,
) -> Planned {
    let cl = &b.client;
    let other = cmd_seq.wrapping_add(1);
    let reqs: Vec<Request> = match op {
        Op::Skey => {
            return Planned {
                op,
                cmd_seq,
                payloads: vec![skey(cmd_seq)],
            };
        }
        Op::Ping => vec![Client::ping(cmd_seq)],
        Op::QueueNew => {
            let (recv, send) = pool.pair(rng, tame);
            let mut q = cl.queue_new(cmd_seq, recv, send);
            if fault && rng.random_bool(0.5) {
                flip_token(&mut q);
            } else if fault {
                swap_sig(&mut q, cl.queue_new(other, recv, send));
            }
            vec![q]
        }
        Op::Send => {
            let (recv, send) = pool.pair(rng, tame);
            let cell = bytes(rng, 4096);
            let mut q = cl.send(cmd_seq, recv, send, &cell);
            if fault {
                swap_sig(&mut q, cl.send(other, recv, send, &cell));
            }
            vec![q]
        }
        Op::Fetch => {
            let (recv, _) = pool.pair(rng, tame);
            let ack = if tame.is_some() {
                0
            } else {
                ack_for(&b.relay, recv, rng)
            };
            let mut q = cl.fetch(cmd_seq, recv, ack);
            if fault {
                swap_sig(&mut q, cl.fetch(other, recv, ack));
            }
            vec![q]
        }
        Op::FetchMulti => vec![fetch_multi(rng, pool, b, cmd_seq, fault, tame)],
        Op::QueueDel => {
            // tame: an honest QUEUE_DEL of the never-created pair 2, a faulted one of pair 1 (both keep the state)
            let target = tame.map(|_| if fault { 1 } else { 2 });
            let (recv, _) = pool.pair(rng, target);
            let mut q = cl.queue_del(cmd_seq, recv);
            if fault {
                swap_sig(&mut q, cl.queue_del(other, recv));
            }
            vec![q]
        }
        Op::LinkPut => link_put(rng, pool, cl, cmd_seq, fault, tame.is_some()),
        Op::LinkGet => {
            let ld = match tame {
                Some(_) => *pool.ld_ids.first().unwrap(),
                None if one_in(rng, 4) => id(rng),
                None => *pick(rng, &pool.ld_ids),
            };
            let consume = if tame.is_some() {
                !fault
            } else {
                rng.random_bool(0.5)
            };
            if consume {
                vec![Client::link_get_consume(cmd_seq, &ld)]
            } else {
                let owner = pick(rng, &pool.owners);
                let mut q = cl.link_get_owner(cmd_seq, &ld, owner);
                if fault {
                    swap_sig(&mut q, cl.link_get_owner(other, &ld, owner));
                }
                vec![q]
            }
        }
    };
    Planned {
        op,
        cmd_seq,
        payloads: reqs.iter().map(payload).collect(),
    }
}

/// A `FETCH_MULTI` of 1 to 10 entries (more errors than `F_M` possible); with `fault` its first entry is signed
/// over another `cmd_seq`.
fn fetch_multi(
    rng: &mut StdRng,
    pool: &Pool,
    b: &Bench,
    cmd_seq: u32,
    fault: bool,
    tame: Option<usize>,
) -> Request {
    let cl = &b.client;
    let n = if tame.is_some() {
        2
    } else {
        rng.random_range(1..=10_usize)
    };
    let mut entries = Vec::new();
    for k in 0..n {
        let (recv, _) = pool.pair(rng, tame.map(|_| k));
        let ack = if tame.is_some() {
            0
        } else {
            ack_for(&b.relay, recv, rng)
        };
        let mut e = cl.fetch_entry(cmd_seq, recv, ack);
        if fault && k == 0 {
            e.sig = cl.fetch_entry(cmd_seq.wrapping_add(1), recv, ack).sig;
        }
        entries.push(e);
    }
    Client::fetch_multi(cmd_seq, entries)
}

/// The three frames of a `LINK_PUT` over a random blob; with `fault` a flipped token, a signature over another
/// `cmd_seq`, or an `expires_bucket` outside `[now, now + 720]` (ADR-048 (o)).
fn link_put(
    rng: &mut StdRng,
    pool: &Pool,
    cl: &Client,
    cmd_seq: u32,
    fault: bool,
    fresh_ld: bool,
) -> Vec<Request> {
    let ld = if fresh_ld {
        id(rng)
    } else {
        *pick(rng, &pool.ld_ids)
    };
    let owner = pick(rng, &pool.owners);
    let blob = bytes(rng, 12_360);
    let bucket = now_bucket();
    let kind = rng.random_range(0..3);
    let expires = match (fault, kind) {
        (true, 0) => *pick(
            rng,
            &[
                bucket.checked_sub(1).unwrap(),
                bucket.checked_add(721).unwrap(),
            ],
        ),
        _ => rng.random_range(bucket..=bucket.checked_add(720).unwrap()),
    };
    let put = |seq: u32| {
        cl.link_put(
            seq,
            &Put {
                ld_id: &ld,
                one_time: kind == 1,
                expires_bucket: expires,
                owner,
                blob: &blob,
            },
        )
    };
    let mut frames = put(cmd_seq);
    match (fault, kind) {
        (true, 1) => flip_token(frames.first_mut().unwrap()),
        (true, 2) => {
            let [first, ..] = put(cmd_seq.wrapping_add(1));
            swap_sig(frames.first_mut().unwrap(), first);
        }
        _ => {}
    }
    frames.to_vec()
}

/// The monotonic clock of a link's requests (advancing by up to `step_ms` per frame) and a mirror of the executor's
/// token bucket (created full at monotonic 0 by `fixture::link_a`).
struct Clock {
    mono: u64,
    step_ms: u64,
    bucket: Option<TokenBucket>,
}

impl Clock {
    fn new(step_ms: u64, rate: Option<RateLimit>) -> Self {
        Self {
            mono: 0,
            step_ms,
            bucket: rate.map(|r| TokenBucket::new(r, 0)),
        }
    }
}

/// Send `p` on `b` at the clock's times, predict its admission (stale before the rate, the rate from the mirrored
/// bucket), and check the D.2 shape.
fn run_planned(
    b: &mut Bench,
    ctx: &str,
    p: &Planned,
    clock: &mut Clock,
    rng: &mut StdRng,
) -> (Admission, Vec<Response>) {
    let last = b.exec.last_cmd_seq();
    let mut times = Vec::new();
    let mut over = false;
    for _ in &p.payloads {
        clock.mono = clock
            .mono
            .saturating_add(rng.random_range(0..=clock.step_ms));
        // every request frame takes a token (executor step 4)
        if let Some(bucket) = clock.bucket.as_mut()
            && !bucket.take(clock.mono)
        {
            over = true;
        }
        times.push(clock.mono);
    }
    let adm = if p.cmd_seq <= last {
        Admission::Stale
    } else if over {
        Admission::Rate
    } else {
        Admission::Run
    };
    let outcomes = feed_at(&mut b.client, &mut b.exec, &b.relay, &p.payloads, &times);
    let resps = shape(ctx, &mut b.client, p.op, p.cmd_seq, outcomes, adm);
    (adm, resps)
}

/// P-06 `prop_executor_response_shape_matches_d2` [SQ-26]: random request sequences, honestly signed over random
/// fields with random faults, stale `cmd_seq`s and a random rate ⇒ `assert_d2_shape` per request.
#[test]
fn prop_executor_response_shape_matches_d2() {
    let seed = master_seed() ^ 0x6;
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(10) {
        let rate = rng.random_bool(0.5).then(|| RateLimit {
            burst: rng.random_range(4..=16),
            per_sec: rng.random_range(1..=3),
        });
        let mut b = Bench::new(Limits {
            link_rate: rate,
            ..Limits::vectors()
        });
        let pool = Pool::new(&mut rng);
        let mut clock = Clock::new(1500, rate);
        for step in 0..40 {
            let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case} step {step}");
            let last = b.exec.last_cmd_seq();
            let op = *pick(&mut rng, &OPS);
            let cmd_seq = if one_in(&mut rng, 7) {
                rng.random_range(0..=last)
            } else {
                last.saturating_add(rng.random_range(1..=3))
            };
            let fault = one_in(&mut rng, 4);
            let p = planned(&mut rng, &pool, &b, op, cmd_seq, fault, None);
            run_planned(&mut b, &ctx, &p, &mut clock, &mut rng);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// P-09.

/// An outcome class of a response: the kinds with their flags (`present`, `consumed`, the `ERR` code, eviction).
fn class(r: &[Response]) -> String {
    r.iter()
        .map(|x| match &x.cmd {
            ResponseCmd::Ok => "OK".to_owned(),
            ResponseCmd::OkQueueNew { .. } => "OK_QUEUE_NEW".to_owned(),
            ResponseCmd::OkSend { evicted, .. } => format!("OK_SEND {}", evicted.is_some()),
            ResponseCmd::Cellr(c) => format!("CELLR {}", present(c)),
            ResponseCmd::LinkR {
                present, consumed, ..
            } => format!("LINKR {present} {consumed}"),
            ResponseCmd::Err(c) => format!("ERR {}", c.byte()),
            ResponseCmd::Cont(_) => "CONT".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// What P-09 saw: per command the frame lengths of every executed answer and its outcome classes; the frame lengths
/// of every stale or rate-limited answer.
#[derive(Default)]
struct Seen {
    shapes: BTreeMap<Op, BTreeSet<Vec<usize>>>,
    outcomes: BTreeMap<Op, BTreeSet<String>>,
    exceptions: BTreeSet<Vec<usize>>,
}

impl Seen {
    fn record(&mut self, op: Op, adm: Admission, frames: Vec<usize>, resps: &[Response]) {
        if adm == Admission::Run {
            self.shapes.entry(op).or_default().insert(frames);
            self.outcomes.entry(op).or_default().insert(class(resps));
        } else {
            self.exceptions.insert(frames);
        }
    }
}

/// Two queues with one to five cells each and one link-data entry (pairs 0 and 1, `ld_ids[0]`).
fn p09_setup(b: &mut Bench, pool: &Pool, rng: &mut StdRng, ctx: &str) {
    for (recv, send) in pool.pairs.iter().take(2) {
        let s = fresh(&b.exec);
        let q = b.client.queue_new(s, recv, send);
        run(b, ctx, Op::QueueNew, &[payload(&q)], s);
        for _ in 0..rng.random_range(1..=5) {
            let s = fresh(&b.exec);
            let q = b.client.send(s, recv, send, &bytes(rng, 4096));
            run(b, ctx, Op::Send, &[payload(&q)], s);
        }
    }
    let s = fresh(&b.exec);
    let blob = bytes(rng, 12_360);
    let put = b.client.link_put(
        s,
        &Put {
            ld_id: pool.ld_ids.first().unwrap(),
            one_time: rng.random_bool(0.5),
            expires_bucket: EXPIRES,
            owner: pool.owners.first().unwrap(),
            blob: &blob,
        },
    );
    let r = run(
        b,
        ctx,
        Op::LinkPut,
        &put.iter().map(payload).collect::<Vec<_>>(),
        s,
    );
    assert_eq!(class(&r), "OK", "{ctx}: setup LINK_PUT");
}

/// Every command once stale, then — on a link of burst 1 whose token a `PING` took — once over the rate.
fn p09_exceptions(b: &mut Bench, pool: &Pool, seen: &mut Seen, rng: &mut StdRng, ctx: &str) {
    let mut clock = Clock::new(0, None);
    for op in OPS {
        let stale = rng.random_range(0..=b.exec.last_cmd_seq());
        let p = planned(rng, pool, b, op, stale, false, Some(0));
        let (adm, resps) = run_planned(b, ctx, &p, &mut clock, rng);
        assert_eq!(adm, Admission::Stale, "{ctx}: {op:?}");
        seen.record(op, adm, vec![FRAME; resps.len()], &resps);
    }
    let rate = RateLimit {
        burst: 1,
        per_sec: 1,
    };
    let mut r = Bench::new(Limits {
        link_rate: Some(rate),
        ..Limits::vectors()
    });
    // the clock stands still at 0: the PING takes the one token and none comes back
    let mut clock = Clock::new(0, Some(rate));
    let ping = Planned {
        op: Op::Ping,
        cmd_seq: 1,
        payloads: vec![payload(&Client::ping(1))],
    };
    let (adm, _) = run_planned(&mut r, ctx, &ping, &mut clock, rng);
    assert_eq!(adm, Admission::Run, "{ctx}: the first PING");
    for op in OPS {
        let s = fresh(&r.exec);
        let p = planned(rng, pool, &r, op, s, false, Some(0));
        let (adm, resps) = run_planned(&mut r, ctx, &p, &mut clock, rng);
        assert_eq!(adm, Admission::Rate, "{ctx}: {op:?}");
        seen.record(op, adm, vec![FRAME; resps.len()], &resps);
    }
}

/// P-09 `prop_response_count_independent_of_outcome`: per command, the frame count and the frame lengths depend
/// only on the command (the exceptions of the shape table: one frame when stale or over the rate).
#[test]
fn prop_response_count_independent_of_outcome() {
    let seed = master_seed() ^ 0x9;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut obs = Seen::default();
    for case in 0..cases(4) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let pool = Pool::new(&mut rng);
        let mut b = Bench::vectors();
        p09_setup(&mut b, &pool, &mut rng, &ctx);
        // every command honest and faulted, aimed at the existing state, in random order; then random requests
        let mut schedule: Vec<(Op, bool, Option<usize>)> = OPS
            .iter()
            .flat_map(|op| [(*op, false, Some(0)), (*op, true, Some(0))])
            .collect();
        shuffle(&mut schedule, &mut rng);
        for _ in 0..24 {
            schedule.push((*pick(&mut rng, &OPS), one_in(&mut rng, 3), None));
        }
        let mut clock = Clock::new(0, None);
        for (step, (op, fault, tame)) in schedule.into_iter().enumerate() {
            let ctx = format!("{ctx} step {step}");
            let s = fresh(&b.exec);
            let p = planned(&mut rng, &pool, &b, op, s, fault, tame);
            let (adm, resps) = run_planned(&mut b, &ctx, &p, &mut clock, &mut rng);
            // the wire view: every frame 4352 B (assert_d2_shape), so the lengths are the count times FRAME
            obs.record(op, adm, vec![FRAME; resps.len()], &resps);
        }
        p09_exceptions(&mut b, &pool, &mut obs, &mut rng, &ctx);
    }
    let ctx = format!("SECMP_PROPTEST_SEED={seed}");
    for op in OPS {
        let shapes = obs.shapes.get(&op);
        assert_eq!(
            shapes.map(BTreeSet::len),
            Some(1),
            "{ctx}: {op:?}: {shapes:?}"
        );
        assert_eq!(
            shapes.and_then(|s| s.first()),
            Some(&vec![FRAME; op.frames()]),
            "{ctx}: {op:?}"
        );
        let outcomes = obs.outcomes.get(&op).map_or(0, BTreeSet::len);
        assert!(
            !op.has_outcomes() || outcomes >= 2,
            "{ctx}: {op:?}: only {outcomes} outcome(s) obs: {:?}",
            obs.outcomes.get(&op)
        );
    }
    assert_eq!(
        obs.exceptions.into_iter().collect::<Vec<_>>(),
        vec![vec![FRAME]],
        "{ctx}: stale and rate-limited answers"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// P-07.

/// A response as P-07 compares it (cells by their SHA-256; the random bytes of dummies and error frames ignored).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Exp {
    Ok,
    OkQueueNew(Id, Id),
    OkSend(u64, Option<u64>),
    Err(u8),
    Dummy,
    Cell(Id, u64, [u8; 32]),
    CellErr(u8, Id),
    Other,
}

fn observed(r: &Response) -> Exp {
    match &r.cmd {
        ResponseCmd::Ok => Exp::Ok,
        ResponseCmd::OkQueueNew { rid, sid } => Exp::OkQueueNew(*rid, *sid),
        ResponseCmd::OkSend { cell_id, evicted } => Exp::OkSend(*cell_id, *evicted),
        ResponseCmd::Err(c) => Exp::Err(c.byte()),
        ResponseCmd::Cellr(Cellr::Dummy { .. }) => Exp::Dummy,
        ResponseCmd::Cellr(Cellr::Cell { rid, cell_id, cell }) => {
            Exp::Cell(*rid, *cell_id, sha256(&[cell.as_bytes()]))
        }
        ResponseCmd::Cellr(c @ Cellr::Error { rid, .. }) => Exp::CellErr(present(c), *rid),
        ResponseCmd::LinkR { .. } | ResponseCmd::Cont(_) => Exp::Other,
    }
}

/// One queue of the model.
struct MQueue {
    sid: Id,
    /// (`cell_id`, arrival, SHA-256 of the cell), oldest first.
    cells: VecDeque<(u64, u64, [u8; 32])>,
    next: u64,
}

/// The plain model of P-07: queues by `rid`, a global arrival counter, the vector budget of two queues.
#[derive(Default)]
struct Model {
    queues: BTreeMap<Id, MQueue>,
    arrival: u64,
}

/// `QUEUE_CAPACITY` (spec §4.2).
const CAPACITY: usize = 128;
/// The vector budget in queues (`Limits::vectors`, OPEN-M5-07).
const BUDGET_QUEUES: usize = 2;

impl Model {
    fn queue_new(&mut self, recv: &Key, send: &Key, honest: bool) -> Vec<Exp> {
        let (r, s) = (rid_of(&recv.pk), sid_of(&recv.pk, &send.pk));
        if !honest {
            return vec![Exp::Err(4)];
        }
        if let Some(q) = self.queues.get(&r) {
            return vec![if q.sid == s {
                Exp::OkQueueNew(r, s)
            } else {
                Exp::Err(4)
            }];
        }
        if self.queues.len() >= BUDGET_QUEUES {
            return vec![Exp::Err(2)];
        }
        self.queues.insert(
            r,
            MQueue {
                sid: s,
                cells: VecDeque::new(),
                next: 1,
            },
        );
        vec![Exp::OkQueueNew(r, s)]
    }

    fn send(&mut self, recv: &Key, send: &Key, cell: &[u8], honest: bool) -> Vec<Exp> {
        let s = sid_of(&recv.pk, &send.pk);
        let Some(q) = self.queues.values_mut().find(|q| q.sid == s) else {
            return vec![Exp::Err(3)];
        };
        if !honest {
            return vec![Exp::Err(4)];
        }
        let cell_id = q.next;
        q.next = q.next.checked_add(1).unwrap();
        let evicted = if q.cells.len() >= CAPACITY {
            q.cells.pop_front().map(|c| c.0)
        } else {
            None
        };
        self.arrival = self.arrival.checked_add(1).unwrap();
        q.cells.push_back((cell_id, self.arrival, sha256(&[cell])));
        vec![Exp::OkSend(cell_id, evicted)]
    }

    /// The checks and the acknowledgement of one `FETCH` or `FETCH_MULTI` entry: `None` if served, else `present`.
    fn check(&mut self, r: &Id, ack: u64, honest: bool) -> Option<u8> {
        let Some(q) = self.queues.get_mut(r) else {
            return Some(2);
        };
        if !honest {
            return Some(3);
        }
        if ack >= q.next {
            return Some(4);
        }
        q.cells.retain(|c| c.0 > ack);
        None
    }

    fn fetch(&mut self, recv: &Key, ack: u64, honest: bool) -> Vec<Exp> {
        let r = rid_of(&recv.pk);
        let mut out = match self.check(&r, ack, honest) {
            Some(p) => vec![Exp::CellErr(p, r)],
            None => self
                .queues
                .get(&r)
                .unwrap()
                .cells
                .iter()
                .take(4)
                .map(|c| Exp::Cell([0; 16], c.0, c.2))
                .collect(),
        };
        out.resize(4, Exp::Dummy);
        out
    }

    fn fetch_multi(&mut self, entries: &[(Id, u64, bool)]) -> Vec<Exp> {
        let mut errors = Vec::new();
        let mut served: Vec<Id> = Vec::new();
        for (r, ack, honest) in entries {
            match self.check(r, *ack, *honest) {
                Some(p) => errors.push(Exp::CellErr(p, *r)),
                None if !served.contains(r) => served.push(*r),
                None => {}
            }
        }
        errors.truncate(8);
        let room = 8_usize.saturating_sub(errors.len());
        // every cell of the served queues, oldest first by arrival across queues
        let mut cells: Vec<(u64, Exp)> = served
            .iter()
            .flat_map(|r| {
                self.queues
                    .get(r)
                    .unwrap()
                    .cells
                    .iter()
                    .map(|c| (c.1, Exp::Cell(*r, c.0, c.2)))
            })
            .collect();
        cells.sort_by_key(|c| c.0);
        errors.extend(cells.into_iter().take(room).map(|c| c.1));
        errors.resize(8, Exp::Dummy);
        errors
    }

    fn queue_del(&mut self, recv: &Key, honest: bool) -> Vec<Exp> {
        let r = rid_of(&recv.pk);
        if !self.queues.contains_key(&r) {
            return vec![Exp::Err(3)];
        }
        if !honest {
            return vec![Exp::Err(4)];
        }
        self.queues.remove(&r);
        vec![Exp::Ok]
    }

    fn snapshot(&self) -> Vec<QueueSnapshot> {
        self.queues
            .iter()
            .map(|(r, q)| QueueSnapshot {
                rid: *r,
                sid: q.sid,
                cell_ids: q.cells.iter().map(|c| c.0).collect(),
                next_cell_id: q.next,
            })
            .collect()
    }

    /// An `ack` for the queue of `recv`: 0, a stored id, the newest, `next_cell_id − 1`, `next_cell_id`,
    /// `u64::MAX`, or random below `next_cell_id`.
    fn ack(&self, recv: &Key, rng: &mut StdRng, fill: bool) -> u64 {
        let q = self.queues.get(&rid_of(&recv.pk));
        let next = q.map_or(1, |q| q.next);
        if fill {
            // a fill case lets its queue reach the capacity: nothing is acknowledged
            return 0;
        }
        match (rng.random_range(0..7), q) {
            (1, Some(q)) if !q.cells.is_empty() => {
                q.cells.get(rng.random_range(0..q.cells.len())).unwrap().0
            }
            (2, _) => next.saturating_sub(1),
            (3, _) => next,
            (4, _) => u64::MAX,
            (5, _) => rng.random_range(0..next),
            _ => 0,
        }
    }
}

/// One P-07 step: a random command on queue pair `0..3` (in a fill case mostly `SEND`s to pair 0, so that the queue
/// reaches its capacity; its first step creates queue 0), the model's answer and the request's payload.
fn p07_step(
    rng: &mut StdRng,
    pool: &Pool,
    m: &mut Model,
    cl: &Client,
    cmd_seq: u32,
    fill: bool,
    first: bool,
) -> (Op, Vec<Exp>, Vec<u8>) {
    let (send_w, fetch_w, multi_w, new_w) = if fill {
        (88, 93, 96, 99)
    } else {
        (40, 60, 75, 90)
    };
    let create = fill && first;
    let roll = if create {
        multi_w
    } else {
        rng.random_range(0..100)
    };
    let honest = create || !one_in(rng, 12);
    let other = cmd_seq.wrapping_add(1);
    let pair = |rng: &mut StdRng| {
        if fill && rng.random_bool(0.95) {
            pool.pairs.first().unwrap()
        } else {
            pick(rng, &pool.pairs)
        }
    };
    if roll < send_w {
        let (recv, send) = pair(rng);
        // one in eight with another pair's sender key: a sid without a queue, or another queue's
        let send = if !fill && one_in(rng, 8) {
            &pick(rng, &pool.pairs).1
        } else {
            send
        };
        let cell = bytes(rng, 4096);
        let mut q = cl.send(cmd_seq, recv, send, &cell);
        if !honest {
            swap_sig(&mut q, cl.send(other, recv, send, &cell));
        }
        (Op::Send, m.send(recv, send, &cell, honest), payload(&q))
    } else if roll < fetch_w {
        let (recv, _) = pair(rng);
        let ack = m.ack(recv, rng, fill);
        let mut q = cl.fetch(cmd_seq, recv, ack);
        if !honest {
            swap_sig(&mut q, cl.fetch(other, recv, ack));
        }
        (Op::Fetch, m.fetch(recv, ack, honest), payload(&q))
    } else if roll < multi_w {
        let mut entries = Vec::new();
        let mut model = Vec::new();
        for k in 0..rng.random_range(1..=10) {
            let (recv, _) = pair(rng);
            let ack = m.ack(recv, rng, fill);
            let ok = honest || k != 0;
            let mut e = cl.fetch_entry(cmd_seq, recv, ack);
            if !ok {
                e.sig = cl.fetch_entry(other, recv, ack).sig;
            }
            entries.push(e);
            model.push((rid_of(&recv.pk), ack, ok));
        }
        let q = Client::fetch_multi(cmd_seq, entries);
        (Op::FetchMulti, m.fetch_multi(&model), payload(&q))
    } else if roll < new_w {
        let (recv, send) = if create {
            pool.pairs.first().unwrap()
        } else {
            pair(rng)
        };
        let send = if !create && one_in(rng, 6) {
            &pick(rng, &pool.pairs).1
        } else {
            send
        };
        let mut q = cl.queue_new(cmd_seq, recv, send);
        if !honest {
            swap_sig(&mut q, cl.queue_new(other, recv, send));
        }
        (Op::QueueNew, m.queue_new(recv, send, honest), payload(&q))
    } else {
        // a fill case never deletes the queue it fills
        let k = if fill {
            rng.random_range(1..3)
        } else {
            rng.random_range(0..3)
        };
        let recv = &pool.pairs.get(k).unwrap().0;
        let mut q = cl.queue_del(cmd_seq, recv);
        if !honest {
            swap_sig(&mut q, cl.queue_del(other, recv));
        }
        (Op::QueueDel, m.queue_del(recv, honest), payload(&q))
    }
}

/// P-07 `prop_queue_store_matches_model`: random queue commands ⇒ the model's responses and states.
#[test]
fn prop_queue_store_matches_model() {
    let seed = master_seed() ^ 0x7;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut evictions = 0_usize;
    for case in 0..cases(4) {
        let fill = case % 2 == 0;
        let pool = Pool::new(&mut rng);
        let mut b = Bench::vectors();
        let mut m = Model::default();
        // a fill case: some 150 cells into queue 0 (capacity 128); a mixed case: every command in turn
        let steps = if fill { 200 } else { 120 };
        for step in 0..steps {
            let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case} step {step}");
            let s = fresh(&b.exec);
            let (op, want, p) = p07_step(&mut rng, &pool, &mut m, &b.client, s, fill, step == 0);
            let got: Vec<Exp> = run(&mut b, &ctx, op, &[p], s)
                .iter()
                .map(observed)
                .collect();
            assert_eq!(got, want, "{ctx}: {op:?} response");
            evictions = evictions.saturating_add(
                got.iter()
                    .filter(|e| matches!(e, Exp::OkSend(_, Some(_))))
                    .count(),
            );
            assert_eq!(
                b.relay.snapshot_kat().queues,
                m.snapshot(),
                "{ctx}: {op:?} state"
            );
            let reserved = QUEUE_RESERVATION
                .checked_mul(u64::try_from(m.queues.len()).unwrap())
                .unwrap();
            assert_eq!(b.relay.budget_used_kat().0, reserved, "{ctx}: budget");
        }
    }
    assert!(
        evictions > 0,
        "SECMP_PROPTEST_SEED={seed}: no eviction reached"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// P-08.

/// What the P-08 prefix left: the relay's response frames and a pending `LINK_PUT` (its frames, how many were sent).
struct History {
    relay_frames: Vec<Frame>,
    pending: Option<(Vec<Request>, usize)>,
}

/// A few honest commands (a queue with cells, maybe link data, a fetch), then, one case in three, the first one or
/// two frames of a `LINK_PUT`.
fn p08_prefix(b: &mut Bench, pool: &Pool, rng: &mut StdRng, ctx: &str) -> History {
    let mut h = History {
        relay_frames: Vec::new(),
        pending: None,
    };
    let (recv, send) = pool.pair(rng, Some(0));
    let mut ops = vec![Op::QueueNew];
    ops.extend(std::iter::repeat_n(Op::Send, rng.random_range(0..3)));
    if rng.random_bool(0.5) {
        ops.push(Op::LinkPut);
    }
    ops.push(Op::Fetch);
    for op in ops {
        let s = fresh(&b.exec);
        let frames = match op {
            Op::QueueNew => vec![b.client.queue_new(s, recv, send)],
            Op::Send => vec![b.client.send(s, recv, send, &bytes(rng, 4096))],
            Op::LinkPut => link_put(rng, pool, &b.client, s, false, true),
            _ => vec![b.client.fetch(s, recv, 0)],
        };
        let payloads: Vec<Vec<u8>> = frames.iter().map(payload).collect();
        let outcomes = feed_at(&mut b.client, &mut b.exec, &b.relay, &payloads, &[]);
        // keep copies of the answer for the reflection mutation
        for o in &outcomes {
            if let Outcome::Respond(fr) = o {
                h.relay_frames.extend(fr.iter().cloned());
            }
        }
        shape(ctx, &mut b.client, op, s, outcomes, Admission::Run);
    }
    if one_in(rng, 3) {
        let s = fresh(&b.exec);
        let frames = link_put(rng, pool, &b.client, s, false, true);
        let n_sent = rng.random_range(1..=2_usize);
        for f in frames.iter().take(n_sent) {
            let unit = b.client.seal(f);
            let out = b.exec.on_unit(&b.relay, &unit, now(), &mut draws());
            assert!(matches!(out, Outcome::Pending), "{ctx}: pending LINK_PUT");
        }
        h.pending = Some((frames, n_sent));
    }
    h
}

/// The payload of the next valid frame on `b`'s link: the pending `LINK_PUT`'s next `CONT`, else a random honest
/// request (`PING`, `FETCH`, `SEND`, `QUEUE_NEW`, `LINK_GET`, `LINK_PUT` frame 1).
fn next_valid(b: &Bench, pool: &Pool, h: &History, rng: &mut StdRng) -> Vec<u8> {
    if let Some((frames, sent)) = &h.pending {
        return payload(frames.get(*sent).unwrap());
    }
    let s = fresh(&b.exec);
    let (recv, send) = pool.pair(rng, Some(0));
    let req = match rng.random_range(0..6) {
        0 => Client::ping(s),
        1 => b.client.fetch(s, recv, 0),
        2 => b.client.send(s, recv, send, &bytes(rng, 4096)),
        3 => b.client.queue_new(s, &pool.pairs.get(1).unwrap().0, send),
        4 => Client::link_get_consume(s, &id(rng)),
        _ => link_put(rng, pool, &b.client, s, false, true).swap_remove(0),
    };
    payload(&req)
}

/// A payload that violates a D.2 decoder rule while keeping valid padding (§4.1, §9.7 item 7; reading OPEN-6):
/// an unknown opcode, a trailing non-zero byte, a truncation, a boolean or count out of range, a small-order key.
fn decoder_fault(valid: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let unknown = |rng: &mut StdRng| {
        let op = *pick(
            rng,
            &[0x00_u8, 0x0a, 0x10, 0x55, 0x7e, 0x80, 0x8f, 0xc3, 0xff],
        );
        let n = rng.random_range(0..=64);
        let tail = bytes(rng, n);
        [&[op][..], valid.get(1..5).unwrap(), &tail].concat()
    };
    let mut v = valid.to_vec();
    let op = *valid.first().unwrap();
    match rng.random_range(0..4) {
        0 => unknown(rng),
        1 if v.len() < 4335 => {
            v.push(mask(rng));
            v
        }
        1 | 2 => {
            v.truncate(rng.random_range(0..v.len()));
            v
        }
        _ => {
            let set = |v: &mut Vec<u8>, i: usize, x: u8| *v.get_mut(i).unwrap() = x;
            match op {
                // LINK_PUT one_time, LINK_GET mode: booleans (§4.1)
                opcode::LINK_PUT | opcode::LINK_GET => {
                    set(&mut v, 21, rng.random_range(2..=u8::MAX));
                }
                // FETCH_MULTI count 1..=32 (D.2)
                opcode::FETCH_MULTI => set(&mut v, 5, *pick(rng, &[0, 33, 0xff])),
                // CONT idx 1 or 2
                opcode::CONT => set(&mut v, 5, *pick(rng, &[0, 3, 0xff])),
                // QUEUE_NEW recv_pk := the identity point (small order, §4.1 (b))
                opcode::QUEUE_NEW => {
                    let mut identity = [0_u8; 32];
                    *identity.first_mut().unwrap() = 1;
                    v.get_mut(5..37).unwrap().copy_from_slice(&identity);
                }
                _ => return unknown(rng),
            }
            v
        }
    }
}

/// A frame the multi-frame assembly refuses (ADR-048 (f), SQ-27): with a `LINK_PUT` pending another request,
/// `SKEY`, its `CONT` with another `cmd_seq` or the other `idx`, or a new `LINK_PUT`; with nothing pending a `CONT`.
fn assembly_fault(b: &Bench, h: &History, rng: &mut StdRng) -> Vec<u8> {
    let s = fresh(&b.exec);
    let Some((frames, sent)) = &h.pending else {
        let mut data = [0_u8; 4100];
        rng.fill(&mut data[..]);
        let idx = if rng.random_bool(0.5) {
            ContIdx::One
        } else {
            ContIdx::Two
        };
        return payload(&Request {
            cmd_seq: rng.random(),
            cmd: RequestCmd::Cont(Cont {
                idx,
                data: Box::new(data),
            }),
        });
    };
    let expected = frames.get(*sent).unwrap();
    match rng.random_range(0..5) {
        0 => payload(&Client::ping(s)),
        1 => skey(s),
        2 => payload(&Request {
            cmd_seq: expected.cmd_seq ^ rng.random_range(1..=u32::MAX),
            cmd: expected.cmd.clone(),
        }),
        3 => payload(frames.get(if *sent == 1 { 2 } else { 1 }).unwrap()),
        _ => payload(frames.first().unwrap()),
    }
}

/// The P-08 unit of mutation class `class` (0–7) and whether the relay must reject it.
fn p08_unit(
    b: &mut Bench,
    pool: &Pool,
    h: &History,
    class: usize,
    rng: &mut StdRng,
) -> (Vec<u8>, bool) {
    let valid = next_valid(b, pool, h, rng);
    match class {
        0 => {
            let mut unit = b.client.seal_payload(&valid);
            *unit.get_mut(rng.random_range(0..FRAME)).unwrap() ^= mask(rng);
            (unit, true)
        }
        1 => {
            let mut unit = b.client.seal_payload(&valid);
            if rng.random_bool(0.5) {
                unit.truncate(rng.random_range(0..FRAME));
            } else {
                let n = rng.random_range(1..=FRAME);
                unit.extend(bytes(rng, n));
            }
            (unit, true)
        }
        2 => {
            // sealed under another counter: ahead (a skip) or behind (a replay position)
            let c = b.client.link.send_counter().unwrap();
            let k = rng.random_range(1..=4);
            let skewed = c
                .checked_sub(k)
                .filter(|_| rng.random_bool(0.5))
                .unwrap_or(c.checked_add(k).unwrap());
            b.client.link.set_send_counter_kat(skewed);
            (b.client.seal_payload(&valid), true)
        }
        3 => {
            // a frame of the other direction (reflection, spec §8.3 `:557`)
            let f = pick(rng, &h.relay_frames);
            (f.to_vec(), true)
        }
        4 => (bad_padding(b, &valid, rng), true),
        5 => (b.client.seal_payload(&decoder_fault(&valid, rng)), true),
        6 => (b.client.seal_payload(&assembly_fault(b, h, rng)), true),
        _ => {
            let mut v = valid;
            let i = rng.random_range(0..v.len());
            *v.get_mut(i).unwrap() ^= mask(rng);
            (b.client.seal_payload(&v), false)
        }
    }
}

/// A frame sealed under the right key and counter (an independent XChaCha20-Poly1305, spec §8.4) whose 4336-byte
/// plaintext is not ISO/IEC 7816-4 padded: no `0x80` marker, a non-zero byte after it, or all zero (spec §4.1).
fn bad_padding(b: &Bench, valid: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let link = &b.client.link;
    let mut plain = pad(valid, PLAIN).unwrap();
    match rng.random_range(0..3) {
        0 => {
            // the bytes after the payload random, the last one neither 0 nor 0x80
            let tail = plain.get_mut(valid.len()..).unwrap();
            rng.fill(tail);
            *plain.last_mut().unwrap() = *pick(rng, &[0x01_u8, 0x7f, 0x81, 0xff]);
        }
        1 => {
            // a byte after the 0x80 marker set to a value other than 0 and 0x80 (the marker at the last byte: that
            // byte itself)
            let after = valid
                .len()
                .checked_add(1)
                .unwrap()
                .min(PLAIN.checked_sub(1).unwrap());
            let i = rng.random_range(after..PLAIN);
            *plain.get_mut(i).unwrap() = *pick(rng, &[0x01_u8, 0x7f, 0x81, 0xff]);
        }
        _ => plain.fill(0),
    }
    let ctr = link.send_counter().unwrap();
    let nonce: [u8; 24] = [&[0_u8; 16][..], &ctr.to_be_bytes()]
        .concat()
        .try_into()
        .unwrap();
    let ad = [Label::LinkFrame.as_bytes(), link.sess_id()].concat();
    let key = SecretBytes::from_slice(link.keys_kat().0).unwrap();
    Aead::seal(&key, Nonce24::from_bytes_kat(nonce), &ad, &plain).unwrap()
}

/// P-08 for the records: a `HELLO` with one bit flipped, or an `HS1` with one byte xored, on a new connection to
/// `b`'s relay ⇒ closed, nothing emitted, no draw, the store unchanged.
fn p08_record(b: &Bench, hs1: bool, rng: &mut StdRng, ctx: &str) {
    let digest = b.digest();
    let mut conn = Connection::accept(&b.relay, now()).unwrap();
    let record = if hs1 {
        let info = conn.on_bytes(&HELLO, now(), &mut draws());
        assert!(!info.close && info.bytes.len() == 1744, "{ctx}: RELAYINFO");
        let access = b.fx.access();
        let (_, st) = link::client::start(b.fx.relay_fp, Some(&access), NOW).unwrap();
        let (mut rec, _) = st
            .on_relayinfo(&info.bytes, &mut FixedEntropy::new(&bytes(rng, 160)))
            .unwrap();
        let at = rng.random_range(0..rec.len());
        *rec.get_mut(at).unwrap() ^= mask(rng);
        rec
    } else {
        flip(&HELLO, rng.random_range(0..HELLO.len()))
    };
    let mut ent = draws();
    let left = ent.remaining();
    let out = conn.on_bytes(&record, now(), &mut ent);
    assert!(out.close, "{ctx}: the connection stays open");
    assert!(
        out.bytes.is_empty(),
        "{ctx}: {} bytes emitted",
        out.bytes.len()
    );
    assert_eq!(ent.remaining(), left, "{ctx}: random draws");
    assert_eq!(b.digest(), digest, "{ctx}: store");
}

/// P-08 `prop_rejection_leaves_link_and_store_unchanged`: a rejected mutation of a valid unit or record changes no
/// counter, no `last`, no store, draws nothing and emits nothing.
#[test]
fn prop_rejection_leaves_link_and_store_unchanged() {
    let seed = master_seed() ^ 0x8;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut checked = 0_u32;
    for case in 0..cases(40) {
        let class = rng.random_range(0..10_usize);
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case} class {class}");
        let pool = Pool::new(&mut rng);
        let mut b = Bench::vectors();
        let h = p08_prefix(&mut b, &pool, &mut rng, &ctx);
        if class >= 8 {
            p08_record(&b, class == 9, &mut rng, &ctx);
            checked = checked.saturating_add(1);
            continue;
        }
        let state = |b: &Bench| {
            let l = b.exec.link();
            (l.recv_counter(), l.send_counter(), b.exec.last_cmd_seq())
        };
        let before = (state(&b), b.digest());
        let (unit, must) = p08_unit(&mut b, &pool, &h, class, &mut rng);
        let mut ent = draws();
        let left = ent.remaining();
        match b.exec.on_unit(&b.relay, &unit, now(), &mut ent) {
            Outcome::Teardown => {
                assert_eq!(
                    (state(&b), b.digest()),
                    before,
                    "{ctx}: link or store changed"
                );
                assert_eq!(ent.remaining(), left, "{ctx}: random draws");
                checked = checked.saturating_add(1);
            }
            Outcome::Pending | Outcome::Respond(_) => {
                assert!(!must, "{ctx}: the mutated unit was accepted");
            }
        }
    }
    assert!(
        checked > 0,
        "SECMP_PROPTEST_SEED={seed}: no rejection checked"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// P-10.

/// `(present, consumed, the blob)` of a `LINKR` answer (frame 1's part and the two `CONT`s).
fn linkr(r: &[Response]) -> (bool, bool, Vec<u8>) {
    let mut blob = Vec::new();
    let mut flags = (false, false);
    for x in r {
        match &x.cmd {
            ResponseCmd::LinkR {
                present,
                consumed,
                blob_part,
            } => {
                flags = (*present, *consumed);
                blob.extend_from_slice(blob_part.as_slice());
            }
            ResponseCmd::Cont(c) => blob.extend_from_slice(c.data.as_slice()),
            _ => {}
        }
    }
    (flags.0, flags.1, blob)
}

/// P-10 `prop_one_time_link_data_single_winner`: random interleavings of consume and owner status from several
/// links ⇒ exactly one consume per one-time entry returns the blob (spec §9.4 "the first consume wins").
#[test]
fn prop_one_time_link_data_single_winner() {
    let seed = master_seed() ^ 0xa;
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(6) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let fx = RelayFx::case1();
        let relay = fx.relay(Limits::vectors());
        let owner = Key::from_seed(&bytes(&mut rng, 32));
        let mut links: Vec<(Client, Executor)> = (0..rng.random_range(2..=4))
            .map(|_| open_link(&relay, &fx, &mut rng))
            .collect();
        // the inviter's link puts one to three one-time blobs
        let mut entries: Vec<(Id, Vec<u8>, bool, u32)> = Vec::new();
        for _ in 0..rng.random_range(1..=3) {
            let (ld, blob) = (id(&mut rng), bytes(&mut rng, 12_360));
            let (cl, ex) = links.first_mut().unwrap();
            let s = fresh(ex);
            let put = Put {
                ld_id: &ld,
                one_time: true,
                expires_bucket: EXPIRES,
                owner: &owner,
                blob: &blob,
            };
            let payloads: Vec<Vec<u8>> = cl.link_put(s, &put).iter().map(payload).collect();
            let outcomes = feed_at(cl, ex, &relay, &payloads, &[]);
            let r = shape(&ctx, cl, Op::LinkPut, s, outcomes, Admission::Run);
            assert_eq!(class(&r), "OK", "{ctx}: LINK_PUT");
            entries.push((ld, blob, false, 0));
        }
        let unknown = id(&mut rng);
        // random (link, entry or the unknown ld_id, consume?) events, then one consume of every entry
        let mut events: Vec<(usize, Option<usize>, bool)> = (0..rng.random_range(6..=24))
            .map(|_| {
                let ld = (!one_in(&mut rng, 6)).then(|| rng.random_range(0..entries.len()));
                (rng.random_range(0..links.len()), ld, rng.random_bool(0.6))
            })
            .collect();
        for k in 0..entries.len() {
            events.push((rng.random_range(0..links.len()), Some(k), true));
        }
        for (step, (who, ld, consume)) in events.into_iter().enumerate() {
            let ctx = format!("{ctx} step {step}");
            let (cl, ex) = links.get_mut(who).unwrap();
            let s = fresh(ex);
            let ld_id = ld.map_or(unknown, |k| entries.get(k).unwrap().0);
            let req = if consume {
                Client::link_get_consume(s, &ld_id)
            } else {
                cl.link_get_owner(s, &ld_id, &owner)
            };
            let outcomes = feed_at(cl, ex, &relay, &[payload(&req)], &[]);
            let r = shape(&ctx, cl, Op::LinkGet, s, outcomes, Admission::Run);
            let (got_present, got_consumed, blob) = linkr(&r);
            let Some(entry) = ld.and_then(|k| entries.get_mut(k)) else {
                assert_eq!(
                    (got_present, got_consumed),
                    (false, false),
                    "{ctx}: unknown ld_id"
                );
                continue;
            };
            let gone = entry.2;
            if consume {
                assert_eq!((got_present, got_consumed), (!gone, gone), "{ctx}: consume");
                if got_present {
                    assert_eq!(blob, entry.1, "{ctx}: the stored blob");
                    entry.2 = true;
                    entry.3 = entry.3.checked_add(1).unwrap();
                }
            } else {
                assert_eq!(
                    (got_present, got_consumed),
                    (!gone, gone),
                    "{ctx}: owner status"
                );
            }
        }
        assert!(
            entries.iter().all(|e| e.3 == 1),
            "{ctx}: winners per entry {:?}",
            entries.iter().map(|e| e.3).collect::<Vec<_>>()
        );
        let snap = relay.snapshot_kat();
        assert_eq!(snap.linkdata.len(), entries.len(), "{ctx}");
        assert!(
            snap.linkdata.iter().all(|e| !e.present && e.consumed),
            "{ctx}: every blob consumed, its marker kept"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// P-11.

/// A random `cmd_seq` relative to the recorded `last`: the next, a gap, equal, lower, 0, `u32::MAX`, anything.
fn p11_cmd_seq(rng: &mut StdRng, last: u32) -> u32 {
    match rng.random_range(0..40) {
        0..=13 => last.saturating_add(1),
        14..=19 => last.saturating_add(rng.random_range(2..=1000)),
        20..=26 => last,
        27..=32 => rng.random_range(0..=last),
        33..=35 => 0,
        36 => u32::MAX,
        _ => rng.random(),
    }
}

/// P-11 `prop_cmd_seq_executes_iff_greater_than_last`: random `cmd_seq` sequences ⇒ a request is executed iff its
/// `cmd_seq` is greater than `last`, and `last` is the maximum recorded, after every frame (spec §9.2, OPEN-5).
#[test]
fn prop_cmd_seq_executes_iff_greater_than_last() {
    let seed = master_seed() ^ 0xb;
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(10) {
        let pool = Pool::new(&mut rng);
        let mut b = Bench::vectors();
        let mut last = 0_u32;
        for step in 0..40 {
            let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case} step {step}");
            let s = p11_cmd_seq(&mut rng, last);
            let executed = s > last;
            let (op, payloads) = match rng.random_range(0..10) {
                0..=3 => (Op::Ping, vec![payload(&Client::ping(s))]),
                4 | 5 => (Op::Skey, vec![skey(s)]),
                6 | 7 => {
                    // a new queue each time (the budget of two answers ERR 2 after that)
                    let recv = Key::from_seed(&bytes(&mut rng, 32));
                    let sender = &pool.pairs.first().unwrap().1;
                    (
                        Op::QueueNew,
                        vec![payload(&b.client.queue_new(s, &recv, sender))],
                    )
                }
                _ => {
                    let frames = link_put(&mut rng, &pool, &b.client, s, false, true);
                    (Op::LinkPut, frames.iter().map(payload).collect())
                }
            };
            let digest = b.digest();
            let mut outcomes = Vec::new();
            for (i, p) in payloads.iter().enumerate() {
                let unit = b.client.seal_payload(p);
                outcomes.push(b.exec.on_unit(&b.relay, &unit, now(), &mut draws()));
                // recorded at the first frame iff greater; the CONT frames (same cmd_seq) are exempt
                assert_eq!(
                    b.exec.last_cmd_seq(),
                    last.max(s),
                    "{ctx}: {op:?} last after frame {i}"
                );
            }
            let adm = if executed {
                Admission::Run
            } else {
                Admission::Stale
            };
            // one ERR 6 frame when stale, right after the last frame (teardowns and early answers fail here)
            let r = shape(&ctx, &mut b.client, op, s, outcomes, adm);
            let changed = b.digest() != digest;
            match (executed, op) {
                // a stale request is answered ERR 6 (assert_d2_shape) and changes nothing
                (false, _) => assert!(!changed, "{ctx}: a stale {op:?} changed the store"),
                (true, Op::LinkPut) => {
                    assert_eq!(class(&r), "OK", "{ctx}: LINK_PUT");
                    assert!(changed, "{ctx}: an executed LINK_PUT stored nothing");
                }
                (true, Op::QueueNew) => {
                    let c = class(&r);
                    assert!(c == "OK_QUEUE_NEW" || c == "ERR 2", "{ctx}: QUEUE_NEW {c}");
                    assert_eq!(changed, c == "OK_QUEUE_NEW", "{ctx}: QUEUE_NEW store");
                }
                (true, _) => assert!(!changed, "{ctx}: {op:?} changed the store"),
            }
            last = last.max(s);
        }
    }
}
