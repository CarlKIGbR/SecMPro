// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The Rust generator of the `tr` vector suite (`vectors/SCHEMA.md` §4.9, `vectors/SCHEMA-4.9-tr.md`), written from
//! the SCHEMA text and the spec alone; it reads no vector file.
//!
//! [`generate`] runs SecMP-TR (`RatchetState` with `FixedEntropy`) through the 96 events of the SCHEMA-4.9
//! transcript. Case *i* draws only from its own SCHEMA §2 stream ([`VectorStream`], suite `tr`, index *i*): the
//! stream-derived values in the order SCHEMA-4.9 lists them, then the derived ones. The SCHEMA-4.9 tables are
//! transcribed below as static tables:
//!
//! - [`MESSAGES`]: the table "Messages" (sender, content, header `pn`/`n`, unpadded Content length) with the rules
//!   "Content per message" and "`KeyChange`";
//! - [`TRANSCRIPT`]: the table "Transcript" (party, op, message or count, the DH-step flag, `|skipped|` after the
//!   event), with the negative events of the table "Negative events" as [`Manipulation`]s.
//!
//! The generator checks every obligation of SCHEMA-4.9 while it runs (a sent header carries the table's `pn`/`n`,
//! a delivery yields the sender's Content and draws DH-step randomness exactly on a step, every negative event is
//! refused with the uniform error and a byte-identical state, `|skipped|` as tabled) and panics on a mismatch.
//!
//! Shared by the `gen-tr` example (which writes `vectors/rust/tr.json` for `cargo xtask vectors`) and the
//! `tr_generator` test.

use serde_json::{Map, Value, json};

use secmp_crypto::{
    Aead, Ed25519SigningKey, Fingerprint, HybridSigningKey, Label, MlKem768Dk, Nonce24,
    SecretBytes, VectorStream, X25519Secret, Zeroizing,
};
use secmp_proto::codec::unpad;
use secmp_proto::keys::{Ed25519Pk, HybridSig, MlKem768Ek, X25519Pk};
use secmp_proto::sizes::{BODY_LEN, CONTENT_BODY_MAX, FRAGMENT_HEADER_LEN, MLDSA65_PK_LEN};
use secmp_proto::tr::content::dummy;
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::{
    AppKind, AppMessage, BatchBody, Cell, Content, ContentBody, Fragment, FragmentPayload,
    HeaderV1, KeyChangeBody, RelayQueue, RouteDescriptor, RouteUpdateBody,
};
use secmp_proto::wire::inv::{IksPublic, Onion, RelayRef};
use secmp_proto::wire::{Id, Period};
use secmp_proto::{Decode, Encode, Error};

#[path = "tr_digest.rs"]
mod tr_digest;

use tr_digest::{digest, fields, hex};

/// The suite name (SCHEMA §3).
pub const SUITE: &str = "tr";

// ---- the tables of SCHEMA-4.9 ------------------------------------------------------------------------------------

/// A party of the transcript: `A` the initiator, `B` the responder, `AB` both (`init`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Who {
    A,
    B,
    AB,
}

use Who::{A, AB, B};

impl Who {
    const fn name(self) -> &'static str {
        match self {
            A => "A",
            B => "B",
            AB => "AB",
        }
    }
}

/// The content of a message (SCHEMA-4.9 "Content per message").
#[derive(Clone, Copy)]
enum Body {
    /// Batch of one text `AppMessage` with a payload of L raw stream bytes.
    Batch(usize),
    /// Dummy (empty body).
    Dummy,
    /// `RouteUpdate` with one `RelayQueue` (the §4.8 row `rd_relayqueue`).
    Route,
    /// Fragment `idx` of the four fragments of one `KeyChange`.
    Fragment(u16),
}

use Body::{Batch, Dummy, Fragment as Frag, Route};

/// One row of the table "Messages": sender, content, header `pn`, header `n`, unpadded Content bytes.
type Message = (Who, Body, u32, u32, usize);

/// The table "Messages" (m01 … m40); m05 per SQ-22.
const MESSAGES: [Message; 40] = [
    (A, Batch(100), 0, 0, 144),
    (A, Dummy, 0, 1, 20),
    (A, Batch(500), 0, 2, 544),
    (B, Batch(100), 0, 0, 144),
    (B, Batch(1665), 0, 1, 1709),
    (B, Dummy, 0, 2, 20),
    (A, Batch(64), 3, 0, 108),
    (A, Batch(64), 3, 1, 108),
    (A, Batch(64), 3, 2, 108),
    (A, Batch(64), 3, 3, 108),
    (B, Batch(32), 3, 0, 76),
    (B, Batch(32), 3, 1, 76),
    (B, Batch(32), 3, 2, 76),
    (A, Batch(16), 4, 0, 60),
    (A, Batch(16), 4, 10001, 60),
    (B, Batch(200), 3, 0, 244),
    (B, Batch(200), 3, 1, 244),
    (A, Frag(0), 10002, 0, 1709),
    (A, Frag(1), 10002, 1, 1709),
    (A, Frag(2), 10002, 2, 1709),
    (A, Frag(3), 10002, 3, 424),
    (B, Route, 2, 0, 176),
    (B, Batch(8), 2, 1, 52),
    (A, Batch(8), 4, 300, 52),
    (A, Batch(8), 4, 301, 52),
    (A, Batch(8), 4, 302, 52),
    (A, Batch(8), 4, 303, 52),
    (A, Batch(8), 4, 304, 52),
    (A, Batch(8), 4, 305, 52),
    (A, Batch(8), 4, 306, 52),
    (B, Dummy, 2, 0, 20),
    (B, Batch(8), 2, 1, 52),
    (B, Batch(8), 2, 2, 52),
    (B, Batch(8), 2, 3, 52),
    (B, Batch(8), 2, 4, 52),
    (A, Batch(8), 307, 0, 52),
    (A, Batch(8), 307, 1, 52),
    (A, Batch(8), 307, 2, 52),
    (B, Batch(8), 5, 0, 52),
    (B, Batch(8), 5, 1, 52),
];

/// The negative events N1 … N13 (SCHEMA-4.9 "Negative events").
#[derive(Clone, Copy)]
enum Manipulation {
    /// N1: the header re-sealed with `ct_pq` bit 0 flipped (a step; the body MAC fails).
    BadKemCt,
    /// N2: the header re-sealed with `ek_pq` := the ek of `ek_pq_seed` (stream).
    KemChangedEk,
    /// N3: the header re-sealed with `ct_pq` bit 0 flipped (a chain message).
    KemChangedCt,
    /// N4: the base cell again (current chain).
    ReplayCurrent,
    /// N5: the base cell again (its skipped key was consumed).
    ReplaySkipped,
    /// N6: the base cell without its last byte.
    Truncated,
    /// N7: the base cell with one 0x00 appended.
    Trailing,
    /// N8: the header re-sealed with `sb` bit 0 flipped in the header AD.
    WrongSb,
    /// N9: the header re-sealed with `dh_pk` := the receiver's `dh_r` (SQ-23: under the sender's current `hk_s`).
    StepWithoutNewDh,
    /// N10: the header re-sealed with `n` := the receiver's `n_r` + 2^20 + 1.
    GapOverMaxFf,
    /// N11: the header re-sealed with `flags` = 0x01.
    FlagsNonzero,
    /// N12: bit 0 of the cell's last byte (the body tag) flipped.
    BodyTagFlip,
    /// N13: bit 0 of the cell's byte 0 (the `hdr_nonce`) flipped.
    HdrNonceFlip,
}

use Manipulation::{
    BadKemCt, BodyTagFlip, FlagsNonzero, GapOverMaxFf, HdrNonceFlip, KemChangedCt, KemChangedEk,
    ReplayCurrent, ReplaySkipped, StepWithoutNewDh, Trailing, Truncated, WrongSb,
};

impl Manipulation {
    /// The `manipulation` string of the case.
    const fn name(self) -> &'static str {
        match self {
            BadKemCt => "bad-kem-ct",
            KemChangedEk => "kem-changed-mid-chain-ek",
            KemChangedCt => "kem-changed-mid-chain-ct",
            ReplayCurrent => "replay-current",
            ReplaySkipped => "replay-skipped",
            Truncated => "truncated",
            Trailing => "trailing",
            WrongSb => "wrong-sb",
            StepWithoutNewDh => "step-without-new-dh",
            GapOverMaxFf => "gap-over-max-ff",
            FlagsNonzero => "flags-nonzero",
            BodyTagFlip => "body-tag-flip",
            HdrNonceFlip => "hdr-nonce-flip",
        }
    }
}

/// An event of the transcript.
#[derive(Clone, Copy)]
enum Op {
    Init,
    /// `send` of message m<k>.
    Send(u8),
    /// `recv` of message m<k>; `true`: the message triggers a DH step.
    Recv(u8, bool),
    /// `advance` by `count` discarded Dummy cells.
    Advance(u32),
    /// `recv-reject` of a manipulation of message m<k> (the base message).
    Reject(u8, Manipulation),
}

use Op::{Advance, Init, Recv, Reject, Send};

const STEP: bool = true;
const CHAIN: bool = false;

/// The table "Transcript": party, event, `|skipped|` of the party after the event (0 for `init`).
const TRANSCRIPT: [(Who, Op, usize); 96] = [
    // phase 0
    (AB, Init, 0),
    // phase 1
    (A, Send(1), 0),
    (A, Send(2), 0),
    (A, Send(3), 0),
    (B, Recv(1, STEP), 0),
    (B, Reject(2, KemChangedEk), 0),
    (B, Reject(2, KemChangedCt), 0),
    (B, Recv(2, CHAIN), 0),
    (B, Reject(3, FlagsNonzero), 0),
    (B, Recv(3, CHAIN), 0),
    (B, Reject(3, ReplayCurrent), 0),
    // phase 2
    (B, Send(4), 0),
    (B, Send(5), 0),
    (B, Send(6), 0),
    (A, Reject(4, BadKemCt), 0),
    (A, Recv(4, STEP), 0),
    (A, Recv(5, CHAIN), 0),
    (A, Recv(6, CHAIN), 0),
    // phase 3
    (A, Send(7), 0),
    (A, Send(8), 0),
    (A, Send(9), 0),
    (A, Send(10), 0),
    (B, Recv(9, STEP), 2),
    (B, Recv(7, CHAIN), 1),
    (B, Recv(10, CHAIN), 1),
    (B, Recv(8, CHAIN), 0),
    (B, Reject(7, ReplaySkipped), 0),
    // phase 4
    (B, Send(11), 0),
    (B, Send(12), 0),
    (B, Send(13), 0),
    (A, Recv(12, STEP), 1),
    (A, Recv(13, CHAIN), 1),
    // phase 5
    (A, Send(14), 1),
    (B, Reject(14, Truncated), 0),
    (B, Reject(14, Trailing), 0),
    (B, Reject(14, WrongSb), 0),
    (B, Recv(14, STEP), 0),
    (A, Advance(10_000), 1),
    (A, Send(15), 1),
    (B, Reject(14, GapOverMaxFf), 0),
    (B, Recv(15, CHAIN), 256),
    // phase 6
    (B, Send(16), 256),
    (B, Send(17), 256),
    (A, Reject(16, StepWithoutNewDh), 1),
    (A, Recv(16, STEP), 1),
    (A, Reject(17, BodyTagFlip), 1),
    (A, Reject(17, HdrNonceFlip), 1),
    (A, Recv(17, CHAIN), 1),
    // phase 7
    (A, Send(18), 1),
    (A, Send(19), 1),
    (A, Send(20), 1),
    (A, Send(21), 1),
    (B, Recv(18, STEP), 256),
    (B, Recv(19, CHAIN), 256),
    (B, Recv(20, CHAIN), 256),
    (B, Recv(21, CHAIN), 256),
    // phase 8
    (B, Send(22), 256),
    (B, Send(23), 256),
    (A, Recv(22, STEP), 1),
    (A, Recv(23, CHAIN), 1),
    // phase 9
    (A, Advance(300), 1),
    (A, Send(24), 1),
    (A, Send(25), 1),
    (A, Send(26), 1),
    (A, Send(27), 1),
    (A, Send(28), 1),
    (A, Send(29), 1),
    (A, Send(30), 1),
    (B, Recv(24, STEP), 512),
    (B, Recv(26, CHAIN), 512),
    (B, Recv(25, CHAIN), 511),
    (B, Recv(28, CHAIN), 512),
    (B, Recv(27, CHAIN), 511),
    (B, Recv(30, CHAIN), 512),
    (B, Recv(29, CHAIN), 511),
    // phase 10
    (B, Send(31), 511),
    (B, Send(32), 511),
    (B, Send(33), 511),
    (B, Send(34), 511),
    (B, Send(35), 511),
    (A, Recv(33, STEP), 3),
    (A, Recv(31, CHAIN), 2),
    (A, Recv(32, CHAIN), 1),
    (A, Recv(35, CHAIN), 2),
    (A, Recv(34, CHAIN), 1),
    // phase 11
    (A, Send(36), 1),
    (A, Send(37), 1),
    (A, Send(38), 1),
    (B, Recv(36, STEP), 511),
    (B, Recv(37, CHAIN), 511),
    (B, Recv(38, CHAIN), 511),
    // phase 12
    (B, Send(39), 511),
    (B, Send(40), 511),
    (A, Recv(39, STEP), 1),
    (A, Recv(40, CHAIN), 1),
    // phase 13
    (A, Recv(11, CHAIN), 0),
];

/// `ts` = 1 700 000 000 + `seq` (SCHEMA-4.9 "Content per message").
const TS_BASE: u64 = 1_700_000_000;
/// `total` of the `KeyChange` fragments m18–m21.
const KEY_CHANGE_FRAGMENTS: u16 = 4;
/// Largest fragment chunk: 1689 − 20.
const CHUNK_MAX: usize = CONTENT_BODY_MAX - FRAGMENT_HEADER_LEN;
/// `period_s` of the `RelayQueue` of the `RouteUpdate` m22.
const ROUTE_PERIOD_S: u16 = 20;
/// 2^20 (N10: `n` := `n_r` + 2^20 + 1).
const TWO_POW_20: u32 = 1_048_576;
/// Sizes of the stream fields (SCHEMA §2).
const X25519_SK: usize = 32;
const MLKEM_SEED: usize = 64;
const ENCAPS_M: usize = 32;
const HDR_NONCE: usize = 24;

// ---- the generator -----------------------------------------------------------------------------------------------

fn h(b: &[u8]) -> Value {
    Value::String(hex(b))
}

/// Canonical serialisation (SCHEMA §1): keys sorted at every level, compact, ASCII only, no trailing newline.
pub fn canonical(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap();
    assert!(s.is_ascii(), "vector files are ASCII");
    s
}

/// The complete `tr` file (the Rust side of `cargo xtask vectors`).
pub fn generate() -> Value {
    let mut g = Generator::default();
    let cases: Vec<Value> = (1_u32..)
        .zip(TRANSCRIPT)
        .map(|(i, (who, op, skipped))| g.event(i, who, op, skipped))
        .collect();
    json!({
        "schema": 4,
        "suite": SUITE,
        "spec": "SecMP/1 rev 2.3",
        "generator": "secmp-rust",
        "cases": cases,
    })
}

/// A sent message: its `send` case id, its cell and its unpadded Content.
struct Sent {
    case: String,
    cell: Vec<u8>,
    content: Vec<u8>,
}

/// The two parties' states and what the events so far produced.
#[derive(Default)]
struct Generator {
    a: Option<RatchetState>,
    b: Option<RatchetState>,
    /// By message number − 1.
    sent: Vec<Option<Sent>>,
    /// The `KeyChange` of m18–m21: `msg_id` and the reassembled bytes `0x05 ‖ KeyChange`.
    key_change: Option<(Id, Vec<u8>)>,
}

/// The stream of case `i` (SCHEMA §2), recording each drawn field under its name.
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

    fn arr<const N: usize>(&mut self, name: &str) -> [u8; N] {
        self.draw(name, N).try_into().unwrap()
    }

    /// Lists input `name` (a *derived* input is listed after the case's stream draws).
    fn list(&mut self, name: &str, v: &[u8]) {
        assert!(
            self.inputs.insert(name.to_owned(), h(v)).is_none(),
            "input {name} listed twice"
        );
    }

    /// The DH-step randomness of `Decrypt` (§7.4 `DHRatchet` order): `dh_sk` 32, `kem_seed` 64, `m` 32.
    fn dh_step(&mut self) -> Vec<u8> {
        [
            self.draw("dh_sk", X25519_SK),
            self.draw("kem_seed", MLKEM_SEED),
            self.draw("m", ENCAPS_M),
        ]
        .concat()
    }
}

fn msg_name(m: u8) -> String {
    format!("m{m:02}")
}

fn case_id(i: u32) -> String {
    format!("tr-{i:04}")
}

fn message(m: u8) -> Message {
    let at = usize::from(m).checked_sub(1).unwrap();
    *MESSAGES.get(at).unwrap()
}

/// The other party (of a single party).
fn peer(who: Who) -> Who {
    assert_ne!(who, AB, "a single party");
    if who == A { B } else { A }
}

/// The unpadded encoding of a Content (§7.6, D.5).
fn unpadded(c: &Content) -> Vec<u8> {
    unpad(&c.encode().unwrap(), BODY_LEN).unwrap().to_vec()
}

/// `AD = "SecMP-TR/1 hdr" ‖ sb` (§7.3).
fn header_ad(sb: &[u8; 32]) -> Vec<u8> {
    [Label::TrHdr.as_bytes(), sb.as_slice()].concat()
}

/// The header of `cell`, opened under `hk` with the AD of `sb`.
fn open_header(cell: &[u8], hk: &SecretBytes<32>, sb: &[u8; 32]) -> HeaderV1 {
    let cell = Cell::from_bytes(cell).unwrap();
    let p = cell.parts().unwrap();
    let nonce: [u8; 24] = p.hdr_nonce.try_into().unwrap();
    let plain = Aead::open(hk, &nonce, &header_ad(sb), p.hdr_ct).expect("the header opens");
    HeaderV1::decode(&plain).unwrap()
}

/// `cell` with its header replaced by `header` sealed again under `hk` with the AD of `ad_sb`, under the cell's own
/// `hdr_nonce`; the body is unchanged (SCHEMA-4.9 "Negative events").
fn reseal(cell: &[u8], hk: &SecretBytes<32>, ad_sb: &[u8; 32], header: &[u8]) -> Vec<u8> {
    let cell = Cell::from_bytes(cell).unwrap();
    let p = cell.parts().unwrap();
    let nonce: [u8; 24] = p.hdr_nonce.try_into().unwrap();
    let hdr_ct = Aead::seal(
        hk,
        Nonce24::from_bytes_kat(nonce),
        &header_ad(ad_sb),
        header,
    )
    .unwrap();
    [p.hdr_nonce, &hdr_ct, p.body_ct, p.tag].concat()
}

/// XOR bit 0 of byte `k` of `b`.
fn flip(b: &mut [u8], k: usize) {
    let byte = b.get_mut(k).unwrap();
    *byte ^= 0x01;
}

impl Generator {
    fn state(&mut self, who: Who) -> &mut Option<RatchetState> {
        assert_ne!(who, AB, "a single party");
        if who == A { &mut self.a } else { &mut self.b }
    }

    fn peek(&self, who: Who) -> &RatchetState {
        assert_ne!(who, AB, "a single party");
        let st = if who == A { &self.a } else { &self.b };
        st.as_ref().expect("the party is initialised")
    }

    fn take(&mut self, who: Who) -> RatchetState {
        self.state(who).take().expect("the party is initialised")
    }

    fn put(&mut self, who: Who, st: RatchetState) {
        *self.state(who) = Some(st);
    }

    fn sent(&self, m: u8) -> &Sent {
        let at = usize::from(m).checked_sub(1).unwrap();
        self.sent
            .get(at)
            .and_then(Option::as_ref)
            .expect("the message was sent before")
    }

    /// Case `i`: the event `op` of `who`, checked against the table's `|skipped|`.
    fn event(&mut self, i: u32, who: Who, op: Op, skipped: usize) -> Value {
        let id = case_id(i);
        let mut s = Stream::new(i);
        let mut case = Map::new();
        case.insert("id".to_owned(), json!(id));
        case.insert("party".to_owned(), json!(who.name()));
        let (op_name, outputs) = if let Init = op {
            assert_eq!(who, AB, "{id}");
            ("init", self.init(&mut s))
        } else {
            let st = self.take(who);
            let pre = digest(&st);
            let (op_name, Step(st, mut outputs)) = self
                .party_event(&id, who, op, st, &mut s, &mut case)
                .expect("init is handled above");
            assert_eq!(fields(&st).skipped.len(), skipped, "{id}: |skipped|");
            outputs.insert("state_pre".to_owned(), json!(pre));
            outputs.insert("state_post".to_owned(), json!(digest(&st)));
            self.put(who, st);
            (op_name, outputs)
        };
        case.insert("op".to_owned(), json!(op_name));
        case.insert("inputs".to_owned(), Value::Object(s.inputs));
        case.insert("outputs".to_owned(), Value::Object(outputs));
        Value::Object(case)
    }

    /// An event of one party on its state `st`, with its case-level fields; `None` for `init`.
    fn party_event(
        &mut self,
        id: &str,
        who: Who,
        op: Op,
        st: RatchetState,
        s: &mut Stream,
        case: &mut Map<String, Value>,
    ) -> Option<(&'static str, Step)> {
        let mut set = |k: &str, v: Value| case.insert(k.to_owned(), v);
        Some(match op {
            Init => return None,
            Send(m) => {
                set("msg", json!(msg_name(m)));
                ("send", self.send(id, who, m, st, s))
            }
            Recv(m, step) => {
                set("msg", json!(msg_name(m)));
                set("from", json!(self.sent(m).case));
                ("recv", self.recv(id, who, (m, step), st, s))
            }
            Advance(count) => {
                set("count", json!(count));
                ("advance", advance(count, st, s))
            }
            Reject(m, manipulation) => {
                set("msg", json!(msg_name(m)));
                set("from", json!(self.sent(m).case));
                set("manipulation", json!(manipulation.name()));
                set("expect", json!("reject"));
                (
                    "recv-reject",
                    self.reject(id, who, (m, manipulation), st, s),
                )
            }
        })
    }

    /// `init`: `sk`, `sb`, `spk_dh_sk`, `rpk_kem_seed`, then A's draws `dh_s_sk`, `kem_s_seed`, `m` (§7.2).
    fn init(&mut self, s: &mut Stream) -> Map<String, Value> {
        let sk = SecretBytes::<32>::from_slice(&s.draw("sk", 32)).unwrap();
        let sb: [u8; 32] = s.arr("sb");
        let spk = X25519Secret::from_bytes(&s.draw("spk_dh_sk", X25519_SK)).unwrap();
        let rpk = MlKem768Dk::from_seed(&s.draw("rpk_kem_seed", MLKEM_SEED)).unwrap();
        let randomness = [
            s.draw("dh_s_sk", X25519_SK),
            s.draw("kem_s_seed", MLKEM_SEED),
            s.draw("m", ENCAPS_M),
        ]
        .concat();
        let dh_r = X25519Pk::from_bytes(spk.public_key().as_bytes()).unwrap();
        let kem_r = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).unwrap();
        let mut e = FixedEntropy::new(&randomness);
        let a = RatchetState::init_initiator_with(&sk, &sb, &dh_r, &kem_r, &mut e).unwrap();
        assert_eq!(e.remaining(), 0, "init: A draws dh_s, kem_s, m");
        let b = RatchetState::init_responder(&sk, &sb, spk, rpk).unwrap();
        let mut outputs = Map::new();
        outputs.insert("state_post_A".to_owned(), json!(digest(&a)));
        outputs.insert("state_post_B".to_owned(), json!(digest(&b)));
        self.a = Some(a);
        self.b = Some(b);
        outputs
    }

    /// `send` of m<k>: the Content's stream fields, `hdr_nonce`, then the derived `content`; Encrypt (§7.3).
    fn send(&mut self, id: &str, who: Who, m: u8, st: RatchetState, s: &mut Stream) -> Step {
        let (sender, body, pn, n, len) = message(m);
        assert_eq!(who, sender, "{id}: the sender of {}", msg_name(m));
        let content = Content {
            seq: u64::from(m),
            ts: TS_BASE.checked_add(u64::from(m)).unwrap(),
            body: self.body(body, s),
        };
        let nonce = s.draw("hdr_nonce", HDR_NONCE);
        let bytes = unpadded(&content);
        assert_eq!(bytes.len(), len, "{id}: Content bytes (unpadded)");
        s.list("content", &bytes);
        let mut e = FixedEntropy::new(&nonce);
        let (st, cell) = st
            .encrypt_with(&content, &mut e)
            .map_err(|r| r.error())
            .expect(id)
            .persist(|_| Ok::<(), ()>(()))
            .unwrap();
        assert_eq!(e.remaining(), 0, "{id}: one hdr_nonce");
        let cell = cell.as_bytes().to_vec();
        let header = open_header(&cell, st.hk_s_kat().unwrap(), st.sb_kat());
        assert_eq!((header.pn, header.n), (pn, n), "{id}: header pn, n");
        let mut outputs = Map::new();
        outputs.insert("cell".to_owned(), h(&cell));
        let at = usize::from(m).checked_sub(1).unwrap();
        if self.sent.len() <= at {
            self.sent.resize_with(at.checked_add(1).unwrap(), || None);
        }
        let slot = self.sent.get_mut(at).unwrap();
        assert!(slot.is_none(), "{id}: {} sent twice", msg_name(m));
        *slot = Some(Sent {
            case: id.to_owned(),
            cell,
            content: bytes,
        });
        Step(st, outputs)
    }

    /// `recv` of m<k>: on a DH step `dh_sk`, `kem_seed`, `m`; Decrypt (§7.4) of the `send` case's cell.
    fn recv(
        &self,
        id: &str,
        who: Who,
        (m, step): (u8, bool),
        st: RatchetState,
        s: &mut Stream,
    ) -> Step {
        assert_eq!(
            peer(message(m).0),
            who,
            "{id}: the receiver of {}",
            msg_name(m)
        );
        let randomness = if step { s.dh_step() } else { Vec::new() };
        let sent = self.sent(m);
        let mut e = FixedEntropy::new(&randomness);
        let opened = st
            .decrypt_with(&sent.cell, &mut e)
            .map_err(|r| r.error())
            .expect(id);
        let content = unpad(opened.plaintext().as_bytes(), BODY_LEN)
            .unwrap()
            .to_vec();
        assert_eq!(content, sent.content, "{id}: the sender's content");
        let (st, _) = opened.commit(|_| Ok::<(), ()>(())).unwrap();
        assert_eq!(
            e.remaining(),
            0,
            "{id}: DH-step randomness drawn exactly on a step"
        );
        let mut outputs = Map::new();
        outputs.insert("content".to_owned(), h(&content));
        Step(st, outputs)
    }

    /// `recv-reject`: the manipulation's stream fields (N2), the DH-step randomness (N1), the derived `cell`;
    /// Decrypt must refuse with the uniform error and leave the state byte-identical (§7.4 note (c)).
    fn reject(
        &self,
        id: &str,
        who: Who,
        (m, manipulation): (u8, Manipulation),
        st: RatchetState,
        s: &mut Stream,
    ) -> Step {
        let sender_who = message(m).0;
        assert_eq!(
            peer(sender_who),
            who,
            "{id}: the receiver of {}",
            msg_name(m)
        );
        let base = &self.sent(m).cell;
        let receiver = fields(&st);
        // the sender's current header key: the key the base cell is sealed under (SQ-23 for N9)
        let sender = self.peek(sender_who);
        let hk = sender.hk_s_kat().expect("the sender's hk_s");
        let sb = *sender.sb_kat();
        let edit = |f: &dyn Fn(&mut HeaderV1)| {
            let mut header = open_header(base, hk, &sb);
            f(&mut header);
            reseal(base, hk, &sb, &header.encode().unwrap())
        };
        let mut randomness = Vec::new();
        let cell = match manipulation {
            BadKemCt => {
                // N1 is rejected by the body MAC after DHRatchet: it lists DHRatchet's randomness (plan D2: the
                // Rust side rejects before drawing it)
                randomness = s.dh_step();
                edit(&|hd| flip(hd.ct_pq.as_mut_slice(), 0))
            }
            KemChangedEk => {
                let dk = MlKem768Dk::from_seed(&s.draw("ek_pq_seed", MLKEM_SEED)).unwrap();
                let ek = MlKem768Ek::from_bytes(dk.encapsulation_key().as_bytes()).unwrap();
                edit(&|hd| hd.ek_pq = ek.clone())
            }
            KemChangedCt => edit(&|hd| flip(hd.ct_pq.as_mut_slice(), 0)),
            ReplayCurrent | ReplaySkipped => base.clone(),
            Truncated => base.split_last().unwrap().1.to_vec(),
            Trailing => [base.as_slice(), &[0]].concat(),
            WrongSb => {
                let header = open_header(base, hk, &sb).encode().unwrap();
                let mut wrong = sb;
                flip(&mut wrong, 0);
                reseal(base, hk, &wrong, &header)
            }
            StepWithoutNewDh => {
                let dh_r = X25519Pk::from_bytes(&receiver.dh_r.unwrap()).unwrap();
                edit(&|hd| hd.dh_pk = dh_r)
            }
            GapOverMaxFf => {
                let n = receiver
                    .n_r
                    .checked_add(TWO_POW_20)
                    .unwrap()
                    .checked_add(1)
                    .unwrap();
                edit(&|hd| hd.n = n)
            }
            FlagsNonzero => {
                let mut header = open_header(base, hk, &sb).encode().unwrap().to_vec();
                // HeaderV1 = ver ‖ flags ‖ …: `flags` is byte 1
                *header.get_mut(1).unwrap() = 0x01;
                reseal(base, hk, &sb, &header)
            }
            BodyTagFlip => {
                let mut cell = base.clone();
                let last = cell.len().checked_sub(1).unwrap();
                flip(&mut cell, last);
                cell
            }
            HdrNonceFlip => {
                let mut cell = base.clone();
                flip(&mut cell, 0);
                cell
            }
        };
        s.list("cell", &cell);
        let before = st.to_bytes().unwrap().to_vec();
        let mut e = FixedEntropy::new(&randomness);
        let refused = st.decrypt_with(&cell, &mut e).err().expect(id);
        assert_eq!(refused.error(), Error::Rejected, "{id}: the uniform error");
        let st = refused.into_state();
        assert_eq!(
            *st.to_bytes().unwrap(),
            before,
            "{id}: state byte-identical"
        );
        Step(st, Map::new())
    }

    /// The Content body of a message, drawing its stream fields (SCHEMA-4.9 "Content per message", "`KeyChange`").
    fn body(&mut self, body: Body, s: &mut Stream) -> ContentBody {
        match body {
            Batch(len) => {
                let msg_id: Id = s.arr("msg_id");
                let payload = s.draw("payload", len);
                ContentBody::Batch(BatchBody {
                    messages: vec![AppMessage {
                        msg_id,
                        kind: AppKind::Text,
                        expire_after: 0,
                        payload: Zeroizing::new(payload),
                    }],
                })
            }
            Dummy => ContentBody::Dummy,
            Route => ContentBody::RouteUpdate(RouteUpdateBody {
                routes: vec![RouteDescriptor::RelayQueue(relay_queue(s))],
            }),
            Frag(idx) => {
                if idx == 0 {
                    assert!(self.key_change.is_none(), "one KeyChange");
                    self.key_change = Some(key_change(s));
                }
                let (msg_id, whole) = self.key_change.as_ref().expect("m18 comes first");
                let chunks: Vec<&[u8]> = whole.chunks(CHUNK_MAX).collect();
                assert_eq!(chunks.len(), usize::from(KEY_CHANGE_FRAGMENTS));
                ContentBody::Fragment(Fragment {
                    msg_id: *msg_id,
                    idx,
                    total: KEY_CHANGE_FRAGMENTS,
                    chunk: Zeroizing::new(chunks.get(usize::from(idx)).unwrap().to_vec()),
                })
            }
        }
    }
}

/// The result of one non-`init` event: the party's new state and the event's outputs (without the digests).
struct Step(RatchetState, Map<String, Value>);

/// `advance`: `count` × Encrypt(Dummy) with the next 24 bytes of `hdr_nonces` each; the cells are discarded.
fn advance(count: u32, mut st: RatchetState, s: &mut Stream) -> Step {
    let len = usize::try_from(count)
        .unwrap()
        .checked_mul(HDR_NONCE)
        .unwrap();
    let nonces = s.draw("hdr_nonces", len);
    for nonce in nonces.chunks(HDR_NONCE) {
        let mut e = FixedEntropy::new(nonce);
        st = st
            .encrypt_with(&dummy(), &mut e)
            .map_err(|r| r.error())
            .expect("advance")
            .persist(|_| Ok::<(), ()>(()))
            .unwrap()
            .0;
        assert_eq!(e.remaining(), 0);
    }
    Step(st, Map::new())
}

/// The `RelayQueue` of m22 as the §4.8 row `rd_relayqueue`: `relay_fp` 32, `onion_seed` 32 (→ `onion` from the
/// Ed25519 public key of the seed), `akc` 32, no `direct`, `sid` 16, `send_seed` 32, `period_s` 20.
fn relay_queue(s: &mut Stream) -> RelayQueue {
    let relay_fp = s.arr("relay_fp");
    let onion_key = Ed25519SigningKey::from_seed(&s.draw("onion_seed", 32)).unwrap();
    let onion_pk = Ed25519Pk::from_bytes(onion_key.verifying_key().as_bytes()).unwrap();
    let relay = RelayRef {
        relay_fp,
        onion: Onion::from_pubkey(onion_pk.as_bytes()),
        akc: s.arr("akc"),
        direct: None,
    };
    RelayQueue {
        relay,
        sid: s.arr("sid"),
        send_seed: SecretBytes::from_slice(&s.draw("send_seed", 32)).unwrap(),
        period_s: Period::from_seconds(ROUTE_PERIOD_S).unwrap(),
    }
}

/// The `KeyChange` of m18–m21 (§7.6, §3.5, §6.2): the stream fields of m18 in order, and the reassembled bytes
/// `0x05 ‖ new IKSPublic ‖ HybridSign(old IK_sig, "SecMP-TR/1 keychange", fingerprint(new IKSPublic))`.
fn key_change(s: &mut Stream) -> (Id, Vec<u8>) {
    let old_xi = s.draw("old_ik_mldsa_xi", 32);
    let old_ed = s.draw("old_ik_ed_seed", 32);
    let new_xi = s.draw("new_ik_mldsa_xi", 32);
    let new_ed = s.draw("new_ik_ed_seed", 32);
    let new_dh = X25519Secret::from_bytes(&s.draw("new_ik_dh_sk", X25519_SK)).unwrap();
    let rnd: [u8; 32] = s.arr("rnd");
    let msg_id: Id = s.arr("msg_id");
    let old = HybridSigningKey::from_seeds(&old_ed, &old_xi).unwrap();
    let new = HybridSigningKey::from_seeds(&new_ed, &new_xi)
        .unwrap()
        .verifying_key();
    let mut ik_mldsa65 = Box::new([0_u8; MLDSA65_PK_LEN]);
    ik_mldsa65.copy_from_slice(new.mldsa65());
    let iks = IksPublic {
        ik_ed25519: Ed25519Pk::from_bytes(new.ed25519()).unwrap(),
        ik_mldsa65,
        ik_dh: X25519Pk::from_bytes(new_dh.public_key().as_bytes()).unwrap(),
    };
    let fp = Fingerprint::of_encoded_iks(&iks.encode().unwrap()).unwrap();
    let sig = old
        .sign_kat(Label::TrKeychange, fp.as_bytes(), &rnd)
        .unwrap();
    let kc = KeyChangeBody {
        iks,
        sig: HybridSig::from_bytes(sig.as_bytes().as_slice()).unwrap(),
    };
    let whole = FragmentPayload::KeyChange(kc).encode().unwrap().to_vec();
    assert_eq!(whole.len(), 5391, "0x05 ‖ KeyChange");
    (msg_id, whole)
}
