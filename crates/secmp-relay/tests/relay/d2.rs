// SPDX-License-Identifier: AGPL-3.0-or-later
//! The D.2 response shape every SecMP-Q row asserts (TEST-SPEC-M5 "Conventions", [`assert_d2_shape`]) and the
//! request helpers of the b4 rows Q-01 … Q-60.
//!
//! A command is sealed by the client of a link, fed frame by frame to the relay's executor, and its answer is
//! checked by [`assert_d2_shape`]:
//!
//! - nothing is emitted before the command's last request frame, and the answer comes right after it (D.2);
//! - the exact D.2 frame count of the request's opcode, or exactly one ERR frame for the two exceptions of D.2 (a
//!   stale `cmd_seq`, spec §9.2; a request over the frame rate, §9.7 item 7) — [`Expect`];
//! - every frame is 4352 B and opens under `k_r2c` at consecutive counters: opened here with `secmp-crypto`'s
//!   XChaCha20-Poly1305 under nonce `0^16 ‖ u64be(counter)` and AD `"SecMP-LINK/1 frame" ‖ sess_id` (spec §8.4),
//!   then by the client's own response decoder;
//! - every plaintext is 4336 B, ISO/IEC 7816-4 padded (spec §4.1), and echoes the request's `cmd_seq` (D.2);
//! - the response opcodes answer the request, and every payload has its D.2 length and value rules (`CELLR`
//!   `present`, `rid`, `cell_id`; `LINKR` flags; `OK_SEND` `evicted_id`; `CONT` `idx`; the `ERR` code), read from the
//!   raw plaintext.
//!
//! The request builders take the signature as an argument so that a row can sign any message; [`d6`] writes the
//! D.6 message with its label spelled out here.

use secmp_crypto::{Aead, SecretBytes, sha256};
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::keys::Ed25519Sig;
use secmp_proto::link;
use secmp_proto::link::cont::split_blob;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::tr::{Entropy, FixedEntropy};
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{
    CellrContext, FetchEntry, LinkGetMode, Request, RequestCmd, Response,
};
use secmp_relay::budget::BudgetLimits;
use secmp_relay::{Executor, Limits, Now, Outcome, Relay};

use crate::fixture::{Bench, Client, FRAME, Key, NOW, PLAIN, Put, RelayFx, VALID_UNTIL, lots, now};

/// Request opcodes (D.2).
pub const OP_QUEUE_NEW: u8 = 0x01;
pub const OP_SKEY: u8 = 0x02;
pub const OP_SEND: u8 = 0x03;
pub const OP_FETCH: u8 = 0x04;
pub const OP_FETCH_MULTI: u8 = 0x05;
pub const OP_QUEUE_DEL: u8 = 0x06;
pub const OP_LINK_PUT: u8 = 0x07;
pub const OP_LINK_GET: u8 = 0x08;
pub const OP_PING: u8 = 0x09;
pub const OP_CONT: u8 = 0x7f;

/// Response opcodes (D.2).
pub const OK: u8 = 0x80;
pub const OK_QUEUE_NEW: u8 = 0x81;
pub const OK_SEND: u8 = 0x82;
pub const CELLR: u8 = 0x83;
pub const LINKR: u8 = 0x84;
pub const ERR: u8 = 0x8f;
pub const CONT: u8 = 0xff;

/// `(present, rid, cell_id)` of a dummy `CELLR` (D.2: `rid` and `cell_id` zero).
pub const DUMMY: (u8, Id, u64) = (0, [0; 16], 0);

/// How a request is answered (TEST-SPEC-M5 "Conventions").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// The D.2 frame count of the request's opcode.
    D2,
    /// One of the D.2 exceptions: exactly one ERR frame with this code — 6 for a stale `cmd_seq` (spec §9.2), 7 for
    /// a request over the per-link frame rate (spec §9.7 item 7).
    Single(u8),
}

/// A stale `cmd_seq`: exactly one ERR 6 frame (spec §9.2, D.2).
pub const STALE: Expect = Expect::Single(6);

/// The D.2 response frame count of a request opcode: `F` = 4 `CELLR`, `F_M` = 8 `CELLR`, `LINKR` + two `CONT`, else
/// one frame.
pub const fn d2_count(op: u8) -> usize {
    match op {
        OP_FETCH => 4,
        OP_FETCH_MULTI => 8,
        OP_LINK_GET => 3,
        OP_QUEUE_NEW | OP_SKEY | OP_SEND | OP_QUEUE_DEL | OP_LINK_PUT | OP_PING => 1,
        _ => 0,
    }
}

/// The request frames of a command: three for `LINK_PUT`, one for every other command.
pub const fn request_frames(op: u8) -> usize {
    if op == OP_LINK_PUT { 3 } else { 1 }
}

/// The D.2 payload length (`op ‖ cmd_seq ‖ fields`) of a response opcode.
const fn payload_len(op: u8) -> usize {
    match op {
        OK => 5,
        OK_QUEUE_NEW => 37,
        OK_SEND => 22,
        CELLR => 4126,
        LINKR => 4167,
        ERR => 6,
        CONT => 4106,
        _ => 0,
    }
}

/// The byte at `at`.
pub fn byte(p: &[u8], at: usize) -> u8 {
    *p.get(at).unwrap()
}

/// `N` bytes from `at`.
pub fn bytes<const N: usize>(p: &[u8], at: usize) -> [u8; N] {
    p.get(at..at.checked_add(N).unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// A big-endian `u64` at `at`.
pub fn be64(p: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes(p, at))
}

// ---------------------------------------------------------------------------------------------------------------
// The answer.

/// A `CELLR` frame (D.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellR {
    pub present: u8,
    pub rid: Id,
    pub cell_id: u64,
    pub cell: Vec<u8>,
}

impl CellR {
    /// `(present, rid, cell_id)`.
    pub const fn head(&self) -> (u8, Id, u64) {
        (self.present, self.rid, self.cell_id)
    }
}

/// A `LINKR` answer: its flags and the 12360-byte blob of its three frames (D.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkR {
    pub present: u8,
    pub consumed: u8,
    pub blob: Vec<u8>,
}

/// What a command was answered with.
#[derive(Default)]
pub struct Reply {
    /// The responses as the client's decoder read them.
    pub resp: Vec<Response>,
    /// The response payloads `op ‖ cmd_seq ‖ fields` without the padding, opened independently.
    pub raw: Vec<Vec<u8>>,
}

impl Reply {
    /// The code of a one-frame `ERR` answer.
    pub fn err(&self) -> Option<u8> {
        match self.raw.as_slice() {
            [p] if p.first() == Some(&ERR) => p.get(5).copied(),
            _ => None,
        }
    }

    /// A one-frame `OK`.
    pub fn is_ok(&self) -> bool {
        matches!(self.raw.as_slice(), [p] if p.first() == Some(&OK))
    }

    /// `OK_QUEUE_NEW { rid, sid }`.
    pub fn ok_queue_new(&self) -> Option<(Id, Id)> {
        match self.raw.as_slice() {
            [p] if p.first() == Some(&OK_QUEUE_NEW) => Some((bytes(p, 5), bytes(p, 21))),
            _ => None,
        }
    }

    /// `OK_SEND { cell_id, evicted_present, evicted_id }`.
    pub fn ok_send(&self) -> Option<(u64, u8, u64)> {
        match self.raw.as_slice() {
            [p] if p.first() == Some(&OK_SEND) => Some((be64(p, 5), byte(p, 13), be64(p, 14))),
            _ => None,
        }
    }

    /// The `CELLR` frames, in order.
    pub fn cellrs(&self) -> Vec<CellR> {
        self.raw
            .iter()
            .filter(|p| p.first() == Some(&CELLR))
            .map(|p| CellR {
                present: byte(p, 5),
                rid: bytes(p, 6),
                cell_id: be64(p, 22),
                cell: p.get(30..).unwrap().to_vec(),
            })
            .collect()
    }

    /// `(present, rid, cell_id)` of every `CELLR` frame.
    pub fn heads(&self) -> Vec<(u8, Id, u64)> {
        self.cellrs().iter().map(CellR::head).collect()
    }

    /// The `LINKR` answer (frame 1 and its two `CONT` frames).
    pub fn linkr(&self) -> Option<LinkR> {
        match self.raw.as_slice() {
            [head, one, two] if head.first() == Some(&LINKR) => Some(LinkR {
                present: byte(head, 5),
                consumed: byte(head, 6),
                blob: [
                    head.get(7..).unwrap(),
                    one.get(6..).unwrap(),
                    two.get(6..).unwrap(),
                ]
                .concat(),
            }),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The shape.

/// `XChaCha20-Poly1305.Open(k_r2c, 0^16 ‖ u64be(counter), "SecMP-LINK/1 frame" ‖ sess_id, frame)` (spec §8.4),
/// computed here from the client's direction key.
fn open_r2c(client: &Client, counter: u64, frame: &[u8]) -> Option<Vec<u8>> {
    let key = SecretBytes::<32>::from_slice(client.link.keys_kat().1).ok()?;
    let mut nonce = [0_u8; 24];
    nonce.get_mut(16..)?.copy_from_slice(&counter.to_be_bytes());
    let ad = [
        b"SecMP-LINK/1 frame".as_slice(),
        client.link.sess_id().as_slice(),
    ]
    .concat();
    Aead::open(&key, &nonce, &ad, frame)
        .ok()
        .map(|p| p.to_vec())
}

/// The payload of an ISO/IEC 7816-4 padded plaintext: everything before the last non-zero byte, which must be
/// `0x80` (spec §4.1).
fn iso_payload(plain: &[u8]) -> Option<&[u8]> {
    let marker = plain.iter().rposition(|&b| b != 0)?;
    if plain.get(marker) == Some(&0x80) {
        plain.get(..marker)
    } else {
        None
    }
}

/// The D.2 length and value rules of one response payload (TEST-SPEC-M5 Q-59).
fn field_rules(case: &str, i: usize, context: CellrContext, p: &[u8]) {
    let op = byte(p, 0);
    assert_eq!(
        p.len(),
        payload_len(op),
        "{case}: frame {i}: D.2 payload length of response opcode {op:#04x}"
    );
    match op {
        OK_SEND => {
            let (cell_id, present, evicted) = (be64(p, 5), byte(p, 13), be64(p, 14));
            assert!(cell_id >= 1, "{case}: frame {i}: OK_SEND cell_id from 1");
            assert!(present <= 1, "{case}: frame {i}: evicted_present is 0 or 1");
            assert_eq!(
                present == 0,
                evicted == 0,
                "{case}: frame {i}: evicted_id is 0 iff evicted_present is 0"
            );
        }
        CELLR => {
            let (present, rid, cell_id) = (byte(p, 5), bytes::<16>(p, 6), be64(p, 22));
            let zero_rid = rid == [0; 16];
            let fits = match present {
                0 => zero_rid && cell_id == 0,
                1 => cell_id >= 1 && zero_rid == (context == CellrContext::Fetch),
                2..=4 => !zero_rid && cell_id == 0,
                _ => false,
            };
            assert!(
                fits,
                "{case}: frame {i}: CELLR field rules (present {present}, rid zero {zero_rid}, cell_id {cell_id})"
            );
        }
        LINKR => {
            assert!(
                byte(p, 5) <= 1 && byte(p, 6) <= 1,
                "{case}: frame {i}: LINKR present and consumed are 0 or 1"
            );
        }
        ERR => assert!(
            (1..=7).contains(&byte(p, 5)),
            "{case}: frame {i}: ERR code 1..=7"
        ),
        CONT => assert!(
            (1..=2).contains(&byte(p, 5)),
            "{case}: frame {i}: CONT idx 1 or 2"
        ),
        _ => {}
    }
}

/// The response opcodes answer the request opcode `op` (D.2 table).
fn kinds(case: &str, op: u8, expect: Expect, raw: &[Vec<u8>]) {
    let ops: Vec<u8> = raw.iter().map(|p| byte(p, 0)).collect();
    // the byte after `op ‖ cmd_seq`: the ERR code, the CONT idx (an OK payload has none)
    let code = raw.first().and_then(|p| p.get(5).copied());
    let idx = |i: usize| raw.get(i).and_then(|p| p.get(5).copied());
    let fits = match expect {
        Expect::Single(c) => ops == [ERR] && code == Some(c),
        Expect::D2 => match op {
            OP_QUEUE_NEW => ops == [OK_QUEUE_NEW] || ops == [ERR],
            OP_SKEY => ops == [ERR] && code == Some(6),
            OP_SEND => ops == [OK_SEND] || ops == [ERR],
            OP_FETCH | OP_FETCH_MULTI => ops.iter().all(|&o| o == CELLR),
            OP_QUEUE_DEL | OP_LINK_PUT => ops == [OK] || ops == [ERR],
            OP_LINK_GET => ops == [LINKR, CONT, CONT] && idx(1) == Some(1) && idx(2) == Some(2),
            OP_PING => ops == [OK],
            _ => false,
        },
    };
    assert!(
        fits,
        "{case}: response opcodes {ops:02x?} answer request opcode {op:#04x} ({expect:?})"
    );
}

/// TEST-SPEC-M5 "D.2 response shape": `outcomes` are the executor's outcomes of the command's request frames, in
/// order (one, or three for `LINK_PUT`); the client of the link opens the answer. Returns the answer.
pub fn assert_d2_shape(
    case: &str,
    client: &mut Client,
    op: u8,
    cmd_seq: u32,
    outcomes: Vec<Outcome>,
    expect: Expect,
) -> Reply {
    let n_req = request_frames(op);
    assert_eq!(
        outcomes.len(),
        n_req,
        "{case}: request frames of opcode {op:#04x}"
    );
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for (i, outcome) in outcomes.into_iter().enumerate() {
        let last = i.checked_add(1) == Some(n_req);
        assert!(
            !matches!(outcome, Outcome::Teardown),
            "{case}: teardown at request frame {i}"
        );
        if let Outcome::Respond(f) = outcome {
            assert!(
                last,
                "{case}: an answer after request frame {i}, before the command's last frame"
            );
            frames = f.iter().map(|x| x.to_vec()).collect();
        } else {
            assert!(
                !last,
                "{case}: no answer right after the command's last request frame"
            );
        }
    }
    let count = match expect {
        Expect::D2 => d2_count(op),
        Expect::Single(_) => 1,
    };
    assert_eq!(
        frames.len(),
        count,
        "{case}: D.2 frame count of opcode {op:#04x} ({expect:?})"
    );
    let context = if op == OP_FETCH_MULTI {
        CellrContext::FetchMulti
    } else {
        CellrContext::Fetch
    };
    let first = client.link.recv_counter().unwrap();
    let mut reply = Reply::default();
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.len(), FRAME, "{case}: frame {i} is 4352 B");
        let counter = first.checked_add(u64::try_from(i).unwrap()).unwrap();
        let plain = open_r2c(client, counter, frame);
        assert!(
            plain.is_some(),
            "{case}: frame {i} opens under k_r2c at counter {counter}"
        );
        let plain = plain.unwrap();
        assert_eq!(plain.len(), PLAIN, "{case}: frame {i} plaintext is 4336 B");
        let payload = iso_payload(&plain);
        assert!(
            payload.is_some(),
            "{case}: frame {i} plaintext is ISO/IEC 7816-4 padded"
        );
        let payload = payload.unwrap().to_vec();
        assert_eq!(
            payload.get(1..5),
            Some(cmd_seq.to_be_bytes().as_slice()),
            "{case}: frame {i} echoes cmd_seq {cmd_seq}"
        );
        field_rules(case, i, context, &payload);
        let resp = client.open(frame, context);
        assert_eq!(
            resp.cmd_seq, cmd_seq,
            "{case}: frame {i} decodes with cmd_seq {cmd_seq}"
        );
        reply.resp.push(resp);
        reply.raw.push(payload);
    }
    assert_eq!(
        client.link.recv_counter(),
        first.checked_add(u64::try_from(count).unwrap()),
        "{case}: the client's r2c counter moved by the frame count"
    );
    kinds(case, op, expect, &reply.raw);
    reply
}

// ---------------------------------------------------------------------------------------------------------------
// Links and running commands.

/// A link of the relay: the relay, the link's client and the relay's executor of it.
pub trait Conn {
    fn parts(&mut self) -> (&Relay, &mut Client, &mut Executor);
}

impl Conn for Bench {
    fn parts(&mut self) -> (&Relay, &mut Client, &mut Executor) {
        (&self.relay, &mut self.client, &mut self.exec)
    }
}

/// A further link: a client and the relay's executor of it.
pub struct Peer {
    pub client: Client,
    pub exec: Executor,
}

/// A [`Peer`] on its relay.
pub struct On<'a> {
    pub relay: &'a Relay,
    pub peer: &'a mut Peer,
}

impl Conn for On<'_> {
    fn parts(&mut self) -> (&Relay, &mut Client, &mut Executor) {
        (self.relay, &mut self.peer.client, &mut self.peer.exec)
    }
}

impl Peer {
    /// Another honest link to `relay`: the client draws `[seed; 160]`, the relay `[!seed; 64]` (so every seed gives
    /// its own `sess_id` and keys).
    pub fn new(relay: &Relay, fx: &RelayFx, seed: u8) -> Self {
        let access = fx.access();
        let (hello, st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
        let (info, st_r) = link::relay::accept_ring(relay.keys().ring())
            .on_hello(&hello, VALID_UNTIL)
            .unwrap();
        let (hs1, wait) = st
            .on_relayinfo(&info, &mut FixedEntropy::new(&[seed; 160]))
            .unwrap();
        let (hs2, relay_link) = st_r
            .on_hs1(&hs1, &mut FixedEntropy::new(&[!seed; 64]))
            .unwrap();
        let link = wait.on_hs2(&hs2).unwrap();
        Self {
            client: Client::new(link, fx.access()),
            exec: Executor::new(relay_link, relay.limits().link_rate, now()),
        }
    }

    pub const fn on<'a>(&'a mut self, relay: &'a Relay) -> On<'a> {
        On { relay, peer: self }
    }
}

/// The unpadded payload `op ‖ cmd_seq ‖ fields` of a request.
pub fn req_payload(req: &Request) -> Vec<u8> {
    unpad(&req.encode().unwrap(), PLAIN).unwrap().to_vec()
}

/// Feed sealed frames one by one at `t`; the outcomes in order.
pub fn feed(
    c: &mut impl Conn,
    frames: &[Vec<u8>],
    t: Now,
    entropy: &mut impl Entropy,
) -> Vec<Outcome> {
    let (relay, _, exec) = c.parts();
    frames
        .iter()
        .map(|f| exec.on_unit(relay, f, t, entropy))
        .collect()
}

/// Run one command given as its request payloads (one, or three for `LINK_PUT`) at `t` and assert its D.2 shape.
pub fn cmd_with(
    c: &mut impl Conn,
    case: &str,
    payloads: &[Vec<u8>],
    expect: Expect,
    t: Now,
    entropy: &mut impl Entropy,
) -> Reply {
    let head = payloads.first().unwrap();
    let (op, seq) = (byte(head, 0), u32::from_be_bytes(bytes(head, 1)));
    let frames: Vec<Vec<u8>> = {
        let (_, client, _) = c.parts();
        payloads.iter().map(|p| client.seal_payload(p)).collect()
    };
    let outcomes = feed(c, &frames, t, entropy);
    assert_d2_shape(case, c.parts().1, op, seq, outcomes, expect)
}

/// [`cmd_with`] of raw payloads at the suite's time, with plenty of draws.
pub fn cmd_raw(c: &mut impl Conn, case: &str, payloads: &[Vec<u8>], expect: Expect) -> Reply {
    cmd_with(c, case, payloads, expect, now(), &mut lots())
}

/// Run one command given as requests (sealed by the client) and assert its D.2 shape.
pub fn cmd(c: &mut impl Conn, case: &str, reqs: &[Request], expect: Expect) -> Reply {
    let head = reqs.first().unwrap();
    let (op, seq) = (head.cmd.op(), head.cmd_seq);
    let frames: Vec<Vec<u8>> = {
        let (_, client, _) = c.parts();
        reqs.iter().map(|r| client.seal(r)).collect()
    };
    let outcomes = feed(c, &frames, now(), &mut lots());
    assert_d2_shape(case, c.parts().1, op, seq, outcomes, expect)
}

/// What a teardown leaves unchanged (TEST-SPEC-M5 "Relay teardown").
#[derive(Debug, PartialEq, Eq)]
pub struct RelaySide {
    pub recv: Option<u64>,
    pub send: Option<u64>,
    pub last: u32,
    pub store: [u8; 32],
    pub keys: Vec<[u8; 32]>,
}

/// The relay's frame counters and recorded `cmd_seq` of the link, the store digest and the relay keys
/// (fingerprints).
pub fn relay_side(c: &mut impl Conn) -> RelaySide {
    let (relay, _, exec) = c.parts();
    let l = exec.link();
    RelaySide {
        recv: l.recv_counter(),
        send: l.send_counter(),
        last: exec.last_cmd_seq(),
        store: relay.store_digest_kat(),
        keys: relay.keys().ring().iter().map(RelayKeys::fp).collect(),
    }
}

/// The unit carrying `payload` is a LINK-level rejection (spec §8.5): teardown, nothing emitted, nothing drawn, the
/// relay's counters, `last`, store and keys unchanged.
pub fn assert_teardown(c: &mut impl Conn, case: &str, payload: &[u8]) {
    let before = relay_side(c);
    let (relay, client, exec) = c.parts();
    let frame = client.seal_payload(payload);
    let mut entropy = lots();
    let left = entropy.remaining();
    let outcome = exec.on_unit(relay, &frame, now(), &mut entropy);
    assert!(matches!(outcome, Outcome::Teardown), "{case}: teardown");
    assert_eq!(entropy.remaining(), left, "{case}: nothing drawn");
    assert_eq!(
        relay_side(c),
        before,
        "{case}: relay counters, last, store and keys unchanged"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Values, messages and requests.

/// Hands out strictly increasing `cmd_seq` values from 1.
#[derive(Default)]
pub struct Seq(u32);

impl Seq {
    pub fn fresh(&mut self) -> u32 {
        self.0 = self.0.checked_add(1).unwrap();
        self.0
    }
}

/// `SHA-256(parts)[0..16]`.
pub fn id16(parts: &[&[u8]]) -> Id {
    sha256(parts).first_chunk::<16>().copied().unwrap()
}

/// A 4096-byte cell of one byte value.
pub fn cell(b: u8) -> Vec<u8> {
    vec![b; 4096]
}

/// A 12360-byte blob whose three parts differ.
pub fn blob(b: u8) -> Vec<u8> {
    (0..12_360_u32)
        .map(|i| u8::try_from(i % 251).unwrap() ^ b)
        .collect()
}

/// Limits without rate limits and with these two pools (`None`: unlimited).
pub const fn limits(queue_bytes: Option<u64>, linkdata_bytes: Option<u64>) -> Limits {
    Limits {
        budget: BudgetLimits {
            queue_bytes,
            linkdata_bytes,
        },
        ..Limits::vectors()
    }
}

/// The D.6 message `"SecMP-Q/1 " ‖ label ‖ sess_id ‖ u32be(cmd_seq) ‖ fields`, the label written out here.
pub fn d6(label: &str, sess_id: &Id, cmd_seq: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut m = [
        b"SecMP-Q/1 ".as_slice(),
        label.as_bytes(),
        sess_id,
        &cmd_seq.to_be_bytes(),
    ]
    .concat();
    for f in fields {
        m.extend_from_slice(f);
    }
    m
}

/// `QUEUE_NEW` signed message (D.6): `recv_pk ‖ send_pk ‖ token`.
pub fn msg_queue_new(sess: &Id, seq: u32, recv: &Key, send: &Key, token: &[u8; 32]) -> Vec<u8> {
    d6(
        "QUEUE_NEW",
        sess,
        seq,
        &[recv.pk.as_bytes(), send.pk.as_bytes(), token],
    )
}

/// `SEND` signed message (D.6): `sid ‖ cell`.
pub fn msg_send(sess: &Id, seq: u32, sid: &Id, cell: &[u8]) -> Vec<u8> {
    d6("SEND", sess, seq, &[sid, cell])
}

/// `FETCH` (label `FETCH`) or `FETCH_MULTI` entry (label `MFETCH`) signed message (D.6): `rid ‖ ack`.
pub fn msg_fetch(label: &str, sess: &Id, seq: u32, rid: &Id, ack: u64) -> Vec<u8> {
    d6(label, sess, seq, &[rid, &ack.to_be_bytes()])
}

/// `QUEUE_DEL` signed message (D.6): `rid`.
pub fn msg_queue_del(sess: &Id, seq: u32, rid: &Id) -> Vec<u8> {
    d6("QUEUE_DEL", sess, seq, &[rid])
}

/// `LINK_PUT` signed message (D.6): `ld_id ‖ one_time ‖ expires_bucket ‖ owner_pk ‖ token ‖ SHA-256(blob)`.
pub fn msg_link_put(sess: &Id, seq: u32, p: &Put<'_>, token: &[u8; 32]) -> Vec<u8> {
    d6(
        "LINK_PUT",
        sess,
        seq,
        &[
            p.ld_id,
            &[u8::from(p.one_time)],
            &p.expires_bucket.to_be_bytes(),
            p.owner.pk.as_bytes(),
            token,
            &sha256(&[p.blob]),
        ],
    )
}

/// `LINK_GET` owner-status signed message (D.6): `ld_id ‖ mode (1)`.
pub fn msg_link_get(sess: &Id, seq: u32, ld_id: &Id) -> Vec<u8> {
    d6("LINK_GET", sess, seq, &[ld_id, &[1]])
}

pub const fn queue_new_req(
    cmd_seq: u32,
    recv: &Key,
    send: &Key,
    token: [u8; 32],
    sig: Ed25519Sig,
) -> Request {
    Request {
        cmd_seq,
        cmd: RequestCmd::QueueNew {
            recv_pk: recv.pk,
            send_pk: send.pk,
            token,
            sig,
        },
    }
}

pub fn send_req(cmd_seq: u32, sid: Id, cell: &[u8], sig: Ed25519Sig) -> Request {
    Request {
        cmd_seq,
        cmd: RequestCmd::Send {
            sid,
            cell: Cell::from_bytes(cell).unwrap(),
            sig,
        },
    }
}

pub const fn fetch_req(cmd_seq: u32, rid: Id, ack: u64, sig: Ed25519Sig) -> Request {
    Request {
        cmd_seq,
        cmd: RequestCmd::Fetch { rid, ack, sig },
    }
}

pub const fn entry(rid: Id, ack: u64, sig: Ed25519Sig) -> FetchEntry {
    FetchEntry { rid, ack, sig }
}

pub const fn queue_del_req(cmd_seq: u32, rid: Id, sig: Ed25519Sig) -> Request {
    Request {
        cmd_seq,
        cmd: RequestCmd::QueueDel { rid, sig },
    }
}

/// The three frames of a `LINK_PUT` with this token and signature.
pub fn link_put_req(cmd_seq: u32, p: &Put<'_>, token: [u8; 32], sig: Ed25519Sig) -> [Request; 3] {
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
                sig,
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

pub const fn link_get_owner_req(cmd_seq: u32, ld_id: Id, sig: Ed25519Sig) -> Request {
    Request {
        cmd_seq,
        cmd: RequestCmd::LinkGet {
            ld_id,
            mode: LinkGetMode::OwnerStatus(sig),
        },
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Honest commands (the fixture's builders), run and shape-checked.

pub fn run_queue_new(c: &mut impl Conn, case: &str, seq: u32, recv: &Key, send: &Key) -> Reply {
    let req = c.parts().1.queue_new(seq, recv, send);
    cmd(c, case, &[req], Expect::D2)
}

pub fn run_send(
    c: &mut impl Conn,
    case: &str,
    seq: u32,
    recv: &Key,
    send: &Key,
    cell: &[u8],
) -> Reply {
    let req = c.parts().1.send(seq, recv, send, cell);
    cmd(c, case, &[req], Expect::D2)
}

pub fn run_fetch(c: &mut impl Conn, case: &str, seq: u32, recv: &Key, ack: u64) -> Reply {
    let req = c.parts().1.fetch(seq, recv, ack);
    cmd(c, case, &[req], Expect::D2)
}

/// `FETCH_MULTI` of honest entries `(recv key, ack)` in this order.
pub fn run_fetch_multi(c: &mut impl Conn, case: &str, seq: u32, entries: &[(&Key, u64)]) -> Reply {
    let client = c.parts().1;
    let list = entries
        .iter()
        .map(|(k, ack)| client.fetch_entry(seq, k, *ack))
        .collect();
    cmd(c, case, &[Client::fetch_multi(seq, list)], Expect::D2)
}

pub fn run_queue_del(c: &mut impl Conn, case: &str, seq: u32, recv: &Key) -> Reply {
    let req = c.parts().1.queue_del(seq, recv);
    cmd(c, case, &[req], Expect::D2)
}

pub fn run_put(c: &mut impl Conn, case: &str, seq: u32, p: &Put<'_>) -> Reply {
    let reqs = c.parts().1.link_put(seq, p);
    cmd(c, case, &reqs, Expect::D2)
}

pub fn run_consume(c: &mut impl Conn, case: &str, seq: u32, ld_id: &Id) -> Reply {
    cmd(c, case, &[Client::link_get_consume(seq, ld_id)], Expect::D2)
}

pub fn run_owner(c: &mut impl Conn, case: &str, seq: u32, ld_id: &Id, owner: &Key) -> Reply {
    let req = c.parts().1.link_get_owner(seq, ld_id, owner);
    cmd(c, case, &[req], Expect::D2)
}

pub fn run_ping(c: &mut impl Conn, case: &str, seq: u32) -> Reply {
    cmd(c, case, &[Client::ping(seq)], Expect::D2)
}
