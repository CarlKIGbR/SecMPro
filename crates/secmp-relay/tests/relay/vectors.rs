// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replay of the link-A command groups of the `link` suite (`vectors/SCHEMA-4.11-link.md`) through the relay and
//! the client (TEST-SPEC-M5 (a): V-06…V-16, V-20). Every link-A case runs in event order from `link-0006` on one
//! relay and one link (a shared replay, `OnceLock`). Per case:
//!
//! - the client builds the requests of the positive cases from the case inputs (keys, cells, blob; signatures and
//!   tokens computed by the fixture from D.6/§9.6) and they equal `req`; every `req` seals to `req_frames`;
//! - the relay answers `req_frames` with exactly `resp_frames` (byte for byte, its draws taken from the case's
//!   relay inputs in response-frame order, all of them consumed), right after the command's last request frame;
//! - the client opens `resp_frames` to `resp`; both sides' counters equal `link_post`; the store equals
//!   `store_post`.
//!
//! The derived values (`rid`, `sid`, `token`, `sig`, `sig_0`, `sig_1`) are recomputed and compared. Every assertion
//! message names the case id.

use std::sync::OnceLock;

use secmp_crypto::sha256;
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::frame::{LinkGetMode, Request, RequestCmd};
use secmp_relay::Outcome;
use secmp_relay::relay::kat::{LinkDataSnapshot, QueueSnapshot, StoreSnapshot};
use serde_json::Value;

use crate::fixture::{
    Bench, Case, Client, EXPIRES, FRAME, Key, PLAIN, Put, decode_request, now, payload_of,
    reference, rid_of, sid_of, token, unhex,
};

/// The `CELLR` context of a request by its opcode (SKEY has no request type).
const fn context_of_op(op: u8) -> secmp_proto::wire::frame::CellrContext {
    if op == 0x05 {
        secmp_proto::wire::frame::CellrContext::FetchMulti
    } else {
        secmp_proto::wire::frame::CellrContext::Fetch
    }
}

/// What the replay of one case produced.
pub struct Run {
    /// The request payloads the client built from the inputs (positive cases).
    built: Option<Vec<Vec<u8>>>,
    /// The client's frames of the case's request payloads.
    sealed: Vec<Vec<u8>>,
    /// The relay's frames after each request unit, in order.
    out: Vec<Vec<Vec<u8>>>,
    /// The response payloads the client decoded.
    opened: Vec<Vec<u8>>,
    /// Relay (`c2r`, `r2c`, `cmd_seq`) after the case.
    relay_post: (u64, u64, u32),
    /// Client (`c2r`, `r2c`) after the case.
    client_post: (u64, u64),
    snapshot: StoreSnapshot,
    /// Relay draws left over (must be 0).
    left: usize,
    /// `send-fill`: SHA-256 of req₁ ‖ resp₁ ‖ … and the last response payload.
    fill: Option<([u8; 32], Vec<u8>)>,
}

/// The relay's draws of a case in response-frame order (reading REF-M5 7): an error frame's `cell_r`, the dummies
/// by index, a dummy blob.
fn relay_draws(c: &Case) -> Vec<u8> {
    let mut d = Vec::new();
    if c.has_input("cell_r") {
        d.extend(c.input("cell_r"));
    }
    for i in 0.. {
        let k = format!("dummy_{i}");
        if !c.has_input(&k) {
            break;
        }
        d.extend(c.input(&k));
    }
    if c.has_input("dummy_blob") {
        d.extend(c.input("dummy_blob"));
    }
    d
}

/// Queue A (`link-0006`), queue B (`link-0015`) and L's owner (`link-0025`).
struct Keys {
    a: (Key, Key),
    b: (Key, Key),
    owner: Key,
}

impl Keys {
    fn new() -> Self {
        let r = reference();
        let pair = |n: usize| {
            (
                Key::from_seed(&r.case(n).input("recv_seed")),
                Key::from_seed(&r.case(n).input("send_seed")),
            )
        };
        Self {
            a: pair(6),
            b: pair(15),
            owner: Key::from_seed(&r.case(25).input("owner_seed")),
        }
    }
}

fn payloads(reqs: &[Request]) -> Vec<Vec<u8>> {
    reqs.iter()
        .map(|r| unpad(&r.encode().unwrap(), PLAIN).unwrap().to_vec())
        .collect()
}

/// The requests of the positive link-A cases, built from the inputs (`None` for the command-error cases, whose
/// manipulated requests are taken from the file).
fn build(n: usize, case: &Case, cl: &Client, k: &Keys) -> Option<Vec<Request>> {
    let seq = case.cmd_seq();
    let file = reference();
    let one = |req: Request| Some(vec![req]);
    match n {
        6 | 9 => one(cl.queue_new(seq, &k.a.0, &k.a.1)),
        15 => one(cl.queue_new(seq, &k.b.0, &k.b.1)),
        7 | 10 | 11 | 18 => one(cl.send(seq, &k.a.0, &k.a.1, &case.input("cell"))),
        17 | 21 => one(cl.send(seq, &k.b.0, &k.b.1, &case.input("cell"))),
        8 | 23 => one(Client::ping(seq)),
        12 | 13 => one(cl.fetch(seq, &k.a.0, 0)),
        14 => one(cl.fetch(seq, &k.a.0, 2)),
        22 => one(cl.fetch(seq, &k.b.0, 0)),
        19 => one(Client::fetch_multi(
            seq,
            vec![
                cl.fetch_entry(seq, &k.b.0, 0),
                cl.fetch_entry(seq, &k.a.0, 2),
            ],
        )),
        24 => one(cl.queue_del(seq, &k.a.0)),
        25 => {
            let ld_id: [u8; 16] = case.input("ld_id").try_into().unwrap();
            Some(
                cl.link_put(
                    seq,
                    &Put {
                        ld_id: &ld_id,
                        one_time: true,
                        expires_bucket: EXPIRES,
                        owner: &k.owner,
                        blob: &case.input("blob"),
                    },
                )
                .to_vec(),
            )
        }
        27 | 29 => {
            let ld_id: [u8; 16] = file.case(25).input("ld_id").try_into().unwrap();
            one(cl.link_get_owner(seq, &ld_id, &k.owner))
        }
        28 => {
            let ld_id: [u8; 16] = file.case(25).input("ld_id").try_into().unwrap();
            one(Client::link_get_consume(seq, &ld_id))
        }
        _ => None,
    }
}

/// The client's frames, the relay's frames per request unit, the decoded response payloads.
type Exchange = (Vec<Vec<u8>>, Vec<Vec<Vec<u8>>>, Vec<Vec<u8>>);

/// Run the request payloads of a case: seal, relay, open.
fn run_requests(b: &mut Bench, reqs: &[Vec<u8>], entropy: &mut FixedEntropy) -> Exchange {
    let context = context_of_op(*reqs.first().unwrap().first().unwrap());
    let mut sealed = Vec::new();
    let mut out = Vec::new();
    let mut opened = Vec::new();
    for payload in reqs {
        let frame = b.client.seal_payload(payload);
        let outcome = b.unit(&frame, now(), entropy);
        assert!(
            !matches!(outcome, Outcome::Teardown),
            "teardown on an honest replay"
        );
        let frames: Vec<Vec<u8>> = match outcome {
            Outcome::Respond(f) => f.iter().map(|x| x.to_vec()).collect(),
            Outcome::Pending | Outcome::Teardown => Vec::new(),
        };
        for f in &frames {
            opened.push(payload_of(&b.client.open(f, context)));
        }
        sealed.push(frame);
        out.push(frames);
    }
    (sealed, out, opened)
}

fn fill(b: &mut Bench, c: &Case, k: &Keys) -> ([u8; 32], Vec<u8>) {
    let count = u32::try_from(c.raw.get("count").and_then(Value::as_u64).unwrap()).unwrap();
    let cell = c.input("fill_cell");
    let mut all = Vec::new();
    let mut last = Vec::new();
    for i in 0..count {
        let req = b
            .client
            .send(c.cmd_seq().checked_add(i).unwrap(), &k.b.0, &k.b.1, &cell);
        let (sealed, out, opened) = run_requests(b, &payloads(&[req]), &mut FixedEntropy::new(&[]));
        all.extend(sealed.concat());
        all.extend(out.concat().concat());
        last = opened.concat();
    }
    (sha256(&[&all]), last)
}

fn snapshot_of(c: &Case) -> StoreSnapshot {
    let sp = c.outputs.get("store_post").unwrap();
    let id = |v: &Value| -> [u8; 16] { unhex(v.as_str().unwrap()).try_into().unwrap() };
    let num = |v: &Value| v.as_u64().unwrap();
    let queues = sp
        .get("queues")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|q| QueueSnapshot {
            rid: id(q.get("rid").unwrap()),
            sid: id(q.get("sid").unwrap()),
            cell_ids: q
                .get("cell_ids")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .map(num)
                .collect(),
            next_cell_id: num(q.get("next_cell_id").unwrap()),
        })
        .collect();
    let linkdata = sp
        .get("linkdata")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|e| LinkDataSnapshot {
            ld_id: id(e.get("ld_id").unwrap()),
            one_time: num(e.get("one_time").unwrap()) == 1,
            expires_bucket: u32::try_from(num(e.get("expires_bucket").unwrap())).unwrap(),
            present: num(e.get("present").unwrap()) == 1,
            consumed: num(e.get("consumed").unwrap()) == 1,
        })
        .collect();
    StoreSnapshot { queues, linkdata }
}

/// The link-A replay, `link-0006` … `link-0050`, index `n − 6`.
fn replay() -> &'static [Run] {
    static RUNS: OnceLock<Vec<Run>> = OnceLock::new();
    RUNS.get_or_init(|| {
        let file = reference();
        assert_eq!(
            file.header.get("suite").and_then(Value::as_str),
            Some("link")
        );
        assert_eq!(file.header.get("schema").and_then(Value::as_u64), Some(6));
        let mut bench = Bench::vectors();
        let keys = Keys::new();
        let mut runs = Vec::new();
        for n in 6..=50 {
            let case = file.case(n);
            let mut entropy = FixedEntropy::new(&relay_draws(case));
            let (built, sealed, out, opened, fill_out) = if case.op() == "send-fill" {
                let f = fill(&mut bench, case, &keys);
                (None, Vec::new(), Vec::new(), Vec::new(), Some(f))
            } else {
                let built = build(n, case, &bench.client, &keys).map(|reqs| payloads(&reqs));
                let (sealed, out, opened) =
                    run_requests(&mut bench, &case.output_list("req"), &mut entropy);
                (built, sealed, out, opened, None)
            };
            let l = &bench.client.link;
            runs.push(Run {
                built,
                sealed,
                out,
                opened,
                relay_post: bench.link_post(),
                client_post: (l.send_counter().unwrap(), l.recv_counter().unwrap()),
                snapshot: bench.relay.snapshot_kat(),
                left: entropy.remaining(),
                fill: fill_out,
            });
        }
        runs
    })
}

fn run_of(n: usize) -> &'static Run {
    replay().get(n.checked_sub(6).unwrap()).unwrap()
}

/// The checks every link-A case gets.
fn check(n: usize) {
    let c = reference().case(n);
    let id = &c.id;
    let run = run_of(n);
    let (c2r, r2c, seq) = c.link_post();
    assert_eq!(run.relay_post, (c2r, r2c, seq), "{id} link_post (relay)");
    assert_eq!(run.client_post, (c2r, r2c), "{id} link_post (client)");
    assert_eq!(run.snapshot, snapshot_of(c), "{id} store_post");
    assert_eq!(run.left, 0, "{id} relay draws left over");
    if run.fill.is_some() {
        return;
    }
    let req = c.output_list("req");
    assert_eq!(
        run.built.is_some(),
        c.manipulation().is_empty(),
        "{id}: built from the inputs exactly when the case has no manipulation"
    );
    if let Some(built) = &run.built {
        assert_eq!(built, &req, "{id} req built from the inputs");
    }
    assert_eq!(run.sealed, c.output_list("req_frames"), "{id} req_frames");
    let resp_frames: Vec<Vec<u8>> = run.out.concat();
    assert_eq!(
        resp_frames,
        c.output_list("resp_frames"),
        "{id} resp_frames"
    );
    assert!(
        resp_frames.iter().all(|f| f.len() == FRAME),
        "{id} frame length"
    );
    assert_eq!(run.opened, c.output_list("resp"), "{id} resp");
    // the response comes right after the command's last request frame (D.2)
    let is_put = req.first().unwrap().first() == Some(&0x07);
    for (i, frames) in run.out.iter().enumerate() {
        let last_of_command = !is_put || i == 2;
        assert_eq!(
            !frames.is_empty(),
            last_of_command,
            "{id} response position after request frame {i}"
        );
    }
}

/// The derived `token`/`sig` of a case against its request (and the recomputed token).
fn check_derived(n: usize) {
    let c = reference().case(n);
    let id = &c.id;
    let payload = c.output_list("req").first().unwrap().clone();
    if payload.first() == Some(&0x02) || !c.has_output("link_post") || run_of(n).built.is_none() {
        // SKEY has no fields; a command-error case lists no derived values (SCHEMA-4.11 case shape)
        return;
    }
    let req = decode_request(&payload);
    match &req.cmd {
        RequestCmd::QueueNew { token: t, sig, .. } | RequestCmd::LinkPut { token: t, sig, .. } => {
            assert_eq!(t.to_vec(), c.output("token"), "{id} token");
            assert_eq!(sig.as_bytes().to_vec(), c.output("sig"), "{id} sig");
        }
        RequestCmd::Send { sig, .. }
        | RequestCmd::Fetch { sig, .. }
        | RequestCmd::QueueDel { sig, .. }
        | RequestCmd::LinkGet {
            mode: LinkGetMode::OwnerStatus(sig),
            ..
        } => assert_eq!(sig.as_bytes().to_vec(), c.output("sig"), "{id} sig"),
        RequestCmd::FetchMulti { entries } => {
            for (i, e) in entries.iter().enumerate() {
                assert_eq!(
                    e.sig.as_bytes().to_vec(),
                    c.output(&format!("sig_{i}")),
                    "{id} sig_{i}"
                );
            }
        }
        _ => {}
    }
}

/// The token of a positive `QUEUE_NEW`/`LINK_PUT` case equals spec §9.6 over link A's `sess_id`.
fn check_token(n: usize) {
    let c = reference().case(n);
    let fx = crate::fixture::RelayFx::case1();
    let sess: [u8; 16] = reference().case(4).output("sess_id").try_into().unwrap();
    assert_eq!(
        token(&fx.access_key, &sess, c.cmd_seq()).to_vec(),
        c.output("token"),
        "{} token = HMAC(access_key, label ‖ sess_id ‖ cmd_seq)",
        c.id
    );
}

fn group(cases: &[usize]) {
    for &n in cases {
        check(n);
        check_derived(n);
    }
}

/// V-06 `link_vectors_queue_new`: 0006, 0009, 0015, 0016, 0030–0034.
#[test]
fn link_vectors_queue_new() {
    group(&[6, 9, 15, 16, 30, 31, 32, 33, 34]);
    let k = Keys::new();
    for (n, q) in [(6, &k.a), (15, &k.b)] {
        let c = reference().case(n);
        assert_eq!(rid_of(&q.0.pk).to_vec(), c.output("rid"), "{} rid", c.id);
        assert_eq!(
            sid_of(&q.0.pk, &q.1.pk).to_vec(),
            c.output("sid"),
            "{} sid",
            c.id
        );
    }
    for n in [6, 9, 15] {
        check_token(n);
    }
}

/// V-07 `link_vectors_send`: 0007, 0010, 0011, 0017, 0018, 0021, 0035–0037.
#[test]
fn link_vectors_send() {
    group(&[7, 10, 11, 17, 18, 21, 35, 36, 37]);
}

/// V-08 `link_vectors_ping`: 0008, 0023, 0050 (two PINGs 172, 172 → OK, ERR 6).
#[test]
fn link_vectors_ping() {
    for n in [8, 23, 50] {
        check(n);
    }
    let resp = reference().case(50).output_list("resp");
    assert_eq!(
        resp,
        vec![unhex("80000000ac"), unhex("8f000000ac06")],
        "link-0050 OK, ERR 6"
    );
}

/// V-09 `link_vectors_fetch`: 0012–0014, 0022, 0038–0041; 0013's present-1 (`cell_id`, `cell`) = 0012's.
#[test]
fn link_vectors_fetch() {
    group(&[12, 13, 14, 22, 38, 39, 40, 41]);
    let present = |n: usize| -> Vec<Vec<u8>> {
        reference()
            .case(n)
            .output_list("resp")
            .into_iter()
            .filter(|p| p.get(5) == Some(&1))
            .map(|p| p.get(22..).unwrap().to_vec())
            .collect()
    };
    assert_eq!(present(13).len(), 3, "link-0013 three cells");
    assert_eq!(
        present(13),
        present(12),
        "link-0013 idempotent with link-0012"
    );
}

/// V-10 `link_vectors_fetch_multi`: 0019, 0042; `sig_0`, `sig_1` in entry order.
#[test]
fn link_vectors_fetch_multi() {
    group(&[19, 42]);
}

/// V-11 `link_vectors_send_fill`: 0020 — `frames_sha256` over the 254 frames, `resp_last` {128, 0, 0}, `link_post`
/// {141, 157, 141}, `store_post`.
#[test]
fn link_vectors_send_fill() {
    check(20);
    let c = reference().case(20);
    let (sha, last) = run_of(20).fill.clone().unwrap();
    assert_eq!(
        sha.to_vec(),
        c.output("frames_sha256"),
        "link-0020 frames_sha256"
    );
    assert_eq!(last, c.output("resp_last"), "link-0020 resp_last");
    assert_eq!(
        c.link_post(),
        (141, 157, 141),
        "link-0020 link_post literal"
    );
}

/// V-12 `link_vectors_queue_del`: 0024, 0043.
#[test]
fn link_vectors_queue_del() {
    group(&[24, 43]);
}

/// V-13 `link_vectors_link_put`: 0025, 0026, 0044, 0045 — `req` sizes [4314, 4106, 4106], one response after
/// frame 3.
#[test]
fn link_vectors_link_put() {
    group(&[25, 26, 44, 45]);
    for n in [25, 26, 44, 45] {
        let c = reference().case(n);
        let sizes: Vec<usize> = c.output_list("req").iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![4314, 4106, 4106], "{} req sizes", c.id);
        assert_eq!(c.output_list("resp").len(), 1, "{} one response", c.id);
    }
    check_token(25);
}

/// V-14 `link_vectors_link_get`: 0027–0029, 0046, 0047, 0049 — `resp` sizes [4167, 4106, 4106].
#[test]
fn link_vectors_link_get() {
    group(&[27, 28, 29, 46, 47, 49]);
    for n in [27, 28, 29, 46, 47, 49] {
        let c = reference().case(n);
        let sizes: Vec<usize> = c.output_list("resp").iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![4167, 4106, 4106], "{} resp sizes", c.id);
    }
}

/// V-15 `link_vectors_skey`: 0048 (ERR 6).
#[test]
fn link_vectors_skey() {
    check(48);
    let c = reference().case(48);
    assert_eq!(
        c.output_list("resp"),
        vec![unhex("8f000000aa06")],
        "link-0048 ERR 6"
    );
}

/// V-16 `link_vectors_indist`: 0051 — `resp_counts`, `frame_len` 4352; for every link-A case the response position,
/// the frame length and the 4336-byte ISO-padded plaintext.
#[test]
fn link_vectors_indist() {
    let c = reference().case(51);
    let groups: Vec<Vec<usize>> = c
        .raw
        .get("cases")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|g| {
            g.as_array()
                .unwrap()
                .iter()
                .map(|id| {
                    id.as_str()
                        .unwrap()
                        .trim_start_matches("link-")
                        .parse()
                        .unwrap()
                })
                .collect()
        })
        .collect();
    let counts: Vec<Vec<u64>> = groups
        .iter()
        .map(|g| {
            g.iter()
                .map(|&n| u64::try_from(run_of(n).out.concat().len()).unwrap())
                .collect()
        })
        .collect();
    let file_counts: Vec<Vec<u64>> = c
        .outputs
        .get("resp_counts")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|g| {
            g.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap())
                .collect()
        })
        .collect();
    assert_eq!(counts, file_counts, "link-0051 resp_counts");
    assert_eq!(
        counts,
        vec![
            vec![1, 1, 1],
            vec![4, 4, 4],
            vec![8, 8],
            vec![1, 1, 1, 1],
            vec![1, 1, 1],
            vec![3, 3, 3, 3, 3, 3],
            vec![1, 1]
        ],
        "link-0051 resp_counts literal"
    );
    assert_eq!(
        c.outputs.get("frame_len").and_then(Value::as_u64),
        Some(4352),
        "link-0051 frame_len"
    );
    for n in 6..=50 {
        check(n);
        // every response plaintext the client opened was a 4336-byte ISO/IEC 7816-4 padded payload: re-pad it
        for p in &run_of(n).opened {
            let padded = secmp_proto::codec::pad(p, PLAIN).unwrap();
            assert_eq!(padded.len(), PLAIN, "link-{n:04} plaintext length");
        }
    }
}

/// The relay and client after `link-0008` (R expects `c2r` 3, C expects `r2c` 3, `last` 3).
fn at_case_8() -> Bench {
    let r = reference();
    let mut b = Bench::vectors();
    for n in 6..=8 {
        let c = r.case(n);
        run_requests(
            &mut b,
            &c.output_list("req"),
            &mut FixedEntropy::new(&relay_draws(c)),
        );
    }
    assert_eq!(b.link_post(), (3, 3, 3));
    b
}

/// V-20 `link_vectors_frame_reject`: 0075–0086 — the receiver rejects (C) / tears down (R); `link_post` {3, 3, 3};
/// store unchanged.
#[test]
fn link_vectors_frame_reject() {
    for n in 75..=86 {
        let c = reference().case(n);
        let id = &c.id;
        assert_eq!(
            c.raw.get("expect").and_then(Value::as_str),
            Some("reject"),
            "{id} expect"
        );
        assert_eq!(c.link_post(), (3, 3, 3), "{id} link_post in the file");
        let mut b = at_case_8();
        let digest = b.digest();
        let frame = c.input("frame");
        if c.party() == "R" {
            let mut entropy = FixedEntropy::new(&[]);
            assert!(
                matches!(b.unit(&frame, now(), &mut entropy), Outcome::Teardown),
                "{id} relay tears down"
            );
            assert_eq!(
                b.link_post(),
                (3, 3, 3),
                "{id} relay counters and last unchanged"
            );
            assert_eq!(b.digest(), digest, "{id} store unchanged");
        } else {
            let before = (b.client.link.send_counter(), b.client.link.recv_counter());
            assert!(
                b.client
                    .link
                    .open_response(&frame, secmp_proto::wire::frame::CellrContext::Fetch)
                    .is_err(),
                "{id} client rejects"
            );
            assert_eq!(
                (b.client.link.send_counter(), b.client.link.recv_counter()),
                before,
                "{id} client counters unchanged"
            );
            assert_eq!(before, (Some(3), Some(3)), "{id} client at 3/3");
        }
    }
}

/// The derived ids of the first `QUEUE_NEW` of each queue are the ids the relay reports (`OK_QUEUE_NEW`).
#[test]
fn link_vectors_ok_queue_new_carries_the_derived_ids() {
    for n in [6, 15] {
        let c = reference().case(n);
        let resp = c.output_list("resp");
        let p = resp.first().unwrap();
        assert_eq!(
            p.get(5..21).unwrap().to_vec(),
            c.output("rid"),
            "{} rid",
            c.id
        );
        assert_eq!(
            p.get(21..37).unwrap().to_vec(),
            c.output("sid"),
            "{} sid",
            c.id
        );
    }
}
