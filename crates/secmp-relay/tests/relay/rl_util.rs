// SPDX-License-Identifier: AGPL-3.0-or-later
//! Helpers of the relay-obligation tests (TEST-SPEC-M5 (b5) RL-01 … RL-23 and (b3) F-11; files `rl_store`,
//! `rl_conn`, `rl_process`): a driver of the fixture's bench that numbers the requests and checks the `cmd_seq`
//! echo, a client that runs the handshake and its requests through `Connection` (bytes in, bytes out, as the server
//! feeds it), a comparable view of response frames, fresh directories under the target's temporary directory, an
//! event capture the test keeps a handle to, and relays started from a key file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use secmp_crypto::SecretBytes;
use secmp_proto::link::client;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::tr::{Entropy, FixedEntropy};
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{Cellr, CellrError, ContIdx, Request, Response, ResponseCmd};
use secmp_relay::budget::BudgetLimits;
use secmp_relay::event::{CaptureSink, Event, EventSink, NullSink};
use secmp_relay::{Connection, KeyFile, Limits, Now, Relay};

use crate::fixture::{
    Answer, Bench, Client, FRAME, Key, NOW, Put, RelayFx, client_entropy, context_of, lots,
    relay_hs_entropy,
};

/// Bytes of a `RELAYINFO` record (`len` 2 ‖ type 1 ‖ `RelayInfoV1` 1741, D.1).
pub const RELAYINFO_RECORD: usize = 1744;
/// Bytes of a cell (spec §4.2).
pub const CELL: usize = 4096;
/// Bytes of a link-data blob (D.3).
pub const BLOB: usize = 12_360;

/// One response frame in a comparable form (`ResponseCmd` has no `Debug`/`PartialEq` outside its crate's tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V {
    /// `OK`.
    Ok,
    /// `OK_QUEUE_NEW { rid, sid }`.
    QueueNew(Id, Id),
    /// `OK_SEND { cell_id, evicted }`.
    Send(u64, Option<u64>),
    /// `CELLR { present, rid, cell_id, cell }`.
    Cellr(u8, Id, u64, Vec<u8>),
    /// `LINKR { present, consumed, blob_part }`.
    LinkR(bool, bool, Vec<u8>),
    /// `ERR code`.
    Err(u8),
    /// `CONT { idx, data }`.
    Cont(u8, Vec<u8>),
}

/// `(cmd_seq, view)` of one response frame.
pub fn view(r: &Response) -> (u32, V) {
    let v = match &r.cmd {
        ResponseCmd::Ok => V::Ok,
        ResponseCmd::OkQueueNew { rid, sid } => V::QueueNew(*rid, *sid),
        ResponseCmd::OkSend { cell_id, evicted } => V::Send(*cell_id, *evicted),
        ResponseCmd::Cellr(c) => match c {
            Cellr::Dummy { cell } => V::Cellr(0, [0; 16], 0, cell.as_bytes().to_vec()),
            Cellr::Cell { rid, cell_id, cell } => {
                V::Cellr(1, *rid, *cell_id, cell.as_bytes().to_vec())
            }
            Cellr::Error { error, rid, cell } => {
                let present = match error {
                    CellrError::NoQueue => 2,
                    CellrError::Auth => 3,
                    CellrError::Malformed => 4,
                };
                V::Cellr(present, *rid, 0, cell.as_bytes().to_vec())
            }
        },
        ResponseCmd::LinkR {
            present,
            consumed,
            blob_part,
        } => V::LinkR(*present, *consumed, blob_part.to_vec()),
        ResponseCmd::Err(code) => V::Err(code.byte()),
        ResponseCmd::Cont(c) => {
            let idx = match c.idx {
                ContIdx::One => 1,
                ContIdx::Two => 2,
            };
            V::Cont(idx, c.data.to_vec())
        }
    };
    (r.cmd_seq, v)
}

/// The views of `frames`, each of which must echo `cmd_seq` (D.2 `:827`).
pub fn strip(cmd_seq: u32, frames: Vec<(u32, V)>) -> Vec<V> {
    frames
        .into_iter()
        .map(|(s, v)| {
            assert_eq!(s, cmd_seq, "the response echoes the request's cmd_seq");
            v
        })
        .collect()
}

/// The views of the frames of an answer (a teardown or a pending `LINK_PUT` frame fails the test).
pub fn answer(a: Answer) -> Vec<(u32, V)> {
    a.frames().iter().map(view).collect()
}

/// `(present, cell_id)` of every `CELLR` frame, in order (any other frame fails the test).
pub fn presents(frames: &[V]) -> Vec<(u8, u64)> {
    frames
        .iter()
        .map(|v| match v {
            V::Cellr(p, _, id, _) => Some((*p, *id)),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .expect("only CELLR frames")
}

/// The cells of the `CELLR` frames, in order.
pub fn cells(frames: &[V]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .map(|v| match v {
            V::Cellr(_, _, _, cell) => Some(cell.clone()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .expect("only CELLR frames")
}

/// The `LINKR` flags and the 12360-byte blob of a three-frame `LINK_GET` answer.
pub fn linkr(frames: &[V]) -> (bool, bool, Vec<u8>) {
    match frames {
        [V::LinkR(p, c, part), V::Cont(1, one), V::Cont(2, two)] => {
            Some((*p, *c, [part.as_slice(), one, two].concat()))
        }
        _ => None,
    }
    .expect("LINKR + CONT + CONT")
}

/// The `LINKR` flags of a `LINK_GET` answer.
pub fn flags(frames: &[V]) -> (bool, bool) {
    let (p, c, _) = linkr(frames);
    (p, c)
}

/// A strictly increasing `cmd_seq` (spec §9.2), from `start` in steps of `step`.
pub struct Seq {
    next: u32,
    step: u32,
}

impl Seq {
    pub const fn starting(start: u32, step: u32) -> Self {
        Self { next: start, step }
    }

    /// The `cmd_seq` the next [`Seq::bump`] returns.
    pub const fn peek(&self) -> u32 {
        self.next
    }

    /// The next `cmd_seq`.
    pub fn bump(&mut self) -> u32 {
        let s = self.next;
        self.next = s.checked_add(self.step).unwrap();
        s
    }
}

/// `a + b` (tests: an overflow fails the test).
pub fn add(a: u64, b: u64) -> u64 {
    a.checked_add(b).unwrap()
}

/// `n × x`.
pub fn times(n: u64, x: u64) -> u64 {
    n.checked_mul(x).unwrap()
}

/// A copy of an access key.
pub fn copy_key(k: &AccessKey) -> AccessKey {
    SecretBytes::from_slice(k.expose_secret()).unwrap()
}

/// No budget limit and no rate limit (the sweeper tests run several queues).
pub const fn unlimited() -> Limits {
    Limits {
        budget: BudgetLimits {
            queue_bytes: None,
            linkdata_bytes: None,
        },
        ..Limits::vectors()
    }
}

/// The keys `(recv, send)` of a queue, from two one-byte seed patterns.
pub fn pair(recv: u8, send: u8) -> (Key, Key) {
    (Key::of(recv), Key::of(send))
}

/// The fields of a one-time `LINK_PUT`.
pub const fn one_time<'a>(
    ld_id: &'a Id,
    expires_bucket: u32,
    owner: &'a Key,
    blob: &'a [u8],
) -> Put<'a> {
    Put {
        ld_id,
        one_time: true,
        expires_bucket,
        owner,
        blob,
    }
}

/// `n` bytes in which no two 32-byte blocks are equal: SHA-256 of a counter under `tag`.
pub fn distinct_bytes(tag: u8, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0_u64;
    while out.len() < n {
        out.extend_from_slice(&secmp_crypto::sha256(&[&[tag], &i.to_be_bytes()]));
        i = i.checked_add(1).unwrap();
    }
    out.truncate(n);
    out
}

// ---------------------------------------------------------------------------------------------------------------
// The bench of the fixture, numbered.

/// The fixture's bench (relay of `link-0001`, link A) with the `cmd_seq` of its requests.
pub struct Drive {
    pub b: Bench,
    pub seq: Seq,
}

impl Drive {
    pub fn new(limits: Limits) -> Self {
        Self {
            b: Bench::new(limits),
            seq: Seq::starting(1, 1),
        }
    }

    /// Build a request for the next `cmd_seq`, run it at `t` and return its response frames.
    pub fn go(&mut self, t: Now, build: impl FnOnce(&Client, u32) -> Request) -> Vec<V> {
        self.go_with(t, &mut lots(), build)
    }

    /// As [`Drive::go`], the relay drawing from `e`.
    pub fn go_with(
        &mut self,
        t: Now,
        e: &mut FixedEntropy,
        build: impl FnOnce(&Client, u32) -> Request,
    ) -> Vec<V> {
        let s = self.seq.bump();
        let req = build(&self.b.client, s);
        strip(s, answer(self.b.run(&req, t, e)))
    }

    /// A `LINK_PUT` at `t`: nothing after frames 1 and 2, the answer after frame 3.
    pub fn put(&mut self, t: Now, p: &Put<'_>) -> Vec<V> {
        self.put_with(t, p, |_, _, _| {})
    }

    /// As [`Drive::put`] with frame 1 changed by `edit(client, cmd_seq, frame 1)` before it is sealed.
    pub fn put_with(
        &mut self,
        t: Now,
        p: &Put<'_>,
        edit: impl FnOnce(&Client, u32, &mut Request),
    ) -> Vec<V> {
        let s = self.seq.bump();
        let [mut one, two, three] = self.b.client.link_put(s, p);
        edit(&self.b.client, s, &mut one);
        assert!(
            self.b.run(&one, t, &mut lots()).is_pending(),
            "nothing after frame 1"
        );
        assert!(
            self.b.run(&two, t, &mut lots()).is_pending(),
            "nothing after frame 2"
        );
        strip(s, answer(self.b.run(&three, t, &mut lots())))
    }

    /// The `cell_id`s of the only queue of the store.
    pub fn cell_ids(&self) -> Vec<u64> {
        let snap = self.b.relay.snapshot_kat();
        assert!(snap.queues.len() <= 1, "at most one queue");
        snap.queues
            .first()
            .map(|q| q.cell_ids.clone())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Files.

/// An empty directory `<CARGO_TARGET_TMPDIR>/<name>-<pid>` (a leftover of an earlier run is removed first).
pub fn fresh_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `keygen` at the suite's `now` (`KeyFile::generate` + `write_new`): the key file `<dir>/relay-keys`.
pub fn key_file(dir: &Path, validity_secs: u64) -> PathBuf {
    let path = dir.join("relay-keys");
    KeyFile::generate(NOW, validity_secs)
        .unwrap()
        .write_new(&path)
        .unwrap();
    path
}

/// A relay started from the key file at `path`: empty (spec §9.7 item 1), events discarded.
pub fn load(path: &Path, limits: Limits, t: Now) -> Relay {
    let ring = KeyFile::read(path).unwrap().ring().unwrap();
    Relay::new(ring, limits, Box::new(NullSink), t)
}

/// What a `RelayRef` and the operator hand a client: the relay's `relay_fp` and its access key.
pub fn identity(relay: &Relay) -> ([u8; 32], AccessKey) {
    let (keys, _) = relay.keys().newest().unwrap();
    (keys.fp(), copy_key(keys.access_key()))
}

/// Every `.rs` file of `crates/secmp-relay/src`, recursively, sorted.
pub fn relay_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out.sort();
    out
}

/// The code of a source line without its `//` comment.
pub fn code(line: &str) -> &str {
    line.split("//").next().unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------------------------
// Events.

/// An event sink the test keeps a handle to (the relay owns its `Box<dyn EventSink>`): forwards to a shared
/// `CaptureSink`.
pub struct Shared(pub Arc<CaptureSink>);

impl EventSink for Shared {
    fn emit(&self, event: &Event<'_>) {
        self.0.emit(event);
    }
}

/// A capture and the sink to hand the relay.
pub fn capture() -> (Arc<CaptureSink>, Box<dyn EventSink>) {
    let cap = Arc::new(CaptureSink::default());
    (Arc::clone(&cap), Box::new(Shared(cap)))
}

/// The names of the captured events.
pub fn names(cap: &CaptureSink) -> Vec<&'static str> {
    cap.events().into_iter().map(|(n, _)| n).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// A client through `Connection`.

/// Accept a connection at `t` and send `HELLO`: the connection and the relay's answer (`close` must be false).
pub fn hello<'r>(relay: &'r Relay, t: Now, e: &mut impl Entropy) -> (Connection<'r>, Vec<u8>) {
    let mut conn = Connection::accept(relay, t).expect("the relay accepts a connection");
    let (hello, _) = client::start([0; 32], None, t.unix_secs).unwrap();
    let out = conn.on_bytes(&hello, t, e);
    assert!(!out.close, "HELLO is answered");
    (conn, out.bytes)
}

/// A client that talks to the relay through a `Connection`, as the server feeds it.
pub struct Wire<'r> {
    pub conn: Connection<'r>,
    pub client: Client,
    pub seq: Seq,
}

impl<'r> Wire<'r> {
    /// Accept at `t`, then `HELLO` → `RELAYINFO` → `HS1` → `HS2`; the client pins `fp` and holds `access`.
    pub fn connect(
        relay: &'r Relay,
        fp: [u8; 32],
        access: &AccessKey,
        t: Now,
        client_e: &mut impl Entropy,
        relay_e: &mut impl Entropy,
    ) -> Self {
        let mut conn = Connection::accept(relay, t).expect("the relay accepts a connection");
        let (hello, st) = client::start(fp, Some(access), t.unix_secs).unwrap();
        let info = conn.on_bytes(&hello, t, relay_e);
        assert!(!info.close, "HELLO is answered");
        let (hs1, wait) = st.on_relayinfo(&info.bytes, client_e).unwrap();
        let hs2 = conn.on_bytes(&hs1, t, relay_e);
        assert!(!hs2.close, "HS1 is answered");
        let link = wait.on_hs2(&hs2.bytes).unwrap();
        assert!(conn.executor().is_some(), "the link is established");
        Self {
            conn,
            client: Client::new(link, copy_key(access)),
            seq: Seq::starting(1, 1),
        }
    }

    /// Link A of the suite (the `link-0003`/`link-0004` draws) through a connection, at `t`.
    pub fn link_a(relay: &'r Relay, fx: &RelayFx, t: Now) -> Self {
        Self::connect(
            relay,
            fx.relay_fp,
            &fx.access(),
            t,
            &mut client_entropy(),
            &mut relay_hs_entropy(),
        )
    }

    /// Feed `bytes` at `t` and open every frame the relay wrote in answer to a request of `context`.
    fn exchange(&mut self, bytes: &[u8], req: &Request, t: Now, e: &mut impl Entropy) -> Vec<V> {
        let out = self.conn.on_bytes(bytes, t, e);
        assert!(!out.close, "the connection stays open");
        let (units, rest) = out.bytes.as_chunks::<FRAME>();
        assert!(rest.is_empty(), "whole 4352-byte frames");
        let context = context_of(&req.cmd);
        let frames: Vec<(u32, V)> = units
            .iter()
            .map(|f| view(&self.client.open(f, context)))
            .collect();
        strip(req.cmd_seq, frames)
    }

    /// Build a request for the next `cmd_seq`, run it at `t` and return its response frames.
    pub fn go(
        &mut self,
        t: Now,
        e: &mut impl Entropy,
        build: impl FnOnce(&Client, u32) -> Request,
    ) -> Vec<V> {
        let req = build(&self.client, self.seq.bump());
        let frame = self.client.seal(&req);
        self.exchange(&frame, &req, t, e)
    }

    /// A `LINK_PUT` for the next `cmd_seq`: nothing is written after frames 1 and 2, the answer after frame 3.
    pub fn put(&mut self, t: Now, e: &mut impl Entropy, p: &Put<'_>) -> Vec<V> {
        let [one, two, three] = self.client.link_put(self.seq.bump(), p);
        for (n, req) in [(1, &one), (2, &two)] {
            let frame = self.client.seal(req);
            assert_eq!(
                self.exchange(&frame, req, t, e),
                Vec::new(),
                "nothing after LINK_PUT frame {n}"
            );
        }
        let frame = self.client.seal(&three);
        self.exchange(&frame, &three, t, e)
    }
}
