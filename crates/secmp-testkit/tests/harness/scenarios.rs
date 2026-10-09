// SPDX-License-Identifier: AGPL-3.0-or-later
//! The harness scenarios of TEST-SPEC-M5 (c): H-01, H-03…H-06, H-08, H-10…H-13 and G-06, written against the public
//! surface of `secmp_testkit::harness` only (H-09).

use std::collections::BTreeSet;

use secmp_crypto::{SecretBytes, VectorStream, sha256};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::tr::RatchetState;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{Cell, RelayQueue};
use secmp_proto::wire::inv::{LinkBlob, Onion, RelayRef};
use secmp_relay::budget::QUEUE_RESERVATION;
use secmp_testkit::harness::{
    Capture, ClientId, EntropyPool, FrameCheck, Harness, HarnessConfig, Side, Split, ratchet_pair,
    text_of, verify_frames,
};
use secmp_transport::{
    Bucket, CellId, Error, FetchMultiOutcome, LdId, LinkGetMode, LinkGetOutcome, QueueTransport,
    RecvCap, SendCap, SendOutcome, Token,
};

use crate::scripted::cell;

/// Messages per direction of the exchange scenario.
pub const EXCHANGE: usize = 1000;
/// Cells a side sends before the other drains its queue (the queue holds 128).
const BATCH: usize = 50;

/// The seeds of a client's main queue: the capabilities are derived from them, so the same seeds re-create the
/// identical queue after a relay restart (spec §9.1).
pub struct Seeds {
    pub recv: SecretBytes<32>,
    pub send: SecretBytes<32>,
}

/// Two clients, each with two pool queues, and a ratchet session between them over the first queue of each (the
/// session starts from one shared `SK`, M3 `init_initiator` / `init_responder`; no SecMP-HX).
pub struct Pair {
    pub h: Harness,
    pub a: ClientId,
    pub b: ClientId,
    pub side_a: Side,
    pub side_b: Side,
    /// The seeds of the main queue of each client.
    pub seeds_a: Seeds,
    pub seeds_b: Seeds,
}

/// Two queues for the client from its stream: the capabilities of both, the seeds of the first.
fn two_queues(h: &mut Harness, c: ClientId) -> (Vec<(RecvCap, SendCap)>, Seeds) {
    let token = h.access_key();
    let mut caps = Vec::new();
    let mut first = None;
    for k in 0..2 {
        let (recv, send) = (h.client(c).seed(), h.client(c).seed());
        let (t, _) = h.client(c).link().unwrap();
        caps.push(t.create_queue(&recv, &send, &token).unwrap());
        if k == 0 {
            first = Some(Seeds { recv, send });
        }
    }
    (caps, first.unwrap())
}

/// The ratchet session of [`pair`]: the initiator (`A`) and the responder (`B`), from one shared `SK` and fixed
/// entropy (the same states on every call).
fn sessions() -> (RatchetState, RatchetState) {
    let sk = SecretBytes::from_slice(&VectorStream::new("harness-sk", 0).take(32)).unwrap();
    let transcript = [0x7e_u8; 32];
    let mut ea = EntropyPool::new("harness-sk-a", 0);
    let mut eb = EntropyPool::new("harness-sk-b", 0);
    ratchet_pair(&sk, &transcript, ea.get(), eb.get())
}

pub fn pair(config: HarnessConfig) -> Pair {
    let mut h = Harness::new(config);
    let (ca, cb) = (h.add_client(), h.add_client());
    h.connect(ca).unwrap();
    h.connect(cb).unwrap();
    let (mut queues_a, seeds_a) = two_queues(&mut h, ca);
    let (mut queues_b, seeds_b) = two_queues(&mut h, cb);
    queues_a.pop().unwrap();
    queues_b.pop().unwrap();
    let (recv_a, send_to_a) = queues_a.pop().unwrap();
    let (recv_b, send_to_b) = queues_b.pop().unwrap();
    let (ia, rb) = sessions();
    Pair {
        side_a: Side::new(ia, recv_a, send_to_b),
        side_b: Side::new(rb, recv_b, send_to_a),
        h,
        a: ca,
        b: cb,
        seeds_a,
        seeds_b,
    }
}

impl Pair {
    /// `A` sends `n` messages `a<i>` (`B` drains after each batch); then `B` answers with `n` messages `b<i>`.
    pub fn exchange(&mut self, n: usize) {
        let (ca, cb) = (self.a, self.b);
        let mut sent = 0_usize;
        while sent < n {
            let batch = BATCH.min(n.saturating_sub(sent));
            let end = sent.saturating_add(batch);
            for i in sent..end {
                let (t, e) = self.h.client(ca).link().unwrap();
                self.side_a
                    .send_text(t, e, format!("a{i}").as_bytes())
                    .unwrap();
            }
            let (t, e) = self.h.client(cb).link().unwrap();
            self.side_b.drain(t, e).unwrap();
            for i in sent..end {
                let (t, e) = self.h.client(cb).link().unwrap();
                self.side_b
                    .send_text(t, e, format!("b{i}").as_bytes())
                    .unwrap();
            }
            let (t, e) = self.h.client(ca).link().unwrap();
            self.side_a.drain(t, e).unwrap();
            sent = end;
        }
    }

    /// The payloads each side delivered, as text.
    pub fn delivered(&self) -> (Vec<String>, Vec<String>) {
        let text = |s: &Side| {
            s.received()
                .iter()
                .map(|p| String::from_utf8(p.clone()).unwrap())
                .collect()
        };
        (text(&self.side_a), text(&self.side_b))
    }

    /// Every byte of every connection of both clients, oldest first.
    pub fn captures(&mut self) -> Vec<Capture> {
        let mut out = self.h.client(self.a).captures();
        out.extend(self.h.client(self.b).captures());
        out
    }

    /// The frame check of the current connection of client `c`.
    pub fn check(&mut self, c: ClientId) -> FrameCheck {
        frame_check(&mut self.h, c)
    }
}

/// The frame check of the current connection of client `c` (H-08).
pub fn frame_check(h: &mut Harness, c: ClientId) -> FrameCheck {
    let client = h.client(c);
    let capture = client.streams().last().unwrap().capture();
    verify_frames(client.transport().unwrap(), &capture)
}

/// H-08 for every current connection of the scenario: whole frames only, and every one opens.
fn assert_frames(h: &mut Harness, clients: &[ClientId], scenario: &str) {
    for c in clients {
        let check = frame_check(h, *c);
        assert!(
            check.aligned && check.all_open && check.to_relay > 0 && check.to_client > 0,
            "{scenario}: {check:?}"
        );
    }
}

fn expected(prefix: char, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}{i}")).collect()
}

/// H-01: two clients create two pool queues each; every `OK_QUEUE_NEW` carries the derived ids.
#[test]
fn harness_clients_create_pool_queues() {
    let mut h = Harness::new(HarnessConfig::default());
    let (ca, cb) = (h.add_client(), h.add_client());
    h.connect(ca).unwrap();
    h.connect(cb).unwrap();
    let token = h.access_key();
    for client in [ca, cb] {
        for _ in 0..2 {
            let (recv, send) = (h.client(client).seed(), h.client(client).seed());
            let (t, _) = h.client(client).link().unwrap();
            let (recv_cap, send_cap) = t.create_queue(&recv, &send, &token).unwrap();
            // the ids, recomputed here from the keys (spec §9.1)
            let pk = |seed: &SecretBytes<32>| {
                *secmp_crypto::Ed25519SigningKey::from_seed(seed.expose_secret())
                    .unwrap()
                    .verifying_key()
                    .as_bytes()
            };
            let rid = sha256(&[b"SecMP-Q/1 rid", &pk(&recv)]);
            let sid = sha256(&[b"SecMP-Q/1 sid", &pk(&recv), &pk(&send)]);
            assert_eq!(recv_cap.queue().rid().as_slice(), rid.get(..16).unwrap());
            assert_eq!(send_cap.sid().as_slice(), sid.get(..16).unwrap());
        }
    }
    assert_frames(&mut h, &[ca, cb], "H-01");
}

/// H-03: 1000 cells each way over the relay, cumulative acknowledgement, dedup by `cell_id`.
#[test]
fn harness_exchange_1000_cells_each_way() {
    let mut p = pair(HarnessConfig::default());
    p.exchange(EXCHANGE);
    let (at_a, at_b) = p.delivered();
    assert_eq!(
        at_b,
        expected('a', EXCHANGE),
        "B got every a<i> once, in order"
    );
    assert_eq!(
        at_a,
        expected('b', EXCHANGE),
        "A got every b<i> once, in order"
    );
    assert_eq!(p.side_a.discarded() + p.side_b.discarded(), 0);
    // the queues end empty: the last FETCH carried the final acknowledgement
    let (ca, cb) = (p.a, p.b);
    let (t, _) = p.h.client(ca).link().unwrap();
    assert!(
        t.fetch(p.side_a.recv_cap(), p.side_a.committed_ack())
            .unwrap()
            .is_empty()
    );
    let (t, _) = p.h.client(cb).link().unwrap();
    assert!(
        t.fetch(p.side_b.recv_cap(), p.side_b.committed_ack())
            .unwrap()
            .is_empty()
    );
    assert_eq!(p.side_a.committed_ack(), u64::try_from(EXCHANGE).unwrap());
    assert_eq!(p.side_b.committed_ack(), u64::try_from(EXCHANGE).unwrap());
    assert_frames(&mut p.h, &[ca, cb], "H-03");
}

/// H-04: the recipient is offline, the sender sends 200 cells; the relay evicts ids 1…72 in order and reports them;
/// the recipient gets the newest 128, which the ratchet fast-forwards over.
#[test]
fn harness_eviction_reports_ids_newest_128_decrypt() {
    let mut p = pair(HarnessConfig::default());
    let (ca, cb) = (p.a, p.b);
    let mut evicted = Vec::new();
    for i in 0..200_usize {
        let (t, e) = p.h.client(ca).link().unwrap();
        let out = p
            .side_a
            .send_text(t, e, format!("a{i}").as_bytes())
            .unwrap();
        assert_eq!(out.cell_id, u64::try_from(i + 1).unwrap());
        evicted.extend(out.evicted);
    }
    assert_eq!(
        evicted,
        (1..=72_u64).collect::<Vec<_>>(),
        "ids 1…72, in order"
    );
    let (t, e) = p.h.client(cb).link().unwrap();
    assert_eq!(p.side_b.drain(t, e).unwrap(), 128);
    let got: Vec<String> = p.delivered().1;
    assert_eq!(
        got,
        (72..200).map(|i| format!("a{i}")).collect::<Vec<_>>(),
        "the newest 128"
    );
    assert_frames(&mut p.h, &[ca, cb], "H-04");
}

/// H-05: the sweeper expires by hour bucket — cells after `CELL_TTL`, an idle queue after `QUEUE_IDLE_TTL`, link data
/// after its `expires_bucket` — end to end through the harness clock.
#[test]
fn harness_sweeper_expires_by_bucket() {
    let mut p = pair(HarnessConfig::default());
    let (ca, cb) = (p.a, p.b);
    let token = p.h.access_key();
    // (1) a cell lives CELL_TTL = 168 h: present at +168, gone at +169
    let (t, e) = p.h.client(ca).link().unwrap();
    p.side_a.send_text(t, e, b"old").unwrap();
    p.h.advance_hours(168);
    let (t, _) = p.h.client(cb).link().unwrap();
    let held = t.fetch(p.side_b.recv_cap(), 0).unwrap();
    assert_eq!(held.len(), 1, "retained at bucket + 168");
    p.h.advance_hours(1);
    let (t, _) = p.h.client(cb).link().unwrap();
    assert!(
        t.fetch(p.side_b.recv_cap(), 0).unwrap().is_empty(),
        "expired at bucket + 169"
    );
    // (2) a queue goes after QUEUE_IDLE_TTL = 720 h without a non-error FETCH (from its creation if there was none):
    // retained at +720, expired at +721; a FETCH refreshes the clock
    let seed = |b: u8| SecretBytes::<32>::from_slice(&[b; 32]).unwrap();
    let (t, _) = p.h.client(cb).link().unwrap();
    let (keep, _) = t.create_queue(&seed(0x61), &seed(0x62), &token).unwrap();
    let (lost, _) = t.create_queue(&seed(0x63), &seed(0x64), &token).unwrap();
    p.h.advance_hours(720);
    let (t, _) = p.h.client(cb).link().unwrap();
    assert!(
        t.fetch(&keep, 0).is_ok(),
        "retained at bucket + 720 (this FETCH refreshes it)"
    );
    p.h.advance_hours(1);
    let (t, _) = p.h.client(cb).link().unwrap();
    assert_eq!(
        t.fetch(&lost, 0).err(),
        Some(Error::NoQueue),
        "expired at bucket + 721"
    );
    assert!(t.fetch(&keep, 0).is_ok(), "refreshed one hour ago");
    p.h.advance_hours(720);
    let (t, _) = p.h.client(cb).link().unwrap();
    assert!(t.fetch(&keep, 0).is_ok(), "720 h after the last FETCH");
    p.h.advance_hours(721);
    let (t, _) = p.h.client(cb).link().unwrap();
    assert_eq!(
        t.fetch(&keep, 0).err(),
        Some(Error::NoQueue),
        "721 h after the last FETCH"
    );
    // (3) link data is valid through its expires_bucket and gone after it
    let owner = SecretBytes::from_slice(&[0x71; 32]).unwrap();
    let bucket = secmp_relay::HourBucket::from_unix_secs(p.h.clock().unix()).0 + 10;
    let (t, _) = p.h.client(ca).link().unwrap();
    t.put_link_data(
        [0x81; 16],
        &owner,
        &crate::fixture::blob(3),
        false,
        bucket,
        &token,
    )
    .unwrap();
    p.h.advance_hours(10);
    let (t, _) = p.h.client(ca).link().unwrap();
    let status = t
        .get_link_data(
            [0x81; 16],
            secmp_transport::LinkGetMode::OwnerStatus(&owner),
        )
        .unwrap();
    assert!(status.present, "valid through expires_bucket");
    p.h.advance_hours(1);
    let (t, _) = p.h.client(ca).link().unwrap();
    let status = t
        .get_link_data(
            [0x81; 16],
            secmp_transport::LinkGetMode::OwnerStatus(&owner),
        )
        .unwrap();
    assert!(!status.present && !status.consumed, "gone after it");
    assert_frames(&mut p.h, &[ca, cb], "H-05");
}

/// H-06: the memory budget refuses a new queue at the limit and still accepts every `SEND`.
#[test]
fn harness_memory_budget_refuses_new_queue_at_limit() {
    let mut config = HarnessConfig::default();
    config.limits.budget.queue_bytes = Some(QUEUE_RESERVATION * 2);
    let mut h = Harness::new(config);
    let ca = h.add_client();
    h.connect(ca).unwrap();
    let queues = h.create_queues(ca, 2).unwrap();
    let token = h.access_key();
    let (recv, send) = (h.client(ca).seed(), h.client(ca).seed());
    let (t, _) = h.client(ca).link().unwrap();
    assert_eq!(
        t.create_queue(&recv, &send, &token).err(),
        Some(Error::Full),
        "ERR_FULL at the limit"
    );
    for i in 0..130_u8 {
        let out = t.send(&queues.first().unwrap().1, &cell(i)).unwrap();
        assert_eq!(
            out.cell_id,
            u64::from(i) + 1,
            "a SEND is never refused for memory"
        );
    }
    // an identical QUEUE_NEW of an existing queue is still answered (spec §9.7 item 8)
    // deleting a queue frees its reservation
    t.delete_queue(&queues.first().unwrap().0).unwrap();
    assert!(t.create_queue(&recv, &send, &token).is_ok());
    assert_frames(&mut h, &[ca], "H-06");
}

/// H-08: after `HS2` every stream is a whole number of 4352-byte units, and every unit opens.
#[test]
fn harness_all_bytes_after_hs2_are_4352_byte_frames() {
    // H-01, H-03, H-04
    let mut p = pair(HarnessConfig::default());
    p.exchange(40);
    for c in [p.a, p.b] {
        let check = p.check(c);
        assert!(
            check.aligned && check.all_open,
            "H-03 client {c:?}: {check:?}"
        );
        assert!(check.to_relay > 0 && check.to_client > 0);
    }
    for capture in p.captures() {
        assert_eq!(capture.frames_to_relay().len() % 4352, 0);
        assert_eq!(capture.frames_to_client().len() % 4352, 0);
    }
    // errors and successes are both frames: a failing and a succeeding command on one link
    let ca = p.a;
    let (t, _) = p.h.client(ca).link().unwrap();
    assert_eq!(
        t.fetch(p.side_a.recv_cap(), 10_000).err(),
        Some(Error::Malformed)
    );
    t.ping().unwrap();
    let check = p.check(ca);
    assert!(check.aligned && check.all_open, "{check:?}");
}

/// The bytes of two runs of the exchange scenario.
fn run_captures(config: HarnessConfig, n: usize) -> (Vec<Capture>, Vec<String>, Vec<String>) {
    let mut p = pair(config);
    p.exchange(n);
    let (at_a, at_b) = p.delivered();
    (p.captures(), at_a, at_b)
}

/// H-10: the same scenario with the same entropy and the virtual clock replays byte for byte.
#[test]
fn harness_replay_is_deterministic() {
    let (first, a1, b1) = run_captures(HarnessConfig::default(), 60);
    let (second, a2, b2) = run_captures(HarnessConfig::default(), 60);
    assert_eq!((a1, b1), (a2, b2));
    assert_eq!(first.len(), second.len());
    for (x, y) in first.iter().zip(&second) {
        assert!(x.to_relay == y.to_relay, "client → relay bytes");
        assert!(x.to_client == y.to_client, "relay → client bytes");
    }
}

/// H-11: the exchange runs over the in-process stream and over one that cuts every read and write into pieces of
/// 1…4352 bytes, with identical outcomes; no socket is opened (the streams are `std::io` objects of this crate).
#[test]
fn harness_transport_runs_over_in_process_streams() {
    let whole = run_captures(HarnessConfig::default(), 60);
    let chunked = run_captures(
        HarnessConfig {
            split: Split::Chunked(0x5eed),
            ..HarnessConfig::default()
        },
        60,
    );
    assert_eq!(
        (&whole.1, &whole.2),
        (&chunked.1, &chunked.2),
        "the same deliveries"
    );
    assert_eq!(whole.1, expected('b', 60));
    // the bytes are the same however they were cut
    for (x, y) in whole.0.iter().zip(&chunked.0) {
        assert!(
            x.to_relay == y.to_relay && x.to_client == y.to_client,
            "same stream content"
        );
    }
}

/// A transport that records every cell handed to `SEND` before the relay answers — also the cells the relay refuses
/// with `ERR_NOQUEUE` — and passes every operation on unchanged (H-12).
struct Tap<'a, T> {
    inner: &'a mut T,
    sent: &'a mut Vec<Cell>,
}

impl<T: QueueTransport> QueueTransport for Tap<'_, T> {
    fn create_queue(
        &mut self,
        recv: &SecretBytes<32>,
        send: &SecretBytes<32>,
        token: &Token,
    ) -> secmp_transport::Result<(RecvCap, SendCap)> {
        self.inner.create_queue(recv, send, token)
    }

    fn send(&mut self, to: &SendCap, cell: &Cell) -> secmp_transport::Result<SendOutcome> {
        self.sent.push(cell.clone());
        self.inner.send(to, cell)
    }

    fn fetch(
        &mut self,
        from: &RecvCap,
        ack: CellId,
    ) -> secmp_transport::Result<Vec<(CellId, Cell)>> {
        self.inner.fetch(from, ack)
    }

    fn fetch_multi(
        &mut self,
        from: &[(&RecvCap, CellId)],
    ) -> secmp_transport::Result<FetchMultiOutcome> {
        self.inner.fetch_multi(from)
    }

    fn delete_queue(&mut self, q: &RecvCap) -> secmp_transport::Result<()> {
        self.inner.delete_queue(q)
    }

    fn put_link_data(
        &mut self,
        id: LdId,
        owner: &SecretBytes<32>,
        blob: &LinkBlob,
        one_time: bool,
        expires: Bucket,
        token: &Token,
    ) -> secmp_transport::Result<()> {
        self.inner
            .put_link_data(id, owner, blob, one_time, expires, token)
    }

    fn get_link_data(
        &mut self,
        id: LdId,
        mode: LinkGetMode<'_>,
    ) -> secmp_transport::Result<LinkGetOutcome> {
        self.inner.get_link_data(id, mode)
    }
}

/// `side` seals `payload` as its next cell and `SEND`s it over client `c`'s link; the cell is recorded in `sent`
/// whatever the relay answers.
fn send_tapped(
    h: &mut Harness,
    c: ClientId,
    side: &mut Side,
    sent: &mut Vec<Cell>,
    payload: &[u8],
) -> Result<SendOutcome, Error> {
    let (t, e) = h.client(c).link().unwrap();
    side.send_text(&mut Tap { inner: t, sent }, e, payload)
}

/// One cell `A` sealed, as `B` opens it: the text, `(n, pn)` of its header (spec §7.3), and SHA-256 of the message key
/// that opened it (feature `kat`; the key that sealed it, spec §7.4).
struct SealedCell {
    text: String,
    position: (u32, u32),
    mk_digest: [u8; 32],
}

/// Every cell of `cells` opened by its own fresh copy of `B`'s initial ratchet state (the responder of [`sessions`]),
/// so that the position and the message key of a cell do not depend on which cells were opened before it — two cells
/// sealed under one key both open, at the same position, with the same digest.
fn open_each(cells: &[Cell]) -> Vec<SealedCell> {
    let initial = sessions().1.to_bytes().unwrap();
    let mut entropy = EntropyPool::new("harness-h12-shadow", 0);
    cells
        .iter()
        .map(|cell| {
            let shadow = RatchetState::from_bytes(&initial).unwrap();
            let opened = shadow
                .decrypt_with(cell.as_bytes(), entropy.get())
                .ok()
                .expect("every cell A sealed opens");
            let content = opened.plaintext().content().unwrap();
            SealedCell {
                text: String::from_utf8(text_of(&content).unwrap()).unwrap(),
                position: opened.header_counters(),
                mk_digest: opened.plaintext().message_key_digest_kat(),
            }
        })
        .collect()
}

/// H-12, no message key reused across the restart (R-115): the cells `A` sealed — `a0`…`a9`, the refused `lost-1` and
/// `lost-2`, `a10`…`a16` — lie in `A`'s one sending chain (`B` sent nothing in between: `pn` = 0), the k-th at `n` = k
/// (pairwise-distinct positions), each under its own message key; `pos(a10) = pos(lost-2) + 1 = pos(a9) + 3`.
fn assert_no_mk_reuse(sent_a: &[Cell]) {
    let opened = open_each(sent_a);
    let mut sealed: Vec<String> = (0..10).map(|i| format!("a{i}")).collect();
    sealed.extend(["lost-1".to_owned(), "lost-2".to_owned()]);
    sealed.extend((10..17).map(|i| format!("a{i}")));
    assert_eq!(
        opened.iter().map(|o| o.text.clone()).collect::<Vec<_>>(),
        sealed,
        "every cell A sealed, the refused ones included"
    );
    let digests: BTreeSet<[u8; 32]> = opened.iter().map(|o| o.mk_digest).collect();
    assert_eq!(
        digests.len(),
        opened.len(),
        "pairwise-distinct message keys"
    );
    let positions: Vec<(u32, u32)> = opened.iter().map(|o| o.position).collect();
    let consecutive: Vec<(u32, u32)> = (0..19).map(|n| (n, 0)).collect();
    assert_eq!(positions, consecutive, "one position per sealed cell");
    let n_of = |text: &str| {
        opened
            .iter()
            .find(|o| o.text == text)
            .map(|o| o.position.0)
            .unwrap()
    };
    assert_eq!(
        Some(n_of("a10")),
        n_of("lost-2").checked_add(1),
        "pos(a10) = pos(lost-2) + 1"
    );
    assert_eq!(
        Some(n_of("a10")),
        n_of("a9").checked_add(3),
        "a10 = the last cell before the restart + 3"
    );
}

/// H-12: the relay restarts mid-conversation → `ERR_NOQUEUE` → the identical queues are re-created → the conversation
/// continues without a new invitation, and no message key is reused across the restart (spec §9.1; the M5 review's
/// `h12_restart_recreate_without_mk_reuse`, R-115 / C-8): every cell `A` sealed — before the restart, the two the
/// relay refused (`lost-1`, `lost-2`) and after the re-creation — sits at its own position under its own message key,
/// and `a10` follows `lost-2` directly. A sender that rolled its ratchet back on `ERR_NOQUEUE` and re-sealed under a
/// refused cell's key fails here. The sender keeps no `cell_id` map in M5 (the outbox is M6, review §E).
#[test]
fn harness_relay_restart_queues_recreated_conversation_continues() {
    let mut p = pair(HarnessConfig::default());
    let (ca, cb) = (p.a, p.b);
    // every cell A seals, in sealing order, whatever the relay answers
    let mut sent_a: Vec<Cell> = Vec::new();
    // A sends 10 cells; B has fetched 5 when the relay restarts
    for i in 0..10 {
        send_tapped(
            &mut p.h,
            ca,
            &mut p.side_a,
            &mut sent_a,
            format!("a{i}").as_bytes(),
        )
        .unwrap();
    }
    let (t, e) = p.h.client(cb).link().unwrap();
    p.side_b.poll(t, e).unwrap();
    let (t, e) = p.h.client(cb).link().unwrap();
    p.side_b.poll(t, e).unwrap();
    let before = p.side_b.received().len();
    assert!((1..=8).contains(&before));
    let live = [p.check(ca), p.check(cb)];
    assert!(live.iter().all(|c| c.aligned && c.all_open));
    p.h.restart_relay();

    // the links are cut: both clients reconnect (a new link, a new RELAYINFO) and meet ERR_NOQUEUE
    p.h.connect(ca).unwrap();
    p.h.connect(cb).unwrap();
    assert_eq!(
        send_tapped(&mut p.h, ca, &mut p.side_a, &mut sent_a, b"lost-1").err(),
        Some(Error::NoQueue),
        "sender: ERR 3"
    );
    assert_eq!(
        send_tapped(&mut p.h, ca, &mut p.side_a, &mut sent_a, b"lost-2").err(),
        Some(Error::NoQueue),
        "it keeps sending"
    );
    let (t, e) = p.h.client(cb).link().unwrap();
    assert_eq!(
        p.side_b.poll(t, e).err(),
        Some(Error::NoQueue),
        "recipient: present 2"
    );

    // pacing of this test, not a measured client behaviour: the test itself draws a delay from U[10 s, 5 min] (the
    // re-creation delay of §9.1) and advances the virtual clock by it; then the recipient re-creates the identical queue
    let draw = u64::from_be_bytes(p.h.client(cb).bytes(8).try_into().unwrap());
    let delay = 10 + draw % 291;
    p.h.advance_secs(delay);
    let token = p.h.access_key();
    let (t, _) = p.h.client(cb).link().unwrap();
    let (re_recv, re_send) = t
        .create_queue(&p.seeds_b.recv, &p.seeds_b.send, &token)
        .unwrap();
    assert!(&re_recv == p.side_b.recv_cap(), "the identical queue");
    assert!(
        &re_send == p.side_a.send_cap(),
        "the sender's capability stays valid"
    );
    p.side_b.reset_receiving();
    // A meets present 2 on its own queue too and re-creates it with its seeds (the test adds no second delay)
    let (t, e) = p.h.client(ca).link().unwrap();
    assert_eq!(p.side_a.poll(t, e).err(), Some(Error::NoQueue));
    let (t, _) = p.h.client(ca).link().unwrap();
    let (re_recv_a, _) = t
        .create_queue(&p.seeds_a.recv, &p.seeds_a.send, &token)
        .unwrap();
    assert_eq!(&re_recv_a, p.side_a.recv_cap());
    p.side_a.reset_receiving();

    // A sends again; the cells after the re-creation decrypt, the lost ones are not re-sent
    for i in 10..17 {
        send_tapped(
            &mut p.h,
            ca,
            &mut p.side_a,
            &mut sent_a,
            format!("a{i}").as_bytes(),
        )
        .unwrap();
    }
    let (t, e) = p.h.client(cb).link().unwrap();
    assert_eq!(p.side_b.drain(t, e).unwrap(), 7);
    let got = p.delivered().1;
    let mut want: Vec<String> = (0..before).map(|i| format!("a{i}")).collect();
    want.extend((10..17).map(|i| format!("a{i}")));
    assert_eq!(got, want, "no new invitation, the lost cells stay lost");
    assert_no_mk_reuse(&sent_a);
    // B can still answer: its first send after the restart uses the same ratchet
    let (t, e) = p.h.client(cb).link().unwrap();
    p.side_b.send_text(t, e, b"b-after").unwrap();
    let (t, e) = p.h.client(ca).link().unwrap();
    p.side_a.drain(t, e).unwrap();
    assert_eq!(p.delivered().0, vec!["b-after".to_owned()]);
    let after = [p.check(ca), p.check(cb)];
    assert!(after.iter().all(|c| c.aligned && c.all_open));
    assert_eq!(p.h.restarts(), 1);
}

/// H-13: a cell that does not decrypt is acknowledged all the same (spec §9.3).
#[test]
fn harness_undecryptable_cell_is_acknowledged() {
    let mut p = pair(HarnessConfig::default());
    let (ca, cb) = (p.a, p.b);
    let (t, e) = p.h.client(ca).link().unwrap();
    p.side_a.send_text(t, e, b"first").unwrap();
    // the hook: a random cell from the sender's key between two real cells
    let junk = Cell::from_bytes(&VectorStream::new("harness-junk", 0).take(4096)).unwrap();
    let (t, _) = p.h.client(ca).link().unwrap();
    assert_eq!(t.send(p.side_a.send_cap(), &junk).unwrap().cell_id, 2);
    let (t, e) = p.h.client(ca).link().unwrap();
    p.side_a.send_text(t, e, b"second").unwrap();
    let (t, e) = p.h.client(cb).link().unwrap();
    assert_eq!(p.side_b.drain(t, e).unwrap(), 2, "both real cells decrypt");
    assert_eq!(p.side_b.discarded(), 1, "the random cell is discarded");
    assert_eq!(
        p.delivered().1,
        vec!["first".to_owned(), "second".to_owned()]
    );
    // the next FETCH's acknowledgement covers the discarded cell: the queue is empty
    assert_eq!(p.side_b.committed_ack(), 3);
    let (t, _) = p.h.client(cb).link().unwrap();
    assert!(
        t.fetch(p.side_b.recv_cap(), p.side_b.committed_ack())
            .unwrap()
            .is_empty()
    );
    assert_frames(&mut p.h, &[ca, cb], "H-13");
}

/// G-06: a `RelayQueue` route built by the derived constructor names the queue the relay derived; a `SEND` with the
/// route reaches it (spec §9.8, §9.1).
#[test]
fn route_relay_queue_sid_is_derived() {
    let mut p = pair(HarnessConfig::default());
    let (ca, cb) = (p.a, p.b);
    let token = p.h.access_key();
    let (recv_seed, send_seed) = (p.h.client(cb).seed(), p.h.client(cb).seed());
    let relay_ref = RelayRef {
        relay_fp: p.h.relay_fp(),
        onion: Onion::from_pubkey(&[0x44; 32]),
        akc: secmp_proto::link::ids::akc(&token),
        direct: None,
    };
    let recv_pk = {
        let key = secmp_crypto::Ed25519SigningKey::from_seed(recv_seed.expose_secret()).unwrap();
        Ed25519Pk::from_bytes(key.verifying_key().as_bytes()).unwrap()
    };
    let route = RelayQueue::derived(
        relay_ref,
        &recv_pk,
        SecretBytes::from_slice(send_seed.expose_secret()).unwrap(),
        Period::S20,
    )
    .unwrap();
    let (t, _) = p.h.client(cb).link().unwrap();
    let (recv_cap, send_cap) = t.create_queue(&recv_seed, &send_seed, &token).unwrap();
    // the sid of the route is the derived sid of the created queue
    assert_eq!(&route.sid, send_cap.sid());
    // a SEND with a capability made from the route reaches the queue
    let via_route = SendCap::from_route(route.sid, &route.send_seed).unwrap();
    let (t, _) = p.h.client(ca).link().unwrap();
    assert_eq!(t.send(&via_route, &cell(0x9a)).unwrap().cell_id, 1);
    let (t, _) = p.h.client(cb).link().unwrap();
    let got = t.fetch(&recv_cap, 0).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got.first().unwrap().1.as_bytes(), cell(0x9a).as_bytes());
}
