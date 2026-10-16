// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The in-process relay for the asynchronous driver (TEST-SPEC-M6 AD-07, AD-08, AD-10, P-05, the tokio repeats of
//! AI-01…AI-06): [`MemRelay`] runs the M5 relay (`secmp_relay::Connection`, sans-IO) behind `tokio::io::duplex`
//! streams that [`MemProvider`] hands out as a [`StreamProvider`]. No socket is opened (docs/06 §4).
//!
//! Time is the runtime's ([`TokioClock`]: virtual under `tokio::time::pause`); the relay's randomness is the stream
//! `harness-relay` of the M5 harness, drawn in connection order, so a run is reproducible and the first connection of
//! a [`MemRelay`] sees the same relay randomness as the first connection of a [`super::Harness`]. Every unit that
//! crosses a connection is recorded with the time it crossed ([`MemRelay::units`]): the client's units when the relay
//! reads them (the instant the client wrote them; a duplex moves bytes without delay), the relay's units when the relay
//! writes them (after `latency_ms`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use secmp_client_core::clock::{Clock, TokioClock};
use secmp_proto::link::ids::{AccessKey, akc};
use secmp_proto::wire::inv::{Onion, RelayRef};
use secmp_relay::{Connection, Now, Relay};
use secmp_transport::Error as TransportError;
use secmp_transport::driver::{Isolation, StreamProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::Harness;
use super::driver::Dir;
use super::entropy::EntropyPool;
use super::stream::FRAME;
use super::world::{HarnessConfig, RelaySeeds, START_UNIX};

/// One unit (handshake record or frame) that crossed a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit {
    /// Virtual milliseconds when it crossed.
    pub t_ms: u64,
    /// Bytes.
    pub len: usize,
    /// Direction.
    pub dir: Dir,
    /// The connection, in the order the relay accepted them.
    pub conn: u64,
    /// The isolation the connection was opened with.
    pub isolation: Isolation,
}

/// A change of one queue in the relay's store, as the relay saw it after a unit of one connection (the extended AI
/// oracle, WEISUNG M6-B-5/-6 EXTB-1): the queue's `next_cell_id` (it moves with every stored `SEND`) and its head (the
/// oldest stored cell id, or `next_cell_id` when empty; it moves with acknowledgements and evictions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreChange {
    /// Virtual milliseconds of the unit.
    pub t_ms: u64,
    /// The isolation of the connection whose unit changed the store.
    pub isolation: Isolation,
    /// The queue (`rid`).
    pub rid: secmp_proto::wire::Id,
    /// Its `next_cell_id` after the unit.
    pub next_cell_id: u64,
    /// Its head after the unit.
    pub head: u64,
}

/// How the relay's answers are cut (P-05): pieces of 1…4352 bytes from a seed, with up to `max_gap_ms` between them.
#[derive(Clone, Copy, Debug)]
pub struct Chunking {
    /// The seed of the piece sizes and gaps.
    pub seed: u64,
    /// The largest gap between two pieces.
    pub max_gap_ms: u64,
}

/// The store as of the last unit and the changes so far (see [`MemRelay::store_changes`]).
type StoreLog = (
    std::collections::BTreeMap<secmp_proto::wire::Id, (u64, u64)>,
    Vec<StoreChange>,
);

struct Inner {
    relay: &'static Relay,
    access: AccessKey,
    clock: TokioClock,
    entropy: Mutex<EntropyPool>,
    units: Mutex<Vec<Unit>>,
    next_conn: AtomicU64,
    latency_ms: AtomicU64,
    chunking: Mutex<Option<Chunking>>,
    captures: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    isolations: Mutex<Vec<(u64, Isolation)>>,
    /// The store as of the last unit (`rid` → `next_cell_id`, head) and every change since the start.
    store: Mutex<StoreLog>,
}

/// The relay host (see the module documentation). Clones share the relay.
#[derive(Clone)]
pub struct MemRelay(Arc<Inner>);

fn now_of(clock: &TokioClock) -> Now {
    Now {
        unix_secs: clock.unix_secs(),
        mono_ms: clock.mono_ms(),
    }
}

/// Sizes 1…4352 and gaps from a seed (xorshift64*; deterministic, not cryptographic).
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// Splits the bytes of one direction into the units of D.1 / D.2: two handshake records, then frames.
struct Units {
    sizes: [usize; 2],
    taken: usize,
    pending: usize,
}

impl Units {
    const fn new(first: usize, second: usize) -> Self {
        Self {
            sizes: [first, second],
            taken: 0,
            pending: 0,
        }
    }

    /// Count `n` more bytes; the lengths of the units they complete.
    fn push(&mut self, n: usize) -> Vec<usize> {
        self.pending = self.pending.saturating_add(n);
        let mut out = Vec::new();
        loop {
            let size = self.sizes.get(self.taken).copied().unwrap_or(FRAME);
            if self.pending < size {
                break;
            }
            self.pending = self.pending.saturating_sub(size);
            self.taken = self.taken.saturating_add(1);
            out.push(size);
        }
        out
    }
}

impl MemRelay {
    /// A relay with `config`'s limits and the keys of the M5 harness. Call inside a tokio runtime (the clock starts
    /// at the runtime's now, Unix time [`START_UNIX`]).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn new(config: HarnessConfig) -> Self {
        let clock = TokioClock::new(START_UNIX);
        let seeds = RelaySeeds::new();
        let relay = Harness::start_relay(&seeds, &config, now_of(&clock));
        Self(Arc::new(Inner {
            relay,
            access: seeds.access(),
            clock,
            entropy: Mutex::new(EntropyPool::new("harness-relay", 0)),
            units: Mutex::new(Vec::new()),
            next_conn: AtomicU64::new(0),
            latency_ms: AtomicU64::new(0),
            chunking: Mutex::new(None),
            captures: Mutex::new(Vec::new()),
            isolations: Mutex::new(Vec::new()),
            store: Mutex::new((std::collections::BTreeMap::new(), Vec::new())),
        }))
    }

    /// The clock the relay reads (the driver of a test reads the same one).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn clock(&self) -> TokioClock {
        self.0.clock
    }

    /// The relay (its stores through the `kat` accessors).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn relay(&self) -> &'static Relay {
        self.0.relay
    }

    /// The relay's access key.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn access_key(&self) -> AccessKey {
        secmp_crypto::SecretBytes::from_slice(self.0.access.expose_secret()).unwrap()
    }

    /// The relay's pinned fingerprint.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn relay_fp(&self) -> [u8; 32] {
        self.0.relay.keys().newest().unwrap().0.fp()
    }

    /// A `RelayRef` of this relay: its fingerprint, the `akc` of its access key, a fixed test onion (pk = 32 × 0x42),
    /// no direct endpoint.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn relay_ref(&self) -> RelayRef {
        let pk = [0x42_u8; 32];
        let check = secmp_crypto::sha3_256(&[b".onion checksum", &pk, &[0x03]]);
        let mut onion = [0_u8; 35];
        onion.get_mut(..32).unwrap().copy_from_slice(&pk);
        onion
            .get_mut(32..34)
            .unwrap()
            .copy_from_slice(check.get(..2).unwrap());
        *onion.get_mut(34).unwrap() = 0x03;
        RelayRef {
            relay_fp: self.relay_fp(),
            onion: Onion::from_bytes(&onion).unwrap(),
            akc: akc(&self.0.access),
            direct: None,
        }
    }

    /// Delay every answer of the relay by `ms` virtual milliseconds.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn set_latency_ms(&self, ms: u64) {
        self.0.latency_ms.store(ms, Ordering::SeqCst);
    }

    /// Cut the relay's answers into pieces (P-05); `None` writes them whole.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn set_chunking(&self, chunking: Option<Chunking>) {
        *self.0.chunking.lock().unwrap() = chunking;
    }

    /// Every unit that crossed so far.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn units(&self) -> Vec<Unit> {
        self.0.units.lock().unwrap().clone()
    }

    /// The bytes of connection `n` so far: (client → relay, relay → client).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn capture(&self, n: u64) -> (Vec<u8>, Vec<u8>) {
        let caps = self.0.captures.lock().unwrap();
        caps.get(usize::try_from(n).unwrap())
            .cloned()
            .unwrap_or_default()
    }

    /// Let the relay's sweeper run at the clock's time.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn tick(&self) {
        self.0.relay.tick(now_of(&self.0.clock));
    }

    /// A new connection (the relay's accept), `None` while the relay drains.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn open(&self, isolation: Isolation) -> Option<DuplexStream> {
        let inner = Arc::clone(&self.0);
        let mut conn = Connection::accept(inner.relay, now_of(&inner.clock))?;
        let n = inner.next_conn.fetch_add(1, Ordering::SeqCst);
        inner
            .captures
            .lock()
            .unwrap()
            .push((Vec::new(), Vec::new()));
        inner.isolations.lock().unwrap().push((n, isolation));
        let (client, mut server) = tokio::io::duplex(1 << 17);
        tokio::spawn(async move {
            let mut c2r = Units::new(9, 2856);
            let mut r2c = Units::new(1744, 1156);
            let mut buf = vec![0_u8; 1 << 16];
            let mut mix = inner
                .chunking
                .lock()
                .unwrap()
                .map(|c| (Mix(c.seed.wrapping_add(n) | 1), c.max_gap_ms));
            while let Ok(read) = server.read(&mut buf).await {
                if read == 0 {
                    break;
                }
                let data = buf.get(..read).unwrap();
                let t = inner.clock.mono_ms();
                {
                    let mut units = inner.units.lock().unwrap();
                    for len in c2r.push(read) {
                        units.push(Unit {
                            t_ms: t,
                            len,
                            dir: Dir::C2R,
                            conn: n,
                            isolation,
                        });
                    }
                }
                let out = {
                    let mut entropy = inner.entropy.lock().unwrap();
                    conn.on_bytes(data, now_of(&inner.clock), entropy.get())
                };
                // what this unit changed in the store (no await since `on_bytes`: nothing else ran in between)
                Self::record_store(&inner, t, isolation);
                {
                    let mut caps = inner.captures.lock().unwrap();
                    let cap = caps.get_mut(usize::try_from(n).unwrap()).unwrap();
                    cap.0.extend_from_slice(data);
                    cap.1.extend_from_slice(&out.bytes);
                }
                let latency = inner.latency_ms.load(Ordering::SeqCst);
                if latency > 0 && !out.bytes.is_empty() {
                    tokio::time::sleep(std::time::Duration::from_millis(latency)).await;
                }
                let mut ok = true;
                if let Some((m, gap)) = mix.as_mut() {
                    let mut rest: &[u8] = &out.bytes;
                    while !rest.is_empty() {
                        let size = usize::try_from(m.next().checked_rem(4352).unwrap_or(0))
                            .unwrap()
                            .saturating_add(1);
                        let (piece, tail) = rest.split_at(size.min(rest.len()));
                        rest = tail;
                        if *gap > 0 {
                            let wait = m.next().checked_rem(gap.saturating_add(1)).unwrap_or(0);
                            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                        }
                        if server.write_all(piece).await.is_err() {
                            ok = false;
                            break;
                        }
                        Self::record_r2c(&inner, &mut r2c, piece.len(), n, isolation);
                    }
                } else if !out.bytes.is_empty() {
                    ok = server.write_all(&out.bytes).await.is_ok();
                    Self::record_r2c(&inner, &mut r2c, out.bytes.len(), n, isolation);
                }
                if out.close || !ok {
                    let _ = server.shutdown().await;
                    break;
                }
            }
        });
        Some(client)
    }

    fn record_store(inner: &Inner, t: u64, isolation: Isolation) {
        let snap = inner.relay.snapshot_kat();
        let mut store = inner.store.lock().unwrap();
        let (last, changes) = &mut *store;
        for q in snap.queues {
            let head = q.cell_ids.first().copied().unwrap_or(q.next_cell_id);
            let now = (q.next_cell_id, head);
            if last.get(&q.rid) != Some(&now) {
                last.insert(q.rid, now);
                changes.push(StoreChange {
                    t_ms: t,
                    isolation,
                    rid: q.rid,
                    next_cell_id: q.next_cell_id,
                    head,
                });
            }
        }
    }

    /// Every change of the store's queues, unit by unit, since the start (see [`StoreChange`]).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn store_changes(&self) -> Vec<StoreChange> {
        self.0.store.lock().unwrap().1.clone()
    }

    fn record_r2c(inner: &Inner, r2c: &mut Units, n_bytes: usize, conn: u64, isolation: Isolation) {
        let t = inner.clock.mono_ms();
        let mut units = inner.units.lock().unwrap();
        for len in r2c.push(n_bytes) {
            units.push(Unit {
                t_ms: t,
                len,
                dir: Dir::R2C,
                conn,
                isolation,
            });
        }
    }

    /// The isolation each connection was opened with, by connection.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn isolations(&self) -> Vec<(u64, Isolation)> {
        self.0.isolations.lock().unwrap().clone()
    }
}

/// The [`StreamProvider`] of a [`MemRelay`] (TEST-SPEC-M6 AD-10): every connect is a new in-process connection; the
/// `RelayRef` must name this relay's fingerprint.
#[derive(Clone)]
pub struct MemProvider {
    relay: MemRelay,
    connects: Arc<Mutex<Vec<(u64, Isolation)>>>,
}

impl MemProvider {
    /// The provider of `relay`.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn new(relay: MemRelay) -> Self {
        Self {
            relay,
            connects: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The relay.
    #[must_use]
    pub const fn relay(&self) -> &MemRelay {
        &self.relay
    }

    /// Every connect: time, isolation.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn connects(&self) -> Vec<(u64, Isolation)> {
        self.connects.lock().unwrap().clone()
    }
}

impl StreamProvider for MemProvider {
    type Stream = DuplexStream;

    fn connect(
        &self,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> impl core::future::Future<Output = Result<DuplexStream, TransportError>> + Send {
        self.connects
            .lock()
            .unwrap()
            .push((self.relay.clock().mono_ms(), isolation));
        let result = if relay.relay_fp == self.relay.relay_fp() {
            self.relay.open(isolation).ok_or(TransportError::Closed)
        } else {
            Err(TransportError::Closed)
        };
        core::future::ready(result)
    }
}
