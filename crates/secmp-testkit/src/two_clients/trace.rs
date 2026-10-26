// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The trace of a `two-clients` run (TEST-SPEC-M6 TC-09) and the providers that record it.
//!
//! One JSON object per line, exactly these keys and no other:
//! - a unit (a handshake record or a 4 352-byte frame the client wrote or read): `t_ms`, `len`, `dir` (`"c2r"` or
//!   `"r2c"`), `link_slot` (the link's index in creation order, over all links of the run — not an id);
//! - a message event: `event` (`"enqueue"` or `"deliver"`), `msg` (the script's ordinal: `0..N` for the inviter's
//!   messages, `N..2N` for the invitee's), `t_ms`.
//!
//! No identifier, key, address or payload byte is ever written. The units are counted where the driver's streams
//! cross ([`Traced`]): the lengths of the handshake records are those of spec D.1 (`HELLO` 9, `RELAYINFO` 1 744,
//! `HS1` 2 856, `HS2` 1 156); every later unit is a frame of 4 352 bytes.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use secmp_client_core::clock::{Clock as _, TokioClock};
use secmp_proto::wire::inv::RelayRef;
use secmp_transport::Error as TransportError;
use secmp_transport::driver::{Isolation, StreamProvider};
use secmp_transport::tls::{Dialer as _, TcpDialer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::harness::Dir;

/// One unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitRec {
    /// The client's clock (milliseconds) when the unit was complete.
    pub t_ms: u64,
    /// Bytes.
    pub len: usize,
    /// Direction.
    pub dir: Dir,
    /// The link, in creation order.
    pub slot: u64,
}

/// One message event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRec {
    /// `"enqueue"` or `"deliver"`.
    pub event: &'static str,
    /// The script's ordinal.
    pub msg: u64,
    /// The clock (milliseconds).
    pub t_ms: u64,
}

#[derive(Default)]
struct Inner {
    slots: u64,
    units: Vec<UnitRec>,
    events: Vec<EventRec>,
    /// What went wrong, with the clock's time.
    errors: Vec<(u64, String)>,
    /// The run is over: streams dropped from now on are not residuals.
    sealed: bool,
    /// The isolation key each link slot was connected with (the driver's, fresh for every connection), by slot.
    isolations: BTreeMap<u64, u64>,
}

/// What a run recorded (shared by both clients of a process).
pub struct Recorder {
    clock: TokioClock,
    inner: Mutex<Inner>,
}

impl Recorder {
    /// A recorder reading `clock`.
    #[must_use]
    pub fn new(clock: TokioClock) -> Arc<Self> {
        Arc::new(Self {
            clock,
            inner: Mutex::new(Inner::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_slot(&self) -> u64 {
        let mut g = self.lock();
        let slot = g.slots;
        g.slots = g.slots.saturating_add(1);
        slot
    }

    fn unit(&self, len: usize, dir: Dir, slot: u64) {
        let t_ms = self.clock.mono_ms();
        self.lock().units.push(UnitRec {
            t_ms,
            len,
            dir,
            slot,
        });
    }

    fn error(&self, what: String) {
        let t_ms = self.clock.mono_ms();
        self.lock().errors.push((t_ms, what));
    }

    /// The run is over: its streams are dropped on purpose from now on, wherever they stand.
    pub fn seal(&self) {
        self.lock().sealed = true;
    }

    fn sealed(&self) -> bool {
        self.lock().sealed
    }

    /// A stream of the run under this recorder: its units are recorded as they cross (see [`TracedStream`]); the link
    /// slot is the next in creation order.
    pub fn wrap<S>(self: &Arc<Self>, inner: S) -> TracedStream<S> {
        self.wrap_isolated(inner, None)
    }

    /// As [`Recorder::wrap`], remembering the isolation key the connection was made with ([`Recorder::isolations`]).
    pub fn wrap_isolated<S>(self: &Arc<Self>, inner: S, isolation: Option<u64>) -> TracedStream<S> {
        let slot = self.next_slot();
        if let Some(key) = isolation {
            self.lock().isolations.insert(slot, key);
        }
        TracedStream {
            inner,
            rec: Arc::clone(self),
            slot,
            pending: 0,
            read: ReadSide::default(),
            lenient: false,
        }
    }

    /// The run's trace is sound: no stream ended inside a unit.
    ///
    /// # Errors
    /// What ended where: the link, the direction and the residual bytes.
    pub fn check(&self) -> Result<(), String> {
        let g = self.lock();
        if g.errors.is_empty() {
            Ok(())
        } else {
            let all: Vec<&str> = g.errors.iter().map(|(_, e)| e.as_str()).collect();
            Err(all.join("; "))
        }
    }

    /// A message event at `t_ms`.
    pub fn event(&self, event: &'static str, msg: u64, t_ms: u64) {
        self.lock().events.push(EventRec { event, msg, t_ms });
    }

    /// The isolation key of each slot's connection, by slot (C2-18b: it tells a control connection from a link).
    #[must_use]
    pub fn isolations(&self) -> BTreeMap<u64, u64> {
        self.lock().isolations.clone()
    }

    /// The units recorded so far.
    #[must_use]
    pub fn units(&self) -> Vec<UnitRec> {
        self.lock().units.clone()
    }

    /// The events recorded so far.
    #[must_use]
    pub fn events(&self) -> Vec<EventRec> {
        self.lock().events.clone()
    }

    /// The trace as JSON lines (units by time, then the events by time).
    #[must_use]
    pub fn jsonl(&self) -> String {
        let g = self.lock();
        let mut units = g.units.clone();
        units.sort_by_key(|u| (u.t_ms, u.slot, u.dir));
        let mut events = g.events.clone();
        events.sort_by_key(|e| (e.t_ms, e.msg));
        let mut out = String::new();
        for u in units {
            let dir = if u.dir == Dir::C2R { "c2r" } else { "r2c" };
            let _ = writeln!(
                out,
                "{{\"t_ms\":{},\"len\":{},\"dir\":\"{dir}\",\"link_slot\":{}}}",
                u.t_ms, u.len, u.slot
            );
        }
        for e in events {
            let _ = writeln!(
                out,
                "{{\"event\":\"{}\",\"msg\":{},\"t_ms\":{}}}",
                e.event, e.msg, e.t_ms
            );
        }
        // a recorder error is a message event too (the keys stay `event`, `msg`, `t_ms`): `msg` is its ordinal
        for (i, (t_ms, _)) in g.errors.iter().enumerate() {
            let _ = writeln!(
                out,
                "{{\"event\":\"trace_error\",\"msg\":{i},\"t_ms\":{t_ms}}}"
            );
        }
        out
    }
}

/// What the read side of a stream has seen of the unit in progress. The boundary of a unit is the reader's own request
/// (`read_exact` of one frame): the length is what the client asked for, observed, never a constant of this module.
/// A handshake record (spec D.1) is read as its two-byte length and then its body: a two-byte read whose big-endian
/// value is the size of the next request is held and logged as one record of `2 + that` bytes.
#[derive(Default)]
struct ReadSide {
    /// The size of the request in progress and the bytes it has received.
    want: usize,
    got: usize,
    /// A completed two-byte read, held until the next request shows whether it was a record's length prefix: its value.
    held: Option<usize>,
    /// The next request completes a record whose prefix was held.
    merged: bool,
    /// The first two bytes of the request in progress.
    head: [u8; 2],
}

/// A provider's stream that records every unit crossing it as it crosses: a write is delimited by the flush that ends
/// it (the driver writes one frame, then flushes), a read by the request that receives it.
pub struct TracedStream<S> {
    inner: S,
    rec: Arc<Recorder>,
    slot: u64,
    /// Bytes written since the last flush.
    pending: usize,
    read: ReadSide,
    /// A drop with a unit in progress is not an error (the streams of a pool that is shut down on purpose).
    lenient: bool,
}

impl<S> Drop for TracedStream<S> {
    /// A stream dropped inside a unit — a link torn down while a frame was half written or half read — is a residual
    /// like one at the close, unless the run is over (`Recorder::seal`) or the stream is lenient.
    fn drop(&mut self) {
        if self.lenient || self.rec.sealed() {
            return;
        }
        if self.pending > 0 {
            self.rec.error(format!(
                "link {} c2r: residual {} B at drop, no unit",
                self.slot, self.pending
            ));
        }
        if self.read.got > 0 {
            self.rec.error(format!(
                "link {} r2c: residual {} B at drop, no unit",
                self.slot, self.read.got
            ));
        }
    }
}

impl<S> TracedStream<S> {
    fn close_write(&mut self) {
        if self.pending > 0 {
            self.rec.error(format!(
                "link {} c2r: residual {} B at close, no unit",
                self.slot, self.pending
            ));
            self.pending = 0;
        }
    }

    /// The reader's request of `capacity` bytes received `filled` (no bytes: the end of the stream).
    fn read_done(&mut self, capacity: usize, filled: &[u8]) {
        let n = filled.len();
        if capacity == 0 {
            return;
        }
        if n == 0 {
            // the end of the stream
            if self.read.got > 0 {
                self.rec.error(format!(
                    "link {} r2c: residual {} B at close, no unit",
                    self.slot, self.read.got
                ));
                self.read.got = 0;
            }
            if self.read.held.take().is_some() {
                self.rec.unit(2, Dir::R2C, self.slot);
            }
            return;
        }
        if self.read.got == 0 {
            // a new request: `capacity` is what the reader asked for
            self.read.want = capacity;
            self.read.merged = false;
            if let Some(prefix) = self.read.held {
                if prefix == capacity {
                    self.read.merged = true;
                } else {
                    self.rec.unit(2, Dir::R2C, self.slot);
                }
                self.read.held = None;
            }
        }
        for (i, b) in filled.iter().enumerate() {
            if let Some(slot) = self.read.head.get_mut(self.read.got.saturating_add(i)) {
                *slot = *b;
            }
        }
        self.read.got = self.read.got.saturating_add(n);
        if self.read.got < self.read.want {
            return;
        }
        let len = self.read.got;
        self.read.got = 0;
        if self.read.merged {
            self.rec.unit(len.saturating_add(2), Dir::R2C, self.slot);
        } else if len == 2 {
            self.read.held = Some(usize::from(u16::from_be_bytes(self.read.head)));
        } else {
            self.rec.unit(len, Dir::R2C, self.slot);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TracedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let capacity = buf.remaining();
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) {
            let filled = buf.filled().get(before..).unwrap_or_default().to_vec();
            self.read_done(capacity, &filled);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TracedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.pending = self.pending.saturating_add(n);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(r, Poll::Ready(Ok(()))) && self.pending > 0 {
            self.rec.unit(self.pending, Dir::C2R, self.slot);
            self.pending = 0;
        }
        r
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.close_write();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A provider shared by the clients of a process, whose streams are traced. Only the driver's connections go through
/// it: the invitation and handshake of the script use the plain provider and are not part of the trace.
pub struct Traced<P> {
    inner: Arc<P>,
    rec: Arc<Recorder>,
    lenient: bool,
}

impl<P> Traced<P> {
    /// `inner`, recording into `rec`.
    pub const fn new(inner: Arc<P>, rec: Arc<Recorder>) -> Self {
        Self {
            inner,
            rec,
            lenient: false,
        }
    }

    /// As [`Traced::new`], for streams that may be dropped inside a unit (a pool shut down on purpose).
    pub const fn lenient(inner: Arc<P>, rec: Arc<Recorder>) -> Self {
        Self {
            inner,
            rec,
            lenient: true,
        }
    }
}

impl<P: StreamProvider> StreamProvider for Traced<P> {
    type Stream = TracedStream<P::Stream>;

    async fn connect(
        &self,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> Result<Self::Stream, TransportError> {
        let inner = self.inner.connect(relay, isolation).await?;
        let mut stream = self.rec.wrap_isolated(inner, Some(isolation.0));
        stream.lenient = self.lenient;
        Ok(stream)
    }
}

/// Plain TCP to the relay's loopback listener (`--transport loopback`): the host and port of the `RelayRef`'s direct
/// endpoint, no TLS, the pin ignored. The relay's loopback listener is the one its onion service forwards to
/// (`tor_loopback` in the relay configuration); a test tool reaches it directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpProvider;

impl StreamProvider for TcpProvider {
    type Stream = tokio::net::TcpStream;

    async fn connect(
        &self,
        relay: &RelayRef,
        _isolation: Isolation,
    ) -> Result<Self::Stream, TransportError> {
        let direct = relay
            .direct
            .as_ref()
            .ok_or(TransportError::NoDirectEndpoint)?;
        let host =
            core::str::from_utf8(direct.host.as_bytes()).map_err(|_| TransportError::Invalid)?;
        TcpDialer.dial(host, direct.port.get()).await
    }
}

/// Write `text` to `path` (the `--trace-out` file).
///
/// # Errors
/// The I/O error.
pub fn write_file(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(text.as_bytes())
}
