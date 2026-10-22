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

    /// A message event at `t_ms`.
    pub fn event(&self, event: &'static str, msg: u64, t_ms: u64) {
        self.lock().events.push(EventRec { event, msg, t_ms });
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
        out
    }
}

/// The length of unit `index` of a direction (spec D.1, §8.4).
const fn unit_len(dir: Dir, index: usize) -> usize {
    match (dir, index) {
        (Dir::C2R, 0) => 9,
        (Dir::C2R, 1) => 2_856,
        (Dir::R2C, 0) => 1_744,
        (Dir::R2C, 1) => 1_156,
        _ => 4_352,
    }
}

#[derive(Default)]
struct Counter {
    index: usize,
    got: usize,
}

impl Counter {
    fn add(&mut self, mut n: usize, dir: Dir, slot: u64, rec: &Recorder) {
        while n > 0 {
            let need = unit_len(dir, self.index).saturating_sub(self.got);
            let take = need.min(n);
            self.got = self.got.saturating_add(take);
            n = n.saturating_sub(take);
            if self.got >= unit_len(dir, self.index) {
                rec.unit(self.got, dir, slot);
                self.index = self.index.saturating_add(1);
                self.got = 0;
            }
        }
    }
}

/// A provider's stream that counts the units crossing it.
pub struct TracedStream<S> {
    inner: S,
    rec: Arc<Recorder>,
    slot: u64,
    c2r: Counter,
    r2c: Counter,
}

impl<S: AsyncRead + Unpin> AsyncRead for TracedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) {
            let n = buf.filled().len().saturating_sub(before);
            let (rec, slot) = (Arc::clone(&self.rec), self.slot);
            self.r2c.add(n, Dir::R2C, slot, &rec);
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
            let (rec, slot) = (Arc::clone(&self.rec), self.slot);
            self.c2r.add(n, Dir::C2R, slot, &rec);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A provider shared by the clients of a process, whose streams are traced. Only the driver's connections go through
/// it: the invitation and handshake of the script use the plain provider and are not part of the trace.
pub struct Traced<P> {
    inner: Arc<P>,
    rec: Arc<Recorder>,
}

impl<P> Traced<P> {
    /// `inner`, recording into `rec`.
    pub const fn new(inner: Arc<P>, rec: Arc<Recorder>) -> Self {
        Self { inner, rec }
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
        Ok(TracedStream {
            inner,
            rec: Arc::clone(&self.rec),
            slot: self.rec.next_slot(),
            c2r: Counter::default(),
            r2c: Counter::default(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_lengths_then_frames() {
        assert_eq!(
            [0, 1, 2, 3].map(|i| unit_len(Dir::C2R, i)),
            [9, 2_856, 4_352, 4_352]
        );
        assert_eq!(
            [0, 1, 2, 3].map(|i| unit_len(Dir::R2C, i)),
            [1_744, 1_156, 4_352, 4_352]
        );
    }
}
