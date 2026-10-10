// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! In-process byte streams between a client and the relay (feature `kat`): no socket is opened (docs/06 §4).
//!
//! A [`HarnessStream`] is the client's end of one connection. Whatever the client writes goes into the relay's
//! [`Connection`] (sans-IO) at once, and the bytes the connection answers wait in the stream until the client reads
//! them; the end of the answers — a relay that closed or has nothing to say — reads as end of stream. Every byte in
//! both directions is captured ([`Capture`]) for the byte-level tests (H-08, H-10).
//!
//! [`Split`] cuts the traffic into pieces of 1…4352 bytes in both directions (H-11): the relay must give the same
//! answers however the stream is cut.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::rc::Rc;

use secmp_relay::{Connection, Relay};

use super::clock::Clock;
use super::entropy::EntropyPool;

/// How the traffic of a stream is cut into pieces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    /// Each write reaches the relay whole and each read returns what is there.
    Whole,
    /// Pieces of 1…4352 bytes whose sizes follow a fixed pseudo-random sequence of this seed (deterministic).
    Chunked(u64),
}

/// The bytes of one connection, as they crossed the stream.
#[derive(Clone, Default)]
pub struct Capture {
    /// Client → relay.
    pub to_relay: Vec<u8>,
    /// Relay → client.
    pub to_client: Vec<u8>,
}

/// `HELLO` (9 B) and `HS1` (2856 B) are what the client sends before `HS2`.
pub const CLIENT_HANDSHAKE_BYTES: usize = 9 + 2856;
/// `RELAYINFO` (1744 B) and `HS2` (1156 B) are what the relay sends before the first frame.
pub const RELAY_HANDSHAKE_BYTES: usize = 1744 + 1156;
/// The size of a frame.
pub const FRAME: usize = 4352;

impl Capture {
    /// The frames the client sent after `HS1` (D.1: the stream carries only 4352-byte units from then on).
    #[must_use]
    pub fn frames_to_relay(&self) -> &[u8] {
        self.to_relay.get(CLIENT_HANDSHAKE_BYTES..).unwrap_or(&[])
    }

    /// The frames the relay sent after `HS2`.
    #[must_use]
    pub fn frames_to_client(&self) -> &[u8] {
        self.to_client.get(RELAY_HANDSHAKE_BYTES..).unwrap_or(&[])
    }
}

/// Sizes 1…4352 from a seed (xorshift64*; deterministic, not cryptographic).
struct Sizes(u64);

impl Sizes {
    fn next(&mut self) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let x = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let frame = u64::try_from(FRAME).unwrap();
        usize::try_from(x.checked_rem(frame).unwrap())
            .unwrap()
            .saturating_add(1)
    }
}

struct Pipe {
    conn: Connection<'static>,
    clock: Clock,
    relay_entropy: Rc<RefCell<EntropyPool>>,
    inbox: VecDeque<u8>,
    capture: Capture,
    capturing: bool,
    closed: bool,
    sizes: Option<Sizes>,
}

impl Pipe {
    fn feed(&mut self, data: &[u8]) {
        if self.capturing {
            self.capture.to_relay.extend_from_slice(data);
        }
        let mut rest = data;
        while !rest.is_empty() && !self.closed {
            let take = self
                .sizes
                .as_mut()
                .map_or(rest.len(), |s| s.next().min(rest.len()));
            let (piece, tail) = rest.split_at(take);
            rest = tail;
            let now = self.clock.now();
            let out = {
                let mut entropy = self.relay_entropy.borrow_mut();
                self.conn.on_bytes(piece, now, entropy.get())
            };
            if self.capturing {
                self.capture.to_client.extend_from_slice(&out.bytes);
            }
            self.inbox.extend(out.bytes);
            if out.close {
                self.closed = true;
            }
        }
    }
}

/// The client's end of one in-process connection; clones share the connection.
#[derive(Clone)]
pub struct HarnessStream(Rc<RefCell<Pipe>>);

impl HarnessStream {
    /// A connection accepted by `relay`, `None` while the relay drains (the listener refuses it).
    pub(crate) fn open(
        relay: &'static Relay,
        clock: &Clock,
        relay_entropy: &Rc<RefCell<EntropyPool>>,
        split: Split,
    ) -> Option<Self> {
        let conn = Connection::accept(relay, clock.now())?;
        let sizes = match split {
            Split::Whole => None,
            Split::Chunked(seed) => Some(Sizes(seed | 1)),
        };
        Some(Self(Rc::new(RefCell::new(Pipe {
            conn,
            clock: clock.clone(),
            relay_entropy: Rc::clone(relay_entropy),
            inbox: VecDeque::new(),
            capture: Capture::default(),
            capturing: true,
            closed: false,
            sizes,
        }))))
    }

    /// The bytes that crossed so far.
    #[must_use]
    pub fn capture(&self) -> Capture {
        self.0.borrow().capture.clone()
    }

    /// Keep (or stop keeping) the byte capture of this connection; long simulations switch it off.
    pub fn set_capture(&self, on: bool) {
        self.0.borrow_mut().capturing = on;
    }

    /// Whether the relay closed the connection (or the harness cut it).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.borrow().closed
    }

    /// Cut the connection (a relay restart): nothing more is read or written.
    pub fn cut(&self) {
        let mut p = self.0.borrow_mut();
        p.closed = true;
        p.inbox.clear();
    }
}

impl Read for HarnessStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut p = self.0.borrow_mut();
        let limit = match p.sizes.as_mut() {
            Some(s) => s.next().min(buf.len()),
            None => buf.len(),
        };
        let mut n = 0_usize;
        while n < limit {
            let (Some(slot), Some(byte)) = (buf.get_mut(n), p.inbox.pop_front()) else {
                break;
            };
            *slot = byte;
            n = n.checked_add(1).unwrap();
        }
        Ok(n)
    }
}

impl Write for HarnessStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut p = self.0.borrow_mut();
        if p.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        p.feed(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
