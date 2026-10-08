// SPDX-License-Identifier: AGPL-3.0-or-later
//! One client connection, sans-IO (spec §8.2–§8.5, D.1; §9.7 item 7): bytes in, bytes out.
//!
//! ```text
//! accept ──► AwaitHello ──HELLO──► AwaitHs1 ──HS1──► Linked(Executor) ──units──► …
//!                        (RELAYINFO)          (HS2)
//! ```
//!
//! Before `HS2` the stream carries records `len: u16 ‖ body` (D.1); the connection reads the length first and tears
//! down at once on a length other than the expected record's (`HELLO` 7, `HS1` 2854). After `HS2` it carries only
//! 4352-byte units (no length prefix) — a second `HELLO` or anything else is read as a unit and fails to open (at
//! most one link per connection, §9.7 item 7). A teardown emits nothing further and closes the connection (§8.5).
//!
//! Limits (§9.7 item 7, ADR-048 (p), OPEN-M5-02): a `HELLO` over the listener's handshake rate closes the
//! connection before `RELAYINFO`; a connection without a complete `HS1` within the `HELLO`→`HS1` timeout of its
//! `HELLO` is closed, nothing emitted (the same bound applies from accept to `HELLO`, an engineering choice); `HS1`
//! is accepted only for a key generation that is still valid (OPEN-M5-10). The connection buffers at most one
//! record or unit.

use secmp_proto::Decode;
use secmp_proto::link::relay::{AwaitHs1, accept_ring};
use secmp_proto::sizes::{FRAME_LEN, HELLO_BODY_LEN, HS1_LEN};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::record::Hs1;

use crate::clock::Now;
use crate::executor::{Executor, Outcome};
use crate::relay::Relay;

/// Bytes of a `HELLO` record (`len` 2 + body 7).
const HELLO_RECORD_LEN: usize = 2 + HELLO_BODY_LEN;
/// The `len` field of `HS1` (type byte + body).
const HS1_BODY_LEN: usize = 1 + HS1_LEN;
/// Bytes of an `HS1` record.
const HS1_RECORD_LEN: usize = 2 + HS1_BODY_LEN;

/// What to write and whether to close.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Bytes to send, in order.
    pub bytes: Vec<u8>,
    /// Close the connection after writing `bytes`.
    pub close: bool,
}

enum Phase<'r> {
    AwaitHello { since_ms: u64 },
    AwaitHs1 { st: AwaitHs1<'r>, since_ms: u64 },
    Linked(Box<Executor>),
    Closed,
}

/// The connection.
pub struct Connection<'r> {
    relay: &'r Relay,
    phase: Phase<'r>,
    input: Vec<u8>,
}

/// The record length announced by the first two bytes of `input`.
fn announced(input: &[u8]) -> Option<usize> {
    input
        .first_chunk::<2>()
        .map(|b| usize::from(u16::from_be_bytes(*b)))
}

impl<'r> Connection<'r> {
    /// A connection the listener accepted at `now`; `None` while the relay drains (the listener refuses it,
    /// OPEN-M5-09).
    #[must_use]
    pub fn accept(relay: &'r Relay, now: Now) -> Option<Self> {
        relay.accepts_connections().then_some(Self {
            relay,
            phase: Phase::AwaitHello {
                since_ms: now.mono_ms,
            },
            input: Vec::new(),
        })
    }

    /// Whether the connection is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Closed)
    }

    /// The link's executor, once established.
    #[must_use]
    pub fn executor(&self) -> Option<&Executor> {
        match &self.phase {
            Phase::Linked(e) => Some(e),
            _ => None,
        }
    }

    fn close(&mut self, out: Vec<u8>) -> Output {
        self.phase = Phase::Closed;
        self.input = Vec::new();
        Output {
            bytes: out,
            close: true,
        }
    }

    fn timed_out(&self, now: Now) -> bool {
        let limit = self.relay.limits().hello_timeout_ms;
        match &self.phase {
            Phase::AwaitHello { since_ms } | Phase::AwaitHs1 { since_ms, .. } => {
                now.mono_ms.saturating_sub(*since_ms) >= limit
            }
            Phase::Linked(_) | Phase::Closed => false,
        }
    }

    /// The clock moved without input: close a connection whose handshake timed out.
    pub fn on_tick(&mut self, now: Now) -> Output {
        if self.is_closed() || self.timed_out(now) {
            return self.close(Vec::new());
        }
        Output::default()
    }

    /// `data` arrived at `now`.
    pub fn on_bytes(&mut self, data: &[u8], now: Now, entropy: &mut impl Entropy) -> Output {
        if self.is_closed() || self.timed_out(now) {
            return self.close(Vec::new());
        }
        self.input.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            match self.advance(now, entropy, &mut out) {
                Progress::More => {}
                Progress::Wait => {
                    return Output {
                        bytes: out,
                        close: false,
                    };
                }
                Progress::Close => return self.close(out),
            }
        }
    }

    fn advance(&mut self, now: Now, entropy: &mut impl Entropy, out: &mut Vec<u8>) -> Progress {
        let relay = self.relay;
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Closed => Progress::Close,
            Phase::AwaitHello { since_ms } => {
                let Some(len) = announced(&self.input) else {
                    self.phase = Phase::AwaitHello { since_ms };
                    return Progress::Wait;
                };
                if len != HELLO_BODY_LEN {
                    return Progress::Close;
                }
                if self.input.len() < HELLO_RECORD_LEN {
                    self.phase = Phase::AwaitHello { since_ms };
                    return Progress::Wait;
                }
                let record: Vec<u8> = self.input.drain(..HELLO_RECORD_LEN).collect();
                // §9.7 item 7: over the handshake rate ⇒ closed before RELAYINFO
                if !relay.take_hello(now) {
                    return Progress::Close;
                }
                let Ok((newest, valid_until)) = relay.keys().newest() else {
                    return Progress::Close;
                };
                if !relay.keys().usable(newest.kid(), now.unix_secs) {
                    return Progress::Close;
                }
                match accept_ring(relay.keys().ring()).on_hello(&record, valid_until) {
                    Ok((info, st)) => {
                        out.extend_from_slice(&info);
                        self.phase = Phase::AwaitHs1 {
                            st,
                            since_ms: now.mono_ms,
                        };
                        Progress::More
                    }
                    Err(_) => Progress::Close,
                }
            }
            Phase::AwaitHs1 { st, since_ms } => {
                let Some(len) = announced(&self.input) else {
                    self.phase = Phase::AwaitHs1 { st, since_ms };
                    return Progress::Wait;
                };
                if len != HS1_BODY_LEN {
                    return Progress::Close;
                }
                if self.input.len() < HS1_RECORD_LEN {
                    self.phase = Phase::AwaitHs1 { st, since_ms };
                    return Progress::Wait;
                }
                let record: Vec<u8> = self.input.drain(..HS1_RECORD_LEN).collect();
                // OPEN-M5-10: the named generation must still be valid now (the kid is cleartext)
                let usable =
                    Hs1::decode(&record).is_ok_and(|h| relay.keys().usable(h.kid, now.unix_secs));
                if !usable {
                    return Progress::Close;
                }
                match st.on_hs1(&record, entropy) {
                    Ok((hs2, link)) => {
                        out.extend_from_slice(&hs2);
                        self.phase = Phase::Linked(Box::new(Executor::new(
                            link,
                            relay.limits().link_rate,
                            now,
                        )));
                        Progress::More
                    }
                    Err(_) => Progress::Close,
                }
            }
            Phase::Linked(mut ex) => {
                if self.input.len() < FRAME_LEN {
                    self.phase = Phase::Linked(ex);
                    return Progress::Wait;
                }
                let unit: Vec<u8> = self.input.drain(..FRAME_LEN).collect();
                match ex.on_unit(relay, &unit, now, entropy) {
                    Outcome::Respond(frames) => {
                        for f in &frames {
                            out.extend_from_slice(f.as_slice());
                        }
                        self.phase = Phase::Linked(ex);
                        Progress::More
                    }
                    Outcome::Pending => {
                        self.phase = Phase::Linked(ex);
                        Progress::More
                    }
                    Outcome::Teardown => Progress::Close,
                }
            }
        }
    }
}

enum Progress {
    More,
    Wait,
    Close,
}
