// SPDX-License-Identifier: AGPL-3.0-or-later
//! The SecMP-LINK client over a byte stream (spec §8, D.1, D.2): the handshake, the frame I/O and the command
//! sequence.
//!
//! The stream is anything that reads and writes bytes ([`Read`] + [`Write`]): a TCP socket, a Tor stream (M6), or an
//! in-process pair in the tests (M5). Before `HS2` it carries records `len: u16 ‖ body` (D.1); after `HS2` only
//! 4352-byte frames. A read that returns 0 bytes is the end of the stream: the link is closed.
//!
//! **Fail closed (spec §8.5, OPEN-M5-11 A).** A frame that does not open or decode, or an authenticated response
//! that does not fit its request, is [`Error::Rejected`]; the session closes and every later call is
//! [`Error::Closed`]. `cmd_seq` starts at 1 and increases by 1 per command (§9.2); the frames of a multi-frame
//! command repeat it.

use std::io::{ErrorKind, Read, Write};

use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link::client::{self};
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::{self, Link};
use secmp_proto::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN, HASH_LEN, HS2_LEN, RELAYINFO_LEN};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{CellrContext, Request, Response};

use crate::channel::{Channel, Command, Completed, Prepared};
use crate::error::{Error, Result};

/// An established link and the stream under it.
pub struct Session<S> {
    stream: S,
    chan: Channel,
}

/// How a connection attempt ended (M05 review F-1, M6 part): the scheduler's back-off (LR-03) must tell a relay that
/// closes before `RELAYINFO` (a full handshake bucket, spec §9.7 item 7) from every other failure.
pub enum ConnectOutcome<S> {
    /// `HS2` accepted.
    Up(Box<Session<S>>),
    /// The stream ended before the `RELAYINFO` record arrived.
    ClosedBeforeRelayInfo,
    /// Any other failure; [`Error::Rejected`] for a check that failed (spec §8.5: no detail), [`Error::Closed`] for a
    /// stream that ended later.
    Failed(Error),
}

/// Read exactly `buf.len()` bytes; the end of the stream is [`Error::Closed`].
fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    let mut at = 0_usize;
    while at < buf.len() {
        let Some(rest) = buf.get_mut(at..) else {
            return Err(Error::Closed);
        };
        match stream.read(rest) {
            Ok(0) => return Err(Error::Closed),
            Ok(n) => at = at.checked_add(n).ok_or(Error::Closed)?,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Closed),
        }
    }
    Ok(())
}

fn write_all(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    stream.write_all(bytes).map_err(|_| Error::Closed)?;
    stream.flush().map_err(|_| Error::Closed)
}

/// One handshake record `len: u16 ‖ body`, whose body must be `expected` bytes (D.1); the record with its length.
fn read_record(stream: &mut impl Read, expected: usize) -> Result<Vec<u8>> {
    let mut len = [0_u8; 2];
    read_exact(stream, &mut len)?;
    if usize::from(u16::from_be_bytes(len)) != expected {
        return Err(Error::Rejected);
    }
    let mut record = vec![0_u8; expected.checked_add(2).ok_or(Error::Rejected)?];
    record
        .get_mut(..2)
        .ok_or(Error::Rejected)?
        .copy_from_slice(&len);
    read_exact(stream, record.get_mut(2..).ok_or(Error::Rejected)?)?;
    Ok(record)
}

impl<S: Read + Write> Session<S> {
    /// `HELLO`, `RELAYINFO`, `HS1`, `HS2` (spec §8.2–§8.3) on `stream`. `pinned_fp` is the relay's `relay_fp` from its
    /// `RelayRef`; `access_key` is the key the client holds, if any (the `akc` of `RELAYINFO` is checked only then);
    /// `now_unix` is the client's clock. The `RELAYINFO` is used for this link only (§8.2).
    ///
    /// # Errors
    /// [`Error::Rejected`] if any check of the handshake fails (no detail, §8.5); [`Error::Closed`] if the stream
    /// ends; [`Error::Unavailable`] without randomness.
    pub fn connect(
        stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Self> {
        match Self::connect_outcome(stream, pinned_fp, access_key, now_unix, entropy) {
            ConnectOutcome::Up(session) => Ok(*session),
            ConnectOutcome::ClosedBeforeRelayInfo => Err(Error::Closed),
            ConnectOutcome::Failed(e) => Err(e),
        }
    }

    /// As [`Session::connect`], telling the end of the stream before `RELAYINFO` apart.
    pub fn connect_outcome(
        mut stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut impl Entropy,
    ) -> ConnectOutcome<S> {
        let started = match client::start(pinned_fp, access_key, now_unix) {
            Ok(started) => started,
            Err(e) => return ConnectOutcome::Failed(e.into()),
        };
        let (hello, awaiting_info) = started;
        if let Err(e) = write_all(&mut stream, &hello) {
            return ConnectOutcome::Failed(e);
        }
        let info = match read_record(&mut stream, 1 + RELAYINFO_LEN) {
            Ok(info) => info,
            Err(Error::Closed) => return ConnectOutcome::ClosedBeforeRelayInfo,
            Err(e) => return ConnectOutcome::Failed(e),
        };
        let rest = (|| {
            let (hs1, awaiting_hs2) = awaiting_info.on_relayinfo(&info, entropy)?;
            write_all(&mut stream, &hs1)?;
            let hs2 = read_record(&mut stream, 1 + HS2_LEN)?;
            Ok::<_, Error>(awaiting_hs2.on_hs2(&hs2)?)
        })();
        match rest {
            Ok(link) => ConnectOutcome::Up(Box::new(Self {
                stream,
                chan: Channel::new(link),
            })),
            Err(e) => ConnectOutcome::Failed(e),
        }
    }

    /// Split into the stream and the sans-IO [`Channel`] (the scheduler owns the channel, its driver the stream).
    #[must_use]
    pub fn into_parts(self) -> (S, Channel) {
        (self.stream, self.chan)
    }

    /// Join a stream and a channel again.
    #[must_use]
    pub const fn from_parts(stream: S, chan: Channel) -> Self {
        Self { stream, chan }
    }

    /// The sans-IO channel of this session.
    #[must_use]
    pub const fn channel(&self) -> &Channel {
        &self.chan
    }

    /// The channel, mutable.
    pub const fn channel_mut(&mut self) -> &mut Channel {
        &mut self.chan
    }

    /// Prepare (build, sign, seal) the request of `command` without writing it (spec §10.1).
    ///
    /// # Errors
    /// As [`Channel::prepare`].
    pub fn prepare(&mut self, command: &Command<'_>) -> Result<Prepared> {
        self.chan.prepare(command)
    }

    /// Write a prepared request: no crypto, no persistence — the bytes only. Frames must be written in the order
    /// they were prepared.
    ///
    /// # Errors
    /// [`Error::OutOfOrder`] (nothing written); [`Error::Closed`] if the stream fails.
    pub fn write_prepared(&mut self, prepared: &Prepared) -> Result<()> {
        self.chan.begin_write(prepared)?;
        if let Err(e) = write_all(&mut self.stream, prepared.bytes()) {
            self.chan.close();
            return Err(e);
        }
        Ok(())
    }

    /// Read frames until the oldest outstanding request has its complete response.
    ///
    /// # Errors
    /// [`Error::Closed`] if the stream ends; [`Error::Rejected`] for a frame that does not fit.
    pub fn read_response(&mut self) -> Result<Completed> {
        loop {
            self.chan.ensure_open()?;
            let mut unit = [0_u8; FRAME_LEN];
            if let Err(e) = read_exact(&mut self.stream, &mut unit) {
                self.chan.close();
                return Err(e);
            }
            if let Some(done) = self.chan.accept(&unit)? {
                return Ok(done);
            }
        }
    }

    /// The link's `sess_id` (bound into every signature and token, spec §8.3).
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        self.chan.sess_id()
    }

    /// The link state: its keys, counters and handshake trace (tests only, feature `harness`).
    #[cfg(feature = "harness")]
    #[must_use]
    pub const fn link_kat(&self) -> &Link {
        self.chan.link_kat()
    }

    /// Whether the link is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.chan.is_closed()
    }

    /// The stream under the link (the tests read the byte capture from it).
    #[must_use]
    pub const fn stream(&self) -> &S {
        &self.stream
    }

    /// The `cmd_seq` of the next command: 1, 2, 3, … (spec §9.2).
    ///
    /// # Errors
    /// [`Error::Closed`] on a closed link; [`Error::NewLinkRequired`] when the `u32` space is used up.
    pub(crate) fn next_cmd_seq(&mut self) -> Result<u32> {
        self.chan.next_cmd_seq()
    }

    pub(crate) const fn ensure_open(&self) -> Result<()> {
        self.chan.ensure_open()
    }

    fn close(&mut self) {
        self.chan.close();
    }

    /// A LINK-level failure: the link is closed (spec §8.5).
    pub(crate) const fn reject(&mut self) -> Error {
        self.chan.reject()
    }

    /// Seal the frames of one command and write them in order (spec §8.4).
    ///
    /// # Errors
    /// [`Error::NewLinkRequired`] before anything is written if the link has used its frames; [`Error::Closed`] if
    /// the stream fails.
    pub(crate) fn send(&mut self, requests: &[Request]) -> Result<()> {
        self.ensure_open()?;
        let mut wire = Vec::with_capacity(requests.len().saturating_mul(FRAME_LEN));
        for request in requests {
            let padded = request.encode()?;
            let payload = unpad(&padded, FRAME_PLAINTEXT_LEN)?;
            match self.chan.link_mut().seal(payload) {
                Ok(frame) => wire.extend_from_slice(frame.as_slice()),
                Err(e @ link::Error::NewLinkRequired) => {
                    if wire.is_empty() {
                        return Err(e.into());
                    }
                    // frames of this command are already sealed: the counters moved, the link is unusable
                    self.close();
                    return Err(e.into());
                }
                Err(e) => {
                    self.close();
                    return Err(e.into());
                }
            }
        }
        if let Err(e) = write_all(&mut self.stream, &wire) {
            self.close();
            return Err(e);
        }
        self.chan.synced();
        Ok(())
    }

    /// Read one frame, open it and decode it as the response to the command `cmd_seq`; its `cmd_seq` must echo the
    /// request's (D.2).
    ///
    /// # Errors
    /// [`Error::Closed`] if the stream ends; [`Error::Rejected`] if the frame does not open, does not decode, or
    /// echoes another `cmd_seq`.
    pub(crate) fn receive(&mut self, cmd_seq: u32, context: CellrContext) -> Result<Response> {
        self.ensure_open()?;
        let mut unit = [0_u8; FRAME_LEN];
        if let Err(e) = read_exact(&mut self.stream, &mut unit) {
            self.close();
            return Err(e);
        }
        let Ok(response) = self.chan.link_mut().open_response(&unit, context) else {
            return Err(self.reject());
        };
        if response.cmd_seq != cmd_seq {
            return Err(self.reject());
        }
        Ok(response)
    }
}
