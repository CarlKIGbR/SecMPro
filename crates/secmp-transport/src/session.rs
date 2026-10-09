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

use crate::error::{Error, Result};

/// An established link and the stream under it.
pub struct Session<S> {
    stream: S,
    link: Link,
    last_cmd_seq: u32,
    closed: bool,
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
        mut stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Self> {
        let (hello, awaiting_info) = client::start(pinned_fp, access_key, now_unix)?;
        write_all(&mut stream, &hello)?;
        let info = read_record(&mut stream, 1 + RELAYINFO_LEN)?;
        let (hs1, awaiting_hs2) = awaiting_info.on_relayinfo(&info, entropy)?;
        write_all(&mut stream, &hs1)?;
        let hs2 = read_record(&mut stream, 1 + HS2_LEN)?;
        let link = awaiting_hs2.on_hs2(&hs2)?;
        Ok(Self {
            stream,
            link,
            last_cmd_seq: 0,
            closed: false,
        })
    }

    /// The link's `sess_id` (bound into every signature and token, spec §8.3).
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        self.link.sess_id()
    }

    /// The link state: its keys, counters and handshake trace (tests only, feature `kat`).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn link_kat(&self) -> &Link {
        &self.link
    }

    /// Whether the link is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
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
        self.ensure_open()?;
        let next = self
            .last_cmd_seq
            .checked_add(1)
            .ok_or(Error::NewLinkRequired)?;
        self.last_cmd_seq = next;
        Ok(next)
    }

    pub(crate) const fn ensure_open(&self) -> Result<()> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    fn close(&mut self) {
        self.closed = true;
    }

    /// A LINK-level failure: the link is closed (spec §8.5).
    pub(crate) fn reject(&mut self) -> Error {
        self.close();
        Error::Rejected
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
            match self.link.seal(payload) {
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
        let Ok(response) = self.link.open_response(&unit, context) else {
            return Err(self.reject());
        };
        if response.cmd_seq != cmd_seq {
            return Err(self.reject());
        }
        Ok(response)
    }
}
