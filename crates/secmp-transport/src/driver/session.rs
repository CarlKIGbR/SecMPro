// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`AsyncSession`]: the SecMP-LINK client over an asynchronous byte stream (spec §8, D.1, D.2) — the asynchronous twin
//! of [`crate::Session`]. Both run the same sans-IO handshake (`secmp_proto::link::client`) and the same [`Channel`];
//! only the reads and writes differ, so the bytes on the wire are the same (TEST-SPEC-M6 AD-07).
//!
//! **Fail closed (spec §8.5, OPEN-M5-11 A).** As the synchronous session: a frame that does not open or does not fit is
//! [`Error::Rejected`] and closes the session; the end of the stream is [`Error::Closed`].

use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link;
use secmp_proto::link::client;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN, HASH_LEN, HS2_LEN, RELAYINFO_LEN};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::frame::{CellrContext, Request, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::channel::{Channel, Command, Completed, Prepared};
use crate::error::{Error, Result};

/// An established link and the asynchronous stream under it.
pub struct AsyncSession<S> {
    stream: S,
    chan: Channel,
}

/// How an asynchronous connection attempt ended (as [`crate::ConnectOutcome`]).
pub enum AsyncConnectOutcome<S> {
    /// `HS2` accepted.
    Up(Box<AsyncSession<S>>),
    /// The stream ended before the `RELAYINFO` record arrived (spec §9.7 item 7: a full handshake bucket).
    ClosedBeforeRelayInfo,
    /// Any other failure: [`Error::Rejected`] for a failed check (no detail, §8.5), [`Error::Closed`] for a stream that
    /// ended later.
    Failed(Error),
}

/// Read exactly `buf.len()` bytes; the end of the stream (or any stream error) is [`Error::Closed`].
async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<()> {
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|_| Error::Closed)
}

async fn write_all<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    stream.write_all(bytes).await.map_err(|_| Error::Closed)?;
    stream.flush().await.map_err(|_| Error::Closed)
}

/// One handshake record `len: u16 ‖ body` whose body must be `expected` bytes (D.1); the record with its length.
async fn read_record<S: AsyncRead + Unpin>(stream: &mut S, expected: usize) -> Result<Vec<u8>> {
    let mut len = [0_u8; 2];
    read_exact(stream, &mut len).await?;
    if usize::from(u16::from_be_bytes(len)) != expected {
        return Err(Error::Rejected);
    }
    let mut record = vec![0_u8; expected.checked_add(2).ok_or(Error::Rejected)?];
    record
        .get_mut(..2)
        .ok_or(Error::Rejected)?
        .copy_from_slice(&len);
    read_exact(stream, record.get_mut(2..).ok_or(Error::Rejected)?).await?;
    Ok(record)
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncSession<S> {
    /// `HELLO`, `RELAYINFO`, `HS1`, `HS2` (spec §8.2–§8.3) on `stream`, as [`crate::Session::connect`].
    ///
    /// # Errors
    /// [`Error::Rejected`] if a check of the handshake fails (no detail, §8.5); [`Error::Closed`] if the stream ends;
    /// [`Error::Unavailable`] without randomness.
    pub async fn connect<E: Entropy + Send>(
        stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut E,
    ) -> Result<Self> {
        match Self::connect_outcome(stream, pinned_fp, access_key, now_unix, entropy).await {
            AsyncConnectOutcome::Up(session) => Ok(*session),
            AsyncConnectOutcome::ClosedBeforeRelayInfo => Err(Error::Closed),
            AsyncConnectOutcome::Failed(e) => Err(e),
        }
    }

    /// As [`AsyncSession::connect`], telling the end of the stream before `RELAYINFO` apart.
    pub async fn connect_outcome<E: Entropy + Send>(
        mut stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut E,
    ) -> AsyncConnectOutcome<S> {
        let (hello, awaiting_info) = match client::start(pinned_fp, access_key, now_unix) {
            Ok(started) => started,
            Err(e) => return AsyncConnectOutcome::Failed(e.into()),
        };
        if let Err(e) = write_all(&mut stream, &hello).await {
            return AsyncConnectOutcome::Failed(e);
        }
        let info = match read_record(&mut stream, 1 + RELAYINFO_LEN).await {
            Ok(info) => info,
            Err(Error::Closed) => return AsyncConnectOutcome::ClosedBeforeRelayInfo,
            Err(e) => return AsyncConnectOutcome::Failed(e),
        };
        let (hs1, awaiting_hs2) = match awaiting_info.on_relayinfo(&info, entropy) {
            Ok(next) => next,
            Err(e) => return AsyncConnectOutcome::Failed(e.into()),
        };
        if let Err(e) = write_all(&mut stream, &hs1).await {
            return AsyncConnectOutcome::Failed(e);
        }
        let hs2 = match read_record(&mut stream, 1 + HS2_LEN).await {
            Ok(hs2) => hs2,
            Err(e) => return AsyncConnectOutcome::Failed(e),
        };
        match awaiting_hs2.on_hs2(&hs2) {
            Ok(link) => AsyncConnectOutcome::Up(Box::new(Self {
                stream,
                chan: Channel::new(link),
            })),
            Err(e) => AsyncConnectOutcome::Failed(e.into()),
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

    /// Write a prepared request: the bytes only. Frames must be written in the order they were prepared.
    ///
    /// # Errors
    /// [`Error::OutOfOrder`] (nothing written); [`Error::Closed`] if the stream fails.
    pub async fn write_prepared(&mut self, prepared: &Prepared) -> Result<()> {
        self.chan.begin_write(prepared)?;
        if let Err(e) = write_all(&mut self.stream, prepared.bytes()).await {
            self.chan.close();
            return Err(e);
        }
        Ok(())
    }

    /// Read frames until the oldest outstanding request has its complete response (pipelined: several requests may
    /// be outstanding; their responses are matched in request order).
    ///
    /// # Errors
    /// [`Error::Closed`] if the stream ends; [`Error::Rejected`] for a frame that does not fit.
    pub async fn read_response(&mut self) -> Result<Completed> {
        loop {
            self.chan.ensure_open()?;
            let mut unit = [0_u8; FRAME_LEN];
            if let Err(e) = read_exact(&mut self.stream, &mut unit).await {
                self.chan.close();
                return Err(e);
            }
            if let Some(done) = self.chan.accept(&unit)? {
                return Ok(done);
            }
        }
    }

    /// The link's `sess_id`.
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        self.chan.sess_id()
    }

    /// The link state (tests only, feature `harness`).
    #[cfg(feature = "harness")]
    #[must_use]
    pub const fn link_kat(&self) -> &link::Link {
        self.chan.link_kat()
    }

    /// Whether the link is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.chan.is_closed()
    }

    /// The stream under the link.
    #[must_use]
    pub const fn stream(&self) -> &S {
        &self.stream
    }

    pub(crate) fn next_cmd_seq(&mut self) -> Result<u32> {
        self.chan.next_cmd_seq()
    }

    /// A LINK-level failure: the link is closed (spec §8.5).
    pub(crate) const fn reject(&mut self) -> Error {
        self.chan.reject()
    }

    /// Seal the frames of one command and write them in order (spec §8.4), as [`crate::Session`] does.
    ///
    /// # Errors
    /// [`Error::NewLinkRequired`] before anything is written if the link has used its frames; [`Error::Closed`] if
    /// the stream fails.
    pub(crate) async fn send(&mut self, requests: &[Request]) -> Result<()> {
        self.chan.ensure_open()?;
        let mut wire = Vec::with_capacity(requests.len().saturating_mul(FRAME_LEN));
        for request in requests {
            let padded = request.encode()?;
            let payload = unpad(&padded, FRAME_PLAINTEXT_LEN)?;
            match self.chan.link_mut().seal(payload) {
                Ok(frame) => wire.extend_from_slice(frame.as_slice()),
                Err(e @ link::Error::NewLinkRequired) => {
                    if !wire.is_empty() {
                        // frames of this command are already sealed: the counters moved, the link is unusable
                        self.chan.close();
                    }
                    return Err(e.into());
                }
                Err(e) => {
                    self.chan.close();
                    return Err(e.into());
                }
            }
        }
        if let Err(e) = write_all(&mut self.stream, &wire).await {
            self.chan.close();
            return Err(e);
        }
        self.chan.synced();
        Ok(())
    }

    /// Read one frame, open it and decode it as a response to `cmd_seq` (D.2).
    ///
    /// # Errors
    /// [`Error::Closed`] if the stream ends; [`Error::Rejected`] if the frame does not open, decode, or echo `cmd_seq`.
    pub(crate) async fn receive(
        &mut self,
        cmd_seq: u32,
        context: CellrContext,
    ) -> Result<Response> {
        self.chan.ensure_open()?;
        let mut unit = [0_u8; FRAME_LEN];
        if let Err(e) = read_exact(&mut self.stream, &mut unit).await {
            self.chan.close();
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
