// SPDX-License-Identifier: AGPL-3.0-or-later
//! The link state and the frame layer (spec §8.4): after `HS2` both sides exchange units of exactly 4352 B
//!
//! ```text
//! frame = XChaCha20-Poly1305.Seal(k_dir, 0^16 ‖ u64be(counter_dir), "SecMP-LINK/1 frame" ‖ sess_id, pad(payload, 4336))
//! ```
//!
//! with one strictly increasing counter per direction (the counter is the nonce; the receiver accepts exactly the
//! expected value, strict `+1`). A unit of any other length is rejected before the AEAD (the stream has no length
//! prefix, D.1). Padding is ISO/IEC 7816-4 (§4.1). Counters use `checked_add`; a counter at `u64::MAX` seals or opens
//! its frame and the next operation is [`Error::CounterOverflow`] (a local abort, reading REF-M5 9). The client
//! additionally refuses to seal once either counter has reached [`LINK_MAX_FRAMES`] ([`Error::NewLinkRequired`],
//! §4.2, ADR-048 OPEN-M5-03); the relay does not check.
//!
//! Receiving is split in two so that a unit that opens but is then rejected by a later check (the plaintext does not
//! decode, a `CONT` with nothing pending) leaves the counters unchanged (spec §8.5): [`Link::open_unit`] does not
//! mutate, [`Link::commit`] advances. [`Link::open_request`] and [`Link::open_response`] do open, decode and commit.

#[cfg(not(kani))]
use secmp_crypto::Aead;
use secmp_crypto::{Label, SecretBytes};

use crate::codec::{Decode, Zeroizing, pad, unpad};
use crate::link::handshake::LinkKeys;
use crate::link::{Error, LINK_MAX_FRAMES, Result};
use crate::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN};
use crate::wire::Id;
use crate::wire::frame::{CellrContext, Request, Response};
#[cfg(kani)]
use kani_stubs::Aead;

/// The largest payload a frame carries (the padding needs one marker byte).
pub const MAX_PAYLOAD_LEN: usize = FRAME_PLAINTEXT_LEN - 1;

/// One sealed frame, 4352 B.
pub type Frame = Box<[u8; FRAME_LEN]>;

/// A direction's frame counter: the next value to use, or `None` once `u64::MAX` has been used.
#[derive(Clone, Copy)]
struct Counter(Option<u64>);

impl Counter {
    const fn new(value: u64) -> Self {
        Self(Some(value))
    }

    /// The counter after using the current value (`checked_add`: `None` once `u64::MAX` has been used).
    fn successor(self) -> Self {
        Self(self.0.and_then(|c| c.checked_add(1)))
    }
}

/// A unit that opened under the expected counter and whose padding is valid; not yet committed ([`Link::commit`]).
pub struct Opened {
    counter: u64,
    plaintext: Zeroizing<Vec<u8>>,
    payload_len: usize,
}

impl Opened {
    /// The frame counter the unit opened under.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The payload `op ‖ cmd_seq ‖ fields` without the padding.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.plaintext.get(..self.payload_len).unwrap_or_default()
    }

    /// The 4336-byte padded plaintext, the input of the D.2 decoders.
    #[must_use]
    pub fn padded(&self) -> &[u8] {
        &self.plaintext
    }
}

/// One side of an established link (spec §8.3–§8.4): the two direction keys, `sess_id` and the two counters.
pub struct Link {
    k_send: SecretBytes<32>,
    k_recv: SecretBytes<32>,
    sess_id: Id,
    send: Counter,
    recv: Counter,
    /// `Some(LINK_MAX_FRAMES)` on the client.
    max_frames: Option<u64>,
    #[cfg(feature = "kat")]
    aead_opens: core::cell::Cell<u64>,
    #[cfg(feature = "kat")]
    trace: crate::link::HandshakeTrace,
}

impl Link {
    /// The client's end: sends under `k_c2r`, receives under `k_r2c`; refuses to seal beyond [`LINK_MAX_FRAMES`].
    pub(crate) fn client(keys: LinkKeys) -> Self {
        Self::new(keys.k_c2r, keys.k_r2c, keys.sess_id, Some(LINK_MAX_FRAMES))
    }

    /// The relay's end: sends under `k_r2c`, receives under `k_c2r`.
    pub(crate) fn relay(keys: LinkKeys) -> Self {
        Self::new(keys.k_r2c, keys.k_c2r, keys.sess_id, None)
    }

    fn new(
        k_send: SecretBytes<32>,
        k_recv: SecretBytes<32>,
        sess_id: Id,
        max: Option<u64>,
    ) -> Self {
        Self {
            k_send,
            k_recv,
            sess_id,
            send: Counter::new(0),
            recv: Counter::new(0),
            max_frames: max,
            #[cfg(feature = "kat")]
            aead_opens: core::cell::Cell::new(0),
            #[cfg(feature = "kat")]
            trace: crate::link::HandshakeTrace::default(),
        }
    }

    /// The link's `sess_id` (spec §8.3): bound into every command signature and access token.
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        &self.sess_id
    }

    fn ad(&self) -> Vec<u8> {
        [Label::LinkFrame.as_bytes(), &self.sess_id].concat()
    }

    /// Seal `payload` (at most [`MAX_PAYLOAD_LEN`] bytes) as the next frame of this direction.
    ///
    /// # Errors
    /// [`Error::PayloadTooLong`]; [`Error::NewLinkRequired`] on the client once a counter has reached
    /// [`LINK_MAX_FRAMES`]; [`Error::CounterOverflow`] once the counter is exhausted; [`Error::Unavailable`] if the
    /// AEAD refuses (not reachable for 4336 bytes). Nothing is sealed and no counter moves on an error.
    pub fn seal(&mut self, payload: &[u8]) -> Result<Frame> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLong);
        }
        if let Some(max) = self.max_frames {
            let reached = |c: Counter| c.0.is_some_and(|v| v >= max);
            if reached(self.send) || reached(self.recv) {
                return Err(Error::NewLinkRequired);
            }
        }
        let counter = self.send.0.ok_or(Error::CounterOverflow)?;
        let plaintext = pad(payload, FRAME_PLAINTEXT_LEN)?;
        let nonce = secmp_crypto::Nonce24::from_link_counter(counter);
        let sealed = Aead::seal(&self.k_send, nonce, &self.ad(), &plaintext)?;
        let frame: Frame = sealed
            .into_boxed_slice()
            .try_into()
            .map_err(|_| Error::Unavailable)?;
        self.send = self.send.successor();
        Ok(frame)
    }

    /// Open `unit` under the expected counter and check its padding; does not change the link.
    ///
    /// # Errors
    /// [`Error::Rejected`] for a unit of another length than 4352 B (before the AEAD), a failed AEAD open (a wrong
    /// counter, key, direction or link included) or invalid padding; [`Error::CounterOverflow`] once the receive
    /// counter is exhausted.
    pub fn open_unit(&self, unit: &[u8]) -> Result<Opened> {
        if unit.len() != FRAME_LEN {
            return Err(Error::Rejected);
        }
        let counter = self.recv.0.ok_or(Error::CounterOverflow)?;
        #[cfg(feature = "kat")]
        self.aead_opens.set(self.aead_opens.get().saturating_add(1));
        let nonce = *secmp_crypto::Nonce24::from_link_counter(counter).as_bytes();
        let plaintext = Aead::open(&self.k_recv, &nonce, &self.ad(), unit)?;
        let payload_len = unpad(&plaintext, FRAME_PLAINTEXT_LEN)?.len();
        Ok(Opened {
            counter,
            plaintext,
            payload_len,
        })
    }

    /// Accept an [`Opened`] unit: advance the receive counter (strict `+1`, `checked_add`).
    ///
    /// # Errors
    /// [`Error::Rejected`] if `opened` is not the unit at the current receive counter (already committed, or opened
    /// before another commit); [`Error::CounterOverflow`] if the counter is exhausted.
    pub fn commit(&mut self, opened: &Opened) -> Result<()> {
        let expected = self.recv.0.ok_or(Error::CounterOverflow)?;
        if opened.counter != expected {
            return Err(Error::Rejected);
        }
        self.recv = self.recv.successor();
        Ok(())
    }

    /// [`Link::open_unit`] then [`Link::commit`].
    ///
    /// # Errors
    /// As [`Link::open_unit`].
    pub fn open(&mut self, unit: &[u8]) -> Result<Opened> {
        let opened = self.open_unit(unit)?;
        self.commit(&opened)?;
        Ok(opened)
    }

    /// Open `unit` and decode it as a D.2 request; the counter advances only if all of it succeeds.
    ///
    /// # Errors
    /// As [`Link::open_unit`]; [`Error::Rejected`] if the plaintext is not a request (unknown opcode, `SKEY`, a
    /// response opcode, a field rule of §4.1).
    pub fn open_request(&mut self, unit: &[u8]) -> Result<Request> {
        let opened = self.open_unit(unit)?;
        let request = Request::decode(opened.padded())?;
        self.commit(&opened)?;
        Ok(request)
    }

    /// Open `unit` and decode it as a D.2 response to the request `context` describes; the counter advances only if
    /// all of it succeeds.
    ///
    /// # Errors
    /// As [`Link::open_unit`]; [`Error::Rejected`] if the plaintext is not a response.
    pub fn open_response(&mut self, unit: &[u8], context: CellrContext) -> Result<Response> {
        let opened = self.open_unit(unit)?;
        let response = Response::decode(opened.padded(), context)?;
        self.commit(&opened)?;
        Ok(response)
    }

    /// The next frame counter this side seals under; `None` once exhausted.
    #[must_use]
    pub const fn send_counter(&self) -> Option<u64> {
        self.send.0
    }

    /// The next frame counter this side expects; `None` once exhausted.
    #[must_use]
    pub const fn recv_counter(&self) -> Option<u64> {
        self.recv.0
    }
}

#[cfg(feature = "kat")]
impl Link {
    /// Set the send counter (vectors and tests only).
    pub fn set_send_counter_kat(&mut self, value: u64) {
        self.send = Counter::new(value);
    }

    /// Set the receive counter (vectors and tests only).
    pub fn set_recv_counter_kat(&mut self, value: u64) {
        self.recv = Counter::new(value);
    }

    /// How many AEAD opens this side attempted (a unit of the wrong length is rejected before the AEAD).
    #[must_use]
    pub fn aead_open_attempts_kat(&self) -> u64 {
        self.aead_opens.get()
    }

    /// The values of the handshake that produced this link.
    #[must_use]
    pub const fn trace_kat(&self) -> &crate::link::HandshakeTrace {
        &self.trace
    }

    pub(crate) fn with_trace(mut self, trace: crate::link::HandshakeTrace) -> Self {
        self.trace = trace;
        self
    }

    /// `k_send` and `k_recv` (vectors and tests only).
    #[must_use]
    pub fn keys_kat(&self) -> (&[u8; 32], &[u8; 32]) {
        (self.k_send.expose_secret(), self.k_recv.expose_secret())
    }
}

/// Kani only (`crate::kani_proofs`, `kani_link_counter_*`): a stand-in for `secmp_crypto::Aead` whose seal records the
/// nonce's counter in the first 8 tag bytes and whose open succeeds iff the nonce's counter equals that record, and
/// a constructor of a [`Link`] with chosen counters. `Zeroizing` is `codec::Zeroizing` (the Kani stand-in; the same
/// type as `secmp_crypto::Zeroizing` outside Kani), because `zeroize` contains inline assembly Kani cannot execute.
#[cfg(kani)]
pub(crate) mod kani_stubs {
    use secmp_crypto::{Nonce24, SecretBytes};

    use super::{AEAD_TAG_LEN, Counter, Id, Link, Zeroizing};

    pub(crate) struct Aead;

    /// The 8-byte frame counter of a link nonce `0^16 || u64be(counter)`.
    fn nonce_counter(nonce: &[u8; 24]) -> Option<u64> {
        nonce.last_chunk::<8>().copied().map(u64::from_be_bytes)
    }

    impl Aead {
        pub(crate) fn seal(
            _k: &SecretBytes<32>,
            nonce: Nonce24,
            _ad: &[u8],
            p: &[u8],
        ) -> Result<Vec<u8>, secmp_crypto::Error> {
            let mut out = p.to_vec();
            let mut tag = [0_u8; AEAD_TAG_LEN];
            if let (Some(c), Some(t)) =
                (nonce_counter(nonce.as_bytes()), tag.first_chunk_mut::<8>())
            {
                *t = c.to_be_bytes();
            }
            out.extend_from_slice(&tag);
            Ok(out)
        }

        pub(crate) fn open(
            _k: &SecretBytes<32>,
            nonce: &[u8; 24],
            _ad: &[u8],
            c: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, secmp_crypto::Error> {
            let tag_at = c
                .len()
                .checked_sub(AEAD_TAG_LEN)
                .ok_or(secmp_crypto::Error::Rejected)?;
            let (ct, tag) = c
                .split_at_checked(tag_at)
                .ok_or(secmp_crypto::Error::Rejected)?;
            let recorded = tag.first_chunk::<8>().copied().map(u64::from_be_bytes);
            if recorded.is_some() && recorded == nonce_counter(nonce) {
                Ok(Zeroizing::new(ct.to_vec()))
            } else {
                Err(secmp_crypto::Error::Rejected)
            }
        }
    }

    /// The counter a sealed frame was sealed under (the stand-in's record in the tag).
    pub(crate) fn sealed_counter(frame: &[u8]) -> Option<u64> {
        let tag_at = frame.len().checked_sub(AEAD_TAG_LEN)?;
        let tag = frame.get(tag_at..)?;
        Some(u64::from_be_bytes(*tag.first_chunk::<8>()?))
    }

    impl Link {
        /// A link with all-zero keys, the given counters and `max_frames`.
        pub(crate) fn kani_new(
            send: Option<u64>,
            recv: Option<u64>,
            max_frames: Option<u64>,
        ) -> Option<Self> {
            let key = SecretBytes::<32>::from_slice(&[0; 32]).ok()?;
            let key2 = SecretBytes::<32>::from_slice(&[0; 32]).ok()?;
            let sess_id: Id = [0; 16];
            let mut link = Self::new(key, key2, sess_id, max_frames);
            link.send = Counter(send);
            link.recv = Counter(recv);
            Some(link)
        }
    }
}
