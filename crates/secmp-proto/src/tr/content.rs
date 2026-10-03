// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content handling after decryption (spec §7.6, §7.7; M3 plan D6, D7).
//!
//! - [`dummy`]: the Dummy Content of the constant-rate stream (`seq` 0, `ts` 0, empty body), encrypted through the
//!   same `RatchetState::encrypt` as every message (CLAUDE.md §1.4); dummies take no `seq`, so a lost dummy never
//!   shows as a gap.
//! - [`Inbox::receive`]: decodes a decrypted Content (outside the decrypt transaction: a MAC-valid cell whose Content
//!   does not decode has consumed its message key and is [`Delivery::Malformed`], plan D6) and returns what it
//!   delivers. Fragments are reassembled; a reassembled message is processed as a Content of its `inner_type`.
//! - `KeyChange` (§7.7): verified with the *old* `IK_sig` over `fingerprint(new IKSPublic)` under
//!   `"SecMP-TR/1 keychange"`. Valid: the contact becomes unverified and real outgoing messages are blocked until it
//!   is re-verified ([`Trust::KeyChanged`]). Unverifiable — a wrong signature, or a reassembled `0x05` payload that does
//!   not decode as `IKSPublic ‖ HybridSig` (M3 review C3) — the session is frozen with a warning ([`Trust::Frozen`]).
//!   There is no accept path. Dummies continue in every [`Trust`] state (the traffic pattern never depends on it).
//!
//! **Reassembly rules** (§7.6 leaves them to reassembly; readings raised as SQ-25): the fragments of one `msg_id`
//! agree on `total`; an identical duplicate of a stored `idx` is ignored; a conflicting duplicate or a `total`
//! mismatch discards the partial message; a message is complete when every `idx < total` is present, and is the
//! concatenation of its chunks in `idx` order, decoded as `FragmentPayload`; the chunk shape is canonical
//! (spec §7.6 rev 2.4, ADR-043 (f); M3 review F16): every chunk but the last is exactly 1669 bytes and the last is
//! 1…1669 bytes, i.e. `total = ⌈len/1669⌉`, checked when the group completes — any other shape discards the message;
//! at most [`MAX_PARTIALS`] messages are in reassembly, the oldest is evicted first. Every chunk and every reassembled
//! buffer is zeroizing. The partial messages are persisted with the ratchet state ([`Inbox::to_bytes`]): a stored
//! fragment is "processing committed" before its cell is acknowledged (§7.5).

use std::collections::VecDeque;

use secmp_crypto::{ConstantTimeEq, Fingerprint, HybridSignature, HybridVerifyingKey, Label};

// the encodings' zeroizing buffer (`secmp_crypto::Zeroizing`; a stand-in under Kani, see `codec`)
use crate::codec::{Decode, Encode, Reader, Writer, Zeroizing};
use crate::error::{Error, Result};
use crate::sizes::{
    CONTENT_BODY_MAX, FRAGMENT_HEADER_LEN, FRAGMENT_TOTAL_MAX, FRAGMENT_TOTAL_MIN, ID_LEN,
};
use crate::tr::ratchet::Plaintext;
use crate::wire::Id;
use crate::wire::cell::{
    AppMessage, Content, ContentBody, ControlBody, Fragment, FragmentPayload, HandshakeBody,
    KeyChangeBody, ReceiptBody, RouteDescriptor, content_type,
};
use crate::wire::inv::IksPublic;

/// Largest number of messages in reassembly at once (plan D7; memory ≤ 8 × 64 × 1669 B).
pub const MAX_PARTIALS: usize = 8;

/// Largest chunk of one fragment: the Content body limit minus the fragment header (1689 − 20).
const CHUNK_MAX: usize = 1669;
const _: () = assert!(CHUNK_MAX == CONTENT_BODY_MAX - FRAGMENT_HEADER_LEN);

/// The format byte of `InboxV1`.
const INBOX_FORMAT_V1: u8 = 0x01;

/// The Dummy Content (spec §7.6: empty body, discarded after decryption).
#[must_use]
pub fn dummy() -> Content {
    Content {
        seq: 0,
        ts: 0,
        body: ContentBody::Dummy,
    }
}

/// The number of chunks of a Content of `len` bytes: `⌈len/1669⌉`, 1 for `len ≤ 1669` (spec §7.6 rev 2.4). A total
/// of 1 is the unfragmented Content; a Fragment itself carries `total ≥ 2` (§4.1).
#[must_use]
pub fn chunk_total(len: usize) -> usize {
    len.div_ceil(CHUNK_MAX).max(1)
}

/// The canonical chunks of `bytes` (spec §7.6 rev 2.4): maximal chunks of 1669 bytes, the remainder last; one empty
/// chunk for empty `bytes`.
#[must_use]
pub fn split_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return vec![bytes];
    }
    bytes.chunks(CHUNK_MAX).collect()
}

/// Whether the chunks of a complete message have the canonical shape: all but the last exactly 1669 bytes, the last
/// 1…1669 bytes (spec §7.6 rev 2.4).
fn canonical_shape(chunks: &[Option<Zeroizing<Vec<u8>>>]) -> bool {
    let Some((last, init)) = chunks.split_last() else {
        return false;
    };
    init.iter()
        .all(|c| c.as_ref().is_some_and(|c| c.len() == CHUNK_MAX))
        && last
            .as_ref()
            .is_some_and(|c| (1..=CHUNK_MAX).contains(&c.len()))
}

/// What the peer's identity allows (spec §6.6, §6.7, §7.7). Kept by the caller with the contact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trust {
    /// A new contact (§6.6 step 4), until the safety number is confirmed.
    Unverified,
    /// Confirmed by the user (§6.7).
    Verified,
    /// A verified key change (§7.7): unverified, real messages blocked until re-verification.
    KeyChanged,
    /// An unverifiable key change (§7.7): the session is frozen with a warning; only a new invitation helps (§7.8).
    Frozen,
}

impl Trust {
    /// Whether real messages may be sent (dummies are sent in every state).
    #[must_use]
    pub const fn may_send_real(self) -> bool {
        matches!(self, Self::Unverified | Self::Verified)
    }

    /// The user confirmed the safety number (§6.7); a frozen session stays frozen.
    pub fn verify(&mut self) {
        if *self != Self::Frozen {
            *self = Self::Verified;
        }
    }
}

/// What a decrypted Content delivers.
pub enum Delivery {
    /// A Dummy: discarded silently.
    Dummy,
    /// The Handshake content (the first message only; checked by SecMP-HX, M4).
    Handshake(HandshakeBody),
    /// The messages of a Batch (direct or reassembled).
    Messages(Vec<AppMessage>),
    /// The routes of a `RouteUpdate` (direct or reassembled).
    Routes(Vec<RouteDescriptor>),
    /// A Receipt (direct or reassembled).
    Receipt(ReceiptBody),
    /// A Control (direct or reassembled).
    Control(ControlBody),
    /// A verified key change: the peer's new identity; the trust is now [`Trust::KeyChanged`].
    KeyChange(IksPublic),
    /// An unverifiable key change: the trust is now [`Trust::Frozen`] (warn the user).
    KeyChangeRefused,
    /// A fragment was stored; the message is not complete yet.
    Partial,
    /// Not a valid Content, or a fragmented message that is inconsistent or does not decode: discarded.
    Malformed,
    /// The session is frozen: nothing is delivered.
    Frozen,
}

/// A message in reassembly.
struct Partial {
    msg_id: Id,
    total: u16,
    chunks: Vec<Option<Zeroizing<Vec<u8>>>>,
}

/// The receive-side content state of one session: the messages in reassembly.
#[derive(Default)]
pub struct Inbox {
    partials: VecDeque<Partial>,
}

/// `HybridVerify(old IK_sig, "SecMP-TR/1 keychange", fingerprint(new IKSPublic))` (spec §7.6, §7.7).
fn key_change_verifies(kc: &KeyChangeBody, old: &HybridVerifyingKey) -> Result<()> {
    let fp = Fingerprint::of_encoded_iks(&kc.iks.encode()?)?;
    let sig = HybridSignature::from_bytes(kc.sig.as_bytes())?;
    old.verify(Label::TrKeychange, fp.as_bytes(), &sig)?;
    Ok(())
}

/// A key change (§7.7): verified → `KeyChanged`, else `Frozen`; no accept path.
fn key_change(kc: KeyChangeBody, old: &HybridVerifyingKey, trust: &mut Trust) -> Delivery {
    if key_change_verifies(&kc, old).is_ok() {
        *trust = Trust::KeyChanged;
        Delivery::KeyChange(kc.iks)
    } else {
        *trust = Trust::Frozen;
        Delivery::KeyChangeRefused
    }
}

/// The contact's `IK_sig` (`Ed25519 ‖ ML-DSA-65`) as `secmp-crypto` verifies with it.
///
/// # Errors
/// [`Error::Rejected`] if the key halves are refused.
pub fn ik_sig(iks: &IksPublic) -> Result<HybridVerifyingKey> {
    Ok(HybridVerifyingKey::from_bytes(
        iks.ik_ed25519.as_bytes(),
        iks.ik_mldsa65.as_slice(),
    )?)
}

impl Inbox {
    /// An empty inbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of messages in reassembly.
    #[must_use]
    pub fn partials(&self) -> usize {
        self.partials.len()
    }

    /// Process the decrypted padded Content of one cell. `peer_ik_sig` is the contact's current (old) `IK_sig`;
    /// `trust` is updated by a key change.
    pub fn receive(
        &mut self,
        plaintext: &Plaintext,
        peer_ik_sig: &HybridVerifyingKey,
        trust: &mut Trust,
    ) -> Delivery {
        if *trust == Trust::Frozen {
            return Delivery::Frozen;
        }
        let Ok(content) = plaintext.content() else {
            return Delivery::Malformed;
        };
        match content.body {
            ContentBody::Dummy => Delivery::Dummy,
            ContentBody::Handshake(b) => Delivery::Handshake(b),
            ContentBody::Batch(b) => Delivery::Messages(b.messages),
            ContentBody::RouteUpdate(b) => Delivery::Routes(b.routes),
            ContentBody::Receipt(b) => Delivery::Receipt(b),
            ContentBody::Control(b) => Delivery::Control(b),
            ContentBody::Fragment(f) => self.fragment(f, peer_ik_sig, trust),
        }
    }

    /// Store a fragment; deliver the message once it is complete.
    fn fragment(
        &mut self,
        f: Fragment,
        peer_ik_sig: &HybridVerifyingKey,
        trust: &mut Trust,
    ) -> Delivery {
        let idx = usize::from(f.idx);
        let known = self.partials.iter().position(|p| p.msg_id == f.msg_id);
        let at = if let Some(at) = known {
            at
        } else {
            if self.partials.len() >= MAX_PARTIALS {
                self.partials.pop_front();
            }
            self.partials.push_back(Partial {
                msg_id: f.msg_id,
                total: f.total,
                chunks: (0..f.total).map(|_| None).collect(),
            });
            self.partials.len().saturating_sub(1)
        };
        let Some(partial) = self.partials.get_mut(at) else {
            return Delivery::Malformed;
        };
        let consistent = partial.total == f.total;
        let slot = partial.chunks.get_mut(idx);
        let stored = match (consistent, slot) {
            (true, Some(slot @ None)) => {
                *slot = Some(f.chunk);
                true
            }
            // an identical duplicate is ignored
            (true, Some(Some(existing))) => {
                if bool::from(existing.as_slice().ct_eq(f.chunk.as_slice())) {
                    return Delivery::Partial;
                }
                false
            }
            _ => false,
        };
        if !stored {
            self.partials.remove(at);
            return Delivery::Malformed;
        }
        if !partial.chunks.iter().all(Option::is_some) {
            return Delivery::Partial;
        }
        let Some(done) = self.partials.remove(at) else {
            return Delivery::Malformed;
        };
        if !canonical_shape(&done.chunks) {
            return Delivery::Malformed;
        }
        // one allocation of the full length: a growing `Vec` would free its earlier blocks unwiped (`codec` docs)
        let len = done
            .chunks
            .iter()
            .flatten()
            .fold(0_usize, |len, chunk| len.saturating_add(chunk.len()));
        let mut whole = Zeroizing::new(Vec::with_capacity(len));
        for chunk in done.chunks.iter().flatten() {
            whole.extend_from_slice(chunk);
        }
        match FragmentPayload::decode(&whole) {
            Ok(FragmentPayload::Batch(b)) => Delivery::Messages(b.messages),
            Ok(FragmentPayload::RouteUpdate(b)) => Delivery::Routes(b.routes),
            Ok(FragmentPayload::Receipt(b)) => Delivery::Receipt(b),
            Ok(FragmentPayload::Control(b)) => Delivery::Control(b),
            Ok(FragmentPayload::KeyChange(kc)) => key_change(kc, peer_ik_sig, trust),
            // a reassembled KeyChange that does not decode as `IKSPublic ‖ HybridSig` (a bad length, an Ed25519 key or
            // signature refused by the §3.5 byte rules, a low-order `ik_dh`) cannot be verified: §7.7 "unverifiable
            // changes freeze the session" (M3 review C3, reading of SQ-26)
            Err(_) if whole.first() == Some(&content_type::KEY_CHANGE) => {
                *trust = Trust::Frozen;
                Delivery::KeyChangeRefused
            }
            Err(_) => Delivery::Malformed,
        }
    }

    /// The persistence encoding `InboxV1`, zeroizing:
    ///
    /// ```text
    /// fmt u8 = 0x01 ‖ count u8 (≤ 8) ‖ { msg_id[16] ‖ total u16 ‖ present u8
    ///                                    ‖ { idx u16 ‖ len u16 ‖ chunk[len] } × present } × count
    /// ```
    ///
    /// in eviction order; chunks in `idx` order, `1 ≤ present < total`, `1 ≤ len ≤ 1669`.
    ///
    /// # Errors
    /// [`Error::Rejected`] only if the inbox breaks its own bounds (never for one built by this module).
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::new();
        w.u8(INBOX_FORMAT_V1);
        if self.partials.len() > MAX_PARTIALS {
            return Err(Error::Rejected);
        }
        w.u8(u8::try_from(self.partials.len()).map_err(|_| Error::Rejected)?);
        for p in &self.partials {
            w.bytes(&p.msg_id);
            w.u16(p.total);
            let present = p.chunks.iter().flatten().count();
            w.u8(u8::try_from(present).map_err(|_| Error::Rejected)?);
            for (idx, chunk) in (0_u16..).zip(&p.chunks) {
                if let Some(chunk) = chunk {
                    w.u16(idx);
                    w.prefixed_u16(chunk)?;
                }
            }
        }
        Ok(w.into_bytes())
    }

    /// Decode `InboxV1` ([`Inbox::to_bytes`]): total and canonical — `count ≤ 8`, distinct `msg_id`s,
    /// `2 ≤ total ≤ 64`, `1 ≤ present < total`, `idx` strictly increasing and `< total`, `1 ≤ len ≤ 1669`.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any other input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.expect(INBOX_FORMAT_V1)?;
        let count = usize::from(r.u8()?);
        if count > MAX_PARTIALS {
            return Err(Error::Rejected);
        }
        let mut partials: VecDeque<Partial> = VecDeque::with_capacity(count);
        for _ in 0..count {
            let msg_id: Id = r.array::<ID_LEN>()?;
            let total = r.u16()?;
            let present = u16::from(r.u8()?);
            if !(FRAGMENT_TOTAL_MIN..=FRAGMENT_TOTAL_MAX).contains(&total)
                || present == 0
                || present >= total
                || partials.iter().any(|p| p.msg_id == msg_id)
            {
                return Err(Error::Rejected);
            }
            let mut chunks: Vec<Option<Zeroizing<Vec<u8>>>> = (0..total).map(|_| None).collect();
            let mut next = 0_u16;
            for _ in 0..present {
                let idx = r.u16()?;
                let chunk = r.prefixed_u16()?;
                if idx < next || chunk.is_empty() || chunk.len() > CHUNK_MAX {
                    return Err(Error::Rejected);
                }
                let slot = chunks.get_mut(usize::from(idx)).ok_or(Error::Rejected)?;
                *slot = Some(Zeroizing::new(chunk.to_vec()));
                next = idx.checked_add(1).ok_or(Error::Rejected)?;
            }
            partials.push_back(Partial {
                msg_id,
                total,
                chunks,
            });
        }
        r.finish()?;
        Ok(Self { partials })
    }
}
