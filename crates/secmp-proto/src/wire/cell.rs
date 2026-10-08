// SPDX-License-Identifier: AGPL-3.0-or-later
//! D.5 — ratchet cell and content (spec §7.5, §7.6; rev 2.3 rules of ADR-039):
//!
//! - `Cell` (4096 B, opaque: length only), `HeaderV1` (2314 B, `flags` = 0).
//! - `Content` padded to 1710 B: `ver ‖ type ‖ seq ‖ ts ‖ body_len ‖ body ‖ pad`, `body` ≤ 1689 B. Type 0x05
//!   (`KeyChange`) never appears unfragmented and rejects; a Dummy has an empty body.
//! - Bodies: Handshake (`caps` = 0, 1..=255 routes), Batch (1..=255 messages), Fragment (`idx` < `total`,
//!   2 ≤ `total` ≤ 64, `chunk` ≥ 1 B), `RouteUpdate` (1..=255 routes), `KeyChange`, Receipt (1..=255 ids), Control;
//!   the reassembled Fragment payload `inner_type ‖ inner_body` with `inner_type` ∈ {0x02, 0x04, 0x05, 0x06, 0x07}.
//! - `AppMessage.payload` and `Control.arg` are opaque length-prefixed bytes (spec §7.6, rev 2.3); as decrypted
//!   content they are held in zeroizing buffers (external review EXT-5, F21).
//! - `RouteDescriptor`: kind 0x01 is a `RelayQueue`; every other kind is kept as opaque bytes (spec §9.8: v1
//!   clients ignore unknown kinds; keeping them makes re-encoding canonical).

use secmp_crypto::{SecretBytes, Zeroize};

use crate::codec::{
    Decode, Encode, Reader, Writer, Zeroizing, boxed, decode_padded, encode_padded,
};
use crate::error::{Error, Result};
use crate::keys::{HybridSig, MlKem768Ek, X25519Pk};
use crate::sizes::{
    BODY_LEN, BODY_TAG_LEN, CELL_LEN, CONTENT_BODY_MAX, FRAGMENT_TOTAL_MAX, FRAGMENT_TOTAL_MIN,
    HASH_LEN, HDR_CT_LEN, MLKEM768_CT_LEN, NONCE_LEN,
};
use crate::wire::inv::{IksPublic, Profile, RelayRef};
use crate::wire::{Id, Period, read_ver, write_ver};

/// A ratchet cell `hdr_nonce[24] ‖ hdr_ct[2330] ‖ body_ct[1710] ‖ tag[32]` (4096 B). Opaque here: only its length
/// is checked (`SCHEMA-4.8` D-13); the parts are views.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Cell(Box<[u8; CELL_LEN]>);

impl Cell {
    /// A cell of exactly 4096 bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] on any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(boxed(bytes)?))
    }

    /// The 4096 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CELL_LEN] {
        &self.0
    }

    /// The buffer itself, without a copy: the relay keeps a received cell in this allocation and wipes it when the
    /// cell is deleted (spec §9.7 item 5).
    #[must_use]
    pub fn into_boxed(self) -> Box<[u8; CELL_LEN]> {
        self.0
    }

    /// The four parts.
    ///
    /// # Errors
    /// None in practice (the sizes are fixed).
    pub fn parts(&self) -> Result<CellParts<'_>> {
        let (hdr_nonce, rest) = self.0.split_at_checked(NONCE_LEN).ok_or(Error::Rejected)?;
        let (hdr_ct, rest) = rest.split_at_checked(HDR_CT_LEN).ok_or(Error::Rejected)?;
        let (body_ct, tag) = rest.split_at_checked(BODY_LEN).ok_or(Error::Rejected)?;
        if tag.len() != BODY_TAG_LEN {
            return Err(Error::Rejected);
        }
        Ok(CellParts {
            hdr_nonce,
            hdr_ct,
            body_ct,
            tag,
        })
    }
}

/// Views of the parts of a [`Cell`].
pub struct CellParts<'a> {
    /// 24 bytes.
    pub hdr_nonce: &'a [u8],
    /// 2330 bytes.
    pub hdr_ct: &'a [u8],
    /// 1710 bytes.
    pub body_ct: &'a [u8],
    /// 32 bytes.
    pub tag: &'a [u8],
}

impl Encode for Cell {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(self.0.as_slice());
        Ok(())
    }
}

impl Decode for Cell {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(r.boxed()?))
    }
}

/// `HeaderV1 = ver ‖ flags u8 (0) ‖ dh_pk[32] ‖ pn u32 ‖ n u32 ‖ ek_pq[1184] ‖ ct_pq[1088]` (2314 B).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct HeaderV1 {
    /// Sender's ratchet key.
    pub dh_pk: X25519Pk,
    /// Length of the previous sending chain.
    pub pn: u32,
    /// Message number in the chain.
    pub n: u32,
    /// Sender's current ML-KEM-768 key.
    pub ek_pq: MlKem768Ek,
    /// The chain's KEM ciphertext.
    pub ct_pq: Box<[u8; MLKEM768_CT_LEN]>,
}

impl Encode for HeaderV1 {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        w.u8(0);
        self.dh_pk.encode_to(w)?;
        w.u32(self.pn);
        w.u32(self.n);
        self.ek_pq.encode_to(w)?;
        w.bytes(self.ct_pq.as_slice());
        Ok(())
    }
}

impl Decode for HeaderV1 {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        // `flags` MUST be zero in v1 (spec §7.5)
        r.expect(0)?;
        Ok(Self {
            dh_pk: X25519Pk::decode_from(r)?,
            pn: r.u32()?,
            n: r.u32()?,
            ek_pq: MlKem768Ek::decode_from(r)?,
            ct_pq: r.boxed()?,
        })
    }
}

/// `Content.type` and `FragmentPayload.inner_type` bytes (spec §7.6).
pub mod content_type {
    /// Dummy.
    pub const DUMMY: u8 = 0x00;
    /// Handshake.
    pub const HANDSHAKE: u8 = 0x01;
    /// Batch.
    pub const BATCH: u8 = 0x02;
    /// Fragment.
    pub const FRAGMENT: u8 = 0x03;
    /// `RouteUpdate`.
    pub const ROUTE_UPDATE: u8 = 0x04;
    /// `KeyChange` (only inside a fragment).
    pub const KEY_CHANGE: u8 = 0x05;
    /// Receipt.
    pub const RECEIPT: u8 = 0x06;
    /// Control.
    pub const CONTROL: u8 = 0x07;
}

/// `AppMessage.kind` (spec §7.6).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum AppKind {
    /// 1 text.
    Text,
    /// 2 attachment-inline.
    AttachmentInline,
    /// 3 view-once-text.
    ViewOnceText,
    /// 4 reaction.
    Reaction,
    /// 5 edit.
    Edit,
    /// 6 delete.
    Delete,
}

impl AppKind {
    /// All kinds.
    pub const ALL: [Self; 6] = [
        Self::Text,
        Self::AttachmentInline,
        Self::ViewOnceText,
        Self::Reaction,
        Self::Edit,
        Self::Delete,
    ];

    /// The kind byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::AttachmentInline => 2,
            Self::ViewOnceText => 3,
            Self::Reaction => 4,
            Self::Edit => 5,
            Self::Delete => 6,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.byte() == b)
            .ok_or(Error::Rejected)
    }
}

/// `AppMessage = msg_id[16] ‖ kind u8 ‖ expire_after u32 ‖ payload_len u16 ‖ payload` (payload opaque). The
/// payload is decrypted message content, confidential: it is zeroized on drop (external review EXT-5, F21).
#[cfg_attr(test, derive(Clone))]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct AppMessage {
    /// Message id (dedup).
    pub msg_id: Id,
    /// Kind.
    pub kind: AppKind,
    /// Seconds until expiry (0: none).
    pub expire_after: u32,
    /// Opaque payload, at most 65535 bytes (zeroized on drop).
    pub payload: Zeroizing<Vec<u8>>,
}

impl Encode for AppMessage {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.msg_id);
        w.u8(self.kind.byte());
        w.u32(self.expire_after);
        w.prefixed_u16(&self.payload)
    }
}

impl Decode for AppMessage {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            msg_id: r.array()?,
            kind: AppKind::from_byte(r.u8()?)?,
            expire_after: r.u32()?,
            payload: Zeroizing::new(r.prefixed_u16()?.to_vec()),
        })
    }
}

/// A list of 1..=255 elements behind a `count u8` (Batch, `RouteUpdate`, Handshake routes, Receipt; rev 2.3).
fn write_count<T>(w: &mut Writer, items: &[T]) -> Result<()> {
    if items.is_empty() {
        return Err(Error::Rejected);
    }
    w.u8(u8::try_from(items.len()).map_err(|_| Error::Rejected)?);
    Ok(())
}

/// Read a `count u8` of 1..=255.
fn read_count(r: &mut Reader<'_>) -> Result<usize> {
    match r.u8()? {
        0 => Err(Error::Rejected),
        n => Ok(usize::from(n)),
    }
}

/// M4 review C-14 (R-30): the wire bodies `AppMessage`, `BatchBody`, `Fragment` and `ControlBody` are `Clone` only in
/// this crate's own tests (`cfg_attr(test, derive(Clone))`), and `wire::inv::Onion` is not `Copy`. Outside the tests a
/// body has no `clone()`:
///
/// ```compile_fail,E0277
/// fn needs_clone<T: Clone>(_: &T) {}
/// fn check(
///     a: &secmp_proto::wire::cell::AppMessage,
///     b: &secmp_proto::wire::cell::BatchBody,
///     f: &secmp_proto::wire::cell::Fragment,
///     c: &secmp_proto::wire::cell::ControlBody,
/// ) {
///     needs_clone(a);
///     needs_clone(b);
///     needs_clone(f);
///     needs_clone(c);
/// }
/// ```
///
/// and an `Onion` is moved, not copied:
///
/// ```compile_fail,E0382
/// use secmp_proto::wire::inv::Onion;
/// fn twice(onion: Onion) -> (Onion, Onion) {
///     (onion, onion)
/// }
/// ```
#[cfg(doctest)]
pub mod wire_bodies_are_not_clone_outside_tests {}

/// `Batch body = count u8 (1..=255) ‖ AppMessage[] × count`.
#[cfg_attr(test, derive(Clone))]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct BatchBody {
    /// 1..=255 messages.
    pub messages: Vec<AppMessage>,
}

impl Encode for BatchBody {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_count(w, &self.messages)?;
        for m in &self.messages {
            m.encode_to(w)?;
        }
        Ok(())
    }
}

impl Decode for BatchBody {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let count = read_count(r)?;
        let messages = (0..count)
            .map(|_| AppMessage::decode_from(r))
            .collect::<Result<_>>()?;
        Ok(Self { messages })
    }
}

/// `Fragment = msg_id[16] ‖ idx u16 ‖ total u16 ‖ chunk`: `idx` < `total`, 2 ≤ `total` ≤ 64, `chunk` ≥ 1 byte
/// (rev 2.3). The chunk runs to the end of the enclosing structure; chunk sizing and consistency across fragments
/// are reassembly rules. A chunk of a fragmented `RouteUpdate` carries `send_seed` bytes, so it is zeroized on drop
/// (review C1).
#[cfg_attr(test, derive(Clone))]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Fragment {
    /// The fragmented message's id.
    pub msg_id: Id,
    /// 0-based index.
    pub idx: u16,
    /// Number of fragments.
    pub total: u16,
    /// This fragment's bytes (zeroized on drop).
    pub chunk: Zeroizing<Vec<u8>>,
}

impl Fragment {
    fn check(idx: u16, total: u16, chunk: &[u8]) -> Result<()> {
        if (FRAGMENT_TOTAL_MIN..=FRAGMENT_TOTAL_MAX).contains(&total)
            && idx < total
            && !chunk.is_empty()
        {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }
}

impl Encode for Fragment {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        Self::check(self.idx, self.total, &self.chunk)?;
        w.bytes(&self.msg_id);
        w.u16(self.idx);
        w.u16(self.total);
        w.bytes(&self.chunk);
        Ok(())
    }
}

impl Decode for Fragment {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let msg_id = r.array()?;
        let idx = r.u16()?;
        let total = r.u16()?;
        let chunk = Zeroizing::new(r.rest().to_vec());
        Self::check(idx, total, &chunk)?;
        Ok(Self {
            msg_id,
            idx,
            total,
            chunk,
        })
    }
}

/// `RelayQueue` route blob `RelayRef ‖ sid[16] ‖ send_seed[32] ‖ period_s u16` (spec §9.8). `send_seed` is the
/// sender capability: a secret.
pub struct RelayQueue {
    /// The recipient's relay.
    pub relay: RelayRef,
    /// The queue's sender id.
    pub sid: Id,
    /// Ed25519 seed of the queue's sender key.
    pub send_seed: SecretBytes<HASH_LEN>,
    /// The send period the recipient asks for (spec §10.2).
    pub period_s: Period,
}

impl Zeroize for RelayQueue {
    fn zeroize(&mut self) {
        self.relay.zeroize();
        self.sid.zeroize();
        crate::wire::inv::wipe_seed(&mut self.send_seed);
    }
}

/// A decoded route that a rejected `process` drops is wiped (M4 review R-61).
impl Drop for RelayQueue {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        crate::wire::wipe_log::note("RelayQueue");
    }
}

impl Encode for RelayQueue {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        self.relay.encode_to(w)?;
        w.bytes(&self.sid);
        w.bytes(self.send_seed.expose_secret());
        self.period_s.encode_to(w)
    }
}

impl Decode for RelayQueue {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            relay: RelayRef::decode_from(r)?,
            sid: r.array()?,
            send_seed: SecretBytes::from_slice(r.take(HASH_LEN)?)?,
            period_s: Period::decode_from(r)?,
        })
    }
}

/// The `RelayQueue` route kind.
pub const ROUTE_KIND_RELAY_QUEUE: u8 = 0x01;

/// `RouteDescriptor = ver ‖ kind u8 ‖ len u16 ‖ blob` (spec §9.8, D.5).
pub enum RouteDescriptor {
    /// Kind 0x01.
    RelayQueue(RelayQueue),
    /// Any other kind (v1.1 kinds 0x02/0x03 included): kept as opaque bytes and ignored by v1 clients.
    Unknown {
        /// The kind byte (never 0x01).
        kind: u8,
        /// The blob, at most 65535 bytes; zeroized on drop, since a future kind may carry a sender capability as
        /// `RelayQueue` does (review C1).
        blob: Zeroizing<Vec<u8>>,
    },
}

/// Wiped by `Zeroizing<Vec<RouteDescriptor>>` (held so by [`crate::hx::Accepted`]).
impl Zeroize for RouteDescriptor {
    fn zeroize(&mut self) {
        match self {
            Self::RelayQueue(q) => q.zeroize(),
            Self::Unknown { kind, blob } => {
                *kind = 0;
                blob.zeroize();
            }
        }
    }
}

impl Drop for RouteDescriptor {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        crate::wire::wipe_log::note("RouteDescriptor");
    }
}

impl Encode for RouteDescriptor {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        match self {
            Self::RelayQueue(q) => {
                w.u8(ROUTE_KIND_RELAY_QUEUE);
                w.prefixed_u16(&q.encode()?)
            }
            Self::Unknown { kind, blob } => {
                if *kind == ROUTE_KIND_RELAY_QUEUE {
                    return Err(Error::Rejected);
                }
                w.u8(*kind);
                w.prefixed_u16(blob)
            }
        }
    }
}

impl Decode for RouteDescriptor {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        let kind = r.u8()?;
        let blob = r.prefixed_u16()?;
        if kind == ROUTE_KIND_RELAY_QUEUE {
            Ok(Self::RelayQueue(RelayQueue::decode(blob)?))
        } else {
            Ok(Self::Unknown {
                kind,
                blob: Zeroizing::new(blob.to_vec()),
            })
        }
    }
}

fn write_routes(w: &mut Writer, routes: &[RouteDescriptor]) -> Result<()> {
    write_count(w, routes)?;
    for route in routes {
        route.encode_to(w)?;
    }
    Ok(())
}

/// The routes of a body, in a vector sized exactly once (M4 review C-13: a growing vector would free its earlier
/// blocks, which hold routing metadata, without wiping them; `codec.rs`'s rule).
fn read_routes(r: &mut Reader<'_>) -> Result<Vec<RouteDescriptor>> {
    let count = read_count(r)?;
    let mut routes = Vec::with_capacity(count);
    for _ in 0..count {
        routes.push(RouteDescriptor::decode_from(r)?);
    }
    Ok(routes)
}

/// `RouteUpdate body = count u8 (1..=255) ‖ RouteDescriptor[] × count`.
pub struct RouteUpdateBody {
    /// 1..=255 routes.
    pub routes: Vec<RouteDescriptor>,
}

impl Encode for RouteUpdateBody {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_routes(w, &self.routes)
    }
}

impl Decode for RouteUpdateBody {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            routes: read_routes(r)?,
        })
    }
}

/// `Handshake body = Profile ‖ caps u32 (0) ‖ route_count u8 (1..=255) ‖ RouteDescriptor[]` (first message only).
pub struct HandshakeBody {
    /// The initiator's profile.
    pub profile: Profile,
    /// The initiator's reply routes, 1..=255.
    pub routes: Vec<RouteDescriptor>,
}

impl Encode for HandshakeBody {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        self.profile.encode_to(w)?;
        w.u32(0);
        write_routes(w, &self.routes)
    }
}

impl Decode for HandshakeBody {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let profile = Profile::decode_from(r)?;
        // `caps` MUST be 0 in v1 (rev 2.3)
        if r.u32()? != 0 {
            return Err(Error::Rejected);
        }
        Ok(Self {
            profile,
            routes: read_routes(r)?,
        })
    }
}

/// `KeyChange body = IKSPublic[2017] ‖ sig[3373]` (5390 B; always fragmented).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct KeyChangeBody {
    /// The new identity.
    pub iks: IksPublic,
    /// `HybridSign(old IK_sig, "SecMP-TR/1 keychange", fingerprint(new))` — verified at use.
    pub sig: HybridSig,
}

impl Encode for KeyChangeBody {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        self.iks.encode_to(w)?;
        self.sig.encode_to(w)
    }
}

impl Decode for KeyChangeBody {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            iks: IksPublic::decode_from(r)?,
            sig: HybridSig::decode_from(r)?,
        })
    }
}

/// `Receipt.kind`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum ReceiptKind {
    /// 1 delivered.
    Delivered,
    /// 2 read.
    Read,
}

/// `Receipt body = kind u8 ‖ count u8 (1..=255) ‖ msg_id[16] × count`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct ReceiptBody {
    /// Delivered or read.
    pub kind: ReceiptKind,
    /// 1..=255 message ids.
    pub msg_ids: Vec<Id>,
}

impl Encode for ReceiptBody {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.u8(match self.kind {
            ReceiptKind::Delivered => 1,
            ReceiptKind::Read => 2,
        });
        write_count(w, &self.msg_ids)?;
        for id in &self.msg_ids {
            w.bytes(id);
        }
        Ok(())
    }
}

impl Decode for ReceiptBody {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let kind = match r.u8()? {
            1 => ReceiptKind::Delivered,
            2 => ReceiptKind::Read,
            _ => return Err(Error::Rejected),
        };
        let count = read_count(r)?;
        let msg_ids = (0..count).map(|_| r.array()).collect::<Result<_>>()?;
        Ok(Self { kind, msg_ids })
    }
}

/// `Control.code`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum ControlCode {
    /// 1 contact-removed.
    ContactRemoved,
    /// 2 session-reset-request.
    SessionResetRequest,
}

/// `Control body = code u8 ‖ arg_len u16 ‖ arg` (arg opaque; decrypted content, zeroized on drop — external review
/// EXT-5, F21).
#[cfg_attr(test, derive(Clone))]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct ControlBody {
    /// The code.
    pub code: ControlCode,
    /// Opaque argument, at most 65535 bytes (zeroized on drop).
    pub arg: Zeroizing<Vec<u8>>,
}

impl Encode for ControlBody {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.u8(match self.code {
            ControlCode::ContactRemoved => 1,
            ControlCode::SessionResetRequest => 2,
        });
        w.prefixed_u16(&self.arg)
    }
}

impl Decode for ControlBody {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let code = match r.u8()? {
            1 => ControlCode::ContactRemoved,
            2 => ControlCode::SessionResetRequest,
            _ => return Err(Error::Rejected),
        };
        Ok(Self {
            code,
            arg: Zeroizing::new(r.prefixed_u16()?.to_vec()),
        })
    }
}

/// The body of a `Content` (spec §7.6); `KeyChange` is not among them — it only travels fragmented.
pub enum ContentBody {
    /// 0x00, empty body.
    Dummy,
    /// 0x01.
    Handshake(HandshakeBody),
    /// 0x02.
    Batch(BatchBody),
    /// 0x03.
    Fragment(Fragment),
    /// 0x04.
    RouteUpdate(RouteUpdateBody),
    /// 0x06.
    Receipt(ReceiptBody),
    /// 0x07.
    Control(ControlBody),
}

impl ContentBody {
    /// The type byte.
    #[must_use]
    pub const fn content_type(&self) -> u8 {
        match self {
            Self::Dummy => content_type::DUMMY,
            Self::Handshake(_) => content_type::HANDSHAKE,
            Self::Batch(_) => content_type::BATCH,
            Self::Fragment(_) => content_type::FRAGMENT,
            Self::RouteUpdate(_) => content_type::ROUTE_UPDATE,
            Self::Receipt(_) => content_type::RECEIPT,
            Self::Control(_) => content_type::CONTROL,
        }
    }

    /// The encoded body, zeroized on drop (a Handshake or `RouteUpdate` body carries `send_seed`, review C1).
    fn encode_body(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Dummy => Ok(Zeroizing::new(Vec::new())),
            Self::Handshake(b) => b.encode(),
            Self::Batch(b) => b.encode(),
            Self::Fragment(b) => b.encode(),
            Self::RouteUpdate(b) => b.encode(),
            Self::Receipt(b) => b.encode(),
            Self::Control(b) => b.encode(),
        }
    }

    fn decode_body(content_type: u8, body: &[u8]) -> Result<Self> {
        Ok(match content_type {
            content_type::DUMMY if body.is_empty() => Self::Dummy,
            content_type::HANDSHAKE => Self::Handshake(HandshakeBody::decode(body)?),
            content_type::BATCH => Self::Batch(BatchBody::decode(body)?),
            content_type::FRAGMENT => Self::Fragment(Fragment::decode(body)?),
            content_type::ROUTE_UPDATE => Self::RouteUpdate(RouteUpdateBody::decode(body)?),
            content_type::RECEIPT => Self::Receipt(ReceiptBody::decode(body)?),
            content_type::CONTROL => Self::Control(ControlBody::decode(body)?),
            // a Dummy with a body, KeyChange unfragmented (rev 2.3), unknown types
            _ => return Err(Error::Rejected),
        })
    }
}

/// `Content = ver ‖ type u8 ‖ seq u64 ‖ ts u64 ‖ body_len u16 ‖ body ‖ pad → 1710` (spec §7.6).
pub struct Content {
    /// Per-session application sequence.
    pub seq: u64,
    /// Sender's clock.
    pub ts: u64,
    /// The typed body (at most 1689 bytes encoded).
    pub body: ContentBody,
}

/// `Content` without its padding.
struct ContentFields<'a>(&'a Content);

impl Encode for ContentFields<'_> {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let c = self.0;
        let body = c.body.encode_body()?;
        if body.len() > CONTENT_BODY_MAX {
            return Err(Error::Rejected);
        }
        write_ver(w);
        w.u8(c.body.content_type());
        w.u64(c.seq);
        w.u64(c.ts);
        w.prefixed_u16(&body)
    }
}

impl Encode for Content {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&encode_padded(&ContentFields(self), BODY_LEN)?);
        Ok(())
    }
}

/// `Content` fields after unpadding.
struct ContentDecoded(Content);

impl Decode for ContentDecoded {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        let content_type = r.u8()?;
        let seq = r.u64()?;
        let ts = r.u64()?;
        let body = r.prefixed_u16()?;
        if body.len() > CONTENT_BODY_MAX {
            return Err(Error::Rejected);
        }
        Ok(Self(Content {
            seq,
            ts,
            body: ContentBody::decode_body(content_type, body)?,
        }))
    }
}

impl Decode for Content {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(decode_padded::<ContentDecoded>(r.take(BODY_LEN)?, BODY_LEN)?.0)
    }
}

/// The reassembled bytes of a fragmented message: `inner_type u8 ‖ inner_body`, processed as a Content of that
/// type (spec §7.6); `inner_type` ∈ {0x02, 0x04, 0x05, 0x06, 0x07} (rev 2.3).
pub enum FragmentPayload {
    /// 0x02.
    Batch(BatchBody),
    /// 0x04.
    RouteUpdate(RouteUpdateBody),
    /// 0x05.
    KeyChange(KeyChangeBody),
    /// 0x06.
    Receipt(ReceiptBody),
    /// 0x07.
    Control(ControlBody),
}

impl Encode for FragmentPayload {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::Batch(b) => {
                w.u8(content_type::BATCH);
                b.encode_to(w)
            }
            Self::RouteUpdate(b) => {
                w.u8(content_type::ROUTE_UPDATE);
                b.encode_to(w)
            }
            Self::KeyChange(b) => {
                w.u8(content_type::KEY_CHANGE);
                b.encode_to(w)
            }
            Self::Receipt(b) => {
                w.u8(content_type::RECEIPT);
                b.encode_to(w)
            }
            Self::Control(b) => {
                w.u8(content_type::CONTROL);
                b.encode_to(w)
            }
        }
    }
}

impl Decode for FragmentPayload {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.u8()? {
            content_type::BATCH => Self::Batch(BatchBody::decode_from(r)?),
            content_type::ROUTE_UPDATE => Self::RouteUpdate(RouteUpdateBody::decode_from(r)?),
            content_type::KEY_CHANGE => Self::KeyChange(KeyChangeBody::decode_from(r)?),
            content_type::RECEIPT => Self::Receipt(ReceiptBody::decode_from(r)?),
            content_type::CONTROL => Self::Control(ControlBody::decode_from(r)?),
            // Dummy, Handshake, Fragment and unknown types (rev 2.3)
            _ => return Err(Error::Rejected),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // the real type, not the crate's alias (which is a stand-in under Kani)
    use crate::wire::inv::tests::{iks, relay_ref};
    use crate::wire::testutil::{
        ek768, exact_fit, hybrid_sig, round_trip, round_trip_bytes, x25519,
    };
    use secmp_crypto::Zeroizing;

    #[test]
    fn cell_parts() -> Result<()> {
        let bytes: Vec<u8> = (0..CELL_LEN)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        let cell = Cell::decode(&bytes)?;
        let p = cell.parts()?;
        assert_eq!(
            (
                p.hdr_nonce.len(),
                p.hdr_ct.len(),
                p.body_ct.len(),
                p.tag.len()
            ),
            (24, 2330, 1710, 32)
        );
        // the parts are the consecutive slices of the 4096 bytes
        let joined = [p.hdr_nonce, p.hdr_ct, p.body_ct, p.tag].concat();
        assert_eq!(joined, bytes);
        assert_eq!(cell.as_bytes().as_slice(), bytes.as_slice());
        // the buffer the relay keeps (spec §9.7 item 5) holds the same 4096 bytes
        assert_eq!(cell.clone().into_boxed().as_slice(), bytes.as_slice());
        assert_eq!(*round_trip(&cell)?, bytes);
        exact_fit::<Cell>(&bytes);
        Ok(())
    }

    #[test]
    fn header() -> Result<()> {
        let h = HeaderV1 {
            dh_pk: x25519(1)?,
            pn: u32::MAX,
            n: 0,
            ek_pq: ek768(2)?,
            ct_pq: Box::new([3; MLKEM768_CT_LEN]),
        };
        let bytes = round_trip(&h)?;
        assert_eq!(bytes.len(), crate::sizes::HEADER_LEN);
        exact_fit::<HeaderV1>(&bytes);
        let mut flagged = bytes.clone();
        if let Some(f) = flagged.get_mut(1) {
            *f = 0x80;
        }
        assert_eq!(HeaderV1::decode(&flagged), Err(Error::Rejected));
        Ok(())
    }

    fn message(kind: AppKind, len: usize) -> AppMessage {
        AppMessage {
            msg_id: [kind.byte(); 16],
            kind,
            expire_after: 60,
            payload: Zeroizing::new(vec![0x61; len]),
        }
    }

    fn relay_queue(direct: bool, period: Period) -> Result<RelayQueue> {
        Ok(RelayQueue {
            relay: relay_ref(direct)?,
            sid: [9; 16],
            send_seed: SecretBytes::from_slice(&[8; 32])?,
            period_s: period,
        })
    }

    /// M4 review C-13 (R-45): the decoded route vector is sized once — `capacity() == len()` for 1, 10 and 255
    /// `RelayQueue` routes (no growth, so no unwiped earlier block).
    #[test]
    fn read_routes_pre_sizes_the_vector() -> Result<()> {
        for n in [1_usize, 10, 255] {
            let body = RouteUpdateBody {
                routes: (0..n)
                    .map(|_| {
                        Ok(RouteDescriptor::RelayQueue(relay_queue(
                            false,
                            Period::S20,
                        )?))
                    })
                    .collect::<Result<Vec<_>>>()?,
            };
            let decoded = RouteUpdateBody::decode(&body.encode()?)?;
            assert_eq!(decoded.routes.len(), n);
            assert_eq!(decoded.routes.capacity(), n, "{n} routes");
        }
        Ok(())
    }

    /// Review C1: every structure that carries a `send_seed` encodes into a `Zeroizing<Vec<u8>>` (a change of a
    /// return type fails to compile here) and the seed is in each of these buffers; fragment chunks and unknown
    /// route blobs, which may carry one, are `Zeroizing<Vec<u8>>` fields.
    #[test]
    fn secret_bearing_encodings_are_zeroizing() -> Result<()> {
        let route = || -> Result<RouteDescriptor> {
            Ok(RouteDescriptor::RelayQueue(relay_queue(
                false,
                Period::S20,
            )?))
        };
        let update = || -> Result<RouteUpdateBody> {
            Ok(RouteUpdateBody {
                routes: vec![route()?],
            })
        };
        let handshake = || -> Result<HandshakeBody> {
            Ok(HandshakeBody {
                profile: Profile::new("a", None)?,
                routes: vec![route()?],
            })
        };
        let queue: Zeroizing<Vec<u8>> = relay_queue(false, Period::S20)?.encode()?;
        let descriptor: Zeroizing<Vec<u8>> = route()?.encode()?;
        let update_body: Zeroizing<Vec<u8>> = update()?.encode()?;
        let handshake_body: Zeroizing<Vec<u8>> = handshake()?.encode()?;
        let content_body: Zeroizing<Vec<u8>> = ContentBody::RouteUpdate(update()?).encode_body()?;
        let route_update: Zeroizing<Vec<u8>> = Content {
            seq: 1,
            ts: 2,
            body: ContentBody::RouteUpdate(update()?),
        }
        .encode()?;
        let handshake_content: Zeroizing<Vec<u8>> = Content {
            seq: 1,
            ts: 2,
            body: ContentBody::Handshake(handshake()?),
        }
        .encode()?;
        let fragment_payload: Zeroizing<Vec<u8>> =
            FragmentPayload::RouteUpdate(update()?).encode()?;
        for (what, bytes) in [
            ("RelayQueue", &queue),
            ("RouteDescriptor", &descriptor),
            ("RouteUpdateBody", &update_body),
            ("HandshakeBody", &handshake_body),
            ("ContentBody", &content_body),
            ("Content{RouteUpdate}", &route_update),
            ("Content{Handshake}", &handshake_content),
            ("FragmentPayload", &fragment_payload),
        ] {
            assert!(bytes.windows(32).any(|w| w == [8; 32]), "{what}");
        }
        // a Content is written in one piece: one allocation of its fixed size, no growth step left a copy behind
        assert_eq!(route_update.capacity(), BODY_LEN);
        assert_eq!(handshake_content.capacity(), BODY_LEN);
        let Fragment { chunk, .. } =
            Fragment::decode(&[[1; 16].as_slice(), &[0, 0, 0, 2, 5]].concat())?;
        let chunk: Zeroizing<Vec<u8>> = chunk;
        assert_eq!(*chunk, [5]);
        // kind 2 is an unknown route
        let route = RouteDescriptor::decode(&[1, 2, 0, 1, 7])?;
        let RouteDescriptor::Unknown { blob, .. } = &route else {
            return Err(Error::Rejected);
        };
        let blob: &Zeroizing<Vec<u8>> = blob;
        assert_eq!(**blob, [7]);
        Ok(())
    }

    /// F21 (external review EXT-5): the decrypted plaintext fields `AppMessage.payload` and `ControlBody.arg` are
    /// `Zeroizing<Vec<u8>>`, decoded values included (a change of either field type fails to compile here).
    #[test]
    fn plaintext_fields_are_zeroizing() -> Result<()> {
        let m = AppMessage::decode(&round_trip(&message(AppKind::Text, 3))?)?;
        let payload: &Zeroizing<Vec<u8>> = &m.payload;
        assert_eq!(**payload, [0x61; 3]);
        let c = ControlBody::decode(&[1, 0, 2, 9, 9])?;
        let arg: &Zeroizing<Vec<u8>> = &c.arg;
        assert_eq!(**arg, [9, 9]);
        Ok(())
    }

    #[test]
    fn app_message_and_batch() -> Result<()> {
        for kind in AppKind::ALL {
            exact_fit::<AppMessage>(&round_trip(&message(kind, 3))?);
        }
        let max = message(AppKind::AttachmentInline, 65_535);
        assert_eq!(round_trip(&max)?.len(), 65_558);
        assert!(message(AppKind::Text, 65_536).encode().is_err());
        let batch = BatchBody {
            messages: vec![
                message(AppKind::Text, 20),
                message(AppKind::ViewOnceText, 0),
            ],
        };
        exact_fit::<BatchBody>(&round_trip(&batch)?);
        assert!(BatchBody { messages: vec![] }.encode().is_err());
        assert!(BatchBody::decode(&[0]).is_err());
        Ok(())
    }

    #[test]
    fn fragment_rules() -> Result<()> {
        let f = |idx, total, chunk: usize| Fragment {
            msg_id: [1; 16],
            idx,
            total,
            chunk: Zeroizing::new(vec![7; chunk]),
        };
        for ok in [f(0, 2, 1), f(1, 2, 100), f(63, 64, 1669)] {
            round_trip(&ok)?;
        }
        for bad in [
            f(2, 2, 1),
            f(0, 1, 1),
            f(0, 65, 1),
            f(0, 0, 1),
            f(1, 2, 0),
            f(0xffff, 2, 1),
        ] {
            assert!(bad.encode().is_err());
            let mut w = Writer::new();
            w.bytes(&bad.msg_id);
            w.u16(bad.idx);
            w.u16(bad.total);
            w.bytes(&bad.chunk);
            assert_eq!(Fragment::decode(&w.into_bytes()), Err(Error::Rejected));
        }
        Ok(())
    }

    #[test]
    fn routes() -> Result<()> {
        for (direct, period) in [(false, Period::S20), (true, Period::S80)] {
            let rq = RouteDescriptor::RelayQueue(relay_queue(direct, period)?);
            exact_fit::<RouteDescriptor>(&round_trip_bytes(&rq)?);
        }
        let unknown = RouteDescriptor::Unknown {
            kind: 0x7e,
            blob: Zeroizing::new(vec![5; 65_535]),
        };
        assert_eq!(round_trip_bytes(&unknown)?.len(), 65_539);
        assert!(
            RouteDescriptor::Unknown {
                kind: ROUTE_KIND_RELAY_QUEUE,
                blob: Zeroizing::new(vec![])
            }
            .encode()
            .is_err()
        );
        let update = RouteUpdateBody {
            routes: vec![
                RouteDescriptor::RelayQueue(relay_queue(false, Period::S10)?),
                RouteDescriptor::Unknown {
                    kind: 0x02,
                    blob: Zeroizing::new(vec![1]),
                },
            ],
        };
        exact_fit::<RouteUpdateBody>(&round_trip_bytes(&update)?);
        assert!(RouteUpdateBody { routes: vec![] }.encode().is_err());
        Ok(())
    }

    #[test]
    fn handshake_body_caps_and_routes() -> Result<()> {
        let body = HandshakeBody {
            profile: Profile::new("ab", Some([2; 32]))?,
            routes: vec![RouteDescriptor::RelayQueue(relay_queue(true, Period::S10)?)],
        };
        let bytes = round_trip_bytes(&body)?;
        exact_fit::<HandshakeBody>(&bytes);
        // caps sits right after the 36-byte profile
        let mut caps = bytes.clone();
        if let Some(b) = caps.get_mut(39) {
            *b = 1;
        }
        assert_eq!(HandshakeBody::decode(&caps).err(), Some(Error::Rejected));
        assert!(
            HandshakeBody {
                profile: Profile::new("", None)?,
                routes: vec![]
            }
            .encode()
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn key_change_receipt_control() -> Result<()> {
        let kc = KeyChangeBody {
            iks: iks(1)?,
            sig: hybrid_sig(2)?,
        };
        assert_eq!(round_trip(&kc)?.len(), crate::sizes::KEYCHANGE_BODY_LEN);
        for kind in [ReceiptKind::Delivered, ReceiptKind::Read] {
            let r = ReceiptBody {
                kind,
                msg_ids: vec![[3; 16]; 255],
            };
            assert_eq!(round_trip(&r)?.len(), 4082);
        }
        assert!(
            ReceiptBody {
                kind: ReceiptKind::Read,
                msg_ids: vec![[3; 16]; 256]
            }
            .encode()
            .is_err()
        );
        for code in [
            ControlCode::ContactRemoved,
            ControlCode::SessionResetRequest,
        ] {
            let c = ControlBody {
                code,
                arg: Zeroizing::new(vec![4; 16]),
            };
            exact_fit::<ControlBody>(&round_trip(&c)?);
        }
        assert_eq!(ControlBody::decode(&[3, 0, 0]), Err(Error::Rejected));
        Ok(())
    }

    #[test]
    fn content_types_padding_and_limits() -> Result<()> {
        let bodies = vec![
            ContentBody::Dummy,
            ContentBody::Batch(BatchBody {
                messages: vec![message(AppKind::Text, 5)],
            }),
            ContentBody::Fragment(Fragment {
                msg_id: [1; 16],
                idx: 1,
                total: 3,
                chunk: Zeroizing::new(vec![2; CONTENT_BODY_MAX - 20]),
            }),
            ContentBody::Receipt(ReceiptBody {
                kind: ReceiptKind::Delivered,
                msg_ids: vec![[1; 16]],
            }),
            ContentBody::Control(ControlBody {
                code: ControlCode::SessionResetRequest,
                arg: Zeroizing::new(vec![]),
            }),
            ContentBody::RouteUpdate(RouteUpdateBody {
                routes: vec![RouteDescriptor::RelayQueue(relay_queue(true, Period::S40)?)],
            }),
            ContentBody::Handshake(HandshakeBody {
                profile: Profile::new("x", None)?,
                routes: vec![RouteDescriptor::Unknown {
                    kind: 0x10,
                    blob: Zeroizing::new(vec![1; 40]),
                }],
            }),
        ];
        for body in bodies {
            let c = Content {
                seq: u64::MAX,
                ts: u64::MAX,
                body,
            };
            let bytes = round_trip_bytes(&c)?;
            assert_eq!(bytes.len(), BODY_LEN);
            exact_fit::<Content>(&bytes);
        }
        // a body over 1689 bytes has no encoding
        let too_big = Content {
            seq: 0,
            ts: 0,
            body: ContentBody::Fragment(Fragment {
                msg_id: [1; 16],
                idx: 0,
                total: 2,
                chunk: Zeroizing::new(vec![2; CONTENT_BODY_MAX - 19]),
            }),
        };
        assert!(too_big.encode().is_err());
        // KeyChange (0x05) unfragmented and unknown types reject
        for t in [content_type::KEY_CHANGE, 0x08, 0xff] {
            let mut w = Writer::new();
            w.u8(1);
            w.u8(t);
            w.u64(0);
            w.u64(0);
            w.u16(0);
            let bytes = crate::codec::pad(&w.into_bytes(), BODY_LEN)?;
            assert!(Content::decode(&bytes).is_err(), "{t}");
        }
        Ok(())
    }

    #[test]
    fn fragment_payload_inner_types() -> Result<()> {
        let kc = FragmentPayload::KeyChange(KeyChangeBody {
            iks: iks(3)?,
            sig: hybrid_sig(4)?,
        });
        assert_eq!(round_trip_bytes(&kc)?.len(), 5391);
        let receipt = FragmentPayload::Receipt(ReceiptBody {
            kind: ReceiptKind::Read,
            msg_ids: vec![[1; 16]],
        });
        exact_fit::<FragmentPayload>(&round_trip_bytes(&receipt)?);
        // every accepted inner type decodes to its own variant (first byte = inner_type)
        let others = [
            (
                content_type::BATCH,
                FragmentPayload::Batch(BatchBody {
                    messages: vec![message(AppKind::Text, 1_800)],
                }),
            ),
            (
                content_type::ROUTE_UPDATE,
                FragmentPayload::RouteUpdate(RouteUpdateBody {
                    routes: vec![RouteDescriptor::RelayQueue(relay_queue(
                        false,
                        Period::S20,
                    )?)],
                }),
            ),
            (
                content_type::CONTROL,
                FragmentPayload::Control(ControlBody {
                    code: ControlCode::ContactRemoved,
                    arg: Zeroizing::new(vec![5; 2_000]),
                }),
            ),
        ];
        for (t, payload) in others {
            let bytes = round_trip_bytes(&payload)?;
            assert_eq!(bytes.first(), Some(&t));
            exact_fit::<FragmentPayload>(&bytes);
            let back = FragmentPayload::decode(&bytes)?;
            let same_variant = matches!(
                (&payload, &back),
                (FragmentPayload::Batch(_), FragmentPayload::Batch(_))
                    | (
                        FragmentPayload::RouteUpdate(_),
                        FragmentPayload::RouteUpdate(_)
                    )
                    | (FragmentPayload::Control(_), FragmentPayload::Control(_))
            );
            assert!(same_variant, "{t}");
        }
        for t in [0x00_u8, 0x01, 0x03, 0x08] {
            assert!(FragmentPayload::decode(&[t, 1, 1]).is_err(), "{t}");
        }
        Ok(())
    }
}

/// M4-12 (M4 review R-61): the hand-written `Zeroize` of `RelayRef`, `RelayQueue`, `RouteDescriptor` and
/// `InvitationV1` clears every byte field, and their `Drop` runs it. A heap field (`direct.host`, an unknown route's
/// `blob`) is wiped and then emptied, so the tests assert that it is empty (an all-zero check over an empty slice
/// would pass whether or not it was wiped). Not wiped, by design: `direct.port` (a `NonZeroU16`, no zero value) and
/// the periods (`period_s`, `inv_period_s`: enum values, not secrets) — M4 review C-14.
#[cfg(test)]
mod wipe_tests {
    use super::*;
    use crate::wire::Period;
    use crate::wire::inv::InvitationV1;
    use crate::wire::inv::tests::relay_ref;
    use crate::wire::wipe_log;

    fn all_zero(b: &[u8]) -> bool {
        b.iter().all(|x| *x == 0)
    }

    fn relay_clear(r: &RelayRef) -> bool {
        all_zero(&r.relay_fp)
            && all_zero(r.onion.as_bytes())
            && all_zero(&r.akc)
            && r.direct
                .as_ref()
                .is_none_or(|d| d.host.as_bytes().is_empty() && all_zero(&d.spki_sha256))
    }

    fn queue() -> Result<RelayQueue> {
        Ok(RelayQueue {
            relay: relay_ref(true)?,
            sid: [0x11; 16],
            send_seed: SecretBytes::from_slice(&[0x22; 32])?,
            period_s: Period::S20,
        })
    }

    fn invitation() -> Result<InvitationV1> {
        Ok(InvitationV1 {
            relay: relay_ref(true)?,
            ld_id: [5; 16],
            link_key: SecretBytes::from_slice(&[6; 32])?,
            inviter_fp: [7; 32],
            inv_sid: [8; 16],
            inv_send_seed: SecretBytes::from_slice(&[9; 32])?,
            inv_period_s: Period::S80,
            expires: u64::MAX,
        })
    }

    #[test]
    fn zeroize_clears_every_byte_field() -> Result<()> {
        // RelayRef: relay_fp, onion, akc, direct.host (wiped and emptied), direct.spki_sha256; direct.port stays
        let mut r = relay_ref(true)?;
        assert!(!relay_clear(&r) && r.direct.is_some());
        assert!(
            r.direct
                .as_ref()
                .is_some_and(|d| !d.host.as_bytes().is_empty())
        );
        let port = r.direct.as_ref().map(|d| d.port);
        r.zeroize();
        assert!(relay_clear(&r));
        assert!(
            r.direct
                .as_ref()
                .is_some_and(|d| d.host.as_bytes().is_empty())
        );
        assert_eq!(
            r.direct.as_ref().map(|d| d.port),
            port,
            "the port is not wiped"
        );

        // RelayQueue: the relay reference, sid, send_seed; period_s stays
        let mut q = queue()?;
        q.zeroize();
        assert!(relay_clear(&q.relay));
        assert!(all_zero(&q.sid));
        assert!(all_zero(q.send_seed.expose_secret()));
        assert!(q.period_s == Period::S20, "the period is not wiped");

        // RouteDescriptor: both variants
        let mut route = RouteDescriptor::RelayQueue(queue()?);
        route.zeroize();
        let RouteDescriptor::RelayQueue(q) = &route else {
            return Err(Error::Rejected);
        };
        assert!(relay_clear(&q.relay) && all_zero(&q.sid) && all_zero(q.send_seed.expose_secret()));
        let mut unknown = RouteDescriptor::Unknown {
            kind: 7,
            blob: Zeroizing::new(vec![0xaa; 40]),
        };
        unknown.zeroize();
        let RouteDescriptor::Unknown { kind, blob } = &unknown else {
            return Err(Error::Rejected);
        };
        assert_eq!(*kind, 0);
        assert!(blob.is_empty(), "the blob is wiped and emptied");

        // InvitationV1: relay, ld_id, link_key, inviter_fp, inv_sid, inv_send_seed, expires; inv_period_s stays
        let mut inv = invitation()?;
        inv.zeroize();
        assert!(inv.inv_period_s == Period::S80, "the period is not wiped");
        assert!(relay_clear(&inv.relay));
        assert!(all_zero(&inv.ld_id) && all_zero(&inv.inviter_fp) && all_zero(&inv.inv_sid));
        assert!(all_zero(inv.link_key.expose_secret()));
        assert!(all_zero(inv.inv_send_seed.expose_secret()));
        assert_eq!(inv.expires, 0);
        Ok(())
    }

    /// The `Drop` of each type runs its wipe (no safe way to read freed memory, so the test observes the call, which
    /// `zeroize_clears_every_byte_field` shows wipes every byte field): a dropped value, and an invitation that
    /// `invitee_check` drops on its rejection path (expired). (Route lists dropped by a rejected `process` take the
    /// same `Drop`; that path is not exercised here.)
    #[test]
    fn dropped_invitation_is_wiped() -> Result<()> {
        wipe_log::take();
        drop(invitation()?);
        assert_eq!(wipe_log::take(), ["InvitationV1", "RelayRef"]);

        // the rejection path: expired (step 1), the invitation is dropped inside `invitee_check`
        let inv = invitation()?;
        let expires = inv.expires;
        assert_eq!(
            crate::inv::invitee_check(inv, &[], expires).err(),
            Some(Error::Rejected)
        );
        assert_eq!(wipe_log::take(), ["InvitationV1", "RelayRef"]);

        drop(RouteDescriptor::RelayQueue(queue()?));
        assert_eq!(
            wipe_log::take(),
            ["RouteDescriptor", "RelayQueue", "RelayRef"]
        );
        drop(RouteDescriptor::Unknown {
            kind: 2,
            blob: Zeroizing::new(vec![1]),
        });
        assert_eq!(wipe_log::take(), ["RouteDescriptor"]);
        drop(relay_ref(true)?);
        assert_eq!(wipe_log::take(), ["RelayRef"]);
        Ok(())
    }
}
