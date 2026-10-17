// SPDX-License-Identifier: AGPL-3.0-or-later
//! Queue capabilities (spec §12.1): opaque, serialisable, secret.
//!
//! A [`RecvCap`] lets its holder `FETCH` and delete the queue (it holds the recipient key's seed); a [`SendCap`] lets
//! its holder `SEND` to it (the sender key's seed). Neither exposes a field: they are created by the transport,
//! compared in constant time (`ct_eq`, no `PartialEq`), and persisted through [`RecvCap::to_bytes`] / [`SendCap::to_bytes`]. A capability
//! names no relay; the transport it is used with does (spec §9.1: the ids are derived, so the same keys re-create the
//! same queue after a relay restart).

use secmp_crypto::{Choice, ConstantTimeEq, Ed25519SigningKey, SecretBytes, Zeroizing};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::link::ids;
use secmp_proto::wire::Id;

use crate::error::{Error, Result};

/// Version byte of a serialised capability.
const CAP_VERSION: u8 = 0x01;
/// Serialised length: `ver` 1 ‖ id 16 ‖ seed 32.
pub const CAP_LEN: usize = 1 + 16 + 32;

/// A queue as `FETCH_MULTI` and the dedup sets name it: its recipient id `rid` (spec §9.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueueRef(Id);

impl QueueRef {
    /// The queue with this recipient id.
    #[must_use]
    pub const fn from_rid(rid: Id) -> Self {
        Self(rid)
    }

    /// The recipient id.
    #[must_use]
    pub const fn rid(&self) -> &Id {
        &self.0
    }
}

impl core::fmt::Debug for QueueRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // an id is a linkable identifier: never printed (CLAUDE.md §4)
        f.write_str("QueueRef(..)")
    }
}

/// The Ed25519 public key of a 32-byte seed.
pub(crate) fn pk_of(seed: &SecretBytes<32>) -> Result<Ed25519Pk> {
    let key = Ed25519SigningKey::from_seed(seed.expose_secret())?;
    Ok(Ed25519Pk::from_bytes(key.verifying_key().as_bytes())?)
}

fn encode(id: &Id, seed: &SecretBytes<32>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(CAP_LEN));
    out.push(CAP_VERSION);
    out.extend_from_slice(id);
    out.extend_from_slice(seed.expose_secret());
    out
}

fn decode(bytes: &[u8]) -> Result<(Id, SecretBytes<32>)> {
    let (ver, rest) = bytes.split_first().ok_or(Error::Invalid)?;
    let (id, seed) = rest.split_first_chunk::<16>().ok_or(Error::Invalid)?;
    if *ver != CAP_VERSION || seed.len() != 32 {
        return Err(Error::Invalid);
    }
    Ok((*id, SecretBytes::from_slice(seed)?))
}

fn same(a: (&Id, &SecretBytes<32>), b: (&Id, &SecretBytes<32>)) -> Choice {
    a.0.as_slice().ct_eq(b.0.as_slice()) & a.1.ct_eq(b.1)
}

/// The recipient's capability of a queue: `rid` and the recipient key's seed.
///
/// It has no `PartialEq` (it holds a seed; M05 review F-5): compare with [`ConstantTimeEq::ct_eq`].
///
/// ```compile_fail,E0369
/// fn same(a: &secmp_transport::RecvCap, b: &secmp_transport::RecvCap) -> bool {
///     a == b
/// }
/// ```
pub struct RecvCap {
    rid: Id,
    seed: SecretBytes<32>,
}

impl RecvCap {
    /// The capability of the recipient key with this seed (`rid` derived, spec §9.1).
    ///
    /// # Errors
    /// [`Error::Invalid`] / [`Error::Unavailable`] if the seed does not yield a key.
    pub fn from_seed(seed: &SecretBytes<32>) -> Result<Self> {
        let rid = ids::rid(&pk_of(seed)?)?;
        Ok(Self {
            rid,
            seed: SecretBytes::from_slice(seed.expose_secret())?,
        })
    }

    /// The queue this capability names.
    #[must_use]
    pub const fn queue(&self) -> QueueRef {
        QueueRef(self.rid)
    }

    pub(crate) const fn rid(&self) -> &Id {
        &self.rid
    }

    pub(crate) fn key(&self) -> Result<Ed25519SigningKey> {
        Ok(Ed25519SigningKey::from_seed(self.seed.expose_secret())?)
    }

    pub(crate) fn public_key(&self) -> Result<Ed25519Pk> {
        pk_of(&self.seed)
    }

    /// The serialised form (49 bytes), to persist.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        encode(&self.rid, &self.seed)
    }

    /// Restore a capability.
    ///
    /// # Errors
    /// [`Error::Invalid`] unless `bytes` is a serialised capability whose `rid` is the one its key derives.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (rid, seed) = decode(bytes)?;
        let cap = Self::from_seed(&seed)?;
        if !bool::from(cap.rid.as_slice().ct_eq(rid.as_slice())) {
            return Err(Error::Invalid);
        }
        Ok(cap)
    }
}

impl ConstantTimeEq for RecvCap {
    fn ct_eq(&self, other: &Self) -> Choice {
        same((&self.rid, &self.seed), (&other.rid, &other.seed))
    }
}

impl core::fmt::Debug for RecvCap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecvCap(..)")
    }
}

/// The sender's capability of a queue: `sid` and the sender key's seed.
///
/// It has no `PartialEq` (it holds a seed; M05 review F-5): compare with [`ConstantTimeEq::ct_eq`].
///
/// ```compile_fail,E0369
/// fn same(a: &secmp_transport::SendCap, b: &secmp_transport::SendCap) -> bool {
///     a == b
/// }
/// ```
pub struct SendCap {
    sid: Id,
    seed: SecretBytes<32>,
}

impl SendCap {
    /// The capability for the queue of recipient key `recv_pk` and the sender key with this seed (`sid` derived,
    /// spec §9.1) — what a route naming the queue (§9.8) becomes.
    ///
    /// # Errors
    /// [`Error::Invalid`] / [`Error::Unavailable`] if the seed does not yield a key.
    pub fn from_seed(recv_pk: &Ed25519Pk, seed: &SecretBytes<32>) -> Result<Self> {
        let sid = ids::sid(recv_pk, &pk_of(seed)?)?;
        Ok(Self {
            sid,
            seed: SecretBytes::from_slice(seed.expose_secret())?,
        })
    }

    /// The capability of a route's `sid` and `send_seed` (spec §9.8), as given; the `sid` is the relay's to check.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the seed cannot be held.
    pub fn from_route(sid: Id, seed: &SecretBytes<32>) -> Result<Self> {
        Ok(Self {
            sid,
            seed: SecretBytes::from_slice(seed.expose_secret())?,
        })
    }

    /// The sender id of the queue (spec §9.1).
    #[must_use]
    pub const fn sid(&self) -> &Id {
        &self.sid
    }

    pub(crate) fn key(&self) -> Result<Ed25519SigningKey> {
        Ok(Ed25519SigningKey::from_seed(self.seed.expose_secret())?)
    }

    /// The serialised form (49 bytes), to persist.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        encode(&self.sid, &self.seed)
    }

    /// Restore a capability.
    ///
    /// # Errors
    /// [`Error::Invalid`] unless `bytes` is a serialised capability.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (sid, seed) = decode(bytes)?;
        Ok(Self { sid, seed })
    }
}

impl ConstantTimeEq for SendCap {
    fn ct_eq(&self, other: &Self) -> Choice {
        same((&self.sid, &self.seed), (&other.sid, &other.seed))
    }
}

impl core::fmt::Debug for SendCap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SendCap(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(first: u8, last: u8) -> Result<SecretBytes<32>> {
        let mut bytes = [0x42_u8; 32];
        if let Some(b) = bytes.first_mut() {
            *b = first;
        }
        if let Some(b) = bytes.last_mut() {
            *b = last;
        }
        Ok(SecretBytes::from_slice(&bytes)?)
    }

    /// G-02 (F-5, R-123): the capabilities hold seeds and have no `PartialEq` (the `compile_fail,E0369` doctests on
    /// the types pin that); `ct_eq` is 1 for equal and 0 for seeds that differ in one byte.
    #[test]
    fn caps_have_no_partial_eq() -> Result<()> {
        let a = RecvCap::from_seed(&seed(1, 2)?)?;
        let same = RecvCap::from_seed(&seed(1, 2)?)?;
        let other = RecvCap::from_seed(&seed(1, 3)?)?;
        assert_eq!(a.ct_eq(&same).unwrap_u8(), 1);
        assert_eq!(a.ct_eq(&other).unwrap_u8(), 0);

        let recv_pk = a.public_key()?;
        let s = SendCap::from_seed(&recv_pk, &seed(5, 6)?)?;
        let s_same = SendCap::from_seed(&recv_pk, &seed(5, 6)?)?;
        let s_other = SendCap::from_seed(&recv_pk, &seed(5, 7)?)?;
        assert_eq!(s.ct_eq(&s_same).unwrap_u8(), 1);
        assert_eq!(s.ct_eq(&s_other).unwrap_u8(), 0);
        // same sid, one differing seed byte: the seed alone decides
        let sid = *s.sid();
        let x = SendCap::from_route(sid, &seed(5, 6)?)?;
        let y = SendCap::from_route(sid, &seed(5, 7)?)?;
        assert_eq!(x.ct_eq(&y).unwrap_u8(), 0);
        Ok(())
    }
}
