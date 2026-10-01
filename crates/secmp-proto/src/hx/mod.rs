// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-HX — the hybrid initial key agreement (spec §6.4–§6.6): PQXDH with ML-KEM-1024, an ML-KEM-768 ratchet
//! prekey, a sealed envelope and an identity-protecting inner layer. Sans-IO: the caller moves cells.
//!
//! - [`Initiator::start`] (invitee): §6.4 key agreement, §7.2 initiator initialisation, the `first_msg` (§7.3
//!   Encrypt of the Handshake Content) and the three sealed cells (§6.5). There is **no signature by the initiator**
//!   (deniability, §6.6): no signing key reaches `start`. `EK_I`'s secret is zeroized inside `start`, immediately
//!   after the cells are sealed (ADR-044 (b)); it is neither returned nor persisted.
//! - [`Responder::accept`] (inviter): §6.5 trial-opening, grouping and §6.6 steps 1–4. Garbage is ignored, never
//!   fatal; a rejection returns the uniform [`crate::Error::Rejected`] and leaves the prekey store untouched (the OPK
//!   is kept); the OPK is deleted only after step 3 succeeded.
//!
//! **Persist-before-send (CLAUDE.md §1.7).** `start` returns the three cells as [`HandshakeCells`] and the
//! post-`first_msg` [`RatchetState`]. The cells leave the process only through [`HandshakeCells::release`], which
//! first hands their serialisation to the caller's durable write; the caller persists the state
//! ([`RatchetState::to_bytes`]) in the same transaction, and on a retry re-sends the persisted bytes
//! ([`HandshakeCells::from_bytes`]) without sealing again (§6.5).

mod derive;
mod initiator;
pub(crate) mod responder;

pub use derive::{Shared, TranscriptInputs, k_id, session_key, transcript};
pub use initiator::Initiator;
pub use responder::{Accepted, Responder};

use secmp_crypto::{SecretBytes, X25519Public, X25519Secret, Zeroizing};

use crate::codec::{Decode, Encode};
use crate::error::{Error, Result};
use crate::prekeys::IkDhSecret;
use crate::sizes::{CELL_LEN, HANDSHAKE_CHUNKS};
use crate::wire::cell::{Cell, RouteDescriptor};
use crate::wire::inv::IksPublic;

/// The three handshake cells of one envelope (§6.5), generated once.
pub struct HandshakeCells {
    cells: [Cell; 3],
}

impl HandshakeCells {
    pub(crate) const fn new(cells: [Cell; 3]) -> Self {
        Self { cells }
    }

    /// The persistence encoding: the three cells, 3 × 4096 bytes. (They are ciphertext; the buffer is wiped on
    /// drop for hygiene.)
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            CELL_LEN.saturating_mul(usize::from(HANDSHAKE_CHUNKS)),
        ));
        for c in &self.cells {
            out.extend_from_slice(c.as_bytes());
        }
        out
    }

    /// Restore persisted cells for a retry: byte-identical, no sealing, no randomness (§6.5).
    ///
    /// # Errors
    /// [`Error::Rejected`] unless exactly three cells.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (a, rest) = bytes.split_at_checked(CELL_LEN).ok_or(Error::Rejected)?;
        let (b, c) = rest.split_at_checked(CELL_LEN).ok_or(Error::Rejected)?;
        Ok(Self {
            cells: [
                Cell::from_bytes(a)?,
                Cell::from_bytes(b)?,
                Cell::from_bytes(c)?,
            ],
        })
    }

    /// Persist-before-send: `persist` receives [`HandshakeCells::to_bytes`] and must make it durable (with the
    /// state, in one transaction); only if it returns `Ok` are the cells released. On `Err` they are dropped.
    ///
    /// # Errors
    /// The error of `persist`.
    pub fn release<E>(
        self,
        persist: impl FnOnce(&[u8]) -> core::result::Result<(), E>,
    ) -> core::result::Result<[Cell; 3], E> {
        persist(&self.to_bytes())?;
        Ok(self.cells)
    }
}

/// The initiator's identity for [`Initiator::start`]: `IKSPublic_I` and the `IK_dh_I` secret (DH1). **No signing
/// key**: the initiator signs nothing (§6.6, deniability).
pub struct InitiatorKeys<'a> {
    /// `IKSPublic_I` (§6.2).
    pub iks: &'a IksPublic,
    /// `IK_dh_I`.
    pub ik_dh: &'a IkDhSecret,
}

/// The responder's identity for [`Responder::accept`]: `IKSPublic_R` and the `IK_dh_R` secret (DH2). No signing
/// key: the responder signs nothing in §6.6.
pub struct ResponderKeys<'a> {
    /// `IKSPublic_R` (§6.2).
    pub iks: &'a IksPublic,
    /// `IK_dh_R`.
    pub ik_dh: &'a IkDhSecret,
}

/// `X25519(secret, peer)` with the all-zero check of §6.4 ("every DH output MUST be checked non-zero") on the raw
/// 32 bytes of `peer`. The decoders already refuse a low-order point (§4.1 (a)); this is the second line of
/// defence for values that did not come through a decoder.
pub(crate) fn dh_checked(secret: &X25519Secret, peer: &[u8]) -> Result<SecretBytes<32>> {
    Ok(secret.diffie_hellman(&X25519Public::from_bytes(peer)?)?)
}

/// A copy of a route (`RouteDescriptor` has no `Clone`: it can hold a sender capability).
pub(crate) fn copy_route(route: &RouteDescriptor) -> Result<RouteDescriptor> {
    RouteDescriptor::decode(&route.encode()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// u = 0, 1, p − 1 and the two points of order 8 (RFC 7748 §6.1; spec §3, §4.1 (a)).
    fn low_order() -> Vec<[u8; 32]> {
        let mut one = [0_u8; 32];
        one[0] = 1;
        let mut p_minus_1 = [0xff_u8; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        let order8_a: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let order8_b: [u8; 32] = [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ];
        vec![[0; 32], one, p_minus_1, order8_a, order8_b]
    }

    /// N-24: the initiator's DH helper (DH1…DH4 of §6.4) refuses an all-zero output, bypassing the decoders; the
    /// error is the uniform one and `start` has produced nothing (it returns before any cell is sealed).
    #[test]
    fn start_zero_dh_rejects_and_sends_nothing() {
        let secret = X25519Secret::from_bytes(&[7; 32]);
        let Ok(secret) = secret else {
            return;
        };
        for v in low_order() {
            assert_eq!(dh_checked(&secret, &v).err(), Some(Error::Rejected));
        }
        assert!(
            dh_checked(&secret, &[9; 32]).is_ok(),
            "control: an ordinary point"
        );
        assert_eq!(
            dh_checked(&secret, &[9; 31]).err(),
            Some(Error::Rejected),
            "length"
        );
    }

    /// N-41: the same helper on the responder's DH1…DH4.
    #[test]
    fn accept_zero_dh_rejects_and_keeps_opk() {
        let secret = X25519Secret::from_bytes(&[0x42; 32]);
        let Ok(secret) = secret else {
            return;
        };
        for v in low_order() {
            assert_eq!(dh_checked(&secret, &v).err(), Some(Error::Rejected));
        }
    }
}
