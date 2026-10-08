// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-HX — the hybrid initial key agreement (spec §6.4–§6.6): PQXDH with ML-KEM-1024, an ML-KEM-768 ratchet
//! prekey, a sealed envelope and an identity-protecting inner layer. Sans-IO: the caller moves cells.
//!
//! - [`Initiator::start`] (invitee): §6.4 key agreement, §7.2 initiator initialisation, the `first_msg` (§7.3
//!   Encrypt of the Handshake Content) and the three sealed cells (§6.5). There is **no signature by the initiator**
//!   (deniability, §6.6): no signing key reaches `start`. `EK_I`'s secret is a local of `agree` (the §6.4 derivation) and is
//!   zeroized when `agree` returns — after `SK` and `K_id` are derived, before the ratchet is initialised and the cells
//!   are sealed (ADR-044 (b)); it is neither returned nor persisted.
//! - [`Responder::accept`] (inviter): §6.5 trial-opening, grouping and §6.6 steps 1–4. Garbage is ignored, never
//!   fatal; a rejection returns the uniform [`crate::Error::Rejected`] and leaves the prekey store untouched (the OPK
//!   is kept); the OPK is deleted (with the record's consumption, `PrekeyStore::commit_accept`) only after step 3 succeeded.
//!
//! **Persist-before-send (CLAUDE.md §1.7).** `start` returns the three cells as [`HandshakeCells`] and the
//! post-`first_msg` [`RatchetState`]. The cells leave the process only through `release(state, persist)`
//! ([`HandshakeCells::release`]), which first hands their serialisation **and the serialisation of the caller's live
//! state at release time** to the caller's durable write (one transaction), and on a retry re-sends the persisted bytes
//! ([`PersistedCells::from_bytes`]) without sealing again (§6.5).

mod derive;
mod initiator;
pub(crate) mod responder;

pub use derive::{Shared, TranscriptInputs, k_id, session_key, transcript};
pub use initiator::Initiator;
#[cfg(feature = "kat")]
pub use responder::ACCEPT_SITE_KAT;
pub use responder::{Accepted, Responder};

use secmp_crypto::{SecretBytes, X25519Public, X25519Secret};

use crate::codec::{Decode, Encode, Zeroizing};
use crate::error::{Error, Result};
use crate::prekeys::IkDhSecret;
use crate::sizes::{CELL_LEN, HANDSHAKE_CHUNKS};
use crate::tr::RatchetState;
use crate::wire::cell::{Cell, RouteDescriptor};
use crate::wire::inv::IksPublic;

/// The three handshake cells of one envelope (§6.5), generated once: the cells are released only with the
/// initiator's state in the same persist call (`release(state, persist)`, [`HandshakeCells::release`]), so a caller
/// cannot make the cells durable without the state (M4 verifier V-6, M3 review F13). The state is the caller's live
/// one at release time, not a snapshot taken at `start` (M4 review C-8, R-22). The cells are reachable only through
/// `release`:
///
/// ```compile_fail,E0624
/// fn bypass(cells: secmp_proto::hx::HandshakeCells) {
///     let _ = cells.to_bytes();
/// }
/// ```
///
/// (test `handshake_cells_expose_no_cells_before_release`)
pub struct HandshakeCells {
    cells: [Cell; 3],
}

fn join_cells(cells: &[Cell; 3]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        CELL_LEN.saturating_mul(usize::from(HANDSHAKE_CHUNKS)),
    ));
    for c in cells {
        out.extend_from_slice(c.as_bytes());
    }
    out
}

impl HandshakeCells {
    pub(crate) fn new(cells: [Cell; 3]) -> Self {
        Self { cells }
    }

    /// The persistence encoding of the cells: 3 × 4096 bytes. (They are ciphertext; the buffer is wiped on drop for
    /// hygiene.) Crate-private: [`HandshakeCells::release`] is the only way out (persist-before-send).
    #[must_use]
    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        join_cells(&self.cells)
    }

    /// The only way to obtain the cells; `persist` must return `Ok` first. Persist-before-send: `persist` receives the
    /// cells ([`HandshakeCells::to_bytes`]) and the serialisation (`RatchetStateV1`) of `state` — the caller's current
    /// initiator state, serialised now, at release time (M4 review C-8, R-22: a dummy sealed after `start` has advanced
    /// `n_s`, and a snapshot from `start` would roll it back) — and must make **both** durable in one transaction; only
    /// if it returns `Ok` are the cells released. On `Err` they are dropped.
    ///
    /// # Errors
    /// The error of `persist`; `E::from` the error of [`RatchetState::to_bytes`] if `state` cannot be serialised — then `persist` is not
    /// called and no cell is released.
    pub fn release<E: From<Error>>(
        self,
        state: &RatchetState,
        persist: impl FnOnce(&[u8], &[u8]) -> core::result::Result<(), E>,
    ) -> core::result::Result<[Cell; 3], E> {
        let state_bytes = state.to_bytes()?;
        persist(&self.to_bytes(), &state_bytes)?;
        Ok(self.cells)
    }
}

/// Handshake cells restored from durable storage for a retry (§6.5): byte-identical, no sealing, no randomness.
pub struct PersistedCells {
    cells: [Cell; 3],
}

impl PersistedCells {
    /// Restore persisted cells.
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

    /// The cells to send again.
    #[must_use]
    pub fn into_cells(self) -> [Cell; 3] {
        self.cells
    }

    /// The persistence encoding (equal to the bytes restored).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        join_cells(&self.cells)
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
    #[cfg(feature = "kat")]
    responder::ACCEPT_SITE_KAT.set(Some("x25519"));
    Ok(secret.diffie_hellman(&X25519Public::from_bytes(peer)?)?)
}

/// A copy of a route (`RouteDescriptor` has no `Clone`: it can hold a sender capability).
pub(crate) fn copy_route(route: &RouteDescriptor) -> Result<RouteDescriptor> {
    RouteDescriptor::decode(&route.encode()?)
}

#[cfg(test)]
mod tests;
