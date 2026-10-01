// SPDX-License-Identifier: AGPL-3.0-or-later
//! The inviter's keys and prekey store (spec §6.1): `IK_sig`/`IK_dh`, signed prekeys by generation, one-time
//! prekeys, the ratchet prekey `RPK_kem`, and the per-invitation records (§5.2).
//!
//! **Lifecycle (§6.1).** A new SPK generation (`SPK_dh`, `SPK_kem`, and its `RPK_kem`) every 7 days
//! ([`SPK_ROTATION_S`]); generations are kept by `spk_id`, and **a generation referenced by an unexpired
//! invitation is retained until that invitation expires** ([`MemoryPrekeyStore::retire_expired`]); its `RPK_kem`
//! has the same lifetime. An OPK is used for exactly one invitation and deleted by [`PrekeyStore::commit_accept`]
//! when a handshake with it succeeded (§6.6 step 4) or when its invitation expires.
//!
//! **Expiry is the record lifecycle's, not `accept`'s (ADR-044 (d)).** [`crate::hx::Responder::accept`] takes no
//! clock: the client offers it only the records of [`MemoryPrekeyStore::offered_records`] and retires the queue of
//! each record that [`MemoryPrekeyStore::retire_expired`] returns.
//!
//! **Persistence.** The in-memory store is the reference for the trait; the encrypted store of M7 implements the
//! same trait. `commit_accept` is the commit point of an accepted handshake: an implementation makes the deletion
//! and the record's consumption durable together with the new session state, and a failed `commit_accept` leaves the OPK in place (the handshake is
//! then rejected and the invitee's byte-identical retry is processed again, §6.5).

#[cfg(any(test, feature = "kat"))]
use secmp_crypto::sha256;
use secmp_crypto::{HybridSigningKey, Label, MlKem768Dk, MlKem1024Dk, SecretBytes, X25519Secret};

use crate::codec::Encode;
use crate::error::{Error, Result};
use crate::inv::{self, IssueError};
use crate::keys::{self, Ed25519Pk, HybridSig, X25519Pk};
use crate::sizes::HASH_LEN;
use crate::tr::Entropy;
use crate::wire::inv::{
    IksPublic, InvitationV1, LinkBlob, LinkDataV1, PrekeyBundle, Profile, RelayRef,
};
use crate::wire::{Id, Period};

/// A signed-prekey generation lasts 7 days (§6.1).
pub const SPK_ROTATION_S: u64 = 7 * 24 * 60 * 60;

/// `IK_dh`: the long-term X25519 identity secret (§6.1).
pub struct IkDhSecret(X25519Secret);

impl IkDhSecret {
    /// A key from its 32 secret bytes (clamped inside X25519).
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(X25519Secret::from_bytes(bytes)?))
    }

    /// A fresh key.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or locked memory.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self> {
        Ok(Self(entropy.x25519()?))
    }

    /// The public key.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a key of this type (the public key of a scalar is never of low order).
    pub fn public_key(&self) -> Result<X25519Pk> {
        X25519Pk::from_bytes(self.0.public_key().as_bytes())
    }

    pub(crate) const fn secret(&self) -> &X25519Secret {
        &self.0
    }
}

/// The inviter's identity: `IK_sig` (Ed25519 ‖ ML-DSA-65), `IK_dh` and the public `IKSPublic` (§6.2).
pub struct IdentityKeys {
    sig: HybridSigningKey,
    dh: IkDhSecret,
    public: IksPublic,
}

impl IdentityKeys {
    /// A fresh identity; draws `IK_sig` (ML-DSA `ξ`, Ed25519 seed) then `IK_dh`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or locked memory.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self> {
        let sig = entropy.hybrid_signing_key()?;
        let dh = IkDhSecret::generate(entropy)?;
        Self::from_parts(sig, dh)
    }

    /// An identity from its keys.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for keys of these types.
    pub fn from_parts(sig: HybridSigningKey, dh: IkDhSecret) -> Result<Self> {
        let vk = sig.verifying_key();
        let public = IksPublic {
            ik_ed25519: Ed25519Pk::from_bytes(vk.ed25519())?,
            ik_mldsa65: Box::new(*vk.mldsa65()),
            ik_dh: dh.public_key()?,
        };
        Ok(Self { sig, dh, public })
    }

    /// `IKSPublic` (§6.2).
    #[must_use]
    pub const fn public(&self) -> &IksPublic {
        &self.public
    }

    /// `fingerprint(IKSPublic)` (§6.2).
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a valid identity.
    pub fn fingerprint(&self) -> Result<[u8; HASH_LEN]> {
        fingerprint_of(&self.public)
    }

    /// The `IK_dh` secret.
    #[must_use]
    pub const fn ik_dh(&self) -> &IkDhSecret {
        &self.dh
    }

    /// The keys the initiator needs (no signing key: the initiator signs nothing, §6.6).
    #[must_use]
    pub const fn initiator_keys(&self) -> crate::hx::InitiatorKeys<'_> {
        crate::hx::InitiatorKeys {
            iks: &self.public,
            ik_dh: &self.dh,
        }
    }

    /// The keys the responder needs to accept (no signing key: R signs nothing in §6.6).
    #[must_use]
    pub const fn responder_keys(&self) -> crate::hx::ResponderKeys<'_> {
        crate::hx::ResponderKeys {
            iks: &self.public,
            ik_dh: &self.dh,
        }
    }
}

/// `SHA-256("SecMP-FP/1" ‖ encode(iks))` (§6.2).
///
/// # Errors
/// [`Error::Rejected`] never for a decoded or generated identity.
pub fn fingerprint_of(iks: &IksPublic) -> Result<[u8; HASH_LEN]> {
    Ok(*secmp_crypto::Fingerprint::of_encoded_iks(&iks.encode()?)?.as_bytes())
}

/// One signed-prekey generation: `SPK_dh`, `SPK_kem` (ML-KEM-1024) and the ratchet prekey `RPK_kem`
/// (ML-KEM-768), which has the SPK's lifetime (§6.1).
pub struct SpkGeneration {
    id: u32,
    created: u64,
    dh: X25519Secret,
    kem: MlKem1024Dk,
    rpk: MlKem768Dk,
}

impl SpkGeneration {
    /// A generation; draws `SPK_dh`, `SPK_kem`, `RPK_kem` in that order.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or locked memory.
    pub fn generate(id: u32, created: u64, entropy: &mut impl Entropy) -> Result<Self> {
        Ok(Self {
            id,
            created,
            dh: entropy.x25519()?,
            kem: entropy.mlkem1024()?,
            rpk: entropy.mlkem768()?,
        })
    }

    /// `spk_id`.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Unix seconds of creation.
    #[must_use]
    pub const fn created(&self) -> u64 {
        self.created
    }

    /// `SPK_dh` public.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a generated key.
    pub fn dh_public(&self) -> Result<X25519Pk> {
        X25519Pk::from_bytes(self.dh.public_key().as_bytes())
    }

    /// `SPK_kem` public.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a generated key.
    pub fn kem_public(&self) -> Result<keys::MlKem1024Ek> {
        keys::MlKem1024Ek::from_bytes(self.kem.encapsulation_key().as_bytes())
    }

    /// `RPK_kem` public.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a generated key.
    pub fn rpk_public(&self) -> Result<keys::MlKem768Ek> {
        keys::MlKem768Ek::from_bytes(self.rpk.encapsulation_key().as_bytes())
    }

    pub(crate) const fn dh_secret(&self) -> &X25519Secret {
        &self.dh
    }

    pub(crate) const fn kem_secret(&self) -> &MlKem1024Dk {
        &self.kem
    }

    /// A copy of the ratchet prekey secret for `init_responder` (which takes ownership; the store keeps its
    /// own copy until the generation is retired).
    pub(crate) fn rpk_copy(&self) -> Result<MlKem768Dk> {
        Ok(MlKem768Dk::from_seed(self.rpk.expose_seed())?)
    }

    /// A copy of the `SPK_dh` secret for `init_responder`.
    pub(crate) fn dh_copy(&self) -> Result<X25519Secret> {
        Ok(X25519Secret::from_bytes(self.dh.expose_secret())?)
    }
}

/// One one-time prekey (§6.1): `OPK_dh` and `OPK_kem` (ML-KEM-1024), single use.
pub struct OpkSecrets {
    id: u32,
    dh: X25519Secret,
    kem: MlKem1024Dk,
}

impl OpkSecrets {
    /// A one-time prekey; draws `OPK_dh`, `OPK_kem`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or locked memory.
    pub fn generate(id: u32, entropy: &mut impl Entropy) -> Result<Self> {
        Ok(Self {
            id,
            dh: entropy.x25519()?,
            kem: entropy.mlkem1024()?,
        })
    }

    /// `opk_id`.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// `OPK_dh` public.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a generated key.
    pub fn dh_public(&self) -> Result<X25519Pk> {
        X25519Pk::from_bytes(self.dh.public_key().as_bytes())
    }

    /// `OPK_kem` public.
    ///
    /// # Errors
    /// [`Error::Rejected`] never for a generated key.
    pub fn kem_public(&self) -> Result<keys::MlKem1024Ek> {
        keys::MlKem1024Ek::from_bytes(self.kem.encapsulation_key().as_bytes())
    }

    pub(crate) const fn dh_secret(&self) -> &X25519Secret {
        &self.dh
    }

    pub(crate) const fn kem_secret(&self) -> &MlKem1024Dk {
        &self.kem
    }
}

/// What the inviter persists per issued invitation until it is consumed or expired (§5.2): `ld_id`, `link_key`,
/// `spk_id`, `opk_id`, `expires`. (The link-data owner key and the invitation queue's recipient key are the
/// session layer's, M5–M7.)
pub struct InvitationRecord {
    /// Link-data id.
    pub ld_id: Id,
    /// The link key; never sent to the relay.
    pub link_key: SecretBytes<HASH_LEN>,
    /// The signed prekey the bundle names.
    pub spk_id: u32,
    /// The one-time prekey the bundle names.
    pub opk_id: u32,
    /// Unix seconds.
    pub expires: u64,
}

impl InvitationRecord {
    /// A copy (the link key is duplicated into locked memory): the caller that keeps its records in the same store
    /// it hands to [`crate::hx::Responder::accept`] copies the record first.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without locked memory.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            ld_id: self.ld_id,
            link_key: SecretBytes::from_slice(self.link_key.expose_secret())?,
            spk_id: self.spk_id,
            opk_id: self.opk_id,
            expires: self.expires,
        })
    }
}

/// What the responder reads from, and deletes from, the prekey store (§6.6). Retention, rotation and expiry are
/// the implementation's lifecycle ([`MemoryPrekeyStore`]); `spk` answers only for retained generations and `opk`
/// only for unused one-time prekeys.
pub trait PrekeyStore {
    /// The retained signed-prekey generation `spk_id`.
    fn spk(&self, spk_id: u32) -> Option<&SpkGeneration>;

    /// The unused one-time prekey `opk_id`.
    fn opk(&self, opk_id: u32) -> Option<&OpkSecrets>;

    /// Delete the one-time prekey (the OPK half of [`PrekeyStore::commit_accept`], §6.6 step 4).
    ///
    /// # Errors
    /// [`Error::Rejected`] if there is no such unused OPK (a second delete), or the deletion could not be made
    /// durable; nothing is deleted then.
    fn delete_opk(&mut self, opk_id: u32) -> Result<()>;

    /// The commit point of an accepted handshake (§6.6 step 4, §5.2 "until the invitation is consumed"): delete
    /// the one-time prekey **and** consume the invitation record of `ld_id`, both or neither (one durable
    /// transaction in a persistent store).
    ///
    /// # Errors
    /// [`Error::Rejected`] if the OPK or the record is absent or the commit could not be made durable; nothing is
    /// changed then.
    fn commit_accept(&mut self, opk_id: u32, ld_id: &Id) -> Result<()>;
}

/// An issued invitation: what goes to the invitee out of band and to the relay.
pub struct Issued {
    /// The invitation (a secret).
    pub invitation: InvitationV1,
    /// The sealed link data for `LINK_PUT`.
    pub blob: LinkBlob,
}

/// The parameters of [`MemoryPrekeyStore::issue_invitation`].
pub struct IssueParams {
    /// The inviter's relay.
    pub relay: RelayRef,
    /// The invitation queue's period.
    pub inv_period: Period,
    /// The inviter's profile for the link data.
    pub profile: Profile,
    /// Unix seconds of creation.
    pub now: u64,
    /// `expires` of the invitation.
    pub expires: u64,
    /// `spk_expiry` of the bundle; must be ≥ `expires` (§6.3).
    pub spk_expiry: u64,
}

/// The in-memory prekey store and invitation records: the reference implementation of [`PrekeyStore`].
pub struct MemoryPrekeyStore {
    generations: Vec<SpkGeneration>,
    opks: Vec<OpkSecrets>,
    records: Vec<InvitationRecord>,
    next_spk_id: u32,
    next_opk_id: u32,
}

impl Default for MemoryPrekeyStore {
    fn default() -> Self {
        Self::starting_at(1, 1)
    }
}

impl MemoryPrekeyStore {
    /// An empty store whose first signed-prekey and one-time-prekey ids are the given ones.
    #[must_use]
    pub const fn starting_at(first_signed_id: u32, first_onetime_id: u32) -> Self {
        Self {
            generations: Vec::new(),
            opks: Vec::new(),
            records: Vec::new(),
            next_spk_id: first_signed_id,
            next_opk_id: first_onetime_id,
        }
    }

    /// The current (newest) signed-prekey generation.
    #[must_use]
    pub fn current_spk(&self) -> Option<&SpkGeneration> {
        self.generations.last()
    }

    /// Start a new generation now.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness; [`Error::Rejected`] if the id space is exhausted.
    pub fn create_spk(&mut self, now: u64, entropy: &mut impl Entropy) -> Result<u32> {
        let id = self.next_spk_id;
        let next = id.checked_add(1).ok_or(Error::Rejected)?;
        let generation = SpkGeneration::generate(id, now, entropy)?;
        self.generations.push(generation);
        self.next_spk_id = next;
        Ok(id)
    }

    /// §6.1: a new generation if there is none or the current one is 7 days old. Returns the current `spk_id`.
    ///
    /// # Errors
    /// As [`MemoryPrekeyStore::create_spk`].
    pub fn rotate_if_due(&mut self, now: u64, entropy: &mut impl Entropy) -> Result<u32> {
        let due = match self.current_spk() {
            None => true,
            Some(g) => g.created.saturating_add(SPK_ROTATION_S) <= now,
        };
        if due {
            self.create_spk(now, entropy)
        } else {
            self.current_spk()
                .map(SpkGeneration::id)
                .ok_or(Error::Rejected)
        }
    }

    /// A new one-time prekey; returns its id.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness; [`Error::Rejected`] if the id space is exhausted.
    pub fn issue_opk(&mut self, entropy: &mut impl Entropy) -> Result<u32> {
        let id = self.next_opk_id;
        let next = id.checked_add(1).ok_or(Error::Rejected)?;
        let opk = OpkSecrets::generate(id, entropy)?;
        self.opks.push(opk);
        self.next_opk_id = next;
        Ok(id)
    }

    /// The signed bundle of `spk_id` and `opk_id` (§6.3): `sig` = HybridSign(`IK_sig`, `"SecMP-HX/1 bundle"`,
    /// the encoded fields before `sig` ‖ `IK_dh`), hedged with randomness from `entropy`.
    ///
    /// # Errors
    /// [`Error::Rejected`] if either prekey is not held; [`Error::Unavailable`] without randomness.
    pub fn bundle(
        &self,
        identity: &IdentityKeys,
        spk_id: u32,
        opk_id: u32,
        spk_expiry: u64,
        entropy: &mut impl Entropy,
    ) -> Result<PrekeyBundle> {
        let spk = self.spk(spk_id).ok_or(Error::Rejected)?;
        let opk = self.opk(opk_id).ok_or(Error::Rejected)?;
        let spk_dh = spk.dh_public()?;
        let spk_kem = spk.kem_public()?;
        let rpk_kem = spk.rpk_public()?;
        let opk_dh = opk.dh_public()?;
        let opk_kem = opk.kem_public()?;
        // the signed message is the one layout of the wire type (`PrekeyBundle::signed_fields`, §6.3): the bundle is
        // built with a placeholder signature (the Ed25519 base point as `R`, `S` = 0: a valid encoding), which the
        // signed fields do not cover, and then given its real signature
        let mut placeholder = [0_u8; crate::sizes::HYBRID_SIG_LEN];
        placeholder[0] = 0x58;
        for b in placeholder.iter_mut().take(32).skip(1) {
            *b = 0x66;
        }
        let unsigned = PrekeyBundle {
            spk_id,
            spk_dh,
            spk_kem,
            rpk_kem,
            spk_expiry,
            opk_id,
            opk_dh,
            opk_kem,
            sig: HybridSig::from_bytes(&placeholder)?,
        };
        let message = inv::bundle_signed_message(&unsigned, identity.public())?;
        let sig = entropy.sign(&identity.sig, Label::HxBundle, &message)?;
        Ok(PrekeyBundle {
            sig: HybridSig::from_bytes(sig.as_bytes())?,
            ..unsigned
        })
    }

    /// Record an issued invitation (§5.2). Both prekeys it names must be held.
    ///
    /// # Errors
    /// [`Error::Rejected`] if a prekey is not held or the `ld_id` is already recorded.
    pub fn add_record(&mut self, record: InvitationRecord) -> Result<()> {
        if self.spk(record.spk_id).is_none()
            || self.opk(record.opk_id).is_none()
            || self.records.iter().any(|r| r.ld_id == record.ld_id)
        {
            return Err(Error::Rejected);
        }
        self.records.push(record);
        Ok(())
    }

    /// The record of `ld_id`.
    #[must_use]
    pub fn record(&self, ld_id: &Id) -> Option<&InvitationRecord> {
        self.records.iter().find(|r| &r.ld_id == ld_id)
    }

    /// Consume the record of `ld_id` (the invitation was used, §5.2): it is no longer offered and its link key is
    /// dropped (zeroized). The signed-prekey generation it referenced stays until [`Self::retire_expired`] finds
    /// no other unexpired reference.
    ///
    /// # Errors
    /// [`Error::Rejected`] if there is no such record.
    pub fn consume_record(&mut self, ld_id: &Id) -> Result<()> {
        let at = self
            .records
            .iter()
            .position(|r| &r.ld_id == ld_id)
            .ok_or(Error::Rejected)?;
        self.records.remove(at);
        Ok(())
    }

    /// The records of unexpired invitations (`expires` > `now`): the only ones offered to `accept` (ADR-044 (d)).
    #[must_use]
    pub fn offered_records(&self, now: u64) -> Vec<&InvitationRecord> {
        self.records.iter().filter(|r| r.expires > now).collect()
    }

    /// Retire what has expired at `now`: the records with `expires` ≤ `now` (their link-data queue and invitation
    /// queue are the caller's to retire — the returned `ld_id`s name them), their one-time prekeys, and every
    /// signed-prekey generation that is neither the current one nor referenced by a remaining record (its
    /// `RPK_kem` goes with it). Dropped secrets are zeroized.
    pub fn retire_expired(&mut self, now: u64) -> Vec<Id> {
        let mut retired = Vec::new();
        let mut dead_opks = Vec::new();
        self.records.retain(|r| {
            if r.expires > now {
                true
            } else {
                retired.push(r.ld_id);
                dead_opks.push(r.opk_id);
                false
            }
        });
        self.opks.retain(|o| !dead_opks.contains(&o.id));
        let current = self.generations.last().map(SpkGeneration::id);
        let referenced: Vec<u32> = self.records.iter().map(|r| r.spk_id).collect();
        self.generations
            .retain(|g| Some(g.id) == current || referenced.contains(&g.id));
        retired
    }

    /// The ids of the held signed-prekey generations, ascending.
    #[must_use]
    pub fn spk_ids(&self) -> Vec<u32> {
        self.generations.iter().map(SpkGeneration::id).collect()
    }

    /// The ids of the unused one-time prekeys, ascending.
    #[must_use]
    pub fn opk_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.opks.iter().map(OpkSecrets::id).collect();
        ids.sort_unstable();
        ids
    }

    /// Issue an invitation (§5.2, §5.4, §6.3): rotate the SPK if due, take a fresh OPK, sign the bundle, draw
    /// `ld_id`, `link_key`, `inv_sid`, `inv_send_seed` and the blob nonce, seal the link data, and record the
    /// invitation. The inviter-side bounds are enforced here ([`inv::check_issue_bounds`]).
    ///
    /// # Errors
    /// [`IssueError`]: the bounds, or a cryptographic or environment error. Nothing is recorded on error.
    pub fn issue_invitation(
        &mut self,
        identity: &IdentityKeys,
        params: IssueParams,
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Issued, IssueError> {
        inv::check_issue_bounds(params.now, params.expires, params.spk_expiry)?;
        let spk_id = self.rotate_if_due(params.now, entropy)?;
        let opk_id = self.issue_opk(entropy)?;
        let issued = self.issue_with(identity, params, spk_id, opk_id, entropy);
        if issued.is_err() {
            // the OPK was issued for this invitation only
            self.opks.retain(|o| o.id != opk_id);
        }
        issued
    }

    fn issue_with(
        &mut self,
        identity: &IdentityKeys,
        params: IssueParams,
        spk_id: u32,
        opk_id: u32,
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Issued, IssueError> {
        let bundle = self.bundle(identity, spk_id, opk_id, params.spk_expiry, entropy)?;
        let ld_id: Id = *entropy.secret::<16>()?.expose_secret();
        let link_key = entropy.secret::<HASH_LEN>()?;
        let inv_sid: Id = *entropy.secret::<16>()?.expose_secret();
        let inv_send_seed = entropy.secret::<HASH_LEN>()?;
        let nonce = entropy.nonce()?;
        let link_data = LinkDataV1 {
            inviter_iks: identity.public().clone(),
            bundle,
            profile: params.profile,
            created: params.now,
        };
        let blob = inv::seal_blob(&ld_id, &link_key, nonce, &link_data)?;
        let record_key = SecretBytes::<HASH_LEN>::from_slice(link_key.expose_secret())?;
        let invitation = InvitationV1 {
            relay: params.relay,
            ld_id,
            link_key,
            inviter_fp: identity.fingerprint()?,
            inv_sid,
            inv_send_seed,
            inv_period_s: params.inv_period,
            expires: params.expires,
        };
        self.add_record(InvitationRecord {
            ld_id,
            link_key: record_key,
            spk_id,
            opk_id,
            expires: params.expires,
        })?;
        Ok(Issued { invitation, blob })
    }

    /// A deep copy, for tests: duplicates every secret into locked memory (feature `kat` or tests only: a shipped
    /// build has no way to copy prekey secrets out of a store).
    ///
    /// # Errors
    /// [`Error::Unavailable`] without locked memory.
    #[cfg(any(test, feature = "kat"))]
    pub fn duplicate_kat(&self) -> Result<Self> {
        let mut generations = Vec::new();
        for g in &self.generations {
            generations.push(SpkGeneration {
                id: g.id,
                created: g.created,
                dh: X25519Secret::from_bytes(g.dh.expose_secret())?,
                kem: MlKem1024Dk::from_seed(g.kem.expose_seed())?,
                rpk: g.rpk_copy()?,
            });
        }
        let mut opks = Vec::new();
        for o in &self.opks {
            opks.push(OpkSecrets {
                id: o.id,
                dh: X25519Secret::from_bytes(o.dh.expose_secret())?,
                kem: MlKem1024Dk::from_seed(o.kem.expose_seed())?,
            });
        }
        let mut records = Vec::new();
        for r in &self.records {
            records.push(r.duplicate()?);
        }
        Ok(Self {
            generations,
            opks,
            records,
            next_spk_id: self.next_spk_id,
            next_opk_id: self.next_opk_id,
        })
    }

    /// A digest of everything the store holds — ids and secret bytes of every SPK generation, RPK and OPK, and
    /// every record — for the tests' "unchanged" assertions (feature `kat` or tests only: it hashes secrets).
    #[cfg(any(test, feature = "kat"))]
    #[must_use]
    pub fn digest_kat(&self) -> [u8; 32] {
        let mut m = Vec::new();
        for g in &self.generations {
            m.extend_from_slice(&g.id.to_be_bytes());
            m.extend_from_slice(&g.created.to_be_bytes());
            m.extend_from_slice(g.dh.expose_secret());
            m.extend_from_slice(g.kem.expose_seed());
            m.extend_from_slice(g.rpk.expose_seed());
        }
        m.push(0xff);
        for o in &self.opks {
            m.extend_from_slice(&o.id.to_be_bytes());
            m.extend_from_slice(o.dh.expose_secret());
            m.extend_from_slice(o.kem.expose_seed());
        }
        m.push(0xff);
        for r in &self.records {
            m.extend_from_slice(&r.ld_id);
            m.extend_from_slice(r.link_key.expose_secret());
            m.extend_from_slice(&r.spk_id.to_be_bytes());
            m.extend_from_slice(&r.opk_id.to_be_bytes());
            m.extend_from_slice(&r.expires.to_be_bytes());
        }
        sha256(&[&m])
    }
}

impl PrekeyStore for MemoryPrekeyStore {
    fn spk(&self, spk_id: u32) -> Option<&SpkGeneration> {
        self.generations.iter().find(|g| g.id == spk_id)
    }

    fn opk(&self, opk_id: u32) -> Option<&OpkSecrets> {
        self.opks.iter().find(|o| o.id == opk_id)
    }

    fn commit_accept(&mut self, opk_id: u32, ld_id: &Id) -> Result<()> {
        // both must exist before either is touched
        if self.opk(opk_id).is_none() || self.record(ld_id).is_none() {
            return Err(Error::Rejected);
        }
        self.consume_record(ld_id)?;
        self.delete_opk(opk_id)
    }

    fn delete_opk(&mut self, opk_id: u32) -> Result<()> {
        let at = self
            .opks
            .iter()
            .position(|o| o.id == opk_id)
            .ok_or(Error::Rejected)?;
        self.opks.remove(at);
        Ok(())
    }
}
