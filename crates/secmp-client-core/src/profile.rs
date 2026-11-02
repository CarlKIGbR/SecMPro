// SPDX-License-Identifier: AGPL-3.0-or-later
//! The profile (spec §6.1, §6.2): the identity key set, the signed-prekey generations and the one-time prekeys, held in
//! the encrypted store. Nothing secret is resident: every operation loads what it needs from the sealed rows, uses it for
//! one step and drops it (zeroizing; Q173).
//!
//! **Rows.** `identity` row 1: `secret` = the 97-byte identity section `ver ‖ ed25519_seed ‖ mldsa65_seed ‖ x25519_secret`
//! (Q143), sealed; `fingerprint` = `fingerprint(IKSPublic)` (§6.2). `prekeys`: kind [`KIND_SPK`] one row per signed-prekey
//! generation (`SpkGeneration::to_seeds`, with `RPK_kem`; `expires_ms` = creation + 7 d), kind [`KIND_OPK`] one row per
//! unused one-time prekey (`OpkSecrets::to_seeds`).
//!
//! **Lifecycle (§6.1).** A new generation every 7 days ([`Profile::rotate_if_due`]); a generation referenced by an
//! unexpired invitation is retained until that invitation expires, then retired with its one-time prekey
//! ([`Profile::retire`]): row delete, and with `secure_delete` on the pages are overwritten.

use std::path::Path;
use std::sync::{Arc, Mutex};

use secmp_proto::prekeys::{
    IDENTITY_SECTION_LEN, IdentityKeys, OpkSecrets, SPK_ROTATION_S, SpkGeneration,
};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_store::Store;
use secmp_store::profile::{
    INVITATION_OPEN, INVITATION_RETIRING, KIND_OPK, KIND_SPK, delete_invitation, delete_prekey,
    insert_prekey, max_prekey_id, meta_u32, put_identity, put_invitation_record,
    put_invitation_retained, put_meta_u32, set_invitation_status,
};
use secmp_store::sessions::insert_pending_control;
use secmp_store::wrap::{self, Unlocked};

use crate::api::Error;
use crate::clock::Clock;
use crate::persist::SharedStore;
use crate::scheduler::types::{QueueId, RelayId};

/// The one identity row.
pub const IDENTITY_ROW: i64 = 1;
/// The length of the identity section (Q143; `IdentityKeys::generate_with_section`).
pub const SECTION_LEN: usize = IDENTITY_SECTION_LEN;

/// The `meta` key of the next one-time prekey id (OPEN-M7-B-10).
const OPK_NEXT: &str = "opk_next";

/// An invitation retired by [`Profile::retire`]: the queue it used is the caller's to retire (§10.6 (4)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retired {
    /// The link-data id of the invitation.
    pub ld_id: Id,
    /// Whether its handshake had been accepted (the record was consumed).
    pub consumed: bool,
    /// The owner status had said that the link data was consumed (§9.4) and no handshake came: the invitation was used by
    /// someone else (§5.2).
    pub used_elsewhere: bool,
    /// The relay the invitation queue lives on.
    pub relay: RelayId,
    /// The invitation queue (a pool queue, §5.2).
    pub queue: QueueId,
    /// When the retiring queue stops being fetched (Unix milliseconds): `now + U[1 h, 24 h]`, drawn once and kept in the
    /// row of the queue until its `QUEUE_DEL` is acknowledged (Q201); 0 for a consumed invitation (its queue is the
    /// contact's).
    pub retire_at_ms: u64,
}

/// The profile of the user (see the module documentation).
#[derive(Clone)]
pub struct Profile {
    store: SharedStore,
}

fn ms(secs: u64) -> Result<u64, Error> {
    secs.checked_mul(1000).ok_or(Error::Unavailable)
}

fn id32(id: i64) -> Result<u32, Error> {
    u32::try_from(id).map_err(|_| Error::Unavailable)
}

impl Profile {
    /// Create the profile in `dir` under `passphrase` (ADR-053: Argon2id with the `PROFILE` cost): a fresh identity, one
    /// signed-prekey generation (expiry +7 d) and one one-time prekey, in one store transaction.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the directory already holds a profile, randomness or locked memory is unavailable or the
    /// store cannot be written.
    pub fn create(
        dir: &Path,
        passphrase: &[u8],
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let unlocked = wrap::create(dir, passphrase)?;
        Self::create_with(dir, &unlocked, clock, entropy)
    }

    /// [`Profile::create`] over a profile that is already unlocked (the key wrap is the caller's).
    ///
    /// # Errors
    /// As [`Profile::create`].
    pub fn create_with(
        dir: &Path,
        unlocked: &Unlocked,
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let now = clock.unix_secs();
        let mut store = Store::open_unlocked(dir, unlocked)?;
        let (keys, section) = IdentityKeys::generate_with_section(entropy)?;
        let fp = keys.fingerprint()?;
        let spk = SpkGeneration::generate(1, now, entropy)?;
        let opk = OpkSecrets::generate(1, entropy)?;
        let spk_expires = ms(now.saturating_add(SPK_ROTATION_S))?;
        store.txn(|tx| {
            put_identity(
                tx,
                IDENTITY_ROW,
                &section,
                &fp,
                ms(now).map_err(|_| secmp_store::Error::Unavailable)?,
            )?;
            insert_prekey(
                tx,
                KIND_SPK,
                i64::from(spk.id()),
                &spk.to_seeds(),
                Some(spk_expires),
            )?;
            insert_prekey(tx, KIND_OPK, i64::from(opk.id()), &opk.to_seeds(), None)?;
            put_meta_u32(tx, OPK_NEXT, 2)
        })?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
        })
    }

    /// Open the existing profile in `dir` that `unlocked` unlocked.
    ///
    /// # Errors
    /// [`Error::Unlock`] for the keys of another profile; [`Error::Unavailable`] otherwise.
    pub fn open_with(dir: &Path, unlocked: &Unlocked) -> Result<Self, Error> {
        Ok(Self::from_store(Arc::new(Mutex::new(
            Store::open_unlocked(dir, unlocked)?,
        ))))
    }

    /// The profile of an open store.
    #[must_use]
    pub const fn from_store(store: SharedStore) -> Self {
        Self { store }
    }

    /// The store, shared with the sessions and the outbox.
    #[must_use]
    pub fn store(&self) -> SharedStore {
        Arc::clone(&self.store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Store>, Error> {
        self.store.lock().map_err(|_| Error::Unavailable)
    }

    /// The store, locked for one step (the invitations and the sessions of this crate).
    pub(crate) fn lock_store(&self) -> Result<std::sync::MutexGuard<'_, Store>, Error> {
        self.lock()
    }

    /// `fingerprint(IKSPublic)` of the user (§6.2).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the profile has no identity or the column is malformed.
    pub fn fingerprint(&self) -> Result<[u8; 32], Error> {
        self.lock()?
            .identity_fingerprint(IDENTITY_ROW)?
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .ok_or(Error::Unavailable)
    }

    /// The identity keys, loaded for one operation and zeroized when dropped.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the profile has no identity or the row does not open.
    pub fn identity(&self) -> Result<IdentityKeys, Error> {
        let section = self
            .lock()?
            .identity_secret(IDENTITY_ROW)?
            .ok_or(Error::Unavailable)?;
        Ok(IdentityKeys::from_section(&section)?)
    }

    /// The signing key `IK_sig` (Ed25519 and ML-DSA-65 seeds of the identity section), loaded for one operation: it signs
    /// the `KeyChange` of an identity rotation (spec §7.7) and is zeroized when dropped.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the profile has no identity or the section is malformed.
    pub(crate) fn signing_key(&self) -> Result<secmp_crypto::HybridSigningKey, Error> {
        let section = self
            .lock()?
            .identity_secret(IDENTITY_ROW)?
            .ok_or(Error::Unavailable)?;
        let ed = section.get(1..33).ok_or(Error::Unavailable)?;
        let mldsa = section.get(33..65).ok_or(Error::Unavailable)?;
        Ok(secmp_crypto::HybridSigningKey::from_seeds(ed, mldsa)?)
    }

    /// The ids of the held signed-prekey generations, ascending.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn spk_ids(&self) -> Result<Vec<u32>, Error> {
        self.lock()?
            .prekeys(KIND_SPK)?
            .iter()
            .map(|r| id32(r.id))
            .collect()
    }

    /// The ids of the unused one-time prekeys, ascending.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn opk_ids(&self) -> Result<Vec<u32>, Error> {
        self.lock()?
            .prekeys(KIND_OPK)?
            .iter()
            .map(|r| id32(r.id))
            .collect()
    }

    /// The newest signed-prekey generation: its id and the Unix milliseconds at which it stops being the current one.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn current_spk(&self) -> Result<Option<(u32, u64)>, Error> {
        let rows = self.lock()?.prekeys(KIND_SPK)?;
        rows.last()
            .map(|r| Ok((id32(r.id)?, r.expires_ms.ok_or(Error::Unavailable)?)))
            .transpose()
    }

    /// §6.1: a new signed-prekey generation if there is none or the current one is 7 days old. Returns the current id.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or if the store cannot be written.
    pub fn rotate_if_due(
        &self,
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<u32, Error> {
        let now = clock.unix_secs();
        let now_ms = ms(now)?;
        let id = match self.current_spk()? {
            Some((id, expires)) if expires > now_ms => return Ok(id),
            Some((id, _)) => id.checked_add(1).ok_or(Error::Unavailable)?,
            None => 1,
        };
        let generation = SpkGeneration::generate(id, now, entropy)?;
        let expires = ms(now.saturating_add(SPK_ROTATION_S))?;
        self.lock()?.txn(|tx| {
            insert_prekey(
                tx,
                KIND_SPK,
                i64::from(id),
                &generation.to_seeds(),
                Some(expires),
            )
        })?;
        Ok(id)
    }

    /// Keep at least `target` one-time prekeys that no open invitation references (the pool the invitations draw from,
    /// §6.1), drawing new ones from `entropy`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or if the store cannot be written.
    pub fn fill_opks(&self, target: usize, entropy: &mut impl Entropy) -> Result<(), Error> {
        let mut have = {
            let store = self.lock()?;
            let referenced = crate::invitations::referenced_opks(&store)?;
            store
                .prekeys(KIND_OPK)?
                .iter()
                .filter(|r| !referenced.iter().any(|o| i64::from(*o) == r.id))
                .count()
        };
        while have < target {
            // the id comes from the counter `meta.opk_next` (absent: the highest id + 1), read and advanced in the transaction
            // that inserts the prekey: an id is never reused, also after its row was deleted (OPEN-M7-B-10, Q197)
            self.lock()?.txn(|tx| {
                let after_last = match max_prekey_id(tx, KIND_OPK)? {
                    Some(id) => id32(id)
                        .map_err(|_| secmp_store::Error::Unavailable)?
                        .checked_add(1)
                        .ok_or(secmp_store::Error::Unavailable)?,
                    None => 1,
                };
                let next = after_last.max(meta_u32(tx, OPK_NEXT)?.unwrap_or(1));
                let opk = OpkSecrets::generate(next, entropy)
                    .map_err(|_| secmp_store::Error::Unavailable)?;
                let following = next.checked_add(1).ok_or(secmp_store::Error::Unavailable)?;
                insert_prekey(tx, KIND_OPK, i64::from(next), &opk.to_seeds(), None)?;
                put_meta_u32(tx, OPK_NEXT, following)
            })?;
            have = have.saturating_add(1);
        }
        Ok(())
    }

    /// Rotation, then retirement (§6.1): [`Profile::rotate_if_due`] and [`Profile::retire`] at the clock's time.
    ///
    /// # Errors
    /// As the two.
    pub fn maintain(
        &self,
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<Retired>, Error> {
        self.rotate_if_due(clock, entropy)?;
        self.retire(clock)
    }

    /// Retire what has expired at the clock's time (§6.1 `docs/03:273`), in one store transaction: every invitation with
    /// `expires` ≤ now (its row, with the record; its one-time prekey unless it was consumed), and every signed-prekey
    /// generation that is neither the current one nor referenced by an unexpired, unconsumed invitation. The invitation
    /// queue of each [`Retired`] is the caller's to retire.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or written (nothing is retired then).
    pub fn retire(&self, clock: &impl Clock) -> Result<Vec<Retired>, Error> {
        self.retire_with(clock, false, |_| Ok(()))
    }

    /// [`Profile::retire`], also retiring every open invitation when `all_open` (an identity rotation, Q164), and running
    /// `extra` as statements of the same store transaction.
    fn retire_with(
        &self,
        clock: &impl Clock,
        all_open: bool,
        extra: impl FnOnce(&mut secmp_store::Tx<'_>) -> secmp_store::Result<()>,
    ) -> Result<Vec<Retired>, Error> {
        let now_ms = ms(clock.unix_secs())?;
        let mut store = self.lock()?;
        let mut dead = Vec::new();
        let mut referenced = Vec::new();
        let mut timing = crate::timing::TimingRng::os();
        for row in store.invitations()? {
            // a stub of an invitation retired earlier: its queue is deleted by the `QUEUE_DEL` that is waiting (Q201)
            if row.status == INVITATION_RETIRING {
                continue;
            }
            let ld_id: Id = row
                .ld_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::Unavailable)?;
            let loaded = crate::invitations::load(&store, &ld_id)?.ok_or(Error::Unavailable)?;
            let refs = (loaded.stored.record.spk_id, loaded.stored.record.opk_id);
            // a consumed record stays while its queue is a session's recv-queue: its row goes with the queue's entry on the
            // `QUEUE_DEL` OK (`Invitations::queue_deleted`, Q207); its cells reach the session until then (Q193)
            if row.status != INVITATION_OPEN
                && crate::invitations::routed(&store, loaded.stored.relay, loaded.stored.queue)?
            {
                continue;
            }
            if row.expires_ms <= now_ms || (all_open && row.status == INVITATION_OPEN) {
                let consumed = row.status != INVITATION_OPEN;
                let (lo, hi) = crate::sessions::rotation::OVERLAP_MS;
                let retire_at_ms = if consumed {
                    0
                } else {
                    now_ms.saturating_add(timing.uniform(lo, hi).map_err(|_| Error::Unavailable)?)
                };
                let stub = if consumed {
                    None
                } else {
                    let mut entry = loaded.stored.entry()?;
                    entry.retire_at_ms = Some(retire_at_ms);
                    Some(entry.encode_one())
                };
                let retired = Retired {
                    ld_id,
                    consumed,
                    used_elsewhere: !consumed
                        && loaded.stored.flags & crate::invitations::FLAG_CONSUMED_SEEN != 0,
                    relay: loaded.stored.relay,
                    queue: loaded.stored.queue,
                    retire_at_ms,
                };
                dead.push((retired, refs, stub));
            } else if row.status == INVITATION_OPEN {
                referenced.push(refs.0);
            }
        }
        let spks = store.prekeys(KIND_SPK)?;
        let opks = store.prekeys(KIND_OPK)?;
        let current = spks.last().map(|r| r.id);
        let dead_spks: Vec<i64> = spks
            .iter()
            .map(|r| r.id)
            .filter(|id| Some(*id) != current && !referenced.iter().any(|r| i64::from(*r) == *id))
            .collect();
        store.txn(|tx| {
            for (retired, (_, opk_id), stub) in &dead {
                // Q201: an unconsumed invitation keeps a row until its queue is deleted: its entry (the recipient key signs
                // the `FETCH` and the `QUEUE_DEL`), nothing else; a consumed one's queue is the contact's
                match stub {
                    Some(entry) => {
                        put_invitation_record(tx, &retired.ld_id, entry.as_slice())?;
                        set_invitation_status(tx, &retired.ld_id, INVITATION_RETIRING)?;
                        put_invitation_retained(tx, &retired.ld_id, None)?;
                    }
                    None => delete_invitation(tx, &retired.ld_id)?,
                }
                if !retired.consumed && opks.iter().any(|r| r.id == i64::from(*opk_id)) {
                    delete_prekey(tx, KIND_OPK, i64::from(*opk_id))?;
                }
            }
            for id in &dead_spks {
                delete_prekey(tx, KIND_SPK, *id)?;
            }
            extra(tx)
        })?;
        Ok(dead.into_iter().map(|(retired, _, _)| retired).collect())
    }

    /// Rotate the identity (spec §7.7, §7.8; O-28; Q164): a new `IKS` and fingerprint replace the old ones in one store
    /// transaction that also retires every unconsumed invitation (their records, one-time prekeys and — for the caller —
    /// queues: a handshake that arrives on a retired invitation is dropped silently, never answered with the new
    /// identity under the old bundle). The `KeyChange` for each of `contacts` contacts is signed by the **old**
    /// `IK_sig`; the caller queues one per session. Bundles issued from now on are signed by the new key.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or if the store cannot be written (nothing changes then).
    pub fn rotate_identity(
        &self,
        sessions: &[i64],
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Rotation, Error> {
        use crate::sessions::actor::PendingControl;

        let old = self.signing_key()?;
        let (keys, section) = IdentityKeys::generate_with_section(entropy)?;
        let mut key_changes = Vec::with_capacity(sessions.len());
        let mut rows = Vec::with_capacity(sessions.len());
        for _ in sessions {
            let body = secmp_proto::tr::content::key_change_body(&old, keys.public())?;
            let pending = PendingControl::KeyChange(body);
            rows.push(pending.encode().map_err(|_| Error::Unavailable)?);
            if let PendingControl::KeyChange(body) = pending {
                key_changes.push(body);
            }
        }
        let fp = keys.fingerprint()?;
        let now_ms = ms(clock.unix_secs())?;
        let mut pending = Vec::with_capacity(sessions.len());
        // the new identity and every contact's `KeyChange` in one transaction (Q210 c): a restart before a slot loses none
        let retired = self.retire_with(clock, true, |tx| {
            put_identity(tx, IDENTITY_ROW, &section, &fp, now_ms)?;
            for (session, row) in sessions.iter().zip(&rows) {
                pending.push(insert_pending_control(tx, *session, row)?);
            }
            Ok(())
        })?;
        Ok(Rotation {
            key_changes,
            pending,
            retired,
            fingerprint: fp,
        })
    }
}

/// What [`Profile::rotate_identity`] did.
pub struct Rotation {
    /// One `KeyChange` body per contact, signed by the old `IK_sig`.
    pub key_changes: Vec<secmp_proto::wire::cell::KeyChangeBody>,
    /// The `ord` of each one's pending control content (in the order of the sessions, Q210 c).
    pub pending: Vec<i64>,
    /// The invitations that were retired.
    pub retired: Vec<Retired>,
    /// The new fingerprint.
    pub fingerprint: [u8; 32],
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "kat")]
    use secmp_crypto::sha256;
    #[cfg(feature = "kat")]
    use secmp_proto::Encode as _;
    #[cfg(feature = "kat")]
    use secmp_proto::tr::FixedEntropy;

    #[cfg(feature = "kat")]
    use super::*;
    #[cfg(feature = "kat")]
    use crate::testutil::{DAY, E, Fixture, T0, hex, insert_record, stream, unhex, vector_field};

    #[cfg(feature = "kat")]
    type R = Result<(), E>;

    /// PR-01 (§6.1 `docs/03:267-275`, §6.2): `Profile::create` with the entropy of the frozen vector `fp-0001` — the
    /// identity is `IK_sig` = Ed25519 ‖ ML-DSA-65 and `IK_dh` X25519 (2017-byte `IKSPublic`), its fingerprint is the §6.2
    /// vector form (`SHA-256("SecMP-FP/1" ‖ encode(iks))`, the vector's `fp`), there is one signed-prekey generation
    /// expiring 7 days on, with its ratchet prekey (`RPK_kem`), and an unused one-time prekey.
    #[cfg(feature = "kat")]
    #[test]
    fn new_profile_keys() -> R {
        let json = include_str!("../../../vectors/fingerprint.json");
        let case = "fp-0001";
        // the draw order of `IdentityKeys::generate`: ML-DSA ξ, Ed25519 seed, X25519 secret
        let mut bytes = Vec::new();
        for key in ["mldsa_seed", "ed_seed", "dh_seed"] {
            bytes.extend(unhex(&vector_field(json, case, key)?)?);
        }
        bytes.extend(stream(11, 4096));
        let dir = secmp_store::kat::TempDir::new("pr01")?;
        let clock = crate::clock::ManualClock::new(T0);
        let mut entropy = FixedEntropy::new(&bytes);
        // the real cost parameters of a profile (CS-3.2), as the row says: `Profile::create`
        let profile = Profile::create(dir.path(), b"correct horse", &clock, &mut entropy)?;

        let identity = profile.identity()?;
        let iks = identity.public();
        assert_eq!(iks.ik_ed25519.as_bytes().len(), 32);
        assert_eq!(iks.ik_mldsa65.len(), 1952);
        assert_eq!(iks.ik_dh.as_bytes().len(), 32);
        let encoded = iks.encode()?;
        assert_eq!(encoded.len(), 2017);
        assert_eq!(hex(&encoded), vector_field(json, case, "iks")?);
        let want_fp = vector_field(json, case, "fp")?;
        assert_eq!(hex(&profile.fingerprint()?), want_fp);
        assert_eq!(hex(&sha256(&[b"SecMP-FP/1", &encoded])), want_fp);

        // one signed-prekey generation, expiring 7 days after creation, with its ratchet prekey; an unused one-time prekey
        assert_eq!(profile.spk_ids()?, [1]);
        assert_eq!(profile.opk_ids()?, [1]);
        let store = profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        let rows = s.prekeys(KIND_SPK)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows.first().and_then(|r| r.expires_ms),
            Some((T0 + 7 * DAY) * 1000)
        );
        let spk_seeds = s.prekey_secret(KIND_SPK, 1)?.ok_or("spk")?;
        let spk = SpkGeneration::from_seeds(&spk_seeds)?;
        assert_eq!((spk.id(), spk.created()), (1, T0));
        assert_eq!(spk.rpk_public()?.as_bytes().len(), 1184);
        let opk = OpkSecrets::from_seeds(&s.prekey_secret(KIND_OPK, 1)?.ok_or("opk")?)?;
        assert_eq!(opk.id(), 1);
        Ok(())
    }

    /// OPEN-M7-B-10 (red first on the tree that took `last row id + 1`: the id of a deleted highest row came back): a
    /// one-time prekey id is never reused — `meta.opk_next` moves with every insert, also across the deletion of the
    /// newest row and a reopen of the profile.
    #[cfg(feature = "kat")]
    #[test]
    fn opk_ids_never_reused() -> R {
        let mut e = crate::testutil::entropy(10);
        let fx = Fixture::new("pr10", &mut e)?;
        let p = &fx.profile;
        p.fill_opks(3, &mut e)?;
        assert_eq!(p.opk_ids()?, [1, 2, 3]);
        p.lock()?.txn(|tx| delete_prekey(tx, KIND_OPK, 3))?;
        assert_eq!(p.opk_ids()?, [1, 2]);
        p.fill_opks(3, &mut e)?;
        assert_eq!(p.opk_ids()?, [1, 2, 4], "3 is not issued a second time");
        assert_eq!(p.lock()?.txn(|tx| meta_u32(tx, OPK_NEXT))?, Some(5));
        // all of them gone: the counter still stands
        p.lock()?.txn(|tx| {
            for id in [1, 2, 4] {
                delete_prekey(tx, KIND_OPK, id)?;
            }
            Ok(())
        })?;
        p.fill_opks(1, &mut e)?;
        assert_eq!(p.opk_ids()?, [5]);
        Ok(())
    }

    /// Killers (mutants of `IdentityKeys::from_section`, `rotate_if_due`, `retire`): a section of the right length with
    /// another version, and one of another length with the right version, are refused; a generation that is exactly 7
    /// days old is replaced; a consumed invitation that expires is retired without touching a one-time prekey.
    #[cfg(feature = "kat")]
    #[test]
    fn section_rotation_and_consumed_retirement() -> R {
        let mut e = crate::testutil::entropy(6);
        let fx = Fixture::new("pr-killers", &mut e)?;
        let p = &fx.profile;
        let section = {
            let store = p.store();
            let s = store.lock().map_err(|_| "lock")?;
            s.identity_secret(IDENTITY_ROW)?.ok_or("section")?.to_vec()
        };
        assert!(IdentityKeys::from_section(&section).is_ok());
        let mut other_version = section.clone();
        *other_version.first_mut().ok_or("ver")? = 2;
        assert!(IdentityKeys::from_section(&other_version).is_err());
        assert!(IdentityKeys::from_section(section.get(..96).ok_or("len")?).is_err());
        assert!(IdentityKeys::from_section(&[section.clone(), vec![0]].concat()).is_err());

        // exactly 7 days after creation the generation is no longer current
        fx.at_day(7);
        assert_eq!(p.rotate_if_due(&fx.clock, &mut e)?, 2);
        assert_eq!(p.rotate_if_due(&fx.clock, &mut e)?, 2, "not again");

        // a consumed invitation expires: its row goes, the one-time prekey is not touched
        insert_record(p, [9; 16], (2, 1), T0 + 8 * DAY)?;
        {
            let store = p.store();
            let mut s = store.lock().map_err(|_| "lock")?;
            s.txn(|tx| {
                secmp_store::profile::set_invitation_status(
                    tx,
                    &[9; 16],
                    secmp_store::profile::INVITATION_CONSUMED,
                )
            })?;
        }
        fx.at_day(9);
        let retired = p.retire(&fx.clock)?;
        assert_eq!(retired.len(), 1);
        assert!(retired.iter().all(|r| r.consumed && !r.used_elsewhere));
        assert_eq!(
            p.opk_ids()?,
            [1],
            "the consumed invitation's OPK row is not this retirement's"
        );
        Ok(())
    }

    /// The events and operations of an identity rotation's retirement of `ld_id` (Q164): `InvitationRetired` with the
    /// reason, one `QUEUE_DEL` on the IN-11 schedule (`Delayed`).
    #[cfg(feature = "kat")]
    fn assert_retirement(ld_id: &[u8; 16], retired: &[Retired]) {
        let gone = crate::invitations::retirement(
            retired,
            Some(crate::api::RetireReason::IdentityRotated),
        );
        let id = u32::from_be_bytes([ld_id[0], ld_id[1], ld_id[2], ld_id[3]]);
        assert_eq!(
            gone.events,
            [crate::api::Event::InvitationRetired {
                id,
                reason: crate::api::RetireReason::IdentityRotated
            }]
        );
        assert_eq!(gone.ops.len(), 1);
        assert!(matches!(
            gone.ops.first().map(|o| o.when),
            Some(crate::scheduler::control::When::AfterEmptyFetch(_))
        ));
    }

    /// SE-09 [O-28] (§7.7; §7.6 `docs/03:503`; Q164, D-B5): `Profile::rotate_identity` with two contacts gives a new
    /// identity and fingerprint, one `KeyChange` per contact signed by the **old** `IK_sig` (each contact's session
    /// verifies it and takes the new identity), and retires every unconsumed invitation (row, one-time prekey) — a
    /// handshake that arrives on a retired invitation afterwards is dropped silently and answered with nothing.
    #[cfg(feature = "kat")]
    #[test]
    fn rotate_identity_announces_key_change() -> R {
        use crate::api::ContactId;
        use crate::invitations::Invitations;
        use crate::sessions::accept_key_change;
        use crate::sessions::actor::SessionEvent;
        use crate::sessions::tests::{Link, big, connect, deliver, next, party, pending_handshake};
        use crate::testutil::entropy;
        use secmp_proto::wire::cell::Cell;

        big(|| {
            let host = party("se09-h", 61)?;
            let (g1, g2) = (party("se09-g1", 63)?, party("se09-g2", 65)?);
            let Link {
                h: mut h1,
                g: mut c1,
                contact: id1,
                ..
            } = connect(&host, &g1, 100)?;
            let Link {
                h: mut h2,
                g: mut c2,
                contact: id2,
                ..
            } = connect(&host, &g2, 200)?;
            assert_eq!((id1, id2), (ContactId(1), ContactId(2)));
            // an open invitation, and a handshake on it that has not been decided yet
            let invitations = Invitations::new(host.profile.clone());
            let (open, cells) = pending_handshake(&host, 300)?;
            let old_fp = host.profile.fingerprint()?;

            let rotation = host
                .profile
                .rotate_identity(&[1, 2], &host.clock, &mut entropy(304))?;
            assert_ne!(rotation.fingerprint, old_fp);
            assert_eq!(host.profile.fingerprint()?, rotation.fingerprint);
            assert_eq!(rotation.key_changes.len(), 2);
            assert_eq!(rotation.retired.len(), 1);
            assert_retirement(&open.invitation.ld_id, &rotation.retired);
            let mut bodies = rotation.key_changes.into_iter();
            h1.queue_key_change(bodies.next().ok_or("body")?)
                .map_err(|_| "queue")?;
            h2.queue_key_change(bodies.next().ok_or("body")?)
                .map_err(|_| "queue")?;
            for (h, c, g) in [(&mut h1, &mut c1, &g1), (&mut h2, &mut c2, &g2)] {
                for i in 0_u64..4 {
                    let cell = next(h, 30_000_u64.saturating_add(i.saturating_mul(1_000)))?;
                    deliver(c, &cell)?;
                }
                let events = c.take_events();
                let new = host.profile.identity()?;
                assert!(
                    matches!(events.as_slice(), [SessionEvent::KeyChanged(iks)] if **iks == *new.public()),
                    "each contact verified the key change under the old IK_sig"
                );
                accept_key_change(&g.profile.store(), c, ContactId(1), new.public())?;
            }
            let store = host.profile.store();
            {
                let s = store.lock().map_err(|_| "lock")?;
                assert!(
                    s.invitations()?.iter().all(|r| r.status != 0),
                    "no open invitation"
                );
                assert!(s.prekeys(KIND_OPK)?.iter().all(|r| r.id != 1 && r.id != 2));
            }

            // the handshake on the retired invitation: dropped silently, never answered
            let fetched: Vec<(u64, Cell)> = (1..).zip(cells).collect();
            let round = invitations.process_round(
                &open.invitation.ld_id,
                crate::testutil::round_on(&invitations, &open.invitation.ld_id)?,
                &fetched,
                &host.clock,
                &mut entropy(306),
            )?;
            assert!(
                round.accepted.is_none() && round.events.is_empty() && round.to_session.is_empty()
            );
            assert_eq!(round.ack_through, Some(3));
            let contacts = crate::contacts::Contacts::new(store, host.profile.fingerprint()?);
            assert_eq!(contacts.list()?.len(), 2, "no third contact");
            Ok(())
        })
    }

    /// PR-03 [O-01] (ST-06 at the `Api`; report §7 "Profile lock and child processes"): `Core::open` with a wrong passphrase is
    /// the uniform `Error::Unlock` and writes no file — the profile directory hashes the same before and after; a
    /// directory that holds no profile is `Error::Unavailable` and stays empty; the profile held by a running core (the `flock` on `<profile>/lock`) is
    /// `Error::Unavailable` to a second opener, not `Unlock`.
    #[cfg(feature = "kat")]
    #[test]
    fn open_wrong_passphrase_uniform() -> R {
        use secmp_store::wrap::Argon2Params;

        use crate::api::Core;
        use crate::clock::ManualClock;
        use crate::testutil::Fixed;

        fn tree_hash(dir: &std::path::Path) -> Result<[u8; 32], E> {
            let mut names: Vec<_> = std::fs::read_dir(dir)?
                .map(|e| e.map(|e| e.path()))
                .collect::<Result<_, _>>()?;
            names.sort();
            let mut all = Vec::new();
            for path in names {
                all.extend_from_slice(path.file_name().map_or(&[][..], |n| n.as_encoded_bytes()));
                if path.is_file() {
                    all.extend_from_slice(&std::fs::read(&path)?);
                }
            }
            Ok(sha256(&[&all]))
        }

        let mut e = crate::testutil::entropy(3);
        let fx = Fixture::new("pr03", &mut e)?;
        let open = |dir: &std::path::Path, pass: &[u8]| {
            Core::<ManualClock, Fixed>::open_kat(
                dir,
                pass,
                Argon2Params::kat_small(),
                ManualClock::new(T0),
                || Fixed(crate::testutil::entropy(1)),
            )
        };
        let before = tree_hash(fx.dir.path())?;
        assert_eq!(open(fx.dir.path(), b"wrong").err(), Some(Error::Unlock));
        assert_eq!(open(fx.dir.path(), b"").err(), Some(Error::Unlock));
        let empty = secmp_store::kat::TempDir::new("pr03-empty")?;
        assert_eq!(
            open(empty.path(), b"correct horse").err(),
            Some(Error::Unavailable)
        );
        assert_eq!(tree_hash(fx.dir.path())?, before, "nothing written");
        assert_eq!(std::fs::read_dir(empty.path())?.count(), 0);
        // the right passphrase while the fixture's profile holds the lock: unavailable, not unlock
        assert_eq!(
            open(fx.dir.path(), b"correct horse").err(),
            Some(Error::Unavailable)
        );
        Ok(())
    }

    /// PR-02 (§6.1 `docs/03:273`): generation 1 is referenced by an invitation expiring on day 20. On day 8 (a new
    /// generation has been made, 1 is no longer current), day 19 and day 21 the clock reads: 1 is present, present,
    /// retired — with the invitation, and the one-time prekey that it named.
    #[cfg(feature = "kat")]
    #[test]
    fn spk_retained_for_open_invitations() -> R {
        let mut e = crate::testutil::entropy(2);
        let fx = Fixture::new("pr02", &mut e)?;
        let p = &fx.profile;
        let ld_id = [7_u8; 16];
        insert_record(p, ld_id, (1, 1), T0 + 20 * DAY)?;

        fx.at_day(8);
        assert!(p.maintain(&fx.clock, &mut e)?.is_empty());
        assert!(p.spk_ids()?.contains(&1), "day 8");
        assert!(
            p.spk_ids()?.len() >= 2,
            "a newer generation exists on day 8"
        );

        fx.at_day(19);
        assert!(p.maintain(&fx.clock, &mut e)?.is_empty());
        assert!(p.spk_ids()?.contains(&1), "day 19");
        assert_eq!(p.opk_ids()?, [1]);

        fx.at_day(21);
        let retired = p.maintain(&fx.clock, &mut e)?;
        let [one] = retired.as_slice() else {
            return Err("one invitation retired".into());
        };
        let day21_ms = (T0 + 21 * DAY) * 1_000;
        assert_eq!(
            (
                one.ld_id,
                one.consumed,
                one.used_elsewhere,
                one.relay,
                one.queue
            ),
            (ld_id, false, false, RelayId(1), QueueId(1))
        );
        // Q201: the queue is deleted after a deadline U[1 h, 24 h] on, drawn once
        assert!(
            (day21_ms + 3_600_000..=day21_ms + 86_400_000).contains(&one.retire_at_ms),
            "{}",
            one.retire_at_ms
        );
        assert!(!p.spk_ids()?.contains(&1), "day 21");
        assert_eq!(p.spk_ids()?.len(), 1, "only the current generation is left");
        assert_eq!(
            p.opk_ids()?,
            Vec::<u32>::new(),
            "the invitation's OPK is gone"
        );
        {
            let store = p.store();
            let s = store.lock().map_err(|_| "lock")?;
            // Q201: the record is gone; the row stays as a stub holding the queue's entry until the `QUEUE_DEL` is acknowledged
            let rows = s.invitations()?;
            let [row] = rows.as_slice() else {
                return Err("one row".into());
            };
            assert_eq!(
                (row.ld_id.as_slice(), row.status),
                (&ld_id[..], secmp_store::profile::INVITATION_RETIRING)
            );
            let plain = s.invitation_record(&ld_id)?.ok_or("stub")?;
            let entry = crate::sessions::rotation::QueueEntry::decode_one(&plain)?;
            assert_eq!(
                entry.seed.expose_secret(),
                &[3_u8; 32],
                "the record's recipient key"
            );
            assert_eq!(entry.retire_at_ms, Some(one.retire_at_ms));
        }
        // what is left is durable
        let spks = p.spk_ids()?;
        let again = fx.reopen()?;
        assert_eq!(again.profile.spk_ids()?, spks);
        Ok(())
    }
}
