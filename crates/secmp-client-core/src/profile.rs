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

use secmp_crypto::{HybridSigningKey, Zeroizing};
use secmp_proto::prekeys::{IdentityKeys, IkDhSecret, OpkSecrets, SPK_ROTATION_S, SpkGeneration};
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_store::Store;
use secmp_store::profile::{
    INVITATION_OPEN, KIND_OPK, KIND_SPK, delete_invitation, delete_prekey, insert_prekey,
    put_identity,
};
use secmp_store::wrap::{self, Unlocked};

use crate::api::Error;
use crate::clock::Clock;
use crate::persist::SharedStore;
use crate::scheduler::types::{QueueId, RelayId};

/// The one identity row.
pub const IDENTITY_ROW: i64 = 1;
/// The version byte of the identity section.
const SECTION_VER: u8 = 1;
/// The length of the identity section (Q143).
pub const SECTION_LEN: usize = 97;

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
}

/// The profile of the user (see the module documentation).
pub struct Profile {
    store: SharedStore,
}

/// A fresh identity from `entropy`: `IK_sig` draws the ML-DSA `ξ` then the Ed25519 seed, `IK_dh` its 32 bytes (the order of
/// `IdentityKeys::generate`); the keys come from the drawn seeds so that the section can be written (`HybridSigningKey`
/// does not give its seeds back).
fn new_identity(entropy: &mut impl Entropy) -> Result<(IdentityKeys, Zeroizing<Vec<u8>>), Error> {
    let xi = entropy.secret::<32>()?;
    let ed = entropy.secret::<32>()?;
    let dh = entropy.secret::<32>()?;
    let mut section = Zeroizing::new(Vec::with_capacity(SECTION_LEN));
    section.push(SECTION_VER);
    section.extend_from_slice(ed.expose_secret());
    section.extend_from_slice(xi.expose_secret());
    section.extend_from_slice(dh.expose_secret());
    let keys = identity_from_section(&section)?;
    Ok((keys, section))
}

/// The identity of an identity section.
pub(crate) fn identity_from_section(section: &[u8]) -> Result<IdentityKeys, Error> {
    let [ver, rest @ ..] = section else {
        return Err(Error::Unavailable);
    };
    if *ver != SECTION_VER || section.len() != SECTION_LEN {
        return Err(Error::Unavailable);
    }
    let ed = rest.get(..32).ok_or(Error::Unavailable)?;
    let mldsa = rest.get(32..64).ok_or(Error::Unavailable)?;
    let x = rest.get(64..96).ok_or(Error::Unavailable)?;
    let sig = HybridSigningKey::from_seeds(ed, mldsa)?;
    let dh = IkDhSecret::from_bytes(x)?;
    Ok(IdentityKeys::from_parts(sig, dh)?)
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
        let (keys, section) = new_identity(entropy)?;
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
            insert_prekey(tx, KIND_OPK, i64::from(opk.id()), &opk.to_seeds(), None)
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
        identity_from_section(&section)
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

    /// Keep at least `target` unused one-time prekeys (the pool the invitations draw from, §6.1).
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness or if the store cannot be written.
    pub fn fill_opks(&self, target: usize, entropy: &mut impl Entropy) -> Result<(), Error> {
        let have = self.lock()?.prekeys(KIND_OPK)?;
        let mut next = have.last().map_or(Ok(1_u32), |r| {
            id32(r.id)?.checked_add(1).ok_or(Error::Unavailable)
        })?;
        for _ in have.len()..target {
            let opk = OpkSecrets::generate(next, entropy)?;
            self.lock()?
                .txn(|tx| insert_prekey(tx, KIND_OPK, i64::from(next), &opk.to_seeds(), None))?;
            next = next.checked_add(1).ok_or(Error::Unavailable)?;
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
        let now_ms = ms(clock.unix_secs())?;
        let mut store = self.lock()?;
        let mut dead = Vec::new();
        let mut referenced = Vec::new();
        for row in store.invitations()? {
            let ld_id: Id = row
                .ld_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::Unavailable)?;
            let loaded = crate::invitations::load(&store, &ld_id)?.ok_or(Error::Unavailable)?;
            let refs = (loaded.stored.record.spk_id, loaded.stored.record.opk_id);
            if row.expires_ms <= now_ms {
                let consumed = row.status != INVITATION_OPEN;
                let retired = Retired {
                    ld_id,
                    consumed,
                    used_elsewhere: !consumed
                        && loaded.stored.flags & crate::invitations::FLAG_CONSUMED_SEEN != 0,
                    relay: loaded.stored.relay,
                    queue: loaded.stored.queue,
                };
                dead.push((retired, refs));
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
            for (retired, (_, opk_id)) in &dead {
                delete_invitation(tx, &retired.ld_id)?;
                if !retired.consumed && opks.iter().any(|r| r.id == i64::from(*opk_id)) {
                    delete_prekey(tx, KIND_OPK, i64::from(*opk_id))?;
                }
            }
            for id in &dead_spks {
                delete_prekey(tx, KIND_SPK, *id)?;
            }
            Ok(())
        })?;
        Ok(dead.into_iter().map(|(retired, _)| retired).collect())
    }
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
        assert_eq!(
            retired,
            [Retired {
                ld_id,
                consumed: false,
                used_elsewhere: false,
                relay: RelayId(1),
                queue: QueueId(1),
            }]
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
            assert!(s.invitations()?.is_empty());
        }
        // what is left is durable
        let spks = p.spk_ids()?;
        let again = fx.reopen()?;
        assert_eq!(again.profile.spk_ids()?, spks);
        Ok(())
    }
}
