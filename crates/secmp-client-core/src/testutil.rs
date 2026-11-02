// SPDX-License-Identifier: AGPL-3.0-or-later
//! Helpers of this crate's own tests (feature `kat`, tests only): derandomised entropy, a profile in a temporary
//! directory, hex and the vector lookups of the unit tests (`serde_json` is not a dependency of this crate).

use secmp_proto::tr::FixedEntropy;
use secmp_store::kat::TempDir;
use secmp_store::wrap::{Argon2Params, Unlocked, create_kat};

use crate::clock::ManualClock;
use crate::profile::Profile;

/// The error type of the tests.
pub(crate) type E = Box<dyn std::error::Error>;

/// Unix seconds of the first instant of the tests' clocks.
pub(crate) const T0: u64 = 1_800_000_000;

/// One day in seconds.
pub(crate) const DAY: u64 = 86_400;

/// A deterministic byte stream (not random, not secret) for [`FixedEntropy`].
pub(crate) fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(23) ^ 0x5851_f42d;
            x.to_be_bytes().first().copied().unwrap_or(0)
        })
        .collect()
}

/// Derandomised entropy of `seed` (4 MiB).
pub(crate) fn entropy(seed: u64) -> FixedEntropy {
    FixedEntropy::new(&stream(seed, 1 << 22))
}

/// `bytes` as lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The bytes of a hex string.
pub(crate) fn unhex(text: &str) -> Result<Vec<u8>, E> {
    text.as_bytes()
        .chunks(2)
        .map(|p| {
            let s = core::str::from_utf8(p)?;
            Ok(u8::from_str_radix(s, 16)?)
        })
        .collect()
}

/// The string field `key` of the vector case `id` in `json` (the frozen files are one line of `{"id":…}` objects).
pub(crate) fn vector_field(json: &str, id: &str, key: &str) -> Result<String, E> {
    let start = json
        .find(&format!("\"id\":\"{id}\""))
        .ok_or("vector case")?;
    let rest = json.get(start..).ok_or("vector case")?;
    let needle = format!("\"{key}\":\"");
    let at = rest.find(&needle).ok_or("vector field")?;
    let tail = rest
        .get(at.checked_add(needle.len()).ok_or("offset")?..)
        .ok_or("vector field")?;
    Ok(tail.split('"').next().ok_or("vector value")?.to_owned())
}

/// A profile in a temporary directory, with a clock at [`T0`] and the unlock that opened it.
pub(crate) struct Fixture {
    pub(crate) dir: TempDir,
    pub(crate) unlocked: Unlocked,
    pub(crate) profile: Profile,
    pub(crate) clock: ManualClock,
}

impl Fixture {
    /// A new profile whose identity and first prekeys come from `entropy`.
    #[cfg(feature = "kat")]
    pub(crate) fn new(label: &str, entropy: &mut FixedEntropy) -> Result<Self, E> {
        let dir = TempDir::new(label)?;
        let unlocked = create_kat(dir.path(), b"correct horse", Argon2Params::kat_small())?;
        let clock = ManualClock::new(T0);
        let profile = Profile::create_with(dir.path(), &unlocked, &clock, entropy)?;
        Ok(Self {
            dir,
            unlocked,
            profile,
            clock,
        })
    }

    /// Close the profile and open it again from disk (the clock is kept).
    pub(crate) fn reopen(self) -> Result<Self, E> {
        let Self {
            dir,
            unlocked,
            profile,
            clock,
        } = self;
        drop(profile);
        let profile = Profile::open_with(dir.path(), &unlocked)?;
        Ok(Self {
            dir,
            unlocked,
            profile,
            clock,
        })
    }

    /// Move the clock to `days` days after [`T0`].
    pub(crate) fn at_day(&self, days: u64) {
        self.clock
            .set_ms(days.saturating_mul(DAY).saturating_mul(1000));
    }
}

/// A relay reference without a direct endpoint.
pub(crate) fn relay_ref() -> secmp_proto::wire::inv::RelayRef {
    secmp_proto::wire::inv::RelayRef {
        relay_fp: [1; 32],
        onion: secmp_proto::wire::inv::Onion::from_pubkey(&[2; 32]),
        akc: [3; 32],
        direct: None,
    }
}

/// A handshake profile.
pub(crate) fn wire_profile(name: &str) -> Result<secmp_proto::wire::inv::Profile, E> {
    Ok(secmp_proto::wire::inv::Profile::new(name, None)?)
}

impl Fixture {
    /// Relay row `id` (the test relay) with `pool` spare queues whose seeds come from `entropy`.
    pub(crate) fn add_relay(
        &self,
        id: u32,
        pool: usize,
        entropy: &mut FixedEntropy,
    ) -> Result<(), E> {
        use secmp_proto::Encode as _;

        let store = self.profile.store();
        let encoded = relay_ref().encode()?;
        {
            let mut s = store.lock().map_err(|_| "lock")?;
            s.txn(|tx| secmp_store::profile::put_relay(tx, i64::from(id), &encoded, None))?;
        }
        crate::invitations::SparePool::new(store).fill(
            crate::scheduler::types::RelayId(id),
            pool,
            entropy,
        )?;
        Ok(())
    }
}

/// The randomness of a [`crate::sessions::actor::Conversation`] in the tests.
pub(crate) struct Fixed(pub(crate) FixedEntropy);

impl crate::sessions::actor::EntropySource for Fixed {
    type E = FixedEntropy;

    fn entropy(&mut self) -> &mut FixedEntropy {
        &mut self.0
    }
}

/// The two sides of a session A → B from one shared secret, with the entropy of each (the pair of the persistence tests).
pub(crate) fn ratchet_pair(
    seed: u64,
) -> Result<
    (
        secmp_proto::tr::RatchetState,
        FixedEntropy,
        secmp_proto::tr::RatchetState,
        FixedEntropy,
    ),
    E,
> {
    use secmp_crypto::SecretBytes;
    use secmp_proto::keys::{MlKem768Ek, X25519Pk};
    use secmp_proto::tr::{Entropy as _, RatchetState};

    let base = seed.wrapping_mul(4);
    let mut responder = FixedEntropy::new(&stream(base.wrapping_add(2), 1 << 16));
    let mut initiator = FixedEntropy::new(&stream(base.wrapping_add(1), 1 << 16));
    let spk_dh = responder.x25519()?;
    let rpk_kem = responder.mlkem768()?;
    let spk = X25519Pk::from_bytes(spk_dh.public_key().as_bytes())?;
    let ek = MlKem768Ek::from_bytes(rpk_kem.encapsulation_key().as_bytes())?;
    let sk = SecretBytes::from_slice(&[7_u8; 32])?;
    let a = RatchetState::init_initiator_with(&sk, &[9_u8; 32], &spk, &ek, &mut initiator)?;
    let b = RatchetState::init_responder(&sk, &[9_u8; 32], spk_dh, rpk_kem)?;
    let ea = FixedEntropy::new(&stream(base.wrapping_add(3), 1 << 22));
    let eb = FixedEntropy::new(&stream(base.wrapping_add(4), 1 << 22));
    Ok((a, ea, b, eb))
}

/// An open invitation record `ld_id` naming `spk_id` and `opk_id` and expiring `expires` (Unix seconds), written to the
/// profile's store without being issued (the lifecycle tests need a record, not an invitation).
pub(crate) fn insert_record(
    profile: &Profile,
    ld_id: [u8; 16],
    (spk_id, opk_id): (u32, u32),
    expires: u64,
) -> Result<(), E> {
    use secmp_crypto::SecretBytes;
    use secmp_proto::prekeys::InvitationRecord;

    use crate::invitations::Stored;
    use crate::scheduler::types::{QueueId, RelayId};

    let seed = |b: u8| SecretBytes::<32>::from_slice(&[b; 32]);
    let stored = Stored {
        record: InvitationRecord {
            ld_id,
            link_key: seed(1)?,
            owner_seed: seed(2)?,
            invq_recv_seed: seed(3)?,
            spk_id,
            opk_id,
            expires,
        },
        relay: RelayId(1),
        queue: QueueId(1),
        flags: 0,
        inv_send_seed: seed(4)?,
        inv_period_s: 10,
        blob: None,
    };
    let store = profile.store();
    let mut s = store.lock().map_err(|_| "lock")?;
    s.txn(|tx| {
        secmp_store::profile::insert_invitation(
            tx,
            &ld_id,
            &stored.encode(),
            expires.saturating_mul(1000),
        )
    })?;
    Ok(())
}

/// The (relay, queue) an invitation's round is fetched from (`Invitations::process_round`'s `on`; Q207), read while its
/// row exists: from the record (open or consumed) or from the stub of a retiring one (Q201).
pub(crate) fn round_on(
    invitations: &crate::invitations::Invitations,
    ld_id: &secmp_proto::wire::Id,
) -> Result<
    (
        crate::scheduler::types::RelayId,
        crate::scheduler::types::QueueId,
    ),
    E,
> {
    use crate::scheduler::types::{QueueId, RelayId};
    if let Ok(q) = invitations.queue_of(ld_id) {
        return Ok((q.relay, q.queue));
    }
    let (_, entry) = invitations
        .retiring()?
        .into_iter()
        .find(|(id, _)| id == ld_id)
        .ok_or("no invitation row")?;
    Ok((RelayId(entry.relay), QueueId(entry.queue)))
}
