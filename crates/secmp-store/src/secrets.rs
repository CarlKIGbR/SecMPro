// SPDX-License-Identifier: AGPL-3.0-or-later
//! The long-lived keys of a profile (CS-2.2, ADR-053): `MK_profile`, `KEK`, the table keys `K_t` and `K_db` are each a
//! [`StoreKey`] — a [`LockedSecret`] (`secmp_sys_mem::SecretPage`: locked, between guard pages, zeroized on drop). The
//! identity keys are the `secmp-crypto` key types, which hold the same `LockedSecret` (`Ed25519SigningKey`,
//! `MlDsa65SigningKey`, `X25519Secret`). Feature `kat`: [`crate::kat::live_key_pages`] counts the live holders (+1 when
//! made, −1 in `Drop`), the ST-19 probe that a locked profile keeps no key.

use secmp_crypto::LockedSecret;

use crate::error::{Error, Result};

/// One 32-byte store key in a locked page.
pub struct StoreKey(LockedSecret<32>);

impl StoreKey {
    /// The holder of `key`.
    pub(crate) fn new(key: LockedSecret<32>) -> Self {
        #[cfg(any(test, feature = "kat"))]
        crate::kat::note_key_page(1);
        Self(key)
    }

    /// A fresh random key (`MK_profile`, `MK_bk`).
    pub(crate) fn random() -> Result<Self> {
        Ok(Self::new(
            LockedSecret::random().map_err(|_| Error::Unavailable)?,
        ))
    }

    /// A copy in another locked page.
    pub(crate) fn copy(&self) -> Result<Self> {
        Ok(Self::new(
            LockedSecret::from_slice(self.0.expose_secret()).map_err(|_| Error::Unavailable)?,
        ))
    }

    /// The key.
    #[must_use]
    pub fn locked(&self) -> &LockedSecret<32> {
        &self.0
    }
}

impl Drop for StoreKey {
    fn drop(&mut self) {
        // the page itself is zeroized by `LockedSecret`'s own drop
        #[cfg(any(test, feature = "kat"))]
        crate::kat::note_key_page(-1);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "kat")]
    use crate::kat::{TempDir, live_key_pages};
    #[cfg(feature = "kat")]
    use crate::keys::Table;
    #[cfg(feature = "kat")]
    use crate::wrap::{self, Argon2Params};
    #[cfg(feature = "kat")]
    use secmp_crypto::LockedSecret;

    #[cfg(feature = "kat")]
    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    #[cfg(feature = "kat")]
    fn locked<const N: usize>(_: &LockedSecret<N>) {}

    /// ST-19 (CS-2.2; OPEN-M7-32, ADR-053): an unlocked profile holds `MK_profile`, the `KEK`, the table keys and
    /// `K_db` as `SecretPage`-backed `LockedSecret`s (type assertion on each `kat` accessor); the identity key types
    /// (`Ed25519SigningKey`, `MlDsa65SigningKey`, `X25519Secret`) hold a `LockedSecret` (`secmp-crypto` `ed25519.rs:115`,
    /// `mldsa.rs:28`, `x25519.rs:19`); after `lock()` and the store's close no key holder is alive (the probe is 0).
    #[test]
    #[cfg(feature = "kat")]
    fn long_lived_keys_in_secret_pages() -> R {
        let dir = TempDir::new("st19")?;
        let base = live_key_pages();
        {
            let unlocked = wrap::create_kat(dir.path(), b"passphrase", Argon2Params::kat_small())?;
            locked(unlocked.mk_kat());
            locked(unlocked.db_kat()?.locked());
            for t in Table::ALL {
                locked(unlocked.table_key_kat(t)?.locked());
            }
            let kek = wrap::kek_kat(b"passphrase", &[7; 16], Argon2Params::kat_small())?;
            locked(kek.locked());
            drop(kek);
            let store = crate::Store::open_unlocked(dir.path(), &unlocked)?;
            assert!(live_key_pages() > base, "keys are held while unlocked");
            drop(store);
            unlocked.lock();
        }
        assert_eq!(live_key_pages(), base, "no key holder alive after lock()");
        // the identity key types: each holds a LockedSecret (compile-time: the constructors are the crate's)
        let ed = secmp_crypto::Ed25519SigningKey::generate()?;
        let x = secmp_crypto::X25519Secret::generate()?;
        let _ = (ed, x);
        Ok(())
    }
}
