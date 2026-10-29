// SPDX-License-Identifier: AGPL-3.0-or-later
//! The keys a profile's master key derives (ADR-053 items 3, 4; spec §3.4 HKDF with salt 0^32 as in §6.4): one table key
//! `K_t` per table of `docs/02` §4.2 under its App. A label `"SecMP-STORE/1 <table>"`, and the SQLCipher key `K_db` under
//! `"SecMP-STORE/1 db"`. `MK_profile` is only ever HKDF input (item 4: no key reuse across constructions). Every key is a
//! [`StoreKey`] (a locked page, CS-2.2).

use secmp_crypto::{Label, LockedSecret, hkdf_locked};

use crate::error::{Error, Result};
use crate::secrets::StoreKey;

/// The HKDF salt of every store derivation (ADR-053 items 3, 4, 6: `salt = 0^32`).
const SALT: [u8; 32] = [0; 32];

/// The nine tables of `docs/02` §4.2 that have a key (ADR-053 item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// `identity`
    Identity,
    /// `prekeys`
    Prekeys,
    /// `relays`
    Relays,
    /// `contacts`
    Contacts,
    /// `sessions`
    Sessions,
    /// `outbox`
    Outbox,
    /// `messages`
    Messages,
    /// `invitations`
    Invitations,
    /// `settings`
    Settings,
}

impl Table {
    /// Every table, in the order of App. A.
    pub const ALL: [Self; 9] = [
        Self::Identity,
        Self::Prekeys,
        Self::Relays,
        Self::Contacts,
        Self::Sessions,
        Self::Outbox,
        Self::Messages,
        Self::Invitations,
        Self::Settings,
    ];

    /// The App. A label of the table (`"SecMP-STORE/1 <table>"`).
    #[must_use]
    pub const fn label(self) -> Label {
        match self {
            Self::Identity => Label::StoreIdentity,
            Self::Prekeys => Label::StorePrekeys,
            Self::Relays => Label::StoreRelays,
            Self::Contacts => Label::StoreContacts,
            Self::Sessions => Label::StoreSessions,
            Self::Outbox => Label::StoreOutbox,
            Self::Messages => Label::StoreMessages,
            Self::Invitations => Label::StoreInvitations,
            Self::Settings => Label::StoreSettings,
        }
    }
}

/// `HKDF-SHA-256(salt = 0^32, IKM = mk, info = label, L = 32)` in a locked page (spec §3.4; ADR-053 items 3, 4, 6).
pub(crate) fn derive(mk: &LockedSecret<32>, label: Label) -> Result<StoreKey> {
    // spec §3.4; ADR-053 items 3, 4
    let k = hkdf_locked::<32, 32>(&SALT, mk, label, &[]).map_err(|_| Error::Unavailable)?;
    Ok(StoreKey::new(k))
}

/// The nine table keys `K_t` of a profile (ADR-053 item 3).
pub(crate) struct TableKeys([StoreKey; 9]);

impl TableKeys {
    /// The nine keys derived from `mk`.
    pub(crate) fn derive(mk: &LockedSecret<32>) -> Result<Self> {
        let keys: Vec<StoreKey> = Table::ALL
            .iter()
            .map(|t| derive(mk, t.label()))
            .collect::<Result<_>>()?;
        Ok(Self(keys.try_into().map_err(|_| Error::Unavailable)?))
    }

    /// A second copy of the same keys (each in its own locked page).
    pub(crate) fn copy(&self) -> Result<Self> {
        let keys: Vec<StoreKey> = self.0.iter().map(StoreKey::copy).collect::<Result<_>>()?;
        Ok(Self(keys.try_into().map_err(|_| Error::Unavailable)?))
    }

    /// The key of `table`.
    #[cfg(any(test, feature = "kat"))]
    pub(crate) fn get(&self, table: Table) -> &LockedSecret<32> {
        let [
            identity,
            prekeys,
            relays,
            contacts,
            sessions,
            outbox,
            messages,
            invitations,
            settings,
        ] = &self.0;
        match table {
            Table::Identity => identity,
            Table::Prekeys => prekeys,
            Table::Relays => relays,
            Table::Contacts => contacts,
            Table::Sessions => sessions,
            Table::Outbox => outbox,
            Table::Messages => messages,
            Table::Invitations => invitations,
            Table::Settings => settings,
        }
        .locked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    /// ST-10 (CS-3.3; ADR-053 items 3, 4) [REF]: for a fixed `MK` (32 × 0x4d) the nine `K_t` are pairwise distinct,
    /// `K_db` differs from each, and each equals the generic `secmp_crypto::hkdf` with salt 0^32 and its App. A label (the
    /// existing HKDF vectors are the oracle). The byte-exact clause against `vectors/store.json` stays open [REF]
    /// (OPEN-M7-38): no vector file exists, none is read.
    #[test]
    fn table_keys_match_vectors() -> R {
        let mk = LockedSecret::<32>::from_slice(&[0x4d; 32])?;
        let tables = TableKeys::derive(&mk)?;
        let db = derive(&mk, Label::StoreDb)?;
        let all: Vec<[u8; 32]> = Table::ALL
            .iter()
            .map(|t| *tables.get(*t).expose_secret())
            .collect();
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i.saturating_add(1)) {
                assert_ne!(a, b, "two table keys equal");
            }
            assert_ne!(a, db.locked().expose_secret(), "K_db equals a table key");
        }
        for t in Table::ALL {
            let generic = secmp_crypto::hkdf::<32>(&[0; 32], &[0x4d; 32], t.label(), &[])?;
            assert_eq!(
                tables.get(t).expose_secret(),
                generic.expose_secret(),
                "{t:?}"
            );
        }
        let generic_db = secmp_crypto::hkdf::<32>(&[0; 32], &[0x4d; 32], Label::StoreDb, &[])?;
        assert_eq!(db.locked().expose_secret(), generic_db.expose_secret());
        Ok(())
    }
}
