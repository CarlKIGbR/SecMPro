// SPDX-License-Identifier: AGPL-3.0-or-later
//! The random inputs of the store's compositions (salts, nonces, master keys), drawn from the operating system CSPRNG
//! through `secmp-crypto` (CLAUDE.md §4: `OsRng` only). Feature `kat`: a test can queue fixed bytes
//! ([`crate::kat::fixed_random`]); each draw takes from that queue first (the known-answer rows BK-04, ST-07).

use secmp_crypto::{LockedSecret, Nonce24};

use crate::error::{Error, Result};
use crate::secrets::StoreKey;

/// `N` random bytes that are not secret (a salt).
pub(crate) fn public<const N: usize>() -> Result<[u8; N]> {
    #[cfg(feature = "kat")]
    if let Some(b) = crate::kat::take_fixed::<N>() {
        return Ok(b);
    }
    let r = LockedSecret::<N>::random().map_err(|_| Error::Unavailable)?;
    Ok(*r.expose_secret())
}

/// A random 24-byte nonce.
pub(crate) fn nonce() -> Result<Nonce24> {
    #[cfg(feature = "kat")]
    if let Some(b) = crate::kat::take_fixed::<24>() {
        return Ok(Nonce24::from_bytes_kat(b));
    }
    Nonce24::random().map_err(|_| Error::Unavailable)
}

/// A random 32-byte key in a locked page.
pub(crate) fn key() -> Result<StoreKey> {
    #[cfg(feature = "kat")]
    if let Some(b) = crate::kat::take_fixed::<32>() {
        return Ok(StoreKey::new(
            LockedSecret::from_slice(&b).map_err(|_| Error::Unavailable)?,
        ));
    }
    StoreKey::random()
}
