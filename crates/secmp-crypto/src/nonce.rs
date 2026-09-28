// SPDX-License-Identifier: AGPL-3.0-or-later
//! Single-use nonces and counters (docs/06 §2 "Nonces are never reused"): both types are consumed by value and
//! are neither `Clone` nor `Copy`, so the type system prevents sealing twice with one nonce or reusing a
//! counter value.

use crate::error::{Error, Result};
use crate::rng;

/// A fresh 24-byte XChaCha20-Poly1305 nonce (spec §3.4: "`XChaCha` nonces elsewhere are random 24 B"). Consumed
/// by the sealing operation; received nonces are plain `&[u8; 24]` on the opening side.
pub struct Nonce24([u8; 24]);

impl Nonce24 {
    /// A nonce from the operating system CSPRNG.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the operating system cannot provide randomness.
    pub fn random() -> Result<Self> {
        let mut n = [0; 24];
        rng::fill(&mut n)?;
        Ok(Self(n))
    }

    /// A fixed nonce, for known-answer tests and vector generation only (feature `kat`).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn from_bytes_kat(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// The nonce value, e.g. to transmit it next to the ciphertext. The copy cannot be used to seal again: only
    /// a [`Nonce24`] seals.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    pub(crate) fn into_bytes(self) -> [u8; 24] {
        self.0
    }
}

/// A 64-bit message counter, consumed by value on every step. Sending uses [`Counter64::next`]; receiving
/// accepts only the exact next value ([`Counter64::accept`], "strict +1 on receive", CLAUDE.md §5). Overflow is
/// an error, never a wrap (the caller aborts the session).
pub struct Counter64(u64);

impl Counter64 {
    /// A counter starting at 0.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// The value the next [`Counter64::next`] returns, or [`Counter64::accept`] expects.
    #[must_use]
    pub const fn peek(&self) -> u64 {
        self.0
    }

    /// Use the current value; returns it together with the successor counter.
    ///
    /// # Errors
    /// [`Error::Rejected`] if the counter would overflow (`u64::MAX` is never used).
    pub fn next(self) -> Result<(u64, Self)> {
        let succ = self.0.checked_add(1).ok_or(Error::Rejected)?;
        Ok((self.0, Self(succ)))
    }

    /// Accept a received counter value: it must be exactly the expected one; returns the successor.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any other value (replay, gap, reordering) or on overflow; the counter is consumed
    /// and the session must be torn down.
    pub fn accept(self, received: u64) -> Result<Self> {
        if received != self.0 {
            return Err(Error::Rejected);
        }
        self.next().map(|(_, succ)| succ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_random() -> Result<()> {
        let a = Nonce24::random()?;
        let b = Nonce24::random()?;
        assert_ne!(a.as_bytes(), b.as_bytes());
        let copy = *a.as_bytes();
        assert_eq!(a.into_bytes(), copy);
        Ok(())
    }

    #[test]
    fn counter_sends_in_order() -> Result<()> {
        let c = Counter64::zero();
        assert_eq!(c.peek(), 0);
        let (v0, c) = c.next()?;
        let (v1, c) = c.next()?;
        assert_eq!((v0, v1, c.peek()), (0, 1, 2));
        Ok(())
    }

    #[test]
    fn counter_receives_strictly_plus_one() -> Result<()> {
        let c = Counter64::zero().accept(0)?.accept(1)?;
        assert_eq!(c.peek(), 2);
        assert_eq!(Counter64::zero().accept(1).err(), Some(Error::Rejected));
        let c2 = Counter64::zero().accept(0)?;
        assert_eq!(c2.accept(0).err(), Some(Error::Rejected), "replay");
        assert_eq!(
            Counter64::zero().accept(u64::MAX).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }

    #[test]
    fn counter_never_wraps() {
        let top = Counter64(u64::MAX);
        assert_eq!(top.next().err(), Some(Error::Rejected));
        let top = Counter64(u64::MAX);
        assert_eq!(top.accept(u64::MAX).err(), Some(Error::Rejected));
        let below = Counter64(u64::MAX - 1);
        assert!(matches!(below.next(), Ok((v, c)) if v == u64::MAX - 1 && c.peek() == u64::MAX));
    }
}
