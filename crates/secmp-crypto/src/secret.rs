// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secret byte containers (docs/04 CS-2.1, CS-2.2; docs/06 §2): zeroised on drop, no `Clone`, no `Debug`, no
//! `PartialEq`; compared only in constant time ([`subtle::ConstantTimeEq`]); read only through an explicit
//! `expose_secret()`.

use secmp_sys_mem::{Backend, SecretPage};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::rng;

/// `N` secret bytes on the heap (a move copies only the pointer, so no stale copies are left on the stack),
/// zeroised on drop. For short-lived secrets: message keys, shared secrets, derived keys.
pub struct SecretBytes<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
    /// All zero; filled by the caller through [`SecretBytes::expose_secret_mut`].
    pub(crate) fn zero() -> Self {
        Self(Box::new([0; N]))
    }

    /// `N` bytes from the operating system CSPRNG.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the operating system cannot provide randomness.
    pub fn random() -> Result<Self> {
        let mut s = Self::zero();
        rng::fill(s.expose_secret_mut())?;
        Ok(s)
    }

    /// A copy of `bytes` (the caller remains responsible for its own copy).
    ///
    /// # Errors
    /// [`Error::Rejected`] if `bytes` is not exactly `N` bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(Error::Rejected);
        }
        let mut s = Self::zero();
        s.expose_secret_mut().copy_from_slice(bytes);
        Ok(s)
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }

    pub(crate) fn expose_secret_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

/// `N` secret bytes in a locked page between guard pages (`secmp_sys_mem::SecretPage`, CS-2.2), zeroised on
/// drop. For long-lived secrets: identity keys, prekey seeds, and later the master and root keys.
pub struct LockedSecret<const N: usize>(SecretPage<N>);

impl<const N: usize> LockedSecret<N> {
    fn page() -> Result<SecretPage<N>> {
        Ok(SecretPage::new()?)
    }

    /// `N` bytes from the operating system CSPRNG, generated directly into locked memory.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if randomness or locked memory is unavailable.
    pub fn random() -> Result<Self> {
        let mut page = Self::page()?;
        rng::fill(page.get_mut())?;
        Ok(Self(page))
    }

    /// A copy of `bytes` in locked memory (the caller remains responsible for its own copy).
    ///
    /// # Errors
    /// [`Error::Rejected`] if `bytes` is not exactly `N` bytes long; [`Error::Unavailable`] if locked memory is
    /// unavailable.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(Error::Rejected);
        }
        let mut page = Self::page()?;
        page.get_mut().copy_from_slice(bytes);
        Ok(Self(page))
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.get()
    }

    /// The mechanism protecting the page (for the client's security status).
    #[must_use]
    pub fn protection(&self) -> Backend {
        self.0.backend()
    }
}

impl<const N: usize> ZeroizeOnDrop for LockedSecret<N> {}

impl<const N: usize> ConstantTimeEq for LockedSecret<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.get().as_slice().ct_eq(other.0.get().as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_basics() -> Result<()> {
        let a = SecretBytes::<16>::from_slice(&[7; 16])?;
        let b = SecretBytes::<16>::from_slice(&[7; 16])?;
        let c = SecretBytes::<16>::from_slice(&[8; 16])?;
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
        assert_eq!(a.expose_secret(), &[7; 16]);
        assert_eq!(
            SecretBytes::<16>::from_slice(&[0; 15]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            SecretBytes::<16>::from_slice(&[0; 17]).err(),
            Some(Error::Rejected)
        );
        let r1 = SecretBytes::<32>::random()?;
        let r2 = SecretBytes::<32>::random()?;
        assert!(!bool::from(r1.ct_eq(&r2)));
        assert_eq!(SecretBytes::<4>::zero().expose_secret(), &[0; 4]);
        Ok(())
    }

    #[test]
    fn secret_bytes_zeroise_on_drop_step() -> Result<()> {
        let mut s = SecretBytes::<8>::from_slice(&[0xff; 8])?;
        s.expose_secret_mut().zeroize();
        assert_eq!(s.expose_secret(), &[0; 8]);
        Ok(())
    }

    #[test]
    fn locked_secret_basics() -> Result<()> {
        let a = LockedSecret::<32>::from_slice(&[1; 32])?;
        let b = LockedSecret::<32>::from_slice(&[1; 32])?;
        let c = LockedSecret::<32>::random()?;
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
        assert_eq!(a.expose_secret(), &[1; 32]);
        assert_eq!(
            LockedSecret::<32>::from_slice(&[0; 31]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            a.protection() == Backend::Heap,
            cfg!(miri),
            "only Miri uses the heap backend"
        );
        Ok(())
    }
}
