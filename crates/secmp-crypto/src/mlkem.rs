// SPDX-License-Identifier: AGPL-3.0-or-later
//! ML-KEM-768 and ML-KEM-1024 (FIPS 203; spec §3 table) via `libcrux-ml-kem` (ADR-023).
//!
//! - Decapsulation keys are stored as their 64-byte seed `d ‖ z` in locked memory and expanded with
//!   `KeyGen_internal(d, z)` for each use; the expanded key is zeroised afterwards (spec §3: "Decapsulation keys
//!   stored as 64-byte seeds").
//! - Encapsulation keys received from others are validated on import (FIPS 203 §7.2 type and modulus checks,
//!   CLAUDE.md §5).
//! - Decapsulation uses FIPS 203 implicit rejection: an invalid ciphertext of the right length yields the
//!   pseudo-random `J(z ‖ c)`, not an error (spec §3.2, Appendix C).

use core::fmt;

use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::{LockedSecret, SecretBytes};

/// Length of an ML-KEM seed `d ‖ z`.
pub const MLKEM_SEED_LEN: usize = 64;
/// Length of an ML-KEM shared secret.
pub const MLKEM_SS_LEN: usize = 32;

macro_rules! ml_kem {
    (
        $module:ident, $name:literal,
        $dk:ident, $ek:ident, $ct:ident,
        $ek_len_name:ident = $ek_len:literal, $ct_len_name:ident = $ct_len:literal, sk_len = $sk_len:literal
    ) => {
        #[doc = concat!("Length of an ", $name, " encapsulation key.")]
        pub const $ek_len_name: usize = $ek_len;
        #[doc = concat!("Length of an ", $name, " ciphertext.")]
        pub const $ct_len_name: usize = $ct_len;

        #[doc = concat!("An ", $name, " decapsulation key, held as its 64-byte seed `d ‖ z` in locked memory.")]
        pub struct $dk(LockedSecret<MLKEM_SEED_LEN>);

        impl $dk {
            /// A new random key.
            ///
            /// # Errors
            /// [`Error::Unavailable`] if randomness or locked memory is unavailable.
            pub fn generate() -> Result<Self> {
                Ok(Self(LockedSecret::random()?))
            }

            /// The key with the given 64-byte seed `d ‖ z` (`KeyGen_internal(d, z)`).
            ///
            /// # Errors
            /// [`Error::Rejected`] unless `seed` is 64 bytes long; [`Error::Unavailable`] if locked memory is
            /// unavailable.
            pub fn from_seed(seed: &[u8]) -> Result<Self> {
                Ok(Self(LockedSecret::from_slice(seed)?))
            }

            /// Expand the seed, run `f` on the key pair, zeroise the expanded decapsulation key.
            fn with_key_pair<T>(
                &self,
                f: impl FnOnce(&libcrux_ml_kem::MlKemKeyPair<$sk_len, $ek_len>) -> T,
            ) -> T {
                let kp = libcrux_ml_kem::$module::generate_key_pair(*self.0.expose_secret());
                let out = f(&kp);
                let (mut sk, _pk) = kp.into_parts();
                sk[0..].zeroize();
                out
            }

            /// The expanded decapsulation key (FIPS 203 `dk`), for differential tests with libraries that import
            /// only expanded keys (feature `kat`; SecMP itself stores and uses only the seed).
            #[cfg(feature = "kat")]
            #[must_use]
            pub fn expanded_kat(&self) -> Vec<u8> {
                self.with_key_pair(|kp| kp.sk().to_vec())
            }

            /// The encapsulation key of this decapsulation key.
            #[must_use]
            pub fn encapsulation_key(&self) -> $ek {
                self.with_key_pair(|kp| $ek(Box::new(*kp.pk())))
            }

            /// `ML-KEM.Decaps(dk, ct)` with implicit rejection.
            #[must_use]
            pub fn decapsulate(&self, ct: &$ct) -> SecretBytes<MLKEM_SS_LEN> {
                self.decapsulate_with_ek(ct).0
            }

            /// Decapsulate and also return the encapsulation key (one key expansion for both; the hybrid
            /// combiner needs `ek`).
            pub(crate) fn decapsulate_with_ek(&self, ct: &$ct) -> (SecretBytes<MLKEM_SS_LEN>, $ek) {
                self.with_key_pair(|kp| {
                    let ct = libcrux_ml_kem::MlKemCiphertext::<$ct_len>::from(&*ct.0);
                    let mut ss = libcrux_ml_kem::$module::decapsulate(kp.private_key(), &ct);
                    let mut out = SecretBytes::<MLKEM_SS_LEN>::zero();
                    out.expose_secret_mut().copy_from_slice(&ss);
                    ss.zeroize();
                    (out, $ek(Box::new(*kp.pk())))
                })
            }
        }

        #[doc = concat!("An ", $name, " encapsulation key; keys from others are validated on import.")]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $ek(Box<[u8; $ek_len]>);

        impl $ek {
            /// Import an encapsulation key: exact length and the FIPS 203 §7.2 modulus check.
            ///
            /// # Errors
            /// [`Error::Rejected`] on a wrong length or a packed coefficient ≥ q.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let arr: [u8; $ek_len] = bytes.try_into().map_err(|_| Error::Rejected)?;
                let pk = libcrux_ml_kem::MlKemPublicKey::<$ek_len>::from(&arr);
                if !libcrux_ml_kem::$module::validate_public_key(&pk) {
                    return Err(Error::Rejected);
                }
                Ok(Self(Box::new(arr)))
            }

            /// The encoded key.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $ek_len] {
                &self.0
            }

            /// `ML-KEM.Encaps(ek)` with fresh randomness.
            ///
            /// # Errors
            /// [`Error::Unavailable`] if randomness is unavailable.
            pub fn encapsulate(&self) -> Result<($ct, SecretBytes<MLKEM_SS_LEN>)> {
                let m = SecretBytes::<32>::random()?;
                Ok(self.encapsulate_with(&m))
            }

            /// `ML-KEM.Encaps_internal(ek, m)` with the given randomness `m`.
            pub(crate) fn encapsulate_with(
                &self,
                m: &SecretBytes<32>,
            ) -> ($ct, SecretBytes<MLKEM_SS_LEN>) {
                let pk = libcrux_ml_kem::MlKemPublicKey::<$ek_len>::from(&*self.0);
                let (ct, mut ss) = libcrux_ml_kem::$module::encapsulate(&pk, *m.expose_secret());
                let mut out = SecretBytes::<MLKEM_SS_LEN>::zero();
                out.expose_secret_mut().copy_from_slice(&ss);
                ss.zeroize();
                ($ct(Box::new(*ct.as_slice())), out)
            }

            /// `ML-KEM.Encaps_internal(ek, m)` with fixed randomness, for known-answer tests (feature `kat`).
            #[cfg(feature = "kat")]
            #[must_use]
            pub fn encapsulate_kat(&self, m: &[u8; 32]) -> ($ct, SecretBytes<MLKEM_SS_LEN>) {
                let mut s = SecretBytes::<32>::zero();
                s.expose_secret_mut().copy_from_slice(m);
                self.encapsulate_with(&s)
            }
        }

        impl fmt::Debug for $ek {
            /// Redacted: key bytes never reach logs (docs/04 CS-2.5).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ek), "(..)"))
            }
        }

        #[doc = concat!("An ", $name, " ciphertext (length-checked; any content decapsulates, FIPS 203 implicit rejection).")]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $ct(Box<[u8; $ct_len]>);

        impl $ct {
            /// A ciphertext of exactly the right length.
            ///
            /// # Errors
            /// [`Error::Rejected`] on any other length.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                Ok(Self(Box::new(bytes.try_into().map_err(|_| Error::Rejected)?)))
            }

            /// The encoded ciphertext.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $ct_len] {
                &self.0
            }
        }

        impl fmt::Debug for $ct {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ct), "(..)"))
            }
        }
    };
}

ml_kem!(
    mlkem768,
    "ML-KEM-768",
    MlKem768Dk,
    MlKem768Ek,
    MlKem768Ct,
    MLKEM768_EK_LEN = 1184,
    MLKEM768_CT_LEN = 1088,
    sk_len = 2400
);
ml_kem!(
    mlkem1024,
    "ML-KEM-1024",
    MlKem1024Dk,
    MlKem1024Ek,
    MlKem1024Ct,
    MLKEM1024_EK_LEN = 1568,
    MLKEM1024_CT_LEN = 1568,
    sk_len = 3168
);

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;

    #[test]
    fn round_trip_768_and_1024() -> Result<()> {
        let dk = MlKem768Dk::generate()?;
        let (ct, ss) = dk.encapsulation_key().encapsulate()?;
        assert!(bool::from(dk.decapsulate(&ct).ct_eq(&ss)));
        let dk = MlKem1024Dk::generate()?;
        let (ct, ss) = dk.encapsulation_key().encapsulate()?;
        assert!(bool::from(dk.decapsulate(&ct).ct_eq(&ss)));
        Ok(())
    }

    #[test]
    fn seed_is_the_key() -> Result<()> {
        let seed = [0x42_u8; MLKEM_SEED_LEN];
        let a = MlKem768Dk::from_seed(&seed)?;
        let b = MlKem768Dk::from_seed(&seed)?;
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());
        let c = MlKem768Dk::from_seed(&[0x43; MLKEM_SEED_LEN])?;
        assert_ne!(a.encapsulation_key(), c.encapsulation_key());
        assert_eq!(MlKem768Dk::from_seed(&[0; 63]).err(), Some(Error::Rejected));
        assert_eq!(
            MlKem1024Dk::from_seed(&[0; 65]).err(),
            Some(Error::Rejected)
        );
        Ok(())
    }

    /// `vectors/SCHEMA.md` §4.4 rows 17–18: a packed coefficient ≥ q fails the modulus check; a short key fails
    /// the length check.
    #[test]
    fn encapsulation_key_import_is_validated() -> Result<()> {
        let ek = MlKem768Dk::generate()?.encapsulation_key();
        assert_eq!(&MlKem768Ek::from_bytes(ek.as_bytes())?, &ek);
        let mut bad = *ek.as_bytes();
        bad[..3].copy_from_slice(&[0xff; 3]);
        assert_eq!(MlKem768Ek::from_bytes(&bad).err(), Some(Error::Rejected));
        let short = ek.as_bytes().split_last().map_or(&[][..], |(_, rest)| rest);
        assert_eq!(MlKem768Ek::from_bytes(short).err(), Some(Error::Rejected));
        let ek = MlKem1024Dk::generate()?.encapsulation_key();
        assert_eq!(&MlKem1024Ek::from_bytes(ek.as_bytes())?, &ek);
        let mut bad = *ek.as_bytes();
        bad[..3].copy_from_slice(&[0xff; 3]);
        assert_eq!(MlKem1024Ek::from_bytes(&bad).err(), Some(Error::Rejected));
        assert_eq!(MlKem1024Ek::from_bytes(&[]).err(), Some(Error::Rejected));
        Ok(())
    }

    #[test]
    fn implicit_rejection_on_a_flipped_ciphertext() -> Result<()> {
        let dk = MlKem768Dk::generate()?;
        let (ct, ss) = dk.encapsulation_key().encapsulate()?;
        let mut flipped = *ct.as_bytes();
        flipped[0] ^= 1;
        let flipped = MlKem768Ct::from_bytes(&flipped)?;
        let r1 = dk.decapsulate(&flipped);
        let r2 = dk.decapsulate(&flipped);
        assert!(
            !bool::from(r1.ct_eq(&ss)),
            "no error, but not the honest secret"
        );
        assert!(
            bool::from(r1.ct_eq(&r2)),
            "implicit rejection is deterministic"
        );
        Ok(())
    }

    #[test]
    fn ciphertext_lengths_and_debug() -> Result<()> {
        assert_eq!(
            MlKem768Ct::from_bytes(&[0; 1089]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            MlKem1024Ct::from_bytes(&[0; 1567]).err(),
            Some(Error::Rejected)
        );
        let ct = MlKem1024Ct::from_bytes(&[7; MLKEM1024_CT_LEN])?;
        assert_eq!(ct.as_bytes(), &[7; MLKEM1024_CT_LEN]);
        assert_eq!(format!("{ct:?}"), "MlKem1024Ct(..)");
        let ek = MlKem768Dk::generate()?.encapsulation_key();
        assert_eq!(format!("{ek:?}"), "MlKem768Ek(..)");
        assert_eq!(MLKEM768_CT_LEN, 1088);
        assert_eq!(MLKEM768_EK_LEN, 1184);
        Ok(())
    }
}
