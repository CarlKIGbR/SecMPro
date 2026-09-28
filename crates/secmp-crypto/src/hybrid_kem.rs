// SPDX-License-Identifier: AGPL-3.0-or-later
//! `HybridKEM-768` and `HybridKEM-1024` (spec §3.2): X25519 + ML-KEM with an X-Wing-shaped combiner that binds
//! the KEM ciphertext, the encapsulation key and both X25519 public keys:
//!
//! ```text
//! ss = SHA3-256( ss_kem ‖ ss_dh ‖ SHA3-256(ct_kem) ‖ SHA3-256(ek_kem) ‖ pk_dh ‖ pk_e ‖ V )
//! ```
//!
//! with `V` the ASCII label `"SecMP-HybridKEM-768/1"` or `"SecMP-HybridKEM-1024/1"` appended raw. `pk_dh` is the
//! recipient's static X25519 key, `pk_e` the ephemeral one, both as transmitted bytes. An all-zero X25519 output
//! is rejected on both sides; ML-KEM decapsulation rejects implicitly (a wrong ciphertext of the right length
//! yields a pseudo-random `ss`, not an error — spec Appendix C).

use crate::error::Result;
use crate::hash::{sha3_256, sha3_256_secret};
use crate::label::Label;
use crate::mlkem::{
    MLKEM_SS_LEN, MlKem768Ct, MlKem768Dk, MlKem768Ek, MlKem1024Ct, MlKem1024Dk, MlKem1024Ek,
};
use crate::secret::SecretBytes;
use crate::x25519::{X25519Public, X25519Secret};

/// Length of a hybrid shared secret.
pub const HYBRID_SS_LEN: usize = 32;

/// The combiner of spec §3.2, inputs in exactly the listed order.
fn combine(
    ss_kem: &SecretBytes<MLKEM_SS_LEN>,
    ss_dh: &SecretBytes<32>,
    ct_kem: &[u8],
    ek_kem: &[u8],
    pk_dh: &X25519Public,
    pk_e: &X25519Public,
    v: Label,
) -> SecretBytes<HYBRID_SS_LEN> {
    let h_ct = sha3_256(&[ct_kem]);
    let h_ek = sha3_256(&[ek_kem]);
    sha3_256_secret(&[
        ss_kem.expose_secret(),
        ss_dh.expose_secret(),
        &h_ct,
        &h_ek,
        pk_dh.as_bytes(),
        pk_e.as_bytes(),
        v.as_bytes(),
    ])
}

macro_rules! hybrid_kem {
    (
        $name:literal, $v:expr,
        $pk:ident, $sk:ident, $ct:ident,
        $ek:ident, $dk:ident, $kct:ident
    ) => {
        #[doc = concat!("A ", $name, " public key `(pk_dh, ek_kem)`.")]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $pk {
            pk_dh: X25519Public,
            ek: $ek,
        }

        impl $pk {
            /// The public key from its parts (`ek` was validated on import).
            #[must_use]
            pub fn new(pk_dh: X25519Public, ek: $ek) -> Self {
                Self { pk_dh, ek }
            }

            /// The X25519 part.
            #[must_use]
            pub fn pk_dh(&self) -> &X25519Public {
                &self.pk_dh
            }

            /// The ML-KEM part.
            #[must_use]
            pub fn ek(&self) -> &$ek {
                &self.ek
            }

            /// `Encaps(pk)` with a fresh ephemeral X25519 key and fresh ML-KEM randomness.
            ///
            /// # Errors
            /// [`Error::Rejected`](crate::Error::Rejected) if the X25519 output is all zero (a low-order
            /// `pk_dh`); [`Error::Unavailable`](crate::Error::Unavailable) if randomness or locked memory is
            /// unavailable.
            pub fn encapsulate(&self) -> Result<($ct, SecretBytes<HYBRID_SS_LEN>)> {
                let sk_e = X25519Secret::generate()?;
                let m = SecretBytes::<32>::random()?;
                self.encapsulate_with(&sk_e, &m)
            }

            fn encapsulate_with(
                &self,
                sk_e: &X25519Secret,
                m: &SecretBytes<32>,
            ) -> Result<($ct, SecretBytes<HYBRID_SS_LEN>)> {
                // spec §3.2 Encaps: (sk_e, pk_e) = X25519.keygen()
                let pk_e = sk_e.public_key();
                // ss_dh = X25519(sk_e, pk_dh), MUST NOT be all-zero
                let ss_dh = sk_e.diffie_hellman(&self.pk_dh)?;
                // (ct_kem, ss_kem) = ML-KEM.Encaps(ek_kem)
                let (ct_kem, ss_kem) = self.ek.encapsulate_with(m);
                // ss = SHA3-256(ss_kem ‖ ss_dh ‖ SHA3-256(ct_kem) ‖ SHA3-256(ek_kem) ‖ pk_dh ‖ pk_e ‖ V)
                let ss = combine(
                    &ss_kem,
                    &ss_dh,
                    ct_kem.as_bytes(),
                    self.ek.as_bytes(),
                    &self.pk_dh,
                    &pk_e,
                    $v,
                );
                Ok(($ct { pk_e, ct: ct_kem }, ss))
            }

            /// `Encaps(pk)` with fixed ephemeral secret `sk_e` and ML-KEM randomness `m`, for known-answer tests
            /// and vector generation (feature `kat`).
            ///
            /// # Errors
            /// As [`Self::encapsulate`].
            #[cfg(feature = "kat")]
            pub fn encapsulate_kat(
                &self,
                sk_e: &[u8; 32],
                m: &[u8; 32],
            ) -> Result<($ct, SecretBytes<HYBRID_SS_LEN>)> {
                let sk_e = X25519Secret::from_bytes(sk_e)?;
                let m = SecretBytes::<32>::from_slice(m)?;
                self.encapsulate_with(&sk_e, &m)
            }
        }

        impl core::fmt::Debug for $pk {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($pk), "(..)"))
            }
        }

        #[doc = concat!("A ", $name, " secret key `(sk_dh, dk_kem)`; both parts in locked memory.")]
        pub struct $sk {
            sk_dh: X25519Secret,
            dk: $dk,
        }

        impl $sk {
            /// A new random key.
            ///
            /// # Errors
            /// [`Error::Unavailable`](crate::Error::Unavailable) if randomness or locked memory is unavailable.
            pub fn generate() -> Result<Self> {
                Ok(Self {
                    sk_dh: X25519Secret::generate()?,
                    dk: $dk::generate()?,
                })
            }

            /// The key from its parts.
            #[must_use]
            pub fn from_parts(sk_dh: X25519Secret, dk: $dk) -> Self {
                Self { sk_dh, dk }
            }

            /// The public key.
            #[must_use]
            pub fn public_key(&self) -> $pk {
                $pk {
                    pk_dh: self.sk_dh.public_key(),
                    ek: self.dk.encapsulation_key(),
                }
            }

            /// `Decaps(sk, ct)`.
            ///
            /// # Errors
            /// [`Error::Rejected`](crate::Error::Rejected) if the X25519 output is all zero (a low-order
            /// `pk_e`). A wrong ML-KEM ciphertext is not an error (implicit rejection).
            pub fn decapsulate(&self, ct: &$ct) -> Result<SecretBytes<HYBRID_SS_LEN>> {
                // spec §3.2 Decaps: ss_dh = X25519(sk_dh, pk_e), MUST NOT be all-zero
                let ss_dh = self.sk_dh.diffie_hellman(&ct.pk_e)?;
                // ss_kem = ML-KEM.Decaps(dk_kem, ct_kem), implicit rejection per FIPS 203
                let (ss_kem, ek) = self.dk.decapsulate_with_ek(&ct.ct);
                // ss = SHA3-256( ... as in Encaps ... ), with pk_dh the recipient's own static key
                let pk_dh = self.sk_dh.public_key();
                Ok(combine(
                    &ss_kem,
                    &ss_dh,
                    ct.ct.as_bytes(),
                    ek.as_bytes(),
                    &pk_dh,
                    &ct.pk_e,
                    $v,
                ))
            }
        }

        #[doc = concat!("A ", $name, " ciphertext `(pk_e, ct_kem)`.")]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $ct {
            pk_e: X25519Public,
            ct: $kct,
        }

        impl $ct {
            /// The ciphertext from its parts.
            #[must_use]
            pub fn new(pk_e: X25519Public, ct: $kct) -> Self {
                Self { pk_e, ct }
            }

            /// The ephemeral X25519 public key.
            #[must_use]
            pub fn pk_e(&self) -> &X25519Public {
                &self.pk_e
            }

            /// The ML-KEM ciphertext.
            #[must_use]
            pub fn ct(&self) -> &$kct {
                &self.ct
            }
        }

        impl core::fmt::Debug for $ct {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($ct), "(..)"))
            }
        }
    };
}

hybrid_kem!(
    "HybridKEM-768",
    Label::HybridKem768,
    HybridKem768PublicKey,
    HybridKem768SecretKey,
    HybridKem768Ciphertext,
    MlKem768Ek,
    MlKem768Dk,
    MlKem768Ct
);
hybrid_kem!(
    "HybridKEM-1024",
    Label::HybridKem1024,
    HybridKem1024PublicKey,
    HybridKem1024SecretKey,
    HybridKem1024Ciphertext,
    MlKem1024Ek,
    MlKem1024Dk,
    MlKem1024Ct
);

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;
    use crate::error::Error;
    use crate::test_util::unhex_n;

    #[test]
    fn round_trips() -> Result<()> {
        let sk = HybridKem768SecretKey::generate()?;
        let (ct, ss) = sk.public_key().encapsulate()?;
        assert!(bool::from(sk.decapsulate(&ct)?.ct_eq(&ss)));
        let sk = HybridKem1024SecretKey::generate()?;
        let (ct, ss) = sk.public_key().encapsulate()?;
        assert!(bool::from(sk.decapsulate(&ct)?.ct_eq(&ss)));
        Ok(())
    }

    /// The combiner, recomputed from its parts in the spec's order (the X25519 and ML-KEM parts are checked
    /// against RFC 7748 and FIPS 203 vectors elsewhere).
    #[test]
    fn combiner_order_and_label() -> Result<()> {
        let sk = HybridKem768SecretKey::from_parts(
            X25519Secret::from_bytes(&[1; 32])?,
            MlKem768Dk::from_seed(&[2; 64])?,
        );
        let pk = sk.public_key();
        let sk_e = X25519Secret::from_bytes(&[3; 32])?;
        let m = SecretBytes::<32>::from_slice(&[4; 32])?;
        let (ct, ss) = pk.encapsulate_with(&sk_e, &m)?;
        let ss_dh = sk_e.diffie_hellman(pk.pk_dh())?;
        let (_, ss_kem) = pk.ek().encapsulate_with(&m);
        let expected = crate::hash::sha3_256(&[
            ss_kem.expose_secret(),
            ss_dh.expose_secret(),
            &crate::hash::sha3_256(&[ct.ct().as_bytes()]),
            &crate::hash::sha3_256(&[pk.ek().as_bytes()]),
            pk.pk_dh().as_bytes(),
            ct.pk_e().as_bytes(),
            b"SecMP-HybridKEM-768/1",
        ]);
        assert_eq!(ss.expose_secret(), &expected);
        assert!(bool::from(sk.decapsulate(&ct)?.ct_eq(&ss)));
        Ok(())
    }

    #[test]
    fn low_order_keys_are_rejected_on_both_sides() -> Result<()> {
        let sk = HybridKem1024SecretKey::generate()?;
        let pk = sk.public_key();
        let bad_pk =
            HybridKem1024PublicKey::new(X25519Public::from_bytes(&[0; 32])?, pk.ek().clone());
        assert_eq!(bad_pk.encapsulate().err(), Some(Error::Rejected));
        let (ct, _) = pk.encapsulate()?;
        for u in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        ] {
            let bad = HybridKem1024Ciphertext::new(
                X25519Public::from_bytes(&unhex_n::<32>(u))?,
                ct.ct().clone(),
            );
            assert_eq!(sk.decapsulate(&bad).err(), Some(Error::Rejected), "{u}");
        }
        Ok(())
    }

    /// Spec Appendix C / SCHEMA §4.4 rows 10–12: a flipped KEM ciphertext or a flipped (non-low-order) `pk_e`
    /// decapsulates to a different secret without an error.
    #[test]
    fn tampering_changes_the_secret_without_error() -> Result<()> {
        let sk = HybridKem768SecretKey::generate()?;
        let (ct, ss) = sk.public_key().encapsulate()?;
        let mut kem = *ct.ct().as_bytes();
        kem[0] ^= 1;
        let flipped = HybridKem768Ciphertext::new(*ct.pk_e(), MlKem768Ct::from_bytes(&kem)?);
        assert!(!bool::from(sk.decapsulate(&flipped)?.ct_eq(&ss)));
        let mut e = *ct.pk_e().as_bytes();
        e[0] ^= 1;
        let flipped_e = HybridKem768Ciphertext::new(X25519Public::from_bytes(&e)?, ct.ct().clone());
        assert!(!bool::from(sk.decapsulate(&flipped_e)?.ct_eq(&ss)));
        Ok(())
    }

    #[test]
    fn debug_is_redacted() -> Result<()> {
        let sk = HybridKem768SecretKey::generate()?;
        let pk = sk.public_key();
        let (ct, _) = pk.encapsulate()?;
        assert_eq!(format!("{pk:?}"), "HybridKem768PublicKey(..)");
        assert_eq!(format!("{ct:?}"), "HybridKem768Ciphertext(..)");
        Ok(())
    }
}
