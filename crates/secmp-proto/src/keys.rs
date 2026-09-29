// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public-key and signature fields with the decoder obligations of spec §4.1 (rev 2.3, ADR-039): the checks run
//! when a field is constructed or decoded, through `secmp-crypto`, and need no message.
//!
//! - X25519 (`relay_dh_pk`, `e_c`, `pk_e1`, `e_r`, `ik_dh`, `spk_dh`, `opk_dh`, `ek_I`, `dh_pk`): low order refused
//!   (obligation (a)).
//! - Ed25519 keys (`relay_sig_pk`, `ik_ed25519`, `recv_pk`, `send_pk`, `owner_pk`): canonical, not of small order,
//!   a curve point; Ed25519 signatures and the first 64 bytes of a `HybridSig`: the same rules on `R`, `S < L`
//!   (obligation (b)).
//! - ML-KEM encapsulation keys (`relay_kem_ek`, `ek_c`, `spk_kem`, `rpk_kem`, `opk_kem`, `ek_pq`): the FIPS 203
//!   §7.2 modulus check (obligation (c)).
//! - The ML-DSA-65 half of a `HybridSig` is not decoded (no sigDecode at decode).
//!
//! `Debug` is redacted for every type here (docs/04 CS-2.5: key bytes never reach logs).

use core::fmt;

use crate::codec::{Decode, Encode, Reader, Writer, boxed};
use crate::error::{Error, Result};
use crate::sizes::{
    ED25519_PK_LEN, ED25519_SIG_LEN, HYBRID_SIG_LEN, MLKEM768_EK_LEN, MLKEM1024_EK_LEN,
    X25519_PK_LEN,
};

macro_rules! redacted_debug {
    ($t:ident) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($t), "(..)"))
            }
        }
    };
}

/// An X25519 public-key field: any 32 bytes except the low-order encodings (spec §4.1 (a)), kept as received.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X25519Pk([u8; X25519_PK_LEN]);

impl X25519Pk {
    /// The field with these bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 32 bytes and not of low order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            *secmp_crypto::X25519Public::from_bytes_checked(bytes)?.as_bytes(),
        ))
    }

    /// The bytes as received.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; X25519_PK_LEN] {
        &self.0
    }
}

redacted_debug!(X25519Pk);

impl Encode for X25519Pk {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.0);
        Ok(())
    }
}

impl Decode for X25519Pk {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(r.take(X25519_PK_LEN)?)
    }
}

/// An Ed25519 public-key field: canonical, not of small order, a curve point (spec §3.5, §4.1 (b)).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Pk([u8; ED25519_PK_LEN]);

impl Ed25519Pk {
    /// The field with these bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 32 bytes passing the §3.5 key rules.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            *secmp_crypto::Ed25519VerifyingKey::from_bytes(bytes)?.as_bytes(),
        ))
    }

    /// The encoded key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_PK_LEN] {
        &self.0
    }
}

redacted_debug!(Ed25519Pk);

impl Encode for Ed25519Pk {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.0);
        Ok(())
    }
}

impl Decode for Ed25519Pk {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(r.take(ED25519_PK_LEN)?)
    }
}

/// An Ed25519 signature field `R ‖ S`: `R` passes the key rules, `S < L` (spec §4.1 (b)). Verification happens
/// at use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Sig([u8; ED25519_SIG_LEN]);

impl Ed25519Sig {
    /// The field with these bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 64 bytes passing the message-free signature checks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        secmp_crypto::check_ed25519_signature_encoding(bytes)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::Rejected)?))
    }

    /// The encoded signature.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_SIG_LEN] {
        &self.0
    }
}

redacted_debug!(Ed25519Sig);

impl Encode for Ed25519Sig {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.0);
        Ok(())
    }
}

impl Decode for Ed25519Sig {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(r.take(ED25519_SIG_LEN)?)
    }
}

/// A `HybridSig` field `sig_ed (64) ‖ sig_mldsa (3309)` (spec §3.5): the Ed25519 half passes the signature
/// checks; the ML-DSA-65 half is kept opaque (spec §4.1: no ML-DSA sigDecode at decode).
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSig(Box<[u8; HYBRID_SIG_LEN]>);

impl HybridSig {
    /// The field with these bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 3373 bytes whose first 64 pass the Ed25519 signature checks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let sig: Box<[u8; HYBRID_SIG_LEN]> = boxed(bytes)?;
        secmp_crypto::check_ed25519_signature_encoding(
            sig.get(..ED25519_SIG_LEN).ok_or(Error::Rejected)?,
        )?;
        Ok(Self(sig))
    }

    /// The encoded signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HYBRID_SIG_LEN] {
        &self.0
    }
}

redacted_debug!(HybridSig);

impl Encode for HybridSig {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(self.0.as_slice());
        Ok(())
    }
}

impl Decode for HybridSig {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(r.take(HYBRID_SIG_LEN)?)
    }
}

macro_rules! mlkem_ek {
    ($name:ident, $crypto:ident, $len:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Box<[u8; $len]>);

        impl $name {
            /// The field with these bytes.
            ///
            /// # Errors
            /// [`Error::Rejected`] unless of the right length and passing the FIPS 203 §7.2 modulus check.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                secmp_crypto::$crypto::from_bytes(bytes)?;
                Ok(Self(boxed(bytes)?))
            }

            /// The encoded key.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        redacted_debug!($name);

        impl Encode for $name {
            fn encode_to(&self, w: &mut Writer) -> Result<()> {
                w.bytes(self.0.as_slice());
                Ok(())
            }
        }

        impl Decode for $name {
            fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
                Self::from_bytes(r.take($len)?)
            }
        }
    };
}

mlkem_ek!(
    MlKem768Ek,
    MlKem768Ek,
    MLKEM768_EK_LEN,
    "An ML-KEM-768 encapsulation-key field (`ek_c`, `rpk_kem`, `ek_pq`), modulus-checked (spec §4.1 (c))."
);
mlkem_ek!(
    MlKem1024Ek,
    MlKem1024Ek,
    MLKEM1024_EK_LEN,
    "An ML-KEM-1024 encapsulation-key field (`relay_kem_ek`, `spk_kem`, `opk_kem`), modulus-checked (spec §4.1 (c))."
);

/// Kani stubs (`crate::kani_proofs`): the key and signature constructors with the cryptographic check replaced by a
/// nondeterministic outcome and everything else kept (the length rule, the stored bytes). A harness using them
/// covers every accept/reject decision of the `secmp-crypto` checks without modelling curve or lattice arithmetic;
/// the checks themselves are tested against Wycheproof and the frozen vectors (M1, `encodings`).
#[cfg(kani)]
pub(crate) mod kani_stubs {
    use super::{
        ED25519_PK_LEN, ED25519_SIG_LEN, Ed25519Pk, Ed25519Sig, Error, MLKEM768_EK_LEN,
        MLKEM1024_EK_LEN, MlKem768Ek, MlKem1024Ek, Result, boxed,
    };

    fn checked<T>(value: T) -> Result<T> {
        if kani::any() {
            Ok(value)
        } else {
            Err(Error::Rejected)
        }
    }

    pub(crate) fn ed25519_pk(bytes: &[u8]) -> Result<Ed25519Pk> {
        let key: [u8; ED25519_PK_LEN] = bytes.try_into().map_err(|_| Error::Rejected)?;
        checked(Ed25519Pk(key))
    }

    pub(crate) fn ed25519_sig(bytes: &[u8]) -> Result<Ed25519Sig> {
        let sig: [u8; ED25519_SIG_LEN] = bytes.try_into().map_err(|_| Error::Rejected)?;
        checked(Ed25519Sig(sig))
    }

    pub(crate) fn mlkem768_ek(bytes: &[u8]) -> Result<MlKem768Ek> {
        checked(MlKem768Ek(boxed::<MLKEM768_EK_LEN>(bytes)?))
    }

    pub(crate) fn mlkem1024_ek(bytes: &[u8]) -> Result<MlKem1024Ek> {
        checked(MlKem1024Ek(boxed::<MLKEM1024_EK_LEN>(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0_u8; N];
        for (o, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
            *o = core::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .unwrap_or_default();
        }
        out
    }

    /// Overwrite the front of `buf` with `src`.
    fn overwrite(buf: &mut [u8], src: &[u8]) {
        for (d, s) in buf.iter_mut().zip(src) {
            *d = *s;
        }
    }

    #[test]
    fn x25519_field() -> Result<()> {
        let real = *secmp_crypto::X25519Secret::from_bytes(&[7; 32])?
            .public_key()
            .as_bytes();
        let pk = X25519Pk::decode(&real)?;
        assert_eq!(pk.as_bytes(), &real);
        assert_eq!(pk.encode()?, real.to_vec());
        assert_eq!(format!("{pk:?}"), "X25519Pk(..)");
        assert_eq!(X25519Pk::decode(&[0; 32]), Err(Error::Rejected));
        assert_eq!(X25519Pk::decode(&real[..31]), Err(Error::Rejected));
        Ok(())
    }

    #[test]
    fn ed25519_fields() -> Result<()> {
        let sk = secmp_crypto::Ed25519SigningKey::from_seed(&[3; 32])?;
        let pk = Ed25519Pk::decode(sk.verifying_key().as_bytes())?;
        assert_eq!(pk.encode()?, sk.verifying_key().as_bytes().to_vec());
        assert_eq!(
            Ed25519Pk::decode(&unhex::<32>(
                "0100000000000000000000000000000000000000000000000000000000000000"
            )),
            Err(Error::Rejected)
        );
        let sig = sk.sign(b"m");
        let s = Ed25519Sig::decode(&sig)?;
        assert_eq!(s.as_bytes(), &sig);
        assert_eq!(s.encode()?, sig.to_vec());
        let mut bad = sig;
        bad[..32].copy_from_slice(&unhex::<32>(
            "0200000000000000000000000000000000000000000000000000000000000000",
        ));
        assert_eq!(Ed25519Sig::decode(&bad), Err(Error::Rejected));
        assert_eq!(format!("{s:?} {pk:?}"), "Ed25519Sig(..) Ed25519Pk(..)");
        Ok(())
    }

    #[test]
    fn hybrid_sig_checks_only_the_ed25519_half() -> Result<()> {
        let sk = secmp_crypto::Ed25519SigningKey::from_seed(&[4; 32])?;
        let mut bytes = vec![0xa5_u8; HYBRID_SIG_LEN];
        overwrite(&mut bytes, &sk.sign(b"m"));
        let sig = HybridSig::decode(&bytes)?;
        assert_eq!(sig.encode()?, bytes);
        assert_eq!(sig.as_bytes().as_slice(), bytes.as_slice());
        assert_eq!(format!("{sig:?}"), "HybridSig(..)");
        // an arbitrary (never sigDecoded) ML-DSA half is kept; a bad Ed25519 R is refused
        overwrite(&mut bytes, &[0; 32]);
        assert_eq!(HybridSig::decode(&bytes), Err(Error::Rejected));
        assert_eq!(
            HybridSig::decode(bytes.get(..100).unwrap_or_default()),
            Err(Error::Rejected)
        );
        Ok(())
    }

    #[test]
    fn mlkem_fields() -> Result<()> {
        let ek768 = secmp_crypto::MlKem768Dk::from_seed(&[5; 64])?.encapsulation_key();
        let ek = MlKem768Ek::decode(ek768.as_bytes())?;
        assert_eq!(ek.encode()?, ek768.as_bytes().to_vec());
        let mut bad = ek768.as_bytes().to_vec();
        overwrite(&mut bad, &[0xff; 3]);
        assert_eq!(MlKem768Ek::decode(&bad), Err(Error::Rejected));
        let ek1024 = secmp_crypto::MlKem1024Dk::from_seed(&[6; 64])?.encapsulation_key();
        let ek = MlKem1024Ek::decode(ek1024.as_bytes())?;
        assert_eq!(ek.as_bytes(), ek1024.as_bytes());
        assert_eq!(
            MlKem1024Ek::decode(ek768.as_bytes()),
            Err(Error::Rejected),
            "wrong length"
        );
        assert_eq!(format!("{ek:?}"), "MlKem1024Ek(..)");
        Ok(())
    }
}
