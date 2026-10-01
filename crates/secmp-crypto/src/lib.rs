// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-crypto` — typed cryptographic primitives and the SecMP/1 constructions.
//!
//! **Responsibility.** The only crate that uses cryptographic crates for SecMP constructions (CLAUDE.md §1.6,
//! docs/06 §2–3): typed keys, nonces and counters; `HybridKEM` (spec §3.2), `MsgEncrypt` (§3.3), `CAEAD` (§3.4),
//! `HybridSign` (§3.5), plain XChaCha20-Poly1305 for ratchet headers and link frames ([`Aead`], §3 table, §7.5,
//! §8.4), HKDF helpers with the labels of spec Appendix A, the SecMP-TR key derivations (§7.2), the safety number
//! (§6.7) and fingerprints (§6.2). No primitive is implemented here; constructions only compose allowlisted crates
//! exactly as the spec defines them.
//!
//! **Allowed dependencies** (docs/02 §3, docs/06 §3): `secmp-sys-mem`; the allowlisted crypto crates of docs/06 §3
//! (`libcrux-ml-kem`, `ml-kem` for differential tests, `ml-dsa`, `aws-lc-rs` for differential tests,
//! `x25519-dalek`, `ed25519-dalek`, `curve25519-dalek`, `chacha20`, `chacha20poly1305`, `hmac`, `hkdf`, `sha2`,
//! `sha3`, `argon2`, `subtle`, `zeroize`, `getrandom`, `rand_core`), each pinned exactly and added with an ADR
//! and a cargo-vet record (ADR-023, ADR-036, ADR-037). Sans-IO: no tokio, no I/O crate. Its normal dependency
//! closure has zero cargo-vet exemptions.
//!
//! **Conventions.** Secrets live in [`SecretBytes`] (short-lived) or [`LockedSecret`] (long-lived, locked
//! memory); neither is `Clone`, `Debug` or `PartialEq`. Every input-dependent failure is the single
//! [`Error::Rejected`]. Randomised operations draw from the OS CSPRNG; their derandomised forms (fixed
//! randomness) exist only with feature `kat`, for known-answer tests and the vector generator. `Debug` of key,
//! ciphertext and fingerprint types is redacted.
#![forbid(unsafe_code)]

mod aead;
mod caead;
mod ed25519;
mod error;
mod fingerprint;
mod hash;
mod hybrid_kem;
mod hybrid_sign;
mod kdf;
mod label;
mod mldsa;
mod mlkem;
mod msg;
mod nonce;
mod rng;
mod sas;
mod secret;
#[cfg(test)]
mod test_util;
mod tr_kdf;
#[cfg(feature = "kat")]
mod vector_stream;
mod x25519;

pub use aead::Aead;
pub use caead::{AEAD_TAG_LEN, COM_LEN, Caead, NONCE_LEN};
pub use ed25519::{
    ED25519_PK_LEN, ED25519_SEED_LEN, ED25519_SIG_LEN, Ed25519SigningKey, Ed25519VerifyingKey,
    check_ed25519_signature_encoding,
};
pub use error::{Error, Result};
pub use fingerprint::{FINGERPRINT_LEN, Fingerprint, IKS_PUBLIC_LEN};
pub use hash::{sha3_256, sha256};
pub use hybrid_kem::{
    HYBRID_SS_LEN, HybridKem768Ciphertext, HybridKem768PublicKey, HybridKem768SecretKey,
    HybridKem1024Ciphertext, HybridKem1024PublicKey, HybridKem1024SecretKey,
};
pub use hybrid_sign::{HYBRID_SIG_LEN, HybridSignature, HybridSigningKey, HybridVerifyingKey};
#[cfg(feature = "kat")]
pub use kdf::hkdf_kat;
pub use kdf::{HKDF_MAX_LEN, hkdf, hkdf_expand};
pub use label::Label;
pub use mldsa::{
    MLDSA_MAX_CTX_LEN, MLDSA_SEED_LEN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MlDsa65SigningKey,
    MlDsa65VerifyingKey,
};
pub use mlkem::{
    MLKEM_SEED_LEN, MLKEM_SS_LEN, MLKEM768_CT_LEN, MLKEM768_EK_LEN, MLKEM1024_CT_LEN,
    MLKEM1024_EK_LEN, MlKem768Ct, MlKem768Dk, MlKem768Ek, MlKem1024Ct, MlKem1024Dk, MlKem1024Ek,
};
pub use msg::{BODY_LEN, MSG_SEALED_LEN, MSG_TAG_LEN, MsgEncrypt};
pub use nonce::{Counter64, Nonce24};
pub use sas::{SAS_DIGITS, SAS_HALF_DIGITS, SAS_ITERATIONS, SafetyNumber};
pub use secret::{LockedSecret, SecretBytes};
/// Constant-time comparison and selection, re-exported so that `secmp-proto` compares and selects secrets in
/// constant time without a direct dependency on a crypto crate (CLAUDE.md §1.6).
pub use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
pub use tr_kdf::{kdf_ck, kdf_rk, tr_init};
#[cfg(feature = "kat")]
pub use vector_stream::VectorStream;
pub use x25519::{X25519_LEN, X25519Public, X25519Secret};
pub use zeroize::Zeroizing;
