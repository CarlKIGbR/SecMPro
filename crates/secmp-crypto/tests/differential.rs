// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "kat")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Differential tests (docs/06 §4, M1 acceptance "differential tests pass 10 000 iterations"; feature `kat`):
//!
//! - ML-KEM-768/1024: the wrapper (libcrux) vs RustCrypto `ml-kem` (same seed → same ek; same `m` → same
//!   ciphertext and secret; each decapsulates the other's ciphertexts) vs `aws-lc-rs` (the same expanded key
//!   imported → same ek; ciphertexts decapsulate to the same secret in both directions).
//! - ML-DSA-65: the wrapper (`ml-dsa`) vs `aws-lc-rs` (same seed ξ → same pk; each verifies the other's
//!   signatures, empty context).
//! - Ed25519: the wrapper (dalek) vs `aws-lc-rs` (same seed → same pk and identical signatures; cross-verify).
//!
//! Inputs come from SHAKE-256(master seed ‖ u32be(iteration)); the master seed is random per run (or
//! `SECMP_DIFF_SEED`, 64 hex digits) and is part of every assertion message, so a failure is reproducible.
//! `SECMP_DIFF_ITERATIONS` overrides the iteration count (default 10 000).

use aws_lc_rs::signature::{
    ED25519, Ed25519KeyPair, KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use ml_kem::{Decapsulate, KeyExport};
use secmp_crypto::{
    Ed25519SigningKey, Ed25519VerifyingKey, MlDsa65SigningKey, MlDsa65VerifyingKey, SecretBytes,
};
use secmp_testkit::kat::{decode_hex, to_hex};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

const DEFAULT_ITERATIONS: u32 = 10_000;

/// The master seed and iteration count of this run.
fn setup() -> ([u8; 32], u32) {
    let seed = std::env::var("SECMP_DIFF_SEED")
        .ok()
        .and_then(|s| decode_hex(&s))
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .unwrap_or_else(|| *SecretBytes::<32>::random().unwrap().expose_secret());
    let n = std::env::var("SECMP_DIFF_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS);
    (seed, n)
}

/// The input stream of iteration `i`.
fn stream(master: &[u8; 32], label: &str, i: u32) -> impl XofReader {
    let mut h = Shake256::default();
    h.update(master);
    h.update(label.as_bytes());
    h.update(&i.to_be_bytes());
    h.finalize_xof()
}

fn take<const N: usize>(r: &mut impl XofReader) -> [u8; N] {
    let mut out = [0; N];
    r.read(&mut out);
    out
}

macro_rules! mlkem_differential {
    ($name:ident, $label:literal, $ours_dk:ident, $ours_ek:ident, $ours_ct:ident, $rc:ident, $lib:ident, $aws:ident) => {
        #[test]
        fn $name() {
            let (master, n) = setup();
            let ctx = format!("master seed {} (SECMP_DIFF_SEED)", to_hex(&master));
            for i in 0..n {
                let mut r = stream(&master, $label, i);
                let seed: [u8; 64] = take(&mut r);
                let m: [u8; 32] = take(&mut r);

                // same seed -> same encapsulation key (libcrux wrapper vs RustCrypto)
                let ours = secmp_crypto::$ours_dk::from_seed(&seed).unwrap();
                let ek = ours.encapsulation_key();
                let rc = ml_kem::DecapsulationKey::<ml_kem::$rc>::from_seed(seed.into());
                assert_eq!(
                    ek.as_bytes().as_slice(),
                    rc.encapsulation_key().to_bytes().as_slice(),
                    "{ctx}, iteration {i}: ek"
                );

                // same m -> same ciphertext and secret
                let (ct, ss) = ek.encapsulate_kat(&m);
                let (rc_ct, rc_ss) = rc.encapsulation_key().encapsulate_deterministic(&m.into());
                assert_eq!(
                    ct.as_bytes().as_slice(),
                    rc_ct.as_slice(),
                    "{ctx}, iteration {i}: ct"
                );
                assert_eq!(
                    ss.expose_secret().as_slice(),
                    rc_ss.as_slice(),
                    "{ctx}, iteration {i}: ss"
                );
                assert_eq!(
                    rc.decapsulate(&rc_ct).as_slice(),
                    ss.expose_secret().as_slice(),
                    "{ctx}, iteration {i}"
                );

                // aws-lc-rs with the same expanded key decapsulates the wrapper's ciphertext to the same secret
                let sk = libcrux_ml_kem::$lib::generate_key_pair(seed);
                let aws_dk =
                    aws_lc_rs::kem::DecapsulationKey::new(&aws_lc_rs::kem::$aws, sk.sk()).unwrap();
                let aws_ss = aws_dk.decapsulate(ct.as_bytes().as_slice().into()).unwrap();
                assert_eq!(
                    aws_ss.as_ref(),
                    ss.expose_secret().as_slice(),
                    "{ctx}, iteration {i}: aws decaps"
                );
                // aws-lc-rs encapsulates to the wrapper's ek; the wrapper decapsulates to the same secret
                let aws_ek =
                    aws_lc_rs::kem::EncapsulationKey::new(&aws_lc_rs::kem::$aws, ek.as_bytes())
                        .unwrap();
                let (aws_ct, aws_ss) = aws_ek.encapsulate().unwrap();
                let ours_ss =
                    ours.decapsulate(&secmp_crypto::$ours_ct::from_bytes(aws_ct.as_ref()).unwrap());
                assert_eq!(
                    ours_ss.expose_secret().as_slice(),
                    aws_ss.as_ref(),
                    "{ctx}, iteration {i}: ours decaps aws"
                );
                // an aws-lc-rs-generated key imports into the wrapper; aws decapsulates the wrapper's encapsulation
                let aws_gen =
                    aws_lc_rs::kem::DecapsulationKey::generate(&aws_lc_rs::kem::$aws).unwrap();
                let gen_ek = aws_gen.encapsulation_key().unwrap().key_bytes().unwrap();
                let imported = secmp_crypto::$ours_ek::from_bytes(gen_ek.as_ref()).unwrap();
                let (ct2, ss2) = imported.encapsulate_kat(&m);
                let aws_ss2 = aws_gen
                    .decapsulate(ct2.as_bytes().as_slice().into())
                    .unwrap();
                assert_eq!(
                    aws_ss2.as_ref(),
                    ss2.expose_secret().as_slice(),
                    "{ctx}, iteration {i}: aws-generated key"
                );
            }
        }
    };
}

mlkem_differential!(
    mlkem768_libcrux_rustcrypto_awslc,
    "mlkem768",
    MlKem768Dk,
    MlKem768Ek,
    MlKem768Ct,
    MlKem768,
    mlkem768,
    ML_KEM_768
);
mlkem_differential!(
    mlkem1024_libcrux_rustcrypto_awslc,
    "mlkem1024",
    MlKem1024Dk,
    MlKem1024Ek,
    MlKem1024Ct,
    MlKem1024,
    mlkem1024,
    ML_KEM_1024
);

#[test]
fn mldsa65_rustcrypto_awslc() {
    let (master, n) = setup();
    let ctx = format!("master seed {} (SECMP_DIFF_SEED)", to_hex(&master));
    let mut sig = vec![0; 3309];
    for i in 0..n {
        let mut r = stream(&master, "mldsa65", i);
        let xi: [u8; 32] = take(&mut r);
        let msg: [u8; 48] = take(&mut r);
        let ours = MlDsa65SigningKey::from_seed(&xi).unwrap();
        let vk = ours.verifying_key();
        let aws = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &xi).unwrap();
        assert_eq!(
            aws.public_key().as_ref(),
            vk.as_bytes().as_slice(),
            "{ctx}, iteration {i}: pk"
        );
        // aws-lc-rs signs (pure, empty context, hedged) -> the wrapper verifies
        let len = aws.sign(&msg, &mut sig).unwrap();
        vk.verify(&msg, b"", sig.get(..len).unwrap())
            .unwrap_or_else(|_| panic_at(&ctx, i, "ours verifies aws"));
        // the wrapper signs -> aws-lc-rs verifies
        let s = ours.sign(&msg, b"").unwrap();
        UnparsedPublicKey::new(&ML_DSA_65, vk.as_bytes().as_slice())
            .verify(&msg, s.as_slice())
            .unwrap_or_else(|_| panic_at(&ctx, i, "aws verifies ours"));
        // and imports agree
        assert!(MlDsa65VerifyingKey::from_bytes(aws.public_key().as_ref()).is_ok());
    }
}

#[test]
fn ed25519_dalek_awslc() {
    let (master, n) = setup();
    let ctx = format!("master seed {} (SECMP_DIFF_SEED)", to_hex(&master));
    for i in 0..n {
        let mut r = stream(&master, "ed25519", i);
        let seed: [u8; 32] = take(&mut r);
        let msg: [u8; 40] = take(&mut r);
        let ours = Ed25519SigningKey::from_seed(&seed).unwrap();
        let vk = ours.verifying_key();
        let aws = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(
            aws.public_key().as_ref(),
            vk.as_bytes().as_slice(),
            "{ctx}, iteration {i}: pk"
        );
        let s = ours.sign(&msg);
        let aws_s = aws.sign(&msg);
        assert_eq!(
            aws_s.as_ref(),
            s.as_slice(),
            "{ctx}, iteration {i}: deterministic signatures"
        );
        vk.verify(&msg, aws_s.as_ref())
            .unwrap_or_else(|_| panic_at(&ctx, i, "ours verifies aws"));
        UnparsedPublicKey::new(&ED25519, vk.as_bytes().as_slice())
            .verify(&msg, &s)
            .unwrap_or_else(|_| panic_at(&ctx, i, "aws verifies ours"));
        assert!(Ed25519VerifyingKey::from_bytes(aws.public_key().as_ref()).is_ok());
    }
}

/// Fail with the reproduction context.
#[track_caller]
fn panic_at(ctx: &str, i: u32, what: &str) {
    assert_eq!(what, "", "{ctx}, iteration {i}: {what} failed");
}
