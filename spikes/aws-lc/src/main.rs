// SPDX-License-Identifier: AGPL-3.0-or-later
//! M0 spike (b): aws-lc-rs builds and works on the target. Prints `SPIKE-B OK` on success.
#![forbid(unsafe_code)]

use std::error::Error;

use aws_lc_rs::{agreement, digest, kem, rand};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    // FIPS 180-4 / RFC 6234 known answer for SHA-256("abc").
    let d = digest::digest(&digest::SHA256, b"abc");
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if hex(d.as_ref()) != expected {
        return Err("SHA-256 known answer mismatch".into());
    }
    println!("SHA-256(\"abc\") known answer ok");

    let rng = rand::SystemRandom::new();
    let a = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).map_err(|_| "x25519 keygen")?;
    let b = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).map_err(|_| "x25519 keygen")?;
    let a_pub = a.compute_public_key().map_err(|_| "x25519 public")?;
    let b_pub = b.compute_public_key().map_err(|_| "x25519 public")?;
    let ka = agreement::agree_ephemeral(
        a,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, b_pub.as_ref()),
        "x25519 agree",
        |k| Ok(k.to_vec()),
    )?;
    let kb = agreement::agree_ephemeral(
        b,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, a_pub.as_ref()),
        "x25519 agree",
        |k| Ok(k.to_vec()),
    )?;
    if ka != kb {
        return Err("X25519 shared secrets differ".into());
    }
    println!("X25519 agreement ok");

    let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| "ml-kem keygen")?;
    let ek = dk.encapsulation_key().map_err(|_| "ml-kem ek")?;
    let (ct, ss_enc) = ek.encapsulate().map_err(|_| "ml-kem encaps")?;
    let ss_dec = dk.decapsulate(ct.as_ref().into()).map_err(|_| "ml-kem decaps")?;
    if ss_enc.as_ref() != ss_dec.as_ref() {
        return Err("ML-KEM-768 shared secrets differ".into());
    }
    println!("ML-KEM-768 encapsulate/decapsulate ok (ct {} bytes)", ct.as_ref().len());
    println!("SPIKE-B OK ({} {})", std::env::consts::OS, std::env::consts::ARCH);
    Ok(())
}
