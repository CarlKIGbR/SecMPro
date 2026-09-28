// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "kat")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Known-answer tests for ML-DSA-65 as SecMP uses it — pure ML-DSA (FIPS 204 Alg. 2/3) with a context string,
//! keys from the 32-byte seed ξ — through the `secmp-crypto` wrappers (feature `kat`): Wycheproof `sign_seed`
//! and `verify`, NIST ACVP keyGen and sigVer (external interface, pure).

use secmp_crypto::{Error, MlDsa65SigningKey, MlDsa65VerifyingKey};
use secmp_testkit::kat::{
    Tally, Verdict, acvp_cases, bool_field, hex, hex_field, load, opt_str_field, str_field, to_hex,
    wycheproof_cases,
};

/// Wycheproof `mldsa_65_sign_seed_test.json`: from ξ, the verifying key and the signature (deterministic with
/// `rnd = 0^32`, or the listed `rnd`) must be reproduced; wrong seed lengths and contexts longer than 255 bytes
/// are rejected. Cases of the *internal* interface (μ given, no message) do not exist in pure ML-DSA and are
/// skipped.
#[test]
fn wycheproof_sign_seed() {
    let doc = load("external/wycheproof/mldsa_65_sign_seed_test.json");
    let mut tally = Tally::default();
    for c in wycheproof_cases(&doc) {
        if c.has_flag("Internal") {
            tally.skip(c.tc_id, "internal interface (external mu), not pure ML-DSA");
            continue;
        }
        let seed = hex(str_field(c.group, "privateSeed"));
        let msg = hex_field(c.test, "msg");
        let ctx = opt_str_field(c.test, "ctx").map(hex).unwrap_or_default();
        let rnd: [u8; 32] =
            opt_str_field(c.test, "rnd").map_or([0; 32], |r| hex(r).try_into().unwrap());
        let outcome = MlDsa65SigningKey::from_seed(&seed).and_then(|key| {
            assert_eq!(
                to_hex(key.verifying_key().as_bytes()),
                str_field(c.group, "publicKey"),
                "tcId {}",
                c.tc_id
            );
            key.sign_kat(&msg, &ctx, &rnd)
        });
        match c.verdict {
            Verdict::Valid => {
                assert!(outcome.is_ok(), "tcId {} must sign", c.tc_id);
                assert_eq!(
                    to_hex(outcome.unwrap().as_slice()),
                    str_field(c.test, "sig"),
                    "tcId {}",
                    c.tc_id
                );
            }
            Verdict::Invalid => assert_eq!(
                outcome.err(),
                Some(Error::Rejected),
                "tcId {} {:?}",
                c.tc_id,
                c.flags
            ),
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    // 105 cases: 17 of the internal interface
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (88, 17),
        "{}",
        tally.summary("mldsa sign_seed")
    );
}

/// Wycheproof `mldsa_65_verify_test.json`: valid signatures verify; malformed keys, wrong lengths, bad hints,
/// norm violations, modified signatures and over-long contexts are rejected.
#[test]
fn wycheproof_verify() {
    let doc = load("external/wycheproof/mldsa_65_verify_test.json");
    let mut tally = Tally::default();
    for c in wycheproof_cases(&doc) {
        let msg = hex_field(c.test, "msg");
        let ctx = opt_str_field(c.test, "ctx").map(hex).unwrap_or_default();
        let outcome = MlDsa65VerifyingKey::from_bytes(&hex(str_field(c.group, "publicKey")))
            .and_then(|vk| vk.verify(&msg, &ctx, &hex_field(c.test, "sig")));
        match c.verdict {
            Verdict::Valid => assert!(
                outcome.is_ok(),
                "tcId {} {:?} must verify",
                c.tc_id,
                c.flags
            ),
            Verdict::Invalid => assert_eq!(
                outcome.err(),
                Some(Error::Rejected),
                "tcId {} {:?}",
                c.tc_id,
                c.flags
            ),
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (210, 0),
        "{}",
        tally.summary("mldsa verify")
    );
}

/// ACVP ML-DSA-65 keyGen: `KeyGen_internal(ξ)` reproduces `pk`.
#[test]
fn acvp_keygen() {
    let doc = load("external/acvp/ML-DSA-keyGen-FIPS204.json");
    let mut n = 0_usize;
    for (_, t) in acvp_cases(&doc) {
        let vk = MlDsa65SigningKey::from_seed(&hex_field(t, "seed"))
            .unwrap()
            .verifying_key();
        assert_eq!(to_hex(vk.as_bytes()), str_field(t, "pk").to_lowercase());
        n = n.saturating_add(1);
    }
    assert_eq!(n, 25);
}

/// ACVP ML-DSA-65 sigVer (external interface, pure, with context): the verdict equals `testPassed`.
#[test]
fn acvp_sigver() {
    let doc = load("external/acvp/ML-DSA-sigVer-FIPS204.json");
    let mut n = 0_usize;
    for (_, t) in acvp_cases(&doc) {
        let ok = MlDsa65VerifyingKey::from_bytes(&hex_field(t, "pk"))
            .and_then(|vk| {
                vk.verify(
                    &hex_field(t, "message"),
                    &hex_field(t, "context"),
                    &hex_field(t, "signature"),
                )
            })
            .is_ok();
        assert_eq!(
            ok,
            bool_field(t, "testPassed"),
            "tcId {}: {}",
            t.get("tcId").unwrap(),
            str_field(t, "reason")
        );
        n = n.saturating_add(1);
    }
    assert_eq!(n, 15);
}
