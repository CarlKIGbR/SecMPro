// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "kat")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Known-answer tests for X25519 and Ed25519 (feature `kat`): Wycheproof `x25519_test.json` and
//! `ed25519_test.json` through the `secmp-crypto` wrappers, and RFC 7748 §5.2 iterations.

use secmp_crypto::{
    Ed25519VerifyingKey, Error, X25519Public, X25519Secret, check_ed25519_signature_encoding,
};
use secmp_testkit::kat::{
    Tally, Verdict, hex, hex_field, load, str_field, to_hex, wycheproof_cases,
};

/// Wycheproof X25519: every case either yields the listed shared secret, or — exactly when the listed secret is
/// all zero (low-order inputs, `acceptable` in Wycheproof) — is rejected (spec §3: the all-zero output MUST be
/// rejected). Non-canonical and twist inputs are computed per RFC 7748 (spec §3 table).
#[test]
fn wycheproof_x25519() {
    let doc = load("external/wycheproof/x25519_test.json");
    let mut tally = Tally::default();
    let mut zero_rejected = 0_usize;
    for c in wycheproof_cases(&doc) {
        let sk = X25519Secret::from_bytes(&hex_field(c.test, "private")).unwrap();
        let pk = X25519Public::from_bytes(&hex_field(c.test, "public")).unwrap();
        let shared = hex_field(c.test, "shared");
        let got = sk.diffie_hellman(&pk);
        // spec §4.1 decoder obligation (a): the decode-time refusal agrees with the all-zero check at use
        assert_eq!(
            X25519Public::from_bytes_checked(&hex_field(c.test, "public")).is_err(),
            shared.iter().all(|b| *b == 0),
            "tcId {}",
            c.tc_id
        );
        if shared.iter().all(|b| *b == 0) {
            assert_eq!(got.err(), Some(Error::Rejected), "tcId {}", c.tc_id);
            zero_rejected = zero_rejected.saturating_add(1);
        } else {
            assert_ne!(c.verdict, Verdict::Invalid, "tcId {}", c.tc_id);
            assert!(
                got.is_ok(),
                "tcId {}: {got:?}",
                c.tc_id,
                got = got.as_ref().err()
            );
            let got = got.unwrap();
            assert_eq!(
                to_hex(got.expose_secret()),
                to_hex(&shared),
                "tcId {}",
                c.tc_id
            );
        }
        tally.check();
    }
    // 518 cases, of which 31 have an all-zero shared secret
    assert_eq!(
        (tally.checked, zero_rejected),
        (518, 31),
        "{}",
        tally.summary("x25519")
    );
}

/// RFC 7748 §5.2: `k = u = 9`, `k' = X25519(k, u)`, `u' = k`, after 1 and 1 000 iterations.
#[test]
fn rfc7748_iterations() {
    let mut k = [0_u8; 32];
    k[0] = 9;
    let mut u = k;
    for i in 1..=1000 {
        let out = X25519Secret::from_bytes(&k)
            .unwrap()
            .diffie_hellman(&X25519Public::from_bytes(&u).unwrap())
            .unwrap();
        u = k;
        k = *out.expose_secret();
        if i == 1 {
            assert_eq!(
                to_hex(&k),
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
            );
        }
    }
    assert_eq!(
        to_hex(&k),
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
    );
}

/// Wycheproof Ed25519 through the strict verifier of spec §3.5: every `valid` case verifies, every `invalid`
/// case is rejected (at key import or at verification).
#[test]
fn wycheproof_ed25519_strict() {
    let doc = load("external/wycheproof/ed25519_test.json");
    let mut tally = Tally::default();
    let mut refused_keys = 0_usize;
    let mut encoding_refused = 0_usize;
    for c in wycheproof_cases(&doc) {
        let pk = hex(str_field(c.group.get("publicKey").unwrap(), "pk"));
        let msg = hex_field(c.test, "msg");
        let sig = hex_field(c.test, "sig");
        let outcome = match Ed25519VerifyingKey::from_bytes(&pk) {
            Ok(vk) => vk.verify(&msg, &sig),
            Err(e) => {
                refused_keys = refused_keys.saturating_add(1);
                Err(e)
            }
        };
        // spec §4.1 decoder obligation (b): a signature refused at decode is refused by verification too, and
        // every valid signature passes the decode-time check
        if check_ed25519_signature_encoding(&sig).is_err() {
            encoding_refused = encoding_refused.saturating_add(1);
            assert!(outcome.is_err(), "tcId {}", c.tc_id);
        }
        if c.verdict == Verdict::Valid {
            assert!(
                check_ed25519_signature_encoding(&sig).is_ok(),
                "tcId {}",
                c.tc_id
            );
        }
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
        refused_keys, 0,
        "no Wycheproof group key is non-canonical or of small order"
    );
    assert_eq!(
        encoding_refused, 51,
        "signatures refused by the decode-time check (all rejected by verification as well)"
    );
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (151, 0),
        "{}",
        tally.summary("ed25519")
    );
}
