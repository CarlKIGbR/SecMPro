// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "kat")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Known-answer tests for ML-KEM-768 and ML-KEM-1024 (feature `kat`): Wycheproof and NIST ACVP through the
//! `secmp-crypto` wrappers (seed-based decapsulation keys, validated encapsulation keys, implicit rejection).
//! Cases that carry *expanded* decapsulation keys — which SecMP never imports (spec §3: dk stored as seeds) —
//! run against the pinned `libcrux-ml-kem` directly, which is the code the wrappers call.

use secmp_crypto::{
    Error, MlKem768Ct, MlKem768Dk, MlKem768Ek, MlKem1024Ct, MlKem1024Dk, MlKem1024Ek,
};
use secmp_testkit::kat::{
    Tally, Verdict, acvp_cases, bool_field, hex_field, load, opt_str_field, str_field, to_hex,
    wycheproof_cases,
};

macro_rules! mlkem_kats {
    ($modname:ident, $set:literal, $wp:literal, $dk:ident, $ek:ident, $ct:ident, $lib:ident, $sk_len:literal, $ct_len:literal,
     counts = ($n_test:literal, $n_encaps:literal, $n_keygen:literal, $n_semi:literal, $n_acvp_keygen:literal, $n_acvp_ed:literal)) => {
        mod $modname {
            use super::*;

            /// `mlkem_*_test.json`: seed → ek; decapsulation of `c` → `K` (including implicit rejection of
            /// malleated ciphertexts); wrong seed or ciphertext lengths are rejected.
            #[test]
            fn wycheproof_decaps_from_seed() {
                let doc = load(concat!("external/wycheproof/mlkem_", $wp, "_test.json"));
                let mut tally = Tally::default();
                for c in wycheproof_cases(&doc) {
                    let outcome = $dk::from_seed(&hex_field(c.test, "seed")).and_then(|dk| {
                        if let Some(ek) = opt_str_field(c.test, "ek") {
                            assert_eq!(
                                to_hex(dk.encapsulation_key().as_bytes()),
                                ek,
                                "tcId {}",
                                c.tc_id
                            );
                        }
                        let ct = $ct::from_bytes(&hex_field(c.test, "c"))?;
                        Ok(dk.decapsulate(&ct))
                    });
                    match c.verdict {
                        Verdict::Valid => {
                            assert!(outcome.is_ok(), "tcId {} must decapsulate", c.tc_id);
                            let k = outcome.unwrap();
                            assert_eq!(
                                to_hex(k.expose_secret()),
                                str_field(c.test, "K"),
                                "tcId {}",
                                c.tc_id
                            );
                        }
                        Verdict::Invalid => {
                            assert_eq!(outcome.err(), Some(Error::Rejected), "tcId {}", c.tc_id)
                        }
                        Verdict::Acceptable => {
                            tally.skip(c.tc_id, "acceptable");
                            continue;
                        }
                    }
                    tally.check();
                }
                assert_eq!(
                    (tally.checked, tally.skipped.len()),
                    ($n_test, 0),
                    "{}",
                    tally.summary("mlkem test")
                );
            }

            /// `mlkem_*_encaps_test.json`: import of `ek` (modulus and length checks) and deterministic
            /// encapsulation with `m`.
            #[test]
            fn wycheproof_encaps() {
                let doc = load(concat!(
                    "external/wycheproof/mlkem_",
                    $wp,
                    "_encaps_test.json"
                ));
                let mut tally = Tally::default();
                for c in wycheproof_cases(&doc) {
                    let imported = $ek::from_bytes(&hex_field(c.test, "ek"));
                    match c.verdict {
                        Verdict::Valid => {
                            assert!(imported.is_ok(), "tcId {} must import", c.tc_id);
                            let ek = imported.unwrap();
                            let m: [u8; 32] = hex_field(c.test, "m").try_into().unwrap();
                            let (ct, k) = ek.encapsulate_kat(&m);
                            assert_eq!(
                                to_hex(ct.as_bytes()),
                                str_field(c.test, "c"),
                                "tcId {}",
                                c.tc_id
                            );
                            assert_eq!(
                                to_hex(k.expose_secret()),
                                str_field(c.test, "K"),
                                "tcId {}",
                                c.tc_id
                            );
                        }
                        Verdict::Invalid => {
                            assert_eq!(imported.err(), Some(Error::Rejected), "tcId {}", c.tc_id)
                        }
                        Verdict::Acceptable => {
                            tally.skip(c.tc_id, "acceptable");
                            continue;
                        }
                    }
                    tally.check();
                }
                assert_eq!(
                    (tally.checked, tally.skipped.len()),
                    ($n_encaps, 0),
                    "{}",
                    tally.summary("mlkem encaps")
                );
            }

            /// `mlkem_*_keygen_seed_test.json`: `KeyGen_internal(d, z)` from the 64-byte seed; ek through the
            /// wrapper, the expanded dk through libcrux.
            #[test]
            fn wycheproof_keygen_seed() {
                let doc = load(concat!(
                    "external/wycheproof/mlkem_",
                    $wp,
                    "_keygen_seed_test.json"
                ));
                let mut tally = Tally::default();
                for c in wycheproof_cases(&doc) {
                    assert_eq!(c.verdict, Verdict::Valid);
                    let seed = hex_field(c.test, "seed");
                    let ek = $dk::from_seed(&seed).unwrap().encapsulation_key();
                    assert_eq!(
                        to_hex(ek.as_bytes()),
                        str_field(c.test, "ek"),
                        "tcId {}",
                        c.tc_id
                    );
                    let kp = libcrux_ml_kem::$lib::generate_key_pair(seed.try_into().unwrap());
                    assert_eq!(to_hex(kp.sk()), str_field(c.test, "dk"), "tcId {}", c.tc_id);
                    tally.check();
                }
                assert_eq!(
                    tally.checked,
                    $n_keygen,
                    "{}",
                    tally.summary("mlkem keygen")
                );
            }

            /// `mlkem_*_semi_expanded_decaps_test.json` (expanded dk; libcrux directly): length checks, the FIPS 203
            /// §7.3 hash check of dk, and decapsulation.
            #[test]
            fn wycheproof_semi_expanded_decaps_library() {
                let doc = load(concat!(
                    "external/wycheproof/mlkem_",
                    $wp,
                    "_semi_expanded_decaps_test.json"
                ));
                let mut tally = Tally::default();
                for c in wycheproof_cases(&doc) {
                    let dk = hex_field(c.test, "dk");
                    let ct = hex_field(c.test, "c");
                    let k = <[u8; $sk_len]>::try_from(dk.as_slice())
                        .ok()
                        .zip(<[u8; $ct_len]>::try_from(ct.as_slice()).ok())
                        .and_then(|(dk, ct)| {
                            let sk = libcrux_ml_kem::MlKemPrivateKey::from(dk);
                            let ct = libcrux_ml_kem::MlKemCiphertext::from(ct);
                            libcrux_ml_kem::$lib::validate_private_key(&sk, &ct)
                                .then(|| libcrux_ml_kem::$lib::decapsulate(&sk, &ct))
                        });
                    match c.verdict {
                        Verdict::Valid => assert_eq!(
                            k.map(|k| to_hex(&k)).as_deref(),
                            Some(str_field(c.test, "K")),
                            "tcId {}",
                            c.tc_id
                        ),
                        _ => assert!(k.is_none(), "tcId {}", c.tc_id),
                    }
                    tally.check();
                }
                assert_eq!(
                    tally.checked,
                    $n_semi,
                    "{}",
                    tally.summary("mlkem semi-expanded")
                );
            }

            /// ACVP ML-KEM keyGen: `(d, z)` → ek (wrapper, seed `d ‖ z`) and dk (libcrux).
            #[test]
            fn acvp_keygen() {
                let doc = load("external/acvp/ML-KEM-keyGen-FIPS203.json");
                let mut n = 0_usize;
                for (g, t) in acvp_cases(&doc) {
                    if str_field(g, "parameterSet") != $set {
                        continue;
                    }
                    let seed = [hex_field(t, "d"), hex_field(t, "z")].concat();
                    let ek = $dk::from_seed(&seed).unwrap().encapsulation_key();
                    assert_eq!(to_hex(ek.as_bytes()), str_field(t, "ek").to_lowercase());
                    let kp = libcrux_ml_kem::$lib::generate_key_pair(seed.try_into().unwrap());
                    assert_eq!(to_hex(kp.sk()), str_field(t, "dk").to_lowercase());
                    n = n.saturating_add(1);
                }
                assert_eq!(n, $n_acvp_keygen);
            }

            /// ACVP ML-KEM encapDecap: encapsulation and encapsulation-key checks through the wrapper;
            /// decapsulation and decapsulation-key checks (expanded dk) through libcrux.
            #[test]
            fn acvp_encap_decap() {
                let doc = load("external/acvp/ML-KEM-encapDecap-FIPS203.json");
                let mut n = 0_usize;
                for (g, t) in acvp_cases(&doc) {
                    if str_field(g, "parameterSet") != $set {
                        continue;
                    }
                    match str_field(g, "function") {
                        "encapsulation" => {
                            let ek = $ek::from_bytes(&hex_field(t, "ek")).unwrap();
                            let m: [u8; 32] = hex_field(t, "m").try_into().unwrap();
                            let (ct, k) = ek.encapsulate_kat(&m);
                            assert_eq!(to_hex(ct.as_bytes()), str_field(t, "c").to_lowercase());
                            assert_eq!(to_hex(k.expose_secret()), str_field(t, "k").to_lowercase());
                        }
                        "encapsulationKeyCheck" => {
                            let ok = $ek::from_bytes(&hex_field(t, "ek")).is_ok();
                            assert_eq!(
                                ok,
                                bool_field(t, "testPassed"),
                                "{}",
                                str_field(t, "reason")
                            );
                        }
                        "decapsulation" => {
                            let sk = libcrux_ml_kem::MlKemPrivateKey::<$sk_len>::try_from(
                                hex_field(t, "dk").as_slice(),
                            )
                            .unwrap();
                            let ct = libcrux_ml_kem::MlKemCiphertext::<$ct_len>::try_from(
                                hex_field(t, "c").as_slice(),
                            )
                            .unwrap();
                            let k = libcrux_ml_kem::$lib::decapsulate(&sk, &ct);
                            assert_eq!(
                                to_hex(&k),
                                str_field(t, "k").to_lowercase(),
                                "{}",
                                str_field(t, "reason")
                            );
                        }
                        "decapsulationKeyCheck" => {
                            let ok = libcrux_ml_kem::MlKemPrivateKey::<$sk_len>::try_from(
                                hex_field(t, "dk").as_slice(),
                            )
                            .is_ok_and(|sk| {
                                libcrux_ml_kem::$lib::validate_private_key(
                                    &sk,
                                    &libcrux_ml_kem::MlKemCiphertext::from([0; $ct_len]),
                                )
                            });
                            assert_eq!(
                                ok,
                                bool_field(t, "testPassed"),
                                "{}",
                                str_field(t, "reason")
                            );
                        }
                        other => assert_eq!(other, "a known ACVP function"),
                    }
                    n = n.saturating_add(1);
                }
                assert_eq!(n, $n_acvp_ed);
            }
        }
    };
}

mlkem_kats!(
    mlkem768,
    "ML-KEM-768",
    "768",
    MlKem768Dk,
    MlKem768Ek,
    MlKem768Ct,
    mlkem768,
    2400,
    1088,
    counts = (201, 265, 100, 9, 25, 55)
);
mlkem_kats!(
    mlkem1024,
    "ML-KEM-1024",
    "1024",
    MlKem1024Dk,
    MlKem1024Ek,
    MlKem1024Ct,
    mlkem1024,
    3168,
    1568,
    counts = (202, 269, 100, 9, 25, 55)
);
