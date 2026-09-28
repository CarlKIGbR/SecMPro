// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "kat")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Known-answer tests for the symmetric primitives under `MsgEncrypt` and `CAEAD` (feature `kat`): the pinned
//! `chacha20poly1305`, `chacha20`, `hkdf` and `hmac` crates against Wycheproof and RFC vectors. The SecMP
//! wrappers only expose the constructions (label-prefixed HKDF, `EtM`, `UtC`), so the primitives are checked here
//! at the exact crate API the constructions call; the constructions themselves are pinned by the frozen SecMP
//! vectors.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secmp_testkit::kat::{
    Tally, Verdict, hex, hex_field, load, to_hex, u64_field, wycheproof_cases,
};
use sha2::Sha256;

/// Wycheproof XChaCha20-Poly1305: valid cases encrypt to `ct ‖ tag` and decrypt back; invalid cases (modified
/// tags, wrong nonce sizes) fail to open.
#[test]
fn wycheproof_xchacha20_poly1305() {
    let doc = load("external/wycheproof/xchacha20_poly1305_test.json");
    let mut tally = Tally::default();
    for c in wycheproof_cases(&doc) {
        let (key, iv, assoc) = (
            hex_field(c.test, "key"),
            hex_field(c.test, "iv"),
            hex_field(c.test, "aad"),
        );
        let (msg, ct, tag) = (
            hex_field(c.test, "msg"),
            hex_field(c.test, "ct"),
            hex_field(c.test, "tag"),
        );
        let aead = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let (Ok(nonce), Ok(tag)) = (
            XNonce::try_from(iv.as_slice()),
            Tag::try_from(tag.as_slice()),
        ) else {
            assert_eq!(c.verdict, Verdict::Invalid, "tcId {}", c.tc_id);
            tally.check();
            continue;
        };
        let mut buf = ct.clone();
        let opened = aead.decrypt_inout_detached(&nonce, &assoc, buf.as_mut_slice().into(), &tag);
        match c.verdict {
            Verdict::Valid => {
                assert!(opened.is_ok(), "tcId {}", c.tc_id);
                assert_eq!(buf, msg, "tcId {}", c.tc_id);
                let mut enc = msg.clone();
                let t = aead
                    .encrypt_inout_detached(&nonce, &assoc, enc.as_mut_slice().into())
                    .unwrap();
                assert_eq!(
                    (to_hex(&enc), to_hex(&t)),
                    (to_hex(&ct), to_hex(&tag)),
                    "tcId {}",
                    c.tc_id
                );
            }
            Verdict::Invalid => assert!(opened.is_err(), "tcId {}", c.tc_id),
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (315, 0),
        "{}",
        tally.summary("xchacha20-poly1305")
    );
}

/// The ChaCha20 stream as `MsgEncrypt` uses it (IETF variant, 96-bit nonce): the RFC 8439 AEAD encrypts with
/// the keystream from block 1, so for every valid Wycheproof ChaCha20-Poly1305 case with a 12-byte nonce,
/// `msg ⊕ keystream[64..]` must equal `ct`.
#[test]
fn chacha20_stream_from_wycheproof_aead_cases() {
    let doc = load("external/wycheproof/chacha20_poly1305_test.json");
    let mut tally = Tally::default();
    for c in wycheproof_cases(&doc) {
        let iv = hex_field(c.test, "iv");
        if c.verdict != Verdict::Valid || iv.len() != 12 {
            tally.skip(c.tc_id, "not a valid 96-bit-nonce case");
            continue;
        }
        let key = hex_field(c.test, "key");
        let mut buf = hex_field(c.test, "msg");
        let mut cipher = ChaCha20::new_from_slices(&key, &iv).unwrap();
        cipher.seek(64_u64);
        cipher.apply_keystream(&mut buf);
        assert_eq!(
            to_hex(&buf),
            to_hex(&hex_field(c.test, "ct")),
            "tcId {}",
            c.tc_id
        );
        tally.check();
    }
    assert!(tally.checked >= 200, "{}", tally.summary("chacha20 stream"));
}

/// RFC 8439 A.1 test vector #1: block 0 of the all-zero key and nonce — the counter `MsgEncrypt` starts at.
#[test]
fn chacha20_block_zero() {
    let mut buf = [0_u8; 64];
    let mut cipher = ChaCha20::new(&[0; 32].into(), &[0; 12].into());
    cipher.apply_keystream(&mut buf);
    assert_eq!(
        to_hex(&buf),
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
         da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    );
}

/// Wycheproof HKDF-SHA-256: valid cases give `okm`; invalid ones request more than 255 · 32 bytes.
#[test]
fn wycheproof_hkdf_sha256() {
    let doc = load("external/wycheproof/hkdf_sha256_test.json");
    let mut tally = Tally::default();
    for c in wycheproof_cases(&doc) {
        let hk = Hkdf::<Sha256>::new(Some(&hex_field(c.test, "salt")), &hex_field(c.test, "ikm"));
        let mut okm = vec![0; usize::try_from(u64_field(c.test, "size")).unwrap()];
        let r = hk.expand(&hex_field(c.test, "info"), &mut okm);
        match c.verdict {
            Verdict::Valid => {
                assert!(r.is_ok(), "tcId {}", c.tc_id);
                assert_eq!(
                    to_hex(&okm),
                    to_hex(&hex_field(c.test, "okm")),
                    "tcId {}",
                    c.tc_id
                );
            }
            Verdict::Invalid => assert!(r.is_err(), "tcId {}", c.tc_id),
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (86, 0),
        "{}",
        tally.summary("hkdf")
    );
}

/// RFC 5869 A.1 and A.3 (A.3: empty salt, as the spec's `salt = 0^32` call sites use it).
#[test]
fn rfc5869() {
    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&hex("000102030405060708090a0b0c")), &[0x0b; 22]);
    assert_eq!(
        to_hex(&prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let mut okm = [0; 42];
    hk.expand(&hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
    assert_eq!(
        to_hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    let hk = Hkdf::<Sha256>::new(Some(&[]), &[0x0b; 22]);
    hk.expand(&[], &mut okm).unwrap();
    assert_eq!(
        to_hex(&okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

/// Wycheproof HMAC-SHA-256 (including truncated tags): valid ⇔ the tag is a prefix of the full MAC.
#[test]
fn wycheproof_hmac_sha256() {
    let doc = load("external/wycheproof/hmac_sha256_test.json");
    let mut tally = Tally::default();
    for c in wycheproof_cases(&doc) {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&hex_field(c.test, "key")).unwrap();
        mac.update(&hex_field(c.test, "msg"));
        let full = mac.finalize().into_bytes();
        let tag = hex_field(c.test, "tag");
        let matches = full.get(..tag.len()) == Some(tag.as_slice());
        match c.verdict {
            Verdict::Valid => assert!(matches, "tcId {}", c.tc_id),
            Verdict::Invalid => assert!(!matches, "tcId {}", c.tc_id),
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (174, 0),
        "{}",
        tally.summary("hmac")
    );
}

/// RFC 4231 test cases 1–4, 6 and 7 (HMAC-SHA-256).
#[test]
fn rfc4231() {
    let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
        (vec![0x0b; 20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa; 20], vec![0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), vec![0xcd; 50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (
            vec![0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (key, data, expected) in cases {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(&data);
        assert_eq!(to_hex(&mac.finalize().into_bytes()), expected);
    }
}
