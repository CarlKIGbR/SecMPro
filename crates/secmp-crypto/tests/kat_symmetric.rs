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

/// The same Wycheproof XChaCha20-Poly1305 file through the SecMP wrapper `Aead` (ratchet headers, spec §7.5; link
/// frames, §8.4): every case with a 24-byte nonce — valid ones seal to `ct ‖ tag`, open to `msg` and open under
/// `open_ct` with `Choice` 1; invalid ones (modified tags) are `Rejected` by `open` and give `Choice` 0 with an
/// all-zero `out` under `open_ct`. The nine cases with another nonce size cannot be expressed: the nonce is a
/// `[u8; 24]`.
#[test]
fn wycheproof_xchacha20_poly1305_through_aead() {
    use secmp_crypto::{Aead, Error, Nonce24, SecretBytes};
    let doc = load("external/wycheproof/xchacha20_poly1305_test.json");
    let mut tally = Tally::default();
    let (mut valid, mut invalid) = (0_usize, 0_usize);
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
        let Ok(nonce) = <[u8; 24]>::try_from(iv.as_slice()) else {
            assert_eq!(c.verdict, Verdict::Invalid, "tcId {}", c.tc_id);
            tally.skip(c.tc_id, "nonce size is not 24 bytes");
            continue;
        };
        let key = SecretBytes::<32>::from_slice(&key).unwrap();
        let sealed = [ct.as_slice(), tag.as_slice()].concat();
        let mut out = vec![0xaa_u8; msg.len()];
        let ok = bool::from(Aead::open_ct(&key, &nonce, &assoc, &sealed, &mut out));
        match c.verdict {
            Verdict::Valid => {
                let opened = Aead::open(&key, &nonce, &assoc, &sealed).unwrap();
                assert_eq!(to_hex(&opened), to_hex(&msg), "tcId {}", c.tc_id);
                assert!(ok, "tcId {}", c.tc_id);
                assert_eq!(to_hex(&out), to_hex(&msg), "tcId {}", c.tc_id);
                let resealed =
                    Aead::seal(&key, Nonce24::from_bytes_kat(nonce), &assoc, &msg).unwrap();
                assert_eq!(to_hex(&resealed), to_hex(&sealed), "tcId {}", c.tc_id);
                valid = valid.saturating_add(1);
            }
            Verdict::Invalid => {
                assert_eq!(
                    Aead::open(&key, &nonce, &assoc, &sealed).err(),
                    Some(Error::Rejected),
                    "tcId {}",
                    c.tc_id
                );
                assert!(!ok, "tcId {}", c.tc_id);
                assert!(out.iter().all(|b| *b == 0), "tcId {}", c.tc_id);
                invalid = invalid.saturating_add(1);
            }
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    assert_eq!(
        (tally.checked, valid, invalid, tally.skipped.len()),
        (306, 246, 60, 9),
        "{}",
        tally.summary("xchacha20-poly1305 through Aead")
    );
}

/// `Aead::open_ct` and `Aead::open_ct_constant_flow` on the same input, each into its own `out` of `out_len` bytes
/// of `0xaa`: they agree on the verdict and on `out` afterwards; returns them.
fn open_both(
    key: &secmp_crypto::SecretBytes<32>,
    nonce: &[u8; 24],
    assoc: &[u8],
    sealed: &[u8],
    out_len: usize,
    what: &str,
) -> (bool, Vec<u8>) {
    use secmp_crypto::Aead;
    let mut a = vec![0xaa_u8; out_len];
    let mut b = vec![0xaa_u8; out_len];
    let ra = bool::from(Aead::open_ct(key, nonce, assoc, sealed, &mut a));
    let rb = bool::from(Aead::open_ct_constant_flow(
        key, nonce, assoc, sealed, &mut b,
    ));
    assert_eq!(
        (ra, to_hex(&a)),
        (rb, to_hex(&b)),
        "{what}: open_ct vs open_ct_constant_flow"
    );
    (rb, b)
}

/// The Wycheproof XChaCha20-Poly1305 file through `Aead::open_ct_constant_flow` (the opening of the SecMP-TR header
/// trial, spec §7.4; M4 campaign R-59) next to `Aead::open_ct`: on every case with a 24-byte nonce both give the
/// same verdict and the same `out` — valid cases `Choice` 1 and `msg`, invalid ones (modified tags) `Choice` 0 and
/// all zeros — and into an `out` one byte too long both refuse and leave it untouched. The nine cases with another
/// nonce size cannot be expressed (the nonce is a `[u8; 24]`).
#[test]
fn wycheproof_xchacha20_poly1305_constant_flow_equals_open_ct() {
    use secmp_crypto::SecretBytes;
    let doc = load("external/wycheproof/xchacha20_poly1305_test.json");
    let mut tally = Tally::default();
    let (mut valid, mut invalid) = (0_usize, 0_usize);
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
        let Ok(nonce) = <[u8; 24]>::try_from(iv.as_slice()) else {
            assert_eq!(c.verdict, Verdict::Invalid, "tcId {}", c.tc_id);
            tally.skip(c.tc_id, "nonce size is not 24 bytes");
            continue;
        };
        let key = SecretBytes::<32>::from_slice(&key).unwrap();
        let sealed = [ct.as_slice(), tag.as_slice()].concat();
        let what = format!("tcId {}", c.tc_id);
        let (ok, out) = open_both(&key, &nonce, &assoc, &sealed, msg.len(), &what);
        let longer = msg.len().checked_add(1).unwrap();
        assert_eq!(
            open_both(&key, &nonce, &assoc, &sealed, longer, &what),
            (false, vec![0xaa; longer]),
            "{what}: out one byte too long"
        );
        match c.verdict {
            Verdict::Valid => {
                assert!(ok, "{what}");
                assert_eq!(to_hex(&out), to_hex(&msg), "{what}");
                valid = valid.saturating_add(1);
            }
            Verdict::Invalid => {
                assert!(!ok, "{what}");
                assert!(out.iter().all(|b| *b == 0), "{what}");
                invalid = invalid.saturating_add(1);
            }
            Verdict::Acceptable => {
                tally.skip(c.tc_id, "acceptable");
                continue;
            }
        }
        tally.check();
    }
    assert_eq!(
        (tally.checked, valid, invalid, tally.skipped.len()),
        (306, 246, 60, 9),
        "{}",
        tally.summary("xchacha20-poly1305 constant flow vs open_ct")
    );
}

/// A seeded xorshift64* stream: the inputs of `constant_flow_equals_open_ct_randomized` without a dependency.
struct Stream(u64);

impl Stream {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0.wrapping_shr(12);
        self.0 ^= self.0.wrapping_shl(25);
        self.0 ^= self.0.wrapping_shr(27);
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| u8::try_from(self.next().wrapping_shr(56)).unwrap())
            .collect()
    }

    /// Uniform enough in `0..n` (`n > 0`).
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next().checked_rem(u64::try_from(n).unwrap()).unwrap()).unwrap()
    }

    /// One random bit of a byte.
    fn bit(&mut self) -> u8 {
        1_u8.wrapping_shl(u32::try_from(self.below(8)).unwrap())
    }
}

/// An opening that must be rejected: `(key, nonce, AD, ct ‖ tag)`.
type Rejected = ([u8; 32], [u8; 24], Vec<u8>, Vec<u8>);

/// `x` with one random bit flipped in one random byte (`x` not empty).
fn flip_one(s: &mut Stream, x: &mut [u8]) {
    let at = s.below(x.len());
    let bit = s.bit();
    *x.get_mut(at).unwrap() ^= bit;
}

/// `Aead::open_ct_constant_flow` against `Aead::open_ct` on seeded random inputs (an xorshift64* stream, seed
/// `0x5ec3_2d00_0000_0059`; no dependency): plaintexts of 0, 1, 15, 16, 17, 63, 64, 65, 255, 1000 and 2314 bytes
/// (the TR header, spec §7.5), six rounds each, under random keys and nonces and an AD of 0, 13 or 26 bytes, sealed by
/// `Aead::seal`. Both accept with the plaintext; both reject with an all-zero `out` after a flipped bit in each of the
/// 16 tag bytes, in the first, middle and last ciphertext byte and at 8 random positions of the input, under a key, a
/// nonce or a (non-empty) AD with one bit flipped and under an AD one byte longer; both reject leaving `out` untouched
/// for the input truncated or extended by one byte and for an `out` one byte shorter (non-empty plaintexts) or longer.
#[test]
fn constant_flow_equals_open_ct_randomized() {
    use secmp_crypto::{Aead, Nonce24, SecretBytes};
    const LENS: [usize; 11] = [0, 1, 15, 16, 17, 63, 64, 65, 255, 1000, 2314];
    const ROUNDS: usize = 6;
    let mut s = Stream(0x5ec3_2d00_0000_0059);
    let (mut accepted, mut zeroed, mut untouched) = (0_usize, 0_usize, 0_usize);
    for len in LENS {
        for round in 0..ROUNDS {
            let key_bytes: [u8; 32] = s.bytes(32).try_into().unwrap();
            let nonce: [u8; 24] = s.bytes(24).try_into().unwrap();
            let assoc = s.bytes(round.checked_rem(3).unwrap().checked_mul(13).unwrap());
            let msg = s.bytes(len);
            let key = SecretBytes::<32>::from_slice(&key_bytes).unwrap();
            let sealed = Aead::seal(&key, Nonce24::from_bytes_kat(nonce), &assoc, &msg).unwrap();
            let what = format!("len {len}, round {round}");
            assert_eq!(
                open_both(&key, &nonce, &assoc, &sealed, len, &what),
                (true, msg.clone()),
                "{what}: authentic"
            );
            accepted = accepted.saturating_add(1);

            // rejected, `out` all zero
            let mut positions: Vec<usize> = (len..sealed.len()).collect();
            if let Some(last) = len.checked_sub(1) {
                positions.extend([0, len.checked_div(2).unwrap(), last]);
            }
            positions.extend((0..8).map(|_| s.below(sealed.len())));
            let mut rejected: Vec<Rejected> = positions
                .into_iter()
                .map(|at| {
                    let mut bad = sealed.clone();
                    *bad.get_mut(at).unwrap() ^= s.bit();
                    (key_bytes, nonce, assoc.clone(), bad)
                })
                .collect();
            let (mut k2, mut n2) = (key_bytes, nonce);
            flip_one(&mut s, &mut k2);
            flip_one(&mut s, &mut n2);
            rejected.push((k2, nonce, assoc.clone(), sealed.clone()));
            rejected.push((key_bytes, n2, assoc.clone(), sealed.clone()));
            if !assoc.is_empty() {
                let mut a2 = assoc.clone();
                flip_one(&mut s, &mut a2);
                rejected.push((key_bytes, nonce, a2, sealed.clone()));
            }
            let mut longer_ad = assoc.clone();
            longer_ad.push(0);
            rejected.push((key_bytes, nonce, longer_ad, sealed.clone()));
            for (k, n, a, c) in rejected {
                let k = SecretBytes::<32>::from_slice(&k).unwrap();
                assert_eq!(
                    open_both(&k, &n, &a, &c, len, &what),
                    (false, vec![0; len]),
                    "{what}: rejected"
                );
                zeroed = zeroed.saturating_add(1);
            }

            // rejected, `out` untouched (wrong lengths)
            let truncated = sealed.split_last().unwrap().1;
            let mut extended = sealed.clone();
            extended.push(0);
            let mut wrong = vec![
                (truncated, len),
                (extended.as_slice(), len),
                (sealed.as_slice(), len.checked_add(1).unwrap()),
            ];
            if let Some(shorter) = len.checked_sub(1) {
                wrong.push((sealed.as_slice(), shorter));
            }
            for (c, out_len) in wrong {
                assert_eq!(
                    open_both(&key, &nonce, &assoc, c, out_len, &what),
                    (false, vec![0xaa; out_len]),
                    "{what}: wrong length"
                );
                untouched = untouched.saturating_add(1);
            }
        }
    }
    // 11 lengths × 6 rounds = 66 cases; zeroed per case: 16 tag bytes + 8 random positions + key + nonce + longer AD
    // = 27, plus 3 ciphertext positions for the 10 non-empty lengths and the AD flip in rounds 1, 2, 4, 5:
    // 66 × 27 + 60 × 3 + 11 × 4 = 2006; untouched per case: truncated, extended, out + 1 = 3, plus out − 1 for the
    // non-empty lengths: 66 × 3 + 60 = 258
    assert_eq!((accepted, zeroed, untouched), (66, 2006, 258));
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
    // 325 cases, 256 of them valid with a 96-bit nonce
    assert_eq!(
        (tally.checked, tally.skipped.len()),
        (256, 69),
        "{}",
        tally.summary("chacha20 stream")
    );
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
