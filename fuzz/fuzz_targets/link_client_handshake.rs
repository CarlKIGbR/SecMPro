// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-02 (M5): the client side of the SecMP-LINK handshake (spec §8.2–§8.3) against a fixed relay (secrets from
//! constant bytes, `fuzz/common/link_fixture.rs`). Invariants: no panic; every `Err` is the uniform `Rejected` and a
//! client that rejects drew no randomness; an `Ok` only for a consistent record; and the `Link` of an accepted `HS2`
//! holds exactly the keys that an independent composition of §8.3 derives.
//!
//! The first byte selects the mode (modulo 3):
//!
//! - 0 raw `RELAYINFO`: byte 1 bit 0 = the client holds the access key; the rest is the record fed to
//!   `AwaitRelayInfo::on_relayinfo`. An `Ok` only for the honest record (an Ed25519 signature is unique).
//! - 1 structured `RELAYINFO`: two flag bytes, then the fuzzer's fields, which the harness patches into the honest
//!   record and signs with the relay's key (or an attacker's), so that the checks behind the signature are reached.
//!   Flags (big-endian `u16`): bit 0 access key held; 1 signed by an attacker key whose public key is written into
//!   `relay_sig_pk` (32-byte seed follows); 2 `relay_sig_pk` replaced (32 bytes follow); 3 `ver` replaced (1 byte);
//!   4 `kid` replaced (4); 5 `valid_until` = `NOW - 100 + (u32 % 10_000_000)` (4); 6 `akc` byte changed (position
//!   1, xor 1); 7 `relay_dh_pk` replaced (32); 8 `relay_kem_ek` byte changed (position 2, xor 1); 9 a signature bit
//!   flipped after signing (position 1). Expected verdict: `Err` unless version, signature, pinned fingerprint,
//!   validity window (`NOW ≤ valid_until ≤ NOW + 60 d`) and `akc` all hold; `Ok` if they hold and the static keys
//!   are the honest ones.
//! - 2 structured `HS2`: one flag byte, then the fuzzer's fields; the harness patches them into the honest `HS2` and
//!   recomputes `mac2` from the client's own secrets (`ss2` by `Decaps`, `h1`, `ck2`), so the record is consistent
//!   unless a flag breaks it. Flags: bit 0 `e_r` replaced (32); 1 `ct_c` byte changed (position 2, xor 1); 2 `mac2`
//!   bit flipped (position 1); 3 `ver` replaced (1); 4 one byte appended; 5 one byte removed. Expected verdict: `Ok`
//!   iff no flag of bits 2–5 is set (a `ver` equal to 1 excepted) and the decoder and `Decaps` accept; then the keys
//!   and `sess_id` of the `Link` equal the composed ones.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{
    Ed25519SigningKey, HybridKem768Ciphertext, Label, MlKem768Ct, X25519Public, hkdf_expand,
};
use secmp_proto::link::Error;
use secmp_proto::wire::record::Hs1;
use secmp_proto::{Decode, Encode};

#[path = "../common/link_fixture.rs"]
mod link_fixture;

use link_fixture::{Bytes, CLIENT_DRAWS, Fixture, NOW, ck2_mac2, h2, ri};

const MAX_VALIDITY: u64 = 5_184_000;

fn raw_relayinfo(f: &Fixture, mut b: Bytes<'_>) {
    let with_access = b.u8() & 1 == 1;
    let record = b.0;
    let mut entropy = f.client_entropy();
    match f.client(with_access).on_relayinfo(record, &mut entropy) {
        Ok((hs1, _)) => {
            assert_eq!(record, f.relay_info.as_slice());
            assert_eq!(hs1, f.hs1);
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert_eq!(entropy.remaining(), CLIENT_DRAWS);
        }
    }
}

fn structured_relayinfo(f: &Fixture, mut b: Bytes<'_>) {
    let flags = b.u16();
    let on = |bit: u16| flags >> bit & 1 == 1;
    let mut record = f.relay_info.clone();
    let mut signer = f.sig_seed.clone();
    let mut signer_pk = f.sig_pk.clone();
    if on(1) {
        signer = b.take(32);
        signer_pk = Ed25519SigningKey::from_seed(&signer)
            .unwrap()
            .verifying_key()
            .as_bytes()
            .to_vec();
        record[ri::SIG_PK..ri::KID].copy_from_slice(&signer_pk);
    }
    if on(2) {
        record[ri::SIG_PK..ri::KID].copy_from_slice(&b.take(32));
    }
    if on(3) {
        record[ri::VER] = b.u8();
    }
    if on(4) {
        record[ri::KID..ri::DH_PK].copy_from_slice(&b.u32().to_be_bytes());
    }
    if on(5) {
        let valid_until = NOW - 100 + u64::from(b.u32() % 10_000_000);
        record[ri::VALID_UNTIL..ri::SIG].copy_from_slice(&valid_until.to_be_bytes());
    }
    if on(6) {
        let at = usize::from(b.u8()) % 32;
        record[ri::AKC + at] ^= 1;
    }
    if on(7) {
        record[ri::DH_PK..ri::KEM_EK].copy_from_slice(&b.take(32));
    }
    if on(8) {
        let at = usize::from(b.u16()) % ri::KEM_EK_LEN;
        record[ri::KEM_EK + at] ^= 1;
    }
    Fixture::sign_relay_info(&mut record, &signer);
    if on(9) {
        let at = usize::from(b.u8()) % 64;
        record[ri::SIG + at] ^= 1;
    }

    let with_access = on(0);
    let mut entropy = f.client_entropy();
    let result = f.client(with_access).on_relayinfo(&record, &mut entropy);

    // the expected verdict
    let field = |from: usize, to: usize| &record[from..to];
    let valid_until = u64::from_be_bytes(field(ri::VALID_UNTIL, ri::SIG).try_into().unwrap());
    let version_ok = record[ri::VER] == 1;
    // the signature verifies iff it was made by the key now named in the record and no bit was flipped; the relay
    // is the pinned one iff that key is the relay's
    let signature_ok = !on(9) && field(ri::SIG_PK, ri::KID) == signer_pk.as_slice();
    let pinned_ok = field(ri::SIG_PK, ri::KID) == f.sig_pk.as_slice();
    let window_ok = valid_until >= NOW && valid_until - NOW <= MAX_VALIDITY;
    let akc_ok = !with_access || field(ri::AKC, ri::VALID_UNTIL) == f.akc.as_slice();
    let static_honest = field(ri::DH_PK, ri::KEM_EK) == f.dh_pk.as_slice()
        && field(ri::KEM_EK, ri::AKC) == f.kem_ek.as_slice();
    let must_reject = !(version_ok && signature_ok && pinned_ok && window_ok && akc_ok);
    match result {
        Ok((hs1, _)) => {
            assert!(!must_reject, "accepted an inconsistent RELAYINFO");
            // the HS1 is one canonical record that names the relay's generation
            let decoded = Hs1::decode(&hs1).unwrap();
            assert_eq!(decoded.encode().unwrap().as_slice(), hs1.as_slice());
            assert_eq!(
                decoded.kid.to_be_bytes().as_slice(),
                field(ri::KID, ri::DH_PK)
            );
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert_eq!(entropy.remaining(), CLIENT_DRAWS);
            assert!(
                must_reject || !static_honest,
                "rejected a consistent RELAYINFO"
            );
        }
    }
}

fn structured_hs2(f: &Fixture, mut b: Bytes<'_>) {
    let flags = b.u8();
    let on = |bit: u8| flags >> bit & 1 == 1;
    let st = f.client_awaiting_hs2();
    let trace = st.trace_kat().clone();

    let mut e_r: Vec<u8> = f.hs2[h2::E_R..h2::CT_C].to_vec();
    let mut ct_c: Vec<u8> = f.hs2[h2::CT_C..h2::MAC2].to_vec();
    if on(0) {
        e_r = b.take(32);
    }
    if on(1) {
        let at = usize::from(b.u16()) % h2::CT_C_LEN;
        ct_c[at] ^= 1;
    }
    let mac_flip = on(2).then(|| usize::from(b.u8()) % 32);
    let ver = on(3).then(|| b.u8());

    // what an honest relay computes for these fields: Decaps with the client's own secrets, h1, ck2, mac2
    let decaps = X25519Public::from_bytes_checked(&e_r).ok().and_then(|e| {
        let ct = HybridKem768Ciphertext::new(e, MlKem768Ct::from_bytes(&ct_c).ok()?);
        f.client_kem().decapsulate(&ct).ok()
    });
    let (mut mac2, composed) = match &decaps {
        Some(ss2) => {
            let (ck2, mac2) = ck2_mac2(
                &trace.h0,
                &trace.mac1,
                &trace.ck1,
                &e_r,
                &ct_c,
                ss2.expose_secret(),
            );
            (mac2, Some(ck2))
        }
        None => ([0; 32], None),
    };
    if let Some(at) = mac_flip {
        mac2[at] ^= 1;
    }
    let mut record = f.hs2.clone();
    record[h2::E_R..h2::CT_C].copy_from_slice(&e_r);
    record[h2::CT_C..h2::MAC2].copy_from_slice(&ct_c);
    record[h2::MAC2..h2::LEN].copy_from_slice(&mac2);
    if let Some(v) = ver {
        record[h2::VER] = v;
    }
    if on(4) {
        record.push(b.u8());
    }
    if on(5) {
        record.pop();
    }

    let must_reject = decaps.is_none()
        || mac_flip.is_some()
        || ver.is_some_and(|v| v != 1)
        || record.len() != h2::LEN;
    match st.on_hs2(&record) {
        Ok(link) => {
            assert!(!must_reject, "accepted an inconsistent HS2");
            let ck2 = composed.unwrap();
            let okm = hkdf_expand::<80>(ck2.expose_secret(), Label::LinkKeys, &[]).unwrap();
            let okm = okm.expose_secret();
            let (k_send, k_recv) = link.keys_kat();
            assert_eq!(k_send.as_slice(), &okm[..32]);
            assert_eq!(k_recv.as_slice(), &okm[32..64]);
            assert_eq!(link.sess_id().as_slice(), &okm[64..80]);
            assert_eq!(
                (link.send_counter(), link.recv_counter()),
                (Some(0), Some(0))
            );
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert!(must_reject, "rejected a consistent HS2");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let f = Fixture::get();
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let b = Bytes(rest);
    match selector % 3 {
        0 => raw_relayinfo(f, b),
        1 => structured_relayinfo(f, b),
        _ => structured_hs2(f, b),
    }
});
