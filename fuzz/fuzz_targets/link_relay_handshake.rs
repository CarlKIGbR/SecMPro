// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-03 (M5): the relay side of the SecMP-LINK handshake (spec §8.2–§8.3) for a fixed relay (secrets from constant
//! bytes, `fuzz/common/link_fixture.rs`). Invariants: no panic; every `Err` is the uniform `Rejected` and the relay
//! drew no randomness (spec §8.5: `mac1` is checked before anything is drawn); an `Ok` is a canonical `HS2` record and
//! a link at counters (0, 0), and only for a consistent `HS1`.
//!
//! The first byte selects the mode (modulo 3):
//!
//! - 0 raw `HELLO`: the rest is fed to `AwaitHello::on_hello`; `Ok` iff it is exactly the `HELLO` record, and then the
//!   answer is the honest `RELAYINFO`.
//! - 1 raw `HS1`: the rest is fed to `AwaitHs1::on_hs1` (after the honest `HELLO`); `Ok` only for the honest `HS1`.
//! - 2 structured `HS1`: two flag bytes (big-endian `u16`), then the fuzzer's fields; the harness composes the record
//!   the way a client does: it encapsulates to the relay's static keys, takes `ss1` from the relay's own `Decaps` of
//!   what it sends (so a tampered ciphertext still gets a `mac1` that the relay computes), `h0` over the record's
//!   fields, `mac1`. Flags: bit 0 `kid` replaced (4 bytes follow); 1 `e_c` replaced (32); 2 `ek_c` byte changed
//!   (position 2, xor 1); 3 `pk_e1` replaced after encapsulation (32); 4 `ct_kem` byte changed after encapsulation
//!   (position 2, xor 1); 5 fresh encapsulation randomness `sk_e1 ‖ m1` (64); 6 `mac1` bit flipped (position 1);
//!   7 `ver` replaced (1); 8 `h0` computed over a different `relay_fp` (position 1, xor 1). Expected verdict: `Ok` iff
//!   the `HS1` decoder accepts the record, `kid` is the relay's, the relay's `Decaps` succeeds, and neither bit 6 nor
//!   bit 8 is set.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{HybridKem1024Ciphertext, MlKem1024Ct, X25519Public};
use secmp_proto::link::Error;
use secmp_proto::wire::record::{Hs1, Hs2};
use secmp_proto::{Decode, Encode};

#[path = "../common/link_fixture.rs"]
mod link_fixture;

use link_fixture::{
    Bytes, Fixture, HELLO, RELAY_DRAWS, VALID_UNTIL, ck1_mac1, h0_of, h1, h2, hs1_record,
};

fn on_hs1(f: &Fixture, record: &[u8]) -> Result<(), Error> {
    let mut entropy = f.relay_entropy();
    match f.relay_awaiting_hs1().on_hs1(record, &mut entropy) {
        Ok((hs2, link)) => {
            // one canonical HS2 record, a fresh link, both halves of the randomness drawn
            assert_eq!(hs2.len(), h2::LEN);
            assert_eq!(
                Hs2::decode(&hs2).unwrap().encode().unwrap().as_slice(),
                hs2.as_slice()
            );
            assert_eq!(entropy.remaining(), RELAY_DRAWS - 64);
            assert_eq!(
                (link.send_counter(), link.recv_counter()),
                (Some(0), Some(0))
            );
            Ok(())
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert_eq!(entropy.remaining(), RELAY_DRAWS);
            Err(e)
        }
    }
}

fn raw_hello(f: &Fixture, record: &[u8]) {
    match secmp_proto::link::relay::accept(&f.relay_keys).on_hello(record, VALID_UNTIL) {
        Ok((info, _)) => {
            assert_eq!(record, HELLO.as_slice());
            assert_eq!(info, f.relay_info);
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert_ne!(record, HELLO.as_slice());
        }
    }
}

fn raw_hs1(f: &Fixture, record: &[u8]) {
    let ok = on_hs1(f, record).is_ok();
    assert_eq!(ok, record == f.hs1.as_slice());
}

fn structured_hs1(f: &Fixture, mut b: Bytes<'_>) {
    let flags = b.u16();
    let on = |bit: u16| flags >> bit & 1 == 1;
    let kid = if on(0) { b.u32() } else { f.kid };
    let client = f.client_kem();
    let mut e_c = client.public_key().pk_dh().as_bytes().to_vec();
    let mut ek_c = client.public_key().ek().as_bytes().to_vec();
    if on(1) {
        e_c = b.take(32);
    }
    if on(2) {
        let at = usize::from(b.u16()) % link_fixture::h1::EK_C_LEN;
        ek_c[at] ^= 1;
    }
    // the encapsulation to the relay's static keys
    let (sk_e1, m1) = if on(5) {
        let raw = b.take(64);
        (raw[..32].try_into().unwrap(), raw[32..].try_into().unwrap())
    } else {
        f.client_encaps_draws()
    };
    let relay_pk = f.relay_kem.public_key();
    let (ct, _) = relay_pk.encapsulate_kat(&sk_e1, &m1).unwrap();
    let mut pk_e1 = ct.pk_e().as_bytes().to_vec();
    let mut ct_kem = ct.ct().as_bytes().to_vec();
    if on(3) {
        pk_e1 = b.take(32);
    }
    if on(4) {
        let at = usize::from(b.u16()) % link_fixture::h1::CT_KEM_LEN;
        ct_kem[at] ^= 1;
    }
    let ver = if on(7) { b.u8() } else { 1 };
    let mut fp = f.fp;
    if on(8) {
        fp[usize::from(b.u8()) % 32] ^= 1;
    }
    let mac_flip = on(6).then(|| usize::from(b.u8()) % 32);

    // ss1 as the relay computes it from what it receives
    let ss1 = X25519Public::from_bytes_checked(&pk_e1).ok().and_then(|e| {
        let ct = HybridKem1024Ciphertext::new(e, MlKem1024Ct::from_bytes(&ct_kem).ok()?);
        f.relay_kem.decapsulate(&ct).ok()
    });
    let mut mac1 = match &ss1 {
        Some(ss1) => {
            ck1_mac1(
                &h0_of(kid, &fp, &e_c, &ek_c, &pk_e1, &ct_kem),
                ss1.expose_secret(),
            )
            .1
        }
        None => [0; 32],
    };
    if let Some(at) = mac_flip {
        mac1[at] ^= 1;
    }
    let record = hs1_record(ver, kid, &e_c, &ek_c, &pk_e1, &ct_kem, &mac1);
    assert_eq!(record.len(), h1::LEN);

    let consistent = Hs1::decode(&record).is_ok()
        && kid == f.kid
        && ss1.is_some()
        && mac_flip.is_none()
        && !on(8);
    assert_eq!(on_hs1(f, &record).is_ok(), consistent);
}

fuzz_target!(|data: &[u8]| {
    let f = Fixture::get();
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 3 {
        0 => raw_hello(f, rest),
        1 => raw_hs1(f, rest),
        _ => structured_hs1(f, Bytes(rest)),
    }
});
