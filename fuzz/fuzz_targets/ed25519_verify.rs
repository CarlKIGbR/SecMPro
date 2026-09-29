// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 strict import and verification (spec §3.5) on arbitrary bytes `A (32) ‖ sig (64) ‖ msg`: never
//! panics; an imported key re-encodes to its input; a signature accepted under an arbitrary key must also be
//! accepted after a round trip of the key through its encoding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey, Error};

fuzz_target!(|data: &[u8]| {
    let Some((pk, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let (sig, msg) = rest.split_at(rest.len().min(64));
    if let Ok(vk) = Ed25519VerifyingKey::from_bytes(pk) {
        assert_eq!(vk.as_bytes(), pk);
        let r = vk.verify(msg, sig);
        assert!(r.is_ok() || r == Err(Error::Rejected));
    }
    // an honest key (seed = the first 32 bytes): its own signature verifies, a modified one does not
    if let Ok(sk) = Ed25519SigningKey::from_seed(pk) {
        let vk = sk.verifying_key();
        let good = sk.sign(msg);
        assert!(vk.verify(msg, &good).is_ok());
        if sig.len() == 64 && sig != good {
            assert_eq!(vk.verify(msg, sig), Err(Error::Rejected));
        }
    }
});
