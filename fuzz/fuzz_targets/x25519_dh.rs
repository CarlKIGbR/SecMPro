// SPDX-License-Identifier: AGPL-3.0-or-later
//! X25519 on arbitrary secrets and public keys: never panics; the result is either a non-zero shared secret or
//! the uniform rejection (all-zero output, spec §3); the exchange is symmetric.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{Error, X25519Public, X25519Secret};

fuzz_target!(|data: &[u8]| {
    let Some((a, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Some((b, u)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let (Ok(sk_a), Ok(sk_b)) = (X25519Secret::from_bytes(a), X25519Secret::from_bytes(b)) else {
        return;
    };
    // arbitrary public key (any 32 bytes, RFC 7748)
    if let Ok(pk) = X25519Public::from_bytes(u.get(..32).unwrap_or(&[0; 32])) {
        match sk_a.diffie_hellman(&pk) {
            Ok(ss) => assert_ne!(ss.expose_secret(), &[0; 32]),
            Err(e) => assert_eq!(e, Error::Rejected),
        }
    }
    // symmetry for honest keys
    let ab = sk_a.diffie_hellman(&sk_b.public_key());
    let ba = sk_b.diffie_hellman(&sk_a.public_key());
    match (ab, ba) {
        (Ok(x), Ok(y)) => assert_eq!(x.expose_secret(), y.expose_secret()),
        (x, y) => assert_eq!(x.is_err(), y.is_err()),
    }
});
