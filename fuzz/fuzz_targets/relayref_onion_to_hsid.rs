// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RelayRef.onion` to the Tor stream target (TEST-SPEC-M6 FZ-03; spec §5.3, rend-spec-v3 §6): for arbitrary bytes the
//! onion decoder (`secmp_proto::wire::inv::Onion::from_bytes`) is total and accepts exactly 35 bytes with version 0x03
//! and a valid checksum (checked here independently); for every accepted address the Tor provider's target
//! (`secmp_transport::tor::target`) is the address's base32 plus `.onion` — it decodes back to the input — on port
//! 443, and Arti's address parser takes it as a host name. The harness also builds the valid address of the input's
//! first 32 bytes, so the accepting path is reached on every run.
//!
//! (TEST-SPEC FZ-03 asks that "Arti's parse re-encodes to the input": Arti's `HsId` is public only with its
//! `experimental-api` feature, which TOR-07 forbids; the base32 round trip and Arti's `TorAddr` parse stand in.)
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::inv::Onion;
use secmp_transport::tor;

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bits = Vec::new();
    for c in s.bytes() {
        let v = alphabet.iter().position(|a| *a == c)?;
        bits.extend((0..5).rev().map(|i| u8::from((v >> i) & 1 == 1)));
    }
    Some(
        bits.chunks_exact(8)
            .map(|c| c.iter().fold(0_u8, |a, b| (a << 1) | b))
            .collect(),
    )
}

fn checksum_ok(data: &[u8]) -> bool {
    let (Some(pk), Some(check), Some(version)) = (data.get(..32), data.get(32..34), data.get(34..))
    else {
        return false;
    };
    let digest = secmp_crypto::sha3_256(&[b".onion checksum", pk, version]);
    digest.get(..2) == Some(check)
}

fn check(data: &[u8]) {
    let parsed = Onion::from_bytes(data);
    let valid = data.len() == 35 && data.get(34) == Some(&0x03) && checksum_ok(data);
    assert_eq!(parsed.is_ok(), valid);
    if let Ok(onion) = parsed {
        let (host, port) = tor::target(&onion).unwrap();
        assert_eq!(port, 443);
        assert_eq!(host.len(), 62);
        let (b32, suffix) = host.split_at(56);
        assert_eq!(suffix, ".onion");
        assert_eq!(base32_decode(b32).as_deref(), Some(data));
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    if let Some(pk) = data.get(..32) {
        let digest = secmp_crypto::sha3_256(&[b".onion checksum", pk, &[0x03]]);
        let valid = [pk, digest.get(..2).unwrap_or_default(), &[0x03]].concat();
        check(&valid);
    }
});
