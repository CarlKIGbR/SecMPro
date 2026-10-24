// SPDX-License-Identifier: AGPL-3.0-or-later
//! The SPKI pin check of direct mode (`secmp_transport::tls::check_pin`, the decision of its `PinVerifier`; TEST-SPEC-M6
//! FZ-02): an arbitrary end-entity DER and an arbitrary number of intermediates never panic, and the check passes only
//! for exactly one certificate of at most `CERT_MAX` bytes whose `SubjectPublicKeyInfo` hashes to the pin. The harness
//! pins the hash of the input's SPKI when it parses, so the passing path is reached.
//!
//! Input: `n ‖ cert` — `n % 4` intermediates, then the end-entity DER.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_transport::tls::{CERT_MAX, check_pin, spki_of};

fuzz_target!(|data: &[u8]| {
    let Some((n, cert)) = data.split_first() else {
        return;
    };
    let intermediates = usize::from(*n % 4);
    let spki = spki_of(cert);
    // a parsed SPKI is a DER element inside the input
    if let Some(s) = spki {
        assert!(!s.is_empty() && s.len() <= cert.len());
        assert_eq!(s.first(), Some(&0x30));
    }
    let pin = spki.map_or([0x5a; 32], |s| secmp_crypto::sha256(&[s]));
    let verdict = check_pin(cert, intermediates, &pin);
    // EXTB-7: a certificate over `CERT_MAX` is refused whatever its SPKI (FZ-02's `-max_len` keeps inputs at the bound)
    assert_eq!(
        verdict.is_ok(),
        intermediates == 0 && spki.is_some() && cert.len() <= CERT_MAX
    );
    // any other pin is refused
    let mut other = pin;
    if let Some(b) = other.first_mut() {
        *b ^= 1;
    }
    assert!(check_pin(cert, intermediates, &other).is_err());
});
