// SPDX-License-Identifier: AGPL-3.0-or-later
//! HybridSign (spec §3.5) on arbitrary bytes: never panics. Mode 0 imports an arbitrary verifying key
//! `ik_ed25519 (32) ‖ ik_mldsa65 (rest)`; mode 1 verifies an arbitrary signature, label and message under a fixed
//! honest key (always rejected; labels other than the two HybridSign labels are refused); mode 2 signs the input
//! with the fixed key and checks that the signature verifies and that any single-byte change is rejected.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{Error, HYBRID_SIG_LEN, HybridSignature, HybridSigningKey, HybridVerifyingKey, Label};

fn key() -> Option<&'static (HybridSigningKey, HybridVerifyingKey)> {
    static KEY: OnceLock<Option<(HybridSigningKey, HybridVerifyingKey)>> = OnceLock::new();
    KEY.get_or_init(|| {
        let sk = HybridSigningKey::from_seeds(&[1; 32], &[2; 32]).ok()?;
        let vk = sk.verifying_key();
        Some((sk, vk))
    })
    .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Some((label_byte, rest)) = rest.split_first() else {
        return;
    };
    let label = Label::ALL.get(usize::from(*label_byte) % Label::ALL.len()).copied().unwrap_or(Label::HxBundle);
    match mode % 3 {
        0 => {
            let (ed, mldsa) = rest.split_at(rest.len().min(32));
            if let Ok(vk) = HybridVerifyingKey::from_bytes(ed, mldsa) {
                assert_eq!(vk.ed25519().as_slice(), ed);
                assert_eq!(vk.mldsa65().as_slice(), mldsa);
            }
        }
        1 => {
            let Some((_, vk)) = key() else { return };
            let (sig, msg) = rest.split_at(rest.len().min(HYBRID_SIG_LEN));
            match HybridSignature::from_bytes(sig) {
                Ok(sig) => assert_eq!(vk.verify(label, msg, &sig), Err(Error::Rejected)),
                Err(e) => assert_eq!(e, Error::Rejected),
            }
        }
        _ => {
            let Some((sk, vk)) = key() else { return };
            match sk.sign(label, rest) {
                Ok(sig) => {
                    assert!(label.is_hybrid_sign_label());
                    assert!(vk.verify(label, rest, &sig).is_ok());
                    let mut bad = *sig.as_bytes();
                    let i = usize::from(*label_byte).wrapping_mul(13) % HYBRID_SIG_LEN;
                    if let Some(b) = bad.get_mut(i) {
                        *b ^= 0x40;
                    }
                    if let Ok(bad) = HybridSignature::from_bytes(&bad) {
                        assert_eq!(vk.verify(label, rest, &bad), Err(Error::Rejected));
                    }
                }
                Err(e) => {
                    assert!(!label.is_hybrid_sign_label());
                    assert_eq!(e, Error::Rejected);
                }
            }
        }
    }
});
