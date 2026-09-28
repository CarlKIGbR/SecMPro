// SPDX-License-Identifier: AGPL-3.0-or-later
//! ML-DSA-65 public-key import and verification on arbitrary bytes: never panics. Mode 0 imports an arbitrary
//! key (length-checked; a key that imports re-encodes to its input); mode 1 verifies an arbitrary signature and
//! context under a fixed honest key (rejected, uniformly).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{Error, MlDsa65SigningKey, MlDsa65VerifyingKey};

fn key() -> Option<&'static MlDsa65VerifyingKey> {
    static KEY: OnceLock<Option<MlDsa65VerifyingKey>> = OnceLock::new();
    KEY.get_or_init(|| MlDsa65SigningKey::from_seed(&[7; 32]).ok().map(|k| k.verifying_key()))
        .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        if let Ok(vk) = MlDsa65VerifyingKey::from_bytes(rest) {
            assert_eq!(vk.as_bytes().as_slice(), rest);
            let r = vk.verify(b"m", b"", &[0; 3309]);
            assert_eq!(r, Err(Error::Rejected));
        }
    } else if let Some(vk) = key() {
        let (ctx_len, rest) = rest.split_first().unwrap_or((&0, &[]));
        let (ctx, sig) = rest.split_at(rest.len().min(usize::from(*ctx_len)));
        assert_eq!(vk.verify(b"fuzz", ctx, sig), Err(Error::Rejected));
    }
});
