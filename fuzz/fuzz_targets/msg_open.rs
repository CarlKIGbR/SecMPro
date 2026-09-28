// SPDX-License-Identifier: AGPL-3.0-or-later
//! `MsgEncrypt` (spec §3.3) on arbitrary bytes: never panics. Mode 0 opens arbitrary `AD` and `C ‖ TAG` under a
//! fixed message key (always rejected, uniformly, whatever the length); mode 1 seals a body taken from the input,
//! opens it again, and checks that a single-byte change anywhere is rejected.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{BODY_LEN, Error, MSG_SEALED_LEN, MsgEncrypt, SecretBytes};

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Some((ad_len, rest)) = rest.split_first() else {
        return;
    };
    let (ad, body) = rest.split_at(rest.len().min(usize::from(*ad_len)));
    let Ok(mk) = SecretBytes::<32>::from_slice(&[0x33; 32]) else {
        return;
    };
    if mode & 1 == 0 {
        assert_eq!(MsgEncrypt::open(&mk, ad, body).err(), Some(Error::Rejected));
        return;
    }
    let Some(p) = body.get(..BODY_LEN) else {
        let Ok(k) = SecretBytes::<32>::from_slice(&[0x33; 32]) else { return };
        assert_eq!(MsgEncrypt::seal(k, ad, body).err(), Some(Error::Rejected));
        return;
    };
    let Ok(k) = SecretBytes::<32>::from_slice(&[0x33; 32]) else {
        return;
    };
    let Ok(sealed) = MsgEncrypt::seal(k, ad, p) else {
        return;
    };
    assert_eq!(sealed.len(), MSG_SEALED_LEN);
    let opened = MsgEncrypt::open(&mk, ad, &sealed);
    assert_eq!(opened.map(|o| *o.expose_secret() == *p).ok(), Some(true));
    let i = usize::from(*ad_len).wrapping_mul(7) % MSG_SEALED_LEN;
    let mut bad = sealed.clone();
    if let Some(b) = bad.get_mut(i) {
        *b ^= 1;
    }
    assert_eq!(MsgEncrypt::open(&mk, ad, &bad).err(), Some(Error::Rejected));
});
