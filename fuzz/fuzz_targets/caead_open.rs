// SPDX-License-Identifier: AGPL-3.0-or-later
//! `CAEAD` (spec §3.4) on arbitrary bytes: never panics. Mode 0 opens an arbitrary nonce, `AD` and `COM ‖ C`
//! under a fixed key (always rejected, uniformly); mode 1 seals the input, opens it again, and checks that a
//! single-byte change anywhere is rejected.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{Caead, Error, Nonce24, SecretBytes};

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Some((nonce, rest)) = rest.split_first_chunk::<24>() else {
        return;
    };
    let Some((ad_len, rest)) = rest.split_first() else {
        return;
    };
    let (ad, body) = rest.split_at(rest.len().min(usize::from(*ad_len)));
    let Ok(k) = SecretBytes::<32>::from_slice(&[0x44; 32]) else {
        return;
    };
    if mode & 1 == 0 {
        assert_eq!(Caead::open(&k, nonce, ad, body).err(), Some(Error::Rejected));
        return;
    }
    let Ok(n) = Nonce24::random() else {
        return;
    };
    let nb = *n.as_bytes();
    let Ok(sealed) = Caead::seal(&k, n, ad, body) else {
        return;
    };
    let opened = Caead::open(&k, &nb, ad, &sealed);
    assert_eq!(opened.map(|o| o.as_slice() == body).ok(), Some(true));
    let i = usize::from(*ad_len).wrapping_mul(11) % sealed.len();
    let mut bad = sealed.clone();
    if let Some(b) = bad.get_mut(i) {
        *b ^= 1;
    }
    assert_eq!(Caead::open(&k, &nb, ad, &bad).err(), Some(Error::Rejected));
});
