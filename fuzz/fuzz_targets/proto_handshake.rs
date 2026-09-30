// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The D.4 handshake-envelope decoders of `secmp-proto` on arbitrary bytes: never panic, and whatever they accept
//! re-encodes to exactly its input (total, exact-fit, canonical: docs/06 §4). The first byte selects the decoder:
//! 0 `Outer`, 1 `inner_ct`, 2 `Inner`, 3 `HandshakeCell`, 4 `HandshakeCellPlaintext` (modulo 5).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::hx::{HandshakeCell, HandshakeCellPlaintext, Inner, InnerCt, Outer};
use secmp_proto::{Decode, Encode};

/// Decode as `T`; an accepted input re-encodes to itself.
fn canonical<T: Decode + Encode>(bytes: &[u8]) {
    if let Ok(v) = T::decode(bytes) {
        assert_eq!(v.encode().unwrap().as_slice(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, bytes)) = data.split_first() else {
        return;
    };
    match selector % 5 {
        0 => canonical::<Outer>(bytes),
        1 => canonical::<InnerCt>(bytes),
        2 => canonical::<Inner>(bytes),
        3 => canonical::<HandshakeCell>(bytes),
        _ => canonical::<HandshakeCellPlaintext>(bytes),
    }
});
