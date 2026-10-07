// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-01 (M5): the four SecMP-LINK record decoders (D.1) on arbitrary bytes: they never panic, whatever they accept
//! re-encodes to exactly its input (total, exact-fit, canonical: docs/06 §4), and neither a one-byte truncation nor a
//! one-byte extension of an accepted record is accepted.
//!
//! Layout: the first byte selects the decoder (modulo 4): 0 `HELLO`, 1 `RELAYINFO`, 2 `HS1`, 3 `HS2`; the rest is the
//! record, `len` prefix included.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord};
use secmp_proto::{Decode, Encode};

/// Decode as `T`; an accepted input re-encodes to itself, and no truncation or extension by one byte is accepted.
fn canonical<T: Decode + Encode>(bytes: &[u8]) {
    if let Ok(v) = T::decode(bytes) {
        assert_eq!(v.encode().unwrap().as_slice(), bytes);
        assert!(T::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(T::decode(&[bytes, &[0]].concat()).is_err());
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, bytes)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => canonical::<Hello>(bytes),
        1 => canonical::<RelayInfoRecord>(bytes),
        2 => canonical::<Hs1>(bytes),
        _ => canonical::<Hs2>(bytes),
    }
});
