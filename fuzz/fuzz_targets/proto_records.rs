// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The D.1 record decoders of `secmp-proto` on arbitrary bytes: never panic, and whatever they accept re-encodes
//! to exactly its input (total, exact-fit, canonical: docs/06 §4). The first byte selects the decoder:
//! 0 `HELLO`, 1 `RELAYINFO`, 2 `HS1`, 3 `HS2`, 4 `RelayInfoV1` (modulo 5).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord, RelayInfoV1};
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
        0 => canonical::<Hello>(bytes),
        1 => canonical::<RelayInfoRecord>(bytes),
        2 => canonical::<Hs1>(bytes),
        3 => canonical::<Hs2>(bytes),
        _ => canonical::<RelayInfoV1>(bytes),
    }
});
