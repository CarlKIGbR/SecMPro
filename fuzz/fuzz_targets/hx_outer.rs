// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The padded handshake `Outer` (spec §6.5, D.4; 12018 B): the ISO/IEC 7816-4 unpadding and the decoder are total,
//! and whatever they accept re-encodes to exactly its input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::hx::Outer;
use secmp_proto::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = Outer::decode(data) {
        assert_eq!(v.encode().unwrap().as_slice(), data);
    }
});
