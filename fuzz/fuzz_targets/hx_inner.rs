// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The handshake `Inner` (spec §6.5, D.4): `IKSPublic ‖ first_msg` (6113 B): the decoder is total and canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::hx::Inner;
use secmp_proto::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = Inner::decode(data) {
        assert_eq!(v.encode().unwrap().as_slice(), data);
    }
});
