// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The plaintext of a handshake cell (spec §6.5, D.4): `init_id ‖ i ‖ total ‖ chunk` (4024 B): the decoder is total
//! (`total` = 3 and `i` ≤ 2 enforced) and canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::hx::HandshakeCellPlaintext;
use secmp_proto::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = HandshakeCellPlaintext::decode(data) {
        assert_eq!(v.encode().unwrap().as_slice(), data);
    }
});
