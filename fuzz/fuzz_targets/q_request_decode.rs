// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-05 (M5): the D.2 request decoder on a 4336-byte frame plaintext: total, and whatever it accepts is exactly one
//! encoding (`encode(decode(x)) == x`, so the padding and every field are canonical).
//!
//! Layout: the first byte selects how the rest becomes the plaintext (modulo 2): 0 the rest as it is (any length:
//! only 4336 bytes can be accepted); 1 the rest cut to 4335 bytes (`op ‖ cmd_seq ‖ fields`) and ISO/IEC 7816-4
//! padded to 4336 by the harness, so that the fuzzer reaches the field decoders without having to produce the
//! padding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::codec::pad;
use secmp_proto::sizes::FRAME_PLAINTEXT_LEN;
use secmp_proto::wire::frame::Request;
use secmp_proto::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let plaintext = if selector % 2 == 0 {
        rest.to_vec()
    } else {
        let payload = &rest[..rest.len().min(FRAME_PLAINTEXT_LEN - 1)];
        pad(payload, FRAME_PLAINTEXT_LEN).unwrap().to_vec()
    };
    if let Ok(request) = Request::decode(&plaintext) {
        assert_eq!(plaintext.len(), FRAME_PLAINTEXT_LEN);
        assert_eq!(request.encode().unwrap().as_slice(), plaintext.as_slice());
    }
});
