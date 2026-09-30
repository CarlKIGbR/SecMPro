// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The D.2 frame-plaintext decoders of `secmp-proto` on arbitrary bytes: never panic, and whatever they accept
//! re-encodes to exactly its input (total, exact-fit, canonical: docs/06 §4). The first byte selects the decoder:
//! 0 request, 1 response in answer to `FETCH`, 2 response in answer to `FETCH_MULTI` (modulo 3).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::frame::{CellrContext, Request, Response};
use secmp_proto::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    let Some((selector, bytes)) = data.split_first() else {
        return;
    };
    let context = match selector % 3 {
        0 => {
            if let Ok(r) = Request::decode(bytes) {
                assert_eq!(r.encode().unwrap().as_slice(), bytes);
            }
            return;
        }
        1 => CellrContext::Fetch,
        _ => CellrContext::FetchMulti,
    };
    if let Ok(r) = Response::decode(bytes, context) {
        assert_eq!(r.encode().unwrap().as_slice(), bytes);
    }
});
