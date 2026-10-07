// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-06 (M5): the D.2 response decoder on a 4336-byte frame plaintext, under the context of the request it answers
//! (a `CELLR` is checked against it): total, and whatever it accepts is exactly one encoding.
//!
//! Layout: the first byte is the mode: bit 0 selects the request context (0 `FETCH`, 1 `FETCH_MULTI`), bit 1 how the
//! rest becomes the plaintext: 0 as it is (any length: only 4336 bytes can be accepted); 1 cut to 4335 bytes
//! (`op ‖ cmd_seq ‖ fields`) and ISO/IEC 7816-4 padded to 4336 by the harness.
//!
//! Context rule (D.2): a `CELLR` with `present` 1 and a non-zero `rid` is valid only after `FETCH_MULTI`; every other
//! response does not depend on the context.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::Encode;
use secmp_proto::codec::pad;
use secmp_proto::sizes::FRAME_PLAINTEXT_LEN;
use secmp_proto::wire::frame::{Cellr, CellrContext, Response, ResponseCmd};

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let (context, other) = if mode & 1 == 0 {
        (CellrContext::Fetch, CellrContext::FetchMulti)
    } else {
        (CellrContext::FetchMulti, CellrContext::Fetch)
    };
    let plaintext = if mode & 2 == 0 {
        rest.to_vec()
    } else {
        let payload = &rest[..rest.len().min(FRAME_PLAINTEXT_LEN - 1)];
        pad(payload, FRAME_PLAINTEXT_LEN).unwrap().to_vec()
    };
    if let Ok(response) = Response::decode(&plaintext, context) {
        assert_eq!(plaintext.len(), FRAME_PLAINTEXT_LEN);
        assert_eq!(response.encode().unwrap().as_slice(), plaintext.as_slice());
        // the other context accepts exactly the same bytes, except a `Cell` with a non-zero `rid` after `FETCH`
        let fetch_only_multi = matches!(
            &response.cmd,
            ResponseCmd::Cellr(Cellr::Cell { rid, .. }) if *rid != [0; 16]
        );
        let again = Response::decode(&plaintext, other);
        if fetch_only_multi {
            // accepted under FETCH_MULTI only
            assert!(context == CellrContext::FetchMulti);
            assert!(again.is_err());
        } else {
            assert!(again.is_ok());
        }
    }
});
