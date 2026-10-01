// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The SecMP-TR persistence decoders on arbitrary bytes (M3 plan D5, D7): never panic, reject with the uniform
//! `Rejected` (a malformed encoding never yields `Unavailable`, plan D1), and whatever they accept re-encodes to
//! exactly its input (total, canonical: one encoding per state). The first byte selects the decoder (modulo 2):
//! 0 `RatchetState::from_bytes` (`RatchetStateV1`), 1 `Inbox::from_bytes` (`InboxV1`, the fragments in reassembly).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::Error;
use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::Inbox;

fuzz_target!(|data: &[u8]| {
    let Some((selector, bytes)) = data.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        match RatchetState::from_bytes(bytes) {
            Ok(state) => assert_eq!(state.to_bytes().unwrap().as_slice(), bytes),
            Err(e) => assert_eq!(e, Error::Rejected),
        }
    } else {
        match Inbox::from_bytes(bytes) {
            Ok(inbox) => assert_eq!(inbox.to_bytes().unwrap().as_slice(), bytes),
            Err(e) => assert_eq!(e, Error::Rejected),
        }
    }
});
