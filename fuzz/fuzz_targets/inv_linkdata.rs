// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The link data (spec §5.4, §5.5) on arbitrary bytes. The first byte selects the mode (modulo 2):
//!
//! - 0: the rest is an opened `LinkDataV1` plaintext (12288 B padded): the decoder never panics, and whatever it
//!   accepts re-encodes to exactly its input.
//! - 1: the rest is a blob handed to the invitee with the fixture's invitation (`fuzz/common/hx_fixture.rs`):
//!   `invitee_accept` never panics and answers `Ok` or the uniform `Rejected`; `Ok` only for the fixture's own blob.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::inv::invitee_accept;
use secmp_proto::wire::inv::LinkDataV1;
use secmp_proto::{Decode, Encode, Error};

#[path = "../common/hx_fixture.rs"]
mod hx_fixture;

use hx_fixture::{Fixture, NOW};

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        if let Ok(v) = LinkDataV1::decode(rest) {
            assert_eq!(v.encode().unwrap().as_slice(), rest);
        }
    } else {
        let f = Fixture::get();
        match invitee_accept(&f.uri, rest, NOW) {
            Ok(_) => assert_eq!(rest, f.blob.as_slice()),
            Err(e) => assert_eq!(e, Error::Rejected),
        }
    }
});
