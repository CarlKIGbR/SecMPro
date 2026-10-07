// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The invitation URI (spec §5.2) on arbitrary text: never panic, and whatever parses re-encodes to exactly its
//! input — the text is canonical (the exact `secmp://i/` prefix, URL-safe alphabet, no padding, zero unused low
//! bits; SPEC-QUESTIONS reading 4). The base64url decoder alone is held to the same rule. Input bytes that are not
//! UTF-8 are not a string and are skipped.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::inv::{base64url_decode, base64url_encode, invitation_uri, parse_invitation_uri};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(invitation) = parse_invitation_uri(text) {
        assert_eq!(invitation_uri(&invitation).unwrap().as_str(), text);
    }
    if let Ok(bytes) = base64url_decode(text) {
        assert_eq!(base64url_encode(&bytes).as_str(), text);
    }
});
