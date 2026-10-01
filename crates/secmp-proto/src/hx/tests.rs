// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Unit tests of the SecMP-HX helpers.

use super::*;

/// u = 0, 1, p − 1 and the two points of order 8 (RFC 7748 §6.1; spec §3, §4.1 (a)).
fn low_order() -> Vec<[u8; 32]> {
    let mut one = [0_u8; 32];
    one[0] = 1;
    let mut p_minus_1 = [0xff_u8; 32];
    p_minus_1[0] = 0xec;
    p_minus_1[31] = 0x7f;
    let order8_a: [u8; 32] = [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ];
    let order8_b: [u8; 32] = [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ];
    // non-canonical encodings of 0 and 1: p, p + 1, and 0 with bit 255 set (RFC 7748 §5)
    let mut p = p_minus_1;
    p[0] = 0xed;
    let mut p_plus_1 = p_minus_1;
    p_plus_1[0] = 0xee;
    let mut zero_top = [0_u8; 32];
    zero_top[31] = 0x80;
    vec![
        [0; 32], one, p_minus_1, order8_a, order8_b, p, p_plus_1, zero_top,
    ]
}

/// N-24: the initiator's DH helper (DH1…DH4 of §6.4) refuses an all-zero output, bypassing the decoders; the
/// error is the uniform one and `start` has produced nothing (it returns before any cell is sealed).
#[test]
fn start_zero_dh_rejects_and_sends_nothing() {
    let secret = X25519Secret::from_bytes(&[7; 32]).unwrap();
    for v in low_order() {
        assert_eq!(dh_checked(&secret, &v).err(), Some(Error::Rejected));
    }
    assert!(
        dh_checked(&secret, &[9; 32]).is_ok(),
        "control: an ordinary point"
    );
    assert_eq!(
        dh_checked(&secret, &[9; 31]).err(),
        Some(Error::Rejected),
        "length"
    );
}

/// N-41: the same helper on the responder's DH1…DH4.
#[test]
fn accept_zero_dh_rejects_and_keeps_opk() {
    let secret = X25519Secret::from_bytes(&[0x42; 32]).unwrap();
    for v in low_order() {
        assert_eq!(dh_checked(&secret, &v).err(), Some(Error::Rejected));
    }
}
