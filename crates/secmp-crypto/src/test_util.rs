// SPDX-License-Identifier: AGPL-3.0-or-later
//! Helpers for the unit tests of this crate.

use core::fmt::Write as _;

/// Lowercase hex.
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Decode lowercase or uppercase hex; `None` on odd length or a non-hex digit.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            let t = core::str::from_utf8(p).ok()?;
            u8::from_str_radix(t, 16).ok()
        })
        .collect()
}

/// Decode a hex constant of exactly `N` bytes (test data; a malformed constant yields zeros and fails the
/// test's comparisons).
pub(crate) fn unhex_n<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0; N];
    if let Some(v) = unhex(s)
        && v.len() == N
    {
        out.copy_from_slice(&v);
    }
    out
}

#[test]
fn hex_round_trip() {
    assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    assert_eq!(unhex("00abFF"), Some(vec![0x00, 0xab, 0xff]));
    assert_eq!(unhex("0"), None);
    assert_eq!(unhex("zz"), None);
    assert_eq!(unhex_n::<2>("0102"), [1, 2]);
    assert_eq!(unhex_n::<2>("01"), [0, 0]);
}
