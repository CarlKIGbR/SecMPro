// SPDX-License-Identifier: AGPL-3.0-or-later
//! The safety number (spec §6.7):
//!
//! ```text
//! iter(fp):  h = fp; repeat 5200 times: h = SHA-256("SecMP-SAS/1" ‖ h ‖ fp); return h
//! half(fp):  6 groups of 5 decimal digits: for k in 0..6: int_be(iter(fp)[5k..5k+5]) mod 100000, zero-padded
//! safety_number = concat(sorted_lexicographically(half(fp_A), half(fp_B)))     ; 60 digits
//! ```
//!
//! Shown as 12 groups of 5. The derivation runs in time independent of the fingerprints: the hash iterations
//! are fixed, the digit conversion uses only multiplications and divisions by constants, and the ascending
//! sort of the two halves is a constant-time comparison followed by a conditional swap.

use core::fmt;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

use crate::fingerprint::Fingerprint;
use crate::hash::sha256;
use crate::label::Label;

/// Digits of a safety number (spec §4.2 `SAS_DIGITS`).
pub const SAS_DIGITS: usize = 60;
/// Digits of one half.
pub const SAS_HALF_DIGITS: usize = 30;
/// Hash iterations of `iter` (spec §6.7).
pub const SAS_ITERATIONS: usize = 5200;

/// `iter(fp)`.
fn iter(fp: &[u8; 32]) -> [u8; 32] {
    let mut h = *fp;
    for _ in 0..SAS_ITERATIONS {
        h = sha256(&[Label::Sas.as_bytes(), &h, fp]);
    }
    h
}

/// `half(fp)` as 30 ASCII digits.
pub(crate) fn half(fp: &Fingerprint) -> [u8; SAS_HALF_DIGITS] {
    let h = iter(fp.as_bytes());
    let mut out = [b'0'; SAS_HALF_DIGITS];
    for (group, digits) in h.as_chunks::<5>().0.iter().zip(out.as_chunks_mut::<5>().0) {
        // int_be(iter(fp)[5k..5k+5])
        let mut be = [0_u8; 8];
        for (d, s) in be.iter_mut().skip(3).zip(group) {
            *d = *s;
        }
        let mut v = u64::from_be_bytes(be);
        // mod 100000, zero-padded to 5 digits: the five least significant decimal digits of v, written most
        // significant first, are exactly `v mod 100000` zero-padded (spec §6.7)
        for d in digits.iter_mut().rev() {
            let digit = u8::try_from(v % 10).unwrap_or(0);
            *d = b'0'.wrapping_add(digit);
            v /= 10;
        }
    }
    out
}

/// `a < b` lexicographically, in constant time (equal-length digit strings).
fn ct_less(a: &[u8; SAS_HALF_DIGITS], b: &[u8; SAS_HALF_DIGITS]) -> Choice {
    let mut decided = Choice::from(0);
    let mut less = Choice::from(0);
    for (x, y) in a.iter().zip(b) {
        less |= !decided & x.ct_lt(y);
        decided |= !x.ct_eq(y);
    }
    less
}

/// A 60-digit safety number.
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber([u8; SAS_DIGITS]);

impl SafetyNumber {
    /// The safety number of two fingerprints (symmetric: the halves are sorted).
    #[must_use]
    pub fn new(fp_a: &Fingerprint, fp_b: &Fingerprint) -> Self {
        let mut lo = half(fp_a);
        let mut hi = half(fp_b);
        // sorted_lexicographically(half(fp_A), half(fp_B)): swap iff hi < lo, in constant time
        let swap = ct_less(&hi, &lo);
        for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
            u8::conditional_swap(x, y, swap);
        }
        let mut out = [0; SAS_DIGITS];
        let (first, second) = out.split_at_mut(SAS_HALF_DIGITS);
        first.copy_from_slice(&lo);
        second.copy_from_slice(&hi);
        Self(out)
    }

    /// The 60 digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// The 12 display groups of 5 digits.
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.0
            .as_chunks::<5>()
            .0
            .iter()
            .map(|g| core::str::from_utf8(g).unwrap_or_default())
    }

    /// `half(fp)` as a digit string, for the `sas` vector suite (feature `kat`).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn half_kat(fp: &Fingerprint) -> String {
        String::from_utf8(half(fp).to_vec()).unwrap_or_default()
    }
}

impl fmt::Debug for SafetyNumber {
    /// Redacted: derived from fingerprints, never logged (docs/04 CS-2.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SafetyNumber(..)")
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;
    use crate::error::Result;

    fn fp(b: u8) -> Result<Fingerprint> {
        Fingerprint::from_bytes(&[b; 32])
    }

    /// `half` recomputed with plain arithmetic from spec §6.7.
    #[test]
    fn half_matches_the_definition() -> Result<()> {
        let f = fp(0xab)?;
        let mut h = [0xab_u8; 32];
        for _ in 0..5200 {
            h = sha256(&[b"SecMP-SAS/1", &h, &[0xab; 32]]);
        }
        let mut expected = String::new();
        for group in h.as_chunks::<5>().0.iter().take(6) {
            let mut be = [0_u8; 8];
            be[3..].copy_from_slice(group);
            let _ = write!(expected, "{:05}", u64::from_be_bytes(be) % 100_000);
        }
        assert_eq!(
            String::from_utf8(half(&f).to_vec()).unwrap_or_default(),
            expected
        );
        Ok(())
    }

    #[test]
    fn symmetric_sorted_and_grouped() -> Result<()> {
        let (a, b) = (fp(1)?, fp(2)?);
        let ab = SafetyNumber::new(&a, &b);
        let ba = SafetyNumber::new(&b, &a);
        assert_eq!(ab, ba);
        assert_eq!(ab.as_str().len(), SAS_DIGITS);
        assert!(ab.as_str().bytes().all(|c| c.is_ascii_digit()));
        let (h1, h2) = ab.as_str().split_at(SAS_HALF_DIGITS);
        assert!(h1 <= h2, "ascending");
        let mut halves = [half(&a), half(&b)];
        halves.sort_unstable();
        let expected: Vec<u8> = halves.concat();
        assert_eq!(ab.as_str().as_bytes(), expected.as_slice());
        let groups: Vec<&str> = ab.groups().collect();
        assert_eq!(groups.len(), 12);
        assert!(groups.iter().all(|g| g.len() == 5));
        assert_eq!(groups.concat(), ab.as_str());
        // equal fingerprints: the same half twice
        let aa = SafetyNumber::new(&a, &a);
        let (x, y) = aa.as_str().split_at(SAS_HALF_DIGITS);
        assert_eq!(x, y);
        assert_eq!(format!("{aa:?}"), "SafetyNumber(..)");
        Ok(())
    }

    #[test]
    fn constant_time_order() {
        let mut a = [b'0'; SAS_HALF_DIGITS];
        let b = a;
        assert!(!bool::from(ct_less(&a, &b)));
        a[29] = b'1';
        assert!(bool::from(ct_less(&b, &a)));
        assert!(!bool::from(ct_less(&a, &b)));
        let mut c = [b'9'; SAS_HALF_DIGITS];
        c[0] = b'0';
        let mut d = [b'0'; SAS_HALF_DIGITS];
        d[0] = b'1';
        assert!(bool::from(ct_less(&c, &d)), "first difference decides");
        assert!(!bool::from(ct_less(&d, &c)));
    }
}
