// SPDX-License-Identifier: AGPL-3.0-or-later
//! A small deterministic generator for the cases and the activity of the M6 tests (not the timing randomness, not
//! cryptographic).

pub struct Mix(u64);

impl Mix {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value below `bound` (≥ 1).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next().checked_rem(bound).unwrap()
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        let at = self.below(u64::try_from(items.len()).unwrap());
        *items.get(usize::try_from(at).unwrap()).unwrap()
    }

    /// A length 1…65535, log-uniform in the bit length.
    pub fn len(&mut self) -> usize {
        let bits = u32::try_from(self.below(17)).unwrap();
        let top = 1_u64.checked_shl(bits).unwrap().saturating_sub(1).max(1);
        let len = self.below(top).min(65_534).saturating_add(1);
        usize::try_from(len).unwrap()
    }
}
