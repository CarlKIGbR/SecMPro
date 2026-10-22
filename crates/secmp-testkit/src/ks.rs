// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The analyser of the real-time activity-independence run (TEST-SPEC-M6 AI-07, AI-10): a two-sample
//! Kolmogorov–Smirnov test on the inter-departure times of the C2R frames of each scheduled link, an idle hour against an
//! active hour, per link and pooled.
//!
//! `D` is the largest distance between the two empirical distribution functions; the p-value is the asymptotic one,
//! `Q(λ)` with `λ = (√nₑ + 0.12 + 0.11/√nₑ)·D`, `nₑ = n₁n₂/(n₁+n₂)`. The times are whole milliseconds, so the samples are
//! discrete with many ties; for discrete data the asymptotic p-value is conservative (larger than the exact one), which
//! favours "no dependence" — AI-10 is the control that the tool still sees a shift of one millisecond at the row's `n`
//! when the jitter of the timer is at most a few milliseconds wide.

use std::collections::BTreeMap;

/// The result of one test.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Ks {
    /// The largest distance of the two distribution functions.
    pub d: f64,
    /// The asymptotic p-value.
    pub p: f64,
    /// The size of the first sample.
    pub n1: usize,
    /// The size of the second sample.
    pub n2: usize,
}

fn count(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// `Q(λ) = 2 Σ_{j≥1} (−1)^{j−1} e^{−2j²λ²}`: the tail of the Kolmogorov distribution.
fn q_ks(lambda: f64) -> f64 {
    let a = -2.0 * lambda * lambda;
    let (mut sum, mut sign, mut last) = (0.0_f64, 1.0_f64, 0.0_f64);
    for j in 1..=100_u32 {
        let jf = f64::from(j);
        let term = sign * 2.0 * (a * jf * jf).exp();
        sum += term;
        if term.abs() <= 1e-10 * sum.abs() || term.abs() <= 1e-12 {
            return sum.clamp(0.0, 1.0);
        }
        sign = -sign;
        last = term;
    }
    // no convergence: λ is small, the distributions are not distinguished
    let _ = last;
    1.0
}

/// The two-sample test of `first` against `second`; `None` if either sample is empty.
#[must_use]
pub fn two_sample(first: &[u64], second: &[u64]) -> Option<Ks> {
    if first.is_empty() || second.is_empty() {
        return None;
    }
    let (mut xs, mut ys) = (first.to_vec(), second.to_vec());
    xs.sort_unstable();
    ys.sort_unstable();
    let (n1, n2) = (count(xs.len()), count(ys.len()));
    let (mut ix, mut iy) = (0_usize, 0_usize);
    let mut dist = 0.0_f64;
    while let (Some(x), Some(y)) = (xs.get(ix), ys.get(iy)) {
        let at = *x.min(y);
        while xs.get(ix).is_some_and(|t| *t <= at) {
            ix = ix.saturating_add(1);
        }
        while ys.get(iy).is_some_and(|t| *t <= at) {
            iy = iy.saturating_add(1);
        }
        dist = dist.max((count(ix) / n1 - count(iy) / n2).abs());
    }
    let ne = n1 * n2 / (n1 + n2);
    let en = ne.sqrt();
    let p = q_ks((en + 0.12 + 0.11 / en) * dist);
    Some(Ks {
        d: dist,
        p,
        n1: xs.len(),
        n2: ys.len(),
    })
}

/// One frame the client wrote: when (ms), on which link, how long.
pub type Frame = (u64, u64, usize);

/// The verdict of a run.
#[derive(Debug)]
pub struct Report {
    /// Per scheduled link: its slot and the test of its idle gaps against its active gaps.
    pub per_link: Vec<(u64, Ks)>,
    /// All links pooled.
    pub pooled: Ks,
    /// Every unit of a scheduled link has the length of a frame (4 352 B).
    pub all_frames_full: bool,
}

/// The frame length of the link layer (spec §8.4).
pub const FRAME: usize = 4_352;

/// Frames closer than this belong to one departure: a combined link (direct mode implies Balanced, spec §10.2) writes the
/// requests of one slot back to back.
pub const SAME_SLOT_MS: u64 = 100;

/// The scheduled links' gaps: for each slot with at least `min_frames` frames of [`FRAME`] bytes, the gaps between
/// consecutive departures (frames less than [`SAME_SLOT_MS`] apart are one departure) that end at or before `split`
/// (idle) and the gaps that start at or after it (active). A gap that spans `split` is in neither.
#[must_use]
pub fn gaps(
    frames: &[Frame],
    split: u64,
    min_frames: usize,
) -> BTreeMap<u64, (Vec<u64>, Vec<u64>)> {
    let mut by_slot: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (t, slot, len) in frames {
        if *len == FRAME {
            by_slot.entry(*slot).or_default().push(*t);
        }
    }
    let mut out = BTreeMap::new();
    for (slot, mut times) in by_slot {
        if times.len() < min_frames {
            continue;
        }
        times.sort_unstable();
        let mut departures: Vec<u64> = Vec::new();
        for t in &times {
            if departures
                .last()
                .is_none_or(|last| t.saturating_sub(*last) >= SAME_SLOT_MS)
            {
                departures.push(*t);
            }
        }
        let times = departures;
        let (mut idle, mut active) = (Vec::new(), Vec::new());
        for pair in times.windows(2) {
            let [from, to] = pair else { continue };
            if *to <= split {
                idle.push(to.saturating_sub(*from));
            } else if *from >= split {
                active.push(to.saturating_sub(*from));
            }
        }
        out.insert(slot, (idle, active));
    }
    out
}

/// The test of every scheduled link and of all pooled.
#[must_use]
pub fn analyse(frames: &[Frame], split: u64, min_frames: usize) -> Option<Report> {
    let per = gaps(frames, split, min_frames);
    let (mut all_idle, mut all_active) = (Vec::new(), Vec::new());
    let mut per_link = Vec::new();
    for (slot, (idle, active)) in &per {
        per_link.push((*slot, two_sample(idle, active)?));
        all_idle.extend_from_slice(idle);
        all_active.extend_from_slice(active);
    }
    let pooled = two_sample(&all_idle, &all_active)?;
    // a unit of a scheduled link that is not a frame: handshake records are the first two units of each direction and are
    // not counted here; anything else of another length on a link with frames is a finding
    let scheduled: Vec<u64> = per.keys().copied().collect();
    let all_frames_full = frames
        .iter()
        .filter(|(_, slot, _)| scheduled.contains(slot))
        .all(|(_, _, len)| *len == FRAME || [9, 2_856].contains(len));
    Some(Report {
        per_link,
        pooled,
        all_frames_full,
    })
}

/// The text of the evidence file: one line per link and one pooled, `D`, `p`, `n` of each sample.
#[must_use]
pub fn evidence(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (slot, k) in &report.per_link {
        let _ = writeln!(
            s,
            "link {slot}: D = {:.6}, p = {:.6}, n_idle = {}, n_active = {}",
            k.d, k.p, k.n1, k.n2
        );
    }
    let k = report.pooled;
    let _ = writeln!(
        s,
        "pooled: D = {:.6}, p = {:.6}, n_idle = {}, n_active = {}",
        k.d, k.p, k.n1, k.n2
    );
    let _ = writeln!(s, "all units 4352 B: {}", report.all_frames_full);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seeded stream (xorshift64*), not cryptographic.
    struct Mix(u64);

    impl Mix {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    /// The synthetic trace: `links` links of `n` idle and `n` active gaps (`P` = 10 s plus a jitter of 0…2 ms), the active
    /// gaps `shift` ms shorter; as frames of one run whose active hour starts at `split`.
    fn trace(links: u64, n: usize, shift: u64, seed: u64) -> (Vec<Frame>, u64) {
        let mut mix = Mix(seed | 1);
        let split = 3_600_000_u64;
        let mut frames = Vec::new();
        for slot in 0..links {
            let mut t = 0_u64;
            frames.push((t, slot, FRAME));
            while t < split.saturating_mul(2) {
                let jitter = mix.next() % 3;
                let gap = 10_000_u64
                    .saturating_add(jitter)
                    .saturating_sub(if t >= split { shift } else { 0 });
                t = t.saturating_add(gap);
                frames.push((t, slot, FRAME));
            }
            let _ = n;
        }
        (frames, split)
    }

    /// AI-10 `ks_tool_detects_planted_dependence` (control): the analyser of AI-07 on a synthetic trace whose gaps shrink
    /// by 1 ms while "active" finds `p < 0.01` per link and pooled at the n of the real run (≈ 360 gaps per link and
    /// hour, 4 links pooled), with a timer jitter of 0…2 ms.
    #[test]
    fn ks_tool_detects_planted_dependence() {
        let (frames, split) = trace(4, 360, 1, 7);
        let r = analyse(&frames, split, 100).unwrap();
        assert_eq!(r.per_link.len(), 4);
        assert!(r.pooled.n1 >= 1_400, "{}", r.pooled.n1);
        for (slot, k) in &r.per_link {
            assert!(k.p < 0.01, "link {slot}: D = {}, p = {}", k.d, k.p);
        }
        assert!(
            r.pooled.p < 0.01,
            "pooled D = {}, p = {}",
            r.pooled.d,
            r.pooled.p
        );
    }

    /// The other half of the control: with no shift the same analyser does not flag any link (p ≥ 0.01) — over many seeds
    /// the false-positive rate of the per-link test stays near 1 %.
    #[test]
    fn ks_tool_accepts_equal_distributions() {
        let mut flagged = 0_usize;
        let mut tests = 0_usize;
        for seed in 1..=50 {
            let (frames, split) = trace(4, 360, 0, seed);
            let r = analyse(&frames, split, 100).unwrap();
            for (_, k) in &r.per_link {
                tests += 1;
                if k.p < 0.01 {
                    flagged += 1;
                }
            }
            assert!(r.pooled.p > 1e-4, "seed {seed}: pooled p = {}", r.pooled.p);
        }
        assert!(flagged * 20 <= tests, "{flagged} of {tests} links flagged");
    }

    #[test]
    fn two_sample_known_values() {
        // identical samples: D = 0, p = 1
        let a: Vec<u64> = (0..100).collect();
        let k = two_sample(&a, &a).unwrap();
        assert!(k.d.abs() < 1e-12 && (k.p - 1.0).abs() < 1e-9);
        // disjoint samples: D = 1, p ≈ 0
        let b: Vec<u64> = (1_000..1_100).collect();
        let k = two_sample(&a, &b).unwrap();
        assert!((k.d - 1.0).abs() < 1e-12 && k.p < 1e-10, "{k:?}");
        // Q(1.36) ≈ 0.049 (the 5 % point of the Kolmogorov distribution)
        assert!((q_ks(1.36) - 0.0493).abs() < 0.001, "{}", q_ks(1.36));
        assert!(two_sample(&[], &a).is_none());
    }

    #[test]
    fn frames_of_one_slot_are_one_departure() {
        // a combined link: two frames 1 ms apart every 10 s
        let frames: Vec<Frame> = (0..300_u64)
            .flat_map(|k| [(k * 10_000, 0, FRAME), (k * 10_000 + 1, 0, FRAME)])
            .collect();
        let g = gaps(&frames, 1_500_000, 100);
        let (idle, active) = g.get(&0).unwrap();
        assert!(idle.iter().chain(active).all(|d| *d == 10_000), "{idle:?}");
        assert_eq!((idle.len(), active.len()), (150, 149));
    }

    #[test]
    fn a_gap_that_spans_the_split_is_in_neither_sample() {
        let frames: Vec<Frame> = [0, 10, 20, 35, 45, 55]
            .iter()
            .map(|t| (*t * 1_000, 0, FRAME))
            .collect();
        let g = gaps(&frames, 30_000, 1);
        let (idle, active) = g.get(&0).unwrap();
        assert_eq!(
            (idle.clone(), active.clone()),
            (vec![10_000, 10_000], vec![10_000, 10_000])
        );
    }
}
