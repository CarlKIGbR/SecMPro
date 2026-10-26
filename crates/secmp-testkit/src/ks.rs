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
    /// Per scheduled link: the test of the number of frames per departure, idle against active.
    pub counts_per_link: Vec<(u64, Ks)>,
    /// All links pooled, the number of frames per departure.
    pub counts_pooled: Ks,
    /// The smallest and the largest number of frames in one departure, over every scheduled slot (the short connections
    /// below `min_frames` included, FIN5b-2) and both hours.
    pub frames_per_departure: (u64, u64),
    /// The same per scheduled link: `(slot, (min, max))`.
    pub frames_per_departure_per_link: Vec<(u64, (u64, u64))>,
    /// Every unit of a scheduled link is a frame of 4 352 B, except the handshake records at the start of a connection (a
    /// 9 B first unit, a 2 856 B first or second unit).
    pub all_frames_full: bool,
    /// The number of scheduled slots whose shape (unit length, frames per departure) was checked.
    pub slots_checked: usize,
    /// How many of them have fewer than `min_frames` frames and so enter no KS sample.
    pub slots_below_min: usize,
}

impl Report {
    /// The number of frames every departure of every link carries in both hours, if it is one number (min == max).
    #[must_use]
    pub const fn constant_frames_per_departure(&self) -> Option<u64> {
        if self.frames_per_departure.0 == self.frames_per_departure.1 {
            Some(self.frames_per_departure.0)
        } else {
            None
        }
    }
}

/// The frame length of the link layer (spec §8.4).
pub const FRAME: usize = 4_352;

/// Frames closer than this belong to one departure: a combined link (direct mode implies Balanced, spec §10.2) writes the
/// requests of one slot back to back. The merge is not blind: [`Report::frames_per_departure`] counts the frames of every
/// departure, so an extra frame inside a slot is a finding (min ≠ max), not a hidden detail.
pub const SAME_SLOT_MS: u64 = 100;

/// The samples of one link.
#[derive(Clone, Debug, Default)]
pub struct Samples {
    /// The gaps between consecutive departures that end at or before the split.
    pub idle: Vec<u64>,
    /// The gaps that start at or after the split.
    pub active: Vec<u64>,
    /// The number of frames of each departure before the split.
    pub idle_counts: Vec<u64>,
    /// The number of frames of each departure from the split on.
    pub active_counts: Vec<u64>,
}

/// The departures of one slot: `(time of the first frame, frames)`, frames less than [`SAME_SLOT_MS`] apart being one.
fn departures_of(times: &mut [u64]) -> Vec<(u64, u64)> {
    times.sort_unstable();
    let mut departures: Vec<(u64, u64)> = Vec::new();
    let mut last_frame = 0_u64;
    for t in times.iter() {
        match departures.last_mut() {
            Some(d) if t.saturating_sub(last_frame) < SAME_SLOT_MS => {
                d.1 = d.1.saturating_add(1);
            }
            _ => departures.push((*t, 1)),
        }
        last_frame = *t;
    }
    departures
}

/// Every scheduled slot — one with at least one frame of [`FRAME`] bytes, however few — and its frame times. The KS
/// samples ([`gaps`]) need `min_frames` of them; the shape checks (unit length, frames per departure) do not (FIN5b-2).
fn scheduled_slots(frames: &[Frame]) -> BTreeMap<u64, Vec<u64>> {
    let mut by_slot: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (t, slot, len) in frames {
        if *len == FRAME {
            by_slot.entry(*slot).or_default().push(*t);
        }
    }
    by_slot
}

/// The scheduled links' samples: for each slot with at least `min_frames` frames of [`FRAME`] bytes, the gaps between
/// consecutive departures (frames less than [`SAME_SLOT_MS`] apart are one departure) that end at or before `split`
/// (idle) and the gaps that start at or after it (active) — a gap that spans `split` is in neither — and the number of
/// frames of every departure.
#[must_use]
pub fn gaps(frames: &[Frame], split: u64, min_frames: usize) -> BTreeMap<u64, Samples> {
    let mut out = BTreeMap::new();
    for (slot, mut times) in scheduled_slots(frames) {
        if times.len() < min_frames {
            continue;
        }
        let departures = departures_of(&mut times);
        let mut samples = Samples::default();
        for (at, count) in &departures {
            if *at < split {
                samples.idle_counts.push(*count);
            } else {
                samples.active_counts.push(*count);
            }
        }
        for pair in departures.windows(2) {
            let [(from, _), (to, _)] = pair else { continue };
            if *to <= split {
                samples.idle.push(to.saturating_sub(*from));
            } else if *from >= split {
                samples.active.push(to.saturating_sub(*from));
            }
        }
        out.insert(slot, samples);
    }
    out
}

/// Whether every unit of the scheduled links is a frame, handshake records only where a connection starts (a link slot is
/// one connection, so a reconnect — a new slot — has its own handshake records at its start).
fn units_are_frames(frames: &[Frame], scheduled: &[u64]) -> bool {
    scheduled.iter().all(|slot| {
        let mut units: Vec<&Frame> = frames.iter().filter(|f| f.1 == *slot).collect();
        units.sort_by_key(|f| f.0);
        units.iter().enumerate().all(|(i, (_, _, len))| {
            *len == FRAME || (*len == 9 && i == 0) || (*len == 2_856 && i <= 1)
        })
    })
}

/// The test of every scheduled link and of all pooled.
#[must_use]
pub fn analyse(frames: &[Frame], split: u64, min_frames: usize) -> Option<Report> {
    let per = gaps(frames, split, min_frames);
    let (mut all_idle, mut all_active) = (Vec::new(), Vec::new());
    let (mut all_idle_n, mut all_active_n) = (Vec::new(), Vec::new());
    let (mut per_link, mut counts_per_link) = (Vec::new(), Vec::new());
    let mut fpd_per_link = Vec::new();
    for (slot, s) in &per {
        let all = s.idle_counts.iter().chain(&s.active_counts);
        fpd_per_link.push((*slot, (all.clone().min().copied()?, all.max().copied()?)));
        per_link.push((*slot, two_sample(&s.idle, &s.active)?));
        counts_per_link.push((*slot, two_sample(&s.idle_counts, &s.active_counts)?));
        all_idle.extend_from_slice(&s.idle);
        all_active.extend_from_slice(&s.active);
        all_idle_n.extend_from_slice(&s.idle_counts);
        all_active_n.extend_from_slice(&s.active_counts);
    }
    let pooled = two_sample(&all_idle, &all_active)?;
    let counts_pooled = two_sample(&all_idle_n, &all_active_n)?;
    // FIN5b-2: the shape checks run over every scheduled slot, the short connections included
    let all_slots = scheduled_slots(frames);
    let mut per_departure: Vec<u64> = Vec::new();
    for times in all_slots.values() {
        let mut times = times.clone();
        per_departure.extend(departures_of(&mut times).iter().map(|d| d.1));
    }
    let frames_per_departure = (
        per_departure.iter().min().copied()?,
        per_departure.iter().max().copied()?,
    );
    let scheduled: Vec<u64> = all_slots.keys().copied().collect();
    Some(Report {
        per_link,
        pooled,
        counts_per_link,
        counts_pooled,
        frames_per_departure,
        frames_per_departure_per_link: fpd_per_link,
        all_frames_full: units_are_frames(frames, &scheduled),
        slots_checked: scheduled.len(),
        slots_below_min: scheduled.len().saturating_sub(per.len()),
    })
}

/// The text of the evidence file: one line per link and one pooled, `D`, `p`, `n` of each sample, and the frames per departure.
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
    for (slot, k) in &report.counts_per_link {
        let _ = writeln!(
            s,
            "frames per departure, link {slot}: D = {:.6}, p = {:.6}",
            k.d, k.p
        );
    }
    let k = report.counts_pooled;
    let _ = writeln!(
        s,
        "frames per departure, pooled: D = {:.6}, p = {:.6}, min = {}, max = {}",
        k.d, k.p, report.frames_per_departure.0, report.frames_per_departure.1
    );
    for (slot, (lo, hi)) in &report.frames_per_departure_per_link {
        let _ = writeln!(
            s,
            "frames per departure, link {slot}: min = {lo}, max = {hi}"
        );
    }
    let _ = writeln!(
        s,
        "slots checked: {} ({} below min_frames, shape-checked only)",
        report.slots_checked, report.slots_below_min
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

    /// The common split of the synthetic traces.
    const SPLIT: u64 = 3_600_000;

    /// The synthetic trace: `links` links of exactly `n` idle gaps (ending at [`SPLIT`]) and `n` active gaps, each `P` = 10 s
    /// plus a jitter of `0..width` ms, the active gaps `shift` ms shorter; every departure is `per` frames 1 ms apart.
    fn trace(links: u64, n: usize, shift: u64, width: u64, per: u64, seed: u64) -> Vec<Frame> {
        let mut mix = Mix(seed | 1);
        let mut frames = Vec::new();
        for slot in 0..links {
            let idle: Vec<u64> = (0..n)
                .map(|_| 10_000_u64.saturating_add(mix.next().checked_rem(width).unwrap_or(0)))
                .collect();
            let active: Vec<u64> = (0..n)
                .map(|_| {
                    10_000_u64
                        .saturating_add(mix.next().checked_rem(width).unwrap_or(0))
                        .saturating_sub(shift)
                })
                .collect();
            let mut t = SPLIT.saturating_sub(idle.iter().sum::<u64>());
            let departure = |t: u64, frames: &mut Vec<Frame>| {
                for k in 0..per {
                    frames.push((t.saturating_add(k), slot, FRAME));
                }
            };
            departure(t, &mut frames);
            for gap in idle.iter().chain(&active) {
                t = t.saturating_add(*gap);
                departure(t, &mut frames);
            }
        }
        frames
    }

    /// AI-10 `ks_tool_detects_planted_dependence` (control): the analyser of AI-07 on a synthetic trace whose gaps shrink
    /// by 1 ms while "active" finds `p < 0.01` per link and pooled at the n of the real run (360 gaps per link and hour,
    /// 4 links pooled), with a timer jitter of 0…2 ms.
    #[test]
    fn ks_tool_detects_planted_dependence() {
        let frames = trace(4, 360, 1, 3, 1, 7);
        let r = analyse(&frames, SPLIT, 100).unwrap();
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
            let frames = trace(4, 360, 0, 3, 1, seed);
            let r = analyse(&frames, SPLIT, 100).unwrap();
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

    /// m-4 (verifier): the control at a realistic timer jitter, 0…20 ms uniform. The smallest shift of {1, 2, 5, 10, 20} ms
    /// that is found (`p < 0.01` on each of the 4 links, n = 360 per link and hour) is the minimum detectable shift the
    /// report states: 5 ms. (A shift of 2 ms over a 21-ms jitter is not found: D ≈ 0.1, p ≈ 0.07.)
    #[test]
    fn ks_tool_detects_shift_under_realistic_jitter() {
        let found = |shift: u64| {
            let frames = trace(4, 360, shift, 21, 1, 11);
            let r = analyse(&frames, SPLIT, 100).unwrap();
            r.per_link.iter().all(|(_, k)| k.p < 0.01)
        };
        let smallest = [1_u64, 2, 5, 10, 20].into_iter().find(|s| found(*s));
        // F-3 (verifier, C2-3b): the figure the report quotes is in the test output (`--no-capture`)
        {
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr(),
                "minimum detectable shift: {smallest:?} ms (jitter 0..21 ms, n = 360 per link and hour)"
            );
        }
        assert_eq!(smallest, Some(5), "the smallest detectable shift");
        assert!(found(10) && found(20));
        assert!(!found(1) && !found(2));
    }

    /// M-2 (verifier): the merge of frames less than 100 ms apart does not hide an extra frame. Every departure carries 2
    /// frames (a combined link); one extra 4 352 B frame 3 ms after a departure of the active hour only is a finding, the
    /// number of frames per departure is no longer constant. Without it the number is constant (2) in both hours.
    #[test]
    fn ks_tool_flags_an_extra_frame_in_a_slot() {
        let mut frames = trace(4, 360, 0, 3, 2, 5);
        let r = analyse(&frames, SPLIT, 100).unwrap();
        assert_eq!(r.constant_frames_per_departure(), Some(2));
        assert!(r.counts_pooled.d.abs() < 1e-12);
        let at = frames.iter().find(|f| f.0 > SPLIT + 100_000).unwrap().0;
        frames.push((at + 3, 0, FRAME));
        let r = analyse(&frames, SPLIT, 100).unwrap();
        assert_eq!(r.frames_per_departure, (2, 3));
        // F-2: the per-link figures show which link carries the extra frame
        assert!(r.frames_per_departure_per_link.contains(&(0, (2, 3))));
        assert!(r.frames_per_departure_per_link.contains(&(1, (2, 2))));
        assert!(evidence(&r).contains("frames per departure, link 0: min = 2, max = 3"));
        assert_eq!(r.constant_frames_per_departure(), None);
    }

    /// m-5 (verifier): the handshake records are allowed only where a connection starts, not anywhere on the link.
    #[test]
    fn a_handshake_sized_unit_in_the_middle_is_not_a_frame() {
        let mut frames = trace(1, 120, 0, 3, 1, 3);
        assert!(analyse(&frames, SPLIT, 100).unwrap().all_frames_full);
        // a 9 B first unit and a 2 856 B second unit, as at the start of a connection
        frames.push((0, 0, 9));
        frames.push((1, 0, 2_856));
        assert!(analyse(&frames, SPLIT, 100).unwrap().all_frames_full);
        // F-4: a reconnect is a new link slot and has its own handshake records at its start
        let mut again = trace(1, 120, 0, 3, 1, 3);
        again.extend(frames.iter().map(|(t, _, l)| (*t, 1, *l)));
        assert!(analyse(&again, SPLIT, 100).unwrap().all_frames_full);
        // the same lengths in the middle of the link
        frames.push((SPLIT, 0, 2_856));
        assert!(!analyse(&frames, SPLIT, 100).unwrap().all_frames_full);
    }

    /// FIN5b-2: a short scheduled connection (below `min_frames`): 6 departures of 2 frames, 10 s apart, from `from` on.
    fn short_slot(slot: u64, from: u64) -> Vec<Frame> {
        (0..6_u64)
            .flat_map(|k| {
                let t = from.saturating_add(k.saturating_mul(10_000));
                [(t, slot, FRAME), (t.saturating_add(1), slot, FRAME)]
            })
            .collect()
    }

    /// FIN5b-2 (positive control): four long links plus one short connection with clean frames: every shape check
    /// holds, the short slot is counted as shape-checked only, and the criterion's inputs are all MET.
    #[test]
    fn short_connection_with_clean_frames_stays_met() {
        let mut frames = trace(4, 360, 0, 3, 2, 11);
        frames.extend(short_slot(99, 1_000_000));
        let r = analyse(&frames, SPLIT, 100).unwrap();
        assert_eq!(r.per_link.len(), 4);
        assert!(r.all_frames_full);
        assert_eq!(r.constant_frames_per_departure(), Some(2));
        assert_eq!((r.slots_checked, r.slots_below_min), (5, 1));
        assert!(r.per_link.iter().all(|(_, k)| k.p >= 0.01));
        assert!(evidence(&r).contains("slots checked: 5 (1 below min_frames, shape-checked only)"));
    }

    /// FIN5b-2: one 4 353 B unit on a short scheduled connection is a finding (`all units 4352 B: false`), as on a long one.
    #[test]
    fn short_connection_with_a_4353_byte_unit_is_not_met() {
        let mut frames = trace(4, 360, 0, 3, 2, 11);
        frames.extend(short_slot(99, 1_000_000));
        frames.push((1_000_050, 99, FRAME + 1));
        let r = analyse(&frames, SPLIT, 100).unwrap();
        assert!(!r.all_frames_full, "the 4353-byte unit was not checked");
        assert!(evidence(&r).contains("all units 4352 B: false"));
    }

    /// FIN5b-2: a departure of 3 frames on a short scheduled connection is a finding (frames per departure min 2, max 3).
    #[test]
    fn short_connection_with_a_three_frame_departure_is_not_met() {
        let mut frames = trace(4, 360, 0, 3, 2, 11);
        frames.extend(short_slot(99, 1_000_000));
        frames.push((1_000_002, 99, FRAME));
        let r = analyse(&frames, SPLIT, 100).unwrap();
        assert_eq!(r.frames_per_departure, (2, 3));
        assert_eq!(r.constant_frames_per_departure(), None);
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
        let s = g.get(&0).unwrap();
        assert!(s.idle.iter().chain(&s.active).all(|d| *d == 10_000));
        assert_eq!((s.idle.len(), s.active.len()), (150, 149));
        assert!(
            s.idle_counts
                .iter()
                .chain(&s.active_counts)
                .all(|c| *c == 2)
        );
    }

    #[test]
    fn a_gap_that_spans_the_split_is_in_neither_sample() {
        let frames: Vec<Frame> = [0, 10, 20, 35, 45, 55]
            .iter()
            .map(|t| (*t * 1_000, 0, FRAME))
            .collect();
        let g = gaps(&frames, 30_000, 1);
        let s = g.get(&0).unwrap();
        assert_eq!(
            (s.idle.clone(), s.active.clone()),
            (vec![10_000, 10_000], vec![10_000, 10_000])
        );
    }
}
