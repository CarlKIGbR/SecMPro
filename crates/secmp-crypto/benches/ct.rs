// SPDX-License-Identifier: AGPL-3.0-or-later
//! dudect-style constant-time tests (docs/06 §2, §4; M1 acceptance "constant-time test (dudect-style) for tag
//! comparison shows no leak"; Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", 2017), with the
//! instrument and the verdict of ADR-038.
//!
//! For each target, two input classes are measured in random interleaving; Welch's t-statistic is computed on
//! the raw timings and on timings cropped at several percentiles of the pooled distribution. A deliberately
//! variable-time comparison is measured as a **control**: it must be detected, otherwise the harness is not
//! sensitive enough and the run fails.
//!
//! Targets:
//! - `tag_compare`: the tag comparison used by `MsgEncrypt` (`subtle::ConstantTimeEq` on 32 bytes), tags that
//!   differ in the first vs the last byte (batched, 256 comparisons per measurement);
//! - `msg_open_reject`: `MsgEncrypt::open` rejecting a tag wrong in the first vs the last byte;
//! - `caead_open_reject`: `Caead::open` with a wrong key (commitment and tag fail) vs a tampered ciphertext
//!   (commitment matches, tag fails) — the trial-decryption case of spec §6.5;
//! - `sas`: `SafetyNumber::new` for a fixed pair of fingerprints vs random pairs.
//!
//! Isolating targets for the residual signal of `caead_open_reject` after the `Caead::open` fix (M1 review C4
//! diagnosis), each on one component with the same fresh-input discipline:
//! - `caead_derive`: `derive` alone (HKDF-Expand to `K_enc ‖ COM`, AEAD key setup), wrong key vs right key;
//! - `caead_aead_reject`: XChaCha20-Poly1305 `decrypt_inout_detached` alone on the same tampered ciphertext, with
//!   the AEAD key derived from the wrong vs the right key (both reject);
//! - `caead_com_compare`: the `COM` comparison alone, mismatching vs matching (batched, 256 comparisons per
//!   measurement, as `tag_compare`: one 32-byte comparison is below the timer resolution);
//! - `caead_open_reject_samekey`: `Caead::open` with the right key in both classes, ciphertext tampered at byte
//!   100 vs byte 300 (`COM` matches and the tag fails in both).
//!
//! Sign: `t = (mean(class 0) − mean(class 1)) / SE` (Welch), so **`t < 0` means class 0 is faster**; the report
//! states it once (`sign`) and names both classes of every target (`class0`, `class1`).
//!
//! The classes may differ only in their contents, never in where the inputs live: every measured input is a
//! fresh copy made by `prepare` (by value or in a new allocation, identical sequence for both classes), so buffer
//! placement cannot correlate with the class. With one fixed buffer per class, the alignment-dependent cost of
//! copying and loading the input is itself a class difference (M1, `x86_64` CI: |t| = 24 and 210 for the two
//! openers with per-class buffers; M1 report §4).
//!
//! ADR-038:
//! - **Timer (1).** Each call is timed with the CPU counter — `rdtscp` on `x86_64`, `cntvct_el0` on `aarch64`,
//!   `Instant` elsewhere (named in the report). The tick length is calibrated against `Instant` over 200 ms. The
//!   timer's resolution is its quantum: the smallest step between distinct values of 10⁶ back-to-back
//!   `now_ticks()` differences (the smallest non-zero difference itself, the cost of one read, is reported as
//!   `overhead`). Samples stay in ticks; the report gives ticks and ns.
//! - **Verdict (2).** Per target, max |t| over raw and the five crops: ≤ pass → PASS; > fail → FAIL; otherwise
//!   the target is measured once more (fresh class sequence and inputs from the stream, same n) and the verdict is
//!   INCONCLUSIVE→FAIL if the second measurement is above pass **with the same sign at a crop where the first
//!   was above pass**, INCONCLUSIVE→PASS otherwise. The control is measured once: detected (> pass) → PASS, else
//!   FAIL. `(pass, fail)`, the resolution fraction and the batch cap below are read from `xtask/src/expect.rs`
//!   (`CT_THRESHOLDS`, `CT_RESOLUTION_MAX_FRACTION`, `CT_MAX_BATCH`) — this file contains no copy of them.
//! - **Runner metadata and batching (3).** One sample is `k` consecutive calls on `k` inputs of the same
//!   class, all prepared before the window opens (identical allocation sequence for both classes), timed as one
//!   batch; `k` is the smallest integer with `quantum ≤ fraction · k · m` for the median call duration `m`
//!   (= `ceil(100 · quantum / m)`, and 1 on a fine counter). The calibration (no verdict; M1 review F8) first
//!   runs a warm-up pass whose timings are discarded, then `CALIBRATION_SAMPLES` single calls for a first
//!   estimate of `k`; where that is above 1, `k` is derived from the median of *batches* of `k` calls (`m` =
//!   batch median / `k`), re-derived until the batch median is resolved (`quantum ≤ fraction · batch median`), at
//!   most `CALIBRATION_ROUNDS` times. A target that would need `k > CT_MAX_BATCH`, whose quantum is unknown, or
//!   that is still unresolved after the rounds is NOT MEASURABLE on this runner: its verdict is
//!   `NOT_MEASURABLE`, which fails the gate with that wording. The report carries the clock (arch, Linux
//!   clocksource, timer, tick, resolution, overhead), and per target `k`, the calibration (single-call median,
//!   every batched round, the per-call median `k` rests on) and, per measurement, the batch median and the number
//!   of distinct batch durations.
//!
//! Run by `cargo xtask step ct` (ci-full) as `cargo bench -p secmp-crypto --features kat --bench ct`; the results
//! are written to `target/ct-report.json` and the exit status is the verdict. `SECMP_CT_SCALE` (a divisor, default
//! 1) shortens every sample count for quick local runs.

// ADR-038 (1): the cycle-counter read in `now_ticks` is the only `unsafe` code in the bench. `xtask policy`
// sanctions this attribute at exactly this path (`expect::UNSAFE_EXEMPT_ROOT`).
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secmp_crypto::{
    AEAD_TAG_LEN, BODY_LEN, COM_LEN, Caead, Fingerprint, Label, MsgEncrypt, Nonce24, SafetyNumber,
    SecretBytes, hkdf_expand,
};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use subtle::ConstantTimeEq;

/// The sign convention of every t in the report (`Stats::t`).
const SIGN: &str =
    "t = (mean(class 0) - mean(class 1)) / SE (Welch); t < 0 means class 0 is faster";
/// Associated data of the CAEAD targets.
const CAEAD_AD: &[u8] = b"SecMP-HX/1 initcell";
/// Percentiles (per mille) of the pooled distribution at which measurements are cropped (dudect outlier handling).
const CROPS_PERMILLE: [usize; 5] = [500, 750, 900, 950, 990];
/// How long the tick length is calibrated against `Instant` (ADR-038: at least 100 ms).
const CALIBRATION: Duration = Duration::from_millis(200);
/// Back-to-back timer reads for the resolution estimate.
const RESOLUTION_PAIRS: usize = 1_000_000;
/// Samples per calibration pass (the warm-up, the single calls and each batched round; ADR-038 (3): "a few
/// thousand").
const CALIBRATION_SAMPLES: usize = 2_000;
/// Batched calibration rounds at most (M1 review F8); a target still unresolved after them is NOT MEASURABLE.
const CALIBRATION_ROUNDS: usize = 3;

// ---- thresholds (ADR-038 (2), (3)): read from xtask/src/expect.rs ---------------------------------------------

/// The file that fixes the gate's parameters (ADR-038: "not in code that a later commit can tune silently").
const EXPECT_RS: &str = include_str!("../../../xtask/src/expect.rs");

/// The verdict parameters.
#[derive(Clone, Copy)]
struct Rules {
    /// ≤ `pass` → PASS; the control must exceed it.
    pass: f64,
    /// > `fail` → FAIL without a second measurement.
    fail: f64,
    /// The timer resolution may be at most this fraction of a sample's median (batching restores it).
    max_resolution_fraction: f64,
    /// The largest batch size; a target that needs more is NOT MEASURABLE.
    max_batch: u32,
}

/// The value text of the one-line `pub(crate) const <name>: … = <value>;` in `EXPECT_RS`.
fn const_value(name: &str) -> Option<&'static str> {
    let prefix = format!("pub(crate) const {name}:");
    let line = EXPECT_RS
        .lines()
        .find(|l| l.trim_start().starts_with(&prefix))?;
    let (_, value) = line.split_once('=')?;
    value.trim().strip_suffix(';').map(str::trim)
}

impl Rules {
    fn from_expect() -> Option<Self> {
        let (pass, fail) = const_value("CT_THRESHOLDS")?
            .strip_prefix('(')?
            .strip_suffix(')')?
            .split_once(',')?;
        let rules = Self {
            pass: pass.trim().parse().ok()?,
            fail: fail.trim().parse().ok()?,
            max_resolution_fraction: const_value("CT_RESOLUTION_MAX_FRACTION")?.parse().ok()?,
            max_batch: const_value("CT_MAX_BATCH")?.parse().ok()?,
        };
        let sane = rules.pass > 0.0
            && rules.fail > rules.pass
            && rules.max_resolution_fraction > 0.0
            && rules.max_resolution_fraction < 1.0
            && rules.max_batch >= 1;
        sane.then_some(rules)
    }

    /// The batch size for a target with median call duration `per_call_ticks` on a timer with quantum
    /// `quantum_ticks`: the smallest `k ≤ max_batch` with `quantum ≤ fraction · k · per_call`, or `None` if
    /// there is none.
    fn batch(self, quantum_ticks: u64, per_call_ticks: f64) -> Option<u32> {
        let quantum = f64_of(quantum_ticks);
        (1..=self.max_batch)
            .find(|k| quantum <= self.max_resolution_fraction * f64::from(*k) * per_call_ticks)
    }

    /// Whether a sample with median `median_ticks` is resolved: `quantum ≤ fraction · median`.
    fn resolved(self, quantum_ticks: u64, median_ticks: u64) -> bool {
        f64_of(quantum_ticks) <= self.max_resolution_fraction * f64_of(median_ticks)
    }

    fn json(self) -> String {
        format!(
            "{{\"pass\":{},\"fail\":{},\"max_resolution_fraction\":{},\"max_batch\":{}}}",
            self.pass, self.fail, self.max_resolution_fraction, self.max_batch
        )
    }
}

// ---- timer (ADR-038 (1)) ---------------------------------------------------------------------------------------

/// Which counter `now_ticks` reads.
#[cfg(target_arch = "x86_64")]
const TIMER: &str = "rdtscp";
#[cfg(target_arch = "aarch64")]
const TIMER: &str = "cntvct_el0";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const TIMER: &str = "instant";

/// The time-stamp counter. RDTSCP waits until every earlier instruction has executed before it reads.
#[cfg(target_arch = "x86_64")]
#[inline]
fn now_ticks() -> u64 {
    let mut aux = 0_u32;
    // SAFETY: `__rdtscp` executes RDTSCP, which reads the time-stamp counter and stores IA32_TSC_AUX through the
    // pointer; the pointer is to `aux`, a live, aligned local that nothing else borrows. On a CPU without RDTSCP
    // the instruction faults (#UD) and the bench aborts, so the gate fails closed.
    unsafe { core::arch::x86_64::__rdtscp(&raw mut aux) }
}

/// The virtual counter `CNTVCT_EL0`, read after an instruction barrier.
#[cfg(target_arch = "aarch64")]
#[inline]
fn now_ticks() -> u64 {
    let ticks: u64;
    // SAFETY: `isb` orders the read after the preceding instructions; `mrs` reads CNTVCT_EL0, which Linux and
    // macOS make readable at EL0 (their clocks are built on it). The asm touches no memory, the stack or the
    // flags and writes only the output register bound to `ticks`.
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {ticks}, cntvct_el0",
            ticks = out(reg) ticks,
            options(nomem, nostack, preserves_flags)
        );
    }
    ticks
}

/// Nanoseconds since the first call (`Instant`), where no counter is read directly.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn now_ticks() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// `x` as `f64` (exact below 2^53, the range of every tick count here).
fn f64_of(x: u64) -> f64 {
    let hi = u32::try_from(x.checked_shr(32).unwrap_or(0)).unwrap_or(u32::MAX);
    let lo = u32::try_from(x & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(hi) * 4_294_967_296.0 + f64::from(lo)
}

/// Where the Linux clocksource is published (sysfs).
const CLOCKSOURCE_DIR: &str = "/sys/devices/system/clocksource/clocksource0";

/// The instrument (ADR-038 (1), (3)): which counter, its calibrated tick length, its resolution (quantum) and
/// read overhead, and the Linux clocksource `Instant` runs on.
struct Clock {
    current_clocksource: String,
    available_clocksource: String,
    /// ns per tick, measured against `Instant` over `CALIBRATION`.
    tick_ns: f64,
    /// Ticks counted during the calibration, and its duration by `Instant` (ns).
    calibration_ticks: u64,
    calibration_ns: f64,
    /// The quantum: the smallest step between distinct back-to-back differences, in ticks (`None` if no two
    /// distinct differences occurred).
    resolution_ticks: Option<u64>,
    /// The smallest non-zero back-to-back difference (the cost of one read), in ticks.
    overhead_ticks: Option<u64>,
    /// The median back-to-back difference, in ticks.
    median_delta_ticks: Option<u64>,
}

impl Clock {
    fn probe() -> Self {
        let read = |file: &str| {
            std::fs::read_to_string(format!("{CLOCKSOURCE_DIR}/{file}"))
                .map_or_else(|_| "n/a".to_owned(), |s| s.trim().to_owned())
        };
        // calibration: ticks per `Instant` interval of at least `CALIBRATION`
        let i0 = Instant::now();
        let t0 = now_ticks();
        while i0.elapsed() < CALIBRATION {
            std::hint::spin_loop();
        }
        let t1 = now_ticks();
        let calibration_ns = i0.elapsed().as_secs_f64() * 1e9;
        let calibration_ticks = t1.saturating_sub(t0);
        let tick_ns = if calibration_ticks > 0 {
            calibration_ns / f64_of(calibration_ticks)
        } else {
            f64::NAN
        };
        // resolution: back-to-back reads
        let mut deltas: Vec<u64> = (0..RESOLUTION_PAIRS)
            .map(|_| {
                let a = now_ticks();
                let b = now_ticks();
                b.saturating_sub(a)
            })
            .collect();
        deltas.sort_unstable();
        let median_delta_ticks = deltas.get(deltas.len() / 2).copied();
        let overhead_ticks = deltas.iter().copied().find(|d| *d > 0);
        deltas.dedup();
        let resolution_ticks = deltas
            .windows(2)
            .filter_map(|w| match w {
                [a, b] => Some(b.saturating_sub(*a)),
                _ => None,
            })
            .filter(|step| *step > 0)
            .min();
        Self {
            current_clocksource: read("current_clocksource"),
            available_clocksource: read("available_clocksource"),
            tick_ns,
            calibration_ticks,
            calibration_ns,
            resolution_ticks,
            overhead_ticks,
            median_delta_ticks,
        }
    }

    fn ns(&self, ticks: Option<u64>) -> Option<f64> {
        ticks.map(|t| f64_of(t) * self.tick_ns)
    }

    fn resolution_ns(&self) -> Option<f64> {
        self.ns(self.resolution_ticks)
    }

    fn json(&self) -> String {
        serde_json::json!({
            "arch": std::env::consts::ARCH,
            "current_clocksource": self.current_clocksource,
            "available_clocksource": self.available_clocksource,
            "timer": TIMER,
            "tick_ns": self.tick_ns,
            "calibration_ticks": self.calibration_ticks,
            "calibration_ns": self.calibration_ns,
            "resolution_ticks": self.resolution_ticks,
            "resolution_ns": self.resolution_ns(),
            "overhead_ticks": self.overhead_ticks,
            "overhead_ns": self.ns(self.overhead_ticks),
            "median_delta_ticks": self.median_delta_ticks,
            "median_delta_ns": self.ns(self.median_delta_ticks),
        })
        .to_string()
    }
}

// ---- statistics ---------------------------------------------------------------------------------------------

/// One sample: the class and the duration in timer ticks.
type Samples = Vec<(usize, u64)>;

/// Welford accumulators for the two classes.
#[derive(Default, Clone, Copy)]
struct Stats {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Stats {
    fn push(&mut self, class: usize, x: f64) {
        let c = class.min(1);
        let (Some(n), Some(mean), Some(m2)) =
            (self.n.get_mut(c), self.mean.get_mut(c), self.m2.get_mut(c))
        else {
            return;
        };
        *n += 1.0;
        let d = x - *mean;
        *mean += d / *n;
        *m2 += d * (x - *mean);
    }

    /// Welch's t-statistic.
    fn t(&self) -> f64 {
        let [n0, n1] = self.n;
        let [m0, m1] = self.mean;
        let [s0, s1] = self.m2;
        if n0 < 2.0 || n1 < 2.0 {
            return 0.0;
        }
        let v = s0 / (n0 - 1.0) / n0 + s1 / (n1 - 1.0) / n1;
        if v <= 0.0 { 0.0 } else { (m0 - m1) / v.sqrt() }
    }
}

/// A deterministic byte stream for classes and random inputs, seeded from the OS CSPRNG.
struct Stream(sha3::Shake256Reader);

impl Stream {
    fn new() -> Result<Self, secmp_crypto::Error> {
        let seed = SecretBytes::<32>::random()?;
        let mut h = Shake256::default();
        h.update(seed.expose_secret());
        Ok(Self(h.finalize_xof()))
    }

    fn fill(&mut self, buf: &mut [u8]) {
        self.0.read(buf);
    }

    fn classes(&mut self, n: usize) -> Vec<usize> {
        let mut bytes = vec![0; n];
        self.fill(&mut bytes);
        bytes.iter().map(|b| usize::from(b & 1)).collect()
    }
}

/// Measure `n` samples of `k` calls each (ADR-038 (3); `k = 1` on a fine counter). For sample `i` of class `c`,
/// the `k` inputs `prepare(c, i·k + j)` are built before the window opens (dudect: inputs are prepared before
/// measuring; the previous sample's inputs are dropped first, so both classes see the same allocation sequence),
/// then the `k` calls `op(&input)` are timed as one batch. The class sequence is per sample.
fn measure<T>(
    n: usize,
    k: usize,
    stream: &mut Stream,
    mut prepare: impl FnMut(usize, usize) -> T,
    mut op: impl FnMut(&T),
) -> Samples {
    let k = k.max(1);
    let classes = stream.classes(n);
    let mut out = Vec::with_capacity(n);
    // warm-up
    for (i, c) in classes.iter().take(n / 100).enumerate() {
        op(&prepare(*c, i));
    }
    let mut batch: Vec<T> = Vec::with_capacity(k);
    for (i, c) in classes.into_iter().enumerate() {
        batch.clear();
        for j in 0..k {
            batch.push(black_box(prepare(c, i.saturating_mul(k).saturating_add(j))));
        }
        let start = now_ticks();
        for input in &batch {
            op(input);
        }
        let end = now_ticks();
        out.push((c, end.saturating_sub(start)));
    }
    out
}

/// The median sample duration, in ticks.
fn median_ticks(samples: &[(usize, u64)]) -> u64 {
    let mut sorted: Vec<u64> = samples.iter().map(|(_, x)| *x).collect();
    sorted.sort_unstable();
    sorted.get(sorted.len() / 2).copied().unwrap_or(0)
}

/// Welch t on the raw samples and on the samples below each crop percentile.
fn analyse(samples: &[(usize, u64)]) -> Vec<(String, f64)> {
    let mut sorted: Vec<u64> = samples.iter().map(|(_, x)| *x).collect();
    sorted.sort_unstable();
    let mut results = Vec::new();
    let mut raw = Stats::default();
    for (c, x) in samples {
        raw.push(*c, f64_of(*x));
    }
    results.push(("raw".to_owned(), raw.t()));
    for permille in CROPS_PERMILLE {
        let idx = sorted.len().saturating_mul(permille) / 1000;
        let cut = sorted
            .get(idx.min(sorted.len().saturating_sub(1)))
            .copied()
            .unwrap_or(u64::MAX);
        let mut s = Stats::default();
        for (c, x) in samples.iter().filter(|(_, x)| *x < cut) {
            s.push(*c, f64_of(*x));
        }
        results.push((format!("p{}", permille / 10), s.t()));
    }
    results
}

/// One measurement of one target: the t statistics and how finely its samples (batch durations) are resolved.
struct Measurement {
    ts: Vec<(String, f64)>,
    distinct: usize,
    median_ticks: u64,
}

impl Measurement {
    fn of(samples: &[(usize, u64)]) -> Self {
        let mut sorted: Vec<u64> = samples.iter().map(|(_, x)| *x).collect();
        sorted.sort_unstable();
        let median_ticks = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
        sorted.dedup();
        Self {
            ts: analyse(samples),
            distinct: sorted.len(),
            median_ticks,
        }
    }

    /// The largest |t| and the statistic it belongs to (`raw` or a crop).
    fn max(&self) -> (f64, &str) {
        self.ts.iter().fold((0.0, "raw"), |(best, at), (k, t)| {
            if t.abs() > best {
                (t.abs(), k.as_str())
            } else {
                (best, at)
            }
        })
    }

    fn json(&self, clock: &Clock) -> String {
        let ts: Vec<String> = self
            .ts
            .iter()
            .map(|(k, t)| format!("\"{k}\":{t:.3}"))
            .collect();
        let (max, at) = self.max();
        let median_ns = f64_of(self.median_ticks) * clock.tick_ns;
        let per_resolution = clock.resolution_ticks.filter(|r| *r > 0).map_or_else(
            || "null".to_owned(),
            |r| format!("{:.1}", f64_of(self.median_ticks) / f64_of(r)),
        );
        format!(
            "{{\"max_abs_t\":{max:.3},\"max_at\":\"{at}\",\"t\":{{{}}},\"distinct\":{},\"median_ticks\":{},\"median_ns\":{median_ns:.1},\"median_per_resolution\":{per_resolution}}}",
            ts.join(","),
            self.distinct,
            self.median_ticks
        )
    }
}

// ---- verdict (ADR-038 (2), (3), (4)) ------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
    InconclusivePass,
    InconclusiveFail,
    NotMeasurable,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::InconclusivePass => "INCONCLUSIVE→PASS",
            Self::InconclusiveFail => "INCONCLUSIVE→FAIL",
            Self::NotMeasurable => "NOT_MEASURABLE",
        }
    }

    fn passed(self) -> bool {
        matches!(self, Self::Pass | Self::InconclusivePass)
    }
}

/// A target: its classes, sample count, role and how to measure it once (`run(n, k, stream)`: `n` samples of
/// `k` calls each).
struct Target {
    name: &'static str,
    /// What class 0 and class 1 measure.
    classes: [&'static str; 2],
    samples: usize,
    control: bool,
    run: fn(usize, usize, &mut Stream) -> Result<Samples, secmp_crypto::Error>,
}

/// How a target's batch size was found (ADR-038 (3), M1 review F8).
struct Calibration {
    /// Median of the single calls after the warm-up, in ticks.
    single_median_ticks: u64,
    /// The batched rounds, as (batch size, median batch duration in ticks).
    rounds: Vec<(u32, u64)>,
    /// The batch size (`None`: NOT MEASURABLE).
    k: Option<u32>,
}

impl Calibration {
    /// The median duration of one call, in ticks, by the last round (the single calls if there was none).
    fn per_call_ticks(&self) -> f64 {
        self.rounds.last().map_or_else(
            || f64_of(self.single_median_ticks),
            |(k, median)| f64_of(*median) / f64::from(*k),
        )
    }

    fn json(&self, clock: &Clock) -> String {
        let rounds: Vec<String> = self
            .rounds
            .iter()
            .map(|(k, median)| {
                format!(
                    "{{\"k\":{k},\"batch_median_ticks\":{median},\"per_call_ns\":{:.1}}}",
                    f64_of(*median) / f64::from(*k) * clock.tick_ns
                )
            })
            .collect();
        format!(
            "{{\"warmup_calls\":{},\"single_median_ticks\":{},\"single_median_ns\":{:.1},\"rounds\":[{}]}}",
            CALIBRATION_SAMPLES,
            self.single_median_ticks,
            f64_of(self.single_median_ticks) * clock.tick_ns,
            rounds.join(",")
        )
    }
}

/// The batch size of `target` (ADR-038 (3); M1 review F8: warm-up, then `k` from the median of *batches*): a
/// warm-up pass whose timings are discarded (on the first target the calibration ran cold: the control
/// calibrated at 1 875 ns per call and measured 667 ns per call); single calls give the first estimate; while
/// the median batch duration of `k` calls is not resolved (`quantum > fraction · median`), `k` is re-derived from
/// that batch median divided by `k` (at most `CALIBRATION_ROUNDS` batched rounds; a call shorter than one quantum
/// starts at `max_batch`). NOT MEASURABLE when the quantum is unknown, when even `max_batch` calls would not be
/// resolved, or when the rounds run out.
fn calibrate(
    target: &Target,
    stream: &mut Stream,
    clock: &Clock,
    rules: Rules,
) -> Result<Calibration, secmp_crypto::Error> {
    let n = CALIBRATION_SAMPLES.min(target.samples);
    // warm-up: timings discarded
    (target.run)(n, 1, stream)?;
    let single_median_ticks = median_ticks(&(target.run)(n, 1, stream)?);
    let mut calibration = Calibration {
        single_median_ticks,
        rounds: Vec::new(),
        k: None,
    };
    let Some(quantum) = clock.resolution_ticks else {
        return Ok(calibration);
    };
    // a call shorter than one quantum (single-call median 0) is probed with the largest batch
    let first = match rules.batch(quantum, f64_of(single_median_ticks)) {
        None if single_median_ticks == 0 => Some(rules.max_batch),
        first => first,
    };
    let Some(mut k) = first else {
        return Ok(calibration);
    };
    if k == 1 {
        // the single calls are the batches of size 1, and they are resolved
        calibration.k = Some(1);
        return Ok(calibration);
    }
    for _ in 0..CALIBRATION_ROUNDS {
        let median = median_ticks(&(target.run)(n, usize::try_from(k).unwrap_or(1), stream)?);
        calibration.rounds.push((k, median));
        if rules.resolved(quantum, median) {
            calibration.k = Some(k);
            return Ok(calibration);
        }
        // not resolved ⇒ the estimate from this batch median is larger than `k`, or none fits
        match rules.batch(quantum, calibration.per_call_ticks()) {
            Some(next) if next > k => k = next,
            _ => return Ok(calibration),
        }
    }
    Ok(calibration)
}

struct Outcome {
    target: Target,
    calibration: Calibration,
    verdict: Verdict,
    first: Option<Measurement>,
    second: Option<Measurement>,
}

/// Measure `target` and decide (ADR-038): the calibration sets the batch size `k`; NOT MEASURABLE if none up to
/// `max_batch` suffices; the control must exceed `pass`; every other target is judged by the two-tier rule with
/// at most one re-measurement.
fn evaluate(
    target: Target,
    stream: &mut Stream,
    clock: &Clock,
    rules: Rules,
) -> Result<Outcome, secmp_crypto::Error> {
    let calibration = calibrate(&target, stream, clock, rules)?;
    let Some(k) = calibration.k else {
        return Ok(Outcome {
            target,
            calibration,
            verdict: Verdict::NotMeasurable,
            first: None,
            second: None,
        });
    };
    let batch = usize::try_from(k).unwrap_or(1);
    let first = Measurement::of(&(target.run)(target.samples, batch, stream)?);
    let (max, _) = first.max();
    let (verdict, second) = if target.control {
        let detected = max > rules.pass;
        (
            if detected {
                Verdict::Pass
            } else {
                Verdict::Fail
            },
            None,
        )
    } else if max <= rules.pass {
        (Verdict::Pass, None)
    } else if max > rules.fail {
        (Verdict::Fail, None)
    } else {
        let second = Measurement::of(&(target.run)(target.samples, batch, stream)?);
        // same crop, same sign, both above `pass`
        let confirmed = first.ts.iter().zip(&second.ts).any(|((k1, t1), (k2, t2))| {
            k1 == k2 && t1.abs() > rules.pass && t2.abs() > rules.pass && (*t1 < 0.0) == (*t2 < 0.0)
        });
        let verdict = if confirmed {
            Verdict::InconclusiveFail
        } else {
            Verdict::InconclusivePass
        };
        (verdict, Some(second))
    };
    Ok(Outcome {
        target,
        calibration,
        verdict,
        first: Some(first),
        second,
    })
}

impl Outcome {
    fn json(&self, clock: &Clock) -> String {
        let [class0, class1] = self.target.classes;
        let measurement =
            |m: Option<&Measurement>| m.map_or_else(|| "null".to_owned(), |m| m.json(clock));
        let per_call_ticks = self.calibration.per_call_ticks();
        format!(
            "{{\"name\":\"{}\",\"class0\":\"{class0}\",\"class1\":\"{class1}\",\"samples\":{},\"control\":{},\"k\":{},\"calibration_median_ticks\":{per_call_ticks:.2},\"calibration_median_ns\":{:.1},\"calibration\":{},\"verdict\":\"{}\",\"passed\":{},\"first\":{},\"second\":{}}}",
            self.target.name,
            self.target.samples,
            self.target.control,
            self.calibration
                .k
                .map_or_else(|| "null".to_owned(), |k| k.to_string()),
            per_call_ticks * clock.tick_ns,
            self.calibration.json(clock),
            self.verdict.as_str(),
            self.verdict.passed(),
            measurement(self.first.as_ref()),
            measurement(self.second.as_ref())
        )
    }
}

// ---- targets --------------------------------------------------------------------------------------------------

/// Batched 32-byte tag comparisons: class 0 differs in byte 0, class 1 in byte 31.
fn tag_compare(n: usize, k: usize, stream: &mut Stream, variable_time: bool) -> Samples {
    let mut expected = [0_u8; 32];
    stream.fill(&mut expected);
    let mut first = expected;
    first[0] ^= 1;
    let mut last = expected;
    last[31] ^= 1;
    let inputs = [first, last];
    measure(
        n,
        k,
        stream,
        |c, _| inputs.get(c).copied().unwrap_or(first),
        |tag| {
            for _ in 0..256 {
                let eq = if variable_time {
                    // the control: an early-exit comparison, as a naive `==` loop would do
                    black_box(&expected)
                        .iter()
                        .zip(black_box(tag))
                        .all(|(a, b)| a == b)
                } else {
                    bool::from(
                        black_box(&expected)
                            .as_slice()
                            .ct_eq(black_box(tag).as_slice()),
                    )
                };
                black_box(eq);
            }
        },
    )
}

fn msg_open_reject(
    n: usize,
    k: usize,
    stream: &mut Stream,
) -> Result<Samples, secmp_crypto::Error> {
    let mut mk = [0_u8; 32];
    stream.fill(&mut mk);
    let mut body = vec![0_u8; BODY_LEN];
    stream.fill(&mut body);
    let ad = vec![0x5a_u8; 2401];
    let sealed = MsgEncrypt::seal(SecretBytes::from_slice(&mk)?, &ad, &body)?;
    let mut first = sealed.clone();
    let mut last = sealed;
    if let Some(b) = first.get_mut(BODY_LEN) {
        *b ^= 1;
    }
    if let Some(b) = last.last_mut() {
        *b ^= 1;
    }
    let inputs = [first, last];
    let key = SecretBytes::<32>::from_slice(&mk)?;
    Ok(measure(
        n,
        k,
        stream,
        |c, _| inputs.get(c).cloned().unwrap_or_default(),
        |ct| {
            black_box(MsgEncrypt::open(&key, &ad, black_box(ct)).is_ok());
        },
    ))
}

fn caead_open_reject(
    n: usize,
    batch: usize,
    stream: &mut Stream,
) -> Result<Samples, secmp_crypto::Error> {
    let mut k = [0_u8; 32];
    stream.fill(&mut k);
    let mut other = k;
    other[0] ^= 1;
    let mut p = vec![0_u8; 4024];
    stream.fill(&mut p);
    let nonce = Nonce24::random()?;
    let nb = *nonce.as_bytes();
    let sealed = Caead::seal(
        &SecretBytes::from_slice(&k)?,
        nonce,
        b"SecMP-HX/1 initcell",
        &p,
    )?;
    let mut tampered = sealed.clone();
    if let Some(b) = tampered.get_mut(100) {
        *b ^= 1;
    }
    // class 0: wrong key (COM and tag fail); class 1: right key, tampered ciphertext (COM ok, tag fails)
    Ok(measure(
        n,
        batch,
        stream,
        |c, _| {
            let (key, ct) = if c == 0 {
                (&other, &sealed)
            } else {
                (&k, &tampered)
            };
            (SecretBytes::<32>::from_slice(key).ok(), ct.clone())
        },
        |(key, ct)| {
            if let Some(key) = key {
                black_box(Caead::open(key, &nb, b"SecMP-HX/1 initcell", black_box(ct)).is_ok());
            }
        },
    ))
}

/// The inputs of the isolating CAEAD targets, drawn like those of `caead_open_reject`: the right key `k`, a
/// wrong key `other` (byte 0 flipped), a nonce and `COM ‖ C` of a 4024-byte plaintext sealed under `k`.
struct CaeadInputs {
    k: [u8; 32],
    other: [u8; 32],
    nonce: [u8; 24],
    sealed: Vec<u8>,
}

impl CaeadInputs {
    fn new(stream: &mut Stream) -> Result<Self, secmp_crypto::Error> {
        let mut k = [0_u8; 32];
        stream.fill(&mut k);
        let mut other = k;
        other[0] ^= 1;
        let mut p = vec![0_u8; 4024];
        stream.fill(&mut p);
        let nonce = Nonce24::random()?;
        let nb = *nonce.as_bytes();
        let sealed = Caead::seal(&SecretBytes::from_slice(&k)?, nonce, CAEAD_AD, &p)?;
        Ok(Self {
            k,
            other,
            nonce: nb,
            sealed,
        })
    }

    /// `sealed` with byte `at` flipped.
    fn tampered(&self, at: usize) -> Vec<u8> {
        let mut t = self.sealed.clone();
        if let Some(b) = t.get_mut(at) {
            *b ^= 1;
        }
        t
    }

    /// `(K_enc, COM)` of `key` (spec §3.4, recomputed from the public `hkdf_expand`).
    fn derived(&self, key: &[u8; 32]) -> Result<([u8; 32], [u8; COM_LEN]), secmp_crypto::Error> {
        let okm = hkdf_expand::<64>(key, Label::Commit, &[&self.nonce])?;
        let (k_enc, com) = okm
            .expose_secret()
            .split_first_chunk::<32>()
            .ok_or(secmp_crypto::Error::Rejected)?;
        let com: [u8; COM_LEN] = com.try_into().map_err(|_| secmp_crypto::Error::Rejected)?;
        Ok((*k_enc, com))
    }
}

/// `derive` alone: class 0 wrong key, class 1 right key.
fn caead_derive(n: usize, k: usize, stream: &mut Stream) -> Result<Samples, secmp_crypto::Error> {
    let io = CaeadInputs::new(stream)?;
    Ok(measure(
        n,
        k,
        stream,
        |c, _| SecretBytes::<32>::from_slice(if c == 0 { &io.other } else { &io.k }).ok(),
        |key| {
            if let Some(key) = key {
                // the inner `black_box` materialises the derived key and `COM`
                black_box(black_box(Caead::derive_kat(key, black_box(&io.nonce))).is_ok());
            }
        },
    ))
}

/// XChaCha20-Poly1305 `decrypt_inout_detached` alone on the same tampered `C` (byte 100 of `COM ‖ C`): class 0
/// with `K_enc` of the wrong key, class 1 with `K_enc` of the right key; both reject.
fn caead_aead_reject(
    n: usize,
    k: usize,
    stream: &mut Stream,
) -> Result<Samples, secmp_crypto::Error> {
    let io = CaeadInputs::new(stream)?;
    let (k_enc_other, _) = io.derived(&io.other)?;
    let (k_enc_k, _) = io.derived(&io.k)?;
    let tampered = io.tampered(100);
    let c = tampered.get(COM_LEN..).unwrap_or_default();
    let (body, tag) = c.split_at(c.len().saturating_sub(AEAD_TAG_LEN));
    let tag = Tag::try_from(tag).map_err(|_| secmp_crypto::Error::Rejected)?;
    let xnonce = XNonce::from(io.nonce);
    Ok(measure(
        n,
        k,
        stream,
        |c, _| {
            let k_enc = if c == 0 { &k_enc_other } else { &k_enc_k };
            (
                SecretBytes::<32>::from_slice(k_enc).ok(),
                RefCell::new(body.to_vec()),
            )
        },
        |(key, buf)| {
            if let (Some(key), Ok(mut buf)) = (key, buf.try_borrow_mut()) {
                let aead = XChaCha20Poly1305::new(key.expose_secret().into());
                black_box(
                    aead.decrypt_inout_detached(&xnonce, CAEAD_AD, buf.as_mut_slice().into(), &tag)
                        .is_ok(),
                );
            }
        },
    ))
}

/// The `COM` comparison alone (`expected.ct_eq(com)` as in `Caead::open`), batched: class 0 `expected` of the
/// wrong key (mismatch), class 1 `expected` of the right key (match).
fn caead_com_compare(
    n: usize,
    k: usize,
    stream: &mut Stream,
) -> Result<Samples, secmp_crypto::Error> {
    let io = CaeadInputs::new(stream)?;
    let (_, expected_other) = io.derived(&io.other)?;
    let (_, expected_k) = io.derived(&io.k)?;
    let com: [u8; COM_LEN] = io
        .sealed
        .get(..COM_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(secmp_crypto::Error::Rejected)?;
    Ok(measure(
        n,
        k,
        stream,
        |c, _| (if c == 0 { expected_other } else { expected_k }, com),
        |(expected, com)| {
            for _ in 0..256 {
                black_box(black_box(*expected).ct_eq(black_box(com)));
            }
        },
    ))
}

/// `Caead::open` with the right key in both classes: class 0 tampered at byte 100, class 1 at byte 300 (`COM`
/// matches, the tag fails in both).
fn caead_open_reject_samekey(
    n: usize,
    k: usize,
    stream: &mut Stream,
) -> Result<Samples, secmp_crypto::Error> {
    let io = CaeadInputs::new(stream)?;
    let at_100 = io.tampered(100);
    let at_300 = io.tampered(300);
    Ok(measure(
        n,
        k,
        stream,
        |c, _| {
            let ct = if c == 0 { &at_100 } else { &at_300 };
            (SecretBytes::<32>::from_slice(&io.k).ok(), ct.clone())
        },
        |(key, ct)| {
            if let Some(key) = key {
                black_box(Caead::open(key, &io.nonce, CAEAD_AD, black_box(ct)).is_ok());
            }
        },
    ))
}

fn sas(n: usize, k: usize, stream: &mut Stream) -> Result<Samples, secmp_crypto::Error> {
    let mut fixed = [[0_u8; 32]; 2];
    stream.fill(&mut fixed[0]);
    stream.fill(&mut fixed[1]);
    let mut random = vec![[0_u8; 64]; n.saturating_mul(k)];
    for r in &mut random {
        stream.fill(r);
    }
    let fixed_a = Fingerprint::from_bytes(&fixed[0])?;
    let fixed_b = Fingerprint::from_bytes(&fixed[1])?;
    let random: Vec<(Fingerprint, Fingerprint)> = random
        .iter()
        .map(|r| {
            let (a, b) = r.split_at(32);
            Ok((Fingerprint::from_bytes(a)?, Fingerprint::from_bytes(b)?))
        })
        .collect::<Result<_, secmp_crypto::Error>>()?;
    Ok(measure(
        n,
        k,
        stream,
        |c, i| {
            if c == 0 {
                (fixed_a, fixed_b)
            } else {
                random.get(i).copied().unwrap_or((fixed_a, fixed_b))
            }
        },
        |(a, b)| {
            black_box(SafetyNumber::new(black_box(a), black_box(b)));
        },
    ))
}

fn run(rules: Rules) -> Result<(Clock, Vec<Outcome>), secmp_crypto::Error> {
    let clock = Clock::probe();
    let scale: usize = std::env::var("SECMP_CT_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let mut stream = Stream::new()?;
    let n = 1_000_000_usize.checked_div(scale).unwrap_or(1);
    let n_sas = 20_000_usize.checked_div(scale).unwrap_or(1);
    let targets = [
        Target {
            name: "control_variable_time_compare",
            classes: ["tag differs in byte 0", "tag differs in byte 31"],
            samples: n,
            control: true,
            run: |n, k, s| Ok(tag_compare(n, k, s, true)),
        },
        Target {
            name: "tag_compare",
            classes: ["tag differs in byte 0", "tag differs in byte 31"],
            samples: n,
            control: false,
            run: |n, k, s| Ok(tag_compare(n, k, s, false)),
        },
        Target {
            name: "msg_open_reject",
            classes: ["tag wrong in its first byte", "tag wrong in its last byte"],
            samples: n,
            control: false,
            run: msg_open_reject,
        },
        Target {
            name: "caead_open_reject",
            classes: [
                "wrong key (COM and tag fail)",
                "right key, tampered at byte 100 (COM ok, tag fails)",
            ],
            samples: n,
            control: false,
            run: caead_open_reject,
        },
        Target {
            name: "sas",
            classes: ["fixed fingerprint pair", "random fingerprint pairs"],
            samples: n_sas,
            control: false,
            run: sas,
        },
        Target {
            name: "caead_derive",
            classes: ["wrong key", "right key"],
            samples: n,
            control: false,
            run: caead_derive,
        },
        Target {
            name: "caead_aead_reject",
            classes: [
                "K_enc of the wrong key, same tampered C",
                "K_enc of the right key, same tampered C",
            ],
            samples: n,
            control: false,
            run: caead_aead_reject,
        },
        Target {
            name: "caead_com_compare",
            classes: ["COM mismatch (wrong key)", "COM match (right key)"],
            samples: n,
            control: false,
            run: caead_com_compare,
        },
        Target {
            name: "caead_open_reject_samekey",
            classes: [
                "right key, tampered at byte 100",
                "right key, tampered at byte 300",
            ],
            samples: n,
            control: false,
            run: caead_open_reject_samekey,
        },
    ];
    let mut out = Vec::new();
    for target in targets {
        out.push(evaluate(target, &mut stream, &clock, rules)?);
    }
    Ok((clock, out))
}

fn main() -> ExitCode {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ct-report.json");
    let Some(rules) = Rules::from_expect() else {
        // written for the gate to print; the bench itself may not print (docs/06 §2)
        let error = "{\"error\":\"CT_THRESHOLDS / CT_RESOLUTION_MAX_FRACTION not readable from xtask/src/expect.rs\"}";
        let _ = std::fs::write(path, error);
        return ExitCode::FAILURE;
    };
    let Ok((clock, outcomes)) = run(rules) else {
        return ExitCode::FAILURE;
    };
    let json = format!(
        "{{\"thresholds\":{},\"sign\":\"{SIGN}\",\"clock\":{},\"results\":[{}]}}",
        rules.json(),
        clock.json(),
        outcomes
            .iter()
            .map(|o| o.json(&clock))
            .collect::<Vec<_>>()
            .join(",")
    );
    if std::fs::write(path, json).is_err() {
        return ExitCode::FAILURE;
    }
    if outcomes.iter().all(|o| o.verdict.passed()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
