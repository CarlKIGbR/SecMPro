// SPDX-License-Identifier: AGPL-3.0-or-later
//! dudect-style constant-time tests (docs/06 §2, §4; M1 acceptance "constant-time test (dudect-style) for tag
//! comparison shows no leak"; Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", 2017), with the
//! instrument of ADR-038 and the verdict of ADR-041.
//!
//! For each target, two input classes are measured in random interleaving; Welch's t-statistic is computed on
//! the raw timings and on timings cropped at several percentiles of the pooled distribution. A deliberately
//! variable-time comparison is measured as a **positive control**: it must be detected, otherwise the harness is
//! not sensitive enough and the run fails. An inline **A/A control** repeats every target with the same inputs
//! under both labels: it must stay quiet, otherwise the harness or the runner is unsound. The **sensitivity
//! control** `min_leak_control` (ADR-041 Amendment 1 (2)) measures the smallest leak the gate must see — the work
//! of a 32-byte comparison that exits one byte early for class 1, in one out-of-line function whose instruction
//! stream is the same for both classes (ADR-042 Amendment 1) — and must reach the effect floor with class 0 the
//! slower, otherwise the run is `CONTROL_FAIL`; it records the gate's sensitivity per run.
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
//! SecMP-TR targets (M3 plan D9): `RatchetState::decrypt_with` rejecting a cell, on one fixed receiver state with a
//! current receiving chain (A → B, two messages delivered; the states built with `FixedEntropy` from the bench's
//! stream). The state lives outside the timed input: every call takes it, decrypts and puts back the unchanged state
//! of the refusal (an accepted cell aborts the bench). The cells of both classes are built from A's next, not yet
//! delivered cell of that chain (n = 2):
//! - `tr_decrypt_reject_hdr_key`: the header sealed under a wrong key vs sealed under `hk_r` with the last byte of
//!   the header tag flipped (no candidate key opens it in either class; spec §7.4 trial decryption);
//! - `tr_decrypt_reject_body_tag`: the honest header under `hk_r`, the body tag wrong in byte 0 vs byte 31 (the body
//!   MAC rejects);
//! - `tr_decrypt_reject_ct_pq`: a header under `hk_r` whose `ct_pq` differs from `last_ct_r` in byte 0 vs byte 1087,
//!   the body unchanged (the KEM-constancy check rejects).
//!
//! The same-content control `same_content_control` (ADR-042 Amendment 2) is measured and judged like a target, after
//! the TR targets: `tr_decrypt_reject` on the `tr_decrypt_reject_body_tag` fixture (the largest cell) with identical
//! contents in both classes — its class-1 cell, the body tag wrong in byte 31 — through the real per-class
//! preparation path (`blend`). It sees what neither the inline A/A control (one class under both labels) nor the A/A′
//! control (no `blend`) can: a preparation path that differs by class. If it FAILs, the run is `CONTROL_FAIL`.
//!
//! The A/A′ placement control `aa_prime_control` (ADR-042 (2), M2 review F6) is measured and judged like a target:
//! `MsgEncrypt::open` rejecting a tag wrong in its last byte with identical contents in both classes, class 0 copied
//! from one source allocation and class 1 from another — the one deliberate exception to the source rule below. If it
//! FAILs (a reproduced shift at or above the effect floor), the run is `CONTROL_FAIL`.
//!
//! Sign: `t = (mean(class 0) − mean(class 1)) / SE` (Welch), so **`t < 0` means class 0 is faster**; the report
//! states it once (`sign`) and names both classes of every target (`class0`, `class1`).
//!
//! The classes may differ only in their contents, never in where the inputs live: every measured input is a
//! fresh copy made by `prepare` (by value or in a new allocation, identical sequence for both classes), so buffer
//! placement cannot correlate with the class (M1 review F7); the fresh copies are made from one common source
//! per target (F9, `f7b3066`; the targets section below); and the preparation runs the same code for both classes
//! (`blend`, ADR-042 Amendment 2).
//!
//! ADR-038 (the instrument):
//! - **Timer (1).** Each call is timed with the CPU counter — `rdtscp` on `x86_64`, `cntvct_el0` on `aarch64`,
//!   `Instant` elsewhere (named in the report). The tick length is calibrated against `Instant` over 200 ms. The
//!   reported resolution is the smallest step between distinct values of 10⁶ back-to-back `now_ticks()`
//!   differences (the smallest non-zero difference, the cost of one read, is `overhead`); it stays in the report
//!   for comparison. Samples stay in ticks; the report gives ticks and ns.
//! - **Batching (3).** One sample is `k` consecutive calls on `k` inputs of the same class, all prepared before
//!   the window opens, timed as one batch; `k` is the smallest integer with `margin · quantum ≤ fraction · k · m`
//!   for the median call duration `m` (a 10 % margin: `k = ceil(110 · quantum / m)`, and 1 on a fine counter). The
//!   calibration (no verdict; M1 review F8) runs a warm-up pass whose timings are discarded, then
//!   `CALIBRATION_SAMPLES` single calls for a first estimate of `k`; where that is above 1, `k` is derived from the
//!   median of *batches* of `k` calls, re-derived until the batch median reaches the target, at most
//!   `CALIBRATION_ROUNDS` times. Every median of these rules is the smaller of the two class medians
//!   (`median_ticks`). The quantum of the calibration is the coarsest lattice observed before the first
//!   measurement (ADR-041 Amendment 2 (1)): the clock's effective quantum (below), the median gap of the clock
//!   probe's lattice — also where the probe saw too few runs to recognise one — and the lattice of the calibration's
//!   own samples (`batch_quantum` in the report's calibration); so a sample of `k` calls spans at least
//!   `CT_MIN_REALISED_QUANTA` quanta of that lattice. A measurement's realised count uses its own effective quantum.
//!   If a measurement of the pair realises fewer than `CT_MIN_REALISED_QUANTA` quanta, `k` is derived again from
//!   that measurement's effective quantum and per-call duration and the pair is measured once more (Amendment 2 (2):
//!   `requantised`, `k_initial` and `k` in the report; every measurement records the `k` it was taken with). A pair
//!   still short of the minimum is NOT MEASURABLE (Amendment 2 (3)); so is a target that would need
//!   `k > CT_MAX_BATCH`, whose quantum is unknown or that is still short of the target after the rounds.
//!
//! ADR-041 (the verdict):
//! - **Effective quantum `q_eff`.** The spacing of the lattice the samples lie on, measured from the data
//!   (`lattice_spacing`): of the samples between the 5th and the 95th percentile, the distinct values are grouped
//!   into runs of consecutive integers (a lattice point of spacing `q` shows as one value or as two adjacent ones,
//!   `⌊jq⌋` and `⌈jq⌉`); if there are at least `LATTICE_MIN_RUNS` runs and at least 90 % of the gaps between run
//!   starts lie within half and one and a half times their median, `q_eff` is the mean of those gaps (≈ 24.5 ticks
//!   on the Linux runners whose counter reports a 1-tick resolution, M2 `ct-verdict` evidence); dense or
//!   irregular data show no lattice. A measurement's `q_eff` is its own lattice spacing where its samples show one,
//!   else the clock's (`Clock::quantum`: the lattice of `LATTICE_SAMPLES` timings of a fixed workload, else the
//!   reported resolution), never below the reported resolution.
//! - **Effect floor** (Amendment 1 (1)). `max(CT_EFFECT_FLOOR_QUANTA × q_eff, CT_EFFECT_FLOOR_NS)`, in ticks of
//!   the measurement (`Rules::floor_ticks`): one effective quantum, but never less than 10 ns, so that fine- and
//!   coarse-timer runners reach the same verdict. It applies to the per-sample Δ (a batch of `k` calls), the same
//!   statistic as ADR-041 (2).
//! - **Verdict.** Every non-control target is measured twice (fresh class sequences and inputs from the stream).
//!   Per crop (raw and the five percentiles), a shift is *reproduced* if |t| > `CT_THRESHOLDS` in both measurements
//!   with the same sign, and *relevant* if in both measurements the cropped class means differ by at least the
//!   effect floor. FAIL if a crop is reproduced and relevant; `SUB_FLOOR_SHIFT` (informative, passes) if a crop is
//!   reproduced but no reproduced crop is relevant; PASS otherwise. The positive control is measured once and must
//!   exceed `CT_THRESHOLDS` (FAIL otherwise). The inline A/A control measures every target once more with class-0
//!   inputs under both labels; if any of its crops exceeds `CT_AA_MAX_T`, the run is `CONTROL_FAIL`. The
//!   sensitivity control (Amendment 1 (2)) is measured once after the A/A control with `tag_compare`'s batch size
//!   and sample count; if its raw Δ (class 0 slower) is below its effect floor, or it cannot be measured, the run is
//!   `CONTROL_FAIL`; so it is if the A/A′ placement control FAILs (ADR-042). A `CONTROL_FAIL` run fails the gate and
//!   gives no target verdict (every target shows
//!   `CONTROL_FAIL`). `NOT_MEASURABLE` fails the gate as before. A clock without a positive, finite tick length
//!   makes every target NOT MEASURABLE (the floor in ticks needs it).
//! - The parameters are read from `xtask/src/expect.rs` (`CT_THRESHOLDS`, `CT_RESOLUTION_MAX_FRACTION`,
//!   `CT_MAX_BATCH`, `CT_BATCH_MARGIN`, `CT_MIN_REALISED_QUANTA`, `CT_EFFECT_FLOOR_QUANTA`, `CT_EFFECT_FLOOR_NS`,
//!   `CT_AA_MAX_T`, `CT_SAMPLES`, `CT_SAS_SAMPLES`) — this file contains no copy of them — and echoed in the report,
//!   which the gate checks; the gate also re-derives every verdict from the report (M2 review C3).
//!
//! The report carries the clock (arch, Linux clocksource, timer, tick, reported resolution, overhead, the clock's
//! lattice and quantum), the run verdict and, per target, `k`, the calibration, both measurements (per crop: n,
//! class means, Δ in ticks, in `q_eff` and in effect floors, pooled sd, t; the class medians, the realised quanta,
//! `q_eff` and where it came from, the effect floor, per-class percentiles), `t1`/`t2` at the first measurement's
//! maximum, the deciding crop and the A/A measurement; and the sensitivity control (`k`, sample count, floor, raw
//! Δ, whether it reached the floor, its measurement).
//!
//! Run by `cargo xtask step ct` (ci-full) as `cargo bench -p secmp-testkit --features kat --bench ct` (ADR-042 moved
//! the bench here from `secmp-crypto`, so that it can measure `secmp-proto` too); the results are written to
//! `target/ct-report.json` and the exit status is the verdict. `SECMP_CT_SCALE`, a divisor of every sample count
//! (default 1), shortens quick local runs; the report then carries `secmp_ct_scale`, which the gate refuses (M2
//! review C3 (c)), and the gate unsets the variable for its own run.

// ADR-038 (1): the cycle-counter read in `now_ticks` is the only `unsafe` code in the bench. `xtask policy`
// sanctions this attribute at exactly this path (`expect::UNSAFE_EXEMPT_ROOT`).
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::hint::black_box;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secmp_crypto::{
    AEAD_TAG_LEN, Aead, BODY_LEN, COM_LEN, Caead, Fingerprint, Label, MSG_TAG_LEN, MlKem768Dk,
    MsgEncrypt, Nonce24, SafetyNumber, SecretBytes, X25519Secret, Zeroizing, hkdf_expand,
};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::sizes::{HDR_CT_LEN, NONCE_LEN};
use secmp_proto::tr::content::dummy;
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::HeaderV1;
use secmp_proto::{Decode, Encode};
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
/// Batched calibration rounds at most (M1 review F8); a target still short of the target after them is NOT
/// MEASURABLE.
const CALIBRATION_ROUNDS: usize = 3;
/// Timings of the fixed workload for the clock's lattice (ADR-041 (2)).
const LATTICE_SAMPLES: usize = 100_000;
/// Iterations of the fixed workload (a few thousand cycles: many lattice points wide on every counter).
const LATTICE_WORK: u64 = 2_000;
/// Runs of consecutive values needed before a lattice is recognised (fewer: no lattice).
const LATTICE_MIN_RUNS: usize = 4;

// ---- parameters (ADR-038 (3), ADR-041): read from xtask/src/expect.rs --------------------------------------------

/// The file that fixes the gate's parameters (ADR-038: "not in code that a later commit can tune silently").
const EXPECT_RS: &str = include_str!("../../../xtask/src/expect.rs");

/// The verdict and instrument parameters.
#[derive(Clone, Copy)]
struct Rules {
    /// ADR-041 (1): the |t| threshold of a reproduced shift; the positive control must exceed it.
    pass: f64,
    /// The quantum may be at most this fraction of a sample's median (batching restores it).
    max_resolution_fraction: f64,
    /// The largest batch size; a target that needs more is NOT MEASURABLE.
    max_batch: u32,
    /// The calibration aims at `margin` times the resolution bound (10 %: 110 quanta at the 1 % fraction).
    margin: f64,
    /// A measurement whose realised median is below this many quanta is NOT MEASURABLE.
    min_realised_quanta: u64,
    /// ADR-041 (2): a reproduced shift fails only if |Δ| ≥ this many effective quanta (and ≥ `effect_floor_ns`).
    effect_floor: f64,
    /// ADR-041 Amendment 1 (1): the absolute part of the effect floor, in ns.
    effect_floor_ns: f64,
    /// ADR-041 (3): the inline A/A control passes if every |t| is at most this.
    aa_max_t: f64,
    /// Samples per measurement of every target but `sas` (M2 review C3 (c)).
    samples: usize,
    /// Samples per measurement of `sas`.
    sas_samples: usize,
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

/// The value of `name` in `EXPECT_RS`, parsed (digit separators `_` removed first).
fn parsed<T: std::str::FromStr>(name: &str) -> Option<T> {
    const_value(name)?.replace('_', "").parse().ok()
}

impl Rules {
    fn from_expect() -> Option<Self> {
        let rules = Self {
            pass: parsed("CT_THRESHOLDS")?,
            max_resolution_fraction: parsed("CT_RESOLUTION_MAX_FRACTION")?,
            max_batch: parsed("CT_MAX_BATCH")?,
            margin: parsed("CT_BATCH_MARGIN")?,
            min_realised_quanta: parsed("CT_MIN_REALISED_QUANTA")?,
            effect_floor: parsed("CT_EFFECT_FLOOR_QUANTA")?,
            effect_floor_ns: parsed("CT_EFFECT_FLOOR_NS")?,
            aa_max_t: parsed("CT_AA_MAX_T")?,
            samples: parsed("CT_SAMPLES")?,
            sas_samples: parsed("CT_SAS_SAMPLES")?,
        };
        let sane = rules.pass > 0.0
            && rules.max_resolution_fraction > 0.0
            && rules.max_resolution_fraction < 1.0
            && rules.max_batch >= 1
            && rules.margin >= 1.0
            && rules.min_realised_quanta >= 1
            && rules.effect_floor > 0.0
            && rules.effect_floor_ns > 0.0
            && rules.effect_floor_ns.is_finite()
            && rules.aa_max_t > 0.0
            && rules.samples > 0
            && rules.sas_samples > 0;
        sane.then_some(rules)
    }

    /// The effect floor of a measurement with effective quantum `q_eff` (ticks) on a clock with tick length
    /// `tick_ns`, in ticks (ADR-041 (2) with Amendment 1 (1)): `max(effect_floor · q_eff, effect_floor_ns)`.
    fn floor_ticks(self, q_eff: f64, tick_ns: f64) -> f64 {
        (self.effect_floor * q_eff).max(self.effect_floor_ns / tick_ns)
    }

    /// The batch size for a target with median call duration `per_call_ticks` on a timer with quantum
    /// `quantum_ticks`: the smallest `k ≤ max_batch` with `margin · quantum ≤ fraction · k · per_call` (ADR-038
    /// (3) as amended: `k = ceil(110 · quantum / median)`), or `None` if there is none.
    fn batch(self, quantum_ticks: f64, per_call_ticks: f64) -> Option<u32> {
        let target = self.margin * quantum_ticks;
        (1..=self.max_batch)
            .find(|k| target <= self.max_resolution_fraction * f64::from(*k) * per_call_ticks)
    }

    /// Whether a calibration batch with median `median_ticks` reaches the target with the margin:
    /// `margin · quantum ≤ fraction · median`.
    fn resolved(self, quantum_ticks: f64, median_ticks: u64) -> bool {
        self.margin * quantum_ticks <= self.max_resolution_fraction * f64_of(median_ticks)
    }

    /// Whether a measurement with class median `median_ticks` is too coarse to judge: fewer than
    /// `min_realised_quanta` effective quanta (NOT MEASURABLE; ADR-038 (3) as amended).
    fn too_coarse(self, quantum_ticks: f64, median_ticks: u64) -> bool {
        f64_of(median_ticks) < f64_of(self.min_realised_quanta) * quantum_ticks
    }

    fn json(self) -> String {
        format!(
            "{{\"pass\":{},\"max_resolution_fraction\":{},\"max_batch\":{},\"batch_margin\":{},\"min_realised_quanta\":{},\"effect_floor_quanta\":{},\"effect_floor_ns\":{},\"aa_max_t\":{},\"samples\":{},\"sas_samples\":{}}}",
            self.pass,
            self.max_resolution_fraction,
            self.max_batch,
            self.margin,
            self.min_realised_quanta,
            self.effect_floor,
            self.effect_floor_ns,
            self.aa_max_t,
            self.samples,
            self.sas_samples
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

/// `n` as `f64` (sample counts, exact in this range).
fn f64_of_usize(n: usize) -> f64 {
    f64_of(u64::try_from(n).unwrap_or(u64::MAX))
}

/// What `lattice` found in a set of sample values (ADR-041 (2); method in the module documentation).
#[derive(Clone, Copy, Default)]
struct Lattice {
    /// Runs of consecutive values among the distinct values of the central 90 %.
    runs: usize,
    /// The median gap between run starts, in ticks.
    median_gap: u64,
    /// The share of those gaps within half and one and a half times the median.
    regular: f64,
    /// The lattice spacing (`None`: too few samples, dense, or irregular).
    spacing: Option<f64>,
}

/// The lattice of `sorted` sample values (ADR-041 (2)).
fn lattice(sorted: &[u64]) -> Lattice {
    let mut found = Lattice::default();
    let n = sorted.len();
    if n < 1_000 {
        return found;
    }
    let lo = n.saturating_mul(5) / 100;
    let hi = n.saturating_mul(95) / 100;
    let Some(central) = sorted.get(lo..=hi.min(n.saturating_sub(1))) else {
        return found;
    };
    let mut central = central.to_vec();
    central.dedup();
    // starts of the runs of consecutive values
    let starts: Vec<u64> = central
        .iter()
        .zip(std::iter::once(None).chain(central.iter().map(Some)))
        .filter(|(v, prev)| prev.is_none_or(|p| p.checked_add(1) != Some(**v)))
        .map(|(v, _)| *v)
        .collect();
    found.runs = starts.len();
    let gaps: Vec<u64> = starts
        .windows(2)
        .filter_map(|w| match w {
            [a, b] => Some(b.saturating_sub(*a)),
            _ => None,
        })
        .collect();
    if gaps.is_empty() {
        return found;
    }
    found.median_gap = median_of(gaps.clone());
    let (low, high) = (
        f64_of(found.median_gap) * 0.5,
        f64_of(found.median_gap) * 1.5,
    );
    let regular: Vec<f64> = gaps
        .iter()
        .map(|g| f64_of(*g))
        .filter(|g| *g >= low && *g <= high)
        .collect();
    found.regular = f64_of_usize(regular.len()) / f64_of_usize(gaps.len());
    if found.runs >= LATTICE_MIN_RUNS && found.median_gap >= 2 && found.regular >= 0.9 {
        found.spacing = Some(regular.iter().sum::<f64>() / f64_of_usize(regular.len()));
    }
    found
}

/// The lattice spacing of `sorted` sample values, if they show one.
fn lattice_spacing(sorted: &[u64]) -> Option<f64> {
    lattice(sorted).spacing
}

/// A fixed workload for the clock's lattice: `LATTICE_WORK` dependent multiply-adds.
fn workload() {
    let mut x = 1_u64;
    for i in 0..LATTICE_WORK {
        x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
    }
    black_box(x);
}

/// Where the Linux clocksource is published (sysfs).
const CLOCKSOURCE_DIR: &str = "/sys/devices/system/clocksource/clocksource0";

/// The instrument (ADR-038 (1), (3); ADR-041 (2)): which counter, its calibrated tick length, its reported
/// resolution and read overhead, the lattice its timings show, and the Linux clocksource `Instant` runs on.
struct Clock {
    current_clocksource: String,
    available_clocksource: String,
    /// ns per tick, measured against `Instant` over `CALIBRATION`.
    tick_ns: f64,
    /// Ticks counted during the calibration, and its duration by `Instant` (ns).
    calibration_ticks: u64,
    calibration_ns: f64,
    /// The reported resolution: the smallest step between distinct back-to-back differences, in ticks (`None` if
    /// no two distinct differences occurred).
    resolution_ticks: Option<u64>,
    /// The smallest non-zero back-to-back difference (the cost of one read), in ticks.
    overhead_ticks: Option<u64>,
    /// The median back-to-back difference, in ticks.
    median_delta_ticks: Option<u64>,
    /// The lattice of `LATTICE_SAMPLES` timings of `workload`.
    lattice: Lattice,
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
        // reported resolution: back-to-back reads
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
        // the lattice of a fixed workload's timings
        let mut timings: Vec<u64> = (0..LATTICE_SAMPLES)
            .map(|_| {
                let a = now_ticks();
                workload();
                now_ticks().saturating_sub(a)
            })
            .collect();
        timings.sort_unstable();
        Self {
            current_clocksource: read("current_clocksource"),
            available_clocksource: read("available_clocksource"),
            tick_ns,
            calibration_ticks,
            calibration_ns,
            resolution_ticks,
            overhead_ticks,
            median_delta_ticks,
            lattice: lattice(&timings),
        }
    }

    /// The clock's effective quantum in ticks: its lattice spacing, never below the reported resolution; the
    /// reported resolution where there is no lattice; `None` if neither is known.
    fn quantum(&self) -> Option<f64> {
        match (self.resolution_ticks.map(f64_of), self.lattice.spacing) {
            (Some(r), Some(l)) => Some(r.max(l)),
            (r, l) => r.or(l),
        }
    }

    /// The tick length in ns if the calibration produced a positive, finite one (the effect floor in ticks needs
    /// it; without it every target is NOT MEASURABLE and the sensitivity control fails).
    fn tick(&self) -> Option<f64> {
        (self.tick_ns.is_finite() && self.tick_ns > 0.0).then_some(self.tick_ns)
    }

    fn ns(&self, ticks: Option<u64>) -> Option<f64> {
        ticks.map(|t| f64_of(t) * self.tick_ns)
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
            "resolution_ns": self.ns(self.resolution_ticks),
            "overhead_ticks": self.overhead_ticks,
            "overhead_ns": self.ns(self.overhead_ticks),
            "median_delta_ticks": self.median_delta_ticks,
            "median_delta_ns": self.ns(self.median_delta_ticks),
            "lattice_ticks": self.lattice.spacing,
            "lattice_probe": {
                "runs": self.lattice.runs,
                "median_gap": self.lattice.median_gap,
                "regular": self.lattice.regular,
            },
            "q_eff_ticks": self.quantum(),
            "q_eff_ns": self.quantum().map(|q| q * self.tick_ns),
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

    /// `mean(class 0) − mean(class 1)`, in ticks (ADR-041 (2)).
    fn delta(&self) -> f64 {
        let [m0, m1] = self.mean;
        m0 - m1
    }

    /// The pooled standard deviation of the two classes.
    fn pooled_sd(&self) -> f64 {
        let [n0, n1] = self.n;
        let [s0, s1] = self.m2;
        if n0 + n1 < 3.0 {
            return 0.0;
        }
        ((s0 + s1) / (n0 + n1 - 2.0)).sqrt()
    }

    /// `{"n0":…,"n1":…,"mean0":…,"mean1":…,"delta":…,"delta_q":…,"delta_floor":…,"sd":…,"t":…}` (`delta` in
    /// ticks, `delta_q` in effective quanta, `delta_floor` in effect floors of `floor` ticks).
    fn json(&self, q_eff: f64, floor: f64) -> String {
        let [n0, n1] = self.n;
        let [m0, m1] = self.mean;
        let delta = self.delta();
        format!(
            "{{\"n0\":{n0},\"n1\":{n1},\"mean0\":{m0:.3},\"mean1\":{m1:.3},\"delta\":{delta:.4},\"delta_q\":{:.4},\"delta_floor\":{:.4},\"sd\":{:.3},\"t\":{:.3}}}",
            delta / q_eff,
            delta / floor,
            self.pooled_sd(),
            self.t()
        )
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

/// Set while the inline A/A control runs (ADR-041 (3)): `measure` gives both labels class-0 inputs.
static AA_PASS: AtomicBool = AtomicBool::new(false);

/// Measure `n` samples of `k` calls each (ADR-038 (3); `k = 1` on a fine counter). For sample `i` of class `c`,
/// the `k` inputs `prepare(c, i·k + j)` are built before the window opens (dudect: inputs are prepared before
/// measuring; the previous sample's inputs are dropped first, so both classes see the same allocation sequence),
/// then the `k` calls `op(&input)` are timed as one batch. The class sequence is per sample. During the A/A
/// control every sample is prepared as class 0 (the labels stay random).
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
    let aa = AA_PASS.load(Ordering::Relaxed);
    let input_class = |c: usize| if aa { 0 } else { c };
    // warm-up
    for (i, c) in classes.iter().take(n / 100).enumerate() {
        op(&prepare(input_class(*c), i));
    }
    let mut batch: Vec<T> = Vec::with_capacity(k);
    for (i, c) in classes.into_iter().enumerate() {
        batch.clear();
        for j in 0..k {
            batch.push(black_box(prepare(
                input_class(c),
                i.saturating_mul(k).saturating_add(j),
            )));
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

/// The median of `values` (0 if empty).
fn median_of(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or(0)
}

/// The median sample duration a target's resolution rules use, in ticks: the smaller of the two class medians,
/// so that the resolution holds for each class. For every target whose classes take the same time it equals the
/// pooled median up to noise; for the variable-time control, whose pooled distribution is a 50/50 mixture of a
/// fast and a slow class, the pooled median falls into either mode from run to run (M2 report, F8), while the
/// smaller class median is stable.
fn median_ticks(samples: &[(usize, u64)]) -> u64 {
    let class = |c: usize| {
        median_of(
            samples
                .iter()
                .filter(|(k, _)| *k == c)
                .map(|(_, x)| *x)
                .collect(),
        )
    };
    class(0).min(class(1))
}

/// The class statistics of the raw samples and of the samples below each crop percentile of the pooled
/// distribution (`sorted`: the pooled sample values, sorted).
fn analyse(samples: &[(usize, u64)], sorted: &[u64]) -> Vec<(String, Stats)> {
    let mut results = Vec::new();
    let mut raw = Stats::default();
    for (c, x) in samples {
        raw.push(*c, f64_of(*x));
    }
    results.push(("raw".to_owned(), raw));
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
        results.push((format!("p{}", permille / 10), s));
    }
    results
}

/// Percentiles (per mille) of each class's samples that the report carries for diagnosis (WEISUNG M2-2 C.4). No
/// verdict uses them.
const SHAPE_PERMILLE: [usize; 9] = [10, 50, 100, 250, 500, 750, 900, 950, 990];

/// `{"n":…,"p1":…,…,"p99":…}` of the samples of `class`, in ticks.
fn class_shape(samples: &[(usize, u64)], class: usize) -> String {
    let mut v: Vec<u64> = samples
        .iter()
        .filter(|(c, _)| *c == class)
        .map(|(_, x)| *x)
        .collect();
    v.sort_unstable();
    let percentiles: Vec<String> = SHAPE_PERMILLE
        .iter()
        .map(|permille| {
            let idx = v.len().saturating_mul(*permille) / 1000;
            let value = v
                .get(idx.min(v.len().saturating_sub(1)))
                .copied()
                .unwrap_or(0);
            format!("\"p{}\":{value}", permille / 10)
        })
        .collect();
    format!("{{\"n\":{},{}}}", v.len(), percentiles.join(","))
}

/// One measurement of one target: the class statistics per crop, its effective quantum and how finely its samples
/// (batch durations) are resolved.
struct Measurement {
    /// The batch size the measurement was taken with (ADR-041 Amendment 2 (2)).
    k: u32,
    /// Per crop (`raw`, `p50` … `p99`): the class statistics.
    crops: Vec<(String, Stats)>,
    distinct: usize,
    /// The pooled median batch duration.
    median_ticks: u64,
    /// The smaller class median (`median_ticks()`), which the realised-resolution rule uses.
    class_median_ticks: u64,
    /// The effective quantum (ADR-041 (2)) and where it came from (`samples` or `clock`).
    q_eff: f64,
    q_eff_source: &'static str,
    /// Per-class count and percentiles (`class_shape`), diagnosis only.
    shape: [String; 2],
}

impl Measurement {
    /// The measurement of `samples`, taken with batch size `k`; `clock_quantum` is the fallback effective quantum
    /// and its floor comes from the reported resolution (`reported`).
    fn of(samples: &[(usize, u64)], clock_quantum: f64, reported: Option<u64>, k: u32) -> Self {
        let mut sorted: Vec<u64> = samples.iter().map(|(_, x)| *x).collect();
        sorted.sort_unstable();
        let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
        let crops = analyse(samples, &sorted);
        let floor = reported.map_or(1.0, f64_of);
        let (q_eff, q_eff_source) = lattice_spacing(&sorted)
            .map_or((clock_quantum, "clock"), |q| (q.max(floor), "samples"));
        sorted.dedup();
        Self {
            k,
            crops,
            distinct: sorted.len(),
            median_ticks: median,
            class_median_ticks: median_ticks(samples),
            q_eff,
            q_eff_source,
            shape: [class_shape(samples, 0), class_shape(samples, 1)],
        }
    }

    /// The t of `crop` (0 if absent).
    fn t(&self, crop: &str) -> f64 {
        self.crops
            .iter()
            .find(|(k, _)| k == crop)
            .map_or(0.0, |(_, s)| s.t())
    }

    /// The largest |t| and the crop it belongs to.
    fn max(&self) -> (f64, &str) {
        self.crops.iter().fold((0.0, "raw"), |(best, at), (k, s)| {
            if s.t().abs() > best {
                (s.t().abs(), k.as_str())
            } else {
                (best, at)
            }
        })
    }

    /// The realised quanta of the class median (ADR-038 (3) with the effective quantum).
    fn realised_quanta(&self) -> f64 {
        f64_of(self.class_median_ticks) / self.q_eff
    }

    /// The raw (uncropped) class statistics.
    fn raw(&self) -> Option<&Stats> {
        self.crops.iter().find(|(k, _)| k == "raw").map(|(_, s)| s)
    }

    fn json(&self, clock: &Clock, rules: Rules) -> String {
        let ts: Vec<String> = self
            .crops
            .iter()
            .map(|(k, s)| format!("\"{k}\":{:.3}", s.t()))
            .collect();
        let floor = rules.floor_ticks(self.q_eff, clock.tick_ns);
        let crops: Vec<String> = self
            .crops
            .iter()
            .map(|(k, s)| format!("\"{k}\":{}", s.json(self.q_eff, floor)))
            .collect();
        let (max, at) = self.max();
        let median_ns = f64_of(self.median_ticks) * clock.tick_ns;
        format!(
            "{{\"k\":{},\"max_abs_t\":{max:.3},\"max_at\":\"{at}\",\"t\":{{{}}},\"crops\":{{{}}},\"q_eff_ticks\":{:.3},\"q_eff_source\":\"{}\",\"floor_ticks\":{floor:.3},\"floor_ns\":{:.3},\"distinct\":{},\"median_ticks\":{},\"median_ns\":{median_ns:.1},\"class_median_ticks\":{},\"realised_quanta\":{:.1},\"shape\":{{\"class0\":{},\"class1\":{}}}}}",
            self.k,
            ts.join(","),
            crops.join(","),
            self.q_eff,
            self.q_eff_source,
            floor * clock.tick_ns,
            self.distinct,
            self.median_ticks,
            self.class_median_ticks,
            self.realised_quanta(),
            self.shape[0],
            self.shape[1]
        )
    }
}

// ---- verdict (ADR-041; NOT MEASURABLE per ADR-038 (3)) --------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    /// A reproduced shift below the effect floor (informative; passes).
    SubFloorShift,
    Fail,
    NotMeasurable,
    /// The run's inline A/A control failed: no target verdict.
    ControlFail,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::SubFloorShift => "SUB_FLOOR_SHIFT",
            Self::Fail => "FAIL",
            Self::NotMeasurable => "NOT_MEASURABLE",
            Self::ControlFail => "CONTROL_FAIL",
        }
    }

    fn passed(self) -> bool {
        matches!(self, Self::Pass | Self::SubFloorShift)
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
    /// The batch size of the measurements (`None`: NOT MEASURABLE); after a re-batch, the re-derived one.
    k: Option<u32>,
    /// The quantum the batch size was derived with (`None`: the clock has no quantum).
    batch_quantum: Option<BatchQuantum>,
    /// Set when a measurement of the first pair realised too few quanta and the pair was measured again (`evaluate`).
    requantised: Option<Requantised>,
}

/// The quantum of the batch-size rules (ADR-041 Amendment 2 (1)): the coarsest lattice observed before the first
/// measurement.
#[derive(Clone, Copy)]
struct BatchQuantum {
    /// The clock's effective quantum (`Clock::quantum`).
    clock: f64,
    /// The median gap of the clock probe's lattice, in ticks, also where it saw too few runs to recognise one.
    clock_gap: u64,
    /// The coarsest lattice spacing the calibration's own samples showed, if any.
    samples: Option<f64>,
}

impl BatchQuantum {
    /// The coarsest of the three, in ticks.
    fn ticks(self) -> f64 {
        self.clock
            .max(f64_of(self.clock_gap))
            .max(self.samples.unwrap_or(0.0))
    }

    fn json(self) -> String {
        format!(
            "{{\"clock_q_eff_ticks\":{:.3},\"clock_lattice_gap_ticks\":{},\"samples_lattice_ticks\":{},\"ticks\":{:.3}}}",
            self.clock,
            self.clock_gap,
            self.samples
                .map_or_else(|| "null".to_owned(), |q| format!("{q:.3}")),
            self.ticks()
        )
    }
}

/// The one re-batch of a target (ADR-041 Amendment 2 (2)).
#[derive(Clone, Copy)]
struct Requantised {
    /// The batch size of the first pair.
    k_initial: u32,
    /// The coarsest effective quantum among the measurements of that pair that realised too few quanta.
    q_eff: f64,
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
        let requantised = self.requantised.map_or_else(
            || "null".to_owned(),
            |r| {
                format!(
                    "{{\"q_eff_ticks\":{:.3},\"k_initial\":{}}}",
                    r.q_eff, r.k_initial
                )
            },
        );
        format!(
            "{{\"warmup_calls\":{},\"single_median_ticks\":{},\"single_median_ns\":{:.1},\"batch_quantum\":{},\"rounds\":[{}],\"requantised\":{requantised}}}",
            CALIBRATION_SAMPLES,
            self.single_median_ticks,
            f64_of(self.single_median_ticks) * clock.tick_ns,
            self.batch_quantum
                .map_or_else(|| "null".to_owned(), BatchQuantum::json),
            rounds.join(",")
        )
    }
}

/// The lattice spacing of a set of samples, if they show one (ADR-041 (2)).
fn sample_lattice(samples: &[(usize, u64)]) -> Option<f64> {
    let mut sorted: Vec<u64> = samples.iter().map(|(_, x)| *x).collect();
    sorted.sort_unstable();
    lattice_spacing(&sorted)
}

/// The batch size of `target` (ADR-038 (3) as amended; M1 review F8: warm-up, then `k` from the median of
/// *batches* with a 10 % margin), with the coarsest lattice observed before the first measurement (ADR-041
/// Amendment 2 (1), `BatchQuantum`; the batched rounds' samples count too): a warm-up pass whose timings are discarded;
/// single calls give the first estimate; while the median batch duration of `k` calls misses the target (`margin
/// · quantum > fraction · median`), `k` is re-derived from that batch median divided by `k` (at most
/// `CALIBRATION_ROUNDS` batched rounds; a call shorter than one quantum starts at `max_batch`). NOT MEASURABLE when
/// the quantum is unknown, when even `max_batch` calls would miss the target, or when the rounds run out.
fn calibrate(
    target: &Target,
    stream: &mut Stream,
    clock: &Clock,
    rules: Rules,
) -> Result<Calibration, secmp_crypto::Error> {
    let n = CALIBRATION_SAMPLES.min(target.samples);
    // warm-up: timings discarded
    (target.run)(n, 1, stream)?;
    let singles = (target.run)(n, 1, stream)?;
    let single_median_ticks = median_ticks(&singles);
    let mut calibration = Calibration {
        single_median_ticks,
        rounds: Vec::new(),
        k: None,
        batch_quantum: None,
        requantised: None,
    };
    let Some(clock_quantum) = clock.quantum() else {
        return Ok(calibration);
    };
    let mut quantum = BatchQuantum {
        clock: clock_quantum,
        clock_gap: clock.lattice.median_gap,
        samples: sample_lattice(&singles),
    };
    calibration.batch_quantum = Some(quantum);
    // a call shorter than one quantum (single-call median 0) is probed with the largest batch
    let first = match rules.batch(quantum.ticks(), f64_of(single_median_ticks)) {
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
        let batches = (target.run)(n, usize::try_from(k).unwrap_or(1), stream)?;
        let median = median_ticks(&batches);
        calibration.rounds.push((k, median));
        // a round's samples may show a coarser lattice than the single calls
        if let Some(q) = sample_lattice(&batches) {
            quantum.samples = Some(quantum.samples.map_or(q, |s| s.max(q)));
            calibration.batch_quantum = Some(quantum);
        }
        if rules.resolved(quantum.ticks(), median) {
            calibration.k = Some(k);
            return Ok(calibration);
        }
        // not resolved ⇒ the estimate from this batch median is larger than `k`, or none fits
        match rules.batch(quantum.ticks(), calibration.per_call_ticks()) {
            Some(next) if next > k => k = next,
            _ => return Ok(calibration),
        }
    }
    Ok(calibration)
}

/// The ADR-041 decision on two measurements: per crop, reproduced (|t| > pass in both, same sign) and relevant
/// (|Δ| ≥ the effect floor of each measurement, `Rules::floor_ticks`, in both); the verdict and the deciding crop.
fn decide(
    first: &Measurement,
    second: &Measurement,
    rules: Rules,
    tick_ns: f64,
) -> (Verdict, Option<String>) {
    let mut reproduced: Option<(f64, &str)> = None;
    let mut relevant: Option<(f64, &str)> = None;
    for ((crop, s1), (crop2, s2)) in first.crops.iter().zip(&second.crops) {
        let (t1, t2) = (s1.t(), s2.t());
        if crop != crop2
            || t1.abs() <= rules.pass
            || t2.abs() <= rules.pass
            || (t1 < 0.0) != (t2 < 0.0)
        {
            continue;
        }
        let strength = t1.abs().min(t2.abs());
        if reproduced.is_none_or(|(s, _)| strength > s) {
            reproduced = Some((strength, crop));
        }
        let big =
            |s: &Stats, m: &Measurement| s.delta().abs() >= rules.floor_ticks(m.q_eff, tick_ns);
        if big(s1, first) && big(s2, second) && relevant.is_none_or(|(s, _)| strength > s) {
            relevant = Some((strength, crop));
        }
    }
    match (relevant, reproduced) {
        (Some((_, crop)), _) => (Verdict::Fail, Some(crop.to_owned())),
        (None, Some((_, crop))) => (Verdict::SubFloorShift, Some(crop.to_owned())),
        (None, None) => (Verdict::Pass, None),
    }
}

struct Outcome {
    target: Target,
    calibration: Calibration,
    verdict: Verdict,
    /// The crop that decided a FAIL or a sub-floor shift.
    decisive_crop: Option<String>,
    first: Option<Measurement>,
    second: Option<Measurement>,
    /// The inline A/A control's measurement of this target (ADR-041 (3)).
    aa: Option<Measurement>,
}

/// Measure `target` and decide (ADR-041): the calibration sets the batch size `k`; the positive control is measured
/// once and must exceed `pass`; every other target is measured twice (the pair) and judged by `decide`. If a
/// measurement of the pair realises too few quanta, `k` is derived again from it and the pair is measured once more
/// (ADR-041 Amendment 2 (2)); NOT MEASURABLE if no `k` up to `max_batch` suffices or the pair is still too coarse.
/// The A/A control runs later (`run`).
fn evaluate(
    target: Target,
    stream: &mut Stream,
    clock: &Clock,
    rules: Rules,
) -> Result<Outcome, secmp_crypto::Error> {
    let calibration = calibrate(&target, stream, clock, rules)?;
    let mut outcome = Outcome {
        target,
        calibration,
        verdict: Verdict::NotMeasurable,
        decisive_crop: None,
        first: None,
        second: None,
        aa: None,
    };
    let (Some(k), Some(quantum), Some(tick_ns)) =
        (outcome.calibration.k, clock.quantum(), clock.tick())
    else {
        return Ok(outcome);
    };
    let measure_once =
        |stream: &mut Stream, t: &Target, k: u32| -> Result<Measurement, secmp_crypto::Error> {
            Ok(Measurement::of(
                &(t.run)(t.samples, usize::try_from(k).unwrap_or(1), stream)?,
                quantum,
                clock.resolution_ticks,
                k,
            ))
        };
    // the pair: two measurements, one for the positive control
    let measure_pair = |stream: &mut Stream,
                        t: &Target,
                        k: u32|
     -> Result<(Measurement, Option<Measurement>), secmp_crypto::Error> {
        let first = measure_once(stream, t, k)?;
        let second = if t.control {
            None
        } else {
            Some(measure_once(stream, t, k)?)
        };
        Ok((first, second))
    };
    let too_coarse = |m: &Measurement| rules.too_coarse(m.q_eff, m.class_median_ticks);
    let (mut first, mut second) = measure_pair(stream, &outcome.target, k)?;
    // ADR-041 Amendment 2 (2): a measurement short of the minimum realised quanta derives the batch size again from
    // its own effective quantum and per-call duration (the larger if both are short), and the pair is measured once
    // more
    let shortfall = {
        let short: Vec<&Measurement> = [Some(&first), second.as_ref()]
            .into_iter()
            .flatten()
            .filter(|m| too_coarse(m))
            .collect();
        (!short.is_empty()).then(|| {
            let q_eff = short.iter().map(|m| m.q_eff).fold(0.0, f64::max);
            let next = short
                .iter()
                .map(|m| rules.batch(m.q_eff, f64_of(m.class_median_ticks) / f64::from(k)))
                .collect::<Option<Vec<u32>>>()
                .and_then(|ks| ks.into_iter().max());
            (q_eff, next)
        })
    };
    if let Some((q_eff, next)) = shortfall {
        outcome.calibration.requantised = Some(Requantised {
            k_initial: k,
            q_eff,
        });
        let Some(k2) = next else {
            // no batch size up to `max_batch` reaches the minimum: NOT MEASURABLE
            outcome.calibration.k = None;
            outcome.first = Some(first);
            outcome.second = second;
            return Ok(outcome);
        };
        outcome.calibration.k = Some(k2);
        (first, second) = measure_pair(stream, &outcome.target, k2)?;
    }
    // ADR-041 Amendment 2 (3): a pair still short of the minimum is NOT MEASURABLE
    if too_coarse(&first) || second.as_ref().is_some_and(too_coarse) {
        outcome.first = Some(first);
        outcome.second = second;
        return Ok(outcome);
    }
    if outcome.target.control {
        outcome.verdict = if first.max().0 > rules.pass {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        outcome.first = Some(first);
        return Ok(outcome);
    }
    if let Some(second) = &second {
        let (verdict, crop) = decide(&first, second, rules, tick_ns);
        outcome.verdict = verdict;
        outcome.decisive_crop = crop;
    }
    outcome.first = Some(first);
    outcome.second = second;
    Ok(outcome)
}

impl Outcome {
    fn json(&self, clock: &Clock, rules: Rules) -> String {
        let [class0, class1] = self.target.classes;
        let measurement =
            |m: Option<&Measurement>| m.map_or_else(|| "null".to_owned(), |m| m.json(clock, rules));
        let per_call_ticks = self.calibration.per_call_ticks();
        // t1 and t2 (sign kept) at the crop of the first measurement's maximum
        let t1_t2 = match (&self.first, &self.second) {
            (Some(first), Some(second)) => {
                let (_, at) = first.max();
                format!(
                    "{{\"crop\":\"{at}\",\"t1\":{:.3},\"t2\":{:.3}}}",
                    first.t(at),
                    second.t(at)
                )
            }
            _ => "null".to_owned(),
        };
        let aa_passed = self.aa.as_ref().map_or_else(
            || "null".to_owned(),
            |m| (m.max().0 <= rules.aa_max_t).to_string(),
        );
        format!(
            "{{\"name\":\"{}\",\"class0\":\"{class0}\",\"class1\":\"{class1}\",\"samples\":{},\"control\":{},\"k\":{},\"requantised\":{},\"k_initial\":{},\"calibration_median_ticks\":{per_call_ticks:.2},\"calibration_median_ns\":{:.1},\"calibration\":{},\"verdict\":\"{}\",\"passed\":{},\"decisive_crop\":{},\"t1_t2\":{t1_t2},\"aa_passed\":{aa_passed},\"aa_control\":{},\"first\":{},\"second\":{}}}",
            self.target.name,
            self.target.samples,
            self.target.control,
            self.calibration
                .k
                .map_or_else(|| "null".to_owned(), |k| k.to_string()),
            self.calibration.requantised.is_some(),
            self.calibration
                .requantised
                .map(|r| r.k_initial)
                .or(self.calibration.k)
                .map_or_else(|| "null".to_owned(), |k| k.to_string()),
            per_call_ticks * clock.tick_ns,
            self.calibration.json(clock),
            self.verdict.as_str(),
            self.verdict.passed(),
            self.decisive_crop
                .as_ref()
                .map_or_else(|| "null".to_owned(), |c| format!("\"{c}\"")),
            measurement(self.aa.as_ref()),
            measurement(self.first.as_ref()),
            measurement(self.second.as_ref())
        )
    }
}

// ---- targets --------------------------------------------------------------------------------------------------
//
// Input preparation (M2 finding, WEISUNG M2-2 C; ADR-042 Amendment 2): every measured input is built from **one
// common source per target**, `base` (the class-1 input), as `base ^ deltas[class]` — `Deltas` holds class 0's
// delta (class 0 XOR class 1) and class 1's all-zero delta of the same length, in two buffers selected by index —
// by one out-of-line XOR loop (`blend`) that runs the same instructions for both classes; the classes differ in the
// contents of the fresh copy and in which of the two delta buffers the loop reads (the one class-dependent address
// left in the preparation). History: before M2, `prepare` copied each input from a per-class source buffer
// (`inputs[c]`, `&sealed` vs `&tampered`, `&at_100` vs `&at_300`, `&other` vs `&k`) right before the timed window,
// and the class-dependent source address left a class-dependent cache footprint at the start of every timed call:
// an A/A′ control (identical contents, the class-1 source only moved to its own allocation) failed with it on
// GitHub-hosted Linux (`msg_open_reject` 13.0, `caead_open_reject` 50.1, run 36569831144), while the A/A control
// (one source for both labels) passed in every run — the M1 review F7 rule ("the classes may differ only in their
// contents, never in where the inputs live") applied one step earlier. The M2 form `base ^ (delta & mask)` was
// then split by the compiler into a `memcpy` for class 1 and an XOR loop for class 0 (ADR-042 Amendment 2). The
// same-content control `same_content_control` measures this whole preparation path with identical contents in
// both classes.

/// The per-class deltas of `blend` (ADR-042 Amendment 2), indexed by the class: class 0's `class0 ^ class1` and
/// class 1's all-zero delta of the same length.
struct Deltas([Vec<u8>; 2]);

impl Deltas {
    /// The deltas that turn the base (`class1`) into `class0` for class 0 and leave it unchanged for class 1.
    fn new(class0: &[u8], class1: &[u8]) -> Self {
        let delta = xor(class0, class1);
        let zero = vec![0_u8; delta.len()];
        Self([delta, zero])
    }
}

/// `out = base ^ deltas[class]`: `base ^ (class0 ^ class1)` for class 0, `base` for class 1 (ADR-042 Amendment 2).
/// One out-of-line XOR loop for both classes: the class only selects the delta buffer by index, and the selected
/// buffer passes through `black_box`, so the compiler can neither branch on the class nor split the loop by it. The
/// mask form `base ^ (delta & mask)` it replaces was split into a `memcpy` for class 1 and an XOR loop for class 0,
/// both before the timed window (`docs/reviews/M03-evidence/ct-blend-disasm-aarch64-bc5088b.txt`).
#[inline(never)]
fn blend(base: &[u8], deltas: &Deltas, class: usize, out: &mut [u8]) {
    let delta = black_box(deltas.0.get(class & 1).map_or(&[][..], Vec::as_slice));
    for ((o, b), d) in out.iter_mut().zip(base).zip(delta) {
        *o = b ^ d;
    }
}

/// `a ^ b`, bytewise (class 0's delta of `Deltas`).
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// A fresh `Vec` input of class `class` (see `blend`).
fn blended_vec(base: &[u8], deltas: &Deltas, class: usize) -> Vec<u8> {
    let mut v = vec![0_u8; base.len()];
    blend(base, deltas, class, &mut v);
    v
}

/// A fresh 32-byte key of class `class` (see `blend`), built on the stack and copied into a `SecretBytes`.
fn blended_key(base: &[u8; 32], deltas: &Deltas, class: usize) -> Option<SecretBytes<32>> {
    let mut key = [0_u8; 32];
    blend(base, deltas, class, &mut key);
    SecretBytes::from_slice(&key).ok()
}

/// Batched 32-byte tag comparisons: class 0 differs in byte 0, class 1 in byte 31.
fn tag_compare(n: usize, k: usize, stream: &mut Stream, variable_time: bool) -> Samples {
    let mut expected = [0_u8; 32];
    stream.fill(&mut expected);
    let mut first = expected;
    first[0] ^= 1;
    let mut last = expected;
    last[31] ^= 1;
    let delta = Deltas::new(&first, &last);
    measure(
        n,
        k,
        stream,
        |c, _| {
            let mut tag = [0_u8; 32];
            blend(&last, &delta, c, &mut tag);
            tag
        },
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

/// The input of one call of the sensitivity control (ADR-042 Amendment 1): the number of byte steps of the
/// early-exit comparison the call stands for — 32 for class 0 (a mismatch in byte 31), 31 for class 1 (a mismatch in
/// byte 30: it exits one byte early) — and the 32 bytes the steps read, in one 64-byte-aligned block, so that both
/// classes read the same cache line at the same offsets.
#[repr(C, align(64))]
struct LeakInput {
    steps: u8,
    bytes: [u8; 32],
}

/// The sensitivity control's work for one call: 256 times, `input.steps` byte steps (a load through `black_box` and
/// an xor each). One out-of-line function, so its code is the same for every caller and both classes execute the
/// identical instruction stream; they differ only in the step count, a value read from the input. The loop counter
/// passes through `black_box`, so the compiler cannot unroll the loop or split off a remainder whose shape would
/// depend on the count (an early-exit `break` at byte 30 vs 31 left a class-dependent branch/layout artefact
/// larger than the leak itself: run 36800231503, ADR-042 Amendment 1).
#[inline(never)]
fn min_leak_call(input: &LeakInput) {
    for _ in 0..256 {
        let steps = usize::from(black_box(input.steps));
        let mut acc = 0_u8;
        let mut i = 0_usize;
        while black_box(i) < steps {
            acc ^= black_box(input.bytes.get(i).copied().unwrap_or(0));
            i = i.wrapping_add(1);
        }
        black_box(acc);
    }
}

/// The sensitivity control `min_leak_control` (ADR-041 Amendment 1 (2); layout-independent since ADR-042 Amendment
/// 1): the smallest software leak the gate must see — the work of a 32-byte early-exit comparison, class 0 with 32
/// byte steps, class 1 with 31 (one byte early); 256 comparisons per call as in `tag_compare`, so class 0 is slower
/// by 256 byte steps. Both classes' inputs are built from one common source (`blend`, the F9 rule).
fn min_leak(n: usize, k: usize, stream: &mut Stream) -> Samples {
    let mut bytes = [0_u8; 32];
    stream.fill(&mut bytes);
    // source: `steps ‖ bytes`; class 1 (the base) 31 steps, class 0 32 steps
    let class1: Vec<u8> = [31_u8].iter().chain(bytes.iter()).copied().collect();
    let class0: Vec<u8> = [32_u8].iter().chain(bytes.iter()).copied().collect();
    let delta = Deltas::new(&class0, &class1);
    measure(
        n,
        k,
        stream,
        |c, _| {
            let mut raw = [0_u8; 33];
            blend(&class1, &delta, c, &mut raw);
            let (steps, rest) = raw.split_first().map_or((0, &[][..]), |(s, r)| (*s, r));
            let mut input = LeakInput {
                steps,
                bytes: [0; 32],
            };
            input.bytes.copy_from_slice(rest);
            input
        },
        min_leak_call,
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
    let delta = Deltas::new(&first, &last);
    let key = SecretBytes::<32>::from_slice(&mk)?;
    Ok(measure(
        n,
        k,
        stream,
        |c, _| blended_vec(&last, &delta, c),
        |ct| {
            black_box(MsgEncrypt::open(&key, &ad, black_box(ct)).is_ok());
        },
    ))
}

/// The A/A′ placement control (ADR-042 (2), M2 review F6): `MsgEncrypt::open` rejecting a tag wrong in its last byte,
/// as `msg_open_reject` — with **identical contents** in both classes, class 0 copied from one source allocation and
/// class 1 from its own, separate allocation. This is deliberately the per-class-source pattern that `blend` exists to
/// avoid (M1 review F9; the comment above `blend`): the classes differ only in where their source lives. A reproduced
/// shift at or above the effect floor means the placement artefact alone reaches the floor on this runner, and the
/// run is `CONTROL_FAIL` (`placement_failure`).
fn aa_prime_control(
    n: usize,
    k: usize,
    stream: &mut Stream,
) -> Result<Samples, secmp_crypto::Error> {
    let mut mk = [0_u8; 32];
    stream.fill(&mut mk);
    let mut body = vec![0_u8; BODY_LEN];
    stream.fill(&mut body);
    let ad = vec![0x5a_u8; 2401];
    let mut last = MsgEncrypt::seal(SecretBytes::from_slice(&mk)?, &ad, &body)?;
    if let Some(b) = last.last_mut() {
        *b ^= 1;
    }
    // two allocations with the same contents, one per class (never `blend`: the placement is what is measured)
    let sources = [last.clone(), last];
    let key = SecretBytes::<32>::from_slice(&mk)?;
    Ok(measure(
        n,
        k,
        stream,
        |c, _| sources.get(c).cloned().unwrap_or_default(),
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
    let key_delta = Deltas::new(&other, &k);
    let ct_delta = Deltas::new(&sealed, &tampered);
    Ok(measure(
        n,
        batch,
        stream,
        |c, _| {
            (
                blended_key(&k, &key_delta, c),
                blended_vec(&tampered, &ct_delta, c),
            )
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
    let key_delta = Deltas::new(&io.other, &io.k);
    Ok(measure(
        n,
        k,
        stream,
        |c, _| blended_key(&io.k, &key_delta, c),
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
    let k_enc_delta = Deltas::new(&k_enc_other, &k_enc_k);
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
            (
                blended_key(&k_enc_k, &k_enc_delta, c),
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
    let expected_delta = Deltas::new(&expected_other, &expected_k);
    let com: [u8; COM_LEN] = io
        .sealed
        .get(..COM_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(secmp_crypto::Error::Rejected)?;
    Ok(measure(
        n,
        k,
        stream,
        |c, _| {
            let mut expected = [0_u8; COM_LEN];
            blend(&expected_k, &expected_delta, c, &mut expected);
            (expected, com)
        },
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
    let ct_delta = Deltas::new(&at_100, &at_300);
    Ok(measure(
        n,
        k,
        stream,
        |c, _| {
            (
                SecretBytes::<32>::from_slice(&io.k).ok(),
                blended_vec(&at_300, &ct_delta, c),
            )
        },
        |(key, ct)| {
            if let Some(key) = key {
                black_box(Caead::open(key, &io.nonce, CAEAD_AD, black_box(ct)).is_ok());
            }
        },
    ))
}

/// Class 0: a fixed pair of fingerprints; class 1: random pairs. Both classes read the fixed pair and the next
/// random pair and select with `blend` (the selection is the only class-dependent step).
fn sas(n: usize, k: usize, stream: &mut Stream) -> Samples {
    let mut fixed = [0_u8; 64];
    stream.fill(&mut fixed);
    let mut random = vec![[0_u8; 64]; n.saturating_mul(k)];
    for r in &mut random {
        stream.fill(r);
    }
    measure(
        n,
        k,
        stream,
        |c, i| {
            let random_pair = random.get(i).copied().unwrap_or(fixed);
            // base = the random pair (class 1), delta = fixed XOR random (class 0 gets the fixed pair)
            let delta = Deltas::new(&fixed, &random_pair);
            let mut pair = [0_u8; 64];
            blend(&random_pair, &delta, c, &mut pair);
            let (first, second) = pair.split_at(32);
            Fingerprint::from_bytes(first)
                .ok()
                .zip(Fingerprint::from_bytes(second).ok())
        },
        |pair| {
            if let Some((first, second)) = pair {
                black_box(SafetyNumber::new(black_box(first), black_box(second)));
            }
        },
    )
}

// ---- SecMP-TR targets (M3 plan D9) -----------------------------------------------------------------------------

/// Randomness of A (`FixedEntropy`, SCHEMA-4.9 order): `init_initiator` (X25519 secret 32, ML-KEM-768 seed 64,
/// `Encaps` 32) and three header nonces (24 each).
const TR_A_RANDOMNESS: usize = 200;
/// Randomness of B: the sending half of its DH step on A's first message (32 + 64 + 32).
const TR_B_RANDOMNESS: usize = 128;

/// Set when a TR target's cell was accepted: the bench aborts (`main` writes the reason instead of a report).
static TR_ACCEPTED: AtomicBool = AtomicBool::new(false);

/// The fixture of the TR targets: B's state with a current receiving chain and A's next cell of that chain.
struct TrSession {
    /// B after A's messages n = 0 (B's DH step) and n = 1: `hk_r`, `ck_r`, `last_ct_r` of A's chain, `n_r = 2`.
    receiver: RatchetState,
    /// A's honest cell n = 2 of that chain, not delivered.
    cell: Vec<u8>,
    /// A's `hk_s` (= B's `hk_r`).
    hk: SecretBytes<32>,
    /// The header's `AD = "SecMP-TR/1 hdr" ‖ sb` (spec §7.3).
    hdr_ad: Vec<u8>,
}

/// A secmp-proto error as the bench's error.
fn crypto_error(e: secmp_proto::Error) -> secmp_crypto::Error {
    match e {
        secmp_proto::Error::Rejected => secmp_crypto::Error::Rejected,
        secmp_proto::Error::Unavailable => secmp_crypto::Error::Unavailable,
    }
}

/// `n` random bytes from the stream.
fn drawn(stream: &mut Stream, n: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0_u8; n]);
    stream.fill(&mut bytes);
    bytes
}

/// A → B, three cells; B receives the first two. `SK`, `sb`, B's prekeys and both parties' randomness come from the
/// stream (`FixedEntropy`: the states are a deterministic function of it). Checks that B's `hk_r` is A's `hk_s` and
/// that the undelivered cell opens on a copy of B, so that each class below is refused for its manipulation alone.
fn tr_session(stream: &mut Stream) -> Result<TrSession, secmp_proto::Error> {
    let sk = SecretBytes::<32>::from_slice(&drawn(stream, 32))?;
    let mut sb = [0_u8; 32];
    stream.fill(&mut sb);
    let spk = X25519Secret::from_bytes(&drawn(stream, 32))?;
    let rpk = MlKem768Dk::from_seed(&drawn(stream, 64))?;
    let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes())?;
    let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes())?;
    let mut a_entropy = FixedEntropy::new(&drawn(stream, TR_A_RANDOMNESS));
    let mut b_entropy = FixedEntropy::new(&drawn(stream, TR_B_RANDOMNESS));
    let mut a = RatchetState::init_initiator_with(&sk, &sb, &spk_pub, &rpk_ek, &mut a_entropy)?;
    let mut b = RatchetState::init_responder(&sk, &sb, spk, rpk)?;
    let mut cells = Vec::new();
    for _ in 0..3 {
        let (next, cell) = a
            .encrypt_with(&dummy(), &mut a_entropy)
            .map_err(|r| r.error())?
            .persist(|_| Ok::<(), secmp_proto::Error>(()))?;
        a = next;
        cells.push(cell);
    }
    let [c0, c1, c2] = cells.as_slice() else {
        return Err(secmp_proto::Error::Rejected);
    };
    for cell in [c0, c1] {
        (b, _) = b
            .decrypt_with(cell.as_bytes(), &mut b_entropy)
            .map_err(|r| r.error())?
            .commit(|_| Ok::<(), secmp_proto::Error>(()))?;
    }
    let (Some(hk_s), (Some(hk_r), _)) = (a.hk_s_kat(), b.receiving_header_keys_kat()) else {
        return Err(secmp_proto::Error::Rejected);
    };
    if !bool::from(hk_s.ct_eq(hk_r)) {
        return Err(secmp_proto::Error::Rejected);
    }
    let hk = SecretBytes::<32>::from_slice(hk_s.expose_secret())?;
    let copy = RatchetState::from_bytes(&b.to_bytes()?)?;
    copy.decrypt_with(c2.as_bytes(), &mut FixedEntropy::new(&[]))
        .map_err(|r| r.error())?;
    let hdr_ad = [Label::TrHdr.as_bytes(), b.sb_kat().as_slice()].concat();
    Ok(TrSession {
        receiver: b,
        cell: c2.as_bytes().to_vec(),
        hk,
        hdr_ad,
    })
}

/// `bytes[at] ^= 1`.
fn flip(bytes: &mut [u8], at: usize) -> Result<(), secmp_proto::Error> {
    let b = bytes.get_mut(at).ok_or(secmp_proto::Error::Rejected)?;
    *b ^= 1;
    Ok(())
}

/// A cell's `hdr_nonce`, `hdr_ct` and body (spec §7.5).
type CellParts<'a> = (&'a [u8; NONCE_LEN], &'a [u8], &'a [u8]);

impl TrSession {
    /// The cell's `hdr_nonce`, `hdr_ct` and body.
    fn parts(&self) -> Result<CellParts<'_>, secmp_proto::Error> {
        let (nonce, rest) = self
            .cell
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(secmp_proto::Error::Rejected)?;
        let (hdr_ct, body) = rest
            .split_at_checked(HDR_CT_LEN)
            .ok_or(secmp_proto::Error::Rejected)?;
        Ok((nonce, hdr_ct, body))
    }

    /// The honest header plaintext, opened under `hk`.
    fn header(&self) -> Result<Zeroizing<Vec<u8>>, secmp_proto::Error> {
        let (nonce, hdr_ct, _) = self.parts()?;
        Ok(Aead::open(&self.hk, nonce, &self.hdr_ad, hdr_ct)?)
    }

    /// The cell with `header` sealed under `key` with the cell's nonce, and the cell's body.
    fn resealed(
        &self,
        key: &SecretBytes<32>,
        header: &[u8],
    ) -> Result<Vec<u8>, secmp_proto::Error> {
        let (nonce, _, body) = self.parts()?;
        let hdr_ct = Aead::seal(key, Nonce24::from_bytes_kat(*nonce), &self.hdr_ad, header)?;
        Ok([nonce.as_slice(), &hdr_ct, body].concat())
    }
}

/// The two classes of a TR target, class 0 first.
type TrClasses = fn(&TrSession, &mut Stream) -> Result<[Vec<u8>; 2], secmp_proto::Error>;

/// `tr_decrypt_reject_hdr_key`: class 0 the honest header sealed under a wrong key (from the stream), class 1 the
/// honest cell with the last byte of the header tag flipped; nonce and body as the honest cell's.
fn tr_hdr_key_classes(
    s: &TrSession,
    stream: &mut Stream,
) -> Result<[Vec<u8>; 2], secmp_proto::Error> {
    let wrong = SecretBytes::<32>::from_slice(&drawn(stream, 32))?;
    let class0 = s.resealed(&wrong, &s.header()?)?;
    let mut class1 = s.cell.clone();
    let tag_end = NONCE_LEN
        .checked_add(HDR_CT_LEN)
        .and_then(|end| end.checked_sub(1))
        .ok_or(secmp_proto::Error::Rejected)?;
    flip(&mut class1, tag_end)?;
    Ok([class0, class1])
}

/// `tr_decrypt_reject_body_tag`: the honest cell with the body tag (its last `MSG_TAG_LEN` bytes) wrong in byte 0
/// (class 0) vs byte 31 (class 1).
fn tr_body_tag_classes(s: &TrSession, _: &mut Stream) -> Result<[Vec<u8>; 2], secmp_proto::Error> {
    let tag_at = s
        .cell
        .len()
        .checked_sub(MSG_TAG_LEN)
        .ok_or(secmp_proto::Error::Rejected)?;
    let last = s
        .cell
        .len()
        .checked_sub(1)
        .ok_or(secmp_proto::Error::Rejected)?;
    let mut class0 = s.cell.clone();
    flip(&mut class0, tag_at)?;
    let mut class1 = s.cell.clone();
    flip(&mut class1, last)?;
    Ok([class0, class1])
}

/// `same_content_control` (ADR-042 Amendment 2): the class-1 cell of `tr_body_tag_classes` (the body tag wrong in
/// byte 31) for both classes.
fn tr_same_content_classes(
    s: &TrSession,
    stream: &mut Stream,
) -> Result<[Vec<u8>; 2], secmp_proto::Error> {
    let [_, class1] = tr_body_tag_classes(s, stream)?;
    Ok([class1.clone(), class1])
}

/// `tr_decrypt_reject_ct_pq`: the honest header with `ct_pq` changed in byte 0 (class 0) vs byte 1087 (class 1),
/// re-sealed under `hk_r` with the cell's nonce; the body unchanged.
fn tr_ct_pq_classes(s: &TrSession, _: &mut Stream) -> Result<[Vec<u8>; 2], secmp_proto::Error> {
    let header = s.header()?;
    let mut first = HeaderV1::decode(&header)?;
    let mut last = HeaderV1::decode(&header)?;
    *first
        .ct_pq
        .first_mut()
        .ok_or(secmp_proto::Error::Rejected)? ^= 1;
    *last.ct_pq.last_mut().ok_or(secmp_proto::Error::Rejected)? ^= 1;
    Ok([
        s.resealed(&s.hk, &first.encode()?)?,
        s.resealed(&s.hk, &last.encode()?)?,
    ])
}

/// One call of a TR target: take the receiver's state out of `slot`, decrypt `cell`, put back the unchanged state
/// of the refusal. An accepted cell leaves the slot empty (every later call finds no state), which
/// `tr_decrypt_reject` turns into an abort.
fn tr_decrypt(slot: &RefCell<Option<RatchetState>>, entropy: &mut FixedEntropy, cell: &[u8]) {
    let Ok(mut slot) = slot.try_borrow_mut() else {
        return;
    };
    if let Some(state) = slot.take()
        && let Err(refused) = black_box(state.decrypt_with(black_box(cell), entropy))
    {
        *slot = Some(refused.into_state());
    }
}

/// A TR target: `RatchetState::decrypt_with` on one receiver state (`tr_session`), class 0 vs class 1 of
/// `classes`, every input built from one common source with `blend` (class 1 the base). No call draws randomness
/// (a rejection draws none, plan D2), so the entropy is empty. Aborts (`TR_ACCEPTED`) if any call accepted its cell.
fn tr_decrypt_reject(
    n: usize,
    k: usize,
    stream: &mut Stream,
    classes: TrClasses,
) -> Result<Samples, secmp_crypto::Error> {
    let session = tr_session(stream).map_err(crypto_error)?;
    let [class0, class1] = classes(&session, stream).map_err(crypto_error)?;
    let delta = Deltas::new(&class0, &class1);
    let slot = RefCell::new(Some(session.receiver));
    let mut entropy = FixedEntropy::new(&[]);
    let samples = measure(
        n,
        k,
        stream,
        |c, _| blended_vec(&class1, &delta, c),
        |cell| tr_decrypt(&slot, &mut entropy, cell),
    );
    if slot.into_inner().is_none() {
        TR_ACCEPTED.store(true, Ordering::Relaxed);
        return Err(secmp_crypto::Error::Rejected);
    }
    Ok(samples)
}

/// `SECMP_CT_SCALE` if set (local quick runs only; echoed in the report, refused by the gate).
fn ct_scale() -> Option<String> {
    std::env::var("SECMP_CT_SCALE").ok()
}

/// The targets in measurement order, `n` samples per measurement (`n_sas` for `sas`).
fn targets(n: usize, n_sas: usize) -> [Target; 10] {
    [
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
            run: |n, k, s| Ok(sas(n, k, s)),
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
        Target {
            name: AA_PRIME,
            classes: [
                "tag wrong in its last byte, copied from source allocation 0",
                "the same bytes, copied from source allocation 1",
            ],
            samples: n,
            control: false,
            run: aa_prime_control,
        },
    ]
}

/// The SecMP-TR targets (M3 plan D9) and the same-content control (ADR-042 Amendment 2), measured after `targets`,
/// `n` samples per measurement.
fn tr_targets(n: usize) -> [Target; 4] {
    [
        Target {
            name: "tr_decrypt_reject_hdr_key",
            classes: [
                "header sealed under a wrong key",
                "header sealed under hk_r, its tag's last byte flipped",
            ],
            samples: n,
            control: false,
            run: |n, k, s| tr_decrypt_reject(n, k, s, tr_hdr_key_classes),
        },
        Target {
            name: "tr_decrypt_reject_body_tag",
            classes: ["body tag wrong in byte 0", "body tag wrong in byte 31"],
            samples: n,
            control: false,
            run: |n, k, s| tr_decrypt_reject(n, k, s, tr_body_tag_classes),
        },
        Target {
            name: "tr_decrypt_reject_ct_pq",
            classes: [
                "ct_pq differs from last_ct_r in byte 0",
                "ct_pq differs from last_ct_r in byte 1087",
            ],
            samples: n,
            control: false,
            run: |n, k, s| tr_decrypt_reject(n, k, s, tr_ct_pq_classes),
        },
        Target {
            name: SAME_CONTENT,
            classes: [
                "the class-1 cell of tr_decrypt_reject_body_tag (body tag wrong in byte 31)",
                "the same cell",
            ],
            samples: n,
            control: false,
            run: |n, k, s| tr_decrypt_reject(n, k, s, tr_same_content_classes),
        },
    ]
}

/// Every target (`evaluate`), then the inline A/A control over the full target set (ADR-041 (3)) and the
/// sensitivity control (Amendment 1 (2)); the third value is the reason of a `CONTROL_FAIL` run (either control
/// failed, or the A/A′ placement control or the same-content control gave FAIL, ADR-042 and its Amendment 2; every
/// target verdict is then `CONTROL_FAIL`).
fn run(
    rules: Rules,
) -> Result<(Clock, Vec<Outcome>, Option<String>, Sensitivity), secmp_crypto::Error> {
    let clock = Clock::probe();
    let scale: usize = ct_scale().and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let mut stream = Stream::new()?;
    let n = rules.samples.checked_div(scale).unwrap_or(1);
    let n_sas = rules.sas_samples.checked_div(scale).unwrap_or(1);
    let mut out = Vec::new();
    for target in targets(n, n_sas).into_iter().chain(tr_targets(n)) {
        out.push(evaluate(target, &mut stream, &clock, rules)?);
    }
    let aa_fail = aa_control(&mut out, &mut stream, &clock, rules)?;
    let sensitivity = sensitivity_control(&out, &mut stream, &clock, rules);
    let mut reasons: Vec<String> = aa_fail.into_iter().collect();
    reasons.extend(sensitivity.failure(rules));
    reasons.extend(placement_failure(&out, &clock, rules));
    reasons.extend(same_content_failure(&out, &clock, rules));
    let control_fail = (!reasons.is_empty()).then(|| reasons.join("; "));
    if control_fail.is_some() {
        for outcome in &mut out {
            outcome.verdict = Verdict::ControlFail;
        }
    }
    Ok((clock, out, control_fail, sensitivity))
}

/// The sensitivity control of a run (ADR-041 Amendment 1 (2)): `min_leak` with `tag_compare`'s batch size and
/// sample count, and its effect floor. `measurement` is `None` if it could not be measured (`tag_compare` without
/// a batch size, or a clock without a quantum or a tick length) — which fails the run like a missed floor.
struct Sensitivity {
    k: Option<u32>,
    samples: usize,
    measurement: Option<Measurement>,
    /// The effect floor of the measurement, in ticks.
    floor_ticks: Option<f64>,
}

impl Sensitivity {
    /// The raw Δ (class 0 − class 1, in ticks) if measured.
    fn raw_delta(&self) -> Option<f64> {
        self.measurement.as_ref()?.raw().map(Stats::delta)
    }

    /// Whether the raw Δ reaches the floor with the expected sign (class 0, 32 byte steps, is the slower one).
    fn reached(&self) -> bool {
        matches!((self.raw_delta(), self.floor_ticks), (Some(d), Some(f)) if d >= f)
    }

    /// The `CONTROL_FAIL` reason, if the control did not reach its floor.
    fn failure(&self, rules: Rules) -> Option<String> {
        if self.reached() {
            return None;
        }
        Some(match (self.raw_delta(), self.floor_ticks) {
            (Some(d), Some(f)) => format!(
                "sensitivity control min_leak_control below the effect floor: raw Δ {d:.2} ticks < floor {f:.2} ticks ({} q_eff, {} ns)",
                rules.effect_floor, rules.effect_floor_ns
            ),
            _ => "sensitivity control min_leak_control not measured".to_owned(),
        })
    }

    fn json(&self, clock: &Clock, rules: Rules) -> String {
        let num = |x: Option<f64>| x.map_or_else(|| "null".to_owned(), |x| format!("{x:.4}"));
        let ns = |x: Option<f64>| num(x.map(|x| x * clock.tick_ns));
        let raw = self.raw_delta();
        let ratio = raw.zip(self.floor_ticks).map(|(d, f)| d / f);
        format!(
            "{{\"name\":\"min_leak_control\",\"class0\":\"32 byte steps (an early-exit comparison mismatching in byte 31)\",\"class1\":\"31 byte steps (mismatch in byte 30: exits one byte early)\",\"comparisons_per_call\":256,\"k\":{},\"samples\":{},\"floor_ticks\":{},\"floor_ns\":{},\"raw_delta_ticks\":{},\"raw_delta_ns\":{},\"raw_delta_floor\":{},\"reached\":{},\"measurement\":{}}}",
            self.k.map_or_else(|| "null".to_owned(), |k| k.to_string()),
            self.samples,
            num(self.floor_ticks),
            ns(self.floor_ticks),
            num(raw),
            ns(raw),
            num(ratio),
            self.reached(),
            self.measurement
                .as_ref()
                .map_or_else(|| "null".to_owned(), |m| m.json(clock, rules))
        )
    }
}

/// ADR-041 Amendment 1 (2): the sensitivity control, measured once after the A/A control with `tag_compare`'s
/// batch size (after any re-batching) and sample count.
fn sensitivity_control(
    out: &[Outcome],
    stream: &mut Stream,
    clock: &Clock,
    rules: Rules,
) -> Sensitivity {
    let tag = out.iter().find(|o| o.target.name == "tag_compare");
    let mut sensitivity = Sensitivity {
        k: tag.and_then(|t| t.calibration.k),
        samples: tag.map_or(0, |t| t.target.samples),
        measurement: None,
        floor_ticks: None,
    };
    if let (Some(k), Some(quantum), Some(tick_ns)) = (sensitivity.k, clock.quantum(), clock.tick())
    {
        let samples = min_leak(sensitivity.samples, usize::try_from(k).unwrap_or(1), stream);
        let m = Measurement::of(&samples, quantum, clock.resolution_ticks, k);
        sensitivity.floor_ticks = Some(rules.floor_ticks(m.q_eff, tick_ns));
        sensitivity.measurement = Some(m);
    }
    sensitivity
}

/// The name of the A/A′ placement control (ADR-042 (2); `expect::CT_TARGETS`).
const AA_PRIME: &str = "aa_prime_control";

/// ADR-042 (2): the A/A′ placement control is judged like a target; if its verdict is FAIL, the placement artefact
/// alone reaches the effect floor on this runner and the run is `CONTROL_FAIL` with this reason (its Δ at the
/// deciding crop in effect floors of each measurement). `None` if it passed, showed a sub-floor shift or was not
/// measured (NOT MEASURABLE fails the run on its own).
fn placement_failure(out: &[Outcome], clock: &Clock, rules: Rules) -> Option<String> {
    let o = out.iter().find(|o| o.target.name == AA_PRIME)?;
    if o.verdict != Verdict::Fail {
        return None;
    }
    let crop = o.decisive_crop.as_deref().unwrap_or("?");
    let floors = |m: Option<&Measurement>| {
        m.and_then(|m| {
            let s = m.crops.iter().find(|(k, _)| k == crop)?;
            Some(s.1.delta() / rules.floor_ticks(m.q_eff, clock.tick_ns))
        })
        .map_or_else(|| "?".to_owned(), |f| format!("{f:.2}"))
    };
    Some(format!(
        "A/A′ placement control {AA_PRIME} FAIL at {crop}: identical contents copied from two source allocations \
         shift the class means by {} / {} effect floors — the placement artefact of M1 review F9 reaches the floor on \
         this runner (ADR-042)",
        floors(o.first.as_ref()),
        floors(o.second.as_ref())
    ))
}

/// The name of the same-content control (ADR-042 Amendment 2; `expect::CT_TARGETS`).
const SAME_CONTENT: &str = "same_content_control";

/// ADR-042 Amendment 2: the same-content control is judged like a target; if its verdict is FAIL, a preparation path
/// that differs by class alone reaches the effect floor and the run is `CONTROL_FAIL` with this reason (its Δ at the
/// deciding crop in effect floors of each measurement). `None` if it passed, showed a sub-floor shift or was not
/// measured (NOT MEASURABLE fails the run on its own).
fn same_content_failure(out: &[Outcome], clock: &Clock, rules: Rules) -> Option<String> {
    let o = out.iter().find(|o| o.target.name == SAME_CONTENT)?;
    if o.verdict != Verdict::Fail {
        return None;
    }
    let crop = o.decisive_crop.as_deref().unwrap_or("?");
    let floors = |m: Option<&Measurement>| {
        m.and_then(|m| {
            let s = m.crops.iter().find(|(k, _)| k == crop)?;
            Some(s.1.delta() / rules.floor_ticks(m.q_eff, clock.tick_ns))
        })
        .map_or_else(|| "?".to_owned(), |f| format!("{f:.2}"))
    };
    Some(format!(
        "same-content control {SAME_CONTENT} FAIL at {crop}: identical contents through the per-class preparation \
         path shift the class means by {} / {} effect floors — the preparation path differs by class (ADR-042 \
         Amendment 2)",
        floors(o.first.as_ref()),
        floors(o.second.as_ref())
    ))
}

/// ADR-041 (3): the inline A/A control — every measurable target once more, with its `k`, class-0 inputs under
/// both labels. Returns the reason of a `CONTROL_FAIL` run (`run` then sets every target verdict to it).
fn aa_control(
    out: &mut [Outcome],
    stream: &mut Stream,
    clock: &Clock,
    rules: Rules,
) -> Result<Option<String>, secmp_crypto::Error> {
    AA_PASS.store(true, Ordering::Relaxed);
    let mut aa_failures = Vec::new();
    for outcome in out.iter_mut() {
        let (Some(k), Some(quantum)) = (outcome.calibration.k, clock.quantum()) else {
            continue;
        };
        let batch = usize::try_from(k).unwrap_or(1);
        let samples = (outcome.target.run)(outcome.target.samples, batch, stream)?;
        let aa = Measurement::of(&samples, quantum, clock.resolution_ticks, k);
        let (max, at) = aa.max();
        if max > rules.aa_max_t {
            aa_failures.push(format!("{} |t| = {max:.2} at {at}", outcome.target.name));
        }
        outcome.aa = Some(aa);
    }
    AA_PASS.store(false, Ordering::Relaxed);
    Ok((!aa_failures.is_empty()).then(|| {
        format!(
            "inline A/A control above {}: {}",
            rules.aa_max_t,
            aa_failures.join(", ")
        )
    }))
}

fn main() -> ExitCode {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ct-report.json");
    let Some(rules) = Rules::from_expect() else {
        // written for the gate to print; the bench itself may not print (docs/06 §2)
        let error = "{\"error\":\"CT_THRESHOLDS / CT_RESOLUTION_MAX_FRACTION / CT_MAX_BATCH / CT_BATCH_MARGIN / CT_MIN_REALISED_QUANTA / CT_EFFECT_FLOOR_QUANTA / CT_EFFECT_FLOOR_NS / CT_AA_MAX_T / CT_SAMPLES / CT_SAS_SAMPLES not readable from xtask/src/expect.rs\"}";
        let _ = std::fs::write(path, error);
        return ExitCode::FAILURE;
    };
    let Ok((clock, outcomes, control_fail, sensitivity)) = run(rules) else {
        // the gate prints the reason of an aborted run (`ctreport::ct_table_for` reads `error`)
        let error = if TR_ACCEPTED.load(Ordering::Relaxed) {
            "{\"error\":\"bench aborted: RatchetState::decrypt_with accepted a cell of a TR target, which must be rejected in both classes\"}"
        } else {
            "{\"error\":\"bench aborted: OS randomness or locked memory unavailable, or an input of the bench itself was refused\"}"
        };
        let _ = std::fs::write(path, error);
        return ExitCode::FAILURE;
    };
    // the run verdict (ADR-041, Amendment 1): CONTROL_FAIL if the inline A/A control or the sensitivity control
    // failed, else PASS iff every target passed
    let run_verdict = if control_fail.is_some() {
        "CONTROL_FAIL"
    } else if outcomes.iter().all(|o| o.verdict.passed()) {
        "PASS"
    } else {
        "FAIL"
    };
    let json = format!(
        "{{\"thresholds\":{},{}\"sign\":\"{SIGN}\",\"clock\":{},\"run_verdict\":\"{run_verdict}\",\"run_reason\":{},\"sensitivity_control\":{},\"results\":[{}]}}",
        rules.json(),
        // M2 review C3 (c): a shortened run says so, and the gate refuses it
        ct_scale().map_or_else(String::new, |s| format!(
            "\"secmp_ct_scale\":{},",
            serde_json::Value::from(s)
        )),
        clock.json(),
        serde_json::Value::from(control_fail),
        sensitivity.json(&clock, rules),
        outcomes
            .iter()
            .map(|o| o.json(&clock, rules))
            .collect::<Vec<_>>()
            .join(",")
    );
    if std::fs::write(path, json).is_err() {
        return ExitCode::FAILURE;
    }
    if run_verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
