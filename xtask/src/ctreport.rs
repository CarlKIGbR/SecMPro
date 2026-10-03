// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `ct` report (`target/ct-report.json`, written by `crates/secmp-testkit/benches/ct.rs`) as the gate reads it
//! (ADR-038, ADR-041 with Amendment 1).
//!
//! The gate does not take the bench's word (M2 review C3). Besides the parameters the report must echo, it
//! re-derives from the recorded per-crop statistics, `q_eff_ticks` and `tick_ns`:
//! - every target's verdict (`decide` of the bench), with each measurement's `q_eff_ticks` bounded above by the
//!   clock (M2 review F17, [`q_eff_bound`]);
//! - the positive control's presence and detection (whatever its label says, M2 review F15), and the inline A/A
//!   control;
//! - the sensitivity control, bound to `tag_compare`'s batch size and sample count: in a report that records both of
//!   its measurements, caught by the target rule with class 0 slower at its deciding crop, with the host identity,
//!   the bench's SHA-256, the histograms and the same-content variant recorded (ADR-041 Amendment 3); in the reports
//!   written before, its raw Δ at or above the floor (Amendment 1 (2));
//! - the target set and the sample counts; a shortened run (`secmp_ct_scale`) is refused;
//! - the batch sizes (ADR-041 Amendment 2, M3 review R-57): every measurement taken with the target's recorded `k`,
//!   the `requantised` flag consistent with `k_initial` and `k`, and each judged measurement realising at least
//!   `CT_MIN_REALISED_QUANTA` effective quanta ([`batch_findings`]).
//!
//! The bench prints rounded values: t to 3 decimals, Δ and the floors in ticks to 4, `q_eff_ticks` to 3; `tick_ns`
//! is exact. Every comparison allows exactly that rounding, so a report is refused only if no values within it give
//! what the report says. `cargo xtask ct-check <report>…` applies the gate's reading to saved reports.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::expect;
use crate::util::{Error, Result, bail, say};

/// Half a unit in the last printed place: t (3 decimals).
const HALF_T: f64 = 5e-4;
/// Δ, `floor_ticks` and `raw_delta_ticks` (4 decimals).
const HALF_4: f64 = 5e-5;
/// `q_eff_ticks` (3 decimals).
const HALF_Q: f64 = 5e-4;

/// The report as the gate reads it: one line per target, and the targets that fail or are not measurable on this
/// runner (with every refusal of the re-derivation among the failures).
#[derive(Debug, Default)]
pub(crate) struct CtTable {
    pub(crate) lines: Vec<String>,
    pub(crate) failed: Vec<String>,
    pub(crate) not_measurable: Vec<String>,
}

/// The verdicts a report may carry per target and whether each passes (ADR-041 with Amendment 1; `NOT_MEASURABLE`
/// per ADR-038 (3)).
const CT_VERDICTS: &[(&str, bool)] = &[
    ("PASS", true),
    ("SUB_FLOOR_SHIFT", true),
    ("FAIL", false),
    ("NOT_MEASURABLE", false),
    ("CONTROL_FAIL", false),
];

/// The run verdicts a report may carry (ADR-041 (3)).
const CT_RUN_VERDICTS: &[&str] = &["PASS", "FAIL", "CONTROL_FAIL"];

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("?")
}

/// `max |t| = x (crop), batch median y ns, q_eff q ticks (source), realised r quanta` of one measurement object.
fn ct_measurement(m: &Value) -> String {
    let t = m
        .get("max_abs_t")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    let at = m.get("max_at").and_then(Value::as_str).unwrap_or("?");
    let median = m
        .get("median_ns")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    let q = m
        .get("q_eff_ticks")
        .and_then(Value::as_f64)
        .map_or_else(|| "?".to_owned(), |q| format!("{q:.1}"));
    let source = m.get("q_eff_source").and_then(Value::as_str).unwrap_or("?");
    let realised = m
        .get("realised_quanta")
        .and_then(Value::as_f64)
        .map_or_else(|| "?".to_owned(), |r| format!("{r:.1}"));
    format!(
        "max |t| = {t:.2} ({at}), batch median {median:.1} ns, q_eff {q} ticks ({source}), realised {realised} quanta"
    )
}

/// The report must echo exactly the parameters of `expect.rs` (the bench reads them from there). The sample counts
/// are echoed since M2 review C3; a report written before carries them per target only, which `rederive` checks.
fn ct_check_parameters(v: &Value) -> Result<()> {
    let th = v
        .get("thresholds")
        .ok_or_else(|| Error("ct report: no thresholds".to_owned()))?;
    let num = |k: &str| th.get(k).and_then(Value::as_f64).map(f64::to_bits);
    if num("pass") != Some(expect::CT_THRESHOLDS.to_bits())
        || num("max_resolution_fraction") != Some(expect::CT_RESOLUTION_MAX_FRACTION.to_bits())
        || th.get("max_batch").and_then(Value::as_u64) != Some(u64::from(expect::CT_MAX_BATCH))
        || num("batch_margin") != Some(expect::CT_BATCH_MARGIN.to_bits())
        || th.get("min_realised_quanta").and_then(Value::as_u64)
            != Some(expect::CT_MIN_REALISED_QUANTA)
        || num("effect_floor_quanta") != Some(expect::CT_EFFECT_FLOOR_QUANTA.to_bits())
        || num("effect_floor_ns") != Some(expect::CT_EFFECT_FLOOR_NS.to_bits())
        || num("aa_max_t") != Some(expect::CT_AA_MAX_T.to_bits())
    {
        bail!(
            "ct report: parameters {th} differ from expect::CT_THRESHOLDS {} / CT_RESOLUTION_MAX_FRACTION {} / \
             CT_MAX_BATCH {} / CT_BATCH_MARGIN {} / CT_MIN_REALISED_QUANTA {} / CT_EFFECT_FLOOR_QUANTA {} / \
             CT_EFFECT_FLOOR_NS {} / CT_AA_MAX_T {}",
            expect::CT_THRESHOLDS,
            expect::CT_RESOLUTION_MAX_FRACTION,
            expect::CT_MAX_BATCH,
            expect::CT_BATCH_MARGIN,
            expect::CT_MIN_REALISED_QUANTA,
            expect::CT_EFFECT_FLOOR_QUANTA,
            expect::CT_EFFECT_FLOOR_NS,
            expect::CT_AA_MAX_T
        );
    }
    for (key, expected) in [
        ("samples", expect::CT_SAMPLES),
        ("sas_samples", expect::CT_SAS_SAMPLES),
    ] {
        if let Some(echoed) = th.get(key)
            && echoed.as_u64() != u64::try_from(expected).ok()
        {
            bail!("ct report: {key} {echoed} differs from expect ({expected})");
        }
    }
    Ok(())
}

/// The clock's tick length in ns, if positive and finite.
fn tick_ns(report: &Value) -> Option<f64> {
    report
        .get("clock")
        .and_then(|clock| clock.get("tick_ns"))
        .and_then(Value::as_f64)
        .filter(|t| t.is_finite() && *t > 0.0)
}

/// A measurement's `q_eff_ticks`, if finite and at least one tick (M2 review C3 (f): a smaller quantum would void
/// the one-quantum clause of the effect floor).
fn q_eff(m: &Value) -> Option<f64> {
    m.get("q_eff_ticks")
        .and_then(Value::as_f64)
        .filter(|q| q.is_finite() && *q >= 1.0)
}

/// The largest effective quantum (ticks) a target's measurement may carry (M2 review F17): the timer's quantum as the
/// clock probe measured it independently of the targets (`clock.q_eff_ticks`: the reported resolution, or the lattice
/// of the fixed workload where coarser), or the absolute floor `CT_EFFECT_FLOOR_NS` in ticks, whichever is larger,
/// plus one tick. Reasoning: the effect floor is `max(q_eff, 10 ns)` (ADR-041 Amendment 1), and a larger `q_eff`
/// raises it, so an inflated `q_eff` could turn a FAIL into `SUB_FLOOR_SHIFT`. A measurement's own lattice is a
/// property of the timer, not of the code under test; ADR-041 Amendment 1 sets the 10 ns part of the floor at the
/// coarse lattice seen on the fine-counter runners (≈ 24.5 ticks = 10.0 ns, which the clock probe does not see), and
/// a coarse counter shows its coarseness in the probe (26 ticks = 10.0 ns; 1 tick = 41.7 ns on Apple Silicon). The
/// one tick absorbs the estimate of a lattice from integer sample values (observed 24.25–24.6 ticks for the 24.46-tick
/// lattice). A lattice coarser than both would be a runner the ADR did not anticipate: the report is refused (fail
/// closed) rather than judged with a floor that nothing independent of the targets confirms. `None` without a
/// readable clock quantum and tick length: every measured target is then refused.
fn q_eff_bound(report: &Value) -> Option<f64> {
    let tick = tick_ns(report)?;
    let clock = report
        .get("clock")
        .and_then(|c| c.get("q_eff_ticks"))
        .and_then(Value::as_f64)
        .filter(|q| q.is_finite() && *q >= 1.0)?;
    Some(clock.max(expect::CT_EFFECT_FLOOR_NS / tick) + 1.0)
}

/// The effect floor in ticks for an effective quantum `q` (ticks) on a clock of `tick` ns (ADR-041 Amendment 1).
fn floor_ticks(q: f64, tick: f64) -> f64 {
    (expect::CT_EFFECT_FLOOR_QUANTA * q).max(expect::CT_EFFECT_FLOOR_NS / tick)
}

/// Whether a report records the sensitivity control as a pair of measurements (`sensitivity_control.second`, ADR-041
/// Amendment 3), which the gate judges by the verdict rule; the reports written before carry one `measurement` and
/// are read by the raw rule of Amendment 1 (2).
fn control_pair(report: &Value) -> Option<&Value> {
    report
        .get("sensitivity_control")
        .filter(|c| c.get("second").is_some())
}

/// The sensitivity control `min_leak_control`: its line and whether it passed — by the verdict rule for a report
/// that records both measurements ([`ct_sensitivity_pair`], ADR-041 Amendment 3), else by the raw rule of Amendment
/// 1 (2) ([`ct_sensitivity_raw`]).
fn ct_sensitivity(report: &Value) -> (String, bool) {
    match control_pair(report) {
        Some(control) => ct_sensitivity_pair(report, control),
        None => ct_sensitivity_raw(report),
    }
}

/// The two measurements of the sensitivity control as the gate reads them (ADR-041 Amendment 3): per measurement its
/// `q_eff_ticks` and crops (`None` if unreadable), and the clock's tick length.
struct ControlPair {
    tick: Option<f64>,
    first: Option<(f64, Vec<(String, Stat)>)>,
    second: Option<(f64, Vec<(String, Stat)>)>,
}

impl ControlPair {
    fn read(tick: Option<f64>, first: Option<&Value>, second: Option<&Value>) -> Self {
        let read = |m: Option<&Value>| Some((q_eff(m?)?, crops(m?)?));
        Self {
            tick,
            first: read(first),
            second: read(second),
        }
    }

    /// t, Δ (ticks) and `q_eff` of measurement `m` at `crop`.
    fn stat(m: Option<&(f64, Vec<(String, Stat)>)>, crop: &str) -> Option<(f64, f64, f64)> {
        let (q, crops) = m?;
        let (_, s) = crops.iter().find(|(n, _)| n == crop)?;
        Some((s.t, s.delta, *q))
    }

    fn first_delta(&self, crop: &str) -> Option<f64> {
        Self::stat(self.first.as_ref(), crop).map(|(_, d, _)| d)
    }

    /// The crop names of the first measurement.
    fn crop_names(&self) -> Vec<String> {
        self.first
            .as_ref()
            .map(|(_, c)| c.iter().map(|(n, _)| n.clone()).collect())
            .unwrap_or_default()
    }

    /// The target rule at `crop` within the printed rounding (the tests of [`possible_verdicts`]): whether a FAIL with
    /// class 0 slower (Δ > 0 in both) is possible, whether a FAIL with class 1 slower is sure, and the strength
    /// min(|t1|, |t2|) by which `decide` picks its crop. `None` if a measurement or the tick length is unreadable.
    fn judge(&self, crop: &str) -> Option<(bool, bool, f64)> {
        let tick = self.tick?;
        let (t1, d1, q1) = Self::stat(self.first.as_ref(), crop)?;
        let (t2, d2, q2) = Self::stat(self.second.as_ref(), crop)?;
        let pass = expect::CT_THRESHOLDS;
        let same_sign = (t1 < 0.0) == (t2 < 0.0);
        let shift_maybe = same_sign && t1.abs() + HALF_T > pass && t2.abs() + HALF_T > pass;
        let shift_surely = same_sign && t1.abs() - HALF_T > pass && t2.abs() - HALF_T > pass;
        let floor_maybe = d1.abs() + HALF_4 >= floor_ticks(q1 - HALF_Q, tick)
            && d2.abs() + HALF_4 >= floor_ticks(q2 - HALF_Q, tick);
        let floor_surely = d1.abs() - HALF_4 >= floor_ticks(q1 + HALF_Q, tick)
            && d2.abs() - HALF_4 >= floor_ticks(q2 + HALF_Q, tick);
        let slower0 = d1 > 0.0 && d2 > 0.0 && t1 > 0.0;
        Some((
            shift_maybe && floor_maybe && slower0,
            shift_surely && floor_surely && t1 < 0.0,
            t1.abs().min(t2.abs()),
        ))
    }

    /// Δ in ns, Δ in effect floors and t of both measurements at `crop`, as printed.
    fn describe(&self, crop: &str) -> (String, String, String) {
        let two = |v: Option<f64>| v.map_or_else(|| "?".to_owned(), |v| format!("{v:.2}"));
        let both = [
            Self::stat(self.first.as_ref(), crop),
            Self::stat(self.second.as_ref(), crop),
        ];
        let [d1, d2] = both.map(|s| s.zip(self.tick).map(|((_, d, _), tick)| d * tick));
        let [f1, f2] = both.map(|s| {
            s.zip(self.tick)
                .map(|((_, d, q), tick)| d / floor_ticks(q, tick))
        });
        let [t1, t2] = both.map(|s| s.map(|(t, _, _)| t));
        (
            format!("{} / {} ns", two(d1), two(d2)),
            format!("{} / {} floors", two(f1), two(f2)),
            format!("t {} / {}", two(t1), two(t2)),
        )
    }
}

/// ADR-041 Amendment 3 (1), (3): the sensitivity control of a report with both measurements, re-derived by the target
/// rule (`decide` of the bench, [`possible_verdicts`]'s tests): at the recorded `deciding_crop`, within the printed
/// rounding, |t| above `CT_THRESHOLDS` in both measurements with the same sign, |Δ| at or above each measurement's
/// floor `max(q_eff, CT_EFFECT_FLOOR_NS)`, and class 0 the slower (Δ > 0 in both); and no crop where a FAIL with class
/// 1 slower is sure and surely stronger (`decide` takes the strongest relevant crop, by min(|t1|, |t2|)). The report's
/// `reached` must be true as well; a control recorded as caught whose crops do not give it is refused. The line names
/// the deciding crop with Δ (ns, floors) and t of both measurements, and both raw Δ as information.
fn ct_sensitivity_pair(report: &Value, control: &Value) -> (String, bool) {
    let measured = |key: &str| control.get(key).filter(|m| !m.is_null());
    let pair = ControlPair::read(tick_ns(report), measured("first"), measured("second"));
    let crop = control.get("deciding_crop").and_then(Value::as_str);
    let decision = control
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let caught_at = crop.and_then(|c| pair.judge(c));
    let overtaken = caught_at.is_some_and(|(_, _, strength)| {
        pair.crop_names()
            .iter()
            .filter_map(|n| pair.judge(n))
            .any(|(_, wrong_sure, other)| wrong_sure && other - HALF_T > strength + HALF_T)
    });
    let reached = control.get("reached").and_then(Value::as_bool) == Some(true)
        && caught_at.is_some_and(|(caught, _, _)| caught)
        && !overtaken;
    let (raw_ns, _, _) = pair.describe("raw");
    let reading = match (crop, caught_at) {
        (Some(c), Some((true, _, _))) => {
            let (d, f, t) = pair.describe(c);
            format!("decide {decision} at {c}, class 0 slower: Δ {d} ({f}), {t}")
        }
        (Some(c), Some(_)) if pair.first_delta(c).is_some_and(|d| d < 0.0) => {
            let (d, f, t) = pair.describe(c);
            format!("decide {decision} at {c}, class 1 slower: Δ {d} ({f}), {t}")
        }
        _ => format!(
            "decide {decision}{}: no crop reproduces the injected leak at ≥ 1 floor with |t| > {} in both \
             measurements",
            crop.map(|c| format!(" at {c}")).unwrap_or_default(),
            expect::CT_THRESHOLDS
        ),
    };
    let batch = control
        .get("k")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_owned(), |k| k.to_string());
    let samples = control.get("samples").and_then(Value::as_u64).unwrap_or(0);
    let measurements: String = [("first", "first"), ("second", "second")]
        .iter()
        .filter_map(|(key, label)| {
            measured(key).map(|m| format!("; {label} {}", ct_measurement(m)))
        })
        .collect();
    let state = if reached { "CAUGHT" } else { "NOT CAUGHT" };
    (
        format!(
            "min_leak_control: {state} — {reading}; raw Δ {raw_ns} (information); k={batch}, {samples} samples\
             {measurements} (sensitivity control: the verdict rule must catch the injected leak with class 0 slower, \
             ADR-041 Amendment 3)"
        ),
        reached,
    )
}

/// ADR-041 Amendment 1 (2), for the reports written before Amendment 3 (one `measurement`): the control's line and
/// whether it reached the effect floor. The gate does not take the bench's word for it: the report's `reached` must
/// be true **and** the raw Δ must be at least the floor, which must be at least `CT_EFFECT_FLOOR_NS` and one effective
/// quantum (at least one tick) of the control's measurement. A missing or incomplete control never reaches the floor.
/// The comparisons are in ticks within the printed rounding: the floor of linux-ct run 36678826377 equals one `q_eff`
/// (24.4928 ticks printed next to 24.493), which a comparison of the rounded values in ns refused. The ns and floor
/// counts printed are computed from the ticks (review C3 (h)), not copied from the report.
fn ct_sensitivity_raw(report: &Value) -> (String, bool) {
    let Some(control) = report.get("sensitivity_control").filter(|c| c.is_object()) else {
        return (
            "min_leak_control: missing from the report (sensitivity control, must reach the floor)"
                .to_owned(),
            false,
        );
    };
    let num = |key: &str| control.get(key).and_then(Value::as_f64);
    let tick = tick_ns(report);
    let q = control.get("measurement").and_then(q_eff);
    let (delta, floor) = (num("raw_delta_ticks"), num("floor_ticks"));
    let reached = control.get("reached").and_then(Value::as_bool) == Some(true)
        && match (delta, floor, q, tick) {
            (Some(delta), Some(floor), Some(q), Some(tick)) => {
                delta + 2.0 * HALF_4 >= floor
                    && (floor + HALF_4) * tick >= expect::CT_EFFECT_FLOOR_NS
                    && floor + HALF_4 + HALF_Q * expect::CT_EFFECT_FLOOR_QUANTA
                        >= expect::CT_EFFECT_FLOOR_QUANTA * q
            }
            _ => false,
        };
    let two_places =
        |value: Option<f64>| value.map_or_else(|| "?".to_owned(), |v| format!("{v:.2}"));
    let ns = |ticks: Option<f64>| ticks.zip(tick).map(|(t, tick)| t * tick);
    let batch = control
        .get("k")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_owned(), |k| k.to_string());
    let samples = control.get("samples").and_then(Value::as_u64).unwrap_or(0);
    let measurement = control
        .get("measurement")
        .filter(|m| !m.is_null())
        .map(|m| format!("; {}", ct_measurement(m)))
        .unwrap_or_default();
    let state = if reached {
        "REACHED"
    } else {
        "BELOW THE FLOOR"
    };
    (
        format!(
            "min_leak_control: {state} — raw Δ {} ns, floor {} ns ({} floors), k={batch}, {samples} samples\
             {measurement} (sensitivity control, must reach the floor)",
            two_places(ns(delta)),
            two_places(ns(floor)),
            two_places(delta.zip(floor).map(|(d, f)| d / f))
        ),
        reached,
    )
}

/// ADR-041 Amendment 3 (2): the bins per class of the histograms of the sensitivity control and its same-content
/// variant (the bench's `HISTOGRAM_BINS`).
const CONTROL_HISTOGRAM_BINS: usize = 21;

/// ADR-041 Amendment 3 (2): the line of the informative same-content variant `min_leak_same_content` (no verdict,
/// never a failure): its p50 Δ (ns, floors) and t, and the interquartile range of each class with their ratio
/// (class 1 / class 0); `None` for a report without it.
fn ct_same_content_line(report: &Value) -> Option<String> {
    let variant = report
        .get("min_leak_same_content")
        .filter(|v| v.is_object())?;
    let Some(m) = variant.get("measurement").filter(|m| !m.is_null()) else {
        return Some("min_leak_same_content: informative (no verdict) — not measured".to_owned());
    };
    let tick = tick_ns(report);
    let p50 = |key: &str| {
        m.get("crops")
            .and_then(|c| c.get("p50"))
            .and_then(|c| c.get(key))
            .and_then(Value::as_f64)
    };
    let (delta, t) = (p50("delta"), p50("t"));
    let floor = q_eff(m).zip(tick).map(|(q, tick)| floor_ticks(q, tick));
    let iqr = |class: &str| {
        let s = m.get("shape")?.get(class)?;
        Some(s.get("p75")?.as_f64()? - s.get("p25")?.as_f64()?)
    };
    let (i0, i1) = (iqr("class0"), iqr("class1"));
    let ratio = i0.zip(i1).and_then(|(a, b)| (a > 0.0).then(|| b / a));
    let two = |v: Option<f64>| v.map_or_else(|| "?".to_owned(), |v| format!("{v:.2}"));
    Some(format!(
        "min_leak_same_content: informative (no verdict) — p50 Δ {} ns ({} floors), t {}; IQR class 0 {} / class 1 {} \
         ticks (ratio {}); {} (same content through the per-class preparation, ADR-041 Amendment 3)",
        two(delta.zip(tick).map(|(d, tick)| d * tick)),
        two(delta.zip(floor).map(|(d, f)| d / f)),
        two(t),
        two(i0),
        two(i1),
        two(ratio),
        ct_measurement(m)
    ))
}

/// ADR-041 Amendment 3 (2): a report with both control measurements carries the evidence that separates a layout
/// effect from a host effect — `host.cpu_model` and `host.microcode` (text; the bench writes `unknown` where the host
/// does not say), `bench_sha256` (64 lowercase hex digits) and, where the control was measured, both measurements
/// taken with the control's `k`, a histogram of [`CONTROL_HISTOGRAM_BINS`] bins per class whose counts sum to the
/// class counts of the first measurement (`sensitivity_control.histogram`), and the same-content variant with its
/// measurement and histogram (`min_leak_same_content`). Each gap is a refusal.
fn pair_record_findings(report: &Value, control: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["cpu_model", "microcode"] {
        let value = report
            .get("host")
            .and_then(|h| h.get(key))
            .and_then(Value::as_str);
        if value.is_none_or(|s| s.trim().is_empty()) {
            out.push(format!(
                "ct report: no host.{key} (ADR-041 Amendment 3 (2))"
            ));
        }
    }
    let sha = report.get("bench_sha256").and_then(Value::as_str);
    if !sha.is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        out.push(format!(
            "ct report: bench_sha256 {sha:?} is not a SHA-256 in hex (ADR-041 Amendment 3 (2))"
        ));
    }
    let Some(first) = control.get("first").filter(|m| !m.is_null()) else {
        return out;
    };
    let k = control.get("k").and_then(Value::as_u64);
    for key in ["first", "second"] {
        let taken = control
            .get(key)
            .and_then(|m| m.get("k"))
            .and_then(Value::as_u64);
        if taken.is_none() || taken != k {
            out.push(format!(
                "ct report: min_leak_control {key} taken with k {taken:?}, not the control's k {k:?}"
            ));
        }
    }
    out.extend(histogram_findings(
        "sensitivity_control",
        control.get("histogram"),
        first,
    ));
    let same = report.get("min_leak_same_content");
    match same
        .and_then(|v| v.get("measurement"))
        .filter(|m| !m.is_null())
    {
        Some(m) => out.extend(histogram_findings(
            "min_leak_same_content",
            same.and_then(|v| v.get("histogram")),
            m,
        )),
        None => out.push(
            "ct report: no min_leak_same_content measurement next to a measured sensitivity control (ADR-041 \
             Amendment 3 (2))"
                .to_owned(),
        ),
    }
    out
}

/// The histogram `h` of `name`: per class [`CONTROL_HISTOGRAM_BINS`] counts that sum to the class count of `m`'s raw
/// crop (`n0`, `n1`).
fn histogram_findings(name: &str, h: Option<&Value>, m: &Value) -> Vec<String> {
    let raw = m.get("crops").and_then(|c| c.get("raw"));
    let count = |key: &str| raw.and_then(|r| r.get(key)).and_then(Value::as_u64);
    [("class0", count("n0")), ("class1", count("n1"))]
        .into_iter()
        .filter_map(|(class, n)| {
            let bins: Option<Vec<u64>> = h
                .and_then(|h| h.get(class))
                .and_then(Value::as_array)
                .and_then(|a| a.iter().map(Value::as_u64).collect());
            let sum = bins
                .as_ref()
                .map(|b| b.iter().fold(0_u64, |s, x| s.saturating_add(*x)));
            let len = bins.as_ref().map(Vec::len);
            (len != Some(CONTROL_HISTOGRAM_BINS) || n.is_none() || sum != n).then(|| {
                format!(
                    "ct report: {name} histogram {class}: {len:?} bins summing to {sum:?}, expected \
                     {CONTROL_HISTOGRAM_BINS} bins summing to the class count {n:?} (ADR-041 Amendment 3 (2))"
                )
            })
        })
        .collect()
}

/// One target's line: verdict (with the deciding crop), `k`, calibration, both measurements and the A/A control.
fn ct_line(r: &Value) -> (String, String, bool) {
    let name = text(r, "name");
    let verdict = text(r, "verdict");
    let control = r.get("control").and_then(Value::as_bool).unwrap_or(false);
    let n = r.get("samples").and_then(Value::as_u64).unwrap_or(0);
    let k = r
        .get("k")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_owned(), |k| k.to_string());
    let k = match (
        r.get("requantised").and_then(Value::as_bool),
        r.get("k_initial").and_then(Value::as_u64),
    ) {
        (Some(true), Some(k0)) => format!("{k} (re-batched from k={k0})"),
        _ => k,
    };
    let calibration = r.get("calibration_median_ns").and_then(Value::as_f64);
    let ns = |x: Option<f64>| x.map_or_else(|| "?".to_owned(), |x| format!("{x:.1}"));
    let measurement = |key: &str, label: &str| {
        r.get(key)
            .filter(|m| !m.is_null())
            .map(|m| format!("; {label} {}", ct_measurement(m)))
            .unwrap_or_default()
    };
    let decisive = r
        .get("decisive_crop")
        .and_then(Value::as_str)
        .map(|c| format!(" at {c}"))
        .unwrap_or_default();
    let line = format!(
        "{name}: {verdict}{decisive} — k={k}, calibration median {} ns, {n} samples{}{}{}{}",
        ns(calibration),
        measurement("first", "first"),
        measurement("second", "second"),
        measurement("aa_control", "A/A"),
        if control {
            " (positive control, must be detected)"
        } else if name == expect::CT_AA_PRIME_CONTROL {
            " (A/A′ placement control: a FAIL makes the run CONTROL_FAIL)"
        } else if name == expect::CT_SAME_CONTENT_CONTROL {
            " (same-content control: a FAIL makes the run CONTROL_FAIL)"
        } else if name == expect::CT_HX_SAME_CONTENT_CONTROL {
            " (HX same-content control: a FAIL makes the run CONTROL_FAIL)"
        } else {
            ""
        }
    );
    let passes = CT_VERDICTS
        .iter()
        .find(|(v, _)| *v == verdict)
        .is_some_and(|(_, ok)| *ok);
    (
        line,
        format!("{name} (median {} ns)", ns(calibration)),
        passes,
    )
}

/// One crop of a measurement: t and Δ (ticks).
struct Stat {
    t: f64,
    delta: f64,
}

/// The crops of a measurement in report order (`raw`, `p50` … `p99`), each with a finite t and Δ.
fn crops(m: &Value) -> Option<Vec<(String, Stat)>> {
    m.get("crops")?
        .as_object()?
        .iter()
        .map(|(name, c)| {
            let t = c.get("t")?.as_f64().filter(|x| x.is_finite())?;
            let delta = c.get("delta")?.as_f64().filter(|x| x.is_finite())?;
            Some((name.clone(), Stat { t, delta }))
        })
        .collect()
}

/// The largest |t| over the crops of a measurement.
fn max_abs_t(m: &Value) -> Option<f64> {
    crops(m)?.iter().map(|(_, s)| s.t.abs()).reduce(f64::max)
}

/// What the bench's `decide` can have concluded from two measurements, given the printed rounding.
#[derive(Debug, Default)]
struct Possible {
    /// Among PASS, `SUB_FLOOR_SHIFT` and FAIL.
    verdicts: BTreeSet<&'static str>,
    /// The crops at which the shift can be reproduced (|t| > threshold in both, same sign).
    reproducible: BTreeSet<String>,
}

/// ADR-041 (1), (2) and Amendment 1 (1) on the recorded statistics: per crop, reproduced if |t| > `CT_THRESHOLDS` in
/// both measurements with the same sign, relevant if |Δ| reaches each measurement's floor
/// `max(q_eff, CT_EFFECT_FLOOR_NS)`; FAIL if a crop is both, `SUB_FLOOR_SHIFT` if one is reproduced but none is
/// both, PASS otherwise. "Sure" and "possible" bound each test by the printed rounding. `None`: a measurement is
/// unreadable (missing crops, or `q_eff_ticks` not a finite value ≥ 1).
fn possible_verdicts(first: &Value, second: &Value, tick: f64) -> Option<Possible> {
    let (q1, q2) = (q_eff(first)?, q_eff(second)?);
    let (c1, c2) = (crops(first)?, crops(second)?);
    if c1.is_empty() || c1.len() != c2.len() {
        return None;
    }
    let pass = expect::CT_THRESHOLDS;
    let bounds = |q: f64| (floor_ticks(q - HALF_Q, tick), floor_ticks(q + HALF_Q, tick));
    let ((lo1, hi1), (lo2, hi2)) = (bounds(q1), bounds(q2));
    let mut possible = Possible::default();
    let (mut fail_possible, mut fail_sure, mut reproduced_sure, mut sub_floor_possible) =
        (false, false, false, false);
    for (name, s1) in &c1 {
        let (_, s2) = c2.iter().find(|(n, _)| n == name)?;
        let same_sign = (s1.t < 0.0) == (s2.t < 0.0);
        // reproduced: |t| above the threshold in both measurements, same sign
        let shift_maybe = same_sign && s1.t.abs() + HALF_T > pass && s2.t.abs() + HALF_T > pass;
        let shift_surely = same_sign && s1.t.abs() - HALF_T > pass && s2.t.abs() - HALF_T > pass;
        // relevant: |Δ| at or above each measurement's floor
        let floor_maybe = s1.delta.abs() + HALF_4 >= lo1 && s2.delta.abs() + HALF_4 >= lo2;
        let floor_surely = s1.delta.abs() - HALF_4 >= hi1 && s2.delta.abs() - HALF_4 >= hi2;
        if shift_maybe {
            possible.reproducible.insert(name.clone());
        }
        fail_possible |= shift_maybe && floor_maybe;
        fail_sure |= shift_surely && floor_surely;
        reproduced_sure |= shift_surely;
        sub_floor_possible |= shift_maybe && !floor_surely;
    }
    if fail_possible {
        possible.verdicts.insert("FAIL");
    }
    if !reproduced_sure {
        possible.verdicts.insert("PASS");
    }
    if sub_floor_possible && !fail_sure {
        possible.verdicts.insert("SUB_FLOOR_SHIFT");
    }
    Some(possible)
}

/// A target set a report is read against: `expect::CT_TARGETS` (the gate) or the set a committed report was written
/// with (`cargo xtask ct-check --targets m2`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetSet {
    label: &'static str,
    names: &'static [&'static str],
    /// Whether its reports record `k` per measurement, `requantised` and `k_initial` (ADR-041 Amendment 2); the
    /// reports of the M2 set predate it.
    batch_record: bool,
}

/// The gate's target set.
pub(crate) const CURRENT_TARGETS: TargetSet = TargetSet {
    label: "expect::CT_TARGETS",
    names: expect::CT_TARGETS,
    batch_record: true,
};

/// The target set of the reports written before ADR-042 added `aa_prime_control` (M2; the committed evidence under
/// `docs/reviews/M02-evidence/`), for re-reading them with `cargo xtask ct-check --targets m2`.
pub(crate) const M2_TARGETS: TargetSet = TargetSet {
    label: "the M2 target set",
    names: &[
        "control_variable_time_compare",
        "tag_compare",
        "msg_open_reject",
        "caead_open_reject",
        "sas",
        "caead_derive",
        "caead_aead_reject",
        "caead_com_compare",
        "caead_open_reject_samekey",
    ],
    batch_record: false,
};

/// M2 review C3 (a), (c): the target set is `targets` (the gate: `expect::CT_TARGETS`), each measured with the sample
/// count of `expect.rs`, and the run was not shortened.
fn set_findings(report: &Value, results: &[Value], targets: TargetSet) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(scale) = report.get("secmp_ct_scale") {
        out.push(format!(
            "ct report: a shortened run (secmp_ct_scale = {scale}); the gate runs the full sample counts"
        ));
    }
    let names: Vec<&str> = results.iter().map(|r| text(r, "name")).collect();
    let set: BTreeSet<&str> = names.iter().copied().collect();
    let expected: BTreeSet<&str> = targets.names.iter().copied().collect();
    if set.len() != names.len() || set != expected {
        out.push(format!(
            "ct report: targets {names:?} differ from {} {:?}",
            targets.label, targets.names
        ));
    }
    for r in results {
        let name = text(r, "name");
        let want = if name == "sas" {
            expect::CT_SAS_SAMPLES
        } else {
            expect::CT_SAMPLES
        };
        let got = r.get("samples").and_then(Value::as_u64);
        if got != u64::try_from(want).ok() {
            out.push(format!(
                "ct report: {name} measured {got:?} samples, expect {want}"
            ));
        }
    }
    out
}

/// The verdicts the bench can give the positive control: measured once, PASS if detected, FAIL if not, or not
/// measurable (`evaluate`).
const CT_CONTROL_VERDICTS: &[&str] = &["PASS", "FAIL", "NOT_MEASURABLE"];

/// M2 review C3 (a): exactly one positive control, `expect::CT_POSITIVE_CONTROL`, detected; F15: detected whatever its
/// label says (in a run that is not `CONTROL_FAIL`), and labelled with a verdict the bench can give it.
fn control_findings(results: &[Value], run_verdict: &str) -> Vec<String> {
    let controls: Vec<&Value> = results
        .iter()
        .filter(|r| r.get("control").and_then(Value::as_bool) == Some(true))
        .collect();
    let [control] = controls.as_slice() else {
        return vec![format!(
            "ct report: {} positive controls, expected exactly {}",
            controls.len(),
            expect::CT_POSITIVE_CONTROL
        )];
    };
    if text(control, "name") != expect::CT_POSITIVE_CONTROL {
        return vec![format!(
            "ct report: the positive control is {}, expected {}",
            text(control, "name"),
            expect::CT_POSITIVE_CONTROL
        )];
    }
    let mut out = Vec::new();
    let verdict = text(control, "verdict");
    if run_verdict != "CONTROL_FAIL" && !CT_CONTROL_VERDICTS.contains(&verdict) {
        out.push(format!(
            "ct report: the positive control {} is {verdict}; it can only be {CT_CONTROL_VERDICTS:?}",
            expect::CT_POSITIVE_CONTROL
        ));
    }
    let detected = control
        .get("first")
        .and_then(max_abs_t)
        .is_some_and(|t| t + HALF_T > expect::CT_THRESHOLDS);
    if run_verdict != "CONTROL_FAIL" && !detected {
        out.push(format!(
            "ct report: {} {verdict}, but its crops do not exceed |t| {} (the positive control must be detected)",
            expect::CT_POSITIVE_CONTROL,
            expect::CT_THRESHOLDS
        ));
    }
    out
}

/// M2 review C3 (b): the sensitivity control runs with `tag_compare`'s batch size and sample count.
fn binding_findings(report: &Value, results: &[Value]) -> Vec<String> {
    let Some(tag) = results.iter().find(|r| text(r, "name") == "tag_compare") else {
        return vec!["ct report: no tag_compare target".to_owned()];
    };
    // a missing control is refused by `ct_sensitivity`
    let Some(control) = report.get("sensitivity_control").filter(|c| c.is_object()) else {
        return Vec::new();
    };
    ["k", "samples"]
        .into_iter()
        .filter(|key| {
            control.get(*key).and_then(Value::as_u64) != tag.get(*key).and_then(Value::as_u64)
        })
        .map(|key| {
            format!(
                "ct report: min_leak_control {key} {:?} is not tag_compare's {:?}",
                control.get(key),
                tag.get(key)
            )
        })
        .collect()
}

/// M2 review C3 (a), (f): per measured target, a quiet inline A/A control, and a verdict (with its deciding crop)
/// that the recorded crops, `q_eff_ticks` and `tick_ns` give; F17: both measurements' `q_eff_ticks` within
/// [`q_eff_bound`].
fn target_findings(
    report: &Value,
    results: &[Value],
    run_verdict: &str,
    targets: TargetSet,
) -> Vec<String> {
    let mut out = Vec::new();
    let tick = tick_ns(report);
    let q_bound = q_eff_bound(report);
    for r in results {
        let (name, verdict) = (text(r, "name"), text(r, "verdict"));
        if verdict == "NOT_MEASURABLE" {
            continue;
        }
        match r
            .get("aa_control")
            .filter(|m| !m.is_null())
            .and_then(max_abs_t)
        {
            Some(t) if t - HALF_T <= expect::CT_AA_MAX_T => {}
            Some(t) => out.push(format!(
                "ct report: {name} A/A |t| {t} above {} in a {run_verdict} run",
                expect::CT_AA_MAX_T
            )),
            None => out.push(format!("ct report: {name} has no readable A/A measurement")),
        }
        if targets.batch_record && matches!(verdict, "PASS" | "SUB_FLOOR_SHIFT" | "FAIL") {
            out.extend(batch_findings(r));
        }
        if r.get("control").and_then(Value::as_bool) == Some(true)
            || !matches!(verdict, "PASS" | "SUB_FLOOR_SHIFT" | "FAIL")
        {
            continue;
        }
        // F17: an effective quantum above the clock's bound would raise the floor; refused, whatever the verdict
        for key in ["first", "second"] {
            let q = r.get(key).and_then(q_eff);
            match (q, q_bound) {
                (Some(q), Some(bound)) if q - HALF_Q <= bound => {}
                (Some(q), Some(bound)) => out.push(format!(
                    "ct report: {name} {key} q_eff_ticks {q} above the bound {bound:.3} (max(clock q_eff, {} ns) + 1 \
                     tick)",
                    expect::CT_EFFECT_FLOOR_NS
                )),
                // an unreadable q_eff is refused below
                (None, _) => {}
                (Some(_), None) => out.push(format!(
                    "ct report: {name} {verdict}, but the clock has no readable q_eff_ticks and tick_ns to bound its \
                     effective quantum"
                )),
            }
        }
        let possible = match (r.get("first"), r.get("second"), tick) {
            (Some(first), Some(second), Some(tick)) => possible_verdicts(first, second, tick),
            _ => None,
        };
        let Some(possible) = possible else {
            out.push(format!(
                "ct report: {name} {verdict}, but its measurements are unreadable (crops, q_eff_ticks ≥ 1, tick_ns)"
            ));
            continue;
        };
        if !possible.verdicts.contains(verdict) {
            out.push(format!(
                "ct report: {name} {verdict}, but its recorded crops give {:?}",
                possible.verdicts
            ));
        }
        if verdict != "PASS" {
            let crop = r.get("decisive_crop").and_then(Value::as_str);
            if !crop.is_some_and(|c| possible.reproducible.contains(c)) {
                out.push(format!(
                    "ct report: {name} {verdict} at {crop:?}, where no shift is reproduced"
                ));
            }
        }
        // ADR-042 (2): the A/A′ placement control at or above the floor makes the run CONTROL_FAIL, never FAIL
        if name == expect::CT_AA_PRIME_CONTROL && verdict == "FAIL" {
            out.push(format!(
                "ct report: {name} FAIL in a {run_verdict} run: the A/A′ placement control reached the effect floor, \
                 which makes the run CONTROL_FAIL (ADR-042)"
            ));
        }
        // ADR-042 Amendment 2: so does the same-content control
        if name == expect::CT_SAME_CONTENT_CONTROL && verdict == "FAIL" {
            out.push(format!(
                "ct report: {name} FAIL in a {run_verdict} run: the same-content control reached the effect floor, \
                 which makes the run CONTROL_FAIL (ADR-042 Amendment 2)"
            ));
        }
        // ADR-042 Amendment 3 (M4 review C-2): so does the HX same-content control
        if name == expect::CT_HX_SAME_CONTENT_CONTROL && verdict == "FAIL" {
            out.push(format!(
                "ct report: {name} FAIL in a {run_verdict} run: the HX same-content control reached the effect floor, \
                 which makes the run CONTROL_FAIL (ADR-042 Amendment 3)"
            ));
        }
    }
    out
}

/// ADR-041 Amendment 2 (M3 review R-57): the batch sizes of a judged target as the report records them — every
/// measurement (the pair and the A/A measurement) taken with the target's `k`; `requantised` consistent with the two
/// batch sizes (`k_initial < k` after the one re-batch, `k_initial = k` without); and each measurement of the pair
/// realising at least `CT_MIN_REALISED_QUANTA` effective quanta (class median / `q_eff_ticks`; refused only if surely
/// below within the printed rounding of `q_eff_ticks`), which the bench requires of a pair it judges. An unreadable
/// `q_eff_ticks` is refused by `target_findings`.
fn batch_findings(r: &Value) -> Vec<String> {
    let name = text(r, "name");
    let mut out = Vec::new();
    let k = r.get("k").and_then(Value::as_u64);
    let k_initial = r.get("k_initial").and_then(Value::as_u64);
    let requantised = r.get("requantised").and_then(Value::as_bool);
    match (k, k_initial, requantised) {
        (Some(k), Some(k0), Some(true)) if k0 < k => {}
        (Some(k), Some(k0), Some(false)) if k0 == k => {}
        _ => out.push(format!(
            "ct report: {name} records k {k:?}, k_initial {k_initial:?} and requantised {requantised:?}, which is no \
             first pair or one re-batch (ADR-041 Amendment 2)"
        )),
    }
    let min = u32::try_from(expect::CT_MIN_REALISED_QUANTA).map_or(f64::INFINITY, f64::from);
    for key in ["first", "second", "aa_control"] {
        let Some(m) = r.get(key).filter(|m| !m.is_null()) else {
            continue;
        };
        let taken = m.get("k").and_then(Value::as_u64);
        if taken.is_none() || taken != k {
            out.push(format!(
                "ct report: {name} {key} taken with k {taken:?}, not the target's k {k:?}"
            ));
        }
        if key == "aa_control" {
            continue;
        }
        // M3 review F-ctreport: a measurement without a readable median cannot be shown to realise the minimum, so
        // it is refused (this function runs only for the target sets of the ADR-041 Amendment 2 record format)
        let median = m.get("class_median_ticks").and_then(Value::as_f64);
        if median.is_none() {
            out.push(format!("ct report: {name} {key} has no class_median_ticks"));
        }
        if let (Some(median), Some(q)) = (median, q_eff(m))
            && median < min * (q - HALF_Q)
        {
            out.push(format!(
                "ct report: {name} {key} realises fewer than {min} quanta (class median {median} ticks, q_eff {q} \
                 ticks): a pair the bench cannot judge (ADR-041 Amendment 2 (3))"
            ));
        }
    }
    out
}

/// M2 review C3 (a)–(c), (f): the re-derivation of a report against the target set `targets`. Every finding is a
/// refusal. In a `CONTROL_FAIL` run no target verdict counts, and each must say `CONTROL_FAIL`.
fn rederive(
    report: &Value,
    run_verdict: &str,
    results: &[Value],
    targets: TargetSet,
) -> Vec<String> {
    let mut out = set_findings(report, results, targets);
    out.extend(control_findings(results, run_verdict));
    out.extend(binding_findings(report, results));
    if let Some(control) = control_pair(report) {
        out.extend(pair_record_findings(report, control));
    }
    if run_verdict == "CONTROL_FAIL" {
        out.extend(
            results
                .iter()
                .filter(|r| text(r, "verdict") != "CONTROL_FAIL")
                .map(|r| {
                    format!(
                        "ct report: {} is {} in a CONTROL_FAIL run",
                        text(r, "name"),
                        text(r, "verdict")
                    )
                }),
        );
    } else {
        out.extend(target_findings(report, results, run_verdict, targets));
    }
    out
}

/// The gate's reading of a report (`expect::CT_TARGETS`).
pub(crate) fn ct_table(json: &str) -> Result<CtTable> {
    ct_table_for(json, CURRENT_TARGETS)
}

/// The gate's reading of a report against the target set `targets`.
pub(crate) fn ct_table_for(json: &str, targets: TargetSet) -> Result<CtTable> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("ct report: {e}")))?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        bail!("ct report: {e}");
    }
    ct_check_parameters(&v)?;
    let run_verdict = v
        .get("run_verdict")
        .and_then(Value::as_str)
        .filter(|rv| CT_RUN_VERDICTS.contains(rv))
        .ok_or_else(|| Error("ct report: no known run_verdict".to_owned()))?;
    let resolution = v
        .get("clock")
        .and_then(|c| c.get("q_eff_ns"))
        .and_then(Value::as_f64);
    let results = v
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| Error("ct report: no results".to_owned()))?;
    let mut table = CtTable::default();
    if results.is_empty() {
        table
            .failed
            .push("ct report: no target was measured".to_owned());
    }
    if run_verdict == "CONTROL_FAIL" {
        // ADR-041 (3): the harness or the runner is unsound; no target verdict counts
        let reason = v.get("run_reason").and_then(Value::as_str).unwrap_or("?");
        table.failed.push(format!("CONTROL_FAIL — {reason}"));
    }
    for r in results {
        let (line, not_measurable, passes) = ct_line(r);
        let verdict = text(r, "verdict");
        if run_verdict != "CONTROL_FAIL" {
            if verdict == "NOT_MEASURABLE" {
                table.not_measurable.push(format!(
                    "{not_measurable}, effective quantum {} ns",
                    resolution.map_or_else(|| "?".to_owned(), |x| format!("{x:.1}"))
                ));
            } else if !passes {
                table.failed.push(line.clone());
            }
        }
        table.lines.push(line);
    }
    // M2 review C3 (e): a FAIL run has a failing or unmeasurable target
    if run_verdict == "FAIL" && table.failed.is_empty() && table.not_measurable.is_empty() {
        table
            .failed
            .push("ct report: run verdict FAIL without a failing target".to_owned());
    }
    // ADR-041 Amendment 1 (2), Amendment 3: a control below the floor, or one the verdict rule did not catch, must have
    // made the run CONTROL_FAIL
    let (sensitivity, reached) = ct_sensitivity(&v);
    if !reached && run_verdict != "CONTROL_FAIL" {
        let missed = if control_pair(&v).is_some() {
            "the verdict rule did not catch the sensitivity control"
        } else {
            "the sensitivity control did not reach the floor"
        };
        table.failed.push(format!(
            "ct report: run verdict {run_verdict} although {missed} — {sensitivity}"
        ));
    }
    table.lines.push(sensitivity);
    if let Some(line) = ct_same_content_line(&v) {
        table.lines.push(line);
    }
    table
        .failed
        .extend(rederive(&v, run_verdict, results, targets));
    if run_verdict == "PASS" && !(table.failed.is_empty() && table.not_measurable.is_empty()) {
        table
            .failed
            .push("ct report: run verdict PASS with a failing target".to_owned());
    }
    Ok(table)
}

/// The arguments of `ct-check`: an optional `--targets m2` (the target set of the committed M2 reports, before
/// ADR-042) or `--targets current` (the default, `expect::CT_TARGETS`), then the report files.
fn check_args(args: &[String]) -> Result<(TargetSet, &[String])> {
    let usage = "usage: cargo xtask ct-check [--targets current|m2] <ct-report.json>…";
    let (targets, files) = match args {
        [flag, set, files @ ..] if flag == "--targets" => match set.as_str() {
            "current" => (CURRENT_TARGETS, files),
            "m2" => (M2_TARGETS, files),
            other => bail!("ct-check: unknown target set {other:?}; {usage}"),
        },
        [flag, ..] if flag.starts_with('-') => bail!("ct-check: unknown option {flag:?}; {usage}"),
        files => (CURRENT_TARGETS, files),
    };
    if files.is_empty() {
        bail!("{usage}");
    }
    Ok((targets, files))
}

/// `cargo xtask ct-check [--targets current|m2] <report>…`: the gate's reading of saved reports (M2 review C3: every
/// committed report of the ADR-041 Amendment 1 format must still pass; the M2 reports are read against the M2 target
/// set). Fails unless every report passes.
pub(crate) fn check_files(args: &[String]) -> Result<()> {
    let (targets, args) = check_args(args)?;
    say(&format!("ct-check against {}", targets.label));
    let mut refused = 0_usize;
    for file in args {
        let json = std::fs::read_to_string(file)?;
        match ct_table_for(&json, targets) {
            Ok(t) if t.failed.is_empty() && t.not_measurable.is_empty() => {
                say(&format!("PASS {file}"));
            }
            Ok(t) => {
                refused = refused.saturating_add(1);
                say(&format!(
                    "FAIL {file}: {}",
                    [t.failed, t.not_measurable].concat().join("; ")
                ));
            }
            Err(e) => {
                refused = refused.saturating_add(1);
                say(&format!("REFUSED {file}: {e}"));
            }
        }
    }
    if refused > 0 {
        bail!("{refused} of {} ct reports do not pass", args.len());
    }
    say(&format!("ct-check: {} reports pass", args.len()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CROPS: [&str; 6] = ["raw", "p50", "p75", "p90", "p95", "p99"];

    /// A measurement: at every crop, `t` and Δ `delta` ticks; `q_eff` 1 tick.
    fn measurement(t: f64, delta: f64) -> Value {
        let crop = serde_json::json!({"n0": 5, "n1": 5, "mean0": 1.0, "mean1": 1.0, "delta": delta,
            "delta_q": delta, "delta_floor": 0.0, "sd": 1.0, "t": t});
        let crops: serde_json::Map<String, Value> = CROPS
            .iter()
            .map(|c| ((*c).to_owned(), crop.clone()))
            .collect();
        serde_json::json!({"max_abs_t": t.abs(), "max_at": "p90", "t": {}, "crops": crops, "q_eff_ticks": 1.0,
            "q_eff_source": "clock", "floor_ticks": 20.0, "floor_ns": 10.0, "distinct": 900,
            "median_ticks": 6000, "median_ns": 3000.0, "class_median_ticks": 6000, "realised_quanta": 6000.0,
            "k": 1})
    }

    /// A PASS target (t 1, Δ 0.1 tick in both measurements, A/A t 1.25).
    fn target(name: &str) -> Value {
        let control = name == expect::CT_POSITIVE_CONTROL;
        let samples = if name == "sas" {
            expect::CT_SAS_SAMPLES
        } else {
            expect::CT_SAMPLES
        };
        serde_json::json!({"name": name, "class0": "a", "class1": "b", "samples": samples, "control": control,
            "k": 1, "requantised": false, "k_initial": 1, "calibration_median_ticks": 3000,
            "calibration_median_ns": 1500.0, "verdict": "PASS",
            "passed": true, "decisive_crop": null, "aa_passed": true, "aa_control": measurement(1.25, 0.1),
            "first": if control { measurement(99.0, 500.0) } else { measurement(1.0, 0.1) },
            "second": if control { Value::Null } else { measurement(1.0, 0.1) }})
    }

    /// A report that passes: every target of `expect::CT_TARGETS` PASS, a 0.5 ns clock (floor 20 ticks = 10 ns) and
    /// a sensitivity control of 450 ns (900 ticks) with `tag_compare`'s `k` and samples.
    fn report() -> Value {
        let results: Vec<Value> = expect::CT_TARGETS.iter().map(|t| target(t)).collect();
        serde_json::json!({
            "thresholds": {"pass": expect::CT_THRESHOLDS, "max_resolution_fraction": expect::CT_RESOLUTION_MAX_FRACTION,
                "max_batch": expect::CT_MAX_BATCH, "batch_margin": expect::CT_BATCH_MARGIN,
                "min_realised_quanta": expect::CT_MIN_REALISED_QUANTA,
                "effect_floor_quanta": expect::CT_EFFECT_FLOOR_QUANTA, "effect_floor_ns": expect::CT_EFFECT_FLOOR_NS,
                "aa_max_t": expect::CT_AA_MAX_T, "samples": expect::CT_SAMPLES, "sas_samples": expect::CT_SAS_SAMPLES},
            "sign": "t < 0: class 0 faster",
            "clock": {"timer": "rdtscp", "tick_ns": 0.5, "resolution_ns": 0.5, "q_eff_ticks": 1.0, "q_eff_ns": 0.5},
            "run_verdict": "PASS", "run_reason": null,
            "sensitivity_control": {"name": "min_leak_control", "k": 1, "samples": expect::CT_SAMPLES,
                "floor_ticks": 20.0, "floor_ns": 10.0, "raw_delta_ticks": 900.0, "raw_delta_ns": 450.0,
                "raw_delta_floor": 45.0, "reached": true, "measurement": {"max_abs_t": 1500.0, "max_at": "p50",
                "t": {}, "crops": {}, "q_eff_ticks": 1.0, "q_eff_source": "clock", "distinct": 900,
                "median_ticks": 20000, "median_ns": 10000.0, "class_median_ticks": 20000,
                "realised_quanta": 20000.0}},
            "results": results
        })
    }

    fn table(v: &Value) -> Result<CtTable> {
        ct_table(&v.to_string())
    }

    /// The target named `name`, mutably.
    fn at<'a>(v: &'a mut Value, name: &str) -> &'a mut Value {
        let results = v.get_mut("results").and_then(Value::as_array_mut);
        results
            .and_then(|r| r.iter_mut().find(|t| text(t, "name") == name))
            .unwrap_or_else(|| unreachable!("fixture target {name}"))
    }

    fn set(v: &mut Value, path: &[&str], value: Value) {
        let mut cur = v;
        for key in path {
            cur = cur
                .get_mut(*key)
                .unwrap_or_else(|| unreachable!("fixture path {path:?}"));
        }
        *cur = value;
    }

    fn refused(v: &Value, needle: &str) -> Result<bool> {
        let t = table(v)?;
        Ok(t.failed.iter().any(|f| f.contains(needle)))
    }

    /// A measurement with `q_eff` ticks: `t` and Δ per crop as given, every other crop at t 1, Δ 0.1.
    fn measurement_with(crops: &[(&str, f64, f64)], q_eff: f64) -> Value {
        let mut m = measurement(1.0, 0.1);
        for (crop, t, delta) in crops {
            set(&mut m, &["crops", crop, "t"], Value::from(*t));
            set(&mut m, &["crops", crop, "delta"], Value::from(*delta));
        }
        set(&mut m, &["q_eff_ticks"], Value::from(q_eff));
        m
    }

    /// The refusals of a report, without the one derived from them ("run verdict PASS with a failing target"), and
    /// with nothing reported as not measurable: a fixture whose refusals are exactly one check's findings passes
    /// once that check is removed.
    fn refusals(v: &Value) -> Result<Vec<String>> {
        let t = table(v)?;
        assert!(t.not_measurable.is_empty(), "{t:?}");
        Ok(t.failed
            .into_iter()
            .filter(|f| f != "ct report: run verdict PASS with a failing target")
            .collect())
    }

    /// `tag_compare` with both measurements as given, its verdict and deciding crop; the run verdict follows.
    fn tag_compare_with(first: Value, second: Value, verdict: &str, crop: Option<&str>) -> Value {
        let mut v = report();
        if verdict == "FAIL" {
            set(&mut v, &["run_verdict"], Value::from("FAIL"));
        }
        let tag = at(&mut v, "tag_compare");
        set(tag, &["first"], first);
        set(tag, &["second"], second);
        set(tag, &["verdict"], Value::from(verdict));
        set(
            tag,
            &["decisive_crop"],
            crop.map_or(Value::Null, Value::from),
        );
        v
    }

    /// Whether the gate accepts `tag_compare` with t `t1`/`t2` and Δ `delta` ticks at every crop (effective quantum
    /// `q`) under `verdict` (a FAIL counts as accepted when its only refusal is the failing target itself).
    fn accepts(t1: f64, t2: f64, delta: f64, q: f64, verdict: &str) -> Result<bool> {
        let all = |t: f64| {
            let crops: Vec<(&str, f64, f64)> = CROPS.iter().map(|c| (*c, t, delta)).collect();
            measurement_with(&crops, q)
        };
        let crop = (verdict != "PASS").then_some("p90");
        let v = tag_compare_with(all(t1), all(t2), verdict, crop);
        Ok(refusals(&v)?
            .iter()
            .all(|f| f.starts_with("tag_compare: FAIL at p90")))
    }

    #[test]
    fn a_consistent_report_passes_and_is_printed() -> Result<()> {
        let mut v = report();
        // a sub-floor shift: reproduced (t 30 / 25), Δ 5 ticks < floor 20
        let msg = at(&mut v, "msg_open_reject");
        set(msg, &["first"], measurement(30.0, 5.0));
        set(msg, &["second"], measurement(25.0, 5.0));
        set(msg, &["verdict"], Value::from("SUB_FLOOR_SHIFT"));
        set(msg, &["decisive_crop"], Value::from("p90"));
        let t = table(&v)?;
        assert!(t.failed.is_empty() && t.not_measurable.is_empty(), "{t:?}");
        assert_eq!(t.lines.len(), expect::CT_TARGETS.len().saturating_add(1));
        assert!(
            t.lines
                .iter()
                .any(|l| l.contains("positive control, must be detected"))
        );
        assert!(
            t.lines.iter().any(|l| l.starts_with(
                "min_leak_control: REACHED — raw Δ 450.00 ns, floor 10.00 ns (45.00 floors), k=1, 1000000 samples; max |t| = 1500.00 (p50)"
            )),
            "{t:?}"
        );
        assert!(
            t.lines.iter().any(|l| l.starts_with("msg_open_reject: SUB_FLOOR_SHIFT at p90 — k=1, calibration median 1500.0 ns")
                && l.contains("first max |t| = 30.00 (p90), batch median 3000.0 ns, q_eff 1.0 ticks (clock), realised 6000.0 quanta")
                && l.contains("second max |t| = 25.00 (p90)")
                && l.contains("A/A max |t| = 1.25 (p90)")),
            "{t:?}"
        );
        Ok(())
    }

    #[test]
    fn failing_and_unknown_verdicts_fail_the_gate() -> Result<()> {
        // a FAIL the crops give (Δ 30 ticks ≥ floor 20 in both, t 30 / 25) fails the gate
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("FAIL"));
        let tag = at(&mut v, "tag_compare");
        set(tag, &["first"], measurement(30.0, 30.0));
        set(tag, &["second"], measurement(25.0, 30.0));
        set(tag, &["verdict"], Value::from("FAIL"));
        set(tag, &["decisive_crop"], Value::from("p90"));
        let t = table(&v)?;
        assert_eq!(t.failed.len(), 1, "{t:?}");
        // verdicts ADR-041 and its Amendment 1 withdrew, and unknown ones, fail closed
        for bad in [
            "INCONCLUSIVE→FAIL",
            "INCONCLUSIVE→PASS",
            "SUB_QUANTUM_SHIFT",
            "MAYBE",
        ] {
            let mut v = report();
            set(&mut v, &["run_verdict"], Value::from("FAIL"));
            set(at(&mut v, "sas"), &["verdict"], Value::from(bad));
            assert!(!table(&v)?.failed.is_empty(), "{bad}");
        }
        // NOT_MEASURABLE is reported separately
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("FAIL"));
        let derive = at(&mut v, "caead_derive");
        set(derive, &["verdict"], Value::from("NOT_MEASURABLE"));
        set(derive, &["k"], Value::Null);
        for key in ["first", "second", "aa_control"] {
            set(derive, &[key], Value::Null);
        }
        let t = table(&v)?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert_eq!(
            t.not_measurable,
            vec!["caead_derive (median 1500.0 ns), effective quantum 0.5 ns".to_owned()]
        );
        Ok(())
    }

    /// C3 (a): a verdict the recorded crops do not give is refused: a PASS whose crops reproduce a relevant shift,
    /// a FAIL below the floor, a `SUB_FLOOR_SHIFT` at a crop without a reproduced shift.
    #[test]
    fn refuses_a_verdict_the_crops_do_not_give() -> Result<()> {
        let mut v = report();
        let tag = at(&mut v, "tag_compare");
        set(tag, &["first"], measurement(30.0, 30.0));
        set(tag, &["second"], measurement(25.0, 30.0));
        assert!(refused(
            &v,
            "tag_compare PASS, but its recorded crops give"
        )?);
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("FAIL"));
        let tag = at(&mut v, "tag_compare");
        set(tag, &["first"], measurement(30.0, 5.0));
        set(tag, &["second"], measurement(25.0, 5.0));
        set(tag, &["verdict"], Value::from("FAIL"));
        set(tag, &["decisive_crop"], Value::from("p90"));
        assert!(refused(
            &v,
            "tag_compare FAIL, but its recorded crops give"
        )?);
        let mut v = report();
        let tag = at(&mut v, "tag_compare");
        set(tag, &["verdict"], Value::from("SUB_FLOOR_SHIFT"));
        set(tag, &["decisive_crop"], Value::from("p90"));
        assert!(refused(&v, "where no shift is reproduced")?);
        // at the edge of the printed rounding both readings are accepted: t 4.5 is |t| ≤ 4.5 or 4.5004 > 4.5
        let mut v = report();
        let tag = at(&mut v, "tag_compare");
        set(tag, &["first"], measurement(4.5, 1.0));
        set(tag, &["second"], measurement(4.5, 1.0));
        assert!(table(&v)?.failed.is_empty());
        set(
            at(&mut v, "tag_compare"),
            &["verdict"],
            Value::from("SUB_FLOOR_SHIFT"),
        );
        set(
            at(&mut v, "tag_compare"),
            &["decisive_crop"],
            Value::from("p90"),
        );
        assert!(table(&v)?.failed.is_empty());
        Ok(())
    }

    /// C3 (a): the positive control must be there, exactly once, and detected.
    #[test]
    fn refuses_a_missing_or_undetected_positive_control() -> Result<()> {
        let mut v = report();
        set(
            at(&mut v, expect::CT_POSITIVE_CONTROL),
            &["control"],
            Value::from(false),
        );
        assert!(refused(&v, "positive controls")?);
        let mut v = report();
        set(at(&mut v, "sas"), &["control"], Value::from(true));
        assert!(refused(&v, "positive controls")?);
        let mut v = report();
        set(
            at(&mut v, expect::CT_POSITIVE_CONTROL),
            &["first"],
            measurement(3.0, 500.0),
        );
        assert!(refused(&v, "PASS, but its crops do not exceed")?);
        Ok(())
    }

    /// F15: the positive control is checked for detection whatever its label says, and its label must be one the
    /// bench can give it. Each fixture sits on one check's edge: its refusals are that check's finding alone.
    #[test]
    fn the_positive_control_is_checked_whatever_its_label() -> Result<()> {
        let control = expect::CT_POSITIVE_CONTROL;
        // a passing label the bench never gives the control, detected: the label check alone
        let mut v = report();
        set(
            at(&mut v, control),
            &["verdict"],
            Value::from("SUB_FLOOR_SHIFT"),
        );
        assert_eq!(
            refusals(&v)?,
            vec![format!(
                "ct report: the positive control {control} is SUB_FLOOR_SHIFT; it can only be [\"PASS\", \"FAIL\", \"NOT_MEASURABLE\"]"
            )]
        );
        // the same label, not detected: both checks (before F15 this report passed the gate)
        set(at(&mut v, control), &["first"], measurement(3.0, 500.0));
        assert_eq!(refusals(&v)?.len(), 2, "{:?}", refusals(&v)?);
        assert!(refused(
            &v,
            "SUB_FLOOR_SHIFT, but its crops do not exceed |t| 4.5"
        )?);
        // PASS at the edge of the printed rounding: 4.5 may be 4.5004 > 4.5; 4.4994 is at most 4.4999
        let mut v = report();
        set(at(&mut v, control), &["first"], measurement(4.4996, 500.0));
        assert!(refusals(&v)?.is_empty());
        set(at(&mut v, control), &["first"], measurement(4.4994, 500.0));
        assert_eq!(
            refusals(&v)?,
            vec![format!(
                "ct report: {control} PASS, but its crops do not exceed |t| 4.5 (the positive control must be detected)"
            )]
        );
        // NOT_MEASURABLE or FAIL: still checked (the gate fails on those labels anyway)
        for label in ["FAIL", "NOT_MEASURABLE"] {
            let mut v = report();
            set(&mut v, &["run_verdict"], Value::from("FAIL"));
            set(at(&mut v, control), &["verdict"], Value::from(label));
            set(at(&mut v, control), &["first"], measurement(3.0, 500.0));
            assert!(refused(
                &v,
                &format!("{control} {label}, but its crops do not exceed")
            )?);
        }
        // in a CONTROL_FAIL run no target verdict counts, the control's neither
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("CONTROL_FAIL"));
        for name in expect::CT_TARGETS {
            set(at(&mut v, name), &["verdict"], Value::from("CONTROL_FAIL"));
        }
        set(at(&mut v, control), &["first"], measurement(3.0, 500.0));
        assert_eq!(table(&v)?.failed, vec!["CONTROL_FAIL — ?".to_owned()]);
        Ok(())
    }

    /// F16: a `SUB_FLOOR_SHIFT` is refused when another crop reproduces a shift surely at or above the floor (the
    /// `!fail_sure` condition of `possible_verdicts`); the report's refusals are that finding alone, and the
    /// deciding crop of such a report can only be a FAIL.
    #[test]
    fn refuses_a_sub_floor_shift_next_to_a_relevant_crop() -> Result<()> {
        let first = measurement_with(&[("p50", 30.0, 30.0), ("p90", 30.0, 5.0)], 1.0);
        let second = measurement_with(&[("p50", 25.0, 30.0), ("p90", 25.0, 5.0)], 1.0);
        let v = tag_compare_with(
            first.clone(),
            second.clone(),
            "SUB_FLOOR_SHIFT",
            Some("p90"),
        );
        assert_eq!(
            refusals(&v)?,
            vec![
                "ct report: tag_compare SUB_FLOOR_SHIFT, but its recorded crops give {\"FAIL\"}"
                    .to_owned()
            ]
        );
        // the same crops without the relevant p50 give a sub-floor shift
        let sub_first = measurement_with(&[("p90", 30.0, 5.0)], 1.0);
        let sub_second = measurement_with(&[("p90", 25.0, 5.0)], 1.0);
        assert!(
            refusals(&tag_compare_with(
                sub_first,
                sub_second,
                "SUB_FLOOR_SHIFT",
                Some("p90")
            ))?
            .is_empty()
        );
        // and the mixed crops as FAIL at p50: accepted
        let v = tag_compare_with(first, second, "FAIL", Some("p50"));
        assert_eq!(
            refusals(&v)?.len(),
            1,
            "only the failing target itself: {:?}",
            refusals(&v)?
        );
        Ok(())
    }

    /// F16: the effect floor of a target is tight on both sides of the printed rounding, for its 10 ns part (`q_eff` 1
    /// tick on a 0.5 ns clock: 20 ticks) and for its `q_eff` part (20.5 ticks): each edge is probed 1e-5 ticks on
    /// either side (literal values, so that a changed constant cannot move the probes with it). A floor scaled by 1.4
    /// or by 0.99, and a rounding allowance of Δ (5e-5) or of `q_eff` (5e-4) changed by more than 1e-5, fail this
    /// test.
    #[test]
    fn the_effect_floor_is_tight_on_both_sides() -> Result<()> {
        // (q_eff, FAIL edge = floor − q rounding − Δ rounding, SUB_FLOOR_SHIFT edge = floor + both)
        for (q, fail_edge, sub_edge) in [
            // 10 ns on a 0.5 ns clock: 20 ticks, whatever the rounding of q_eff 1
            (1.0, 19.999_95, 20.000_05),
            // one q_eff of 20.5 ticks: 20.5 ∓ 5e-4 ∓ 5e-5
            (20.5, 20.499_45, 20.500_55),
        ] {
            // FAIL needs a crop that may reach the floor
            assert!(!accepts(30.0, 25.0, fail_edge - 1e-5, q, "FAIL")?, "q {q}");
            assert!(accepts(30.0, 25.0, fail_edge + 1e-5, q, "FAIL")?, "q {q}");
            assert!(accepts(30.0, 25.0, fail_edge - 1e-5, q, "SUB_FLOOR_SHIFT")?);
            // SUB_FLOOR_SHIFT needs no crop that surely reaches it
            assert!(
                accepts(30.0, 25.0, sub_edge - 1e-5, q, "SUB_FLOOR_SHIFT")?,
                "q {q}"
            );
            assert!(
                !accepts(30.0, 25.0, sub_edge + 1e-5, q, "SUB_FLOOR_SHIFT")?,
                "q {q}"
            );
            assert!(accepts(30.0, 25.0, sub_edge + 1e-5, q, "FAIL")?);
        }
        Ok(())
    }

    /// F16: the t threshold is tight on both sides of the printed rounding (t to 3 decimals, ±5e-4): a shift at
    /// |t| 4.4994 is never reproduced, one at 4.4996 may be; one at 4.5006 surely is, one at 4.5004 may not be.
    #[test]
    fn the_t_threshold_is_tight_on_both_sides() -> Result<()> {
        // literal values (4.5 ∓ 5e-4 ± 1e-4), so that a changed constant cannot move the probes with it
        assert!(!accepts(4.4994, 25.0, 30.0, 1.0, "FAIL")?);
        assert!(!accepts(25.0, 4.4994, 30.0, 1.0, "FAIL")?);
        assert!(accepts(4.4996, 25.0, 30.0, 1.0, "FAIL")?);
        assert!(accepts(25.0, 4.4996, 30.0, 1.0, "FAIL")?);
        assert!(accepts(4.4994, 25.0, 30.0, 1.0, "PASS")?);
        assert!(accepts(4.5004, 25.0, 30.0, 1.0, "PASS")?);
        assert!(!accepts(4.5006, 25.0, 30.0, 1.0, "PASS")?);
        assert!(!accepts(25.0, 4.5006, 30.0, 1.0, "PASS")?);
        // opposite signs never reproduce
        assert!(accepts(-30.0, 25.0, 30.0, 1.0, "PASS")?);
        assert!(!accepts(-30.0, 25.0, 30.0, 1.0, "FAIL")?);
        Ok(())
    }

    /// F16: the positive control must be `expect::CT_POSITIVE_CONTROL`: another target flagged as the one control,
    /// detected, with the real control measured like a passing target, is refused by the name check alone.
    #[test]
    fn refuses_another_target_as_the_positive_control() -> Result<()> {
        let mut v = report();
        let control = at(&mut v, expect::CT_POSITIVE_CONTROL);
        set(control, &["control"], Value::from(false));
        set(control, &["second"], measurement(1.0, 0.1));
        let sas = at(&mut v, "sas");
        set(sas, &["control"], Value::from(true));
        set(sas, &["first"], measurement(99.0, 500.0));
        assert_eq!(
            refusals(&v)?,
            vec![format!(
                "ct report: the positive control is sas, expected {}",
                expect::CT_POSITIVE_CONTROL
            )]
        );
        Ok(())
    }

    /// F16: a target measured twice is refused by the duplicate check alone (the set of names is still
    /// `expect::CT_TARGETS`).
    #[test]
    fn refuses_a_duplicated_target() -> Result<()> {
        let mut v = report();
        let sas = at(&mut v, "sas").clone();
        if let Some(r) = v.get_mut("results").and_then(Value::as_array_mut) {
            r.push(sas);
        }
        let found = refusals(&v)?;
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found
                .iter()
                .all(|f| f.contains("differ from expect::CT_TARGETS") && f.contains("\"sas\"]"))
        );
        Ok(())
    }

    /// F17: a target's `q_eff_ticks` is bounded by `max(clock q_eff, 10 ns) + 1 tick`, so an inflated quantum cannot
    /// turn a FAIL into a `SUB_FLOOR_SHIFT`: t 30/25 and Δ 30 ticks with `q_eff` 40 claimed as sub-floor is refused
    /// by the bound alone; the bound is tight to the printed rounding for both of its parts.
    #[test]
    fn refuses_an_effective_quantum_above_the_clock_bound() -> Result<()> {
        let all = |t: f64, q: f64| {
            let crops: Vec<(&str, f64, f64)> = CROPS.iter().map(|c| (*c, t, 30.0)).collect();
            measurement_with(&crops, q)
        };
        let v = tag_compare_with(
            all(30.0, 40.0),
            all(25.0, 40.0),
            "SUB_FLOOR_SHIFT",
            Some("p90"),
        );
        assert_eq!(
            refusals(&v)?,
            vec![
                "ct report: tag_compare first q_eff_ticks 40 above the bound 21.000 (max(clock q_eff, 10 ns) + 1 tick)"
                    .to_owned(),
                "ct report: tag_compare second q_eff_ticks 40 above the bound 21.000 (max(clock q_eff, 10 ns) + 1 tick)"
                    .to_owned()
            ]
        );
        // the 10 ns part: tick 0.5 ns, clock q_eff 1 → bound 21 ticks
        let at_q = |q: f64, clock_q: f64, tick: f64| -> Result<Vec<String>> {
            let mut v = tag_compare_with(all(30.0, q), all(25.0, q), "FAIL", Some("p90"));
            set(&mut v, &["clock", "q_eff_ticks"], Value::from(clock_q));
            set(&mut v, &["clock", "tick_ns"], Value::from(tick));
            Ok(refusals(&v)?
                .into_iter()
                .filter(|f| f.contains("above the bound"))
                .collect())
        };
        assert!(at_q(21.0004, 1.0, 0.5)?.is_empty());
        assert_eq!(at_q(21.0006, 1.0, 0.5)?.len(), 2);
        // the clock part: 26 ticks of 0.385 ns (10.01 ns, above 10 ns) → bound 27 ticks
        assert!(at_q(27.0004, 26.0, 0.385)?.is_empty());
        assert_eq!(at_q(27.0006, 26.0, 0.385)?.len(), 2);
        // no clock quantum: the measurement cannot be bounded and is refused
        let mut v = report();
        if let Some(clock) = v.get_mut("clock").and_then(Value::as_object_mut) {
            clock.remove("q_eff_ticks");
        }
        assert!(refused(&v, "the clock has no readable q_eff_ticks")?);
        Ok(())
    }

    /// C3 (a): the inline A/A control stays quiet in a run that is not `CONTROL_FAIL`.
    #[test]
    fn refuses_an_aa_control_above_its_threshold() -> Result<()> {
        let mut v = report();
        set(
            at(&mut v, "msg_open_reject"),
            &["aa_control"],
            measurement(6.0, 0.1),
        );
        assert!(refused(&v, "msg_open_reject A/A |t| 6")?);
        let mut v = report();
        set(at(&mut v, "msg_open_reject"), &["aa_control"], Value::Null);
        assert!(refused(
            &v,
            "msg_open_reject has no readable A/A measurement"
        )?);
        Ok(())
    }

    /// C3 (a): the target set is `expect::CT_TARGETS`.
    #[test]
    fn refuses_another_target_set() -> Result<()> {
        let mut v = report();
        if let Some(r) = v.get_mut("results").and_then(Value::as_array_mut) {
            r.retain(|t| text(t, "name") != "caead_aead_reject");
        }
        assert!(refused(&v, "differ from expect::CT_TARGETS")?);
        let mut v = report();
        set(
            at(&mut v, "caead_aead_reject"),
            &["name"],
            Value::from("caead_derive"),
        );
        assert!(refused(&v, "differ from expect::CT_TARGETS")?);
        Ok(())
    }

    /// C3 (b): the sensitivity control runs with `tag_compare`'s batch size and sample count, and `tag_compare` is
    /// there.
    #[test]
    fn refuses_a_sensitivity_control_not_bound_to_tag_compare() -> Result<()> {
        let mut v = report();
        set(&mut v, &["sensitivity_control", "k"], Value::from(2));
        assert!(refused(&v, "min_leak_control k")?);
        let mut v = report();
        set(&mut v, &["sensitivity_control", "samples"], Value::from(10));
        assert!(refused(&v, "min_leak_control samples")?);
        let mut v = report();
        set(at(&mut v, "tag_compare"), &["name"], Value::from("tag"));
        assert!(refused(&v, "no tag_compare target")?);
        Ok(())
    }

    /// C3 (c): the sample counts of `expect.rs`, per target and in the echo, and no shortened run.
    #[test]
    fn refuses_short_sample_counts_and_a_scaled_run() -> Result<()> {
        let mut v = report();
        set(at(&mut v, "tag_compare"), &["samples"], Value::from(10));
        set(&mut v, &["sensitivity_control", "samples"], Value::from(10));
        assert!(refused(&v, "tag_compare measured Some(10) samples")?);
        let mut v = report();
        set(
            at(&mut v, "sas"),
            &["samples"],
            Value::from(expect::CT_SAMPLES),
        );
        assert!(refused(&v, "sas measured")?);
        let mut v = report();
        set(&mut v, &["thresholds", "samples"], Value::from(10));
        assert!(table(&v).is_err());
        let mut v = report();
        if let Some(o) = v.as_object_mut() {
            o.insert("secmp_ct_scale".to_owned(), Value::from("50"));
        }
        assert!(refused(&v, "a shortened run")?);
        Ok(())
    }

    /// C3 (e): a FAIL run needs a failing or unmeasurable target.
    #[test]
    fn refuses_a_fail_run_without_a_failing_target() -> Result<()> {
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("FAIL"));
        assert!(refused(&v, "run verdict FAIL without a failing target")?);
        Ok(())
    }

    /// C3 (f): `q_eff_ticks` is a finite value of at least one tick, for the targets and the sensitivity control.
    #[test]
    fn refuses_an_effective_quantum_below_one_tick() -> Result<()> {
        let mut v = report();
        set(
            at(&mut v, "tag_compare"),
            &["first", "q_eff_ticks"],
            Value::from(0.5),
        );
        assert!(refused(&v, "measurements are unreadable")?);
        let mut v = report();
        set(
            &mut v,
            &["sensitivity_control", "measurement", "q_eff_ticks"],
            Value::from(0.0),
        );
        assert!(refused(&v, "sensitivity control did not reach the floor")?);
        Ok(())
    }

    /// `CONTROL_FAIL`: the run fails with its reason, and every target must say `CONTROL_FAIL`.
    #[test]
    fn control_fail_runs() -> Result<()> {
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("CONTROL_FAIL"));
        set(
            &mut v,
            &["run_reason"],
            Value::from("inline A/A control above 4.5: tag_compare |t| = 6.00 at p50"),
        );
        for name in expect::CT_TARGETS {
            set(at(&mut v, name), &["verdict"], Value::from("CONTROL_FAIL"));
        }
        let t = table(&v)?;
        assert_eq!(
            t.failed,
            vec![
                "CONTROL_FAIL — inline A/A control above 4.5: tag_compare |t| = 6.00 at p50"
                    .to_owned()
            ]
        );
        set(at(&mut v, "sas"), &["verdict"], Value::from("PASS"));
        assert!(refused(&v, "sas is PASS in a CONTROL_FAIL run")?);
        Ok(())
    }

    /// The sensitivity control: a `CONTROL_FAIL` below the floor is consistent; a run that ignores a missed floor, a
    /// missing control, a `reached` the numbers contradict and a floor below 10 ns or one quantum are refused.
    #[test]
    fn sensitivity_control() -> Result<()> {
        let mut below = report();
        set(&mut below, &["run_verdict"], Value::from("CONTROL_FAIL"));
        set(
            &mut below,
            &["run_reason"],
            Value::from("sensitivity control min_leak_control below the effect floor"),
        );
        for name in expect::CT_TARGETS {
            set(
                at(&mut below, name),
                &["verdict"],
                Value::from("CONTROL_FAIL"),
            );
        }
        set(
            &mut below,
            &["sensitivity_control", "raw_delta_ticks"],
            Value::from(16.0),
        );
        set(
            &mut below,
            &["sensitivity_control", "reached"],
            Value::from(false),
        );
        let t = table(&below)?;
        assert_eq!(
            t.failed,
            vec![
                "CONTROL_FAIL — sensitivity control min_leak_control below the effect floor"
                    .to_owned()
            ]
        );
        // (h) the ns are computed from the ticks: 16 ticks × 0.5 ns
        assert!(
            t.lines
                .iter()
                .any(|l| l.starts_with("min_leak_control: BELOW THE FLOOR — raw Δ 8.00 ns")),
            "{t:?}"
        );
        let needle = "sensitivity control did not reach the floor";
        for (path, value) in [
            (&["sensitivity_control", "reached"][..], Value::from(false)),
            // raw Δ 9.5 ns, a floor of 5 ns, a floor below one q_eff of 84 ticks, no tick length
            (
                &["sensitivity_control", "raw_delta_ticks"][..],
                Value::from(19.0),
            ),
            (
                &["sensitivity_control", "floor_ticks"][..],
                Value::from(10.0),
            ),
            (
                &["sensitivity_control", "measurement", "q_eff_ticks"][..],
                Value::from(84.0),
            ),
            (&["clock", "tick_ns"][..], Value::Null),
            (&["sensitivity_control", "measurement"][..], Value::Null),
            (&["sensitivity_control"][..], Value::Null),
        ] {
            let mut v = report();
            set(&mut v, path, value);
            assert!(refused(&v, needle)?, "{path:?}");
        }
        Ok(())
    }

    /// The sensitivity recheck at the edges of the printed rounding. linux-ct run 36678826377 (31d13de): a floor of
    /// exactly one `q_eff`, printed as 24.4928 ticks next to a `q_eff` of 24.493, reaches the floor. C3 (g): the
    /// refusals are tight — Δ = floor − 3e-4 ticks, floor = 10 ns / tick − 1.1e-4 and floor = `q_eff` − 1.2e-3 are
    /// refused (each would be accepted by a check up to 3 × looser).
    #[test]
    fn sensitivity_rounding_edges() -> Result<()> {
        let tick = 0.408_927_976_438_559_1;
        let run = |delta: f64, floor: f64, q: f64| -> Result<bool> {
            let mut v = report();
            set(&mut v, &["clock", "tick_ns"], Value::from(tick));
            set(
                &mut v,
                &["sensitivity_control", "raw_delta_ticks"],
                Value::from(delta),
            );
            set(
                &mut v,
                &["sensitivity_control", "floor_ticks"],
                Value::from(floor),
            );
            set(
                &mut v,
                &["sensitivity_control", "measurement", "q_eff_ticks"],
                Value::from(q),
            );
            Ok(!refused(&v, "sensitivity control did not reach the floor")?)
        };
        assert!(run(1100.5041, 24.4928, 24.493)?, "run 36678826377");
        let floor = 24.4928;
        assert!(!run(floor - 3e-4, floor, 24.493)?, "Δ = floor − 3e-4");
        assert!(
            run(floor - 1e-4, floor, 24.493)?,
            "Δ = floor − 1e-4 is rounding"
        );
        let floor_10ns = 10.0 / tick;
        assert!(
            !run(1100.0, floor_10ns - 1.1e-4, 1.0)?,
            "floor = 10 ns − 1.1e-4 ticks"
        );
        assert!(
            run(1100.0, floor_10ns - 4e-5, 1.0)?,
            "floor = 10 ns − 4e-5 ticks is rounding"
        );
        assert!(
            !run(1100.0, 24.493 - 1.2e-3, 24.493)?,
            "floor = q_eff − 1.2e-3"
        );
        assert!(
            run(1100.0, 24.493 - 5e-4, 24.493)?,
            "floor = q_eff − 5e-4 is rounding"
        );
        Ok(())
    }

    /// The report must echo exactly the parameters of `expect.rs`; the thresholds and a known run verdict are
    /// required; an error report, an empty report and a malformed one are refused.
    #[test]
    fn parameters_and_malformed_reports() -> Result<()> {
        assert!(table(&report())?.failed.is_empty());
        for (key, value) in [
            ("pass", Value::from(10.0)),
            ("max_batch", Value::from(128)),
            ("max_resolution_fraction", Value::from(0.1)),
            ("batch_margin", Value::from(1.0)),
            ("min_realised_quanta", Value::from(40)),
            ("effect_floor_quanta", Value::from(2.0)),
            ("effect_floor_ns", Value::from(20.0)),
            ("aa_max_t", Value::from(9.0)),
            ("sas_samples", Value::from(10)),
        ] {
            let mut v = report();
            set(&mut v, &["thresholds", key], value);
            assert!(table(&v).is_err(), "{key}");
        }
        let mut v = report();
        if let Some(o) = v.as_object_mut() {
            o.remove("thresholds");
        }
        assert!(table(&v).is_err(), "no thresholds");
        let mut v = report();
        set(&mut v, &["run_verdict"], Value::from("OK"));
        assert!(table(&v).is_err());
        assert!(ct_table(r#"{"error":"thresholds not readable"}"#).is_err());
        let mut v = report();
        set(&mut v, &["results"], Value::Array(Vec::new()));
        set(&mut v, &["run_verdict"], Value::from("FAIL"));
        assert!(refused(&v, "no target was measured")?);
        assert!(ct_table("{}").is_err());
        Ok(())
    }

    /// C3 acceptance: the reports of the ADR-041 Amendment 1 format committed under `docs/reviews/M02-evidence/`
    /// pass the gate as it reads them now, against the M2 target set they were written with (ADR-042); against the
    /// current set they lack `aa_prime_control` and `same_content_control` and the batch record of ADR-041
    /// Amendment 2, and are refused for that alone.
    #[test]
    fn the_committed_amendment_1_reports_pass() -> Result<()> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| Error("no workspace root".to_owned()))?
            .join("docs/reviews/M02-evidence");
        let mut files: Vec<std::path::PathBuf> =
            std::fs::read_dir(root.join("ct-adr041-amendment1"))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
        files.push(root.join("ct-report-x86_64-linux-pr-run-36679963223-6b9da3b.json"));
        assert_eq!(files.len(), 15);
        for f in &files {
            let json = std::fs::read_to_string(f)?;
            let t = ct_table_for(&json, M2_TARGETS)?;
            assert!(
                t.failed.is_empty() && t.not_measurable.is_empty(),
                "{}: {t:?}",
                f.display()
            );
            let now = ct_table(&json)?;
            assert!(
                now.failed
                    .iter()
                    .any(|l| l.contains("differ from expect::CT_TARGETS"))
                    && now.failed.iter().all(|l| {
                        l.contains("differ from expect::CT_TARGETS")
                            || l == "ct report: run verdict PASS with a failing target"
                            || l.contains("which is no first pair or one re-batch")
                            || l.contains("taken with k None")
                    }),
                "{}: {now:?}",
                f.display()
            );
        }
        Ok(())
    }

    /// ADR-042 (2): the A/A′ placement control is judged like a target — PASS and a sub-floor shift pass; a FAIL
    /// outside a `CONTROL_FAIL` run is refused (the bench must have made the run `CONTROL_FAIL`), and so is a label
    /// its crops do not give; a `CONTROL_FAIL` run naming it fails with its reason alone; it is not the positive
    /// control.
    #[test]
    fn the_aa_prime_control_fails_the_run_as_control_fail() -> Result<()> {
        let aa = expect::CT_AA_PRIME_CONTROL;
        assert!(expect::CT_TARGETS.contains(&aa));
        let all = |t: f64, delta: f64| {
            let crops: Vec<(&str, f64, f64)> = CROPS.iter().map(|c| (*c, t, delta)).collect();
            measurement_with(&crops, 1.0)
        };
        let with = |first: Value, second: Value, verdict: &str, run: &str| {
            let mut v = report();
            set(&mut v, &["run_verdict"], Value::from(run));
            let target = at(&mut v, aa);
            set(target, &["first"], first);
            set(target, &["second"], second);
            set(target, &["verdict"], Value::from(verdict));
            set(
                target,
                &["decisive_crop"],
                if verdict == "PASS" {
                    Value::Null
                } else {
                    Value::from("p90")
                },
            );
            v
        };
        // PASS (the fixture) and a sub-floor shift (reproduced, Δ 5 ticks < floor 20) pass the gate
        let t = table(&report())?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert!(
            t.lines
                .iter()
                .any(|l| l.starts_with("aa_prime_control: PASS")
                    && l.ends_with("(A/A′ placement control: a FAIL makes the run CONTROL_FAIL)"))
        );
        let sub = with(all(30.0, 5.0), all(25.0, 5.0), "SUB_FLOOR_SHIFT", "PASS");
        assert!(refusals(&sub)?.is_empty());
        // a reproduced shift at the floor, labelled FAIL in a FAIL run: refused (only CONTROL_FAIL is consistent)
        let fail = with(all(30.0, 30.0), all(25.0, 30.0), "FAIL", "FAIL");
        let found = refusals(&fail)?;
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("aa_prime_control: FAIL at p90"))
        );
        assert!(found.contains(
            &"ct report: aa_prime_control FAIL in a FAIL run: the A/A′ placement control reached the effect floor, which makes the run CONTROL_FAIL (ADR-042)"
                .to_owned()
        ));
        // the same crops labelled as a sub-floor shift: refused by the re-derivation
        let hidden = with(all(30.0, 30.0), all(25.0, 30.0), "SUB_FLOOR_SHIFT", "PASS");
        assert_eq!(
            refusals(&hidden)?,
            vec!["ct report: aa_prime_control SUB_FLOOR_SHIFT, but its recorded crops give {\"FAIL\"}".to_owned()]
        );
        // the CONTROL_FAIL run the bench writes for it: its reason is the one finding
        let mut control_fail = with(
            all(30.0, 30.0),
            all(25.0, 30.0),
            "CONTROL_FAIL",
            "CONTROL_FAIL",
        );
        let reason = "A/A′ placement control aa_prime_control FAIL at p90: identical contents copied from two source \
                      allocations shift the class means by 1.50 / 1.50 effect floors";
        set(&mut control_fail, &["run_reason"], Value::from(reason));
        for name in expect::CT_TARGETS {
            set(
                at(&mut control_fail, name),
                &["verdict"],
                Value::from("CONTROL_FAIL"),
            );
        }
        assert_eq!(
            table(&control_fail)?.failed,
            vec![format!("CONTROL_FAIL — {reason}")]
        );
        // it is not the positive control
        let mut two = report();
        set(at(&mut two, aa), &["control"], Value::from(true));
        assert!(refused(&two, "2 positive controls")?);
        Ok(())
    }

    /// ADR-042 Amendment 2: the same-content control is judged like a target and wired like the A/A′ control — PASS
    /// and a sub-floor shift pass; a FAIL outside a `CONTROL_FAIL` run is refused, and so is a label its crops do not
    /// give; a `CONTROL_FAIL` run naming it fails with its reason alone; it is not the positive control.
    #[test]
    fn the_same_content_control_fails_the_run_as_control_fail() -> Result<()> {
        let same = expect::CT_SAME_CONTENT_CONTROL;
        assert!(expect::CT_TARGETS.contains(&same));
        assert_ne!(same, expect::CT_AA_PRIME_CONTROL);
        let all = |t: f64, delta: f64| {
            let crops: Vec<(&str, f64, f64)> = CROPS.iter().map(|c| (*c, t, delta)).collect();
            measurement_with(&crops, 1.0)
        };
        let with = |first: Value, second: Value, verdict: &str, run: &str| {
            let mut v = report();
            set(&mut v, &["run_verdict"], Value::from(run));
            let target = at(&mut v, same);
            set(target, &["first"], first);
            set(target, &["second"], second);
            set(target, &["verdict"], Value::from(verdict));
            set(
                target,
                &["decisive_crop"],
                if verdict == "PASS" {
                    Value::Null
                } else {
                    Value::from("p90")
                },
            );
            v
        };
        let t = table(&report())?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert!(
            t.lines
                .iter()
                .any(|l| l.starts_with("same_content_control: PASS")
                    && l.ends_with("(same-content control: a FAIL makes the run CONTROL_FAIL)"))
        );
        let sub = with(all(30.0, 5.0), all(25.0, 5.0), "SUB_FLOOR_SHIFT", "PASS");
        assert!(refusals(&sub)?.is_empty());
        // a reproduced shift at the floor, labelled FAIL in a FAIL run: refused (only CONTROL_FAIL is consistent)
        let fail = with(all(30.0, 30.0), all(25.0, 30.0), "FAIL", "FAIL");
        let found = refusals(&fail)?;
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("same_content_control: FAIL at p90"))
        );
        assert!(found.contains(
            &"ct report: same_content_control FAIL in a FAIL run: the same-content control reached the effect floor, which makes the run CONTROL_FAIL (ADR-042 Amendment 2)"
                .to_owned()
        ));
        // the same crops labelled as a sub-floor shift: refused by the re-derivation
        let hidden = with(all(30.0, 30.0), all(25.0, 30.0), "SUB_FLOOR_SHIFT", "PASS");
        assert_eq!(
            refusals(&hidden)?,
            vec!["ct report: same_content_control SUB_FLOOR_SHIFT, but its recorded crops give {\"FAIL\"}".to_owned()]
        );
        // the CONTROL_FAIL run the bench writes for it: its reason is the one finding
        let mut control_fail = with(
            all(30.0, 30.0),
            all(25.0, 30.0),
            "CONTROL_FAIL",
            "CONTROL_FAIL",
        );
        let reason = "same-content control same_content_control FAIL at p90: identical contents through the \
                      per-class preparation path shift the class means by 1.50 / 1.50 effect floors";
        set(&mut control_fail, &["run_reason"], Value::from(reason));
        for name in expect::CT_TARGETS {
            set(
                at(&mut control_fail, name),
                &["verdict"],
                Value::from("CONTROL_FAIL"),
            );
        }
        assert_eq!(
            table(&control_fail)?.failed,
            vec![format!("CONTROL_FAIL — {reason}")]
        );
        // it is not the positive control
        let mut two = report();
        set(at(&mut two, same), &["control"], Value::from(true));
        assert!(refused(&two, "2 positive controls")?);
        Ok(())
    }

    /// ADR-042 Amendment 3 (M4 review C-2): the HX same-content control is judged like `same_content_control` — PASS
    /// and a sub-floor shift pass; a FAIL inside a FAIL run is refused (the bench must have made the run
    /// `CONTROL_FAIL`), and so is a label its crops do not give; a `CONTROL_FAIL` run naming it fails with its reason
    /// alone; it is not the positive control.
    #[test]
    fn the_hx_same_content_control_fails_the_run_as_control_fail() -> Result<()> {
        let hx = expect::CT_HX_SAME_CONTENT_CONTROL;
        assert!(expect::CT_TARGETS.contains(&hx));
        assert_ne!(hx, expect::CT_SAME_CONTENT_CONTROL);
        assert_ne!(hx, expect::CT_POSITIVE_CONTROL);
        let all = |t: f64, delta: f64| {
            let crops: Vec<(&str, f64, f64)> = CROPS.iter().map(|c| (*c, t, delta)).collect();
            measurement_with(&crops, 1.0)
        };
        let with = |first: Value, second: Value, verdict: &str, run: &str| {
            let mut v = report();
            set(&mut v, &["run_verdict"], Value::from(run));
            let target = at(&mut v, hx);
            set(target, &["first"], first);
            set(target, &["second"], second);
            set(target, &["verdict"], Value::from(verdict));
            set(
                target,
                &["decisive_crop"],
                if verdict == "PASS" {
                    Value::Null
                } else {
                    Value::from("p90")
                },
            );
            v
        };
        let t = table(&report())?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert!(
            t.lines
                .iter()
                .any(|l| l.starts_with("hx_same_content_control: PASS")
                    && l.ends_with("(HX same-content control: a FAIL makes the run CONTROL_FAIL)"))
        );
        // a reproduced shift below the floor (Δ 5 ticks < floor 20) passes as SUB_FLOOR_SHIFT
        let sub = with(all(30.0, 5.0), all(25.0, 5.0), "SUB_FLOOR_SHIFT", "PASS");
        assert!(refusals(&sub)?.is_empty());
        assert!(table(&sub)?.failed.is_empty());
        // a reproduced shift at the floor, labelled FAIL in a FAIL run: refused (only CONTROL_FAIL is consistent)
        let fail = with(all(30.0, 30.0), all(25.0, 30.0), "FAIL", "FAIL");
        let found = refusals(&fail)?;
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("hx_same_content_control: FAIL at p90"))
        );
        assert!(found.contains(
            &"ct report: hx_same_content_control FAIL in a FAIL run: the HX same-content control reached the effect floor, which makes the run CONTROL_FAIL (ADR-042 Amendment 3)"
                .to_owned()
        ));
        assert!(
            found
                .iter()
                .any(|f| f.contains("which makes the run CONTROL_FAIL"))
        );
        // the same crops labelled as a sub-floor shift: refused by the re-derivation
        let hidden = with(all(30.0, 30.0), all(25.0, 30.0), "SUB_FLOOR_SHIFT", "PASS");
        assert_eq!(
            refusals(&hidden)?,
            vec!["ct report: hx_same_content_control SUB_FLOOR_SHIFT, but its recorded crops give {\"FAIL\"}".to_owned()]
        );
        // the CONTROL_FAIL run the bench writes for it: its reason is the one finding
        let mut control_fail = with(
            all(30.0, 30.0),
            all(25.0, 30.0),
            "CONTROL_FAIL",
            "CONTROL_FAIL",
        );
        let reason = "same-content control hx_same_content_control FAIL at p90: identical contents through the \
                      per-class preparation path shift the class means by 1.50 / 1.50 effect floors";
        set(&mut control_fail, &["run_reason"], Value::from(reason));
        for name in expect::CT_TARGETS {
            set(
                at(&mut control_fail, name),
                &["verdict"],
                Value::from("CONTROL_FAIL"),
            );
        }
        assert_eq!(
            table(&control_fail)?.failed,
            vec![format!("CONTROL_FAIL — {reason}")]
        );
        // it is not the positive control
        let mut two = report();
        set(at(&mut two, hx), &["control"], Value::from(true));
        assert!(refused(&two, "2 positive controls")?);
        Ok(())
    }

    /// ADR-041 Amendment 2 (M3 review R-57): a requantised record — `k_initial` 1, `k` 3, every measurement taken
    /// with k 3 — passes and its line names the re-batch; the gate reads `k` per measurement and the flag: a
    /// measurement taken with another `k`, a flag that does not fit the two batch sizes, a missing record, and a
    /// judged measurement realising fewer than `CT_MIN_REALISED_QUANTA` quanta are refused; the M2 set, whose
    /// reports predate the record, is not asked for it.
    #[test]
    fn reads_the_batch_sizes_of_a_requantised_record() -> Result<()> {
        let rebatched = || {
            let mut v = report();
            let t = at(&mut v, "caead_derive");
            set(t, &["k"], Value::from(3));
            set(t, &["k_initial"], Value::from(1));
            set(t, &["requantised"], Value::from(true));
            for m in ["first", "second", "aa_control"] {
                set(t, &[m, "k"], Value::from(3));
            }
            v
        };
        let t = table(&rebatched())?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert!(
            t.lines
                .iter()
                .any(|l| l.starts_with("caead_derive: PASS — k=3 (re-batched from k=1),"))
        );
        // the second measurement taken with the first pair's k
        let mut v = rebatched();
        set(at(&mut v, "caead_derive"), &["second", "k"], Value::from(1));
        assert_eq!(
            refusals(&v)?,
            vec![
                "ct report: caead_derive second taken with k Some(1), not the target's k Some(3)"
                    .to_owned()
            ]
        );
        // a flag that does not fit the batch sizes, both ways
        let mut v = rebatched();
        set(
            at(&mut v, "caead_derive"),
            &["requantised"],
            Value::from(false),
        );
        assert!(refused(
            &v,
            "caead_derive records k Some(3), k_initial Some(1) and requantised Some(false)"
        )?);
        let mut v = report();
        set(
            at(&mut v, "caead_derive"),
            &["requantised"],
            Value::from(true),
        );
        assert!(refused(
            &v,
            "caead_derive records k Some(1), k_initial Some(1) and requantised Some(true)"
        )?);
        // no record at all
        let mut v = report();
        if let Some(t) = at(&mut v, "caead_derive").as_object_mut() {
            t.remove("k_initial");
        }
        if let Some(m) = at(&mut v, "caead_derive")
            .get_mut("first")
            .and_then(Value::as_object_mut)
        {
            m.remove("k");
        }
        let found = refusals(&v)?;
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found.contains(
                &"ct report: caead_derive first taken with k None, not the target's k Some(1)"
                    .to_owned()
            )
        );
        // a judged measurement short of the minimum: 79 quanta of 24.5 ticks (1935.5 ticks) refused, 80 accepted
        let mut v = rebatched();
        let t = at(&mut v, "caead_derive");
        set(t, &["second", "q_eff_ticks"], Value::from(20.5));
        set(t, &["second", "class_median_ticks"], Value::from(1619));
        assert!(refused(
            &v,
            "caead_derive second realises fewer than 80 quanta"
        )?);
        set(
            at(&mut v, "caead_derive"),
            &["second", "class_median_ticks"],
            Value::from(1640),
        );
        assert!(table(&v)?.failed.is_empty());
        // the M2 set predates the record
        let mut v = report();
        if let Some(t) = at(&mut v, "caead_derive").as_object_mut() {
            t.remove("k_initial");
            t.remove("requantised");
        }
        assert!(
            !ct_table_for(&v.to_string(), M2_TARGETS)?
                .failed
                .iter()
                .any(|f| f.contains("which is no first pair or one re-batch"))
        );
        Ok(())
    }

    /// M3 review (ct report hardening): a judged measurement without a `class_median_ticks` is refused for a report of
    /// the Amendment 2 record format, not skipped; the M2 set, whose reports predate the record, is not asked for it.
    #[test]
    fn a_missing_class_median_is_refused() -> Result<()> {
        let mut v = report();
        assert!(table(&v)?.failed.is_empty());
        let t = at(&mut v, "caead_derive");
        if let Some(m) = t.get_mut("second").and_then(Value::as_object_mut) {
            m.remove("class_median_ticks");
        }
        assert!(refused(
            &v,
            "ct report: caead_derive second has no class_median_ticks"
        )?);
        let t = at(&mut v, "caead_derive");
        if let Some(t) = t.as_object_mut() {
            t.remove("k_initial");
            t.remove("requantised");
        }
        assert!(
            !ct_table_for(&v.to_string(), M2_TARGETS)?
                .failed
                .iter()
                .any(|f| f.contains("has no class_median_ticks"))
        );
        Ok(())
    }

    /// `ct-check --targets m2|current`: the target set is chosen explicitly; the M2 set is the nine targets of M2, all
    /// still in `expect::CT_TARGETS`, without `aa_prime_control`; a report of the current set is refused against it.
    #[test]
    fn ct_check_reads_reports_against_a_chosen_target_set() -> Result<()> {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<String>>();
        let m2 = args(&["--targets", "m2", "a.json", "b.json"]);
        let (set, files) = check_args(&m2)?;
        assert_eq!((set.label, files.len()), ("the M2 target set", 2));
        let plain = args(&["a.json"]);
        let (set, files) = check_args(&plain)?;
        assert_eq!((set.label, files.len()), ("expect::CT_TARGETS", 1));
        assert!(check_args(&args(&["--targets", "current", "a.json"])).is_ok());
        assert!(check_args(&args(&["--targets", "m3"])).is_err());
        assert!(check_args(&args(&["--targets", "m2"])).is_err());
        assert!(check_args(&args(&["--target", "m2", "a.json"])).is_err());
        assert!(check_args(&[]).is_err());
        assert_eq!(M2_TARGETS.names.len(), 9);
        assert!(
            M2_TARGETS
                .names
                .iter()
                .all(|t| expect::CT_TARGETS.contains(t) && *t != expect::CT_AA_PRIME_CONTROL)
        );
        let json = report().to_string();
        assert!(
            ct_table_for(&json, M2_TARGETS)?
                .failed
                .iter()
                .any(|f| f.contains("differ from the M2 target set"))
        );
        Ok(())
    }

    /// The sensitivity control's crops (crop, t, Δ ticks) of PR run 37127247911 (cac6eff, `ct` job): raw Δ −11.70 at
    /// t −4.79, the injected leak at p50/p75/p90 (Δ 6.2/6.3/3.1 floors of 26 ticks, t 203.7/259.6/139.8).
    const RUN_37127247911_CONTROL: [(&str, f64, f64); 6] = [
        ("raw", -4.794, -11.6982),
        ("p50", 203.655, 161.8166),
        ("p75", 259.563, 162.9221),
        ("p90", 139.784, 80.0337),
        ("p95", 44.108, 25.5119),
        ("p99", -14.608, -9.93),
    ];

    /// The tick length of that runner (2.600 GHz TSC): 10 ns = 26 ticks, the floor at `q_eff` 2 ticks.
    const TICK_2600_MHZ: f64 = 0.384_616_118_196_471;

    /// A histogram of 21 bins with all `n` samples of a class in the first bin.
    fn bins(n: u64) -> Value {
        Value::from(
            std::iter::once(n)
                .chain(std::iter::repeat_n(0, 20))
                .collect::<Vec<u64>>(),
        )
    }

    /// `report()` on the 2.600 GHz clock (`q_eff` 2 ticks, floor 26 ticks) with a sensitivity control of two
    /// measurements (ADR-041 Amendment 3) with the given crops and `q_eff` 2, the bench's `decision`, `deciding_crop`
    /// and `reached`, and the evidence of Amendment 3 (2): host, bench SHA-256, histograms (the fixture measurements
    /// have 5 samples per class), the same-content variant. Not caught: the run is `CONTROL_FAIL` with `reason`.
    fn pair_report(
        first: &[(&str, f64, f64)],
        second: &[(&str, f64, f64)],
        bench: (&str, Option<&str>, bool),
        reason: &str,
    ) -> Value {
        let (decision, crop, reached) = bench;
        let mut v = report();
        set(&mut v, &["clock", "tick_ns"], Value::from(TICK_2600_MHZ));
        set(&mut v, &["clock", "q_eff_ticks"], Value::from(2.0));
        let histogram = serde_json::json!({"bins": 21, "lo_ticks": 15000, "hi_ticks": 15700,
            "bin_ticks": 33.333, "class0": bins(5), "class1": bins(5)});
        set(
            &mut v,
            &["sensitivity_control"],
            serde_json::json!({"name": "min_leak_control", "k": 1, "samples": expect::CT_SAMPLES,
                "decision": decision, "deciding_crop": crop, "reached": reached, "histogram": histogram.clone(),
                "first": measurement_with(first, 2.0), "second": measurement_with(second, 2.0)}),
        );
        if let Some(o) = v.as_object_mut() {
            o.insert(
                "host".to_owned(),
                serde_json::json!({"cpu_model": "AMD EPYC 7763 64-Core Processor", "microcode": "0xffffffff"}),
            );
            o.insert("bench_sha256".to_owned(), Value::from("ab".repeat(32)));
            o.insert(
                "min_leak_same_content".to_owned(),
                serde_json::json!({"name": "min_leak_same_content", "k": 1, "samples": expect::CT_SAMPLES,
                    "verdict": null, "informative": true, "histogram": histogram,
                    "measurement": measurement_with(&[("p50", 1.5, 2.0)], 2.0)}),
            );
        }
        if !reached {
            set(&mut v, &["run_verdict"], Value::from("CONTROL_FAIL"));
            set(&mut v, &["run_reason"], Value::from(reason));
            for name in expect::CT_TARGETS {
                set(at(&mut v, name), &["verdict"], Value::from("CONTROL_FAIL"));
            }
        }
        v
    }

    /// The `min_leak_control` line of a report.
    fn control_line(v: &Value) -> Result<String> {
        table(v)?
            .lines
            .into_iter()
            .find(|l| l.starts_with("min_leak_control: "))
            .ok_or_else(|| Error("no min_leak_control line".to_owned()))
    }

    /// ADR-041 Amendment 3 (1): the control of run 37127247911 — raw Δ −11.70 ticks, which the raw rule of Amendment 1
    /// (2) failed — in both measurements is caught by the target rule at p75 (and p50 would do as well), class 0 slower;
    /// the line names the deciding crop, Δ and t of both measurements and both raw Δ as information.
    #[test]
    fn sensitivity_control_passes_when_decide_catches_the_leak_at_a_crop() -> Result<()> {
        let run = RUN_37127247911_CONTROL;
        let v = pair_report(&run, &run, ("FAIL", Some("p75"), true), "");
        let t = table(&v)?;
        assert!(t.failed.is_empty(), "{t:?}");
        let line = control_line(&v)?;
        assert!(
            line.starts_with(
                "min_leak_control: CAUGHT — decide FAIL at p75, class 0 slower: Δ 62.66 / 62.66 ns (6.27 / 6.27 \
                 floors), t 259.56 / 259.56; raw Δ -4.50 / -4.50 ns (information); k=1, 1000000 samples"
            ),
            "{line}"
        );
        assert!(line.ends_with(
            "(sensitivity control: the verdict rule must catch the injected leak with class 0 slower, ADR-041 \
             Amendment 3)"
        ));
        let p50 = pair_report(&run, &run, ("FAIL", Some("p50"), true), "");
        assert!(table(&p50)?.failed.is_empty());
        // the same crops as one measurement under the raw rule: below the floor
        let mut raw = report();
        set(&mut raw, &["clock", "tick_ns"], Value::from(TICK_2600_MHZ));
        set(
            &mut raw,
            &["sensitivity_control", "raw_delta_ticks"],
            Value::from(-11.6982),
        );
        set(
            &mut raw,
            &["sensitivity_control", "floor_ticks"],
            Value::from(26.0),
        );
        assert!(refused(
            &raw,
            "the sensitivity control did not reach the floor"
        )?);
        Ok(())
    }

    /// ADR-041 Amendment 3 (1): every |Δ| below the 26-tick floor (a sub-floor shift at most) is not caught: a run
    /// recorded as caught is refused, the `CONTROL_FAIL` run the bench writes fails with its reason alone.
    #[test]
    fn sensitivity_control_fails_when_no_crop_reaches_the_floor() -> Result<()> {
        let small = [
            ("raw", -4.794, -11.6982),
            ("p50", 203.655, 20.0),
            ("p75", 259.563, 25.99),
            ("p90", 139.784, 15.0),
            ("p95", 44.108, 10.0),
            ("p99", -14.608, -9.93),
        ];
        let claimed = pair_report(&small, &small, ("FAIL", Some("p75"), true), "");
        assert_eq!(refusals(&claimed)?.len(), 1, "{:?}", refusals(&claimed)?);
        assert!(refused(
            &claimed,
            "run verdict PASS although the verdict rule did not catch the sensitivity control"
        )?);
        let reason = "sensitivity control min_leak_control not caught by the verdict rule (decide: SUB_FLOOR_SHIFT \
                      at p75): no crop reproduces the injected leak at ≥ 1 floor with |t| > 4.5 in both measurements \
                      (ADR-041 Amendment 3)";
        let v = pair_report(
            &small,
            &small,
            ("SUB_FLOOR_SHIFT", Some("p75"), false),
            reason,
        );
        assert_eq!(table(&v)?.failed, vec![format!("CONTROL_FAIL — {reason}")]);
        assert!(control_line(&v)?.starts_with(
            "min_leak_control: NOT CAUGHT — decide SUB_FLOOR_SHIFT at p75: no crop reproduces the injected leak"
        ));
        Ok(())
    }

    /// ADR-041 Amendment 3 (1): the sign rule is kept — a FAIL with class 1 slower at the deciding crop (Δ −162 ticks at
    /// p50/p75, |t| 204/260) is not caught; the line and the bench's reason name the sign.
    #[test]
    fn sensitivity_control_fails_when_class_one_is_slower() -> Result<()> {
        let swapped = [
            ("raw", 4.794, 11.6982),
            ("p50", -203.655, -161.8166),
            ("p75", -259.563, -162.9221),
            ("p90", 1.0, 0.1),
            ("p95", 1.0, 0.1),
            ("p99", 1.0, 0.1),
        ];
        let claimed = pair_report(&swapped, &swapped, ("FAIL", Some("p75"), true), "");
        assert!(refused(
            &claimed,
            "although the verdict rule did not catch the sensitivity control"
        )?);
        let reason = "sensitivity control min_leak_control caught with the wrong sign: class 1 slower at the deciding \
                      crop p75 (Δ -162.92 / -162.92 ticks, t -259.56 / -259.56), where the injected leak makes class \
                      0 slower (ADR-041 Amendment 3)";
        let v = pair_report(&swapped, &swapped, ("FAIL", Some("p75"), false), reason);
        assert_eq!(table(&v)?.failed, vec![format!("CONTROL_FAIL — {reason}")]);
        let line = control_line(&v)?;
        assert!(
            line.starts_with(
                "min_leak_control: NOT CAUGHT — decide FAIL at p75, class 1 slower: Δ -62.66 / -62.66 ns"
            ),
            "{line}"
        );
        Ok(())
    }

    /// ADR-041 Amendment 3 (1): the leak must be reproduced — the first measurement shows it (run 37127247911), the
    /// second does not (raw and p50 ≈ 0): not caught.
    #[test]
    fn sensitivity_control_fails_when_the_leak_is_not_reproduced() -> Result<()> {
        let run = RUN_37127247911_CONTROL;
        let flat = [
            ("raw", 0.3, 0.1),
            ("p50", 0.4, 0.2),
            ("p75", 1.0, 0.5),
            ("p90", -0.6, -0.3),
            ("p95", 0.2, 0.1),
            ("p99", 0.1, 0.0),
        ];
        let claimed = pair_report(&run, &flat, ("FAIL", Some("p75"), true), "");
        assert!(refused(
            &claimed,
            "although the verdict rule did not catch the sensitivity control"
        )?);
        let reason = "sensitivity control min_leak_control not caught by the verdict rule (decide: PASS): no crop \
                      reproduces the injected leak at ≥ 1 floor with |t| > 4.5 in both measurements (ADR-041 \
                      Amendment 3)";
        let v = pair_report(&run, &flat, ("PASS", None, false), reason);
        assert_eq!(table(&v)?.failed, vec![format!("CONTROL_FAIL — {reason}")]);
        assert!(
            control_line(&v)?
                .starts_with("min_leak_control: NOT CAUGHT — decide PASS: no crop reproduces")
        );
        Ok(())
    }

    /// ADR-041 Amendment 3 (3): the gate re-derives a control of two measurements from its crops and refuses one recorded
    /// as caught whose crops do not give it (not reproduced; caught at a crop where `decide` would have taken a
    /// stronger one with class 1 slower); a report of the earlier format — the committed one of run 37127247911 — keeps
    /// the raw rule and re-derives as the `CONTROL_FAIL` it records.
    #[test]
    fn ct_check_rederives_the_sensitivity_control_from_both_measurements() -> Result<()> {
        let run = RUN_37127247911_CONTROL;
        let flat: Vec<(&str, f64, f64)> = CROPS.iter().map(|c| (*c, 1.0, 0.1)).collect();
        // recorded as caught, the second measurement shows nothing
        let v = pair_report(&run, &flat, ("FAIL", Some("p75"), true), "");
        assert_eq!(
            refusals(&v)?
                .iter()
                .filter(|f| f.contains("the verdict rule did not catch"))
                .count(),
            1
        );
        // recorded as caught at p50, while p99 reproduces a stronger shift with class 1 slower
        let stronger = [
            ("raw", 1.0, 0.1),
            ("p50", 203.655, 161.8166),
            ("p75", 1.0, 0.1),
            ("p90", 1.0, 0.1),
            ("p95", 1.0, 0.1),
            ("p99", -400.0, -100.0),
        ];
        let v = pair_report(&stronger, &stronger, ("FAIL", Some("p50"), true), "");
        assert!(refused(
            &v,
            "although the verdict rule did not catch the sensitivity control"
        )?);
        // as caught at p50 without the stronger p99: accepted
        let mut weaker = stronger;
        if let Some(p99) = weaker.last_mut() {
            *p99 = ("p99", -4.0, -100.0);
        }
        assert!(
            table(&pair_report(
                &weaker,
                &weaker,
                ("FAIL", Some("p50"), true),
                ""
            ))?
            .failed
            .is_empty()
        );
        // the committed report of run 37127247911 (one measurement): the raw rule, its recorded CONTROL_FAIL
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/reviews/M04-evidence/ct-report-linux-37127247911-cac6eff.json");
        let json = std::fs::read_to_string(path)?;
        let committed: Value =
            serde_json::from_str(&json).map_err(|e| Error(format!("committed report: {e}")))?;
        assert!(control_pair(&committed).is_none());
        let t = ct_table(&json)?;
        assert_eq!(
            t.failed,
            vec![
                "CONTROL_FAIL — sensitivity control min_leak_control below the effect floor: raw Δ -11.70 ticks < \
                 floor 26.00 ticks (1 q_eff, 10 ns)"
                    .to_owned()
            ]
        );
        assert!(t.lines.iter().any(|l| l.starts_with(
            "min_leak_control: BELOW THE FLOOR — raw Δ -4.50 ns, floor 10.00 ns (-0.45 floors), k=1, 1000000 samples"
        )));
        Ok(())
    }

    /// ADR-041 Amendment 3 (2): a report with both control measurements carries the host (CPU model, microcode), the
    /// bench's SHA-256, a 21-bin histogram per class summing to the class counts, and the same-content variant with
    /// its histogram; each gap is refused, `unknown` (macOS microcode) is accepted, and the same-content variant gets
    /// a line of its own (no verdict).
    #[test]
    fn ct_report_carries_host_identity_and_histograms() -> Result<()> {
        let run = RUN_37127247911_CONTROL;
        let good = || pair_report(&run, &run, ("FAIL", Some("p75"), true), "");
        let t = table(&good())?;
        assert!(t.failed.is_empty(), "{t:?}");
        assert!(t.lines.iter().any(|l| l.starts_with(
            "min_leak_same_content: informative (no verdict) — p50 Δ 0.77 ns (0.08 floors), t 1.50; IQR class 0 ? / \
             class 1 ? ticks (ratio ?)"
        )));
        let mut unknown = good();
        set(&mut unknown, &["host", "microcode"], Value::from("unknown"));
        assert!(table(&unknown)?.failed.is_empty());
        let edit = |path: &[&str], value: Value| -> Result<Vec<String>> {
            let mut v = good();
            set(&mut v, path, value);
            refusals(&v)
        };
        let one = |found: Vec<String>, needle: &str| {
            assert!(
                found.len() == 1 && found.iter().all(|f| f.contains(needle)),
                "{needle}: {found:?}"
            );
        };
        one(
            edit(&["host", "cpu_model"], Value::Null)?,
            "no host.cpu_model",
        );
        one(
            edit(&["host", "microcode"], Value::from(""))?,
            "no host.microcode",
        );
        assert_eq!(edit(&["host"], Value::Null)?.len(), 2);
        one(edit(&["bench_sha256"], Value::Null)?, "bench_sha256 None");
        one(
            edit(&["bench_sha256"], Value::from("AB".repeat(32)))?,
            "is not a SHA-256 in hex",
        );
        one(
            edit(&["bench_sha256"], Value::from("ab".repeat(31)))?,
            "is not a SHA-256 in hex",
        );
        let twenty: Vec<u64> = std::iter::once(5)
            .chain(std::iter::repeat_n(0, 19))
            .collect();
        one(
            edit(
                &["sensitivity_control", "histogram", "class0"],
                Value::from(twenty),
            )?,
            "sensitivity_control histogram class0: Some(20) bins summing to Some(5)",
        );
        one(
            edit(&["sensitivity_control", "histogram", "class1"], bins(4))?,
            "sensitivity_control histogram class1: Some(21) bins summing to Some(4), expected 21 bins summing to the \
             class count Some(5)",
        );
        assert_eq!(
            edit(&["sensitivity_control", "histogram"], Value::Null)?.len(),
            2
        );
        one(
            edit(&["min_leak_same_content", "histogram", "class0"], bins(6))?,
            "min_leak_same_content histogram class0",
        );
        one(
            edit(&["min_leak_same_content"], Value::Null)?,
            "no min_leak_same_content measurement",
        );
        one(
            edit(&["sensitivity_control", "second", "k"], Value::from(2))?,
            "min_leak_control second taken with k Some(2), not the control's k Some(1)",
        );
        Ok(())
    }
}
