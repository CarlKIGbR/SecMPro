// SPDX-License-Identifier: AGPL-3.0-or-later
//! dudect-style constant-time tests (docs/06 §2, M1 acceptance "constant-time test (dudect-style) for tag
//! comparison shows no leak"; Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", 2017).
//!
//! For each target, two input classes are measured in random interleaving; Welch's t-statistic is computed on
//! the raw timings and on timings cropped at several percentiles of the pooled distribution. A target passes if
//! every |t| < 4.5. A deliberately variable-time comparison is measured as a **control**: it must be detected
//! (|t| ≥ 4.5), otherwise the harness is not sensitive enough and the run fails.
//!
//! Targets:
//! - `tag_compare`: the tag comparison used by `MsgEncrypt` (`subtle::ConstantTimeEq` on 32 bytes), tags that
//!   differ in the first vs the last byte (batched, 256 comparisons per measurement);
//! - `msg_open_reject`: `MsgEncrypt::open` rejecting a tag wrong in the first vs the last byte;
//! - `caead_open_reject`: `Caead::open` with a wrong key (commitment and tag fail) vs a tampered ciphertext
//!   (commitment matches, tag fails) — the trial-decryption case of spec §6.5;
//! - `sas`: `SafetyNumber::new` for a fixed pair of fingerprints vs random pairs.
//!
//! The classes may differ only in their contents, never in where the inputs live: every measured input is a
//! fresh copy made by `prepare` (by value or in a new allocation, identical sequence for both classes), so buffer
//! placement cannot correlate with the class. With one fixed buffer per class, the alignment-dependent cost of
//! copying and loading the input is itself a class difference (M1, `x86_64` CI: |t| = 24 and 210 for the two
//! openers with per-class buffers; M1 report §4).
//!
//! Run by `cargo xtask step ct` (ci-full) as `cargo bench -p secmp-crypto --features kat --bench ct`; the results
//! are written to `target/ct-report.json` and the exit status is the verdict. `SECMP_CT_SCALE` (a divisor, default
//! 1) shortens every sample count for quick local runs.

#![forbid(unsafe_code)]

use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use secmp_crypto::{BODY_LEN, Caead, Fingerprint, MsgEncrypt, Nonce24, SafetyNumber, SecretBytes};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use subtle::ConstantTimeEq;

/// |t| threshold of dudect.
const T_THRESHOLD: f64 = 4.5;
/// Percentiles (per mille) of the pooled distribution at which measurements are cropped (dudect outlier handling).
const CROPS_PERMILLE: [usize; 5] = [500, 750, 900, 950, 990];

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

/// Measure `n` samples. For sample `i` of class `c`, `prepare(c, i)` builds the input outside the timed region
/// (dudect: inputs are prepared before measuring), then only `op(&input)` is timed.
fn measure<T>(
    n: usize,
    stream: &mut Stream,
    mut prepare: impl FnMut(usize, usize) -> T,
    mut op: impl FnMut(&T),
) -> Vec<(usize, f64)> {
    let classes = stream.classes(n);
    let mut out = Vec::with_capacity(n);
    // warm-up
    for (i, c) in classes.iter().take(n / 100).enumerate() {
        op(&prepare(*c, i));
    }
    for (i, c) in classes.into_iter().enumerate() {
        let input = black_box(prepare(c, i));
        let start = Instant::now();
        op(&input);
        let dt = start.elapsed();
        out.push((c, dt.as_secs_f64() * 1e9));
    }
    out
}

/// Welch t on the raw samples and on the samples below each crop percentile.
fn analyse(samples: &[(usize, f64)]) -> Vec<(String, f64)> {
    let mut sorted: Vec<f64> = samples.iter().map(|(_, x)| *x).collect();
    sorted.sort_by(f64::total_cmp);
    let mut results = Vec::new();
    let mut raw = Stats::default();
    for (c, x) in samples {
        raw.push(*c, *x);
    }
    results.push(("raw".to_owned(), raw.t()));
    for permille in CROPS_PERMILLE {
        let idx = sorted.len().saturating_mul(permille) / 1000;
        let cut = sorted
            .get(idx.min(sorted.len().saturating_sub(1)))
            .copied()
            .unwrap_or(f64::MAX);
        let mut s = Stats::default();
        for (c, x) in samples.iter().filter(|(_, x)| *x < cut) {
            s.push(*c, *x);
        }
        results.push((format!("p{}", permille / 10), s.t()));
    }
    results
}

struct Outcome {
    name: &'static str,
    samples: usize,
    ts: Vec<(String, f64)>,
    control: bool,
}

impl Outcome {
    fn max_abs_t(&self) -> f64 {
        self.ts.iter().map(|(_, t)| t.abs()).fold(0.0, f64::max)
    }

    fn passed(&self) -> bool {
        if self.control {
            self.max_abs_t() >= T_THRESHOLD
        } else {
            self.max_abs_t() < T_THRESHOLD
        }
    }

    fn json(&self) -> String {
        let ts: Vec<String> = self
            .ts
            .iter()
            .map(|(k, t)| format!("\"{k}\":{t:.3}"))
            .collect();
        format!(
            "{{\"name\":\"{}\",\"samples\":{},\"control\":{},\"max_abs_t\":{:.3},\"passed\":{},\"t\":{{{}}}}}",
            self.name,
            self.samples,
            self.control,
            self.max_abs_t(),
            self.passed(),
            ts.join(",")
        )
    }
}

/// Batched 32-byte tag comparisons: class 0 differs in byte 0, class 1 in byte 31.
fn tag_compare(n: usize, stream: &mut Stream, variable_time: bool) -> Vec<(usize, f64)> {
    let mut expected = [0_u8; 32];
    stream.fill(&mut expected);
    let mut first = expected;
    first[0] ^= 1;
    let mut last = expected;
    last[31] ^= 1;
    let inputs = [first, last];
    measure(
        n,
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
    stream: &mut Stream,
) -> Result<Vec<(usize, f64)>, secmp_crypto::Error> {
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
        stream,
        |c, _| inputs.get(c).cloned().unwrap_or_default(),
        |ct| {
            black_box(MsgEncrypt::open(&key, &ad, black_box(ct)).is_ok());
        },
    ))
}

fn caead_open_reject(
    n: usize,
    stream: &mut Stream,
) -> Result<Vec<(usize, f64)>, secmp_crypto::Error> {
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

fn sas(n: usize, stream: &mut Stream) -> Result<Vec<(usize, f64)>, secmp_crypto::Error> {
    let mut fixed = [[0_u8; 32]; 2];
    stream.fill(&mut fixed[0]);
    stream.fill(&mut fixed[1]);
    let mut random = vec![[0_u8; 64]; n];
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

fn run() -> Result<Vec<Outcome>, secmp_crypto::Error> {
    let scale: usize = std::env::var("SECMP_CT_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let mut stream = Stream::new()?;
    let mut out = Vec::new();
    let n = 1_000_000_usize.checked_div(scale).unwrap_or(1);
    out.push(Outcome {
        name: "control_variable_time_compare",
        samples: n,
        ts: analyse(&tag_compare(n, &mut stream, true)),
        control: true,
    });
    out.push(Outcome {
        name: "tag_compare",
        samples: n,
        ts: analyse(&tag_compare(n, &mut stream, false)),
        control: false,
    });
    out.push(Outcome {
        name: "msg_open_reject",
        samples: n,
        ts: analyse(&msg_open_reject(n, &mut stream)?),
        control: false,
    });
    out.push(Outcome {
        name: "caead_open_reject",
        samples: n,
        ts: analyse(&caead_open_reject(n, &mut stream)?),
        control: false,
    });
    let n_sas = 20_000_usize.checked_div(scale).unwrap_or(1);
    out.push(Outcome {
        name: "sas",
        samples: n_sas,
        ts: analyse(&sas(n_sas, &mut stream)?),
        control: false,
    });
    Ok(out)
}

fn main() -> ExitCode {
    let Ok(outcomes) = run() else {
        return ExitCode::FAILURE;
    };
    let json = format!(
        "{{\"threshold\":{T_THRESHOLD},\"results\":[{}]}}",
        outcomes
            .iter()
            .map(Outcome::json)
            .collect::<Vec<_>>()
            .join(",")
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ct-report.json");
    if std::fs::write(path, json).is_err() {
        return ExitCode::FAILURE;
    }
    if outcomes.iter().all(Outcome::passed) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
