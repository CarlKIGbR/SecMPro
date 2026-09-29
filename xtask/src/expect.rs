// SPDX-License-Identifier: AGPL-3.0-or-later
//! The explicit input set of every gate.
//!
//! Gates discover their inputs (KAT features, fuzz targets, ProVerif models, Kani harnesses, systemd units)
//! and **fail if the discovered set differs from the set listed here**, in either direction. A gate can
//! therefore never pass vacuously because its inputs disappeared: removing a fuzz target or a model is a
//! reviewed change of this file. Each milestone that adds inputs extends these lists.

/// The two crates that may contain `unsafe` (CLAUDE.md §1.6, docs/02 §3, docs/06 §2 (a)). Their library root
/// carries `#![allow(unsafe_code)]` — the only relaxation of `unsafe_code` allowed in first-party code; their
/// other target roots (integration tests, benches, examples) carry `#![forbid(unsafe_code)]` like every crate
/// not listed here or in `UNSAFE_DENY_ONLY`.
pub(crate) const UNSAFE_ALLOWED: &[&str] = &["secmp-sys-mem", "secmp-sys-desktop"];

/// The one target root outside the two sys crates that may relax `unsafe_code` (ADR-038 (1)): the constant-time
/// bench reads the CPU cycle counter (`rdtscp` / `cntvct_el0`). Matched path-exactly (relative to the workspace
/// root) by the `policy` step; its header must carry `#![allow(unsafe_code)]` at the file top, nothing else.
pub(crate) const UNSAFE_EXEMPT_ROOT: &str = "crates/secmp-crypto/benches/ct.rs";

/// Crates that carry `#![deny(unsafe_code)]` instead of `forbid`, because `slint::slint!` expansions contain
/// `#[allow(unsafe_code)]` (E0453 under `forbid`; docs/06 §2 (b), ADR-033). Their own `.rs` files may contain
/// neither the token `unsafe` nor any relaxation of `unsafe_code`.
pub(crate) const UNSAFE_DENY_ONLY: &[&str] = &["secmp-ui"];

/// Crates whose normal (shipped) dependency closure must have zero cargo-vet exemptions (docs/06 §3, ADR-036).
pub(crate) const ZERO_EXEMPTION_ROOTS: &[&str] = &["secmp-crypto", "secmp-proto"];

/// The targets over which that closure is taken and united: the `[graph] targets` of `deny.toml` (the two
/// shipped targets and the development host, ADR-029).
pub(crate) const VET_CLOSURE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
];

/// Workspace binaries (hello-world banner in M0; SBOM + `cargo auditable` release builds).
pub(crate) const BINARIES: &[&str] = &["secmp-relay", "secmp-cli", "secmp-ui"];

/// `RustSec` advisories that `cargo audit` (docs/06 §5 step 3) ignores, as (id, reason). An entry needs an ADR
/// (`deny.toml`: "An advisory may only be ignored with an ADR and a reason") and is re-triaged at every release.
/// The gate prints every ignored id in its result line.
pub(crate) const AUDIT_IGNORES: &[(&str, &str)] = &[(
    "RUSTSEC-2026-0173",
    "ADR-037: proc-macro-error2 (unmaintained) is in Cargo.lock only as a cfg(hax) dependency of hax-lib-macros \
     and is never compiled for any target; cargo deny, which evaluates the per-target graph, does not report it",
)];

/// Packages exposing the `kat` feature (docs/06 §5 step 5): external KATs, differential tests, vector checks.
pub(crate) const KAT_PACKAGES: &[&str] = &["secmp-crypto", "secmp-testkit"];

/// ADR-038 (2): the two-tier verdict of the `ct` gate on max |t| over raw + 5 crops — `(pass, fail)`: ≤ pass →
/// PASS, > fail → FAIL, in between one confirmatory re-measurement. Fixed by the ADR. The bench reads this line
/// (and the next constant) from this file at compile time, and the gate checks the report echoes both, so the
/// values are written down exactly once. Keep each on one line.
pub(crate) const CT_THRESHOLDS: (f64, f64) = (4.5, 10.0);

/// ADR-038 (3): the timer resolution may be at most this fraction of a sample's median; where a single call is
/// too short, one sample batches `k = ceil(quantum / (fraction · median))` calls.
pub(crate) const CT_RESOLUTION_MAX_FRACTION: f64 = 0.01;

/// ADR-038 (3): the largest batch size; a target that would need more is NOT MEASURABLE on that runner.
pub(crate) const CT_MAX_BATCH: u32 = 64;

/// ADR-038 (3), amended 2026-09-29 (M1 review F8): the calibration aims at this multiple of the resolution bound,
/// a 10 % margin: `k = ceil(110 · quantum / median)` with the 1 % fraction above.
pub(crate) const CT_BATCH_MARGIN: f64 = 1.1;

/// ADR-038 (3), amended 2026-09-29: a measurement whose realised batch median is below this many timer quanta
/// is NOT MEASURABLE for that target (from here up to 100 the realised count is informative only).
pub(crate) const CT_MIN_REALISED_QUANTA: u64 = 80;

/// cargo-fuzz targets under `fuzz/fuzz_targets/` (docs/06 §5 step 6): M1 key, ciphertext and signature parsers
/// and the two openers of `secmp-crypto`.
pub(crate) const FUZZ_TARGETS: &[&str] = &[
    "caead_open",
    "ed25519_verify",
    "hybrid_sign_verify",
    "mldsa65_verify",
    "mlkem_parse",
    "msg_open",
    "x25519_dh",
];

/// Packages under the mutation gate (docs/06 §4, §5 step 8).
pub(crate) const MUTANT_PACKAGES: &[&str] = &["secmp-crypto", "secmp-proto"];

/// Packages run under Miri (docs/06 §4).
pub(crate) const MIRI_PACKAGES: &[&str] = &["secmp-sys-mem", "secmp-sys-desktop", "secmp-crypto"];

/// The target Miri interprets, on every host. `libcrux-ml-kem` selects its backend at run time through
/// `libcrux-platform`, which executes `cpuid` (inline assembly, unsupported by Miri) on `x86`/`x86_64`; on `AArch64` the
/// selection is a compile-time constant (and the gate compiles libcrux's NEON backend out, since Miri cannot run
/// SIMD intrinsics). `secmp-sys-mem` uses its heap backend under Miri on every target.
pub(crate) const MIRI_TARGET: &str = "aarch64-unknown-linux-gnu";

/// Test-name filters excluded from the Miri run only (docs/06 §4: "under Miri (where feasible)"), as (filter,
/// reason). The tests still run natively on every target. Measured M1 (macOS arm64, nightly-2026-09-21): one
/// ML-DSA-65 test takes about 25 minutes under Miri, the two modules together several hours.
pub(crate) const MIRI_SKIP: &[(&str, &str)] = &[
    (
        "mldsa::",
        "ML-DSA-65 key generation and signing take ~25 min per test under Miri",
    ),
    ("hybrid_sign::", "HybridSign runs ML-DSA-65 (as above)"),
    (
        "sas::",
        "5200 SHA-256 iterations per half take ~10 min per test under Miri; SHA-256 itself runs under Miri in hash::",
    ),
];

/// Packages containing Kani harnesses (docs/06 §4). M2 adds `secmp-proto`.
pub(crate) const KANI_PACKAGES: &[&str] = &[];

/// The SecMP vector suites (`vectors/SCHEMA.md` §3): frozen as `vectors/<suite>.json`, reference files
/// `vectors/ref/<suite>.json`, Rust files `vectors/rust/<suite>.json` (docs/06 §5 step 12a). M2–M5 add suites.
pub(crate) const VECTOR_SUITES: &[&str] = &[
    "caead",
    "encodings",
    "fingerprint",
    "hkdf-labels",
    "hybridkem-1024",
    "hybridkem-768",
    "hybridsign",
    "msgencrypt",
    "sas",
];

/// Reference files committed before their suite is generated by the Rust side and frozen: present as
/// `vectors/ref/<suite>.json`, absent from `vectors/`. The `ref-vectors` step requires each to be present and
/// well-formed (JSON, `suite` = its name, a non-empty `cases` array) and compares nothing yet. Moving a suite from
/// here to `VECTOR_SUITES` is its freeze step (M2: `encodings`, frozen in `docs/reviews/M02-report.md` plan step 10).
pub(crate) const VECTOR_REF_PENDING: &[&str] = &[];

/// Suites whose Rust generator writes the positive rows only (M2 cross-generates the `encodings` positives, docs/07
/// M2 deliverables): `cargo xtask vectors` compares the header and the positive rows, and requires the decoders to
/// reject every other row of the reference file (`secmp-proto` test `encodings_ref`) before the freeze.
pub(crate) const VECTOR_POSITIVE_ONLY: &[&str] = &["encodings"];

/// ProVerif models under `formal/` (docs/06 §5 step 10). M3 adds `tr.pv`, M4 `hx.pv`, M5 `link.pv`.
pub(crate) const PROVERIF_MODELS: &[&str] = &[];

/// systemd units under `deploy/` checked with `systemd-analyze security --offline` (docs/06 §5 step 14,
/// exposure ≤ 2.0). M10 adds `secmp-relay.service`.
pub(crate) const SYSTEMD_UNITS: &[&str] = &[];

/// Maximum systemd exposure level (docs/05 §4, docs/06 §5 step 14).
pub(crate) const SYSTEMD_MAX_EXPOSURE: f64 = 2.0;

/// Line-coverage thresholds in percent (docs/06 §4): `secmp-crypto` and `secmp-proto` ≥ 90, every other
/// shipped crate ≥ 80. `xtask` is build tooling and not measured.
pub(crate) const COVERAGE_STRICT: &[&str] = &["secmp-crypto", "secmp-proto"];
pub(crate) const COVERAGE_STRICT_MIN: f64 = 90.0;
pub(crate) const COVERAGE_MIN: f64 = 80.0;

/// Every lint-relaxing attribute (`allow`, `expect`, `warn`, also inside `cfg_attr`) in first-party Rust code,
/// as (path relative to the workspace root, lint, reason). Anything not listed fails the `policy` step.
/// Deny-level lints (every `clippy::all` lint, `unsafe_code`, `unused_must_use` and the explicit deny list of
/// docs/06 §2) may only appear here for the sites sanctioned by docs/06 §2 — the `SystemTime::now` sites
/// (`secmp-client-core::clock`, the relay's hour bucket, `secmp-cli` output timestamps); none exist in M0.
/// The docs/06 §2 test allowance (`#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top of a file
/// under `tests/`, `fuzz/` or `crates/secmp-testkit/`) is handled by rule and needs no entry.
pub(crate) const LINT_ALLOWANCES: &[(&str, &str, &str)] = &[];

/// The only lints the docs/06 §2 test-file allowance may relax.
pub(crate) const TEST_FILE_ALLOWANCE: &[&str] = &["clippy::unwrap_used", "clippy::expect_used"];

/// Path prefixes (relative to the workspace root) where the test-file allowance applies.
pub(crate) const TEST_FILE_PREFIXES: &[&str] = &["fuzz/", "crates/secmp-testkit/"];

/// CI jobs that may use `continue-on-error: true`. None: Amendment A1 §5 allowed it for the cargo-xwin
/// cross-build in M0 only, and the M0 review (condition C1) made that job a hard gate from M1 on.
pub(crate) const CONTINUE_ON_ERROR_JOBS: &[&str] = &[];
