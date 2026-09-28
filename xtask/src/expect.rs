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

/// Crates that carry `#![deny(unsafe_code)]` instead of `forbid`, because `slint::slint!` expansions contain
/// `#[allow(unsafe_code)]` (E0453 under `forbid`; docs/06 §2 (b), ADR-033). Their own `.rs` files may contain
/// neither the token `unsafe` nor any relaxation of `unsafe_code`.
pub(crate) const UNSAFE_DENY_ONLY: &[&str] = &["secmp-ui"];

/// Crates whose full dependency closure must have zero cargo-vet exemptions (docs/06 §3).
pub(crate) const ZERO_EXEMPTION_ROOTS: &[&str] = &["secmp-crypto", "secmp-proto"];

/// Workspace binaries (hello-world banner in M0; SBOM + `cargo auditable` release builds).
pub(crate) const BINARIES: &[&str] = &["secmp-relay", "secmp-cli", "secmp-ui"];

/// Packages exposing the `kat` feature (docs/06 §5 step 5). M1 adds `secmp-crypto`.
pub(crate) const KAT_PACKAGES: &[&str] = &[];

/// cargo-fuzz targets under `fuzz/fuzz_targets/` (docs/06 §5 step 6). M1 adds the first ones.
pub(crate) const FUZZ_TARGETS: &[&str] = &[];

/// Packages under the mutation gate (docs/06 §4, §5 step 8).
pub(crate) const MUTANT_PACKAGES: &[&str] = &["secmp-crypto", "secmp-proto"];

/// Packages run under Miri (docs/06 §4).
pub(crate) const MIRI_PACKAGES: &[&str] = &["secmp-sys-mem", "secmp-sys-desktop", "secmp-crypto"];

/// Packages containing Kani harnesses (docs/06 §4). M2 adds `secmp-proto`.
pub(crate) const KANI_PACKAGES: &[&str] = &[];

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
