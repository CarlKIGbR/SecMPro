# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project will use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first release.

## [Unreleased]

### Added

- M0 repository bootstrap: Cargo workspace with the eleven `secmp-*` crates as documented skeletons (responsibility
  and allowed dependencies per `docs/02` §3; `#![forbid(unsafe_code)]` everywhere except `secmp-sys-mem` and
  `secmp-sys-desktop`), pinned toolchain (Rust 1.98.1), workspace lint set of `docs/06` §2, release profile and
  target flags of `docs/06` §6.
- `cargo xtask`: `ci-fast`, `ci-full`, `step`, policy checks (`forbid(unsafe_code)`, lint allowances, build
  scripts, SPDX, workflow hygiene, cargo-vet closure), 7-day dependency cooldown, `sbom`, `win-test --backend
  github` (with a documented `libvirt` backend for M9), `install-tools`, and documented stubs for `vectors`,
  `repro-check` and `ops-check`.
- Supply chain: `deny.toml` (crates.io only, license allowlist, bans), cargo-vet with Mozilla, Google, ISRG,
  Bytecode Alliance and Zcash imports and a tracked-exemption procedure.
- GitHub Actions CI: Linux fast gate with SBOM and systemd exposure gate, Windows gate on `windows-latest`,
  cargo-xwin cross-build, nightly `ci-full`.
- `LICENSE` (AGPL-3.0-or-later), `SECURITY.md`, ADR-029 to ADR-032, owner decisions OQ-1, OQ-2, OQ-3 and OQ-17
  recorded.
- M0 build spikes (`docs/reviews/M0-spikes.md`): SQLCipher with vendored OpenSSL builds and runs natively on
  Windows, Linux and macOS but does not cross-build with cargo-xwin (ADR-027: SQLCipher stays primary); aws-lc-rs
  builds natively everywhere and cross-builds with cargo-xwin when NASM is present; a Slint hello-world window
  opens on macOS and compiles for Linux and Windows (`slint!` conflicts with `#![forbid(unsafe_code)]`, reported
  for M8).
- M0 milestone report with evidence (`docs/reviews/M00-report.md`, `docs/reviews/M00-evidence/`).
- M0 review follow-ups (`docs/reviews/M00-review.md` §F): reviewer amendments to `docs/02`, `06`, `08` (ADR-033,
  ADR-034), `09` (OQ-18), `vectors/SCHEMA.md` and `docs/prompts/kickoff-ref.md`; cargo-vet publisher trust for
  dtolnay and BurntSushi replaces the ten tracked exemptions (no exemptions left); workspace lints
  `undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block`; the `policy` step enforces the sanctioned
  `unsafe_code` relaxations of `docs/06` §2 (`#![allow(unsafe_code)]` at the library root of exactly the two
  `secmp-sys-*` crates, `#![deny(unsafe_code)]` and no `unsafe` token in `secmp-ui`, `forbid` everywhere else);
  Dependabot for Cargo and GitHub Actions (weekly, grouped, 7-day cooldown).
