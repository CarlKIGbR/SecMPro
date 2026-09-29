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
- M1 `secmp-crypto`: typed primitives (X25519 with all-zero rejection, ML-KEM-768/1024 via libcrux with seed-held
  decapsulation keys and validated encapsulation keys, Ed25519 with the strict verification rule of spec §3.5
  checked on the bytes, pure hedged ML-DSA-65) and the SecMP constructions `HybridKEM-768/1024` (§3.2),
  `MsgEncrypt` (§3.3), `CAEAD` (§3.4), `HybridSign` (§3.5), fingerprints (§6.2) and the safety number (§6.7);
  `SecretBytes`/`LockedSecret`, single-use `Nonce24`/`Counter64`, the Appendix A label enum (checked against the
  spec text, prefix-free), label-first HKDF helpers, one uniform error.
- M1 `secmp-sys-mem::SecretPage`: a secret in a locked page between guard pages (`memfd_secret`, `mlock` +
  `MADV_DONTDUMP`/`MADV_WIPEONFORK`, `VirtualLock`), zeroised before release; Miri via a heap backend.
- M1 verification: Wycheproof and NIST ACVP known-answer tests on every target (`vectors/external/`),
  three-way differential tests (10 000 iterations), dudect-style constant-time tests (`cargo xtask step ct`),
  seven fuzz targets with corpora, the mutation gate with the KATs, and the SecMP vectors of all eight M1 suites
  cross-checked against the independent `ref/` implementation and frozen (`cargo xtask vectors`).
- M1 supply chain (ADR-036, ADR-037): publisher trust for the RustCrypto, dalek, Cryspen and AWS accounts,
  crate-scoped trust for `getrandom`, `hax-lib*` and `typenum`, delta audits for `rand_core` and `rand`, tracked
  exemptions only outside the normal `secmp-crypto`/`secmp-proto` closure (checked per target).

### Changed

- xtask: `vet-closure` follows only normal dependency edges on each target (ADR-036); `clippy` lints all features;
  `cargo audit` ignores are ADR-backed entries in `expect.rs`; the cooldown check covers `fuzz/Cargo.lock`; Miri
  interprets `aarch64-unknown-linux-gnu` (libcrux's x86 CPU detection uses inline assembly); policy checks have
  fixture-based negative tests (M0 review F1).

- CI: the cargo-xwin cross-build job is a hard gate (no `continue-on-error`) and installs NASM (M0 review,
  condition C1).
- Repository public (OQ-18, decided 2026-09-28): README pre-release banner, private vulnerability reporting as the
  only reporting channel, ruleset `main-protection` with the four CI jobs as required checks, squash-only merges.
- Constant-time gate (ADR-038): calls timed with the CPU counter (`rdtscp` / `cntvct_el0`), batching on coarse
  counters, two-tier verdict (≤ 4.5 PASS, > 10 FAIL, otherwise one confirmatory re-measurement), NOT MEASURABLE
  when a runner's timer cannot resolve a target, runner metadata in the report; parameters only in
  `xtask/src/expect.rs`; the bench is the one `unsafe_code` exemption outside the sys crates (path-exact policy).
- Protocol specification revision 2.3 (ADR-039, answers SQ-12 … SQ-21 in `docs/reviews/ref-spec-questions-M2.md`):
  the `ver` rule of §4.1 reworded; decoder obligations for X25519, Ed25519 and ML-KEM key fields; `RelayRef.onion`
  (rend-spec-v3 version and checksum) and `RelayRef.direct` (host 1..=253 printable bytes, port ≠ 0) validity;
  Handshake `caps` = 0; list counts ≥ 1; Fragment rules; the Batch, RouteUpdate, reassembled-Fragment and Dummy
  layouts in Appendix D.5; `AppMessage.payload` and `Control.arg` opaque at the encoding layer. No byte layout changed.
- Test-vector schema revision 3 (`vectors/SCHEMA.md` §4.8, case table `vectors/SCHEMA-4.8-encodings.md`) and the
  reference file `vectors/ref/encodings.json` (632 cases) for the M2 `encodings` suite; the `ref-vectors` step
  accepts reference files listed as pending freeze (`expect::VECTOR_REF_PENDING`).
- M1 review follow-ups: `expanded_kat` returns a zeroising buffer (F1); weekly `miri-full` workflow over the
  complete Miri set (F3); the constant-time report is uploaded as a CI artefact (§E 5.7); the constant-time
  calibration warms up and derives the batch size from the median of batches (F8).
- CI: `push` runs only for `main`; pull-request runs cover every branch head.
- Constant-time gate (ADR-038 (3) as amended): 10 % calibration margin, NOT MEASURABLE below 80 realised quanta,
  resolution rules on the smaller class median.
- M2 `secmp-crypto`: decode-time checks for spec §4.1 — `X25519Public::from_bytes_checked` (low-order encodings)
  and `check_ed25519_signature_encoding` (`R` canonical, not small order, on the curve; `S < L`), cross-checked
  against Wycheproof.
- M2 `secmp-proto` (in progress): bounded reader/writer, ISO/IEC 7816-4 padding, Appendix B sizes checked at compile
  time, key and signature fields with the decoder obligations of spec §4.1, and `Encode`/`Decode` for every
  Appendix D structure (records, frame plaintexts with the complete opcode table, invitation and link data,
  handshake envelope, ratchet cell/header/content and bodies, signed command messages); every row of the
  `encodings` reference file decodes (positives, byte-exact) or is rejected (547 negatives).
