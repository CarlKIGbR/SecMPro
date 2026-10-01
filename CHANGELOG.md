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
- M2 `secmp-proto`: bounded reader/writer, ISO/IEC 7816-4 padding, Appendix B sizes checked at compile
  time, key and signature fields with the decoder obligations of spec §4.1, and `Encode`/`Decode` for every
  Appendix D structure (records, frame plaintexts with the complete opcode table, invitation and link data,
  handshake envelope, ratchet cell/header/content and bodies, signed command messages); every row of the
  `encodings` reference file decodes (positives, byte-exact) or is rejected (547 negatives).
- M2 `secmp-proto`: canonicality property tests on seeded `rand` generators (ADR-040); the Rust generator of the
  `encodings` positives (SCHEMA §2 streams via `secmp_crypto::VectorStream`, feature `kat`) agrees with the
  reference file, and `vectors/encodings.json` is frozen (`cargo xtask vectors` compares the positive rows and
  requires every negative row to be rejected); Kani harnesses for `Cell`, `HeaderV1`, the padding and both
  frame-plaintext directions; fuzz targets `proto_records`, `proto_frames`, `proto_invitation`,
  `proto_handshake`, `proto_cell` for every Appendix D decoder, seeded from the vectors.
- Constant-time harness (WEISUNG M2-2 C.6): both classes' inputs are built from one common source per target
  (branch-free blend), removing a class-dependent source-buffer artefact; a dispatch-only `linux-ct` CI job and
  per-class sample percentiles in the report support the diagnosis (`docs/reviews/M02-evidence/ct-diagnosis/`).
- Constant-time gate verdict per ADR-041 (owner-accepted): FAIL only for a shift reproduced in two measurements at
  the same crop and sign (|t| > 4.5) of at least one effective quantum — the lattice spacing of the samples,
  measured from the data — with an inline A/A control per run (`CONTROL_FAIL` otherwise) and the positive control
  detected; smaller reproduced shifts are reported as sub-quantum shifts; the immediate-FAIL tier of ADR-038 is
  withdrawn (`CT_EFFECT_FLOOR_QUANTA`, `CT_AA_MAX_T` in `xtask/src/expect.rs`).
- xtask: the `kani` gate passes a harness package's Kani unstable features (`[package.metadata.kani.unstable]`,
  e.g. stubbing) as `-Z`; the `mutants` gate leaves out code compiled only under Kani.
- Constant-time gate per ADR-041 Amendment 1 (owner-accepted 2026-09-30):
  - The effect floor is one effective quantum or 10 ns, whichever is larger (`CT_EFFECT_FLOOR_NS`). A reproduced
    shift below it is reported as `SUB_FLOOR_SHIFT`, which replaces `SUB_QUANTUM_SHIFT`.
  - The sensitivity control `min_leak_control` (a 32-byte comparison exiting one byte early, 256 per sample,
    `tag_compare`'s `k` and N) is mandatory. Its raw Δ must reach the floor in every run, otherwise the run is
    `CONTROL_FAIL`; the gate re-checks this from the report.
- `ref/`: the Python reference implementation's tree is committed (`68ac537`, external review M1 EXT-1): the
  encoders and the renderer of `vectors/SCHEMA-4.8-encodings.md` (`ref/tools/render_schema_4_8.py`); the reference
  `vectors/ref/encodings.json` carries the rev 2.3 `"spec"` header.
- M2 review conditions C1–C5 (`b75679d`):
  - `secmp-proto` keeps every encoding buffer in `secmp_crypto::Zeroizing<Vec<u8>>`: the `Writer` (it grows by
    moving into a new zeroizing buffer), `Encode::encode`, `pad`, `encode_padded`, `Fragment.chunk` and
    `RouteDescriptor::Unknown.blob`. No freed heap block keeps a `send_seed`, `link_key` or `inv_send_seed`.
  - CI: `ci.yml` has no `workflow_dispatch`; on-demand suites run from `ci-dispatch.yml` under `dispatch-*` job
    names, so a dispatch never adds a check run under a required name. Policy enforces this.
  - The `ct` gate re-derives every verdict, the controls, the target set and the sample counts from the report
    (`xtask/src/ctreport.rs`, `cargo xtask ct-check`). The bench echoes `CT_SAMPLES`/`CT_SAS_SAMPLES`, and a
    shortened run (`SECMP_CT_SCALE`) is refused.
  - The mutants gate refuses a missing survivor listing; fuzzing passes `-max_len` per target
    (`FUZZ_MAX_LEN`); the Kani gate pins the 16 harnesses (`KANI_HARNESSES`).
- Docs (M2 review C6): report corrections, the evidence of `b75679d`, the ADR-040 note on `std_rng` and the owner's
  approval of the `rand` delta audit, `CLAUDE.md`'s statement of who approves which ADR, and `fuzz/README.md` without
  the nightly-campaign claim.
- M3 `secmp-crypto`: `Aead` (plain XChaCha20-Poly1305 for ratchet headers and link frames, with the constant-work
  `open_ct` returning a `Choice`), the SecMP-TR derivations `tr_init`, `kdf_rk`, `kdf_ck` (spec §7.2), persistence
  accessors for the X25519 secret and the ML-KEM seed, and re-exports of `subtle`'s `Choice`,
  `ConditionallySelectable`, `ConstantTimeEq`.
- M3 `secmp-proto::tr`: the SecMP-TR hybrid ratchet (spec §7) — `RatchetState` with the versioned persistence encoding
  `RatchetStateV1`, `init_initiator`/`init_responder`, `encrypt` → `Sealed` (persist-before-send), transactional
  `decrypt` → `Opened` (persist-before-ack), the DH ratchet with ML-KEM-768 in both halves, skipped keys
  (`SKIP_WINDOW` 256, `MAX_FF` 2^20, 512 total, earliest-first eviction), constant-work header trial decryption,
  `Error::Unavailable` (M2 review F4), and `tr::content` (dummies, delivery, fragment reassembly, key changes with
  `Trust`).
- M3 vectors: the `tr` suite (96 events) generated by Rust from the SCHEMA §2 streams and frozen as `vectors/tr.json`,
  byte-identical to the independent reference file; unit and negative tests for every rejection of §7.4, seeded
  property tests against a model of §7.4, Kani harnesses for the header-key selection and the skip/eviction bounds,
  fuzz targets `tr_decrypt` and `tr_state`, ct targets for the decrypt rejections, the ci-full step `perf`
  (encrypt + decrypt < 3 ms).
- M3 `formal/`: `CLAIMS.md` §TR (the reviewer's query set) and the ProVerif model `tr.pv`; the ProVerif gate compares
  every result with the claims (`PROVERIF_EXPECTED`).
- M3 CI and gates (M2 review follow-ups): the policy step pins the job-level conditions of the required jobs (F19);
  step 12a byte-compares frozen and reference vectors (F8); the fuzz gate fuzzes a scratch corpus seeded from the
  tracked corpus and the frozen vectors (F7, F18); a scheduled `fuzz-nightly` workflow (4 h, env-seeded property run;
  F2, F10); `secmp-proto` under Miri (F3); ct-gate hardening (F15–F17); the ct bench moved to `secmp-testkit` with an
  inline A/A′ placement control (ADR-042, F6); PartialEq only in tests on MAC/commitment/token/tag types (F1);
  zeroizing signed messages and plaintext fields (F20, F21); the fine-timer recomputation script (F13).
