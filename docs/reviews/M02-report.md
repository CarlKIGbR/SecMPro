# Milestone report — M02 `secmp-proto`: encodings, cells, frames, command types

Branch: `m02-proto` · Base: `main` at `bc8d6d559795cf515bcf08f63fcfe0b9eb3058d9` (M1 squash merge) · Author: Claude Code (Opus 5.5) · Date: 2026-09-29

Status: **commit 1 done (docs, reviewer deliverables, M1 carry-overs, CI trigger; `9f20b95` … `168ede0`), local
`ci-fast` green; M2 code not started.** Inputs:
`docs/07` M2, spec rev 2.3 (ADR-039), `vectors/SCHEMA.md` rev 3 with the §4.8 case table
`vectors/SCHEMA-4.8-encodings.md` (decoding contract D-1 … D-13), `docs/reviews/ref-spec-questions-M2.md` (SQ-12 …
SQ-21, binding readings), `docs/reviews/M01-review.md` §G/§H, and the reviewer's M2 brief. `ref/`, `vectors/ref/`,
`vectors/SCHEMA.md`, `vectors/SCHEMA-4.8-encodings.md` and the sibling `SecMProRef/` are never edited by this
session.

## 1. Plan (written before implementation, updated during)

Scope: `docs/07` M2; spec `docs/03` §4, §5.2–5.4, §6.2–6.5, §7.5–7.6, §8.2–8.4, §9.2–9.8, Appendices B and D;
`docs/06` §2–§5, §8, §9. `secmp-proto` stays sans-IO (no tokio, no I/O, no persistence, no `secmp-tr` logic);
all cryptography it needs for the decoder obligations of §4.1 (X25519 low-order, Ed25519 byte rules and
on-curve, ML-KEM modulus check, SHA3-256 for the onion checksum) goes through `secmp-crypto`.

| Step | What | Proves acceptance criterion | Status |
|---|---|---|---|
| 0a | Reference SHA verified: `vectors/ref/encodings.json` SHA-256 `9abd63d7…80131b8` (632 rows, 85 positive, 547 negative, `"schema": 3`) | precondition | done (before any change) |
| 0b | ADR-039, SQ-12 … SQ-21 answers, SCHEMA rev 3, SCHEMA-4.8 case table, `vectors/ref/encodings.json` committed unchanged | brief commit 1.2 | done `9f20b95` |
| 0c | Spec rev 2.3 per ADR-039 (§4.1 `ver` wording and decoder obligations, §5.3 onion, §7.6, D.3 direct host/port, D.5 `caps`/counts/Fragment/four §7.6 layouts/0x05), revision line, changelog | brief commit 1.1 | done `15acadf` |
| 0d | M1 F1: `expanded_kat` returns `Zeroizing<Vec<u8>>` | M1 review F1 | done `962069b` |
| 0e | M1 F3: weekly `miri-full` workflow (schedule + dispatch, 360 min, not required), xtask on-demand step `miri-full` | M1 review F3 | done `a22fbf6` |
| 0f | M1 §E 5.7: `target/ct-report.json` uploaded from every `linux-full` run | M1 review §E 5.7 | done `7aa853f` |
| 0g | M1 F8: ct calibration warm-up and `k` from the batch median (`CT_THRESHOLDS`, `CT_MAX_BATCH` unchanged) | M1 review F8 (ADR-038 (3)) | done `9835bb3` (§3) |
| 0h | CI `push` only for `main` (+ one line in `docs/06` §4) | brief commit 1.4 | done `54da5af` |
| 0i | `CLAUDE.md` GO delegation; `docs/07` status lines (M1 merged, M2 started) | brief commit 1.5, 1.6 | done `90a1d3c` |
| 0j | `ref-vectors` step: explicit list of reference files pending freeze (`encodings`), so committing the reference file does not break `linux-full` | keeps step 12a exact (§8) | done `285cb17` |
| 0k | F8 follow-up: a call shorter than one quantum starts the batched calibration at `CT_MAX_BATCH` | M1 review F8 | done `168ede0` |
| 1 | Crate foundation: uniform `Reject` error; bounded `Reader`/`Writer` (checked arithmetic, `try_into`, no indexing); ISO/IEC 7816-4 padding helpers; App. B size constants with `const` assertions; `Encode`/`Decode` traits (exact fit, D-1) | review focus: no unchecked `usize` arithmetic; sizes match App. B | open |
| 2 | Decoder-obligation types: X25519 public key (D-9), Ed25519 key and signature encodings (D-10), HybridSig, ML-KEM-768/1024 `ek` (D-11); the missing message-free checks added to `secmp-crypto` with unit and Wycheproof-derived tests | spec §4.1 decoder obligations | open |
| 3 | D.1 records and `RelayInfoV1` | App. D coverage | open |
| 4 | D.2 frame plaintext: request and response decoders per direction, complete opcode table (SKEY 0x02 reserved → reject), CONT, CELLR with its request context, D-7 zero fields | review focus: opcode table complete | open |
| 5 | D.3 `RelayRef` (onion version/checksum, direct host/port), `InvitationV1`, `Profile` (strict UTF-8), `LinkDataV1` (padded), `LinkBlob`, `IKSPublic`, `PrekeyBundle` | App. D coverage; `Option` strictness (D-5) | open |
| 6 | D.4 `Outer` (padded), `inner_ct`, `Inner`, `HandshakeCell`, `HandshakeCellPlaintext` | App. D coverage | open |
| 7 | D.5 `Cell`, `HeaderV1`, `Content` (typed bodies, padded), `AppMessage`, `Fragment`, `FragmentPayload`, `RouteDescriptor` (unknown kinds kept), `RelayQueue`, the Handshake/Batch/RouteUpdate/KeyChange/Receipt/Control bodies | App. D coverage; consistency rule | open |
| 8 | D.6 signed-message builders (encode only) | App. D coverage | open |
| 9 | Unit tests with every failure path; property tests `decode(encode(x)) == x`, `encode(decode(b)) == b` per structure (`proptest` is a new dev-dependency: ADR + `cargo vet` record first, `docs/06` §3) | "`decode(encode(x)) == x` and `encode(decode(b)) == b` for all structures" | open |
| 10 | `cargo xtask vectors` for `encodings`: Rust generator of the 85 positives from the SCHEMA §2 streams, structural comparison with `vectors/ref/encodings.json` (byte-for-byte on every positive, decode of every positive to its value), every one of the 547 negatives rejected with the uniform error; freeze `vectors/encodings.json`; per-target re-check test | "every negative vector rejected with the uniform error"; "Rust and `ref/` encodings identical" | open |
| 11 | Kani harnesses for `Cell`, `Frame`, `HeaderV1` and frame-plaintext parsing (no panic, exact fit); `KANI_PACKAGES` += `secmp-proto` | "Kani proofs pass" | open |
| 12 | Fuzz targets for every decoder (corpora seeded from the vectors); `FUZZ_TARGETS` extended; 2 min each | "fuzzers run 2 min without findings" | open |
| 13 | Mutation gate on `secmp-proto` (and the `secmp-crypto` additions), coverage ≥ 90 % | `docs/06` §4, §8 | open |
| 14 | `ci-full --strict` locally and on CI (PR run), evidence under `docs/reviews/M02-evidence/`, CHANGELOG, report, PR ready for review | `docs/06` §8 DoD | open |

## 2. What was built

Commit 1 (before any M2 code):

- `docs/03-protocol-spec.md` rev 2.3 (ADR-039): §4.1 — the `ver` rule in the brief's wording, and a
  "decoder obligations" bullet (X25519 low-order set; Ed25519 §3.5 byte rules and on-curve for keys and `R`, `S < L`;
  FIPS 203 §7.2 modulus check on every ML-KEM `ek`; no ML-DSA sigDecode at decode); §5.3 — `onion` is the rend-spec-v3
  §6 address, VERSION 0x03 and a valid CHECKSUM, no rule on PUBKEY; §7.6 — `caps` = 0, counts 1..=255, Fragment
  rules, unfragmented 0x05 rejects, `payload`/`arg` opaque pending an application-layer ADR; D.3 — `direct.host`
  1..=253 bytes in 0x21..=0x7E, `port` ≠ 0; D.5 — `caps u32 (0)`, `count u8 (1..=255)`, Fragment rules and the
  Batch, RouteUpdate, reassembled-Fragment and Dummy layouts. Revision line and changelog in the document header;
  `CHANGELOG.md`. Every layout stays as App. D rev 2.2 lists it (SQ-20).
- `secmp-crypto`: `MlKem{768,1024}Dk::expanded_kat` returns `Zeroizing<Vec<u8>>` (feature `kat`).
- `.github/workflows/miri-full.yml` (new) and xtask step `miri-full` (on demand; `ci-full` keeps the bounded Miri
  scope with `MIRI_SKIP`); tool set `miri`.
- `.github/workflows/ci.yml`: `push` only for `main`, the unreachable milestone-branch clause of `linux-full`
  removed, `concurrency` unchanged; `target/ct-report.json` uploaded as artefact `ct-report-<os>-<arch>-<sha>`
  unless the run was cancelled.
- `crates/secmp-crypto/benches/ct.rs` (F8): a warm-up pass before the calibration; `k` derived from the median of
  batches of `k` calls (at most three batched rounds, until `quantum ≤ fraction · batch median`); the report gains
  a `calibration` object (single-call median, every round's `k` and batch median); `calibration_median_ns` is now
  the per-call median `k` rests on. `CT_THRESHOLDS`, `CT_RESOLUTION_MAX_FRACTION`, `CT_MAX_BATCH` unchanged.
- `docs/06` §4 (CI triggers line), `CLAUDE.md` (GO delegation), `docs/07` (M1 and M2 status lines).
- `xtask` `ref-vectors` (ci-full step 12a): `expect::VECTOR_REF_PENDING = ["encodings"]` — `vectors/*.json` must
  equal `VECTOR_SUITES`, `vectors/ref/*.json` must equal `VECTOR_SUITES` plus the pending suites (disjoint), and a
  pending reference file must name its suite and have cases; two unit tests. Without it the committed reference
  file would have failed `linux-full` until the freeze.
- `ct.rs` follow-up: a call shorter than one quantum starts its batched calibration at `CT_MAX_BATCH`.
- `CHANGELOG.md` entries; `docs/reviews/M02-evidence/` (ct reports and gate logs, `ci-fast` summary).

## 3. Evidence per acceptance criterion

| Criterion (from `07-milestones.md`) | Test / command | Result |
|---|---|---|
| `decode(encode(x)) == x` and `encode(decode(b)) == b` for all structures | — | open (step 9) |
| every negative vector rejected with the uniform error | — | open (step 10) |
| Kani proofs pass | — | open (step 11) |
| fuzzers run 2 min without findings | — | open (step 12) |
| Rust and `ref/` encodings identical | — | open (step 10) |

Commit-1 evidence:

| Item | Command | Result |
|---|---|---|
| Reference file intact | `shasum -a 256 vectors/ref/encodings.json` | `9abd63d7ea5c35c0a9731f91ab7584de57890de728f8799ad3dae30f380131b8` (matches the brief) |
| F1 | `cargo nextest run -p secmp-testkit --features kat --release --test differential` | 4/4 pass (the ML-KEM tests import the zeroising expanded key into aws-lc-rs) |
| F3, §E 5.7, trigger change | `cargo xtask step policy` | PASS — "workflows: 2 files, triggers/SHA pins/continue-on-error ok"; `cargo nextest run -p xtask` 47/47 (incl. the two new vector-set tests) |
| `ci-fast` | `cargo xtask ci-fast` on `9835bb3` (macOS arm64) | **PASS** — fmt, clippy, policy, deny, vet (normal closure 52 crates, 0 exempted), audit, cooldown (119 packages ≥ 7 days), nextest, doctest, hello, kat 315 s (differential 10/10 incl. ML-DSA 299 s; portable libcrux backend 21/21). `M02-evidence/ci-fast-aarch64-apple-darwin-9835bb3.txt` |
| Later commits | `cargo xtask step fmt clippy policy nextest ref-vectors` on `168ede0` | **PASS** — `ref-vectors`: "8 frozen suites (118 cases) structurally identical to vectors/ref (ADR-026); pending freeze: encodings (632 cases, reference only)". `M02-evidence/steps-aarch64-apple-darwin-168ede0.txt` |
| F8, final code | `cargo xtask step ct` on `168ede0` (macOS arm64, `cntvct_el0`, tick = resolution = 41.67 ns) | **PASS**, every target on its first measurement: control detected (max \|t\| 37 345, k = 20); `tag_compare` 1.46 (k = 1); `msg_open_reject` 2.45 (k = 2); `caead_open_reject` 0.95 (k = 1); `sas` 1.85 (k = 1); `caead_derive` 1.45 (k = 15); `caead_aead_reject` 1.18 (k = 2); `caead_com_compare` 1.68 (k = 1); `caead_open_reject_samekey` 1.79 (k = 1). Calibration → measurement batch medians (ticks): `caead_derive` single 7 → k = 15, round 105 → measured 101; `msg_open_reject` 59 → k = 2, 124 → 123; `caead_aead_reject` 87 → k = 2, 174 → 174. Evidence: `M02-evidence/ct-report-aarch64-apple-darwin-168ede0.json`, `M02-evidence/ct-gate-aarch64-apple-darwin-168ede0.txt`. |
| F8, first run | `cargo xtask step ct` (same host; code of `9835bb3`) | **PASS**, 97 s. Control detected (max \|t\| 31 670, k = 3); `tag_compare` 1.85 (k = 1); `msg_open_reject` 1.79 (k = 2); `caead_open_reject` 4.13 (p90, k = 1); `sas` 1.54 (k = 1, 2·10⁴ samples); `caead_derive` 2.90 (k = 14); `caead_aead_reject` 1.31 (k = 2); `caead_com_compare` 2.00 (k = 1); `caead_open_reject_samekey` INCONCLUSIVE→PASS (first 6.68 at p50, second 3.74 at p95, no same-crop same-sign confirmation). Calibration rounds per target in the report: e.g. `caead_derive` single-call median 8 ticks → k = 13, batch median 94 ticks (unresolved) → k = 14, batch median 100 ticks (resolved). Evidence: `M02-evidence/ct-report-aarch64-apple-darwin-9835bb3.json`, `M02-evidence/ct-gate-aarch64-apple-darwin-9835bb3.txt`. Observations: (1) `caead_derive` realised a measurement batch median of 97 quanta against 100 in its calibration (M1: 90) — the measurement ran ≈ 3 % faster per call than the calibration; the rule is met as written for the calibration, not with a margin for the measurement. (2) The control's calibration median (1 903 ns per call) and measurement median (264 ns per call) differ because the control is variable-time by design: its two classes form a 50/50 bimodal distribution and the pooled median falls into either mode; this does not affect its role (detected). |

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci` (Linux) | open |
| Windows (`windows-native`, `xwin-cross`) | open |
| `cargo xtask ci-fast` (macOS arm64) | PASS on `9835bb3` (§3); fmt/clippy/policy/nextest/ref-vectors PASS on `168ede0` |
| KATs / differential | PASS in `ci-fast` (§3); differential 4/4 in release after F1 |
| Constant time (`ct`, M1 code) | macOS arm64 PASS on `168ede0` and `9835bb3` (§3); Linux: in the PR run's `linux-full`, report uploaded as artefact |
| Fuzz smoke | open |
| Mutation | open |
| Coverage | open |
| Kani / Miri | open; weekly `miri-full` workflow added (runs on `main` once merged: `schedule` works only on the default branch) |
| `cargo deny` / `cargo vet` / `cargo audit` / cooldown | open |
| CI runs of commit 1 | see §8 (run ids) |

## 5. Deviations from spec / plan

None. Notes: (a) the brief asks for the CI-trigger line in `docs/06` §4; it sits after the §4 table. (b) Removing
the `push && ref != main` clause of `linux-full` is the direct consequence of `push: branches: [main]` (the clause
could no longer be true); no other workflow change. (c) ADR-038 (3) says the calibration "measures each target's
median once"; F8 replaces that with a warm-up plus up to three batched rounds — the ADR text may want the
reviewer's amendment line.

## 6. Dependencies added or bumped

None so far. Planned: `proptest` as a dev-dependency of `secmp-proto` (step 9) — ADR line and `cargo vet` record
before it is added.

## 7. Open risks and known limitations

- The weekly `miri-full` job cannot be exercised before the workflow is on `main` (`schedule`/`workflow_dispatch`
  only run for workflows on the default branch); its xtask step is the same code path as `miri` with an empty skip
  list.

## 8. Blocked / questions for the reviewer or owner

None blocking.

- Q-1 (F8, for the reviewer): the batched calibration resolves each target *in the calibration* (`quantum ≤ 1 % ·
  batch median`), but the measurement itself may run a few per cent faster (`caead_derive` on `9835bb3`: 100 quanta
  calibrated, 97 realised; on `168ede0`: 105 calibrated, 101 realised). Keep the rule as written (ADR-038 (3)), or should `k` carry a margin (e.g. aim at 110 quanta)? No
  change without the reviewer's word; `CT_*` constants untouched.
- Q-2 (step 10, early notice): the header of `vectors/ref/encodings.json` reads `"spec": "SecMP/1 rev 2.2"`
  (`"schema": 3`). The structural comparison (SCHEMA §1) removes only `generator`, so the Rust generator must
  write the same `spec` string. The layouts are unchanged in rev 2.3, but the file encodes rev 2.3 rules (SQ-12 …
  SQ-18). Unless the reviewer says otherwise, the Rust side writes `"SecMP/1 rev 2.2"` to match the delivered
  reference; the reference file is not touched either way.
- CI: since `54da5af` a push to `m02-proto` starts no `push` run by design; the PR run covers every head.
- `ref-vectors` gate (ci-full step 12a): it required `vectors/ref/*.json` to equal the frozen suite list, so the
  committed `vectors/ref/encodings.json` would have failed `linux-full` until the freeze. Fixed in xtask by an
  explicit list `expect::VECTOR_REF_PENDING = ["encodings"]` (reference present and well-formed, no frozen file
  yet); step 10 moves `encodings` to `VECTOR_SUITES`. Nothing is skipped: the pending file is checked for presence,
  its `suite` name and a non-empty `cases` array.

## 9. Checklist before requesting review

- [ ] All acceptance criteria evidenced above
- [ ] `cargo xtask ci` green on a clean checkout
- [ ] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [ ] Vectors frozen and reviewed (if changed)
- [ ] Docs/CHANGELOG updated
- [x] Threat model untouched; spec changed only per ADR-039 (rev 2.3)
