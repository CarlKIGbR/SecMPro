# Milestone report — M02 `secmp-proto`: encodings, cells, frames, command types

Branch: `m02-proto` · Base: `main` at `bc8d6d559795cf515bcf08f63fcfe0b9eb3058d9` (M1 squash merge) · Author: Claude Code (Opus 5.5) · Date: 2026-09-29

Status: **commit 1 done (`9f20b95` … `168ede0`); WEISUNG M2-1 applied (`d09666a` … `ffe0612`); plan steps 1–8
done (`86830da`, `b2e3319`, `d90f3b7`): every Appendix D structure encodes and decodes, all 547 negative rows of the
reference file are rejected. Steps 9–14 open. One open item on the ct gate (M1 code, §8 Blocked).** Inputs:
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
| 0l | WEISUNG M2-1: repository security settings (secret scanning + push protection on; CodeQL default setup for Rust rejected by the API, left) | owner decision 2026-09-29 | done `d09666a` |
| 0m | WEISUNG M2-1 Q-1: ADR-038 amendment line; 10 % calibration margin, < 80 realised quanta → NOT_MEASURABLE | M1 review F8 | done `19f5700` (ct event: §8) |
| 1 | Crate foundation: uniform `Error::Rejected`; bounded `Reader`/`Writer` (checked arithmetic, `try_into`, no indexing); ISO/IEC 7816-4 padding helpers; App. B size constants with `const` assertions; `Encode`/`Decode` traits (exact fit, D-1) | review focus: no unchecked `usize` arithmetic; sizes match App. B | done `b2e3319` (§3) |
| 2 | Decoder-obligation types: X25519 public key (D-9), Ed25519 key and signature encodings (D-10), HybridSig, ML-KEM-768/1024 `ek` (D-11); the missing message-free checks added to `secmp-crypto` with unit and Wycheproof-derived tests | spec §4.1 decoder obligations | done `86830da` (`secmp-crypto`), `b2e3319` (`keys.rs`) |
| 3 | D.1 records and `RelayInfoV1` | App. D coverage | done `b2e3319` |
| 4 | D.2 frame plaintext: request and response decoders per direction, complete opcode table (SKEY 0x02 reserved → reject), CONT, CELLR with its request context, D-7 zero fields | review focus: opcode table complete | done `b2e3319` |
| 5 | D.3 `RelayRef` (onion version/checksum, direct host/port), `InvitationV1`, `Profile` (strict UTF-8), `LinkDataV1` (padded), `LinkBlob`, `IKSPublic`, `PrekeyBundle` | App. D coverage; `Option` strictness (D-5) | done `b2e3319` |
| 6 | D.4 `Outer` (padded), `inner_ct`, `Inner`, `HandshakeCell`, `HandshakeCellPlaintext` | App. D coverage | done `b2e3319` |
| 7 | D.5 `Cell`, `HeaderV1`, `Content` (typed bodies, padded), `AppMessage`, `Fragment`, `FragmentPayload`, `RouteDescriptor` (unknown kinds kept), `RelayQueue`, the Handshake/Batch/RouteUpdate/KeyChange/Receipt/Control bodies | App. D coverage; consistency rule | done `b2e3319` |
| 8 | D.6 signed-message builders (encode only) | App. D coverage | done `b2e3319` |
| 8a | Every row of `vectors/ref/encodings.json` through the decoders (ahead of step 10's generator): 78 decodable positives byte-exact, **547/547 negatives rejected** | "every negative vector rejected with the uniform error" (the Rust side; the freeze in step 10) | done `d90f3b7` |
| 9 | Unit tests with every failure path; canonicality property tests on generators built from `rand` (already vetted; WEISUNG M2-1: no new dependency, no `proptest`): random valid values from a seeded RNG, `decode(encode(x)) == x` and `encode(decode(b)) == b` per structure, plus targeted edge values (every counter and length at its minimum and maximum, every enum variant); any case that needs shrinking is reported | "`decode(encode(x)) == x` and `encode(decode(b)) == b` for all structures" | open |
| 10 | `cargo xtask vectors` for `encodings`: Rust generator of the 85 positives from the SCHEMA §2 streams (header `"spec": "SecMP/1 rev 2.3"`, WEISUNG M2-1 Q-2), structural comparison with `vectors/ref/encodings.json` (byte-for-byte on every positive, decode of every positive to its value), every one of the 547 negatives rejected with the uniform error; freeze `vectors/encodings.json`; per-target re-check test; **`expect::VECTOR_REF_PENDING` empty again** (`encodings` moved to `VECTOR_SUITES`) — acceptance condition of `285cb17` (WEISUNG M2-1) | "every negative vector rejected with the uniform error"; "Rust and `ref/` encodings identical"; `285cb17` condition | open |
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

WEISUNG M2-1 and plan steps 1–8:

- `d09666a` repository security settings (log `M02-evidence/repo-settings-2026-09-29.txt`); `19f5700` ADR-038
  amendment and the ct margin / realised-quanta rule (`expect::CT_BATCH_MARGIN`, `CT_MIN_REALISED_QUANTA`, echoed
  and checked by the gate).
- `86830da` `secmp-crypto`: `X25519Public::from_bytes_checked` (the 14 low-order encodings, spec §4.1 (a)) and
  `check_ed25519_signature_encoding` (spec §4.1 (b): R canonical, not of small order, a curve point; S < L); the
  Ed25519 key and ML-KEM `ek` checks already existed. Wycheproof cross-checks: X25519 refused at decode exactly when
  the shared secret is all zero (518 cases); 51 Ed25519 signatures refused at decode, each also refused by strict
  verification; every valid one accepted.
- `b2e3319` `secmp-proto` (sans-IO; depends on `secmp-crypto` only):
  - `error.rs` — `Error::Rejected`, the one error; `codec.rs` — `Reader` (every read `split_at_checked`, lengths
    `usize::from`/`try_from`), `Writer`, `Encode`/`Decode` (exact fit), `pad`/`unpad` (ISO/IEC 7816-4, marker
    required, zero tail, no room → reject); `sizes.rs` — Appendix B/§4.2 sizes re-derived at compile time from the
    App. D field lists (`const _: () = assert!(…)`, incl. every largest frame payload < 4336 and agreement with
    `secmp-crypto`'s constants); the crate root repeats the deny set (`arithmetic_side_effects`, `indexing_slicing`,
    `as_conversions`, `unwrap_used`, `expect_used`, `panic`).
  - `keys.rs` — `X25519Pk`, `Ed25519Pk`, `Ed25519Sig`, `HybridSig` (Ed25519 half checked, ML-DSA half opaque:
    no sigDecode at decode), `MlKem768Ek`, `MlKem1024Ek`; redacted `Debug`.
  - `wire/` — D.1 `record.rs`, D.2 `frame.rs` (opcode table `opcode::REQUESTS`/`RESPONSES`, checked against the
    spec text), D.3 `inv.rs`, D.4 `hx.rs`, D.5 `cell.rs`, D.6 `signed.rs`. App.-D constants (`ver`, record types,
    `flags`, `caps`, `total = 3`, `opk_present`, reserved zero fields) are not struct fields: written by the
    encoder, checked by the decoder. Optional parts are `Option`s (`Direct`, avatar, evicted id, LINK_GET owner
    signature), booleans `bool`, closed sets enums (`Period`, `AppKind`, `ErrCode`, `CellrError`,
    `ReceiptKind`, `ControlCode`, `ContIdx`); unknown `RouteDescriptor` kinds are kept opaque (§9.8). Secret fields
    (`link_key`, `inv_send_seed`, `send_seed`) are `SecretBytes<32>`; their structures have no `Clone`/`PartialEq`/
    `Debug`. Other structures get `Debug` only in unit tests (CS-2.5). No decoder recurses or allocates more than
    its input bounds (≤ 64 KiB per length field, ≤ 255 list elements).
- `d90f3b7` `tests/encodings_ref.rs` (every row of the reference file) and ADR-040 (Proposed: `serde_json`, later
  `rand`, as dev-dependencies of `secmp-proto`; no new crate in `Cargo.lock`).

## 3. Evidence per acceptance criterion

| Criterion (from `07-milestones.md`) | Test / command | Result |
|---|---|---|
| `decode(encode(x)) == x` and `encode(decode(b)) == b` for all structures | — | open (step 9) |
| every negative vector rejected with the uniform error | `cargo nextest run -p secmp-proto --test encodings_ref` (`every_row_of_the_encodings_file`, reference file SHA-256 `9abd63d7…`) | **547/547 negatives rejected with `Error::Rejected`**; 78/78 decodable positives decode and re-encode byte-for-byte (frames to the named command); 7 `Signed/*` rows encode-only (step 10). Freeze pending (step 10). Evidence `M02-evidence/secmp-proto-tests-d90f3b7.txt` |
| Kani proofs pass | — | open (step 11) |
| fuzzers run 2 min without findings | — | open (step 12) |
| Rust and `ref/` encodings identical | — | open (step 10) |
| `expect::VECTOR_REF_PENDING` empty at the DoD (condition on `285cb17`, WEISUNG M2-1) | `cargo xtask step ref-vectors` ("pending freeze: none") | open (step 10) |
| Review focus: sizes match Appendix B | `crates/secmp-proto/src/sizes.rs` compile-time assertions (every App. B size re-derived from its App. D field list, frame payload maxima < 4336, agreement with `secmp-crypto`) | compiles (a wrong size is a build error); per-structure unit tests assert the encoded lengths (e.g. `relay_info_and_its_record` 1741/1744, `iks_bundle_link_data_blob` 2017/7775/12288/12360, `outer_is_padded_to_three_chunks` 12018, `every_request_round_trips_at_frame_size` 4336) |
| Review focus: no unchecked `usize` arithmetic | `cargo clippy -p secmp-proto --all-targets -- -D warnings` with the crate-level deny set (`arithmetic_side_effects`, `indexing_slicing`, `as_conversions`) on top of the workspace lints | clean; lengths come from `split_at_checked`/`try_from`, the few size computations use `checked_add`/`checked_sub` |
| Review focus: opcode table complete | `wire::frame::tests::opcode_table_equals_appendix_d2` (parses D.2 of `docs/03`), `reserved_and_foreign_opcodes_reject` (all 256 opcodes in both directions) | pass: 10 request opcodes (SKEY listed, rejects), 7 response opcodes |
| Review focus: `Option` strictness, consistency rule | presence/boolean bytes through `Reader::flag` (0/1 only); `Option` fields derive their presence byte; exact fit everywhere (`testutil::exact_fit` in every structure's unit test) | pass (39 unit tests); the reference rows of families OPT, LEN, TRAIL, SIZE all reject |
| Spec §4.1 decoder obligations | `secmp-crypto`: `decode_refuses_exactly_the_low_order_encodings`, `signature_encoding_check`, `kat_curve25519::wycheproof_x25519`/`wycheproof_ed25519_strict` (decode-time checks agree with the checks at use); `secmp-proto`: `keys::tests::*`, `onion_checksum_and_version` (incl. a published v3 address) | pass (`M02-evidence/secmp-crypto-decode-checks-86830da.txt`, 16/16); reference rows of families X25519 (all 9 fields), ED25519, MLKEM reject |

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
| Constant time (`ct`, M1 code) | macOS arm64 PASS on `168ede0` and `9835bb3` (§3); on `19f5700` (margin): run 1 **FAIL** (`caead_open_reject_samekey` 18.39 at p50, raw −0.80), runs 2 and 3 PASS (2.95, 0.91) — §8 Blocked; Linux: in the PR run's `linux-full`, report uploaded as artefact |
| Fuzz smoke | open |
| Mutation | gate in step 13; local look-ahead (`M02-evidence/mutants-local-steps1-8.txt`): `cargo mutants -p secmp-proto` first pass 343 mutants — 258 caught, 75 unviable, **10 missed** (four untested accessors, three `FragmentPayload` inner-type arms, `Profile::name`, and `FETCH_MULTI` `count == 0 \|\| count > 32` → `&&`, which the reference-file test missed because it judged negatives after re-encoding and the encoder enforces the same rule). Fixed by tests, and the reference test now judges every negative on the decoder alone: second pass **268 caught, 75 unviable, 0 missed**; the changed `secmp-crypto` files (`x25519.rs`, `ed25519.rs`, feature `kat`): 47 mutants, 28 caught, 19 unviable, 0 missed |
| Coverage | open (gate in step 13); preliminary local measurement on `d90f3b7`: `cargo llvm-cov nextest -p secmp-proto` — lines 2321, missed 26, **98.88 %** (codec 100, frame 100, hx 100, record 99.5, signed 99.0, mod 98.9, inv 98.3, keys 98.0, cell 97.5) |
| Kani / Miri | open; weekly `miri-full` workflow added (runs on `main` once merged: `schedule` works only on the default branch) |
| `cargo xtask ci-fast` on `d90f3b7` (macOS arm64) | **PASS** — every step, nextest over the workspace, kat 368 s (`M02-evidence/ci-fast-aarch64-apple-darwin-d90f3b7.txt`) |
| `cargo deny` / `cargo vet` / `cargo audit` / cooldown | PASS in local `ci-fast` on `d90f3b7` (vet: 92 fully audited, 1 partially, 24 exempted — normal `secmp-crypto`/`secmp-proto` closure: 52 external crates, 0 exempted; cooldown: 119 packages ≥ 7 days) |
| `secmp-proto` unit + reference tests | 40/40 on `d90f3b7` (`M02-evidence/secmp-proto-tests-d90f3b7.txt`) |
| CI runs | PR run of each pushed head (no push runs on milestone branches since `54da5af`); ids in the final message of each run |

## 5. Deviations from spec / plan

None. Notes: (a) the brief asks for the CI-trigger line in `docs/06` §4; it sits after the §4 table. (b) Removing
the `push && ref != main` clause of `linux-full` is the direct consequence of `push: branches: [main]` (the clause
could no longer be true); no other workflow change. (c) ADR-038 (3) now carries the reviewer's amendment line
(warm-up, batch median, 10 % margin, < 80 → NOT_MEASURABLE), implemented in `19f5700`.

## 6. Dependencies added or bumped

| Crate | Version | ADR | Vet record | Reason |
|---|---|---|---|---|
| `secmp-crypto` (path) | workspace | docs/02 §3 | — (first party) | `secmp-proto`'s only allowed workspace dependency |
| `serde_json` (dev, `secmp-proto`) | 1.0.151 (already in the lock) | ADR-040 (Proposed) | trust `dtolnay` (ADR-031) | reading the `encodings` vector file in tests |

`rand` (dev, for step 9) is covered by ADR-040 but not added yet. `proptest` is not used (WEISUNG M2-1). No new
crate entered `Cargo.lock` (the only lock change is `secmp-proto`'s two dependency edges).

## 7. Open risks and known limitations

- The weekly `miri-full` job cannot be exercised before the workflow is on `main` (`schedule`/`workflow_dispatch`
  only run for workflows on the default branch); its xtask step is the same code path as `miri` with an empty skip
  list.

## 8. Blocked / questions for the reviewer or owner

**Blocked (ct gate, M1 code — docs/06 §4 STOP rule):** `cargo xtask step ct` on `19f5700` (macOS arm64,
`cntvct_el0`, 41.67 ns) failed once: `caead_open_reject_samekey` FAIL, max |t| **18.39 at p50** (raw −0.80; p75
3.82, p90 3.25, p95 4.92, p99 6.34; k = 1, realised 190 quanta; every other target PASS). Root-cause step in the
code under test first: `Caead::open` (`crates/secmp-crypto/src/caead.rs`, unchanged since `b24bcfa`) has no path
that depends on *where* the ciphertext is tampered — both classes use the right key, the commitment matches, the
whole ciphertext is copied and authenticated and the tag compare is `subtle`-based; the harness gives both classes
fresh copies of equal size in the same allocation sequence. The change under test in `19f5700` does not touch this
target (k = 1 before and after; the margin and the class-median rule change only k > 1 targets). Two further runs of
the same code, recorded as they came: run 2 PASS, `caead_open_reject_samekey` **2.95** (p50 **−**2.95, the opposite
sign; raw 0.35); run 3 PASS, **0.91** (raw 0.91). The shape of run 1 (raw ≈ 0, crop-dependent size, sign not
reproduced) is the one ADR-038's context describes for quantised timers; on this 24 MHz counter a single call is
~190 quanta and the p50 crop cuts through a mass point. Nothing was changed to make the gate pass (thresholds,
sample counts, control, verdict tiers untouched). Evidence: `M02-evidence/ct-report-aarch64-apple-darwin-19f5700-
run1-FAIL.json`, `…-run2.json`, `…-run3.json` and the three gate logs. **Question:** does the reviewer accept run 1
as instrument noise (the ADR-038 verdict has no re-measurement above 10), or should the target be isolated further
(e.g. a same-key/same-position A/A control on this host)? The M2 decoder work below does not touch `Caead` or any
measured code and continued.

Decisions of WEISUNG M2-1 (2026-09-29), applied:

- Q-1 (F8 margin): **10 %** — `k = ceil(110 · quantum / median)`, realised count recorded, < 80 quanta →
  NOT_MEASURABLE; ADR-038 amended with the reviewer's line; implemented in `19f5700` (constants
  `CT_BATCH_MARGIN = 1.1`, `CT_MIN_REALISED_QUANTA = 80` in `expect.rs`, echoed in the report and checked by the
  gate). Reading to confirm: "median" in these rules is the smaller of the two class medians (resolution must hold
  for each class). For all targets but the control this equals the pooled median up to noise; for the
  variable-time control the pooled median of its 50/50 bimodal distribution fell into either mode from run to run
  (realised 19 quanta on `9835bb3`, which would now be NOT_MEASURABLE), while the smaller class median is stable
  (realised 115–120 quanta in the three runs). Realised counts in runs 1–3: every target ≥ 109 quanta.
- Q-2 (`"spec"` string): the reference file will be regenerated with `"spec": "SecMP/1 rev 2.3"`; the Rust
  generator writes `"SecMP/1 rev 2.3"`; the reference file is committed unchanged when the reviewer places it.
- `proptest`: not used; property tests on `rand`-based generators (plan step 9).
- `285cb17` accepted with the condition that `VECTOR_REF_PENDING` is empty at the DoD (§3 acceptance table).
- Repository security settings: done, `M02-evidence/repo-settings-2026-09-29.txt` — secret scanning and push
  protection **enabled**; CodeQL default setup for Rust **rejected by the API** (HTTP 422: "`rust` is not a possible
  value", accepted languages: actions, c-cpp, csharp, go, java-kotlin, javascript-typescript, python, ruby, swift),
  left as it is; private vulnerability reporting and vulnerability alerts still enabled. Observed but not changed
  (not in the instruction): `secret_scanning_non_provider_patterns` and `secret_scanning_validity_checks` are
  `disabled`.

Open questions:

- Q-3: ADR-040 (Proposed) — `serde_json` is in use as a dev-dependency of `secmp-proto` for the reference-file test
  (same crate/version/use as `secmp-crypto`'s, ADR-037); `rand` follows in step 9 per WEISUNG M2-1. Acceptance
  requested.
- No App. D reading was unsettled in steps 1–8: every rule implemented is in rev 2.3, ADR-039, the SQ answers or
  the SCHEMA-4.8 contract, and no row of the reference file disagreed with the decoders.

Other notes:

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
