# Milestone report — M01 `secmp-crypto`: typed primitives and constructions

Branch: `m01-crypto` · Commit range: `cd5eeb4..` (M0 merge base; M1 work from `2aa5b1d`) · Author: Claude Code (Opus 5.5) · Date: 2026-09-28 (updated 2026-09-29)

Status: **implementation complete; all acceptance criteria evidenced locally (macOS arm64) and on CI (Linux,
Windows) as listed in §3–§4 — the Linux constant-time gate is evidenced under ADR-038 by the push and PR runs of
the final commit (§4: PENDING (final run), recorded with the reviewer's GO); reviewed and approved with
conditions (`docs/reviews/M01-review.md`).** Inputs: `docs/07` M1, spec rev 2.2,
`vectors/SCHEMA.md` rev 2, ADR-035/036, the reviewer's M1 brief (decisions on B-1, Q-1…Q-4), brief M1-2 (reference
vectors, public-repository configuration, `shake` note) and `docs/reviews/ref-spec-questions-M1.md` (SQ-01…SQ-11
and the confirmed SCHEMA §4 readings, which bind the Rust side as well).

## 1. Plan (written before implementation, updated during)

Scope: `docs/07` M1; spec `docs/03` §3.2–3.5, §6.2, §6.7, Appendices A–C; `docs/06` §2–§5; `vectors/SCHEMA.md`;
carried over from the M0 review: C1 (done) and F1. `ref/`, `vectors/ref/` and the sibling `SecMProRef/` are never
written by this session.

| Step | What | Proves acceptance criterion | Status |
|---|---|---|---|
| 0 | C1: `xwin-cross` hard gate + NASM | M0 condition C1 | done `2aa5b1d` |
| 1 | B-1 resolved by ADR-036; ADR-023 versions; ADR-037 (dependency set); cargo-vet trust entries, two delta audits (diffs attached), tracked exemptions only outside the normal closure; xtask `vet-closure` on normal edges per target | "no new dependency without ADR + vet entry"; zero exemptions in the normal closure | done `ced70b0` (+ corrections `006942f`) |
| 2 | `secmp-sys-mem::SecretPage` (memfd_secret / mlock + MADV / VirtualLock, guard pages, zeroise, Miri heap backend) | "SecretPage … Miri on the crate" (CS-2.2) | done `75abeea` |
| 3 | Foundation: `Error`, `SecretBytes`, `LockedSecret`, `Nonce24`, `Counter64`, `Label` (Appendix A, prefix-free test), HKDF helpers, hashes, OS RNG | types / HKDF / label deliverables | done `a5c7ba9` |
| 4 | Primitives: X25519, ML-KEM-768/1024, Ed25519 (strict, byte-level checks), ML-DSA-65 (pure, hedged) | review focus: all-zero DH, strict verification, dk as seed | done `a5c7ba9` |
| 5 | Constructions: HybridKEM-768/1024, MsgEncrypt, CAEAD, HybridSign, Fingerprint, SafetyNumber | review focus: combiner order/label | done `a5c7ba9` |
| 6 | Unit tests with every failure path | coverage ≥ 90 % | done (99.8 %, §3) |
| 7 | External KATs (Wycheproof, ACVP, RFC) under feature `kat`, loaders in `secmp-testkit` | "All KATs pass on Linux and ⚙ Windows" | done `cf92792` |
| 8 | Differential tests, 10 000 iterations | "differential tests pass 10 000 iterations" | done `cf92792` (moved to `secmp-testkit` in `006942f`) |
| 9 | dudect-style constant-time tests; `ci-full` step `ct` | "constant-time test … shows no leak" | done `68897d0`; harness fixed after the first Linux run `ee7d30b` (§4) |
| 10 | Fuzz targets (7) with corpora | "fuzz targets for key/ciphertext/signature parsers" | done `68897d0` |
| 11 | `cargo mutants` on `secmp-crypto`/`secmp-proto` | "mutation survivors zero or documented" | done (`006942f`, §3) |
| 12 | F1: fixture-based negative tests for every policy check | M0 review F1 | done `5018b02` |
| 13 | `cargo xtask vectors`: generator, structural comparison with `vectors/ref/`, freeze | "Rust and `ref/` vectors identical" | done `68897d0` (reference files committed verbatim in `63965fe`; re-run identical after `d81d0d0`, §5) |
| 14 | `ci-full --strict` on Linux, `windows-native`, `xwin-cross`, `win-test --backend github`, report, CHANGELOG, PR | `06` §8 DoD | see §4 |
| M1-2 B | Public-repository configuration (OQ-18, owner decision delegated by the reviewer): README banner, `SECURITY.md` route, merge settings, ruleset `main-protection`, security features, Actions hardening | brief M1-2 B | done `fd94ec5` (§3, §4) |
| M1-2 C | `shake` dev-dependency replaced by `sha3::Shake256` | brief M1-2 C | done `d81d0d0` (§6) |

Crate versions were live-checked on 2026-09-28 and approved in the M1 brief; the final dependency set with its vet
coverage is in §6 (the original probe is `docs/reviews/M01-evidence/vet-probe-2026-09-28.txt`).

## 2. What was built

| Area | Files | Spec / requirement |
|---|---|---|
| `secmp-sys-mem` | `src/secret_page.rs` (+ `secret_page/{unix,windows,heap}.rs`): `SecretPage<N>` — `[guard \| data \| guard]`; Linux `memfd_secret` (+ `MADV_DONTFORK`), fallback `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK`; Windows `VirtualAlloc`/`VirtualProtect`/`VirtualLock` with one working-set enlargement on `ERROR_WORKING_SET_QUOTA`; macOS `mlock`; heap backend only under Miri; zeroised before release; fails closed. Every `unsafe` block does one operation and has a `// SAFETY:` comment; `Send`/`Sync` justified | CS-2.2, `06` §2 (a) |
| `secmp-crypto` foundation | `error.rs` (one `Error`: `Rejected` for every input-dependent failure, `Unavailable` for OS RNG/locked memory), `secret.rs` (`SecretBytes<N>` boxed + zeroised, `LockedSecret<N>` on `SecretPage`; no `Clone`/`Debug`/`PartialEq`, `ConstantTimeEq`), `nonce.rs` (`Nonce24`, `Counter64` consumed by value, `checked_add`, strict `+1` on receive), `label.rs` (49 labels of Appendix A rev 2.2), `kdf.rs` (HKDF with `Label` first), `hash.rs`, `rng.rs` | §3, App. A, CS-2.1 |
| Primitives | `x25519.rs` (RFC 7748 handling, all-zero rejected in constant time), `mlkem.rs` (ML-KEM-768/1024 via libcrux; dk = 64-byte seed `d ‖ z` in locked memory, expanded per use and zeroised; ek validated on import; implicit rejection), `ed25519.rs` (strict rule of §3.5 on the bytes: `A` canonical and not small-order on import; `R` canonical and not small-order, `S < L` before `verify_strict`), `mldsa.rs` (pure ML-DSA-65: `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M`, `Sign_internal` with 32 bytes of OS randomness; seed ξ in locked memory) | §3, §3.5 |
| Constructions | `hybrid_kem.rs` (§3.2 combiner in the listed order, `V` raw, decapsulator hashes its own `ek`/`pk_dh` and the received `pk_e`/`ct_kem`), `msg.rs` (`MsgEncrypt` §3.3: HKDF split 32/32/12, ChaCha20 from block 0, HMAC over `AD ‖ C`, tag compared with `subtle` before decryption, length checks), `caead.rs` (§3.4: `COM` compared in constant time, AEAD evaluated in both failure cases, plaintext released only if both pass), `hybrid_sign.rs` (§3.5: only the two labels, both components evaluated), `fingerprint.rs` (§6.2 over the 2017-byte encoded `IKSPublic`), `sas.rs` (§6.7, constant-time sort of the halves) | §3.2–3.5, §6.2, §6.7 |
| Derandomised APIs | feature `kat` only: `encapsulate_kat`, `sign_kat`, `Nonce24::from_bytes_kat`, `hkdf_kat`, `MsgEncrypt::derived_keys_kat`, `SafetyNumber::half_kat`, `MlKem*Dk::expanded_kat` | plan step 5 |
| KATs | `crates/secmp-crypto/tests/kat_{curve25519,symmetric,mlkem,mldsa}.rs`, vendored data `vectors/external/` with `SOURCES.md` (URL, commit, SHA-256, filter, licence); loaders `crates/secmp-testkit/src/kat.rs` | App. C, `06` §4 |
| Differential | `crates/secmp-testkit/tests/differential.rs` (feature `kat` of `secmp-testkit`) | `06` §4 |
| Constant time | `crates/secmp-crypto/benches/ct.rs`, `ci-full` step `ct` | `06` §2 |
| Fuzzing | `fuzz/` (own workspace and lockfile): `x25519_dh`, `ed25519_verify`, `mldsa65_verify`, `mlkem_parse`, `hybrid_sign_verify`, `msg_open`, `caead_open`; minimised corpora (436 files) | `06` §4 |
| Vectors | generator `crates/secmp-crypto/tests/common/vectors.rs` (+ example `gen-vectors`), re-check `tests/vectors.rs`, `xtask/src/vectors.rs` (`cargo xtask vectors`, step 12a), frozen `vectors/<suite>.json` | ADR-026, SCHEMA rev 2 |
| xtask | `vet-closure` on normal edges per target (ADR-036); `AUDIT_IGNORES`; `clippy --all-features`; cooldown over `fuzz/Cargo.lock`; gates `ct`, `ref-vectors`, `vectors`; KAT gate also with libcrux's portable backend; mutants gate with `kat` and documented survivors; Miri on `aarch64-unknown-linux-gnu`; `Cmd::env`; F1 fixture tests (`xtask/fixtures/policy/`) | `06` §3, §5, M0 F1 |
| Docs | ADR-023 (versions), ADR-037 (dependency set; corrected for libcrux SIMD), `supply-chain/README.md`, `vectors/README.md`, `fuzz/README.md`, `docs/mutants-accepted.md`, CHANGELOG, this report | `06` §8 |

## 3. Evidence per acceptance criterion

| Criterion (`07` M1) | Test / command | Result |
|---|---|---|
| **All KATs pass on Linux and ⚙ in the Windows VM** (Windows = GitHub `windows-latest` until M8, ADR-029/A1; VM from M9) | `cargo xtask step kat` → `cargo nextest run -p secmp-crypto --features kat` + portable-backend re-run; CI `linux-fast` and `windows-native` | macOS arm64: pass. Linux (CI run 36481098423, job linux-fast): `kat PASS 511s`. Windows (same run, job windows-native, 19 min): pass. Per test file: X25519 518/518 (31 all-zero outputs rejected) + RFC 7748 1 000 iterations; Ed25519 strict 151/151; XChaCha20-Poly1305 315/315; ChaCha20 stream 256 (of 325) — the keystream test derives from the Wycheproof ChaCha20-Poly1305 file and skips every case that is not `valid` or has no 96-bit nonce (`tally.skip`), which are the 69; HKDF 86/86 + RFC 5869 A.1/A.3; HMAC 174/174 + RFC 4231; ML-KEM-768/1024 Wycheproof 201/202 decaps-from-seed, 265/269 encaps, 100/100 keygen, 9/9 expanded decaps; ACVP 25 keyGen + 55 encapDecap per set; ML-DSA-65 sign_seed 88 checked (+17 internal-interface cases not applicable to pure ML-DSA), verify 210/210, ACVP keyGen 25, sigVer 15. Every test asserts its exact counts |
| **Differential tests pass 10 000 iterations** | `cargo nextest run -p secmp-testkit --features kat --test differential` (default `SECMP_DIFF_ITERATIONS` = 10 000; master seed random per run, printed in any failure) | local: 4/4 pass (ML-KEM-768 151 s, ML-KEM-1024 207 s, ML-DSA-65 297 s, Ed25519 7 s); CI Linux and Windows within the `kat` step |
| **Constant-time test (dudect-style) for tag comparison shows no leak** | `cargo xtask step ct` (release, 10⁶ samples, Welch t on raw + 5 percentile crops; ADR-038 two-tier verdict, cycle counter, batching) | **macOS arm64 under ADR-038 (`0d2c6e8`; `cntvct_el0`, tick 41.67 ns = resolution = overhead):** every target PASS on the first measurement — control 90 060 (detected, k = 3); `tag_compare` 1.20 (k = 1); `msg_open_reject` 1.49 (k = 2); `caead_open_reject` 1.18 (k = 1); `sas` 0.97 (k = 1, 2·10⁴ samples); `caead_derive` 1.40 (k = 13); `caead_aead_reject` 0.44 (k = 2); `caead_com_compare` 0.95 (k = 1); `caead_open_reject_samekey` 2.70 (k = 1). Report with per-crop t, calibration and batch medians: `docs/reviews/M01-evidence/ct-report-aarch64-apple-darwin.json`. Observation: the calibration pass of the first target (the control) ran slower than its measurement (calibration median 1 875 ns per call, batch median 666.7 ns for k = 3), so the realised batch median was 16 quanta for the control and 90 for `caead_derive` rather than ≥ 100; `k` follows the ADR's rule as written (the control is detected regardless). Earlier, with `Instant`, after the `Caead::open` fix (review C4): control 21 887; `tag_compare` 1.54; `msg_open_reject` 1.58; `caead_open_reject` 1.45 (raw 1.45; crops p50 0.44, p75 0.14, p90 0.09, p95 0.25, p99 −0.20); `sas` 1.68. Before the fix (harness of `ee7d30b`): 37 374 / 1.07 / 2.06 / **3.69** (raw; every crop ≤ 2.53) / 0.53. Linux: §4 — the first Linux run failed with the old harness, a later one on `0a788dc` with the `Caead::open` branch |
| **Mutation survivors zero or documented** | `cargo xtask step mutants` (`cargo mutants --features secmp-crypto/kat -p secmp-crypto -p secmp-proto`) | first full run: 241 mutants in 13 min — 149 caught, 86 unviable, 6 missed; 5 fixed in `006942f`, 1 documented (`SecretBytes` zeroise-on-drop, `docs/mutants-accepted.md`). **Re-run after the fixes: 234 mutants in 10 min — 147 caught, 86 unviable, 1 missed (documented); gate PASS** |
| **Coverage ≥ 90 %** | `cargo xtask step coverage` | `secmp-crypto` 1657/1660 lines = **99.8 %**; `secmp-sys-mem` 95.6 % (macOS; Linux/Windows paths are measured on their CI hosts); `secmp-testkit` 100 % |
| **Rust and `ref/` vectors identical** | `cargo xtask vectors`; `cargo xtask step ref-vectors`; `tests/vectors.rs` in the `kat` step | all 8 suites (118 cases, 40 of them negative) structurally identical on the **first** comparison; frozen as `vectors/<suite>.json`; step 12a PASS; re-generated identically on every target |
| Deliverable: types | unit tests in every module (`cargo nextest run -p secmp-crypto --lib`: 61 unit tests) | pass |
| Deliverable: `SecretPage` + Miri on the crate | `secmp-sys-mem` unit tests (8, incl. kernel-level guard-page probes via `write(2)`/`VirtualQuery` and `VmFlags` in `/proc/self/smaps` on Linux); `cargo xtask step miri` | native: pass on macOS, Linux, Windows (CI nextest); Miri: 7 tests pass (OS-probe test not compiled under Miri); `secmp-crypto` under Miri: 50 tests pass |
| Deliverable: KAT loaders | `secmp-testkit` unit tests (6) | pass |
| Deliverable: `ref/` implementations, cross-check | separate session (ADR-026); `cargo xtask vectors` | see row "vectors identical" |
| Deliverable: fuzz targets, mutation run | `cargo xtask step fuzz`, `mutants` | 7 targets, local smoke 20 s each without findings (e.g. `caead_open` 1.47 M runs, `msg_open` 1.50 M); ci-full runs 120 s each |
| Repository configuration (not an M1 criterion) | `gh` (keyring login), every command and result in `docs/reviews/M01-evidence/repo-settings-2026-09-28.txt` | done on the **reviewer's delegation of the owner's decision OQ-18** (public, 2026-09-28; brief M1-2 B): squash-only merges, delete branch on merge, wiki/projects off; ruleset `main-protection` (id 24146212) on `refs/heads/main` + `~DEFAULT_BRANCH`, active, no bypass actors: `deletion`, `non_fast_forward`, `required_linear_history`, `pull_request` (0 approvals, dismiss stale reviews, thread resolution), strict `required_status_checks` `linux-fast`, `windows-native`, `xwin-cross`, `linux-full` (verified with `gh api repos/CarlKIGbR/SecMPro/rules/branches/main`); private vulnerability reporting, Dependabot alerts and security updates on; default workflow token read-only, Actions cannot approve PRs, approval required for all external fork contributors, allowed actions = GitHub-owned only (`ci.yml` uses only SHA-pinned `actions/*`, so `patterns_allowed` is empty). No call was refused |

Review focus:

- **Combiner label/variant and input order byte-for-byte:** `hybrid_kem::combine` takes the inputs in the order of §3.2; `hybrid_kem::tests::combiner_order_and_label` recomputes `ss` with independent SHA3-256 calls and the literal `"SecMP-HybridKEM-768/1"`; the frozen `hybridkem-768/1024` vectors agree with `ref/`.
- **All-zero DH rejection:** `X25519Secret::diffie_hellman` compares the output with zero in constant time; Wycheproof: all 31 all-zero cases rejected; hybrid KEM rejects low-order `pk_dh` (encaps) and `pk_e` (decaps) (vectors rows 14–16, 19).
- **`verify_strict`:** the brief asked what `ed25519-dalek 3.0.0` rejects. Source read: it rejects `S ≥ L`, small-order `A` and `R`, and non-canonical `R` implicitly (canonical recomputation compared with the received bytes), with the cofactorless equation — but **accepts a non-canonical `A`** (`decompress` reduces y mod p; test `small_order_and_non_canonical_keys_are_refused` shows dalek decompressing large-order `y = p + t` keys). All four byte-level rules of §3.5 are therefore checked by the wrapper (`ed25519::strict`), `A` on import and `R`/`S` before verification; SCHEMA §4.5 rows 14–16 are frozen vectors.
- **dk as seed:** `MlKem*Dk` holds only `LockedSecret<64>`; the expanded key exists inside `with_key_pair` and is zeroised in place afterwards.
- **No `Clone` on secrets:** `SecretBytes`, `LockedSecret`, `SecretPage`, all secret-key types and `Nonce24`/`Counter64` have no `Clone`/`Copy`; public types have redacted `Debug`.
- **No primitive implemented locally:** only compositions of the pinned crates; the only byte arithmetic is the §3.5 encoding checks (y < p, S < L, the five small-order y values) and the §6.7 digit conversion, both demanded by the spec.
- **`ref/` independent:** this session never read `ref/` or `SecMProRef/`. Before generating the Rust files it listed `vectors/ref/` (names and sizes only); the content was first compared by `cargo xtask vectors` after the Rust files existed. No Rust value was adjusted.

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci-fast` (macOS arm64) | pass (fmt, clippy `--all-features`, policy, deny, vet, audit, cooldown, nextest, doctest, hello, kat) |
| `ci-full --strict` (Linux, CI) | run 36486510630 on `d379c6c` (job `linux-full`, 61 min): **every step PASS except `ct` FAIL** (below). `ee7d30b` (harness fix): run 36494251604 cancelled by the next push. **`0a788dc`, two runs of the same commit:** PR run 36495050724 (`pull_request`, job `linux-full` 55 m 56 s, Azure centralus): `ci-full: PASS` — every step PASS incl. `ct` (kat 519 s, ct 50 s, fuzz 879 s, coverage 99.5 %, mutants 366 s with 234/147/86/1 documented, Miri 657 s with 50 + 7 tests), `repro` STUB (M11), Windows steps DELEGATED; `docs/reviews/M01-evidence/pr2-run-36495050724.txt`. Push run 36495044976 (`push`, job `linux-full` 60 m 26 s, Azure eastus2): **every step PASS except `ct` FAIL** (`caead_open_reject` 32.17, §8 Blocked); `docs/reviews/M01-evidence/push-run-36495044976-ct-fail.txt` |
| `windows-native` (CI) | pass on `0a788dc` (PR run 36495050724, 20 m 41 s; push run 36495044976, 20 m 59 s); before: pass on `68897d0` (run 36481098423) and on `d379c6c` (run 36486510630, 18 min): clippy `--all-features`, nextest (156 tests), doctest, kat 859 s (secmp-crypto 96 tests, secmp-testkit 10 incl. 10 000-iteration differential, portable-backend re-run 21), hello; collected with `cargo xtask win-test --backend github` (`docs/reviews/M01-evidence/win-test-run-36486510630.txt`) |
| `xwin-cross` (hard since C1) | pass on every M1 push (e.g. run 36481098423, 2 min) |
| KATs / differential | §3 |
| Constant time (`ct`) | macOS: pass (§3). **Linux, run 36486510630 (`d379c6c`): FAIL** — control 60 785 (detected), `tag_compare` 1.86, `sas` 1.65, but `msg_open_reject` **24.23** and `caead_open_reject` **210.52** (`docs/reviews/M01-evidence/ct-linux-run-36486510630-per-class-buffers.txt`). Analysis: the openers' code paths do the same work in both classes (`MsgEncrypt::open`: HMAC over the whole input, `subtle` compare, reject; `Caead::open`: HKDF, `COM` compare, copy, Poly1305 check in both classes; neither decrypts); what differed per class besides the contents was *where the input lived* — the old harness measured one fixed buffer (and, for CAEAD, one key object and one ciphertext buffer) per class, so the alignment-dependent cost of `memcpy` (`ct.to_vec()` in `Caead::open`) and of unaligned loads (HMAC over the input) on `x86_64` was a class difference; `tag_compare`, whose inputs are copied by value, passed. Fix `ee7d30b`: every measured input is a fresh copy made by `prepare` in the same allocation sequence for both classes, so the classes differ only in contents; the gate now also prints the full report (per-crop t) into the CI log. This is a measurement-design fix, not a relaxed threshold (4.5 unchanged, control still required). The re-run on the fixed harness passed in PR run 36495050724 (`0a788dc`, centralus): control 61 568.50 (detected), `tag_compare` 0.76, `msg_open_reject` 1.20, `caead_open_reject` 1.69, `sas` 1.05 (max over raw and five crops). **But the push run 36495044976 of the same commit (eastus2) failed:** control 25 362.69 (detected), `tag_compare` 2.30, `msg_open_reject` 2.26, `sas` 2.88, **`caead_open_reject` 32.17** — raw −0.42, crops p50 −18.49, p75 −24.37, p90 −32.18, p95 −31.82, p99 −9.92, i.e. a consistent class difference in the bulk of the distribution, class 0 (wrong key) faster. **Root cause (review C4) — a code defect, unlike the `d379c6c` failure, which was a harness defect:** `Caead::open` ended with `if bool::from(com_ok) && tag_ok`, a short-circuit branch on whether the commitment matched; the two reject classes (wrong key: `COM` fails; right key with tampered ciphertext: `COM` matches, tag fails) took different paths through it, so a rejection revealed whether `COM` matched — what spec §6.5 trial decryption must not leak and a secret-dependent branch (`CLAUDE.md` §1). All work before it was identical in both classes. **Fix** (commit `fix(crypto): Caead::open — combine commitment and tag results without a secret-dependent branch (M1 review C4)`): `let ok = com_ok & Choice::from(u8::from(tag_ok)); if bool::from(ok) { … }` — both checks still always evaluated, one `Rejected`, zeroise on reject. No other place in `secmp-crypto` turns a `Choice` into `bool` before combining it with another check (`msg.rs`, `x25519.rs`, `fingerprint.rs` convert a single result; the `ed25519`/`hybrid_sign` checks work on public data). macOS after the fix: `caead_open_reject` 1.45 (before: 3.69 raw, crops ≤ 2.53), §3. **Residual failures after the fix** (both runs of `b24bcfa`: `caead_open_reject` 5.87 / 11.06; PR run of `59aea03`: `msg_open_reject` 55.17, `caead_open_reject` 36.34 while the four isolating targets stayed clean; push run of `a8d86a4`: `msg_open_reject` 4.76 on one crop; the other runs passed; evidence `docs/reviews/M01-evidence/runs-b24bcfa-linux-full.txt`, `runs-59aea03-ct-isolation.txt`, `runs-a8d86a4-clock.txt`): raw t ≈ 0, crop-dependent sign, runner-dependent — **diagnosed as instrument noise** (`Instant` on shared VMs plus a single-shot threshold; review C4). **ADR-038 rule (implemented in `0d2c6e8`):** each call timed with the CPU counter (`rdtscp` on x86_64, `cntvct_el0` on aarch64, `Instant` elsewhere; tick calibrated against `Instant` over 200 ms); resolution = the counter's quantum, read cost reported as overhead; a 2 000-call calibration pass per target gives the median call `m`, and one sample batches `k = ceil(100 · quantum / m)` calls on `k` same-class inputs prepared before the window (`k = 1` on a fine counter; `k > 64` → NOT_MEASURABLE, which fails the gate with that wording); per target max \|t\| over raw + 5 crops ≤ 4.5 → PASS, > 10 → FAIL, otherwise one re-measurement and INCONCLUSIVE→FAIL only if it exceeds 4.5 with the same sign at a crop where the first did; the control must exceed 4.5; the parameters live only in `xtask/src/expect.rs` and the gate refuses a report that echoes others. **macOS arm64 under ADR-038** (24 MHz counter, 41.67 ns): all nine targets PASS, `k` = 3 (control), 13 (`caead_derive`), 2 (`msg_open_reject`, `caead_aead_reject`), 1 elsewhere (§3; `docs/reviews/M01-evidence/ct-report-aarch64-apple-darwin.json`). **Linux on the final commit: PENDING (final run).** |
| Fuzz smoke | local 20 s × 7, no findings; Linux ci-full (run 36486510630): PASS, 120 s × 7, no findings (890 s; e.g. `caead_open` 2.47 M runs, `msg_open` 48.9 M, `mlkem_parse` 1.34 M, `ed25519_verify` 196 k, `x25519_dh` 137 k, `hybrid_sign_verify` 27 k) |
| Mutation | macOS: PASS — 234 mutants, 147 caught, 86 unviable, 1 documented survivor (§3); Linux (run 36486510630): PASS, identical counts, 540 s |
| Coverage | macOS 99.8 % `secmp-crypto`; Linux (run 36486510630): `secmp-crypto` 1731/1739 = 99.5 %, `secmp-sys-mem` 234/246 = 95.1 %, `secmp-testkit` 100 % |
| Miri | macOS host: PASS in 702 s — `secmp-crypto` 50 tests (11 skipped by `MIRI_SKIP`), `secmp-sys-mem` 7 tests, interpreted as `aarch64-unknown-linux-gnu` with libcrux's portable backend. An earlier run without the SAS skip also passed the first SAS tests (`docs/reviews/M01-evidence/miri-partial-with-sas-aarch64.log`). Linux (run 36486510630): PASS in 1120 s, same scope and counts |
| KAT on Linux in ci-full | run 36486510630: PASS 832 s (host and portable libcrux backends) |
| Kani / ProVerif | no harnesses/models in M1 (M2/M3); ProVerif self-test runs |
| `cargo deny` / `vet` / `audit` / cooldown | pass: normal closure 52 crates, 0 exempted; 25 tracked exemptions outside; audit ignores RUSTSEC-2026-0173 (ADR-037); 119 packages ≥ 7 days (both lockfiles) |
| Reproducible build | not applicable before M11 |
| Required checks on `main` (ruleset `main-protection`) | `linux-fast`, `windows-native`, `xwin-cross`, `linux-full`; on PR #2, `gh pr checks 2 --required` lists exactly these four (run 36495050724, `pull_request` on `0a788dc`), and `gh pr view 2` showed `mergeStateStatus: BLOCKED` while they were pending. After completion: all four green in PR run 36495050724 (`linux-fast` 8 m 38 s, `windows-native` 20 m 41 s, `xwin-cross` 2 m 22 s, `linux-full` 55 m 56 s), but the push run 36495044976 of the same commit reports its own four check runs under the same names (`linux-fast` 14 m 15 s pass, `windows-native` 20 m 59 s pass, `xwin-cross` 2 m 57 s pass, **`linux-full` 1 h 0 m 26 s fail**); `gh pr checks 2 --required` lists all eight, and `mergeStateStatus` is still **BLOCKED** on `0a788dc` |

## 5. Deviations from spec / plan

Spec: **none.** Every construction follows rev 2.2 as written; the vectors agree with the independent reference.

**Frozen vectors** (`cargo xtask vectors`: all eight suites structurally identical to `vectors/ref/` on the first
comparison, and again after `d81d0d0`; the frozen files are the reference files byte for byte, ADR-026). The
reference files were committed in `63965fe` (they had arrived in the working tree during the first M1 run, so
that commit carries the message `vectors(ref): …` rather than the one named in brief M1-2 A.2; its content is the
eight files unmodified plus the updated `ref-spec-questions-M1.md`, and the SHA-256 values equal the brief's):

| Suite | + / − | SHA-256 of `vectors/<suite>.json` (= `vectors/ref/<suite>.json`) |
|---|---|---|
| hkdf-labels | 12 / 0 | `8566b4abd2fc5794e89bb30128532dc4ede727d266a3d410d21a395421b8180b` |
| caead | 8 / 9 | `845ac0425941d20aee78b3ffcd52e55c8564c2c477c1da43219b36a1c0c8d1f3` |
| msgencrypt | 8 / 8 | `0af6181aa974a373585c288006342ac4a78dff6a1a1317386191bd12be8e356d` |
| hybridkem-768 | 12 / 7 | `a2f226ded4995ef96650ab9104363aed88265a9d343a8410158dc0b65b6cd233` |
| hybridkem-1024 | 12 / 7 | `50a47f598958088f97467af9d487e8774325b2dfe431a5015e3e3b7746542cc9` |
| hybridsign | 8 / 9 | `fca25e061cb63217ad1041235e5558a7880a874927a5392b786eda3478273ebd` |
| fingerprint | 8 / 0 | `5af8afc88c790aa21ac18974eefa5b958c8868b6bfae2492c3162e711fb3e379` |
| sas | 10 / 0 | `a36bb29b07df26d9264d445810b1ad60be9e031178f912afaa7df3075d255778` |

The confirmed SCHEMA §4 readings bind the generator and the verifier as follows: (1) every derived negative row
draws from its own `stream_i` with the referenced row's shape (`tests/common/vectors.rs`, module doc and the
per-suite generators); (3) `HybridKem*SecretKey::decapsulate` hashes its own recomputed `ek_kem`/`pk_dh` and the
received `pk_e`/`ct_kem` (`hybrid_kem.rs`); (7) `Ed25519VerifyingKey` enforces canonical and non-small-order `A`
on import and `ed25519::strict::signature_ok` checks canonical, non-small-order `R` and `S < L` before
`verify_strict` (§3 review focus). Rows 14–16 of `hybridsign` pass on both sides.

Plan / engineering (none weakens an invariant; reviewer please confirm):

1. **ML-DSA sigGen (ACVP) and Wycheproof `sign_noseed` not run:** both provide only *expanded* ML-DSA private keys; importing them needs `ml-dsa`'s `#[deprecated]` `from_expanded`, i.e. an unsanctioned `allow(deprecated)`. SecMP keys are seeds; pure hedged/deterministic signing with contexts is covered by Wycheproof `sign_seed` through the wrapper, verification by ACVP sigVer and Wycheproof verify. Expanded-key ML-KEM cases (Wycheproof semi-expanded, ACVP decapsulation) run against libcrux directly.
2. **HKDF, HMAC, (X)ChaCha20(-Poly1305) KATs at the crate level** (the wrappers expose only label-prefixed HKDF, EtM and UtC); the constructions are pinned by the frozen vectors.
3. **Differential tests live in `secmp-testkit`** (feature `kat`) instead of `secmp-crypto`, so that `secmp-crypto`'s test graph contains no C code (needed for Miri on aarch64; also removes the aws-lc-sys build from every mutant).
4. **libcrux SIMD backends** (found by Miri): `libcrux-ml-kem`/`-sha3`/`-intrinsics` build scripts compile NEON on aarch64 and the run-time-selected AVX2 backend on x86_64 regardless of Cargo features. ADR-023/ADR-037 said "portable backend only" and are corrected. Consequence taken: the `kat` gate runs the ML-KEM KATs and frozen vectors twice per target (host backend, and portable with `LIBCRUX_DISABLE_SIMD128/256=1`).
5. **Miri** interprets `aarch64-unknown-linux-gnu` with libcrux's portable backend on every host (x86 CPU detection is inline assembly; NEON intrinsics are unsupported), and skips the test modules `mldsa::`, `hybrid_sign::` and `sas::` under Miri only (≈ 25 min per ML-DSA test, ≈ 10 min per SAS test; `expect::MIRI_SKIP`, `06` §4 "where feasible"). See §8 Q-M1.
6. **`rand_core` is not a direct dependency** (no randomised third-party API is used); it stays in the closure with its delta audit. `aws-lc-rs` without the `unstable` feature (ML-DSA is stable in 1.18).
7. **Constant-time harness is a `harness = false` bench** (release profile; the workspace lints forbid printing, so it writes `target/ct-report.json`), run by the new `ci-full` step `ct` (numbered 5).
8. **Mutants gate** runs with `secmp-crypto/kat` and accepts exactly the survivors documented in `docs/mutants-accepted.md` (file + description).

## 6. Dependencies added or bumped

Direct dependencies (all `=`-pinned, ADR-023/ADR-037; vet per ADR-036):

| Crate | Version | Where | ADR | Vet record |
|---|---|---|---|---|
| `libcrux-ml-kem` | 0.0.10 | `secmp-crypto` | 023, 037 | trust `jschneider-bensch` |
| `ml-dsa` | 0.1.1 | `secmp-crypto` | 023, 037 | trust `tarcieri`, `github:RustCrypto/signatures` |
| `x25519-dalek`, `ed25519-dalek` | 3.0.0 | `secmp-crypto` | 037 | trust `rozbb` |
| `chacha20` 0.10.2, `chacha20poly1305` 0.11.0, `hmac` 0.13.0, `hkdf` 0.13.0, `sha2` 0.11.0, `sha3` 0.11.0, `zeroize` 1.9.0 (`alloc`) | — | `secmp-crypto` (`zeroize` also `secmp-sys-mem`) | 037 | trust RustCrypto accounts |
| `subtle` | 2.6.1 | `secmp-crypto` | 037 | imported audit |
| `getrandom` | 0.4.3 | `secmp-crypto` | 037 | trust `github:rust-random/getrandom` (crate-scoped) |
| `libc` | 0.2.189 | `secmp-sys-mem` (unix) | 037 | trust `rust-lang-owner` (M0 rule) |
| `windows-sys` | 0.61.2 | `secmp-sys-mem` (windows) | 037 | trust `kennykerr` (M0 rule) |
| `ml-kem` 0.3.2, `aws-lc-rs` 1.18.1 | — | dev `secmp-testkit` | 023, 037 | trust `tarcieri`/`github:RustCrypto/KEMs`; `justsmth` |
| `sha3` 0.11.0 | — | dev `secmp-testkit` (already a normal dependency of `secmp-crypto`) | 037 | trust RustCrypto accounts |
| `serde_json` | 1.0.151 | `secmp-testkit`; dev `secmp-crypto` | 031, 037 | trust `dtolnay` |
| `libfuzzer-sys` 0.4.13 (+ `arbitrary` 1.4.2) | — | `fuzz/` only | 037 | outside the workspace graph; cooldown checked |

`shake` 0.1.0 was a direct dev-dependency for the SHAKE-256 seed streams until the reviewer's note of 2026-09-28
(brief M1-2 C); the streams now use `sha3::Shake256` (same bytes: the frozen vectors re-generate identically). The
crate is no longer a direct dependency but remains in the normal closure as a dependency of `ml-dsa 0.1.1`, so its
trust record (`github:RustCrypto/XOFs`) stays; `Cargo.lock` lost only the two dev edges.

**Every trust record** (`supply-chain/audits.toml`, all `safe-to-deploy`, `end = 2027-09-28`):

| Publisher | Crates |
|---|---|
| Tony Arcieri (`tarcieri`, RustCrypto) | `aead`, `block-buffer`, `chacha20`, `chacha20poly1305`, `cipher`, `cmov`, `cpufeatures`, `crypto-common`, `ctutils`, `digest`, `ed25519`, `hkdf`, `hmac`, `hybrid-array`, `keccak`, `kem`, `ml-dsa`, `ml-kem`, `module-lattice`, `poly1305`, `sha2`, `sha3`, `signature`, `universal-hash`, `zeroize` |
| `github:RustCrypto/{traits, utils, stream-ciphers, signatures, KDFs, MACs, hashes, hybrid-array, sponges, XOFs, universal-hashes, KEMs}` | `aead`, `cipher`, `crypto-common`, `digest`, `kem`, `signature`, `universal-hash`; `block-buffer`, `cmov`, `ctutils`, `sponge-cursor`, `zeroize`; `chacha20`; `ed25519`, `ml-dsa`; `hkdf`; `hmac`; `sha2`, `sha3`; `hybrid-array`; `keccak`; `shake`; `poly1305`; `ml-kem`, `module-lattice` |
| Michael Rosenberg (`rozbb`, dalek-cryptography) | `curve25519-dalek`, `curve25519-dalek-derive`, `ed25519-dalek`, `x25519-dalek` |
| Jonas Schneider-Bensch (`jschneider-bensch`, Cryspen) | `core-models`, `libcrux-intrinsics`, `libcrux-ml-kem`, `libcrux-platform`, `libcrux-secrets`, `libcrux-sha3`, `libcrux-traits` |
| `maximebuyse` (Cryspen hax; co-owner with `franziskuskiefer` and `github:cryspen:tools`), crate-scoped | `hax-lib`, `hax-lib-macros`, `hax-lib-macros-types` |
| Justin W Smith (`justsmth`, AWS) | `aws-lc-rs`, `aws-lc-sys` (dev only) |
| `github:rust-random/getrandom`, crate-scoped | `getrandom` |
| Paho Lurie-Gregg (`paholg`), crate-scoped (**outside the named families**: no audited base exists for a delta audit; brief decision 1 allowed trust) | `typenum` |
| M0 rule (trusted by ≥ 2 imported sets): `rust-lang-owner`; `kennykerr`; `cuviper`; `Darksonn`; `dtolnay`; `BurntSushi` | `cc`, `cfg-if`, `cmake`, `glob`, `jobserver`, `libc`; `windows-sys`; `autocfg`, `either`, `find-msvc-tools`, `num-bigint`, `num-integer`; `slab`; `itoa`, `prettyplease`, `proc-macro2`, `rustversion`, `serde`, `serde_core`, `serde_derive`, `serde_json`, `syn`, `unicode-ident`, `zmij`; `aho-corasick`, `memchr`, `regex`, `regex-automata`, `regex-syntax` |

**Delta audits** (ADR-036 (3); note "delta audit by implementer; reviewer read; owner approval pending"):
`rand_core` 0.10.0 → 0.10.1 (doc-only; `docs/reviews/M01-evidence/vet-deltas/rand_core-0.10.0-0.10.1.diff`) and
`rand` 0.10.1 → 0.10.3 (two `unsafe` blocks removed, serde validation, float fixes; `…/rand-0.10.1-0.10.3.diff`).

**Tracked exemptions:** 25, all outside the normal closure (checked per target by `vet-closure`): aws-lc-sys build
tools (`cc` 1.4.7, `find-msvc-tools`, `fs_extra`, `pkg-config`), the `bindgen` chain of `crabgrind`
(`cfg(valgrind_ct_test)`), `cfg(hax)`-only crates (`uuid`, `pastey`), wasm32/UEFI-only crates (`wasm-bindgen*`,
`js-sys`, `futures-*`, `pin-project-lite`, `once_cell`, `r-efi`). Cooldown pins below the newest releases: `cc`
1.4.7, `find-msvc-tools` 0.1.13, `wasm-bindgen` 0.2.128, `js-sys` 0.3.105.

## 7. Open risks and known limitations

- **Vetting of the primitives is trust-based**, not line-by-line; compensating controls (KATs on every target incl. the portable ML-KEM backend, three-way differential tests, fuzzing, mutation gate, frozen cross-checked vectors) are all in place (ADR-036).
- **libcrux SIMD backends:** on x86_64 the AVX2 backend is chosen by CPUID at run time; CI runners have AVX2, so the Linux/Windows KATs exercise AVX2, and the portable re-run covers non-AVX2 CPUs. Disabling SIMD for shipped builds would need `LIBCRUX_DISABLE_SIMD*` in every build environment — not done; reviewer decision if wanted.
- **`SecretPage` fails closed** when locked memory is refused (`RLIMIT_MEMLOCK`, Windows quota after one enlargement). Many long-lived keys (e.g. one page per prekey) could exhaust small limits; M7/M9 decide the budgeting. `memfd_secret` mappings are shared mappings and are excluded from `fork` children with `MADV_DONTFORK`.
- **Zeroisation is best effort** for values the libraries copy on the stack (`StaticSecret::from(*bytes)`, libcrux's expanded key and shared secret are zeroised in place where the API allows).
- **dudect on shared CI runners** is noisy; the thresholds are dudect's (4.5) and the control proves sensitivity. The SAS test uses 2·10⁴ samples (each derivation is ≈ 1–2 ms). The first Linux run showed that the harness itself can create class differences (per-class buffers, §4); the fix removes that confounder, but a dudect pass remains evidence of "no detectable leak on this host", not a proof.
- **Miri does not cover the ML-DSA and SAS code paths in the gate** (runtime); natively everything runs on three targets.
- **ci-full duration:** differential (≈ 5 min), portable KAT re-run, mutants (13 min locally), fuzz (14 min), Miri; `linux-full` has a 240-minute timeout. M0 review F2 (revisit after M2) stands.
- **RUSTSEC-2026-0173** (`proc-macro-error2` unmaintained, `cfg(hax)` only) is ignored with ADR-037; re-triage at every release.
- **`shake` (brief M1-2 C):** no reason to keep the direct dev-dependency was found; it is replaced by `sha3::Shake256` (§6). The crate stays in `Cargo.lock` and the vetted closure only because `ml-dsa 0.1.1` depends on it.
- **Repository settings not covered by the brief:** the ruleset's `pull_request` rule reports `allowed_merge_methods: [merge, squash, rebase]` (API default); the repository setting allows only squash, and `required_linear_history` excludes merge commits, so squash is the only effective method. `sha_pinning_required` (repository-level "require actions to be pinned to a full-length commit SHA") is `false`; every action in `ci.yml` is SHA-pinned and `cargo xtask policy` checks it, so turning it on would add a second, server-side guard — owner's choice, not done.

## 8. Blocked / questions for the reviewer or owner

**C4 fixed in `b24bcfa`; residual failures diagnosed as instrument noise (review C4, ADR-038).** The `0a788dc`
failure (`caead_open_reject` 32.17) was a **code defect** (the short-circuit `bool::from(com_ok) && tag_ok` in
`Caead::open`), unlike the `d379c6c` failure, which was a **harness defect** (per-class buffers; that analysis
stands unchanged). The later runner-dependent failures (§4) were the instrument; ADR-038 (implemented in
`0d2c6e8`) replaces it. The final-commit `ct` values are recorded with the reviewer's GO.

Decisions requested (all answered in `docs/reviews/M01-review.md` §D/§E):

- **Q-M1 (reviewer) — Miri scope.** ML-DSA under Miri takes ≈ 25 min per test (several hours for `mldsa::` and `hybrid_sign::`), a SAS test ≈ 10 min (5 200 SHA-256 iterations per half). The gate skips these three modules under Miri only (`expect::MIRI_SKIP`); everything else of `secmp-crypto` (ML-KEM via libcrux's portable backend, X25519, Ed25519, AEADs, HKDF, SHA-256/SHA3) and `secmp-sys-mem` runs. Accept, or run the full set in a nightly-only job?
- **Q-M2 (reviewer) — libcrux SIMD.** Keep libcrux's default (NEON/AVX2 compiled in, run-time selected; KATs for both host and portable backend), or force the portable backend in all builds?
- **Owner approvals (C3) — recorded:** the owner (Christopher Carl) approved on 2026-09-29 the two delta audits (`rand_core` 0.10.0→0.10.1, `rand` 0.10.1→0.10.3), the crate-scoped trusts `typenum` → `paholg` and `hax-lib*` → `maximebuyse`, and ADR-037 including the RUSTSEC-2026-0173 ignore (review §D); the notes in `supply-chain/audits.toml` carry the name and date, ADR-037 is *Accepted*, `cargo vet --locked` passes unchanged.
- **Findings for the reviewer's attention:** (1) `ed25519-dalek` 3.0.0 accepts non-canonical `A` — covered by the byte-level check; (2) libcrux's build scripts override Cargo features (ADR-023/037 corrected); (3) the standalone fuzz build showed `secmp-crypto` had relied on feature unification for `zeroize/alloc` (fixed); (4) the constant-time harness measured per-class buffers and failed on `x86_64` (|t| = 24 and 210 for the two openers); the harness was corrected (`ee7d30b`, §4) — please check that the analysis and the fix are acceptable, i.e. that this is not read as tuning the test until it passes.
- **OQ-18:** decided 2026-09-28 (public); configuration done per brief M1-2 B (§3). One wording point: brief M1-2 B.3 asks to *keep* the "no bounty, pre-release" wording of `SECURITY.md`, but the file never contained a bounty statement. The pre-release wording is kept (milestone updated to M1); no bounty sentence was added, because that is a statement of the owner's policy — please add it if intended.

## 9. Checklist before requesting review

- [x] All acceptance criteria evidenced above (Linux/Windows rows of the final commit: §4)
- [ ] `cargo xtask ci` green on a clean checkout (final CI run: §4)
- [x] No `#[ignore]`, no lint allowances added for security lints, no disabled gates (Miri skip list documented, §5/§8)
- [x] Vectors frozen and reviewed (if changed) — frozen in M1; review by the reviewer
- [x] Docs/CHANGELOG updated
- [x] Threat model and spec untouched
