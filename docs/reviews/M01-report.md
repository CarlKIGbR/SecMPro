# Milestone report — M01 `secmp-crypto`: typed primitives and constructions

Branch: `m01-crypto` · Commit range: `cd5eeb4..` (M0 merge base; M1 work from `2aa5b1d`) · Author: Claude Code (Opus 5.5) · Date: 2026-09-28

Status: **implementation complete; all acceptance criteria evidenced locally (macOS arm64) and on CI (Linux,
Windows) as listed in §3–§4; open items in §8 (reviewer/owner decisions, no blocker).** Inputs: `docs/07` M1,
spec rev 2.2, `vectors/SCHEMA.md` rev 2, ADR-035/036, the reviewer's M1 brief (decisions on B-1, Q-1…Q-4) and
`docs/reviews/ref-spec-questions-M1.md` (SQ-01…SQ-11 and the confirmed SCHEMA §4 readings, which bind the Rust
side as well).

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
| 9 | dudect-style constant-time tests; `ci-full` step `ct` | "constant-time test … shows no leak" | done `68897d0` |
| 10 | Fuzz targets (7) with corpora | "fuzz targets for key/ciphertext/signature parsers" | done `68897d0` |
| 11 | `cargo mutants` on `secmp-crypto`/`secmp-proto` | "mutation survivors zero or documented" | done (`006942f`, §3) |
| 12 | F1: fixture-based negative tests for every policy check | M0 review F1 | done `5018b02` |
| 13 | `cargo xtask vectors`: generator, structural comparison with `vectors/ref/`, freeze | "Rust and `ref/` vectors identical" | done `68897d0` (reference files committed verbatim in `63965fe`) |
| 14 | `ci-full --strict` on Linux, `windows-native`, `xwin-cross`, `win-test --backend github`, report, CHANGELOG, PR | `06` §8 DoD | see §4 |

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
| **All KATs pass on Linux and ⚙ in the Windows VM** (Windows = GitHub `windows-latest` until M8, ADR-029/A1; VM from M9) | `cargo xtask step kat` → `cargo nextest run -p secmp-crypto --features kat` + portable-backend re-run; CI `linux-fast` and `windows-native` | macOS arm64: pass. Linux (CI run 36481098423, job linux-fast): `kat PASS 511s`. Windows (same run, job windows-native, 19 min): pass. Per test file: X25519 518/518 (31 all-zero outputs rejected) + RFC 7748 1 000 iterations; Ed25519 strict 151/151; XChaCha20-Poly1305 315/315; ChaCha20 stream 256 (of 325); HKDF 86/86 + RFC 5869 A.1/A.3; HMAC 174/174 + RFC 4231; ML-KEM-768/1024 Wycheproof 201/202 decaps-from-seed, 265/269 encaps, 100/100 keygen, 9/9 expanded decaps; ACVP 25 keyGen + 55 encapDecap per set; ML-DSA-65 sign_seed 88 checked (+17 internal-interface cases not applicable to pure ML-DSA), verify 210/210, ACVP keyGen 25, sigVer 15. Every test asserts its exact counts |
| **Differential tests pass 10 000 iterations** | `cargo nextest run -p secmp-testkit --features kat --test differential` (default `SECMP_DIFF_ITERATIONS` = 10 000; master seed random per run, printed in any failure) | local: 4/4 pass (ML-KEM-768 151 s, ML-KEM-1024 207 s, ML-DSA-65 297 s, Ed25519 7 s); CI Linux and Windows within the `kat` step |
| **Constant-time test (dudect-style) for tag comparison shows no leak** | `cargo xtask step ct` (release, 10⁶ samples, Welch t on raw + 5 percentile crops) | macOS arm64: control (early-exit compare) max \|t\| = 29 568 (detected, as required); `tag_compare` 0.69; `msg_open_reject` 1.45; `caead_open_reject` (wrong key vs tampered ciphertext) 0.78; `sas` (2·10⁴ samples) 1.48 — all < 4.5. Report: `docs/reviews/M01-evidence/ct-report-aarch64-apple-darwin.json`; Linux: §4 |
| **Mutation survivors zero or documented** | `cargo xtask step mutants` (`cargo mutants --features secmp-crypto/kat -p secmp-crypto -p secmp-proto`) | first full run: 241 mutants in 13 min — 149 caught, 86 unviable, 6 missed; 5 fixed in `006942f`, 1 documented (`SecretBytes` zeroise-on-drop, `docs/mutants-accepted.md`). **Re-run after the fixes: 234 mutants in 10 min — 147 caught, 86 unviable, 1 missed (documented); gate PASS** |
| **Coverage ≥ 90 %** | `cargo xtask step coverage` | `secmp-crypto` 1657/1660 lines = **99.8 %**; `secmp-sys-mem` 95.6 % (macOS; Linux/Windows paths are measured on their CI hosts); `secmp-testkit` 100 % |
| **Rust and `ref/` vectors identical** | `cargo xtask vectors`; `cargo xtask step ref-vectors`; `tests/vectors.rs` in the `kat` step | all 8 suites (118 cases, 40 of them negative) structurally identical on the **first** comparison; frozen as `vectors/<suite>.json`; step 12a PASS; re-generated identically on every target |
| Deliverable: types | unit tests in every module (`cargo nextest run -p secmp-crypto --lib`: 61 unit tests) | pass |
| Deliverable: `SecretPage` + Miri on the crate | `secmp-sys-mem` unit tests (8, incl. kernel-level guard-page probes via `write(2)`/`VirtualQuery` and `VmFlags` in `/proc/self/smaps` on Linux); `cargo xtask step miri` | native: pass on macOS, Linux, Windows (CI); Miri: 7 tests pass (OS-probe test not compiled under Miri) |
| Deliverable: KAT loaders | `secmp-testkit` unit tests (6) | pass |
| Deliverable: `ref/` implementations, cross-check | separate session (ADR-026); `cargo xtask vectors` | see row "vectors identical" |
| Deliverable: fuzz targets, mutation run | `cargo xtask step fuzz`, `mutants` | 7 targets, local smoke 20 s each without findings (e.g. `caead_open` 1.47 M runs, `msg_open` 1.50 M); ci-full runs 120 s each |

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
| `ci-full --strict` (Linux, CI) | PENDING — run for the final commit, filled in below |
| `windows-native` (CI) | pass on `68897d0` (run 36481098423, 19 min, incl. KATs and differential); final commit: PENDING |
| `xwin-cross` (hard since C1) | pass on every M1 push (e.g. run 36481098423, 2 min) |
| KATs / differential | §3 |
| Constant time (`ct`) | macOS: pass (§3); Linux: PENDING |
| Fuzz smoke | local 20 s × 7, no findings; ci-full 120 s × 7: PENDING |
| Mutation | macOS: PASS — 234 mutants, 147 caught, 86 unviable, 1 documented survivor (§3); Linux: in ci-full |
| Coverage | 99.8 % `secmp-crypto` |
| Miri | `secmp-sys-mem`, `secmp-sys-desktop`, `secmp-crypto` interpreted as `aarch64-unknown-linux-gnu` with libcrux's portable backend; ML-DSA modules skipped under Miri only (§5, §8): PENDING |
| Kani / ProVerif | no harnesses/models in M1 (M2/M3); ProVerif self-test runs |
| `cargo deny` / `vet` / `audit` / cooldown | pass: normal closure 52 crates, 0 exempted; 25 tracked exemptions outside; audit ignores RUSTSEC-2026-0173 (ADR-037); 119 packages ≥ 7 days (both lockfiles) |
| Reproducible build | not applicable before M11 |

## 5. Deviations from spec / plan

Spec: **none.** Every construction follows rev 2.2 as written; the vectors agree with the independent reference.

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
| `shake` | 0.1.0 | dev `secmp-crypto`, `secmp-testkit` | 037 | trust `github:RustCrypto/XOFs` |
| `serde_json` | 1.0.151 | `secmp-testkit`; dev `secmp-crypto` | 031, 037 | trust `dtolnay` |
| `libfuzzer-sys` 0.4.13 (+ `arbitrary` 1.4.2) | — | `fuzz/` only | 037 | outside the workspace graph; cooldown checked |

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
- **dudect on shared CI runners** is noisy; the thresholds are dudect's (4.5) and the control proves sensitivity. The SAS test uses 2·10⁴ samples (each derivation is ≈ 1–2 ms).
- **Miri does not cover the ML-DSA and SAS code paths in the gate** (runtime); natively everything runs on three targets.
- **ci-full duration:** differential (≈ 5 min), portable KAT re-run, mutants (13 min locally), fuzz (14 min), Miri; `linux-full` has a 240-minute timeout. M0 review F2 (revisit after M2) stands.
- **RUSTSEC-2026-0173** (`proc-macro-error2` unmaintained, `cfg(hax)` only) is ignored with ADR-037; re-triage at every release.

## 8. Blocked / questions for the reviewer or owner

No blocker. Decisions requested:

- **Q-M1 (reviewer) — Miri scope.** ML-DSA under Miri takes ≈ 25 min per test (several hours for `mldsa::` and `hybrid_sign::`), a SAS test ≈ 10 min (5 200 SHA-256 iterations per half). The gate skips these three modules under Miri only (`expect::MIRI_SKIP`); everything else of `secmp-crypto` (ML-KEM via libcrux's portable backend, X25519, Ed25519, AEADs, HKDF, SHA-256/SHA3) and `secmp-sys-mem` runs. Accept, or run the full set in a nightly-only job?
- **Q-M2 (reviewer) — libcrux SIMD.** Keep libcrux's default (NEON/AVX2 compiled in, run-time selected; KATs for both host and portable backend), or force the portable backend in all builds?
- **Owner approvals pending** (recorded in the files): the two delta audits (`rand_core`, `rand`) need the owner's name in the note; crate-scoped trust for `typenum` (`paholg`) and `hax-lib*` (`maximebuyse`); ADR-037 (status *Proposed*), including the RUSTSEC-2026-0173 ignore.
- **Findings for the reviewer's attention:** (1) `ed25519-dalek` 3.0.0 accepts non-canonical `A` — covered by the byte-level check; (2) libcrux's build scripts override Cargo features (ADR-023/037 corrected); (3) the standalone fuzz build showed `secmp-crypto` had relied on feature unification for `zeroize/alloc` (fixed).
- **Owner (open):** OQ-18 (repository visibility), due before the M1 merge at the latest M2.

## 9. Checklist before requesting review

- [x] All acceptance criteria evidenced above (Linux/Windows rows of the final commit: §4)
- [ ] `cargo xtask ci` green on a clean checkout (final CI run: §4)
- [x] No `#[ignore]`, no lint allowances added for security lints, no disabled gates (Miri skip list documented, §5/§8)
- [x] Vectors frozen and reviewed (if changed) — frozen in M1; review by the reviewer
- [x] Docs/CHANGELOG updated
- [x] Threat model and spec untouched
