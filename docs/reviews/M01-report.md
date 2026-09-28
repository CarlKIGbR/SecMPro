# Milestone report — M01 `secmp-crypto`: typed primitives and constructions

Branch: `m01-crypto` · Commit range: `cd5eeb4..` (in progress) · Author: Claude Code (Opus 5.5) · Date: 2026-09-28 (plan)

Status: **plan written, implementation not started — blocked on B-1 (supply chain) before any dependency lands.**
The first commit on the branch is condition C1 of the M0 review (`2aa5b1d`: `xwin-cross` without
`continue-on-error`, NASM installed; M0 review §G closure line).

## 1. Plan (written before implementation, updated during)

Scope: `docs/07` M1; spec `docs/03` §3.2–3.5, §6.2, §6.7, Appendices A–C; `docs/06` §2–§5; `vectors/SCHEMA.md`;
carried over: C1 (done), F1 (policy fixture tests). `ref/`, `vectors/ref/` and the sibling `SecMProRef/` are
never written by this session; `ref/` vectors are only read.

| Step | What | Proves acceptance criterion | Status |
|---|---|---|---|
| 0 | C1: `xwin-cross` hard gate + NASM; M0 review §G closure line | M0 condition C1 (hard job in this report's gates table) | done `2aa5b1d` |
| 1 | **Decisions B-1, Q-1…Q-4 (§8)**; then ADR-023 update with the exact versions (§1.1) and ADR-035 for the M1 dependency set (why / alternatives / maintenance / audit status per crate), `cargo vet` records as decided, `cargo deny` green | "no new dependency without ADR + vet entry" (`06` §8.5); zero exemptions in the `secmp-crypto` closure (`06` §3) | blocked |
| 2 | `secmp-sys-mem::SecretPage`: fixed-size secret in a locked page between two guard pages. Linux: `memfd_secret`, fallback `mmap` + `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK`; Windows: `VirtualAlloc` + `VirtualLock` (working-set adjustment) + `PAGE_NOACCESS` guards; macOS (dev host): `mmap` + `mlock` + guards. Zeroised before unmap. Under `cfg(miri)` a heap backend so Miri checks the safe wrapper (Miri cannot execute the OS calls; those paths run natively on all three targets). Every `unsafe` block: `// SAFETY:`, one operation, a unit test | deliverable "SecretPage … Miri on the crate" (CS-2.2) | open |
| 3 | `secmp-crypto` foundation: `SecretBytes<N>` (`ZeroizeOnDrop`, no `Clone`/`Debug`/`PartialEq`, `expose_secret()`, `subtle` comparison); `LockedSecret<N>` on `SecretPage` for long-lived secrets (identity seeds, prekey seeds); `Nonce24`, `Counter64` (consumed by value, `checked_add`); one opaque `Error` (all authentication/decoding failures identical); `Label` = exactly Appendix A (the `<CMD_NAME>`/`<table>` forms as closed enums); HKDF helpers that only accept a `Label` as the start of `info` | deliverable "types …, HKDF helpers with the label enum, `SecretBytes<N>`, `Nonce24`/`Counter64`"; review focus "no `Clone` on secrets" | open |
| 4 | Typed primitives (no primitive implemented locally): `X25519{Secret,Public}` (all-zero output rejected), `Ed25519` (`verify_strict`), `MlKem{768,1024}{Dk,Ek,Ct}` via `libcrux-ml-kem` (Dk stored as the 64-byte seed `d‖z`, expanded per use; Ek validated on import), `MlDsa65` via `ml-dsa` (seed ξ, hedged signing with `rnd` from the OS RNG, `ctx`), SHA-256, SHA3-256, HMAC-SHA-256, ChaCha20 (RFC 8439, counter 0), XChaCha20-Poly1305 | review focus "all-zero DH rejection; `verify_strict`; dk as seed" | open |
| 5 | Constructions, each step commented with its spec section: `HybridKem{768,1024}` (§3.2, combiner input order byte-for-byte, label `V`), `HybridSign` (§3.5), `MsgEncrypt` (§3.3, tag compared in constant time before decryption), `Caead` (§3.4, `COM` compared in constant time before opening), `Fingerprint` (§6.2, over the 2017-byte encoded `IKSPublic`; the encoder itself is M2), `Sas` (§6.7). Randomised public APIs are thin wrappers over derandomised internal functions; the derandomised entry points are compiled only with feature `kat` (vector generation, KATs) | review focus "combiner label/variant and input order byte-for-byte" | open |
| 6 | Unit tests incl. every failure path (wrong key/nonce/AD/COM/tag, truncation, bit flips at every position class, all-zero DH, invalid ek, malformed signature parts); seeded property loops over lengths and inputs (no `proptest` in M1 — see §6) | coverage ≥ 90 % (`secmp-crypto`) | open |
| 7 | External KATs under feature `kat`, vendored as data with provenance (`vectors/external/SOURCES.md`: URL, commit, SHA-256, licence): Wycheproof `C2SP/wycheproof@3fa63dd0344a` (x25519, ed25519, xchacha20_poly1305, hkdf_sha256, hmac_sha256, mlkem_{768,1024}{,_encaps,_keygen_seed,_semi_expanded_decaps}, mldsa_65_{sign_seed,sign_noseed,verify}); NIST `usnistgov/ACVP-Server@975de31eb83d` ML-KEM keyGen/encapDecap and ML-DSA keyGen/sigGen/sigVer, filtered to ML-KEM-768/1024 and ML-DSA-65; RFC 7748, 8032, 8439, 5869, 4231 and the XChaCha20-Poly1305 draft vectors inline. Loaders in `secmp-testkit` (`02` §3) | "All KATs pass on Linux and ⚙ in the Windows VM" (Windows: `windows-latest` until M8 per ADR-029/Amendment A1 — the VM gate applies from M9) and on the `aarch64-apple-darwin` dev host | open |
| 8 | Differential tests (feature `kat`, 10 000 iterations each, failing seed in the assertion message): ML-KEM-768/1024 libcrux vs `ml-kem` vs `aws-lc-rs` (keygen from the same seed → identical ek/dk; deterministic encaps libcrux vs `ml-kem`; `aws-lc-rs` random encaps → both decapsulate to the same secret, and the reverse); ML-DSA-65 `ml-dsa` vs `aws-lc-rs` (same seed → same pk; cross-verify both directions); Ed25519 dalek vs `aws-lc-rs` (same seed → same pk and identical signatures; cross-verify) | "differential tests pass 10 000 iterations" | open |
| 9 | Constant-time tests, dudect-style (fixed-vs-random classes, interleaved at random, Welch's t-test; |t| < 4.5 over ≥ 10^6 measurements), release build, for the tag/`COM` comparisons and the SAS derivation (`06` §2). Own small harness in test code (no new dependency); new `ci-full` step `ct` | "constant-time test (dudect-style) for tag comparison shows no leak" | open |
| 10 | Fuzz targets (cargo-fuzz package in `fuzz/`, outside the workspace): parsers of X25519/Ed25519/ML-DSA public keys, ML-KEM ek/ct (768/1024), `HybridSignature`, `HybridVerifyingKey`, and `MsgEncrypt::open`/`Caead::open` on arbitrary input; `expect::FUZZ_TARGETS` updated; 2 min each in `ci-full` | "fuzz targets for key/ciphertext/signature parsers" | open |
| 11 | `cargo mutants -p secmp-crypto` (and `secmp-proto`, still empty): zero survivors or each documented in `docs/mutants-accepted.md` | "mutation survivors zero or documented" | open |
| 12 | F1: fixture-based negative tests for every policy check (workflow with `pull_request_target`, unpinned action, `continue-on-error`, crate with `build.rs`, unsanctioned `#[allow]`, missing SPDX, untracked or closure exemption, `unsafe_code` rules) | M0 review F1 | open |
| 13 | `cargo xtask vectors`: Rust generator (feature `kat`) writes `target/vectors/rust/<suite>.json` per `vectors/SCHEMA.md`; canonical JSON (sorted keys, no whitespace, lowercase hex) compared with `vectors/ref/<suite>.json` excluding `generator`; on a full match the agreed files are frozen (Q-3); afterwards the `kat` step re-verifies every frozen case on every target and `ci-full` step 12a compares frozen vs `vectors/ref/`. A mismatch is reported with suite, case id and both values — never adjusted on the Rust side. **Last acceptance step**; if `vectors/ref/` is absent when everything else is done: report "M1 complete except cross-check" and stop | "Rust and `ref/` vectors identical" | open |
| 14 | `ci-full --strict` green on Linux; `windows-native` (clippy, nextest, doctest, **kat incl. differential**, hello) and `xwin-cross` (hard) green; `cargo xtask win-test --backend github`; report, CHANGELOG, PR | `06` §8 Definition of Done | open |

Order: 1 → 2 → 3 → 4 → 5/6 (per construction) → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14. `cargo xtask ci-fast` after
every logical unit; `ci-full` before the report.

### 1.1 Crate versions, live-checked 2026-09-28 (crates.io API; reference time = crates.io `Date` header 2026-09-28 19:01 UTC)

Proposed exact pins for ADR-023 (and ADR-035). "Age" = days since publication (cooldown ≥ 7 d). All are the newest
stable release of their crate except `sha3` (see note). RustSec (advisory-db `ef036051`, 2026-09-28): every pin is
at or above the patched version of every advisory for its crate (RUSTSEC-2025-0144 ml-dsa ≥ 0.1.0-rc.3;
RUSTSEC-2024-0344 curve25519-dalek ≥ 4.1.3; RUSTSEC-2022-0093 ed25519-dalek ≥ 2; RUSTSEC-2026-0044…0048
aws-lc-sys ≥ 0.39.0). `cargo deny check` with the repository `deny.toml` on the resolved graph: advisories,
bans, licenses, sources ok (with `sha3 =0.11.0`).

| Crate | Pin | Published | Age | Role | Imported vet coverage (five sets) |
|---|---|---|---|---|---|
| `libcrux-ml-kem` | `=0.0.10` | 2026-07-15 | 75 d | ML-KEM-768/1024 primary (ADR-023); `generate_key_pair([u8;64])`, `encapsulate(pk, [u8;32])`, `validate_public_key` | none |
| `ml-dsa` | `=0.1.1` | 2026-06-05 | 115 d | ML-DSA-65 (ADR-023); `from_seed(ξ)`, hedged `sign_randomized(M, ctx, rng)`, `verify_with_context` | none |
| `x25519-dalek` | `=3.0.0` | 2026-07-06 | 84 d | X25519 (`static_secrets`, `zeroize`); `was_contributory` | none |
| `ed25519-dalek` | `=3.0.0` | 2026-07-06 | 84 d | Ed25519, `verify_strict` | none |
| `curve25519-dalek` | `=5.0.0` (transitive; not a direct dependency) | 2026-07-06 | 84 d | via the two dalek crates | none (Google/Zcash have only 4.1.x deltas without an audited base) |
| `chacha20` | `=0.10.2` | 2026-08-27 | 32 d | ChaCha20 (IETF) for `MsgEncrypt` | delta from 0.10.0 (ISRG) |
| `chacha20poly1305` | `=0.11.0` | 2026-06-28 | 92 d | XChaCha20-Poly1305 | none |
| `hmac` | `=0.13.0` | 2026-03-29 | 182 d | HMAC-SHA-256 | delta from 0.12.1 (ISRG) |
| `hkdf` | `=0.13.0` | 2026-03-30 | 182 d | HKDF-SHA-256 (`new`, `from_prk`, `expand`) | none |
| `sha2` | `=0.11.0` | 2026-03-25 | 187 d | SHA-256 | delta from 0.10.9 |
| `sha3` | `=0.11.0` (not 0.12.0) | 2026-04-02 | 179 d | SHA3-256 in the combiner | delta from 0.10.8. **0.12.0 is newer, but `ml-kem 0.3.2` depends on 0.11 and `deny.toml` bans duplicate versions** |
| `subtle` | `=2.6.1` | 2024-06-24 | 826 d | constant-time comparison | audited (ISRG) |
| `zeroize` | `=1.9.0` | 2026-06-12 | 108 d | zeroisation | delta from 1.8.2 |
| `getrandom` | `=0.4.3` | 2026-06-17 | 103 d | OS CSPRNG (`fill`, `SysRng`) | none at 0.4 |
| `rand_core` | `=0.10.1` | 2026-04-13 | 168 d | RNG traits for the dalek/ml-dsa APIs | delta from 0.10.0 (ISRG) |
| `ml-kem` (dev, `kat`) | `=0.3.2` | 2026-05-10 | 140 d | differential partner | none |
| `aws-lc-rs` (dev, `kat`) | `=1.18.1` (`aws-lc-sys` 0.45.0) | 2026-09-01 | 26 d | differential partner (`kem`, `unstable` ML-DSA, Ed25519) | none |
| `libc` (`secmp-sys-mem`) | `=0.2.189` | 2026-07-21 | 68 d | `mmap`/`mlock`/`madvise`/`memfd_secret` | publisher `rust-lang-owner` trusted by ISRG, Mozilla, Bytecode Alliance |
| `windows-sys` (`secmp-sys-mem`) | `=0.61.2` | 2025-10-06 | 356 d | `VirtualAlloc`/`VirtualLock`/`VirtualProtect` | trusted-publisher entries in the imports |
| `libfuzzer-sys` (fuzz package only) | `=0.4.13` | 2026-06-04 | 116 d | cargo-fuzz harness (outside the `secmp-crypto` closure) | to be checked with the fuzz package |

Not added in M1: `argon2` 0.6.0 (local password KDF, M7), `proptest` (unaudited; M1 uses seeded loops),
`dudect-bencher` (own harness instead). Full probe output: `docs/reviews/M01-evidence/vet-probe-2026-09-28.txt`.

## 2. What was built

(in progress) `2aa5b1d` — CI: `xwin-cross` hard gate with NASM (C1).

## 3. Evidence per acceptance criterion

(pending)

## 4. Gates

(pending)

## 5. Deviations from spec / plan

None so far.

## 6. Dependencies added or bumped

None yet — waiting for B-1. Planned set: §1.1.

## 7. Open risks and known limitations

- `aws-lc-sys` (C, CMake/NASM build) enters the build graph as a dev-dependency for the differential tests;
  `windows-native` builds it natively, `xwin-cross` needs NASM (C1 done).
- `memfd_secret` is unavailable on kernels where secretmem is disabled; `SecretPage` then falls back to
  `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` (CS-2.2 allows it); the chosen backend is observable in tests.
- dudect-style tests on shared CI runners are noisy; the step uses a large sample and fixed thresholds and records
  the t-values in the report.

## 8. Blocked / questions for the reviewer or owner

**B-1 (blocking; `docs/06` §3, CLAUDE.md §1.9 and §6) — the M1 crypto crates cannot be vetted under the current
rule.** Adding a direct dependency needs an imported audit or a local audit by a named human, and the
`secmp-crypto`/`secmp-proto` closure must have zero exemptions. A scratch probe (outside the repository) with the
pins of §1.1 shows:

- None of the five imported sets (nor the other four sets in the cargo-vet registry) has a `safe-to-deploy`
  audit chain for `libcrux-ml-kem`, `ml-kem`, `ml-dsa`, `x25519-dalek`, `ed25519-dalek`, `curve25519-dalek`,
  `hkdf`, `chacha20poly1305`, `aws-lc-rs` or `aws-lc-sys` — **at any version** (Google/Zcash hold only
  `curve25519-dalek` 4.1.x deltas without an audited base). Choosing older versions does not help.
- Audit backlog: 95 crates / 2 861 365 lines for the full M1 graph; 689 152 lines without the two
  differential-only crates (`aws-lc-sys` alone is 2.1 M lines).
- (a) Trusting the publishers the **current** rule already permits (trusted by ≥ 2 imported sets: dtolnay,
  BurntSushi, cuviper, rust-lang-owner, alexcrichton) leaves 81 crates / 2.58 M lines.
- (b) Additionally trusting the maintainers of the ADR-023/`02` §7 primitive crates (RustCrypto: `tarcieri` and
  the `github:RustCrypto/*` trusted-publishing identities; dalek: `rozbb`; libcrux/Cryspen: `jschneider-bensch`,
  `franziskuskiefer`; aws-lc-rs: `justsmth`; `github:rust-random/*`, `github:rust-lang/cc-rs`,
  `github:wasm-bindgen/wasm-bindgen`) leaves 26 crates / 206 477 lines, of which only **five** are compiled into
  the runtime closure: `rand_core` (delta 0.10.0 → 0.10.1), `keccak` (delta 0.2.0-rc.1 → 0.2.2), `hax-lib` and
  `hax-lib-macros` (delta 0.1.0-rc.1 → 0.3.7), `typenum` 1.20.1 (full, 41 k lines). The other 21 are
  build-script, proc-macro, test-only or other-platform crates (`clang-sys`, `fs_extra`, `crabgrind`, `uuid`,
  `futures-*`, `r-efi`, …).

An AI agent may not record audits, and I will not add exemptions in the closure. Options, for the reviewer/owner
(no decision taken):

1. **Amend `06` §3 (ADR-015 update)**: permit crate-scoped `cargo vet trust` for the maintainers of the primitive
   crates chosen by ADR-023/`02` §7 (list (b)), with `end` ≤ 12 months and notes, compensated by the mandatory
   external KATs on every target, the three-way differential tests, fuzzing, exact pins and KAT re-runs on every
   bump; plus a named-human audit of the five runtime residuals (mostly small deltas; `typenum` is the large one)
   **or** their acceptance as tracked exemptions by an explicit reviewer exception; and define whether build-only,
   proc-macro, dev-only and other-platform crates count towards the zero-exemption closure (today `xtask`'s
   `vet-closure` counts all dependency kinds and all targets).
2. Keep the rule and have the owner (or a named human reviewer) audit the backlog — about 0.69 M lines for the
   production graph alone; not realistic for M1.
3. Add further audit sources — the public cargo-vet registry has none that covers these crates.

My recommendation is option 1. The number of residuals depends on this decision, so the dependencies stay out of
the workspace until it is taken.

**Q-1 — `vectors/SCHEMA.md` input derivation is not fully specified.** Both sides must derive identical inputs or
the byte-for-byte comparison cannot succeed. Open points: (i) the encoding of `i` and `suite` in
`seed_i = SHA-256("SecMP-vectors/1" ‖ suite ‖ i)` (ASCII decimal? `u32` big-endian?) and whether `i` starts at 0
or 1 (ids start at `-0001`); (ii) how the SHAKE-256 output is split among the inputs (order = the key order of the
suite table?); (iii) lengths of the variable inputs (`ad`, `p` for `caead`, `msg`, `salt`, `ikm`, `extra_info`,
`len`) and which Appendix A label each `hybridsign`/`hkdf-labels` case uses; (iv) whether `iks` for
`fingerprint` is arbitrary 2017 bytes or a well-formed `IKSPublic` (`ver = 0x01`, derived keys); (v) the JSON
type of `label` (ASCII string or hex) and of the SAS digit strings; (vi) the suite tags for ids other than `hk768`;
(vii) the inputs of negative cases (an all-zero X25519 result needs a low-order *public* key as input, which the
positive key lists do not have). Proposal: the reviewer fixes these in `SCHEMA.md` (the `ref/` session is told to
stop on the same questions). Until then I implement the generator with the derivation as a single replaceable
function and mark the cross-check open.

**Q-2 — "wrong padding" negative case.** None of the M1 constructions checks padding (`MsgEncrypt` takes an
already padded body; `CAEAD` has none). Proposal: the padding negatives belong to the M2 `encodings` suite.

**Q-3 — frozen-vector location.** `docs/07` M1 says `vectors/crypto/*.json`; `vectors/SCHEMA.md` says
`vectors/<suite>.json`. Which one?

**Q-4 — `ci-full` step 12a.** Should CI re-run the Python generator from `ref/` (then CI installs `ref/`'s
pinned Python packages from PyPI — a new supply-chain input), or compare the frozen files with the committed
`vectors/ref/*.json` that the owner copies in? Proposal for M1: the latter; re-running `ref/` in CI once its
requirements are hash-pinned.

**Owner (open):** OQ-18 (repository visibility) is due "before M1 merge, at the latest M2".

## 9. Checklist before requesting review

- [ ] All acceptance criteria evidenced above
- [ ] `cargo xtask ci` green on a clean checkout
- [ ] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [ ] Vectors frozen and reviewed (if changed)
- [ ] Docs/CHANGELOG updated
- [ ] Threat model and spec untouched (or ADR'd)
