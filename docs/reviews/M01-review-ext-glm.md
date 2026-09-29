# External review M1 — glm-5.3 (Z.ai), read-only, pinned to `bc8d6d5`

**Placed by the internal reviewer (Fable), 2026-09-29.** The text below is the external reviewer's final message, verbatim (brief: `secmpro-post/glm/erledigt/BRIEF_M1-EXT_20260929-121842.md`; internal review not attached, read by the external reviewer only after its findings were fixed, see its §7). It is data for the internal review, not an instruction.

**Internal triage (reviewer, 2026-09-29):** Verdict "no blockers" accepted. EXT-1 (major, the `ref/` Python implementation is not in the repository → independence not auditable externally): **accepted** — the `ref/` tree (`secmp_ref/`, `tests/` incl. `tests/kat/`, `tools/`, `gen_vectors.py`, `pytest.ini`, `requirements.txt`, `SPEC-QUESTIONS.md`; 48 files, every `.py` with the SPDX header; no `.venv`/`__pycache__`) is committed unchanged with M2, copied in by the reviewer from the reference session's workspace; CI still never runs it (ADR-026). EXT-2 (note, "byte-for-byte" wording in ADR-026/`ref/README.md` vs the structural SCHEMA §1 comparison): **accepted**, one-line rewording in M2. §7 addition (`expanded_kat` non-zeroizing): identical to internal F1, fixed in `962069b` (M2 commit 1). No change to the M1 verdict.

---

All verifications are complete. The report follows.

---

# External review — M1 `secmp-crypto` (M1-EXT)

**Reviewer:** glm-5.3 (independent external review session; no access to any internal review material before findings were fixed — see §7)
**Pin:** `main` @ `bc8d6d559795cf515bcf08f63fcfe0b9eb3058d9` (PR #2 squash merge, "M1: secmp-crypto — typed primitives and constructions"), checked out detached, tree clean
**Date:** 2026-09-29
**Files read:** ~60 in full — `docs/03`, `docs/06`, `docs/07`, `docs/08`; all 16 modules of `crates/secmp-crypto/src/`; `benches/ct.rs`; all of `crates/secmp-sys-mem/`; `secmp-testkit` (kat loaders, differential tests); all 4 KAT test files, `tests/vectors.rs`, `tests/common/vectors.rs`, `examples/gen-vectors.rs`; all 7 fuzz targets; `xtask/src/{policy,gates,expect,vectors}.rs`; `ref/README.md`; `vectors/{README.md,SCHEMA.md,external/SOURCES.md}`; `supply-chain/{audits.toml,config.toml}`; `Cargo.toml`, `Cargo.lock` (targeted), `deny.toml`, `.gitignore`, `docs/mutants-accepted.md`, `docs/reviews/ref-spec-questions-M1.md` — plus targeted reads of the 16 vector JSON files (8 frozen + 8 ref), independent `cmp`/`grep` comparisons, SHA-256 re-hashing of all 20 vendored external vector files, and (after findings, §7) `docs/reviews/M01-review.md` + `M01-evidence/`.
**Constraint compliance:** read-only throughout — no file edited, no cargo command run, nothing pushed, no issue/PR opened.

---

## §1 Spec conformance of the constructions — **nothing found**

Verified against `docs/03-protocol-spec.md` §3, §6.2, §6.7 and Appendix A, byte-for-byte:

- **HybridKEM (§3.2):** combiner input order is exactly `ss_kem ‖ ss_dh ‖ SHA3-256(ct_kem) ‖ SHA3-256(ek_kem) ‖ pk_dh ‖ pk_e ‖ V` with the raw ASCII label and variant byte from Appendix A (`hybrid_kem.rs`); the decapsulation side recomputes its own `ek_kem`/`pk_dh` from the seed and hashes the *received* `pk_e`/`ct_kem` bytes — matching the spec's transcript-binding rule and exercised by frozen vector row hk768-0012 (modified `pk_e` recomputes the secret rather than erroring). All-zero X25519 output is rejected in constant time on **both** sides (`x25519.rs`); frozen vectors cover `u = 0`, `u = 1` and the order-8 point `e0eb7a7c…b800` (rows 14–16, constants present in the frozen JSON). Implicit rejection is deterministic and not an error (rows 10–11 positive).
- **HybridSign (§3.5):** `m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)`, `ctx = label`, `sig = sig_ed(64) ‖ sig_mldsa(3309)` (3373 const-asserted); foreign labels refused with the uniform `Rejected` on **both** sign and verify (frozen rows hsig-0012 and -0011); both components always evaluated, no short-circuit. Strict Ed25519 is enforced by first-party byte-level rules (`S < L`, canonical `A`/`R`, small-order `A`/`R`) before `verify_strict` runs, with a test demonstrating that `ed25519-dalek 3.0.0` alone accepts a non-canonical `A` — the gap the spec's first-party checks close; frozen rows hsig-0014 (`S + L`), -0015 (identity pk), -0016 (non-canonical y=1 encoding `eeff…7f`) cover exactly these rules.
- **MsgEncrypt (§3.3):** `|P| = 1710` and `|C‖TAG| = 1742` enforced with the uniform error (frozen row msgenc-0016 seals a 1709-byte body and asserts the reject); OKM split 32/32/12; ChaCha20 from block counter 0; `TAG = HMAC(K_mac, AD‖C)`; tag compared in constant time (`msg.rs:113`, one `bool::from` at the final decision).
- **CAEAD (§3.4):** commitment `HKDF-Expand(PRK = K, "SecMP-commit/1" ‖ N, 64) → K_enc ‖ COM`, output `COM ‖ C` without `N`; `open` evaluates the commitment `ct_eq` **and** the AEAD in every case, combines on `Choice`, converts once, returns one `Rejected`, zeroizes on reject (the C4 fix is present in the reviewed code); frozen negatives cover flips of `c`/`com`/`ad`/`n`/`k`, truncation and sub-tag-length ciphertext.
- **HKDF labels:** all 49 labels match Appendix A's spelling exactly (`label.rs`); the label-set test re-reads the spec via `include_str!` (ADR-035) and enforces prefix-freedom and the three rev-2.2 renames; the seed label `"SecMP-vectors/1"` used by the vector generator is itself spec-defined (App. A, "test-vector seed derivation only").
- **SAS (§6.7):** 5200 SHA-256 iterations per half, six zero-padded 5-digit groups, 60 digits, constant-time sort/swap on `Choice`; frozen row sas-0010 (swapped inputs → identical safety number) and sas-0009 (equal fingerprints) pin the symmetry rules.
- **Fingerprint (§6.2):** `SHA-256("SecMP-FP/1" ‖ iks)` with `|iks| = 2017` enforced.

## §2 docs/06 §9 guard list — **nothing found** (item-by-item verdicts in the table below)

- `SecretBytes<N>`: boxed, zeroised on drop, no `Clone`/`Debug`/`PartialEq`; `ct_eq` for comparison; `LockedSecret` over `SecretPage`. Redacted `Debug` on every key/ciphertext/fingerprint type. `Nonce24`/`Counter64` consumed by value, strict `+1` with overflow an error.
- **Choice→bool inventory (complete, every non-test conversion site):** `fingerprint.rs:52`, `sas.rs` (sort/swap arithmetic on `Choice`), `caead.rs` (open: `com_ok & Choice::from(u8::from(tag_ok))`, one `bool::from`), `msg.rs:113`, `x25519.rs:56` — each combines with `&`/`|` and converts exactly once at the final decision. No `bool::from(…) &&` pattern remains.
- **No primitive implemented locally:** the only first-party byte arithmetic is the spec-mandated §3.5 encoding checks and the §6.7 digit conversion; everything else delegates to libcrux / dalek / RustCrypto at `=`-pinned versions.
- **`unsafe`:** only in `secmp-sys-mem`/`secmp-sys-desktop` roots plus the single path-exact ADR-038 bench root, enforced by the policy gate with fail-closed tests (a near-miss path like `ct2.rs` fails).
- **No panic paths on attacker input:** deny-level `unwrap`/`expect`/`indexing_slicing`/`panic`/`arithmetic_side_effects` workspace-wide; every parser returns `Result` with the uniform error; every wire-facing parser is fuzzed with uniform-error assertions.

## §3 Independence of `ref/` — one finding (EXT-1, EXT-2)

**Findings** (see list below). The **freeze step itself is sound and independently confirmed**: `xtask/src/vectors.rs` implements the normative SCHEMA §1 comparison (both files parsed, `generator` dropped, JSON values compared, no case folding, hex-format validator); the frozen file is a verbatim copy of the ref file, an existing frozen file is never overwritten (mismatch fails), a missing ref file fails; `ci-full` step 12a re-checks frozen vs ref with `same_set` in both directions. I confirmed independently (`cmp`) that all 8 frozen `vectors/<suite>.json` are **byte-identical** to `vectors/ref/<suite>.json`, that the 118 cases match the SCHEMA §4 case tables row-for-row (including every negative row and the low-order constants), and that the negative cases are genuinely asserted as rejected *during generation* in the Rust generator. The Rust-vs-ref cross-check compares values structurally, not bytes — deliberate and normative (SCHEMA §1), since the `generator` field differs by design.

## §4 Constant-time gate (ADR-038) — **nothing found**

- **Thresholds** `(4.5, 10.0)`, `max_resolution_fraction 0.01`, `max_batch 64` are written exactly once in `expect.rs`, read by the bench at compile time, and the gate (`gates.rs::ct_table`) refuses any report whose echoed thresholds differ (bit-exact f64 comparison, unit-tested against tampered values). Fail-closed: unknown verdict strings, empty results, error reports and missing thresholds all fail.
- **Two-tier verdict + confirmation:** ≤ 4.5 → PASS; > 10 → FAIL (no confirmation possible); in between exactly one re-measurement, and FAIL requires the *same crop, both measurements above pass, same sign* (`ct.rs:587-597`). `NOT_MEASURABLE` (batch cap exceeded) **fails** the gate, as ADR-038 requires.
- **Positive control:** measured once; `detected = max |t| > pass`, else the control's verdict is FAIL and the gate fails (`ct.rs:572-581`) — a harness that measured nothing cannot pass. Confirmed on the committed artifact: control `max |t| = 90060`, all real targets ≤ 2.7, thresholds echoed exactly (`docs/reviews/M01-evidence/ct-report-aarch64-apple-darwin.json`).
- **Can a real leak slip through?** A leak with true |t| in the inconclusive band whose re-measurement lands on a different crop or flips sign would pass as INCONCLUSIVE→PASS. That residual false-negative window is the deliberate counterpart of ADR-038's protection against the crop-noise false positives that motivated it; a leak > 10 fails immediately. This is within the ADR's accepted trade-off, so not a finding. I found no secret-dependent branch or memory access outside the inventoried Choice sites (§2); batching cap, per-target `k`, `median_per_resolution` and the `cntvct_el0`/`rdtscp` timer all conform.

## §5 Supply chain — **nothing found**

- `supply-chain/audits.toml` matches ADR-037 exactly: ~60 `[[trusted.*]]` entries over the named publisher accounts (tarcieri/RustCrypto orgs, jschneider-bensch/libcrux, rozbb, justsmth/AWS, dtolnay, rust-lang-owner, BurntSushi, …, paholg/typenum crate-scoped with owner-approval note), every `end = 2027-09-28` (≤ 12 months), plus two delta audits (`rand` 0.10.1→0.10.3, `rand_core` 0.10.0→0.10.1) carrying the implementer-audit/reviewer-read/owner-approved trail with the owner's name and date.
- `supply-chain/config.toml`: 5 standard imports; exactly 25 exemptions, each with the tracked-exemption note, all build-only/dev-only/wasm32/UEFI/`cfg(hax)`/`cfg(valgrind_ct_test)` — none inside the normal closure of `secmp-crypto`/`secmp-proto` (the policy gate computes that closure per shipped target over normal edges and fails closed; unit-tested).
- `Cargo.lock`: 129 packages; all `=`-pins match ADR-023/037; cooldown pins present as recorded (cc 1.4.7, find-msvc-tools 0.1.13, wasm-bindgen 0.2.128, js-sys 0.3.105); no git dependencies; no build scripts in first-party crates (policy-checked). `deny.toml`: 3 shipped/host targets, all-features, `unsound`/`unmaintained = "all"`, `yanked = deny"`, `ignore = []` except the one ADR-recorded `RUSTSEC-2026-0173` (via `cargo audit`'s `expect::AUDIT_IGNORES`, ADR-noted, never compiled for any target).

## §6 Tests and gates — **nothing found**

- **KAT loaders:** negative cases are individually asserted (`assert_eq!(got.err(), Some(Error::Rejected))` per case — e.g. all 31 all-zero X25519 outcomes in `kat_curve25519.rs`), `numberOfTests` cross-checked against the parsed count (loader panics on mismatch), pinned `Tally` checked/skipped counts per file, skipped classes named (ML-DSA `Internal`-interface cases; ChaCha20 keystream skips = "not a valid 96-bit-nonce case"). ACVP `sigVer` asserts `testPassed` equality with the reason in the failure message.
- **Differential tests are genuinely independent:** ML-KEM is a *three-way* cross (libcrux vs RustCrypto `ml-kem` vs `aws-lc-rs`, both directions), ML-DSA-65 and Ed25519 two-way vs `aws-lc-rs`; 10 000 iterations, deterministic master seed printable for reproduction, env-overridable.
- **Fuzz:** all 7 targets feed arbitrary bytes to real parsers/openers with uniform-error assertions, single-bit-flip reject checks and re-encode round-trips; `expect::FUZZ_TARGETS` `same_set` prevents silent removal. Every wire-facing parser in the crate is covered; `Fingerprint::from_bytes`/`from_seed` are length-check constructors (unit-tested negatives), not decoders.
- **Miri:** scope (3 packages, `aarch64-unknown-linux-gnu`, portable libcrux) and the three `MIRI_SKIP` filters with measured runtime reasons are declared in `expect.rs` and documented as reviewed-per-milestone; the ct-report thresholds, mutant-survivor documentation matching (path + description) and coverage thresholds are all gate-enforced against `expect.rs`.
- **Vector provenance:** I re-hashed all 20 vendored external files — every SHA-256 matches `SOURCES.md` (16 Wycheproof, 4 filtered ACVP).

---

## Findings

**[EXT-1] major — ref/README.md:16 (and docs/07 M1 deliverable, `ref/` line 45) — the independent Python reference implementation is not in the repository; its independence is therefore not auditable from the repository alone.**
Evidence:
> `Status: empty in M0 (this README only).`
> (docs/07:45) "`ref/` (Python, ADR-026) implementations of HybridKEM, HybridSign, MsgEncrypt, CAEAD, SAS, written **in a separate session from the spec alone**"
`find` over the tree finds **no `.py` file anywhere**; only the stale README and the 8 committed `vectors/ref/*.json` outputs exist. The M1 review-focus item "ref/ really independent (no shared code, different author session)" is a claim about code that is not present, so an external reviewer can verify the *outputs* and the *freeze mechanism* (both sound, §3) but not the "no shared code / different session" property. Mitigating in-repo process evidence exists (`docs/reviews/ref-spec-questions-M1.md` documents the ref session finding genuine spec defects from the spec alone — SQ-05/06/07 — which is hard to fake and strongly suggests a real independent implementation existed; SCHEMA §6 forbids Rust-derived code by rule). Suggested fix: publish/commit the `ref/` implementation (it is test tooling, AGPL, never shipped) or archive its tree hash in the repo; until then the review-focus item should be recorded as "attested by the internal reviewer, not auditable externally". Severity is major (unverifiable acceptance/review-focus claim, docs/06 §9-style "tests that only round-trip" protection rests on it), not a blocker: no spec violation, no secret leak, and the frozen vectors' cross-check value does not retroactively depend on auditability.

**[EXT-2] note — ref/README.md:5-6 / docs/06 §5 step 12a ("byte-for-byte") vs SCHEMA §1 and `xtask/src/vectors.rs` ("structural") — doc-level inconsistency in how the agreement is described.**
Evidence:
> "`vectors` runs it and the Rust implementation over the same inputs and freezes `vectors/` only when both agree byte-for-byte (ADR-026…)"
The implemented and (normatively, SCHEMA §1) specified comparison parses both files, drops `generator` and compares values — deliberately not byte-for-byte, since the generator field must differ. The frozen artifact is a verbatim copy of the ref file (so "frozen ≡ ref" *is* byte-for-byte, and step 12a's check is literally true as implemented); only ADR-026's/README's phrase for the Rust-vs-ref agreement is stale wording. Suggested fix: one-line rewording in ADR-026/README to "agree structurally per SCHEMA §1 (generator field excluded); the frozen file is a verbatim copy of the reference file". No security impact.

---

## Review-focus verdict table

| docs/07 M1 review-focus item | Verdict | Evidence pointer |
|---|---|---|
| Combiner label/variant and input order byte-for-byte | met | `hybrid_kem.rs` vs docs/03 §3.2 + App. A; frozen `hybridkem-{768,1024}.json` (incl. row 12 modified-`pk_e`) |
| All-zero DH rejection | met | `x25519.rs` constant-time check, both sides; frozen rows 14–16 (`u=0`, `u=1`, order-8 point) |
| `verify_strict` | met | `ed25519.rs` first-party byte rules before dalek; dalek-3.0.0 gap test; frozen hsig rows 14–16 |
| dk as seed | met | `mlkem.rs` `from_seed` (64 B `d‖z` in `LockedSecret`), `with_key_pair` expand-use-zeroize; ACVP keyGen KATs |
| No `Clone` on secrets | met | `secret.rs` (`SecretBytes`: no Clone/Debug/PartialEq, zeroising, `ct_eq`), `nonce.rs` by-value types |
| No primitive implemented locally | met | only spec-mandated §3.5/§6.7 byte logic; all primitives from pinned crates |
| `ref/` really independent (no shared code, different author session) | **not verifiable from the repository** (EXT-1); freeze mechanism and frozen≡ref identity: met | §3 above; `cmp` of all 8 suites; `xtask/src/vectors.rs` |

| docs/06 §9 guard item | Verdict | Evidence pointer |
|---|---|---|
| Invented constructions | met (none) | every construction cites its spec section; no construction absent from docs/03 |
| Nonce/counter handling (reset on restart, reuse both directions) | met in M1 scope (value types, strict +1, overflow = error); restart semantics first arise in M3/M7 | `nonce.rs`, `msg.rs` |
| Missing domain separation / transcript binding | met | App. A label enum (prefix-free, include_str! test); combiner hashes ct/ek/pk; CAEAD binds N; HybridSign hashes label |
| Non-constant-time comparisons | met | all secret comparisons via `subtle`/`ct_eq` |
| `Choice`→`bool` combined correctly (once, at the final decision) | met | §2 inventory (5 sites); C4 fix present in `caead.rs` |
| Unchecked inputs (zero DH, non-canonical points, malformed KEM keys) | met | §1; mlkem import validation both sides; frozen negatives |
| Secrets in Debug/logs/errors | met | redacted Debug everywhere; crate has no logging; error type carries no secrets/ids |
| Tests only round-trip own code | met | external KATs (Wycheproof/ACVP/RFC, hashes re-verified), frozen cross-checked vectors, three-way differentials |
| Panics on malformed input | met | deny-lints; all parsers return `Result`; fuzz targets with uniform-error assertions |
| Hallucinated crates/APIs | met | Cargo.lock pins resolve; pinned APIs exercised by committed tests |
| Error oracles (uniform auth errors) | met | single `Error::Rejected` per construction; reject classes indistinguishable (fuzz-asserted) |
| Persist-before-send ordering | n/a in M1 — sans-IO crate, no persistence or send path yet (M3/M7) | — |
| Timing side channels in helpful early returns | met | §4; ct gate artifact all-PASS, control detected |

## Not verified (with reasons)

1. **No gate was executed** (`cargo vet/deny/audit/nextest/mutants/Miri/fuzz/ct`, coverage): read-only brief. All statements about them derive from reading the gate code, manifests, lockfile and committed artifacts — including the ADR-038 ct report artifact and the frozen/ref byte-identity, which I did verify directly.
2. **Imported-audit foreign coverage resolution** (whether the 5 imports actually certify the pinned versions): requires `cargo vet`'s network fetch; audits.toml/config.toml checked textually/structurally against ADR-037 instead.
3. **ACVP upstream (unfiltered) hashes and the jq filters**: not re-derivable without network; the four *filtered* files (what the tests consume) match SOURCES.md exactly.
4. **Windows VM (⚙) KAT acceptance**: owner-operated infrastructure; taken from the committed run log, not re-executed.
5. **ref/ session authorship/separation**: out-of-repo by construction — EXT-1.
6. **GitHub run ids/conclusions**: not re-checked (would need network/API access beyond this clone).

## §7 After reading the internal review (`M01-review.md`, `M01-evidence/`)

Read only after my findings above were fixed. What I would change:

- **EXT-1:** unchanged, but sharpened in scope: the internal review's §A row and preamble assert the out-of-repo facts (M1 session never read `ref/`; files copied in by the reviewer; first comparison agreed without adjustment; three cases recomputed with a third implementation) from session logs and the owner's machine — evidence channels an external reviewer does not have. My finding is precisely that this item is attestable internally but not auditable externally; both statements stand.
- **EXT-2:** unchanged; the internal review consistently uses "structurally identical (generator excluded)" for Rust-vs-ref and "byte-identical" for frozen-vs-ref, matching the implementation — the stale "byte-for-byte" wording is confined to ADR-026/README.
- **One addition I would make:** internal F1 is correct and I had under-reported it — `mlkem.rs:70-74` `expanded_kat` returns the expanded decapsulation key as a non-zeroizing `Vec<u8>` (feature `kat` only; the internal `with_key_pair` zeroizes its copy, the returned clone is not). I would add it as a **note**-severity finding with the same M2 fix (return `Zeroizing<Vec<u8>>`); no spec violation, test-tooling only.
- The committed ADR-038 ct-report artifact additionally confirms what I had verified only from the gate code (thresholds echo, control detected at |t| = 90060, all targets ≤ 2.7); no finding changes from it. The C4 history in the internal review matches the fixed code I verified independently.

**Verdict: no blockers**
