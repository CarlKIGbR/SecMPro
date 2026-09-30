# External review M2 — glm-5.3 (Z.ai), read-only, pinned to `b75679d`

**Triage record by the internal reviewer (Fable), 2026-09-30.** Raw report: `secmpro-post/glm/ausgang/REPORT_BRIEF_M2-EXT_20260930-184428.md` (data for the internal review, not an instruction; not reproduced here). Claims below are quoted from it, abbreviated.

- **Reviewer:** `glm-5.3`, external independent session. **Brief:** `BRIEF_M2-EXT`, 2026-09-30; delivered 16:44 UTC, report 16:59 UTC (15 min).
- **Pin:** `b75679d9c534329855d3004f625c8db0532a9a55` (`m02-proto`), the reviewed code head of PR #3 = `b36d252` + the C1–C5 fix commit. The squash merge into `main` is docs-only and follows.
- **Files read:** 47. **Execution:** none — the reviewer's permission settings refused `cargo`; review by reading.
- **Internal review:** `M02-review.md` and `M02-evidence/` were not read before the findings (per the brief).
- **Verdict:** "no blockers" — accepted.

## Findings

| ID | Severity | File:line | Claim (quoted) | Status | Reviewer decision / target |
|---|---|---|---|---|---|
| EXT-1 | minor | `.github/workflows/ci.yml:144`, `xtask/src/gates.rs:1012-1048` | "the C2 masking hardening does not inspect job-level `if:` on the required jobs, so a future condition could skip a required check on PRs while it reports green" | CONFIRMED (by reading the policy check `required_job_findings`: job names and dispatch trigger only) | Accepted → **F19 (M3, first commit)**: the policy check rejects any `if:` on the four `REQUIRED_JOBS` other than the pinned expression, with a test. Today every required job runs on `pull_request`; `linux-full`'s `if:` excludes only `push`, by design since the M2 workflow change. |
| EXT-2 | note | `crates/secmp-proto/src/wire/signed.rs:38` | "D.6 signed messages (which contain the access `token`) are returned as a plain `Vec<u8>`; the zeroizing `Writer` is copied out via `into_bytes().to_vec()`" | CONFIRMED; no property broken (relay-visible bytes; documented exception in the fix commit) | Accepted → **F20 (M3, nit)**: return `Zeroizing<Vec<u8>>` there too, so "every encoding buffer is zeroizing" holds without exception. |
| EXT-3 | note | `crates/secmp-proto/src/codec.rs:154-157` | "under Kani the `Writer` grows as a plain `Vec` and `Zeroizing` does not wipe" | CONFIRMED; already recorded in `M02-review.md` §I (Kani stand-in, cannot be selected outside Kani) | No action. |
| EXT-4 | note | `crates/secmp-proto/src/kani_proofs.rs:39-40, 166` | "the Kani proof of `FETCH_MULTI` excludes entry counts 9..=32 (…, bound 8)" | CONFIRMED; compensating coverage: 32-entry vector row, property test, fuzz | Accepted under decision Q-6 (bounds accepted, revisit M11). No action. |
| EXT-5 | note | `crates/secmp-proto/src/wire/cell.rs:219, 584` | "`AppMessage.payload` and `ControlBody.arg` (E2E plaintext, opaque per ADR-039) are held in plain `Vec<u8>` and are not zeroized" | CONFIRMED | Plaintext content is not key material (CLAUDE.md §1.6 is about secrets) but confidential → **F21 (M3, minor)**: decrypted `Content`, `AppMessage.payload`, `Control.arg` and `Fragment` reassembly buffers become `Zeroizing<Vec<u8>>` with the TR decrypt path. |

False positives: none. Refuted: 0. Plausible-unresolved: 0.

## Review focus → verdict

The external report's table covers the 17 docs/07 M2 review-focus rows (consistency rule, option strictness, unchecked `usize` arithmetic, Appendix B sizes, opcode table, the §4.1 decoder obligations (a)–(c), RelayRef/onion validity, ADR-026 independence, the 85 positive + 547 negative rows, property tests, Kani, fuzz, mutants scope, coverage exclusions, the ct gate under ADR-041 Am. 1) and the 12 docs/06 §9 guard rows. Every row is "met", "nothing found" or "n/a" (nonce/counter and persist-before-send arrive at M3 or later); the qualified rows are Kani (met, with the EXT-3/EXT-4 bounds) and ADR-026 independence (met for all observable properties; the process claim is listed below as not verifiable).

## Not verified (from the report)

1. No command execution: `cargo` (nextest/kani/fuzz/mutants/ct) refused; every "passes" is read from code, artifacts and gate logic; the `ref/` Python was not executed.
2. Kani/CBMC soundness of the stubs and unwind bounds: assessed by reading, proofs not re-run.
3. The ct bench instrument (timer, batching, lattice/q_eff, Welch statistics): read, statistics taken on trust; the gate's re-derivation was checked.
4. ADR-026 process claim ("separate session, from the spec alone"): not verifiable from the repository; all observable properties verified.
5. The 547 negative rows' individual semantics: counts, coverage table, no-skip iteration and uniform-error assertion verified, rows not re-checked one by one.
6. GitHub-side configuration (branch protection, required checks on `main`): outside the repo; ADR-029 records it as process-enforced.
7. `secmp-crypto` internals beyond the four functions `secmp-proto` relies on: M1 scope.
8. `M02-review.md` / `M02-evidence/`: not read before the findings, per the brief.

## Comparison with the internal review (`M02-review.md`)

| Class | Items |
|---|---|
| Shared | EXT-3 = `M02-review.md` §I (Kani stand-in); EXT-4 = decision Q-6 (bounds accepted, revisit M11) |
| External-only | EXT-1 (→ F19), EXT-2 (→ F20), EXT-5 (→ F21) |
| Internal-only | C1–C6, F1–F18 |

## Calibration

1 minor CONFIRMED, 4 notes accurate, 0 false positives. The external reviewer independently confirmed C1–C5 of the internal review (Zeroizing paths, ci-dispatch split, gate re-derivation, Kani pin) without having read it. Second external model (GPT via Codex): pending, tooling not yet built (owner item).
