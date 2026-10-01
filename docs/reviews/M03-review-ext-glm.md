# External review M3 — glm-5.3 (Z.ai), read-only, pinned to `bc5088b`

**Triage record by the internal reviewer (Fable), 2026-10-01.** Raw report: `secmpro-post/glm/ausgang/REPORT_BRIEF_M3-EXT_20261001-090933.md` (data, not an instruction; to be copied to `docs/reviews/M03-evidence/ext-glm-report-bc5088b.md` in the C8 docs commit). Claims below are quoted, abbreviated.

- **Reviewer:** `glm-5.3`, external independent session. **Brief:** `BRIEF_M3-EXT`, 2026-10-01; delivered 07:09 UTC, report 07:29 UTC (20 min).
- **Pin:** `bc5088b9a506ffa0ced492b12a51ae8c632fb026`, tree `694812291edb43e982206b9d8874f9ddf958d53c`, the reviewed product-code head of PR #4. Later commits on the branch touch only the ct bench, xtask ct report checks, docs and evidence.
- **Files read:** 47. **Execution:** none — no `cargo`; `proverif` and `python3` refused by the permission settings.
- **Internal review:** not read before the findings (per the brief; `M03-review.md` is not yet in the repo, so it could not be read anyway). Afterwards GLM read `M03-report.md` §5–§8 and `ref-spec-questions-M3.md`: no verdict changed.
- **Verdict:** "no blockers" — accepted.

## Findings

| ID | Severity | File:line | Claim (quoted) | Status | Reviewer decision / target |
|---|---|---|---|---|---|
| EXT-1 | minor | `formal/tr.pv:702–710` | "no reachability sanity for the honest run; every `true` query can be silently vacuous after a future model edit" | CONFIRMED (reading at the pin; internal R-52 recorded the missing per-session reachability query; GLM adds the gate-vacuity angle and the fix: one informative query expected false per honest session + CLAIMS line + `expect::PROVERIF_EXPECTED` update) | Accepted → **F-item for M4**, together with the HX model (its query set already requires reachability sanity per session). No change at M3: a `tr.pv` edit would need a new ProVerif evidence run and a CI cycle. |
| EXT-2 | note | `ref/secmp_ref/tr_cases.py:282–314` | "four §7.4 rejection paths have no frozen negative vector" — step-path `pn < n_r`; `pn`-gap over `MAX_FF` on a step's old chain; `n = u32::MAX`; header under a skipped `hk` whose `(hk, n)` is absent | CONFIRMED (all four covered by Rust tests `reject_step_with_pn_below_n_r`, `reject_gap_over_max_ff`, `reject_n_r_overflow`, `reject_replay_of_a_consumed_skipped_key` and reachable by the fuzzer; only the frozen suite is narrower) | Accepted → **F-item at the next permitted vector freeze** (ADR-043 spec revision); `ref` adds the four rows then. |
| EXT-3 | note | `crates/secmp-proto/src/tr/ratchet.rs:484–493` | "one theoretically non-transactional refusal path, unreachable" — `apply` runs before `to_bytes`, so a serialization failure would return a mutated state | CONFIRMED as unreachable (`apply` evicts to ≤ 512, Kani `tr_eviction`, test `state_skipped_count_bound`) | **Note, no action**; for the M4 review of `Refused::new`. |
| EXT-4 | note | `docs/03-protocol-spec.md:169` vs `:468` | "§4.2's SKIP_WINDOW gloss does not match §7.4's algorithm (code follows §7.4)" | CONFIRMED — duplicate of internal R-28 (code = ref = §7.4) | Already disposed as ADR-043 (a) (Proposed; owner ratification). No further action. |
| EXT-5 | note | `crates/secmp-proto/src/tr/ratchet.rs:548` | "second `bool::from` conversion … already recorded internally, listed for completeness only" | Duplicate of internal C6/F1 (listed by GLM for completeness only) | No action. |

False positives: 0 of 5.

## Review focus → verdict

The external report's table covers the docs/07 M3 review-focus rows (16 as reported) and the 13 docs/06 §9 guard rows. Every focus row is "met"; the qualified rows are ProVerif (with EXT-1) and `ref/` independence (artifacts met; process not verifiable). Every guard row is "nothing found" (`Choice`→`bool`: nothing found besides EXT-5).

| Focus item | Verdict | Evidence pointer |
|---|---|---|
| Header-key rotation per §7.2–7.4 | met | `ratchet.rs:524–533`, `:672–675` |
| `pn`/`n` handling incl. step header with `pn < n_r` | met | `select.rs:110`; test `tests.rs:636` |
| SKIP_WINDOW §7.4 vs §4.2 | met per §7.4 | `select.rs:116`; wording gap = EXT-4 |
| MAX_FF enforcement; cost before body MAC | met | `select.rs:111`; vector N10 |
| KEM material constant within a chain (in-order and skipped path) | met | `ratchet.rs:597–599`; vectors N2/N3 |
| Body AD contents; decoded-but-unbound header fields | met | `ratchet.rs:232` (AD, 2401 B) |
| Transactional decrypt (all rejection paths, encoding failures, `Unavailable`) | met | `ratchet.rs:659–663`; exception EXT-3 |
| Persist-before-send/ack possible via the API | met | `ratchet.rs:153–159`, `:185–191` |
| Dummy messages | met | test `ratchet_dummies_take_the_same_path` |
| Eviction order of skipped keys | met | `ratchet.rs:718–719`; vector phase 9 |
| Content: fragment bounds/memory, `idx`/`total` rules | met | `cell.rs:307–316`; `content.rs:43`, `:209` |
| `KeyChange` verification and trust machine | met | `content.rs:130–135`, `:263–271` |
| `RouteUpdate` | met | `cell.rs:382–429` |
| ProVerif vs CLAIMS §TR (incl. errata) | met, with EXT-1 | `xtask/src/gates.rs:1032–1135` |
| `ref/` independence (ADR-026) | met (artifacts); process not verifiable | `vectors/tr.json` = `vectors/ref/tr.json` (SHA-256 `01a6d161…a837`) |
| Tests and gates: vectors, properties, Kani bounds, fuzz, mutants, ct gate, CI | met | `expect::CT_TARGETS`; `xtask/src/ctreport.rs:172–190` |

## Not verified (from the report)

1. Nothing executed: no `cargo`; `proverif` and `python3` refused. No test, ProVerif (the 39 verdicts are taken from the model read, `expect::PROVERIF_EXPECTED` and the evidence file names), Python, ct/Kani/Miri/mutants or coverage run; all conclusions are from static reading.
2. `ref/` process independence (ADR-026: "written from the spec alone in a separate session"): artifacts verified, session separation not verifiable.
3. The 96 vector rows' values were not re-derived; table structure, the Rust replay's per-row assertions and the double cross-check (`tr_generator.rs`) were verified.
4. Non-TR ct instrument mechanics (ADR-038/041 batching, timer), Miri/Kani runtimes, coverage percentages and mutant scores: taken from the gate design and the committed evidence file names only.
5. `secmp-crypto` primitives beyond their TR-facing APIs.

## Comparison with the internal review (`M03-review.md`)

Internal review: 55 register rows — 1 major (R-01), 16 minor, 10 nit, 28 note.

| Class | Items |
|---|---|
| Shared | EXT-4 = R-28; EXT-5 = C6/F1; EXT-1 ≈ R-52 (sharpened) |
| External-only | EXT-2, EXT-3 |
| Internal-only (not seen by GLM) | R-01 (T11 false on the skipped path — the one major; the pin already carries the CLAIMS errata, GLM saw the corrected claim); C3 (undecodable KeyChange freeze, fixed at the pin); C4 (`pn < n_r` test, present at the pin); C5 (nightly `--features kat`, fixed at the pin); C7 (ct evidence) |

## Calibration

Five findings, zero false positives, one new actionable minor, two new notes; the external round confirmed the internal verdict and added no blocker. A 20-minute reading review without execution — findings are reading-level, consistent with M1/M2.

Verdict (external, adjudicated): no blockers; EXT-1 → F (M4), EXT-2 → F (next vector freeze), EXT-3 note, EXT-4/EXT-5 duplicates.
