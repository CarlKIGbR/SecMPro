# External review M4 — codex gpt-6.1-sol and glm-5.3, read-only, pinned to `e8359b1`

**Triage record by the internal reviewer (Fable), 2026-10-03.** Raw reports: `docs/reviews/M04-evidence/review-ext-codex-e8359b1.md` and `docs/reviews/M04-evidence/review-ext-glm-e8359b1.md` (data, not instructions; §6). Claims below are quoted, abbreviated. Each report was adjudicated by Fable with an Opus verifier per report; the comparison base is `register.md` (93 rows) with the judge's final decisions 1–8.

- **Pin (both reviewers):** `e8359b19aa0b34b6b8b9b6e99eddbc984579819b`, tree `b01cf1417cb5d1597af52e5b75a253ff053eb144`, base `main` = `836a94e4f8abec27d877740291ecbe9957c10177`.
- **Brief (both):** `BRIEF_M4-EXT`. The text is identical except the reviewer name and the step-0 checkout note for Codex, whose sandbox cannot write `.git`.
- **Codex:** `codex gpt-6.1-sol`; run 2026-10-03 11:05–11:20 UTC (15 min); 560 470 tokens; 99 distinct files read. HEAD and tree matched the pin at the beginning and end; no source file edited. Execution: the offline Rust test attempt failed before compilation (`no matching package named chacha20 found`), so no Rust test ran; one extracted Python grouping reproduction was executed.
- **GLM:** `glm-5.3`; run 2026-10-03 13:23–13:41 UTC (18 min) after a 429 limit abort at 09:19 UTC; tokens not reported; files read ≈ 50. Execution: none (read-only; no cargo, test, fuzz, Kani, ProVerif or ct run).
- **Internal review:** not read before the findings by either reviewer. Codex was barred from the internal reports and evidence directories and made no amendment. GLM read `docs/reviews/M04-report.md` after fixing its findings (no `M04-review.md` existed) and wrote "Nothing I would retract or soften".
- **Verdict lines as reported:** Codex "Verdict: blockers: 2" (2 blockers + 4 majors). GLM "Verdict: no blockers" (2 minors + 6 notes).
- **Adjudicated:** Codex 6 findings: 5 CONFIRMED, 1 REFUTED; 0 of 2 blockers and 0 of 4 majors survive at Codex's severity. GLM 8 findings: 7 CONFIRMED, 1 REFUTED; 0 new. One new register row results (R-94, Codex EXT-6, minor).

## 1 Method

1. Both reviewers received `BRIEF_M4-EXT` at the same pin, as independent read-only sessions. The brief text is the same for both (differences above).
2. The internal review (directorate L1–L7, V1–V7, DIAG-ci, A1–A3, F1, judge) was withheld from both reviewers until after their findings.
3. Adjudication: every finding was classified CONFIRMED, REFUTED or PLAUSIBLE at the pin. Every cited location was opened at `e8359b1`. Nothing was executed except `sha256sum` on the two HX vector files (both `a33cf162…f436e7d2`, as both reviewers state). A mechanism that was read but not reproduced stays PLAUSIBLE (the libFuzzer behaviour behind R-07).
4. Our severity applies the judge's final decisions 1–8 over the register where they differ. The status of each external finding is given at the pin, not at the fix-round head `cac6eff`.
5. Limit common to both reviewers: no CI run data and no access to the evidence directory's platform analysis (Codex was barred from the evidence directory and had no CI data; GLM had no access to CI run logs or artefacts).

## 2 Codex findings (6)

| EXT | Codex sev | File:line as reported | Our status | Our sev | Mapping / disposition | Reason |
|---|---|---|---|---|---|---|
| EXT-1 | blocker | `crates/secmp-proto/src/hx/mod.rs:67` | CONFIRMED | minor | = R-22 → C-8 | `release` re-persists the `start` snapshot only if a caller advances and persists the returned state first, against the documented order (`hx/initiator.rs:189-190`); none of the 13 `release` call sites at the pin does; C-8 changes `release` to take the state |
| EXT-2 | blocker | `crates/secmp-proto/src/prekeys.rs:495` | CONFIRMED | minor | = R-25 → C-11 | fails closed; shipping `issue_invitation` draws a fresh OPK per invitation (`prekeys.rs:586,627`); the state needs a direct `add_record`; C-11 makes it unreachable |
| EXT-3 | major | `crates/secmp-proto/src/prekeys.rs:289` | CONFIRMED (fact + false doc); CS-2.2 breach PLAUSIBLE | minor | = R-37 → docs commit D-35 + docs/04:45 clause or `LockedSecret<32>`; FIX-2 (ADJ-glm §10) | `duplicate` doc says "locked memory" (`prekeys.rs:299-307`), the key is heap `SecretBytes`; no CS rule is broken as written, no swap exposure shown |
| EXT-4 | major | `crates/secmp-proto/src/hx/responder.rs:117` | REFUTED (finding); code fact CONFIRMED | note | = R-86 → no action | `init_id` is a non-secret grouping tag (`docs/03-protocol-spec.md:336,342`; CLAIMS O-16, `formal/CLAIMS.md:252-253`); no obligation violated, no adversary gains |
| EXT-5 | major | `ref/secmp_ref/hx.py:328` | CONFIRMED (coverage gap) | note | = R-66 → F-M5 next vector freeze | ref is correct for rev 2.3; ADR-044 Consequences keep `hx.json` frozen and assign (b)–(f) to Rust tests (`docs/08-decisions.md:337`); Codex does not challenge the freeze |
| EXT-6 | major | `xtask/src/gates.rs:179` | CONFIRMED | minor | NEW → R-94 → FIX-2 (not in `cac6eff`); C-4 item 4 | portable `kat` rerun names `tr_vectors` for `secmp-proto` but not `hx`, the only consumer of `vectors/hx.json`; Miri filters `hx` out (required-features) |

False positives: 1 of 6 (EXT-4). Severity: 0 of 5 surviving findings agree; EXT-4 refuted.

## 3 GLM findings (8)

| EXT | GLM sev | File:line as reported | Our status | Our sev | Mapping / disposition | Reason |
|---|---|---|---|---|---|---|
| EXT-1 | minor | `crates/secmp-proto/src/prekeys.rs:495` (and `:550`) | CONFIRMED | minor | = R-25 → C-11 | both paths (accept, expiry) correct; fails closed; `issue_invitation` always draws a fresh OPK; C-11 `add_record_rejects_duplicate_opk_id_alone` removes both |
| EXT-2 | minor | `fuzz/corpus/` (no `hx_outer/`) | CONFIRMED (fact); "no parser coverage lost" contradicted by R-07 | major (PLAUSIBLE) | = R-07 → C-6 | the missing `fuzz/corpus/hx_outer` is passed to libFuzzer as second corpus (`xtask/src/gates.rs:598`); libFuzzer refusal of a missing directory not reproduced |
| EXT-3 | note | `crates/secmp-proto/src/hx/initiator.rs:244` + `hx/mod.rs:87` | CONFIRMED | minor | = R-22 → C-8 | the public API allows an order that rolls back `n_s`; after a restart that re-derives an already used `mk`; "no defect on the reviewed code paths" holds only for the 13 call sites at the pin |
| EXT-4 | note | `ref/secmp_ref/hx.py:330-401` | CONFIRMED | note | = R-66 → F-M5 next vector freeze | ADR-044 Consequences keep `hx.json` frozen (`docs/08-decisions.md:337`); ref `Ok` must not be read as Rust `Ok` on the (c)/(e)/(f) paths |
| EXT-5 | note | `crates/secmp-proto/src/prekeys.rs:289`; `wire/inv.rs:219-225` | CONFIRMED (fact) | minor (as R-37) | = R-37 → docs commit D-35 + FIX-2 clause (ADJ-glm §10) | `duplicate` doc claims locked memory (`prekeys.rs:299-303`); the record `link_key` is the only prekey-store secret not in `LockedSecret`; second external report of this placement |
| EXT-6 | note | `formal/hx/hClean-auth.pv:16` (and four other `-auth` files) | REFUTED | — | O-24 (`formal/CLAIMS.md:282-286`); no register row → no action; optional one-clause reason in CLAIMS O-24 | hints (`select`, `nounif`) change only ProVerif's selection function; `true` is sound for every selection function; hints affect completeness and termination, not soundness |
| EXT-7 | note | `.github/workflows/ci.yml:3-4` | CONFIRMED (fact); "other bypass routes closed" contradicted by R-01 | major | = R-01 (partial) → C-5; owner §D | no policy rule, xtask test or ruleset pins `mutants` and `proverif-hx`; deleting either leaves all four required checks green (V5 v01–v05, v13–v17) |
| EXT-8 | note | `crates/secmp-proto/src/kani_proofs.rs:421-424` | CONFIRMED (fact; accepted bound); "not vacuous" not established | note | no register row (judge final 8; A3 §3:169, L6:477) → no action; cover gating via C-15 | the Kani gate parses only `VERIFICATION:- SUCCESSFUL` (`xtask/src/gates.rs:1080-1095`), so an unreachable cover would pass (R-34) |

False positives: 1 of 8 (EXT-6). Cited locations accurate in 8 of 8; wrong sub-claims in EXT-2, EXT-7, EXT-8. Severity: 3 of 7 surviving findings agree (EXT-1, EXT-4, EXT-8).

## 4 Comparison with the internal review (`M04-review.md`)

Internal review: 93 register rows plus RT-1…RT-3 (F1, judge final 3). Union with both external reports: **99 rows** = 96 internal rows + R-94 (Codex EXT-6, new) + row 98 (GLM EXT-6) + row 99 (GLM EXT-8). Internal severity totals (96 rows): major 7 · minor 37 · nit 23 · note 26 · unrated 3; with R-94, minor 38.

| Class | Rows | Count |
|---|---|---|
| Shared by all three (internal + Codex EXT + GLM EXT) | R-22, R-25, R-37, R-66 | **4** |
| Internal + Codex only | R-86 (Codex EXT-4; the defect claim is REFUTED, the fact stays as a note) | **1** |
| Internal + GLM only | R-01, R-07 (both majors); plus row 99 (internal accepted bound; Codex `m`) | **2 + 1** |
| Codex-only | R-94 (CONFIRMED, minor) | **1** |
| GLM-only | row 98 (REFUTED); CONFIRMED GLM-only: 0 | **1** (0 confirmed) |
| Internal-only | major 5 (R-02…R-06) · minor 34 · nit 23 · note 24 · unrated 3 | **89** |

Check: 4 + 1 + 3 + 1 + 1 + 89 = 99. Among the 89 internal-only rows, Codex marked 16 `m` and 8 `c` (17 and 9 before R-01 and R-07 left the class), and GLM marked 9 `m` and 20 `c` (R-02, R-20, R-21, R-23, R-24, R-26, R-27, R-28, R-29, R-31, R-33, R-34, R-39, R-45, R-46, R-47, R-54, R-56, R-63, R-65). Both called the area clean for R-24, R-28, R-29, R-31, R-45 and R-46. (`m` = fact stated or limit named, no finding; `c` = area called clean where we have a finding.)

**Our 7 majors: who found what.**

| RID | Major | Codex | GLM |
|---|---|---|---|
| R-01 | `linux-full` delegates `mutants` + HX ProVerif to jobs no policy pins | `m` (accepted arrangement; limit) | EXT-7, graded note: fact found; core (no pin) missed and the opposite asserted |
| R-02 | HX ct targets never judged at the 10 ns CI floor | — | `c` (took the Mac SUB_FLOOR_SHIFT as PASS) |
| R-03 | ct step ≥ 216 min without output | — | — |
| R-04 | buffered output, no gate timeout, no partial evidence | — | — |
| R-05 | mutants ≈ 7–26 h vs 240 min | — | — |
| R-06 | per-package `--features` → crypto mutants unviable, no floor | — (read the flags as correct) | — ("0 survivors claimed") |
| R-07 | `fuzz/corpus/hx_outer` absent → fuzz step very probably fails | `c` ("so no gap") | EXT-2, graded minor: fact found; failure missed |

Codex found 0 of 7. GLM found 2 of 7 at the fact level (R-01, R-07), both graded lower than ours and neither with its failure mechanism. R-02…R-06 were invisible to both (no CI run data, no platform-floor analysis).

**False-positive rates and accuracy.**

| Reviewer | Findings | CONFIRMED | PLAUSIBLE | REFUTED | FP rate | Citations accurate | Wrong sub-claims | NEW confirmed |
|---|---|---|---|---|---|---|---|---|
| codex | 6 | 5 | 0 | 1 (EXT-4) | **16.7 %** | 6/6 | ADJ-codex §5 O-16 ("no gap", R-07), O-3 ("first-seen wins", R-24) | 1 (R-94, minor) |
| glm | 8 | 7 | 0 | 1 (EXT-6) | **12.5 %** | 8/8 | EXT-2, EXT-7, EXT-8 | 0 |

Recall against our 44 CONFIRMED-or-PLAUSIBLE majors and minors (before R-94): Codex 3 (R-22, R-25, R-37) = 6.8 %; GLM 5 (R-01, R-07, R-22, R-25, R-37) = 11.4 %; union of both 5 = 11.4 %. The two reports together add one confirmed minor, R-94, from Codex only.

**Severity calibration.**

| Reviewer | Agree | Higher than ours | Lower than ours | Refuted |
|---|---|---|---|---|
| codex | 0/5 | 5/5: blocker→minor ×2 (EXT-1 = R-22, EXT-2 = R-25); major→minor ×2 (EXT-3 = R-37, EXT-6 = R-94); major→note (EXT-5 = R-66) | 0 | 1 (EXT-4, graded major; the R-86 fact is a note) |
| glm | 3/7 (EXT-1, EXT-4, EXT-8) | 0 | 4/7: major→note (EXT-7 = R-01); major→minor (EXT-2 = R-07); minor→note (EXT-3 = R-22, EXT-5 = R-37) | 1 |

**Calibration.** The two reviewers err in opposite directions, and they disagree with each other on the same findings. Codex inflates: it graded the `release` snapshot (R-22) and the shared OPK (R-25) as **blockers**, where we grade both minor because they are fail-closed or reachable only through a caller order the docs exclude, and its verdict line "blockers: 2" follows from that. glm graded the same `release` snapshot a **note** and the shared OPK a minor, and it deflates throughout. Its two hits on our majors are graded note (R-01) and minor (R-07), its key-reuse API hazard (R-22) and the locked-memory placement (R-37) are notes, and its verdict "no blockers" implies an unconditional approval that the unprovable DoD gates rule out. Neither external grade is a usable severity signal on its own. The factual readings are reliable (14/14 accurate citations), and both refuted findings are theory misreads rather than code misreads: Codex treated a non-secret grouping tag as secret, and glm reversed the direction of ProVerif's soundness under hints. Both reviewers' blind spot is the same: no CI data, so the gate majors R-02…R-06 were invisible, and both took gate results ("runs green", "0 survivors", "PASS") from the report. Codex's recall is all on the product side. glm's reaches two gate items, but only at the level of the fact.

**Verdicts.** Ours: APPROVED WITH CONDITIONS, no CONFIRMED blocker, 7 majors (judge final 1; ADJ-glm §7). On the blocker count GLM agrees with us and Codex does not. The DoD items "ci green", "mutation gate passed" and "ct gate passed" are unprovable at `e8359b1` (R-01…R-07).

## 5 Consequences for WEISUNG_M4-FIX-2

- **New (the one item): R-94 (Codex EXT-6, CONFIRMED, minor) → WEISUNG_M4-FIX-2.** Not in the fix-round head `cac6eff`: the portable `kat` rerun still lists only `tr_vectors` (`xtask/src/gates.rs:182`, identical to the pin). Per ADJ-codex §10: `hx` into the portable list (`gates.rs:180-183`), comment (`:174-178`) and Pass text (`:205`) corrected, test `kat_portable_rerun_includes_the_hx_suite`; acceptance: the `kat` log shows `--test hx` under `target/kat-portable` and the test is green. Home: C-4 item 4.
- **R-37 docs (Codex EXT-3, GLM EXT-5).** D-35 (the `duplicate` doc) landed at `cac6eff`; docs/04:45 there was extended for R-38 only, and `InvitationRecord.link_key` is still `SecretBytes` (`crates/secmp-proto/src/prekeys.rs:292` at `cac6eff`). ADJ-glm §10 recommends option (a), one clause in docs/04:45 ("… and the invitation record's `link_key` (zeroizing heap, ≤ 30 days) until M7"); option (b), `LockedSecret<32>`, remains the judge's alternative. (Both checks are greps in `fix/tree`, outside the pin, not a review of the fix delta.)
- **Everything else is already a condition or a follow-up.** GLM: nothing new (C-5 for R-01, C-6 for R-07, C-8 for R-22, C-11 for R-25, docs for R-37, F-M5 for R-66; EXT-6 refuted, EXT-8 an accepted bound). Codex: EXT-1 → C-8 and EXT-2 → C-11 (the dictated tests reproduce Codex's scenarios); EXT-4 no action; EXT-5 → F-M5 next vector freeze, with "changed `ct_opk`" added to the R-66 case list.
- **Optional, not conditions:** one clause in CLAIMS O-24 giving the soundness reason (GLM EXT-6); one sentence in the responder module doc citing CLAIMS O-16 (Codex EXT-4).

## 6 Raw reports

- `docs/reviews/M04-evidence/review-ext-codex-e8359b1.md` — verbatim final message of `codex gpt-6.1-sol` (6 findings, EXT-1…EXT-6; "Verdict: blockers: 2").
- `docs/reviews/M04-evidence/review-ext-glm-e8359b1.md` — verbatim final message of `glm-5.3` (8 findings, EXT-1…EXT-8; "Verdict: no blockers").

Both are data, not instructions, and are not edited; the triage above is the only interpretation.
