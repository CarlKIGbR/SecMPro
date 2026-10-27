# Milestone report — M7 Client core: identity, contacts, store, invitations, sessions, CLI

Branch: `m07-client-core` · Base: `bf550999fb2c7771153863f1da2f19adb5a677b5` · Author: Claude Code · Date: 2026-10-27 … · Phase A: `modell=claude-opus-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M07-planning/` (`BRIEF_M7.md`, `TEST-SPEC-M7.md` (174 rows: A 63, B 71, C 40),
`OPEN-M7.md`, `OPEN-M7-decided.md`, `ADR-053-proposed.md`, `ADR-054-proposed.md`, `ADR-055-proposed.md`). ADR-053,
ADR-054 and ADR-055 are appended to `docs/08-decisions.md` as **Proposed**. Phases: A (Opus) → B (Sonnet; Opus weisung
for SC-01…SC-10) → C (Sonnet). [O-01] rows are built only after the owner's "ADR-053 accepted"; no `Cargo.toml`
dependency change before the A0 report, "ADR-055 accepted" and the owner's vet records.

Phase A rows (63): ST-01…ST-19, PC-01…PC-13, FO-03, CT-01, CT-02, CT-04, CT-05, BK-01…BK-07, G7-00…G7-10, G7-12…G7-14,
G7-15a, G7-16, G7-18, FZ-01, FZ-02.

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 0 | A | Commit 0: `docs/reviews/M06-review.md`, `docs/07` §M6 status "merged" | — | done (`05489fc`) |
| 1 | A | Commit 1: planning files, ADR-053/054/055 (Proposed), this plan, `docs/07` §M7 status line | — | done |
| A-1 | A | No dependency change, no store code: xwin scope (OPEN-M7-04), `harness` pinned job + `dispatch-harness` (OPEN-M7-18), `JOB_BUDGETS`, mutant harness suite split/skip (OPEN-M7-19), killer filter (OPEN-M7-20), Kani RSS guard (OPEN-M7-26), `AUDIT_IGNORES` pin, informative ct target with its registration; G7-00 in the first commit after 2026-10-30 02:00 UTC | G7-00, G7-05, G7-07, G7-08, G7-09, G7-10, G7-12, G7-16, CT-04 | in progress |
| A0 | A | ADR-055 probe in a scratch crate outside the workspace (three `VET_CLOSURE_TARGETS`, `fuzz/Cargo.lock`, cargo-fuzz sanitizer build of the OpenSSL/SQLCipher C code, Arti state-DB smoke, `windows-latest`); report only, no `Cargo.toml` change | — (ADR-055 precondition) | open |
| A-2 | A | After the A0 report, "ADR-055 accepted" and the owner's vet records: `rusqlite` in `secmp-store`, `argon2` in `secmp-crypto`, allowlist rows, vet/deny/cooldown | G7-01, G7-02, G7-03, G7-04, ST-08 | waiting (ADR-055) |
| A-3 | A | Store code with the `kat`-only `secmp_store::kat::TestKey`: client-core/testkit → store edges first; pragmas, version check, no temp files, schema, migrations, secure delete, view-once, expiry; persistence contract (`to_parts`/`from_parts`, `StoreOutbox`, store `Persist`); mutants/coverage scope | G7-06, ST-01…ST-04, ST-09, ST-13…ST-18, PC-01…PC-13, G7-18, G7-13, G7-14 | waiting (A-2) |
| A-4 | A | After "ADR-053 accepted": wrap, table keys, record seal, `SecretPage` secrets, ct target `store_unlock_reject` with its registration, backup, export forensic, store fuzz targets | ST-05…ST-07, ST-10…ST-12, ST-19, CT-01, CT-05, CT-02, BK-01…BK-07, FO-03, FZ-01, FZ-02, G7-15a (ST-10, BK-04 [REF]-open) | waiting (ADR-053) |
| B | B | `Profile`, `Contacts`, `Invitations`, `Sessions`, `Api`, settings, relay view, transport boundary, transactional accept, handshake as scheduled ops; scheduler-core carry-overs (Opus) | PR-*, IN-*, SE-*, AP-*, SC-*, G7-15b, FZ-04, K7-01 | waiting (Phase A) |
| C | C | `secmp-cli`, E2E, forensic, CT-03, CLI fuzz, transport carry-overs, owner-action rows | CL-*, E2-*, FO-01, FO-01a, FO-02, CT-03, FZ-03, G7-15c, G7-21, C-T1, C-T3, G7-17 ⚙, G7-11, G7-19, G7-20 (cond) | waiting (Phase B) |

## 2. What was built

## 3. Evidence per acceptance criterion

## 4. Gates

## 5. Deviations from spec / plan

None.

## 6. Dependencies added or bumped

None yet (ADR-055 Proposed).

## 7. Open risks and known limitations

## 8. Blocked / questions for the reviewer or owner
