# Milestone report — M7 Client core: identity, contacts, store, invitations, sessions, CLI

Branch: `m07-client-core` · Base: `bf550999fb2c7771153863f1da2f19adb5a677b5` · Author: Claude Code · Date: 2026-10-27 … · Phase A: `modell=claude-opus-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M07-planning/` (`BRIEF_M7.md`, `TEST-SPEC-M7.md` (174 rows: A 63, B 71, C 40),
`OPEN-M7.md`, `OPEN-M7-decided.md`, `ADR-053-proposed.md`, `ADR-054-proposed.md`, `ADR-055-proposed.md`). ADR-053,
ADR-054 and ADR-055 are appended to `docs/08-decisions.md` as **Proposed**. Phases: A (Opus) → B (Sonnet; Opus weisung
for SC-01…SC-10) → C (Sonnet). [O-01] rows are built only after the owner's "ADR-053 accepted"; no `Cargo.toml`
dependency change before the A0 report, "ADR-055 accepted" and the owner's vet records.

Phase A rows (64): ST-01…ST-20, PC-01…PC-13, FO-03, CT-01, CT-02, CT-04, CT-05, BK-01…BK-07, G7-00…G7-10, G7-12…G7-14,
G7-15a, G7-16, G7-18, FZ-01, FZ-02.

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 0 | A | Commit 0: `docs/reviews/M06-review.md`, `docs/07` §M6 status "merged" | — | done (`05489fc`) |
| 1 | A | Commit 1: planning files, ADR-053/054/055 (Proposed), this plan, `docs/07` §M7 status line | — | done |
| A-1 | A | No dependency change, no store code: xwin scope (OPEN-M7-04), `harness` pinned job + `dispatch-harness` (OPEN-M7-18), `JOB_BUDGETS`, mutant harness suite split/skip (OPEN-M7-19), killer filter (OPEN-M7-20), Kani RSS guard (OPEN-M7-26), `AUDIT_IGNORES` pin, informative ct target with its registration; G7-00 in the first commit after 2026-10-30 02:00 UTC | G7-00, G7-05, G7-07, G7-08, G7-09, G7-10, G7-12, G7-16, CT-04 | done except G7-00 (not before 2026-10-30 02:00 UTC) |
| A0 | A | ADR-055 probe in a scratch crate outside the workspace (three `VET_CLOSURE_TARGETS`, `fuzz/Cargo.lock`, cargo-fuzz sanitizer build of the OpenSSL/SQLCipher C code, Arti state-DB smoke, `windows-latest`); report only, no `Cargo.toml` change | — (ADR-055 precondition) | report delivered: `docs/reviews/M07-evidence/A0-probe.md` |
| A-2 | A | After the A0 report, "ADR-055 accepted" and the owner's vet records: `rusqlite` in `secmp-store`, `argon2` in `secmp-crypto`, allowlist rows, vet/deny/cooldown | G7-01, G7-02, G7-03, G7-04, ST-08 | waiting (ADR-055) |
| A-3 | A | Store code with the `kat`-only `secmp_store::kat::TestKey`: client-core/testkit → store edges first; pragmas, version check, defensive mode (ST-20, Q128), no temp files, schema, migrations, secure delete, view-once, expiry; persistence contract (`to_parts`/`from_parts`, `StoreOutbox`, store `Persist`); mutants/coverage scope | G7-06, ST-01…ST-04, ST-09, ST-13…ST-18, ST-20, PC-01…PC-13, G7-18, G7-13, G7-14 | waiting (A-2) |
| A-4 | A | After "ADR-053 accepted": wrap, table keys, record seal, `SecretPage` secrets, ct target `store_unlock_reject` with its registration, backup, export forensic, store fuzz targets | ST-05…ST-07, ST-10…ST-12, ST-19, CT-01, CT-05, CT-02, BK-01…BK-07, FO-03, FZ-01, FZ-02, G7-15a (ST-10, BK-04 [REF]-open) | waiting (ADR-053) |
| B | B | `Profile`, `Contacts`, `Invitations`, `Sessions`, `Api`, settings, relay view, transport boundary, transactional accept, handshake as scheduled ops; scheduler-core carry-overs (Opus) | PR-*, IN-*, SE-*, AP-*, SC-*, G7-15b, FZ-04, K7-01 | waiting (Phase A) |
| C | C | `secmp-cli`, E2E, forensic, CT-03, CLI fuzz, transport carry-overs, owner-action rows | CL-*, E2-*, FO-01, FO-01a, FO-02, CT-03, FZ-03, G7-15c, G7-21, C-T1, C-T3, G7-17 ⚙, G7-11, G7-19, G7-20 (cond) | waiting (Phase B) |

## 2. What was built

Phase A, step A-1 (xtask, workflows, docs; no dependency change, no store code):

| Row | Commit | What |
|---|---|---|
| G7-05 | `4a47a23` | `expect::XWIN_EXCLUDE`; `gates::windows_cross_args` passes `--exclude` for the five store-dependent packages; ADR-034 Amendment 1; docs/06 job table |
| G7-16 | `06f5c99` | `expect::tests::audit_ignores_unchanged` pins the five ignores |
| G7-07, G7-08 | `50124cf` | step `harness` (`gates::harness`, `testscan::harness_runs`); `kat` runs the testkit with `-E 'not binary(=harness)'`; job `harness` (150 min, every event) and twin `dispatch-harness`; `--delegated harness` in `linux-fast`/`linux-full`/`dispatch-fast`/`dispatch-full`; `harness` added to the native Windows gate lines (`windows-native`, `dispatch-windows`, `win-ondemand.yml` win-test); `expect::JOB_BUDGETS`, `expect::DISPATCH_TWINS`, `gates::job_budget_findings` in the policy step; `dispatch-fast` 90 → 120 min (= `linux-fast`); ADR-045 Amendment 12; docs/06 job table |
| G7-09, G7-10 | `5139e73` | short forms `timing_draws_unmoved_by_one_hour_of_activity`, `relay_idle_and_age_bounds_defaults`; the two long forms in `MUTANT_HARNESS_SKIP_TESTS`; nextest profile `mutants-harness` (`.config/nextest.toml`, priority 100 on `m0_early::`), `--profile mutants-harness` in the second mutants run, policy check `mutants_profile`; ADR-047 Amendment 9; `docs/mutants-accepted.md` §Skipped |
| G7-12 | `97a7d12` | `gates::kani_guarded`: every `cargo kani` with its output in `target/kani-<pkg>.log`, `ps` sampled every 2 s, cbmc RSS > `KANI_CBMC_RSS_LIMIT_KIB` (14 160 156 KiB = 14.5 GB) kills cbmc, stops the step and names the harness; peak RSS per harness printed |
| CT-04 | `4700464` | ct informative target `tr_decrypt_header_contents_dependence` (`pn` 0 vs 3, one nonce, skipped path, body MAC) and its `CT_INFORMATIVE_TARGETS` entry in the same commit; `ct-check --targets m6` for the committed M6 reports |

A0 probe: `docs/reviews/M07-evidence/A0-probe.md` (raw outputs in `docs/reviews/M07-evidence/a0/`).

## 3. Evidence per acceptance criterion

## 4. Gates

## 5. Deviations from spec / plan

None.

## 6. Dependencies added or bumped

None yet (ADR-055 Proposed).

## 7. Open risks and known limitations

## 8. Blocked / questions for the reviewer or owner

**Waiting (owner).** A-2 needs "ADR-055 accepted" and the vet records (A0 §7: `argon2` 0.6.0, `blake2` 0.11.0 in the
zero-exemption crypto closure; `openssl-sys` 0.9.117, `openssl-src` 300.6.1+3.6.3, `password-hash` 0.6.1, `phc` 0.6.1);
A-4 needs "ADR-053 accepted".

**Waiting (date).** G7-00: first commit after 2026-10-30 02:00 UTC; the cooldown gate is red from 2026-10-31 00:00 UTC
until it lands.

**Not done by the A0 probe (A0 §6).** Native `windows-latest` build of the unified graph and `tor-smoke` (dispatch runs;
the executor cannot dispatch); vendor CVE lists of SQLite 3.50.4 / SQLCipher 4.10.0 / OpenSSL 3.6.3 (no web access in
the container; RustSec shows none).

**Q-A1 (G7-05 vs G7-06, OPEN-M7-04 A).** `secmp-crypto` and `secmp-transport` dev-depend on `secmp-testkit`. With the
G7-06 edge `secmp-testkit` → `secmp-store`, `cargo xwin build --workspace --all-targets --exclude …` still builds the
testkit, the store and vendored OpenSSL as dev-dependencies of the non-excluded packages, so the excluded list does not
keep OpenSSL out of the xwin build. Not observable before G7-06 (A-3). Needs a reviewer reading before A-3.

**Note for ST-02.** The bundled SQLCipher reports `PRAGMA cipher_version` = `4.10.0 community` (A0 §3); the row's
expected value 4.10.0 is the leading version of that string.
