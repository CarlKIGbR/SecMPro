# Milestone report — M7 Client core: identity, contacts, store, invitations, sessions, CLI

Branch: `m07-client-core` · Base: `bf550999fb2c7771153863f1da2f19adb5a677b5` · Author: Claude Code · Date: 2026-10-27 … · Phase A: `modell=claude-opus-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M07-planning/` (`BRIEF_M7.md`, `TEST-SPEC-M7.md` (175 rows: A 64, B 71, C 40),
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

Phase A, A-1 (numbers; raw files under `docs/reviews/M07-evidence/`). Phase B/C and A-2…A-4 rows: not yet built.

| Row | Test / command | Result |
|---|---|---|
| G7-05 | `xtask::policy::tests::xwin_scope_excludes_sqlcipher_crates`, `xwin_full_roots_have_no_excluded_dev_dependency`, `xwin_dev_dependency_scan_sees_target_tables` (Q127, Q130) | pass. Red first, new test with `XWIN_LIB_ONLY` emptied (= the single-invocation list of `fa0adef`): `roots with an excluded dev-dependency: ["secmp-crypto:36", "secmp-transport:37"]`; red first of the scan test: `left: [12]  right: [5, 7, 12]` (the old scanner saw only the plain `[dev-dependencies]` table). The `cargo xwin` invocations themselves were not run (no network for the Windows SDK) |
| G7-07 | `xtask::policy::tests::harness_job_is_pinned`, `testscan::scan::tests::pr_ci_runs_props_with_ci_run_seed`, `nextest_does_not_run_the_harness_binary_twice` | pass; `ci-fast` step `harness`: PASS 942 s (`fa0adef`), 927 s (`f6e2928`); `kat` 93 s / 92 s |
| G7-08 | `xtask::policy::tests::job_budgets_are_pinned` | pass |
| G7-09 | `xtask::gates::tests::mutant_harness_suite_under_30s`; command `sh g7-09-measure.sh.txt` (`cargo nextest run --locked -p secmp-client-core -p secmp-transport -p secmp-testkit --features secmp-testkit/harness --max-fail=1:immediate --profile mutants-harness -- <--skip of every entry of MUTANT_SKIP_TESTS and MUTANT_HARNESS_SKIP_TESTS>`) | per-mutant harness suite on the **32-core container** (`nproc` 32, unmutated tree): nextest `Summary [12.773s] 349 tests run: 349 passed, 33 skipped` (`g7-09-per-mutant-harness-suite.txt`); the 4-vCPU runner is not measured here. Before the split (C2-18c): 70 s |
| G7-09 short forms (OPEN-M7-19 B) | `m6_activity::timing_draws_unmoved_by_one_hour_of_activity`, `m6_sched_life::relay_idle_and_age_bounds_defaults` | 4.4 s (long form 69.5 s, C2-18c; 128 s under load in the `ci-fast` of `5a66eda`); 0.006 s (long form 26.1 s). Trace of the AI-05 short form: **1717** user sends (trace 900, 1 h, 2 contacts; asserted ≥ 100; the long form asserts no count) |
| G7-10 | `xtask::gates::tests::mutant_killers_run_first_by_filter`; `g7-10-nextest-priority.txt` | pass; `--test-threads 1`: with the repo profile the first test started is `m0_early::async_handshake_writes_its_records`; with the same block aimed at `m6_sched_life::` that module's test starts first |
| G7-12 | `xtask::gates::tests::kani_rss_guard`, `kani_rss_guard_fails_closed_without_ps_sample`, `kani_rss_guard_requires_a_peak_per_checked_harness` (`ea0f9b7`) | pass; red first, line of the first test: `empty: ` (the guard returned without error on an empty sample); line of the second: `panicked at xtask/src/gates.rs:10166:9` (no error for a log with a checked harness and no peak). Local `cargo xtask step kani` on `97a7d12`: `secmp-client-core` 13/13 verified (`Complete - 13 successfully verified harnesses`), the step was then stopped by the 30-min background limit during `secmp-proto`; no `kani-rss` line (printed after the last package) — no pass/fail verdict of the step, no peak figures |
| G7-16 | `xtask::expect::tests::audit_ignores_unchanged` | pass |
| CT-04 | `SECMP_CT_SCALE=1000 cargo bench --locked -p secmp-testkit --features kat --bench ct` (`target/m7logs/ct-smoke.sh`; the bench has no single-target filter, the scale divides every sample count, the gate refuses scaled reports; `ct-04-informative-smoke-scale1000.txt`) | run_verdict PASS, pre-check passed (`Err(Rejected)`, site `body MAC`, both classes) for `tr_decrypt_header_contents_dependence`; 1000 samples per half, Δ in ticks / t: first `raw −221.66/−0.51, p50 +7.63/+0.99, p75 +4.77/+0.55, p90 +4.41/+0.44, p95 −3.17/−0.27, p99 −395.41/−2.10`; second `raw +120.50/+0.35, p50 −0.08/−0.01, p75 +0.33/+0.04, p90 +4.19/+0.39, p95 +6.15/+0.52, p99 −112.12/−0.62`. Same run, `tr_decrypt_nonce_dependence`: p90 −58.22/−4.64 (second). Informative: no verdict; the full-sample run is the `ct` job |
| A0 | `A0-probe.md` | see there |
| G7-00 | — | not before 2026-10-30 02:00 UTC |

Extra tests of A-1 (not rows of TEST-SPEC-M7): `xtask::ctreport::tests::informative_targets_per_target_set`;
`xtask::testscan::scan::tests` helper `check_harness_invocations` (inside `pr_ci_runs_props_with_ci_run_seed`);
`xtask::gates::tests::kani_rss_guard`, `kani_rss_guard_fails_closed_without_ps_sample`,
`kani_rss_guard_requires_a_peak_per_checked_harness`; `xtask::policy::tests::xwin_full_roots_have_no_excluded_dev_dependency`;
harness `m6_activity::timing_draws_unmoved_by_one_hour_of_activity`, `m6_sched_life::relay_idle_and_age_bounds_defaults`
(short forms). Changed existing tests: `ctreport::tests::informative_targets_are_pinned_printed_and_never_fail`,
`gates::tests::deleting_or_neutering_a_pinned_job_is_a_finding` (harness variants), `required_jobs_keep_their_pinned_conditions`
(14 jobs), `testscan::scan::tests::nextest_does_not_run_the_harness_binary_twice`.

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci-fast` at `fa0adef` (`ci-fast-a1-fa0adef.txt`) | PASS: kat 93 s, harness 942 s |
| `cargo xtask ci-fast` at `62c2dbc` (`ci-fast-a1c-62c2dbc.txt`, first line names the head, clean tree) | PASS: fmt 0 s, clippy 0 s, policy 1 s, deny 1 s, vet 1 s, audit 2 s, cooldown 23 s (561 packages), nextest 16 s, doctest 1 s, hello 0 s, kat 89 s, harness 1023 s |
| `cargo xtask ci-full` | not run in A-1b |
| Kani | see G7-12 row |
| Fuzz / mutants / coverage / ct (full) | not run |

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

**Q-A1 (closed by Q127, `f6e2928`).** Two cross-build invocations; see G7-05.

**Q-A2 (answered, Q130).** `secmp-proto` and `secmp-relay` dev-depend on `secmp-crypto`, not on `secmp-testkit`; the earlier
red for them came from treating `XWIN_LIB_ONLY` crates as poison. `XWIN_LIB_ONLY` is `[secmp-crypto, secmp-transport]` again; the poison
set of the test is `XWIN_EXCLUDE`.

**Q-A3 (Kani peak figures).** The `kani` step prints its `kani-rss` lines after the last package; a step that is stopped
earlier prints none. The first guarded local run was stopped by the background limit during `secmp-proto`.

**Note for ST-02.** The bundled SQLCipher reports `PRAGMA cipher_version` = `4.10.0 community` (A0 §3); the row's
expected value 4.10.0 is the leading version of that string.
