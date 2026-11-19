# Milestone report — M7 Client core: identity, contacts, store, invitations, sessions, CLI

Branch: `m07-client-core` · Base: `bf550999fb2c7771153863f1da2f19adb5a677b5` · Author: Claude Code · Date: 2026-10-27 … · Phase A: `modell=claude-opus-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M07-planning/` (`BRIEF_M7.md`, `TEST-SPEC-M7.md` (178 rows: A 66, B 72, C 40; Q145),
`OPEN-M7.md`, `OPEN-M7-decided.md`, `ADR-053-proposed.md`, `ADR-054-proposed.md`, `ADR-055-proposed.md`). ADR-053,
ADR-054 and ADR-055 are appended to `docs/08-decisions.md` as **Proposed**. Phases: A (Opus) → B (Sonnet; Opus weisung
for SC-01…SC-10) → C (Sonnet). [O-01] rows are built only after the owner's "ADR-053 accepted"; no `Cargo.toml`
dependency change before the A0 report, "ADR-055 accepted" and the owner's vet records.

Phase A rows (66): ST-01…ST-20, PC-01…PC-13, FO-03, CT-01, CT-02, CT-04, CT-05, BK-01…BK-07, G7-00…G7-10, G7-12…G7-14,
G7-15a, G7-16, G7-18, K7-02, K7-03, FZ-01, FZ-02.

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 0 | A | Commit 0: `docs/reviews/M06-review.md`, `docs/07` §M6 status "merged" | — | done (`05489fc`) |
| 1 | A | Commit 1: planning files, ADR-053/054/055 (Proposed), this plan, `docs/07` §M7 status line | — | done |
| A-1 | A | No dependency change, no store code: xwin scope (OPEN-M7-04), `harness` pinned job + `dispatch-harness` (OPEN-M7-18), `JOB_BUDGETS`, mutant harness suite split/skip (OPEN-M7-19), killer filter (OPEN-M7-20), Kani RSS guard (OPEN-M7-26), `AUDIT_IGNORES` pin, informative ct target with its registration; G7-00 in the first commit after 2026-10-30 02:00 UTC | G7-00, G7-05, G7-07, G7-08, G7-09, G7-10, G7-12, G7-16, CT-04 | done; G7-00 landed in A-4 @ `eb9d3b8` (2026-10-30 02:01 UTC) |
| A0 | A | ADR-055 probe in a scratch crate outside the workspace (three `VET_CLOSURE_TARGETS`, `fuzz/Cargo.lock`, cargo-fuzz sanitizer build of the OpenSSL/SQLCipher C code, Arti state-DB smoke, `windows-latest`); report only, no `Cargo.toml` change | — (ADR-055 precondition) | report delivered: `docs/reviews/M07-evidence/A0-probe.md` |
| A-2 | A | After the A0 report, "ADR-055 accepted" and the owner's vet records: `rusqlite` in `secmp-store`, `argon2` in `secmp-crypto`, allowlist rows, vet/deny/cooldown | G7-01, G7-02, G7-03, G7-04, ST-08 | done @ `bf54d98` |
| A-3 | A | Store code with the `kat`-only `secmp_store::kat::TestKey`: client-core/testkit → store edges first; pragmas, version check, defensive mode (ST-20, Q128), no temp files, schema, migrations, secure delete, view-once, expiry; persistence contract (`to_parts`/`from_parts`, `StoreOutbox`, store `Persist`); mutants/coverage scope | G7-06, ST-01…ST-04, ST-09, ST-13…ST-18, ST-20, PC-01…PC-13, G7-18, G7-13, G7-14 | closed @ `cdc3c0a` (ST-17: store half; A-3b/A-3d/A-3e fix-ups; Kani exception Q138; `modell=claude-opus-5-5`) |
| A-4 | A | After "ADR-053 accepted": wrap, table keys, record seal, `SecretPage` secrets, ct target `store_unlock_reject` with its registration, backup, export forensic, store fuzz targets | ST-05…ST-07, ST-10…ST-12, ST-19, CT-01, CT-05, CT-02, BK-01…BK-07, FO-03, FZ-01, FZ-02, G7-15a (ST-10, BK-04 [REF]-open) | **A-4 built @ `c3c1dcf`; Phase A closes with the green PR run (BRIEF_M7 §5, reviewer)** (`modell=claude-opus-5-5`) |
| B | B | `Profile`, `Contacts`, `Invitations`, `Sessions`, `Api`, settings, relay view, transport boundary, transactional accept, handshake as scheduled ops; scheduler-core carry-overs (Opus) | B-SC (Opus): SC-01…SC-10, K7-03b, proto additions (Q147); B-1…B-3 (Sonnet): PR-01, PR-02, PR-04…PR-09, IN-01…IN-13, IN-18…IN-21, K7-01, FZ-04, G7-15b; B-4…B-7 (Sonnet, continuation): PR-03, IN-14…IN-17, SE-01…SE-20 (SE-13a not built), AP-01…AP-07 | B-SC closed @ `923b9ee` (SC-01…SC-10, K7-03b; G7-15b opened); B-1…B-3 built (Q146); B-4 built @ `1318baa` (verifier: DO NOT PUSH, 3 B/16 M); B-4c built @ `ab72776` (ci-full `e80e11c`); Phase B closes on the reviewer's verdict |
| C | C | `secmp-cli`, E2E, forensic, CT-03, CLI fuzz, transport carry-overs, owner-action rows | CL-*, E2-*, FO-01, FO-01a, FO-02, CT-03, FZ-03, G7-15c, G7-21, C-T1, C-T3, G7-17 ⚙, G7-11, G7-19, G7-20 (cond) | waiting (Phase B) — superseded: built in C-1…C-5 except the OWNER-PENDING and OWNER-OPERATED rows of Phase C close, corrected by S-1, S-2, S-2b; see `## Phase C close (M7-C5)` and `## D-11` |

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

Phase A, step A-2 (ADR-055 effective, memo default 2026-10-27 item 3):

| Row | Commit | What |
|---|---|---|
| G7-01…G7-04 | `1e49fab` | workspace deps `rusqlite =0.39.0` (`bundled-sqlcipher-vendored-openssl`), `argon2 =0.6.0`, path entry `secmp-store`; edges `secmp-store` → {`rusqlite`, `secmp-crypto`, `secmp-proto`}, `secmp-crypto` → `argon2`; allowlist rows `secmp-store`, `secmp-crypto` and the ADR-051 table in `policy.rs`; provisional vet records (Q129); ADR-051 Amendment 7; ADR-055 status Accepted; Q129 row |
| ST-08 | `bf54d98` | `secmp-crypto::argon2` (`argon2id`, `argon2id_with_secret_and_ad`) |

Phase A, step A-3 (WEISUNG M7-A3; `modell=claude-opus-5-5`; no ADR-053 construction, the only key is `secmp_store::kat::TestKey`, no
non-`kat` way to obtain a `DbKey`):

| Rows | Commit | What |
|---|---|---|
| §0.1 | `27bfce2` | A-2 fix-ups: ADR-051 Am. 7 closure count (+5), ratification wording, argon2 zeroization note, `vet-suggest-m7-a3.txt`, `cooldown-m7-a3.txt` (ci-fast `8f5d29c`) |
| G7-06 | `b4b99db`, `3064c74` | `[target.'cfg(not(kani))'.dependencies] secmp-store` in client-core, testkit edge in its `cfg(not(miri))` table; `NORMAL_DEPENDENCY_ALLOW`, `normal_dependency_allow_m7` and `cooldown_covers_m7_lock` re-dictated; `kani_build_has_no_store`; the OB-07 harness test `m6_outbox::outbox_is_the_store_boundary` follows the new edge (`3064c74`, ci-fast red at `f5c099d` committed) |
| ST-01…ST-04, ST-13…ST-15, ST-20 | `1f10f10` | `secmp-store` modules `store`, `schema`, `migrate`, `kat` (+ `error`); one `open_connection` (defensive mode first, raw key, `cipher_memory_security`, version check, WAL, `temp_store` 2, `secure_delete`); `Error::{Unlock, Unsupported, TooNew, Unavailable}`; `KAT_PACKAGES` += `secmp-store`; `expect::SQLCIPHER_MIN` |
| ST-16…ST-18, ST-09 | `f6f68c1` | `delete`, `messages` (view-once in memory, expiry, retention); `testscan::kat_argon2_params_only_with_kat` |
| PC-07, PC-08, PC-01, PC-02, PC-09 | `3dc63fd` | `RatchetParts`, `RatchetState::{to_parts, from_parts}`; `secmp_store::sessions`; `CommitParts`, `Persist::commit_parts`; client-core `persist` (`StorePersist`); `PROPERTY_PACKAGES` += `secmp-client-core` |
| PC-06, PC-10, PC-11, PC-12 | `beb12ef` | `secmp_store::outbox`; client-core `outbox` (`StoreOutbox`); `MemOutbox::{entries, from_entries}`; `testscan::scheduler_sees_only_traits` |
| PC-03, PC-04, PC-05, PC-13 | `0c448f0` | `PreparedCell` private witness (compile_fail doc test `E0451`), `PreparedCell::unpersisted_kat`; kat `PrepRecord.seal`; testkit `Audit::Decided`; harness `m7_persist`, `m7_crash`; skip-list entries for PC-05/PC-13 |
| G7-18 | `dbae42a` | `tr::state::tests::ratchet_state_v1_layout_unchanged` |
| G7-13 | `bc67679`, `be0d82d`, `04b9795`, `365a3da` | `MUTANT_PACKAGES` += `secmp-store`, ADR-047 Amendment 10, docs/06 §4/§5; store unit tests and kat fixes found by the mutants runs (§5 D8) |
| G7-14 | `613689b` | `COVERAGE_STRICT` += `secmp-store`, docs/06 §4 |

Final shape of the persistence contract (WEISUNG §3 "name the final shape"): `secmp_proto::tr::RatchetParts { fixed:
Zeroizing<Vec<u8>>, skipped: Vec<Zeroizing<Vec<u8>>> }` (`split`, `to_bytes`; `fixed ‖ count u16 ‖ entries` = the frozen
`RatchetStateV1`), `RatchetState::{to_parts, from_parts}`; `scheduler::outbox::CommitParts<'a> { ratchet: &RatchetParts, inbox:
Option<&[u8]>, trust: Option<u8>, delivered: &[DeliveredMessage<'a>] }` and `Persist::commit_parts(kind, &CommitParts)` (default:
`commit` of the joined state); the conversation's receive commit carries the `Inbox` bytes when the reassembly state is or was
non-empty, the trust code when the trust changed, and the messages the cell delivers for the first time; `StorePersist` diffs the
skipped entries by key `(hk, n)` and writes fixed part, deletes, inserts, inbox, trust and history rows in one transaction.
`StorePersist` (`persist.rs`) and `StoreOutbox` (`outbox.rs`) are top-level client-core modules under `cfg(not(kani))`.

Phase A, step A-4 (WEISUNG M7-A4; `modell=claude-opus-5-5`; ADR-053 accepted, Q127a; Amendment 1 accepted by the owner 2026-10-29 (Q144, commit 6ad3ec6)):

| Rows | Commit | What |
|---|---|---|
| §0.1 | `45c3c3e` | A-3e records: `kani_proofs.rs:336` comment, OPEN-M7-decided `:65` and TEST-SPEC K7-03 (exception Q138 text), report Kani table one source per column, D15/D16 (ci-fast `4247c47` → `ci-fast-a4-0-45c3c3e.txt`) |
| §1 | `c2ad056` | `docs/03` rev 2.7: Appendix A + `"SecMP-STORE/1 wrap"`, `"SecMP-STORE/1 db"`, `"SecMP-STORE/1 backup"`, `"SecMP-STORE/1 bwrap"` (53 labels), changelog; `secmp_crypto::Label::{StoreWrap, StoreDb, StoreBackup, StoreBwrap}`; ADR-053 Status "Accepted (Owner, 2026-10-28, Q127a)", Amendment 1 (Proposed); `docs/04` CS-3.1 `synchronous = FULL` (Q-A14); OPEN-M7-decided Q127a, Q139, Q140 (open), Q141–Q143 |
| §2 (F3) | `e9851d9` | `argon2::derive` with `hash_password_into_with_memory` over a `Zeroizing<Vec<Block>>`; `argon2id_locked`, `hkdf_locked`, `Caead::{seal_locked, open_locked}` (thin overloads, no label or parameter choice) |
| ST-05, ST-06, ST-07, ST-10, ST-19, CT-02 | `bd9e240` | `secmp-store` `wrap` (`Argon2Params`, `PROFILE`, `kat_small`, `create`/`unlock`/`open_kat`, the unlock order of item 2), `keys` (`Table`, `TableKeys`, `derive`), `secrets` (`StoreKey`), `rand`; `DbKey` with the nine `K_t`; `Store::open_unlocked`; `Store::open` kat-only; kat counters `argon2_calls`, `caead_open_calls`, `live_key_pages`, `fixed_random` |
| ST-11, ST-12 | `b014540` | `seal` (`row_key`, record seal, uniform open); the Q139 columns sealed: `sessions.data`/`skey` (new column), `outbox.payload`, `identity.secret`, `prekeys.secret`, `relays.access_key`, `invitations.record`; `profile` (identity, prekeys, relays, invitations); `contacts.profile` (Q143); ST-09 re-dictation (`testscan.rs:456`, §5 D18) |
| CT-01, CT-05 | `82148dd` | bench `store_unlock_reject` and informative `store_unwrap_reject_post_kdf` (`wrap::WRAP_SITE_KAT`, `wrap::open_with_kek_kat`); `expect::{CT_STORE_SAMPLES, CT_TARGETS (27), CT_TARGETS_M6, CT_INFORMATIVE_TARGETS (3), CT_TARGET_SITES (12), KNOWN_SITES}`, `ct_targets_m7`; ctreport/gates pins; ADR-042 Amendment 6 |
| FO-03 | `0882c77` | harness `m7_forensic::export_file_has_no_plaintext` |
| (fix) | `9ab5d5b` | `ctreport::tests::informative_targets_are_pinned_printed_and_never_fail` within the line limit (ci-fast red at `0882c77`, §5 D19) |
| BK-01…BK-05, extra | `f393a22` | `backup` (format of item 6 + Appendix, `export_kat`, `import`, `open_export_kat`), `contacts` (`STATE_REINVITE_REQUIRED` = 1, Q142), `wrap::kek` crate-visible |
| BK-06, BK-07 | `f0a7802` | `backup::export(store, path, passphrase, confirm, force)`, `CLOUD_FOLDERS` (Q141), `Error::{ConfirmRequired, CloudFolder}` |
| FZ-01, FZ-02, G7-15a | `f51f7c2` | fuzz targets `backup_import`, `store_record_open`, corpora (8 + 6 seeds), `fuzz/Cargo.toml` (2 bins, `secmp-store` path dependency with `kat`), `fuzz/Cargo.lock` one line; `FUZZ_TARGETS` (35), `FUZZ_MAX_LEN`, `FUZZ_TRACKED_ONLY`, `fuzz_targets_store`; nightly pins 33 → 35; kat entry points `backup::{seal_file_kat, encode_body_kat}`, `seal::{seal_kat, open_kat}` |
| (fix) | `4383c8a` | `secmp-proto/tests/fuzz_max_len.rs` recomputes the two store entries (ci-fast red at `f51f7c2`, §5 D20) |
| killers | `1be3f1d` | 9 store tests for the 43 missed mutants of the first run; 1 accepted row (`docs/mutants-accepted.md`, `wrap.rs:123:9`) |
| G7-00 | `eb9d3b8` | `COOLDOWN_EXCEPTIONS` = `&[]`; `cooldown_covers_m6_lock`/`_m7_lock` re-dictated; `expect::cooldown_exceptions_empty`; ADR-015 list (3) "expired 2026-10-30, entry removed (G7-00)" |

`Store::open(` callers (kat-only since `bd9e240`; `grep -rn "Store::open(" crates xtask` at `c3c1dcf`, 50 lines): `secmp-store/src` (the
definition, its doc and the test modules of `store`, `schema`, `migrate`, `messages`, `delete`, `sessions`, `outbox`, `profile`,
`backup`, `lib`), `secmp-client-core/src/outbox.rs:247` and `persist.rs:418` (both in `#[cfg(test)] mod tests`),
`secmp-testkit/tests/harness/m7_persist.rs:68` and `m7_forensic.rs` (harness, feature `harness` ⊃ `secmp-store/kat`). The
workspace builds without `kat` (`cargo build --workspace --all-targets`). The A-3 tests are unchanged: `kat::TestKey`,
`Store::open(dir, &DbKey)`, `DbKey::from_bytes` (now with the nine `K_t` from `kat::TEST_MK`), `key_statement`.

## 3. Evidence per acceptance criterion

Phase A, A-1 (numbers; raw files under `docs/reviews/M07-evidence/`). Phase B/C rows: not yet built; A-2…A-4 rows below. (Superseded: the Phase B and C rows were built later; the Phase C rows and their evidence are in `## Phase C close (M7-C5)`, followed by `## S-1`, `## S-2`, `## S-2b` and `## D-11`.)

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
| G7-00 | see A-4 below | landed @ `eb9d3b8` |
| G7-01 | `xtask::expect::normal_dependency_allow_m7`; `policy::tests::normal_dependencies_match_adr_allowlist` | red first (rows missing): `left: []  right: ["rusqlite", "secmp-crypto", "secmp-proto"]`; then pass |
| G7-02 | `xtask::gates::tests::vet_records_for_m7_closure`; `cargo vet --locked` | pass; `Vetting Succeeded (241 fully audited, 2 partially audited, 322 exempted)`; `vet` step: 60 external crates in the crypto/proto closure, 0 exempted (`vet-m7-a2.txt`). **Deviation from the weisung, §5:** `password-hash` 0.6.1 and `phc` 0.6.1 are in the closure of the zero-exemption gate (the first run of the test: `vet exemption inside the crypto/proto closure: password-hash@0.6.1; … phc@0.6.1`), so they carry publisher trust (`github:RustCrypto/traits`, `github:RustCrypto/formats`, provisional, Q129; their notes say that the implementer read no code of them — none is compiled) instead of the tracked exemptions the weisung names |
| G7-03 | `xtask::gates::tests::licenses_cover_m7_closure`; step `deny` | pass; `advisories, bans, licenses, sources: ok` (`deny-m7-a2.txt`); `deny.toml` unchanged |
| G7-04 | `xtask::cooldown::tests::cooldown_covers_m7_lock`; step `cooldown` | pass; 567 registry packages ≥ 7 days; youngest of the lock `rustls-webpki` 0.103.16, 8 days; youngest new entry `argon2` 0.6.0, 60 days (`cooldown-m7-a2.txt`); `COOLDOWN_EXCEPTIONS` unchanged |
| ST-08 | `secmp-crypto::argon2::tests::rfc9106_argon2id_vector` | pass: RFC 9106 §5.3 tag `0d640df5…6b01e659` byte-exact; extra tests `argon2id_rejects_out_of_range_params`, `argon2id_is_the_empty_secret_and_ad_case_and_every_input_counts`; local mutants on `argon2.rs`: 13 mutants, 1 caught, 12 unviable, 0 missed. Under Miri (nightly-2026-09-21, aarch64-unknown-linux-gnu, portable libcrux): the three tests pass; `rfc9106_argon2id_vector` alone ≈ 105 s host wall time, 271 s libtest virtual time for the pair; **no `MIRI_SKIP` entry added** — the 60-s rule of M3 is `secmp-proto`'s and `argon2` has `unsafe` the test reaches (§8 Q-A4) |

Phase A, A-3 (times: `ci-fast-a3l-06c28ec.txt`; every row under its TEST-SPEC name):

| Row | Test | Result |
|---|---|---|
| G7-06 | `xtask::gates::tests::kani_build_has_no_store` | pass (3.0 s); with `--cfg kani` no `secmp-store v`/`rusqlite v`/`openssl-src v` line, the control has all three (`g7-06-b4b99db.txt`); `kani-codegen-g7-06-b4b99db.txt`: `grep -c openssl-src` = 0, `grep -c -e secmp-store -e secmp_store` = 0. Red first: `negative control lacks openssl-src v` with `-e normal` (§5 D1). ADR-051 table: no third-party change (workspace edges only) |
| ST-01 | `store::tests::create_sets_pragmas` | pass (0.08 s) |
| ST-02 | `store::tests::refuses_older_cipher_version`; extra `xtask::expect::tests::sqlcipher_min_matches_store` | pass; `4.9.4` → `Unsupported`, `4.10.0`/`4.10.1` → Ok; build `PRAGMA cipher_version` = `4.10.0 community` |
| ST-03 | `store::tests::no_temp_files_anywhere` | pass (0.15 s; child with `TMPDIR`, 2 000 inserts, `ORDER BY` over 10 000 rows, `VACUUM`) |
| ST-04 | `store::tests::wrong_key_cannot_open` | pass; no key and one bit off → `Unlock`, file SHA-256 unchanged |
| ST-09 | `xtask::testscan::kat_argon2_params_only_with_kat` | pass (2.4 s); kat_small: 0 sites (A-4); scanner fixture finds the ungated line only |
| ST-13 | `schema::tests::tables_match_docs_02` | pass |
| ST-14 | `migrate::tests::fresh_reopen_and_too_new` | pass |
| ST-15 | `migrate::tests::migration_is_atomic` | pass (0.9 s) |
| ST-16 | `delete::tests::secure_delete_removes_message` | pass; path: `sqlcipher_export` (no `sqlite_dbpage` in the build, asserted) with a positive control before the delete |
| ST-17 | `messages::tests::view_once_never_written` | **partial (store half) — B completes** (§8) |
| ST-18 | `messages::tests::expire_after_deletes` | pass |
| ST-20 | `secmp_store::tests::open_sets_defensive_mode` | pass; `set_db_config` needed no feature |
| PC-01 | `persist::tests::store_persist_is_durable` | pass (0.4 s; child aborts after `commit(Send, S1)`) |
| PC-02 | `persist::tests::failed_commit_changes_nothing` | pass (§5 D5) |
| PC-03 | `harness::m7_persist::persist_before_send_by_construction`; doc test `scheduler::types::PreparedCell` (`compile_fail,E0451`) | pass (3.2 s; ≥ 195 SEND frames, each after ≥ j durable commits) |
| PC-04 | `harness::m7_persist::persist_before_ack_by_construction` | pass (3.0 s; ≥ 195 fetches checked, ≥ 150 non-zero acks, every injected cell decided once) |
| PC-05 | `harness::m7_crash::crash_between_persist_and_send_no_key_reuse` | pass (383 s in ci-fast, 244 s alone); `pc-05-key-digests-0c448f0.txt` and `-06c28ec.txt`: distinct/total **6076/6076**, duplicates 0, per crash point 1200/1220/1216/1220/1220; every message exactly once. Negative controls (not committed): without `seed_seen` → `b delivered again what its history held`; life 2 from the initial state → `a message key sealed two released cells` |
| PC-06 | `persist::tests::prop_store_matches_mem_model` | pass (2.8 s; 3 × 150 seeded steps, `DEFAULT_SEED` 0x5ec32d0000000701) |
| PC-07 | `persist::tests::incremental_rows_per_slot` | pass (0.9 s; §5 D4) |
| PC-08 | `persist::tests::prop_parts_reassemble_to_state` | pass (8.1 s; 2 seeded runs × 300 messages) |
| PC-09 | `persist::tests::ratchet_inbox_trust_one_commit` | pass (1.0 s; k = 1…5 all old, after the commit all new) |
| PC-10 | `outbox::tests::store_outbox_survives_restart` | pass |
| PC-11 | `outbox::tests::never_relayed_30_days_fails` | pass |
| PC-12 | `xtask::testscan::scheduler_sees_only_traits` | pass; red first (a `// secmp_store` line appended to `scheduler/types.rs`): `the scheduler names the store: ["crates/secmp-client-core/src/scheduler/types.rs:258: // secmp_store"]` |
| PC-13 | `harness::m7_persist::write_amplification_measured` | pass (385 s in ci-fast, 295 s alone); `pc-13-write-amplification-06c28ec.txt`: **142 135 880 bytes/day**, 34 495 commits/day, 17 250 send slots, **8 239 bytes/dummy slot** (sender + receiver commit) ≤ bound 2 × (3 767 + 1 782) = 11 098 |
| G7-18 | `secmp-proto::tr::state::tests::ratchet_state_v1_layout_unchanged` | pass (0.35 s; 96 events, 192 states); red first (`RatchetParts::to_bytes` without `count`): FAIL; `git diff bf55099..HEAD -- vectors/`: empty (0 lines) |
| G7-13 | `xtask::expect::tests::mutants_scope_includes_store`; re-dictated `gates::tests::mutants_scope_includes_client_core_and_transport` | pass; red first (`secmp-store` removed): `left: Some("secmp-transport") right: Some("secmp-store")`; `mutants-secmp-store-a3-365a3da.txt`: **175 caught / 3 missed / 42 unviable / 0 timeouts of 220 (79.5 %)**, the 3 missed documented as equivalent |
| G7-14 | `xtask::expect::tests::coverage_store_90`; re-dictated `gates::tests::coverage_strict_includes_client_core` | pass; red first: `left: Some("secmp-client-core") right: Some("secmp-store")`; `coverage-a3-7ee87a2.txt`: secmp-store **94.3 %** (1476/1566), client-core 94.5 %, crypto 99.3 %, proto 97.5 % |

Extra tests of A-3 (not rows): `xtask::expect::tests::sqlcipher_min_matches_store`; store (G7-13 mutants):
`sessions::tests::{session_rows_round_trip, delivered_history_dedups}`, `outbox::tests::outbox_rows_round_trip`,
`store::tests::{raw_key_pragma_value, crash_points_fire_where_armed, write_measurement_counts_committed_log_bytes,
tx_query_row_reads_inside_the_transaction}`, `messages::tests::{retention_setting_days_or_keep,
view_once_lookups_by_id_and_direction}`, `delete::tests::delete_reports_presence`, `error::tests::errors_display_fixed_text`,
`kat::tests::{temp_dir_removed_on_drop, scan_finds_raw_and_printable_substrings}` (14). Changed existing tests: `expect::normal_dependency_allow_m7`,
`cooldown::tests::cooldown_covers_m7_lock` (§1 re-dictations); `m6_outbox::outbox_is_the_store_boundary` (§5 D2);
`m6_sched_io::persist_before_send_order` (an `Audit::Decided` arm) and its fake source (`PreparedCell::unpersisted_kat`), as
`fuzz/fuzz_targets/scheduler_event_sequence.rs`; `testscan::scan::tests::{pr_ci_runs_props_with_ci_run_seed,
the_seed_scan_flags_each_rule}` (`secmp-client-core` is a property package); the floor/merge fixtures of
`gates::tests::{mutants_floor_fails_a_package_without_a_caught_mutant, mutants_merge_fails_when_the_caught_share_is_below_half,
mutants_merge_passes_the_crypto_tally_of_run_37127247911, mutants_merge_reports_every_shard_and_package_before_it_fails}` carry a
`secmp-store` tally (the other packages' expectations unchanged).

A-3b/A-3d/A-3e (WEISUNGEN M7-A3b, -A3d, -A3e; `modell=claude-opus-5-5`): §1, §2/§2′/§2″, §3–§6 done:

| Item | Test | Result |
|---|---|---|
| V1-F1 | extra `persist::tests::entry_keys_are_zeroizing_secrets` | pass; red first (unfixed tree): `error[E0425]: cannot find type EntryKey in module super` (persist.rs:272) |
| V1-F2 | `sessions::tests::open_reads_no_message_keys`; extra `persist::tests::open_reads_no_message_keys` | pass; red first of the extra test (`StorePersist::open`/`load_inbox_trust` still on `session_rows`): `assertion left == right failed, left: 7670, right: 0` (persist.rs:1023); the store test's 0s hold by construction, its oracle the 36-byte key length |
| V1-F3 | `store::tests::key_pragma_order_and_zeroizing` | pass; red first: `error[E0425]: cannot find function open_steps in module crate::kat`, `error[E0599]: no method named key_statement found for struct store::DbKey`; ST-01 still reads `cipher_memory_security` = 1 (no D11) |
| V1-F7 | extra `xtask::testscan::kat_mod_declaration_matches_crlf` | pass; red first (helper without normalising): `assertion failed: declares_kat_module(&lf.replace('\n', "\r\n"))` |
| §1 gate | `cargo xtask ci-fast` at `7c927a6` (`ci-fast-a3b-1-7c927a6.txt`) | PASS: kat 119 s, harness 945 s |
| K7-03 (Q135, Q137, Q138) | the six split harnesses, each alone: `kani-m7-a3b-split-150d997.txt` (unwind 6 everywhere: STOP of A-3b), `kani-m7-a3d-tr-25e9f38.txt` (Q137 bounds, not committed: STOP of A-3d), `kani-m7-a3e-tr-8ce73d9.txt` (Q138) | q_frame `_request` 7.1 %, `_response_fetch` 59.2 %, `_response_fetch_multi` 65.6 % (each 1 of 1 cover); Q138 bounds: `tr_header_selection_k0_2` unwind 5 57.7 %, `_k3` unwind 5 57.9 %, `_k4` unwind 6 96.3 % (exception Q138) — each SUCCESSFUL, 6/6 unwinding assertions SUCCESS; full step `kani-m7-a3e-full-c276c37.txt`: 51/51, `_k4` 94.0 % |
| V1-F4 | `sessions::tests::delivered_message_expires`; extra `persist::tests::commit_parts_delivered_message_expires`, `scheduler::conversation::tests::delivered_carries_unix_ms` | pass; red first (insert without `ts_ms`/`expire_at_ms`): `assertion left == right failed, left: 0, right: 1` (sessions.rs:362), the persist twin likewise (persist.rs:1066); `delivered_carries_unix_ms` red by construction (no `received_ms` on the unfixed tree) |
| V1-F10 | `outbox::tests::store_outbox_view_once_reported_lost` (PC-10, kind 3) | pass; red first (no `queue_view_once`): `left: [], right: [[51; 16]]` (outbox.rs:360) |
| V1-F13 (Q-A14) | ST-01 `store::tests::create_sets_pragmas` += `synchronous` = 2; `key_pragma_order_and_zeroizing` += step `synchronous` | pass; **not red** without the pragma: the bundled SQLite's default is already `synchronous` = 2 (FULL); the explicit pragma and the assertion pin it against a change of the default |
| V1-F15 | extra `kat::tests::temp_dirs_distinct_across_threads` | pass; red first (per-thread counter): `assertion left != right failed`, both `…/same-label-<pid>-0` (kat.rs:457) |
| V1-F8, V1-F11 | PC-13 `commits >= slots`, `per_slot >= 4 096`; PC-05 duplicate check of life 1 | pass (`pc-13-write-amplification-675bad6.txt`: WAL bytes/day 142 135 880, 8 239 bytes/dummy slot ≤ 11 098; `pc-05-key-digests-675bad6.txt`: 6076/6076, 0 duplicates) |
| Q-A15 ST-16 | `delete::tests::secure_delete_removes_message` (name unchanged) | pass: D3 path + plaintext control — on unkeyed profiles, after delete and `wal_checkpoint(TRUNCATE)`, the canary is absent from raw `profile.db` + `-wal` with `secure_delete` and **present** after `PRAGMA secure_delete = OFF` |
| Q-A16 ST-03 | `store::tests::no_temp_files_anywhere` (name unchanged) | pass: child env `TMPDIR`/`TMP`/`TEMP`; a 20 000-row `randomblob(512)` temp table: 0 descriptors into `TMPDIR` (Linux); control child `st03-control` (`temp_store = FILE`): ≥ 1 descriptor, first try with 20 000 rows |
| V2-1 | killers `outbox::tests::{store_outbox_restores_every_field, store_outbox_counts_refused_writes, store_outbox_writes_only_changes, store_outbox_restart_requeues_in_flight}`, `persist::tests::{entry_key_zeroize_and_holds, load_and_delivered_ids_read_back, decrypt_crash_point_only_on_receive, trust_codes_are_fixed, default_commit_parts_commits_the_joined_state}`, `scheduler::conversation::tests::{receive_commit_carries_inbox_only_while_fragmented, seed_seen_suppresses_redelivery}`, `secmp-proto tr::state::tests::ratchet_parts_to_bytes_refuses_each_bad_shape` | pass; each kills its mutant (`mutants-a3b-core-proto-store-cdc3c0a.txt`: every first-run survivor caught in the rerun); red of the proto killer on its mutant: `assertion left == right failed: an entry of 67 bytes, left: None` |

Extra tests of A-1 (not rows of TEST-SPEC-M7): `xtask::ctreport::tests::informative_targets_per_target_set`;
`xtask::testscan::scan::tests` helper `check_harness_invocations` (inside `pr_ci_runs_props_with_ci_run_seed`);
`xtask::gates::tests::kani_rss_guard`, `kani_rss_guard_fails_closed_without_ps_sample`,
`kani_rss_guard_requires_a_peak_per_checked_harness`; `xtask::policy::tests::xwin_full_roots_have_no_excluded_dev_dependency`;
harness `m6_activity::timing_draws_unmoved_by_one_hour_of_activity`, `m6_sched_life::relay_idle_and_age_bounds_defaults`
(short forms). Changed existing tests: `ctreport::tests::informative_targets_are_pinned_printed_and_never_fail`,
`gates::tests::deleting_or_neutering_a_pinned_job_is_a_finding` (harness variants), `required_jobs_keep_their_pinned_conditions`
(14 jobs), `testscan::scan::tests::nextest_does_not_run_the_harness_binary_twice`.

Phase A, A-4 (times: `ci-fast-a4-6-4383c8a.txt`; red-first lines: `redfirst-a4-1efe9b6.txt`, the two red ci-fast files, `target/m7draft/a4-red.txt` for §1/§2):

| Row | Test | Result |
|---|---|---|
| §1 labels | `secmp-crypto label::tests::enum_equals_appendix_a_of_the_spec`, `label_set_is_prefix_free` | pass (53 labels, 0 prefix pairs); red first (Appendix A without the four rev-2.7 labels): `Appendix A should list 49 labels … left: 53, right: 49` (`label.rs:264`; `a4-red-first.txt`) |
| §2 F3 | extra `argon2::tests::block_matrix_is_zeroizing`; ST-08 `rfc9106_argon2id_vector` | pass; red first (the scan on the unfixed file): `the call without the matrix, left: 1, right: 0` (`argon2.rs:184`; `a4-red-first.txt`) |
| §2 overloads | extra `argon2::tests::locked_output_equals_argon2id`, `kdf::tests::hkdf_locked_equals_hkdf`, `caead::tests::locked_key_forms_equal_seal_and_open` | pass (each equal to the existing primitive on the same bytes) |
| ST-05 | `wrap::tests::unlock_roundtrip` | pass (0.007 s, `kat_small`); same `MK_profile` digest after unlock(P); P with its last byte flipped → `Err(Unlock)` |
| ST-06 | `wrap::tests::unlock_errors_are_uniform` | pass; the eight cases (wrong P, truncated, flipped salt, flipped tag, version, m = 4 194 304, t = 4, p = 1) one `Error::Unlock`, equal `Debug`; `argon2_calls` = 0 for the version and the three `params` cases (shipped `wrap::unlock`, accept = `PROFILE`) |
| ST-06 extra | `wrap::tests::unlock_error_text_is_fixed` | pass; the text of `error.rs:27` for every case; scan of `crates/secmp-store/src` (CRLF-normalised, test modules excluded): 0 `{e}`, `{e:?}`, `{:?}`, `.to_string()` |
| ST-07 | `wrap::tests::argon2_params_are_cs_3_2` | pass (1.29 s); `PROFILE` = (262 144, 3, 4), block `00 04 00 00 00 00 00 03 00 00 00 04` at wrap offset 17..29; **one `PROFILE` wrap: create 553 ms** (`st-07-wrap-create-5d44443.txt`, measured by ci-fast at `5d44443`; A-4 report: 523 ms / 485 ms, not retained) |
| ST-10 | `keys::tests::table_keys_match_vectors` | pass; nine `K_t` pairwise distinct, `K_db` distinct from each, each equal to `secmp_crypto::hkdf` (salt 0^32, App. A label) for MK = 32 × 0x4d. **[REF] closed by M7-VEC1: byte-exact against `vectors/store.json`** |
| ST-19 | `secrets::tests::long_lived_keys_in_secret_pages` | pass; `fn locked<const N>(_: &LockedSecret<N>)` on `mk_kat`, `db_kat`, every `table_key_kat`, `kek_kat`; IKS types hold `LockedSecret` (`ed25519.rs:115`, `mldsa.rs:28`, `x25519.rs:19`); `live_key_pages()` = 0 after `lock()` |
| CT-02 | `wrap::tests::unlock_work_is_outcome_independent` | pass; right, wrong, empty, prefix-sharing, one-byte-longer: `argon2_calls` = 1 and `caead_open_calls` = 1 each; the four failures one `Error::Unlock` |
| ST-11 | `seal::tests::record_bound_to_table_and_row` | pass; Ok only for (`sessions`, `data`, (7, 0, 0)); (8, 0, 0), `outbox` `[7; 16]`, column `skey`, flipped `COM`, flipped tag → one `Unavailable`; row keys 24 B / 17 B |
| ST-12 | `schema::tests::secret_columns_are_sealed` | pass; populated profile (identity, 3 prekey generations × 3 kinds, 2 contacts, 2 sessions, outbox, 1 invitation, relay access key): 23 cells in the seven Q139 columns, each `len = plaintext + 72`, no plaintext and no 8-byte prefix inside |
| PC-13 (+72 B) | `harness::m7_persist::write_amplification_measured` (A-3 test, unchanged) | pass: 8 241 bytes/dummy slot ≤ 11 098 (`pc-13-write-amplification-5d44443.txt`, ci-fast at `5d44443`; A-4 report: 8 241 B at b014540, not retained; A-3: 8 239 B at 675bad6) (the unchanged A-3 bound; with +72 B per sealed record the weisung's bound is 11 098 + 4 × 72 = 11 386) |
| CT-01 | ct target `store_unlock_reject` (`ct-m7-a4-4b0ffaf.txt`) | **PASS** (run PASS, every control PASS, sensitivity CAUGHT); 100 000 samples, k = 1, 63.6 µs per call; first max \|t\| 2.46 at p99 (Δ +153.39 ticks = 38.3 ns, below the threshold 4.5, not reproduced: second p99 Δ +22.21 t +0.35), second max \|t\| 0.52 at p95 (Δ +13.03 ticks), A/A 2.28 at p75 (Δ −13.73 ticks); floor 40 ticks = 10 ns; site `wrap: open`, pre-check `Err(Unlock)` both classes, twin `Ok` |
| CT-01 (Q140) | informative `store_unwrap_reject_post_kdf` | no verdict; first p90 Δ +1.04 t +6.47, p95 +1.19 / +6.82; second p90 +1.20 / +7.43, p95 +1.56 / +8.66 (ticks of 0.25 ns: ≤ 0.4 ns, 0.04 floors) |
| CT-05 | `xtask::expect::ct_targets_m7`; `gates::tests::ct_targets_unchanged_in_m6` (`[..26]`), `ct_target_sites_bind_each_target_to_its_site` (12), `known_sites_equal_the_product_site_tags` (walks `secmp-store/src`), `ctreport::tests::ct_targets_list_names_m5_targets` (M4 + 6 + 1, last `store_unlock_reject`), `informative_targets_are_pinned_printed_and_never_fail` (3 names), `informative_targets_per_target_set` | pass; red first: `ct_targets_m7` with `CT_TARGETS` of 26 → `left: 26 right: 27` (`expect.rs:2114`); `known_sites_equal_the_product_site_tags` without the store walk → the tag set lacks `"wrap: open"` (`gates.rs:9766`) |
| FO-03 | `harness::m7_forensic::export_file_has_no_plaintext` | pass (0.09 s); 1 file scanned; 26 needles (message text ASCII and UTF-16LE, display name, own name, both fingerprints raw/lower/upper hex, 6 `IKSPublic` components, `link_key`, 3 identity seeds, passphrase); 0 hits raw or in printable runs (substring ≥ 8 B) |
| BK-01 | `backup::tests::contents_whitelist` | pass (0.14 s); magic, count 4, tags 1–4; identity 97 B; contacts (`IKSPublic`, verified, `Bobby`/empty, `Profile`), settings (2), messages (in/out with `ts_ms`, `expire_after`) |
| BK-02 | `backup::tests::no_ratchet_material` | pass (0.33 s); no 16-byte window of 11 secrets (2 fixed parts, 2 skipped entries, reassembly state, SPK/OPK/RPK seeds, unsent payload, relay access key, invitation record) in the decrypted body |
| BK-03 | `backup::tests::restore_requires_reinvite` | **partial (store half) — B completes**: contacts `STATE_REINVITE_REQUIRED`, 0 rows in sessions/prekeys/outbox/relays/invitations, identity and messages restored, a non-empty store refused; `Api.send` and prekey generation are Phase B |
| BK-04 | `backup::tests::wrapping_and_header_kat` | pass; fixed salt/`MK_bk`/`N'`/`N` (kat entropy, `kat_small`): magic 0..13, ver 13, salt 14..30, params 30..42, `N'` 42..66, bwrap seal 66..146, `N` 167..191, header 154 B; `bwrap` and the body seal equal the item-6 compositions recomputed from `argon2id`, `hkdf`, `Caead::seal`; wrong passphrase → `Err(Unlock)`. **[REF] closed by M7-VEC1: byte-exact against `vectors/store.json`** |
| BK-05 | `backup::tests::import_rejects_malformed` | pass; wrong version, truncated, trailing byte, section twice (correctly sealed), wrong magic, wrong passphrase, unknown contact index (correctly sealed): each `Err(Unlock)`, equal `Debug`, 0 rows written |
| BK-05 extra | `backup::tests::no_view_once_in_export` | pass; a held received and a queued view-once with canaries: no kind-3 record, no canary in the body |
| BK-06 | `backup::tests::explicit_never_cloud` | pass (1.2 s, `PROFILE`); `confirm = false` → `ConfirmRequired` with the CS-3.5 warning text (also on a cloud path); `…/OneDrive/…` → `CloudFolder`; every `CLOUD_FOLDERS` entry in three cases; `OneDriveX` not; with `force` the file opens; nothing written by a refusal |
| BK-07 | `backup::tests::never_automatic` | pass; > 100 product files of `crates/*/src` scanned, 0 lines naming `backup::export` (allowed set: `secmp-client-core/src/api.rs`, Phase B) |
| FZ-01 | fuzz `backup_import` (`fuzz-m7-a4-f51f7c2.txt`) | 175 212 runs in 121 s, 0 crashes; final `cov: 2159 ft: 3783 corp: 223/210Kb lim: 2615` |
| FZ-02 | fuzz `store_record_open` | 181 646 runs in 121 s, 0 crashes; final `cov: 904 ft: 2457 corp: 115/13299b lim: 1235` |
| G7-15a | `xtask::expect::tests::fuzz_targets_store`; `gates::tests::fuzz_executor_depth`, `nightly_budget_per_target`; `secmp-proto` `fuzz_max_len_is_the_largest_valid_input_plus_one` | pass; red first: `fuzz_targets_store` without `backup_import` → `left: 34 right: 35` (`expect.rs:2260`); `fuzz_max_len` before `4383c8a` → `left: 35 right: 33` (`ci-fast-a4-6-f51f7c2-red.txt`) |
| ST-09 (re-dictated) | `xtask::testscan::kat_argon2_params_only_with_kat` | pass (2.4 s), `kat_small` one site; red first with the A-3 expectation: `kat_small: 0 sites in A-3 (A-4) left: 1 right: 0` (`testscan.rs:456`) |
| G7-00 | `xtask::expect::cooldown_exceptions_empty`; `cooldown::tests::cooldown_covers_m6_lock`, `cooldown_covers_m7_lock` | pass; red first (the `ctutils` entry still listed): `expect::cooldown_exceptions_empty` panicked at `expect.rs:2113` (`g700-red-eb9d3b8.txt`); `cooldown` step: 567 packages, no exception, youngest `ctutils` 0.4.4, 7 days (`ci-fast-a4-l-eb9d3b8.txt`, `ci-full-a4-c3c1dcf.txt`) |

## 4. Gates

| Gate | Result |
|---|---|
| PR run 41293668505 on `9b511a2` (Draft-PR #15) | main jobs green; mutants-shards 1, 2, 8 red with one undocumented survivor each: `secmp-client-core/src/testutil.rs:23:22`, `:26:71`, `:199:64` (Q20 trap: `cfg(all(test, feature = "kat"))`); shard 9 red, cause not yet read, re-run on the next push. Fix Q198 (`mutants-list-testutil-07ad07c.txt`: 30 → 0; `mutants-list-proto-cfg-07ad07c.txt`: 268 → 268, none inside the split modules; `ci-fast-ci2-07ad07c.txt` PASS) |
| PR run 42768313638 on `331723c` (CI3) | all jobs green except **windows-native** (`nextest`, `kat`: `profile::tests::open_wrong_passphrase_uniform`, `Os { code: 33 }` on `profile.db-shm`; the `VirtualLock() … 1453` lines are the runner's working-set quota, a warning) and **mutants** shards 0/2/3/7/8 (6 survivors: `run.rs:881:34`, `:1081:54`, `wrap.rs:134:9` = rows 891/1091/133 drifted by B-4c; `actor.rs:557 set_peer` and `sessions/mod.rs:73 accept_key_change` deleted by B-4d (C1-4b, no longer in `cargo mutants --list`); `actor.rs mark_reset → ()` (Q210b) without a killer). Shard 9 green (the 41293668505 red was runner variance). Floors held (core 79.8 %, store 70.9 %). Fixes: `tree_hash` skips `-shm` (D-CI4); three rows re-pinned (`mutants-list-ci3-def9d8b.txt`); killer `sessions::tests::mark_reset_blocks_the_session_and_persists` (`cargo mutants … --re mark_reset --test-tool nextest`: `actor.rs:567:9: replace Conversation<O, P, S>::mark_reset with ()` caught; plain `cargo test` baseline fails in an unmutated tree (19 tests; the cause was not investigated), so nextest was used locally; the CI gate runs the client-core mutants with `--test-tool nextest --features harness` (`xtask/src/gates.rs:1462-1500`), so this is not a CI path) |
| PR run 42873145127 on `8f4bcbd` (CI4) | **windows-native** red (`nextest`, `kat`: `profile::tests::open_wrong_passphrase_uniform`, `Os { code: 33 }` — the read of the held `lock` file, first in sorted order; the `-shm` exclusion of CI3 was necessary but not the cause); every other job green, mutants shards 0–11 all success (run completed 22:43 UTC; `ci-verdict` red only as the consequence of windows-native). Fix: `tree_hash` hashes `lock` by name + length 0, fs errors name their path (Q228, D-CI5); new tests `tree_hash_covers_persistent_bytes`, `held_profile_lock_refuses_reads_on_windows`; `delete.rs` reads fail loudly (`ci4-red-first.txt`, `ci-fast-ci4-f66eb73.txt`) |
| PR run 43033287006 on `88caecb` (B-4f3) | **linux-fast** (job 130565533490) and **linux-full** (job 130565533594) red: `secret_page::tests::guard_pages_and_locking_as_seen_by_the_os` at `unix.rs:228:13`, `MemfdSecret: VmFlags " rd wr sh mr mw ms dc dd sd " lacks lo` (runner image ubuntu-26.04, Version 20261101.186.1; fix Q232, ADR-059, §MEM1); **xwin-cross** (job 130565533165) red at the apt step, `Temporary failure resolving` (runner DNS, infrastructure; no change); `ci-verdict` red as the consequence. **windows-native** (job 130565533690) success: `open_wrong_passphrase_uniform` and `held_profile_lock_refuses_reads_on_windows` PASS, 0 lines `code: 33`, 1444/1444 (the D-CI5 proof); mutants shards 0–11 success (§CI5, §DOCS2) |
| PR run 43083238010 on `9589530` (MEM1) | **mutants-shard (4)** red: `FAIL [8] mutants: mutants: timeout, killed after 16800 s; last line: Error: interrupted` after 450 of 458 mutants (8 `secmp-transport` mutants not reached); the other 11 shards success; merge `mutants shard 4/12: FAIL — 450 mutants`, 20 survivors documented, 0 undocumented. Same mutants as shard 4 of PR run 43033287006 on `88caecb` (success), on a slower host. Fix: 24 shards (Q234, ADR-047 Amendment 11, §CI5). **ct** (job 130740933385) red only at the artifact upload (`Failed to CreateArtifact … not valid JSON` after 5 attempts; the ct step reported `step: PASS`; CI infrastructure, no change). `linux-fast` (job 130740933493) and `linux-full` success with the Q232 test; `xwin-cross` success (§DOCS2) |
| PR run 43137870981 on `ab3280b` (CI5) | **every job green** (conclusion success), the first such PR run after run 42873145127 (`8f4bcbd`; runs 43033287006 and 43083238010 red): all 24 `mutants-shard (k)` success, longest shard 16 about 2 h 58 min job wall time; `mutants` (merge), `linux-fast`, `linux-full`, `ct`, `ci-verdict` success. Closes D-B70 and D-CI8 (§DOCS2) |
| PR run 43299417039 on `d0ea52d` (B-4g) | **every job green** (36 jobs, conclusion success, `ci-verdict` 2026-11-12 23:38:18 UTC), the first PR run with ADR-047 Amendment 12: all 24 `mutants-shard (k)` success; `mutants` (merge) with the inventory check green 23:33:54–23:34:35 UTC. M (`core/mod.rs:860:30`, `World::step_due`) caught after 41 s build + 690 s test (shard 14), S (`core/mod.rs:1907:33`, `Scheduler::next_deadline`) after 34 s build + 863 s test (shard 17). Closes D-CI9 (§DOCS3) |
| PR run 43385042727 on `a1de559` (B17a) | **mutants-shard (14)** red: `crates/secmp-client-core/src/scheduler/core/mod.rs:860:30: replace match guard now >= up.die_at with false in World::step_due` TIMEOUT (36 s build + 901 s test), one undocumented survivor; `mutants` (merge) and `ci-verdict` red as the consequence; every other job green. The same mutant was caught in PR run 43299417039 (`d0ea52d`) after 690 s of test time. Fix §CI7 (Q243, D-CI10) |
| PR run 43417767896 on `85a589a` (B22) | conclusion success (created 2026-11-13 11:31:38 UTC). Head before the CI7 killers (`919da9e`): M caught after 38 s build + 682 s test (shard 2), S after 54 s build + 611 s test (shard 5); not a proof of D-CI10 (§DOCS3) |
| PR run 43474391164 on `23b7424` (CI7) | completed, conclusion success (created 2026-11-13 17:36:01 UTC). Head contains the CI7 killers (`919da9e`): M (`core/mod.rs:860:30 … with false in World::step_due`) caught after 23 s build + 2 s test (shard 2), S (`core/mod.rs:1907:33: replace > with >= in Scheduler::next_deadline`) after 52 s build + 2 s test (shard 5); 0 TIMEOUT. Before the killers: M / S 690 s / 863 s of test time (run 43299417039), 901 s TIMEOUT / — (run 43385042727), 682 s / 611 s (run 43417767896). Closes D-CI10 (§DOCS4) |
| PR run 43539306737 on `d5dfdc7` (B17b-1) | **windows-native** red (job 132275850235): harness test `m7_activity::store_backed_source_activity_independent` panicked with `Unavailable` from `Profile::create_with` (`m7_world.rs:122`) amid 2283 `WARN MEMORY sqlcipher_mlock: VirtualLock() returned 0 LastError=1453` lines; `ci-verdict` (job 132337677919) red as the consequence; the other 34 jobs green, among them all 24 `mutants-shard (k)` and the `mutants` merge. Cause and fix §WIN1 (D-CI11, Q247, ADR-061); proof open until `windows-native` of the next PR run |
| PR run 43591576223 on `3f564f8` (WIN1) | completed, conclusion success, `ci-verdict` 2026-11-14 15:22:25 UTC, all 36 jobs green. `windows-native` (job 132437232187, 11:46:05–13:37:41 UTC) success: SE-19 `m7_activity::store_backed_source_activity_independent` PASS [949.210s] (296/296), `secret_page::os::tests::concurrent_locks_beyond_the_default_quota_all_succeed` PASS [0.027s], `secret_page::os::tests::every_lock_waits_for_the_growth_lock` PASS [0.214s], `secret_page::grow::tests` 10/10 PASS, workspace 1503/1503; 0 lines `VirtualLock`, `LastError=1453`, `sqlcipher_mlock`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at`, `##[error]` (nextest prints stderr only for failed tests, so 0 lines is no evidence that the warning is absent). Closes D-CI11 (§DOCS4); the 949 s of SE-19 is D-CI12 (open observation, §DOCS4) |
| PR run 43647712727 on `b5ec47a` (B17b-2) | completed, conclusion success, `ci-verdict` 2026-11-15 02:28:47–02:29:22 UTC, all 36 jobs success. `windows-native` (job 132609084725, 2026-11-14 22:22:03 UTC – 2026-11-15 00:19:51 UTC) success: SE-19 `m7_activity::store_backed_source_activity_independent` PASS [1132.569s] (296/296), `secret_page::os::tests::concurrent_locks_beyond_the_default_quota_all_succeed` PASS [0.028s], `secret_page::os::tests::every_lock_waits_for_the_growth_lock` PASS [0.248s], workspace 1516/1516 (2 leaky), harness summary 296 run: 296 passed (15 slow), 16 skipped (1482.254 s); 0 lines `LastError=1453`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at`, `##[error]`. Longest shard: `mutants-shard (1)`, 246 min (job 132609084843). The 1132 s of SE-19 is D-CI12 and the 246 min of the shard is D-CI13 (open observations, §DOCS5) |
| PR run 43668999495 on `467b769` (DOCS4; docs-only on `b5ec47a`) | completed, conclusion success, `ci-verdict` 2026-11-15 06:34:01–06:34:30 UTC, all 36 jobs success. `windows-native` (job 132674628908, 02:42:07–04:40:09 UTC) success: SE-19 `m7_activity::store_backed_source_activity_independent` PASS [1153.836s] (296/296), `secret_page::os::tests::concurrent_locks_beyond_the_default_quota_all_succeed` PASS [0.074s], `secret_page::os::tests::every_lock_waits_for_the_growth_lock` PASS [0.226s], workspace 1516/1516 (2 leaky), harness summary 296 run: 296 passed (15 slow), 16 skipped (1504.051 s); 0 lines `LastError=1453`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at`, `##[error]`. Longest shard: `mutants-shard (1)`, 231 min (job 132674629047). D-CI12 and D-CI13 (open observations, §DOCS5) |
| PR run 43706937667 on `194de59` (DOCS5; docs-only on `467b769`) | completed, conclusion success, `ci-verdict` 2026-11-15 14:51:48–14:52:17 UTC, all 36 jobs success. `windows-native` (job 132789937039, 11:02:13–13:01:16 UTC) success: SE-19 `m7_activity::store_backed_source_activity_independent` PASS [1099.062s] (296/296), `secret_page::os::tests::concurrent_locks_beyond_the_default_quota_all_succeed` PASS [0.034s], `secret_page::os::tests::every_lock_waits_for_the_growth_lock` PASS [0.214s], workspace 1516/1516 (2 leaky), harness summary 296 run: 296 passed (14 slow), 16 skipped (1449.333 s); 0 lines `LastError=1453`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at`, `##[error]`. Longest shard: `mutants-shard (1)`, 229 min (job 132789937270). D-CI12 (closed) and D-CI13 (open observation), §DOCS6 |
| PR run 43728831159 on `595eb14` (W, WIN2-DIAG; **diagnostic**, throw-away commit, Q260, D-CI14) | completed, conclusion success, `ci-verdict` 2026-11-15 19:05:15–19:05:45 UTC, all 36 jobs success. `windows-native` (job 132856553210, 15:15:15–17:14:00 UTC) success, with the nextest override `success-output = "final"` for four tests: SE-19 PASS [1174.054s] (296/296), harness summary 296 run: 296 passed (14 slow), 16 skipped (1522.374 s), step table clippy 632 s, nextest 1926 s, doctest 3 s, kat 2922 s, harness 1550 s, hello 0 s, all PASS; 0 fail lines in `windows-native` and in `harness`; 3005 lines `sqlcipher_mlock: VirtualLock() returned 0 LastError=1453` in `windows-native` (shown stderr of PC-13, SE-03 and SE-19: 814, 751 and 1440), none in `harness`. Longest shard: `mutants-shard (1)`, 229 min (job 132856553610). Evaluation of the `W2DIAG` lines: D-CI14, §DOCS6. The run measures an instrumented tree; it is not a gate result of a product head |
| PR run 43750760342 on `cf80a2f` (A, A/B; **diagnostic**, throw-away commit whose tree is the tree of `23b7424`, Q261, D-CI14) | completed, conclusion success, `ci-verdict` 2026-11-15 22:42:39–22:43:07 UTC, all 36 jobs success. `windows-native` (job 132923961894, 19:08:48–21:04:54 UTC) success: SE-19 PASS [1043.569s] (296/296), workspace 1485/1485 (2 leaky), harness summary 296 run: 296 passed (14 slow), 16 skipped (1390.968 s), step table clippy 644 s, nextest 1894 s, doctest 3 s, kat 2905 s, harness 1417 s, hello 0 s, all PASS; 0 lines `LastError=1453`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at`, `##[error]`; the two `secret_page::os::tests` of WIN1 are not in this tree (0 lines). Longest shard: `mutants-shard (1)`, 213 min (job 132923962133). Verdict: D-CI12 and D-CI14 closed as CI-environment observations, §DOCS6 |
| PR run 43785816858 on `5ee0669` (B17b-3) | completed, conclusion success, `ci-verdict` 2026-11-16 05:16:00–05:16:35 UTC, all 36 jobs success. `windows-native` (job 133033071692, 01:21:45–03:19:52 UTC) success; its test lines (SE-19, harness summary, step table) are not in the job lists of this unit and are not extracted. Longest shard: `mutants-shard (3)`, 234 min (job 133033071961). D-CI13 (open observation), §DOCS7 |
| PR run 43810117638 on `3bb0fc2` (DOCS6; docs-only on `5ee0669`) | completed, conclusion success, `ci-verdict` 2026-11-16 09:22:57–09:23:32 UTC, all 36 jobs success. `windows-native` (job 133109695013, 05:25:24–07:06:51 UTC) success; its test lines (SE-19, harness summary, step table) are not in the job lists of this unit and are not extracted. Longest shard: `mutants-shard (15)`, 237 min (job 133109695381). D-CI13 (open observation), §DOCS7 |
| PR run 43901117679 on `37abef9` (B17c) | completed, conclusion success, `ci-verdict` 2026-11-16 19:54:10–19:54:43 UTC, all 36 jobs success. `windows-native` (job 133417671345, 15:52:19–17:05:52 UTC) success; its test lines (SE-19, harness summary, step table) are not in the job lists of this unit and are not extracted. Longest shard: `mutants-shard (7)`, 241 min (job 133417671879). D-CI13 (open observation), §DOCS7 |
| `cargo xtask ci-fast` at `fa0adef` (`ci-fast-a1-fa0adef.txt`) | PASS: kat 93 s, harness 942 s |
| `cargo xtask ci-fast` at `62c2dbc` (`ci-fast-a1c-62c2dbc.txt`, first line names the head, clean tree) | PASS: fmt 0 s, clippy 0 s, policy 1 s, deny 1 s, vet 1 s, audit 2 s, cooldown 23 s (561 packages), nextest 16 s, doctest 1 s, hello 0 s, kat 89 s, harness 1023 s |
| `cargo xtask ci-fast` at `bf54d98` (`ci-fast-a2-bf54d98.txt`, first line names the head, clean tree) | PASS: fmt 1 s, clippy 0 s, policy 1 s, deny 1 s, vet 1 s, audit 1 s, cooldown 24 s, nextest 42 s, doctest 1 s, hello 2 s, kat 141 s, harness 862 s |
| `cargo xtask ci-fast` at `27bfce2` (`ci-fast-a3-fix-27bfce2.txt`, A-3 §0.1) | PASS: cooldown 26 s, nextest 20 s, kat 101 s, harness 889 s |
| `cargo xtask ci-fast` at `f5c099d` (`ci-fast-a3-g706-f5c099d-red.txt`) | **FAIL** harness 263 s: `m6_outbox::outbox_is_the_store_boundary` (the M6 pin "no store dependency"; fixed in `3064c74`, §5 D2) |
| `cargo xtask ci-fast` at `3064c74` (`ci-fast-a3-g706-3064c74.txt`) | PASS: cooldown 27 s, nextest 15 s, kat 89 s, harness 1022 s |
| `cargo xtask ci-fast` at `f6f68c1` (`ci-fast-a3a-f6f68c1.txt`, after §2) | PASS: cooldown 24 s, nextest 31 s, kat 108 s, harness 913 s |
| `cargo xtask ci-fast` at `0c448f0` (`ci-fast-a3b-0c448f0.txt`, after §3) | PASS: cooldown 25 s, nextest 16 s, kat 102 s, harness 1038 s |
| `cargo xtask ci-fast` at `06c28ec` (`ci-fast-a3l-06c28ec.txt`, after §4; code head `365a3da`) | PASS: fmt 1 s, clippy 0 s, policy 1 s, deny 0 s, vet 1 s, audit 1 s, cooldown 24 s, nextest 14 s, doctest 1 s, hello 0 s, kat 113 s, harness 926 s |
| `cargo xtask ci-full --strict` at `1f3129c` (code head `365a3da`; `ci-full-a3-1f3129c.txt`, head on line 1) with the linux-full delegations of `ci.yml` (`--delegated windows-native windows-cross mutants ct proverif-link --models tr`, the M6 precedent) | **PASS**, 3 h 27 min: fmt 1 s, clippy 0 s, policy 1 s, deny 0 s, vet 1 s, audit 2 s, cooldown 23 s, nextest 13 s, doctest 1 s, hello 0 s, kat 99 s, harness 1032 s, perf 10 s, fuzz 4135 s (33 targets, 120 s each), coverage 1007 s, miri 2350 s, kani 3591 s (47/47), proverif 143 s (`tr`), linux-target, ref-vectors (12 suites, 969 cases), sbom 15 s, systemd; repro STUB (M11); ct, mutants, proverif-link, windows-cross, windows-native DELEGATED. Run as a background task (one tool call is limited to 4 h) |
| `secmp-store` mutants (`mutants-secmp-store-a3-365a3da.txt`, `cargo mutants --no-shuffle -j 3 --package secmp-store --features kat`) | 220 mutants: **175 caught, 3 missed, 42 unviable, 0 timeouts (79.5 %)**; the earlier runs at `bc67679` (46.3 %) and `be0d82d` and the baseline failure at `04b9795` are in the file and §5 D8 |
| Coverage (`coverage-a3-7ee87a2.txt`, `cargo xtask step coverage`, code `365a3da`) | PASS: secmp-store 94.3 %, secmp-client-core 94.5 %, secmp-crypto 99.3 %, secmp-proto 97.5 %, secmp-relay 97.5 %, secmp-transport 89.8 %, secmp-testkit 93.6 %, secmp-sys-mem 95.3 % |
| Kani (`cargo xtask step kani`, foreground, 3679 s, `kani-m7-a1e-9eac343.txt`) | all harnesses verified (`secmp-client-core` 13/13, `secmp-proto` 31/31, `secmp-relay` 3/3); the step failed at the cover pin of the first split (Q133, §8 A1e). Re-run of the two split harnesses with the covers in the harnesses (`kani-m7-a1f-commit-accept-9eac343.txt`): see K7-02 and the peak table below |
| ct (full) | not run locally (delegated in ci-full) |
| `cargo xtask ci-fast` at `7c927a6` (`ci-fast-a3b-1-7c927a6.txt`, A-3b §1) | PASS: kat 119 s, harness 945 s |
| `cargo xtask step --strict kani` at `c276c37` (`kani-m7-a3e-full-c276c37.txt`) | PASS 3710 s, 51/51 |
| `cargo xtask ci-fast` at `675bad6` (`ci-fast-a3b-l-675bad6.txt`; code head `cdc3c0a`) | PASS: kat 122 s, harness 932 s (one run for §2″, §3, §4 and §6, §5 D13) |
| local mutants (`mutants-a3b-core-proto-store-cdc3c0a.txt`) | first runs: core 51 caught / 18 missed / 21 unviable; proto 13 / 1 / 7; store (new code) 83 / 0 / 44; after the killers (`cdc3c0a`): core 69 / 0 / 21 / 0 timeout, proto 14 / 0 / 7 / 0, store 83 / 0 / 44 / 0 |
| `cargo xtask ci-full --strict` at `dd92e5c` (code head `cdc3c0a`; `ci-full-a3b-dd92e5c.txt`, head on line 1, clean tree), A-3 delegations | **PASS**, 3 h 28 min: kat 99 s, harness 1053 s, perf 9 s, fuzz 4071 s (33 targets), coverage 1052 s (secmp-store 94.9 %, client-core 94.7 %, crypto 99.3 %, proto 97.6 %, relay 97.5 %, transport 89.8 %, testkit 93.6 %), miri 2342 s, kani 3642 s (51/51), proverif 142 s (`tr`), ref-vectors (12 suites, 969 cases), sbom, systemd; repro STUB; ct, mutants, proverif-link, windows-cross, windows-native DELEGATED |
| `cargo xtask ci-fast` at `45c3c3e` (`ci-fast-a4-0-45c3c3e.txt`, A-4 §0.1) · `c2ad056` (`-a4-1-`, §1) · `e9851d9` (`-a4-2-`, §2) | PASS each (`modell=claude-opus-5-5`) |
| `cargo xtask ci-fast` at `b014540` (`ci-fast-a4-3-b014540.txt`, §3) | PASS: cooldown 28 s, nextest 18 s, kat 117 s, harness 959 s |
| `cargo xtask ci-fast` at `0882c77` (`ci-fast-a4-4-0882c77-red.txt`) | **FAIL** clippy (`too_many_lines` 104/100, §5 D19); every other step PASS |
| `cargo xtask ci-fast` at `9ab5d5b` (`ci-fast-a4-4-9ab5d5b.txt`, §4 after FO-03) | PASS: cooldown 29 s, nextest 15 s, kat 100 s, harness 964 s |
| `cargo xtask ci-fast` at `f0a7802` (`ci-fast-a4-5-f0a7802.txt`, §5) | PASS: cooldown 24 s, nextest 24 s, kat 113 s, harness 1046 s |
| `cargo xtask ci-fast` at `f51f7c2` (`ci-fast-a4-6-f51f7c2-red.txt`) | **FAIL** nextest and kat: `secmp-proto` `fuzz_max_len_is_the_largest_valid_input_plus_one` `left: 35 right: 33` (§5 D20) |
| `cargo xtask ci-fast` at `4383c8a` (`ci-fast-a4-6-4383c8a.txt`, §6) | PASS: cooldown 25 s, nextest 14 s, kat 101 s, harness 1011 s |
| fuzz smoke at `f51f7c2` (`fuzz-m7-a4-f51f7c2.txt`, §5 D21) | `backup_import` 175 212 runs, `cov: 2159 ft: 3783`; `store_record_open` 181 646 runs, `cov: 904 ft: 2457`; 0 crashes; tracked corpora unchanged |
| `cargo xtask step ct` at `4b0ffaf` (`ct-m7-a4-4b0ffaf.txt`, 5806 s, unscaled) | **PASS**; every gated target PASS (`caead_derive`: SUB_FLOOR_SHIFT at p99, a passing verdict of a gated target, ct L144), controls PASS (A/A′, three same-content), sensitivity CAUGHT (Δ 108.91 / 113.32 ns, p75); `store_unlock_reject` PASS (table below) |
| local mutants (`mutants-a4-crypto-store-1be3f1d.txt`, first runs on `b697b7b`, diff `92b4404..`) | crypto (new code) 23 caught / 0 missed / 25 unviable / 0 timeout of 48; store (new code) first run 272 / 44 / 186 / 0 of 502, after the killers (`1be3f1d`) **315 / 1 / 186 / 0** — the 1 accepted (equivalent, `wrap.rs:123:9`) |
| coverage pre-check (`cargo xtask step coverage` at `57927cc`, `target/m7draft/coverage-a4-pre.log`, not committed) | PASS: secmp-store 96.3 % (3851/4001), secmp-crypto 99.4 % (2765/2783) |
| `cargo xtask ci-fast` at `eb9d3b8` (`ci-fast-a4-l-eb9d3b8.txt`; G7-00 and the last A-4 run, one run for the dictated `ci-fast-a4-g700` and `ci-fast-a4-l`, §5 D29) | PASS: cooldown 25 s (567 packages, no exception, youngest `ctutils` 0.4.4, 7 days), nextest 19 s, kat 106 s, harness 983 s |
| `cargo xtask ci-full --strict` at `c3c1dcf` (`ci-full-a4-c3c1dcf.txt`, head on line 1, clean tree; reduced to the summary form in A-4d2, D30), the A-3 delegations (`--delegated windows-native --delegated windows-cross --delegated mutants --delegated ct --delegated proverif-link --models tr`) | **PASS**, step times sum ≈ 3 h 33 min (summary table; the file carries no wall-clock timestamps): kat 100 s, harness 953 s, perf 9 s, fuzz 4294 s (35 targets), coverage 1109 s (**secmp-store 96.3 %** (3851/4001), **secmp-crypto 99.4 %** (2765/2783), client-core 94.7 %, proto 97.6 %, relay 97.5 %, transport 89.8 %, testkit 93.6 %), miri 2429 s, kani 3715 s (51/51; `tr_header_selection_k4` 13 315 156 KiB = 94.0 %, exception Q138; `kani_accept_opk_delete_only_on_success` 12 422 268 KiB = 87.7 %), proverif 143 s (`tr`), ref-vectors (12 suites, 969 cases), sbom, systemd; repro STUB; ct, mutants, proverif-link, windows-cross, windows-native DELEGATED. A first call with `--delegated windows-native windows-cross …` ended at once (`unknown argument "windows-cross"`); rerun in the form above |
| `cargo xtask ci-fast` at `6ad3ec6` (`ci-fast-a4b-6ad3ec6.txt`, A-4b) | **FAIL** policy `large-files: 1 finding(s)` and nextest `gates::tests::large_file_gate_is_clean_on_this_tree` (the 2.9 MB ci-full log) |
| A-4d (WEISUNG M7-A4d) | not run in this box before A-4d2; A-4d2 brings the ci-full evidence file to the summary form |
| A-4d2 `docs(m7): ci-full evidence at c3c1dcf in the summary form with exact line selection (ADR-052; Q174)` | `5d44443`: file 2 896 642 B → 22 986 B, 51 `VERIFICATION:- ` lines; `gates::tests::large_file_gate_is_clean_on_this_tree` PASS |
| `cargo xtask ci-fast` at `5d44443` (`ci-fast-a4d2-5d44443.txt`; green A-4d2 run) | PASS: cooldown 26 s, nextest 14 s, kat 100 s, harness 978 s; `st-07-wrap-create-5d44443.txt` (553 ms), `pc-13-write-amplification-5d44443.txt` (8 241 B/slot); commit `8426991` |
| A-4d2 corrections `3ce6c70` (`docs(m7): A-4 report corrections (A4-2-01, verifier of 2026-10-30)`; `modell=claude-sonnet-5-5`) and `cargo xtask ci-fast` at `3ce6c70` (`ci-fast-a4d2-2-3ce6c70.txt`, A-4d2 close) | PASS: cooldown 26 s, nextest 18 s, kat 106 s, harness 978 s; `docs::` 7/7 |

ct, `store_unlock_reject` (`ct-m7-a4-4b0ffaf.txt`; Δ in ticks of 0.25 ns; floor 40 ticks = 10 ns; threshold |t| 4.5):

| Half | raw | p50 | p75 | p90 | p95 | p99 | max \|t\| |
|---|---|---|---|---|---|---|---|
| first | −12.48 / −0.09 | +4.47 / +0.95 | +4.72 / +0.86 | −0.65 / −0.07 | +15.07 / +0.61 | +153.39 / +2.46 | 2.46 (p99) |
| second | +28.54 / +0.28 | +1.88 / +0.38 | +1.30 / +0.22 | +4.65 / +0.49 | +13.03 / +0.52 | +22.21 / +0.35 | 0.52 (p95) |
| A/A | −252.17 / −2.03 | −7.25 / −1.44 | −13.73 / −2.28 | +2.12 / +0.23 | −20.02 / −0.81 | −16.67 / −0.25 | 2.28 (p75) |

Verdict PASS; k = 1, 100 000 samples, calibration median 63 641.5 ns; site `wrap: open`, pre-check `Err(Unlock)` in both classes,
twin `Ok`. Informative `store_unwrap_reject_post_kdf` (no verdict, `CAEAD.Open` only, 1 000 000 samples, median ≈ 2.1 µs): first
p50 +0.30 / +2.28, p75 +0.39 / +2.92, p90 +1.04 / +6.47, p95 +1.19 / +6.82, p99 +1.14 / +1.76, raw +16.34 / +1.17; second p50
+0.46 / +3.57, p75 +0.70 / +5.30, p90 +1.20 / +7.43, p95 +1.56 / +8.66, p99 +1.99 / +2.94, raw +17.62 / +1.28 (Δ ticks / t).

Kani peaks (cbmc RSS, KiB; limit 14 160 156; the five new names first). One source per column: "step c276c37" =
`kani-m7-a3e-full-c276c37.txt`, "ci-full dd92e5c" = `ci-full-a3b-dd92e5c.txt`, "alone" = `kani-m7-a3b-split-150d997.txt` (q_frame) and
`kani-m7-a3e-tr-8ce73d9.txt` (`tr_header_selection_*`); 42 of 51 harnesses are sampled in a step (the other nine end before the guard's
first 2-s sample). `kani-m7-a3e-tr-8ce73d9.txt:34` keeps its historical CI sentence (not edited).

| Harness | step c276c37 | ci-full dd92e5c | alone | CI 92b4404 | Flag |
|---|---|---|---|---|---|
| `kani_q_frame_plaintext_exact_fit_request` | 954 596 (6.7 %) | 968 016 (6.8 %) | 999 464 (7.1 %) | pending (reviewer) | |
| `kani_q_frame_plaintext_exact_fit_response_fetch` | 8 159 064 (57.6 %) | 9 007 180 (63.6 %) | 8 375 848 (59.2 %) | pending (reviewer) | |
| `kani_q_frame_plaintext_exact_fit_response_fetch_multi` | 9 068 184 (64.0 %) | 8 645 156 (61.1 %) | 9 288 076 (65.6 %) | pending (reviewer) | |
| `tr_header_selection_k0_2` (unwind 5) | 7 981 520 (56.4 %) | 7 786 360 (55.0 %) | 8 170 476 (57.7 %) | pending (reviewer) | |
| `tr_header_selection_k3` (unwind 5) | 8 012 720 (56.6 %) | 7 831 784 (55.3 %) | 8 201 176 (57.9 %) | pending (reviewer) | |
| `tr_header_selection_k4` (unwind 6) | 13 315 376 (94.0 %) | 13 313 532 (94.0 %) | 13 637 312 (96.3 %) | pending (PR run 92b4404) | **exception Q138: `tr_header_selection_k4` 94.0 % container (ci-full) / 96.3 % alone; CI figure from the PR run on `92b4404` to be recorded; the RSS guard trips above 100 % (`gates.rs:2550`); K7-03b (heap-free harness) is pulled forward if CI is red or above 95 %** |
| `kani_accept_opk_delete_only_on_success` | 12 324 192 (87.0 %) | 12 322 920 (87.0 %) | — | pending (reviewer) | > 80 %, reported |
| `request_link_get` | 9 437 900 (66.7 %) | 9 454 808 (66.8 %) | — | pending (reviewer) | |

`ci-fast-a3c-af4e848.txt`, `gate-vet-records-a3c.txt`, `vet-m7-a3c.txt` were taken on `af4e848` (the two vet files committed in
`af4e848` itself); the files are not edited.

Kani peaks of the ci-full `kani` step (cbmc RSS, KiB; limit `KANI_CBMC_RSS_LIMIT_KIB` 14 160 156; 90 % = 12 744 140):

| Harness | Peak | Share |
|---|---|---|
| `kani_proofs::kani_q_frame_plaintext_exact_fit` | 13 467 828 | **95.1 % — STOP (§8)**; A1e 85.6 % |
| `kani_proofs::tr_header_selection` | 13 415 900 | 94.7 % (the known case; A1e 94.6 %) |
| `kani_proofs::kani_accept_opk_delete_only_on_success` | 12 411 440 | 87.7 % |
| `kani_proofs::request_link_get` | 9 437 036 | 66.6 % |
| `kani_proofs::kani_frame_pad_total` | 9 114 684 | 64.4 % |
| `kani_proofs::response_frame` | 8 081 260 | 57.1 % |

## 5. Deviations from spec / plan

No deviation from the spec text. One decision touches §7.7 and awaits the owner's ratification: ADR-058 (accepted by the reviewer under the delegation of 2026-11-10; an authenticated repeat of the last accepted KeyChange is a no-op instead of a freeze; review R7-2); docs/03 is unchanged until then. Deviations from the weisung's wording or the TEST-SPEC rows (each for the reviewer, Q-A6…Q-A13):

- **D1 (Q-A6) G7-06:** the `cargo tree` of `kani_build_has_no_store` uses `-e normal,build`, not `-e normal`: `openssl-src` is a
  build-dependency of `openssl-sys`, so with `-e normal` the dictated negative control has no `openssl-src v` line (first run:
  `negative control lacks openssl-src v`).
- **D2 (Q-A7) OB-07:** `m6_outbox::outbox_is_the_store_boundary` pinned "no `secmp-store` dependency" (ci-fast red at `f5c099d`);
  re-dictated in `3064c74`: the store edge only in the `cfg(not(kani))` table, the scheduler (`src/scheduler/**`) free of it.
- **D3 ST-16:** the build has no `sqlite_dbpage` (asserted), so the page images come from `sqlcipher_export` (the row's fallback).
- **D4 (Q-A8) PC-07:** "an eviction of 3 skipped entries" is a receive that skips 3 more at the 512 bound: +3 inserts and −3 deletes
  in one commit (an eviction always comes with insertions; the 3 deleted rows are asserted to be the 3 earliest); the "−3 alone" case
  is the extra step "three late cells consume their entries" (−3, +0). The skip k = 10 inserts 10; the undelivered dummy of the first
  slot is an 11th entry.
- **D5 (Q-A9) PC-02:** the "no frame / no ack" part is asserted on the cell source the scheduler calls (`Conversations`):
  `prepare_cell` returns `Err` (no cell, hence no SEND frame) and `deliver` returns `Err` (the core does not move `acked`,
  `core/mod.rs:897`, hence no acknowledgement), and after the failures the same cell is decided; there is no driver-level frame counter
  in this unit test (PC-03/PC-04 check the frames).
- **D6 (Q-A10) PC-03/PC-04 instrumentation:** `PreparedCell` has a private witness field (`compile_fail,E0451`) and the
  constructors `committed` (crate) and `unpersisted_kat` (feature `kat`, the fake sources of `m6_sched_io` and the fuzz target);
  PC-04 orders decisions and seals by the thread's seal counter: the kat-only field `PrepRecord.seal` in the scheduler's preparation
  log and the testkit gate's `Audit::Decided([queue, cell_id, seal])`. PC-03 checks counts (the j-th SEND frame written follows ≥ j
  durable Send commits), not the identity of each cell's state.
- **D7 (Q-A11) PC-05 relay and timing:** the "relay" of PC-05 is a queue of files per direction; the receiver fetches and decides each
  cell before the sender's `OK_SEND` (else a crash between write and `OK_SEND` never produces a message the receiver already
  delivered — the first version passed with the dedup removed). PC-05 takes 244 s alone (row: 4 min), PC-13 295 s (row: 50 s; one
  fsync per commit, 34 495 commits/day): both in `MUTANT_HARNESS_SKIP_TESTS` and `docs/mutants-accepted.md` §Skipped.
- **D8 (Q-A12) G7-13 follow-ups:** the first store mutants run (`bc67679`) caught 46.3 % < 50 %; cause found — `sessions.rs` and
  `outbox.rs` were exercised only by client-core tests, which the per-package run does not run, and the `kat` helpers had no tests —
  so `be0d82d` adds 13 store unit tests; `04b9795` makes a child process refuse to start children (4 `child_role` mutants re-entered
  without end, timeouts) and documents 3 equivalent mutants; `365a3da` fixes a race of the `cargo test` run (a child between `fork`
  and the close of its descriptors held a copy of another test's released profile lock: `try_lock` `WouldBlock` for about 1 ms in
  3 of 30 runs) with a kat-only spawn guard. The `kat` crash point `MidTxn(k)` after the last statement now fires only before the
  commit point (`3dc63fd`, `be0d82d`; earlier `transaction_ended` fired it a second time after the commit or rollback). Four gate
  tests' floor/merge fixtures carry a `secmp-store` tally.
- **D9 (Q-A13) G7-18:** `vectors/tr.json` holds `StateDigestV1` digests, not serialised states, so the test replays the 96 events and
  passes every state through `to_parts`/`from_parts` (the digest parses `RatchetStateV1` at its documented offsets); it is gated on
  feature `kat` (the derandomised entry points), so the feature-less Miri run does not build it (no `MIRI_SKIP` entry);
  `secmp-proto/src/lib.rs` gains `#[cfg(test)] extern crate self as secmp_proto;` so the unit test shares `tests/common/tr_digest.rs`.
- **D2 addendum:** Q-A7 ratified by the reviewer (2026-10-29).
- **D10 (Q-A14) V1-F13:** `PRAGMA synchronous = FULL` in `open_connection` (step `synchronous`); CS-3.1 is silent; the default is
  already FULL in the bundled build (ST-01 not red without it).
- **D11:** none (`cipher_memory_security` reads 1 with the early statement).
- **D12 (Q135, Q137, Q138):** the q_frame and `tr_header_selection` splits; the bounds of Q138; `tr_header_selection_k4` the one
  documented exception (exception Q138: `tr_header_selection_k4` 94.0 % container (ci-full) / 96.3 % alone; CI figure from the PR run on `92b4404` to be recorded; the RSS guard trips above 100 % (`gates.rs:2550`); K7-03b (heap-free harness) is pulled forward if CI is red or above 95 %); B row K7-03b.
- **D13:** one `ci-fast` (`ci-fast-a3b-l-675bad6.txt`, code `cdc3c0a`) stands for the four dictated runs `ci-fast-a3e-kani`,
  `ci-fast-a3b-3`, `ci-fast-a3b-4` and `ci-fast-a3b-l`: §3–§5 were committed while the full Kani step ran (Kani builds of the
  touched crates had ended, so the measured Kani tree is `c276c37`), and §6 followed; the PC-05/PC-13 numbers of §3 come from it.
- **D14 (Q-A17) §6 run (1):** `--features kat` instead of the gate's `--features harness` — with the `--file` filters only
  `secmp-client-core` has mutants, cargo-mutants builds the baseline for it alone, and it has no `harness` feature ("the package
  'secmp-client-core' does not contain this feature: harness"); client-core `kat` turns on `secmp-transport/harness` and
  `secmp-store/kat`, the testkit's `kat` includes `harness`.
- **D15 (Q-A15):** ST-16 plaintext control (`open_unkeyed_kat`, `secure_delete = OFF` → canary present), reviewer decision.
- **D16 (Q-A16):** ST-03 `TMP`/`TEMP`, the spill table and the Linux `st03-control` (`temp_store = FILE` → ≥ 1 fd), reviewer decision.
- **Commit 3 subject:** first committed as `a02069b` with a different subject; amended (subject as dictated, PC-05 evidence per crash
  point) before any measurement, as `0c448f0`; nothing was measured on `a02069b`.

A-4 (`modell=claude-opus-5-5`; no deviation from the spec, ADR-053 or Amendment 1):

- **A-4 record seal under Amendment 1:** the composite `row_key`s (`prekeys` (kind, id) 16 B, `sessions` (session_id, part, ord)
  24 B) are built under Proposed Am. 1 — accepted by the owner 2026-10-29 (Q144).
- **D17 (Q-A18) `Unlocked::db_key` returns `Result<DbKey>`** (weisung: `-> DbKey`): the HKDF of `K_db` and the nine `K_t` into
  locked pages can fail (locked memory unavailable); the error is `Unavailable`.
- **D18 (Q-A19) ST-09 re-dictation in the second §3 commit:** `testscan.rs:456` moved to `kat_small_sites == 1` in `b014540`, not
  in `bd9e240`, which introduced the site (`bd9e240` alone: the A-3 assertion red, `left: 1 right: 0`); ci-fast ran after both
  commits, as dictated.
- **D19 ci-fast red at `0882c77`:** clippy `too_many_lines` (104/100) on `informative_targets_are_pinned_printed_and_never_fail` (ci-fast red at `82148dd`, `f393a22` and `0882c77`; the clippy `too_many_lines` failure originates in `82148dd`'s ctreport.rs)
  after the three-name pins (`ci-fast-a4-4-0882c77-red.txt`); `9ab5d5b` edits the fixture's own entries instead of rebuilding the
  list; `ci-fast-a4-4-9ab5d5b.txt` PASS.
- **D20 ci-fast red at `f51f7c2`:** the M2 test `secmp-proto/tests/fuzz_max_len.rs` recomputes every `FUZZ_MAX_LEN` entry
  (`left: 35 right: 33`, `ci-fast-a4-6-f51f7c2-red.txt`); `4383c8a` adds `m7_entries` (the backup file and the sealed record from
  `NONCE_LEN`, `COM_LEN`, `AEAD_TAG_LEN`, `RatchetState::MAX_ENCODED_LEN`); `ci-fast-a4-6-4383c8a.txt` PASS.
- **D21 (Q-A20) fuzz smoke form:** `cargo +nightly-2026-09-21 fuzz run <t> target/fuzz-scratch/<t> fuzz/corpus/<t> --
  -max_total_time=120 -max_len=<FUZZ_MAX_LEN> -timeout=60` instead of the bare `fuzz run <t> -- -max_total_time=120`: libFuzzer
  writes new inputs into its first corpus directory, which would have been the tracked corpus; `-max_len`/`-timeout` as the gate.
- **D22 (Q-A21) store API beyond the dictated items:** ST-12 needs rows in tables that had no API — `profile` (`put_identity`,
  `insert_prekey`, `put_relay`, `insert_invitation` and their sealed reads) and `contacts` (`Contact`, `put_contact`,
  `Store::contacts`, `STATE_ACTIVE` = 0 beside Q142's `STATE_REINVITE_REQUIRED` = 1); `Tx`'s field `tx` renamed `inner` (clippy
  `struct_field_names` with the third field); `Store`/`Tx` carry the table keys (`Tx::seal`, `Store::open_record`).
- **D23 `sessions.skey` of a short entry:** an entry shorter than 36 B gets the whole entry as its `skey` (the A-3 `substr(data, 1,
  36)` semantics), so the A-3 test `session_rows_round_trip` (7-byte entries) runs unchanged.
- **D24 PC-13:** the A-3 test is unchanged; it passes its own bound (11 098 B, measured 8 241 B, `pc-13-write-amplification-5d44443.txt`; A-4 report: 8 241 B at b014540, not retained; A-3: 8 239 B at 675bad6), which is tighter
  than the weisung's +72 B-per-sealed-record bound (11 386 B).
- **D25 (Q-A22) backup details the weisung leaves open:** `import(store, path, passphrase, now_ms)` restores into an empty profile
  the caller opened (identity `created_ms` = `now_ms`; the store has no clock); a message whose contact is not in the contacts
  section has no `contact_index` and is not exported; export refuses a contact without a `Profile` (`Unavailable`); every
  `settings` row is exported; the random inputs are drawn in the order salt, `MK_bk`, `N'`, `N` (BK-04 fixes them in that order);
  `Error::CloudFolder`'s text is "secmp-store: the export path is inside a cloud-synchronised folder".
- **D26 ct pre-check wording:** the store targets reuse `SiteCheck::Tagged`, whose `check` text says "Err(Rejected) and the kat
  reject-site tag"; their `expected`/`observed` strings are `Err(Unlock), site wrap: open`.
- **D27 kat entry points (Q-A23):** `wrap::open_with_kek_kat` (Q140's post-KDF target), `backup::{seal_file_kat, encode_body_kat,
  open_body_kat, open_export_kat, export_kat, import_kat}`, `seal::{seal_kat, open_kat}` — all `cfg(feature = "kat")` (or tests).
- **D28 mutants rerun diff:** the first-run diff (`92b4404..b697b7b`) was refused for the rerun after the killers ("Diff content
  doesn't match source file"); the rerun used the same range regenerated at `1be3f1d`.
- **D30:** A-4 committed the full ci-full log (2.9 MB) against the A-3b precedent; reduced in A-4d2 (Q174).
- **D31:** the red-first outputs of §3 (labels, F3) are in `a4-red-first.txt` (A-4d2).
- **D29:** one `ci-fast` at `eb9d3b8` (`ci-fast-a4-l-eb9d3b8.txt`) stands for the dictated `ci-fast-a4-g700` and
  `ci-fast-a4-l` (G7-00 was the last code commit before it; D13 precedent).
- **D32 (A4-1-01):** `DbKey` holds K_db as `StoreKey`; the `PRAGMA key` statement is built in a `LockedSecret<82>` (`secmp-crypto` `LockedSecret::with_fill`, new).
- **D33 (A4-1-03):** the sessions AD vector uses (4, 1, 0) — the ruling's part 4 does not exist (parts 0–3); part 1 (skipped) covers both sealed columns (`data`, `skey`).
- **D34 (A4-1-05):** a cloud-folder hit is a component equal to a listed name or starting with it followed by a space, `-` or `_` (`OneDrive - Org`, `Dropbox_Team`); no bare prefix (`Boxes` is not a hit); override: `force`.
- **D35 (A4-1-04):** `own_name` is not allowlisted (no product code uses it), so it is never exported and the FO-03 `own_name` needle (`m7_forensic.rs:112`) is vacuous; FO-01a in Phase C re-targets that needle.
- **Q175** (reviewer, 2026-10-30): a `sessions` skipped entry shorter than 36 B is malformed → the uniform record error; supersedes D23; the A-3 test `session_rows_round_trip` re-dictated to ≥ 36-B entries.

## 6. Dependencies added or bumped

ADR-055 effective 2026-10-28 (memo default); records ratified 2026-10-29 (Q136). `Cargo.lock` +70 lines
(six packages), `fuzz/Cargo.lock` +42 (four packages); `git diff --stat bf55099..HEAD -- Cargo.lock fuzz/Cargo.lock`: 112 insertions.

| Crate | Version | Published | Record | Who |
|---|---|---|---|---|
| `rusqlite` | 0.39.0 | 2026-03-15 | audit (direct dependency of `secmp-store`) | Christopher Carl (owner), ratified 2026-10-29 by delegation to the reviewer (Q136); source audit by the reviewer's verifier |
| `argon2` | 0.6.0 | 2026-08-27 | publisher trust `github:RustCrypto/password-hashes` | same, ratified 2026-10-29 (Q136) |
| `blake2` | 0.11.0 | 2026-08-26 | publisher trust `github:RustCrypto/hashes` | same, ratified 2026-10-29 (Q136) |
| `password-hash` | 0.6.1 | 2026-04-08 | publisher trust `github:RustCrypto/traits` (lock-only) | same, ratified 2026-10-29 (Q136) |
| `phc` | 0.6.1 | 2026-03-09 | publisher trust `github:RustCrypto/formats` (lock-only) | same, ratified 2026-10-29 (Q136) |
| `openssl-sys` | 0.9.117 | 2026-06-12 | tracked exemption | — |
| `openssl-src` | 300.6.1+3.6.3 | 2026-06-09 | tracked exemption | — |
| `libsqlite3-sys` | 0.37.0 | 2026-03-15 | tracked exemption (text now names `rusqlite`) | — |

`base64ct` 1.8.3 and `cpufeatures` 0.3.1 are covered by the existing `[[trusted.*]]` of user-id 267. Youngest crate of the lock: `rustls-webpki` 0.103.16 (8 days).

A-3 lock movement (§1 G7-06 only, as predicted by A0): `git diff --stat ba1dce6..HEAD -- Cargo.lock fuzz/Cargo.lock` = `Cargo.lock | 2 ++`,
`fuzz/Cargo.lock | 33 +++`, 35 insertions (`Cargo.lock`: the line `"secmp-store"` in the dependency lists of `secmp-client-core` and
`secmp-testkit`; `fuzz/Cargo.lock`: `openssl-src` 300.6.1+3.6.3, `openssl-sys` 0.9.117, `secmp-store`, `"openssl-sys"` in
`libsqlite3-sys`, `"secmp-store"` in `secmp-client-core`). No `Cargo.toml` dependency change beyond §1; features as dictated in §2.
Vet: `Vetting Succeeded (241 fully audited, 2 partially audited, 322 exempted)`; vet step `60 external crates, 0 exempted`.

A-4 (`modell=claude-opus-5-5`): no `Cargo.toml` dependency change other than §6's fuzz path dependency;
`git diff --stat 92b4404..HEAD -- Cargo.lock fuzz/Cargo.lock` = `fuzz/Cargo.lock | 1 +` (the line `"secmp-store"` in the
dependencies of `secmp-fuzz`); `Cargo.lock` unchanged; `git diff bf55099..HEAD -- vectors/` empty (0 lines). G7-00:
`COOLDOWN_EXCEPTIONS` empty; the cooldown gate passes (`ctutils` 0.4.4 is 7 days old on 2026-10-30).

ADV1 (Q229): `rustix` 1.1.5 → 1.1.6, `git diff --numstat` 2/2 in `Cargo.lock` and `fuzz/Cargo.lock` (version + checksum only), delta audit `1.1.5 -> 1.1.6` (`vet-deltas/rustix-1.1.5-1.1.6.diff`), published 2026-10-27 (15 days); no other package moved.

## 7. Open risks and known limitations

**Upstream advisories (ADR-055 item 7).** SQLite 3.50.4 (CVE-2026-11822/-11824, fixed 3.53.2; CVE-2025-70873 zipfile, fixed 3.53.0), SQLCipher 4.10.0 (defensive-mode bypass in `sqlcipher_export`, fixed 4.15.0, Low), OpenSSL 3.6.3 (fixed in 3.6.4 and 3.6.5; CVE-2026-84782 DTLS High) — bundled by `libsqlite3-sys` 0.37.0 / `openssl-src` 300.6.1+3.6.3, which follow Arti's `links = "sqlite3"`; exposure as listed in the ADR (no attacker SQL, FTS5/zipfile unused, OpenSSL only through SQLCipher); mitigation row ST-20 in A-3.

**Argon2 working memory.** The block matrix is zeroized on drop since A-4 (F3: `secmp-crypto` allocates it as `Zeroizing<Vec<argon2::Block>>` for `hash_password_into_with_memory`); the crate zeroizes the initial hash (`src/lib.rs:390`) and, in `finalize`, `blockhash`/`blockhash_bytes` (`:572-573`). `modell=claude-opus-5-5`

**Kani memory.** ci-full of A-3: `kani_q_frame_plaintext_exact_fit` 95.1 % (STOP, §8), `tr_header_selection` 94.7 %,
`kani_accept_opk_delete_only_on_success` 87.7 % of 14 160 156 KiB (A1e: 85.6 %, 94.6 %, 87.4 %); either of the first two can trip the guard
on the 4-core runner's run-to-run spread.

**ADR-055 item 7 after ST-20.** `SQLITE_DBCONFIG_DEFENSIVE` is set on every connection the store opens, before any statement
(ST-20); the store never runs attacker SQL; `sqlcipher_export` (SQLCipher 4.10.0's defensive-mode bypass, fixed in 4.15.0) is used only
by the `kat` page-image path of ST-16/ST-17, never by shipped code. The SQLite/OpenSSL CVE exposure of ADR-055 item 7 is unchanged.

**Argon2 matrix → A-4 F3** (as before).

**Profile lock and child processes.** The profile lock is an `flock` on `<profile>/lock`; a process that starts a child while another
thread closes and reopens a profile can see `Unavailable` for about 1 ms (the child's copy of the descriptor until its `exec` closes it,
D8). Shipped code starts no child process today; the client fails closed (`Unavailable`) and a retry succeeds. Recorded for Phase B
(the `Api`'s profile open).

**Write cost.** PC-13: 8 239 bytes per dummy slot (one fixed-part page per commit, sender and receiver), 34 495 commits/day for one
contact at P = 10 s, each with one fsync of the write-ahead log (`synchronous` FULL, persist-before-send); 142 MB/day of log for two
profiles with checkpoints off in the measurement. More contacts multiply it; checkpointing writes each page once more.

**F9.** A refused outbox insert keeps the message in memory only (`write_errors` counts it) → Phase B `Api` reports it.

**F9b (EXT1-1, Q176).** A receipt's `Delivered` update (`conversation.rs:691-694` → `StoreOutbox::delivered` → `sync`) is a transaction separate from the receive commit and swallowed into `write_errors`. A refused write or a crash between the two loses it: the message stays `Relayed`, is re-sent after a relay loss, and the peer dedups it without a second receipt. The ratchet, the reassembly, the trust and the delivered messages are committed before the ack (spec 03:488). Phase B (B-4, sessions actor, with SC-02): `CommitParts.receipted`, with `StorePersist` marking `DELIVERED` in the receive transaction; row SE-21.

**F14.** The AI (activity-independence) runs use `MemPersist`; a run with `StorePersist` behind the scheduler is B/C.

**Windows runtime of PC-05/PC-13 unmeasured.** Both run in the `harness` step of `windows-native` (not in `WINDOWS_SKIP_TESTS`); 30 000+
fsyncs and 200 child processes per run may be slow on the Windows runner.

**Coverage leaves `.profraw` files.** The coverage step left `default_*.profraw` files in the tree root and in `crates/secmp-testkit/`
(re-entered child processes of the store tests, PC-01/PC-05/PC-09, write the default profile name); deleted; they are untracked, so no
gate saw them, but `ci-full-a3-1f3129c.txt` line 2 counts two of them.

**Argon2id under CT-01 (A-4).** `store_unlock_reject` measures the whole unlock — Argon2id (`kat_small`), `CAEAD.Open` — and
passed (max |t| 2.46 / 0.52, floor 10 ns). Argon2id's data-dependent second half (RFC 9106 §3.4.1.3) is a documented property of
the crate, not a leak of a SecMP construction: its memory accesses after the first half-pass depend on the passphrase-derived
blocks, so a co-resident cache observer can learn about the passphrase in principle; the gate's classes differ in the passphrase,
the measured times do not. The informative post-KDF target (Q140) isolates `CAEAD.Open` (≤ 0.4 ns shifts, 0.04 floors). The real
parameters (256 MiB) are measured by CT-03 in Phase C.

**Backup file (A-4).** The export reveals the file type (magic), the Argon2 parameters, the salt and the four section lengths
(the number of contacts, settings and messages can be estimated from them); everything else is sealed (ADR-053 item 6). An export
is written only on `confirm`, never into a folder of `CLOUD_FOLDERS` without `force` (BK-06), and no code path calls it (BK-07).

## 8. Blocked / questions for the reviewer or owner

**Waiting (owner).** A-2 needs "ADR-055 accepted" and the vet records (A0 §7: `argon2` 0.6.0, `blake2` 0.11.0 in the
zero-exemption crypto closure; `openssl-sys` 0.9.117, `openssl-src` 300.6.1+3.6.3, `password-hash` 0.6.1, `phc` 0.6.1);
A-4 needs "ADR-053 accepted". (Superseded: ADR-055 and ADR-053 are accepted, `docs/08-decisions.md:1025` and `:919`; A-2 is done @ `bf54d98` and A-4 built @ `c3c1dcf`, §1; the owner items open at D-11 are the OWNER-PENDING and OWNER-OPERATED rows of `## Phase C close (M7-C5)`, the cadence of the owner-status query (Q297), and the items carried in `## D-11`.)

**Waiting (date).** G7-00: first commit after 2026-10-30 02:00 UTC; the cooldown gate is red from 2026-10-31 00:00 UTC
until it lands.

**Not done by the A0 probe (A0 §6).** Native `windows-latest` build of the unified graph and `tor-smoke` (dispatch runs;
the executor cannot dispatch); vendor CVE lists of SQLite 3.50.4 / SQLCipher 4.10.0 / OpenSSL 3.6.3 (no web access in
the container; RustSec shows none).

**Q-A1 (closed by Q127, `f6e2928`).** Two cross-build invocations; see G7-05.

**Q-A2 (answered, Q130).** `secmp-proto` and `secmp-relay` dev-depend on `secmp-crypto`, not on `secmp-testkit`; the earlier
red for them came from treating `XWIN_LIB_ONLY` crates as poison. `XWIN_LIB_ONLY` is `[secmp-crypto, secmp-transport]` again; the poison
set of the test is `XWIN_EXCLUDE`.

**A-2 closed @ `bf54d98`; A-3 next.**

**Q-A4 (Miri budget of ST-08).** `rfc9106_argon2id_vector` takes about 105 s of host wall time under Miri (aarch64, portable libcrux); no `MIRI_SKIP` entry was added (the 60-s rule is documented for `secmp-proto`; the crypto entries are ≥ 10 min). Reviewer to confirm or dictate the entry.

**Q-A5 (G7-02 deviation).** `password-hash` and `phc`: publisher trust instead of exemptions (see §3 G7-02).

**A2b** (verifier nits of A-2): the G7-01 test is at module level (`xtask::expect::normal_dependency_allow_m7`), `vet_records_for_m7_closure` pins `start`/`end` of the trust entries, doc nits; Q-A4 answered: no `MIRI_SKIP` entry (re-measure the three tests in ci-full), Q-A5 answered: trust instead of exemption is right.

**Q-A3 (Kani peak figures).** The `kani` step prints its `kani-rss` lines after the last package; a step that is stopped
earlier prints none. The first guarded local run was stopped by the background limit during `secmp-proto`.

**Note for ST-02.** The bundled SQLCipher reports `PRAGMA cipher_version` = `4.10.0 community` (A0 §3); the row's
expected value 4.10.0 is the leading version of that string.

**A1d.** Smoke `hello` (owner dispatch, run 40692102750) red: the step "Probe the runner toolchain" of `win-ondemand.yml` ended with `pwsh -v || echo no-pwsh`; in `shell: cmd` the exit code is the final ERRORLEVEL and `echo` does not reset it, so the 9009 of the missing `pwsh` survived. Fixed: the line is dropped (nothing uses `pwsh`), policy test `win_ondemand_cmd_steps_have_no_bare_optional_probe`. Re-run after merge (or on a temporary `m07-client-core` federated credential, owner's choice).

**A1e / A1f (Q132, Q133).** PR run 40688358569: the guard stopped `kani_commit_accept_atomic` at cbmc 14 188 096 KiB (limit 14 160 156 KiB; M6: 13 751 MB). OPEN-M7-26 B: the harness is split by store configuration into `kani_commit_accept_atomic_record_names_opk1` and `…_deleted_opk2` (no bound, unwind, stub or limit change). First split run (shared cover in `kani_commit_on`): `..._deleted_opk2` 0 of 1 cover — the record's OPK is deleted, so that configuration never commits. Q133: `kani_commit_on` returns `ok`; opk1 covers "a commit", deleted_opk2 covers "a rejected commit". Historical evidence untouched; `kani_cover_pin_findings` fixture takes the real run `kani-m7-a1f-commit-accept-9eac343.txt` in place of the M5 block of the old name (left out in memory, not rewritten).

Quoted (foreground, `cargo kani -p secmp-proto -Z stubbing --harness <name>`):
- `kani_commit_accept_atomic_record_names_opk1`: `** 1 of 1 cover properties satisfied`, `VERIFICATION:- SUCCESSFUL`, 92.0803 s
- `kani_commit_accept_atomic_record_names_deleted_opk2`: `** 1 of 1 cover properties satisfied`, `VERIFICATION:- SUCCESSFUL`, 116.59998 s

Peaks of the full step (`kani-m7-a1e-9eac343.txt`, KiB; limit 14 160 156): `..._deleted_opk2` 6 220 484, `..._opk1` 5 737 528 (re-measured in the PR run); `tr_header_selection` 13 393 720, `kani_accept_opk_delete_only_on_success` 12 372 716, `kani_q_frame_plaintext_exact_fit` 12 121 336, `request_link_get` 9 479 788, `response_frame` 8 945 636, `kani_frame_pad_total` 8 053 804, `kani_outer_unpad_total` 7 780 720; `secmp-relay` largest `kani_executor_response_count` 4 136 084; `secmp-client-core` largest `kani_rate_bound_integer_form` 2 952 940.

**A-4: F3** — Argon2 matrix zeroization (`hash_password_into_with_memory` with a `Zeroizing<Vec<Block>>`). No code for it in A-3.

**Resolved:** the three Kani STOPs below (A-3, A-3b, A-3d) are resolved by Q135, Q137 and Q138 (split, bounds, the `_k4`
exception); A-3 closed @ `cdc3c0a`.

**K7-03b (Phase B, open, Q138 item 3).** Rewrite `tr_header_selection_k0_2`, `_k3`, `_k4` without the heap (`Vec<Choice>` built by
`collect` → `[Choice; TR_SKIPPED_KEYS]` sliced to `k`), re-measure, lift the exception if `_k4` falls under 90 %.

**A-4: ADR-053 landing adds `synchronous = FULL` to the CS-3.1 wording (Q-A14).**

**Blocked — STOP (WEISUNG M7-A3, STOP list: "a Kani harness peak RSS > 90 % of `KANI_CBMC_RSS_LIMIT_KIB`").** The ci-full `kani` step
on `1f3129c` (code `365a3da`) measured `kani_proofs::kani_q_frame_plaintext_exact_fit` (secmp-proto, K-08 frame decode) at
13 467 828 KiB = 95.1 % of 14 160 156 KiB (A1e: 85.6 %); the step passed (47/47, the guard did not trip). Re-measured alone
(`kani-q-frame-peak-a3.txt`, `getrusage` of the largest child): 12 910 628 KiB = 91.2 % on the A-3 tree, **12 936 468 KiB = 91.4 % with
the three A-3-changed `secmp-proto` files reverted to `ba1dce6`** — the harness reaches no code A-3 changed and is above 90 % without
A-3. Reviewer: decide (e.g. OPEN-M7-26 B for this harness, as for `kani_commit_accept_atomic`, or an exception like `tr_header_selection`).
No bound, unwind, stub or limit was changed.

**Q134 (G7-06).** ADR-051 table: no third-party change (workspace edges only) — reviewer reading: `policy.rs:2482` compares
non-secmp-* crates only.

**ST-17 open clauses (Phase B/C).** The `Api` event `ViewOnceLost(msg_id)` after a restart (Q125; the store half returns the ids from
`Store::take_view_once_lost()`) is Phase B; the full FO-01a forensic scan of a profile is Phase C (the store half uses the Conventions'
Rust scan over the profile directory). ST-17 counts as partial (store half).

**A-3 done @ `365a3da` (STOP above); A-4 next (ADR-053 accepted, Q127a).** Records ratified 2026-10-29 (Q136).

A-4: never format rusqlite `Error`/`Statement` on the key path (vet note N-3/N-4).

**Blocked — STOP (WEISUNG M7-A3b §2: "each peak ≤ 12 744 140 KiB (90 % of 14 160 156), else STOP with the numbers — no other remedy
than the `_k3`/`_k4` step").** `modell=claude-opus-5-5`. The q_frame split resolves `kani_q_frame_plaintext_exact_fit` (7.1 / 59.2 /
65.6 %). The `tr_header_selection` split by `k` does not reduce memory: alone (`getrusage` of the largest child, one process per
harness, `kani-m7-a3b-split-150d997.txt`) `_k0_2` 13 588 600 KiB = 96.0 %, `_k3_4` 12 759 388 KiB = 90.1 % → the dictated `_k3`
13 635 700 KiB = 96.3 % and `_k4` 13 636 560 KiB = 96.3 %; the unsplit harness of `150d997` 13 746 024 KiB = 97.1 % with the same
method (94.7 % sampled by the `kani` step in the A-3 ci-full). Every variant has the same **985 checks** (`** 0 of 985 failed (11
unreachable)`): `#[kani::unwind(6)]` unrolls the loops over `opened`/`found`/`first` to 6 whatever `k` is, so an `assume` on `k`
prunes no part of the formula CBMC builds. Committed as dictated (`9ef0b81`: 51 harnesses, `_k0_2`, `_k3`, `_k4`; every harness
SUCCESSFUL; no bound, unwind, stub or limit changed). Not run: the full `kani` step, ci-fast `-2`, §3–§6. Reviewer: decide the
remedy for `tr_header_selection` (options the weisung excludes for me: a per-harness `unwind` matching `k` + 2 — `unwind(4)` for
`k ≤ 2` —, a smaller `TR_SKIPPED_KEYS` per harness, a limit or an exception like A-3's; or leave it unsplit with the A-3 exception).

**Blocked — STOP (WEISUNG M7-A3d §2′.2: "if `_k4` (unwind 6, the original bound with k fixed) is still above 90 %, STOP with the three
numbers").** `modell=claude-opus-5-5`. Q137 bounds applied on `25e9f38` and measured alone (`kani-m7-a3d-tr-25e9f38.txt`; the source
change is **not committed**, the tree is the A-3c head):

| Harness | unwind | Peak (KiB) | Share | Result |
|---|---|---|---|---|
| `tr_header_selection_k0_2` | 4 | 371 556 | 2.6 % | **VERIFICATION:- FAILED** — the unwinding assertion of `kani::any::<[bool; 4]>()` (`core::array::try_from_fn_erased`, loop 0): the arbitrary arrays `opened_all`/`found_all` are built by a loop of `TR_SKIPPED_KEYS` = 4 iterations, so every harness needs unwind ≥ 5 whatever its `k` |
| `tr_header_selection_k3` | 5 | 8 204 240 | 57.9 % | SUCCESSFUL, 6/6 unwinding assertions SUCCESS |
| `tr_header_selection_k4` | 6 | 13 640 532 | **96.3 %** | SUCCESSFUL, 6/6 unwinding assertions SUCCESS — over 90 % |

Not run: the full `kani` step, ci-fast `-kani`, §3–§6. For the reviewer: `_k3` at unwind 5 shows that the array generation needs 5 and
that 5 is affordable; `_k0_2` at unwind 5 is then the floor `max(k_max + 2, TR_SKIPPED_KEYS + 1)`; `_k4` needs 6 (its loops over
`opened` run 4 times + exit), and at the original bound it is the original's cost (96–97 %). A remedy for `_k4` needs a decision outside
Q137 (e.g. arrays of length `k` per harness instead of `TR_SKIPPED_KEYS`, an exception like A-3's, or the limit).

**Blocked — STOP (WEISUNG M7-B-4f §5: "any instruction that cannot be followed literally"; step 5, SE-28).** `modell=claude-opus-5-5`.
The dictated expectations of SE-28 `queue_lost_replans_unsealed_and_sealed_control_content` ("`rows == 3` (B, C, A re-written);
… exactly one `ResetRequested` and three `Routes`") contradict the dictated `replan_control` supersession of §2 ("a `Routes` entry
… for which `controls` holds a `Routes` entry with a higher id is **not** re-planned: its row goes …"), which SE-37 requires. Probe
(not committed): with both as dictated, after `lost_direct()` the rows are 2 (A re-written, C) and the peer gets one
`ResetRequested` and one `Routes`; only with the supersession branch deleted (SE-37's red mutation) are they 3 / 1 / 3 — the
in-memory `RouteUpdate` of `established`'s reply (id 0) and B are both superseded by C. Evidence:
`docs/reviews/M07-evidence/b4f-stop-se28-probe.txt`. Question: which holds after a lost queue — (A) supersession also there (SE-28
re-dictated: rows 2, one `ResetRequested`, one `Routes` with `sid == [4; 16]`), or (B) a lost queue re-sends every `Routes` entry
(then `replan_control` needs a "no supersession" path for `on_lost`, and SE-37 stays as it is)? Steps 5 (rest)–10 not done; see §B-4f. **Resolved (WEISUNG M7-B-4f2, 2026-11-11): Q223 = (A), Q224
Option R; steps 5–10 done in the continuation (§B-4f).**

**Blocked — STOP (WEISUNG M7-B-4f §5 "any gate red that the step did not expect"; step 10 ci-fast, RUSTSEC-2026-0486).** See §B-4f.5: `ci-fast-b4f-10-4b95e6a.txt` red in `deny`/`audit` only (rustix 1.1.5 via tempfile ← arti-client); (A) lock bump in both lock files or (B) ADR-051 amendment. **Resolved by ADV1 @ `598a948` (WEISUNG M7-ADV1, Q229, ADR-051 Am. 9): rustix 1.1.6 in both lockfiles (version + checksum only), delta audit, `deny`/`audit` green.**

**Correction (A-3 §0.1).** The age of `argon2` 0.6.0 (published 2026-08-27) was given as 60 days in A0 and A-2; it is 61 days on 2026-10-27 and 62 days on 2026-10-28 (`cooldown-m7-a3.txt`). The vet closure grew by five crates, not four (`vet-suggest-m7-a3.txt`).

**A-4 built @ `c3c1dcf` (`modell=claude-opus-5-5`); Phase A closes with the green PR run
(BRIEF_M7 §5, reviewer).** Blocked: none. STOP: none. Open:

- **ST-10, BK-04 [REF]:** the byte-exact clauses wait for `vectors/store.json` (OPEN-M7-38); both rows pass their built clauses.
- **BK-03, ST-17 partial (store halves) — Phase B completes** (`Api.send` → `ReinviteRequired`, fresh prekeys; `ViewOnceLost`).
- **PR-03, IN-03 (Phase B).**
- **Owner's ref session (OPEN-M7-38):** add the four rev-2.7 labels (ADR-053 item 7) to `ref/secmp_ref/labels.py`; no CI job runs it;
  no action here.
- **Q124 "54 labels" vs ADR-053 item 7 = 53:** followed the ADR (53; `label::tests` pin 53).
- **Q140 (open — reviewer):** which CT-01 form is gated; `store_unlock_reject` (full path) is gated and passed, the post-KDF form
  is informative (§4).
- **K7-03b:** not done in A-4 (§0.2 ran only if named); Phase B row.
- **The CI Kani figure of `92b4404`:** pending (reviewer); the report's Kani table keeps "pending".
- Q-A18…Q-A23 (§5 D17, D18, D21, D22, D25, D27) for the reviewer.

**A-4c fixes (WEISUNG M7-A4c; `modell=claude-sonnet-5-5`).** Base `ebb639f`, commits `13174b1`, `d35f60e`.

- **§3 CRLF audit** (tests added since `bf55099` that read a file and match a multi-line needle): `expect::tests::coverage_store_90` (the
  failure of PR run 40918729835) and `expect::tests::mutants_scope_includes_store` (`"\nkat = ["`) now read through `lf()`; already
  normalised: `scan.rs` testkit `kat` manifest, `fuzz_targets_store`, `declares_kat_module`, the nextest killer profile,
  `mutant_harness_suite_under_30s`. New test `expect::tests::crlf_needles_normalised`.
- **Seed helper (Q20):** `persist.rs` `#[cfg(test)]` and `#[cfg(feature = "kat")]` on separate lines; `cargo mutants … --package
  secmp-client-core --features kat --list`: 859 → 857 mutants, `seed.rs` 2 → 0.
- **Renumbering after A-3:** `mutants-accepted.md` `core/mod.rs` `:751:39`→`:755:39`, `:1733:21`→`:1737:21`, `:1733:44`→`:1737:44` (no new
  acceptance); the fixture `run_163` in `gates.rs` follows; all five client-core rows match the current `--list`.
- **Windows harness (run 40918729835, job 123605864045):** the four "failed" tests — `m6_sched::strict_one_link_per_queue`,
  `m6_props::prop_schedule_independent_of_activity`, `m6_sched::strict_counts_for_every_period`,
  `m6_sched::strict_recv_link_one_fetch_per_period` — are `ABORT` with `0xc000013a` (CTRL+C) at 18:40:20, children killed by the
  cancellation: a budget cut, no product-test change. The 23 min of `kat` (18:14:07–18:37:12) are the rebuild of the kat feature set
  (`openssl-src` 18:25–18:27, `secmp-relay` 18:28–18:36), no test running. Evidence: `windows-a3-timings-40918729835.txt`.
- **ADR-045 Amendment 13:** `windows-native`/`dispatch-windows` 90 → 240 min, `JOB_BUDGETS`, docs/06 §4.
- **§4 ci-fast:** `ci-fast-a4c-1-13174b1.txt` (run on the tree of `13174b1` before `cargo fmt`; fmt FAIL there), `ci-fast-a4c-2-d35f60e.txt`:
  all steps PASS except **policy `large-files`** (and the nextest test `gates::tests::large_file_gate_is_clean_on_this_tree`):
  `docs/reviews/M07-evidence/ci-full-a4-c3c1dcf.txt` is 2 896 642 B > 2 097 152 B and not in `LARGE_FILE_ALLOW` (committed in `29a1865`,
  A-4). **Blocked:** not touched here (evidence file, no gate change); needs the reviewer's decision (trim the file, or an
  `LARGE_FILE_ALLOW` entry by ADR-052).

## A-4e fix-ups (WEISUNG M7-A4e; verifier `VERIFY-A4-part1` of 2026-10-30; `modell=claude-sonnet-5-5`)

Guard: tree clean, HEAD `9d0f22f9280ebf911e1794635068e9258e01c308` (A-4c commits `13174b1`, `d35f60e`, `37118da`, the A-4d2 commits `5d44443`, `8426991`, `3ce6c70`, `9d0f22f` present). The weisung's header names base `bf55099…` (the A-2 commit); the actual HEAD at the guard is `9d0f22f`. Commits: `fix(store): K_db only in locked pages…` (A4-1-01, 08), `fix(store): durable wrap creation…` (A4-1-02, 07), `test(store): hand-written record AD…` (A4-1-03), `fix(store): backup settings allowlist…` (A4-1-04, 05, 06), `fix(store): a skipped entry shorter than its key…` (Q175, A4-1-09, 10), `test(crypto,store): killers for the A-4e mutants`, `docs(m7): mutants-accepted wrap.rs row follows the code (A-4e)`. Code head `e88fd22`. No spec, ADR, label, vector or wire/format byte change; `Cargo.lock` unmoved; no skip, no `#[ignore]`, no threshold, no new error variant. `wrapping_and_header_kat` and `wrap_bytes_recomputed` stay green unchanged.

### §3 tests (one row per new or re-dictated test)

| item | test | commit | red first |
|---|---|---|---|
| A4-1-01 | `store::tests::k_db_never_outside_a_locked_page` | §1 | `left: 1, right: 0` (`Zeroizing<[u8; 32]>`) |
| A4-1-01 | `secmp-crypto secret::tests::with_fill_writes_in_place` (the `Err(Unavailable)` path needs a failing locked-memory backend and is not reachable from a unit test) | §1 | new function, no red |
| A4-1-01 (re-dictated) | `store::tests::key_pragma_order_and_zeroizing` (82 bytes via `expose_secret()`, prefix/suffix), `store::tests::raw_key_pragma_value` (compares `expose_secret()` bytes; the one-bit check reads `DbKey::k_db_kat()`), `secrets::tests::long_lived_keys_in_secret_pages` (+ `locked(db_key.k_db_kat())`) | §1 | expectations unchanged, types changed |
| A4-1-08 | `wrap::tests::locked_memory_failure_is_unavailable` | §1 | `left: Unlock, right: Unavailable` (with `kdf_error = |_| Unlock` first) |
| A4-1-02 | `wrap::tests::create_is_durable_and_refuses_existing` | §2 | `left: 0, right: 2` (`sync_all` count); the create-twice half is green at first run |
| A4-1-07 | `store::tests::open_unlocked_with_another_profile_is_unlock`, `wrap::tests::unlock_without_wrap_is_unavailable`, `contacts::tests::contacts_read_failure_is_unavailable` (new `contacts.rs` test module) | §2 | green at first run (pin already-correct behaviour) |
| A4-1-03 | `seal::tests::ad_vector_{prekeys, sessions, identity, relays, invitations, outbox}` | §3 | each with one wrong byte first (int width / length byte): all six `Error: Rejected` (`a4e-red-first.txt`), then the correct vector, green |
| A4-1-04 | `backup::tests::settings_allowlist_pinned` | §4 | `left: ["retention", "retention_days", "theme"] right: ["retention_days"]` |
| A4-1-04 (re-dictated) | `backup::tests::contents_whitelist` (BK-01): fixture `('retention_days', …), ('theme', …)`, settings section = `[retention_days]` | §4 | — |
| A4-1-05 | `backup::tests::export_path_hardening` (`OneDrive - X`, `Dropbox_Team`, `Nextcloud-Work` → `CloudFolder`; `Boxes`, `Boxed-in` no hit; `<tmp>/Dropbox/../safe/x` → Ok, written into `safe`, mode `0o600`; existing file → `Unavailable`, bytes unchanged; symlink into `Dropbox` → `CloudFolder`) | §4 | `left: Ok(()) right: Err(CloudFolder)` (`OneDrive - X`) |
| A4-1-06 | `backup::tests::import_refuses_any_nonempty_table` (eight cases) | §4 | `left: Ok(()) right: Err(Unavailable)` (`prekeys`) |
| A4-1-09 / Q175 | `sessions::tests::short_skipped_entry_refused`; `sessions::tests::session_rows_round_trip` re-dictated (entries `[b'e'; 36]` + ordinal; `again` = 36 B; + `skipped_keys` = first 36 B) | §5 | `left: Ok(()) right: Err(Unavailable)` |
| mutant killers | `store::tests::incomplete_keys_open_nothing`, `backup::tests::bare_file_name_resolves_against_the_current_dir` | killers | — |

New tests: 19 (17 plus 2 mutant killers); 13 seen failing first (`a4e-red-first.txt`); green at first run: the three of A4-1-07, `with_fill_writes_in_place` and the two killers; re-dictated: 5 (`key_pragma_order_and_zeroizing`, `raw_key_pragma_value`, `long_lived_keys_in_secret_pages`, `contents_whitelist`, `session_rows_round_trip`). Red-first outputs: `docs/reviews/M07-evidence/a4e-red-first.txt` (13 failing tests).

### Anchors and checks

- **A4-1-01:** `store.rs:42` `pub struct DbKey(Option<StoreKey>, Option<TableKeys>);`; `open_inner` refuses a key without `K_db` or without table keys with `Unavailable` (`DbKey::has_db`). `wrap.rs` `db_key` hands the derived `StoreKey` over by value.
- **A4-1-08:** `wrap.rs:86` `kdf_error` used at `:99` (`kek`), `:334` (`open_mk`) and `backup.rs:714` (`open_body`; the `kek` of `backup.rs:648` goes through `wrap::kek`). `Caead::open_locked` uses no locked memory, so its errors stay `Unlock`.
- **A4-1-04 settings keys in product code** (`grep -rn "settings" crates --include=*.rs`, outside `#[cfg(test)]`): only `messages.rs:155` `"SELECT value FROM settings WHERE key = 'retention_days'"`; `BACKUP_SETTINGS_KEYS = ["retention_days"]`, `BACKUP_SETTINGS_EXCLUDED = []` (`backup.rs:73,75`). The filter is applied after the read.
- **A4-1-05:** `in_cloud_folder` stays lexical; `export_checked` canonicalises the parent (`resolved`, `backup.rs:161`), refuses an existing path before the key derivation and at creation (`create_new`, Unix `0o600`, `sync_all`; a failed write removes the file). `export_kat` goes through the same path (its parent must exist).
- **A4-1-09 callers of `insert_skipped`** (`grep -rn "insert_skipped" crates`): `backup.rs:972` and `:976` (68 B) checked: ≥ 36 B; `sessions.rs:271–273` and `:279` re-dictated to ≥ 36 B; `sessions.rs:362` (`SKIPPED_ENTRY_LEN`) checked: ≥ 36 B; `seal.rs:272` (47 B) checked: ≥ 36 B; `schema.rs:147` (68 B) checked: ≥ 36 B; `m7_forensic.rs:91` (68 B) checked: ≥ 36 B; `secmp-client-core/src/persist.rs:214` (entries of `RatchetParts.skipped`, `SKIPPED_ENTRY_LEN` each; `persist.rs:76` already refuses < `SKIPPED_KEY_LEN`) checked: ≥ 36 B. No short caller outside `secmp-store` tests.
- **A4-1-10:** `seal.rs:2` already reads "accepted 2026-10-29, Q144" (A-4d2); nothing changed.

### §4 gates

| gate | result |
|---|---|
| `cargo xtask ci-fast` at `e88fd22` (`ci-fast-a4e-e88fd22.txt`, head on line 1, clean tree; named by the real head, the code head after the killers, not by the §5 commit `f0e4bdf`) | PASS: fmt 1 s, clippy 3 s, policy 1 s, deny 0 s, vet 1 s, audit 2 s, cooldown 23 s, nextest 20 s, doctest 1 s, hello 0 s, kat 121 s, harness 1034 s |
| local mutants (`mutants-a4e-f0e4bdf.txt`; diff `9d0f22f..`) | crypto 0 / 0 / 1 / 0 of 1 (c/m/u/t); store first run 49 / 3 / 28 / 0 of 80, after the killers 52 / 0 / 28 / 0; `mutants-accepted.md` row `wrap.rs:123:9` → `:133:9` |
| `cargo nextest run -p secmp-testkit --features harness` (before the killers) | 317 passed |

### §7 risks

None new. Blocked: none. STOP: none.

## B-SC (WEISUNG M7-B-SC; scheduler-core carry-overs, their Kani proofs, heap-free `tr_header_selection`; `modell=claude-opus-5-5`)

Guard: tree clean, HEAD `99ad44c174227c6bac5b8f621e612d26a7b72489`. Pins quoted at `99ad44c`: `gates.rs:11245-11246` `assert_eq!(all.len(), 51);` / `assert_eq!(kani_verified(&kani_log(all, 0))?.len(), 51);` (`KANI_HARNESSES.len()` = 51, `FUZZ_TARGETS` 35); A-4 §0.2 (K7-03b) had not run — `kani_proofs.rs:291` `let results: Vec<Choice> = opened.iter().map(|o| choice(*o)).collect();`, so §4 ran; `git diff --stat 92b4404..99ad44c -- crates/secmp-client-core/src/scheduler crates/secmp-proto`: `crates/secmp-proto/src/kani_proofs.rs | 2 +-`, `crates/secmp-proto/tests/fuzz_max_len.rs | 34 ++++++++++++++++++++++++++++++--` (2 files, 33 insertions, 3 deletions). No spec, ADR, label, vector, wire or store change; `Cargo.lock`/`fuzz/Cargo.lock` unmoved; no skip, `#[ignore]`, threshold, Kani bound change of an existing harness, stub or limit change.

### §2 commits

| commit | what |
|---|---|
| `74b7ea6` | commit 0 `docs(m7): Phase B re-dictations (Q145–Q174)`, edits E1–E16, E5b, E12b (every old quote found exactly once) |
| `14acea8` | §0.2 `feat(proto): pooled invitation queue, prekey seeds, classified accept, KeyChange signing, K_id/SK kat accessors (Q147)` |
| `107dad8` | §1 `feat(core): deferred-commit deliver; ack = highest committed prefix (OQ-20; SC-01, SC-02)` (amended once before its ci-fast: a clippy fix in the new test code) |
| `9722477` | §2 `feat(core): logical link id in Purpose and LinkEvent; frame ids for frame_written (FIN5b-1, FINAL3 (e); SC-04, SC-05)` (amended: an extra K-C2 cover dropped — `kani_cover_count_is_pinned` pins covers against committed runs) |
| `ca99b15`, `1f5b604`, `07117f0`, `20eae50` | §3 SC-06, SC-07, SC-08, SC-09: one commit per harness with its registration (`KANI_HARNESSES`, `KANI_COVERS`, pin +1, the committed alone run `kani-m7-bsc-sc-<harness>.txt` read by `kani_cover_count_is_pinned`, G7-15b) |
| `a4897e3` | §3 SC-10 `feat(core): pure::fetch_lead_deadline and pure::flush_bound; K-C5 calls them (SC-10, D-B3)` |
| `b7d7ee6` | §4 `fix(kani): tr_header_selection without the heap (K7-03b, Q138 item 3)` (exception Q138 lifted in the same commit) |
| `57d7da2` | `fix(xtask): G7-15b test spells the Kani proof attribute in parts` (the literal made `gates::kani` count `xtask` as a harness package; found by the first full step) |
| `b92c28f`, `27c644c` | mutant killers (`core::tests::old_generation_errors_change_nothing`, `Received::is_empty`); the committed-id trim of `Deferred::on_done` is an `if` (its `while` mutant hung) |
| `864ac09`, `651edce`, `6d36dc0` | `docs(mutants)`: the `pure.rs:84:30` equivalent row; renumbering (no new acceptance); the gate test `accepted_rows_with_escaped_pipes_match_the_survivors` follows `755:39 → 800:39` |
| `923b9ee` | evidence |

### §3 rows

| row | test | result | red first |
|---|---|---|---|
| Q147 (i) | `hx::store::issue_invitation_on_uses_the_pool_queue_seeds` (frozen hx-0003/0004 as oracle), `issue_invitation_on_draws_no_seed` | pass; `cargo xtask vectors` before (`74b7ea6`) and after (§0.2 tree): `vectors: 12 suites identical to vectors/ref (structural, SCHEMA §1; positive rows of encodings)`, every suite "agrees with ref; frozen file unchanged", identical; `vectors/` untouched | new API |
| Q147 (ii) | `hx::store::seed_encodings_round_trip_and_reject_every_other_length` (SPK 172 B, OPK 100 B, record 128 B; every truncation and one extension `Rejected`) | pass | new API |
| Q147 (iii) | `hx::classified::{classified_valid_group_among_garbage_spends_the_group, classified_rejected_group_is_spent, classified_partial_group_is_not_spent, classified_unavailable_spends_nothing}` | pass | new API |
| Q147 (iv) | `tr::tests::key_change_body_is_signed_by_the_old_key` (oracle `tr/tests.rs` `key_change`; the existing KeyChange tests unchanged) | pass | new API |
| Q147 (v) | `hx::tests::key_accessors_report_the_last_derivation` (kat), doctest `hx::kat_key_accessors_only_under_kat` (`compile_fail,E0425` without `kat`) | pass | — |
| SC-01 | `harness::m7_drain::drain_f_cells_per_response` (2.4 s) | Strict silent: 4 committed per response, drained after 32 periods (bound 45); Strict 1/P: 4 per response, 43 periods (66); Balanced silent: 8 per `FETCH_MULTI` response, 16 slots (21); Balanced 1/slot: 8, 19 slots (24) | not runnable on the old tree (new API); the old behaviour is R-01's M6 series |
| SC-02 | `harness::m7_drain::ack_is_highest_committed_prefix` | commits 1, 3, 2 at 12, 15, 25 s → ack 1, 1, 3; the `FETCH`es carry 0, 1, 3 at their ticks 10, 20, 30 s; handed to the source 1, 2, 3, then 2 (3 committed, not asked again) | new API |
| SC-03 | the six modules (`sc-03-regression-57d7da2.txt`) | 42 passed (380 s); SIM-02 queue B → A at the end: 1 cell (M6: 128) | the SIM-02 assertion on the old core: "queue B -> A holds 128 cells at the end of the run" |
| R-01 (OPEN-M6-B-1, name kept) | `m6_driver_io::receive_throughput_per_fetch_is_measured` | new series: committed at (s) [11, 11, 11, 11], ready to acknowledge [11, 11, 11, 11], relay acknowledgement [20] (M6: [11, 21, 31, 41] / relay [30, 40, 50, 60]) | the new expectation on the old core: "the relay saw one acknowledgement of all four" left 4, right 1 |
| SC-04 | `harness::m7_links::logical_link_id_in_events` | the swap is rejected per logical link ("1500 ms") and accepted pooled; a run with 60-s link lifetimes: 2 logical links × 15 connections, every `Up`/`TornDown` names its connect's logical id, 28 lifetime teardowns checked per link; the FIN5b-1 oracle tests keep their names (`oracle_rejects_a_crossed_reconnect_that_breaks_the_pooled_bound` now reports A's own 2 500 ms) | the swap fixture under the M6 pooled matching passes (shown in the test) |
| SC-05 | `scheduler::core::tests::frame_written_duplicate_detected` | out of order, duplicate with a non-empty ledger, empty ledger: `Err(UnknownFrame)`, counted, ledger unchanged; unknown link `Ok` | new API (M6: a duplicate popped the oldest entry by design, FINAL3 (e)) |
| SC-06…SC-09 | `kani_in_flight_over_transitions`, `kani_queue_generations`, `kani_persist_contract_abstract`, `kani_paired_executions` | `VERIFICATION:- SUCCESSFUL` each, covers 2/2, 3/3, 3/3, 3/3 (§4 table) | — |
| SC-10 | `xtask::testscan::kc5_calls_extracted` | pass | on `9722477` + SC-06 work, before any extraction: `left: []` (no call site) |
| K7-03b | `tr_header_selection_k0_2`, `…_k3`, `…_k4` | 5.8 %, 5.8 %, 7.4 % alone; exception Q138 lifted | — |
| G7-15b | `xtask::expect::tests::fuzz_and_kani_lists_core` (opened with SC-06, the four B-SC harnesses) | pass | — |

Extracted (store-free, codec-free) into `core/pure.rs` and called by the core: `Received`/`RecvLedger` (+`take_response`), `InFlight`, `sendable`, `send_choice`, `fetch_lead_deadline`, `flush_bound` (+`FLUSH_WAIT_MS`, re-exported by `scheduler::run`). `InFlight` is a fixed 4-slot array: a `Vec` or `VecDeque` of symbolic length ran CBMC out of memory (116 GB) over eight events; `max_in_flight` is clamped to `IN_FLIGHT_TICKS` = 2 (spec §10.3).

### §4 gates and Kani

| harness | alone (`kani-m7-bsc-a4897e3.txt`, `kani-m7-bsc-k703b-b7d7ee6.txt`, `kani-m7-bsc-accept-14acea8.txt`) | in the step (`kani-m7-bsc-full-57d7da2.txt`) |
|---|---|---|
| `kani_in_flight_over_transitions` (SC-06) | 10.6 %, 39 s | 10.6 % |
| `kani_queue_generations` (SC-07) | 24.9 %, 80 s | 22.3 % |
| `kani_persist_contract_abstract` (SC-08, unwind 4) | 84.6 %, 458 s | 83.2 % |
| `kani_paired_executions` (SC-09, unwind 4) | 68.6 %, 139 s | 67.2 % |
| `kani_deadline_arithmetic_checked` (K-C5) | 1.6 %, 779 s | (step) |
| K-C1 / K-C2 / K-C3 / K-C4 / K-C6 | 35.9 / 39.7 / 31.8 / 14.2 / 4.2 % | (step) |
| `kani_accept_opk_delete_only_on_success` | 87.7 %, 426 s | 87.0 % |
| `kani_hx_grouping` / `…_record_names_opk1` / `…_deleted_opk2` | 42.2 / 41.8 / 45.2 % | (step) |
| `tr_header_selection_k0_2` / `_k3` / `_k4` | 5.8 / 5.8 / 7.4 % | 5.8 / 5.5 / 7.2 % |

Full step `cargo xtask step --strict kani` at `57d7da2`: PASS, 55/55 harnesses verified, every cover satisfied, wall 4197 s (70 min; `expect::JOB_BUDGETS` `("kani", 150)`; not above 120 min, so no per-harness timing table is required); highest peak in the step 87.0 % (`kani_accept_opk_delete_only_on_success`). Unwinds of SC-08 and SC-09 are 4 = each loop's bound + 1 (unwind 6/5 measured 132.6 % / 86.0 % alone).

| gate | result |
|---|---|
| ci-fast | `ci-fast-bsc-0-74b7ea6`, `-p-14acea8`, `-1-107dad8`, `-2-9722477`, `-3-a4897e3`, `-l-923b9ee`: PASS each (harness 852–1088 s) |
| mutants (`mutants-bsc-651edce.txt`) | core 133 caught / 7 missed / 24 unviable / 1 timeout of 165 at first; after the killers 140 / 1 (accepted: `pure.rs:84:30`, equivalent) / 24 / 0; proto 43 / 0 / 31 / 0 of 74 |
| coverage (`coverage-bsc-6d36dc0.txt`) | secmp-client-core 95.0 %, secmp-proto 97.6 % (min 90 %) |
| ci-full (`ci-full-bsc-923b9ee.txt`, A-3b summary form, Q174) | PASS: fuzz 4317 s, coverage 941 s, Miri 2426 s, Kani 4327 s (55/55; highest peak 86.7 % `kani_accept_opk_delete_only_on_success`; SC-08 83.3 %, SC-09 66.7 %, SC-07 22.3 %, SC-06 10.6 %, `tr_header_selection_k4` 7.2 %), ProVerif `--models tr` 142 s, ref-vectors 969 cases identical; ct, mutants, proverif-link, windows-native, windows-cross delegated |

### §5 deviations

- **D-B3** (Q157): SC-10 is `xtask::testscan::kc5_calls_extracted`, a source scan, not a Kani harness; K-C5 keeps its name.
- **D-SC1**: `pure::InFlight` clamps `max_in_flight` to 2 ticks (spec §10.3's two) and holds 4 requests in a fixed array; a caller asking for more gets two (no caller does: `Params::default()` is 2, no test changes it).
- **D-SC2**: the extra K-C2 cover (a duplicate report) was dropped; K-C2 asserts it instead (a cover needs a committed run under `kani_cover_count_is_pinned`).
- **D-SC3**: the full Kani step ran once, after §4 (at `57d7da2`), covering §3 and K7-03b; §3's alone runs are per commit.
- **D-SC4**: `World::fetched` gives a recv-queue a generation (`RecvLedger`), and error answers of an older generation are ignored too (SC-07 "a response of an old generation never updates the new one").
- **D-SC5**: the `FETCH` is built once the previous response's cells are committed, at the latest at its lead (`fetch_lead_ms`, the parameter's documented meaning); its tick time does not move.

### §8

- **OQ-20** resolved by OPEN-M7-08 A (no spec change); `docs/09` not edited.
- **FIN5b-1** closed (logical link id, per-link oracle). **FINAL3 (e)** closed (frame ids). **KANI-M6-C-1**: see B-SC2 §7. **K-C5** closed (SC-10).
- Blocked: none. STOP: none.


## A-4f fix-ups (WEISUNG M7-A4f; external review EXT1, Astra @ 99ad44c; rulings Q176–Q180; `modell=claude-sonnet-5-5`)

Guard: `git status --short` empty; `merge-base --is-ancestor 99ad44c HEAD` exit 0; `diff --stat 99ad44c HEAD -- <store, fuzz target, corpus>` empty. `<G>` = `1a7b4da` (`docs(m7): B-SC closed @ 923b9ee`). Migration check: `grep -n "settings" crates/secmp-store/src/migrate.rs` → no match (the table is created in `schema.rs:51`, no default row).

### §2 commits
| commit | subject |
|---|---|
| `842145e` | fix(store): wrap creation serialized by the profile lock (EXT1-2, Q178; A4-1-02) |
| `c16d9ac` | fix(store): typed retention_days codec, import allowlist, settings in the empty-profile rule (EXT1-3, EXT1-4, Q177, Q179; A4-1-04) |
| `847d1dd` | fix(fuzz): store_record_open even mode accepts an authentic record; authentic seed (EXT1-5, Q180) |
| `ee0f79e` | docs(m7): ADR-053 Amendment 2 (Proposed), F9b, outbox doc; Q176–Q180 (EXT1) |

### §3 tests (one row per new or re-dictated test)
| test | commit | state |
|---|---|---|
| `wrap::tests::create_publishes_without_replace` (new) | `842145e` | red first (`left: 0, right: 1`, try_lock) |
| `wrap::tests::concurrent_create_exactly_one_wins` (new, kat_small, 16 rounds) | `842145e` | red first (the winner's digest was not the wrap on disk) |
| `wrap::tests::create_is_durable_and_refuses_existing` (re-dictated: `create_new` ≥ 1) | `842145e` | green |
| `backup::tests::retention_round_trips_through_store_retention` (new) | `c16d9ac` | red first (`left: Err(Unavailable), right: Ok(())`) |
| `backup::tests::retention_wire_length_other_than_4_rejected` (new) | `c16d9ac` | red first (`left: Ok(()), right: Err(Unlock)`) |
| `backup::tests::import_refuses_non_allowlisted_setting` (new) | `c16d9ac` | red first (`left: Ok(())`) |
| `backup::tests::import_refuses_profile_with_settings` (new) | `c16d9ac` | red first (`left: Ok(()), right: Err(Unavailable)`) |
| `backup::tests::contents_whitelist` + `settings_allowlist_pinned` fixtures (re-dictated: INTEGER 30 via `?1`; section `[("retention_days", [0,0,0,0x1e])]` unchanged) | `c16d9ac` | green |
| `backup::tests::import_refuses_any_nonempty_table` (re-dictated: nine cases) | `c16d9ac` | green |
| `seal::tests::authentic_even_seed_opens` (new; seed `8d094c96986f6f9330eb1c8639191fa4099c6021`) | `847d1dd` | red first (`left: None, right: Some(Unavailable)`) |
| `backup::tests::import_refuses_duplicate_settings_key` (new, Q181) | `88ce8bb` | red first (`left: Ok(()), right: Err(Unlock)`) |
| `backup::tests::export_refuses_out_of_range_retention` (new; verifier nit 4, no product change) | `88ce8bb` | green at first run |

New tests: 7; re-dictated: 4 (+ the BK-01/allowlist fixtures). Red seen: 7 (`a4f-red-first.txt`; the race test was red at its first run). `wrapping_and_header_kat` and `wrap_bytes_recomputed` unchanged and green. Store suite: 80 passed. `grep -rn store_record_open xtask/src`: no corpus-count or hash pin (the check is `seeds >= 4`), no xtask edit; `cargo nextest run -p xtask -E 'test(/fuzz_targets_store|large_file_gate/)'` 6 passed; `cargo +nightly-2026-09-21 fuzz run --fuzz-dir fuzz store_record_open fuzz/corpus/store_record_open/8d094c96... -- -runs=1`: executed, no crash.

### §4 gates
| gate | result |
|---|---|
| `cargo xtask ci-fast` at `ee0f79e` (`ci-fast-a4f-ee0f79e.txt`, clean tree) | **FAIL: step 1 `fmt` only** (rustfmt layout of the new test code in `backup.rs`, `seal.rs`, `wrap.rs`); every other step PASS (clippy, policy, deny, vet, audit, cooldown, nextest, doctest, hello, kat, harness 285/285). No further fix made (weisung §5.1). |
| local mutants (`mutants-a4f-ee0f79e.txt`; diff `1a7b4da..`) | store 17 caught / 0 missed / 10 unviable / 0 timeout of 27 |

### §5 deviations
- **D-A4f1** (EXT1-2, Q178): lock-serialized create: `wrap::create` holds `<dir>/lock` from before the existence check to the publish (`rename`); a writer that ignores the lock is outside the contract; a per-call `wrap.<pid>.<n>.tmp`; a stale one from a crash is left in place (never read).
- **D-A4f2** (EXT1-3, Q177): `retention_days` = u32 BE on the wire, INTEGER in SQLite; BK-01 fixture re-dictated to INTEGER 30 (`contents_whitelist`), wire bytes unchanged; ADR-053 Amendment 2 Proposed.
- **D-A4f3** (EXT1-4/Q179): import rejects a non-allowlisted settings key (`Unlock`); the empty-profile rule covers nine tables (+ `settings`).
- **D-A4f4** (EXT1-5, Q180): even-mode oracle accepts an authentic record; seed `8d094c96986f6f9330eb1c8639191fa4099c6021` added.
- **D-A4f5** (Q181): a repeated settings key in a backup section is refused with the uniform `Unlock` (canonical decode, §1.8); the verifier's scratch reproduction (last value won) is the red of `import_refuses_duplicate_settings_key`.
- **Note A-4f (verifier m-2):** the red-first line of `concurrent_create_exactly_one_wins` (`a4f-red-first.txt:54-57`, `wrap.rs:427@ee0f79e`, bare arrays) predates the committed assertion form (`wrap.rs:449@51e918c`, `Some([...])`); the oracle is the dictated one; against the pre-fix `create_with` the test is red by chance (verifier: 7 of 10 runs), deterministic red is the scan test.
- A4-1-02 and A4-1-04 were closed by half in A-4e (VERIFY-A4-part1:101,111: no-replace publish and the import-side allowlist missing); closed by `842145e` and `c16d9ac`.
- Q176: EXT1-1 minor; F9b recorded in A-4f; fix in Phase B (B-4, SE-21). Q177: retention_days typed codec. Q178: lock-serialized wrap create. Q179: import allowlist + nine-table empty rule. Q180: even-mode oracle + authentic seed.
- Implementation note: `create_with` keeps the write/sync/rename inside a closure in its own body so the source scans of `create_is_durable_and_refuses_existing` and `create_publishes_without_replace` read all of it. `seal.rs` (test only) is edited because §3 dictates the seed test there.

### §7
- F9b: see §7 Open risks (`:480`).

### §8
- Blocked: ci-fast step `fmt` (new test code layout, see §4); no other failure. STOP: none.

### A-4f2 gates (WEISUNG M7-A4f2; `modell=claude-sonnet-5-5`)
| gate | result |
|---|---|
| commits | `9ac2451` style(store): rustfmt (4 hunks, all in `#[cfg(test)]`); `88ce8bb` Q181; `2f9dc89` docs |
| `cargo xtask ci-fast` at `2f9dc89` (`ci-fast-a4f2-2f9dc89.txt`, clean tree) | PASS, all steps (fmt now green) |
| local mutants (`mutants-a4f2-2f9dc89.txt`; diff `51e918c..`) | store 7 caught / 0 missed / 1 unviable / 0 timeout of 8 |
| red-first (`a4f2-red-first.txt`) | 1 red (`import_refuses_duplicate_settings_key`: `left: Ok(()), right: Err(Unlock)`); `export_refuses_out_of_range_retention` green at first run |
| store suite | 82 passed; `wrapping_and_header_kat`, `wrap_bytes_recomputed` unchanged |
- `settings_slot` (helper of the decode loop) keeps `decode` under clippy's `too_many_lines`.
- Blocked: none. STOP: none.

## B-SC2 fix-ups (WEISUNG M7-B-SC2; rulings Q182–Q186; `modell=claude-opus-5-5`)

Guard (2026-10-31): `git status --short` empty (exit 0); `merge-base --is-ancestor 51e918c HEAD` exit 0; `git log --oneline 1a7b4da..HEAD` = `bf34f9b`, `2f9dc89`, `88ce8bb`, `9ac2451`, `51e918c`, `ee0f79e`, `847d1dd`, `c16d9ac`, `842145e` (A-4f, A-4f2); the diff of the B-SC paths `1a7b4da..HEAD` empty (exit 0); `cargo fmt --all -- --check` clean (exit 0). `<G>` = `bf34f9b73b1d13ef55914737505a7fd8ee1a9af8`. The §2 blocker (the SC-10 scan pinned `prepare_link → fetch_lead_deadline`; `testscan.rs` outside the file list) was resolved by WEISUNG M7-B-SC2b (Q183 amendment); guard of B-SC2b: tree clean, HEAD `d2b93ba`.

### §2 commits

| commit | what |
|---|---|
| `2ae2270` | §1 `fix(core): nothing is handed to the worker unrecorded (Q182, §1.7)` |
| `d2b93ba` | the §2 blocker note (docs) |
| `5ad062b` | §2 `fix(kani): SC-09 over the activity inputs that reach the core (Q183); SC-10 scan follows the extraction` |
| `0110d44` | §3 `test(kani,core): SC-08 hostile-relay responses (Q184)` |
| `a1c1d96` | §4 `test(fuzz): scheduler_event_sequence drives the deferred path with the §1.7 oracle (Q185)` |
| `0bed941` | §5.1 `test(xtask): Q44 skip-list entries for two drifted harness tests (Q186)` |
| `0b9a5ed` | `docs(mutants): line renumbering after B-SC2, no new acceptance` (`core/mod.rs` 800:39 → 806:39, 1806 → 1812; `pure.rs` 84:30 → 99:30; the accepted-rows gate test follows) |
| `4eee783` | evidence (red-first, mutants, Kani step) and planning follow-ups |
| `69bfc24` | `fix(xtask): the cover pin reads the B-SC runs through a helper (clippy too_many_lines)` (the reader of `5ad062b` pushed `kani_cover_count_is_pinned` past 100 lines; caught by the first ci-fast, `ci-fast-bsc2-4eee783` not committed) |

### §3 tests

| row | test | commit | red first (`bsc2-red-first.txt`) |
|---|---|---|---|
| Q182 | `pure::tests::hostile_relay_never_acks_uncommitted` | `2ae2270` | `id 6 acked 7 not committed` |
| Q182 | `pure::tests::full_ledger_hands_nothing` | `2ae2270` | `left: 5, right: 4` |
| Q182 | `pure::tests::hostile_relay_random_sequences` (10 000 runs × 12 steps; LCG in the test) | `2ae2270` | first run on the pre-fix tree: `id 13 acked 17 not committed` |
| Q183 | `kani_proofs::kani_paired_executions` (re-dictated; 4 covers) | `5ad062b` | the pin with 4 covers against the B-SC run: `missing: kani_proofs::kani_paired_executions: 4 of 4 satisfied` |
| Q183 | `xtask::testscan::kc5_calls_extracted` (amended: `prepare_link → fetch_due → fetch_lead_deadline`; the SC-09 site is its run `balanced_run`) | `5ad062b` | on `d2b93ba`: `left: [... ("scheduler/core/mod.rs", "prepare_link", "fetch_lead_deadline") ...]`, `right: [... ("scheduler/core/mod.rs", "prepare_link", "fetch_due") ...]` |
| Q183 | `pure::tests::fetch_due_and_note_sent` | `5ad062b` | new functions |
| Q184 | `kani_proofs::kani_persist_contract_abstract` (widened: arbitrary ids ≤ 7, any order, duplicates, gaps; handed-id oracle) | `0110d44` | against the pre-Q182 `take` (check removed temporarily): `VERIFICATION:- SUCCESSFUL` — not red: the F1 sequence needs more responses than N = 3 and three responses of ≤ 3 ids reach; F1 is red in the §1 unit tests |
| Q185 | FZ-04 `scheduler_event_sequence` (deferred path, hostile responses, §1.7 oracle) + seed `3ef4177e…` | `a1c1d96` | 120 s against `bf34f9b` (pre-Q182) in a scratch copy: not reached (`Done 6163 runs in 121 second(s)`), as the ruling expected (64-slot ledger, ≤ 192 events) |

`a_full_ledger_keeps_the_ack_below_what_it_could_not_record` is unchanged and green. After §1 the SC-01 (four fixtures), R-01 and SIM-02 series are byte-identical to `bsc-series-57d7da2.txt` (strict-silent 4/period drained after 32; strict-constant 43; balanced-silent 8/slot 16; balanced-constant 19; R-01 committed [11, 11, 11, 11], relay [20]; SIM-02 1 cell).

### §4 Kani, mutants, CI

| harness | alone | in the step (`kani-m7-bsc2-full-0b9a5ed.txt`) |
|---|---|---|
| `kani_paired_executions` (SC-09, unwind 4) | 52.4 %, 235 s (`kani-m7-bsc2-sc-kani_paired_executions.txt`) | 51.6 % |
| `kani_persist_contract_abstract` (SC-08, unwind 4) | 88.4 %, 754 s (`kani-m7-bsc2-sc-kani_persist_contract_abstract.txt`) | 87.2 % |
| K-C1 / K-C2 / K-C3 / K-C4 / K-C5 / K-C6 (F6: re-measured) | — | 33.5 / 37.5 / 29.7 / 13.6 / 0.7 / 4.1 % |

Kani step at `0b9a5ed`: PASS, 55/55 (the pin of 55 unchanged), wall 4620 s (77 min; `JOB_BUDGETS` `("kani", 150)`), highest peak 87.2 % (`kani_persist_contract_abstract`; `kani_accept_opk_delete_only_on_success` 86.9 %). SC-09 measurement path: a `Vec` ledger carried over three ticks with symbolic report points ran CBMC out of memory (116 GB, also split by `n`: `_n1` and `_n3` alone each); one tick 3.9 %, two ticks 23.6 %; with a fresh pre-sized ledger per tick after `report_all` asserts it empty, the unsplit harness is 52.4 % — no split, name and pin unchanged.

Mutants (`mutants-bsc2-0b9a5ed.txt`; one run per package over the whole B-SC in-diff set `99ad44c..0bed941`, no `--re`; F5): core 151 caught / 1 missed / 24 unviable / 0 timeout of 176 — the miss is the accepted equivalent row (`pure.rs:99:30`, formerly `:84:30`); proto 43 / 0 / 31 / 0 of 74. These replace the composed B-SC core tally (140/1/24/0).

| gate | result |
|---|---|
| ci-fast (`ci-fast-bsc2-69bfc24.txt`) | PASS (harness 900 s) |
| ci-full (`ci-full-bsc2-69bfc24.txt`, summary form Q174) | PASS: fuzz 4279 s, coverage 892 s (secmp-client-core 95.1 %), Miri 2429 s, Kani 4724 s (55/55; highest peak 87.5 % `kani_accept_opk_delete_only_on_success`; SC-08 87.1 %, SC-09 51.2 %), ProVerif `--models tr` 143 s, ref-vectors 969 cases identical; ct, mutants, proverif-link, windows-native, windows-cross delegated |
| fuzz (Q185) | 300 s on the §4 tree: no crash, `Done 17667 runs in 301 second(s)` |

### §5 deviations

- **D-SC6** (Q182): `take` checks `Received::can_record` before `deliver`; a handed cell is always recorded.
- **D-SC7**: an id seen but never handed (the ledger was full) may be passed by the acknowledgement once the floor's id is recorded — equivalent to the relay omitting it (docs/01: the relay may drop cells); no §1.7 violation.
- **D-SC8** (Q183): the core sees an opaque `PreparedCell` (`core/mod.rs:749`); real versus dummy is the cell source's (`Conversation::prepare`) and is carried by AI-01…AI-06, SE-19 and ProVerif L12 — a type-level fact, not an SC-09 input. A source not ready at the tick is an overrun (`types.rs:248`, `core/mod.rs:577-584`), covered by the overrun tests.
- **D-SC9** (Q183): `pure::fetch_due` (`prepare_link`) and `pure::note_sent` (`World::tick`) extracted; `fetch_lead_deadline` is reached from `prepare_link` through `pure::fetch_due`; the SC-10 scan pins the chain `prepare_link → fetch_due → fetch_lead_deadline` (WEISUNG M7-B-SC2b). Each SC-09 tick starts from a fresh ledger after `report_all` (the production ledger is empty there too).
- **D-SC10** (Q184): SC-08 widened and kept (88.4 % alone ≤ 90 %); no `kani_persist_contract_hostile`. *[B-4c (VERIFY-B4 P3 m-8): the SC-08 Kani bound does not reach the F1 sequence; F1 is guarded by `pure::tests::hostile_relay_*` (A4f2-BSC2 m-1).]*
- **D-SC11** (Q185): FZ-04 relay with real cells, hostile response modes, late commits, frame reports and the §1.7 oracle; event budget ≤ 5 bytes, `FUZZ_MAX_LEN` 970 unchanged.
- **D-SC12** (Q186): the reviewer extends Q44 to drifted tests: `lifetime_end_reconnects_fresh` (16.8 s) and `link_lifetime_uniform_6h_24h` (10.9 s) in `MUTANT_HARNESS_SKIP_TESTS` (times of the full harness run of `ci-fast-bsc-l-923b9ee`; alone 8.5 s and 5.8 s).

### §7 risks

*[B-4c (VERIFY-B4 P3 m-8): the A4f2-BSC2 minors m-1…m-5 of the B-4 Commit-0 block (below, §Commit 0 corrections) belong here: m-1 the SC-08 Kani bound vs F1 (D-SC10); m-2 the SC-10 red-first line is of an earlier `want`, the committed `want` is red on `d2b93ba` too; m-3 the Q186 times rest on Q44; m-4 SC-09 covers 1 and 2 are input-only, the reserved branch of `reserved_rr` has no cover; m-5 the SC-01/R-01/SIM-02 series are summarised.]*

- KANI-M6-C-1: items 1–3 and 5 closed; item 4 closed by the re-dictated SC-09 (Q183); the SEND-before-FETCH guard (`core/mod.rs:670-671`, M06-report:791) is not harness-covered — OPEN-M7-B-2.
- SC-07: late commits of an old generation are routed by `Deferred`'s counter (`run.rs:451-492`); `Scheduler::delivery_committed` takes no generation — OPEN-M7-B-3.
- Two activity-dependent overrun margins at system level: real-cell preparation latency in the Deferred worker; FETCH prepared at its 1 s lead while commits are pending (D-SC5) — not a core leak; Phase B measurement posten.
- (F6) `kani-m7-bsc-a4897e3.txt` was measured on the amended commit `9a5d10a` (not in history); re-measured in `kani-m7-bsc2-full-0b9a5ed.txt`.
- SC-08 runs at 87–88 % of the Kani limit (alone and in the step): the closest harness to the 90 % line.

### §8

Blocked: none (the §2 blocker resolved by WEISUNG M7-B-SC2b, Q183 amendment). STOP: none.


## Phase B part 1 — B-1…B-3 (BRIEF M7-B; `modell=claude-sonnet-5-5`)

### §1 Status and preconditions

B-3 built @ `b5bb6e0` (code head; the evidence and report commits follow it); **K7-01 blocked** (§8); B-4…B-7 follow (WEISUNG M7-B-4). Start head `b57ca46`.
Guard and preconditions, checked before any change: `git status --short` empty, `git log --oneline -1` = `b57ca46`; (1) `git merge-base --is-ancestor 99ad44c HEAD` succeeds and
`secmp-store/src/{wrap,seal,profile,contacts,backup}.rs` exist; (2) `grep -c '^    "kani_proofs::kani_paired_executions",$' xtask/src/expect.rs` = 1, `pub fn frame_written(&mut self, link: LinkId, frame: FrameId) -> Result<(), SchedError>`
(`scheduler/core/mod.rs:1929`), the four proto `pub fn` lines = 4, commit `docs(m7): Phase B re-dictations (Q145–Q174)` in `git log`; (3) `COOLDOWN_EXCEPTIONS: … = &[]`; (4) `git diff bf55099..HEAD -- vectors/` empty.
Start counts: `KANI_HARNESSES.len()` 55, `FUZZ_TARGETS.len()` 35, the `kani_refuses_fifteen_harnesses` literals 55/55. End counts: Kani 55 (K7-01 not registered), fuzz 36.

### §2 Commits

| Step | Commit | What |
|---|---|---|
| B-1 | `cf440c4` | `Profile::create/open_with/rotate_if_due/retire`, the 97-B identity section, prekey rows (PR-01, PR-02); `api::{Error, InviteReject, Event}`; the sealed record (`invitations::Stored`); store rows for prekeys, invitations, relay pool, retained cells; schema V1 in place (`relays.pool`, `invitations.retained`) |
| B-1 | `1e2f1c8` | `contacts` (PR-04…PR-08); store `contacts.routes`/`queues` sealed (Q151), `STATE_REMOVED`, state/verified updates |
| B-1 | `140b510` | `settings` (PR-09), store `settings.rs`, `BACKUP_SETTINGS_EXCLUDED` |
| B-1 | `1e358a7` | evidence `ci-fast-b1-140b510.txt` |
| B-2 | `0314820` | `invitations` (issue, owner status, `maintain`, `process_round`, `check_invitation`, `accept_invitation`, `SparePool`, `StagedPrekeys`), `retention::retain`, `sessions::write_initial`, `initial_parts`, `schema::tests::capability_columns_are_sealed`, `docs/04:45` (IN-01…IN-04, IN-09…IN-13, IN-18, IN-19, IN-21) |
| B-2 | `cdac99c` | FZ-04 (`invitation_queue_retention`, corpus, lists, pins, `fuzz_max_len.rs` entry V-01, G7-15b extended) |
| B-2 | `9dd26c8` | `gates::tests::fuzz_executor_depth` follows 36 targets (211 s) |
| B-3 | `8b0c5ba` | `kat::txn_log`, `harness::m7_accept` (IN-05, IN-06, IN-07, IN-20), `invitations::tests::opk_and_record_in_one_txn` (IN-08) |
| close | `04b5249`, `a86e0eb`, `451dfac`, `b5bb6e0` | killers; accepted rows (six equivalent survivors); IN-05 trace writes `target/m7-evidence/in-05-accept-trace.txt` |

### §3 Rows (28 dictated; 26 built, G7-15b FZ-04 half only, K7-01 blocked — corrected by B-3b, Q195; both close with Q191, see B-3b)

| Row | Test | Result |
|---|---|---|
| PR-01 | `profile::tests::new_profile_keys` | pass; `Profile::create` with the real Argon2 cost; entropy of `fp-0001` gives the vector's IKS (2017 B) and fingerprint |
| PR-02 | `profile::tests::spk_retained_for_open_invitations` | pass; gen 1 present on day 8 and 19, retired on day 21 with the invitation and its OPK; reopened state equal |
| PR-04 | `contacts::tests::identity_is_whole_iks` | pass; two contacts, source scan finds no signing-half use |
| PR-05 | `contacts::tests::sas_matches_vectors` | pass; `vectors/sas.json` cases 1–3, both sides |
| PR-06 | `contacts::tests::verify_by_digits_or_qr` | pass; Q158 own-first form |
| PR-07 | `contacts::tests::same_iks_as_existing_contact` | pass; `Event::DuplicateIdentity { existing, new }` |
| PR-08 | `contacts::tests::contact_removed_control` | pass; the conversation keeps preparing cells; the `Control` delivery is wired by B-4 |
| PR-09 | `settings::tests::defaults_and_roundtrip` | pass |
| IN-01 | `invitations::tests::uses_pool_queue` | pass; oldest pool queue, `LinkPut` `Prompt`, no `QUEUE_NEW`, zero timing draws |
| IN-02 | `invitations::tests::queue_keys_independent_of_iks` | pass |
| IN-03 | `invitations::tests::record_fields_persisted_sealed` | pass; column = plaintext + 72 B |
| IN-04 | `invitations::tests::uri_roundtrip` | pass; 332 characters |
| IN-08 | `invitations::tests::opk_and_record_in_one_txn` | pass; `kat::txn_log`, `StagedPrekeys::commit_accept` refuses another OPK / invitation |
| IN-09 | `invitations::tests::unclassified_cells_capped_24` | pass; ids checked after each of four rounds |
| IN-10 | `invitations::tests::complete_group_spent_after_one_accept` | pass |
| IN-11 | `invitations::tests::accept_only_offered_records` | pass; `accept_calls_kat` 1 → 1; `QueueDel` due in [1 min, 60 min] |
| IN-12 | `invitations::tests::invitee_checks_5_5` | pass; Expired / Unsupported / Mismatch / Invalid / Ok |
| IN-13 | `invitations::tests::invitee_reply_queue_from_pool` | pass |
| IN-18 | `invitations::tests::used_by_someone_else` | pass; once |
| IN-19 | `invitations::tests::reissue_link_put_after_relay_restart` | pass; same blob and `ld_id`, no write, `Delayed` |
| IN-21 | `invitations::tests::link_key_lifetime` | pass; peak 1, 0 after each step |
| IN-05 | `harness::m7_accept::commit_with_accepted_before_any_ack` | pass (≈1 s); `in-05-accept-trace-451dfac.txt` |
| IN-06 | `harness::m7_accept::commit_failure_is_unavailable` | pass; `FailAt(k)` for k = 1…6 |
| IN-07 | `harness::m7_accept::crash_inside_accept_is_atomic` | pass; `MidTxn(1…6)` all-before, `AfterCommitBeforeAck` all-after |
| IN-20 | `harness::m7_accept::k_id_independent_end_to_end` | pass |
| FZ-04 | fuzz `invitation_queue_retention` | `fuzz-m7-b-cdac99c.txt`: 1 974 581 runs, 0 crashes, final `cov: 369 ft: 2286` |
| G7-15b | `xtask::expect::tests::fuzz_and_kani_lists_core` | FZ-04 half; K7-01 half closes with Q191 (B-3b `1057964`). Was: "FZ-04 half built" counted as built (Q195); red first: without the target in `FUZZ_TARGETS` it fails at `expect.rs:2299:9` (`invitation_queue_retention`); the K7-01 half is not built |
| K7-01 | `kani_retention_bound_24` | **blocked**, §8 |

Extra tests: `schema::tests::capability_columns_are_sealed`, `kat::tests::txn_log_records_table_and_verb`, `secmp-store` `profile::tests::{lifecycle_rows, identity_fingerprint_column}`, `contacts::tests::routes_and_queues_are_sealed`,
`settings::tests::{settings_round_trip, byte_keys_are_excluded_from_backups}`, `contacts::tests::reinvite_required_state`, `profile::tests::section_rotation_and_consumed_retirement`, `retention::tests::{matches_the_reference, never_more_than_24, zero_and_full_set}`,
`invitations::tests::{issue_equals_issue_invitation_on, killers_pool_and_counters, killers_rounds_and_contact, killers_expired_invitation}`, `api::tests::errors_display_fixed_text`.

### §4 Gates

ci-fast: B-1 `ci-fast-b1-140b510.txt` green; B-2 `ci-fast-b2-cdac99c.txt` **red** (`fuzz_executor_depth`, an unlisted count pin, fixed in `9dd26c8`); B-3 `ci-fast-b3-8b0c5ba.txt` green; close `ci-fast-b3-l-b5bb6e0.txt` green. No ci-full.
Fuzz FZ-04: above. Coverage (`coverage-b3-8b0c5ba.txt`): client-core 95.1 %, store 96.1 %.
Mutants (`mutants-b3-451dfac.txt`): core first run 365 tested: 216 caught, 49 missed, 100 unviable; rerun after the killers 359: 251 caught, 8 missed, 100 unviable; of the 8 two are killed by `451dfac`, six are equivalent and are rows of `docs/mutants-accepted.md`
(`invitations.rs:817:19`, `:930:58`, `:1143:22`, `retention.rs:42:15`, `:56:14`, `:56:29`). Store: 122 tested: 94 caught, 4 missed (`identity_fingerprint`, killer `identity_fingerprint_column`), 24 unviable; rerun: 98 caught, 0 missed.
Kani K7-01: three attempts: 34 min stopped at 9.6 GB (≈ 68 % of the limit), 60 min, 60 min (`kani-m7-b-k701-blocked.txt`); none finished (corrected by B-3b, Q195). The comment of the old harness (`kani-k701-harness.rs.txt:28`, "no proof in 70 minutes") is wrong: the evidence is 34/60/60 min. The harness is history, superseded by Q191 (B-3b).

### §5 Deviations

- **D-B6 (issue path).** The brief has the product issue through `MemoryPrekeyStore` as a view built from the sealed store. `MemoryPrekeyStore` has no constructor or import for persisted generations, OPKs or records (Q147 added the seed codecs of the parts only), `Entropy` is sealed (no replay), and an empty view would create a new signed prekey per invitation (spec §6.1: one per 7 days). B-2 therefore assembles the bundle and the invitation in `invitations::issue` from the public pieces (`SpkGeneration::from_seeds`, `OpkSecrets::from_seeds`, `inv::bundle_signed_message`, `Entropy::sign`, `inv::seal_blob`) with the draws of `issue_invitation_on` in the same order; `issue_equals_issue_invitation_on` compares the blob, the invitation and the URI byte for byte with the reference. No `secmp-proto` change. A proto `MemoryPrekeyStore::from_parts` would replace it; reviewer's choice. For the same reason the identity is drawn as three 32-byte secrets (`HybridSigningKey` gives no seeds back).
- **D-B7.** The accept path (`StagedPrekeys`, `sessions::write_initial`, `initial_parts`) is in `0314820`, not in the B-3 commit: IN-10 (B-2) needs an accepted handshake. The B-3 commit has `kat::txn_log` and the atomicity tests.
- **D-B8.** Two count pins outside the brief's list changed with the 36th fuzz target: `expect::tests::fuzz_targets_store` (35 → 36) and `gates::tests::fuzz_executor_depth` (218 s, 14 394 → 211 s, 14 374).
- **D-B9.** K7-01 is not registered and has no commit; `KANI_HARNESSES` stays 55. The retention function itself is built, tested (reference oracle, fuzz) and loop-counter-indexed for the checker.
- Initial `Inbox` of a new session is empty and has no `sessions` part-2 row (as a conversation writes it only when non-empty); the trust row is written (`Unverified`).
- The `api.rs`/`relay_view.rs` of the placement: `api.rs` holds the error and event types only; `relay_view.rs` is not built (no row in B-1…B-3).
- `ci-fast` per step: B-2 and B-3 ran separately; the evidence of B-2 is the red run.

### §6 Locks and vectors

`git diff --stat b57ca46..HEAD -- Cargo.lock fuzz/Cargo.lock`: empty. `git diff b57ca46..HEAD -- vectors/`: empty.

### §7 Risks

Write cost of the new sealed columns: `relays.pool` is rewritten whole per take/fill (≤ 68 B per queue), `invitations.retained` up to 24 × 4104 B per non-deciding round, `invitations.record` carries the 12 360-B blob; none is on the per-slot path. A consumed invitation's sealed record (link key) stays until its expiry (`maintain`); IN-21 covers memory, not that. `link_data_n` is the first four bytes of `ld_id` (2⁻³² collision refused at issue).

### §8 Blocked / questions

**K7-01 (`kani_retention_bound_24`, RT-1): not proven within the time the step can afford.** The harness (`kani-k701-harness.rs.txt`: `retain` over ≤ 40 inputs, fixed arrays sliced to symbolic lengths, no heap) ran three ways (`kani-m7-b-k701-blocked.txt`): symbolic-index insertion, 34 min at 9.6 GB and growing; loop-counter insertion (committed), killed at 60 min with 6.7 GB; with ids below 64, killed at 60 min with 6.2 GB. A shorter harness (fewer inputs) needs a bound change, which the brief forbids without a ruling. Question: accept a K7-01 over a smaller bound (e.g. 8 + 8 inputs, 8-bit ids) and a separate induction argument for the full 40, or a different formulation? Until then FZ-04 and `retention::tests` are the evidence.

Return to the reviewer: D-B6 (proto `from_parts` or the assembly kept).

## CI1 (WEISUNG M7-CI1; Q187, Q188; modell=claude-sonnet-5-5)

### §2 Commits
`6ae6f44` test(harness): m0_early killers of the timing.rs rejection-sampling mutants (Q187, G7-10) · `aa89fd5` ci(win-ondemand): probe perl and cargo-nextest before the build (Q188). Guard `<G>` = `7d80d6a`.

### §3 The tests
`m0_early::accept_ceiling_is_the_largest_multiple_of_span`, `sample_with_accepts_below_the_ceiling_and_rejects_at_it`, `sample_round_composes_ceiling_and_sample` (three; the weisung says four but lists three and excludes `uniform_counts_one_draw_per_call`). `cargo nextest run -p secmp-testkit --features harness -E 'test(/^m0_early::/)'`: 7 passed, new tests 0.007–0.011 s each, slowest 0.147 s. Q188: steps "Probe perl" and "Probe cargo-nextest" after "Probe the runner toolchain"; `cargo nextest run -p xtask -E 'test(/win_|vm_up|vm_down|nasm|id_token|oidc|workflow|ondemand/)'`: 30 passed. *[Corrected by B-4 Commit 0, amended in place by B-4c (VERIFY-B4 P3 m-8): the two filters on the start head `9b511a2`: `m0_early::` 7 passed; the xtask filter 30 passed (`ci1-m0early-xtask-9b511a2.txt`).]*

### §4 Evidence
`mutants-ci1-timing-aa89fd5.txt`: RED (old `m0_early.rs`, `--timeout 120`) 40 mutants: 30 caught, 4 unviable, **6 timeouts** — exactly `accept_ceiling` None/Some(0)/Some(1), `sample_with` None and `>=`→`<`, `sample_round` None (reproduced locally). GREEN (HEAD): 40 mutants, 36 caught, 4 unviable, **0 timeouts, 0 missed**; of the timing.rs mutants 30 caught, 3 unviable. Command deviation (documented in the file): the weisung's `--features harness --package secmp-client-core --file timing.rs` fails in the unmutated tree (no such feature in that package), so `--package secmp-transport` was added and `--re` replaces `--file`; `--re` let 7 non-timing mutants through. *[Corrected by B-4 Commit 0, amended in place by B-4c (VERIFY-B4 P3 m-8): `timing.rs`: 30 caught / 3 unviable / 0 timeout of 33; the whole run 36 / 4 / 0 of 40; the CI1c footer reading "30/3/0, 40 run" is superseded by this.]*
ci-fast-ci1-aa89fd5.txt red at fmt; ci-fast-ci1c-f32e8e8.txt green (after `f32e8e8` style(harness): rustfmt of the m0_early killers, formatting only).

### §5 Deviations
D-CI1: the Q186 skips removed the accidental early killers of the `timing.rs` mutants; explicit `m0_early` killers (G7-10) replace them; the skips stay. *[Corrected by B-4 Commit 0, amended in place by B-4c (VERIFY-B4 P3 m-8): D-CI2: the CI1 mutants command deviated (`--package secmp-transport` added, `--re` instead of `--file`; recorded in CI1 §4).]*

### §6 win-test
win-test 41128820834 failed in 15 min (perl + nextest invisible to the SYSTEM runner service); with Q188 the next failure is at the probe; `vm-down` skipped by design (`was_running == true`).

### §7 PR-run 41193864080
all jobs green except mutants shards 2/3/4/5/8/9 (timeouts of timing.rs mutants); fixed here.

### §8 Blocked
**Resolved by CI1c (`f32e8e8`): ci-fast green.** Was: ci-fast red at `fmt` (WEISUNG M7-CI1 §3: BLOCKED, no further fix). `cargo fmt --all --check` wants `m0_early.rs:108` wrapped over four lines:
```
-    assert_eq!(sample_with(18_446_744_073_709_551_609, 5, 10, C10), Some(14));
+    assert_eq!(
+        sample_with(18_446_744_073_709_551_609, 5, 10, C10),
+        Some(14)
+    );
```
Pure formatting of `6ae6f44`; the mutants runs are unaffected. Return to the reviewer: allow `cargo fmt` as a fix-up.

## B-3b (WEISUNG M7-B3b; Q189–Q195; modell=claude-opus-5-5)

Guard (2026-10-31, session M7-B3b2; single commands, each exit 0): `git status --short` empty; `git merge-base --is-ancestor 7d80d6a HEAD`; `git log --oneline 7d80d6a..HEAD` = `05f58e1` (CI1 ci-fast green), `f32e8e8` (CI1c rustfmt), `6a34863`, `aa89fd5`, `6ae6f44` — as expected; `git diff --stat 7d80d6a HEAD -- crates/secmp-client-core/src crates/secmp-proto/src crates/secmp-store/src xtask/src/expect.rs` empty; `cargo fmt --all -- --check` clean. `<G>` = `05f58e1da71ee5010efc28e9b496a544ea7d4246`.

### §2 commits

| commit | what |
|---|---|
| `373869b` | §1 `refactor(proto,core): one issue construction — issue_on_parts, identity section (Q189)`; the `mutants-accepted` row of the deleted `signed_bundle` (`invitations.rs:817:19`) removed with it |
| `323b209` | §2 `test(core): killers for three non-equivalent mutants (Q190)` + `b3b-red-first.txt` |
| `1057964` | §3 `test(kani,core): K7-01 as an inductive step over offer (Q191)` + the alone run |
| `c70827c` | §4 `fix(core): invitation minors (Q192)` |
| `5d2be5f` | `test(core): decide acknowledges the cells of a consumed record (mutants miss)` — the one miss of the §5 mutants run |
| this commit | §5 `docs(m7): B-3b @ 5d2be5f (Q189–Q195)` with the evidence files |

### §3 tests (one row per new or re-dictated test)

| ruling | test | commit | evidence |
|---|---|---|---|
| Q189 | `secmp-proto` `prekeys::tests::identity_section_round_trip` | `373869b` | green; `generate_with_section` and `generate` from one `FixedEntropy` stream give the same `IKSPublic`; `from_section` gives it back; version 0x02 and 96 bytes `Rejected` |
| Q189 | `invitations::tests::issue_equals_issue_invitation_on` (extended) | `373869b` | green on three paths, each blob, invitation, URI **and stored `InvitationRecord` (`to_bytes`)** byte-equal to `MemoryPrekeyStore::issue_invitation_on`: reused OPK; `opk_is_new` (the creation's OPK row deleted first); SPK rotated inside the issue (day 8; reference `spk_id` 2). The rotation case runs on the `opk_is_new` path: the reference rotates before it draws the OPK, the product draws the reused OPK at creation — reused-OPK + rotation has no reference draw order | *[Corrected by B-4 Commit 0, amended in place by B-4c (VERIFY-B4 P3 m-8): it runs `issue_on_parts` on both sides and pins the core's store work (lookups, OPK/rotation draw position, stored record), no longer the construction itself (pinned by the hx/encodings vectors).]*
| Q190 | `invitations::tests::commit_accept_twice_is_rejected` | `323b209` | red 1/3 (`left: Ok(())`, `right: Err(Rejected)`) |
| Q190 | `invitations::tests::check_invitation_refuses_bad_version_before_kind` | `323b209` | red 2/3 (`left: Some(Unsupported)`, `right: Some(Invalid)`) |
| Q190 | `retention::tests::offer_ignores_a_prefilled_out` | `323b209` | red 3/3 (`left: Some([18446744073709551615])`, `right: Some([1])`) |
| Q191 | `retention::tests::retain_is_fold_of_offer` (10 000 LCG runs) | `1057964` | green |
| Q191 | `kani_proofs::kani_retention_bound_24` (K7-01, unwind 25, 4 covers) | `1057964` | `VERIFICATION:- SUCCESSFUL`, 0 of 343 failed, 4 of 4 covers |
| Q192 | `invitations::tests::live_counter_counts_owner_status_open` | `c70827c` | green; peak 1, live 0 after, flag written. Green on the old code too (the old path's raw plaintext was not counted, so no counter test can see it); it pins the single open | *[Corrected by B-4 Commit 0, amended in place by B-4c (VERIFY-B4 P3 m-8): it pins peak 1 / live 0 / the persisted flag; the no-raw-read property is structural (read in `invitations.rs`); the test stays green with a raw read reintroduced.]*
| Q192 | `invitations::tests::decide_rechecks_status_after_lock` | `c70827c`, `5d2be5f` | green; with the re-check disabled by hand: `consumed: accept is not called` fails (sanity, not committed); (a) also asserts `ack_through == Some(3)` (`5d2be5f`, the mutants killer; red with the field deleted: `left: None`) |
| Q192 | `harness::m7_accept::k_id_independent_end_to_end` (IN-20) | `c70827c` | green; now also asserts the two sealed records byte-identical (D-B13) |
| Q191 | `xtask::expect::tests::fuzz_and_kani_lists_core`, `gates::tests::{kani_refuses_fifteen_harnesses, kani_cover_count_is_pinned}` | `1057964` | green (56; the pin reads `kani-m7-b3b-sc-kani_retention_bound_24.txt`) |

All new tests green on the final code (`cargo nextest run -p secmp-client-core -p secmp-proto --features kat`: 487 passed at `c70827c`; the m7_accept harness 4/4; ci-fast at `5d2be5f`). *[Corrected by B-4 Commit 0, amended in place by B-4c (VERIFY-B4 P3 m-8): on the start head `9b511a2`: 487 passed; `m7_accept::` 4 passed (`nextest-b3b-9b511a2.txt`).]*

### §4 Kani, mutants, coverage, vectors

- **K7-01 alone** (`kani-m7-b3b-sc-kani_retention_bound_24.txt`): 40 s wall, peak 783 092 KiB = **5.5 %** of `KANI_CBMC_RSS_LIMIT_KIB`. `KANI_HARNESSES` 55 → 56.
- **Mutants** (`mutants-b3b-5d2be5f.txt`; in-diff `git diff 7d80d6a..HEAD -- crates/secmp-client-core/src crates/secmp-proto/src`, forms of `mutants-a3b-core-proto-store-cdc3c0a.txt:11/:15`, no `--re`): core run 1 (`c70827c`) 18: 10 caught / **1 missed** / 7 unviable / 0 timeouts — `invitations.rs:941:21` delete field `ack_through` in `decide` → killer `5d2be5f`; core run 2 (`5d2be5f`) 18: **11 / 0 / 7 / 0**; proto 23: **7 / 0 / 16 / 0**. Unviable: `Default::default()` returns of types without `Default`, and `+ → -` in the const `IDENTITY_SECTION_LEN` (compile-time underflow). Caught of the viable: 100 % in both.
- **Coverage** (`coverage-b3b-5d2be5f.txt`, `cargo xtask step coverage`, PASS 976 s): secmp-client-core 95.6 % (B-3: 95.1 %), secmp-proto 97.7 %, secmp-store 96.1 %.
- **Vectors** (`b3b-vectors-373869b.txt`): before (`05f58e1`) and after (`373869b`) `vectors: 12 suites identical to vectors/ref (structural, SCHEMA §1; positive rows of encodings)`; the outputs differ only in build times, run ids and per-test timings (filtered diff empty).
- **ci-fast** (`ci-fast-b3b-5d2be5f.txt`): PASS (harness 897 s; the working tree had the uncommitted §5 docs only).
- Locks: `git diff --stat 05f58e1..HEAD -- Cargo.lock fuzz/Cargo.lock vectors/ '*Cargo.toml' docs/03-protocol-spec.md formal/ crates/secmp-store/src crates/secmp-client-core/src/scheduler` empty.

### §5 deviations

- **D-B6 closed (Q189).** `secmp-proto` exposes the existing construction: `prekeys::bundle_on_parts`, `prekeys::issue_on_parts` (the bodies of `MemoryPrekeyStore::bundle`/`issue_with`, moved), `IdentityKeys::{generate_with_section, from_section}` (+ `IDENTITY_SECTION_VER`, `IDENTITY_SECTION_LEN`). `generate_with_section` draws the three 32-byte seeds with `Entropy::secret` (byte-identical under `FixedEntropy` to `hybrid_signing_key` + `x25519`; the core's former `new_identity`), because `HybridSigningKey` gives no seeds back. The core keeps the store work; its `issue_in` assembly, `signed_bundle`, `new_identity`, `keys_from_section`, `identity_parts` are deleted; `profile::SECTION_LEN` is now `IDENTITY_SECTION_LEN`.
- **D-B9 closed** (K7-01 built, Q191).
- **D-B10** (Q193): `invitations.rs` (consumed path of `process_round`/`decide`) acknowledges and drops the cells of a consumed record; spec `docs/03:351` keeps processing them as TR cells of the session for U[1 h, 24 h] — B-4 commit 1 (OPEN-M7-B-6).
- **D-B11** (Q194): QUEUE_DEL only after an empty FETCH is deferred to the host's queue; nothing sequences it (Q163) — B-4 (OPEN-M7-B-7).
- **D-B12** (Q195): `a86e0eb` (`test(core,store): killers …`) changed product code: `TRAILER_LEN` removed and the `Stored::encode` capacity hint changed (`invitations.rs:65-66,145` @`a86e0eb`).
- **D-B13** (Q192, IN-20): IN-20 keeps its method — both host profiles built from one entropy stream (same identity, prekeys, queue and record) — instead of `InvitationRecord::duplicate_kat`, which copies the record without the SPK/OPK it names (the second store would have none of them); the test now asserts the two sealed records' plaintexts byte-identical.
- **D-B14** (form): the weisung writes the `B_SC_HARNESSES` entry as `("kani_proofs::kani_retention_bound_24", 4)`; the list holds bare names (the test prefixes `kani_proofs::`), so the entry is `("kani_retention_bound_24", 4)`.
- **D-B15** (Q190 scope): besides the three dictated rows, the row `invitations.rs:817:19` (`signed_bundle`) was deleted in `373869b`: its code is gone (the file's rule "an entry is removed when the code changes"). `retention.rs:42:15` and `:56:29` stay (lines unchanged).
- `on_owner_status`/`process_round`/`decide` share `offer_state` (open / consumed / expired from the row); `FLAGS_AT` removed (the flag is set on the decoded record and re-encoded).

**Corrections in the B-1…B-3 section (Q195):** §3 heading — 26 built, G7-15b the FZ-04 half only (K7-01 half closes with Q191); G7-15b row likewise; §4 K7-01 — three attempts: 34 min stopped at 9.6 GB (≈ 68 % of the limit), 60 min, 60 min (`kani-m7-b-k701-blocked.txt`); the old harness comment "no proof in 70 minutes" (`kani-k701-harness.rs.txt:28`) is wrong. `kani-k701-harness.rs.txt` is history, superseded by Q191.

### §7 risks

- OPK ids are still `max + 1` (OPEN-M7-B-10): an id of a consumed/retired OPK is issued again once no row holds it.
- `issue` commits in three transactions (rotation; the issue; `fill_opks`): a failure after the rotation leaves the new SPK generation (harmless: it is the current one).
- The `opk_is_new` and rotated paths of the differential test share one case; reused-OPK + rotation has no reference order (§3).

### §8 Blocked / questions

- **OPK counter (Q192 item 3) not built — item STOP only.** `git grep -n 'fn .*meta' 05f58e1 -- crates/secmp-store/src`: no match (exit 1); no store function persists a counter without a schema or store-code change. Proposal (OPEN-M7-B-10): a `meta` row `opk_next` — store `fn meta_u32(&self, key: &str) -> Result<Option<u32>>` and `fn put_meta_u32(tx, key: &str, v: u32)` over a `meta(key TEXT PRIMARY KEY, value BLOB)` table — read and advanced (`checked_add`) in the transaction that inserts an OPK (`issue_in`, `fill_opks`, `Profile::create_with`); test `opk_ids_never_reused` (consume the highest OPK, `fill_opks`, the new id exceeds every id ever issued).
- Question OPEN-M7-B-9: `spk_expiry` = this invitation's `expires` versus `docs/03:293` ("MUST be ≥ the expiry of every invitation referencing it").

Blocked: none. STOP: none.


## Commit 0 corrections (WEISUNG M7-B-4; VERIFY-DELTA-B3b, VERIFY-DELTA-A4f2-BSC2; `modell=claude-sonnet-5-5`)

*[B-4c (VERIFY-B4 P3 m-8): each correction below is now also amended in place at its line (CI1 §3, §4, §5; B-3b §3 `issue_equals…`, `live_counter…`, the 487-passed line; B-SC2 §5 D-SC10 and §7); this block stays as the record.]*

- **CI1 §4:** `timing.rs`: 30 caught / 3 unviable / 0 timeout of 33; the whole run 36 / 4 / 0 of 40 (`mutants-ci1-timing-aa89fd5.txt`); the CI1c footer reading "30/3/0, 40 run" is superseded by this line.
- **CI1 §3:** the two filters it names, on the start head: `m0_early::` 7 passed; the xtask `win_|vm_up|vm_down|nasm|id_token|oidc|workflow|ondemand` filter 30 passed (`ci1-m0early-xtask-9b511a2.txt`).
- **B-3b §3 ("487 passed at `c70827c`; the m7_accept harness 4/4"):** on the start head `9b511a2`: `cargo nextest run -p secmp-client-core -p secmp-proto --features kat` 487 passed; `m7_accept::` 4 passed (`nextest-b3b-9b511a2.txt`).
- **D-CI2:** the CI1 mutants command deviated (`--package secmp-transport` added, `--re` instead of `--file`; recorded in CI1 §4).
- **B-3b §3 `live_counter_counts_owner_status_open`:** pins peak 1 / live 0 / persisted flag; the no-raw-`invitation_record`-read property is structural (shown by reading `invitations.rs`); the test stays green with a raw read reintroduced.
- **B-3b §3 `issue_equals_issue_invitation_on`:** runs `issue_on_parts` on both sides; pins the core's store work (lookups, OPK/rotation draw position, stored record), no longer the construction itself (that is pinned by the hx/encodings vectors).
- **B-SC2 §7 (A4f2-BSC2 minors):** m-1 SC-08 Kani bound does not reach the F1 sequence; F1 is guarded by `pure::tests::hostile_relay_*` (same clause in D-SC10). m-2 the red-first line of the amended SC-10 scan (`bsc2-red-first.txt`) is of an earlier revision of `want` (`fetch_due`); the committed `want` (`balanced_run`) is also red on `d2b93ba` (same left side). m-3 Q186 times not re-measured: ci-fast-bsc2 shows 16.471 s / 10.762 s (`ci-fast-bsc2-69bfc24.txt:3116,3108`); the entries rest on Q44 (full-run time), not on the alone-time rule text of `expect.rs:636-640`. m-4 SC-09 covers 1 and 2 are input-only predicates; the reserved-position branch of `reserved_rr` is reached (tick 0 is always a SEND) but no cover witnesses it — follow-up: a cover "choice made against a non-empty ledger". m-5 the SC-01/R-01/SIM-02 series are summarised at B-SC2 §3, not quoted; the delta verifier re-ran them byte-identical to `bsc-series-57d7da2.txt`.
- **TEST-SPEC / OPEN-M7:** SE-21 inserted (g 22, B 73, total 179, unconditional 174); Q196 and Q197 decided and booked (`OPEN-M7.md` B-9, B-10).


## Phase B part 2 — B-4…B-7 (WEISUNG M7-B-4; sessions actor, `Api`, scheduled handshake, rotation, restart, boundary, activity; `modell=claude-sonnet-5-5`)

### §1 Status and preconditions

~~Phase B closed @ `1318baa`~~ (withdrawn, WEISUNG M7-B-4c Q212 (11): VERIFY-B4 found 3 blockers and 16 majors; Phase B closes with B-4c): 33 of the 34 dictated rows are built and pass (SE-13a is dictated "not built"), the three completions (ST-17 partial, BK-03, BK-07) and the follow-ups Q193, Q194, OPEN-M7-B-2/3/5/8/10 are done; Phase B is 72 of 73 rows built (B-SC 11 + part 1 28 + part 2 33). Gates: `ci-fast` PASS at `5838ed3`, `ci-full` PASS at `1318baa` (second run; the first failed on one fuzz target, D-B26), Kani 57/57, mutants 0 undocumented survivors, coverage client-core 95.6 %, store 96.1 %. Blocked: none. STOP: none.

Guard of the weisung: `git status --short` empty and `HEAD` = `9b511a24167e33861a0c9ca95e91e0c7700c83c5` at the start (checked). `secmp-proto`, `vectors/`, `Cargo.lock`, `fuzz/Cargo.lock` and every `Cargo.toml` are unchanged since that head (`git diff --stat 9b511a2..HEAD -- Cargo.lock fuzz/Cargo.lock vectors crates/secmp-proto '*Cargo.toml'` is empty); since `<SC-HEAD>` the `secmp-proto` diff is B-3b's Q189 (`prekeys.rs`, `fuzz_max_len.rs`), reported there.

### §2 Commits (`git log --oneline b57ca46..HEAD`, the part-2 ones)

| step | commits |
|---|---|
| Commit 0, SE-18, Q193 | `f387d8d` (TEST-SPEC SE-21, Q196/Q197, verifier notes), `cccf4f9` (`git mv scheduler/conversation.rs sessions/actor.rs`, scans re-pointed), `281a148` (Q193, SE-21) |
| B-4 wiring | `676e9eb` (sessions: routes, key change, reset, receipts, handshake cells, identity rotation; SE-01, SE-06…SE-09, SE-12, SE-13b, SE-15…SE-17, SE-20, IN-15), `c9ea4a1` (lint), `f0d03ad` (Q194, D-B11), `ec36bea` (OPEN-M7-B-3), `941e70f`/`575c34a` (OPEN-M7-B-10), `7336ef4` (OPEN-M7-B-2), `d603655` (OPEN-M7-B-5), `462b6a3` (SE-04, SE-05), `b497092` (SE-10, SE-11), `e3d3728` (`Api`, `Core`, relay view, restore: AP-01, AP-03, AP-07, PR-03, BK-03/ST-17 halves), `5358200` (IN-16, `AfterEmptyFetchFrom`, PR-08 through the `Core`), `a9e3a72` (scan spellings), evidence `1a93bcd`, `71f58c9`, `3343bf4` |
| B-5 | `b2c248a` (queue entries carry relay, queue id, sender seed, period), `b824055` (the hub; IN-14, IN-17, SE-02, SE-03, SE-14; commit title as dictated) |
| B-6 | `6f264a1` (AP-02, AP-04, AP-05, AP-06, SE-19; skip rows) |
| B-7 | Kani evidence `325371c`, `8a10b2e` (the hub tells the core the recv-queue periods; SE-04 on the driver), `1699b44` (killers), `d164f65` (a rotated contact's retiring queue outlives another queue's deletion; accepted rows), `dae510c` (mutants evidence), `c420953` (pipes escaped in the rows), `b72a0fc` (coverage evidence), `66da1d4` (SE-19, SE-03, IN-17 evidence), `5838ed3` (red-first lines), `e365c9f` (final `ci-fast` evidence), `1318baa` (fuzz target fix) |

### §3 Rows (34 dictated: 33 built, SE-13a not built — "SE-13a not built (OPEN-M7-07 B)")

Times are alone-runs of the test (nextest, 32-core container); in `cargo xtask ci-fast` the harness tests run in parallel and take longer (`ci-fast-b6-6f264a1.txt`). Red-first lines: `docs/reviews/M07-evidence/b4-red-first.txt` (B-4 gates), `b6-red-first.txt` (SE-02, AP-02, AP-04).

| row | test | time | notes |
|---|---|---|---|
| PR-03 | `profile::tests::open_wrong_passphrase_uniform` | 0.2 s | `Core::open_kat` with a wrong passphrase and with none is `Error::Unlock`, an empty directory `Error::Unavailable`; the profile directory hashes the same before and after; a profile held by a running core is `Unavailable` (the `flock`), not `Unlock` |
| IN-14 | `harness::m7_accept::initiator_cells_byte_identical_after_restart` | 0.6 s | in-process reopen of the store (a restart of the process for the state; D-B18). After the restart the three persisted cells go out again in order — what was in flight at the crash is not known to have arrived — and a send that failed is retried with the same bytes; `tr_encrypt_calls` does not move (the one encryption of the envelope is `Initiator::start`'s, in `secmp-proto`, which has no counter: the row's "= 1" is read so) |
| IN-15 | `sessions::tests::initiator_only_dummies_until_first_reply` | 1.5 s | |
| IN-16 | `sessions::tests::first_reply_carries_route_update` | 1.2 s | the first reply is a `RouteUpdate` with a pool queue (the pool shrinks by one, no `QUEUE_NEW`); the invitation queue's `QUEUE_DEL` is `When::AfterEmptyFetchFrom(queue, end of U[1 h, 24 h])`: an empty `FETCH` inside the window does not count, another queue's does not, then `U[1 min, 60 min]` |
| IN-17 | `harness::m7_scheduled::handshake_as_scheduled_ops` | 7.5 s | the invitation through the scheduler on two store-backed clients: `LINK_PUT` and `LINK_GET` on one-shot links, the invitee's first three `SEND`s to the invitation queue are the persisted cells byte for byte, the inviter accepts and replies, the invitee has the route update; `overruns()` = 0 and no tick sealed or persisted (`IN-17-tick-audit` in `in-17-tick-audit-b72a0fc.txt`: 3 links, ~220 ticks per client); no set-up link, the pool queues are made on the relay beforehand (set-up outside the run) |
| SE-01 | `sessions::tests::route_update_applied` | 1.4 s | |
| SE-02 | `harness::m7_rotation::sender_resends_last_real_on_new_queue` | 40 s | 3 real + 12 real among the last 128 of 200 cells; after the switch the old queue carries dummies only (`Gate` counts per queue), exactly the 12 are sent again, each message delivered once. Red first: with the `requeue` of `switch_send_queue` removed the test fails at "the 12 real messages … go again" (`left: 0, right: 12`) |
| SE-03 | `harness::m7_rotation::recipient_retires_old_queue` (+ `retirement_survives_restart`, `retirement_delays_are_uniform`) | 144 s / 96 s / 0.02 s | overlap deadline in `[t0+1 h, t0+24 h]`; `QUEUE_DEL` once, on a control link of its own, after max(deadline, the sender's last cell + one period) + `U[1 min, 60 min]`; fetched up to the deletion and not after; gone from the queue set; the deadline is stored with the queue and re-armed after a restart (Q194). KS (seeded, n = 1000): overlap D = 0.030, p = 0.753; delay D = 0.046, p = 0.235 (`se-03-ks-b72a0fc.txt`). The run uses seeded draws (176, 234) chosen for a short run — both in range (D-B20) |
| SE-04 | `sessions::tests::rotation_respects_rate_bound` + `harness::m7_rotation::rotation_deferred_at_the_rate_bound` | 1.3 s / 10 s | Σ and 32 entries (31 + 1 fits, 40 > 32 and 33 entries do not); on the driver a Balanced client at four queues at 10 s answers `Rotated(false)` with `RotationDeferred` and asks nothing of the scheduler |
| SE-05 | `sessions::tests::rotation_every_30_days_or_on_demand` | 1.3 s | |
| SE-06 | `sessions::tests::key_change_blocks_sending` | 1.7 s | the "C2R trace equal to idle (Δ ≤ 5 ms)" clause is SE-19's (a verified key change and an invalid one are part of its activity; D-B21) |
| SE-07 | same test (re-verification unblocks) | — | the row's name `reverify_unblocks` is not a separate test (D-B21) |
| SE-08 | `sessions::tests::invalid_key_change_freezes` | 1.9 s | bad signature, signed by another key; the "unfragmented 0x05" clause is not producible through the session (a `KeyChange` exists only as the fragmented payload; the content-body decoder refuses 0x05 in `secmp-proto`'s own tests) (D-B21) |
| SE-09 | `profile::tests::rotate_identity_announces_key_change` | 3.5 s | |
| SE-10 | `sessions::tests::view_once_refused_for_unverified` | 1.3 s | |
| SE-11 | `sessions::tests::view_once_from_unverified_locked` | 1.3 s | |
| SE-12 | `sessions::tests::receipts_defaults` | 3 s | |
| SE-13a | not built (OPEN-M7-07 B) | — | |
| SE-13b | `sessions::tests::unconfirmed_after_receipt_timeout` | 1.4 s | `Event::NotConfirmed` is an `Api` event (`Core::session_event`) |
| SE-14 | `harness::m7_restart::relay_restart_with_store` | 14 s | each recv-queue re-created 10 s–5 min after the `FETCH` that found it gone, the same queue (the queue set from the store), five messages delivered once |
| SE-15 | `sessions::tests::session_reset_request` | 1.4 s | |
| SE-16 | `sessions::tests::scheduler_entry_after_first_step` | 2 s | |
| SE-17 | `sessions::tests::may_send_real_single_entry` | 1.4 s | |
| SE-18 | `xtask::testscan::session_actor_owns_ratchet` | <0.1 s | |
| SE-19 | `harness::m7_activity::store_backed_source_activity_independent` | 543–602 s | 3 modes × (idle, active) × 6 h virtual, four profiles each, commit latency `U[0, 200] ms`; **max |Δt| C2R = 0 ms and R2C = 0 ms in every mode** (`se-19-activity-b72a0fc.txt`); same control links, same timing draws; refusals seen in each state; D-B22 |
| SE-20 | `sessions::tests::inline_attachment_64k` | 1.6 s | |
| SE-21 | `harness::m7_crash::receipt_effect_commits_with_receive_ratchet` | 2.6 s | scenario (i) fault on the outbox update; (ii) the crash case is the extended PC-05 `crash_between_persist_and_send_no_key_reuse` with `receipts = true` |
| AP-01 | `api::tests::request_response_and_events` | 1.7 s | every request kind (14 incl. `Remove`), F9 (a refused outbox row: error response, history row taken back), `ViewOnceLost` first |
| AP-02 | `xtask::testscan::api_exposes_no_secrets_or_store` | <0.01 s | red first: a public `profile_store() -> SharedStore` on `Core` is found by name (`api.rs:486`) |
| AP-03 | `api::tests::relay_view_lists_11_3` | <0.01 s | the five items are read from `docs/03` and equal the constants; the grouping line for Balanced, Low-bandwidth and direct, the IP line for direct |
| AP-04 | `xtask::testscan::no_identifiers_reach_transport_types` | <0.01 s | red first: `use secmp_transport::Channel;` in `hub.rs` is named (`importers` ≠ the three). The allowlist as pinned: capability and wire types `RecvCap SendCap LdId LinkBlob Cell CellId Token RelayRef Period Bucket OwnerKey`, plumbing `AsyncConnectOutcome AsyncRelayQueueTransport AsyncSession Channel Command EitherStream Error Isolation Outcome Prepared ProviderStream QueueRef StreamProvider channel counters driver evicted evicted_is_plausible seal_calls sign_calls`; grep at the B-6 head: `kani_proofs.rs:19`, `scheduler/core/mod.rs:31,340,341,366`, `scheduler/run.rs:54,58` (all other `secmp_transport` mentions are comments, except the import of the `#[cfg(test)] #[cfg(feature = "kat")] mod tests` of `scheduler/core/mod.rs` (then `:2211`), which the scan reads too — its names are allowlisted; VERIFY-B4 P3 m-10) |
| AP-05 | `harness::m7_boundary::no_identifiers_in_request_plaintexts` | 65 s | three parties, two invitations, messages, a verification, a rotation, a key change; > 1 000 request plaintexts (scheduled and control links) searched for texts (ASCII, UTF-16LE), names, fingerprints (raw, hex, HEX), identity-key prefixes, the safety number, `link_key`, the URI, the passphrase and the contact ids (u64 BE/LE, a random 60-bit offset by a placeholder row); the oracle finds the invitation queue's sender id in the invitee's `SEND`s |
| AP-06 | `xtask::testscan::transport_has_no_core_or_store_dep` | 0.3 s | normal dependencies (the dev-dependency on the test kit is the harness of its own tests) |
| AP-07 | `api::tests::clock_injected` | 1.4 s | |

Completions: ST-17 (partial: FO-01a in C) — `ViewOnceLost` is asserted in AP-01; BK-03 — `api::tests::restore_requires_reinvite_api`: `Send` → `ReinviteRequired` after an export and import, no session opened, every OPK secret differs from every pre-backup one (Q197); BK-07 `never_automatic` re-run: its last assertion said "A-4: no caller" and now says "exactly the `Api` handler" (D-B17).

Follow-ups (extra tests): Q193 `invitations::tests::consumed_queue_cells_reach_session`; Q194 `invitations::tests::expired_queue_del_after_empty_fetch`; OPEN-M7-B-2 `kani_proofs::kani_prepare_link_send_before_fetch` (D-B16); OPEN-M7-B-3 `scheduler::core::tests::late_commit_of_old_generation_ignored` and the re-dictated `run.rs` tests; OPEN-M7-B-5 `invitations::tests::accept_failure_keeps_pool_queue`; OPEN-M7-B-8: IN-05 through the scheduler's real acknowledgement `harness::m7_scheduled::accept_commits_before_the_real_ack` (the scheduler's `acked` for the invitation queue never reaches the group's last cell before the contact is in the store, and does reach it), PR-08 through the `Core` `api::tests::contact_removed_keeps_schedule` (5 slots before and after, Δ = 0); OPEN-M7-B-10 `profile::tests::opk_ids_never_reused`; and `sessions::tests::queue_set_codec_is_canonical`.

Red-first lines of this step beside `b4-red-first.txt`: SE-02 (`target/wip/red-se02.txt`): `m7_rotation.rs:112: the 12 real messages of the last 128 cells go again, not the 3 before them — left: 0, right: 12`; AP-02/AP-04 as in the table.

*[B-4c (VERIFY-B4 P3 m-9): the Q193 killer of `delete field to_session from struct Round expression in Invitations::decide` is at `invitations.rs:1057:21` @`d77fb3c` (`:1202:21` at the B-4c head, the `Consumed` arm of `decide`), killed by `invitations::tests::decide_rechecks_status_after_lock`; re-dictated in B-4: IN-10 and `decide_rechecks_status_after_lock` (`to_session == [1, 2, 3]`, `ack_through == None`), `scheduler::run::tests::late_delivery_of_an_old_generation_commits_nothing` and `scheduler::run::tests::committed_ids_are_a_set` (OPEN-M7-B-3). Red-first of SE-18: none in B-4 — B-4c's is in `b4c-red-first.txt` (a `.to_bytes(` call planted in `hub.rs`); of AP-06: none — a red needs a temporary dependency edge (`Cargo.toml`, `Cargo.lock`), which WEISUNG M7-B-4c forbids; its positive controls (transport reaches proto/crypto, core reaches transport and store) stand.]*

### §4 Gates

| gate | result | evidence |
|---|---|---|
| `cargo xtask ci-fast`, B-4 | PASS at `a9e3a72` | `ci-fast-b4-a9e3a72.txt` |
| `cargo xtask ci-fast`, B-5 | PASS at `b824055` (run on that commit, checked out detached) | `ci-fast-b5-b824055.txt` |
| `cargo xtask ci-fast`, B-6 | PASS at `6f264a1` | `ci-fast-b6-6f264a1.txt` |
| Kani | 57/57, 4796 s (budget 150 min), largest peak 88.0 % (`kani_persist_contract_abstract`), none above 90 % | `kani-m7-b-3343bf4.txt`; new harness alone: `kani-m7-b4-sc-kani_prepare_link_send_before_fetch.txt` |
| mutants | core (4 batches, `git diff b57ca46..HEAD`): 793 tested = 598 caught / 10 missed / 185 unviable / 0 timeout; store: 150 tested = 122 caught / 0 missed / 28 unviable / 0 timeout. The 10 survivors: 9 in accepted rows (2 of B-3, 7 new "M7 B-7": equivalent or unreachable, 3 test-fixture lines in `testutil.rs`), 1 killed (`hub.rs:533:50`, test extended; checked by hand with the mutation applied, not re-run by cargo-mutants). First pass before the killers: 6 + 18 + (C cut by the timeout, 68 missed of 264 of 291) core and 24 store survivors | `mutants-b-d164f65.txt` |
| coverage | PASS: secmp-client-core 10249/10722 lines = 95.6 % (min 90 %); secmp-store 5256/5470 = 96.1 % (min 90 %) | `coverage-b-c420953.txt` |
| `ci-fast` (last) | PASS at `5838ed3` (clean tree) | `ci-fast-b-l-5838ed3.txt` |
| `ci-full` | PASS at `1318baa` (clean tree; Kani step 4933 s = 82 min, 57/57; 36 fuzz targets; delegated: windows-native, windows-cross, mutants, ct, proverif-link). First run at `e365c9f` FAIL (fuzz only, D-B26) | `ci-full-b-1318baa.txt` |

*[B-4c7 (Q217): RUSTSEC-2026-0459 (`libsqlite3-sys` 0.37.0, CVE-2026-119375) is in `cargo audit`'s database and `cargo deny`'s output as of 2026-11-09, found by B-4c5's `ci-full` attempt 4 (the step-by-step run of the same day, on an older local database, was green). Ignored with ADR-051 Am. 8 (Q217) in `expect::AUDIT_IGNORES` and `deny.toml`; no lock movement. `ci-fast` PASS (`ci-fast-b4c7-ab72776.txt`): `deny` PASS, `audit` PASS — "ignored with an ADR: RUSTSEC-2026-0173, RUSTSEC-2023-0071, RUSTSEC-2024-0436, RUSTSEC-2025-0141, RUSTSEC-2026-0387, RUSTSEC-2026-0459"; evidence of `cipher_use_hmac` = 1 and the page-HMAC rejection: `sqlcipher-hmac-b4c7-ab72776.txt`.]*

### §5 Deviations from the weisung (new: D-B16…; D-B10 and D-B11 closed)

*[B-4c (VERIFY-B4 P3 m-9): the entries dictated earlier and missing here —]*
- **D-B1**: no ruling, weisung or report of the tree or the material names a D-B1 (`grep -rn 'D-B1[^0-9]'`); the number is unused.
- **D-B2** (Q153): AP-04 scans no `net` module (there is none): the boundary is the importer set {`scheduler::core`, `scheduler::run`, `kani_proofs`} and the pinned allowlist; AP-05 is the dynamic oracle.
- **D-B4** (Q159): `T_RS` = max(24 h, 2·QUEUE_CAPACITY·P_q) is a named constant citing OPEN-M7-07, not normative; once per `msg_id`; verified contacts with receipts only (B-4c Q210 d: our verification of the contact is the proxy).
- **D-B5** (Q164): an identity rotation retires every unconsumed invitation (`Event::InvitationRetired { reason: IdentityRotated }`, `QUEUE_DEL` on the IN-11 schedule); a handshake on a retired invitation is dropped silently. **Owner memo:** an identity rotation ends every open invitation — the user has to send new ones (Q164, owner informed).

- **D-B10 closed (Q193)**: a consumed record's queue is retired with its session; its cells go to the session's receive path and are acknowledged by its commit (`consumed_queue_cells_reach_session`, red first).
- **D-B11 closed (Q194)**: `QUEUE_DEL` after an empty `FETCH` is a control-op dependency, `ControlOps::schedule_after_empty_fetch`/`…_from`, one implementation for the expired invitation, the rotated queue and the consumed invitation's queue.
- **D-B16 (OPEN-M7-B-2)**: `pure::fetch_gate(tear, send_missing, fetch_missing)` plus `pure::send_missing(needs_send, has_send_part)` instead of the dictated five-boolean signature — `clippy::fn_params_excessive_bools` (limit three) denies it and the weisung forbids an `#[allow]`; the harness has three covers (not two) and a four-pass loop (`unwind(5)`) that models the SEND-first order over passes with a cell source that becomes ready at any pass, a teardown at any pass; `KANI_COVERS` has 3. The properties are the dictated ones.
- **D-B17 (BK-07)**: `backup::tests::never_automatic` could not be re-run unchanged once the `Api` handler exists — its last assertion (`callers == []`, "A-4: no caller") contradicts its own allowed-caller list. It now asserts `callers == ["secmp-client-core/src/api.rs"]` (stronger). Reviewer to confirm.
- **D-B18 (IN-14)**: in-process reopen instead of a child process; the three cells are sent again (cell 0 too); the "`tr_encrypt_calls` = 1" read as above.
- **D-B19 (queue sets)**: `contacts.queues` is a `QueueSet` (`rotated_ms`, per entry relay, queue id, recipient seed, sender seed or none, period, retirement deadline) — a richer sealed column than B-1's `count ‖ seed` (nothing read the old form; the backup does not export it). An invitation queue's entry has no sender seed (replaced by the first reply, not re-created after a relay restart).
- **D-B20 (SE-03 draws)**: the run is made short with seeded draws (the inviter's second overlap draw 1.07 h, the invitee's stop 1.08 h); the range of every draw is asserted and the KS test covers the generator.
- **D-B21 (SE-06, SE-07, SE-08 clauses)**: see the table.
- **D-B22 (SE-19)**: the invitation accept (hour two) and the rotation (hour three) are structural events at the same virtual time in both runs — a new queue starts a link at a random phase (§10.6 (1)), so the idle trace has them too; the activity is everything else. Peers are store-backed `Hub`s too.
- **D-B23 (Q121 timing)**: the `MUTANT_HARNESS_SKIP_TESTS` rows of the B-5 tests (`b824055`) came one commit later (`6f264a1`), not in their own commit.
- **D-B24 (testscan scope)**: `public_surface` (AP-02) leaves out items gated by `#[cfg(feature = "kat")]` (test-only accessors).
- **D-B25 (mutants batching)**: the core run is split into four `--file` batches (A..D) instead of three; with three, batch C ran into the `timeout 3600` of the A-3b form (264 of 291 mutants tested, 27 untested). The command form is otherwise A-3b; the per-batch lines are in `mutants-b-d164f65.txt`.
- **D-B26 (fuzz target)**: `fuzz/fuzz_targets/scheduler_event_sequence.rs` did not compile from `ec36bea` (OPEN-M7-B-3) to `e365c9f`: `Src` lacked the `generation` field its `deliver` and `delivery_committed` call use. `ci-fast` does not build the fuzz targets; `ci-full` found it (first run FAIL, fuzz step only, the other 35 targets passed). Fixed in `1318baa` (the field, two lines; a 120 s run: 7237 runs, no crash), the whole gate re-run. Reviewer: whether `ci-fast` should compile the fuzz targets (`cargo check --manifest-path fuzz/Cargo.toml`) is a gate question, not decided here.
- **Found by the hub test (fixed in `1699b44`)**: `Hub::queue_material` held the store guard across `queue_of`, which locks the store again (a deadlock on first use); `drop(s)` before the call; `hub::tests::invitation_reply_route_update_and_retirement` runs it.

### §6 Locks and vectors

`git diff --stat b57ca46..HEAD -- Cargo.lock fuzz/Cargo.lock` is empty; no `vectors/` change; no `secmp-proto` change in part 2 (see §1).

### §7 Open risks and known limitations

- **R-ROT-1**: the rotation transaction (the pooled queue, the queue set) commits before the `RouteUpdate` cell is planned; a crash between them leaves a current queue the peer never learns. The old queue then retires on its stored deadline and the contact would need a reset. The `RouteUpdate` intent should be persisted with the queue set (a field of `QueueSet`) and re-planned on open — not done.
- **R-ID-1**: pool queue ids are numbered per relay (`PoolBlob.next`), the hub's send queues from `SEND_BASE`; with more than one relay in a profile ids can collide in the scheduler. The hub is configured with one relay.
- **R-HUB-1**: `Hub::register_route` takes the first route of a kind this version knows, on the configured relay.
- **R-LAT-1**: the commit latency of SE-19 is modelled on the driver's worker (`Costs.jitter`), as the other costs; the real store's fsync cost is PC-13's.
- Windows runtime of IN-07/IN-14/SE-14: the new harness tests use `flock`-free in-process stores; their Windows time is not measured.
- Profile lock (report §7 "Profile lock and child processes"): `Core::open` on a held profile is `Unavailable` (tested in PR-03).
- *[B-4c (VERIFY-B4 P3 m-9):]* F9 (a refused outbox row) is closed by AP-01's F9 clause; F9b (a receipt's effect outside the receive commit) is closed by SE-21 (`receipt_effect_commits_with_receive_ratchet`, through the file relay since B-4c); F14 (activity-dependent schedule) is SE-19's; the write cost of the sealed columns (`contacts.routes`/`queues`, `sessions.data`: one AEAD seal per write) is measured only inside PC-13's bytes, not on its own.

### §8 Open / questions

[REF] ST-10/BK-04, FO-01a/FO-02 (C), C-T3 (C). `OPEN-M7.md` rows B-2, B-3, B-5, B-8, B-9, B-10 are decided/done by this part; B-6 and B-7 by Commit 1 and the Q194 commit. Question for the reviewer: D-B17 (the BK-07 assertion) and D-B16 (the `fetch_gate` signature).


## §B-4b — Nachtrag to B-4 from the external review EXTB1 (WEISUNG M7-B-4b; rulings Q199–Q203; `modell=claude-sonnet-5-5`)

`<B4-END>` = `d77fb3c` ("Phase B closed @ 1318baa"; superseded by "Phase B closed @ 75d7bb6", the B-4b code head — both claims withdrawn by WEISUNG M7-B-4c Q212 (11)); the guard held at the start (`git status --short` empty, branch `m07-client-core`). Anchors below are as found at `d77fb3c` / the final code head with `grep -n`; Astra's anchors are @9b511a2 and have all moved.

### §B-4b.1 Findings

| finding | fix commit | test (red-first line in `b4b-red-first.txt`) |
|---|---|---|
| EXTB1-1 (invitee's contact and reply queue lost; major) | already fixed by B-4 `676e9eb` (`accept_invitation` writes the pool take, the contact, its reply-queue entry, the session and the handshake cells in one `store.txn`, `invitations.rs` `accept_invitation`); B-4b adds the success-and-reopen half | `extb1_successful_invitee_keeps_reply_recipient` — **green at `<B4-END>`**, red proved by reverse-applying the hunk that greened it (the `NewContact.queues` of the accept replaced by `None`): red at its message assertion; `accept_failure_keeps_pool_queue` gains the success half (contact row, its entry's recv/send seed = the pool queue's, period, routes present, pool shortened in the same txn) |
| EXTB1-2 (period and sender seed of the invitation queue lost; major) | `e6ccbb5` | `extb1_issue_preserves_invitation_period`, `extb1_issue_preserves_queue_sender_key` — red at their message, green; IN-03 `record_fields_persisted_sealed` amended; `hub::tests::invitation_queue_period_and_sender_seed_come_from_the_entry` |
| EXTB1-3 (recipient key lost at retirement; major) | `78611fb` (+ `ab06e73`, SE-14 follows) | `extb1_retirement_keeps_recipient_until_queue_del` — red, green; `invitations::tests::retiring_stub_survives_restart_until_queue_del`; `hub::tests::retiring_invitation_queue_is_rearmed_after_a_restart`; `scheduler::core::tests::no_queue_on_a_retiring_queue_completes_the_retirement` |
| EXTB1-4 (duplicate chunks of a rejected group re-form it; minor) | `0bd6698` | `extb1_rejected_duplicate_group_not_reprocessed_after_restart`, `extb1_rejected_duplicate_group_spent_next_round` (the extra test, Q202's killer) — red, green; mutant killer `byte_identical_cells_of_spent_ones_are_spent` (`f4a4cb5`) |
| EXTB1-5 (IN-05 compares count and length; minor) | `51f4b9b` | IN-05 `harness::m7_accept::commit_with_accepted_before_any_ack` and `invitations::tests::killers_rounds_and_contact` compare the route bytes; Astra's mutation turns both red (`b4b-in05-mutation.txt`) |
| EXTB1-6 (note) | `OPEN-M7.md` | one sentence, no code |

Red-first (`b4b-red-first.txt`, head `d77fb3c` + the module): **5 red + 1 green-at-B4-END** of the 6 tests. The red tests were committed with their fixes, not alone: a commit with red tests cannot pass `ci-fast` (D-B29).

### §B-4b.2 What was built

- **Q199.** `invitations::Stored` gains `inv_send_seed` (32) and `inv_period_s` (u16) after `flags` (in place, V1; `invitations.rs:137-139,153-154,178-180`), `Stored::entry()` (`:203`) builds the `contacts.queues` entry, `encode_queues` (`:1353`) uses it, `issue_in` keeps a copy of the sender seed and writes `req.inv_period` (`:905,925-926`), `OpenQueue` carries both (`:667-668`). The hub registers an invitation queue at its stored period (`hub.rs:139,355`) and answers `queue_material` with its stored sender seed (`:572`). No `secmp-proto` change.
- **Q200.** Built by B-4 (`676e9eb`): `InviteeStart.contact` and the one transaction exist; the contact's `routes` hold the inviter's invitation-queue route, as B-4 writes it.
- **Q201.** `secmp_store::profile::INVITATION_RETIRING = 2`; `Profile::retire` rewrites the row of an unconsumed expired invitation (also for an identity rotation, SE-09) into a stub — `QueueEntry::encode_one` (83 bytes: relay, queue, recipient seed, sender seed, period, deadline = now + `U[1 h, 24 h]` drawn once) — and drops link key, owner seed, blob, retained cells and the OPK (`profile.rs:344-410`); the readers skip or understand it (`retire`, `link_put_args`, `offer_state` → `OfferState::Retiring`, `on_owner_status`, `process_round`/`decide`: acknowledge and drop); `Invitations::retiring()` and `Invitations::queue_deleted(relay, queue)` (`invitations.rs:778,797`); the hub registers the stubs after a restart, re-arms `QUEUE_DEL` from the stored deadline and deletes the stub in `Hub::queue_deleted`; `queue_material` falls back to the stub. `ERR_NOQUEUE` on a recv-queue whose `QUEUE_DEL` waits emits `LinkEvent::QueueGone` instead of re-creating the queue (`scheduler/core/mod.rs` `queue_error`), `remove_queue` drops its `QUEUE_DEL` (`ControlOps::drop_queue_del`), the test driver completes the retirement on the event and treats `ERR_NOQUEUE` on `QUEUE_DEL` as success.
- **Q202.** `duplicates_of_spent` (`invitations.rs:1249`): in `decide` every id of the union whose bytes equal (`ct_eq`) a spent cell is spent too, before `retain`.
- **Q203.** Both route assertions compare bytes with the route derived from the guest's reply queue, then the decoded fields.

Sites re-pointed to the stored entry (step 2): `Stored::{encode,decode,entry}`, `issue_in`, `encode_queues`/`commit_accept`, `Invitations::queue_of`, `testutil::insert_record`, `Hub::new`, `Hub::invite`, `Hub::queue_material`; already reading the `QueueSet` entry since B-4 and unchanged: the SE-16 scheduler entry, SE-02/SE-03 (`rotation::rotate`), the host's key lookup for `QUEUE_NEW`/`QUEUE_DEL` (`queue_material`), `Hub::register_contact`'s re-arm.

Sanctioned test edits (old → new): `has_recipient` decodes `contacts.queues` through `QueueSet` (B-4's format) and RETIRING rows through `QueueEntry::decode_one`; `extb1_retirement_…`: `When::Delayed` → `When::AfterEmptyFetch(QueueId(1))` (Q194); IN-11 `accept_only_offered_records` (`invitations_tests.rs`, `s.invitations()?.is_empty()`) → exactly one row, status RETIRING, whose record decodes as a `QueueEntry` with a deadline; PR-02 `profile::tests::spk_retained_for_open_invitations` → the same and `Retired.retire_at_ms ∈ [now + 1 h, now + 24 h]`; both EXTB1-4 tests `retained_ids == [2, 4, 6]` → empty; `record_fields_persisted_sealed` and TEST-SPEC IN-03: "…invitation-queue recipient key" → "…invitation-queue recipient key **and sender key**, **`inv_period_s`**, `spk_id`/`opk_id`, …"; `hub::tests::…` `material_send == [0; 32]` → the invitation's sender seed (Q199).

### §B-4b.3 Gates

| gate | result | evidence |
|---|---|---|
| `ci-fast` step 2 | PASS at `e6ccbb5` | `ci-fast-b4b2-e6ccbb5.txt` |
| `ci-fast` step 3 | **FAIL** at `78611fb` (one test: SE-14 `relay_restart_with_store`, see D-B30) | fixed in `ab06e73` |
| `ci-fast` (final code) | PASS at `bd23c23` | `ci-fast-b4b-bd23c23.txt` |
| mutants | core: 116 tested = 84 caught / 2 missed / 30 unviable / 0 timeout; store: no mutant in the diff; both survivors dispositioned (killer `f4a4cb5`; re-pinned accepted row) | `mutants-b4b-f4a4cb5.txt` |
| coverage | PASS: secmp-client-core 10560/11033 lines = 95.7 % (min 90 %); secmp-store 5256/5470 = 96.1 % (min 90 %) | `coverage-b4b-75d7bb6.txt` |
| Kani | not touched (no `#[cfg(kani)]` file changed) | — |
| `ci-full` | PASS at `ab24ba1` (clean tree; Kani step 4786 s, 57/57 harnesses; 36 fuzz targets; delegated: windows-native, windows-cross, mutants, ct, proverif-link) | `ci-full-b4b-ab24ba1.txt` |

### §B-4b.4 Deviations (new: D-B27…)

- **D-B27 (Q199 type).** B-4 had already built `QueueEntry`/`QueueSet` (`sessions/rotation.rs`: `count ‖ rotated_ms ‖ 83-byte entries`, optional sender seed, deadline in Unix **milliseconds**); the Q199 type (82 bytes, deadline in seconds) is not built a second time — "one definition" is kept. The stub row holds `QueueEntry::encode_one` (the same 83 bytes). The invitation queue's entry in `contacts.queues` now carries the sender seed and the period (it had none/10 s).
- **D-B28 (Q200).** Built by B-4 (`676e9eb`); B-4b adds only the success-and-reopen test half.
- **D-B29 (commit order).** Step 1 (red tests) is not a commit of its own; the red tests arrived with their fixes (`e6ccbb5`, `78611fb`, `0bd6698`); `ci-fast` ran after steps 2, 3 and at the final code, not after steps 4 and 5 separately (one run at `bd23c23` covers both).
- **D-B30 (SE-14, not on the sanctioned list).** `harness::m7_restart::relay_restart_with_store` compared the host's queue set before and after the relay restart for equality; under Q201 the queue in overlap (a deadline, `QUEUE_DEL` waiting) is not re-created but its retirement completes, so the test now asserts the same *current* queue from the store and that no queue with a deadline is re-created. Reviewer to confirm.
- **D-B31 (Q201 timing).** A freshly retired invitation's `QUEUE_DEL` keeps `When::AfterEmptyFetch(queue)` (empty `FETCH`, then `U[1 min, 60 min]`, Q194's tested form); only the re-arm after a restart uses the stored deadline (`AfterEmptyFetchFrom`). The drawn deadline is therefore the restart bound for an expired-unused invitation.
- **D-B32 (scope of `ERR_NOQUEUE`).** `LinkEvent::QueueGone` is a scheduler-core change with a unit test; the harness driver's handling of the event and of `ERR_NOQUEUE` on `QUEUE_DEL` is exercised only through SE-14, no test of its own.
- **D-B33 (relay).** `Hub::queue_deleted` matches a stub by (the hub's configured relay, queue), as B-4's hub is single-relay (R-ID-1).
- `gates::tests::accepted_rows_with_escaped_pipes_match_the_survivors` follows the renumbered row (806:39 → 816:39), as at B-SC2.

### §B-4b.5 Risks

- **RT-1 (Q202):** a complete group is spent after one `accept`, including byte-identical duplicates of its chunks in the same round's union of fetched and retained cells (EXTB1-4); a byte-identical re-send fetched in a later round, after the spent cells are gone, re-forms the group and is rejected again deterministically (bounded; `docs/03:342`), noted, not closed.
- A crash between the `QUEUE_DEL` OK and the stub delete re-runs the `QUEUE_DEL` on a queue the relay no longer has: the relay answers `ERR_NOQUEUE`, the test driver treats it as success; the production driver's handling is B-8/C's.
- Spec errata for the owner: see `OPEN-M7.md` (B-4b notes).

### §B-4b.6 Locks

`git diff --stat d77fb3c..HEAD -- crates/secmp-proto vectors Cargo.lock fuzz/Cargo.lock` is empty.


## §B-4c — Nachtrag to B-4/B-4b from the external review VERIFY-B4 Parts 1–3 (WEISUNG M7-B-4c; rulings Q204–Q212; code by session M7-B-4c, `modell=claude-opus-5-5`; report, ci-full and docs by B-4c2…B-4c8, `modell=claude-sonnet-5-5`)

### §B-4c.0 Inventory

`<B4B-END>` = `9290e20`. At the start of B-4c2: `git status --short` empty, `git log --oneline 9290e20..HEAD` = 13 commits ending at `ab72776` (listed in §B-4c.1; `git log` output reproduced in the return block of B-4c8). Session M7-B-4c ended by the weekly plan limit 2026-11-02 22:22 UTC after `ab72776d`; B-4c2 completes the report and ci-full.

After `ab72776` the branch carries one more commit: `e80e11c` `ci(audit): ignore RUSTSEC-2026-0459 with ADR-051 Am. 8 (Q217)` (the subject of `e80e11c` says "Am. 7"; renumbered to 8 by the fix-up commit of B-4c14) (WEISUNG M7-B-4c7: a RustSec advisory dated 2026-10-30 reached the local database after the green step-by-step run and turned `deny`/`audit` red in attempt 4; ignored with an ADR, no lock movement; evidence `ci-fast-b4c7-ab72776.txt`, `sqlcipher-hmac-b4c7-ab72776.txt`). Its code part is `xtask/src/expect.rs` (`AUDIT_IGNORES`, `audit_ignores_unchanged`) and `deny.toml`; the B-4c code head of the rest stays `bffafe4`/`ab72776`.

**ci-full attempts (D-B41, §B-4c.4):** five attempts; log mtimes (UTC): attempt 1 ended 2026-11-09 03:06 (4 h cap, step 8), attempt 2 ended 2026-11-09 08:31 (4 h cap, step 8), attempt 3 (step by step) ended 2026-11-09 18:17, attempt 4 ended 2026-11-09 19:29, attempt 5 (the one that counts) 2026-11-09 ~20:3x – 2026-11-10 00:52 (`# exit 0  2026-11-10T00:52:23Z` in its file). The reviewer's text names "2026-11-08 20:01 UTC" for the first attempt; no file of this session records that time.

### §B-4c.1 Findings

Source of the data: `git show <sha> --stat`, the commit messages, `docs/reviews/M07-evidence/b4c-red-first.txt` (red-first lines, quoted short), `mutants-b4c-bffafe4.txt`, `coverage-b4c-bffafe4.txt`, `kani-m7-b4c-bffafe4.txt`, `se-19-activity-b4c-bffafe4.txt`, the `ci-fast-b4c-<k>-<sha7>.txt` files and the Q204–Q212 rows of `OPEN-M7-decided.md`. A cell none of them records says "not recorded". The ci-fast file of step k is the one run after that commit (all `ci-fast: PASS`).

| finding | fix commit | test / red-first line | ci-fast |
|---|---|---|---|
| Q204 (ci-fast does not build the fuzz targets; VERIFY-B4 P3 §Q6) | `5b54779` | `xtask::ci::tests::fast_checks_fuzz_targets` — red: `ci-fast steps ["fmt", …, "harness"]` (`ci.rs:395`), green with `fuzz-check`; ADR-045 Am. 14; D-B26 | `ci-fast-b4c-0-5b54779.txt` |
| Q205 (`Frozen` not durable; `Verify` could unfreeze; VERIFY-B4 P1 B-1, SE-08) | `53e7f36` | `sessions::tests::frozen_survives_verify_and_reopen` — red `left: Verified right: Frozen` (`sessions/tests.rs:1219`); store `trust_writer_keeps_frozen_and_block`; SE-08 asserts `Err(Frozen)` and the reopen; PC-09 counts the guard's read | `ci-fast-b4c-1-53e7f36.txt` |
| Q210b (`ResetRequested`/`Removed` block not durable; same commit) | `53e7f36` | `sessions::tests::reset_request_survives_reopen` — red `left: Ok(()) right: Err(Reset)` (`sessions/tests.rs:1272`) | (same) |
| Q206 (`Debug` of request/response/event types prints secrets; P1 B-2) | `0565c29` | `api::tests::debug_redacts_secrets` — red `Export { path: "/tmp/x", passphrase: Zeroizing([104, 117, …` (`api.rs:1375`); `xtask::testscan::no_derive_debug_on_secret_carriers` — red `secret carriers derive Debug: ["api.rs: Request: …"` (`testscan.rs:1027`) | `ci-fast-b4c-2-0565c29.txt` |
| Q207 (expiry sweep drops a consumed invitation row; P1 B-3, Q193) | `a05db4e` | `invitations::tests::consumed_queue_survives_expiry_sweep` — red `left: (Some(11), []) right: (None, [10, 11])`, second case `left: None right: Some(Unavailable)`; hub tests step 7 asserts the row goes with the entry | `ci-fast-b4c-3-a05db4e.txt` |
| Q208 (hub does not drain `Core::ops` nor run `maintain`; P1 M-1, P2 M-1) | `bb9a407` | `hub::tests::identity_rotation_queue_del_reaches_scheduler` — red `left: 0 right: 1` (`hub.rs:1254`); `hub::tests::expired_invitation_queue_del_without_traffic` — red `left: 0 right: 1` (`hub.rs:1293`) | `ci-fast-b4c-4-bb9a407.txt` |
| Q209 (empty-FETCH detection before the error loop; P2 M-2) | `ee331e8` | `scheduler::core::tests::empty_fetch_not_armed_on_error_or_starved_queue` — red `mine 0, others 0, error true left: true right: false` (`scheduler/core/mod.rs:2666`); `harness::m7_rotation::recipient_retires_old_queue_balanced` (SE-03 in Balanced; D-B34) | `ci-fast-b4c-5-ee331e8.txt` |
| Q210 (a) key-change identity in the receive commit | `a958780` | `sessions::tests::key_change_identity_commits_with_receive` — red `the receive commit of the completing cell writes the identity: the fault refuses it` (`sessions/tests.rs:767`, see the provenance note of B-4c2b) | `ci-fast-b4c-6-a958780.txt` |
| Q210 (c) pending control content durable | `a958780` | `sessions::tests::pending_control_content_survives_restart` — red `the last cell's send commit took the row left: 1 right: 0` (`sessions/tests.rs:859`); `pending_control_codec_is_strict`; store `pending_controls_round_trip` | (same) |
| Q210 (d) `T_RS` from the send queue | `a958780` | `api::tests::not_confirmed_fires_after_t_rs` — red `at T_RS left: 0 right: 1` (`api.rs:1485`) | (same) |
| Q210 (e) single entry asked per cell | `a958780` | `sessions::tests::planned_fragments_held_after_freeze` — red `nothing of the message after the change` (`sessions/tests.rs:910`); `control_content_waits_for_first_reply` — red `only dummies before the first reply` (`:935`) | (same) |
| Q210 (f) SE-06/SE-08 through the `Api` | `a958780` | `api::tests::send_refused_after_key_change` (kills hand mutant P1-M2) — red `left: None right: Some(Blocked)` (`api.rs:1535`); SE-06 `key_change_blocks_sending` (`tests.rs:596`), SE-08 `invalid_key_change_freezes` (`tests.rs:634`) | (same) |
| Q211 (queue seeds leave client-core as plain arrays; P1 M-5, P2 M-4, P1 m-3) | `2cdfafb` | `xtask::testscan::no_plain_seed_returns` — red `plain seed returns: ["crates/secmp-client-core/src/hub.rs:621: pub fn queue_material(&self, …` (`testscan.rs:1156`); store `outbox::tests::set_delivered_needs_the_contact` | `ci-fast-b4c-7-2cdfafb.txt` |
| Q212 (1) SE-21 through the file relay, TEST-SPEC row verbatim | `5bff2ee` | `harness::m7_crash::receipt_effect_commits_with_receive_ratchet` — red `nothing of the receive is durable` (`m7_crash.rs:700`) | `ci-fast-b4c-8-5bff2ee.txt` |
| Q212 (2) Q194's red-first by mutation | `5bff2ee` | `invitations::tests::expired_queue_del_after_empty_fetch` under the mutation `AfterEmptyFetch → Delayed` — red `assertion failed: queue.awaits_empty_fetch(OpId(1))` (`invitations_tests.rs:1577`) | (same) |
| Q212 (3) the `decide` killer | `5bff2ee` | `invitations::tests::decide_retired_acks` — red under the mutant `invitations.rs:1211:21` `left: None right: Some(3)` | (same) |
| Q212 (4) OPEN-M7 B-6/B-7 decided (A); Q193/Q194 "fixed in B-4" | `5bff2ee` | docs only (`OPEN-M7.md`, `OPEN-M7-decided.md`); no test | (same) |
| Q212 (5) Kani liveness on the pre-update state; `fetch_gate` truth table | `cf6eda4` | `scheduler::core::pure::tests::fetch_gate_truth_table` kills VERIFY-B4 P2 hand mutant 1 (`pure.rs:627`); `kani_prepare_link_send_before_fetch` 3/3 covers alone (`kani-m7-b4c-sc-kani_prepare_link_send_before_fetch.txt`, 1.6 %) | `ci-fast-b4c-7-2cdfafb.txt` is the file after `2cdfafb`; the one for `cf6eda4` itself: not recorded |
| Q212 (6) SE-14: one `QUEUE_NEW` per current queue, first FETCH after restart acks 0 | `5bff2ee` | `harness::m7_restart` (SE-14); red-first line: not recorded | `ci-fast-b4c-8-5bff2ee.txt` |
| Q212 (7) fuzz model keys handed/pending/committed by (queue, generation, id) | `5bff2ee` | `fuzz/fuzz_targets/scheduler_event_sequence.rs`; compiled by `fuzz-check`; red-first line: not recorded | (same) |
| Q212 (8) SE-19 counts the `Removed` refusal; SE-18 needles; docs fix-ups (P1 m-4, m-5, m-9) | `5bff2ee` | `harness::m7_activity` SE-19 (`se-19-activity-b4c-bffafe4.txt`: `removed` 11 / 7 / 8 in Strict / Balanced / LowBw); SE-18 `xtask::testscan::session_actor_owns_ratchet` needles `.encrypt(`, `.decrypt(`, `.to_bytes(` — red `RatchetState used outside the actor: ["crates/secmp-client-core/src/hub.rs:655: s.to_bytes().len()"]` (`testscan.rs:761`; labelled Q212 (9) in `b4c-red-first.txt`) | (same) |
| Q212 (9) VERIFY-B4 Part 3 minors m-1…m-10, m-12 — evidence and report fix-ups (SHA-less evidence files listed, header-only claims noted, `hub.rs:533:50` one-mutant re-run, `rotation.rs:203:35` row qualified under F_M = 8, SE-18 needles `.encrypt(`/`.decrypt(`/`.to_bytes(`, AP-05 D entry, Commit-0 fix-ups, D-B1/2/4/5, §3 and §7 lines, CHANGELOG line) | `ab72776` | docs only | `b4c-red-first.txt:60` (the SE-18 needle labelled Q212(9)) |
| Q212 (10) VERIFY-B4 Part 1 minors m-1…m-10, Part 2 m-2, m-4, m-8 (a)–(g) — each a fix or a D entry / one report line (retire_op and register_route relay source, Q199 check, Q211, `Error::Unlock` doc, IN test doc, deadlock-fix D entry, `on_accepted` failure after the accept commit) | `ab72776` | docs only | none |
| Q212 (11) report §1 row B: 'Phase B closed' withdrawn until B-4c's ci-full is green on the final head | `ab72776` | docs only | none |
| Mutant killers | `bffafe4` | `api::tests::event_debug_names_the_variant_only`; hub step 7 (retiring-entry test); `invitations::tests::next_expiry_and_routed`; `sessions::tests::set_verified_maps_the_store_refusal`; `sessions::actor::tests::receive_commit_carries_the_block`, `failed_seal_keeps_only_control_content`; store `trust_writer_keeps_frozen_and_block` (`init_trust`) | `ci-fast-b4c-8-5bff2ee.txt` is the file before it; the one for `bffafe4`: not recorded |
| Evidence | `bf56f3f`, `ab72776` | `mutants-b4c-bffafe4.txt`, `b4c-red-first.txt`, `coverage-b4c-bffafe4.txt`, `kani-m7-b4c-bffafe4.txt`, `se-19-activity-b4c-bffafe4.txt` | — |

**Red-first provenance (verifier note 2026-11-08).** The red lines of `b4c-red-first.txt` for Q207 (`invitations_tests.rs:1564/1572`), Q210a (`sessions/tests.rs:767`) and Q212 (3) (`invitations_tests.rs:1576:5`) match no committed tree: the committed asserts are at `1541/1549`@`a05db4e`, `799`@`a958780` and `1587`@`5bff2ee`. The SE-21 red line is a paraphrase. Line 1 of the file names `bffafe4`, while one entry ran on `bf56f3f`. The file itself is not edited.

The 13 commits `9290e20..ab72776`: `5b54779`, `53e7f36`, `0565c29`, `a05db4e`, `bb9a407`, `ee331e8`, `a958780`, `2cdfafb`, `cf6eda4`, `5bff2ee`, `bffafe4`, `bf56f3f`, `ab72776`.

### §B-4c.2 What was built

- **Q204.** `ci-fast` ends with `fuzz-check` (`xtask/src/ci.rs:110`, test `:400-401`); ADR-045 Am. 14.
- **Q205 / Q210b.** One guarded trust writer `secmp_store::sessions::update_trust` (`crates/secmp-store/src/sessions.rs:226`), `init_trust` (`:256`), the raw `put_trust` crate-private (`:195`); `set_verified` (`crates/secmp-client-core/src/sessions/mod.rs:92`) writes trust and contact flag in one transaction and is `Err(Frozen)` on a frozen session.
- **Q206.** Hand-written `Debug` for `Event` (`crates/secmp-client-core/src/api.rs:186`), `Request` (`:343`), `Response` (`:373`); scan `testscan.rs:1020` (`no_derive_debug_on_secret_carriers`).
- **Q207.** `Profile::retire_with` (`profile.rs:334`) keeps a consumed record while `invitations::routed` (`invitations.rs:1369`, called at `profile.rs:360`); `offer_state` (`invitations.rs:1340`) returns `Unavailable` when no row exists for a routed queue; `Invitations::queue_deleted` (`:814`), `process_round` (`:1141`) and `decide` (`:1184`) take the queue.
- **Q208.** `Hub::pump` drains `Core::take_ops` (`hub.rs:510,519`), `Hub::tick` (`:559`) runs `maintain` on the IN-11 schedule with `Invitations::next_expiry` (`invitations.rs:777`).
- **Q209.** `World::fetched_multi` (`scheduler/core/mod.rs:1027`) arms "FETCH returned no present cell" only after the error loop.
- **Q210.** Identity of a key change in `CommitParts` and `persist::write_parts` (`persist.rs:258`, `put_contact_identity` at `:273`); pending control content as sealed `sessions` part `part::CONTROL` (`secmp-store/src/schema.rs:44`); `T_RS` set at `api.rs:623`; the single entry asked per cell in `Conversation::prepare` (`sessions/actor.rs:1017`).
- **Q211.** `Hub::queue_material` (`hub.rs:622`) returns `SecretBytes<32>`; `PoolSeeds` (`invitations.rs:316`) typed; `outbox::set_delivered` takes the contact (`secmp-store/src/outbox.rs:63`); scan `testscan.rs:1163` (`no_plain_seed_returns`).
- **Q212.** `fetch_gate` truth table (`scheduler/core/pure.rs:359`, test `:616`); SE-18 scan `testscan.rs:705`; the remaining items are tests, evidence and docs (§B-4c.1).

### §B-4c.3 Gates

| gate | result | evidence |
|---|---|---|
| `ci-fast`, per commit | PASS after each of the 9 code commits `5b54779`…`5bff2ee` | `ci-fast-b4c-0-5b54779.txt` … `ci-fast-b4c-8-5bff2ee.txt` (the `cf6eda4`, `bffafe4` runs: not recorded as files of their own, see §B-4c.1) |
| `ci-fast`, after Q217 | PASS at the `e80e11c` tree (`deny`, `audit`, `vet`, `cooldown` green; `audit` ignores 6 ids) | `ci-fast-b4c7-ab72776.txt` |
| mutants | in-diff, code head `5bff2ee`: core 172 tested = 123 caught / 15 missed / 34 unviable / 0 timeout; store 79 tested = 55 caught / 2 missed / 22 unviable / 0 timeout; every missed one killed by `bffafe4` (reruns: core 17 tested = 16 caught + 1 unviable, 0 missed; store 4 caught, 0 missed); caught of the viable 89.1 % (core), 96.5 % (store) | `mutants-b4c-bffafe4.txt` |
| coverage | secmp-client-core 95.6 %, secmp-store 96.2 % (`coverage-b4c-bffafe4.txt`); in the ci-full run: client-core 11371/11891 = 95.6 %, store 5456/5673 = 96.2 % (min 90 %) | `coverage-b4c-bffafe4.txt`; ci-full gate `coverage` |
| Kani | 57/57 SUCCESSFUL in 4788 s (budget 135 min), largest peak 87.5 % (`kani_persist_contract_abstract`); the second run inside ci-full: 57/57 in 4782 s | `kani-m7-b4c-bffafe4.txt`; ci-full gate `kani` |
| `ci-full` | **PASS, attempt 5, in two parts** (D-B41): steps 1–9 `miri` by `cargo xtask ci-full --strict --delegated windows-native --delegated windows-cross --delegated mutants --delegated ct --delegated proverif-link --models tr`, stopped by the agent 5 min into `kani` (it could not end before the harness' 4 h cap); then `cargo xtask step --strict --delegated windows-native --delegated windows-cross --delegated proverif-link --models tr kani proverif proverif-link windows-cross windows-native linux-target ref-vectors repro sbom systemd` (exit 0). Per step: fmt 1 s, clippy 0 s, policy 1 s, deny 0 s, vet 1 s, audit 1 s, cooldown 25 s, nextest 19 s, doctest 1 s, hello 0 s, kat 105 s, harness 1038 s, fuzz-check 0 s, perf 0 s, fuzz 4389 s (36 targets; superseded by `fuzz-b4c14-2e420d8.txt`, D-B42), coverage 1096 s, miri 2415 s, **kani 4782 s (57/57)**, proverif 143 s (`--models tr`, 31/31 model hashes), linux-target, ref-vectors (969 cases), sbom 14 s, systemd 0 s: PASS; repro STUB (as in B-4b). **Delegated to CI, as in B-4b:** ct, mutants (12 CI shards; local in-diff evidence above), proverif-link, windows-cross, windows-native. Non-delegated steps: 23 of 24 PASS, the 24th is `repro` (STUB, a documented stub until M11). | `ci-full-b4c-e80e11c.txt` (attempt 5; every step except `fuzz`); `fuzz` re-run on the Q219 tree: `fuzz-b4c14-2e420d8.txt`; history `ci-full-b4c-ab72776.partial-4h-cap.txt`, `….partial2-4h-cap.txt`, `….partial3.txt`, `….partial4-advisory.txt`. The committed evidence files are B-4b-form excerpts (Q218); the raw logs (0.65–4.2 MB; `partial4-advisory` is 652 734 B, below the ADR-052 2 MiB gate, the four others above it) are kept outside the repo — the excerpt form is used for all of them for uniformity (Q218), not because every raw log exceeds the gate, digests in `ci-full-b4c-raw-digests.txt` |

### §B-4c.4 Deviations (new: D-B41, D-B42; D-B34…D-B40 follow)

- **D-B26 (closed by Q204).** The fuzz target `scheduler_event_sequence` did not compile from `ec36bea` to `e365c9f` because `ci-fast` did not build the fuzz package; Q204 adds the step `fuzz-check` (ADR-045 Am. 14). `fuzz/Cargo.toml` changed only in a comment (`git diff --stat 9290e20..HEAD -- '*Cargo.toml'` = that file).
- **D-B34 (SE-03 Balanced, Q209/Q216).** `check_deleted` (`crates/secmp-testkit/tests/harness/m7_rotation.rs:267-288`) lets the first `FETCH_MULTI` after `QUEUE_DEL` still name the deleted queue, because the combined link's next frame is sealed before its tick (spec §10.1; the LINK counter of a sealed frame is spent); every later `FETCH_MULTI` must not. Not "the same assertions as Strict" (Q209). **Accepted by the reviewer as Q216** (the relaxation is exactly one pre-built frame; a second late fetch is still a failure).
- **D-B35 (`bffafe4`).** The `test(core,store)` commit also removes product code: `Conversation::block` (`sessions/actor.rs`, `pub const fn block(&self) -> Option<Refusal>`, "The block of this session, if any"), an accessor without a caller after Q210b (the block lives in the trust row and is read through `may_send_real`/`prepare`); the mutant `actor.rs:585:9` `block -> None` was missed because nothing called it (`mutants-b4c-bffafe4.txt`). `git show bffafe4 --stat`: `sessions/actor.rs` +97/−, `api.rs`, `hub.rs`, `invitations_tests.rs`, `sessions/tests.rs`, `secmp-store/src/sessions.rs`. Precedent: Q195.
- **D-B36 (harness zero seed; open → B-4d, Q214).** The B-4b verifier's finding "`[0;32]` sender-seed fallback" left the product with Q211 but moved into the test driver: `crates/secmp-testkit/src/harness/driver.rs:1376` maps a missing sender seed to `[0; 32]` and `QUEUE_NEW` reads it (`driver.rs:1277-1291`, `tokio_driver.rs:121-131`); the comment "only a `QUEUE_DEL` uses such an entry" (`driver.rs:1373-1374`) is wrong. Unreachable today (every writer stores a seed). Open: fail-closed `None` in B-4d. **Closed by B-4d @ ad50c19, gates @ dcd4a93 (Q214).**
- **D-B37 (interfaces changed without a ruling).** (a) The new `on: (RelayId, QueueId)` argument of `Invitations::process_round`/`decide` (`invitations.rs:1141,1184`): Q207 needs the queue a round was fetched from, so `offer_state` can fail closed (`Unavailable`) when no row exists for a routed queue; callers pass it (tests through `testutil::round_on`); test `invitations::tests::consumed_queue_survives_expiry_sweep`. (b) The in-memory pre-check in `set_verified` (`sessions/mod.rs:97-99`, `if matches!(conversation.trust(), Trust::Frozen) { return Err(Error::Frozen) }` before the store lock): a frozen conversation is refused without a write; tests `sessions::tests::frozen_survives_verify_and_reopen`, `set_verified_maps_the_store_refusal`. (c) The `fresh` skip in `Hub::new` (`hub.rs:144,158`): a queue that `maintain` retired at start is not re-armed from its stub a second time; test `hub::tests::expired_invitation_queue_del_without_traffic` (Q208).
- **D-B38 (AP-05, VERIFY-B4 P3 m-6).** `m7_boundary.rs` offsets and searches only the **contact** row ids (`offset_ids`, `:16`; the offset at `:226-233`); relay, message and identity row ids are not offset, without a D entry. Accepted limit of AP-05 as built; the plant test (contact id written into a re-registered route's `sid`) is red at `m7_boundary.rs:119`. Open: offset the other tables (B-4d) or keep as a documented limit.
- **D-B39 (`1699b44`, VERIFY-B4 P1 m-7).** The hub deadlock fix (`drop(s)` before `self.inv_queues`/`queue_of`, now `hub.rs:638`; product code) is in `1699b44`, titled `test(core,store): killers…`, with no D entry (a report bullet only). `git show 1699b44` (message: "killers for the B mutants", +1323/−0) adds one product line, `drop(s);`, in `Hub::queue_material` before `self.inv_queues.get(&queue)`/`queue_of`; the commit message does not state the reason (the verifier's text calls it the deadlock fix: the store lock `s` was still held when `queue_of` took it again — not recorded in the commit). Precedent: Q195 for product code in a `test(…)` commit.
- **D-B40 (VERIFY-B4 P1 m-8).** `hub.rs:476` (`on_accepted` after the accept committed): if `on_accepted` fails after the accept committed, the cell is not acknowledged but the session is never opened, registered or rotated in this run, and after a restart nothing runs the first-reply rotation (it only runs at accept). Limit of B-4/B-4c, not closed; open → B-4d.
- **D-B41 (ci-full run in five attempts; no step skipped; the fifth is the one that counts).** (0) A first start was cut off after 30 min by the harness' background limit (wrong timeout; the log was overwritten by the next start and is not kept). (1) `ci-full-b4c-ab72776.partial-4h-cap.txt`: steps 1–7 PASS except **fuzz FAIL** (`scheduler_event_sequence`: `two SENDs 9985 ms apart on a queue of period 10000`, `fuzz_targets/scheduler_event_sequence.rs:171:37`, artifact `fuzz/artifacts/scheduler_event_sequence/crash-00c9f8349706f91def7a3f602fcf15877eae901b`, 4330 s; a defect of the fuzz model's clock, not of the scheduler: D-B42, fixed by Q219 in `2e420d8`), then killed by the harness' 4 h cap in step 8 (mutants, `secmp-proto`) — B-4c2's weisung omitted the delegation flags, so the unsharded mutants step ran. (2) `….partial2-4h-cap.txt`: the same again with `nohup` (the cap is on the command, not the shell), killed in step 8. (3) `….partial3.txt`: step by step (`cargo xtask step`, groups of steps, B-4c3 §0.3): steps 1–7, miri, kani 57/57 (4780 s), proverif (`--models all` instead of `tr`), proverif-link, ref-vectors, sbom, systemd PASS; the unsharded `mutants` killed by the cap in `secmp-transport`; `windows-cross` FAIL (`cargo xwin` could not fetch the MSVC CRT: proxy 403 for `aka.ms`); `windows-native` SKIP — not the B-4b form (no delegation flags, no `--strict`, no `--models tr`; the reviewer's omission), hence not accepted (B-4c5 ruling). (4) `….partial4-advisory.txt`: the B-4b form; `deny` and `audit` FAIL on RUSTSEC-2026-0459 (`libsqlite3-sys` 0.37.0) → stopped after 30 min; ignored with ADR-051 Am. 8 (Q217, `e80e11c`). (5) `ci-full-b4c-e80e11c.txt`: the B-4b form, two parts as described in §B-4c.3, because Kani (80 min) could not end inside the cap after about 2 h 55 min of earlier steps; the `step` call repeats the delegation flags and `--models tr` of the first part. **Accepted by the reviewer as Q220 (2026-11-10): same head, same flags, every step run.** The head line names `e80e11c`; the code of B-4c is `ab72776`, `e80e11c` adds only the `AUDIT_IGNORES`/`deny.toml` entry and docs. The committed evidence files of all five attempts are B-4b-form excerpts (Q218): the raw logs (0.65–4.2 MB; `partial4-advisory` is 652 734 B, below the ADR-052 2 MiB gate, the four others above it) are kept outside the repo — the excerpt form is used for all of them for uniformity (Q218), not because every raw log exceeds the gate, digests in `ci-full-b4c-raw-digests.txt`.
- **D-B42 (latent fuzz-model defect since M6, `bf550999`; Q219).** The SEND-spacing assert of `fuzz/fuzz_targets/scheduler_event_sequence.rs` compared the *poll* time of two writes, not `Output::Write::at`. A driver may wake up to `driver_jitter_ms` = 50 ms after a tick (`core/mod.rs:571`), so polls 35 ms and 20 ms after the ticks 210 000 and 220 000 gave `9985 ms` between two SENDs of a queue of period 10 000 (`crash-00c9f834…`, attempt 1's `fuzz` FAIL). The scheduler's ticks are exactly one period apart: a model fault, no product change (B-4c13 diagnosis, verdict D). Attempts 2, 3 and 5 passed `fuzz` only because their 120 s random runs did not reach the input. Fixed by Q219 (`2e420d8`): the model binds `at`, asserts `at ≤ now ≤ at + driver_jitter_ms` for every write and compares the ticks; regression seeds `regress-b4c13-00c9f834` and `regress-b4c13-in15` (red before, exit 0 after); deterministic test `scheduler::core::tests::sends_stamped_at_tick_are_period_apart_under_late_polls`. The attempt-5 `fuzz` PASS is superseded by `fuzz-b4c14-2e420d8.txt`.

### §B-4c.5 Risks

- `OPEN-M7.md` carries no B-4c risk notes: its only B-4c mentions are the decided B-6/B-7 rows (`OPEN-M7-B-6`, `OPEN-M7-B-7`). Not recorded elsewhere than the items below.
- RUSTSEC-2026-0459 (ADR-051 Am. 8, Q217) stays ignored until Arti's `rusqlite` pulls a SQLCipher on SQLite ≥ 3.54.0 or the M8 dependency refresh.
- `cargo audit bin` (sbom step, `xtask/src/sbom.rs:164`) runs without `--ignore`: red on RUSTSEC-2026-0459 once a release binary links the store (M8; OPEN-M7-B-14).
- ct, mutants (as CI shards), proverif-link, windows-cross and windows-native are delegated to CI, not run locally (as in B-4b); the local mutants evidence is the in-diff run of `bffafe4`.
- Wire-level jitter: the production driver (`scheduler/run.rs:1075-1090`) writes at wake-up, up to `driver_jitter_ms` = 50 ms after the tick; two SENDs to a queue can therefore be up to 50 ms closer than `P_q` on the wire. Sanctioned by `params.rs:45-48` and not activity-dependent; the spec names no wire-level tolerance → `OPEN-M7.md` note for the owner (docs/03 §10.1 errata candidate).
- **Q212 (9)/(10) lists B-4c left out.** Evidence files without a head SHA on line 1 (P3 m-1; `grep` for a 7–40 hex string on line 1 over `docs/reviews/M07-evidence/*b4*.txt`): `b4-red-first.txt`, `ci-fast-b4c7-ab72776.txt`, `ci-fast-b4c14-1-2e420d8.txt`, `ci-full-b4c-ab72776.partial-4h-cap.txt`, `ci-full-b4c-raw-digests.txt`, `kani-codegen-g7-06-b4b99db.txt` (the SHA of the last four is in their name or body); the verifier's five (`b4-red-first.txt`, `b6-red-first.txt`, `se-19-activity-b72a0fc.txt`, `se-03-ks-b72a0fc.txt`, `in-17-tick-audit-b72a0fc.txt`) are not edited. Header-only claims (P3 m-2): `ci-full-b-1318baa.txt:4` (the failed first ci-full run) and `mutants-b-d164f65.txt:3-5` (the first mutants pass, whose header labels the batching D-B24 where the report says D-B25) are header claims without a log; no line of this report carries a "[B-4c (VERIFY-B4 P3 m-2) …]" amendment — not recorded which lines B-4c amended. AP-04 scan limit (P3 m-5): the scan misses a crate alias or a re-export (`xtask/src/testscan.rs:701` states it for SE-18; AP-04's text scan has the same limit).
- **Q213 (open → B-4d).** Two deletion deadlines for a retired invitation queue: live, `When::AfterEmptyFetch(queue)` (`invitations.rs:904`); after a restart, `AfterEmptyFetchFrom(retire_at_ms)` from the stub (`hub.rs:144-167`, `profile.rs:366-371`).
- **Q215 (open → B-4d).** `Stored::encode` capacity (`invitations.rs:146-148`): the `Vec::with_capacity(blob_len + RECORD_LEN)` is not the exact size of the encoding.
- **Scan blind spots (open → B-4d).** `no_derive_debug_on_secret_carriers` (`testscan.rs:1020`) does not see a multi-line `derive`, `cfg_attr(…, derive(Debug))` or a hand-written `impl Debug`; `no_plain_seed_returns` (`:1163`) does not see `pub async fn`/`unsafe fn`, trait impls or aliases in other files.
- `repro` is a stub until M11.

### §B-4c.6 Locks

```
$ git diff --stat 9290e20..HEAD -- crates/secmp-proto vectors docs/03-protocol-spec.md Cargo.lock fuzz/Cargo.lock
$
```
(empty; `HEAD` = `e80e11c`.)
- **D-CI3:** `secmp-client-core/src/testutil.rs` was mutated in PR run 41293668505 because `lib.rs` declared it under `cfg(all(test, feature = "kat"))` (cargo-mutants skips only a plain `cfg(test)`; Q20 rule, `5e1a136`). Fixed by splitting into `#[cfg(test)]` + `#[cfg(feature = "kat")]` at three sites (`client-core/src/lib.rs` `mod testutil`, `proto/src/prekeys.rs` `mod tests`, `proto/src/tr/state.rs` `mod tr_digest`; the two proto edits permitted by the reviewer, CI2c ruling); no `mutants-accepted` row. Proto list unchanged at 268: the proto test modules were already outside the list.
- **D-CI4:** `profile::tests::open_wrong_passphrase_uniform`'s `tree_hash` ignores files ending in `-shm` (SQLite's transient WAL index; on Windows its byte-range locks make `std::fs::read` fail with ERROR_LOCK_VIOLATION while the fixture's connection is open; Linux locks are advisory). `profile.db` and `profile.db-wal` stay in the hash, so the 'nothing written' proof is kept. Red-first is not reproducible on Linux; the Windows proof is the next PR run (`windows-native`). *Correction (CI4): necessary but not the cause — see D-CI5.*
- **D-CI5:** the Windows failure of `open_wrong_passphrase_uniform` was the read of `<profile>/lock`, which the fixture's open store holds through `File::try_lock` (a mandatory `LockFileEx` on Windows, an advisory `flock` on Linux); it is the first entry in sorted order, so the CI3 `-shm` exclusion was never reached. `tree_hash` now hashes `lock` by name and length (which must be 0: the file is never written), `-shm` by name, everything else by bytes, and every file-system error names its path (Q228). `store::tests::held_profile_lock_refuses_reads_on_windows` characterises the lock on both platforms; `delete.rs` reads use `?`. `kat::scan_dir` (`kat.rs:441-470`) reads `lock` too and must stay outside an open store's scope (its caller `messages.rs:352` runs after the store's block closes). Red-first on Linux: `ci4-red-first.txt` (the lock row and M-wal/M-shm); the Windows proof is the next `windows-native` run (`PASS` of both tests, no `code: 33`). **Closed by DOCS2 (PR run 43033287006, `windows-native`; §DOCS2).**
- **D-CI6 (B-4f, L3):** `mutants-list-ci3-def9d8b.txt` has no `head <sha>` on line 1 (CI3 asked for it); its three rows are right; the file is not edited.
- **D-CI7 (B-4f, L4):** `ci-fast-ci3-e1682f6.txt` is a hand-copied, shortened summary (short sha, no raw-log path), not raw output; no gate parses it; the PR run is the evidence. From B-4f on, every ci-fast evidence file is the raw output with the 40-hex head on line 1.

## §B-4d — fix-ups after Phase B (WEISUNG M7-B-4d; rulings Q213–Q215; VERIFY-DELTA-B4b, B4c parts 1–2; `modell=claude-sonnet-5-5`)

### §B-4d.0 Guard and inventory

- Start: `git rev-parse HEAD` = `331723c` (B4D-START); `git log --oneline ab72776..331723c` lists `2e420d8` (Q219, test-only, `scheduler/core/mod.rs` `mod tests`) and `331723c` (Q198 attribute splits in `secmp-client-core/src/lib.rs`, `secmp-proto/src/prekeys.rs`, `secmp-proto/src/tr/state.rs`) next to docs/CI commits. The first session turn stopped at the guard on them and on the missing material (`6eb14b2`); the reviewer sanctioned both commits (WEISUNG M7-B-4d2/3) and the material was mirrored to `target/fable/material/M7-B-4d3/` (`VERIFY-DELTA-B4b.md`, `VERIFY-DELTA-B4c-part1.md`, `VERIFY-DELTA-B4c-part2.md`); the "Blocked" paragraph that `6eb14b2` put here is replaced by this section.
- `OPEN-M7-decided.md` is at `docs/reviews/M07-planning/` (rows Q213/Q214/Q215 were "open → B-4d"); the highest D entry was `D-B42`: new entries are D-B43…D-B47. No `Cargo.toml`/`Cargo.lock`/`fuzz/Cargo.lock` change, no `secmp-proto`, `vectors/` or `docs/03` change: `git diff --stat 331723c..HEAD -- crates/secmp-proto vectors docs/03-protocol-spec.md Cargo.lock fuzz/Cargo.lock` is empty.
- Commits (`git log --oneline 331723c..HEAD`): `57ebb1e` Q213 + C1-3 · `ad50c19` Q214 · `71c1c44` Q215 · `9d23dbf` B4b-4, B4b-8, hub errors · `301ba23` C1-4 a/b/c · `3104cb2` C1-6 a/b, C2-5 · `dcd4a93` B4b-1, C1-8 a/b, C2-4 · `531e802` Q121 skip row · `6a3132e`, `d614546` evidence docs (and `6eb14b2`, the guard note).

### §B-4d.1 Findings: fix, test, red-first

Every red line is quoted verbatim, with its command, in `docs/reviews/M07-evidence/b4d-red-first.txt` (line 1 = `head 331723c`). "Mutation" = a compiling one-line mutation of the fix in the committed tree, reverted (`git diff` empty), used where the test needs an item the unfixed tree lacks.

| Id | Fix commit | Test | Red-first line (`path:line:col`) |
|---|---|---|---|
| Q213 (B4b-3, C1-9) | `57ebb1e` | `hub::tests::retiring_invitation_queue_is_rearmed_after_a_restart` (re-dictated: the re-armed op is exactly `[When::AfterEmptyFetch(queue)]` and equals the live `maintain` op) | `hub.rs:1287:13`, `left: [AfterEmptyFetchFrom(QueueId(1), 544165666)]` `right: [AfterEmptyFetch(QueueId(1))]` (unfixed tree) |
| C1-3 | `57ebb1e` | `invitations::tests::queue_deleted_keeps_consumed_row_without_retiring_entry` | `invitations_tests.rs:2165:5`, `assertion failed: !invitations.queue_deleted(record.relay, record.queue)?` (unfixed tree) |
| Q214 (B4b-2, C1-10) | `ad50c19` | `harness::m7_restart::queue_new_without_sender_seed_fails_closed` | `m7_restart.rs:238:5` "no QUEUE_NEW without a sender seed" — mutation: the `driver.rs` arm `Some((recv, None)) => (recv, [0; 32])` (the unfixed tree does not compile the readers of the new `Material::queues` type) |
| Q215 (B4b-5) | `71c1c44` | `invitations::tests::stored_encode_reserves_exact_capacity` | `invitations_tests.rs:2188:9`, `left: 856` `right: 472` (unfixed `encode` body, `TRAILER_LEN` kept) |
| B4b-6 | `9d23dbf` (test) | `harness::m7_restart::queue_deleted_failure_reaches_hub_errors` | `m7_restart.rs:304:5` "the refused write of queue_deleted is reported" (driver edit stashed). The Q202 killer is `invitations::tests::extb1_review::extb1_rejected_duplicate_group_spent_next_round`; the red line it was written against is `crates/secmp-client-core/src/invitations_tests.rs:1617:9` ("no new cells: an already rejected complete group must not be reconstructed from retained duplicates", `docs/reviews/M07-evidence/b4b-red-first.txt`) |
| hub errors | `9d23dbf` | `harness::m7_restart::hub_step_error_reaches_hub_errors` (fault: `TEMP` trigger `BEFORE UPDATE OF state ON contacts` on the host's connection, hit by `Core::pump` → `Contacts::on_control` when the guest removes the contact) | `m7_restart.rs:340:5` "Hub::pump failed on the ContactRemoved control: []" (driver edit stashed) |
| B4b-4 | `9d23dbf` | `harness::m7_restart::relay_restart_with_store` (the overlap entry before the restart; absent from `queues_after`, `overlap_absent`); TEST-SPEC SE-14 row amended | green at the unfixed tree too (assertions on existing behaviour); no red claimed |
| B4b-8 | `9d23dbf` | `harness::m7_restart::queue_del_on_a_gone_queue_completes`; hook `Options::relay_drops_before_queue_del` (`#[doc(hidden)] pub`, `driver.rs`) | `m7_restart.rs:400:5` "the QUEUE_DEL completed on ERR_NOQUEUE" — mutation `Ok(()) \| Err(TransportError::NoQueue) => {}` → `Ok(()) => {}` (`driver.rs`) |
| C1-4 a | `301ba23` | `api::tests::verify_without_session_keeps_stored_frozen` | `api.rs:1573:13`, `left: None` `right: Some(Frozen)` (the `contacts.rs` hunk stashed) |
| C1-4 b | `301ba23` | `sessions::tests::second_key_change_verifies_under_the_new_key`, SE-06 `key_change_blocks_sending` (without the deleted calls) | proof, not a red-first: mutation `if let Some(peer) = new_peer { self.peer = peer; }` → `let _ = new_peer;`: `sessions/tests.rs:1583:9` "the second key change is accepted under the first new key" |
| C1-4 c | `301ba23` | `sessions::actor::tests::unloadable_new_ik_sig_freezes` | `actor.rs:2212:9` `assertion failed: matches!(delivery, Delivery::KeyChangeRefused)` — mutation: the `Err(_)` arm of `admit_key_change_with` returns the delivery unchanged |
| C1-6 a | `3104cb2` | `scheduler::core::tests::empty_fetch_not_armed_on_error_or_starved_queue` (new case `F_M = 16`, 8 frames of the other queue) | `core/mod.rs:2756:13` "mine 0, others 8, error false, F_M 16", `left: true` `right: false` — mutation `had_dummy = frames < self.params.f_m` |
| C1-6 b | `3104cb2` | the same test (cells by value; case `(1, 0, ..)` with a refusing source `Refusing`) | none claimed (a refactor; the test needs the new signature) |
| C2-5 | `3104cb2` | doc line moved back above `fetch_due_and_note_sent` (`pure.rs:638`) | — |
| B4b-1 | `dcd4a93` | `invitations::tests::killers_rounds_and_contact` (+ `assert_queue_entry_is_the_records`) | `invitations_tests.rs:1282:9`, `left: None` — mutation of `encode_queues`: `QueueEntry { send_seed: None, ..stored.entry()? }` (the right-hand side is the KAT test seed's 32 bytes) |
| C1-8 a | `dcd4a93` | `hub::tests::register_route_sets_t_rs` (+ `#[cfg(feature = "kat")] Conversation::receipt_timeout_ms_kat`) | `hub.rs:1349:13`, `left: Some(0)` `right: Some(86400000)` — mutation: the `set_receipt_timeout_ms` call of `register_route` deleted |
| C1-8 b | `dcd4a93` | `harness::m7_scheduled::expired_invitation_queue_del_end_to_end` | `m7_scheduled.rs:173:5` "exactly one QUEUE_DEL: []" — mutation: `Hub::tick` does not call `maintain` |
| C2-4 | `dcd4a93` | `harness::m7_activity::store_backed_source_activity_independent` (`assert_eq!(outcome, Err(Error::Blocked))` for a send to a `Removed` contact) | `m7_activity.rs:278:21`, `left: Err(Unavailable)` `right: Err(Blocked)` — mutation `ContactState::Removed => Err(Error::Unavailable)` in `Contacts::check_send` (see D-B47 (c)) |

Not done here (ruling): C1-5, C2-2 (scan blind spots) → WEISUNG M7-B-4e; the scans of hand-written `impl Debug` and of raw-seed struct fields → B-4e/M8.

Anchors re-found (old @ab72776 → new at `d614546`): `hub.rs` stub re-arm loop `:150-168` → `:149-170`, `When::AfterEmptyFetch` `:165`, `register_route` `:309` → `:308`, `queue_deleted` `:584` → `:583`; `invitations.rs` `Stored::encode` `:146-161` → `:150` (`TRAILER_LEN` `:146`), `queue_deleted` `:814` → `:824`, `retirement` `:884` → `:898`; `profile.rs` `retire_with` deadline `:366-371` → `:366-372`; `contacts.rs` `confirm_digits` `:261` → `:262`, `confirm_qr` `:282` → `:288`, `verified_if` `:289` → `:299`; `sessions/mod.rs` `set_verified` `:92` → `:68`, `accept_key_change` `:67-83` deleted; `sessions/actor.rs` `set_peer` `:556` deleted, `let delivery` `:1177` → `:1180`, `admit_key_change` `:1378`, `apply_delivery` `:1263`; `scheduler/core/mod.rs` `fetched_multi` `:1027` → `:1029`, `had_dummy` `:1035` → `:1039`; `pure.rs` SC-09 doc `:612` → `:638`; `invitations_tests.rs` `killers_rounds_and_contact` `:1188` → `:1200`; testkit `driver.rs` `Material` `:131`, `StoreHub::step`/`queue_deleted` `:260`/`:276`, impls `:288`/`:320`, `hub_step` `:819`, `run_control` `:1289`, zero-seed `QUEUE_NEW` arm → `:1300-1320`, `hub_material` `:1419`.

### §B-4d.2 Gates

| Gate | Result |
|---|---|
| `ci-fast` per commit group | PASS: `ci-fast-b4d-1-57ebb1e.txt`, `-3-ad50c19`, `-4-71c1c44`, `-6-9d23dbf`, `-7-9-301ba23`, `-10-12-3104cb2`, `-13-16-dcd4a93`, `-skiprow-531e802`, final `-l-6a3132e`. Fmt/clippy failures met on the way (too-many-lines, `collapsible_if`, `manual_assert_eq`) were fixed in the code, not allowed. |
| mutants (in-diff `331723c..HEAD`, core; the store is untouched, so no store run) | `mutants-b4d-531e802.txt`: 56 mutants, 45 caught, 11 unviable, 0 missed, 0 timeouts: no killer commit needed. The five accepted rows of the touched files were rerun with `--re` (all five still missed as documented) and renumbered (`mod.rs:1940:21/44` → `:1937:21/44`, `hub.rs:484:30` → `:483:30`). |
| coverage | `coverage-b4d-6a3132e.txt`: `secmp-client-core` 11601/12138 = 95.6 %, `secmp-store` 5456/5673 = 96.2 % (min 90 %). |
| `ci-full` (strict, delegated windows-native, windows-cross, mutants, ct, proverif-link; `--models tr`; background, polled) | **PASS** on `d614546`: `ci-full-b4d-d614546.txt` (B-4b-form excerpt; raw log 3.2 MiB outside the repo, digest in `ci-full-b4d-raw-digests.txt`, Q218). The first start was rejected at once by xtask (`--delegated windows-native windows-cross …` in one flag: "unknown argument windows-cross"), no step ran; the second start (the B-4c form, one `--delegated` per step) ran to the end. |

### §B-4d.3 Deviations (new: D-B43…D-B47)

- **D-B43 (Q213).** The stub's `retire_at_ms` (`profile.rs`, `U[1 h, 24 h]`) is still drawn and stored in the `QueueEntry` (format unchanged) but is not an arming deadline: an informational upper bound (comments at `profile.rs:366` and `hub.rs:165`). `base`/`from` and the `unix_base` call are gone from `Hub::new`. Rotated queues and a consumed invitation's queue in `contacts.queues` stay `AfterEmptyFetchFrom` (not touched; the existing hub test `step_handshake`/`step_restart` still asserts them).
- **D-B44 (interfaces of the harness).** `Material::queues` is `BTreeMap<u32, ([u8; 32], Option<[u8; 32]>)>`; `StoreHub::step` and `StoreHub::queue_deleted` return `Result<(), String>` and every caller pushes an `Err` into `hub_errors` (`"step: …"`, `"queue_deleted: …"`); `Options` gains `#[doc(hidden)] pub relay_drops_before_queue_del: bool` (not `cfg(test)`: `tests/harness` links the library without it). `tokio_driver.rs` has its own `ControlMaterial` (`[u8; 32]` both seeds, filled without the hub): unchanged.
- **D-B45 (removed and narrowed items).** `sessions::accept_key_change` and `Conversation::set_peer` are deleted (the receive commit writes the identity, the `KeyChange` arm of `apply_delivery` sets `peer`; the three test calls and the doc at `tests.rs` follow). `Contacts::confirm_digits` is `pub(crate)`; `confirm_qr` is `pub(crate)` **and compiled for the tests only** (`cfg(test)` + `cfg(feature = "kat")`): no `Request` carries a scanned QR, so in a product build it would be dead code (`dead_code` is denied by `-D warnings`; an `#[allow]` was not taken). `verified_if` now writes the flag and, if the session has a TRUST row, the trust in one transaction (a refusal is `Error::Frozen`, through the new `sessions::trust_write_refusal` shared with `set_verified`). `admit_key_change`/`admit_key_change_with` are private to `actor.rs`; no `IksPublic` whose `ik_sig` fails is constructible through `secmp-proto` (`Ed25519Pk` decodes strictly, ML-DSA `pkDecode` cannot fail), hence the injected loader in the test.
- **D-B46 (C1-6 b).** `fetched_multi` takes `cells: Vec<(QueueRef, u64, Cell)>` by value (`Cell` is not `Clone`, `secmp-proto` is untouched) and moves each queue's cells into `mine`: no copy and no second `Cell::from_bytes`, so `present == !mine.is_empty()` by construction; `had_dummy` compares with `secmp_proto::link::FETCH_MULTI_BATCH`. The case `(1, 0, false, false)` is relabelled "one present cell, present; its source refuses it" (test source `Refusing`). No undecodable `Cell` exists at this interface (`Cell::from_bytes` fails only on length).
- **D-B47 (test choices that differ from the dictated text).** (a) `expired_invitation_queue_del_end_to_end` uses `expires` = start + 1 h and a 3 h run, not 1 day / day 2: the 1-day run took 13.6 s (> 10 s, Q121), the 1-h run 1.3 s; the sequence asserted is the same. (b) `hub_step_error_reaches_hub_errors` uses the `ContactRemoved` control and `UPDATE contacts`, not `INSERT INTO messages`: `insert_message` is `INSERT OR IGNORE`, and the outer statement's conflict policy overrides `RAISE(ABORT)` in a trigger (the first try was green at the fixed tree and red nowhere). (c) C2-4: the one-line mutation `ContactState::Removed => Ok(())` in `check_send` stays green because the session's block (`Refusal::Removed`) refuses the send as well (defence in depth; run: 685 s, PASS); the quoted red is `=> Err(Error::Unavailable)`, which the new `assert_eq!(…, Err(Error::Blocked))` catches and the old `removed && outcome == Err(Blocked)` branch did not. (d) `queue_new_without_sender_seed_fails_closed` took 13 s: `MUTANT_HARNESS_SKIP_TESTS` and `docs/mutants-accepted.md` §Skipped row in `531e802` (Q121). (e) The Q214 and C1-6 a red-firsts are mutations of the fix (the tests need items — the `Material::queues` type, `Refusing`, by-value cells — that the unfixed tree lacks to compile), named as the weisung allows. (f) The `Scene` literal of `hub.rs` tests was extracted into `scene()` for the new test (the dictated test would otherwise exceed the 100-line clippy bound). (g) The QUEUE_NEW arm's too-many-lines bound was met by the free function `hub_queue_deleted` in `driver.rs`.

### §B-4d.4 Risks

- Not closed here: C1-5, C2-2 (scan blind spots, B-4e). `confirm_qr` has no caller in a product build until the UI milestone.
- `store_backed_source_activity_independent` takes 9–11 min per run; every mutation red of it costs one such run.

### §B-4d.5 Blocked

None.

## §B-4e — Debug and seed scans close their blind spots (WEISUNG M7-B-4e2; C1-5, C2-2; `modell=claude-sonnet-5-5`)

### §B-4e.0 Guard
`<B4E-START>` = `aac2242`, subject `docs(m7): B-4d @ dcd4a93 (Q213–Q215; VERIFY-DELTA-B4b, B4c 1–2)`; clean tree, branch `m07-client-core`; highest D entry before: `D-B47`. `target/fable/material/M7-B-4e/` did not exist in the container; the fixtures are those dictated in the Weisung. No dependency, lockfile, `secmp-proto`, `vectors/`, `docs/03`/`docs/02` change; no product code change.

### §B-4e.1 Findings
Commit `eeaa895` `test(xtask): Debug and seed scans close their blind spots (C1-5, C2-2)` — `xtask/src/testscan.rs`. Red lines verbatim in `docs/reviews/M07-evidence/b4e-red-first.txt` (head `aac2242`).

| Finding | Change | Fixtures (all red against the old scanner) |
|---|---|---|
| C1-5 | `attributes_of` joins a multi-line attribute (read upward from its closing `]` to its `#[`) and walks across attribute and `//` lines; `derives_debug` finds `derive(…Debug…)` anywhere in an attribute, so also in `cfg_attr(…, derive(…))` | `#[derive(\n Clone,\n Debug,\n)]` on `QueueEntry` caught (red: `attributes_of(multi, "QueueEntry").is_some_and(|a| derives_debug(&a))`); `#[cfg_attr(feature = "kat", derive(Debug))]` on `Request` caught (red); `cfg_attr(…, derive(Clone))` not caught (green both) |
| C2-2 | `public_signatures` takes `pub async fn`, `pub unsafe fn`, `pub const unsafe fn` (and `const async`, `async unsafe`) and every `fn` one indent level inside an `impl … for …` block; `plain_aliases` collects the plain-`[u8; 32]` aliases of every file in a first pass, `plain_seed_returns` takes them as a parameter; `no_plain_seed_returns` walks twice | `pub async fn queue_material`, `pub unsafe fn seed_raw`, `pub const unsafe fn seed_raw`, trait method `fn send_seed` in `impl SeedSource for Hub` (each red: expected 1 hit, got `[]`); two-file alias `RawSeed` / `material() -> RawSeed` (red: `left: 0 right: 1`); negative: trait method returning `SecretBytes<32>` gives no hit |

Product hits of the widened scans: none (`no_derive_debug_on_secret_carriers` and `no_plain_seed_returns` are green on `secmp-client-core/src`), so no product code changed and no `SecretBytes<32>` retyping was needed.

### §B-4e.2 Gates
`cargo xtask ci-fast` at `eeaa895`: PASS (first run on the uncommitted tree failed in clippy `items_after_statements` for a `const` in `public_signatures`; moved it above the first statement, fmt/clippy clean, rerun PASS) → `docs/reviews/M07-evidence/ci-fast-b4e-1-eeaa895.txt`. ci-full: not run (no product change).

### §B-4e.3 Deviations (new: D-B48)
- **D-B48 (red-first form).** The old `plain_seed_returns` has a two-argument signature, so the seed fixtures could not be compiled unchanged against it; the old scanner body was kept behind the new signature (the `crate_aliases` parameter ignored) for the red run. **Erratum (B-4f, L2):** the red run used the **new** `public_signatures` with the old `plain_seed_returns` body (the two-file panic at `testscan.rs:1332:5` of `b4e-red-first.txt` fits only that combination); against the old `public_signatures` (@aac2242 `:1087-1089`, only `pub fn `/`pub const fn `/`pub type `) the fixtures are red by reading. Fixtures 9, red 7 (2 Debug + 4 loop + 1 two-file); any count of 8 red in §B-4e is wrong. The four single-file fixtures of the loop were reported by a temporary `eprintln!` (the committed loop asserts and would stop at the first failure). Scope kept: hand-written `impl Debug` bodies and raw-seed struct fields stay deferred to M8.

### §B-4e.4 Blocked
None.

## §B-4f — control content keeps its owner until `OK_SEND` (Q222), ADR-058, EXTB2-2, EXTB2-3 (WEISUNG M7-B-4f; `modell=claude-opus-5-5`) — stopped at step 5, continued by WEISUNG M7-B-4f2 (Q223–Q226)

### §B-4f.0 Guard and inventory

- Guard (`modell=claude-opus-5-5`): `git status --short` empty; branch `m07-client-core`; `test(core): killer for mark_reset (Q210b)` in the log (1); `grep -c '^| Q221' docs/reviews/M07-planning/OPEN-M7-decided.md` = 1; `^### ADR-058` absent. `<START>` = `git rev-parse HEAD` = `8f4bcbdecee5e7926749aac0ccc1e5f156f40682` (B4F-START `8f4bcbd`), subject `docs(m7): ci-fast evidence for CI3` — **DOCS1 had not run**: `git log --oneline 8f4bcbd..HEAD` was empty, `HEAD` = `8f4bcbd`; `^### ADR-056` and `^### ADR-057` do not exist (the weisung allows this start; ADR-058 was inserted after ADR-055's closing `---`, before `*Template for new entries:*`). Highest D entry: `D-B48`; new entries start at `D-B49`.
- Fixture grep (`grep -rnE 'AppKind::(Reaction|Edit|Delete|AttachmentInline)|kind: [2456],' crates/secmp-client-core/src crates/secmp-testkit`): `crates/secmp-client-core/src/outbox.rs:413` (`m.kind = AppKind::Edit;`), `:420` (`assert_eq!(m.kind.byte(), AppKind::Edit.byte());`) — the StoreOutbox field test, not through `queue_message` — and `crates/secmp-client-core/src/sessions/mod.rs:203` (the check step 2 replaced). No other hit.
- Kani/fuzz: `grep -n 'Conversation\|Owner\|Delivery\|receive' crates/secmp-client-core/src/kani_proofs.rs fuzz/fuzz_targets/*.rs` gives only `kani_proofs.rs:579` (`l.received().len()`, a link), `:911` (a doc string) and comment/fixture lines of `link_relay_handshake.rs:119`, `tr_decrypt.rs:3,7,9,20,46,70`, `link_frame_open.rs:5,10`: no harness models the actor, `Owner`, `Delivery` or `Inbox::receive` (`tr_state` decodes `Inbox::from_bytes` only; `InboxV1` unchanged). No model step.
- Commits (`git log --oneline 8f4bcbd..HEAD`): `5e7094a` EXTB2-2 · `7ac3307` EXTB2-3 · `a24ca32` ADR-058 · `4251a0b` Q222 (1)–(3) · the docs commit of this STOP.
- **B-4f2 guard (WEISUNG M7-B-4f2 step 0).** `git status --short` empty; branch `m07-client-core`; `git merge-base --is-ancestor 1a5c5ed HEAD` exit 0; `git diff --stat 4251a0b..HEAD` over the guarded paths (`sessions`, `scheduler`, `hub.rs`, `api.rs`, `persist.rs`, `secmp-proto`, store `sessions.rs`, `schema.rs`) empty. `<START2>` = `72f72d810921eb24661d94841bfb4ae6921fd4a1` (`72f72d8`). `git log --oneline 4251a0b..72f72d8`: `cc19517` (this STOP), DOCS1b `1ac1906`, `795ad1d`, `1a5c5ed`; CI4 `f66eb73`, `2312251`; REF-M7-store3 `c652db4`, `052127c`, `72f72d8`. `git diff --stat 4251a0b..72f72d8` (26 files): `crates/secmp-client-core/src/profile.rs`, `crates/secmp-store/src/delete.rs`, `crates/secmp-store/src/store.rs` (CI4); `docs/02-architecture.md`, `docs/03-protocol-spec.md`, `docs/08-decisions.md`, `docs/09-open-questions.md`, `OPEN-M7-decided.md`, `TEST-SPEC-M7.md`, `M07-report.md`, `ci-fast-ci4-f66eb73.txt`, `ci4-red-first.txt` (DOCS1b/CI4, `docs/**`); `ref/gen_vectors.py`, `ref/secmp_ref/store.py`, `ref/secmp_ref/store_cases.py`, `ref/tests/test_encodings.py`, `ref/tests/test_store.py`, `ref/tools/render_schema_4_{8,9,10,11,12}.py`, `ref/SCHEMA-4.12-store.md` → `vectors/SCHEMA-4.12-store.md` (REF-M7-store3); `xtask/src/docs.rs` (DOCS1b); `b4f-stop-se28-probe.txt`, `ci-fast-b4f-4-4251a0b.txt` (`cc19517`). Every path is a foreign path of the B-4f2 list or `cc19517`'s; M7-VEC1 had not committed. ADR-056 and ADR-057 are present (DOCS1b), before ADR-058.
- Material: `target/fable/material/M7-B-4f2/DICT-B4f2-fixups.md` (present). B-4f2 commits: `e161e4d` F1 · `634648d` F2 · `4adcaf1` F3 · `717b4b0` F4 · `307b033` step 5 · `dd345f3` step 6 · `7ed551c` step 7 · `f51d603` killers · `2225414` step-8 evidence · the ci-full evidence and docs commits.

### §B-4f.1 Findings: fix, test, red-first

Every red line is quoted verbatim, with its command, in `docs/reviews/M07-evidence/b4f-red-first.txt` (line 1 `head 8f4bcbd…`). "Mutation" = a one-site mutation of the fix in the committed tree, applied, run and reverted (`git diff` empty after).

| Item | Commit | Test | Red-first (`path:line:col`) |
|---|---|---|---|
| EXTB2-2 | `5e7094a` | SE-22 `sessions::tests::extb2_reset_with_argument_is_ignored` | `sessions/tests.rs:543:9` `left: Err(Reset)` `right: Ok(())` (unfixed tree) |
| EXTB2-3 Api | `7ac3307` | SE-23 `sessions::tests::extb2_api_rejects_undefined_kinds_and_invalid_text` | `sessions/tests.rs:599:9` "ADR-054(1,3): Api accepted invalid cases with kinds [1, 1, 1, 4, 5, 6]" (unfixed tree) |
| EXTB2-3 receive | `7ac3307` | SE-24 `sessions::tests::extb2_receive_drops_undefined_kinds_and_invalid_text` | `sessions/tests.rs:654:9` "ADR-054(1,3): receiver delivered invalid cases with kinds [1, 1, 1, 4, 5, 6]" (unfixed tree) |
| EXTB2-3 every constructor | `7ac3307` | SE-36 `sessions::actor::tests::adr054_receive_rules_on_without_the_switch` | `actor.rs:2090:9` `left: [[50; 16], [51; 16]]` (unfixed tree); mutation: empty body of `raw_app_payloads_kat` → `actor.rs:2100:9` "the test kit's switch" `left: []` |
| ADR-058 proto | `a24ca32` | `tr::tests::content_key_change_authenticated_repeat_branches` | mutation (1) fallback arm deleted → `tr/tests.rs:2467:5` "(b)" `left: "KeyChangeRefused"`; (2) `current == Some(&kc.iks) &&` deleted → `tr/tests.rs:2480:5` "(e)" `left: "KeyChangeUnchanged"` |
| ADR-058 store | `a24ca32` | `secmp-store` `sessions::tests::previous_identity_round_trip` | mutation `put_previous_identity` body `Ok(())` → `secmp-store/src/sessions.rs:458:9` `left: None` |
| ADR-058 receiver | `a24ca32` | SE-33 `sessions::tests::duplicate_key_change_is_dropped_not_frozen` | `sessions/tests.rs:1876:9` "a repeat is not frozen" `left: Frozen` `right: KeyChanged` (unfixed tree) |
| ADR-058 forged | `a24ca32` | SE-42 `forged_duplicate_key_change_freezes` | mutation `previous.is_some_and(…)` → `previous.is_some()`: `sessions/tests.rs:1916:9` `left: KeyChanged` `right: Frozen` |
| ADR-058 no previous | `a24ca32` | SE-43 `key_change_naming_current_identity_without_previous_freezes` | mutation → `previous.map_or(true, …)`: `sessions/tests.rs:1941:9` `left: Unverified` `right: Frozen` |
| OPEN-M7-B-12 residual | `a24ca32` | SE-44 `older_key_change_after_a_newer_one_freezes` | green on the unfixed tree; the named two-line mutation (`get_or_insert` + current check deleted): `sessions/tests.rs:1980:9` `left: KeyChanged` `right: Frozen` |
| ADR-058 third identity | `a24ca32` | SE-45 `old_key_cannot_announce_another_identity` | green on the unfixed tree; mutation current check deleted: `sessions/tests.rs:2003:9` `left: KeyChanged` `right: Frozen` |
| Q222 (2) restart | `4251a0b` | SE-25 `sessions::tests::extb2_key_change_survives_last_seal_before_write_restart` | `sessions/tests.rs:2093:9` "the row outlives the seal of the last cell (Q222 2)" `left: 0 right: 1` (unfixed tree) |
| Q222 (3) failure | `4251a0b` | SE-26 `sessions::actor::tests::extb2_failed_control_send_remains_retryable` | `actor.rs:2193:9` "a failed SEND lost the reset notification" (unfixed tree) |
| Q222 eviction | `4251a0b` | SE-27 `evicted_route_update_is_resent` | `sessions/tests.rs:2131:9` `left: 0 right: 1` (unfixed tree) |
| Q222 (2) | `4251a0b` | SE-29 `control_row_deleted_only_after_last_ok_send` | `sessions/tests.rs:2162:13` "after the seal of cell 3" `left: 0 right: 1` (unfixed tree) |
| Q222 (3) superseded | `4251a0b` | SE-30 `superseded_control_attempt_outcomes_are_ignored` | `sessions/tests.rs:2193:17` "after the last seal" `left: 0 right: 1` (unfixed tree); mutations: `on_relayed` without the attempt comparison → `:2202:17` same assert; `replan_control` without the attempt check → `:2208:9` "nothing planned again" |
| Q222 (2) restart | `4251a0b` | SE-31 `control_written_without_ok_send_is_resent_after_restart` | `sessions/tests.rs:2241:9` "read again after the restart" `left: 0 right: 1` (unfixed tree) |
| M-4 Routes | `4251a0b` | SE-37 `superseded_route_update_is_not_resent` | green on the step-3 tree (as dictated); mutation supersession branch deleted → `sessions/tests.rs:2279:9` `left: 2 right: 1`; B-4f2 (Q224): branch removed, red re-proved by "`retire_routes()` call deleted" → `sessions/tests.rs:2279:9` `left: 2 right: 1` (measured at `sessions/tests.rs:2319:9` — the line moved by SE-48, inserted above it in F2) |
| PC-03 | `4251a0b` | SE-39 `scheduler::outbox::tests::mem_persist_forwards_control_rows_to_its_mirror` | mutation `MemPersist::control_requeued` → `Ok(None)`: `scheduler/outbox.rs:586:9` `left: Ok(None)` `right: Ok(Some(7))` |
| Q222 (2) settle | `4251a0b` | SE-40 `sessions::actor::tests::settle_retries_a_failed_row_delete` | mutation "`Err` also sets `ord = None`": `actor.rs:2477:9` `left: [4]` `right: [4, 4]` |
| §9.5 late eviction | `4251a0b` | SE-41 `late_eviction_rewrites_the_control_row` | `sessions/tests.rs:2303:9` "written again" `left: 0 right: 1` (unfixed tree) |
| Q226 (F1) | `e161e4d` | none (a cfg change); no-`kat` `cargo check --locked -p secmp-client-core` ok (`b4f2-F1-nokat-check-e161e4d.txt`) | — |
| Q224 Option R (F2) | `634648d` | SE-46 `sessions::actor::tests::superseded_route_row_delete_is_retried` | `actor.rs:2638:9` `left: []` `right: [("relayed", 4)]` (unfixed tree); mutations: `entry.retired ||` deleted → `actor.rs:2663:9` `left: [[4; 16], [3; 16]]`; settle (ii) `(e.done)` → `actor.rs:2652:9` `left: [("relayed", 4)]`; retain `{ true }` → `actor.rs:2658:9` `left: 4 right: 2` |
| Q224 (F2) | `634648d` | SE-47 `sessions::actor::tests::superseded_routes_row_is_not_rewritten` | `actor.rs:2674:9` `left: 2 right: 1` (unfixed tree); mutation `self.controls.remove(&id)` deleted → `actor.rs:2679:9` `left: 2 right: 1` |
| Q224 at open (F2) | `634648d` | SE-48 `sessions::tests::two_route_rows_read_back_send_only_the_newer` | `sessions/tests.rs:2092:9` "the older RouteUpdate row goes at open" `left: 2 right: 1` (unfixed tree) |
| Q225 (F3) | `4adcaf1` | SE-49 `sessions::actor::tests::control_cell_waits_for_its_row` | `actor.rs:2669:9` `left: 1 right: 0` (F2 tree); mutation `row_missing` → `false` → `actor.rs:2694:9` same |
| Q225 `Ok(None)` (F3) | `4adcaf1` | SE-50 `sessions::actor::tests::durability_without_rows_holds_nothing` | green on the F2 tree and under the one-site mutation; the named two-line mutation (both `Ok(None)` arms → `{}`) → `actor.rs:2733:9` `left: 0 right: 1` |
| F-03 (F4) | `717b4b0` | SE-51 `sessions::tests::undecodable_previous_identity_freezes_a_repeat` | mutation `.map(|row| IksPublic::decode(&row)).transpose()?` → the open fails, runner line `Error: "unavailable"` |
| F-03 (F4) | `717b4b0` | SE-52 `sessions::tests::previous_identity_read_error_fails_open` | mutation `.previous_identity(contact.0).ok().flatten()` → `sessions/tests.rs:2071:9` "ADR-058: a previous identity that does not open fails the open" |
| Q222 (3) lost queue, Q223 | `307b033` | SE-28 `sessions::tests::queue_lost_replans_unsealed_and_sealed_control_content` (re-dictated) | `sessions/tests.rs:2205:9` `left: [Some(1)]` `right: [Some(1), Some(2)]` (no `on_lost` hunk); mutation `retire_routes()` deleted → same line `left: [Some(1), Some(1), Some(2)]` |
| Q-5 switch | `307b033` | SE-35 `sessions::actor::tests::switch_replans_unsettled_control_content` | `actor.rs:2764:9` "Q-5: unsettled control content is planned again for the new queue" (unfixed tree); mutation `!e.done` → `e.done` → `actor.rs:2794:9` same |
| Q222 (5), §10.1 | `307b033` | SE-32 `sessions::actor::tests::replanning_control_seals_nothing_outside_a_slot` | green on the unfixed tree; mutation `let _ = self.seal(&dummy());` last in `replan_control` → `actor.rs:2835:9` "after on_failed" `left: 2 right: 1` |
| M-3 hub repeat | `307b033` | SE-38 `hub::tests::repeated_route_update_registers_one_send_queue` | `hub.rs:1363:13` `left: [1, 1, 1]` `right: [1, 0, 1]` (unfixed tree) |
| KC guard | `dd345f3` | SE-34 `api::tests::second_rotation_refused_while_key_change_in_flight` | `api.rs:1837:13` `left: None` `right: Some(Unavailable)` (unfixed tree); F-05 mutations body → `false` and `Some(&3)` → `Some(&1)`: `api.rs:1846:13` same |
| VD-1 | `7ed551c` | skip rows measured from `ci-fast-b4f-6-dd345f3.txt`: `PASS [  29.025s] … queue_new_without_sender_seed_fails_closed`, `PASS [  16.830s] … hub_step_error_reaches_hub_errors` → 29 s (was 13 s) and a new row 17 s in `expect::MUTANT_HARNESS_SKIP_TESTS` and `docs/mutants-accepted.md` §Skipped (gate `mutants_skip_list_names_existing_tests` green) | — |
| VD-2 | `7ed551c` | `harness::m7_restart::queue_deleted_failure_reaches_hub_errors` asserts the `queue_deleted:` prefix | mutation `driver.rs` `"step: {err}"` → `m7_restart.rs:309:5` "the refused write of queue_deleted is reported" |
| VD-3 | docs | OPEN-M7-B-13 | — |
| L1 | `7ed551c` | `xtask::testscan::no_plain_seed_returns` one-line trait-impl fixture | `testscan.rs:1321:5` "a one-line trait impl opens no block (L1)" (scanner as at START) |
| PP-1…4, L2–L5 | docs commit | report text (below) | — |
| step-8 killers | `f51d603` | `sessions::actor::tests::held_control_cell_lets_a_message_through` (`actor.rs:1314:27`), `sessions::actor::tests::lost_queue_replans_each_control_content_once` (`actor.rs:1438:16`) | mutant applied by hand: `actor.rs:2898:9` `left: []`; `actor.rs:2932:9` `left: 3 right: 2` |
| G7-19 needles (DOCS1b minor) | docs commit | `xtask::docs::adr_018_status` two new needles | line 109 of `docs/08` deleted in the working tree: `docs.rs:299:5` `assertion failed: adr018.contains("**ADR-018 Amendment 1 — acceptance after M6. Status: Accepted (Owner, 2026-11-09")` |

Sanctioned edits made: SE-20 payload (`inline_attachment_64k`, ASCII letters); `pending_control_content_survives_restart` (its cells relayed, cell ids `1..`, one more `next` before the row-0 assert, message "the last cell's OK_SEND took the row (Q222)", doc line); the test `Persist` impls `Stamps`, `Commits`, `Blocks` (`actor.rs`), `Whole` (`persist.rs`), `Logged` (`m7_persist.rs`, forwards to `inner`); `tr/tests.rs` `kind()` arm `KeyChangeUnchanged`; `raw_app_payloads_kat()` after `Conversation::new` at the 17 listed sites (`two_clients/run.rs:522` binding made `mut`; `m6_activity.rs:155,164` and `m6_tokio.rs:326,335` one line each); no unlisted site needed it (ci-fast of `7ac3307` green). Mechanical (signature change of `plan_control`): `receive_commit_carries_the_block` and `contact_removed_needs_an_empty_argument` pass `super::Owner::Dummy` where they passed `None`. **Sanctioned edits — 11 (F-04):** steps 1–4 (10): SE-20 payload (`inline_attachment_64k`); `pending_control_content_survives_restart`; the test `Persist` impls `Stamps`, `Commits`, `Blocks` (`actor.rs`), `Whole` (`persist.rs`), `Logged` (`m7_persist.rs`); `tr/tests.rs` `kind()` arm; `receive_commit_carries_the_block`, `contact_removed_needs_an_empty_argument` (`None` → `Owner::Dummy`); B-4f2 (1): `session` → `pair` (the body moved, `session` calls `pair`). The 17 `raw_app_payloads_kat` sites are counted apart. The test `Persist` impls also gained `Script`/`FlakyDelete` (new, not edits).

Anchors re-found (old @aac2242 → `4251a0b`): `sessions/actor.rs` `Owner` `:134` → `:135`, `Planned` `:143` → `:146`, `PendingControl` `:156` → `:182`, `Conversation` `:302` → `:338`, `new` `:355` → `:401`, `from_parts` `:409` → `:460`, `plan_control` `:429` → `:480`, `queue_pending` `:473` → `:519`, `plan_key_change` `:493` → `:661`, `restart_from` `:605` → `:783`, `switch_send_queue` `:661` → `:840`, `seal` `:905` → `:1081`, `restore` `:957` → `:1133`, `prepare` `:1019` → `:1216`, `hold_planned_real` `:1092` → `:1290`, `on_relayed` `:1115` → `:1317`, `on_evicted` `:1134` → `:1347`, `on_failed` `:1140` → `:1353`, `on_lost` `:1146` → `:1359`, `on_deliver` `:1156` → `:1369`, `apply_delivery` `:1263` → `:1502`, `effects` `:1401` → `:1659`, `CellSource` `:1507` → `:1765`, `mod tests` `:1576` → `:1834`, `session()` `:1858` → `:2144`; new: `app_payload_ok` `:253`, `key_change_in_flight` `:526`, `add_control` `:532`, `plan_content` `:568`, `replan_control` `:591`, `settle_controls` `:639`. `sessions/mod.rs` `peer_key` `:51` (unchanged), new `peer_identity` `:60`, `set_verified` `:68` → `:77`, `block_session` `:112` → `:122`, `MESSAGE_MAX` `:163` → `:173`, `queue_message` `:186` → `:196`, `open_conversation` `:343` → `:353`. `persist.rs` `write_parts` `:273` (unchanged; `put_previous_identity` `:292`), `impl Persist for StorePersist` `:155`. `scheduler/outbox.rs` `CommitParts` `:309`, `trait Persist` `:346` → `:347`, `MemPersist` impl `:457`. `hub.rs` `register_route` `:308`, `register_route_sets_t_rs` `:1327`; `api.rs` `rotate_identity` `:909` (unchanged, not touched). `sessions/tests.rs` `world` `:153`, `established` `:381`, SE-20 `:402`, `flush` `:549` → `:723`, `pending_control_content_survives_restart` `:836` → `:1036` (the file map's `:836` was already `:862` at `8f4bcbd`).

### §B-4f.2 Gates

| Gate | Result |
|---|---|
| `cargo xtask ci-fast` per step (foreground; raw output, `head <40-hex>` on line 1) | PASS: `ci-fast-b4f-1-5e7094a.txt`, `ci-fast-b4f-2-7ac3307.txt`, `ci-fast-b4f-3-a24ca32.txt`, `ci-fast-b4f-4-4251a0b.txt` (each with the harness step, 915–960 s: the constant-rate oracles SE-19, AI-01…AI-06, `m6_tokio_ai`/`m6_tokio`/`m6_sim`/`m6_props` green with their assertions unchanged). A first commit of step 2 failed `cargo fmt --check` (layout of SE-23) and was amended before its ci-fast. Clippy findings on the way (`doc_markdown`, `too_many_lines` of `on_deliver`, `needless_pass_by_value` of `plan_key_change`) were fixed in the code, not allowed. |
| B-4f2 ci-fast per commit | PASS: `ci-fast-b4f2-F1-e161e4d.txt`, `-F2-634648d`, `-F3-4adcaf1`, `-F4-717b4b0`, `ci-fast-b4f-5-307b033.txt`, `ci-fast-b4f-6-dd345f3.txt`, `ci-fast-b4f-7-7ed551c.txt`, final `ci-fast-b4f-l-2225414.txt`; constant-rate oracles green with their assertions unchanged. No-`kat` check after F1: `b4f2-F1-nokat-check-e161e4d.txt` (`Finished`). |
| mutants (in-diff `8f4bcbd..7ed551c`, foreign `profile.rs` excluded) | `mutants-b4f-7ed551c.txt`: core 121 mutants, 96 caught, 2 missed (`actor.rs:1314:27`, `:1438:16`, killed by `f51d603`), 23 unviable, 0 timeouts (98 %); proto (`tr/content.rs`) 6: 2 caught, 4 unviable; store 12: 8 caught, 4 unviable — every outcome printed, then the dictated `timeout 900` interrupted the run before its summary (exit 124). New accepted rows: none; re-pinned `hub.rs:483:30` → `:497:30`. |
| coverage | `coverage-b4f-f51d603.txt`: client-core 12387/12999 = 95.3 %, proto 7113/7283 = 97.7 %, store 5505/5726 = 96.1 % (min 90 %). |
| ci-full | **PASS** on `2225414` (strict; delegated windows-native, windows-cross, mutants, ct, proverif-link; `--models tr`): `ci-full-b4f-2225414.txt` (Q218 excerpt, 212 lines; raw log 3 192 559 B, above the 2 MiB gate, outside the repo, digest in `ci-full-b4f-raw-digests.txt`); 04:20–08:18 UTC 2026-11-11 (step times sum 14 235 s), detached, polled; Kani 57/57, fuzz 4440 s, Miri 2418 s, ProVerif tr 31/31 hashes |

### §B-4f.3 Deviations (new: D-B49…D-B67)

- **D-B49 (a).** `Owner::Control(ControlRef { id, attempt })`, `ControlEntry { row, ord, durable, attempt, total, relayed, done }`, `Conversation::{controls, next_control}`: the id is conversation-local because `insert_pending_control` reuses `ord`s (`MAX(ord) + 1` after a delete). `Owner::Dummy` stays for dummies and the raw test content.
- **D-B50 (b).** `Persist::control_relayed` and `Persist::control_requeued` are required methods (no default body); `CommitParts::control_done` and `seal`'s `pending` parameter are removed (the eight literals dropped it), `CommitParts::previous_identity` is added (`None` in every literal but the receive commit).
- **D-B51 (c).** A control row goes at the next `prepare` after the last cell's `OK_SEND` (`settle_controls`, first in `prepare`): the scheduler reports an `OK_SEND` as `relayed`, then the evictions it names (`scheduler/core/mod.rs:1092-1095`).
- **D-B52 (d).** A later eviction re-writes the row (`control_requeued`); a failed re-write is retried before the next seal; a failed delete is retried at the next `prepare`.
- **D-B53 (e).** The ADR-054 receive rules are on in every constructor (`app_rules = true` in `new`); the only opt-out is `raw_app_payloads_kat` (`cfg(any(test, feature = "kat"))`), called at the 17 harness sites (4 in constant-rate oracle files, one line each); SE-20's payload is ASCII.
- **D-B54 (f).** SE-25 detects the last seal by count (`chunk_total(1 + 5390)` cells), not by the row's disappearance; `pending_control_content_survives_restart` relays its cells.
- **D-B55 (g).** A re-sent `Control{1|2}` repeats its event at the peer (state idempotent; UI de-dup is Phase C) — SE-31 asserts the state, not the event; an older `RouteUpdate` is dropped when a newer one exists (`add_control` retires it, Q224). The hub registers a repeated route once (`send_routes`, full descriptor, `ct_eq`; step 5, `307b033`).
- **D-B56 (h).** `sessions` part 6 `PREVIOUS_IDENTITY` (no DDL; ADR-058), one row at ord 0, sealed like every `sessions` row; `Store::previous_identity`, `sessions::put_previous_identity`. A row that reads but does not decode or whose `ik_sig` does not load is treated as absent at open; a read/open error fails the open.
- **D-B57 (i).** `queue_route_update`/`queue_control` no longer plan a body that does not encode; a content whose re-plan fails stays unplanned until the next open; `add_control` removes the entry again when its first plan fails (no live entry without cells).
- **D-B58 (implementer's choices).** (1) The dictated test helper `rows(store)` is `control_rows(store)`: `rows(fx, table)` exists in `sessions/tests.rs`. Further test helpers: `rotated_host` (the scene of SE-25/29/30: `established`, a core's `RotateIdentity`, reopen — seeds `seed + 1`, `seed + 2`, i.e. SE-25's 612/613), `routes_of`, `accepted_key_change` (SE-33/42/44/45 up to copy 1), `contact_one`, `trust_and_block`, actor `text_batch`, `FlakyDelete`. (2) `on_deliver` exceeded clippy's 100 lines: `fresh_messages` (the `fresh` filter, ADR-054) and `replaced_identity` (the ADR-058 previous identity) are factored out; `plan_key_change` consumes its `owner` through `core::iter::repeat_n` (`needless_pass_by_value`). (3) `Inbox::receive`'s doc gains one sentence ("No repeat … is recognised (see `Inbox::receive_known`)"). (4) The subject of `4251a0b` reads `(Q222 1-3)` with an ASCII hyphen instead of the dictated `(Q222 1–3)`; not amended, because its ci-fast evidence names `4251a0b`. (5) `secmp-store` `delete_pending_control`'s doc still says "its last cell was sealed and persisted" (not in the dictated doc list; stale since Q222).

- **D-B59 (Q224, F2).** Option R: `add_control` retires every kept `RouteUpdate` entry before a newer one is planned (its cells leave the plan, its row is deleted, a failed delete is retried at every settle, the entry is dropped once its row is gone; `retired` entries are never planned or re-written, their outcomes ignored). The restart defence of Q224 is `add_control`'s retirement, which `open_conversation` reaches for every stored row; the `replan_control` branch is dead under Option R and removed. In test/kat builds an in-memory `RouteUpdate` (Q226) may retire a durable one — accepted, test-only.
- **D-B60 (Q225, F3).** A planned cell of a durable control content whose row is not in the store is not sealed (`row_missing`); the slot carries the next sendable item, a newly planned receipt/message, or a dummy (one cell per preparation, same frame). A re-write that returns `Ok(None)` marks the entry non-durable (a durability that keeps no rows, `MemPersist` without mirror); `StorePersist` never returns `Ok(None)`.
- **D-B61 (Q226, F1).** `queue_route_update` is `#[cfg(any(test, feature = "kat"))]`; no product caller; one no-`kat` `cargo check` (`b4f2-F1-nokat-check-e161e4d.txt`), since no ci-fast step builds client-core without `kat` (OPEN-M7-B-15).
- **D-B62 (Q223).** SE-28 re-dictated: rows {reset, newest `RouteUpdate`}, one `ResetRequested`, sids `[[4; 16]]`.
- **D-B63 (F-05).** `Conversation::key_change_in_flight` landed in `4251a0b` (step 4) instead of step 6; unused until step 6 (`dd345f3`). SE-34's two mutation reds (body → `false`, `Some(&3)` → `Some(&1)`) are in `b4f-red-first.txt`.
- **D-B64 (F-04, sanctioned edits).** 11, named in §B-4f.1 (10 in steps 1–4 — the report named 8, the two `Owner::Dummy` call sites were listed as "mechanical" — and `session` → `pair` in B-4f2).
- **D-B65 (material §4.5 list).** F2 Option R with the branch removal and the test-kit retirement (D-B59); F3 hold and `Ok(None)` rule (D-B60); F1 with the no-kat check (D-B61); F-05 (D-B63); F-04 (D-B64).
- **D-B66 (implementer, B-4f2).** (1) SE-37's re-proved red is at `sessions/tests.rs:2319:9` (the material's `:2279:9` before SE-48 was inserted above it). (2) The `resets` helper moved from F2 to F3 (unused in F2: `dead_code`). (3) Two killer tests for the two missed core mutants (`f51d603`). (4) `docs::adr_018_status` red-first restored the line by copying the saved file, not by `git checkout` (`git diff` empty either way). (5) ci-full was started detached (own session, raw log `target/fable/ci-full-raw/ci-full-b4f-2225414.txt`) so that the tool's 4-h background limit cannot stop it; a first background start was stopped by me after a few seconds for that reason (no step had finished). (6) The store mutants run ended by its dictated `timeout 900` after all 12 outcomes. (7) `Core::rotate_identity`'s guard uses `crate::sessions::actor::Conversation::key_change_in_flight` as a path (clippy `redundant_closure_for_method_calls`).
- **D-B67 (L2–L4 placement).** L3/L4 are `D-CI6`/`D-CI7`: `D-CI5` was taken by CI4. L2: §B-4e states no count of 8 red (its table says "all red against the old scanner"); nothing to correct beyond the erratum.
- **D-B69 (m-1).** `mutants-b4f-7ed551c.txt`'s core section omits the two `MISSED` lines that cargo-mutants printed; from `target/m7-b4f-mutants-core/mutants.out/missed.txt`: `crates/secmp-client-core/src/sessions/actor.rs:1314:27: delete ! in Conversation<O, P, S>::prepare` and `crates/secmp-client-core/src/sessions/actor.rs:1438:16: delete ! in Conversation<O, P, S>::on_lost`.

### §B-4f.4 Risks

- OPEN-M7-B-12 (two successions in flight; residual: a restart inside the eviction window; cross-queue order of `RouteUpdate`s before a switch), OPEN-M7-B-13 (QR confirmation unreachable), OPEN-M7-B-14 (`cargo audit bin` without `--ignore`), OPEN-M7-B-15 (`kat` must not reach a product binary).

### §B-4f.5 Blocked

The STOP at step 5 (SE-28) is resolved by WEISUNG M7-B-4f2 (Q223 = (A), Q224 Option R). The RUSTSEC-2026-0486 STOP below is resolved by ADV1 @ `598a948` (WEISUNG M7-ADV1, Q229, ADR-051 Am. 9).
**STOP (WEISUNG M7-B-4f §5 "any gate red that the step did not expect"; CLAUDE.md §6 "an open RustSec advisory").** The ci-fast of the
docs commit `4b95e6a` (`ci-fast-b4f-10-4b95e6a.txt`) is red in `deny` and `audit` only: RUSTSEC-2026-0486 "xattr functions mark
unwritten bytes as initialized when given a zero-length buffer" (unsound), `rustix 1.1.5` (`Cargo.lock:3406`; also `fuzz/Cargo.lock:3359`), solution "Upgrade to
>=1.1.6"; `cargo tree -i rustix@1.1.5 -e normal`: `rustix` ← `tempfile 3.27.0` ← `arti-client 0.46.0`. The advisory reached the
local database after the final ci-fast (`2225414`, PASS) and ci-full (`2225414`, PASS, `audit` PASS at 04:20 UTC); no B-4f commit
touches `Cargo.toml`, `Cargo.lock` or `fuzz/Cargo.lock`. Not fixed here (a lock bump or an ignore needs an ADR; WEISUNG M7-B-4f §0
forbids lock movement). Every other ci-fast step of `4b95e6a` passed. Question: (A) `cargo update -p rustix --precise 1.1.6` in the workspace and in `fuzz/` (if ≥ 7
days old, `cargo vet` record) or (B) an ADR-051 amendment ignoring RUSTSEC-2026-0486 with a closure check of the xattr functions.

### Pre-push fix-ups (PP) and B-4e2/CI3 fix-ups (L2–L5)

- PP-1…PP-4 applied in this report (D-B41, the two raw-log sentences, the Q212 rows, §B-4c.5 bullet). The evidence file `ci-full-b4c-raw-digests.txt` is not edited: its line 1 says "each is above the 2 MiB gate", its line 7 holds 652 734 B — this report corrects it.
- L2 (§B-4e.3 erratum), L3 (`D-CI6`), L4 (`D-CI7`), L5 (CI row of run 42768313638) applied.

### DOCS1b

DOCS1b @ 1a5c5ed (1ac1906 ADR-056 errata, spec rev 2.7.1; 795ad1d ADR-018 accepted + G7-19 adr_018_status; 1a5c5ed ADR-057 proposed) — docs:: 8/8, ci-fast ok; reviewer verification: PUSH, 0 blocker, 0 major, 1 minor (adr_018_status needles, closed in B-4f2), 7 info.

## §VEC1 — store suite frozen (WEISUNG M7-VEC1 after REF-M7-store3; OPEN-M7-38; `modell=claude-sonnet-5-5`)

- **Commits.** REF-M7-store3: `c652db4` (ref tools L6), `052127c` (ref L7), `72f72d8` (ref case table R1–R6). M7-VEC1: `da9bd6d` (A: `vector_gen`, registration, `store` frozen), `ed453c2` (B: ST-10 and BK-04 byte-exact), and the docs commit (C).
- **Tests (feature `kat`).** `vector_gen::rust_store_vectors_equal_the_reference_file` 3.7 s; `keys::tests::table_keys_match_vectors` (ST-10) 0.008 s; `backup::tests::wrapping_and_header_kat` (BK-04) 6.2 s. `cargo nextest run --locked -p secmp-store --features kat`: 99/99. The plain form does not compile at `1a5c5ed` (`wrap.rs` tests call `kat_small`). `xtask` `vectors::` 9/9 (new: `hex_validator_accepts_the_store_column`, `vectors_step_12a_covers_the_store_suite`; X-01 now 13 suites).
- **Gates.** `cargo xtask vectors`: `store: agrees with ref; frozen as vectors/store.json`, `vectors: 13 suites identical to vectors/ref (structural, SCHEMA §1; positive rows of encodings)`; `cmp vectors/store.json vectors/ref/store.json` equal; `cargo xtask step --strict ref-vectors`: `13 frozen suites (995 cases) structurally and byte-identical to vectors/ref (ADR-026); pending freeze (shape only): none`. DIGEST of `store.json`: `bf45fee4d57ce094c33668d6b8d98ef117bbdc94ca90bd22129af0ecba1c8ddb`, 32 272 bytes, 26 cases.
- **ci-fast.** `ed453c2` (`ci-fast-vec1-ed453c2.txt`): fmt, clippy, policy, vet, cooldown, nextest, doctest, hello, kat, harness, fuzz-check PASS; `deny` and `audit` FAIL on RUSTSEC-2026-0486 (`rustix 1.1.5`, the open STOP of §B-4f.5, unchanged by this unit); last line `exit 1`.
- **ci-fast after commit A.** The `ci-fast` run after `da9bd6d` (commit A) is not recorded: no evidence file exists for it; the only recorded run is the one at `ed453c2` above (VERIFY-DELTA-VEC1 V1-01, folded in by M7-MEM1).
- **Evidence.** `docs/reviews/M07-evidence/vec1-red-first.txt`, `ci-fast-vec1-ed453c2.txt`.
- **D-B68.** The Rust side of `store` is the test-only module `vector_gen` (feature `kat`), not an example: `secmp-store` has no `serde_json` and its constructions are `pub(crate)`; precedent `secmp-client-core` `testutil`. ST-10 is `kat`-gated (`VectorStream`).
- **Implementation notes.** `xtask` `generate` kept under 100 lines by `generate_store()`; `document_of` returns `J` (clippy `unnecessary_wraps`), not `Res<J>`.

## ADV1 (WEISUNG M7-ADV1; RUSTSEC-2026-0486; modell=claude-sonnet-5-5)

- **Red-first.** `cargo xtask step --strict audit` FAIL (exit 1, "1 denied warning found"): `Crate: rustix`, `Version: 1.1.5`, `ID: RUSTSEC-2026-0486`, URL `https://rustsec.org/advisories/RUSTSEC-2026-0486`. No second advisory.
- **Lock (step 2).** `git diff --numstat`: `2 2 Cargo.lock`, `2 2 fuzz/Cargo.lock` (version 1.1.5 → 1.1.6, checksum 891efaba… → e5e76742…, per file). sha256 `Cargo.lock` `19811c71681c48da2c58da179d586c9cb9ec568af850b182d04c0597ffd873ac`, `fuzz/Cargo.lock` `70d624e3823219945c0d2287bd5304816000de1ddf59e26d108e4789c3df45c5` (both as expected). `cargo metadata --locked` (workspace and `fuzz/`), `cargo tree --locked -i rustix@1.1.6` (rustix 1.1.6 ← tempfile 3.27.0 ← arti-client 0.46.0, both lockfiles) and `cargo check --workspace --locked --all-targets` ok; numstat unchanged afterwards.
- **Vet delta (step 3).** `docs/reviews/M07-evidence/vet-deltas/rustix-1.1.5-1.1.6.diff`: 1807 lines, 28 `diff --git` headers, sha256 `fb1e5e3193cd368f10bb6cbd1954107e28a30962a569165c9ac7e743077cc6f1` (same as the planner's copy).
- **Vet record (step 4).** `cargo vet certify --locked rustix 1.1.5 1.1.6 --criteria safe-to-deploy`: `supply-chain/audits.toml` `6 0`, only change in `supply-chain/`; `cargo vet --locked`: Vetting Succeeded (241 fully audited, 3 partially audited, 321 exempted). `config.toml` and `imports.lock` unchanged.
- **Tests (step 9).** xtask pins (`cooldown_covers_m7_lock`, `cooldown_covers_m6_lock`, `audit_ignores_unchanged`, `audit_ignores_match_deny_toml`, `vet_records_for_m7_closure`): 5 passed; `docs::`: 8/8 passed.

| gate | verdict | note |
|---|---|---|
| deny | PASS | advisories, bans, licenses, sources ok |
| vet | PASS | secmp-crypto/secmp-proto closure 60 external crates, 0 exempted; tracked exemptions elsewhere 328 |
| audit | PASS | no advisories; ignored with an ADR (unchanged): RUSTSEC-2026-0173, -2023-0071, -2024-0436, -2025-0141, -2026-0387, -2026-0459 |
| cooldown | PASS | 567 registry packages; youngest rustix 1.1.6, 15 days |
| sbom | PASS | 12 CycloneDX SBOMs; `cargo audit bin` on relay, cli, ui |

- **D-ADV1 (lock edit).** The lockfiles were edited with the dictated `sed` (rustix version + checksum) instead of `cargo update -p rustix --precise 1.1.6`, which also re-points seven `windows-sys` edges (Q229); `cargo metadata/tree --locked` and `cargo check --workspace --locked --all-targets` accept the edit without rewriting it; `cargo vet certify` ran with `--locked` (without it, cargo-vet refreshes `imports.lock`).
- **ci-fast.** `598a948` (`ci-fast-adv1-598a948.txt`): 13/13 steps PASS, `exit 0`; commits `598a948` fix(deps), `432f43a` evidence (VERIFY-DELTA-ADV1 A1-01, folded in by M7-MEM1).

## ADV2 (WEISUNG M7-ADV2; RUSTSEC-2026-0542, RUSTSEC-2026-0543; Q277, ADR-051 Amendment 10; modell=claude-sonnet-5-5)

- **Red.** CAP's ci-fast 1 on `de62a20` (2026-11-17, fresh advisory database): `deny` FAIL on RUSTSEC-2026-0542 (`humantime` 2.4.0, unmaintained); `audit` FAIL, "2 denied warnings": RUSTSEC-2026-0543 (`chrono` 0.4.45) and RUSTSEC-2026-0542; every other step passed. The record stays as `docs/reviews/M07-evidence/ci-fast-cap-1-red-de62a20.txt` (committed with CAP's docs).
- **Advisories.** Both `informational = "unmaintained"`, 2026-09-14, `patched = []`, no vulnerability named; the locked versions are the newest on crates.io, so no bump exists (ADR-051 Am. 10).
- **Paths.** `humantime`: `arti-client` 0.46.0 (directly and via `humantime-serde` 1.1.1 from `tor-*`) ← `secmp-transport` ← `secmp-client-core`; compiled in the client only (not relay, cli, ui; not the `secmp-crypto`/`secmp-proto` closure). `chrono`: lock-only, optional dependency of `serde_with` 3.24.0, never compiled.
- **Change.** `deny.toml` +1 (0542); `xtask/src/expect.rs` `AUDIT_IGNORES` +2 and `audit_ignores_unchanged` (eight ids; path, class, "no known vulnerability" and removal condition of both new entries pinned); `xtask/src/policy.rs` `AUDIT_IGNORES_NOT_IN_DENY` +1 (0543). No lock, `Cargo.toml` or `supply-chain/` change.
- **Gates.** `cargo xtask step --strict deny`, `--strict audit`, `--strict vet`, `--strict policy`: PASS; `cargo nextest run -p xtask`: all passed (324 at `eb2d5cb`, no test added). ci-fast runs in CAP's continuation on this commit.
- **Removal.** At the pre-release hardening phase (ADR-062) or when Arti drops the crate, whichever is first.

## B-4f3 (WEISUNG M7-B-4f3; Q230, Q231; modell=claude-sonnet-5-5)

* START `432f43a`; commits: `c9ac6a5` fix(core) (Q230, SE-53, V-04/V-05/V-02 docs), `3ed68d0` docs, `88caecb` ci-fast evidence; VEC1 (`da9bd6d`, `ed453c2`, `9777151`) and ADV1 (`598a948`, `432f43a`) were present, `sessions/`, `hub.rs`, `api.rs` unchanged since `f51d603`.
* Q230: `settle_controls` keeps the row of a done newer `RouteUpdate` while a retired one holds its row; SE-53 `newer_routes_row_outlives_a_retired_one` red first at `actor.rs:2887:9` (left `[4, 4, 4, 5]`, right `[4, 4, 4]`; `b4f3-red-first.txt`). Q231/OPEN-M7-B-17: guard bound documented (V-02 doc, OPEN-M7-B-12); V-04 two doc additions; V-05 extra `Zeroizing` copy removed in `register_route`; m-1 = D-B69.
* Tests: `cargo test -p secmp-client-core --features kat --lib -- --test-threads=1` 217/217; with the default thread count 35–38 tests fail in the implementer's container, also on `432f43a` without this change. Probable cause (verifier reproduction; not measured in this container): every `LockedSecret` is one locked page charged to the `RLIMIT_MEMLOCK` of the whole process; plain `cargo test` runs all tests of the binary in one process, so concurrent tests add up, while nextest (and so `ci-fast`) runs one process per test (on kernels without 97d34aa65c29; after it the `memfd_secret` charge is per user, OPEN-M7-B-18) (VERIFY-DELTA-B4f3 B3-02, reproduced by the verifier with a 1 MiB limit without `CAP_IPC_LOCK`). The six-test nextest filter: 8/8.
* Mutants (`mutants-b4f3-c9ac6a5.txt`): 8 found, 8 caught / 0 missed / 0 unviable / 0 timeout; `missed.txt` empty. cargo-mutants makes 8 mutants on the changed lines, the 11 hand mutants of the WEISUNG were not re-run by hand.
* ci-fast: `ci-fast-b4f3-1-c9ac6a5.txt` (exit 0), `ci-fast-b4f3-2-3ed68d0.txt` (exit 0; ci-fast of the docs commit `3ed68d0`, committed in `88caecb`). modell=claude-sonnet-5-5

## MEM1 (WEISUNG M7-MEM1; Q232, Q233, ADR-059; modell=claude-sonnet-5-5)

- **Commits.** START `88caecb`; `9bfe1cb` test(sys-mem) (Q232: OS-level evidence of the `memfd_secret` page; three doc comments), the docs commit, the ci-fast evidence commit.
- **Cause.** PR run 43033287006 (`linux-fast`, runner image ubuntu-26.04, Version 20261101.186.1): `guard_pages_and_locking_as_seen_by_the_os` failed with `MemfdSecret: VmFlags " rd wr sh mr mw ms dc dd sd " lacks lo`; the earlier run on ubuntu-24.04 (Version 20261101.360.1) passed; `crates/secmp-sys-mem` is unchanged between the heads. Kernel commit 97d34aa65c29 no longer marks secretmem mappings locked (ADR-059).
- **Test (Q232).** For `MemfdSecret`: a read of the data page through `/proc/self/mem` is refused (an error, errno not pinned) and returns no byte, the same read of an ordinary page succeeds (control), VMA path `/secretmem`, VmFlags `sh` `dd` `dc`; `lo` not required. `Mlock`: `lo` `dd` `wf` as before; guard pages unchanged. Product code unchanged except the doc comments `secret_page.rs:11`, `unix.rs:150` and `unix.rs:197-200` (lines at `88caecb`); no new `unsafe`, no `#[allow]`.
- **Red-first** (`mem1-red-first.txt`, temporary edits not committed): the predicate on the `mlock` page (R1) and on a memfd page mapped by the `MemfdSecret` path (R2) both panic at `crates/secmp-sys-mem/src/secret_page/unix.rs:237:13`: `MemfdSecret: /proc/self/mem read of the data page gave Ok(32) (the kernel must refuse it)`.
- **Tests.** Kernel `7.0.0-34-generic`. `cargo test --locked -p secmp-sys-mem` 9/9; `cargo nextest run --locked -p secmp-sys-mem` 9/9; at START the old test passed on this kernel. ci-fast: `ci-fast-mem1-1-9bfe1cb.txt` (code commit, `exit 0`), `ci-fast-mem1-2-9bfe1cb.txt` (the docs commit; its line 1 names that head; committed in the evidence commit).
- **D-B70 (runner measurements open).** The kernel here still sets `lo` for secretmem (the old test passed at START), so this green run shows the new predicate where `lo` is still present; on a patched kernel it rests on ADR-059's kernel facts (the `get_user_pages` refusal and the `/secretmem` path predate the commit; `sh` `dd` `dc` are in the failing CI line). The runner measurements of DIAG-M7-memfd-secret-vmflags §7 (`uname -r`, `ulimit -l`, VmFlags/VmLck of the secret page) are not taken in this unit; the next PR run shows the test's verdict only. Q233: OPEN-M7-B-18. **Closed by DOCS2 (PR runs 43083238010 and 43137870981; §DOCS2).**
- **Fix-ups folded in.** V1-01 (§VEC1), A1-01 (§ADV1), B3-01 and B3-02 (§B-4f3).

## CI5 (WEISUNG M7-CI5; Q234, ADR-047 Amendment 11; modell=claude-sonnet-5-5)

- **Commits.** START `9589530`; `864102a` ci(mutants): 24 shards (Q234, ADR-047 Amendment 11), the docs commit, the ci-fast evidence commit.
- **Cause.** PR run 43083238010 (`9589530`), `mutants-shard (4)`: `FAIL [8] mutants: mutants: timeout, killed after 16800 s; last line: Error: interrupted` (log `target/mutants-harness-step.log`) with 450 of 458 mutants done; the 8 not reached are all in `secmp-transport`. The same shard (the same 458 mutants: `88caecb..9589530` touches one `secmp-sys-mem` test and docs) passed in PR run 43033287006 (`88caecb`), result lines 14:02:19–16:56:28 (331 caught, 2 missed, 125 unviable). Both runs: runner image ubuntu-26.04 20261101.186.1. Baselines (build + test) 452 + 28 s and 417 + 44 s in the first run, 659 + 45 s and 608 + 82 s in the second. Median test seconds per mutant, second run against first: `secmp-client-core` 81.5 / 47.5 (max 481 / 251), `secmp-transport` 377 / 209.5 (max 542 / 277), `secmp-store` 21 / 14.5. Host speed, not shard content: round-robin sharding gives every shard the same share of each package. No mutant timed out in either run.
- **Decision (Q234).** Full coverage kept (no mutant, package or test skipped; no per-mutant, step or job timeout changed); `expect::MUTANT_SHARDS` 12 → 24; both workflow matrices 0…23, run lines `--shard ${{ matrix.shard }}/24`. Bounds (ADR-047 Amendment 11): (a) 2.1 × the fast-host shard (W 10449 s, B 941 s): N ≥ 263314.8 / 14823.9 = 17.76; (b) 1.5 × the slowest observed shard (W ≤ 18856 s, B 1394 s): N ≥ 339408 / 14709 = 23.07; N = 24. Expected worst case on the slowest observed host: 10822 s, at most 13356 s with one extra full build per extra `-j 3` build directory and run. 24 shards + 10 other gate jobs = 34 concurrent jobs.
- **Guard.** `gates::mutant_shard_findings` (policy step): the matrix of `mutants-shard` (`ci.yml`) and of `dispatch-mutants-shard` (`ci-dispatch.yml`) is 0…N−1 in order and each run line ends in `/N`, N = `expect::MUTANT_SHARDS`. Tests `mutant_shard_matrix_matches_the_shard_count`, `mutant_shard_mismatches_are_findings`, `mutants_merge_needs_all_24_shards`; `mutants_scope_includes_relay` and `mutants_scope_includes_client_core_and_transport` re-pinned to 24. `cargo test -p xtask`: 319/319.
- **Red-first** (`ci5-red-first.txt`, temporary edits not committed): R1 (shard 23 dropped from the `ci.yml` matrix), R2 (`ci-dispatch.yml` run line `/12`), R3 (`MUTANT_SHARDS` = 12) red at `xtask/src/gates.rs:9956:9`, each naming file and job; R4 (the merge reads only 12 shards) red at `xtask/src/gates.rs:11039:9`.
- **Partition** (`ci5-shard-partition.txt`): `cargo mutants --list` of `secmp-store` with `--shard K/24 --sharding round-robin`, K = 0…23: the 24 lists together are the unsharded list.
- **Ruleset.** No change: the required checks of `main-protection` are job-level names (`docs/06` §4); the new check runs are `mutants-shard (12)` … `mutants-shard (23)`.
- **ci-fast.** `ci-fast-ci5-1-864102a.txt` (code commit), `ci-fast-ci5-2-864102a.txt` (the docs commit; its line 1 names that head; committed in the evidence commit).
- **D-CI8 (not yet proven on CI).** The 24-shard layout has not run on GitHub in this unit; the next PR run shows whether every shard ends under 16800 s. If any shard's step exceeds 14000 s in a later run, N is re-derived (ADR-047 Amendment 11 (4)). **Closed by DOCS2 (PR run 43137870981; §DOCS2).**

## DOCS2 (WEISUNG M7-DOCS2; D-B70, D-CI8, D-CI5 closed from PR-run data; docs only; modell=claude-sonnet-5-5)

- **Commit.** START `ab3280b`; one docs commit (`docs/reviews/M07-report.md` only).
- **D-B70 (closed).** PR run 43083238010 (`9589530`): job `linux-fast` 130740933493 on runner image ubuntu-26.04 (Version 20261101.186.1): `secmp-sys-mem secret_page::tests::guard_pages_and_locking_as_seen_by_the_os` PASS (nextest, 1446 tests); job `linux-full` success (nextest and coverage). PR run 43137870981 (`ab3280b`): `linux-fast` and `linux-full` success again. The old test on that image (run 43033287006, jobs 130565533490 `linux-fast` and 130565533594 `linux-full`) failed at `unix.rs:228:13` with `MemfdSecret: VmFlags " rd wr sh mr mw ms dc dd sd " lacks lo`: on that runner the secret page's VmFlags have no `lo` (a direct runner measurement for ADR-059). Of the measurements of DIAG-M7-memfd-secret-vmflags §7 only these VmFlags exist; `uname -r`, `ulimit -l` and VmLck were not extracted. D-B70 is closed on the test's verdict on the runner, which it left to the next PR run. Open and unchanged: OPEN-M7-B-18 (Q233).
- **D-CI8 (closed).** PR run 43137870981 (`ab3280b`, started 2026-11-12 01:56:04 UTC): completed, conclusion success; all 24 `mutants-shard (k)` jobs success, `mutants` (merge) success 04:54:46 UTC, `ci-verdict` success 05:03:17 UTC. Shard job wall times (job start 01:56:06–08 UTC): shortest shard 5 ended 03:45:29 UTC (about 1 h 49 min), longest shard 16 ended 04:54:12 UTC (about 2 h 58 min, about 10 690 s), below the 14000-s re-derivation trigger of ADR-047 Amendment 11 and below the 16800-s step timeout. These are job wall times (all steps of the job included); the xtask step seconds per shard were not extracted.
- **D-CI5 (Windows proof).** PR run 43033287006 (`88caecb`): job `windows-native` 130565533690 success; `open_wrong_passphrase_uniform` PASS, `held_profile_lock_refuses_reads_on_windows` PASS, 0 lines `code: 33`, 1444/1444 tests; `windows-native` success again in runs 43083238010 and 43137870981.
- **CI infrastructure (no change).** Run 43083238010: job `ct` (130740933385) failed only at the artifact upload (`Failed to CreateArtifact … not valid JSON` after 5 attempts) while the ct step itself reported `step: PASS`; in run 43137870981 `ct` success. Run 43083238010: `xwin-cross` success after the apt DNS failure of run 43033287006 (job 130565533165, `Temporary failure resolving`).
- **First all-green PR run.** Run 43137870981 is the first PR run with every job green after run 42873145127 (`8f4bcbd`); the runs in between, 43033287006 and 43083238010, were red. Its head `ab3280b` covers B-4f/B-4f2/B-4f3, DOCS1b, CI4, REF-M7-store3, VEC1, ADV1, MEM1, CI5.
- **Gates.** `cargo test --locked -p xtask` 319/319; `cargo xtask step --strict policy` PASS. No CHANGELOG line (docs-only units add none: DOCS1b, the CI3 and CI4 rows).

## B16 (WEISUNG M7-B16; Q235, ADR-053 Amendment 4; modell=claude-sonnet-5-5)

- **Commits.** START = the REF-M7-store4 head `ba61e4b` (`ref/` and `vectors/SCHEMA-4.12-store.md`); C1 `3391ee0` (code, `vectors/ref/store.json` copied from the ref session's file, `vectors/store.json` re-frozen, red-first evidence); this docs commit. The ci-fast evidence on this docs commit follows in its own commit (CI5 precedent `ab3280b`).
- **Rule.** A backup body is accepted only if every message has `ts + 1000 · expire_after ≤ 2^63 − 1` over the integers; otherwise `decode` returns the uniform `Error::Unlock` and nothing is imported (ADR-053 Amendment 4).
- **Authority for the re-freeze.** Q235 / OPEN-M7-B-16 option A / ADR-053 Amendment 4 / SCHEMA rev 9; approved by the owner in chat, 2026-11-12 ≈ 11:30 UTC ("ja"); cases 1–26 and the header byte-identical.
- **Red-first.** `docs/reviews/M07-evidence/b16-red-first.txt`: `decode_refuses_unrepresentable_message_time` panics at `backup.rs:2047:13` (`left: None`, `right: Some(Unlock)`); `import_refuses_unrepresentable_message_time` at `backup.rs:2084:13` (`left: Err(Unavailable)`, `right: Err(Unlock)`); `wrapping_and_header_kat` ends with `Error: "a reject case failed with another error"`; ref/: `secmp_ref.cases.TableMismatch: a reject case was accepted`, `1 error in 2.56s`.
- **Tests.** Red run (2.2): 3 failed. Green run (4.1): 4 passed. `cargo nextest run --locked -p secmp-store --features kat` (4.2): 101 passed. `cargo test --locked -p xtask -- vectors::` (3.3): 9 passed. `backup::tests::wrapping_and_header_kat` run alone: 1 passed, finished in 6.85 s.
- **Vectors.** `store: agrees with ref; frozen as vectors/store.json`; twelve lines `agrees with ref; frozen file unchanged`; `vectors: 13 suites identical to vectors/ref (structural, SCHEMA §1; positive rows of encodings)`. `store.json` sha256 `550905ebac732f94ad77df8f1a319d9ef6fbe0ac8810cef11379e4275a0c3187`, 42276 bytes, 28 cases (cases 1–26, header, schema, spec, suite identical to the previous file, checked by comparison). `ref-vectors`: `13 frozen suites (997 cases) structurally and byte-identical to vectors/ref (ADR-026); pending freeze (shape only): none`.
- **Mutants.** `docs/reviews/M07-evidence/mutants-b16-3391ee0.txt` (`--in-diff` on `backup.rs`): found 2, caught 1 (`replace message_time -> Result<()> with Ok(())`), missed 0, unviable 1 (`replace decode -> Result<Contents> with Ok(Default::default())`), timeout 0.
- **ci-fast.** `docs/reviews/M07-evidence/ci-fast-b16-1-3391ee0.txt` (`ci-fast: PASS`, exit 0).
- **Not changed.** `backup.rs` import keeps its `Unavailable` conversions of `ts_ms`/`expire_at` as defence in depth; a decoded body can no longer reach them (Q-B16-5). The live insert path `messages.rs` is unchanged (Q-B16-4).
- **No new deviation.** D-B71 is not used.

## B-4g (WEISUNG M7-B-4g; EXT-M7B-EXT2c; Q236–Q239, ADR-047 Amendment 12; modell=claude-sonnet-5-5)

- **Commits.** START `840e72b`; `8f10096` fix(core) B20 (Q236, with the `mutants-accepted.md` re-pin); `e7a84dc` fix(core) APP2 (Q237); `c94767f` fix(core) B19 (Q238); `c340595` ci(mutants) CI6 (Q239); this docs commit; the ci-fast evidence commit.
- **External review EXT2c.**

```text
| EXT2c | Astra | Internal | Status after B-4g (updated by DOCS3) |
|---|---|---|---|
| EXT2c-1 control row gone in the eviction window; restart loses content | BLOCKER | Major (known, OPEN-M7-B-12) | closed for `KeyChange` — Q240, ADR-060 (1), `4ff264e` (B17a); `RouteUpdate`/`Control` keep the accepted residual of OPEN-M7-B-12; D-B73 closed — `4f0d59f` (B17b-2; Q248–Q251, OPEN-M7-B-24 (A)) |
| EXT2c-2 switch drops settled control content | BLOCKER | Major | closed — Q238, `c94767f`, SE-60/61/62 |
| EXT2c-3 A → B → A registers a physical queue twice | BLOCKER | Blocker | closed — Q236, `8f10096`, SE-54…57, SE-63 |
| EXT2c-4 mutation merge not tied to the inventory | BLOCKER | Major | closed — Q239, ADR-047 Am. 12, `c340595`, G7-22; on CI: PR run 43299417039 (D-CI9 closed, §DOCS3) |
| EXT2c-5 ADR-054 item 5 not implemented | BLOCKER | Blocker | closed — Q237, `e7a84dc`, SE-58/59 |
| EXT2c-6 guard without a bound | MAJOR | Major (known, OPEN-M7-B-17) | closed — `f93ffb8` (B17b-1; Q244–Q246, ADR-060 (4)–(6)): the profile-wide refusal is gone; one chain per contact and the `SuccessionPending` warning; no automatic bound (owner decision 2026-11-13, ADR-060 (7)); the durable marker of D-B73 is OPEN-M7-B-24 |
| EXT2c-7 first-plan failure leaves the guard | MAJOR | minor | closed — Q240, ADR-060 (3), `4ff264e` (B17a; OPEN-M7-B-19 closed) |
| EXT2c-8 secretmem branch not asserted | MINOR | minor | open — OPEN-M7-B-20, with the OPEN-M7-B-18 unit; not merge-blocking |
```

  Adjudication: `EXT-M7B-EXT2c-adjudication` (reviewer, 2026-11-12), overall BLOCK at `ab3280b`; this unit closes EXT2c-2, -3, -4, -5.
- **Red-first.** Evidence files in `docs/reviews/M07-evidence/`:
  - `b4g-red-b20.txt`: edit `sed -i '336s#if self.send_targets#if false && self.send_targets#' hub.rs`; `2 passed; 3 failed`; `hub.rs:1474:13` `AddSend per register_route` left `[1, 1, 1]` right `[1, 1, 0]`; `hub.rs:1495:13` left `(1, 1)` right `(1, 0)`; `hub.rs:1582:13` `after a restart` left sixteen 9s, right sixteen 4s.
  - `b4g-red-app2.txt`: edit `contacts.rs:103` `c.display_name.as_deref().map(shown_name)` → `c.display_name.clone()`; `1 passed; 1 failed`; `hub.rs:1550:13` left `[Some("A\u{85}B\n")]` right `[Some("")]`.
  - `b4g-red-b19.txt`: edit `actor.rs:929` `(r, !e.done || stranded.contains(&r))` → `(r, !e.done)`; `3 passed; 2 failed`; `actor.rs:2859:9` `Q238: settled control content stranded on the old queue is planned again`; `tests.rs:2319:9` `Q225: the row is written again before a cell of the new attempt is sealed` left `0` right `1`.
  - `b4g-red-ci6.txt`: three edits in `gates.rs` (2182, 2190, 2209); `6 passed; 4 failed`; `gates.rs:11313:9` (left `[]`, right the 23 empty-shard lines), `11337:9` (left `[]`), `11375:9` (left `[]`), `11424:9`.
  - Green: B20 `5 passed`, `hub::` `12 passed`, APP2 `2 passed`, B19 `5 passed`, CI6 `10 passed`.
- **Tests.** `secmp-client-core` lib `--test-threads=1`: `227 passed; 0 failed`. nextest of `secmp-client-core`: `227 tests run: 227 passed, 0 skipped`. `cargo test -p xtask`: `324 passed; 0 failed`. `cargo fmt --all -- --check`: no output. clippy: part of `ci-fast` (gate 2, PASS).
- **List names.** `b4g-list-names.txt`: `listed 2, tested 2, total_mutants 2` / `names equal` (backup.rs `--in-diff` against the B16 outcomes); `listed 969` (`secmp-store`, whole package).
- **Mutants.** `--in-diff` run, `docs/reviews/M07-evidence/mutants-b4g-c340595.txt`: 11 found; 10 caught; 0 missed; 1 unviable (`contact_of` → `Ok(Default::default())`); 0 timeout. No `docs/mutants-accepted.md` row added.
- **ci-fast.** `ci-fast-b4g-1-c340595.txt` (`ci-fast: PASS`).
- **D-B71 (B20, closed in C1).** The receive commit stores the routes of every `RouteUpdate`, including a stale one that Q236 does not register. The hub's skip branch writes the contact's current route back, so a restart registers the current queue (SE-63). A crash between the receive commit and that write leaves the stale route stored (a narrow window, OPEN-M7-B-12). A failed write-back fails the pump with `Unavailable`, as a failed store read there already does; the live registration is unchanged.
- **D-B72 (B19 residual, recorded).** A settled `Control` (codes 1, 2) that is re-sent on the new queue can reach the peer twice if the peer also fetches the old copy. The peer then raises `ContactRemoved` or `ResetRequested` twice. As with the re-plan of unsettled content under Q222, `Control` has no `msg_id` to deduplicate. `KeyChange` (ADR-058) and `RouteUpdate` (Q222, Q236) repeats are no-ops. A stranded `KeyChange` copy on the old queue is not covered by the guard once the re-planned attempt leaves the new queue's window; a later rotation can reach the peer before that copy (freeze, fail closed). B17's truthful guard must also cover the old queue until it leaves overlap (OPEN-M7-B-17).
- **D-CI9 (not yet proven on CI).** Amendment 12 has not run on GitHub in this unit. The next PR run shows all 24 shards recording an inventory and the merge passing on it. **Closed by DOCS3 (PR run 43299417039; §DOCS3).**

## B17a (WEISUNG M7-B17a; EXT2c-1, EXT2c-7, D-B72; Q240, Q241, ADR-060; modell=claude-sonnet-5-5)

- **Commits.** START `d0ea52d`; `4ff264e` fix(core) B17a; this docs commit; the ci-fast evidence commit.
- **Red-first.** The four edits of WEISUNG 1.3, evidence in `docs/reviews/M07-evidence/b17a-red-a.txt` … `b17a-red-d.txt`. (a) row hold off (`actor.rs:753`): 10 passed; 7 failed, `left: 0`, `right: 1` at `api.rs:1916:13` (`restart_in_the_window_keeps_the_rotation_guard`), `tests.rs:3224:9`, `2651:9`, `2380:9`, `2550:9`, `2317:9`, `2483:9`. (b) plan-failure keep off (`actor.rs:597`): 16 passed; 1 failed, `failed_first_plan_keeps_the_key_change_guarded` at `tests.rs:2439:9`. (c) stranded marks off (`actor.rs:1025`): 10 passed; 7 failed at `tests.rs:2645:9`, `2694:9`, `3156:9`, `2595:9`, `2549:9`, `2748:9`, `3100:9`. (d) marks of unknown outcome off (`actor.rs:1072`): 16 passed; 1 failed, `unknown_send_at_the_switch_is_held` at `tests.rs:2880:5`. Green: 17 passed; 0 failed.
- **Tests.** `secmp-client-core` lib (`--test-threads=1`, `--features kat`): 240 passed; 0 failed. nextest of `secmp-client-core`: 240 run, 240 passed. `cargo fmt --all -- --check`: no output. clippy (`-D warnings`, all targets): exit 0.
- **Mutants.** `--in-diff` run on `crates/secmp-client-core/src/sessions/actor.rs`: found 64 / caught 60 / missed 0 / unviable 4 / timeout 0 (unviable: `&&` -> `||` at `actor.rs:620:13`, `1025:13`, `1071:13`, `1072:13`). Evidence `mutants-b17a-4ff264e.txt`.
- **ci-fast.** `ci-fast-b17a-1-4ff264e.txt` (`ci-fast: PASS`).
- **EXT2c status.** EXT2c-1: closed for `KeyChange` (Q240); `RouteUpdate`/`Control` keep the accepted residual of OPEN-M7-B-12. EXT2c-7: closed (Q240, OPEN-M7-B-19). EXT2c-6: open, B17b (OPEN-M7-B-17, option (C)).
- **D-B73 (B17a residual, recorded).** The marks of Q241 (also those of a `SEND` without an answer) are in memory and the send overlap is not durable: after a restart the old send queue is no longer sent to, so a `KeyChange` copy stranded there is not tracked. The re-read row sends the `KeyChange` once more on the current queue and the guard holds until that copy leaves its window. A freeze needs, in addition, that the peer fetches the current queue but not the old one for at least that window and that a second rotation follows. B17b's durable marker closes it (OPEN-M7-B-17).
- **D-B74 (B17a residual, recorded; fail closed).** A mark of Q241 (a stranded copy, or a copy of unknown outcome) whose old queue ends its send overlap (U[1 h, 24 h]) before an `OK_SEND` there reaches the mark's id + `QUEUE_CAPACITY` stays until the process restarts: the old queue carries one dummy per `P_q`, so the count needs 128 · `P_q` (up to 171 min at 80 s) of sending, and a suspended or offline client sends nothing. Until then `RotateIdentity` answers `Unavailable` for every contact (profile-wide until B17b). The only way out is a restart, which drops the mark (D-B73). B17b confines the refusal to the contact and makes the mark durable. One fail-closed path remains open: a `SEND` still in flight on a dropped Tor circuit may reach an honest relay after a later link's `SEND` (circuits are not ordered against each other), so the unknown cell may be stored above the id it took and its mark may go early; the result is a freeze, never an accepted identity, and a margin of the link's in-flight depth on that id is a B17b item.
- **Property (no number).** The window exit proves delivery only against an honest relay: a relay that keeps a cell beyond `QUEUE_CAPACITY` without reporting its eviction can make a peer receive a later succession first. The result is a freeze (fail closed), never an accepted identity; the relay can deny service anyway (docs/01).
- **Known (unchanged).** `rotate_identity` keeps `?` on `queue_pending`: only an encode error of the body stops it (`api.rs`, code comment); the rows are committed and the next open plans them.
- **Recorded.** OPEN-M7-B-21 (VERIFY-DELTA-B4g D-04, record only) and OPEN-M7-B-22 (a new route before a stale one in one pump; its own hub unit).

## B22 (WEISUNG M7-B22; OPEN-M7-B-22; Q242; modell=claude-sonnet-5-5)

- **Commits.** START `a1de559`; `86c292f` fix(core) B22; this docs commit; the ci-fast evidence commit.
- **Red-first.** The two edits of WEISUNG 1.3, evidence in `docs/reviews/M07-evidence/b22-red-a.txt` and `b22-red-b.txt`. (a) register from the last stored body (`hub.rs:576`): 5 passed; 3 failed: `hub.rs:1734:13` `Q242: C once, A nothing`, `left: []`, `right: [[7×16]]`; `hub.rs:1783:13` `Q242: C, then D`, `left: []`, `right: [[7×16], [5×16]]`; `hub.rs:1848:13` `Q242: after a restart`, `left: [[[4×16]], [[7×16]]]`, `right: [[[7×16]], [[7×16]]]`. (b) no write-back after the routes (`hub.rs:580`): 6 passed; 2 failed: `hub.rs:1848:13` `Q242: after a restart`, `left: [[[7×16]], [[4×16]]]`, `right: [[[7×16]], [[7×16]]]`; `hub.rs:1761:13` `Q242: the store ends on C`, `left: Some([4×16])`, `right: Some([7×16])`. Green: 8 passed; 0 failed.
- **Tests.** `secmp-client-core` lib (`--test-threads=1`, `--features kat`): 248 passed; 0 failed. nextest of `secmp-client-core`: 248 run, 248 passed. `cargo fmt --all -- --check`: no output. clippy (`-D warnings`, all targets): exit 0.
- **Mutants.** `--in-diff` run on `hub.rs` and `persist.rs`: found 16 / caught 11 / missed 0 / unviable 5 / timeout 0 (unviable: `persist.rs:91:9` `StorePersist::open` -> `Ok(Default::default())`; four replacements of `persist.rs:113:9` `take_routes`). Evidence `mutants-b22-86c292f.txt`.
- **ci-fast.** `ci-fast-b22-1-86c292f.txt` (`ci-fast: PASS`). One docs line (the Q242 row) was appended to `OPEN-M7-decided.md` in the working tree while that run was in progress; no code or gate input changed.
- **Source of the routes.** `Core::pump` (`api.rs`) consumes each `SessionEvent::Routes` and keeps only the contact, and `Core::handle` runs it after every request, so the payload never reaches the hub. The hub therefore takes the same bytes from the receive commit (`StorePersist`, `persist.rs`): one entry per committed `RouteUpdate`, pushed only after its transaction succeeded, in commit order. They equal the event payload (both are the relay-queue routes of the delivery).
- **D-B75 (B22 residual, recorded; availability only).** The receive commit writes each `RouteUpdate`'s routes to the store before the hub decides on them. If the process stops between the receive commits of a new route C and a stale A and the next pump, the store holds A, and the restart registers A (or, when another contact registered A's physical queue first, nothing). The contact then sends to an old queue until the peer's next `RouteUpdate`. The same window keeps OPEN-M7-B-21's restart effect. Closing it needs the decision inside the receive commit (`sessions/actor.rs`), not in this unit. The same holds when the write-back after the routes fails: the pump returns the error after the `AddSend`, the list is already taken, and the store keeps the last committed route until the next `RouteUpdate`.
- **Known (unchanged).** `Core::routes_changed` (`api.rs`) is still filled and is now only cleared by the hub; its doc comment is left for the next unit that edits `api.rs`. The in-memory route list of a session grows only by committed `RouteUpdate`s and is emptied at every `Hub::pump`, like `routes_changed`.
- **Recorded.** OPEN-M7-B-22 closed; OPEN-M7-B-21 stays (A), with option (C) and the reasons it is not built here.
- **First attempt.** The first run of WEISUNG M7-B22 stopped at guard 0.4 before any change: the guard expected no `hub.rs` row in `docs/mutants-accepted.md`, but the row of the equivalent mutant in `Hub::deliver_invitation` exists (directive error). WEISUNG M7-B22b corrected the guard; the row follows the code from `hub.rs:519:30` to `hub.rs:525:30` in the code commit, and `cargo xtask step --strict policy` passes.

## CI7 (WEISUNG M7-CI7; Q243; modell=claude-sonnet-5-5)

- **Commits.** START `85a589a`; `919da9e` test(testkit) CI7; this docs commit; the ci-fast evidence commit. Changed: `crates/secmp-testkit/tests/harness/m0_early.rs` (68 lines appended, no line above them moves) and `docs/` only.
- **Cause.** Mutant M = `crates/secmp-client-core/src/scheduler/core/mod.rs:860:30: replace match guard now >= up.die_at with false in World::step_due`. Under M no link dies of its lifetime and `Scheduler::next_deadline` stays at the passed `die_at`. The only per-mutant tests that run past a lifetime spin at that instant: `m6_props::prop_at_most_once_per_period` and `m6_reconnect::rotation_and_reconnect_keep_send_spacing` until the virtual driver's 50 000 000-pass guard (`crates/secmp-testkit/src/harness/driver.rs:765:13`, `the virtual run does not make progress`, 110–117 s each on the planner's 2-core container), `m7_links::logical_link_id_in_events` (tokio driver, paused clock) for ever. The kill time is a function of the runner's speed: 690 s in PR run 43299417039, TIMEOUT at 901 s in PR run 43385042727 (DIAG-M7-mutant-timeout-step_due).
- **Fix (Q243).** Two killers appended to `m0_early`, each polling `m6_sched_io::Rig` by hand at fixed times: `link_is_torn_down_at_the_end_of_its_lifetime` (a Strict send link living exactly 30 s is torn down with `Reason::Lifetime` at `t_up + 30 s`) for M, and `next_deadline_moves_past_the_lead_once_it_is_reached` (after a wake at the `FETCH` lead the next deadline is the tick, Strict and Balanced) for the sibling S = `crates/secmp-client-core/src/scheduler/core/mod.rs:1907:33: replace > with >= in Scheduler::next_deadline`, which spins the same way (no failure within 120 s in gate order on the planner's container). No product code, no xtask, no nextest profile, no skip list, no timeout, no `docs/mutants-accepted.md` row.
- **Red-first.** `docs/reviews/M07-evidence/ci7-red.txt`: M applied by hand at `core/mod.rs:860`; `link_is_torn_down_at_the_end_of_its_lifetime` FAIL at `m0_early.rs:160:5`, `torn down at its end: []`; `next_deadline_moves_past_the_lead_once_it_is_reached` PASS. `docs/reviews/M07-evidence/ci7-red-b.txt`: S applied by hand at `core/mod.rs:1907`; `next_deadline_moves_past_the_lead_once_it_is_reached` FAIL at `m0_early.rs:188:9`, `Strict: the tick after the lead`, `left: Some(9000)`, `right: Some(10000)`; `link_is_torn_down_at_the_end_of_its_lifetime` PASS. Both edits reverted with `git checkout`; green: `m0_early` 9 passed, 0 failed.
- **Mutants.** Targeted run of M and S with the gate's test tool, timeout and nextest options (`--test-tool nextest --timeout 900`, `--max-fail=1:immediate --profile mutants-harness`), without the gate's `--skip` list, `-j 3` and exclusions, and with `-j 1 --baseline skip`, `docs/reviews/M07-evidence/mutants-ci7-919da9e.txt`: `Found 2 mutants to test`; `caught   crates/secmp-client-core/src/scheduler/core/mod.rs:860:30: replace match guard now >= up.die_at with false in World::step_due in 116s build + 0s test`; `caught   crates/secmp-client-core/src/scheduler/core/mod.rs:1907:33: replace > with >= in Scheduler::next_deadline in 4s build + 0s test`; `2 mutants tested in 10m: 2 caught`.
- **Siblings (planner's measurement, NOTES-CI7-planner).** Killed by an `m0_early` test within 1.1 s: `core/mod.rs:860:30` guard → `true`, `860:34` `>=` → `<`, `859:39` `<=` → `>`, `1895:9` `next_deadline` → `None` / `Some(0)` / `Some(1)`, `1907:33` `>` → `==` / `<`. Unviable: `1903:25` `&&` → `||` (`||` in a let chain does not compile). `859:35` guard → `true` is not killed by `m0_early` but by an assertion, `two_clients::tests::control_slots_are_exactly_the_pool_connections` at `two_clients/mod.rs:199:9`, after 101.6 s in gate order (test 290 of 600): not a guard kill, no killer.
- **ci-fast.** `ci-fast-ci7-1-919da9e.txt` (test commit): `5 harness         PASS       1046s  secmp-testkit harness binary; property tests with their DEFAULT_SEED only (SECMP_PROPTEST_SEED removed, no CI run seed outside GitHub Actions)`; `ci-fast: PASS`. `ci-fast-ci7-2-919da9e.txt` (this docs commit; its line 1 names that head; committed in the evidence commit).
- **D-CI10 (not yet proven on CI).** PR run 43385042727 (`a1de559`) was red at `mutants-shard (14)` only through M's TIMEOUT (901 s; 690 s in PR run 43299417039): a kill through the virtual driver's 50 000 000-pass guard, whose time depends on the host. Fix: the two `m0_early` killers (Q243). Proof here: red-first and the targeted mutant run. The next PR run shows M and S caught within seconds of test time (their outcome lines in the harness log of their shards). **Closed by DOCS4 (PR run 43474391164; §DOCS4).**
- **Open (reviewer).** Other mutants caught only after a long test time are not known from the repository. The query: in the harness logs of the last PR runs, every `caught in … s build + Y s test` with Y > 450 and every `TIMEOUT`. **Answered by DOCS3 for test times ≥ 500 s, as counts (PR runs 43299417039, 43385042727, 43417767896; OPEN-M7-B-23; §DOCS3).**

## DOCS3 (WEISUNG M7-DOCS3; D-CI9 closed, PR-run rows, OPEN-M7-B-23, EXT2c status; docs only; modell=claude-sonnet-5-5)

- **Commit.** START `23b7424`; one docs commit (`docs/reviews/M07-report.md`, `docs/reviews/M07-planning/OPEN-M7.md`). The PR-run facts are from the runs' GitHub job logs (reviewer's queries), as in §DOCS2.
- **D-CI9 (closed).** PR run 43299417039 (`d0ea52d`, B-4g), the first PR run with ADR-047 Amendment 12: completed, conclusion success, `ci-verdict` 2026-11-12 23:38:18 UTC, all 36 jobs green; the `mutants` merge job, which checks the shards against the inventory, ran 23:33:54–23:34:35 UTC and was green. The merge passes only if each of the 24 shards has a `PASS` verdict, a non-empty outcome list and a recorded inventory, all inventories are identical, and the outcomes of all shards are that inventory with each mutant once (`merge_mutant_shards`, `inventory_failures`, `xtask/src/gates.rs`). In PR run 43385042727 (`a1de559`) the merge log lists all 24 shards with their mutant counts and `mutants survivors documented in docs/mutants-accepted.md: 20, undocumented: 1`; shard 14 had failed (M's TIMEOUT), so there the inventory comparison was not reached, since it runs only when no shard failed. EXT2c-4 (Q239) is now proven on CI as well (§B-4g table).
- **Gate table (VERIFY-DELTA-CI7 D-01).** Rows for PR runs 43299417039 (`d0ea52d`) and 43417767896 (`85a589a`) added in §4. Run 43417767896 (created 2026-11-13 11:31:38 UTC, conclusion success) ran on a head without the CI7 killers (`919da9e`): M = `core/mod.rs:860:30 … World::step_due` was caught after 38 s build + 682 s test (shard 2), S = `core/mod.rs:1907:33 … Scheduler::next_deadline` after 54 s build + 611 s test (shard 5); in run 43299417039 after 41 s + 690 s (shard 14) and 34 s + 863 s (shard 17). D-CI10 stays open until a PR run on a head that contains `919da9e`.
- **Long test times (the open item of §CI7; log queries LOG11/LOG12, 2026-11-13).** Apart from M and S, no mutant result reached 700 s of test time in runs 43299417039 and 43417767896. Apart from M and S, the results with a long test time are overwhelmingly `secmp-transport` mutants at about 535–600 s: run 43299417039 46 results ≥ 500 s, 3 ≥ 600 s; run 43385042727 87 ≥ 500 s, 19 ≥ 600 s, 1 ≥ 700 s (the TIMEOUT of M); run 43417767896 54 ≥ 500 s, 29 ≥ 600 s, 0 ≥ 700 s (all results, caught and missed, M and S included). The probable cause, not yet measured, is that the transport tests start late in the order of the harness run (`[profile.mutants-harness]` of `.config/nextest.toml` moves only `m0_early` to the front). Recorded as OPEN-M7-B-23 (reviewer, engineering): measure first; the fix is chosen on the measurement (one candidate: order the harness run so that a transport mutant meets the transport tests first); a change of the gate configuration needs an ADR-047 amendment. No change in this unit.
- **EXT2c status (§B-4g table).** EXT2c-2, -3, -5 closed by B-4g; EXT2c-4 closed by B-4g and proven on CI (D-CI9). EXT2c-1 closed for `KeyChange` and EXT2c-7 closed by B17a (Q240, ADR-060 (1), (3)); `RouteUpdate`/`Control` keep the accepted residual of OPEN-M7-B-12, and D-B73 is left to B17b. EXT2c-6 open until B17b (OPEN-M7-B-17, option (C)). EXT2c-8 open (OPEN-M7-B-20, not merge-blocking). Statuses as §B17a and ADR-060 state them.
- **Owner decision (2026-11-13, in chat).** The owner declined Astra's proposal for the `KeyChange` guard (24 h / 3 attempts, then re-invitation, plus an emergency override; ADR-060 alternative (e)). OPEN-M7-B-17 stays on option (C): a truthful guard and one ordered succession chain per contact, a per-contact warning event after T (default 24 h) or with two or more pending successions, no automatic bound (ADR-060 (6), (7)). Recorded in the OPEN-M7-B-17 row; no Q number.
- **Wording.** §B16 "Authority for the re-freeze": the doubled phrase about the owner's approval now reads "approved by the owner in chat" (same meaning, as in the Q235 row).
- **Gates.** `cargo nextest run -p xtask`: 324 passed; `cargo xtask step --strict policy` PASS. No ci-fast and no CHANGELOG line (DOCS2 precedent: a commit under `docs/reviews/` only).

## B17b-1 (WEISUNG M7-B17b; EXT2c-6, OPEN-M7-B-17; Q244–Q246, ADR-060 (4)–(6); modell=claude-sonnet-5-5)

- **Commits.** START `64650f6`; `f93ffb8` fix(core) B17b-1; this docs commit; the ci-fast evidence commit. Changed code: `crates/secmp-client-core/src/api.rs`, `hub.rs` (one test), `sessions/actor.rs`, `sessions/tests.rs`.
- **Split.** B17b is built in two units. B17b-1 (this one): the chain per contact, the profile-wide refusal removed, the warning. B17b-2 (OPEN-M7-B-24): the durable marker that closes D-B73, and the in-flight margin. The chain comes first because a durable mark on a queue that is no longer sent to never resolves; under the profile-wide refusal it would block every later rotation of the profile.
- **Red-first.** Eight edits of WEISUNG 2, evidence in `docs/reviews/M07-evidence/b17b-red-a.txt` … `b17b-red-h.txt`, each against the eight tests SE-34, SE-69, SE-85…SE-90. (a) every `KeyChange` plannable (`actor.rs:212`): 5 passed, 3 failed: `tests.rs:3457:9` `Q244: KC2 waits while KC1 is in its window` (`left: (1, false)`, `right: (0, false)`), `tests.rs:3505:9` `Q244: only the head is planned again` (`(2, false)` / `(1, false)`), `tests.rs:3540:9` `KC1 first, then dummies` (`(2, false)` / `(1, false)`). (b) no chain check in `replan_control` (`actor.rs:719`): 7 passed, 1 failed: `tests.rs:3505:9`. (c) the warning not once (`actor.rs:824`): 7 passed, 1 failed: `tests.rs:3601:9` `once` (`left: 1`, `right: 0`). (d) two pending no longer warn (`actor.rs:824`, `>= 3`): 6 passed, 2 failed: `api.rs:2009:13` (`left: []`, `right: [ContactId(1)]`), `tests.rs:3627:9` `two pending: at the first preparation` (`left: 0`, `right: 1`). (e) the profile-wide refusal put back (`api.rs:919`): 1 passed, 7 failed, each `Error: "unavailable"`. (f) a B17a mark filed under the new queue instead of the old one (`actor.rs:1052`): 7 passed, 1 failed: `hub.rs:1969:13` `B's 132 alone releases: nothing on C`. (g) `by_cell` kept at a switch (`actor.rs:1079`; the behaviour B22-delta D-03 supposed: B's cells marked again on C at the C → D switch): 7 passed, 1 failed: `hub.rs:1969:13`, the same message. (h) every control content counted as a succession (`actor.rs:594`): 7 passed, 1 failed: `tests.rs:3613:9` `a Control is no succession`. Green: 8 passed.
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 254 run, 254 passed (248 before; six new: SE-85…SE-90; SE-34 and SE-69 re-dictated and renamed). `cargo fmt --all -- --check`: no output. clippy (`-D warnings`, all targets, all features): exit 0.
- **Mutants.** `--in-diff` run on `sessions/actor.rs` and `api.rs`, evidence `mutants-b17b-f93ffb8.txt`: 33 mutants tested in 22m: 31 caught, 2 unviable
- **Design.** `plannable` (`sessions/actor.rs`): a durable `KeyChange` with an older durable `KeyChange` entry in its conversation is not planned; `add_control`, `replan_control` (switch, loss, eviction, failed `SEND`) and the unplanned loop of `settle_controls` ask it; that loop now runs after the drop, so the next link is planned in the preparation that drops the head. `rotate_identity` (`api.rs`) no longer scans the conversations. `note_succession` in `prepare` raises `SessionEvent::SuccessionPending`, which `Core::pump` turns into `Event::SuccessionPending(contact)`. `queue_key_change` is test kit only (Q245).
- **D-B76 (B17b-1, recorded; fail closed).** D-B73 and D-B74 are unchanged in kind but confined to one contact: a mark that outlives its old queue's overlap holds that contact's chain until a restart (later successions towards it wait, `SuccessionPending` warns); the profile and every other contact rotate. A restart drops the mark (D-B73); B17b-2 makes it durable (OPEN-M7-B-24).
- **D-B77 (B17b-1, recorded).** The 24-h count of `SuccessionPending` starts again with the process: a client that restarts more often than every 24 h warns only for two pending successions. A durable start time needs a time in a row (a new row kind or a tag-3 layout change); not built.
- **D-B78 (B22-delta D-03, not confirmed).** Two switches in one pump (routes C and D before any cell on C) leave the mark of a `KeyChange` copy on the queue it was sent on (B), not on C: `switch_send_queue` empties `by_cell` at every switch, so the C → D switch finds no cell to mark. SE-90 pins it: B's id 132 alone releases the `KeyChange`, with no `OK_SEND` on C; red-first (g) keeps `by_cell` at a switch (the supposed behaviour) and SE-90 fails.
- **D-B79 (B17b-1, recorded; fail closed).** The row seal's AD (session, part, ord; ADR-053 item 5) carries no freshness, and the store reuses `ord`s (`insert_pending_control` takes `MAX(ord) + 1`, so an emptied CONTROL part starts at 0 again). A same-user adversary (ADV-M, docs/01 §3.6) who can write the store file can replay old sealed `PendingControl` rows and so make the sender plan a stale, genuine `KeyChange`. The peer rejects it (it accepts only a `KeyChange` signed under its current `IK_sig` or the authenticated repeat of ADR-058): a freeze at that peer, never an accepted identity. Rollback or replay protection is not a property the store claims: docs/01 §5 names SQLCipher's HMAC against tampering of the store file, which authenticates a page but carries no freshness, and docs/04 CS-3.5 keeps ratchet states out of backups because restoring them would roll a ratchet back; neither says that an older copy of the store or of a row is detected. Not addressed in B17b.
- **Recorded.** OPEN-M7-B-17 closed (C) for the profile-wide refusal; EXT2c-6 closed: the profile-wide refusal is gone, each contact has its own chain and the `SuccessionPending` warning, and there is no automatic bound (owner decision 2026-11-13, ADR-060 (7)). D-B73 and the in-flight margin (ADR-060 Consequences; B17a-delta D-03) stay open as OPEN-M7-B-24 (B17b-2); B17b-2 also adds the missing test that an `unknown` mark (Q241) on the head keeps its row (no test fails today if `held` ignores `unknown` marks; hand mutant H7 of the B17b verification). D-B74: behaviour as D-B76. ADR-060 (4)–(6) confirmed, (5) amended (no signature-link check), in its confirmation paragraph.

## WIN1 (WEISUNG M7-WIN1; D-CI11, Q247, ADR-061; modell=claude-sonnet-5-5)

- **Commits.** START `d5dfdc7`; `8e35c4f` fix(sys-mem) WIN1; this docs commit; the ci-fast evidence commit. Changed code: `crates/secmp-sys-mem/src/secret_page.rs` (`mod grow`, the Windows row of the module table), `crates/secmp-sys-mem/src/secret_page/grow.rs` (new), `crates/secmp-sys-mem/src/secret_page/windows.rs`.
- **Cause (D-CI11).** PR run 43539306737 on `d5dfdc7` was red only at `windows-native` (§4). Diagnosis DIAG-M7-windows-virtuallock-b17b, verdict (B): a latent limit of the Windows backend, not introduced by B17b-1 (the red and the green tree lock the same amounts and make the same three successful rotations; the failing call is the profile creation at a world's start). `lock` raised the working set once by 64 pages, with an unserialised read and set of the sizes, and retried `VirtualLock` once; SQLCipher (`cipher_memory_security = ON`, process-wide) locks every SQLite allocation from the same quota and only warns, so another thread could take the new pages before the retry.
- **Fix (Q247, ADR-061).** `grow::lock_with_growth`: lock; while the quota error persists, read the sizes, raise minimum and maximum by the next step (64 pages first, doubling, at most 8 steps, the minimum never above 256 MiB) and lock again; every other way out is `Error`. The Windows backend supplies the three calls as closures and runs the policy under the process-wide mutex `GROW`. Public API, dependencies, `windows-sys` features, store pragmas, docs/04 and the skip lists unchanged.
- **`unsafe`.** Lock path: six blocks before, five after (`GetCurrentProcess`, `VirtualLock`, `GetLastError`, `GetProcessWorkingSetSize`, `SetProcessWorkingSetSize`; each with `// SAFETY:`); `grow.rs` has none; one test-only block (`VirtualUnlock` as lock evidence in a `cfg(windows)` test).
- **Red-first.** Eight edits of `grow.rs`, evidence `docs/reviews/M07-evidence/win1-red-a.txt` … `win1-red-h.txt`, each against the ten policy tests. (a) one step and one retry, the behaviour before this unit (`0..1`): 4 passed, 6 failed, among them `grows_again_when_the_grown_quota_is_taken` (`left: Err(Error(()))`, `right: Ok(())`). (b) the sizes read once and then remembered: 5 passed, 5 failed, among them `re_reads_the_sizes_when_a_step_was_undone`. (c) no cap: 9 passed, 1 failed, `fails_at_the_cap_and_never_locks_beyond_it` (`left: Ok(())`). (d) a failing set ignored: 9 passed, 1 failed, `fails_closed_when_the_quota_cannot_be_set` (`left: Ok(())`). (e) any lock error treated as the quota error: 9 passed, 1 failed, `other_lock_errors_fail_without_growth` (`left: Ok(())`). (f) the step doubled with saturation: 9 passed, 1 failed, `steps_double_and_overflow_fails` (`step overflow`, `left: Ok(())`). (g) no first lock before a step: 1 passed, 9 failed, among them `first_lock_success_touches_no_sizes` (`right: [Lock]`). (h) one step more than the bound (`0..=`): 9 passed, 1 failed, `stops_after_the_last_step` (`left: 10`, `right: 9`). Green: 10 passed.
- **Tests.** `cargo nextest run -p secmp-sys-mem`: 19 passed (9 before). Verifier (round 1): Miri (`nightly-2026-09-21`, `aarch64-unknown-linux-gnu`, the gate's form) 18 passed (the OS test is not compiled under Miri). The two `cfg(windows)` tests (`concurrent_locks_beyond_the_default_quota_all_succeed`, `every_lock_waits_for_the_growth_lock`) were type-checked and linted for `x86_64-pc-windows-msvc` (`docs/reviews/M07-evidence/win1-windows-clippy.txt`, exit 0) but run only in `windows-native`. `concurrent_locks_beyond_the_default_quota_all_succeed` is a behaviour test (growth beyond the default quota, every page locked and released) that probably also passes on the base `d5dfdc7`; the race itself is pinned by the platform-independent policy test `grows_again_when_the_grown_quota_is_taken` (red a).
- **Mutants.** `secmp-sys-mem` is not under the mutation gate (`expect::MUTANT_PACKAGES`). Targeted run on `grow.rs` with the gate's test tool and timeout, `docs/reviews/M07-evidence/mutants-win1-8e35c4f.txt`: 7 mutants tested in 16m: 6 caught, 1 unviable (unviable: `Growth::working_set` → `Ok(Default::default())`). The five mutants of the diff in `windows.rs` are `cfg(windows)` and cannot be built or tested on Linux; `lock` → `Ok(())` would be killed on Windows by the `VirtualUnlock` evidence of `concurrent_locks_beyond_the_default_quota_all_succeed` (not run here).
- **D-B80 (recorded; owner, OPEN-M7-B-25).** On Windows SQLCipher's own page locking (`cipher_memory_security`, CS-3.1) degrades to a `WARN` beyond the working-set quota and the allocation proceeds unlocked; CS-3.1's memory security is therefore best effort on Windows until the owner decides the budget and `cache_size` question; this unit records that residual and does not accept it. Our secret pages are not affected: a `SecretPage` is locked or its allocation fails. ADR-061's steps enlarge the quota, which SQLCipher then also uses; that is a side effect, not a guarantee. The growth is never returned (no shrink when a `SecretPage` is dropped). **Evidence added by DOCS6 (§DOCS6; SE-130, the `W2DIAG-BENCH` lines of PR run 43728831159, job 132856553210): in a Windows micro-benchmark of the SQLCipher lock, use and unlock pattern (4 rounds of 8192 blocks of 1 KiB, 32 768 `VirtualLock` calls per regime), 700 calls succeeded and 32 068 failed with the working-set quota error under the default working set (`ws_min` 204 800 bytes), and all 32 768 succeeded after 64 MiB more working set (`ws_min` 67 313 664 bytes): under the default working set most locks of this pattern fail with the quota error, and SQLCipher's own locks fail on Windows too (the same job log has 3005 SQLCipher WARN lines `VirtualLock() returned 0 LastError=1453`); how many of SQLCipher's own locks succeed is not measured (L3 of the WIN2-DIAG table). Our own secret pages: `failed=0` in every instrumented test. D-B80 stays recorded as a residual risk and is not accepted; OPEN-M7-B-25 is unchanged.**
- **D-CI11 (open).** PR run 43539306737: red at `windows-native` in SE-19 (`Unavailable` at `m7_world.rs:122`, 2283 `LastError=1453` warnings); cause and fix above. Not proven on Windows that this path produced the `Unavailable` (it also covers a store I/O error). Proof: `windows-native` of the next PR run green, including SE-19 and the two new `cfg(windows)` tests. If SE-19 fails there again with `Unavailable`, the diagnosis's overturning measurement (ii) (which step failed, from a scratch print on Windows) comes next. **Closed by DOCS4 (PR run 43591576223; §DOCS4).**
- **Open on Windows (not verified, not measured).** (i) Raising the working set may require the `SeIncreaseWorkingSetPrivilege` and may be limited by a job object — unverified, to be checked against the Win32 documentation and on the runner; the code stays bounded and fail closed either way. (ii) The wait for the growth mutex `GROW` under load is unmeasured on Windows, to be measured on `windows-native` (duration of `lock`, wait for the mutex, tick lateness); it is relevant to the constant-rate scheduler only as a late frame preparation.
- **Recorded.** OPEN-M7-B-25 (owner: docs/04 statement and budget for CS-2.2/CS-3.1 on Windows, optional `cache_size`); OPEN-M7-B-26 (DIAG T4 live-page test, the 18 live pages after teardown, the SQLCipher version in CS-3.1). DIAG T4 is not built in this unit.

## B17b-2 (WEISUNG M7-B17b2; OPEN-M7-B-24 (A), D-B73, B17a-delta D-03; Q248–Q251, ADR-060 amendment; modell=claude-sonnet-5-5)

- **Commits.** START `3f564f8`; `4f0d59f` fix(core) B17b-2; this docs commit; the ci-fast evidence commit. Changed code: `crates/secmp-client-core/src/sessions/actor.rs`, `sessions/mod.rs`, `hub.rs`, `sessions/tests.rs`; `docs/mutants-accepted.md` re-pinned in `4f0d59f` (`hub.rs:525:30` → `hub.rs:527:30`: two lines inserted above it, the mutant and its row unchanged).
- **Design.** A `KeyChange` marker is a CONTROL row `4 ‖ ord ‖ sid` (Q248; `marker_row` / `marker_of` in `sessions/actor.rs`), written through `Persist::control_requeued` by `write_markers` in `prepare` before the first cell of a durable `KeyChange` is sealed for the current send queue (`unmarked` holds the cell meanwhile), deleted through `control_relayed` in `settle_controls`: an old queue's marker once no mark is on that queue and no cell of the `KeyChange` is on its way to it (`Sent` now records its queue); all markers before the row at the release. The hub calls `Conversation::set_send_sid` in `register_route` before `set_send_queue` / `switch_send_queue`. The open (`sessions/mod.rs`) hands a marker row to `restore_marker`; at the first `set_send_sid` of the process a marker of that `sid` is taken over by the registered queue with a mark of unknown outcome (token 0), every other one holds its `KeyChange` for good (`ControlEntry::marked`, Q249). `count_stranded` adds `IN_FLIGHT_MARGIN` (2) to the id an unknown mark takes; `drop_send_queue` marks a `KeyChange` cell on its way to the dropped queue (Q250). A marker row that does not decode fails the open (Q251).
- **STOP checks.** `vectors/store.json` has one seal case with a CONTROL-part row key, `store-0011` (`sessions`, `data`, row key (3, 5, 0)); its record is 80 bytes of the ref stream (`ref/secmp_ref/store_cases.py:37`), not a content, and the seal does not read it: tag 4 changes nothing a vector or `ref/` accepts. The backup exports no `sessions` row (`crates/secmp-store/src/backup.rs:17-18`). No DDL, no store function, no wire, label, `docs/03` or `docs/01` change.
- **Red-first.** Fourteen edits of WEISUNG 2, evidence `docs/reviews/M07-evidence/b17b2-red-a.txt` … `b17b2-red-n.txt`, each against the fourteen tests SE-75, SE-91…SE-103: (a) the marker not read back (`sessions/mod.rs:408`): 8 passed, 6 failed: `tests.rs:4055:9` `Q249: only the first registration takes a marker over`, `tests.rs:3797:9` (`left: [1, 4, 4]`, `right: [1]`), `hub.rs:2041:13`, `tests.rs:3758:5` (`false` / `true`), `tests.rs:3948:9` `Q249: B's pre-restart copy is not counted yet`, `tests.rs:4007:9` `Q249: B's copy holds for good`. (b) no take-over at the first registration (`actor.rs:680`): 11 passed, 3 failed: `tests.rs:3766:5` (three markers / two), `hub.rs:2041:13`, `tests.rs:3963:9` `630 counts B's copy away`. (c) no cell waits for its marker (`actor.rs:1734`): 13 passed, 1 failed: `actor.rs:3805:9` (`([], 1, 1)` / `([[7; 16]], 0, 1)`). (d) an old queue's marker never goes (`actor.rs:956`): 12 passed, 2 failed: `actor.rs:3917:9` (`(2, [])` / `(2, [100])`), `tests.rs:3740:5`. (e) a cell on its way keeps no marker (`actor.rs:958`): 13 passed, 1 failed: `actor.rs:3908:9` (`(2, [100])` / `(2, [])`). (f) the row goes with a marker left (`actor.rs:982`): 13 passed, 1 failed: `actor.rs:3863:9` (`(1, [100, 7, 50])` / `(1, [100, 50])`). (g) margin 0 (`actor.rs:221`): 12 passed, 2 failed: `tests.rs:3960:9` `Q249, Q250: 629 is not enough for 500 + 2`, `tests.rs:2888:5` `Q250: 134 is inside the in-flight margin`. (h) no mark at the end of the overlap (`actor.rs:1363`): 13 passed, 1 failed: `actor.rs:3976:9`. (i) every cell on its way marked at the end of the overlap (`actor.rs:1355`): 13 passed, 1 failed: `actor.rs:3938:9`. (j) `held` ignores unknown marks and markers (B17a code, hand mutant H7; `actor.rs:939`): 7 passed, 7 failed: `tests.rs:4055:9` `Q249: only the first registration takes a marker over`, `actor.rs:3980:9`, `hub.rs:2041:13`, `tests.rs:3758:5`, `tests.rs:3952:9` `both markers stay`, `tests.rs:4007:9`, `tests.rs:3893:9` (`0` / `1`). (k) a longer marker row accepted (`actor.rs:244`): 12 passed, 2 failed: `tests.rs:3683:9`, `tests.rs:3831:13` `Q251: 26 bytes`. (l) the hub sets no `sid` (`hub.rs:358`): 13 passed, 1 failed: `hub.rs:2007:17` (`([3], [])` / `([3, 4], [[4; 16]])`). (m) the take-over adds no mark of unknown outcome (`actor.rs:692`; verification R1 W-01): 13 passed, 1 failed: `tests.rs:3948:9` `Q249: B's pre-restart copy is not counted yet`. (n) a take-over at every registration of the process (`actor.rs:680`; verification R2): 13 passed, 1 failed: `tests.rs:4055:9` `Q249: only the first registration takes a marker over`. Green: 14 passed.
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 267 run, 267 passed (254 before; thirteen new: SE-91…SE-103; SE-75 re-dictated for the margin: 133 → 135, 129 → 131). `cargo fmt --all --check`: no output. clippy (`-D warnings`, all targets, all features): exit 0.
- **Mutants.** `--in-diff` run on `sessions/actor.rs`, `hub.rs` and `sessions/mod.rs`, evidence `mutants-b17b2-4f0d59f.txt`: 68 mutants tested in 27m: 59 caught, 9 unviable
- **D-B73 (closed).** A mark no longer goes with a restart: its marker is read back (Q249).
- **D-B81 (B17b-2, recorded, NOT accepted as final; see OPEN-M7-B-27; fail closed, availability).** A `KeyChange` copy that nothing can count away any more — its old queue not counted before a restart, its old queue's overlap ended before the count (D-B74), or a cell on its way at the end of the overlap (Q250) — holds its contact's chain for good: later successions towards that contact are not sent, `SuccessionPending` warns; for a rotation after a compromise the held contact keeps trusting `IK_n`. The count needs 128 · `P_q` (up to 171 min) of sending on the old queue after a switch, so a restart or a suspended client in that span after a switch is enough. Release only through an owner-reserved action (ADR-060 (7)); OPEN-M7-B-24 (B) and (C) are not built. The reviewer does not accept this as the final state: the durable send overlap (unit B17b-3, OPEN-M7-B-27) removes the restart trigger before the M7 merge.
- **D-B82 (B17b-2, recorded; fail closed, availability).** Crash windows that hold without a copy: a marker written and the process stopped before the cell's seal, with the peer's `RouteUpdate` committed before the restart (the restart registers another `sid`); or an old queue counted away and the process stopped before its marker's delete. Both narrow.
- **D-B83 (B17b-2, recorded; fail closed).** The margin of 2 (Q250) is a bound by the link's in-flight depth, not a proof: a `SEND` on a dropped Tor circuit that reaches the relay behind more than two later cells of its queue (more than one when both outstanding `SEND`s arrive late) is counted too early; the same holds for a copy in flight at a restart (Q249); the result, if a later succession follows before the copy is fetched, is a freeze at the peer, never an accepted identity (ADR-060 Consequences). The margin of 2 is a heuristic and does not follow from `docs/03` §10.3: §10.3 bounds the requests outstanding on one link, not how many later cells of the queue, sent on a new link after the drop, reach the relay before a `SEND` of the dropped link (external review EXT2d-3; recorded as a docs note in M7 REST, Q279; a protocol variant with a provable bound would be the owner's decision).
- **D-B84 (B17b-2, recorded).** A conversation that knows no `sid` for its send queue writes no marker and holds nothing for one (the test kit's `bind`; behaviour as before). The product registers every send queue through `Hub::register_route`, which sets the `sid` first; SE-95 pins it (red l).
- **D-B85 (B17b-2, recorded; fail closed).** Marker rows share D-B79: an adversary who can write the store (ADV-M) can delete a marker (a copy then counted too early: a freeze at the peer) or replay an old one (a hold for good). Never an accepted identity.
- **Recorded.** OPEN-M7-B-24 closed with (A) (Q248–Q251); OPEN-M7-B-27 opened (durable send overlap, unit B17b-3; M7 is not merged before it); D-B73 closed; EXT2c-1's D-B73 note closed in the §B-4g table. B17b verification I-03 / hand mutant H7 (`held` ignores unknown marks) is killed by SE-99 (red j). Verification R1 W-01: the take-over's mark of unknown outcome (Q249) is killed by SE-101 (red m); before it, no test of the suite saw it. Verification R2: a take-over at every registration instead of the first (`actor.rs:680`) survived the whole suite; SE-103 kills it (red n); B17b-3 (OPEN-M7-B-27) re-dictates SE-103. Hand mutants outside cargo-mutants (NOTES-M7-B17b2-planner): a swallowed marker write, marker delete, old-marker delete or orphan delete, and a forgotten orphan are each killed by SE-92, SE-93 or SE-94; `marker_of(..).unwrap_or(None)` at open is equivalent (`PendingControl::decode` refuses tag 4, the open fails the same). ADR-060 amended (B17b-2) in its last paragraph.

## DOCS4 (WEISUNG M7-DOCS4; D-CI10 and D-CI11 closed from PR-run data, D-CI12 opened, PR-run rows; docs only; modell=claude-sonnet-5-5)

- **Commit.** START `b5ec47a`; one docs commit (`docs/reviews/M07-report.md` only). The job facts are from the runs' GitHub job logs (log extractions LOG13, 2026-11-13 22:30 UTC, LOG15, 2026-11-14 04:51 UTC, and LOG16, 2026-11-14 13:52 UTC, all read-only); the run-level facts from the reviewer's run queries h59 (2026-11-13 21:51 UTC: run 43474391164, head `23b7424`, created, completed, conclusion success) and h67 (2026-11-14 16:21 UTC: run 43591576223 completed, conclusion success, its 36 jobs, each success, with their times). LOG13 and LOG15 do not name their run; that LOG13 and the green job 132054263784 of LOG15 belong to PR run 43474391164 is the reviewer's attribution.
- **D-CI10 (closed).** PR run 43474391164 (`23b7424`, CI7), completed, conclusion success, on a head that contains the CI7 killers (`919da9e`): M = `core/mod.rs:860:30 … with false in World::step_due` caught after 23 s build + 2 s test (shard 2); S = `core/mod.rs:1907:33: replace > with >= in Scheduler::next_deadline` caught after 52 s build + 2 s test (shard 5); 0 TIMEOUT. Before the killers, M / S: 690 s / 863 s of test time (run 43299417039), 901 s TIMEOUT / — (run 43385042727), 682 s / 611 s (run 43417767896). Source: log extraction LOG13; the times before the killers are those of §4 and §DOCS3. This is the proof §CI7 asked for; OPEN-M7-B-23 (the long `secmp-transport` results) is not touched by it and stays open.
- **D-CI11 (closed).** PR run 43591576223 (`3f564f8`, WIN1), completed, conclusion success, `ci-verdict` 2026-11-14 15:22:25 UTC, all 36 jobs green. Job `windows-native` 132437232187, 11:46:05–13:37:41 UTC, success: `m7_activity::store_backed_source_activity_independent` (SE-19) PASS [949.210s] (296/296); the harness summary `296 run: 296 passed (15 slow), 16 skipped` (1286.726 s); `secret_page::os::tests::concurrent_locks_beyond_the_default_quota_all_succeed` PASS [0.027s]; `secret_page::os::tests::every_lock_waits_for_the_growth_lock` PASS [0.214s]; `secret_page::grow::tests` 10/10 PASS; the workspace nextest `1503 run: 1503 passed (2 leaky)`; step table clippy 617 s, nextest 1827 s, doctest 3 s, kat 2828 s, harness 1313 s, hello 0 s, all PASS; runner image windows-2025-vs2026 20261103.298.1. The log has 0 lines containing `VirtualLock`, `LastError=1453`, `sqlcipher_mlock`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at` or `##[error]`. Nextest prints a test's stderr only when the test fails, so 0 lines is not evidence that the quota warning did not occur. The proof defined in §WIN1 (`windows-native` green, including SE-19 and the two new `cfg(windows)` tests) is met. That the quota path produced the `Unavailable` of run 43539306737 stays unproven (§WIN1), and the two points "Open on Windows" of §WIN1 are unchanged. Source: log extraction LOG16; run-level facts and job times from h67.
- **D-CI12 (open observation; not classified, not accepted, not closed; to be measured).** In PR run 43591576223 the test `m7_activity::store_backed_source_activity_independent` took 949.210 s on `windows-native` (job 132437232187; LOG16), against 387.118 s in the green `windows-native` job 132054263784 of PR run 43474391164 (`23b7424`; LOG15), on the same runner image (windows-2025-vs2026, Version 20261103.298.1; LOG15, LOG16). The cause is not measured. Candidates named so far: runner variance; waiting at the process-wide mutex `GROW` of ADR-061 (§WIN1 open point (ii)); the two heads also differ by the code of B17b-1 and WIN1. None is shown and none is excluded. A second data point from PR run 43647712727 (`b5ec47a`) is pending (the run was in progress when this was written). No change in this unit; no decision before a measurement. **Updated by DOCS5 (PR runs 43647712727 and 43668999495; §DOCS5): five data points; the observation stays open.** **Closed by DOCS6 (D-CI14, Q260 and Q261; §DOCS6): by the reviewer's verdict on the A/B run, a CI-environment observation, not product code; no code fix.**
- **Gate table (§4).** Rows added for PR run 43474391164 (`23b7424`, CI7) and PR run 43591576223 (`3f564f8`, WIN1). The row for PR run 43539306737 (`d5dfdc7`, red at `windows-native`) was already present (WIN1) and is unchanged; its tail "proof open until `windows-native` of the next PR run" is historical and is answered by the row of PR run 43591576223. No row for PR run 43647712727 (not finished). **Rows for PR runs 43647712727 and 43668999495 added by DOCS5 (§DOCS5).**
- **Gates.** `cargo nextest run -p xtask`: 324 passed; `cargo xtask step --strict policy` PASS. No ci-fast and no CHANGELOG line (DOCS2 and DOCS3 precedent: a commit under `docs/reviews/` only).

## DOCS5 (WEISUNG M7-DOCS5; D-CI12 updated with five data points, D-CI13 opened, PR-run rows; docs only; modell=claude-sonnet-5-5)

- **Commit.** START `467b769`; one docs commit (`docs/reviews/M07-report.md` only). Sources, all read-only and of 2026-11-15: the reviewer's log extractions LOG17 (Windows job of PR run 43647712727; it names its run by "CI seed 43647712727"), LOG18 (Linux `harness` jobs of four PR runs), LOG19 (Windows jobs of four PR runs) and LOG20 (Windows job of PR run 43668999495); the return files of LOG18 and LOG19 as printed verbatim by h77 (each names its runs and heads); and the reviewer's run queries h74 (PR run 43668999495), h75 (PR run 43591576223) and h76 (PR run 43647712727): per job its name, conclusion, id, start and end. LOG20, h74, h75 and h76 do not name their run; their attribution to these runs is the reviewer's. Every cell of the D-CI12 table below is in one of these extractions: the columns `23b7424`, `d5dfdc7`, `3f564f8` and `b5ec47a` in the LOG18 and LOG19 return files (h77; the `b5ec47a` Windows values except `crash_between_persist_and_send_no_key_reuse` also in LOG17), the column `467b769` in LOG20. The job ids and times of the two `windows-native` jobs are from h76 and h74.
- **D-CI12 (open observation; update; not classified, not accepted, not closed).** The second data point announced in §DOCS4 (PR run 43647712727) is in, together with a later run (PR run 43668999495) and the values of PR run 43539306737: seconds per test on `windows-native` (and, for SE-19 and the 312-test harness summary, on the Linux job `harness`) at five heads. Run 43474391164 = `23b7424`; run 43539306737 = `d5dfdc7` (B17b-1; red at `windows-native`, D-CI11); run 43591576223 = `3f564f8` (WIN1); run 43647712727 = `b5ec47a` (B17b-2); run 43668999495 = `467b769` (DOCS4, docs-only on `b5ec47a`).

| Test (seconds) | `23b7424` | `d5dfdc7` | `3f564f8` | `b5ec47a` | `467b769` |
|---|---|---|---|---|---|
| Windows `m7_activity::store_backed_source_activity_independent` (SE-19) | 387.118 | 541.781 FAIL | 949.210 | 1132.569 | 1153.836 |
| Windows `m7_persist::write_amplification_measured` | 94.145 | 127.669 | 398.998 | 601.403 | 643.575 |
| Windows `m7_rotation::recipient_retires_old_queue` | 57.509 | 122.101 | 290.713 | 382.564 | 368.754 |
| Windows `m7_crash::crash_between_persist_and_send_no_key_reuse` | 123.501 | 176.095 | 296.503 | 294.433 | 425.130 |
| Windows `m6_two_clients::two_clients_direct_tls_loopback` (control) | 614.303 | 531.614 | 569.463 | 579.855 | 475.436 |
| Windows `m6_two_clients::two_clients_loopback_tcp` (control) | 603.728 | 659.185 | 688.129 | 553.942 | 516.596 |
| Windows harness summary | 773.890 | 884.409 (268/296 run, 1 failed) | 1286.726 | 1482.254 | 1504.051 |
| Linux SE-19 (job `harness`) | 749.939 | 773.829 | 768.814 | 364.704 | not extracted |
| Linux harness summary (312 tests) | 3572.553 | 4480.224 | 4461.627 | 2374.567 | not extracted |

- **D-CI12 facts (LOG17, LOG20, h74, h76).** The `FAIL` in the `d5dfdc7` column is the run in which SE-19 panicked with `Unavailable` (D-CI11): the value is the time to the failure, not the duration of a passing test, and the harness summary of that run is `268/296 tests run: 267 passed (9 slow), 1 failed, 16 skipped` (884.409 s). LOG17 (run 43647712727; job `windows-native` 132609084725, 22:22:03–00:19:51 UTC, from h76): SE-19 PASS [1132.569s] (296/296), the harness summary `296 run: 296 passed (15 slow), 16 skipped` (1482.254 s), the workspace nextest `1516 run: 1516 passed (2 leaky)`, step table clippy 643 s, nextest 1895 s, doctest 3 s, kat 2916 s, harness 1506 s, hello 0 s, all PASS; 0 lines containing `LastError=1453`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at` or `##[error]`; runner image windows-2025-vs2026 20261103.298.1. LOG20 (run 43668999495; job `windows-native` 132674628908, 02:42:07–04:40:09 UTC, from h74): SE-19 PASS [1153.836s] (296/296), the harness summary `296 run: 296 passed (15 slow), 16 skipped` (1504.051 s), the workspace nextest `1516 run: 1516 passed (2 leaky)`, step table clippy 647 s, nextest 1893 s, doctest 3 s, kat 2918 s, harness 1526 s, hello 0 s, all PASS; the same six counts 0; the same runner image. Both jobs: `secret_page::os::tests::concurrent_locks_beyond_the_default_quota_all_succeed` and `secret_page::os::tests::every_lock_waits_for_the_growth_lock` PASS (0.028 s and 0.248 s; 0.074 s and 0.226 s).
- **D-CI12 reviewer's reading (inference; not a measurement of the cause).** (1) The slowdown is on Windows: on Linux the SE-19 time of the job `harness` was 749.939, 773.829 and 768.814 s at the first three heads and 364.704 s at `b5ec47a` (LOG18), while on Windows it rose from 387.118 s to 1132.569 s. (2) It is bound to the store-backed tests: SE-19, `write_amplification_measured`, `recipient_retires_old_queue` and `crash_between_persist_and_send_no_key_reuse` are slower at `467b769` than at `23b7424`, while the two `m6_two_clients` tests used as controls are not (614.303 / 603.728 s at `23b7424`, 475.436 / 516.596 s at `467b769`). (3) It is not explained by scatter between these two runs: `467b769` differs from `b5ec47a` only in `docs/reviews/M07-report.md` (`git diff --stat`), and in these two runs the identical code reproduces the Windows durations: SE-19 1132.569 → 1153.836 s (+1.9 %), `write_amplification_measured` 601.403 → 643.575 s (+7.0 %), `recipient_retires_old_queue` 382.564 → 368.754 s (−3.6 %), harness summary 1482.254 → 1504.051 s (+1.5 %); the exception is `crash_between_persist_and_send_no_key_reuse`, 294.433 → 425.130 s (+44 %). The cause is not measured. The candidates named in §DOCS4 are neither shown nor excluded by this; this unit adds none.
- **D-CI12 status and next step.** Open observation. Next step: the diagnostic unit WIN2-DIAG (cause before fix). No change of code, test, gate, workflow, budget or threshold in this unit, and no decision before a measurement. **The next step named here is done and D-CI12 is closed by DOCS6: WIN2-DIAG (Q260) and the A/B run (Q261) are in (§DOCS6).**
- **D-CI13 (open observation; not classified, not accepted; to be watched on each PR run).** The job `mutants-shard (1)` ran 246 min in PR run 43647712727 (`b5ec47a`; job 132609084843) and 231 min in PR run 43668999495 (`467b769`; job 132674629047), against the job budget of 300 min: the entry `("mutants-shard", 300)` of `JOB_BUDGETS` (`xtask/src/expect.rs:2153`; the constant starts at line 2146) and `timeout-minutes: 300` of the job `mutants-shard` (`.github/workflows/ci.yml:371`). The remaining headroom is 54 min and 69 min. In PR run 43591576223 (`3f564f8`) the longest shard was shard 16 with 215 min. Minutes are the job's start to end (h74, h75, h76), rounded to the minute; the sums are of the rounded values.

| PR run (head) | longest of the 24 `mutants-shard` jobs | sum of the 24 shards |
|---|---|---|
| 43591576223 (`3f564f8`) | 215 min (shard 16) | 3969 min |
| 43647712727 (`b5ec47a`) | 246 min (shard 1) | 4069 min |
| 43668999495 (`467b769`) | 231 min (shard 1) | 3962 min |

- **D-CI13 scatter and limits.** Between `b5ec47a` and `467b769` the code, and with it the mutant set, is identical (docs-only commit, see D-CI12), and single shards still moved by up to 66 min: shard 0 139 → 205 min, shard 22 213 → 147 min, shard 23 191 → 132 min, shard 3 193 → 135 min; by 76 min if the h74 row of shard 8 is taken as listed (134 → 210 min; h74 gives that row the same job id as the row of shard 2, so it is the least certain row; its times are used as listed, also in the sum); the sums differ by 107 min (4069 → 3962). The headroom of 54–69 min is of the same size as this run-to-run scatter. The step inside the job has its own budget of 16 800 s = 280 min (`MUTANTS_STEP_TIMEOUT_SECONDS`, `xtask/src/expect.rs:953`); a shard step ended at that budget once before (PR run 43083238010, §4, remedy: 24 shards, ADR-047 Amendment 11). How much of the 246 min and the 231 min was the step, and which mutants make shard 1 long, is not measured. No change of the shard count, the job or step budget, the skip list or any limit in this unit: such a change is an amendment of ADR-047 or ADR-045 and goes through the reviewer. The observation is watched on each PR run (per-shard job minutes against 300 min). **Updated by DOCS6 (PR runs 43706937667, 43728831159 and 43750760342; §DOCS6): six data points; stays open.**
- **Gate table (§4).** Rows added for PR run 43647712727 (`b5ec47a`, B17b-2) and PR run 43668999495 (`467b769`, DOCS4), after the row of PR run 43591576223, in the form of the existing rows; both runs completed, conclusion success, 36 jobs success. The D-CI12 line and the gate-table bullet of §DOCS4 keep their text and carry an appended marker.
- **Gates.** `cargo nextest run -p xtask`: 324 passed; `cargo xtask step --strict policy` PASS. No ci-fast and no CHANGELOG line (DOCS2, DOCS3 and DOCS4 precedent: a commit under `docs/reviews/` only).

## B17b-3 (WEISUNG M7-B17b3; OPEN-M7-B-27, D-B81; Q252–Q256, ADR-060 amendment (B17b-3); modell=claude-sonnet-5-5)

- **Commits.** START `bf06e60`; `c0df9b5` fix(core) B17b-3; this docs commit; the ci-fast evidence commit. Changed code: `crates/secmp-client-core/src/sessions/actor.rs`, `sessions/mod.rs`, `hub.rs`, `sessions/tests.rs`; `docs/mutants-accepted.md` re-pinned in `c0df9b5` (`hub.rs:527:30` → `hub.rs:582:30`: 55 lines inserted above it, the mutant and its row unchanged).
- **Design.** Every send-queue switch writes the old queue's overlap as a CONTROL row `5 ‖ sid ‖ seed ‖ period ‖ until ‖ newest ‖ unknown` (68 bytes; `OverlapRoute::row` / `overlap_of` in `sessions/actor.rs`): `Hub::register_route` hands the old route and the end it drew (Unix ms of the core clock) to `Conversation::keep_overlap`, which names the `KeyChange` copies on the old queue at the switch (`copies_on`) and writes the row at once; a failed write is tried again before every seal (`write_overlaps` in `prepare`); `drop_send_queue` deletes it (a failed delete joins the orphan retry). At open the rows join the conversation (`restore_overlap`); `Hub::resume_overlaps` (from `register_contact`, after the current route) registers each old queue again in overlap when `0 < until − now ≤ OLD_SEND_MS` and its physical queue is not registered, retires it at the same end, and `Conversation::resume_overlap` takes its markers over with the copies the rows name (`adopt`); rows not registered go at the first preparation. `set_send_sid` takes markers over at every registration (the B17b-2 first-registration gate is removed). The row is written for every switch, also without a `KeyChange`: a restart then registers the old queues whatever the user did (`docs/03` §10.1); OPEN-M7-B-27's wording put the route into the `KeyChange` marker, which would have tied the post-restart link set to a pending identity rotation (Q252).
- **STOP checks.** `vectors/store.json`: the only CONTROL-part seal case is `store-0011`, 80 bytes of the ref stream (`ref/secmp_ref/store_cases.py:37`), not a content; the backup exports no `sessions` row (`crates/secmp-store/src/backup.rs:17-18`, test at `:1197`). Row size 1 + 16 + 32 + 2 + 8 + 8 + 1 = 68 bytes, no fixed-size assumption on CONTROL rows (`insert_pending_control` seals any length). No DDL, no store function, no wire, label, vector, `ref/`, `docs/03` or `docs/01` change.
- **Red-first.** Thirty-five edits of WEISUNG 2, evidence `docs/reviews/M07-evidence/b17b3-red-a.txt` … `b17b3-red-ai.txt`, each against the 42 tests SE-63, SE-75, SE-81, SE-91…SE-129: (a) an overlap flag other than 0/1 accepted (`actor.rs:324`): 39 passed, 3 failed: `sessions/tests.rs:4168:9` `flag 2`, `sessions/tests.rs:4695:13` `decoded against the rule`, `sessions/tests.rs:4471:13` `Q255: one byte long`. (b) overlap rows not read at open (`sessions/mod.rs:413`): 25 passed, 17 failed: `hub.rs:2438:13`, `hub.rs:1694:13` `after a restart: B, then the old queues in overlap (Q253)`, `hub.rs:1911:17` `hub-rca: the old queues in overlap (Q253)`, `hub.rs:2583:13` `Q236: 22 once`, `hub.rs:2533:13` `B and the old queues, once each`, `hub.rs:2285:13` `Q253: 22 and 23 only, and B once`, `hub.rs:2841:13` `Q253: 22 after the skipped row of B`, `sessions/tests.rs:4348:5` `q254-id: Q254: B's copy is not counted yet`, `sessions/tests.rs:4348:5` `q254-way: Q254: B's copy is not counted yet`, `sessions/tests.rs:4872:9` `Q254: B's copy at id 1 is not counted yet`, `sessions/tests.rs:4585:5` `q254-two-id: B's copy is not counted yet`, `sessions/tests.rs:4488:9`, `sessions/tests.rs:4945:9` `Q254: B's copy of unknown id is not counted yet`, `Error: "B"`, `Error: "B"`, `Error: "A again"`, `Error: "sends"`. (c) the switch names no copy (`actor.rs:826`): 36 passed, 6 failed: `hub.rs:2381:13` `Q241: the end of B's overlap does not clear its mark`, `hub.rs:2312:13` `Q254: B's copy, id 4`, `sessions/tests.rs:4348:5` `q254-id: Q254: B's copy is not counted yet`, `sessions/tests.rs:4192:9` `Q254: on its way; relayed; unknown outcome; no KeyChange`, `sessions/tests.rs:4348:5` `q254-way: Q254: B's copy is not counted yet`, `sessions/tests.rs:4552:5` `q254-two-id: B's row, then the later one`. (d) marks of unknown outcome not named (`actor.rs:857`): 40 passed, 2 failed: `sessions/actor.rs:4410:9` `Q254: per queue, the highest mark; unknown by a mark or by a cell on its way`, `sessions/tests.rs:4192:9` `Q254: on its way; relayed; unknown outcome; no KeyChange`. (e) any control cell on its way named (`actor.rs:857`): 41 passed, 1 failed: `sessions/tests.rs:4192:9` `Q254: on its way; relayed; unknown outcome; no KeyChange`. (f) no write at the switch (`actor.rs:840`): 29 passed, 13 failed: `hub.rs:1699:13` `A is one of them`, `hub.rs:1916:17` `hub-rca: A, then B`, `hub.rs:2596:13` `Q236: A in overlap again is not registered a second time`, `hub.rs:2080:17` `hub-mk-same: the marker names B (after the overlap rows of the two earlier switches, Q252)`, `hub.rs:2190:13` `Q252: A's route and the drawn end`, `sessions/actor.rs:4292:9` `another queue: nothing`, `sessions/actor.rs:4435:9` `Q252: no late write for a dropped queue`, `sessions/actor.rs:4263:9` `Q252: written at the switch (this write fails)`, `sessions/tests.rs:4396:9`, `sessions/tests.rs:4552:5` `q254-two-id: B's row, then the later one`, `Error: "A's row"`, `Error: "A's row"`, `Error: "one overlap row"`. (g) a failed write taken as written (`actor.rs:867`): 41 passed, 1 failed: `sessions/actor.rs:4269:9` `tried again at the next preparation`. (h) unregistered rows kept (`actor.rs:1211`): 38 passed, 4 failed: `hub.rs:2438:13`, `hub.rs:2290:13` `the rows not registered go`, `hub.rs:2846:13` `B's row goes, 22's stays`, `sessions/actor.rs:4336:9` `the unregistered row (this delete fails)`. (i) a failed delete of an unregistered row forgotten (`actor.rs:1213`): 41 passed, 1 failed: `sessions/actor.rs:4343:9` `tried again, once; 6 stays`. (j) a failed delete at the drop forgotten (`actor.rs:1578`): 41 passed, 1 failed: `sessions/actor.rs:4305:9` `tried again, once`. (k) the drop deletes the other rows (`actor.rs:1576`): 38 passed, 4 failed: `hub.rs:2080:17` `hub-mk-same: the marker names B (after the overlap rows of the two earlier switches, Q252)`, `hub.rs:2231:13` `A's row goes with it`, `sessions/actor.rs:4292:9` `another queue: nothing`, `sessions/actor.rs:4349:9`. (l) no take-over at the re-registration (`actor.rs:913`): 35 passed, 7 failed: `hub.rs:2343:13` `132 counts B's copy away`, `sessions/tests.rs:4360:5` `q254-id: 132 counts B's copy away`, `sessions/tests.rs:4360:5` `q254-way: 630 counts B's copy away`, `sessions/tests.rs:4409:9` `Q254: B's marker goes, C's is written`, `sessions/tests.rs:4878:9` `129 counts the copy away`, `sessions/tests.rs:4597:5` `q254-two-id: 132 counts B's copy away`, `sessions/tests.rs:4954:9` `631 counts the copy away`. (m) a take-over with newest 0 marks id 0 (`actor.rs:801`): 41 passed, 1 failed: `sessions/tests.rs:4409:9` `Q254: B's marker goes, C's is written`. (n) take-over only at the first registration (B17b-2 gate) (`actor.rs:781`): 41 passed, 1 failed: `sessions/tests.rs:4058:9` `Q253: the later registration takes the marker over`. (o) the take-over adds no mark of unknown outcome (`actor.rs:805`): 38 passed, 4 failed: `sessions/tests.rs:3948:9` `Q249: B's pre-restart copy is not counted yet`, `sessions/tests.rs:4357:5` `q254-way: 629 is not enough`, `sessions/tests.rs:4594:5` `q254-two-way: 629 is not enough`, `sessions/tests.rs:4945:9` `Q254: B's copy of unknown id is not counted yet`. (p) an end equal to now registers (`hub.rs:334`): 41 passed, 1 failed: `hub.rs:2285:13` `Q253: 22 and 23 only, and B once`. (q) the retirement 1 ms late (`hub.rs:353`): 40 passed, 2 failed: `hub.rs:2893:13` `at the stored end`, `hub.rs:2224:13` `at the end`. (r) the end on the monotonic clock (`hub.rs:421`): 32 passed, 10 failed: `hub.rs:1694:13` `after a restart: B, then the old queues in overlap (Q253)`, `hub.rs:1911:17` `hub-rca: the old queues in overlap (Q253)`, `hub.rs:2583:13` `Q236: 22 once`, `hub.rs:2533:13` `B and the old queues, once each`, `hub.rs:2285:13` `Q253: 22 and 23 only, and B once`, `hub.rs:2190:13` `Q252: A's route and the drawn end`, `hub.rs:2841:13` `Q253: 22 after the skipped row of B`, `Error: "B"`, `Error: "B"`, `Error: "A again"`. (s) the row written from the new route (`hub.rs:422`): 32 passed, 10 failed: `hub.rs:2381:13` `Q241: the end of B's overlap does not clear its mark`, `hub.rs:1694:13` `after a restart: B, then the old queues in overlap (Q253)`, `hub.rs:1911:17` `hub-rca: the old queues in overlap (Q253)`, `hub.rs:2312:13` `Q254: B's copy, id 4`, `hub.rs:2583:13` `Q236: 22 once`, `hub.rs:2512:13` `Q252: the first row keeps its own seed and its period of 10 s`, `hub.rs:2114:13` `Q249: same queue released by its window; moved: held by B's marker`, `hub.rs:2285:13` `Q253: 22 and 23 only, and B once`, `hub.rs:2190:13` `Q252: A's route and the drawn end`, `hub.rs:2841:13` `Q253: 22 after the skipped row of B`. (t) markers with a queue taken over too (`actor.rs:795`): 41 passed, 1 failed: `sessions/actor.rs:4378:9` `D-B92: the dropped queue's marker stays; the new queue id gets its own`. (u) the row's seed from the new route (`hub.rs:426`): 41 passed, 1 failed: `hub.rs:2504:13` `Q252: A's row keeps A's seed and period`. (v) the row's period from the new route (`hub.rs:427`): 41 passed, 1 failed: `hub.rs:2512:13` `Q252: the first row keeps its own seed and its period of 10 s`. (w) the re-registration with another seed (`hub.rs:347`): 41 passed, 1 failed: `hub.rs:2535:17` `Q253: registered again with its own seed and period`. (x) two rows of one `sid`: the newest of the last row (`actor.rs:909`): 41 passed, 1 failed: `sessions/tests.rs:4585:5` `q254-two-id: B's copy is not counted yet`. (y) two rows of one `sid`: the flag of the last row (`actor.rs:910`): 41 passed, 1 failed: `sessions/tests.rs:4594:5` `q254-two-way: 629 is not enough`. (z) the last mark instead of the highest (`actor.rs:851`): 41 passed, 1 failed: `sessions/actor.rs:4410:9` `Q254: per queue, the highest mark; unknown by a mark or by a cell on its way`. (aa) a dropped overlap kept in memory (`actor.rs:1583`): 41 passed, 1 failed: `sessions/actor.rs:4435:9` `Q252: no late write for a dropped queue`. (ab) markers of every `sid` taken over (`actor.rs:795`): 28 passed, 14 failed: `hub.rs:2437:13` `B's copy holds`, `hub.rs:2381:13` `Q241: the end of B's overlap does not clear its mark`, `hub.rs:2334:13` `Q254: B's copy is not counted yet`, `hub.rs:2114:13` `Q249: same queue released by its window; moved: held by B's marker`, `sessions/tests.rs:4058:9` `Q253: the later registration takes the marker over`, `sessions/tests.rs:4348:5` `q254-id: Q254: B's copy is not counted yet`, `sessions/tests.rs:3758:5` `q249-uncounted: Q249: only an uncounted old queue holds after the restart`, `sessions/tests.rs:4348:5` `q254-way: Q254: B's copy is not counted yet`, `sessions/tests.rs:4652:9` `Q256: B's marker holds without its overlap row`, `sessions/tests.rs:4409:9` `Q254: B's marker goes, C's is written`, `sessions/tests.rs:4872:9` `Q254: B's copy at id 1 is not counted yet`, `sessions/tests.rs:4007:9` `Q249: B's copy holds for good`, `sessions/tests.rs:4585:5` `q254-two-id: B's copy is not counted yet`, `sessions/tests.rs:4945:9` `Q254: B's copy of unknown id is not counted yet`. (ac) a queue registered again is no send target (`hub.rs:351`): 41 passed, 1 failed: `hub.rs:2582:13` `Q236: 22 once`. (ad) a row skipped by the Q236 check ends the re-registration (`hub.rs:339`): 41 passed, 1 failed: `hub.rs:2841:13` `Q253: 22 after the skipped row of B`. (ae) the retirement of a queue registered again measured from monotonic 0 (`hub.rs:329`): 41 passed, 1 failed: `hub.rs:2885:13` `1 ms before the stored end`. (af) a row naming id 1 marks nothing (`actor.rs:801`): 41 passed, 1 failed: `sessions/tests.rs:4872:9` `Q254: B's copy at id 1 is not counted yet`. (ag) an overlap flag 255 accepted (`actor.rs:323`): 41 passed, 1 failed: `sessions/tests.rs:4695:13` `decoded against the rule`. (ah) an overlap period 0 accepted (`actor.rs:329`): 41 passed, 1 failed: `sessions/tests.rs:4695:13` `decoded against the rule`. (ai) the take-over's mark of unknown outcome resolved one cell later (`actor.rs:805`): 41 passed, 1 failed: `sessions/tests.rs:4954:9` `631 counts the copy away`. Green: 42 passed.
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 293 run, 293 passed (267 before; twenty-six new: SE-104…SE-129, of them SE-119…SE-124 from verification R1, SE-125…SE-128 from verification R2 and SE-129 from verification R3; re-dictated: SE-63, SE-81, SE-95 — the restart now also registers the old queues in overlap — and SE-103 — a later registration takes the marker over). `cargo fmt --all --check`: no output. clippy (`-D warnings`, all targets, all features): exit 0.
- **Mutants.** `--in-diff` run on `sessions/actor.rs`, `hub.rs` and `sessions/mod.rs`, evidence `mutants-b17b3-c0df9b5-s0.txt`, `mutants-b17b3-c0df9b5-s1.txt` (two shards): s0: 31 mutants tested in 19m: 20 caught, 11 unviable; s1: 31 mutants tested in 22m: 28 caught, 3 unviable
- **D-B81 (B17b-2) narrowed.** Its restart trigger is removed (OPEN-M7-B-27 closed); the remaining trigger is D-B86.
- **D-B86 (B17b-3, recorded; owner: OPEN-M7-B-28; fail closed, availability).** A `KeyChange` copy on an old send queue is still held for good when the overlap end drawn at the switch (`U[1 h, 24 h]`) comes before the count of 128 later cells there; across a restart the end is wall-clock time, so minutes the client is off inside the overlap count against it. Per switch with such a copy, computed, not measured: P = max(0, k·I + d − 60 min) / 1380 min, k = 128 for a relayed copy and 131 for a copy of unknown outcome (first later id + 2 + 128), I = `P_q` in Strict mode and `max(P_q, N·T_BALANCED)` / `max(P_q, N·T_LOWBW)` in Balanced / Low-bandwidth mode with N send queues on the link (`docs/03` §10.2). Strict, k = 131: 0 / 0 / 1.98 / 8.31 % at 10 / 20 / 40 / 80 s with d = 0, 32.02 / 33.60 / 36.76 / 43.09 % with d = 480 min (k = 128: 0 / 0 / 1.84 / 8.02 %, 31.98 / 33.53 / 36.62 / 42.80 %); Low-bandwidth, five queues at 40 s (I = 150 s), k = 131: 19.38 % with d = 0. The count also needs the old queue's `OK_SEND`s: time without a link inside the overlap counts against it like downtime. Before B17b-3 every restart within the count held for good.
- **D-B87 (B17b-3, recorded; fail closed).** Crash windows without a row: a `RouteUpdate` committed and the process stopped before the pump (SE-95 "moved": B is not registered again, its marker holds), or the overlap row's write failing until the process stops (SE-121). Both hold, never release.
- **D-B88 (B17b-3, recorded; fail closed).** The stored end is Unix time of the core clock; a running process retires on the monotonic clock (a suspend does not advance it on Linux). A clock moved back by more than `OLD_SEND_MS`, or forward past the end, registers nothing (hold); a smaller step back lengthens the overlap by that step, at most to `OLD_SEND_MS` from the restart.
- **D-B89 (B17b-3, recorded).** After a restart every old send queue sends dummies again until its stored end (before: a restart ended every send overlap): one `SEND` per `P_q` per old queue for the rest of its overlap, as without the restart; the old queue's link starts like every link at app start (`docs/03` §10.6 (1)) instead of stopping when the client's links drop.
- **D-B90 (B17b-3, recorded).** An old queue's sender seed stays in the store (sealed, `sessions` part 5) until its overlap ends — up to 24 h + 1 min after the switch — or, if the client is not running then, until the first preparation of that conversation after the next start (a clock set back before every restart keeps it longer, D-B88) (before B17b-3: overwritten at the switch; deleted with `secure_delete`, CS-3.4). It lets its holder send to that queue only (spec §9.1).
- **D-B91 (B17b-3, recorded; fail closed).** Overlap rows share D-B79/D-B85: an adversary who can write the store (ADV-M) can delete one (no re-registration: a hold) or replay an older row of the same queue with fewer copies named (a copy counted too early: a freeze at the peer). Never an accepted identity.
- **D-B92 (B17b-3, recorded; availability).** A marker of a send queue dropped in this process is not taken over by a later registration of its `sid` in the same process, only after a restart (SE-118).
- **D-B93 (B17b-3, recorded; availability; verification R2).** The number of a contact's send queues in overlap — and of its overlap rows — is bounded only by the `RouteUpdate`s the peer sends within the longest overlap (24 h + 1 min): each one to a new `sid` adds a send queue (one `SEND` per `P_q`, at the peer's period) and a row. A malicious contact (ADV-C) can raise the client's traffic that way; before B17b-3 the same held until the next restart, now also across it. No cap is built; open: OPEN-M7-B-29 (1). (B17c: the longest overlap is 48 h + 1 min after the switch, D-B103.) (CAP: at most 6 old send queues per contact, Q268; D-B104–D-B106.)
- **D-B94 (B17b-3, recorded; verification R3; open: OPEN-M7-B-29 (2)).** The CONTROL-row decoders (`overlap_of` (new, tag 5), `marker_of` (B17b-2, tag 4), `PendingControl::decode`) parse bytes read from the store but have no fuzz target (CLAUDE.md §2.4; `fuzz/` has none for `secmp-client-core` rows). SE-125 (every period, flag and tag byte, the extreme ends and ids, 20 000 pseudo-random rows of length 0…80) and SE-104/SE-112 cover `overlap_of` as unit tests only; they do not replace a fuzz target. Not built in B17b-3 (`fuzz/` and `xtask/` are outside its scope). Closed in FZ (Q272–Q275): fuzz target FZ-05 `client_control_rows` over `control_row_of`.
- **D-B95 (B17b-3, recorded; verification R3; fail closed, availability; since B17b-2).** A marker taken over at a registration (`adopt`: the current queue, Q249, or a queue registered again, Q254) is marked as of unknown outcome with the token 0, and a mark of unknown outcome takes the id of the first `OK_SEND` of a cell prepared after it (`count_stranded`: token greater than the mark's); the cell prepared first after the open has token 0, so its `OK_SEND` does not count and the copy takes the id of a later one — at most one cell later than Q249's wording, a later release, never an earlier one (verification R3: SE-129 with B's id 630 in place of 631 fails its last assertion; 500 + 2 + 128 = 630 would be the release by Q249's wording).
- **Recorded.** OPEN-M7-B-27 closed (Q252–Q256); OPEN-M7-B-28 opened (owner: D-B86, options C and C′); OPEN-M7-B-29 opened (D-B93: no cap of a contact's send queues in overlap; D-B94: no fuzz target for the CONTROL-row decoders). Hand mutants outside cargo-mutants (NOTES-M7-B17b3-planner): `overlap_of(..).unwrap_or(None)` at open is equivalent (`PendingControl::decode` refuses tag 5, the open fails the same); the swallowed seed copy of `overlaps_read` is equivalent (a 32-byte copy cannot fail); a swallowed overlap write, unregistered-row delete and drop delete are killed (red g, i, j). Verification R1 (39 hand mutants of the new code): fourteen survived the 282 tests — the seed or the period of an old route in its row or in its re-registration, the merge of two rows of one `sid`, `copies_on`'s per-queue maximum, a late write for a dropped queue, the Q236 check against a queue registered again — and are killed by SE-119…SE-124 (red u…ac); a row written only when a copy may be there (the design Q252 rejects) is killed by SE-63, SE-81, SE-95, SE-105…SE-107, SE-110, SE-113, SE-119, SE-122, SE-124; equivalent: `registered.insert` in `resume_overlaps` (it only dedupes receive registrations, send ids are ≥ `SEND_BASE`) and the `newest`/`unknown` of `OverlapRoute::copy` (not read by the hub). Verification R2 (21 further hand mutants: the re-registration window's bounds and clock, the Q236 skip, the retirement, every condition of the take-over, the row's write, retry and delete, the decoder): fifteen killed by the 288 tests; five survived — the Q236 skip ending the loop, the retirement measured from monotonic 0, a stored copy id of 1 not marked, an overlap flag 255 and a period 0 accepted — and are killed by SE-125…SE-128 (red ad…ah); equivalent: `resume_overlap` taking rows already bound (it runs only at open, when no row is bound). Verification R3 (18 further hand mutants: the re-registration's previous queue, period, bounds, loop and retirement, the stored end, the decoder's field order, endianness, length 67/69 and tag 4/5, the encoder's endianness, the merge of two rows, `copies_on`'s queue and marks): seventeen killed by the 292 tests; one survived — the take-over's mark of unknown outcome resolved one cell later (`(queue, 1)`) — and is killed by SE-129 (red ai). ADR-060 amended (B17b-3) in its last paragraph.

## DOCS6 (WEISUNG M7-DOCS6; D-CI14 opened and closed (WIN2-DIAG, Q260; A/B, Q261), D-CI12 closed, D-CI13 updated, D-B80 evidence, PR-run rows; docs only; modell=claude-sonnet-5-5)

- **Commit.** START `5ee0669`; one docs commit (`docs/reviews/M07-report.md` only). Sources, all read-only and of 2026-11-15 and 2026-11-16: the executor return files of the units WIN2DIAG, WIN2DIAG-R, LOG21 (with its raw lines as printed verbatim by h83), LOG22, LOG23, AB1, AB1-R and LOG24; AUD15, AUD16 and AUD17; the push gate files for `194de59`, `595eb14`, `cf80a2f` and `5ee0669`; the reviewer's decision table of WIN2-DIAG (`DECISION-TABLE-M7-WIN2DIAG`, fixed 2026-11-15 before the run); the reviewer's handover of 2026-11-15 17:50 UTC (the decision rule of the A/B run Q261, fixed before the push of A); and the reviewer's run queries h79b, h84 and h87 (per job its name, conclusion, id, start and end) and h85 and h88 (run id, head, status, time). The job lists carry no run id: their attribution to PR runs 43706937667 (h79b), 43728831159 (h84) and 43750760342 (h87) is by the time listed for the runs in h85 and h88 (11:02:10, 15:15:12 and 19:08:46 UTC; the first jobs start within 5 s of it). LOG22 and LOG24 do not name their run; their attribution to the `windows-native` jobs of runs 43706937667 and 43750760342 is the reviewer's (the 14 989 log lines of LOG22 equal the 14 989 lines of that job in LOG23). LOG23 names its seven logs by run id (the seventh by job id 132856553210 of run 43728831159). Q260 (WIN2-DIAG) and Q261 (A/B) have no row in `OPEN-M7-decided.md`: they decide a measurement, not a rule, and no code, ADR, gate or limit changes in this unit.
- **The throw-away commits W and A (neither was ever the head of a merge GO; both stay in the branch history with their reverts).** W = `595eb1485e5387301da5b1a3c5ca3fb3715fd601` (unit WIN2-DIAG; subject `test(diag): WIN2-DIAG lock and process counters for one windows-native run (Q260, D-CI14) — throw-away, revert before any further unit`; parent `194de59`; 12 files, 554 insertions, 17 deletions), pushed (`194de59..595eb14`) at 2026-11-15 15:15:06 UTC; reverted by `1cd96f882d7e2b02b58993a7fe4c2e287eb7cf56` (unit WIN2-DIAG-R; its tree `60f7251a5a575cd468129b31a6e29c342360f84e` is the tree of `194de59`, the diff against `194de59` is empty). A = `cf80a2f03d4344dd6d8191ea671ef46650ebbc11` (unit AB1; subject `test(diag): A/B — tree of 23b7424 for one windows-native run on today's runners (Q261, D-CI14) — throw-away, revert before any further unit`; parent `1cd96f8`; its tree `aca5ef7b6741db34e1f1a6aebab103fe2780d5fb` is the tree of `23b7424`, the diff against `23b7424` is empty; against its parent: 55 files, 132 insertions, 30 132 deletions), pushed (`595eb14..cf80a2f`, with `1cd96f8` below it) at 2026-11-15 19:08:39 UTC; reverted by `bf06e60c570306c273f1b2b771cace9fb132ba65` (unit AB1-R; tree `60f7251a5a575cd468129b31a6e29c342360f84e`, the diff against `194de59` is empty), pushed with the B17b-3 commits (`cf80a2f..5ee0669`) at 2026-11-16 01:21:35 UTC. Dependency gates (AUD15 at W, AUD16 at A, AUD17 at `5ee0669`, each on a clean tree): the steps `audit` and `deny` PASS (audit 2 s, 2 s and 1 s; deny 0 s each); audit: RustSec: no advisories (warnings denied), ignored with an ADR: RUSTSEC-2026-0173, RUSTSEC-2023-0071, RUSTSEC-2024-0436, RUSTSEC-2025-0141, RUSTSEC-2026-0387, RUSTSEC-2026-0459; deny: advisories, bans, licenses, sources: ok.
- **D-CI14 (opened and closed in this unit; the diagnosis of D-CI12; unit WIN2-DIAG, Q260).** One diagnostic `windows-native` run on W (PR run 43728831159). Transport: the nextest override `success-output = "final"` in `.config/nextest.toml` for four tests, SE-19 `m7_activity::store_backed_source_activity_independent`, PC-13 `m7_persist::write_amplification_measured`, SE-03 `m7_rotation::recipient_retires_old_queue` and the new SE-130 `secret_page::os::tests::w2diag_sqlcipher_pattern_cost`, so that the `W2DIAG`, `W2DIAG-JOB` and `W2DIAG-BENCH` lines they print and SQLCipher's own stderr lines are in the job log of a green run. Deviation (Q260): in W only, the instrumented tests print through a locked stdout handle with `write_all` instead of `println!`. The run: completed, conclusion success, 36 jobs success; `windows-native` job 132856553210 (15:15:15–17:14:00 UTC; 18 059 log lines) printed 3 `W2DIAG` lines (PC-13, SE-03, SE-19), 6 `W2DIAG-JOB` lines (SE-19) and 2 `W2DIAG-BENCH` lines (SE-130); the Linux job `harness` of the same run (job 132856553296; 1906 log lines) printed 3 `W2DIAG` and 6 `W2DIAG-JOB` lines, all with `process=none`.
- **D-CI14 decision table and its evaluation (SE-19, job 132856553210).** The reviewer fixed the table on 2026-11-15, before the run. The inputs are only the lines the code prints and SQLCipher's WARN lines in the shown stderr; the arithmetic is `w2diag_eval.py` (sha256 `5ac9da565c3cda0eee3d1a00606fe9080bc379f9c21bfc652273f50c0e50b568`; M7-LOG21). TT, the decision value, is the sum of the six `W2DIAG-JOB` `wall_ms` = 2 990 417 ms (the `W2DIAG test=SE-19` line: `wall_ms=1174031`, `threads=4`). KF = kernel / (kernel + user) CPU time, UTIL = CPU time / TT, WAITF = wait for the growth mutex `GROW` / TT, LOCKF = (time in `VirtualLock` + time in the working-set set call) / TT, RB = cost per block with headroom / cost per block with the default working set (SE-130), `N_warn` = SQLCipher WARN lines in SE-19's shown stderr.

| Row | Value on SE-19 | Confirms if | Refutes if | Result |
|---|---|---|---|---|
| H1 `GROW` wait | WAITF 0.0001 (wait mean 695 ns, hold mean 8074 ns) | WAITF ≥ 0.20 and wait mean ≥ 5 × hold mean | WAITF < 0.05 | refuted |
| H2 genuine protection cost | KF 0.036; UTIL 0.560; `ws_min` 4 399 104 bytes (4.2 MiB); RB 1.217 | `ws_min` ≥ 16 MiB and RB ≥ 2 and KF ≥ 0.5 with UTIL ≥ 0.6 and WAITF < 0.05; `N_warn` small relative to pre-WIN1 | RB ≤ 1.2 or KF < 0.3 | refuted (KF 0.036 < 0.3) |
| H3 kernel contention in our calls | LOCKF 0.0007 | LOCKF ≥ 0.10 and the mean `VirtualLock` time per call ≥ 10 × SE-130's per-call lock cost in the regime matching `ws_min` | LOCKF < 0.02 | refuted |
| H4 store path | UTIL 0.560; commits per job equal on Windows and on Linux: 4174, 5110, 9783, 10 686, 36 309, 37 108 (sum 103 170) | (a) UTIL ≤ 0.5 with WAITF < 0.05 and (`io_writes` + `io_others` − `N_warn`) / commits ≥ 2, or (b) commits not equal | UTIL ≥ 0.8 and (LOCKF + WAITF) ≥ 0.5 × (1 − CPU_user / TT) | neither confirmed nor refuted |
| H5 SQLCipher WARN storm | `N_warn` 1440 | `N_warn` ≥ 10⁵ | `N_warn` < 10⁴ | refuted |
| none | UTIL 0.560 | UTIL ≥ 0.7, KF < 0.3, WAITF < 0.05, LOCKF < 0.02, `N_warn` < 10⁴ and commits equal | | does not hold (UTIL 0.560 < 0.7) |
| result | | | | inconclusive (fall-through) |

- **D-CI14 further values and consequence.** The same formulas on the two single-world tests (k = 1): PC-13 (TT 470 524 ms) KF 0.074, UTIL 0.338, WAITF 0.0000, LOCKF 0.0010, `N_warn` 814, commits 34 495; SE-03 (TT 391 957 ms) KF 0.025, UTIL 0.340, WAITF 0.0000, LOCKF 0.0005, `N_warn` 751, commits 9651. `failed=0` in every `W2DIAG` and `W2DIAG-JOB` line of the Windows job (our own secret pages). The job log has 3005 lines `sqlcipher_mlock: VirtualLock() returned 0 LastError=1453` (PC-13 814, SE-03 751, SE-19 1440; no other `LastError` value); the Linux job has none. Result: inconclusive. The table's consequence for it: no fix; D-CI14 stays open; a request to the owner for Posten 5 (owner VM, WPR profile of SE-19, and an A/B on the heads `23b7424`, `3f564f8` and `194de59`); a second CI diagnostic run only if the numbers name a specific missing counter. No fix was made on the basis of W. Not measured by W (limitation L3 of the table): the time per commit, page faults, SQLCipher's successful locks.
- **Step table of the stored `windows-native` logs (LOG23, LOG24).** Seconds per step of `cargo xtask step --strict clippy nextest doctest kat harness hello` (each log: `Image: windows-2025-vs2026`, `Version: 20261103.298.1`, `Version: 20261103.629`):

| PR run (head) | clippy | nextest | doctest | kat | harness | hello |
|---|---|---|---|---|---|---|
| 43474391164 (`23b7424`) | 413 | 1194 | 2 | 1832 | 789 | 0 |
| 43539306737 (`d5dfdc7`) | 506 | 1488 | 3 | 2265 | 885 FAIL | 0 |
| 43591576223 (`3f564f8`) | 617 | 1827 | 3 | 2828 | 1313 | 0 |
| 43647712727 (`b5ec47a`) | 643 | 1895 | 3 | 2916 | 1506 | 0 |
| 43668999495 (`467b769`) | 647 | 1893 | 3 | 2918 | 1526 | 0 |
| 43706937667 (`194de59`) | 658 | 1913 | 3 | 2987 | 1482 | 0 |
| 43728831159 (W `595eb14`) | 632 | 1926 | 3 | 2922 | 1550 | 0 |
| 43750760342 (A `cf80a2f`; LOG24) | 644 | 1894 | 3 | 2905 | 1417 | 0 |

- **Step table, reading (arithmetic of this unit on the seconds above).** Against run 43474391164 the steps clippy, nextest and kat took ×1.49 to ×1.59, ×1.53 to ×1.61 and ×1.54 to ×1.63 as long in the six runs from `3f564f8` on (in the run of `d5dfdc7`: ×1.23, ×1.25 and ×1.24; its harness step failed). Clippy executes none of our tests; its time rose in the same factor range as nextest and kat. This is not explained.
- **Q261, the A/B run (D-CI14).** One `windows-native` run of the old code on the CI runners of 2026-11-15: A = `cf80a2f` (tree = tree of `23b7424`), PR run 43750760342 (completed, conclusion success, 36 jobs success), `windows-native` job 132923961894 (2026-11-15 19:08:48–21:04:54 UTC; 14 964 log lines; LOG24; same image lines as above). The decision rule was fixed by the reviewer before the run (recorded in the reviewer's handover of 2026-11-15 17:50 UTC; A was pushed at 19:08:39 UTC); it stands in no repo file and not in the decision table of WIN2-DIAG, whose "inconclusive" row names an A/B on old heads only as part of the owner request (Posten 5) and allows a second CI diagnostic run only if the numbers name a specific missing counter. The rule: PC-13 ≥ 300 s and SE-19 ≥ 800 s → runner environment; PC-13 ≤ 150 s and SE-19 ≤ 550 s → code; between → a further A/B on `3f564f8`. Measured on A (PC-13 = `m7_persist::write_amplification_measured`, SE-03 = `m7_rotation::recipient_retires_old_queue`): PC-13 478.789 s, SE-19 1043.569 s, SE-03 347.659 s, `m7_crash::crash_between_persist_and_send_no_key_reuse` 325.802 s, controls `m6_two_clients::two_clients_direct_tls_loopback` 511.792 s and `two_clients_loopback_tcp` 625.839 s, harness summary 1390.968 s (296 run: 296 passed (14 slow), 16 skipped), steps clippy 644 s, nextest 1894 s, kat 2905 s, harness 1417 s. The same tree on 2026-11-13 (PR run 43474391164): PC-13 94.145 s, SE-19 387.118 s, SE-03 57.509 s, crash test 123.501 s, controls 614.303 s and 603.728 s, harness summary 773.890 s, steps 413, 1194, 1832 and 789 s. PC-13 478.789 s ≥ 300 s and SE-19 1043.569 s ≥ 800 s: the first branch.
- **Verdict (reviewer, engineering; by the A/B rule fixed before the run, its first branch; not a measured cause): runner environment, not product code. D-CI12 and D-CI14 are closed as CI-environment observations on the A/B run (for D-CI14 in place of the table's "stays open" for an inconclusive result). No code fix and no ADR-061 amendment; no change of any test, gate, workflow, budget or threshold.** The observations of §DOCS5 stand as written; the A/B run adds the tree of `23b7424` itself, measured on the runners of 2026-11-15.
- **Not measured.** The cause inside the runner environment: not measured, not explained. The store write time on real Windows hardware: not measured; it needs the owner-operated Windows VM (`cargo xtask win-test`; Posten 5), which is open. Time per commit, page faults and SQLCipher's successful locks (L3 above). Nothing about the cause is stated beyond the refutations of H1, H2, H3 and H5 and the open H4 in the table above.
- **D-CI12 (closed; CI-environment observation).** The table of §DOCS5 with three more columns: `194de59` (PR run 43706937667; LOG22), W `595eb14` (PR run 43728831159; LOG21, with its raw lines as printed by h83; instrumented, with the output shown) and A `cf80a2f` (PR run 43750760342; the tree of `23b7424`; LOG24). The other columns are as in §DOCS5. Closing paragraph: with PR run 43750760342 (A) the tree of `23b7424` itself took 478.789 s (PC-13) and 1043.569 s (SE-19) on the runners of 2026-11-15, against 94.145 s and 387.118 s on 2026-11-13 (×5.09 and ×2.70, arithmetic of this unit); by the verdict above D-CI12 is closed as a CI-environment observation, together with D-CI14, with no code fix.

| Test (seconds) | `23b7424` | `d5dfdc7` | `3f564f8` | `b5ec47a` | `467b769` | `194de59` | W `595eb14` | A `cf80a2f` |
|---|---|---|---|---|---|---|---|---|
| Windows `m7_activity::store_backed_source_activity_independent` (SE-19) | 387.118 | 541.781 FAIL | 949.210 | 1132.569 | 1153.836 | 1099.062 | 1174.054 | 1043.569 |
| Windows `m7_persist::write_amplification_measured` | 94.145 | 127.669 | 398.998 | 601.403 | 643.575 | 542.278 | 470.834 | 478.789 |
| Windows `m7_rotation::recipient_retires_old_queue` | 57.509 | 122.101 | 290.713 | 382.564 | 368.754 | 371.176 | 392.352 | 347.659 |
| Windows `m7_crash::crash_between_persist_and_send_no_key_reuse` | 123.501 | 176.095 | 296.503 | 294.433 | 425.130 | 338.093 | not extracted | 325.802 |
| Windows `m6_two_clients::two_clients_direct_tls_loopback` (control) | 614.303 | 531.614 | 569.463 | 579.855 | 475.436 | 504.436 | not extracted | 511.792 |
| Windows `m6_two_clients::two_clients_loopback_tcp` (control) | 603.728 | 659.185 | 688.129 | 553.942 | 516.596 | 626.292 | not extracted | 625.839 |
| Windows harness summary | 773.890 | 884.409 (268/296 run, 1 failed) | 1286.726 | 1482.254 | 1504.051 | 1449.333 | 1522.374 | 1390.968 |
| Linux SE-19 (job `harness`) | 749.939 | 773.829 | 768.814 | 364.704 | not extracted | not extracted | not extracted | not extracted |
| Linux harness summary (312 tests) | 3572.553 | 4480.224 | 4461.627 | 2374.567 | not extracted | not extracted | not extracted | not extracted |

- **D-CI12 facts (LOG22, LOG24, LOG21, h79b, h84, h87).** LOG22 (run 43706937667; job `windows-native` 132789937039, 11:02:13–13:01:16 UTC, from h79b): SE-19 PASS [1099.062s] (296/296), the harness summary `296 run: 296 passed (14 slow), 16 skipped` (1449.333 s), the workspace nextest `1516 run: 1516 passed (2 leaky)`, step table clippy 658 s, nextest 1913 s, doctest 3 s, kat 2987 s, harness 1482 s, hello 0 s, all PASS; 0 lines containing `LastError=1453`, `Unavailable`, `FAIL [`, `TIMEOUT [`, `panicked at` or `##[error]`; the two `secret_page::os::tests` PASS (0.034 s and 0.214 s); the same runner image. LOG21 (run 43728831159; job 132856553210): the PASS lines SE-19 [1174.054s] (296/296), PC-13 [470.834s], SE-03 [392.352s]; the harness summary `1522.374s 296 tests run: 296 passed (14 slow), 16 skipped`; the three instrumented tests were run with their output shown, which is part of the measurement. LOG24 (run 43750760342; job 132923961894, from h87): SE-19 PASS [1043.569s] (296/296), the workspace nextest `1485 run: 1485 passed (2 leaky)`, step table as above, all PASS; the six counts 0; the same runner image. The tree of `23b7424` has not the two `secret_page::os::tests` of WIN1 (no lines).
- **D-CI13 (open observation; update; not classified, not accepted).** Three more data points. The job `mutants-shard (1)` was the longest shard in each: 229 min in PR run 43706937667 (`194de59`; job 132789937270), 229 min in PR run 43728831159 (W; job 132856553610) and 213 min in PR run 43750760342 (A, the tree of `23b7424`; job 132923962133), against the job budget of 300 min (`("mutants-shard", 300)` of `JOB_BUDGETS`, `xtask/src/expect.rs:2153`; `timeout-minutes: 300` of the job `mutants-shard`, `.github/workflows/ci.yml:371`; both lines unchanged at `5ee0669`). The remaining headroom is 71, 71 and 87 min. Minutes are the job's start to end (h79b, h84, h87), rounded to the minute as in §DOCS5 (whose sums correspond to half to even on an exact half; no exact half occurs in these three runs); the sums are of the rounded values (exact: 4362.9, 4054.2 and 3748.2 min). **Updated by DOCS7 (PR runs 43785816858, 43810117638 and 43901117679; §DOCS7): nine data points; stays open.**

| PR run (head) | longest of the 24 `mutants-shard` jobs | sum of the 24 shards | headroom to 300 min |
|---|---|---|---|
| 43591576223 (`3f564f8`) | 215 min (shard 16) | 3969 min | 85 min |
| 43647712727 (`b5ec47a`) | 246 min (shard 1) | 4069 min | 54 min |
| 43668999495 (`467b769`) | 231 min (shard 1) | 3962 min | 69 min |
| 43706937667 (`194de59`) | 229 min (shard 1) | 4362 min | 71 min |
| 43728831159 (W `595eb14`) | 229 min (shard 1) | 4054 min | 71 min |
| 43750760342 (A `cf80a2f`) | 213 min (shard 1) | 3746 min | 87 min |

- **D-CI13 scatter and limits (update).** `467b769` and `194de59` have identical code (`git diff --numstat`: only `docs/reviews/M07-report.md`, 36 insertions, 2 deletions), so the same mutant set, and the sums of their 24 shards differ by 400 min (3962 → 4362): shard 9 137 → 209 (+72), shard 20 122 → 188 (+66), shard 15 133 → 197 (+64), shard 22 147 → 210 (+63), shard 23 132 → 190 (+58), shard 3 135 → 191 (+56); the largest decrease is shard 8, 210 → 171 (−39; the h74 row of shard 8 is the least certain row, §DOCS5), then shard 19, 168 → 130 (−38). The six sums are 3969, 4069, 3962, 4362, 4054 and 3746 min and the six maxima 215, 246, 231, 229, 229 and 213 min. The headroom of 54–87 min is of the same size as this run-to-run scatter. How much of the longest shard's time was the step, and which mutants make shard 1 long, is not measured. No change of the shard count, the job or step budget, the skip list or any limit in this unit. The observation stays open and is watched on each PR run.
- **D-B80 (evidence).** The sentence appended to the D-B80 line of §WIN1 is SE-130, the `W2DIAG-BENCH` lines of job 132856553210: regime `default` (`blocks_per_round=8192`, `rounds=4`): `lock_ok=700`, `lock_quota=32068`, `lock_other=0`, `ws_min=204800`; regime `headroom` (64 MiB more minimum and maximum working set): `lock_ok=32768`, `lock_quota=0`, `lock_other=0`, `ws_min=67313664`; cost per block 2572.4 ns and 3130.1 ns (RB 1.217). `lock_quota` counts the failures with `ERROR_WORKING_SET_QUOTA`. D-B80 stays recorded as a residual risk, not accepted; the owner item OPEN-M7-B-25 is unchanged.
- **Gate table (§4).** Rows added for PR run 43706937667 (`194de59`), PR run 43728831159 (W; marked diagnostic) and PR run 43750760342 (A; marked diagnostic A/B), after the row of PR run 43668999495, in the form of the existing rows; all three completed, conclusion success, 36 jobs success. No row for PR run 43785816858 (head `5ee0669`; in progress when this was written).
- **Gates.** `cargo nextest run -p xtask`: 324 passed; `cargo xtask step --strict policy` PASS. No ci-fast and no CHANGELOG line (DOCS2 to DOCS5 precedent: a commit under `docs/reviews/` only). The D-CI12 and D-CI13 lines of §DOCS4 and §DOCS5 and the D-B80 line of §WIN1 keep their text and carry an appended marker.

## B17c (WEISUNG M7-B17c; OPEN-M7-B-28 option (C′), D-B86; Q264–Q267, ADR-060 amendment (B17c); modell=claude-sonnet-5-5)

- **Commits.** START `3bb0fc2`; `a0e44b8` fix(core) B17c; this docs commit; the ci-fast evidence commit. Changed code: `crates/secmp-client-core/src/hub.rs`, `crates/secmp-client-core/src/sessions/actor.rs`; `docs/mutants-accepted.md` re-pinned in `a0e44b8` (`hub.rs:582:30` → `hub.rs:651:30`: 69 lines inserted above it, the mutant and its row unchanged).
- **Design.** `Hub` keeps every old send queue in overlap as `Retiring { queue, until, floor: Option<Anchor { from, blur }> }`: `Some` at a switch (`from` = the switch, `blur` = the draw − 1 h), `None` for a queue `resume_overlaps` registers again at a restart (Q267 (a)); `send_periods` holds the period of every send queue a route registered. `Hub::tick` first runs `raise_floors`: per anchored queue `floor_end(from, blur, cell_interval_ms(Params::default(), effective mode, P_q, n))` = `from + min(blur + min(132 · I, 25 h), 48 h + 1 min)`, n = the send queues on its relay; the conversation holding the queue's overlap is asked to `extend_overlap` to that end (Unix = `unix_base` + monotonic) and only on `Some(true)` the hub sets `until = max(until, floor)`. `resume_overlaps` takes the latest end of each `sid` and registers exactly that end when `0 < left ≤ MAX_SEND_OVERLAP_MS`. `Conversation::extend_overlap` writes the new row before it deletes the old one (orphan retry), never shortens, writes an unwritten row with the later end. No change to the row layout (tag 5, 68 bytes), the schema, the wire, `docs/03` or `docs/01`.
- **STOP checks.** No `docs/03`/`docs/01`/wire/label/DDL/vector/`ref/`/backup change; no new dependency, no `unsafe`, no `#[allow]`; all new arithmetic `checked_*`/`saturating_*`; no request outside the slot schedule (§10.5); the floor reads no rotation or `KeyChange` state (§10.1).
- **Red-first.** Thirty-three edits of WEISUNG 2, evidence `docs/reviews/M07-evidence/b17c-red-<id>.txt`, each against the 23 tests SE-105, SE-106, SE-113…SE-117, SE-122, SE-128 and SE-140…SE-153; every edit fails at least one test (counts and locations: WEISUNG 2).
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 307 run, 307 passed (293 before; fourteen new: SE-140…SE-153 — SE-148 added by verification R1, SE-149…SE-151 by the finalizer, SE-152 and SE-153 by verification R2; re-dictated: SE-114). Without `kat`: 49 run, 49 passed (46 before; SE-140, SE-141, SE-149). `cargo fmt --all --check`: no output. clippy (`-D warnings`, all targets, all features): exit 0.
- **Mutants.** `--in-diff` run on `sessions/actor.rs` and `hub.rs`, evidence `mutants-b17c-a0e44b8.txt`: 34 mutants tested in 15m: 28 caught, 6 unviable
- **D-B96 (B17c, recorded).** The example "Low-bandwidth, 10 queues × 80 s → 132 · 800 s ≈ 29.3 h" of the unit's brief multiplied n by `P_q`; by `docs/03` §10.2 the interval is `max(P_q, n · T_LOWBW)` = 300 s (11.0 h), by the round-robin bound of Q264 `(3 + 9) · 30` = 360 s (13.2 h). A floor above 24 h needs I > 654.5 s; realistic maxima (Low-bandwidth ≤ 10 contacts at 80 s plus overlaps, Balanced ≤ 30) are 15.4 h and 14.3 h.
- **D-B97 (B17c, recorded; deviation from the brief's formula, stronger).** The floor is added to the draw's lower bound (`U[L, L + 23 h]`, `L = max(1 h, min(132 · I, 25 h))`) instead of `max(U[1 h, 24 h], 132 · I)`: the latter ends at exactly `switch + 132 · I` with probability (132 · I − 60 min) / 1380 min — 2.0 % at 40 s, 8.4 % at 80 s, 43.5 % at 300 s — and the new queue's first `SEND` follows the switch within U[0, 3 min] (§10.6 (1)), which pairs the old with the new queue (§10.6 (4), §11.1, not in §11.3). Cost: Strict, every switch, `max(0, 132 · P_q − 60 min)` of dummies: 0 / 0 / 28 / 116 min at 10 / 20 / 40 / 80 s (≈ 0.37 / 0.76 MB at 40 / 80 s); Balanced/Low-bandwidth: no extra frames (one per slot), the old queue stays in the round robin up to `min(132 · I, 25 h) − 1 h` longer.
- **D-B98 (B17c, recorded; owner: OPEN-M7-B-31; fail closed, availability).** What remains of D-B86, computed, not measured (span from the switch `u + max(0, min(132·I, 25 h) − 60 min)`, u ~ U[60, 1440] min, k = 131 for a copy of unknown outcome (128 relayed), d = minutes without a link): R0 a link throughout, I ≤ 681.8 s: no hold except the gap of a scheduled link re-handshake (`LINK_LIFETIME` U[6 h, 24 h], the new link's phase U[0, 3 min], handshake time not counted): per re-key inside a count at most 0.17 / 0.12 / 0.04 % at 40 / 80 / 150 s (mean 0.066 / 0.034 / 0.003 %), 0 at 10 / 20 s and from 180 s; ≈ 0.006 % per switch at 40–80 s. R1 downtime inside the process: `132·I > 60 min`: max(0, d − (132 − k)·I)/1380; `132·I ≤ 60 min`: max(0, k·I + d − 60)/1380 — d = 60 min: 1.58 / 3.16 / 4.30 / 4.25 / 4.17 / 3.99 % at 10 / 20 / 40 / 80 / 150 / 300 s (B17b-3: 1.58 / 3.16 / 6.33 / 12.66 / 23.73 / 47.46 %); d = 480 min: 32.02 / 33.60 / 34.73 / 34.69 / 34.60 / 34.42 % (B17b-3: 32.02 / 33.60 / 36.76 / 43.09 / 54.17 / 77.90 %). R2 a restart inside the count (Q267 (a)): a relayed copy as R1 with the time off as d and k = 128 (d = 60 min: 1.55 / 3.09 / 4.15 / 3.96 / 3.62 / 2.90 %); a copy of unknown outcome counts again from the restart (D-B102): as R1 with d = t, the time from the switch to the restart (t = 60 min: 1.58 … 4.30 %, t = 480 min: 32.02 … 34.73 %); an end that passed while the client was off holds (SE-117); a floor not yet durable at the crash: the drawn end. R3 I > 681.8 s (Low-bandwidth n ≥ 21 at 80 s, ≥ 23 at 10 s; Balanced n ≥ 62, ≥ 69; reachable through D-B93): the floor is cut, the end stays uniform. R4 a growth of n or a mode change after a restart is not followed for the queues that restart registered; the hub uses `Params::default()` slot lengths (as `Core::rotate`). R5 more than one missed slot per 132, the in-flight reordering and the withholding relay of ADR-060's consequences: unchanged.
- **D-B99 (B17c, recorded).** The sender may outlive the recipient's old queue (window `U[1 h, 24 h]`, `QUEUE_DEL` after an empty `FETCH` + `U[1 min, 60 min]`); a `SEND` then gets `ERR_NOQUEUE` (`secmp-relay/src/exec.rs:156-158`), the scheduler marks the route dead and reports `queue_lost` (`scheduler/core/mod.rs:1097-1103`), and `Conversations::queue_lost` → `on_overlap_lost` clears that queue's marks (Q241): the queue is gone, no copy can reach the peer — a proof-based release. Dummies continue to the dead route until the end (§10.3). A Strict recipient at the same period rarely sees an empty `FETCH` while the sender sends and keeps the old queue until shortly after the sender stops (up to ≈ 2 h longer at 80 s than before; availability only). `CELL_TTL` (7 d) and `QUEUE_IDLE_TTL` (30 d) exceed every overlap.
- **D-B100 (B17c, recorded).** Store writes: one row write and delete per raise (a switch with 132 · I > 1 h, each growth of I); none at a restart. An old queue's sender seed stays at rest until its later end (D-B90: up to 48 h + 1 min after the switch; restarts do not lengthen it, SE-150).
- **D-B101 (B17c, recorded).** Re-dictated tests: SE-114 (restart bound `MAX_SEND_OVERLAP_MS`); SE-113, SE-116 and SE-128 keep their B17b-3 assertions (only the access to the hub's retiring entry follows the new struct).
- **D-B102 (B17c, recorded; finding on D-B86, revised).** After a restart an overlap row's copy of unknown outcome takes the id of the first `OK_SEND` after the restart (`adopt`, token 0) and needs 131 cells from there; the B17b-3 memo's formula counted the downtime but not this restart of the count. With Q267 (a) the stored end is kept, so that count may not complete before it: the `KeyChange` holds (fail closed; D-B98 R2). A re-anchor at the restart was rejected (verification R1 B-1, M-1).
- **D-B103 (B17c, recorded; amplifies D-B93; verification R1 m-3).** Old send queues now live up to 48 h + 1 min after their switch (was 24 h + 1 min): the window of D-B93 doubles, in Balanced/Low-bandwidth a large n raises every anchored old queue's floor (up to the 25 h term cap), and each growth of n rewrites one row per anchored old queue (O(k) per `RouteUpdate`, O(k²) in total). No cap is built; OPEN-M7-B-29 (1) stays open. (CAP: at most 6 anchored old queues per contact, so at most 6 rewrites per contact and growth of n, Q268.)
- **Recorded.** OPEN-M7-B-28 closed for a link throughout (Q264–Q267); OPEN-M7-B-31 opened (owner: the owner may object to C′ or its shifted form; D-B98 remains). Verification R1 (DO NOT DELIVER): B-1 (restart ends at a common instant) and M-1 (restarts keep an old queue without bound) closed by Q267 (a), SE-145, SE-150; M-2 (the cap on the sum fixed the end) closed by Q266 (revised), SE-141, SE-149; m-1 closed by SE-148; m-2 and m-3 recorded (D-B98 R0, D-B103). The finalizer's term cap is 25 h, not the 25 h + 1 min R1 proposed: the draw's fallback (`blur` 23 h + 1 min) would otherwise reach 48 h + 2 min, beyond the restart bound. Hand mutants beyond cargo-mutants: the red edits of WEISUNG 2 (all killed); equivalent: `raise_floors` ignoring a missing anchor (a queue registered at a restart has no period entry either), `checked_add` → `saturating_add` of blur and term in `floor_end` (both reach the bound), `send_periods.remove` at the drop (ids are never reused), a `break` after the first conversation holding the overlap (one conversation holds a queue's overlap), and R1's equivalents (the relay filter of n with one relay, `checked_sub` → `saturating_sub` in the restart predicate, `unwrap_or(0)` of a usize→u64 conversion). Verification R2: two test gaps closed insert-only — SE-152 (`raise_floors` asking only the first conversation survived every test) and SE-153 (a restart clipping a stored end at `OLD_SEND_MS` survived every test); also equivalent: a missing period taken as a default (every anchored queue has a period).

## RNG (WEISUNG M7-RNG; finding EXT2d-1 of the external review at `37abef9`, adjudicated MINOR; Q276, ADR-060 amendment (RNG); amends B17c's Q266, hence after §B17c; modell=claude-sonnet-5-5)

- **Commits.** START `91ebdb8`; fix(core) RNG (`crates/secmp-client-core/src/hub.rs`, `persist.rs`, `timing.rs`); this docs and evidence commit.
- **Design.** `Hub::register_route` draws the old queue's overlap after the byte-equal check (Q222), the Q236 skip and the cap (Q268) and before `alloc_send`; a failed draw returns "not registered" with nothing changed, and `Hub::pump` puts that route and the contact's later ones back (`StorePersist::restore_routes`, ahead of any committed since, so a newer route never falls behind an older one), writes the current route back to the store and returns `Unavailable`; the next pump registers them. The constant fallback (`unwrap_or(OLD_SEND_MS)`) is removed; the constants and the floor are unchanged. Test-only seam `TimingRng::failing` (`cfg(test)`).
- **STOP checks.** No `docs/03`/`docs/01`/wire/label/DDL/vector/`ref/`/backup change; no new dependency, no `unsafe`, no `#[allow]`; no new public API.
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 329 run, 329 passed (327 before; SE-179, SE-180). Without `kat`: 50 run, 50 passed (unchanged). SE-141 changed only in its names (the share `OLD_SEND_MS − 1 h` is no longer called the fallback; the same assertions). `cargo fmt --all --check`: no output; clippy (`-D warnings`, all targets, all features): exit 0; policy step: evidence `docs/reviews/M07-evidence/rng-policy.txt`; ci-fast: evidence `docs/reviews/M07-evidence/rng-ci-fast.txt`.
- **Recorded.** EXT2d-1 closed. A restart between the refused pump and the next one registers the queue sent to and loses the kept route until the peer sends one again (EXT2d-2, D-B71; the route journal of a later unit). The other timing draws of the crate replace no failed draw by a constant (Q276).

## RNG2 (WEISUNG M7-RNG2; finding X-1 of the cross-review of `37abef9..0dfdb10`, MAJOR; Q278, ADR-060 amendment (RNG) corrected; corrects §RNG, hence after it; modell=claude-sonnet-5-5)

- **Commits.** START `0dfdb10`; fix(core) RNG2 (`crates/secmp-client-core/src/hub.rs`); this docs commit; an evidence commit (policy and ci-fast).
- **Design.** In the refusal branch of `Hub::pump` (EXT2d-1) the call that wrote the route sent to back to the contact's stored routes is removed. The kept routes still go back ahead of any committed since (`restore_routes`), and `pump` still returns `Unavailable`. The stored routes therefore stay as the receive commit wrote them before the cell was acked, and a crash after a refusal is a crash before the pump (D-B71, D-B75, D-B87). Nothing else in product code changes. The Q236 skip and the cap's refusal (Q268) keep their write-back (their route is not followed, by decision).
- **Several routes of one contact in one pump (Q242).** [C1 switched, C2 refused]: the store holds C2 as committed; a restart registers C2 (no draw at an open) and B's overlap row, if it was written, as after any switch (Q253, within the cap); C1 has no row, and a `KeyChange` marker on C1 holds (fail closed, D-B87). [newer X refused, stale Y last]: the store holds Y, a restart registers Y, and X is lost until the peer sends a route again, which is the state of D-B75. Neither case is worse than a crash before the pump.
- **STOP checks.** No `docs/03`/`docs/01`/wire/label/DDL/vector/`ref/`/backup change; no new dependency, no `unsafe`, no `#[allow]`; no new public API. `docs/mutants-accepted.md` unchanged: its only `hub.rs` row (`697:30`) lies above the removed line.
- **Tests.** SE-179 re-dictated (it asserted the write-back, "the store names B"): the receive commit stored C, the stored routes after the refusal are byte-identical to the receive commit's, and a restart after the refusal (the profile reopened from its files) registers C first. No new test. nextest of `secmp-client-core` (`--features kat`): 329 run, 329 passed (unchanged). Without `kat`: 50 run, 50 passed (unchanged). `cargo fmt --all --check`: no output; clippy (`-D warnings`, all targets, all features): exit 0; policy step: evidence `docs/reviews/M07-evidence/rng2-policy.txt`; ci-fast: evidence `docs/reviews/M07-evidence/rng2-ci-fast.txt`.
- **Recorded.** X-1 closed. In §RNG, "writes the current route back to the store" (Design) and the first sentence of **Recorded** are superseded by this section. X-2 and X-3 are HB-7 and HB-8 (`docs/HARDENING-BACKLOG.md`); X-4 to X-6 are notes without action.

## REST (WEISUNG M7-REST; the last M7 residuals under ADR-062: OPEN-M7-B-18, -20, -21, -22, -23, D-B83, D-1 to D-3 of the delta cross-review of RNG2 and FZ; Q279; after §RNG2, which D-1 and D-2 concern; modell=claude-sonnet-5-5)

- **Commits.** START `165c2eb`; `791184c` test(sys-mem) REST (`crates/secmp-sys-mem/src/secret_page/unix.rs`; comments in `xtask/src/expect.rs` and `crates/secmp-proto/tests/fuzz_max_len.rs`); this docs commit; the evidence commit (`ref/` pytest, sys-mem tests, policy, ci-fast). No `docs/03`/`docs/01`/wire/label/DDL/vector/`ref/`/backup change, no new dependency, no `unsafe`, no `#[allow]`, no workflow change.
- **Sorting (Q279, ADR-062).** Built: the one `/proc/self/mem` handle (OPEN-M7-B-20 in part) and the comment wording of HB-9 (D-3). Hardening backlog: HB-9 (the size question, owner), HB-10 = OPEN-M7-B-18 (the SIGBUS fails closed; `unsafe` code and kernel measurements), HB-11 = the rest of OPEN-M7-B-20 (a CI step: owner), HB-12 = OPEN-M7-B-21, HB-13 = OPEN-M7-B-23 (mutation testing left the PR path, ADR-047 Amendment 14). OPEN-M7-B-22: closed by B22 (`86c292f`), no action. Docs: D-B83 (the margin of 2 is a heuristic), D-B113, the ADR-060 (RNG) correction's wording (D-2), the README banner (no milestone number), CHANGELOG lines for ADR-062 and REST.
- **Design.** `assert_protected` (Linux, `MemfdSecret`) opens `/proc/self/mem` once; `read_own_memory` takes that handle, so a failed open fails the control read and can no longer satisfy the negative read of the data page (EXT2c-8). Test code only (`#[cfg(test)]`); the predicate itself (ADR-059) is unchanged. The `FUZZ_MAX_LEN` values and the assertions of `fuzz_max_len.rs` are unchanged; only comments change.
- **Tests.** Evidence `docs/reviews/M07-evidence/rest-sysmem.txt` (`cargo nextest run -p secmp-sys-mem`, the same count as at START), `rest-policy.txt`, `rest-ci-fast.txt`. `cargo fmt --all --check`: no output; clippy (`-D warnings`, all targets, all features) of `secmp-sys-mem`, `secmp-proto`, `xtask`: exit 0. Mutants: not run (ADR-047 Amendment 14, ADR-062).
- **ref/.** `.venv/bin/python -m pytest -q` in `ref/`: 1009 tests passed, rc 0 (the file holds only progress lines — 1009 dots, no failure; `addopts = -q` plus `-q` prints no summary line) (evidence `docs/reviews/M07-evidence/rest-ref-pytest.txt`; last known before: 1009 passed, 2026-11-12).
- **D-B113 (REST, recorded; D-1 of the delta cross-review of RNG2 and FZ; with HB-7).** When a newer route X is refused for want of randomness and a stale route Y was committed last, the stored row is Y for as long as the operating system's randomness keeps failing; before RNG2 the next pump's write-back ended that state. A crash in that time registers Y — if Y names an old overlap queue, that queue — as the current queue: the window of D-B71, made as long as the outage. It needs a persistent failure of the OS randomness, a stale route and a crash, and is no worse than the state of a crash before the pump.
- **Recorded.** OPEN-M7-B-18, the rest of OPEN-M7-B-20, OPEN-M7-B-21 and OPEN-M7-B-23 deferred to the hardening phase (HB-10 to HB-13); D-1 (D-B113, HB-7), D-2 (docs/08) and D-3 (HB-9) of the delta cross-review of RNG2 and FZ handled.

## RJ (WEISUNG M7-RJ; finding EXT2d-2 of the external review at `37abef9`, adjudicated MAJOR; D-B71, D-B75, D-B87; Q280, ADR-060 amendment (RJ); an M7 unit — planned as the first M8 unit, pulled forward on 2026-11-18 because M7 stays open for Phase C; modell=claude-sonnet-5-5)

- **Commits.** START `c02e209`; fix(core) RJ `b88fd4b` (`crates/secmp-client-core/src/hub.rs`, `persist.rs`, `sessions/actor.rs`, `sessions/mod.rs`, `sessions/tests.rs`; `fuzz/fuzz_targets/client_control_rows.rs` and the seed `fuzz/corpus/client_control_rows/journal-relay-queue`; `xtask/src/expect.rs`; `docs/mutants-accepted.md`, the place of its `hub.rs` row moved from `697:30` to `848:30`, same code); this docs commit; an evidence commit (policy and ci-fast).
- **Design.** The receive commit journals a received route (CONTROL row tag 6, `6 ‖ RouteUpdateBody` of the first `RelayQueue` route, 157–446 bytes, sealed like every CONTROL row) instead of writing the contact's stored routes, which are now the route the hub applied. `Hub::pump` applies each contact's journaled routes in commit order through `Hub::follow`, each in one store transaction with its outcome (a switch: the old queue's overlap row, the new current route, the journal row's delete; a re-sent route: the delete; a Q236 skip or the cap: the write-back of the current route and the delete); the `AddSend`, the registration and the switch follow the commit. A failed draw or transaction changes nothing and keeps the route and the later ones, with their rows, for the next pump. An open reads the journal rows into the session's route list in `ord` order; the next pump applies them. The overlap row is written before the switch with the `KeyChange` copies the switch leaves (`Conversation::copies_at_switch`). Crash points (after a receive commit; inside the pump before the switch's transaction; after it, before the `AddSend` is taken; after it is taken; after the pump): each restarts into the state before the route, which the next pump applies, or the state after it.
- **STOP checks.** No `docs/03`/`docs/01`/wire/label/construction/DDL/vector/`ref/`/backup change; no new dependency, no `unsafe`, no `#[allow]`; tag 6 was free (only negative tests and two seeds used it, still refused). Old stores open as before (SE-187). `journal_of`'s canonical check compares the re-encoded body (it holds a send seed) in constant time (`ct_eq`; cross-review RJ-1, MAJOR, fixed before delivery).
- **Tests.** SE-181 to SE-188 new (A1: SE-181, SE-183 to SE-185 and SE-179; A2: SE-182, SE-188; A4: SE-186 and FZ-05; A5: SE-187). Re-dictated, because they pinned the receive commit's write of the stored routes: SE-01, SE-82, SE-95 (moved case), SE-164 (was D-B107), SE-179, the B-4c killer `set_verified_maps_the_store_refusal`; SE-166 text only. nextest of `secmp-client-core` (`--features kat`): 340 run, 340 passed (332 before). Without `kat`: 51 run, 51 passed (unchanged). xtask G7-23 (`fuzz_target_control_rows`): passed. `cargo fmt --all --check`: no output; clippy (`-D warnings`, all targets, all features): exit 0; fuzz build and 120-s smoke of `client_control_rows`: no crash; policy step: evidence `docs/reviews/M07-evidence/rj-policy.txt`; ci-fast: evidence `docs/reviews/M07-evidence/rj-ci-fast.txt`.
- **Closed.** For stores written from RJ on: D-B71 and D-B75 (a stale route committed last before a crash no longer becomes current), D-B87 (a route committed before a crash no longer loses the old queue's overlap; an overlap row whose write fails refuses the switch instead of being retried after the `AddSend`), D-B107 (a refused route committed before a crash is refused again, not made current), D-B113 (the outage of HB-7 no longer leaves a stale route stored). EXT2d-2 closed.
- **D-B114 (RJ, recorded).** (a) An overlap end not yet durable at a crash is drawn again when the next pump applies the journaled route: a fresh `U[1 h, 24 h]` from the replay, the floor anchored there; no end at a fixed distance from the restart. (b) A binary from before RJ cannot open a store that holds a journal row (Q251, fail closed): no downgrade. (c) A store-level attacker can delete a journal row (the acked route is not applied: availability) or replay one at its own `ord` (a route the peer once sent; within the cap) — no more than the replay of an older stored route allows today (D-B79, D-B85). (d) A store written before RJ whose last receive commit stored a route the hub had not applied opens as before, once (SE-187). (e) While every pump is refused, journal rows accumulate (HB-15).
- **Known gaps.** SE-95's hub-level "moved" case (B's marker holds while C is current after a restart) is gone with RJ — a restart now registers B; the property stays covered at session level by SE-96 and SE-102 (cross-review RJ-4). The structured mode of FZ-05 never builds a valid journal row (unknown route kinds only); valid tag-6 rows reach the fuzzer only through the seed `journal-relay-queue` and its mutations (cross-review RJ-5, HB-16).
- **Backlog.** HB-14 (test-only overlap retry path), HB-15 (journal growth during refusals; a permanently failing apply transaction, RJ-2), HB-16 (child-process crash inside the switch transaction; a valid journal row in FZ-05's structured mode).

## DOCS7 (WEISUNG M7-DOCS7; D-CI13 updated with the seventh to ninth data points, the time estimates of SE-107 and SE-95 recorded, PR-run rows; docs only; modell=claude-sonnet-5-5)

- **Commit.** START `37abef9`; one docs commit (`docs/reviews/M07-report.md` only). Sources, all read-only and of 2026-11-16: the reviewer's run queries h90, h93 and h96 (per job its name, status, conclusion, id, start and end; the two lines above each table give the run's status and conclusion: `completed` and `success` in all three) and, for the time estimates, the committed `ci-fast` evidence files named below. The job lists carry no run id and no head: their attribution to PR run 43785816858 (head `5ee0669`; h90), PR run 43810117638 (head `3bb0fc2`; h93) and PR run 43901117679 (head `37abef9`; h96) is the reviewer's, by its run queries (the first jobs start 01:21:45, 05:25:24 and 15:52:18 UTC; `5ee0669` was pushed at 01:21:35 UTC, §DOCS6). Each list has 36 jobs with 36 different job ids, all `completed` with conclusion `success`, among them the 24 jobs `mutants-shard (0)` to `(23)`.
- **D-CI13 (open observation; update; not classified, not accepted).** Three more data points, the seventh, eighth and ninth. The longest shard was `mutants-shard (3)` with 234 min in PR run 43785816858 (`5ee0669`; job 133033071961), `mutants-shard (15)` with 237 min in PR run 43810117638 (`3bb0fc2`; job 133109695381) and `mutants-shard (7)` with 241 min in PR run 43901117679 (`37abef9`; job 133417671879), against the job budget of 300 min (at `37abef9`: `("mutants-shard", 300)` of `JOB_BUDGETS`, `xtask/src/expect.rs:2153`, and `timeout-minutes: 300` of the job `mutants-shard`, `.github/workflows/ci.yml:371`; neither line changed between `5ee0669` and `37abef9`). The remaining headroom is 66, 63 and 59 min (to two decimals: 66.35, 63.17 and 58.85 min). Minutes are the job's start to end (h90, h93, h96), rounded to the minute as in §DOCS5 and §DOCS6 (on an exact half: half to even, the rule §DOCS6 reads from the sums of §DOCS5; the one exact half in these three runs is shard 5 of PR run 43785816858, 8250 s = 137.5 min, rounded to 138 by half to even and by half up alike); the sums are of the rounded values, as in the six earlier rows (exact: 4123.8, 4217.9 and 4275.85 min; the ninth exact sum rounds to 4276, the sum of its rounded values is 4275).

| PR run (head) | longest of the 24 `mutants-shard` jobs | sum of the 24 shards | headroom to 300 min |
|---|---|---|---|
| 43591576223 (`3f564f8`) | 215 min (shard 16) | 3969 min | 85 min |
| 43647712727 (`b5ec47a`) | 246 min (shard 1) | 4069 min | 54 min |
| 43668999495 (`467b769`) | 231 min (shard 1) | 3962 min | 69 min |
| 43706937667 (`194de59`) | 229 min (shard 1) | 4362 min | 71 min |
| 43728831159 (W `595eb14`) | 229 min (shard 1) | 4054 min | 71 min |
| 43750760342 (A `cf80a2f`) | 213 min (shard 1) | 3746 min | 87 min |
| 43785816858 (`5ee0669`) | 234 min (shard 3) | 4125 min | 66 min |
| 43810117638 (`3bb0fc2`) | 237 min (shard 15) | 4218 min | 63 min |
| 43901117679 (`37abef9`) | 241 min (shard 7) | 4275 min | 59 min |

- **D-CI13 scatter and limits (update 2).** Measured: the longest shard was shard 1 in five of the six earlier data points (shard 16 in the first) and was shard 3, shard 15 and shard 7 in these three. The headroom was 87, 66, 63 and 59 min in the last four data points; the smallest of the nine is 54 min (PR run 43647712727, also the largest longest-shard value, 246 min), and the ninth is 5 min above it. `5ee0669` and `3bb0fc2` have identical code (`git diff --numstat`: only `docs/reviews/M07-report.md`, 73 insertions, 4 deletions), so cargo-mutants had the same source in both runs (the mutant lists of the shards are not compared in this unit), and the sums of their 24 shards differ by 93 min (4125 → 4218); the largest increases are shard 5 138 → 217 (+79), shard 15 163 → 237 (+74), shard 1 153 → 221 (+68), shard 20 141 → 205 (+64); the largest decreases are shard 23, 219 → 131 (−88), shard 9, 219 → 149 (−70), and shard 3, 234 → 190 (−44); 11 shards are longer and 13 shorter. The largest change of one shard in this pair is 88 min (in the pair of §DOCS6: 72 min), more than the smallest headroom of the nine data points (54 min). `37abef9` differs from `3bb0fc2` in code (B17c, `a0e44b8`: `hub.rs`, `sessions/actor.rs`), so that pair is not a same-code pair; the sums differ by 57 min (4218 → 4275). The nine sums are 3969, 4069, 3962, 4362, 4054, 3746, 4125, 4218 and 4275 min and the nine maxima 215, 246, 231, 229, 229, 213, 234, 237 and 241 min. How much of the longest shard's time was the step, which mutants make a shard long and why the longest shard differs from run to run is not measured. D-CI13 stays open. No change of the shard count, the job or step budget (`MUTANTS_STEP_TIMEOUT_SECONDS` 16 800 s = 280 min, `xtask/src/expect.rs:953` at `37abef9`), the skip list or any limit is made or decided in this unit: such a change is an amendment of ADR-047 or ADR-045 and goes through the reviewer. The observation is watched on each PR run (per-shard job minutes against 300 min).
- **Time estimates of SE-107 and SE-95 (recorded observation; no estimate changed).** At `37abef9`, `docs/reviews/M07-planning/TEST-SPEC-M7.md` defines its column "Est." in line 61 ("expected runtime on the 4-vCPU runner; rows ≥ 60 s are candidates for `MUTANT_HARNESS_SKIP_TESTS`"); that last column says 6 s for SE-107 `sessions::tests::overlap_row_names_the_copies_at_the_switch` (line 303) and 3 s for SE-95 `hub::tests::restart_reads_the_marker_of_the_sent_queue` (line 291). `git grep -n 'TEST-SPEC' -- xtask .github .config` at `37abef9` finds the name only in comments and string literals and no reader of `TEST-SPEC-M7.md`; no gate that reads the column was found. Measured in the committed `ci-fast` evidence of `docs/reviews/M07-evidence/` (nextest `PASS` lines; a file that has the test has it once in its `nextest` step, the workspace run, and once in its `kat` step, the run of `secmp-client-core` with `--features kat`): SE-107 in 8 lines of `ci-fast-b17b3-1-c0df9b5.txt`, `ci-fast-b17b3-2-c0df9b5.txt`, `ci-fast-b17c-1-a0e44b8.txt` and `ci-fast-b17c-2-a0e44b8.txt`, 7.797 s to 9.338 s (smallest `ci-fast-b17c-2-a0e44b8.txt:2265`, largest `ci-fast-b17b3-2-c0df9b5.txt:1366`); SE-95 in 12 lines of those four files and of `ci-fast-b17b2-1-4f0d59f.txt` and `ci-fast-b17b2-2-4f0d59f.txt`, 5.811 s to 7.292 s (smallest `ci-fast-b17c-1-a0e44b8.txt:2179`, largest `ci-fast-b17b2-1-4f0d59f.txt:2118`). All 20 lines are above the estimate. These files come from `cargo xtask ci-fast` of the units and do not state the CPU count of their host; `TEST-SPEC-M7.md` does not name the host of "the 4-vCPU runner", and the time of these two tests in the CI jobs of the three PR runs is in no file of this unit. Not measured: the time of the two tests alone, and the reason for the difference to the estimate. No gate fails and no test result changes; `TEST-SPEC-M7.md` is not edited in this unit (the rows keep 6 s and 3 s; whether the estimates are corrected is the reviewer's decision).
- **Gate table (§4).** Rows added for PR run 43785816858 (`5ee0669`), PR run 43810117638 (`3bb0fc2`) and PR run 43901117679 (`37abef9`), after the row of PR run 43750760342, in the form of the existing rows as far as the job lists of this unit carry it (the test lines of `windows-native` are not extracted and say so); all three completed, conclusion success, 36 jobs success. They complete the gap named in §DOCS6 (no row for PR run 43785816858).
- **Gates.** `cargo nextest run -p xtask`: 324 passed; `cargo xtask step --strict policy` PASS. No ci-fast and no CHANGELOG line (DOCS2 to DOCS6 precedent: a commit under `docs/reviews/` only). The D-CI13 line of §DOCS6 keeps its text and carries an appended marker.

## CAP (WEISUNG M7-CAP; OPEN-M7-B-29 (1) option (B), D-B93, D-B103; Q268–Q271, ADR-060 amendment (CAP); modell=claude-sonnet-5-5)

- **Commits.** START `eb2d5cb`; `de62a20` fix(core) CAP; `f12e9c3` chore(supply-chain) ADV2 (Q277, ADR-051 Am. 10; ci-fast 1 of `de62a20` red on RUSTSEC-2026-0542/0543, `ci-fast-cap-1-red-de62a20.txt`); this docs commit; the ci-fast evidence commit. Changed code: `crates/secmp-client-core/src/hub.rs` only; `docs/mutants-accepted.md` re-pinned in `de62a20` (`hub.rs:651:30` → `hub.rs:685:30`: 34 lines inserted above it, the mutant and its row unchanged).
- **Design.** `MAX_SEND_OVERLAPS` = 6; every `Retiring` names its contact; `Hub::overlaps_held` counts a contact's old send queues in overlap. `register_route`: after the byte-equal check and the Q236 skip, a contact with a current send queue and 6 old ones gets no new queue — `store_current_route` and return, before `alloc_send`, the draw and `keep_overlap`. `resume_overlaps`: after the end filter and the Q236 skip, a row is skipped once its contact holds 6. No change to `sessions/actor.rs`, the row layout, the schema, the wire, `docs/03` or `docs/01`. Design note with the candidates × criteria table: (B1) drop the oldest overlap — rejected (an end shortened, an old-end/new-start coincidence); (B3) a pending route registered when a slot frees — rejected (a start at the instant of an end; a durable pending route would need a new row kind); (B2) refuse — chosen (D-B104).
- **STOP checks.** No `docs/03`/`docs/01`/wire/label/DDL/vector/`ref/`/backup change; no new dependency, no `unsafe`, no `#[allow]`; no new public API or event; no request outside the slot schedule (§10.5); nothing durable added.
- **Red-first.** The edits of WEISUNG 2, evidence `docs/reviews/M07-evidence/cap-red-<id>.txt`, each against the twenty-two tests SE-114, SE-144, SE-154…SE-165 and SE-171…SE-178; every edit fails at least one test (counts and locations: WEISUNG 2).
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 327 run, 327 passed (307 before; twenty new: SE-154…SE-163 of the planner, SE-164, SE-165, SE-171, SE-172 of verification R1, SE-173, SE-174 of verification R2, SE-175…SE-177 of verification R3, SE-178 of verification R4, strengthened by verification R5). SE-144 changed only in its hand-made `Retiring` (the new `contact` field), no assertion. Without `kat`: 50 run, 50 passed (49 before; SE-163). `cargo fmt --all --check`: no output. clippy (`-D warnings`, all targets, all features): exit 0.
- **SE-178 (verification R4, strengthened by R5; what it compares and what it cannot see).** A structural test of the refusal: one world — two contacts, each at the cap; the first with a `KeyChange` held on an old queue, a message relayed and one queued; the second with its `KeyChange` planned on its current queue and our rotation's `RouteUpdate` pending — is closed and its store copied (two builds would differ in the hedged signature of the `KeyChange`), and both copies are opened; in both an accept waits for its `LINK_GET` and the guest's invitation has expired with no tick since (R5). In A a route of each contact (another period) is refused; B receives the same cell, its routes never reach the hub and only the current routes are written back. After the refusal and after time to an end and its tick, the refused route sent again (it registers) and further routes until every old queue of the first contact was switched in this process (R5: a queue registered at an open has no floor and no period, so the first refusal cannot touch either), a second refusal then (R5), our rotation at the cap and a restart it compares: every scheduler action; every field of the hub (current and old send queues with contact, end and floor, routes, targets, periods, previous queues, the next queue id, receive queues, invitation queues, accepts waiting, the invitation check, pending actions) and of the core (events, ops, view, settings, routes changed, rotations, clock) and the next draw of both timing streams; every accessor of each conversation (send and receive queues, `T_RS`, receipts, `KeyChange` state, overlaps read, the ratchet state, received, partials, receipts due, mapped cells, message-key digests, live controls, trust, may-send); the store opened (contact rows, routes, queues, session rows, pending controls with overlap rows and markers, handshake, previous identity, outbox, history ids) and raw (every row of every table, integers and text as stored, sealed blobs by length); and a digest of the next cell of every send queue. Restart part: 8 overlap rows of one contact against the same store with the first 6 — the same open but for the 2 rows read and not registered, which the first preparation deletes; then everything equal. It cannot see: sealed bytes themselves (fresh nonces; compared opened or by length), a conversation's private state without an accessor (the plan, cells in flight, `relayed_at`, `seen`, its events, the marker `sid` but through the rows it writes — the next cells and the store show what leaves the conversation), the store's write count (the refusal writes the same current route once more: identical opened bytes), the process-global `kat` counters, the core's source factory (a stateless `OsSource` in the product), and an effect equal in A and B (a change to every route's or every open's handling; those stay with SE-154…SE-177 and its own checks of no action, the cap, the later registration and the rotation).
- **Mutants.** `--in-diff` run on `hub.rs`, evidence `mutants-cap-de62a20.txt`: 8 mutants tested in 14m: 8 caught
- **D-B104 (CAP, recorded).** The mechanism: OPEN-M7-B-29 (1)'s sketch "drop the oldest overlap" (B1) ends an old queue at the instant the new one is registered — whose first `SEND` follows within U[0, 3 min] (§10.6 (1)) — which pairs the two queues (the lesson of D-B97), and shortens an end below its floor; a pending route registered when a slot frees (B3) starts a queue at the instant another ends (with a random delay: a new end→start relation instead), and a durable pending route would need a new CONTROL row kind. The refusal (B2) changes no start and no end: the only starts stay at a `RouteUpdate`'s arrival; a contact that floods routes can make its own next route start right after one of its own old queues ends, which links only two of our send queues to that contact, both made by it and both known to it (at the base it could cause the same, later by at most one of its own fetch periods: it sees its old queue fall silent).
- **D-B105 (CAP, recorded; availability, fail closed).** No global cap: n ≤ 7·c (computed). D-B98 R3 stays reachable — by one hostile contact beside ≥ 14 other send queues (Low-bandwidth 80 s, n ≥ 21), by ≥ 3 hostile contacts alone (Low-bandwidth 80 s; 10 s: ≥ 4, or 3 beside 2 other queues), by ≥ 9 (Balanced 80 s, n ≥ 62) or ≥ 10 (10 s, n ≥ 69); before CAP one contact alone. In Balanced/Low-bandwidth the round robin is shared (§10.2): a hostile contact's 7 queues lengthen another queue's interval by at most 6·T (60 s / 180 s) and its floor term with it.
- **D-B106 (CAP; not accepted as a residue — open: OPEN-M7-B-32, (B) a sender-side guard built as its own unit CAP2 before the M7 merge review, (C) owner = OPEN-M7-B-29 (1) (C)).** `docs/03` sets no rate for rotations on demand or relay changes (`docs/02` §4.3). A peer that sends a 7th `RouteUpdate` to a new queue within 48 h + 1 min is not followed: the client keeps sending to the queue the peer retires; the peer fetches it U[1 h, 24 h] more (§10.6 (4)), after its `QUEUE_DEL` the `SEND`s get `ERR_NOQUEUE` (dead route, dummies continue, §10.3, D-B99) and real messages stay unconfirmed (`NotConfirmed` after `T_RS`) until the peer's next `RouteUpdate` after one of its old queues ended. The peer does not send the refused `RouteUpdate` again (it was relayed and received), so for a peer that rotates only on the 30-day cadence that is its next rotation, up to 30 days later; meanwhile every `SEND` answered with `ERR_NOQUEUE` takes the existing queue-lost path (the unreceipted messages and the control contents are planned again, as at the base for any deleted queue), and a message not relayed within 30 days is surfaced as failed (§10.4). This client's own `Request::Rotate` has no rate limit, so two clients of this code produce it when a user rotates towards one contact more than 6 times within 48 h + 1 min; a sender-side guard in the client (no spec change: our own on-demand rotation refused or deferred when it would be the 7th `RouteUpdate` to a new queue within 48 h + 1 min) is not built in CAP — OPEN-M7-B-32, unit CAP2. No app event is raised for it.
- **D-B107 (CAP, recorded).** A crash after the receive commit of a refused route (it stores that route, `persist.rs`) and before the write-back: the restart registers the stored route as the contact's current queue and not the queue it sent to before (that one had no overlap row) — as a crash before any pump at the base; a marker on it holds (fail closed); the number of queues does not grow. Rows beyond the cap at an open exist only through a store written by an adversary (D-B79, D-B85, D-B91) or an orphaned row with the clock set back; they are skipped (Q270), a `KeyChange` copy there holds (SE-159). An undecodable overlap row still fails the open (B17b-3), but a contact cannot cause one (the client encodes every row).
- **D-B108 (CAP, recorded).** Hand mutants beyond cargo-mutants: thirty of the planner on every new condition, killed by SE-154…SE-163 except six; twenty-two of verification R1 (the contact field at both `Retiring` sites set to the test contact's id, the count global at the open only, the count of later or earlier contacts, the guard on any contact's current queue, a queue id spent on a skipped row, a queue past its end not counted, among others): seven of them survived the planner's tests and are killed by SE-165, SE-171 and SE-172; four more are equivalent (an old queue counted only while its physical queue is registered — always so until the tick drops both, the cap checked before the byte-equal check — the same current route is written back — or before the Q236 skip at the open, `return` for `continue` at the open). Equivalent of the planner's: `>=` → `==` at either check (a contact never holds more than 6, every addition is checked first), `continue` → `break` at the restart (every later row meets the same full count), the cap checked before the Q236 skip in `register_route` or before the end filter in `resume_overlaps` (both branches refuse with the same write), `send_ids` → `send_routes` in the guard (both are set together). Twelve of verification R2 (the current queue counted at the open, the open's entries added only after its loop, the cap applied to our own receive rotation, an end that passed not counted at the open only, the open in `sid` order either way, a queue loss freeing a slot, the refusal pointing the current queue's marker at the refused route, every queue a restart registered or every switched queue of other contacts counted, the Q236 skip at the open against current queues only, the open's queues given to the lowest contact): two survived the tests of the planner and of R1 — the cap on our own receive rotation and the marker of the refused route — and are killed by SE-174 and SE-173; one is equivalent (at the open every entry of the contact ends ahead). Ten of verification R3 (the refused route kept as the current route in memory, the refused `sid` set for the next queue id before the check, the cap also counting the hub's receive queues, our rotation skipped when any contact is at its cap, the refusal re-switching onto the queue sent to, the refusal setting that queue's `T_RS` or its period from the refused route, the refusal naming the queue sent to as the previous one, our rotation's `QUEUE_DEL` dropped at the cap, the refusal removing targets of the refused `sid`): four survived the tests of the planner, R1 and R2 — the receive queues counted, the re-switch, the refused period, the dropped `QUEUE_DEL` — and are killed by SE-176, SE-175 and SE-177; two are equivalent (`T_RS` is 24 h for every period, since 2 · 128 · 80 s is below 24 h; no target of the refused `sid` exists after the Q236 skip). Verification R4 ran thirty-one hand mutants against SE-178 alone: the thirteen that had survived an earlier round's tests — ten killed by it alone, the three others counting mutants (a queue past its end not counted, the guard on any contact's current queue, the receive queues counted) killed by SE-165, SE-172 and SE-176 — and eighteen new ones that give a refusal one more effect (a queue id spent or registered, a target, the previous queue removed, an end shortened or lengthened, the contact's routes marked changed, an app event, the refused route queued back to the peer, the scheduler view, a draw of the core's stream, `T_RS` cleared, an overlap row of the refused route, the invitation check made due, an old queue dropped from or made current in the conversation, the period removed, the stored route replaced before the check): all eighteen killed. Verification R5 ran forty-three hand mutants against the full `kat` suite: the thirteen earlier survivors again — all killed (ten by SE-178 alone; a queue past its end not counted by SE-165, the guard on any contact's current queue by SE-155 and SE-172, the receive queues counted by SE-176) — and thirty new refusal side effects in four sets (an entropy source taken, the rotation period, an overlap end lengthened in its row, a control planned on the contact or the other contact, the floors cleared or shifted, the other contact's previous queue or ends, an old queue evicted from the count or dropped from the conversation, a `QUEUE_DEL` left in the core, the contact state written, the invitations maintained, ends shortened, the stored queues or the other contact's routes replaced, a marker re-anchored, the oldest old queue's period or target removed, a receive period added, `T_RS` cleared, an overlap row of the current queue, the read-receipts setting, the accepts waiting forgotten, the floors raised, the timing stream reseeded): four survived the full suite as it then was — the floors cleared, the invitations maintained, the oldest old queue's period removed, the accepts forgotten — and SE-178 was strengthened after each until all four were killed (the invitation, the routes until every old queue was switched in this process and the second refusal, the accept); the floors raised early is killed by SE-158; two are equivalent (an entropy source taken: the product's source is stateless; an empty `RouteUpdate` planned: it does not encode and is not planned); the last set of six had no survivor.
- **Recorded.** OPEN-M7-B-29 (1) narrowed: (B) built, (A) rejected, (C) owner (D-B106); (2) unchanged. OPEN-M7-B-32 opened (D-B106: a sender-side guard, CAP2, before the M7 merge review; (C) owner). D-B93 and D-B103 bounded per contact (Q268).

## FZ (WEISUNG M7-FZ; OPEN-M7-B-29 (2), D-B94; Q272–Q275, ADR-047 Amendment 13; modell=claude-sonnet-5-5)

- **Commits.** START `c522941`; `29e11d7` test(fuzz) FZ; this docs commit; the evidence commit (smoke, policy, ci-fast). Changed: `crates/secmp-client-core/src/sessions/actor.rs` (`ControlRow`, `control_row_of`), `crates/secmp-client-core/src/sessions/mod.rs` (`open_conversation` calls it), `crates/secmp-client-core/src/sessions/tests.rs` (SE-166, SE-167, SE-168), `fuzz/fuzz_targets/client_control_rows.rs` (new), `fuzz/corpus/client_control_rows/` (38 seeds, 12 832 B), `fuzz/Cargo.toml`, `fuzz/README.md`, `xtask/src/expect.rs`, `xtask/src/gates.rs`, `crates/secmp-proto/tests/fuzz_max_len.rs`, and line 12 of `.github/workflows/fuzz-nightly.yml` (a comment; owner approval in chat, 2026-11-16). No `docs/03`/`docs/01`/wire/label/DDL/vector/`ref/`/backup change, no new dependency, no `unsafe`.
- **Design.** Q272, Q273: the open's dispatch is one pure function, `control_row_of`, which `open_conversation` calls and the target fuzzes against a restatement of the byte rules (37 fuzz targets, ADR-047 Amendment 13).
- **Red-first.** Not repeated by the executor (ADR-062); no evidence file is committed. At planning and verifications R1 and R2, on reproductions of the base, eighteen hand edits were each found and reverted: twelve of `sessions/actor.rs` found by the target's seed replay (`-runs=0`; three inside `control_row_of`; for three of them one of a named set of seeds of equal size crashes first, as libFuzzer shuffles equal-size seeds), four of `control_row_of` failing SE-166 (without `kat`) and two of the open loop (`sessions/mod.rs`: an undecodable content row skipped; a restored `Control` planned as `ContactRemoved`) failing SE-167 and SE-168.
- **Smoke.** The gate's command for `client_control_rows` (120 s, `-max_len=65543`, `-timeout=60`), evidence `fz-smoke-29e11d7.txt`: Done 4854135 runs in 121 second(s). Not run here: `cargo xtask step --strict fuzz` over all 37 targets (the CI job `fuzz`).
- **Tests.** nextest of `secmp-client-core` (`--features kat`): 332 tests run: 332 passed, 0 skipped (new: SE-166, SE-167, SE-168); without `kat`: 51 tests run: 51 passed, 0 skipped (new: SE-166). `cargo nextest run -p xtask`: 327 passed (326 before; new: G7-23); `secmp-proto` `fuzz_max_len`: 2 passed. `cargo fmt --all --check`: no output. clippy (`-D warnings`, all targets, all features; `secmp-client-core`, `secmp-proto`, `xtask`): no finding. `cargo xtask step --strict policy`: PASS.
- **Mutants.** Not run by the executor (ADR-047 Amendment 14, ADR-062: weekly or on demand). At verification R2 the `--in-diff` run on `sessions/actor.rs` and `sessions/mod.rs` gave `5 mutants tested in 5m: 5 unviable`; the in-diff list of `xtask/src/expect.rs` and `xtask/src/gates.rs` had no mutant (constants and `#[cfg(test)]` code). No pinned `path:line:col` row names `sessions/actor.rs` or `sessions/mod.rs`. cargo-mutants generates no viable mutant on the changed lines (only whole-function replacements, which do not compile), so the hand mutants are the proof: 40 of `control_row_of` and its call site (planner 16, verifier R1 16, verifier R2 8) — 32 killed, 6 equivalent, 2 survivors → SE-167, SE-168. Equivalent: the order of the three decoders and a swallowed marker or overlap error (the decoders accept disjoint tags and `PendingControl::decode` refuses tags 4 and 5, checked by FZ-05 on every input and by an exhaustive comparison with the base dispatch over 230 276 rows); an ignored `queue_pending` error (with an `ord` it fails only if a decoded content does not encode, which FZ-05's canonical check asserts on every accepted row — an argument, not a proof for all inputs); a restored `RouteUpdate` cut to its first route (every `RouteUpdate` row the product writes has one route, `rotation.rs` — equivalent for the rows the product writes only). Survivors, both also at the base: an undecodable row of tag 1–3, 0, 6, 255 or the empty row skipped at the open (a fail-open) → SE-167; a restored `Control` planned with another code → SE-168.
- **D-B109 (FZ, recorded; closed by construction).** The open's dispatch is `control_row_of`, the function the target calls; the target keeps an independent restatement of the byte rules only as its oracle. What remains outside the target: the effects of the open loop (`restore_marker`, `restore_overlap`, `queue_pending`), covered by the restart tests of B17b-2 and B17b-3 and SE-168 (the code of a restored `Control`), and its error path (a row that does not decode fails the open), covered by SE-98 (marker), SE-112 (overlap) and SE-167 (every other row). SE-167 and SE-168 close test gaps that already existed at the base: on the tree of DOCS7 (`eb2d5cb`) the same fail-open and the same change of a restored `Control`'s code each passed the client-core `kat` suite (307 of 307), while both tests pass there and fail with that change — the behaviour was correct, only untested (verifications R1 and R2).
- **D-B110 (FZ, recorded).** No allocation bound is asserted: counting allocations needs a global allocator, i.e. `unsafe`, which the fuzz package does not contain. By reading: `marker_of` and `overlap_of` allocate only the fixed 32-byte seed; `PendingControl::decode` reaches `read_routes`, which sizes its vector once from a `u8` count (`secmp-proto/src/wire/cell.rs:551-556`, M4 review C-13), so a 3-byte row may reserve up to 255 descriptors — a constant bound, not proportional to the row; every other body field is a slice of the row.
- **D-B111 (FZ, recorded; estimate).** CI cost: locally the 120-s smoke of the target took 122 s wall with the build cached; the per-PR fuzz job gains ≈ 2–3 min (estimate, not measured on GitHub) of its 120 min; the nightly share per target drops from 211 s to 205 s.
- **D-B112 (FZ, recorded; owner approval in chat, 2026-11-16).** Line 12 of `.github/workflows/fuzz-nightly.yml` (`#   35 targets x 205 s + 2 targets x 3600 s`) changes in the code commit, because `gates::tests::testkit_manifest_and_workflow_texts` compares it with the computed shares; folding the target into an existing one (no workflow edit) would have halved that target's smoke time and was rejected. Info for the owner: line 13 names `fuzz_executor_depth` as the check, which is `testkit_manifest_and_workflow_texts` (not changed).
- **Recorded.** OPEN-M7-B-29 (2) closed (Q272–Q275); (1) unchanged. No real defect: the target's smoke, a 900-s run (13 081 646 runs) at the planner and three 120-s runs with other seeds at each verification found none.

## C-1 and C-1b (BRIEF M7-C1, WEISUNG M7-C1b; modell=claude-sonnet-5-5)

**C-1** (host runtime, pool bridge D4′, first usable `secmp-cli`): commits `8909fd4` (core, store, pool tests), `17e0d64` (cli, e2e helper, smoke, G7-21), `2839fa9` (CL-12, B-14, Q281–Q283, HB-17…20), `6509add` (ci-fast evidence, `docs/reviews/M07-evidence/c1-ci-fast.txt`, workspace nextest 1613). Tests: `api::tests::hub_is_send`; `hub::tests::pool_material_persisted_before_queue_new`, `harness::m7_pool::adopted_spares_fetched_at_pool_period_no_queue_new`, `harness::m7_pool::invitation_takes_named_spare_refill_delayed`; `cli_it::{profile_new_and_open, invite_create_prints_uri, invite_accept_uri, usage_errors, passphrase_input_rules, single_writer_lock}` (CL-01/02/03/10/11/13); `xtask::testscan::release_targets_have_no_kat` (CL-12); `xtask::expect::tests::cli_dependency_row` (G7-21); `harness::m7_e2e::smoke_invite_and_message_both_ways`. Deviations from the brief:
- `Hub::new` unchanged; `Hub::bridge_pool()` returns the stored spares and the id floor (the bridge is opt-in).
- Extra API: `Scheduler::floor_queue_ids`, `PoolStart`, `Hub::spares`, `runtime::{Caller, Notice, create_profile}`, `Answer::PoolEmpty`, `Error::Transport`, `api` re-exports.
- `Event::ContactAdded` is raised by the loop for every new contact (invitee and inviter); `InviteFailed` by `HostControl`.
- `invite accept` prints an immediate `{"type":"accepting"}` line.
- Smoke deadline 10 min, not 4 (new send-queue links start `U[0, 3 min]` later, spec §10.6 (1)).
- CL-02 runs with a relay reference without `direct` (the 332-character URI form); the tests send `invite accept` again on `error/invitation` (the inviter's `LINK_PUT` lands a moment after `invite create` answers).
- Existing pins changed: `kat_argon2_params_only_with_kat` (normal edges), `normal_dependency_allow_m7` rows, the policy metadata fixture, AP-04 `PLUMBING`.

**Cross-review of C-1: NO-PUSH.** Findings and their disposition:
- C1-1 (§1.4, `Request::Export` on the loop) — fixed in C-1b (`runtime::tests::admitted_is_an_allowlist`, `harness::m7_runtime::export_through_call_core_is_refused`; Q284).
- C1-2 (pending re-create of a removed queue) — fixed in C-1b (`harness::m6_control::removed_queue_drops_pending_recreate`, red without the fix).
- C1-3 (§10.2: start view overwrote the hub's periods; `SetSettings` did not reach the scheduler; scheduler refusals dropped) — fixed in C-1b (`runtime::tests::start_view_keeps_hub_periods`, `runtime::tests::mode_change_refused_restores_settings`; `Notice::Refused`).
- C1-4 (take capped at 600 tries, errors dropped) — fixed in C-1b (`runtime::tests::take_step_outcomes`).
- C1-5 (plain `String` copies in the CLI) — HB-21.
- C1-6 (expired message returned) — fixed in C-1b (`messages::tests::expired_message_not_returned`).
- C1-7 (RUSTSEC-2026-0542 reason named the cli as not affected) — fixed in C-1b (`deny.toml`, `expect.rs`).
- C1-8 (a stopped loop printed `closed`, exit 0) — fixed in C-1b (`Notice::Stopped`, `daemon::tests::stopped_session_exits_1`).
- C1-9 (invitation consumed before stored) — HB-22; the usage text warns.
- C1-10 (passphrase file: FIFO, replaced path) — fixed in C-1b (`passphrase::tests::fifo_is_refused`).

**C-1b** (WEISUNG M7-C1b): K1 `fix(core,cli): Call::Core allowlist, …` (all code and tests; the pin of the RUSTSEC-2026-0542 reason in `expect::tests::audit_ignores_unchanged` follows the new text), K2 docs (Q284, HB-21, HB-22, this section), K3 evidence (`docs/reviews/M07-evidence/c1b-policy.txt`, `c1b-ci-fast.txt`).


## C-2 (BRIEF M7-C2; modell=claude-sonnet-5-5)

Commits: K1 `25d56f6` (core, store, testkit), K2 `8d739e2` (cli), K3 docs (DOCS9 R7-3, Q285, HB-23…29, TEST-SPEC SE-189…191, this section), K4 evidence (`docs/reviews/M07-evidence/ci-fast-c2-1-red-36d3ff9.txt`).

**Built.**
- B0, hub work off the loop: `Engine::run` keeps the schedule (`run_until`, actions and operations, takes); `visit` and the calls that need only the hub run as ONE hub job on `spawn_blocking` (hub lock held there) while the chunks go on; the result is applied at the next chunk boundary and the next job starts when a call or a visit is due (order of calls kept; `SetSettings`, `Export`, `Quit` are handled on the loop when no job runs). `Profile::rotate_identity` signs one `KeyChange` and clones it per contact (spec §7.6).
- A, events: `Event::{Relayed, Delivered, KeyChangeSent}` from `SessionEvent` (`OK_SEND` of a real message's last cell; a committed `Receipt{delivered}` for a message of ours not yet delivered; the `OK_SEND` that settles a `KeyChange` content, the `e.done` transition of Q222 (2)).
- B, export: `secmp-store::backup::{snapshot, Snapshot::write}` (bytes of the file unchanged; BK-01…BK-07, FO-03 unchanged and green); `Call::Export` (snapshot under the hub lock; Argon2id, seal and write on the blocking pool; the reply from a task of its own); `Call::Core(Request::Export)` stays refused (Q284).
- C, runtime: `Call::Status` / `Answer::Status(StatusView)`, `runtime::list_contacts`, `runtime::import_profile` (the contact count is the store's, not the session index's: a restored contact has no session).
- D, CLI: `contacts sas|verify`, `status`, `identity rotate`, `rotate`, `export`; events `relayed`, `delivered`, `key_change_sent`; one-shots `contacts list <dir>` and `import`; error codes `reinvite_required`, `confirm_required`, `cloud_folder`, `blocked`, `frozen`, `unverified`; D-B55 (g) (`daemon::repeats`); stdin lines capped at 65 536 bytes (`daemon::next_line`), `Line::InviteAccept` holds a `Zeroizing<String>`, `Debug` of `Line` is the variant name.

**Tests (wall seconds of the runs in this session).**
- B0: `harness::m7_runtime::loop_keeps_running_during_a_slow_call` (5 s), `profile::tests::rotation_signs_once` (3 s).
- A: SE-189 `sessions::tests::relayed_event_once`, SE-190 `…::delivered_event_after_receipt_commit`, SE-191 `…::key_change_sent_at_ok_send` (1–2 s each).
- B: `runtime::tests::export_does_not_stall_the_loop` (3 s); `daemon::tests::{removal_events_are_printed_once, long_lines_are_drained}`; `args::tests::{the_session_lines, the_one_shot_forms}`.
- CL-04 `cli_it::contacts_list_and_verify` (93 s), CL-05 `cli_it::send_and_tail` (266 s), CL-06 `cli_it::status_shape` (4 s), CL-07 `cli_it::export_import` (156 s), CL-08 `cli_it::identity_rotate` (400 s), CL-09 `cli_it::jsonl_schema` (173 s), CL-14 `cli_it::stdin_commands_are_total` (66 s; 10 000 lines, 60 of them reach the runtime).
- `secmp-client-core` + `secmp-store` with `kat`: 456 tests passed (before the CLI work).

**Deviations from the spec.** None. From the brief: guard 0.2's literal `git grep -c 'fn admitted'` is 2 (it also matches the test `fn admitted_is_an_allowlist`); there is exactly one `fn admitted` (`runtime.rs:148`), C-1 and C-1b are complete. Notes: CL-14 sends the runtime-reaching verbs rarely (a call waits for a chunk boundary, ≤ 1 s); `import_profile` first returned the session count (0) — fixed before K2 was committed.

**Open risks.** HB-29 (a hub job longer than P_min − ε still costs ticks). A call is answered at the next chunk boundary of the loop (≤ 1 s) as before.

**ci-fast (`docs/reviews/M07-evidence/ci-fast-c2-1-red-36d3ff9.txt`, head `36d3ff9`): FAIL, one step — STOP.** Every other gate and test is green (nextest 1634 of 1635 outside the harness; harness 318 of 318; kat 353 of 353). The one failure is `xtask testscan::scan::tests::pr_ci_runs_props_with_ci_run_seed`: `crates/secmp-cli/tests/cli_it.rs: names "SECMP_PROPTEST_SEED" itself; read it through crates/secmp-proto/tests/common/seed.rs`. CL-14 (`cli_it::stdin_commands_are_total`) reads the variable as the brief says, but the seed scan (`scan_seeds`, xtask) allows that literal only in the one helper of `secmp-proto`. Not retried (brief §6). Fix proposed, not applied: CL-14 uses a fixed seed constant (the ci-fast kat and harness steps remove the variable anyway, "DEFAULT_SEED only"), or an ADR'd extension of the scan to a CLI helper; either changes the dictated test or xtask, hence the reviewer's call. Red run, kept; C-2f's run is red as well (`ci-fast-c2f-1-red-582b9f3.txt`); the green run is C-2g's (`c2g-ci-fast.txt`).

## C-2f (WEISUNG M7-C2f; modell=claude-sonnet-5-5)

Commits: K1 `582b9f3` (core, cli, testkit helper), K2 docs (this section, Q286, HB-30…33, SE-192/193, the red evidence renamed to `ci-fast-c2-1-red-36d3ff9.txt`), K3 evidence (`docs/reviews/M07-evidence/ci-fast-c2f-1-red-582b9f3.txt`).

**CL-14 (the STOP of C-2).** The environment seed of the property tests is read by the one helper of `secmp-proto` (R-93, X-07; the seed scan is unchanged and `secmp-cli` is not a property package); TEST-SPEC-M7:423 does not ask for it and CI removes the variable for this crate, so the row runs on the fixed `CL14_SEED`; the row is unchanged. CL-14 drives 10 000 seeded lines; 60 reach the runtime with random arguments over all ten verbs (export answered by confirm_required, so no Argon2), plus one over-long and one invalid-UTF-8 line — the row's oracle holds (never panics, one JSON line per line, exit 0). Hits per verb index 0…9 on the fixed seed: 7, 7, 8, 4, 5, 6, 4, 10, 3, 6 (`identity rotate` is capped at 6). `CliProc::send_bytes` added to the testkit helper.

**Findings.**
- C2-1 (BLOCKER; the brief dictated the export placement): the snapshot read the whole history on the loop task. Fixed: `Call::Export` is a hub call; the snapshot is taken in the hub job under the lock it holds, the write is `spawn_blocking` and sends the reply (`runtime::tests::export_does_not_stall_the_loop`, extended: `hooks::CHUNKS` advances by at least 2 while the snapshot is held for 3 s).
- C2-2 / C1b-1: `SetSettings` order is now: the loop sets the mode (try-lock source; a refusal is `Unsupported` and nothing is stored), the hub job saves, a failed save reverts the mode at the next boundary with one `Notice::Refused`. There is no restore transaction. Tests `runtime::tests::settings_save_failure_reverts_mode` (SE-192) and `mode_change_refused_restores_settings` (reordered: refused, nothing stored).
- C2-3: CL-14 arguments (above).
- C2-7: the line buffers of `next_line` are pre-sized (`LINE_MAX + 2`), so `read_until` never reallocates an unzeroized copy.
- C2-8: the loop never waits on the hub lock: actions that call the cell source (`Remove`, `TakeSpare`), the takes and the mode step use `try_lock`; what cannot run is kept in order in a backlog and retried first at the next boundary (`runtime::tests::loop_side_hub_access_never_waits`, SE-193).
- C2-4, C2-5, C2-6 → HB-31, HB-32, HB-33 (HB-33: the CLI usage text now tells to remove the directory of a failed import); C1b-2 → HB-30 (C-2b).
- C2-10…C2-15: notes, no change.

**Known gaps (C2-9).** A job's replies precede its ops by at most one chunk; a lost `LINK_PUT` was not re-driven at `b2f5e0d` — no owner-status query was ever scheduled and its answer reached only the scheduler (review finding L1-2); since S-2 the owner-status chain (Q297) re-puts it, also after a restart; an accept is repeated.

**ci-fast (`ci-fast-c2f-1-red-582b9f3.txt`, head `582b9f3`): FAIL, one harness test (`m6_driver::driver_has_no_wall_clock`: SE-193 read `Instant::now`) — STOP.** Workspace nextest outside the harness 1637 of 1637; harness stopped at 57 of 318.

## C-2g (WEISUNG M7-C2g; modell=claude-sonnet-5-5)

Commits: K1 `092079d` (core), K2 `2c321fb` (harness), K3 docs (this section, Q287, Q288, HB-34…36, SE-193…195, the red C-2f evidence renamed), K4 evidence (`docs/reviews/M07-evidence/c2g-ci-fast.txt`).

**C2f-1 (MAJOR).** `SetSettings` took its previous mode from the stored settings; after a failed save whose revert the scheduler refused, the next request for the stored mode took no mode step and answered `Done` while the wire kept the other mode. Premise correction: a revert to Strict is never refused (`check_balanced` is `Ok` when Strict has no slot length); only a revert to Balanced or Low-bandwidth can be, so the tests use that direction. Fix: `settings_mode` became `sched_mode` (the mode last set on the scheduler: set by a successful mode step or revert, never by a save); the pure helpers `settings_step` (held while the backlog is not empty, else steps from `sched_mode`) and `revert_step` (a refusal is a second `Notice::Refused`) are shared by the engine and the tests. `revert_step` returns the outputs of a revert that worked (`Result<Vec<Output>, ()>`) so that the caller can submit them. Tests SE-194 `runtime::tests::refused_revert_then_same_request_steps_the_scheduler` and SE-195 `runtime::tests::settings_wait_for_a_pending_revert`; SE-192 and `mode_change_refused_restores_settings` unchanged and green.

**SE-193 without a clock.** The 10 ms bound is gone (`driver_has_no_wall_clock` unchanged): the drain returns while the holder thread still holds the mutex — the holder releases only after the drain's result is in — so a blocking drain would deadlock instead of passing.

**Windows (Q288).** Run 44238379614: `m7_e2e::smoke_invite_and_message_both_ways` failed with "Access is denied" replacing the running `target\debug\secmp-relay.exe`. `m6_two_clients` built the relay without `direct-tls` and ran the shared `target` file in place; the other build (`e2e::relay_bin`, `--features direct-tls`) replaced it. `m6_two_clients::start_relay` now calls `e2e::relay_bin(&dir.join("bin"))` (a copy per test); the relay config sets no `direct_tls`, so the plain `tor_loopback` path is the same. `two_clients_loopback_tcp` drops the relay before removing its directory. No product change. Linux ci-fast cannot show this fix; the evidence is the next PR run's `windows-native` job, step `harness`.

**Scan gates before ci-fast.** fmt, clippy (workspace, all features), `step --strict policy`, `nextest -p xtask` (330/330), the five scan tests of `m6_*` (5/5), `step --strict fuzz-check`, the greps for `Instant::now`/`SystemTime::now` (code only in `clock.rs`) and for the seed variable (nothing in `secmp-cli`), `secmp-client-core` kat (357/357), `two_clients_loopback_tcp` and `relay_config_parses_with_a_windows_style_dir` (2/2): all PASS.

**Backlog.** C2f-2 → HB-34; the engine-level guard → HB-35; the nextest residual on Windows → HB-36.

## C-2b (BRIEF M7-C2b; modell=claude-sonnet-5-5)

Commits: K1 `84aa8ac` (relay `ref`), K3 `5ebd24e` (`revert_step` doc), K4 docs (this section, Q289, HB-37…39), K5 evidence (`docs/reviews/M07-evidence/c2b-ci-fast.txt`). No K2: F is held.

**E — `secmp-relay ref` (Q289).** `ref --keys <file> --onion <addr>.onion [--direct <host>:<port> --cert <cert.der>] --out <file>` writes `relay_ref = <hex RelayRef>` and `access_key = <hex>` (the format of `runtime::read_relay_ref`) to a new file (`create_new`, 0600 on Unix; Windows inherits the directory's ACL, HB-39). The onion text is parsed strictly (56 lower-case base32 characters, `.onion`; version and checksum by `Onion::from_bytes`). Only `ref written` goes to stdout; no error string carries a value. The relay keeps its two workspace dependencies. Test `cli::ref_round_trips` (decoded `RelayRef` equals the expected one with and without `direct`, `access_key` line, mode 0600, five refusals with no secret on stdout/stderr and no file written). Clippy forced two changes in code, not by `allow`: the refusals moved into the helper `ref_refusals` (`too_many_lines`), and `as_chunks::<8>` replaced `chunks_exact(8)`.

**F — held.** The owner line for `fuzz-nightly.yml:12` was NO: no FZ-03 `cli_command_line`, no `fuzz/` change, no Q290, no ADR-047 Amendment 15, no G7-23 edit, no `gates.rs`/`expect.rs` change, gate 6 (`fuzz-check`) not run (nothing it checks changed).

**C2g-2.** The doc of `revert_step` now states `Ok(outputs)` / `Err(())` and what `sched_mode` holds. No code change.

**Backlog.** C2g-5 → HB-37; C2g-4 → HB-38 (`.config/nextest.toml` unchanged); Windows ACL of `ref`/`keygen` → HB-39. HB-30 stays open.

**Scan gates before ci-fast.** fmt OK; clippy (workspace, all targets, all features, `-D warnings`) OK after the two fixes above; `step --strict policy` PASS; `nextest -p xtask` 330/330 (no new xtask test without F); harness scan tests 5/5; `step --strict hello` PASS; greps: `Instant::now`/`SystemTime::now` code only in `clock.rs`, `SECMP_PROPTEST_SEED` comments only; `secmp-relay --test cli` 9/9; `secmp-relay --features kat` 193/193; `secmp-proto --test fuzz_max_len` 2/2; `secmp-client-core --features kat -E 'test(runtime::)'` 10/10.

**ci-fast (head `1041635`).** PASS: workspace nextest 1640/1640 (1639 + `ref_round_trips`), relay `kat` 193/193, harness 318/318, `fuzz-check` PASS; last line `ci-fast: PASS`. Evidence: `docs/reviews/M07-evidence/c2b-ci-fast.txt`. The harness shows 31 slow tests (no failure).

## C-3 (BRIEF M7-C3; modell=claude-sonnet-5-5)

Commits: K1 `test(harness)` (`m7_e2e.rs` + two `pub(crate)` tokens in `m6_driver.rs`), K2 docs (this section, Q291, HB-40, HB-41), K3 evidence (`docs/reviews/M07-evidence/c3-ci-fast.txt`). No product change.

**Rows → tests** (harness `m7_e2e`, real `secmp-relay` + two `secmp-cli open --direct`; pre-run `target/fable/report/c3-e2e.txt`, 6/6):

| Row | Test | Wall time |
|---|---|---|
| E2-01 (+E2-08) | `two_profiles_invite_by_uri_sas_match` | 124.3 s |
| E2-04 (§7.7) | `key_change_blocks_until_reverified` | 209.5 s |
| E2-03 (CLI part) | `rotation_with_overlap` | 843.6 s |
| E2-02, E2-09/FO-01, E2-11 (run log) | `five_hundred_both_ways_with_restarts` | 1329.1 s |
| E2-11 (source) | `cli_uses_no_wall_clock_for_schedule` | 0.01 s |
| (C-1 smoke, unchanged) | `smoke_invite_and_message_both_ways` | 199.4 s |

**N** = `E2_02_EACH_WAY` = 40 messages each way (Q291; the name `five_hundred_both_ways_with_restarts` is the TEST-SPEC name). Two seeded SIGKILLs per side, after the victim printed everything sent to it (HB-40). Every message once, in send order; `at_ms` monotone per process life; FO-01 scans (after the first kill and after the clean close, both profiles) without a hit. TEST-SPEC-M7 is not edited.

**Q291, HB-40, HB-41** added (see `OPEN-M7-decided.md`, `HARDENING-BACKLOG.md`). Open for C-4: E2-02v (500 each way), `QUEUE_DEL` count of E2-03, FO-01a key material, PC-05.

**Scan gates before ci-fast.** fmt OK; clippy (workspace, all targets, all features, `-D warnings`) OK; `step --strict policy` PASS; `nextest -p xtask` 330/330 (unchanged); harness scan tests 6/6; greps: `Instant::now`/`SystemTime::now` only in comments outside `clock.rs`, no seed/`SystemTime` token in `m7_e2e.rs`; `step --strict hello` PASS.

**ci-fast (head `26c89b9`).** PASS: workspace nextest 1640/1640, harness 323/323 (harness step 1872 s), `fuzz-check` PASS; last line `ci-fast: PASS`. Evidence: `docs/reviews/M07-evidence/c3-ci-fast.txt`. No product change.

## C-4 (BRIEF M7-C4; modell=claude-sonnet-5-5)

Commits: K1 `a1856b8` `feat(core)` (`Hub::message_key_digests_kat`, `hub.rs` +13, feature `kat` only, no behaviour change); K2 `36a8a4e` `fix(relay)` (`main.rs` +24/−9: C2b-1 `ref_text` built in one `String::with_capacity` of its exact length, C2b-2 `write_private` removes the partial file on a write or sync error; output and error texts unchanged); K3 `5792e07` `test(harness)` (`m7_e2e_virt.rs` new, `m7_forensic.rs` +469/−4, `m7_rotation.rs` ten `pub(crate)` tokens, `main.rs` `mod m7_e2e_virt;`, `driver.rs` +8: `GateState::ff_max`, `ff_steps`, `SKIP_STEPS_KAT` reset before and read after `convs.deliver`); K4 docs (this section, Q292, HB-42…HB-45); K5 evidence (`docs/reviews/M07-evidence/c4-ci-fast.txt`).

**Rows → tests** (pre-run `target/fable/report/c4-virt.txt`, harness binary, virtual driver, store-backed parties):

| Row | Test | Wall time |
|---|---|---|
| E2-02v (O-17, PC-05 digests) | `m7_e2e_virt::five_hundred_single_cell_virtual` | 80.6 s |
| E2-05 (O-16, F25) | `m7_e2e_virt::offline_24h_receives_every_real_message` | 187.6 s |
| E2-03 (1–24 h wait) | `m7_e2e_virt::rotation_with_overlap_virtual` | 47.9 s |
| FO-01a (O-01) + FO-02 | `m7_forensic::store_dir_has_no_plaintext` | 90.3 s |
| SE-02/SE-03 (unchanged, `m7_rotation::*`) | 6 tests | all PASS |

Pre-run: 9/10 (the 3 new E2 tests and the 6 SE-02/03 tests PASS; FO-01a red: its child failed at once). FO-01a's two failures were the test's own (below); after the fix it was run alone (child with `--no-capture`, then the real test): PASS, 90.3 s. The 10 were not re-run together.

**Evidence texts** (`target/m6-evidence/`):

- E2-02v: `500 messages each way, Balanced; kill points a [57, 391], b [142, 434]; virtual end 10820000 ms; message-key digests 2105 total, 2105 distinct`
- E2-05: `evicted ids 8381; ff_max 7765 KDF_CK steps (the worst cell); ff_steps 8409; worst cell = 15530 HMAC-SHA-256 (two per KDF_CK, spec §7.4 note (a)); all 144 messages after 480 s of virtual time back online`
- E2-03 virtual: `rotation at 600000 ms; overlap deadline 4457294 ms; QUEUE_DEL at 6229372 ms (quiet point 4864498 ms); 20 messages once each`
- FO-01a (+FO-02): `needles 268`; abort image (WAL not checkpointed, `lock` not copied) host 4 files / 2 228 869 B (WAL 2 191 872 B), guest 4 files / 2 105 269 B (WAL 2 068 272 B); clean close host 3 files / 110 725 B, guest 3 files / 94 341 B; no hit; the eight `HOME`/`TMPDIR`/`TMP`/`TEMP`/`XDG_*` directories empty after the child; `tor::config` paths under the profile; profile directory removed.

**Interpretations.** E2-02v: the 10 s `run_until` is taken after both sends of every iteration (a send per side per slot at the queue's 10 s period; virtual end 3 h with the drain); the digests of a side are appended at each kill and at the end. FO-01a: the 25 rounds are followed by 150 s and then 60 s steps until both sides hold 25 messages (cap 3 h): each side's receipts share its slots with its messages, so 150 s were not enough (counts 6/25 at 150 s).

**Deviations (test code only, no spec or product change).** (1) FO-01a, message 7 is sent as its ASCII text, not as UTF-16LE: a kind-1 payload holds no U+0000 (ADR-054, `app_payload_ok`; the core answered `Unsupported`), so UTF-16LE of ASCII cannot be sent. The UTF-16LE form of every text (7 included) is a needle, and the UTF-16LE form of the names too. (2) The drain loop above.

**Observation, not caused by this unit.** `cargo nextest run -p secmp-relay` (no features) has `config::tests::documented_listen_stanzas_parse` red (`direct_tls needs a relay built with feature direct-tls`); it is red at `6b42259` too (checked with the K2 change stashed), and green in the workspace run where feature unification enables `direct-tls` (`c3-ci-fast.txt`, 1640/1640). `ref_round_trips` PASS with and without `kat`; `-p secmp-relay --features kat` 193/193.

**Q292, HB-42…HB-45** added (`OPEN-M7-decided.md`, `HARDENING-BACKLOG.md`). TEST-SPEC-M7 is not edited.

**Scan gates before ci-fast.** fmt OK; clippy (workspace, all targets, all features, `-D warnings`) OK; `step --strict policy` PASS; `nextest -p xtask` 330/330; harness scan tests 6/6; `step --strict fuzz-check` PASS; `Instant::now`/`SystemTime::now` only in comments outside `clock.rs`; no seed/`SystemTime`/`Instant`/`set_var`/`mem::forget` token in `m7_e2e_virt.rs`, `m7_forensic.rs`, `driver.rs`; `-p secmp-client-core --features kat -E 'test(hub::)'` 73/73; `-p secmp-relay --features kat` 193/193.

**ci-fast (head `c0f8e63`).** PASS: workspace nextest 1640/1640 (unchanged: no non-harness test added), harness 327/327 (323 + the 4 new; harness step 1880 s), relay-kat step 193/193, `fuzz-check` PASS; last line `ci-fast: PASS`. Evidence: `docs/reviews/M07-evidence/c4-ci-fast.txt`.

## C-4b (WEISUNG M7-C4b; modell=claude-sonnet-5-5)

PR run 44280920220 (head `5bd3d73`), job `windows-native` 134721555578, step `harness`: exactly one failure, `m7_e2e::smoke_invite_and_message_both_ways`, after 662.7 s, `m7_e2e.rs:40:5`: ``no `opened` within 0ns; saw []``. Cause: the test took `started`/`end` (`DEADLINE` 600 s) before `E2eRelay::start` and `cli_bin`, which run `cargo build` of relay (`direct-tls`) and CLI inside the test; on the cold Windows runner they used the whole budget. No product code involved.

Change (test code only, one function): `built = Instant::now()` first; `started`, `end`, `left` are taken after `cli_bin`, with the note `relay and cli built`; doc line added (Q294). `DEADLINE`, assertions and later uses unchanged. Not demonstrable on Linux (builds are warm: note shows 0.6 s); the evidence for Q288 and Q294 is the next PR run's `windows-native` job, step `harness`.

Gates: fmt OK; clippy `-p secmp-testkit --all-targets --features kat,harness` OK; `step --strict policy` PASS; source scans 14/14 (`m6_driver::`/`m6_scan`) and the six C-4 scan tests 6/6; no `SystemTime::now` in `m7_e2e.rs`; smoke PASS in 156.7 s (`relay and cli built` at 0.6 s, `both open` at 33.1 s).

**ci-fast (head `31fa525`).** PASS: workspace nextest 1640/1640, harness 327/327 (harness step 1850 s), `fuzz-check` PASS; last line `ci-fast: PASS`. Evidence: `docs/reviews/M07-evidence/c4b-ci-fast.txt`.

**Windows evidence.** PR run 44313775321 (head `f73e2e0`): job `windows-native` 134834384908 ended `success` (2026-11-18 13:26:47–16:06:52 UTC); `harness`, `linux-fast`, `ct`, `kani`, `fuzz`, `proverif-hx`, `proverif-link`, `xwin-cross` success; `linux-full` was still running at 16:32 UTC. This is the evidence for Q288 and Q294; the per-test lines of that job were not read.

## C-5 (BRIEF M7-C5; modell=claude-sonnet-5-5)

Commits: K1 `4d48819` `fix(transport)` (`tor/mod.rs` +79/−4, `tests/tor/main.rs` +5/−5, `m6_tor.rs` +2, fuzz target +8/−2); K1b `fbf566e` `test(e2e)` (`m7_e2e.rs` +33/−5); K2 `f176553` `test(e2e)` (`ks_cli.rs` new, 645 lines (the brief said ≈ 300; rustfmt and the doc comment on every item made it longer), `e2e.rs` +27, `Cargo.toml` +5); K3 `b9644b5` evidence (`docs/reviews/M07-evidence/e2e-10-f176553.txt`); K4 docs (this section, Q293, HB-46…HB-48, `docs/07` status line); K5 evidence (`c5-ci-fast.txt`).

**Rows → tests.**

| Row | Test or evidence |
|---|---|
| C-T1 (OPEN-M7-22 A) | `tor::tests::onion_key_must_be_a_point` (T-01/T-02 unchanged and green) |
| E2-10 | example `crates/secmp-testkit/examples/ks_cli.rs`; evidence `docs/reviews/M07-evidence/e2e-10-f176553.txt` |

**Product change (the only one).** `tor::target` (`crates/secmp-transport/src/tor/mod.rs`, +10 lines of code and doc): before `onion_host`, the first 32 bytes of the onion must import through `secmp_crypto::Ed25519VerifyingKey::from_bytes` (spec §3.5: canonical, on the curve, not of small order), else `Error::Invalid`; `TorProvider::connect` returns that before `backend.connect`. The `# Errors` line of `target` names both refusals; the doc of `onion_host` points at `target` instead of the old "fix in M7" note. The test counts connects with an in-memory backend: T-01's real address passes; 32 × 0x42 (not a point), 32 × 0xff (not canonical) and 32 × 0x00 (small order) are `Invalid` in `target` and in `connect`, with the backend called 0 times; the good address then connects once.

**Fixtures and fuzz target.** `tests/tor/main.rs`: TOR-02 0x42 → 0x09, TOR-03 0x43 → 0x0a, TOR-09 {0x42, 0x43, 0x44} → {0x09, 0x0a, 0x0b}, TOR-05 half 0x45 → 0x0c (large-order points; TOR-08 uses `onion_host` only and is unchanged). `m6_tor::relay()` sets MemRelay's onion to 32 × 0x33 (a point). FZ-03's `relayref_onion_to_hsid` asserts `tor::target(..).is_ok()` iff the first 32 bytes import as an Ed25519 public key, then goes on with the unchanged asserts; corpus, `fuzz/Cargo.toml` and pins unchanged. Fuzz run: `cargo fuzz run … relayref_onion_to_hsid … -max_total_time=60 -max_len=36`: 1 941 239 runs in 61 s, no crash; `git status --porcelain fuzz` shows only the target file (K1).

**C-3 review carry-over (test-only, `m7_e2e.rs`; N = 40, deadlines and assertions unchanged or stronger).**
- C3-2: after FO-01's last scan a canary file holding alice's first text is planted in `<root>/fo-control` and the same `scan_dir` call must hit it (`needle == 0 && raw`). The test passed, so the control hit.
- C3-1: `rotation_with_overlap` sends 5 more messages (`rotation-20`…`24`) after `RoutesChanged`, so on the new route, each required once; the loop waits for 25. Not "fewer than 20 seen at `RoutesChanged`": that depends on the link offsets U[0, 180 s] and could flake. Wall time 975.9 s (was 843.6 s, +132 s).
- Item 5: `Side` carries `started`; `note` lines `kill point {i}: draining {n}`, `kill point {i}: reopened`, `alice drained`, `bob drained`. nextest does not show the stderr of passing tests, so the pre-run log does not contain them.
- Pre-run `target/fable/report/c5-e2e.txt`, 6/6 in 1468.9 s: `cli_uses_no_wall_clock_for_schedule` 0.01 s, `smoke_invite_and_message_both_ways` 183.6 s, `two_profiles_invite_by_uri_sas_match` 262.3 s, `key_change_blocks_until_reverified` 345.8 s, `rotation_with_overlap` 975.9 s, `five_hundred_both_ways_with_restarts` 1468.9 s.

**E2-10 (`ks_cli`).** Two release `secmp-cli open --direct` processes on one `secmp-relay` (direct TLS), each through its own recording TCP proxy (`E2eRelay::{direct_port, ref_path_via}`: same relay and SPKI pin at `127.0.0.1:<proxy port>`; TLS ends at the relay). 240 s settle after the invitation (> the 180 s link offset of §10.6 (1)), 1800 s idle with no stdin line, 1800 s active: per side 90 sends (60 steady, 3 bursts of 10; sizes 16 + 3r B from `EntropyPool::new("m7-e2e-10", 0)`), `status`, `contacts list`, `contacts sas` and three Argon2id `export`s (the R3 load). Time only as `Instant` elapsed since one `t0`. The KS method is `secmp_testkit::ks::{cut_at, gaps, two_sample}` on one read = one unit; the units are not opened (HB-47).

Evidence text, in full (`docs/reviews/M07-evidence/e2e-10-f176553.txt`, box run 2026-11-18T14:17:19Z–15:44:12Z, 5213 s, exit status 0):

```text
ks-cli: idle 1800 s, active 1800 s, settle 240 s, 2 secmp-cli processes (Balanced, direct mode, spec §10.2), P = 10 s, each through its own recording TCP proxy (TLS end to end; one read is one unit); a departure is reads less than 100 ms apart; the trace is cut on departure boundaries at the end of the active phase
link 2 (client 0): D = 0.055866, p = 0.936293, n_idle = 179, n_active = 179, median gap idle 10000 ms, active 10000 ms
link 1002 (client 1): D = 0.044693, p = 0.992895, n_idle = 179, n_active = 179, median gap idle 10000 ms, active 10000 ms
connection 2 (client 0): first 424578 ms, last 4014578 ms, 360 departures, 3149280 bytes
connection 3 (client 0): first 2384554 ms, last 2384578 ms, 1 departures, 8763 bytes
connection 4 (client 0): first 3285740 ms, last 3285761 ms, 1 departures, 8763 bytes
connection 1002 (client 1): first 415527 ms, last 4005527 ms, 360 departures, 3149280 bytes
connection 1003 (client 1): first 3042266 ms, last 3042280 ms, 1 departures, 8763 bytes
client 0: sends 90, queued 90, received from the peer 90, calls 69, answered 69, errors [], exit Some(0)
client 1: sends 90, queued 90, received from the peer 90, calls 69, answered 69, errors [], exit Some(0)
reads analysed: 916, sha256 987e9589517bd0d8f9d21942a681b29571c9c97305d6b5e6cdd22aa9329dca03
criterion (p >= 0.01 on exactly one link per client, no torn link: at most 3 departures on every other connection, every call answered and every message received, exits 0): MET
```

One link per client (the connection with 360 departures, one every 10 s over the 3 590 s from the idle start to the cut), p = 0.94 and 0.99; the other connections are one-departure control connections (8 763 B each; two of client 0, one of client 1; all three in the active phase (first departures at 2 384.6 s, 3 285.7 s and 3 042.3 s of the run; the idle/active cut is at ≈ 2 215 s), none in the idle phase; identified by the reviewer in the code as the spare-pool refills (`QUEUE_NEW`, one-shot link, spec §10.6 (2)) of the three spares taken during SETUP — client 0: `invite create` and the first-reply rotation, client 1: `invite accept` — each with a delay drawn at the take from U[1 min, 60 min]; the active script takes no spare, so they do not depend on the measured activity (Q295); the proxy sees no TLS content, HB-47; the criterion would not catch an activity-dependent extra connection, HB-52); no torn link. Smoke (`ks_cli … smoke 60 60`): rc 3 (not judged), 523 s wall, one `link` line per client (p = 0.9996, n = 5/5), both `client` lines `queued == sends` (2), `answered == calls` (4), `received` 2, `errors []`, `exit Some(0)`. The first smoke attempt aborted in `E2eRelay::start` (a relative out-dir: the relay is started with its own directory as the working directory, so its relative binary path did not resolve); the example now makes the out-dir absolute (`std::path::absolute`); one fix, one re-run, as the brief allows.

**Q293, HB-46…HB-48** added (`OPEN-M7-decided.md`, `HARDENING-BACKLOG.md`); `docs/07-milestones.md` status line updated. TEST-SPEC-M7 is not edited.

**Scan gates before ci-fast.** `cargo fmt --all --check` OK; `cargo clippy --workspace --all-targets --all-features -- -D warnings` OK; `cargo xtask step --strict policy` PASS (490 SPDX files, 163 lint-allows all sanctioned, no build scripts); `cargo nextest run -p xtask` 330/330 (= XTASK_BASE); the 8 harness scan tests (`driver_has_no_wall_clock`, `scheduler_core_has_no_tokio`, `scheduler_reads_no_ui_state`, `tick_path_reads_no_outbox`, `outbox_is_the_store_boundary`, `cli_uses_no_wall_clock_for_schedule`, `m6_tor::*`) 8/8; `cargo nextest run -p secmp-transport --all-features` 53/53 (`tor::tests::` 6/6, the tor test binary 7/7); `cargo xtask step --strict fuzz-check` PASS; fuzz run as above; `Instant::now`/`SystemTime::now` in `secmp-client-core/src` and `secmp-transport/src` only in doc comments outside `clock.rs`; no seed/`SystemTime`/`set_var`/`mem::forget` token in `ks_cli.rs`, `e2e.rs`, `m7_e2e.rs`.

**Deviations.** None from the spec. From the brief: the length of `ks_cli.rs` (above); the out-dir is made absolute (above).

## Phase C close (M7-C5)

**(1) Phase C rows.**

| Row | Unit | Test or evidence | Status |
|---|---|---|---|
| CL-01 | C-1 | `cli_it::profile_new_and_open` | evidenced |
| CL-02 | C-1 | `cli_it::invite_create_prints_uri` | evidenced |
| CL-03 | C-1 | `cli_it::invite_accept_uri` | evidenced |
| CL-04 | C-2 | `cli_it::contacts_list_and_verify` | evidenced |
| CL-05 | C-2 | `cli_it::send_and_tail` | evidenced |
| CL-06 | C-2 | `cli_it::status_shape` | evidenced |
| CL-07 | C-2 | `cli_it::export_import` | evidenced |
| CL-08 | C-2 | `cli_it::identity_rotate` | evidenced |
| CL-09 | C-2 | `cli_it::jsonl_schema` | evidenced |
| CL-10 | C-1 | `cli_it::usage_errors` | evidenced |
| CL-11 | C-1 | `cli_it::passphrase_input_rules` | evidenced |
| CL-12 | C-1 | `xtask::testscan::release_targets_have_no_kat` | evidenced |
| CL-13 | C-1 | `cli_it::single_writer_lock` | evidenced |
| CL-14 | C-2 (C-2f) | `cli_it::stdin_commands_are_total` (fixed seed `CL14_SEED`) | evidenced |
| G7-21 | C-1 | `xtask::expect::tests::cli_dependency_row` | evidenced |
| OPEN-M7-B-14 | C-1 | C-1 commit `2839fa9` (per §C-1) | evidenced |
| D-B55 (g) | C-2 | `daemon::tests::removal_events_are_printed_once` (exercises `daemon::repeats`; `crates/secmp-cli/src/daemon.rs:627`; corrected in D-11 from `daemon::repeats`) | evidenced |
| D4′ pool bridge | C-1 | `hub::tests::pool_material_persisted_before_queue_new`, `harness::m7_pool::adopted_spares_fetched_at_pool_period_no_queue_new`, `harness::m7_pool::invitation_takes_named_spare_refill_delayed` | evidenced |
| E2-01 | C-3 | `m7_e2e::two_profiles_invite_by_uri_sas_match` | evidenced |
| E2-08 | C-3 | same test (`--direct`: TLS group, version and ALPN refused otherwise on both ends) | evidenced |
| E2-02 | C-3 | `m7_e2e::five_hundred_both_ways_with_restarts`, 40 each way (Q291) | evidenced |
| E2-02v | C-4 | `m7_e2e_virt::five_hundred_single_cell_virtual`, 500 each way | evidenced |
| E2-03 | C-3, C-4 | `m7_e2e::rotation_with_overlap` (C-5: +5 sends after `RoutesChanged`), `m7_e2e_virt::rotation_with_overlap_virtual` | evidenced |
| E2-04 | C-3 | `m7_e2e::key_change_blocks_until_reverified` | evidenced |
| E2-05 | C-4 | `m7_e2e_virt::offline_24h_receives_every_real_message` | evidenced |
| E2-09/FO-01 | C-3 (C-5) | the scans inside `m7_e2e::five_hundred_both_ways_with_restarts`, plus the planted-canary control (C3-2) | evidenced |
| FO-01a | C-4 | `m7_forensic::store_dir_has_no_plaintext` (HB-44, HB-45 open) | evidenced |
| FO-02 | C-4 | `m7_forensic::store_dir_has_no_plaintext` (the same run, empty `HOME`/`TMPDIR`/`XDG_*`) | evidenced |
| E2-11 | C-3 | `m7_e2e::cli_uses_no_wall_clock_for_schedule` and the `at_ms` check inside E2-02 | evidenced |
| C-T1 | C-5 | `tor::tests::onion_key_must_be_a_point` | evidenced |
| E2-10 | C-5 | `ks_cli`, `e2e-10-f176553.txt` (MET) | evidenced for the one link per client; three further connections fell into the active phase; by the reviewer's explanation from a code trace they are setup-triggered pool refills — not measured (Q295); extra connections are not judged by the criterion (HB-52) |
| E2-07 | — | TEST-SPEC: `m7_e2e::e2e_over_tor_nightly` | OWNER-PENDING (owner relay and the dispatch job, D13) |
| G7-11 | — | TEST-SPEC: `xtask::sbom::tests::sbom_embedded_names_match_lock` | OWNER-PENDING (the `miniz_oxide` vet record; `supply-chain/config.toml` is still an exemption) |
| G7-20 | — | TEST-SPEC: `xtask::gates::tests::optional_jobs_are_not_required` | OWNER-PENDING (the ruleset, then `REQUIRED_JOBS` += `harness`) |
| FZ-03 + G7-15c | — | TEST-SPEC: fuzz `cli_command_line` | OWNER-PENDING (the owner's OK on `.github/workflows/fuzz-nightly.yml:12`) |
| G7-17 | — | TEST-SPEC: `xtask::wintest::tests::win_test_runs_store_suites` | OWNER-OPERATED |
| G7-19 | — | TEST-SPEC: `xtask::docs::adr_018_status` | ALREADY SATISFIED (M7-DOCS1b) |
| C-T2 | — | TEST-SPEC: `tls::tests::direct_socket_keepalive_timings` | NOT BUILT, cond. |
| SE-13a | — | TEST-SPEC: `sessions::tests::resend_after_receipt_timeout` | NOT BUILT, cond. |
| C-T3 | — | TEST-SPEC: `m7_two_clients::two_clients_uses_core_handshake` | BACKLOG (HB-17) |
| CT-03 | — | TEST-SPEC: `examples/unlock-timing` | BACKLOG (HB-18) |
| E2-06 | — | TEST-SPEC: `m7_e2e::relay_restart_mid_run` | BACKLOG (HB-19) |

E2-02: 40 messages each way over the CLI (Q291); 500 in E2-02v.

**(2) M7 acceptance (`docs/07`) against the evidence.**
- "E2E green in CI": no CI run of the C-3…C-5 heads exists (superseded: PR run 44313775321 on head `f73e2e0`, the C-4b evidence commit, ended job `harness` with success, see `## C-4b`; corrected in D-11); the `harness` job is not required (G7-20, owner-pending). ci-fast was green on the heads of C-2b, C-3, C-4 and C-4b.
- "nightly ⚙ over Tor": E2-07, owner-pending (relay host, dispatch job).
- "500 messages with restarts" over the CLI: 40 each way (Q291); 500 each way in virtual time (E2-02v).
- Forensic: FO-01 (with the planted-canary control, C3-2) and FO-01a (HB-44 and HB-45 open).
- Wrong passphrase: CT-01, CT-02 (TEST-SPEC rows of earlier units, not Phase C); CT-03 → HB-18.
- No key reuse: PC-05, E2-02v (message-key digests 2105 total, 2105 distinct).
- `tail`: the `open` event stream (OPEN-M7-12 A).
- No OWNER-PENDING row is "done".

**ci-fast (head `f138665`).** PASS: workspace nextest 1641/1641 (1640 + `tor::tests::onion_key_must_be_a_point`), harness 327/327 (unchanged: the example is no test, the carry-over edits existing tests; harness step 1790 s), relay-kat step 193/193, `fuzz-check` PASS; xtask 330 (unchanged); last line `ci-fast: PASS`. Evidence: `docs/reviews/M07-evidence/c5-ci-fast.txt`.

## C-5b (WEISUNG M7-C5b; modell=claude-sonnet-5-5)

Docs only. The three one-departure connections of the E2-10 evidence are named in `## C-5` (spare-pool refills of the three spares taken during setup, all in the active phase by chance — the reviewer's explanation, not measured, see Q295 as corrected in D-11; Q295, HB-52); the Phase C close row of E2-10 says so; `## C-4b` gets the Windows evidence of PR run 44313775321 (Q288, Q294); HB-49…HB-52 (review items C4-1, C4-3, C4-4, C5-1) and Q295 are added. No code, no TEST-SPEC edit, no evidence file changed.

Cross-review verdicts: C-3 PUSH 0/0/2/8, C-4 PUSH 0/0/4/7, C-5 PUSH 0/0/2/5.

Gates: `git diff --stat` only under `docs/`; `step --strict policy` PASS; `nextest -p xtask` 330/330; `ci-fast` (head `6315386`) PASS: workspace nextest 1641/1641, harness 327/327 (harness step 1660 s); evidence `docs/reviews/M07-evidence/c5b-ci-fast.txt`.

## S-1 (BRIEF M7-S1; modell=claude-sonnet-5-5)

**Finding (review L1-1/L2-1, V-L2-1).** In Strict mode a hand-out of a spare closed the spare's 80 s recv link at the call (`set_queue_period` → `Close` + `TornDown(.., Closed)`), ≤ 1 s after the user action or received reply and next to the prompt `LINK_PUT`/`LINK_GET`(consume); this is not in spec §10.6 or §11.3. The successor started `U[0, 3 min]` later.

**Change.** `set_queue_period` (§2.1, `scheduler/core/mod.rs`): a Strict recv queue whose period changes leaves its link untouched and draws one `U[0, 3 min]` instant; an up link with another period gets `die_at = min(die_at, end)`, a down link `at = min(at, end)`; send queues keep the old replacement. `step_due` (§2.2): a recv link ending by `Lifetime` whose queue now has another period connects its successor (`start_connect`) at that instant. Numstat K1: `core/mod.rs` 47/12, `m6_control.rs` 230/23. Balanced/Low-bandwidth unchanged.

**Tests.** `m6_control::pool_handout_recreates_link_with_announced_period` (QP-05, re-dictated): PASS (0.145 s in the targeted run). New `m6_control::strict_take_emits_nothing_at_the_take`: PASS (1.611 s). Targeted run (§4 step 9): 42 passed, 0 failed (`target/fable/report/s1-targeted.txt`).

**§4 summaries.** (1) fmt --check clean. (2) clippy `-D warnings` clean. (3) `step --strict policy` PASS. (4) `nextest -p xtask` 330/330. (5) 5/5. (6) `fuzz-check` PASS. (7) `Instant::now`/`SystemTime::now` code only in `clock.rs`; no seeded RNG/`#[ignore]` in `m6_control.rs`. (8) `nextest -p secmp-client-core --all-features` 357/357. (9) targeted 42/42.

**Lint-form changes to the dictated tests** (same assertions and values): `pool_client_up`'s caller `strict_take_emits_nothing_at_the_take` — `a`/`b`/`y` renamed to `wc`/`oc`/`bx` (`many_single_char_names`); the Balanced leg moved into the helper `balanced_take_changes_no_link` (`too_many_lines`, 102/100). Product code: a `;` after `up.die_at = up.die_at.min(end)` (`semicolon_if_nothing_returned`, after rustfmt's block form).

**Docs.** Q296 (`OPEN-M7-decided.md`), HB-53 (`HARDENING-BACKLOG.md`). Commits: K1 `05b656f`.

No Kani harness reaches `Scheduler` (`crates/secmp-client-core/src/kani_proofs.rs:224`), so Kani does not cover this change; the PR's `kani` job can show only that the existing harnesses are unaffected (corrected in D-11, XREVIEW-M7-S1 S1-5).

Deviations: none (the lint-form changes above only).

**ci-fast** (head `cfc0fb0`): `ci-fast: PASS`; workspace nextest 1641/1641, harness 328/328 (harness step 1735 s); evidence `docs/reviews/M07-evidence/s1-ci-fast.txt`.

## S-2 (BRIEF M7-S2; modell=claude-sonnet-5-5)

**Finding (review L1-2, V-L1-2).** No production code scheduled `ControlKind::LinkGetOwner`, and its answer (`ControlEffect::OwnerStatus`) reached only `Scheduler::owner_status`, never `Invitations::on_owner_status`. So a `LINK_PUT` lost with the relay was never re-driven (§9.7 (1)) and a link data consumed by someone else was never seen (§5.2).

**Design (Q297).** A chain per open invitation: the first owner-status query `When::Delayed` (U[1 min, 60 min], §10.6 (2)) after the issue's prompt `LINK_PUT`, the next U[1 min, 60 min] after each answer (after a `{0, 0}` answer: after the re-put's due time, not after the answer), a fresh one at every open; none once the invitation is consumed, expired or retired, the link data was seen consumed, or `expires` is within 60 min of the moment the query would be queued (`invitations.rs:877`); the query is then due U[1 min, 60 min] after the latest operation of its link data (`scheduler/control.rs:168-184`), after a `{0, 0}` answer up to 120 min after the answer, so a query can still run after `expires` (corrected in D-11, HB-58). Relay-visible per invitation: one `LINK_PUT` at issue; one owner-status `LINK_GET` per U[1 min, 60 min] (mean 30.5 min) of online time until the handshake (a query already queued when it arrives still runs once), the consumption is seen or `expires` − 60 min (a query queued before that cut can still run after `expires`, HB-58); one delayed `LINK_PUT` per `{0, 0}`; each on its own one-shot link.

**Product change (numstat K1 `8120104`).** `invitations.rs` +84: `Invitations::owner_query`, `owner_queries`, `owner_answer`. `hub.rs` +30/−2: `Hub::new` queues the queries of the open invitations, `Hub::invite` the first one, new `Hub::owner_status`. `runtime.rs` +29/−14: the `LinkGetOwner` arm becomes `HostControl::link_get_owner`.

**Routing.** `with_hub` runs after the transport call; the hub commits `FLAG_CONSUMED_SEEN` before the operation is done (CLAUDE.md §1.7); link data the hub no longer holds is done without a command (CO-06). `Scheduler::owner_status`'s own re-put stays only for hub-less drivers (CO-05).

**Tests.** IN-18/IN-19 end to end: `harness::m7_owner::owner_status_detects_foreign_consumption` (2 queries, `{0, 1}` seen, no re-put, one `InvitationUsedElsewhere` at `expires`), `…::owner_status_reputs_after_relay_loss` (one query, then the identical `LINK_PUT`, which the invitee consumes), activity independence `…::owner_status_schedule_is_activity_independent` (idle = active, ≥ 2 queries, 102 calls). The unit tests of `invitations.rs` are unchanged; TEST-SPEC-M7 is not edited. `hub::tests::step_invite` gained the issue's delayed `LinkGetOwner` action (§2.4 of the brief). Pre-run B: 38/38 (`m7_owner::` walls 2.377 s, 1.863 s, 216.034 s).

**Lint-form changes outside the dictated text** (testkit only, same behaviour): `driver.rs` — the body of the `LinkGetOwner` arm moved to `owner_status_query` (`too_many_lines`, 110/100) and the catch-all arm of `hub_material` named `LinkGetConsume(_)` (`match_wildcard_for_single_variants`); `m7_owner.rs` — local names (`many_single_char_names`), `saturating_add` for the call count.

**Open to the owner:** the cadence (Q297; alternative in the Q297 row, needs a §10.6 (2) erratum). **Note for E2-10:** a re-run now also shows the owner queries of the setup invitation until its handshake.

**Gates (before the commits).** fmt --check clean; clippy `-D warnings` clean; `step --strict policy` PASS; `nextest -p xtask` 330/330; the 6 scans 6/6; `fuzz-check` PASS; `Instant::now`/`SystemTime::now` only in doc comments outside `clock.rs`; nothing seeded in `m7_owner.rs`. Pre-run A: `nextest -p secmp-client-core --features kat` 357/357.

Deviations: none (the lint-form changes above only).

**ci-fast** (head `7538df3`): `ci-fast: PASS`; workspace nextest 1641/1641, harness 331/331 (harness step 1654 s); evidence `docs/reviews/M07-evidence/s2-ci-fast.txt`.

## S-2b (WEISUNG M7-S2b; modell=claude-sonnet-5-5)

**Finding (XREVIEW-M7-S2, S2-1, MAJOR).** The delayed re-put queued by `on_owner_status` was not checked again when it ran: the executor took its arguments from `link_put_args`, which skips only RETIRING rows. (a) A put that ran after the row was retiring or gone failed, was retried by `control_failed` every U[0, 3 min] for ever, and every retry opened a one-shot link without a command (a relay-visible beacon, invariant 1, §11.3). (b) A put that ran after the handshake published the link data of a consumed invitation again (§9.7 (1) allows the re-put only for an offered invitation before `expires`).

**Rule (Q298).** A `LINK_PUT` leaves the process only for an invitation that is Offered, before `expires`, and without `FLAG_CONSUMED_SEEN`, checked at the moment the operation runs; otherwise the operation completes without a command and is never retried. Every `ControlKind::LinkPut`, the issue's prompt put included.

**Change (K1 `a0dead7`).**
- `invitations.rs`: `Invitations::put_args` (the gate, line 789: `offer_state` at the injected clock, then the flag, then the bytes of `link_put_args` through the shared `put_args_of`); `on_owner_status` queues no re-put when `now + longest >= expires` (line 845); `longest_delay_secs` is the one helper of this site and of `owner_query`. `link_put_args` stays for the owner-status query, unchanged.
- `hub.rs`: `Hub::put_args` (line 833), with the hub's injected clock.
- `runtime.rs`: the `LinkPut` arm of `HostControl::run` takes its arguments from `Hub::put_args` (line 766 ff.); `None` ends the operation with `ControlEffect::None` without a command; a store error stays an error and is retried.
- Test side, K2 `5e4adac`: `driver.rs` — `StoreHub::put_allowed` and its use in the `LinkPut` arm of `run_control` (18 lines), so the virtual driver applies the production gate; yes, the driver changed.

**Tests.**
- `invitations::tests::put_args_only_for_an_offered_invitation`: `Some`, field for field equal to `link_put_args`; `None` for an unknown `n`, a consumed row (by a real accepted handshake; its blob is still stored), `expires` and `expires + 1` (`Some` at `expires − 1`), `FLAG_CONSUMED_SEEN` (through `on_owner_status({0, 1})`) and a RETIRING row. It would catch any gate branch that is missing or has the wrong boundary.
- `invitations::tests::no_reput_within_the_longest_delay_of_expires`: one delayed `LinkPut` at `expires − 3 601 s`, none at `expires − 3 600 s` and `expires − 1 s`. It would catch a missing or off-by-one cut.
- `harness::m7_owner::owner_reput_is_not_sent_for_a_retired_invitation`: relay loss → `{0, 0}` answer → identity rotation before the re-put is due → 4 h: no new `LINK_PUT` command, at most one `LinkPut(n)` start after the retirement (the assertion that fails on the retry loop), at most one further `LinkGetOwner(n)` start.
- `harness::m7_owner::owner_reput_is_not_sent_after_the_handshake`: invitee consumes, the answer `{0, 0}` is injected into the host's hub (`Hub::owner_status`, the call the host's operation makes), the handshake is accepted before the re-put is due (asserted: no `LinkPut` start yet), 4 h: no new `LINK_PUT` command, at most one `LinkPut(n)` start after the handshake, contact on both sides.

**Orders driven.** The retired order with the relay's real loss (`restart_relay`). The handshake order with the answer injected through the hub instead of a relay loss: the virtual relay can only restart as a whole (`world.rs`, `restart_relay`: no state at all, queues included), which would also drop the invitation queue that the handshake needs.

**Difference from the Weisung's text (flagged).** The retired test asserts "at most one further `LinkGetOwner(n)` start after the retirement", not "none": the query queued together with the re-put still runs once (the Weisung's own §3.2 says so). In the runtime it ends without a command (`link_get_owner` takes `link_put_args`, which skips a RETIRING row: `crates/secmp-client-core/src/runtime.rs:734-739`, `invitations.rs:764-779`) and its answer never reaches the hub; in the virtual driver the `LINK_GET` is sent from the driver's cached material and the answer goes to `Hub::owner_status` (`crates/secmp-testkit/src/harness/driver.rs:1357-1385`), where `owner_answer` finds no open row and queues nothing (`invitations.rs:912-935`). The chain stops either way (corrected in D-11, XREVIEW-M7-S2b S2b-3); the open link is HB-55 (S2-2). The unit tests live in `invitations_tests.rs`, the module file of `invitations.rs` (`#[path]`).

**Docs.** Q298, the wording of Q297 and of the S-2 design paragraph (after `{0, 0}` the next query is drawn after the re-put's due time; a query already queued at the handshake runs once), HB-55, HB-56 (S2-2, S2-3).

**Gates.** `cargo nextest run -p secmp-client-core --features kat`: 359/359 (without `kat`: 56/56). `cargo nextest run -p secmp-testkit --features kat --test harness`: 333/333 (1759 s; the four new tests PASS). `cargo xtask step --strict policy`: PASS. fmt and clippy `-D warnings` clean.

Deviations: the assertion above (`<= 1` queries), the unit tests in `invitations_tests.rs`.

**ci-fast** (head `b1f798b`): `ci-fast: PASS`; workspace nextest 1643/1643, harness 333/333 (harness step 1561 s), 0 skipped; evidence `docs/reviews/M07-evidence/s2b-ci-fast.txt`.

## D-11 (WEISUNG M7-D11; modell=claude-sonnet-5-5)

Docs only, on head `56e86e3` (S-2b evidence). No code, comment in code, test, existing evidence file, spec, threat model, `formal/` file, ADR status, gate or CI changed.

**Backlog rows.** HB-54 (XREVIEW-M7-S1 S1-2, S1-6; between HB-53 and HB-55), HB-57 (XREVIEW-M7-S2b S2b-1), HB-58 (S2b-2), HB-59 (S2b-5), HB-60 (OPEN-M7-B-25, which had no row). HB-56's line reference corrected to `runtime.rs:1188` (S2b-4).

**Wording corrections.** Q297 and the `## S-2` design paragraph (no query is queued within 60 min of `expires`, but one queued earlier can still run after it, HB-58); `## S-2b` (the query after the retirement ends without a command in the runtime only; in the virtual driver it is sent and answered; the chain stops either way, S2b-3); Q295 and `## C-5b` (the cause of the three extra E2-10 connections is the reviewer's explanation, not measured, review L6-2); Q296 (a link connecting at the take, a failed connect after it, an unchanged period; S1-1, S1-3, S1-7); `## S-1` (Kani does not cover the change, S1-5); stale lines: §1 row C, the §3 intro, §8 "Waiting (owner)", the D-B55 (g) row of the Phase C close (test name, review L6-3), "E2E green in CI" in Phase C close (2) (review L6-5); the `docs/07` M7 status line (cuts and fix units, review L6-5).

**Carried to the milestone review** (listed, not decided here):
- R7-6 (condition of the draft M7 review): cross-review the two CLAUDE.md §1.7 convention seams (handshake cells trusted as durable; `Delivered::Committed` from `CellSource`) and consider a witness type. Open; no document in `docs/` recorded it before this line.
- ADR-058 (owner): `docs/08-decisions.md:1133` reads "Accepted (Reviewer, 2026-11-10, under the owner's delegation of 2026-11-10 …)", while §5 of this report says it awaits the owner's ratification, and `docs/03` §7.7 has no erratum (rev 2.7.1). `docs/08` is not changed here.
- Mutation gate (review L5-4; owner decision): ADR-047 Amendment 14 (`docs/08-decisions.md:503`) runs `mutants-shard` and `mutants` only on the weekly schedule (`.github/workflows/ci.yml:371-372`, `:444-446`); the build-phase relaxation in `docs/06-engineering-standards.md:169` names M8–M10, not M7; HB-4 tracks the release-gate run. Whether M7 merges without a mutation run at its head is the owner's.
- OPEN-M7-B-25 (HB-60; owner decision pending).
- Review minors, each for the milestone review (C-n/F-n), not decided here:
  - L5-3: `audit bin` passes every `expect::AUDIT_IGNORES` id for every binary (`xtask/src/sbom.rs:107-118`), also ids justified as lock-only or as not linked into that binary (OPEN-M7-B-14 (A)).
  - L5-2: CL-12 checks each release package alone (`xtask/src/testscan.rs:487-512`), while the SBOM build is one joint `cargo auditable build` (`xtask/src/sbom.rs:166-173`); equivalent today, not by construction.
  - L6-1: the E2-10 verdict uses KS on inter-departure gaps only; every read's length is replaced by `ks::FRAME` (`crates/secmp-testkit/examples/ks_cli.rs:559`), with no departure-count or bytes-per-departure check (low power).
  - L34-1: the export body grows by `extend_from_slice` from an empty `Zeroizing` vector (`crates/secmp-store/src/backup.rs:164-167`); a reallocation leaves the earlier sections (the identity secret first) unwiped in freed heap. Fixed by S-3 (`## S-3`).
  - L34-2: `unhex` collects into a growing plain `Vec` (`crates/secmp-client-core/src/runtime.rs:426-442`) before the `Zeroizing` wrap (`:456`); the relay reference file is read by `read_text` (`crates/secmp-cli/src/daemon.rs:105-110`) without a size limit or a permission check. (a) fixed by S-3 (`## S-3`); (b) open.
  - L34-3: `Hub::begin_accept` copies the invitation URI into `waiting: BTreeMap<u32, String>` (`crates/secmp-client-core/src/hub.rs:185`, `:856`), not zeroized. Fixed by S-3 (`## S-3`).
  - L1-3: `read_relay_ref` (`crates/secmp-client-core/src/runtime.rs:449-466`) does not check the reference's `akc` against the access key.

**Gates.** `git diff --stat` only under `docs/`; `step --strict policy` PASS; `nextest -p xtask` 330/330.

**ci-fast** (head `83b66c6`): `ci-fast: PASS`; workspace nextest 1643/1643, harness 333/333 (harness step 1795 s), 0 skipped; evidence `docs/reviews/M07-evidence/d11-ci-fast.txt`.

**D-11b (WEISUNG M7-D11b).** Four wording fixes from the cross-review of D-11 (D11-1…D11-4): the list of open owner items in §8 names all three places; §1 row C excepts the OWNER-PENDING and OWNER-OPERATED rows; the E2-10 row of Phase C close marks the refill explanation as not measured; HB-60 says it is not a deferral. Docs only; gates: policy and the xtask tests; no ci-fast of its own (no file outside docs/ since D-11's run on 83b66c6).

## S-3 (BRIEF M7-S3; modell=claude-sonnet-5-5)

**Findings.**
- F1-1 (red team of the M07 review; minor): every relay `ERR` answer to a `LINK_PUT` was a transport `Err`, and `ControlOps::failed` re-dued it at now + U[0, 180 s] with no cap; `ERR_EXISTS` is permanent while the relay holds the `ld_id`'s link data or consumption marker (spec §9.4), so the client sent about 960 one-shot `LINK_PUT`s a day on one `ld_id`, a relay-visible beacon.
- L34-1 = F1-3 (re-rated major): the export body and `Contents::encode` built their buffers by `extend_from_slice` from an empty `Zeroizing` vector; every growth freed the old block unwiped, identity seeds first (CLAUDE.md §1.6, docs/04 CS-2.2).
- L34-2 (a) (minor): `unhex` collected the relay access key (spec §9.6 "secret") into a growing plain `Vec` before the `Zeroizing` wrap.
- L34-3 (minor): `Hub::begin_accept` kept the invitation URI (it carries the link key) in `waiting` as a plain `String`.

**Rule (Q299).** A `LINK_PUT` answered `ERR_EXISTS` is done: the operation completes as if answered `OK` and is never retried. Every other answer is unchanged (HB-61). CO-06 is untouched.

**Change.**
- `crates/secmp-client-core/src/scheduler/run.rs:241` — `link_put_outcome`.
- `crates/secmp-client-core/src/runtime.rs:780` — the executor's `LinkPut` arm calls it; `:429` `unhex` (one zeroizing allocation of exactly the decoded length); `:460` `read_relay_ref` takes its result directly.
- `crates/secmp-client-core/src/hub.rs:185` — `waiting: BTreeMap<u32, Zeroizing<String>>`; `:856` the insert.
- `crates/secmp-store/src/backup.rs:275` `total`, `:283` `sized`, `:288` `joined`; `:164` `snapshot`; `:844` `encode_body_kat`; `Contents::encode` contacts `:338`, settings `:356`, messages `:385` (the `AppMessage` encodings are made first so the section's length is known; same checks, same bytes, same order).
- `crates/secmp-testkit/src/harness/driver.rs:1462` — the virtual driver's `LinkPut` arm applies the same rule.

**Tests.** Red first on the current code (`target/fable/s3-red.txt`):
- T1 `scheduler::run::tests::link_put_exists_is_done`: pins the rule (`Ok`, `Exists` → `Ok`; the 15 other variants unchanged) for the runtime call site; kills the `Ok(())`/identity mutants. Cannot be red on the old code (the function is new).
- T2 `harness::m7_owner::owner_reput_answered_exists_is_not_retried`: a `{0, 0}` answer queues the identical re-put, the relay answers `ERR_EXISTS`; one re-put start, completed, identical `LINK_PUT`, owner-status answers all `(true, false)`. Red: `LinkPut(n)` starts 105, expected 2.
- T3 `backup::tests::export_buffers_are_sized_once`: every section and the body have capacity == length. Red: section 2 capacity 8084, length 4091.
- T4 `runtime::tests::unhex_is_one_exact_allocation`: capacity == length for 1, 31, 32, 33, 100 bytes; odd length and non-hex refused. Red: capacity 8, length 1.
- The runtime call site of `link_put_outcome` (`HostControl::run`) is covered by reading only (HB-59, HB-61).

**Not in this unit.** The other `ERR` answers (HB-61); L34-2 (b) (`secmp-cli` `read_text`); no test for L34-3 (the type only, checked by the compiler).

**Gates.**
1. `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
2. `secmp-client-core --features kat`: 361 run, 361 passed, 0 skipped; `secmp-store --features kat`: 104 run, 104 passed, 0 skipped.
3. harness `m7_owner`/`m6_control`/`m7_pool`/`m7_accept`: 31 run, 31 passed (2 slow), 303 skipped; `m6_control::control_op_retried_after_link_failure` among them, unchanged.
4. `cargo xtask step --strict policy`: PASS.

**ci-fast.** Run on 6394a4e: `ci-fast: PASS`; workspace nextest 1646/1646 (WS_BASE 1643 + 3: T1, T3, T4), harness 334/334 (HARNESS_BASE 333 + 1: T2; harness step 1722 s), 0 skipped; evidence `docs/reviews/M07-evidence/s3-ci-fast.txt`.

Deviations: none.

## S-4 (BRIEF M7-S4; modell=claude-sonnet-5-5)

**Findings.**
- EXT3-4 (external review round 3; V-EXT3-4): `Driver::control` mapped every runner error, a relay `ERR` answer too, to `Err(false)`; `ControlOps::failed` re-dued it at now + U[0, 3 min], uncapped, with the correlation delay cleared by `take_due`: spec §10.6 (2) bypassed, ≈ 900–960 one-shot links a day per operation, linkable by `ld_id`/`recv_pk`; each retry moved `last_start[related]`, so a put retry loop starved the waiting owner-status query of the same link data (new finding), and an answered consuming `LINK_GET` was retried for ever.
- EXT3-1 Repro B (V-EXT3-1): the order was connect → handshake → `with_hub` (hub mutex) → command, and the post-response hub commits ran while the link was open: a hub hold is an idle gap on a one-shot link (§10.1, invariant 4).

**Rule (Q300).** A control operation ends done, link failed (no answer of the relay: CO-06's back-off, unchanged) or answered (a relay `ERR`, or an answer that could not be committed): an answered operation is queued again exactly as a fresh `When::Delayed` operation, with no cap and no growing back-off (HB-61). The owner-status query is gated again when it runs; an answered consume fails the accept. Material from the host before `providers.connect`; the link closed before the commit; done only after the commit (invariant 7); nothing to do opens no link (closes HB-55).

**Change.**
- `crates/secmp-client-core/src/scheduler/run.rs:221` trait `ControlRunner` (`prepare` / `run` / `commit`); `:270` `ControlResult`; `:287` `relay_answered`; `:305` `consume_outcome`; `:1324` the `Driver::control` body (prepare, link, close, commit); `:1093`, `:1112`, `:1116` the handler arms.
- `crates/secmp-client-core/src/scheduler/control.rs:192` `delayed_due` (the moved statements of the `When::Delayed` arm, one draw); `:358` `answered`.
- `crates/secmp-client-core/src/scheduler/core/mod.rs:1970` `control_answered`.
- `crates/secmp-client-core/src/invitations.rs:819` `owner_query_args`; `crates/secmp-client-core/src/hub.rs:842` `owner_query_args`, `:848` `accept_failed`.
- `crates/secmp-client-core/src/runtime.rs:655` `ControlPrepared`; `:670` `ControlAnswer`; `:687` `prepare`; `:740` `run`; `:802` `commit`.
- Test kit: `crates/secmp-testkit/src/harness/driver.rs:1584` `prepare_control`, `:178` `answer_err`, `:1531` `consume_query`; `tokio_driver.rs:117` `TestControl`; `mem.rs:463` `closes`.

**Invariant 7 per kind.**
- QUEUE_NEW: the seeds are made durable in `prepare` (D4′), before the link opens.
- QUEUE_DEL: `queue_deleted` runs in `commit`, after the close; a re-run after a failed commit meets `ERR_NOQUEUE`, counted as deleted.
- LINK_PUT: no commit.
- Owner LINK_GET: `owner_status` runs in `commit`, after the close; the chain is drawn again at open.
- Consuming LINK_GET: `link_consumed` runs in `commit`, after the close; the relay consumed at its response, and the window response → commit is HB-22's and no longer — the close adds no state.

**Tests.** Red first on the current code, with the test-kit hooks on the old structure (`target/fable/s4-red.txt`):
- U1 `scheduler::control::tests::answered_error_redues_through_control_delay`: an answered prompt operation is due U[1 min, 60 min] after the latest related start/due and never overtakes a waiting related one (200 seeds). New API, not red-first.
- U2 `scheduler::run::tests::control_errors_are_classified`: the 7 relay answers vs the 9 link-level/local errors, `relay_answered` and `consume_outcome`. New API, not red-first.
- H1 `m6_control::answered_link_put_is_spaced_like_a_delayed_op`: spacing of an answered `LINK_PUT` over 12 h. Red: 472 runs, min_gap 114 ms.
- H5 `m6_control::answered_queue_new_auth_is_spaced_not_terminal`: as H1 for `QUEUE_NEW` answered `ERR_AUTH`. Red: 489 runs, min_gap 230 ms.
- H2 `m7_owner::answered_reput_does_not_starve_the_owner_query`: a re-put answered `ERR_FULL` leaves the owner query running, no two starts under a minute apart. Red: 117 re-puts.
- H3 `m7_owner::answered_owner_query_ends_once_consumed_seen`: an answered owner query ends without a link once the hub saw `consumed`; no re-put. Red: 158 starts.
- H4 `m7_owner::answered_consume_fails_the_accept_once`: an answered consume fails the accept once (`InviteFailed(Invalid)`), no contact. Red: 168 starts.
- H6 `m6_driver_fix::driver_control_material_is_ready_before_the_link_opens`: the prepare wait of 5 s delays the connect; the command follows the handshake within 200 ms. Red: connect 0 ms after the start (the second assertion was not reached).
- H7 `m6_driver_fix::driver_control_link_closes_before_the_commit`: the link is closed within 200 ms of the last response while the commit waits 5 s; done only after. Red: no close recorded by t0 + 3 000.
- H8 `m6_driver_fix::driver_control_with_nothing_to_do_opens_no_link`: a skipped operation opens no connection. Red: 1 provider connect.
- `HostControl` is covered by reading only (HB-59).

**Not in this unit.** EXT3-1 Repro A (export under the hub lock; HB-29, Q285); a cap or a back-off (HB-61); a runtime-level test (HB-59).

**Gates.**
1. `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
2. `secmp-client-core --features kat`: 363 run, 363 passed, 0 skipped.
3. harness `m7_owner`/`m6_control`/`m6_driver_fix`/`m6_driver`/`m6_mut`/`m7_pool`/`m7_accept`: 109 run, 109 passed (2 slow), 233 skipped; `m6_control::control_op_retried_after_link_failure` and `m6_mut::control_failed_makes_the_operation_due_again` among them, unchanged.
4. `cargo xtask step --strict policy`: PASS.

**ci-fast.** Run on 6d10372: `ci-fast: PASS`; workspace nextest 1648/1648 (WS_BASE 1646 + 2: U1, U2), harness 342/342 (HARNESS_BASE 334 + 8: H1–H8; harness step 1725 s), 0 skipped; evidence `docs/reviews/M07-evidence/s4-ci-fast.txt`.

Deviations:
- `run.rs` handler: rustfmt put the `LinkFailed` arm in a block, so clippy (`semicolon_if_nothing_returned`) asks for `;` after `sched.control_failed(now, op, closed_before)?`; same semantics.
- `driver.rs`: the consuming-`LINK_GET` arm of `run_control` is `VirtualDriver::consume_query` (same code as dictated), because `run_control` reached 105 lines (clippy `too_many_lines`, limit 100).
- H3: the "no `trace` entry with `slot == CONTROL_SLOT_BASE + op.0`" assertion counts only entries at or after the start of the query's second run (`t_ms >= start`): an answered operation keeps its `OpId`, so the entries of its first, answered link carry the same slot.
- Tests: H1/H5 share the helper `answered_is_spaced`; the test files add `min_gap`, `starts_of`, `control_link`, `unit_time`; time arithmetic is saturating (clippy `arithmetic_side_effects`).

**S-4d (WEISUNG M7-S4d; modell=claude-sonnet-5-5).** What: the Q300 phase rule — `Driver::control` records `up` once the handshake is done, and from then on every end other than success (a relay `ERR` of any code, an unfitting or garbled answer, the link closed, the timeout) is answered through the new `ControlRunner::unanswered` (a consuming `LINK_GET` ends the accept, the others are queued again as fresh delayed operations); only the prepare step, the connect, the handshake and the timeout before `RELAYINFO` stay link failed (CO-06); `LinkBlob::decode`, the expiry bucket and `RecvCap::from_seed` moved into `HostControl::prepare` and `VirtualDriver::prepare_control`. Why: S4-1 — a relay that closes, stalls or sends an unfitting code after reading the command chose the U[0, 3 min] retry (≈ 900–960 linkable attempts a day per operation, unbounded for a consume); S4-3 — a local error after the handshake opened a link without a command. Tests: `m6_driver_fix::driver_control_relay_err_is_answered` (H9a), `driver_control_close_after_the_command_is_answered` (H9b), `driver_control_unfitting_answer_is_answered` (H9c), `driver_control_stall_until_the_timeout_is_answered` (H9d), `driver_control_failure_before_the_link_is_up_stays_link_failed` (H9e), `driver_control_consume_lost_after_the_handshake_ends_once` (H9f), `m6_control::corrupt_link_material_opens_no_link` (H10), through the product `Driver::control` with `TestControl`; the U1 step (the drawn delay is kept, a related start after the answer pushes the answered operation back) with the mutant `op.delay = None` in `ControlOps::answered` killed (`seed 0: pushed 4900924, again 4900924`, `target/fable/s4d-mutant.txt`), restored, the diff of `control.rs` only additions. Red first on the current code (`target/fable/s4d-red.txt`; U1 in `s4d-red-u1.txt`, passed as expected): H9a, H9e, H6, H7, H8, U1 PASS; H9b FAIL 21 runs, min_gap 10 463 ms; H9c FAIL 21 runs, min_gap 1 999 ms; H9d FAIL 9 runs, min_gap 132 585 ms; H9f FAIL 22 runs; H10 FAIL traced 80, sent 20. Docs: Q297 (HB-58 wording), Q300 (phase rule), HB-55, HB-58 (closed), HB-59, HB-61, new HB-62. Gates: 1. fmt and clippy clean; 2. `secmp-client-core --features kat` 377 run, 377 passed; 3. harness subset 121 run, 121 passed (2 slow), 228 skipped; 4. policy PASS. ci-fast: run on cb890fa, `ci-fast: PASS`; workspace nextest 1662/1662 (WS_BASE 1662 + 0), harness 349/349 (HARNESS_BASE 342 + 7: H9a–f, H10; harness step 1687 s), 0 skipped. Evidence: `docs/reviews/M07-evidence/s4d-ci-fast.txt`. Deviations: `TestControl::unanswered` is a plain `fn` returning `impl Future<Output = bool> + Send` (`std::future::ready`), because clippy (`unused_async_trait_impl`) rejects an `async fn` without `.await`; `hook(&mut x.control.lock().unwrap())` without the explicit `*`; the test files hold the dictated helpers (`min_gap` copy, `PhaseRun`, `phase_run`, `assert_answered`).

## S-5 (BRIEF M7-S5; modell=claude-sonnet-5-5)

**Findings.**
- EXT3-2 (a) MAJOR (V-EXT3-2): `Scheduler::change_mode` (`set_mode`, `set_direct`) wrote the mode and tore every link down before drawing the new phases; a failed draw left Balanced in force with part of the new links, so the relay learned a queue grouping the user had not chosen (§11.3 item 2; CLAUDE.md §1 invariants 1, 5), while the runtime answered `Unsupported` and kept `sched_mode` and the store on Strict.
- EXT3-2 (b) MINOR (V-EXT3-2): `take_spare` → `set_queue_period` wrote the period before it drew the handover instant and did not restore it: the spare was announced at 10 s but fetched at 80 s for 6–24 h (§10.2), and a retry found "unchanged".
- Sibling: a hand-out whose refill (`top_up_pool`) failed answered `Err` after it had already handed the spare out.
- (d) The same order (a change, then the fallible draw) was in `World::tear`, `recreate`, `top_up_pool`, the queue adds, `remove_queue` and `connect_failed`.

**Rule (Q301).** A scheduler change that needs randomness draws ALL its values before the first change, then applies them through a path that cannot fail. The values, their order and their count are those at the base, so every existing seeded test sees the same stream.

**Change.**
- `crates/secmp-client-core/src/timing.rs:111` `TimingRng::failing_after` (test-only, `Source::FailAfter`, `splitmix`).
- `crates/secmp-client-core/src/scheduler/core/mod.rs:499` `World::close`, `:532` `tear`; `:982` `recreate`; `:1203` `top_up_pool`, `:1212` `draw_top_up`, `:1224` `apply_top_up`; `:453` `wanted_specs`; `:1260` `on_queue`, `:1265` `ends_with`; `:1320` `Scheduler::mode`; `:1518`, `:1583`, `:1618` the three queue adds; `:1650` `remove_queue`; `:1687` `set_queue_period`, `:1708` `check_changed`, `:1736` `plan_recv_period`, `:1759` `apply_recv_period`, `:1786` `set_send_period`; `:1817` `has_link`, `:1824` `draw_links`, `:1832` `add_links`, `:1849` `missing_links` (they replace `sync_links`); `:1887` `change_mode`; `:2026` `take_spare`; `:2389` `connect_failed`.
- `crates/secmp-client-core/src/scheduler/control.rs:217` `ControlOps::schedule_drawn`.
- `crates/secmp-client-core/src/scheduler/pool.rs:124` `QueuePool::oldest`, `:136` `missing_after_take`.
- `crates/secmp-client-core/src/runtime.rs:215` `take_step`, `:240` `mode_step`, `:285` `settings_step`, `:305` `revert_step`.

**Tests.** Red first on the base (`target/fable/s5-red.txt`; the 12 tests ran against the old code with only `failing_after`, `Scheduler::mode` and `schedule_drawn` added):
- SM-1 `scheduler::core::tests::set_mode_without_randomness_changes_nothing`: mode, links and outputs unchanged after a failed phase draw (first or second link). Red: `(Balanced, Balanced)` against `(Strict, Strict)`.
- SM-2 `runtime::tests::settings_step_failed_draw_then_old_mode_keeps_scheduler_in_step`: `Unavailable`, not `Unsupported`; `sched_mode` equals the scheduler's mode. Red: `Err(Unsupported)`.
- SP-1 `take_spare_draw_failure_restores_period`: Red: `(10000, true)` against `(80000, true)`.
- SP-2 `take_spare_retry_after_failed_draw_hands_over`: the retry hands over at the announced instant. Red: `die_at` `Some(83066121)` against `Some(3600001)`.
- SP-3 `take_spare_refill_draw_failure_hands_out_nothing`: Red: `(10000, false)` against `(80000, true)`.
- PS-1 `send_period_change_without_randomness_changes_nothing`: Red: period `Some(20000)` against `Some(10000)`.
- RQ-1 `remove_queue_without_randomness_changes_nothing`: Red: the queue was removed.
- TD-1 `teardown_without_randomness_leaves_the_link`: Red: one of two links gone.
- CF-1 `connect_failed_without_randomness_changes_nothing`: Red: `closed_before` 1 against 0.
- RC-1 `recreate_without_randomness_keeps_the_generation`: Red: generation 1.
- MP-1 `manage_pool_failed_draw_queues_nothing`: Red: 1 operation queued against 0.
- TS-1 `runtime::tests::take_step_retries_a_failed_draw`: Red: `Refused` against `Retry`.
- TR-1 `timing::tests::failing_after_fails_from_the_chosen_draw`, CD-1 `scheduler::control::tests::schedule_drawn_is_the_delayed_schedule`: green only (they pin the new test source and that `schedule_drawn` equals `schedule(When::Delayed)`).
- After the change all 14 pass.

**Not in this unit.**
- `World::work_pass` drops the outcomes after a failed one.
- `Scheduler::poll_due` stops at the first failed link.
- `World::fetched_multi` re-creates after delivering.
- `ControlOps::failed` (M7-S4).
- The runtime's `apply_action` reports a failed `AddRecv`/`AddSend` as `Refused` while the hub has registered the queue, which heals at the next add or open.

**Gates.**
1. `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
2. `secmp-client-core --features kat`: 377 run, 377 passed, 0 skipped (CORE_BASE 363 + 14); without `kat`: 63 run, 63 passed, 0 skipped.
3. harness `m6_control`/`m6_mut`/`m6_sched`/`m7_pool`/`m6_activity`: 144 run, 144 passed (8 slow), 198 skipped; QP-01…QP-05 (in `m6_control`), `strict_take_emits_nothing_at_the_take`, `rejected_pool_handout_keeps_spare`, `control_op_draws_from_timing_rng` among them, unchanged.
4. `cargo xtask step --strict policy`: PASS; `cargo xtask step fuzz-check`: PASS.

**ci-fast.** Run on e69f041: `ci-fast: PASS`; workspace nextest 1662/1662 (WS_BASE 1648 + 14), `secmp-client-core --features kat` 377/377 (CORE_BASE 363 + 14), harness 342/342 (HARNESS_BASE 342 + 0; harness step 1598 s), 0 skipped; evidence `docs/reviews/M07-evidence/s5-ci-fast.txt`.

Deviations:
- The helpers and tests of the core are at the end of `scheduler::core::tests` (the anchored `counters_now_moves_when_a_counted_step_runs` is in the sibling module `m6_mut`); their imports are at the top of `tests`, not inside each test.
- `ControlOps::schedule_drawn` and CD-1 were added before the red run (the 12 red tests compile either way; the function is not called on the base).
- The `Op` literal of `schedule_drawn` is `schedule`'s (the fields of `struct Op` are unchanged by S4); the `let base` anchor is the 8-space line in `delayed_due` (WEISUNG M7-S5b).
- `git grep -c sync_links` prints nothing (zero matches).
- `two_relays_up` names the send cap `out_cap` (clippy `similar_names`).
