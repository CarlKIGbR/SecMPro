# Milestone report — M7 Client core: identity, contacts, store, invitations, sessions, CLI

Branch: `m07-client-core` · Base: `bf550999fb2c7771153863f1da2f19adb5a677b5` · Author: Claude Code · Date: 2026-10-27 … · Phase A: `modell=claude-opus-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M07-planning/` (`BRIEF_M7.md`, `TEST-SPEC-M7.md` (176 rows: A 65, B 71, C 40),
`OPEN-M7.md`, `OPEN-M7-decided.md`, `ADR-053-proposed.md`, `ADR-054-proposed.md`, `ADR-055-proposed.md`). ADR-053,
ADR-054 and ADR-055 are appended to `docs/08-decisions.md` as **Proposed**. Phases: A (Opus) → B (Sonnet; Opus weisung
for SC-01…SC-10) → C (Sonnet). [O-01] rows are built only after the owner's "ADR-053 accepted"; no `Cargo.toml`
dependency change before the A0 report, "ADR-055 accepted" and the owner's vet records.

Phase A rows (65): ST-01…ST-20, PC-01…PC-13, FO-03, CT-01, CT-02, CT-04, CT-05, BK-01…BK-07, G7-00…G7-10, G7-12…G7-14,
G7-15a, G7-16, G7-18, K7-02, FZ-01, FZ-02.

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 0 | A | Commit 0: `docs/reviews/M06-review.md`, `docs/07` §M6 status "merged" | — | done (`05489fc`) |
| 1 | A | Commit 1: planning files, ADR-053/054/055 (Proposed), this plan, `docs/07` §M7 status line | — | done |
| A-1 | A | No dependency change, no store code: xwin scope (OPEN-M7-04), `harness` pinned job + `dispatch-harness` (OPEN-M7-18), `JOB_BUDGETS`, mutant harness suite split/skip (OPEN-M7-19), killer filter (OPEN-M7-20), Kani RSS guard (OPEN-M7-26), `AUDIT_IGNORES` pin, informative ct target with its registration; G7-00 in the first commit after 2026-10-30 02:00 UTC | G7-00, G7-05, G7-07, G7-08, G7-09, G7-10, G7-12, G7-16, CT-04 | done; G7-00 landed in A-4 @ `eb9d3b8` (2026-10-30 02:01 UTC) |
| A0 | A | ADR-055 probe in a scratch crate outside the workspace (three `VET_CLOSURE_TARGETS`, `fuzz/Cargo.lock`, cargo-fuzz sanitizer build of the OpenSSL/SQLCipher C code, Arti state-DB smoke, `windows-latest`); report only, no `Cargo.toml` change | — (ADR-055 precondition) | report delivered: `docs/reviews/M07-evidence/A0-probe.md` |
| A-2 | A | After the A0 report, "ADR-055 accepted" and the owner's vet records: `rusqlite` in `secmp-store`, `argon2` in `secmp-crypto`, allowlist rows, vet/deny/cooldown | G7-01, G7-02, G7-03, G7-04, ST-08 | done @ `bf54d98` |
| A-3 | A | Store code with the `kat`-only `secmp_store::kat::TestKey`: client-core/testkit → store edges first; pragmas, version check, defensive mode (ST-20, Q128), no temp files, schema, migrations, secure delete, view-once, expiry; persistence contract (`to_parts`/`from_parts`, `StoreOutbox`, store `Persist`); mutants/coverage scope | G7-06, ST-01…ST-04, ST-09, ST-13…ST-18, ST-20, PC-01…PC-13, G7-18, G7-13, G7-14 | closed @ `cdc3c0a` (ST-17: store half; A-3b/A-3d/A-3e fix-ups; Kani exception Q138; `modell=claude-opus-5-5`) |
| A-4 | A | After "ADR-053 accepted": wrap, table keys, record seal, `SecretPage` secrets, ct target `store_unlock_reject` with its registration, backup, export forensic, store fuzz targets | ST-05…ST-07, ST-10…ST-12, ST-19, CT-01, CT-05, CT-02, BK-01…BK-07, FO-03, FZ-01, FZ-02, G7-15a (ST-10, BK-04 [REF]-open) | **A-4 built @ `c3c1dcf`; Phase A closes with the green PR run (BRIEF_M7 §5, reviewer)** (`modell=claude-opus-5-5`) |
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

Phase A, A-1 (numbers; raw files under `docs/reviews/M07-evidence/`). Phase B/C rows: not yet built; A-2…A-4 rows below.

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
| ST-10 [REF] | `keys::tests::table_keys_match_vectors` | pass; nine `K_t` pairwise distinct, `K_db` distinct from each, each equal to `secmp_crypto::hkdf` (salt 0^32, App. A label) for MK = 32 × 0x4d. **ST-10 open [REF] — waits for `vectors/store.json` (OPEN-M7-38)** |
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
| BK-04 [REF] | `backup::tests::wrapping_and_header_kat` | pass; fixed salt/`MK_bk`/`N'`/`N` (kat entropy, `kat_small`): magic 0..13, ver 13, salt 14..30, params 30..42, `N'` 42..66, bwrap seal 66..146, `N` 167..191, header 154 B; `bwrap` and the body seal equal the item-6 compositions recomputed from `argon2id`, `hkdf`, `Caead::seal`; wrong passphrase → `Err(Unlock)`. **Byte-exact clause open [REF] (OPEN-M7-38)** |
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

No deviation from the spec. Deviations from the weisung's wording or the TEST-SPEC rows (each for the reviewer, Q-A6…Q-A13):

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
