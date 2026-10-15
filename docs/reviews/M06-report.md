# Milestone report — M6 Transport providers, constant-rate scheduler, measurements

Branch: `m06-transport` · Base: `6300b653d0f1f176b7a31470910d5214fa87b9cc` · Author: Claude Code · Date: 2026-10-09 … 2026-10-10
Phase A: `modell=claude-sonnet-5-5` (sub-agents: `claude-sonnet-5-5` ×2 — xtask gates G-03/G-04/G-05/G-06/G-08/G-10, and a first part of G-01/G-02; the remainder of that agent's rows was written by the main session)

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M06-planning/` (`BRIEF_M6.md`, `TEST-SPEC-M6.md` (177 rows: A 103, B 44, C 30), `OPEN-M6.md`,
`OPEN-M6-decided.md`, `ADR-051-proposed.md`). ADR-051 is appended to `docs/08-decisions.md` as **Proposed**; Part 2 (owner)
is not approved, so Phase A adds no third-party crate and no [DEP] row is built. Phases: A (Sonnet) → B (Opus, after the
owner's ADR-051 Part 2 approval) → C (Sonnet).

Phase A rows (103): AD-01…AD-06, S-01…S-32, CO-01…CO-08, QP-01…QP-05, OB-01…OB-08, LR-01…LR-06, AI-01…AI-06, AI-08,
AI-09, MR-01, MR-02, G-01…G-11, K-01…K-07, P-01…P-04, P-06, P-07, FZ-01, FZ-04, X-05, X-09.

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 1 | A | Commit 1: planning files, ADR-051 (Proposed), this plan, `docs/07` §M6 status line | — | done (`3ab7d24`) |
| 2 | A | Allowlist gate (workspace-only) and the M5 follow-ups: G-04 first, then G-01…G-11 | G-01…G-11, K-07 | done |
| 3 | A | `secmp-client-core::clock` (`Clock`, `SystemClock`, `ManualClock`), `TimingRng`, uniform draws | K-04, P-04 | done |
| 4 | A | `secmp-transport::{Channel, Session::{prepare, write_prepared, read_response, connect_outcome}}`, pipelined responses | AD-01…AD-06, FZ-01 | done |
| 5 | A | `scheduler::core`: LinkTask, modes, periods, phases, lifetimes, in-flight bound, prepare/tick split, FETCH lead, overrun | S-01…S-32, K-01…K-03, K-05, K-06, X-09 | done |
| 6 | A | Back-off and rotation/reconnect | LR-01…LR-06 | done |
| 7 | A | `outbox` (`Outbox`/`Persist`, `MemOutbox`/`MemPersist`), `Conversation` | OB-01…OB-08, P-03, P-07 | done |
| 8 | A | `pool` (`QueuePool`) and `control` (`ControlOps`) | QP-01…QP-05, CO-01…CO-08, P-06 | done |
| 9 | A | `secmp-testkit::VirtualDriver`; activity independence, measurements | AI-01…AI-06, AI-08, AI-09, P-01, P-02, MR-01, MR-02 | done |
| 10 | A | Kani, fuzz, xtask lists, `ci-fast`, `ci-full`, evidence under `M06-evidence/` | K-01…K-07, FZ-01, FZ-04, X-05 | done locally; PR run: see §4 |

## 2. What was built

- `crates/secmp-transport`: `channel.rs` — `Channel`, the sans-IO half of a SecMP-LINK session: `prepare` (build, sign, pad, seal
  under `k_c2r` at the next counter), `begin_write` (counter order, `Error::OutOfOrder`), `accept` (pipelined responses matched
  to the outstanding requests in order, each checked against its request; a misfit is `Rejected` and closes the channel);
  `Session::{prepare, write_prepared, read_response, connect_outcome, into_parts}`, `ConnectOutcome::ClosedBeforeRelayInfo`
  (AD-06); counters `seal_calls`/`sign_calls` (feature `harness`); `evicted.rs` (`evicted_is_plausible`, G-01);
  `RecvCap`/`SendCap` lose `PartialEq` (G-02).
- `crates/secmp-client-core`: `clock` (`Clock`, `SystemClock` — the one `SystemTime::now`/`Instant::now` site —, `ManualClock`),
  `timing` (`TimingRng`, rejection sampling, `fork`), `scheduler::{params, types, core (Scheduler, pure, backoff), control,
  pool, outbox, conversation}`, `kani_proofs`. The core is sans-IO: no stream, no clock, no runtime, `Output`s for a driver.
- `crates/secmp-testkit`: `harness::driver` (`VirtualDriver`, `SimClient`, `Gate`, traces with emission time and tick stamp,
  the cost model `prepare_cost`/`receive_cost`, the `after_write` hook), tests `m6_*` under `tests/harness/`.
- `crates/secmp-relay`: `Limits::link_age_ms` (default `LINK_AGE_MAX_MS`, behaviour unchanged) — see §5.
- `crates/secmp-proto`: `RelayKeys::relay_info` signs once, without a placeholder signature (G-09, R-144), counting accessor
  `SIGN_CALLS_KAT`.
- `xtask`: G-03, G-04, G-05, G-06, G-08, G-10, X-05 (new tests and gate wiring), `KAT_PACKAGES` += `secmp-client-core`,
  `PROPERTY_PACKAGES` += `secmp-testkit`, `KANI_*`, `FUZZ_*`, `LINT_ALLOWANCES` += `secmp-client-core/src/clock.rs`.
- `fuzz/`: targets `client_pipeline_responses` (FZ-01), `scheduler_event_sequence` (FZ-04) with committed seeds.
- Root `Cargo.toml`: `[workspace.dependencies]` += `secmp-relay`, `secmp-transport`, `secmp-client-core` (F-10);
  `[profile.dev.package."*"]`/`secmp-crypto`/`secmp-proto` `opt-level = 3` (dev/test only; one virtual hour fell from 21 s to 1.3 s).

### Phase B commit 1 — dependencies as landed (ADR-051 Part 2, Amendment 1)

The closure count is the number of packages in `cargo tree -p <crate> -e normal --target x86_64-unknown-linux-gnu`.

| Crate | Pin | Published | Used by | Closure (normal, Linux) |
|---|---|---|---|---|
| `arti-client` | `=0.46.0` (`tokio`, `rustls`, `onion-service-client`, `static-sqlite`) | 2026-09-02 | `secmp-transport` | 390 |
| `rustls` | `=0.23.46` (`aws_lc_rs`, `std`) | 2026-10-14 09:54 UTC (ADR-015 Am. 2 exception until 2026-10-21) | `secmp-transport`; `secmp-relay` (optional, `direct-tls`) | 15 |
| `tokio-rustls` | `=0.26.5` | 2026-09-04 | `secmp-transport` | 24 |
| `tokio` | `=1.53.1` (`rt`, `rt-multi-thread`, `net`, `time`, `sync`, `io-util`) | 2026-07-20 | `secmp-transport`, `secmp-client-core`, `secmp-testkit` | 9 |
| `aws-lc-rs` | `=1.18.1` (existing entry) | 2026-09-01 | `secmp-transport`; `secmp-relay` (optional, `direct-tls`) | 8 |
| `turmoil` | `=0.7.2` | 2026-04-24 | `secmp-testkit` (dev) | dev only |

Lock and supply-chain changes:
- `Cargo.lock`: +442 packages, no existing entry changed.
- X-01: ten packages younger than 7 days were pinned back: deranged 0.5.8, equivalent 1.0.2, schemars 1.2.2, smallvec 1.16.2,
  tokio-util 0.7.19, toml 1.1.6, toml_edit 0.25.15, toml_parser 1.1.3, zerocopy/zerocopy-derive 0.8.60. Youngest outside
  the exception: `toml_writer` 1.1.3+spec-1.1.0, 7 days.
- X-02: `deny.toml` has 46 `skip` entries; each names the direct dependency that pulls the version. No `skip-tree`.
- X-04: two license exceptions, `async_executors` (Unlicense) and `notify` (CC0-1.0). `priority-queue` is taken under MPL-2.0.
- X-03: 334 tracked vet exemptions are new; each names its direct dependency. Imports were refreshed (`cargo vet regenerate
  imports`; the 4 exemptions it pruned are kept). The closure check now works by (name, version) (ADR-036 Am. 1).
  `check_vet_closure`: 55 external crates, 0 exempted.

Evidence files:
- `M06-evidence/ci-fast-m6b-deps-8a31d4f.txt`
- `M06-evidence/vet-m6b-deps.txt`
- `M06-evidence/vet-suggest-m6b-deps.txt`. `cargo vet suggest --locked` panics in cargo-vet 0.10.2 (`storage.rs:837`); the
  file is the output of `cargo vet suggest`, which left the store unchanged: 359 exemptions, 43 unvetted.
- `M06-evidence/vet-deltas/rustls-0.23.45-0.23.46.diff`, from `cargo vet diff --mode local rustls 0.23.45 0.23.46` with the
  interactive header stripped: 23 files, +1160/−167.
- `M06-evidence/advisory-rsa-reachability.txt`

Tests: `cooldown::tests::{exception_allows_young_pinned_version_until_date, expired_exception_is_a_finding,
exception_does_not_cover_other_versions}`; `policy::tests::{audit_ignores_match_deny_toml,
vet_closure_exemption_for_closure_version_is_a_finding, vet_closure_other_version_of_closure_name_is_allowed,
vet_closure_of_this_workspace_has_no_exemptions, crypto_and_proto_stay_sans_io (AD-12),
normal_dependencies_match_adr_allowlist (G-04, table = ADR-051)}`.

`secmp-testkit` `m6_followups::scheduler_core_has_no_tokio` (X-09) still asserts that `scheduler/core/backoff.rs`, `core/mod.rs`
and `core/pure.rs` contain no `tokio` token. It also asserts that `tokio.workspace = true` is the only tokio line of the
`secmp-client-core` manifest.

## 3. Evidence per acceptance criterion (Phase A rows)

Commands, all at code head `7a67339` (WEISUNG M6-10, fix round 2): `cargo xtask ci-fast --strict`
(`M06-evidence/ci-fast-m6a-7a67339.txt`), `cargo xtask step kani` (`kani-step-7a67339.txt`; the seven client-core harnesses and
the K-02 negative control: `kani-m6a-7a67339.txt`), `cargo xtask step coverage`, and the AI rows (`AI-nextest-7a67339.txt`,
`AI-0x-7a67339.txt`, `MR-0x-7a67339.txt`). `ci-full` last ran at `03cc660` (`ci-full-m6a-03cc660.txt`) and is left to the PR
run for this round. The M6 rows are in the `nextest`/`kat` steps of those runs.

| Rows | Test (file `crates/secmp-testkit/tests/harness/` unless noted) | Result |
|---|---|---|
| AD-01…AD-06 | `m6_channel.rs`: `prepare_seals_before_write`, `prepared_frames_written_in_counter_order`, `pipelined_responses_matched_in_order`, `pipelined_mismatch_closes_link`, `frames_reassembled_from_any_chunking`, `closed_before_relayinfo_is_its_own_outcome` | pass |
| S-01…S-05, S-18 | `m6_sched.rs` (`strict_*`, `period_outside_set_rejected`, `tick_anchor_after_hs2`) | pass |
| S-06…S-15 | `m6_sched_bal.rs` (`balanced_*`, `lowbw_rate_bound_and_slot`, `direct_mode_implies_balanced`, `mode_change_tears_down_all_links`, `link_phase_uniform_and_independent`) | pass; KS p ≥ 0.01 |
| S-16, S-17, S-19…S-24 | `m6_sched_life.rs` | pass |
| S-25…S-32 | `m6_sched_io.rs` | pass |
| CO-01…CO-08, QP-01…QP-05 | `m6_control.rs` | pass |
| OB-01…OB-08 | `m6_outbox.rs` | pass |
| LR-01…LR-06 | `m6_reconnect.rs` | pass |
| AI-01…AI-06, AI-08, AI-09 | `m6_activity.rs` | pass; with real 20 ms / dummy 1 ms / receive 5 ms and the **actual emission time** compared: max \|Δt\| C2R = R2C = **0 ms** in AI-01/02/03 (`AI-0x-7a67339.txt`) over 64 traces × 6 h each; AI-04, AI-06 assert `Some(0)`; AI-05 compares both generators (VD-M6-A-12/13) |
| VD-M6-A-12…22 (fix round 2) | `m6_sched_io.rs`: `s_due_writes_handed_off_before_any_prepare`, `s_prepare_completing_after_tick_is_overrun_even_within_jitter`, `s_poll_due_performs_no_crypto_and_no_persist`, `receive_commit_failure_does_not_advance_ack`; `m6_activity.rs`: `ai_asymmetric_prepare_cost_does_not_move_emission`, `activity_comparator_detects_a_dropped_dummy`/`_a_resized_frame`/`_a_late_emission`; `m6_outbox.rs`: `receive_commit_failure_keeps_partial_and_trust`, `requeued_relayed_message_is_not_failed_after_30d`; `m6_control.rs`: `control_op_delay_from_related_op` (CO-03, executes), `related_control_ops_never_start_within_a_minute`, `pool_admission_respects_fetch_multi_limit`, `rejected_pool_handout_keeps_spare`; `m6_props.rs`: `prop_at_most_once_per_period` (P-02), `prop_no_message_key_reuse_across_crashes`, `prop_no_message_key_reuse_across_crashes_at_the_write`; `m6_channel.rs`: `pipelined_mismatch_closes_link` (AD-04), `fetch_multi_error_and_cells_same_queue_rejected`; `transport.rs`: `fetch_multi_error_and_cells_same_queue_rejected` | pass; see §5 items 13–24 |
| MR-01 | `m6_measure.rs::bandwidth_model_matches_capture` | pass; model = capture exactly per connection; Strict 3 045.9 B/s while up (spec 3 046.4), Balanced 4 786.3 (4 787.2), Low-bw 1 594.7 (1 595.7) (`MR-01.txt`) |
| MR-02 | `m6_measure.rs::drain_after_offline_virtual` | pass; Strict 232 / 8 512 evicted, drained in 42 recv ticks (≤ 45); Balanced 4×10 s 126 slots (≤ 130); Low-bw 5×40 s 149 slots (≤ 153) (`MR-02.txt`) |
| G-01 | `m6_followups.rs::ok_send_with_implausible_evicted_id_is_rejected` | pass |
| G-02 | `secmp-transport` `caps::tests::caps_have_no_partial_eq` + two `compile_fail,E0369` doctests | pass |
| G-03, G-04, G-05, G-06, G-08, G-10 | xtask tests `ct_guard_sites_use_ct_eq`, `normal_dependencies_match_adr_allowlist`, `fuzz_executor_depth`, `testkit_manifest_and_workflow_texts`, `mutants_report_has_unviable_breakdown`, `no_ignore_without_adr` | pass (`cargo test -p xtask`: 173 passed) |
| G-07 | `secmp-relay` `vectors::v16_checks_unpad`; `m6_followups.rs::h01_identical_queue_new_answers_ok` | pass |
| G-09 | `secmp-proto` `tests/link/vectors.rs::relay_info_without_placeholder_signature` | pass; V-01 bytes unchanged; the counter is `secmp_crypto::SIGN_CALLS_KAT`, incremented inside `Ed25519SigningKey::sign` (VD-2); hand mutation (a placeholder `sign` call re-added): FAIL `sign_calls = 1 per RELAYINFO`, left 2 right 1 (`vd2-g09-hand-mutation.txt`), removed again |
| G-11 | `m6_followups.rs::harness_cap_setters_take_effect`; `cargo mutants --test-tool nextest -p secmp-testkit --features harness -f '**/convo.rs'` | pass; 30 mutants: 25 caught, 0 missed, 5 unviable (`G-11-convo-mutants.txt`) |
| K-01…K-07 | `crates/secmp-client-core/src/kani_proofs.rs` | 7/7 verified (`kani-m6a-7a67339.txt`); negative control K-02 without the in-flight check: `VERIFICATION:- FAILED` (same file, after the marker line) |
| P-01…P-04, P-06, P-07 | `m6_props.rs` (`prop_*`, seed through `seed::master_seed`) | pass |
| FZ-01, FZ-04 | `fuzz/fuzz_targets/client_pipeline_responses.rs`, `scheduler_event_sequence.rs`; 120 s each in the `fuzz` step | pass, no finding |
| X-05 | xtask `gates::tests::kani_and_fuzz_lists_m6` | pass |
| X-09 | `m6_followups.rs::scheduler_core_has_no_tokio` | pass |

Row counts of this phase: implemented 103 / 103 · passing 103 · extra tests (named): `activity_comparator_detects_a_different_schedule`,
`activity_comparator_detects_an_extra_control_link` (VD-5) — negative controls of the AI comparator —, the three
reviewer-dictated `s_overrun_prepare_late_by_one_ms_writes_nothing`, `s_late_driver_wake_within_jitter_writes_once`,
`s_late_driver_wake_beyond_jitter_is_overrun` (VD-1, `m6_sched_io.rs`), and the unit tests of `clock`, `timing`, `params`,
`pure` in `secmp-client-core`. S-01 (VD-6) asserts six pairwise-distinct isolation keys for the six links; AI-01…AI-06,
P-01 compare the units of the one-shot links as well (VD-5).

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci-fast --strict` (Linux) | PASS at 7a67339 (`ci-fast-m6a-7a67339.txt`) |
| `cargo xtask ci-full` (as `linux-full`, with the CI delegations) | `ci-full: PASS` at 03cc660 (`ci-full-m6a-03cc660.txt`): fmt, clippy, policy, deny, vet, audit, cooldown, nextest, doctest, kat (239 s), perf, fuzz (3 785 s, 31 targets), coverage, miri, kani (3 071 s, 40/40), proverif, sbom, systemd PASS; ct, mutants, proverif-link, windows-native, windows-cross delegated to the PR run. (An earlier run at `bb9e45d` had failed `fmt` and the Kani cover pins; both were fixed before this one.) |
| Windows VM tests | not applicable in Phase A (no Windows-specific code); `windows-native`/`xwin-cross` run in the PR |
| KATs / differential | PASS (`kat` step, 5 packages incl. `secmp-client-core`) |
| Fuzz smoke | 31 targets × 120 s, PASS; committed seeds of the two new targets: `client_pipeline_responses` 6, `scheduler_event_sequence` 3 (counted by `git diff --name-status 6300b65..HEAD -- fuzz/corpus`). An earlier commit had carried 94 and 620 files: my manual fuzz runs had written libFuzzer's new inputs into the tracked corpus directory; they were removed again and the nine hand-made seeds restored |
| Mutation (`cargo mutants`) | delegated to the `mutants` CI job on the existing scope (crypto, proto, relay); `secmp-client-core`/`secmp-transport` enter the scope in Phase B (ADR-047 Am. 4); the one-off G-11 run above |
| Coverage (`cargo xtask step coverage` at 7a67339) | secmp-client-core 92.3 % (2239/2427), secmp-transport 88.8 % (926/1043), secmp-testkit 97.3 %, secmp-crypto 99.4 %, secmp-proto 97.7 %, secmp-relay 98.2 %, secmp-sys-mem 95.3 % |
| ProVerif / Kani / Miri | ProVerif PASS (`--models tr`; `proverif-link` delegated; at 03cc660); Kani at 7a67339: 40/40 harnesses (client-core 7/7, 0 failures, 3 068 s; `kani-step-7a67339.txt`); Miri PASS (at 03cc660) |
| `cargo deny` / `vet` / `audit` / cooldown | PASS (no new third-party crate) |
| Reproducible build | not run (no release-profile change) |

## 5. Deviations from spec / plan

None from `docs/03`/`docs/01`. Implementation choices the review should know (no ADR needed, listed for transparency):

1. **`secmp-relay::Limits::link_age_ms`** (new field, default `LINK_AGE_MAX_MS` = 24 h, behaviour unchanged). MR-02 needs a link
   that lives 24 h: the relay closes a link at exactly 24 h age (`>=`), so the 8 640th tick of a 24 h window was lost and the
   dictated figures (8 640 sent / 8 512 evicted) could not be produced. G-12 (Phase B) changes the relay's defaults
   (`link_idle_secs` 240, age 87 000 s); this knob is what it will set.
2. **R-144**: the placeholder signature of `relay_info` is replaced by a constant filler in the `sig` field (`[0x01; 64]`),
   which is not a signature and is not signed; the signed prefix and V-01 bytes are unchanged.
3. **Kani**: K-04 is split into `timing::accept_ceiling`/`sample_with` (one 64-bit division instead of two: 13 s instead of
   no verdict in 20 min); K-06 uses a bounded loop over 32 entries (353 s). `scheduler::conversation` is compiled out under
   `cfg(kani)` (`secmp-proto`'s codec types are stand-ins there).
4. **Scheduler API**: queue ids are assigned by the scheduler; control operations name host-held material by id
   (`ControlKind::QueueNew(QueueId)`, `LinkPut(n)`); the in-flight bound counts ticks (a Balanced slot of two requests counts
   once); the scheduler keeps two timing streams (links; control operations and pool — CO-07) from one seed (`TimingRng::fork`);
   `Output::Connect` carries the link kind, its period and the transport (LR-05).
5. **Profile**: `[profile.dev.package."*"] opt-level = 3` for the test builds (see §2).
6. **Test harness**: `cargo test` (threads in one process) exhausts locked memory for the hours-long scenarios; they are run with
   nextest (one process per test), as the gates do.
7. **Late tolerance withdrawn (reviewer VD-1); driver jitter 50 ms.** `Params::driver_jitter_ms` (default 50) replaces
   `late_tolerance_ms` (was 1 000): a frame is written at its tick only if it was ready; a tick without its frame is an
   overrun; a driver that wakes more than 50 ms after the tick finds an overrun. `Output::Write` carries the tick time `at`,
   the driver stamps traces with it.
8. **`LinkEvent::RouteDead(queue)`**: emitted by `World::outcome` in `scheduler/core/mod.rs` when a `SEND` is answered
   `ERR_NOQUEUE` (the route is marked dead, `Scheduler::route_dead(queue)`; spec §10.3 "route.mark_dead"); covered by S-30
   `send_response_handling` (asserts the event and `route_dead`).
9. **Sub-agent, denied shell command.** The sub-agent that began G-01/G-02/G-07/G-09/G-11 was refused its Bash call that
   appended the G-01 test code to `crates/secmp-testkit/tests/harness/transport.rs` (a shell append); it stopped and reported
   (from its report). I did not ask it to retry or to find another way; I wrote G-01, G-07, G-09, G-11 myself with the
   file tools (`m6_followups.rs`, `vectors.rs` edits). The earlier xtask sub-agent was not refused anything.
10. **Counters, where they live.** `seal_calls`, `sign_calls`: `secmp_transport::channel::counters` (feature `harness`,
    thread-local, `crates/secmp-transport/src/channel.rs`); `tr_encrypt_calls`, `persist_calls`, `encrypt_sites`:
    `secmp_client_core::scheduler::conversation::counters` (feature `kat`); `timing_draws`: `Scheduler::timing_draws()` (no
    feature); the relay-info signature counter: `secmp_crypto::SIGN_CALLS_KAT` (feature `kat`, VD-2).
11. **Test-Listener mit Shutdown-/Drain-Schranke, K = 10 (Shutdown → Drain), 100 (Drain → Ende), `FED_CALLS_MAX` = 1 500; `relay.rs` vollständig mutiert: 22 caught / 0 missed / 0 timeout (10 unviable)** (WEISUNG M6-5/M6-6, `M06-evidence/mutants-relay-4c3995b.txt`): Klasse „`serve` endet unter dem Mutanten nicht“ (`drain_finished -> false`, `start_drain -> ()`). `Fed` bricht jede der drei Phasen mit Phase, Accept-Zahl und virtueller Zeit ab. Phase A hat `drain_finished`/`start_drain` und ihre Aufrufer nicht geändert; der Produktcode ist beschränkt (`serve` endet nach `drain_secs`).
12. **`relay_executor` Fuzz-Crash `next_cell_id decreased` (CI-Lauf 38085054146), Ursache im Harness** (WEISUNG M6-7, `M06-evidence/fuzz-relay-executor-913248d.txt`): das Harness setzte sein `sweep`-Flag nach jedem Befehl mit Verdikt Run zurück, auch nach `SKEY` (ERR 6, erreicht `Relay::execute` nicht, `relay.rs:144`); der Sweep lief erst im folgenden `QUEUE_NEW` und legte die abgelaufene Queue mit denselben Schlüsseln neu an (`next_cell_id` 4 → 1). Zell-IDs gehören zur Queue-Instanz (spec §9.1 `:591`, `:593`); Produktcode unverändert. Fix: nur ein ausgeführter Befehl löscht das Flag, `SKEY` ändert den Store nicht, eine neue Queue beginnt bei 1 ohne Zellen; Test `rl_store::cell_ids_restart_on_queue_recreation`, Seed `fuzz/corpus/relay_executor/335f88e8…`.
13. **VD-M6-A-12 (a6a3b6b) — due writes before any preparation or receive work.** `Scheduler::poll` is now `poll_due(now)` (connect,
    lifetime, the writes of due ticks, teardown/overrun; no cell source, no seal, no persist; teardown releases are noted and
    handed over later) + `work(now, source)` (releases, the cells of completed responses, preparation, control operations) +
    `prepared_until(end)` (a frame whose preparation ended after its tick is an overrun even inside the jitter, OPEN-M6-13);
    `poll` remains as the three in one. `on_frame` no longer touches the cell source: it matches, moves the in-flight count and
    queues the outcome for `work`; `link_up` and `on_closed` take no source. `new_link_required_rotates` now exhausts the link
    (counter 2^20) because the relay's counter cannot be moved, so the last frame itself would be refused as out of step.
14. **VD-M6-A-13 (9e5b811) — the VirtualDriver records actual emission and models cost.** `TraceEntry.t_ms` is the driver's own
    time at the write, the core's stamp is `at_ms`; `prepare_cost(real, dummy)`/`receive_cost(per_cell)` accrue per cell prepared
    or decided and run on a serial worker that does not block the loop (its end is reported with `prepared_until`). AI-01…AI-06
    run with 20/1/5 ms and assert 0 ms. **Proof of the new row:** with the old ordering (the writes handed out after the
    preparation) `ai_asymmetric_prepare_cost_does_not_move_emission` fails: `left: (Some(19), Some(19)) right: (Some(0),
    Some(0))` (`AI-asym-old-ordering-proof-7a67339.txt`); that driver mode is removed.
15. **VD-M6-A-14 (b944a68) — receive commit failure.** `Conversation::on_deliver` stages the reassembly and trust on copies
    (`Inbox` is `Clone`) and keeps them only after `commit`; tests `receive_commit_failure_keeps_partial_and_trust` and
    `receive_commit_failure_does_not_advance_ack` fail with the old order. (The trust half is asserted unchanged; no
    key-change cell is constructed.)
16. **VD-M6-A-15 (6081367) — control operations rebase on the actual related start.** Each delayed op keeps its drawn delay;
    it may start only at `max(due, latest related start + delay)`; one op per correlation per `take_due`; `next_due` and
    `control_due` report the rebased time; a retry after a failure follows the back-off.
17. **VD-M6-A-16 (e112af0) — pool admission.** `check_balanced(relay, added: Option<(period, counts_in_rate)>, mode)`: the added
    queue is an entry in every case; `pool_queue_ready` admits before it registers the spare.
18. **VD-M6-A-17 (2783fc4) — rejected pool handout.** The spare is put back as the oldest one (`QueuePool::untake`).
19. **VD-M6-A-18 (d20031a) — 30-day failure.** `first_relayed_at` is recorded on `relayed` (the outbox has no clock of its own:
    its latest known time), kept by both requeues; only never-relayed messages fail (spec §10.4, `docs/03` line 682).
20. **VD-M6-A-19 (94e35db) — P-02 per queue.** sid → (period, times); case 0 is {10 s, 80 s}; a hand mutation of `rr_select`
    (`>= 10_000`) fails it and passed the old assertion.
21. **VD-M6-A-20 (889e331) — AD-04.** Two outstanding requests, request 1 answered with request 2's `cmd_seq`; the unknown
    sequence is its own part.
22. **VD-M6-A-21 (1d88bf4) — P-07 boundaries.** (i) after `commit` before release (`MemPersist::crash_after_next_commit`),
    (ii) after release before write, (iii) after write at the driver's `after_write` hook; restart from the durable state
    (`Conversation::restart_from`, `Outbox::restart`); no key twice, every message delivered after a drain; a stale durable
    state at the restart fails the row.
23. **VD-M6-A-22 (26bf2bb) — FETCH_MULTI.** A rid in both `errors` and `cells` is `Rejected` in `Channel` and in the M5 twin.
24. **Small items (7a67339).** `timing_draws()` returns `(links, control)`; planted `activity_comparator_detects_a_dropped_dummy`,
    `…_a_resized_frame`, `…_a_late_emission`; the driver obligations are documented in `scheduler/mod.rs`.

### Phase B rows

- **§0b (verifier follow-ups, `11b3725`):**
  - `policy::tests::vet_closure_exemption_without_version_is_a_finding`
  - `SANS_IO_FORBIDDEN` now also contains `futures`, `async-std` and `smol`
  - ADR-036 Am. 1 wording
  - the advisory field of the rustls cooldown exception
- **X-01…X-04:**
  - `cooldown::tests::cooldown_covers_m6_lock`
  - `policy::tests::deny_duplicate_skips_are_justified` (46 entries)
  - `policy::tests::vet_records_for_m6_closure`
  - `policy::tests::licenses_cover_m6_closure`

  The gates themselves are `cooldown`, `deny` and `vet`, all green after the owner's records.
- **X-06:** `gates::tests::windows_builds_nasm_from_source`.
  - Every workflow sets `AWS_LC_SYS_PREBUILT_NASM: "0"` in its top-level `env:`.
  - `windows-native` and `dispatch-windows` install NASM (`choco install nasm`, then `nasm -v`); `xwin-cross` and
    `dispatch-xwin` already had the apt NASM step.
  - The CI log is the evidence that no prebuilt object is used. The choco package version is not pinned; I could not check
    it from the container (no network to chocolatey.org).
- **MU-01:** `gates::tests::mutants_scope_includes_client_core_and_transport` and
  `gates::tests::merge_mutants_runs_unites_outcomes_and_survivors`. ADR-047 Am. 4 is appended, with an implementation note.
  - `MUTANT_PACKAGES` now has five entries.
  - `secmp-client-core` and `secmp-transport` run in a second cargo-mutants run per shard. Their tests live in
    `secmp-testkit/tests/harness`, and the transport has no `kat` feature.
  - The second run uses `--test-package` for client-core, transport and testkit, `--features harness` and
    `--test-tool nextest`.
  - It sets `--timeout 900` and skips the ten long harness tests listed in `MUTANT_HARNESS_SKIP_TESTS`.
  - Its outcomes are merged into the shard's `mutants.out`.
  - The `mutants` tool set gains nextest.
  - Local smoke run of the exact second-run command line on `crates/secmp-transport/src/evicted.rs`: 7/7 caught.
  - `docs/mutants-accepted.md` gains §Excluded. No Arti glue file exists yet; the Tor glue file comes in §2.5.
- **COV-01/COV-02:** `gates::tests::coverage_strict_includes_client_core` and `gates::tests::coverage_transport_80_with_tor_glue`.
  `COVERAGE_STRICT` now includes `secmp-client-core`. The transport ignore pattern is unchanged, with no exclusion list.

## 6. Dependencies added or bumped

Phase A: none (workspace path crates only: `secmp-client-core` → `secmp-transport`; `secmp-testkit` → `secmp-client-core`).
Phase B commit 1: see §2, "Phase B commit 1 — dependencies as landed".

## 7. Open risks and known limitations

- AI-01…AI-03 take ≈ 1–1.5 min each on a 32-core host (64 traces × 6 h on threads); on a 4-core runner expect several minutes.
- The tick path is "equal" in the virtual driver; the real-time path (tokio driver, Tor) is Phase B/C (AI-07).
- `link_age_ms`/`link_idle` defaults are still the M5 placeholders until G-12.
- **API change of fix round 2 (VD-M6-A-12):** the driver calls `poll_due(now)` and flushes its writes, then `work(now, source)`,
  then `prepared_until(end)`; `on_frame`, `link_up`, `on_closed` take no cell source. **What a Phase B driver must do**
  (also in the module documentation of `scheduler/mod.rs`; this text belongs in the Phase B brief): flush `poll_due` first;
  resolve every `Output::Connect` with `link_up` or `connect_failed` — a link in `Connecting` has no deadline in
  `next_deadline`; wake at every `next_deadline`, including the FETCH-lead deadline (`tick − fetch_lead_ms`), which is
  load-bearing; run the preparation off the I/O loop, so that its cost decides only when a frame is ready.
- **CI budget (WEISUNG M6-11, VD-M6-A-23).** `linux-full` exceeded its 240 min since Phase A (PR runs 38064677208 and 38132969656:
  exit 143 inside `[9] kani`). Measured (`M06-evidence/ci-jobs-m6a-4e426c3.txt`): the three biggest steps are fuzz 63.8, miri
  49.3 and kat 41.4 min (coverage 39.7); against the last green main run kat grew by 15.7 and coverage by 31.3 min; kani on
  the runner is client-core 9.8 + proto ~63 + relay ~4 = ~77 min. Kani is now the required job `kani` (150 min; `linux-full`
  delegates it with `--delegated kani`; same caches and runner image; the job runs `cargo xtask step --strict kani`). Expected
  `linux-full` after the split: ~204 min, margin ~36 min to 240 (the faster run: ~182 min). No threshold, harness list or
  other timeout changed. If the margin falls below 30 min the next candidates are fuzz, miri, kat and coverage.
- M6-12: `ci.yml:240` / `ci-dispatch.yml:384` carried an invalid YAML plain scalar as step name (`: ` inside); push run 38538150090 failed with ‚Invalid workflow file‘, no PR run existed for `b83ed0b`; names quoted, policy lint for unquoted step names added (2 tests).
- M6-15: job `kani` was killed by a runner shutdown (exit 143) four times on this branch, 6–22 min into `cargo kani --package secmp-proto -Z stubbing` (runs 38064677208, 38132969656, 38549219665 attempts 1–2), never on main; container run M6-13b verifies 7/7 + 30/30 without error; xtask now logs a runner resource trace every 20 s when `SECMP_RUNNER_TRACE` is set, enabled on the `kani` job.
- M6-16: root cause of the four `kani` runner shutdowns — the Phase-A `[profile.dev.package.*] opt-level = 3` overrides (added for the scheduler tests) also applied to the Kani build; `secmp-proto` at opt-level 3 drove CBMC to 15.5 GB RSS on the 16 GB runner (run 38606378025, runner-trace 17:43:22–17:44:02Z, swap full, exit 143). Overrides moved to `[profile.test.package.*]`; the Kani build is back to opt-level 0 as on main.
- Reviewer question (M6-16): `cargo miri` builds with the `test` profile; whether the opt-level 3 override lowers Miri's MIR-level UB detection is to be verified before the Phase A report is final.
- **MIRI-01 (Phase B, report only).** Command: `cargo +nightly-2026-09-21 miri test -p secmp-proto -v 2>&1 | grep -oE
  "(-C opt-level=[0-9]|-Zmir-opt-level=[0-9]|-Zmiri[a-z-]*)" | sort -u`. The pinned nightly is needed because Miri is not
  on the stable toolchain. Output:
  ```
  -C opt-level=3
  -Zmiri-backtrace
  ```
- **Mutants CI time (ADR-047 Am. 4).** The second run adds 903 mutants: client-core 601, transport 302. The first run has
  2 411. In the local smoke run (32 cores, `-j 3`) each harness mutant took 1–150 s to build and 67–74 s to test. On
  the 4-core runner the time per shard may come close to the 280-min step budget. The per-shard times of the first PR run
  go into §7 (BRIEF §2.7).
- M6-17: cooldown fetch retries transient curl errors (ADR-015 Am. 1) after run 38616364662 `linux-fast` failed on a single connect error.
- The virtual worker is serial and non-blocking; a single-threaded real driver whose preparation blocked its loop would
  delay *other* links' due writes by the preparation of an active link — the cost model cannot show that, the Phase B
  driver must not do it.

## 8. Blocked / questions for the reviewer or owner

None for Phase A. Phase B waits for the owner's ADR-051 Part 2 approval and `cargo vet` records.

### Phase B commit 1 (BRIEF M6-B §1) — BLOCKED, 2026-10-15, base `8a31d4f`

Nothing committed. The ADR-051 Part 2 set, resolved exactly as the table pins it, fails `cargo deny check advisories`. This
matches the §1 STOP "an advisory". Evidence: `M06-evidence/deny-m6b-deps-8a31d4f.txt`. The uncommitted manifests and lock are
in `target/fable/M6-B/deps-wip-8a31d4f.patch` (not tracked).

What was done before the stop: the six pins in `[workspace.dependencies]` and the crate edges as in the ADR table. The relay
got `rustls` and `aws-lc-rs` as optional deps behind `direct-tls`, off by default. Resolving added 442 new crates to
`Cargo.lock`; no existing entry changed. Ten crates were younger than 7 days and were pinned back with `cargo update --precise`:
deranged 0.5.8, equivalent 1.0.2, schemars 1.2.2, smallvec 1.16.2, tokio-util 0.7.19, toml 1.1.6, toml_edit 0.25.15,
toml_parser 1.1.3, zerocopy/zerocopy-derive 0.8.60. After that `cargo xtask cooldown` passed: 561 packages, youngest
toml_writer 1.1.3, 7 days.

Advisories against the pinned set (`cargo deny --locked check advisories`):

| ID | Crate | Pulled by | Fix |
|---|---|---|---|
| RUSTSEC-2026-0349 "Unauthenticated ServerHello can downgrade later connections to classical key exchange" | `rustls` 0.23.45 | direct (`secmp-transport`, `secmp-relay`), `tokio-rustls`, `futures-rustls`, `tor-rtcompat` | ≥ 0.23.46 |
| RUSTSEC-2026-0346 "`Debug` impls for client session values expose TLS secrets" | `rustls` 0.23.45 | as above | ≥ 0.23.46 |
| RUSTSEC-2026-0347 "Buffered application data sent to outer server after ECH rejection" | `rustls` 0.23.45 | as above | ≥ 0.23.46 |
| RUSTSEC-2026-0348 "Brotli certificate decompression can allocate up to 1 GiB before authentication" | `rustls` 0.23.45 | as above | ≥ 0.23.46 |
| RUSTSEC-2023-0071 "Marvin Attack" (vulnerability) | `rsa` 0.9.10 | `tor-llcrypto`, `tor-key-forge`, `ssh-key-fork-arti` (normal edges, Arti 0.46.0) | none (only `0.10.0-rc.*` exists) |
| RUSTSEC-2024-0436 `paste` unmaintained | `paste` 1.0.15 | 15 `tor-*` crates, `pwd-grp`, `slotmap-careful` | none |

Why there is no fix inside the brief:
- `rustls` 0.23.46 is the first fixed version. It was published 2026-10-14 09:54 UTC, so it is inside the 7-day cooldown
  until 2026-10-21 09:54 UTC (CLAUDE.md §1.9). It is also not the version the ADR-051 table pins.
- The `rsa` and `paste` findings come from Arti 0.46.0 itself and have no upgrade path. The ADR-051 Context does not
  mention them. An ignore needs an ADR and a reason (`deny.toml`, `expect::AUDIT_IGNORES`).

The other `cargo deny` findings were as the ADR expected:
- licenses: `async_executors` (Unlicense) and `notify` (CC0-1.0) are rejected; `priority-queue` passes under the existing
  MPL-2.0 allowance.
- bans: 42 duplicated crate names, which become the `skip` list.
- `cargo vet --locked`: red for the whole new closure, since no exemptions had been written yet.

Questions for the reviewer/owner:
1. **rustls.** Should the ADR-051 pin move to `rustls =0.23.46`, with commit 1 waiting until 2026-10-21 09:54 UTC? Or is
   there a cooldown exception (ADR)? `futures-rustls` and `tor-rtcompat` also resolve to the single `rustls` in the graph,
   so the bump fixes Arti's TLS too.
2. **rsa / paste in the Arti closure.** Should these become ADR'd advisory ignores with reasons? For `rsa`, Arti uses RSA
   for Tor relay identity keys; whether only public-key verification is reachable is a question for the reviewer, not
   established here. The alternative is a different `arti-client` version, which means re-checking the ADR-051 table.

**Resolved by WEISUNG M6-B-0 (2026-10-15):**
- D1: `rustls =0.23.46`, using the cooldown exception of ADR-015 Am. 2.
- D2: RUSTSEC-2023-0071 ignored. Evidence: `M06-evidence/advisory-rsa-reachability.txt`, ending `reachable_private_key_ops=none`.
- D3: RUSTSEC-2024-0436 ignored.

### Phase B commit 1, second attempt (WEISUNG M6-B-0) — BLOCKED, 2026-10-15, base `8a31d4f`

Nothing committed. Everything WEISUNG M6-B-0 §Tun 1–4 asks for is in the working tree:
- the ADR texts;
- `COOLDOWN_EXCEPTIONS` and the cooldown code with the three named tests;
- `AUDIT_IGNORES` and `deny.toml` ignore, with test `audit_ignores_match_deny_toml`;
- 46 `skip` entries and 2 license exceptions;
- 337 tracked vet exemptions and the import refresh;
- the G-04 table widened to ADR-051;
- AD-12 `crypto_and_proto_stay_sans_io`;
- X-09 `scheduler_core_has_no_tokio` adapted to Phase B (`tokio.workspace = true` is the only tokio line).

The tracked changes are saved as `target/fable/M6-B/deps-wip-2-8a31d4f.patch`. Two of the weisung's STOP conditions hold.

Gate state at the second stop:
- passing: `cargo deny check` (all four sections), `cargo xtask cooldown` (prints
  `cooldown: exception rustls@0.23.46 until 2026-10-21 (RUSTSEC-2026-0349 (ADR-015 Am. 2))`), xtask 187/187 tests, clippy,
  fmt, nextest, kat (all suites);
- failing: `policy` (vet-closure, 1 finding), `audit` (1 warning), `vet` (40 owner crates).

**STOP 1 — a further advisory.** `cargo audit --deny warnings` reports **RUSTSEC-2025-0141**, `bincode` 2.0.1 "unmaintained".
- `bincode` is in `Cargo.lock` only as an optional dependency of `typed-index-collections` 3.5.0, which is in the Arti closure.
- `cargo tree -i bincode --target all -e normal,build,dev` prints nothing: it is never compiled.
- `cargo deny` (per-target graph) does not report it.
- This is the same pattern as RUSTSEC-2026-0173 (`proc-macro-error2`), which is ignored in `AUDIT_IGNORES` only.

**STOP 2 — `cargo vet` red outside the named groups.** `check_vet_closure` refuses an exemption whose crate *name* is in the
normal closure of `secmp-crypto`/`secmp-proto`, because an exemption can serve as the base of an imported delta.
1. Feature unification with Arti brings three new crates into that closure:
   - `zeroize_derive` 1.5.0: `zeroize` default-features, via `aes` ← `tor-llcrypto`;
   - `libm` 0.2.16: via `num-bigint-dig` ← `ssh-key-fork-arti` (`rsa` feature) ← `tor-key-forge`;
   - `const-oid` 0.10.2: `digest` 0.11 default, via `sha3` default ← `derive-deftly-macros` ← `arti-client`.

   None of the five import sets covers these versions. The traces come from `cargo tree --workspace -e normal,features -i <crate>`.
2. Eight Arti-closure versions share a name with a crate already in the closure:
   - `const-oid` 0.9.6
   - `crypto-common` 0.1.7
   - `getrandom` 0.2.17 and 0.3.4
   - `hkdf` 0.12.4
   - `rand` 0.8.8 and 0.9.5
   - `sha3` 0.10.9

   They are not covered by imports either. Policy finding:
   `vet-closure: cargo-vet exemptions inside the secmp-crypto/secmp-proto closure: const-oid 0.10.2, crypto-common 0.2.2,
   getrandom 0.4.3, hkdf 0.13.0, libm 0.2.16, rand 0.10.3, sha3 0.11.0, zeroize_derive 1.5.0`.

Without exemptions for these 11 versions, `cargo vet --locked` is red for them in addition to the 40 owner crates:
arti-client, rustls 0.23.46, tokio, tokio-rustls and 36 `tor-*`. With the exemptions, `policy` is red.

`cargo vet --locked` with the 337 exemptions: "Vetting Failed! 40 unvetted dependencies", exactly the owner groups.

Questions:
1. **RUSTSEC-2025-0141.** Should it be an `AUDIT_IGNORES` entry (lock-only, never compiled; no `deny.toml` entry because
   `cargo deny` does not report it), like RUSTSEC-2026-0173?
2. **The 11 versions.** How should they be vetted? One route is owner audits/trust records; three of them
   (`zeroize_derive` 1.5.0, `libm` 0.2.16, `const-oid` 0.10.2) are now inside the zero-exemption closure. The other route
   is a reviewer decision on how `check_vet_closure` treats other versions of a closure crate's name.

**Resolved by WEISUNG M6-B-0b (2026-10-15):**
- D4: RUSTSEC-2025-0141 is in `AUDIT_IGNORES` only, carved out of `audit_ignores_match_deny_toml` like RUSTSEC-2026-0173,
  and is listed in the ADR-051 Am. 1 triage.
- D5: the closure is (name, version) (ADR-036 Am. 1). `zeroize_derive` 1.5.0, `libm` 0.2.16 and `const-oid` 0.10.2 have no
  exemption; the eight other versions carry X-03 exemptions.
- D6: the source assertion of `scheduler_core_has_no_tokio` is kept (files in §2).

Gates at commit 1: `cargo xtask ci-fast --strict` green except `vet`. `cargo vet --locked` reports "Vetting Failed! 43
unvetted dependencies": arti-client 0.46.0, tokio 1.53.1, tokio-rustls 0.26.5, the 36 `tor-*` 0.46.0, rustls 0.23.46,
zeroize_derive 1.5.0, libm 0.2.16 and const-oid 0.10.2.

**Owner requests (vet records).** These come from `cargo vet suggest`:
- `rustls` 0.23.46: suggest offers `cargo vet diff rustls 0.21.6 0.23.46` (publisher `ctz`; 180 files, +36233/−21084). Our
  delta file is 0.23.45 → 0.23.46.
- `zeroize_derive` 1.5.0: `cargo vet diff zeroize_derive 1.4.2 1.5.0` (6 files, +132/−70). The note reads "this project
  trusts github:RustCrypto/utils — consider cargo vet trust zeroize_derive github:RustCrypto/utils".
- `libm` 0.2.16: `cargo vet diff libm 0.2.6 0.2.16` (191 files, +10152/−3644). Note: "consider cargo vet trust libm
  rust-lang-owner".
- `const-oid` 0.10.2: `cargo vet inspect const-oid 0.10.2` (7987 lines, publisher `tarcieri`). Note: "consider cargo vet
  trust const-oid tarcieri".
- `arti-client`, `tor-*`, `tokio`, `tokio-rustls`: the routes in the ADR-051 table.

## 9. Checklist before requesting review

- [x] All Phase A rows evidenced above
- [x] `cargo xtask ci-fast --strict` green at `7a67339`; Kani 40/40 at `7a67339`; `ci-full` green (§4) at `03cc660`, not rerun
- [x] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [x] Vectors untouched
- [ ] PR run on `linux-fast`, `windows-native`, `xwin-cross`, `linux-full` (after the push by the reviewer)
- [x] Threat model and spec untouched
