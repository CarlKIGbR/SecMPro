# Milestone report — M6 Transport providers, constant-rate scheduler, measurements

Branch: `m06-transport` · Base: `6300b653d0f1f176b7a31470910d5214fa87b9cc` · Author: Claude Code · Date: 2026-10-09 … 2026-10-10 · Phase C1: `modell=claude-sonnet-5-5`, 2026-10-18
Phase A: `modell=claude-sonnet-5-5` (sub-agents: `claude-sonnet-5-5` ×2 — xtask gates G-03/G-04/G-05/G-06/G-08/G-10, and a first part of G-01/G-02; the remainder of that agent's rows was written by the main session)

## 1. Plan (written before implementation, updated during)

**Phase C1 closed @ `25625bc`** (PR run #165 = 39660191651, all jobs green; local `ci-full` evidence `M06-evidence/ci-full-m6c1-c570d98.txt` at `c570d98`, the later commits `5e1a136`/`25625bc` are covered by run #165) (BRIEF M6-C1; WEISUNG M6-C1-2, -3, -4; Phase C part 1 of 2, `modell=claude-sonnet-5-5`). What C1 did: C-1 hygiene, documentation and the onion re-encode note (DOC-M6-C-1, DOC-M6-C-2, T-01/T-02, MIRI-01); C-2 the unmatched-`frame_written` counter and the `unwritten` bound (items 10, 11, 10b; C2-01…C2-07), Kani K-C1…K-C6 (13/13 client-core harnesses); C-3 the survivors of PR run 160 (item 1: 82 mutants killed, 16 accepted rows, no timeout accepted), ADR-047 Amendments 6 and 7 (12 shards); C-4 `ci-verdict` (ADR-045 Amendment 2, V-01…V-07); C-5 R-01, the `socket2` memo and this report. **Phase C2** (BRIEF_M6-C2: TC-*, SIM-*, AI-07, AI-10, MR-03…MR-07, CT-00, PV-01, X-07, X-08) follows on this head; **M6 merges only after C2**.

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
| 11 | B | BRIEF M6-B §1 dependencies; §2.1 gates; §2.2 driver; §2.3 TLS; §2.4 relay `direct-tls`; §2.5 Tor; §2.6 owner requests | X-01…X-04, X-06, MU-01, COV-01, COV-02, AD-07…AD-12, P-05, TLS-01…TLS-15, G-12, TOR-01…TOR-09, FZ-02, FZ-03 (TOR-10, X-10: owner, §6) | done; see "Phase B closed" |

**Phase B closed @ `cdf2b31`** (code; the report and evidence commit follows it). Phase B: `modell=claude-opus-5-5`.
- **How it got here.** After the P4 closing at `1423029`, the external reviews of `f68d923` (WEISUNG M6-B-5, Codex;
  M6-B-5b, GLM) found blockers. All are fixed (§6). EXTB-1 needed the one core change of Phase B, approved by WEISUNG
  M6-B-6: (A)/(A′) @ `cdf2b31`, with its proofs re-run (§6, "Decisions of WEISUNG M6-B-6").
- **Local `ci-full`:** PASS at `cdf2b31`, with the linux-full delegations (windows-native, windows-cross, mutants, ct,
  proverif-link; `--models tr`).
  - Kani was not delegated: it ran locally, 40/40, 2920 s.
  - fuzz 4130 s, miri 2093 s, coverage 363 s.
- **`ci-fast --strict`:** PASS at `cdf2b31`.
- **Coverage:**

  | Crate | Coverage |
  |---|---|
  | `secmp-client-core` | 92.3 % (min 90) |
  | `secmp-transport` | 85.7 % (min 80) |
  | `secmp-relay` | 97.7 % |
  | `secmp-proto` | 97.7 % |
  | `secmp-crypto` | 99.4 % |
  | `secmp-testkit` | 93.7 % |

- **X-01:** youngest crate `toml_writer 1.1.3+spec-1.1.0`, 8 days.
- **`cargo vet --locked`:** `Vetting Succeeded (236 fully audited, 1 partially audited, 322 exempted)`.
- **Evidence (`docs/reviews/M06-evidence/`):**
  - `ci-fast-m6b-cdf2b31.txt`
  - `ci-full-m6b-cdf2b31.txt`
  - `kani-m6b-cdf2b31.txt`
  - `coverage-x01-m6b-cdf2b31.txt`
  - `vet-m6b-cdf2b31.txt`
  - `ai-tokio-64-m6b-cdf2b31.txt`
  - `ai-sync-64-m6b-cdf2b31.txt`
  - `mutants-core-cdf2b31.txt`
- **Handover B→C:** a green PR run (incl. `ct`, `mutants`, `proverif-hx`, `proverif-link`). `mutants` stays red until
  OPEN-M6-B-2 (§6) is worked in M6-C.

**P4 state, superseded:** Phase B closed @ `1423029`; the paragraphs below describe that run.
- **Local `ci-full`:** PASS, run with the linux-full delegations (windows-native, windows-cross, mutants, ct,
  proverif-link; `--models tr`).
  - Kani was not delegated. It ran locally, 40/40, because `crates/secmp-relay` and `client-core/src/scheduler/run.rs`
    changed since the last local run.
  - Times: fuzz 4033 s, miri 2112 s, kani 2908 s, coverage 350 s.
- **`ci-fast --strict`:** PASS.
- **Evidence (`docs/reviews/M06-evidence/`):**
  - `ci-fast-m6b-1423029.txt`
  - `ci-full-m6b-1423029.txt` (the per-gate tables and the summary)
  - `kani-m6b-1423029.txt`
  - `coverage-x01-m6b-1423029.txt` (coverage per crate and the X-01 youngest-crate line)
  - `vet-m6b-1423029.txt`
  - `ai-tokio-64-m6b-1423029.txt` (AI-01…AI-06 over the tokio driver, 64 traces, max |Δt| = 0 ms)
  - The per-shard mutants times are in §7.
- **Coverage (COV-01/COV-02)** — the thresholds are met; there is no exclusion list:

  | Crate | Lines | Coverage | Phase A |
  |---|---|---|---|
  | `secmp-client-core` | 2745/2984 | 92.0 % (min 90) | 92.3 % |
  | `secmp-transport` | 1746/2037 | 85.7 % (min 80) | 88.8 % |
  | `secmp-relay` | 2738/2803 | 97.7 % | — |
  | `secmp-proto` | 6658/6814 | 97.7 % | — |
  | `secmp-crypto` | 2525/2541 | 99.4 % | — |
  | `secmp-testkit` | 1695/1814 | 93.4 % | — |

  The transport's drop comes from `tor/arti.rs`, the live-network glue, which no test runs.
- **X-01:** youngest crate `toml_writer 1.1.3+spec-1.1.0`, 7 days; the only exception is `rustls@0.23.46` until
  2026-10-21 (ADR-015 Am. 2). 561 registry packages in `Cargo.lock` + `fuzz/Cargo.lock`.
- **`cargo vet --locked`:** `Vetting Succeeded (236 fully audited, 1 partially audited, 322 exempted)`.
- **The handover B→C needs a green PR run** (incl. `ct`, `mutants`, `proverif-hx`, `proverif-link`). The `mutants` job
  will stay red until OPEN-M6-B-2 (§6) is worked in session M6-C.

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

### Phase B P2 — what was built (§2.2)

- `crates/secmp-transport`:
  - `ops.rs`: the commands of spec §12.1 as sans-IO exchanges, shared by both transports. `RelayQueueTransport` now runs
    on it.
  - `driver/`: `AsyncQueueTransport` (the seven operations, `&mut self`, `impl Future + Send`), `AsyncSession`,
    `AsyncRelayQueueTransport`, `StreamProvider`, `Isolation`, `ProviderStream`.
- `crates/secmp-client-core`:
  - `clock::TokioClock`.
  - `scheduler/run.rs`: `Driver` (the tokio driver), `Providers`/`Only`, `Directory`, `HandshakeEntropy`/`OsHandshakes`,
    `ControlRunner`/`ControlEffect`, `Worker`/`BlockingWorker`/`Job`/`JobDone`, `RunLog`/`Step`/`Purpose`,
    `CONNECT_TIMEOUT_MS`.
- `crates/secmp-testkit`:
  - `harness::mem`: `MemRelay` and `MemProvider`, the in-process relay behind `tokio::io::duplex` with unit-level timing.
  - `harness::tokio_driver`: `TestDirectory`, `TestHandshakes`, `TestControl`, `CostedWorker`.
  - Tests: `m6_tokio`, `m6_tokio_ai`, `m6_driver`.

## 3. Evidence per acceptance criterion (Phase A rows)

### Phase C1: the rows of `docs/07` §M6 (6 Deliverables, 5 Acceptance criteria)

Every named test exists in the tree (the xtask test `docs::m06_report_acceptance_rows_are_named` checks it); `OPEN — C2` rows are those of BRIEF_M6-C2. The seven older rows of `docs/mutants-accepted.md` (`core/mod.rs:1733:21`, `:1733:44`, `run.rs:859:34`, `run.rs:1050:54`, `tls.rs:366:13`, `tor/mod.rs:53:26`, `:60:23`) name the places at the C1 head; the gate of the next PR run measures it.

| Row | docs/07 §M6 | Evidence (tests; commands) |
|---|---|---|
| M6-D1 | Deliverable: `secmp-transport::tor` and `::tls` | `the_configuration_is_tls13_with_one_hybrid_group`, `pin_needs_one_certificate_and_a_parseable_spki`, `tls_client_offers_exactly_x25519mlkem768`, `tls_handshake_with_pinned_relay_succeeds`, `tls_no_resumption_no_early_data`, `tor_never_falls_back_to_direct`, `onion_reencode_canonical_inputs_round_trip`; `cargo xtask ci-fast --strict` |
| M6-D2 | Deliverable: scheduler (`LinkTask`, modes, periods, phases, in-flight bounds, reconnect), `ControlOps`, `QueuePool`, `outbox` | `balanced_round_robin_due_rule`, `driver_rr_reservation_does_not_depend_on_worker_timing`, `unwritten_ledger_is_bounded_without_completions`, `control_ops_is_empty_follows_the_queue`, `queue_pool_lists_only_relays_that_are_short_and_knows_its_spares`, `outbox_states`, Kani `kani_unwritten_bound`; `cargo xtask ci-fast --strict`, `cargo kani -p secmp-client-core` (13/13) |
| M6-D3 | Deliverable: `two-clients` binary | OPEN — C2 (TC-01…TC-09) |
| M6-D4 | Deliverable: `turmoil` simulations | OPEN — C2 (SIM-01…SIM-*) |
| M6-D5 | Deliverable: activity-independence test | `activity_independence_strict_virtual`, `ai01_strict_tokio`, `ai06_both_directions_tokio`, `ai07_fault_paired_tokio`; the remaining rows OPEN — C2 (AI-07, AI-10); `SECMP_AI_TRACES=64` harness run 196/196 at `ee3c66f` |
| M6-D6 | Deliverable: measurement report `docs/measurements/M6-traffic.md` | `bandwidth_model_matches_capture`, `drain_after_offline_virtual`; the report and the other rows OPEN — C2 (MR-03…MR-07) |
| M6-A1 | Acceptance: two machines exchange messages over real Tor ⚙ | OPEN — C2 (TC-*, TOR-10 owner-operated, §6); in the tree: `tor_never_falls_back_to_direct`, `transport_selection_follows_user_choice_only` |
| M6-A2 | Acceptance: two machines over direct TLS | OPEN — C2 (TC-*); in the tree: `tls_handshake_with_pinned_relay_succeeds`, `tls_spki_pin_mismatch_rejects`, `relay_and_client_spki_walks_agree` |
| M6-A3 | Acceptance: the activity-independence test passes | `activity_independence_strict_virtual`, `ai01_strict_tokio`, `ai06_both_directions_tokio`; AI max Δt = 0 ms |
| M6-A4 | Acceptance: simulations pass | OPEN — C2 (SIM-*, TC-*) |
| M6-A5 | Acceptance: ⚙ Arti bootstraps and the transport KATs pass in the Windows VM | OPEN — C2 (X-07, X-08; TOR-10 and X-10 owner-operated, §6); the `windows-native` job runs `tls_client_is_tls13_only` |

### Phase A rows

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

- **TC-03 `two_clients_scripted_invitation_handshake`:** passing — handshake scripted outside the scheduler (deviation D-C2-1, M7); the
  invitation queue and the reply queues are spares of the clients' `QueuePool`s (pool 2 → 1, no `QUEUE_NEW` of the script).

- **SIM-01…SIM-10 (Phase C2-2):** tests in §10 ("C2-2 turmoil simulations", "C2-2b"). **SIM-07** is re-dictated by the reviewer (no (E);
  `responses_read == 0`); it runs with two rig parameters of its own, no default changed: the relay's `HELLO`→`HS1` timeout 300 s
  (default 30 s) and the drivers' connect timeout 600 s (default 120 s). SIM-10 asserts the downstream witnesses of `present = 2`,
  not the field itself (§10).

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
- **P2, §2.2 driver.** All tests are in `crates/secmp-testkit/tests/harness/` and run with feature `harness` on a paused
  tokio clock.
  - AD-07: `m6_driver::async_session_equals_sync_session`. `HELLO`, `HS1`, link keys, the first three frames each way and
    the whole capture are equal.
  - AD-08: `m6_driver::async_transport_matches_m5_outcomes`. T-01…T-06 give the same outcome log and the same bytes in both
    directions.
  - AD-09: `m6_driver::queue_transport_async_signature`. The reading of the row (reviewer, WEISUNG M6-B-3 §0.3): no
    *workspace* crate depends on `async-trait`. It is in `Cargo.lock` only through `arti-client` 0.46.0 and its `tor-*`
    crates.
  - AD-10: `m6_driver::stream_provider_impls`, so far for `MemProvider` and a fault-injecting wrapper. Tor, TLS and Turmoil
    providers join the row in P3/P4 and Phase C.
  - AD-11: `m6_driver::driver_has_no_wall_clock`.
  - P-05: `m6_driver::prop_pipelined_matching_any_chunking`, 16 cases by default.
  - **Driver obligations, one test each:**
    - (i) `m6_driver::driver_flushes_due_writes_before_work`
    - (ii) `m6_driver::driver_reports_late_preparation_as_overrun`
    - (iii) `m6_driver::driver_resolves_every_connect`: a failing provider, a provider that never answers (connect timeout,
      resolved at exactly +30 s), and a relay that closes before `RELAYINFO`.
    - (iv) `m6_driver::driver_wakes_at_the_fetch_lead`
    - (v) = AD-11 `driver_has_no_wall_clock`
    - (vi) `m6_driver::driver_slow_work_does_not_delay_other_links`: a 900 ms / 400 ms worker against a free one gives
      max |Δt| = 0 C2R and R2C, and more than 10 frames left while the worker was busy.
  - Further driver tests: `blocking_worker_runs_jobs_on_the_blocking_pool`, `only_refuses_the_other_transport`,
    `driver_releases_unused_cells`, `m6_tokio::tokio_driver_smoke_strict_one_hour`.
  - **AI-01…AI-06 over the tokio driver** (`m6_tokio_ai::ai01_strict_tokio` … `ai06_both_directions_tokio`), with costs
    20/1/5 ms. AI-01…03 ran 16 traces × 6 h each, AI-04/05/06 ran 8/4/8. Max |Δt| = 0 ms C2R and R2C in every trace; the
    timing draws and the one-shot links are equal.
  - Coverage at P2 (local `cargo xtask step coverage`, 444 s): `secmp-client-core` 2722/2961 = 91.9 % (floor 90 %),
    `secmp-transport` 1362/1544 = 88.2 % (floor 80 %), `secmp-testkit` 93.0 %.
  - At P2 the core was untouched (`git diff b5aa27b -- crates/secmp-client-core/src/scheduler/core` empty); since then
    the core changed once in Phase B: EXTB-1 (A)/(A′) @ `cdf2b31`, proofs re-run (client-core Kani 7/7; AI-01…AI-06 sync 64 traces 6/6; AI-01…AI-06 tokio 16 and 64 traces with the extended oracle 6/6; S-* suites 40/40 plus the client-core unit tests 11/11; harness binary 164/164; second mutants run on `core/mod.rs`, see §6).

- **P3, §2.3 TLS (`secmp-transport::tls`; tests in `crates/secmp-transport/tests/tls/`, feature `harness`).**
  - TLS-01 `tls_client_offers_exactly_x25519mlkem768`: the provider has one group, 0x11EC. The `ClientHello` has
    `supported_groups` = `key_share` = [0x11EC] and no SNI.
  - TLS-02 `tls_client_is_tls13_only`: a TLS 1.2-only server fails with `Rejected`, 0 SecMP bytes; `supported_versions` =
    [0x0304].
  - TLS-03 `tls_no_classical_fallback`: servers with [X25519] and with [secp256r1] fail. A hand-made `HelloRetryRequest`
    for X25519 fails too, with exactly one `ClientHello` and only an alert record after it.
  - TLS-04 `tls_handshake_with_pinned_relay_succeeds`: loopback TCP; `X25519MLKEM768` and ALPN `secmp/1`; then
    HELLO…HS2, `PING`, `QUEUE_NEW` and `FETCH` over it.
  - TLS-05 `tls_spki_pin_mismatch_rejects`: pin bytes 0 and 31 flipped, and a second valid certificate; all `Rejected`,
    0 SecMP bytes.
  - TLS-06 `tls_pin_is_the_only_trust_anchor`: pinned certificates that are expired, not yet valid, wrongly named or
    self-signed are accepted. A CA-signed certificate without the pin is rejected, and so is a chain of two.
  - TLS-07 `tls_certificate_verify_still_checked`: the pinned certificate with `CertificateVerify` signed by another key
    is rejected.
  - TLS-08 `tls_no_resumption_no_early_data`: the server sends 2 tickets; on the second connection the `ClientHello` has
    no `pre_shared_key` and no `early_data`; `enable_early_data` is false.
  - TLS-09 `tls_alpn_secmp1_required`: a server without ALPN, and one with only `h2`, are both `Rejected` before any SecMP
    byte.
  - TLS-10 `tls_provider_is_explicit`: with aws-lc-rs's default provider (≥ 3 groups) installed as the process default,
    our configuration still has 1 group. The source scan finds no `ClientConfig::builder()` / `ServerConfig::builder()`
    in `crates/` or `xtask/`.
  - TLS-11 `tls_link_bytes_equal_other_transports`: `HELLO`, `HS1` and the first three C2R frames are byte-identical over
    TLS on loopback and in memory.
  - Unit tests in `tls.rs`: `tlv_is_total_on_short_and_odd_input`, `pin_needs_one_certificate_and_a_parseable_spki`,
    `the_configuration_is_tls13_with_one_hybrid_group`.
  - FZ-02: fuzz target `tls_pin_verifier` with 5 tracked seeds, `max_len` 8194 (count byte + end-entity DER ≤ 8192 B, room
    for an ML-DSA-65 certificate, `docs/05` §7; derived in `fuzz_max_len.rs`). Local smoke 120 s: 76 452 773 runs, cov
    307, ft 583, no failure.
  - **Implementation choices for you to check:**
    - **TLS 1.3 only.** `ClientConfig::supports_version` is crate-private in rustls 0.23, so the provider keeps only the
      TLS 1.3 cipher suites. Every configuration built is asserted with `tls::is_tls13_hybrid_only`: all suites TLS 1.3,
      one group, `X25519MLKEM768`. TLS-02 checks it on the wire. Confirmed by the reviewer as the reading of "asserted
      at config time" (WEISUNG M6-B-4 §0.6).
    - **No SNI** (`enable_sni = false`; confirmed by the reviewer, WEISUNG M6-B-4 §0.3): one certificate per relay, so a
      host name would only be metadata on the wire.
    - **`spki_of`** is our own total DER walker: definite lengths, minimal encoding, at most 3 length bytes. Fuzzed by
      FZ-02.
    - **Fixtures.** The test certificates are built in code (hand-written Ed25519 X.509 DER) in
      `crates/secmp-transport/tests/tls/fixture.rs`. There is no `rcgen`, and `openssl` needs approval in the container.
      The TLS tests are in `secmp-transport`, which has `rustls`/`tokio-rustls` as normal dependencies, plus a
      dev-dependency on `secmp-testkit`, as `secmp-crypto` already has. No crate gained a new third-party edge.
  - **Fuzz lock.** Since commit 1, `fuzz/Cargo.lock` had none of the ADR-051 crates, so the CI fuzz build resolved them
    freshly, outside the vetted, cooldown-checked lock. It is now regenerated from the main `Cargo.lock`: 559 packages,
    the main lock's versions, plus `libfuzzer-sys` 0.4.13 and `arbitrary` 1.4.2 as before. Cooldown passes.
  - The nightly fuzz split is now 30 × 240 s + 2 × 3600 s (`fuzz_executor_depth`, `nightly_budget_per_target`,
    `fuzz-nightly.yml`).
  - Fixture certificates are now built in `secmp_testkit::harness::cert` (moved from the transport fixture, unchanged;
    no TLS crate needed), so that the relay rows below use them too.

- **P4a, §2.4 relay `direct-tls` (BRIEF M6-B §2.4; WEISUNG M6-B-1 had it in P3, WEISUNG M6-B-3 limited P3 to §2.3, so it
  lands here, before §2.5).**
  - **What.** `secmp-relay` feature `direct-tls` (off by default; the default build stays std-only, ADR-049):
    - `src/tls.rs`: `server_config` (`builder_with_provider`, aws-lc-rs with the TLS 1.3 suites and `X25519MLKEM768` only,
      asserted at config time; ALPN `secmp/1`; `send_tls13_tickets` 0, `max_early_data_size` 0, `NoServerSessionStorage`,
      no client authentication; `with_single_cert` refuses a key of another certificate).
    - `TlsConn<S>` (rustls `StreamOwned<ServerConnection, S>` in the existing thread-per-connection model): the
      handshake runs inside the first reads, bounded by the `HELLO`→`HS1` timeout like any connection start; the first
      plaintext is handed on only after TLS 1.3, `X25519MLKEM768` and ALPN `secmp/1` are checked; nothing is written
      before; the close sends `close_notify`.
    - `TlsListener<L>` and `Listeners<A, B>`: the onion loopback listener and the direct one behind the one accept loop,
      asked in turn, sharing `max_connections`.
    - `src/spki.rs` (default build): `spki_of` / `pin_of`, the same DER walk as the client's, and the `spki <cert.der>`
      subcommand.
    - Configuration (`[listen]`): `direct_tls` (empty or absent = off), `direct_tls_cert`, `direct_tls_key` (DER files).
      The file keys without `direct_tls` are refused. So is `direct_tls` in a build without the feature, and a
      certificate or key that does not load: the start is refused before any listener binds.
  - **Feature wiring.** Relay feature `kat` turns on `direct-tls`. The relay's own suite and the mutation gate's first
    run (which builds the package with `--features kat`) then compile and test the listener. `secmp-testkit/harness`
    names `secmp-relay/direct-tls` too. No new crate, no new third-party edge: `rustls`/`aws-lc-rs` stay optional
    dependencies of the relay only.
  - **G-12 (OPEN-M6-15):** `DEFAULT_LINK_IDLE_SECS` 900 → 240, `LINK_AGE_MAX_MS` 86 400 000 → 87 000 000. The M5 C-3
    tests `linked_idle_bound_closes_the_connection` and `linked_age_bound_closes_at_link_lifetime` were updated to the new
    values; the busy link of the age test now sends every 200 s, inside the idle bound.
  - **Tests:**
    - TLS-12 `relay_direct_tls_config` (`secmp-transport` `tests/tls/relay.rs`; plus the relay unit test
      `config::tests::direct_tls_is_off_by_default_and_needs_both_files`).
    - TLS-13 `relay_direct_tls_serves_link` (loopback TCP; `secmp_testkit::harness::DirectRelay` runs
      `secmp_relay::server::serve` over `Listeners` with the real clock and one thread per connection, as the binary
      does).
    - TLS-14 `relay_tls_refuses_classical_client` (loopback): the relay sends exactly one alert record and no SecMP
      byte; with `max_connections` = 1 a compliant client is served afterwards.
    - TLS-15 `relay_spki_command_prints_pin` (`secmp-relay` `tests/cli.rs`, the binary on a fixture file; the pin is
      recomputed from the SPKI's byte range).
    - G-12 `relay_idle_and_age_bounds_from_schedule` (`secmp-testkit` harness) and the relay unit test
      `idle_and_age_defaults_are_the_schedule_bounds`. 25 h in Strict and in Low-bw at P = 80 s with a 24-h lifetime on
      the default relay limits: no `TornDown(Closed)`, and a link reaches its lifetime. The SIM part of the row is
      Phase C.
    - Extra:
      - `secmp-transport` `relay::relay_tls_refuses_a_client_without_alpn` (loopback);
      - `secmp-relay` `cli_direct_tls_refuses_the_start_without_a_usable_certificate`;
      - `secmp-relay` `tests/relay/direct_tls.rs`, over an in-memory socket, no network:
        - `direct_tls_serves_the_link_handshake`
        - `direct_tls_close_sends_close_notify`
        - `direct_tls_refuses_classical_groups`
        - `direct_tls_hands_nothing_on_without_alpn`
        - `listeners_alternate_and_fall_through`
        - `tls_listener_wraps_raw_connections`
        - `server_config_refuses_a_foreign_or_broken_key`
        - `provider_check_refuses_other_providers`
        - `any_conn_delegates_to_its_connection`
        - `tls_conn_passes_the_poll_timeout_on`
        - `tls_conn_flush_delivers_buffered_bytes`
      - `secmp-testkit` `m6_spki::relay_and_client_spki_walks_agree`: the two DER walks agree on 20 000 mutated
        certificates;
      - `tlv_length_forms_at_their_bounds` in both walks.
  - **Mutants.** Local `cargo mutants -p secmp-relay --features kat` over `tls.rs`, `spki.rs`, `config.rs` and `main.rs`.
    The first pass had 18 misses and 4 timeouts; the tests above were added for them. The final pass over `tls.rs` and
    `spki.rs`: 0 missed, 0 timeouts. The last survivor, `TlsConn::flush` → `Ok(())`, was confirmed killed by hand.
  - **For you to check:**
    - `docs/05` §5 shows `direct_tls` only. The two file keys (DER) are new, and the `openssl` command OPEN-M6-09 names
      for `docs/05` §7 is not written there yet. I did not edit `docs/05`.
    - Observation, not caused by this work: in the 25-h Low-bw run of the G-12 test, the second client (seed 1204)
      tears its links down with `Overrun` every 1–3 min. The same happens with the M5 limits 900 s / 86 400 s, so this is
      scheduler or virtual-driver behaviour. I report it and do not change it (OPEN-M6-B-4); the core changed once in Phase B: EXTB-1 (A)/(A′) @ `cdf2b31`, proofs re-run (client-core Kani 7/7; AI-01…AI-06 sync 64 traces 6/6; AI-01…AI-06 tokio 16 and 64 traces with the extended oracle 6/6; S-* suites 40/40 plus the client-core unit tests 11/11; harness binary 164/164; second mutants run on `core/mod.rs`, see §6).

- **P4b, §2.5 Tor (`secmp-transport::tor`, not in the Kani build like `arti-client`).**
  - **What.**
    - `tor/mod.rs`, the testable part, generic over `TorBackend`:
      - `config(profile)`: Arti state in `<profile>/tor/state` and cache in `<profile>/tor/cache` via
        `TorClientConfigBuilder::from_directories`; `fs-mistrust` on, with `ignore_environment()` so that
        `ARTI_FS_DISABLE_PERMISSION_CHECKS` cannot switch it off.
      - `TorProvider<B>`: a fresh `IsolationToken::new()` for every `connect`, so per link and per reconnect; nothing
        is cached.
      - `TorState`: the gate. `observe(Status)` maps Arti's status to `TorEvent::{Progress(%), Ready, Blocked}`, each
        change once. Links are admitted only while ready and not blocked: before that `Error::TorNotReady`, after a
        bootstrap failure `Error::TorUnavailable`. A backend failure is `TorUnavailable`.
      - `onion_host`, `target`: own RFC 4648 base32 of the 35 onion bytes + `.onion`, checked with Arti's `TorAddr`
        parser to be a host and not an IP address; port `ONION_PORT` = 443.
    - `tor/arti.rs`, the glue: client creation (`BootstrapBehavior::Manual`, `create_unbootstrapped`), the bootstrap
      task, the status follower (polls `bootstrap_status()` every 250 ms; `futures` is not a dependency, so the event
      stream is not used), and `connect_with_prefs` with the token. It is in `MUTANT_EXCLUDE_FILES`, with its reason in
      `docs/mutants-accepted.md` §Excluded.
    - `driver::EitherStream` and `secmp_client_core::scheduler::run::Selected<T, D>`: the `Providers` implementation
      that takes the transport the scheduler names, which comes from the user's direct setting alone
      (`Scheduler::set_direct`). Tor goes to Tor only. Direct without `RelayRef.direct` is `NoDirectEndpoint` with no
      attempt anywhere. No fallback path exists.
    - New errors `TorNotReady`, `TorUnavailable`.
  - **Tests:**
    - `secmp-transport` `tests/tor/main.rs` (recording backend, no network):
      - TOR-01 `tor_config_uses_profile_state_dir`: the cache dir from `dir_mgr_config()`, the state dir in the built
        config, no `${ARTI…}` default; on Unix a 0777 directory fails `fs_mistrust().check_directory`; the source never
        disables the check.
      - TOR-02 `tor_isolation_token_per_link`: 5 links plus 1 reconnect give 6 distinct tokens.
      - TOR-03 `tor_no_link_before_bootstrap`: at 0 / 50 / 99 % `TorNotReady` and 0 backend calls; ready gives 1
        stream; blocked again gives no new link.
      - TOR-04 `tor_bootstrap_events_mapped`.
      - TOR-08 `onion_address_from_relayref`.
      - TOR-09 `onion_connect_uses_port_443`.
      - Extra: `tor_connect_failure_is_tor_unavailable`.
    - `secmp-testkit` harness `m6_tor`:
      - TOR-05 `tor_never_falls_back_to_direct`: with a direct endpoint present, a failed bootstrap, Tor not ready, and
        3 failed onion connects; the counting direct provider is called 0 times.
      - TOR-06 `transport_selection_follows_user_choice_only`: the transport is taken from a real `Scheduler` with
        `set_direct(false|true)`; (off, present) → Tor; (on, present) → TLS; (on, absent) → `NoDirectEndpoint` with 0
        calls to either provider.
    - TOR-07 `xtask` `policy::tests::arti_feature_set_is_pinned`: `cargo metadata` resolved features; `arti-client` ⊇
      {`onion-service-client`, `rustls`, `tokio`, `static-sqlite`}, none of `hs-pow-full`, `compression`, `native-tls`,
      `experimental`, `experimental-api`, `__is_experimental`; `tor-hsclient` has no `hs-pow-full`.
    - FZ-03 `fuzz/fuzz_targets/relayref_onion_to_hsid.rs`:
      - `Onion::from_bytes` is total and accepts exactly 35 bytes with version 3 and the checksum (checked
        independently in the harness);
      - for every accepted address, `tor::target` gives port 443, a 62-character host, and a base32 round trip to the
        input;
      - the harness also builds the valid address of the input's first 32 bytes.
      - 5 tracked seeds, `max_len` 36. Local smoke 120 s: 6 079 855 runs, cov 356, ft 777, no failure.
  - **Deviation, needs your decision (TOR-08, FZ-03).** Both rows ask that "Arti's `HsId` parse re-encodes to the same
    35 B".
    - In `arti-client` 0.46, `HsId` is public only with feature `experimental-api`, which TOR-07 forbids.
      `tor-hscrypto` is not a dependency of the workspace: adding it, even dev-only, is beyond the ADR-051 table.
    - **Substitute, implemented:**
      - TOR-08 runs Arti's own HsId check through `connect`: an unbootstrapped client (`BootstrapBehavior::Manual`; no
        network, `connect_with_prefs` parses the onion address before it waits for bootstrap) answers
        `ErrorKind::BootstrapRequired` for our host and `InvalidStreamTarget` for a broken checksum.
      - FZ-03 checks the independent checksum, the base32 round trip and Arti's `TorAddr` parse.
    - **Alternatives:** (a) accept the substitute; (b) a dev-only `tor-hscrypto =0.46.0`, which is already in
      `Cargo.lock` as a transitive crate: an ADR-051 amendment plus vet; (c) wait for a stable `HsId` in Arti.
  - **⚙ TOR-10 / X-10:** the owner request is below. `secmp-testkit/examples/tor_smoke.rs` is the Tor smoke check: Arti
    in a fresh profile, `READY`, then HELLO…HS2 and `PING` to a given `RelayRef`. No test runs it.

- **Extended AI oracle (WEISUNG M6-B-5 EXTB-1 / M6-B-6 §0.2; `m6_tokio_ai.rs`, `MemRelay::store_changes`).** Besides
  the emission comparison (max |Δt| = 0 in both directions), every idle and active run of the six tokio repeats asserts:
  - (a) no teardown other than at a lifetime's end (no `Rejected`, no `Overrun`, …);
  - (c) frames on every tick of every scheduled link: its frame times are one period apart, the first one period after
    it came up, and no tick is missing before its end;
  - (b) the relay-visible SEND sequence — queue `rid` and its `next_cell_id`, in time, as the relay's store changed
    after each unit of the client's own connections — is the idle run's, in every trace.
    - The acknowledgement progression (each queue's head) is compared in one extra trace per AI-01…AI-03 whose peers
      send nothing: no `PeerSend` events and peer delivery receipts switched off.
    - The receipts are needed beyond the approved "no `PeerSend`" rule. They answer the client's own real messages, so
      a `PeerSend`-free trace still brings cells that the client acknowledges, at the peers' pump times plus the fetch
      delay; seen in the first run of the oracle.
  - On the old core the oracle fails AI-02: 162 `Rejected` teardowns in the idle run alone.
  - The sync AI-04…AI-06 take `SECMP_AI_TRACES` for the local 64-trace run; their CI defaults (8, 4, 8) are unchanged.

### FINAL4 round (external review of `007e5b2`, Astra; WEISUNG M6-C1-5) — findings FIN4-1…7, all fixed, none accepted as is

- **FIN4-1 (blocker)** the rows `channel.rs:329:20` and `driver/session.rs:241:24` claimed `NewLinkRequired` needs the `u64` counter space; `Link::seal` returns it at `LINK_MAX_FRAMES` (2^20). Three tests (`m6_mut::channel_prepare_at_the_frame_limit_needs_a_new_link_and_stays_open`, `async_send_closes_the_session_when_the_bound_falls_inside_a_command`, `async_ping_at_the_frame_limit_fails_locally_and_leaves_the_session_open`; the harness gets `Setup::session`), both rows removed. The polarity in the WEISUNG text ("channel closed" at the bound) is the reverse of the code for the single-frame case — at the bound nothing is sealed and the channel stays open; the multi-frame case closes it; the tests assert what the code does, and are red against the mutant either way.
- **FIN4-2 (blocker)** `SystemClock::mono_ms` rows: `clock::tests::system_clock_counts_from_its_origin` (origin 60 s back, no wait); rows removed; the ruling of WEISUNG M6-C1-4 §0.2 is withdrawn.
- **FIN4-3** relay `Deadlined::flush`: `tls::m6_mut::deadlined_flush_reaches_the_socket` (rustls `complete_io` over a socket whose flush fails); row removed.
- **FIN4-4** `reason_of` `Closed` (`m6_mut::reason_of_a_closed_channel_is_closed`), `Channel::synced` and `Session::ensure_open` (in-crate `session::m6_mut` tests over the testkit relay); three rows removed; `tls.rs:366:13` sharpened (the second `||`; the ALPN disjunct stays intact).
- **FIN4-5** ADR-042 Amendment 5 text corrected (`hk`/`mk` are secret keys, `pn`, `n`, `dh_pk`, `ek_pq`, `ct_pq` encrypted header contents; what the nonce target monitors); `OPEN-M6-C1-2` (§7).
- **FIN4-6** R-01 relabelled as internal acknowledgement readiness, relay-observed acks as a second series (30/40/50/60 s), four values asserted before the zip.
- **FIN4-7** the TLS-off example of `docs/05` §5 parses (key lines commented out, an enabled stanza in §7); `secmp-relay config::tests::documented_listen_stanzas_parse`.
- Counts reconciled in `mutants-c1-41ee485.md` (17 M6 rows at the pin, 9 now); ADR-047 Amendment 7 says 44 harness tests.

### PR run 163 round (WEISUNG M6-C1-6): a gate defect, fixed

The mutants gate (`undocumented_survivors`) compared the raw cell text of `docs/mutants-accepted.md`, where a pipe in a description is written `\|` (GFM), with the `||` / `|` that cargo-mutants prints, so
three rows (`core/mod.rs:751:39`, `tls.rs:366:13`, `tor/mod.rs:53:26`) never matched. Fixed in the gate (`unescape_table_pipes`), with three tests and a policy check on the row shape; the
fourth survivor, `MemPersist::set_durable`, has a killer. Details and red quotes: `mutants-c1-41ee485.md`, section "PR run 163".

### RUSTSEC-2026-0382 and the `ci-full` exit status (WEISUNG M6-C1-7)

- **Advisory.** `rustls-webpki` 0.103.15 ("Certificate verification may accept distrusted intermediates", published 2026-10-20) turned `deny`, `audit` and `sbom` of the last `ci-full` red. Handled by a lockfile-only bump to 0.103.16 (`Cargo.lock`, `fuzz/Cargo.lock`; no `Cargo.toml` change, no other crate moved — `cargo update` also re-pointed `tempfile`'s `getrandom` edge, which was reverted by hand, `cargo metadata --locked` accepts both locks), never an ignore. The 7-day cooldown is waived for this patch release under ADR-015 Am. 2 (exception list in `docs/08`, `expect::COOLDOWN_EXCEPTIONS` until 2026-10-27). The delta was read in full (`vet-deltas/rustls-webpki-0.103.15-0.103.16.diff`, 295 lines): version metadata, `end_entity.rs` (+1), `error.rs` (`CertDistrusted`), `verify_cert.rs` (distrusted-SPKI check on every path node and on the trust anchor, one unit test), eight new `.spki.der` data files; no build script, no dependency, no `unsafe`. `cargo vet certify` recorded; `cargo vet --locked --frozen` and `cargo xtask policy --strict` PASS.
- **Exit status.** The reported "`ci-full` exits 0 with three failed steps" was a misreading: the exit status 0 came from the python wrapper of the background task, which printed the child's status (1) to its output. `xtask` itself returns non-zero (`execute` bails on a failed step, `main` maps `Err` to `ExitCode::FAILURE`). No xtask defect; `ci::tests::a_failing_step_makes_execute_fail` pins it. Checked: no `ci-full-*.txt` of M6 has a step line with status FAIL (the same grep over all evidence files finds FAIL step lines only in the M02/M03 `ci-full` files and `ci-fast-local-85f4c01.txt` (M5) and `ci-fast-m6b-deps-8a31d4f.txt`, which were recorded as failing runs); nothing recorded as green was affected.

- **Two follow-ups of the bump.** (1) `xtask` test `cooldown::tests::cooldown_covers_m6_lock` pinned exactly one cooldown exception and went red (nextest, coverage); it now pins both entries. (2) The `sbom` step stayed red after the bump because `target/release/secmp-relay` (Oct 18) was not rebuilt — its sources had not changed — and its embedded `cargo auditable` data still listed `rustls-webpki` 0.103.15 (the data is the resolve of the whole `--package` set at build time). A touch of `crates/secmp-relay/src/main.rs` forced the rebuild; `sbom` PASS. Finding for the reviewer, not fixed here: on a lock-only change a stale release binary can make `sbom` report a version that is no longer in the lock (a CI runner builds from scratch and is not affected); a `cargo clean --release`-style step or a lock-hash check in the `sbom` gate would close it.

- **Test helpers in the mutation set (run 39563783784, WEISUNG M6-C1-8).** cargo-mutants skips only a plain `#[cfg(test)]`; two modules had `#[cfg(all(test, feature = …))]`, so the relay's `FlushFails` stream (four mutants, two reported as undocumented survivors) was mutated. Attributes fixed (`5e1a136`), `--list` grep for `m6_mut|FlushFails|::tests::` prints 0, relay 696 → 692; details in `mutants-c1-41ee485.md`, "PR run 164".

### Phase C1 deviations (BRIEF M6-C1, WEISUNG M6-C1-3, -4): none from the spec or the plan; implementation choices, each with its reason, none needs an ADR

1. **Killers of private functions are unit tests inside their crate** (`scheduler::run::tests::m6_mut_*`, `scheduler::core::m6_mut::counters_now_moves_when_a_counted_step_runs`, `caps`, `channel`, `ops`, `tls` and `session` `m6_mut_*`), not `m6_mut::<function>_<behaviour>` of the harness: the functions are private and the harness reaches only the public API. The killers the harness can reach are in `m6_mut`.
2. **`m0_early`**: the killers of clock, period and write mutants sit in a harness module that sorts before `m6_activity`. Reason: four six-hour `m6_activity::activity_comparator_*` tests hold all four runner threads under such a mutant and starve a failing test queued behind them (reproduced with `--test-threads=4`; PR run 160 had four timeouts from it); the ordering is the module name, documented in `m0_early.rs`.
3. **`pub(crate)` helpers** in the harness (`Rig`, `Fake`, `Call`, `Holding`, `Hold`, `Throttled`, `pair`, `text`, `TokioRig::pump`) so that the killers can share them; no production visibility changes.
4. **`Throttled` failing-writes mode** (`Throttled::FAILING_WRITES`): a stream whose first frame after the handshake fails to write while its flush succeeds — the writer of `start_io` needs it to be observable (mutant `&&` → `||`).
5. **The ledger is a `Vec`** (not a `VecDeque`) and the ledger and reservation logic are in `core/pure.rs` (item 10b): Kani needs them out of `Scheduler`, and a `VecDeque` cost 35 GB at K-C1; behaviour unchanged, regression set and the eight hand mutants green.
6. **Red evidence of the mutant killers** comes from the mutated runs of cargo-mutants (first failing test and panic line per mutant, `mutants-c1-41ee485.md`), not from mutants applied by hand; `AsyncSession::send` was also applied by hand.
7. **The condition of `ci-verdict`** is `always() && (schedule || pull_request)`, like the `mutants` job: on a push to `main` the gate jobs are skipped by design, and the verdict is skipped with them.

- **D-C2-1 (Phase C2, `two-clients`): the handshake is scripted outside the scheduler.** TC-03 (§3.2 of the test specification: "the
  M3–M5 path under the scheduler") is met for the invitation, the pool, the cells and the acceptance, but the handshake's own traffic
  runs on set-up links, not as scheduled ops: the responder's first reply (`RouteUpdate`, §6.6 step 4) cannot be sent with the public API
  of `secmp-client-core` (missing: an outbox/plan entry for Content type 0x04), and `issue_invitation` cannot adopt a pooled queue's seeds
  (missing: an `IssueParams` input). Exact analysis in §8; M7 entry in §7. Awaiting the reviewer's decision (branch (ii) of WEISUNG
  M6-C2-2 §3(b)).

## 6. Dependencies added or bumped

- **`rustls-webpki` 0.103.15 → 0.103.16** (lockfile only, RUSTSEC-2026-0382, ADR-015 Am. 2 cooldown exception until 2026-10-27; `docs/08` exception list; vet delta audit).

### Owner requests at Phase C1

- **ci-verdict → `main-protection` ruleset (OWNER-M6-02).** Add the one name `ci-verdict` to the required checks of the `main-protection` ruleset (ADR-045 Amendment 2). It aggregates every other gate job; the four existing names stay until you remove them.
- **TOR-10 (`tor_smoke`): owner-operated, not run.** On the Windows 11 VM, in a checkout of the pushed head: `cargo run --locked -p secmp-testkit --features harness --example tor_smoke -- C:\secmp-tor-smoke <relay-ref-hex> [<access-key-hex>]`; paste the whole output with the date, `winver` and the commit (details below).
- **X-10 (`win-test`): owner-operated, not run.** `cargo xtask win-test --backend github --ref m06-transport` on the pushed head (details below).

Phase A: none (workspace path crates only: `secmp-client-core` → `secmp-transport`; `secmp-testkit` → `secmp-client-core`).
Phase B commit 1: see §2, "Phase B commit 1 — dependencies as landed".

**External review of `f68d923` (WEISUNG M6-B-5, Codex; M6-B-5b, GLM) — status per finding.** Each test was red on the
probe before its fix, except the guard tests noted.
- **EXTB-1** fixed @ `cdf2b31` (core change approved, WEISUNG M6-B-6). It had been blocked on the core change (§8).
  Reason for the record: with a deferring facade, (A′) is not only a correctness fix; it closes an activity dependence,
  since the queue a slot serves would otherwise follow the worker's timing. Test
  `driver_balanced_first_tick_sends_and_fetches_in_order`: red before, green after. The extended AI oracle is described
  in §5. Before the decision, the test
  `driver_balanced_first_tick_sends_and_fetches_in_order` reproduces the probe red (`TornDown(LinkId(0), Rejected)` at
  10 000, `TornDown(LinkId(1), Rejected)` at 50 000). It is not committed, since it is red on the branch. The extended
  AI oracle (a)–(c) comes with the fix.
- **EXTB-2** fixed @ `6d81017`: the facade binds deliveries and the committed mark to a queue generation, and the
  driver starts a new generation at the scheduler's `QUEUE_NEW`. Tests: `driver_queue_recreation_does_not_ack_undelivered_cells`;
  unit test `scheduler::run::tests::late_delivery_of_an_old_generation_commits_nothing`.
- **EXTB-3** fixed @ `86257bf`:
  - writes are handed out and counted per link;
  - a bounded flush wait, `FLUSH_WAIT_MS` = 250, under the FETCH lead;
  - a link is closed when its next tick is due with a write still pending, after `WRITE_STALL_MS` = 10 000, or when the
    writer acks `false`;
  - events that arrive during the flush wait are stashed for the next pass.

  Tests: `driver_hanging_writer_does_not_delay_other_links` and `driver_pending_flush_later_tick_other_link` (both red
  before the fix), `driver_partial_write_is_completed_before_work` and `driver_pending_flush_same_tick` (guards; green
  on the old driver too, which also waited).
- **EXTB-4** fixed @ `be973a7`:
  - connect tasks are kept per `LinkId`;
  - `Output::Close` and `Driver::shutdown` abort them; `shutdown` also reports each pending connect as failed;
  - a completion for a link that is no longer pending is discarded before any I/O (`RunLog::discarded`);
  - stream tasks start only for a link the scheduler took as up;
  - `Drop` is the backstop;
  - new `Driver::submit` for the outputs of the host's own scheduler calls (`set_mode`, …), which had no way into the
    driver.

  Tests: `driver_shutdown_aborts_pending_connects`, `driver_close_reconnect_race_discards_old_completion`.
- **EXTB-5** fixed @ `c971701`, closed by EXT2B-2 (quoted/escaped keys). xtask has no TOML crate, so the parser is strict: only `[[exemptions.<bare>]]` at column
  0; any other bracket line mentioning `exemptions` is an entry plus a finding. Tests:
  `vet_closure_header_with_comment_is_found`, `vet_closure_header_quoted_key_is_found`,
  `vet_closure_header_with_spaces_is_found`.
- **EXTB-6** fixed @ `c971701`. A missing `fuzz/Cargo.lock` is a cooldown finding, and the lock comparison includes the
  checksum.
  - **Deviation:** cargo-fuzz 0.13.2 has no `--locked`, so the fuzz gate runs `cargo metadata --locked --manifest-path
    fuzz/Cargo.toml` before it builds.

  Tests: `fuzz_lock_matches_workspace_lock`, `fuzz_lock_checksums_and_presence_are_enforced`.
- **EXTB-7** fixed @ `c971701`: `tls::CERT_MAX` = 8192 is enforced in `check_pin`, which is the `PinVerifier`'s path.
  The FZ-02 oracle and `max_len` follow from the constant, read from its source. Tests:
  `tls_certificate_over_size_bound_rejects` (8193 B refused, 8192 B accepted), `tls_pin_bound_is_the_enforced_cert_max`.
- **EXTB-8** fixed @ `c971701`: AD-09 takes the members from `cargo metadata`, `xtask` included
  (`queue_transport_async_signature`).
- **TLS-08** fixed @ `c971701`. One shared config; its store is `NoClientSessionStorage`, and the second `ClientHello`
  has no PSK. A control run with a counting store keeps the tickets and resumes (`tls_no_resumption_no_early_data`).
- **GLMB-1** @ `2885694`: the direct socket has keepalive on and nodelay (`tls::tcp_socket`).
  - **Deviation:** keepalive timings and `TCP_USER_TIMEOUT` need `setsockopt`. tokio does not expose them, and calling
    them needs `socket2` as a direct dependency (outside ADR-051) or `unsafe`.
  - The bound comes from the driver: a black-holed link is closed within `link_idle_secs` by the in-flight bound, at
    the third unanswered tick (≤ 240 s at P = 80 s), and a stuck writer by the write-stall bound.

  Tests: `direct_blackhole_link_is_closed_within_idle_bound` (paused clock), `tls::tests::direct_tcp_socket_has_keepalive_and_no_delay`.
- **GLMB-2** @ `2885694`: a policy test, not a second `cargo deny` run (no CI time). The fuzz graph is the workspace
  graph plus exactly `libfuzzer-sys =0.4.13` and `arbitrary`. Test: `fuzz_graph_is_workspace_graph_plus_allowlist`.
- **GLMB-3** @ `2885694`: `Step::Flushed` carries the time the flush wait ended (`driver_flushes_due_writes_before_work`
  checks `t >= poll`).
- **After the fixes:**
  - `ci-fast --strict` PASS at every commit, the last at `2885694`.
  - The six tokio AI repeats PASS with 16 traces (in `nextest`) and 64 traces
    (`M06-evidence/ai-tokio-64-m6b-2885694.txt`, max |Δt| = 0).
  - M5 harness suite: **25** tests (`scenarios` 11, `transport` 12, `invitation` 2), 25/25. The harness binary has 162
    tests, 162/162.
  - `ci-full` is held until EXTB-1 is decided.

**Decisions of WEISUNG M6-B-6, recorded:**
- **EXTB-1:** (A)/(A′) approved and applied @ `cdf2b31`; the driver contract in `scheduler/mod.rs` states both.
- **Reopened proofs, re-run at `cdf2b31`:**
  - client-core Kani: 7/7 (all harnesses of `kani_proofs.rs`);
  - AI-01…AI-06 sync at 64 traces: 6/6, max |Δt| = 0 (`M06-evidence/ai-sync-64-m6b-cdf2b31.txt`);
  - AI-01…AI-06 tokio with the extended oracle: 16 traces 6/6, 64 traces 6/6 (`ai-tokio-64-m6b-cdf2b31.txt`);
  - S-* suites (`m6_sched*`): 40/40; client-core unit tests 11/11; harness binary 164/164;
  - second cargo-mutants run on `scheduler/core/mod.rs` (local, `--file`; `M06-evidence/mutants-core-cdf2b31.txt`):
    251 mutants, 122 caught, 41 missed, 40 timeouts (8 of them caught-by-hang under §Rules), 48 unviable.
    - The new lines leave no survivor. The only finding near them is the timeout `591:27 && → ||` of the existing
      `needs_send && up.send_part.is_none()`.
    - The misses and timeouts join OPEN-M6-B-2 (the first item of Phase C).
- **OPEN-M6-B-5:** keepalive timings and `TCP_USER_TIMEOUT` need `socket2`. Decide in Phase C, via an ADR-051 amendment,
  or stay with the 240 s in-flight bound. The GLMB-1 deviation (keepalive + nodelay only) is accepted for Phase B.
- **EXTB-6 deviation** (`cargo metadata --locked` on `fuzz/` instead of a non-existent `cargo fuzz --locked`): accepted.
- **Harness count:** 164/164 at `cdf2b31` is the number carried; "138/138" was the whole binary at P2.

**Decisions of WEISUNG M6-B-5c, recorded:**
- **OPEN-M6-B-3:** re-encode through Arti's `HsId` once arti-client exposes it without `experimental-api`; no
  `tor-hscrypto` edge now. The TOR-08/FZ-03 substitute is accepted.
- **§2.4 in P4:** confirmed (relay `direct-tls`, TLS-12…TLS-15, G-12, `bab802b`).
- **DOC-M6-C-1 (Phase C):** `docs/05` §5/§7 get the config keys `direct_tls_cert`/`direct_tls_key` (DER) and the
  `openssl` command of OPEN-M6-09; `docs/05` is not touched now.
- **OPEN-M6-B-4 (Phase C, read-only diagnosis first; scheduler/core stays a STOP).**
  - **Reproduction:** `secmp-testkit` harness `m6_sched_life::relay_idle_and_age_bounds_from_schedule`, the Low-bw
    run: VirtualDriver, seeds 1203 (client a) and 1204 (client b), one contact at P = 80 s both ways, lifetime fixed
    at 24 h, `phase_max` default, default relay limits; also with the M5 limits (900 s / 86 400 s).
  - **Observation:** client b is torn down `Overrun`; first three at 151 526, 323 361 and 497 015 ms, then every 1–3
    min. Client a and the Strict run have at most one.
  - **Not known:** whether it is the virtual driver's cost model or the core's deadline math; not investigated.
  - **CLOSED 2026-10-16 (WEISUNG M6-CI-2, EXT2B-3): fixture defect, not a driver or core fix.** Client b is the ratchet
    responder and had no sending chain (`SourceError` from t = 0); on a combined relay link the FETCH part cannot be
    sealed without a SEND part (EXTB-1), so b's tick tore down with `Overrun`. `m6_common::seed_conversation` delivers
    one cell of a to b before link-up; `relay_idle_and_age_bounds_from_schedule` now requires, for both clients and
    every link, no teardown other than `Lifetime` and one `Lifetime` teardown each. Strict and Low-bw (to 90 000 000
    ms): 0 overruns, passed in 26 s. `core/` untouched. Evidence: `M06-evidence/ext2b-nachfix.md`.

### Codex M6B-EXT2 (WEISUNG M6-CI-2) — status 2026-10-16

- **EXTB-5** now fixed (EXT2B-2 closes the "partially").
- **EXT2B-1** fixed: relay TLS read calls carry an absolute deadline (`Deadlined` in `secmp-relay/src/tls.rs`).
- **EXT2B-2** fixed: quoted or escaped key in a `[[` header is a finding by name; **EXT3B-1** fixed (a byte-order mark in the vet config is a finding, `c9795a6`); **EXT3B-2** fixed (`flush_wait` bounded by the next scheduler deadline less the driver jitter).
- **EXT2B-3** fixed (fixture); **OPEN-M6-B-4** closed (fixture).
- **FIN-1/-2/-3 (Astra final pass, WEISUNG M6-CI-10) fixed:** FIN-3 dotted/inline exemptions are a finding (`vet_closure_findings`); FIN-1 stashed driver events are handled after the flush wait at their arrival time (`ai07_fault_paired_tokio`); FIN-2 the round robin commits at SEND frame write completion (`Scheduler::frame_written`, ADR-051 Amendment 4, Proposed). Residuals (WEISUNG M6-CI-11) fixed: FIN2-1 the next SEND is chosen from the successor of the newest unwritten one (reservation in `Up::unwritten`), FIN2-2 escaped assignment keys are a finding. Evidence: `M06-evidence/final-nachfix.md`.
- **KANI-M6-C-1 (open, Phase C):** no Kani harness covers `prepare_link`/`prepare_send`; the SEND-before-FETCH guard and
  advance-only-on-success are test evidence only.
- **OPEN-M6-C-1 closed by spec reading** (Codex M6B-EXT3c): a fresh responder contact already holds a sending chain after `first_msg` (`docs/03` §6.6/§7.2); an empty send set yields PING + FETCH_MULTI on a combined link (probe `recv-only Balanced PING=50, FETCH=50, overruns=0`); the old fixture's state (registered send queue + raw responder) is not reachable by the specified integration.
- The `tor_smoke` example and the nightly fuzz budget (31 × 232 s + 2 × 3600 s): accepted.

**Owner requests (BRIEF M6-B §2.6; asked 2026-10-15; not waited for).** Infrastructure that is not available stays
under "Blocked — owner infrastructure" until it runs (TEST-SPEC conventions, ⚙ non-availability path).
- **X-10 `win_test_runs_transport_suites`: the Windows transport suites.**
  - **Run:** `cargo xtask win-test --backend github --ref m06-transport`, on the pushed head of Phase B. It waits for
    the `windows-native` job of the PR run, or re-runs it with `--rerun`.
  - **Why the GitHub backend:** the libvirt VM backend is deferred to M9 by owner decision A1, so this is the
    OPEN-M6-20 substitute — `windows-native`'s non-network tests, which include TLS-01…TLS-15, AD-07 and AD-08 (the
    TLS loopback rows run on the Windows runner).
  - **Paste back:** the saved log path `target/win-test/<run>-<job>.log`, plus its lines `win-test: job … concluded
    Success` and `Summary … tests run: … passed`.
- **TOR-10 `tor_bootstrap_and_link_windows_vm`: Arti on the Windows 11 VM against the test relay.** On the VM, in a
  checkout of the pushed head:

  ```text
  cargo run --locked -p secmp-testkit --features harness --example tor_smoke -- C:\secmp-tor-smoke <relay-ref-hex> [<access-key-hex>]
  ```

  - `<relay-ref-hex>` is the test relay's `RelayRef` encoding (spec §5.3) in hex. The access key is needed only if the
    test relay requires one.
  - **Paste back:** the whole output — `tor-smoke start unix=…`, the `tor-event …` lines, `READY unix=…`, `PING OK
    unix=…` (or the `FAIL …` line) — plus the date, the Windows build (`winver`) and the commit. It goes to
    `docs/reviews/M06-evidence/tor-10-windows-<date>.txt`.
  - The same command on Linux, or on GitHub's `windows-latest` as the optional `tor-smoke` dispatch of OPEN-M6-20, is
    the substitute only with your written consent.
- **vet:** no record wanted for Phase B. No new crate since your vet commit; `cargo vet --locked` is green.

**OPEN-M6-B-1 — receive throughput of the driver's facade (accepted for Phase B, WEISUNG M6-B-3 §0.2; decided after the
Phase-B review).**
- **What it costs.**
  - A `FETCH` / `FETCH_MULTI` response commits at most one new cell, instead of up to F = 4. The core stops at the first
    cell the facade reports "not committed", which is the cell the worker is still deciding.
  - Every received cell waits one more fetch period before its acknowledgement (persist before ack holds).
  - The relay hands the uncommitted cells out again. That costs no extra frames: a response is always F frames.
- **Why it carries no activity information.** It applies to every fetched cell alike, real or dummy. Tests:
  `m6_tokio_ai::ai04_when_receiving_tokio` (the peers active, the local user idle: emission equal to the idle run) and
  `ai06_both_directions_tokio` (R2C equal), with the receive cost of 5 ms per cell; and
  `m6_driver::driver_slow_work_does_not_delay_other_links` (400 ms per received cell, emission unchanged).
- **The way out** is a core API change, for example a deferred-commit outcome of `deliver`, after the Phase-B review. The
  core changed once in Phase B: EXTB-1 (A)/(A′) @ `cdf2b31`, proofs re-run (client-core Kani 7/7; AI-01…AI-06 sync 64 traces 6/6; AI-01…AI-06 tokio 16 and 64 traces with the extended oracle 6/6; S-* suites 40/40 plus the client-core unit tests 11/11; harness binary 164/164; second mutants run on `core/mod.rs`, see §6); OPEN-M6-B-1 is not part of it.

**Mutants shards of PR run 38724110285 (head `1517781`) — diagnosis (WEISUNG M6-B-3 §1).**
- **Shard 1** failed after 156 min (job 116385913865, 11:00 → 13:40). **Shard 5** failed after 192 min (job 116385914084,
  11:00 → 14:12).
- **Where the time went.** The first cargo-mutants run took 45 / 50 min (`246 mutants tested in 45m: 2 missed, 185 caught,
  59 unviable`). The second run took 2 h (`113 mutants tested in 2h: 24 missed, 67 caught, 19 unviable, 3 timeouts` /
  `31 missed, 63 caught, 17 unviable, 2 timeouts`). A second-run mutant tests for 121–372 s on the runner: the harness
  suite without the skip list, three mutants in parallel on 4 cores.
- **Verdict lines:** `FAIL [8] mutants: cargo mutants (exit Some(3)): 27 undocumented survivor(s)` (shard 1) and
  `… 33 undocumented survivor(s)` (shard 5).
- **Cause 1, configuration (fixed in `ci(m6): mutants second run — …`).** `crates/secmp-client-core/src/kani_proofs.rs`
  is compiled only under `cfg(kani)` and was missing from `MUTANT_EXCLUDE_FILES`. 21 of the survivors are there (shard 1:
  10, e.g. `kani_proofs.rs:55:21: replace < with == in kani_balanced_rr_selects_due_or_ping`; shard 5: 11). It is now
  excluded like the `secmp-proto` and `secmp-relay` files and listed in `mutants-accepted.md` §Excluded.
- **Cause 2, real survivors — OPEN-M6-B-2 (not in Phase B; WEISUNG M6-B-4 §0.2: the first item of session M6-C).** All misses and
  timeouts outside `kani_proofs.rs`, per shard: 135 misses and 27 timeouts at the 900 s per-mutant timeout, 9 of
  the timeouts caught-by-hang under `docs/mutants-accepted.md` §Rules (`World::tick`, `poll_due`, `accept_ceiling`,
  `find`); every other entry needs a killing test or an accepted row. Each is named as cargo-mutants printed it at
  `1517781` (`<crate> <path>:<line>:<col>`), then its line at `f68d923`: "same line", `:<n>` when it moved within the
  file, `ops.rs:<n>` for the `relay_queue.rs` logic that the P2 refactor moved into `ops.rs` (mapped by hand where the
  text changed: `relay_queue.rs` 256, 289, 340, 363, 395, 416). The first run's four misses (`secret.rs:59`,
  `inv.rs:163:32`, `inv.rs:163:44`, `inv.rs:202`) are accepted rows. Source: the job logs of run 38724110285
  (`gh run view --log --job <id>`).
  - **Shard 0, misses (20):**
    - `client-core clock.rs:39:9` `replace <impl Clock for SystemClock>::mono_ms -> u64 with 0` → @f68d923 same line
    - `client-core timing.rs:18:9` `replace <impl core::fmt::Display for Unavailable>::fmt -> core::fmt::Result with Ok(Default::default())` → @f68d923 same line
    - `client-core timing.rs:113:24` `replace ^ with & in TimingRng::next_u64` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:398:9` `replace World::release with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:875:13` `delete match arm TransportError::Rate in World::queue_error` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:940:52` `replace == with != in World::outcome` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1294:21` `delete ! in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1675:21` `delete match arm State::Up(up) in Scheduler::work_pass` → @f68d923 same line
    - `client-core scheduler/conversation.rs:259:9` `replace Conversation<O, P, S>::set_send_receipts with ()` → @f68d923 same line
    - `client-core scheduler/conversation.rs:324:39` `delete ! in Conversation<O, P, S>::has_pending_real` → @f68d923 same line
    - `client-core scheduler/conversation.rs:345:9` `replace Conversation<O, P, S>::take_seq -> u64 with 0` → @f68d923 same line
    - `client-core scheduler/outbox.rs:302:9` `replace MemPersist::set_durable with ()` → @f68d923 same line
    - `transport channel.rs:308:50` `replace > with >= in Channel::prepare` → @f68d923 same line
    - `transport channel.rs:459:28` `replace match guard cell_id != 0 && evicted_is_plausible(cell_id, evicted) with true in Channel::finish` → @f68d923 same line
    - `transport channel.rs:528:20` `replace match guard error.is_none() && !dummies && cell_id > previous with true in check_fetch` → @f68d923 same line
    - `transport channel.rs:487:18` `replace match guard ok(&other) with true in single` → @f68d923 same line
    - `transport relay_queue.rs:547:33` `replace || with && in <impl QueueTransport for RelayQueueTransport<S>>::get_link_data` → @f68d923 `ops.rs:268`
    - `transport relay_queue.rs:427:40` `replace match guard cell_id > floor with true in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:360`
    - `transport relay_queue.rs:407:55` `replace match guard stage <= 1 with true in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:340`
    - `transport session.rs:240:9` `replace Session<S>::ensure_open -> Result<()> with Ok(())` → @f68d923 same line
  - **Shard 0, timeouts (5):**
    - `client-core timing.rs:56:5` `replace sample_round -> Option<u64> with None` → @f68d923 same line
    - `client-core scheduler/control.rs:235:58` `replace == with != in ControlOps::failed` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:509:16` `replace < with == in World::tick` → @f68d923 same line — caught-by-hang (§Rules)
    - `client-core scheduler/core/mod.rs:1388:44` `delete ! in Scheduler::sync_links` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1793:9` `replace Scheduler::link_up -> Result<Vec<Output>, SchedError> with Ok(vec![])` → @f68d923 same line
  - **Shard 1, misses (17):**
    - `transport secret.rs:59:9` `replace <impl Drop for SecretBytes<N>>::drop with ()` → @f68d923 same line
    - `transport inv.rs:163:32` `replace | with ^ in base64url_encode` → @f68d923 same line
    - `client-core clock.rs:39:9` `replace <impl Clock for SystemClock>::mono_ms -> u64 with 1` → @f68d923 same line
    - `client-core scheduler/control.rs:86:9` `replace ControlOps::len -> usize with 0` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:951:35` `replace == with != in World::outcome` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1282:58` `replace == with != in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1294:57` `replace == with != in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1675:44` `replace == with != in Scheduler::work_pass` → @f68d923 same line
    - `client-core scheduler/conversation.rs:345:9` `replace Conversation<O, P, S>::take_seq -> u64 with 1` → @f68d923 same line
    - `client-core scheduler/conversation.rs:719:9` `replace <impl CellSource for Conversations<O, P, S>>::send_failed with ()` → @f68d923 same line
    - `transport caps.rs:20:35` `replace + with *` → @f68d923 same line
    - `transport channel.rs:329:20` `delete ! in Channel::prepare` → @f68d923 same line
    - `transport channel.rs:528:59` `replace > with >= in check_fetch` → @f68d923 same line
    - `transport channel.rs:566:54` `replace == with != in check_fetch_multi` → @f68d923 same line
    - `transport relay_queue.rs:363:28` `replace || with && in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:570`
    - `transport session.rs:57:23` `replace match guard e.kind() == ErrorKind::Interrupted with true in read_exact` → @f68d923 same line
    - `transport session.rs:244:9` `replace Session<S>::close with ()` → @f68d923 same line
  - **Shard 1, timeouts (3):**
    - `client-core timing.rs:40:5` `replace accept_ceiling -> Option<u64> with None` → @f68d923 same line — caught-by-hang (§Rules)
    - `client-core scheduler/core/mod.rs:509:16` `replace < with > in World::tick` → @f68d923 same line — caught-by-hang (§Rules)
    - `client-core scheduler/core/mod.rs:1591:9` `replace Scheduler::control_failed -> Result<(), SchedError> with Ok(())` → @f68d923 same line
  - **Shard 2, misses (11):**
    - `client-core scheduler/control.rs:86:9` `replace ControlOps::len -> usize with 1` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:214:9` `replace <impl Release for S>::release_discard with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:712:39` `replace || with && in World::prepare_fetch` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1283:53` `replace == with != in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1295:28` `delete ! in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1347:35` `delete ! in Scheduler::set_queue_period` → @f68d923 same line
    - `client-core scheduler/conversation.rs:725:9` `replace <impl CellSource for Conversations<O, P, S>>::discard with ()` → @f68d923 same line
    - `transport channel.rs:459:41` `replace && with || in Channel::finish` → @f68d923 same line
    - `transport channel.rs:570:43` `replace == with != in check_fetch_multi` → @f68d923 same line
    - `transport relay_queue.rs:363:42` `replace > with == in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:570`
    - `transport session.rs:57:23` `replace match guard e.kind() == ErrorKind::Interrupted with false in read_exact` → @f68d923 same line
  - **Shard 2, timeouts (5):**
    - `client-core timing.rs:40:5` `replace accept_ceiling -> Option<u64> with Some(0)` → @f68d923 same line — caught-by-hang (§Rules)
    - `client-core scheduler/core/mod.rs:339:24` `replace && with || in World::effective_mode` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:377:9` `replace World::period_of -> Option<u64> with None` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1120:9` `replace Scheduler::links -> Vec<LinkInfo> with vec![]` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1696:31` `delete ! in Scheduler::work_pass` → @f68d923 same line
  - **Shard 3, misses (13):**
    - `client-core scheduler/control.rs:92:9` `replace ControlOps::is_empty -> bool with true` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:218:9` `replace <impl Release for S>::release_failed with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:712:56` `replace > with == in World::prepare_fetch` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1295:64` `replace == with != in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/conversation.rs:322:9` `delete ! in Conversation<O, P, S>::has_pending_real` → @f68d923 same line
    - `client-core scheduler/conversation.rs:336:9` `replace Conversation<O, P, S>::durable -> &[u8] with Vec::leak(Vec::new())` → @f68d923 same line
    - `client-core scheduler/outbox.rs:278:9` `replace MemPersist::commits -> u64 with 0` → @f68d923 same line
    - `transport caps.rs:20:30` `replace + with *` → @f68d923 same line
    - `transport channel.rs:289:9` `replace Channel::synced with ()` → @f68d923 same line
    - `transport channel.rs:599:44` `replace > with >= in check_fetch_multi` → @f68d923 same line
    - `transport relay_queue.rs:289:43` `replace && with || in <impl QueueTransport for RelayQueueTransport<S>>::create_queue` → @f68d923 `ops.rs:188`
    - `transport relay_queue.rs:395:57` `replace == with != in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:330`
    - `transport session.rs:57:32` `replace == with != in read_exact` → @f68d923 same line
  - **Shard 3, timeouts (3):**
    - `client-core timing.rs:40:5` `replace accept_ceiling -> Option<u64> with Some(1)` → @f68d923 same line — caught-by-hang (§Rules)
    - `client-core scheduler/core/mod.rs:377:9` `replace World::period_of -> Option<u64> with Some(0)` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1776:9` `replace Scheduler::find -> Option<usize> with None` → @f68d923 same line — caught-by-hang (§Rules)
  - **Shard 4, misses (14):**
    - `transport inv.rs:202:34` `replace | with ^ in base64url_decode` → @f68d923 same line
    - `client-core scheduler/control.rs:92:9` `replace ControlOps::is_empty -> bool with false` → @f68d923 same line
    - `client-core scheduler/control.rs:209:63` `replace == with != in ControlOps::take_due` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:231:9` `replace <impl Release for Deferred>::release_discard with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1287:42` `replace != with == in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1303:31` `delete ! in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1615:32` `replace || with && in Scheduler::owner_status` → @f68d923 same line
    - `client-core scheduler/conversation.rs:310:9` `replace Conversation<O, P, S>::discarded -> u64 with 1` → @f68d923 same line
    - `client-core scheduler/conversation.rs:323:38` `replace > with == in Conversation<O, P, S>::has_pending_real` → @f68d923 same line
    - `client-core scheduler/conversation.rs:336:9` `replace Conversation<O, P, S>::durable -> &[u8] with Vec::leak(vec![0])` → @f68d923 same line
    - `client-core scheduler/outbox.rs:278:9` `replace MemPersist::commits -> u64 with 1` → @f68d923 same line
    - `transport channel.rs:528:48` `replace && with || in check_fetch` → @f68d923 same line
    - `transport relay_queue.rs:363:42` `replace > with >= in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:570`
    - `transport relay_queue.rs:427:48` `replace > with >= in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:360`
  - **Shard 4, timeouts (4):**
    - `client-core timing.rs:47:5` `replace sample_with -> Option<u64> with None` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:377:9` `replace World::period_of -> Option<u64> with Some(1)` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1122:25` `delete ! in Scheduler::links` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1357:17` `replace == with != in Scheduler::sync_links` → @f68d923 same line
  - **Shard 5, misses (21):**
    - `client-core clock.rs:75:9` `replace ManualClock::set_ms with ()` → @f68d923 :107
    - `client-core scheduler/control.rs:98:9` `replace ControlOps::kind_of -> Option<ControlKind> with None` → @f68d923 same line
    - `client-core scheduler/control.rs:138:41` `replace == with != in ControlOps::schedule` → @f68d923 same line
    - `client-core scheduler/control.rs:219:9` `replace ControlOps::done with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:235:9` `replace <impl Release for Deferred>::release_failed with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:512:35` `replace > with >= in World::tick` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:712:56` `replace > with >= in World::prepare_fetch` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1160:9` `replace Scheduler::route_dead -> bool with true` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:997:9` `delete match arm TransportError::Closed in reason_of` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1615:20` `replace || with && in Scheduler::owner_status` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1914:59` `replace == with != in Scheduler::on_frame` → @f68d923 same line
    - `client-core scheduler/conversation.rs:336:9` `replace Conversation<O, P, S>::durable -> &[u8] with Vec::leak(vec![1])` → @f68d923 same line
    - `client-core scheduler/conversation.rs:682:9` `replace Conversations<O, P, S>::pending_real -> bool with true` → @f68d923 same line
    - `client-core scheduler/pool.rs:53:23` `replace > with >= in QueuePool::missing` → @f68d923 same line
    - `client-core scheduler/pool.rs:114:9` `replace QueuePool::is_spare -> bool with true` → @f68d923 same line
    - `transport channel.rs:308:36` `replace || with && in Channel::prepare` → @f68d923 same line
    - `transport channel.rs:180:5` `replace fits -> bool with true` → @f68d923 same line
    - `transport channel.rs:486:9` `delete match arm ResponseCmd::Err(_) in single` → @f68d923 same line
    - `transport channel.rs:566:48` `replace match guard stage == 0 with true in check_fetch_multi` → @f68d923 same line
    - `transport channel.rs:528:36` `replace && with || in check_fetch` → @f68d923 same line
    - `transport relay_queue.rs:340:28` `replace || with && in <impl QueueTransport for RelayQueueTransport<S>>::fetch` → @f68d923 `ops.rs:293`
  - **Shard 5, timeouts (2):**
    - `client-core scheduler/core/mod.rs:1719:31` `delete ! in Scheduler::poll_due` → @f68d923 same line — caught-by-hang (§Rules)
    - `client-core scheduler/core/mod.rs:1776:9` `replace Scheduler::find -> Option<usize> with Some(1)` → @f68d923 same line — caught-by-hang (§Rules)
  - **Shard 6, misses (16):**
    - `client-core scheduler/core/mod.rs:297:5` `replace counters_now -> [u64; 4] with [0; 4]` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:393:9` `replace World::relay_has_recv -> bool with false` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1292:52` `replace == with != in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/conversation.rs:249:9` `replace Conversation<O, P, S>::set_send_queue with ()` → @f68d923 same line
    - `client-core scheduler/conversation.rs:323:38` `replace > with >= in Conversation<O, P, S>::has_pending_real` → @f68d923 same line
    - `client-core scheduler/conversation.rs:340:9` `replace Conversation<O, P, S>::ts -> u64 with 0` → @f68d923 same line
    - `transport caps.rs:43:9` `replace <impl core::fmt::Debug for QueueRef>::fmt -> core::fmt::Result with Ok(Default::default())` → @f68d923 same line
    - `client-core scheduler/pool.rs:114:9` `replace QueuePool::is_spare -> bool with false` → @f68d923 same line
    - `transport channel.rs:308:50` `replace > with == in Channel::prepare` → @f68d923 same line
    - `transport channel.rs:485:35` `replace match guard fits(code, allowed) with true in single` → @f68d923 same line
    - `transport channel.rs:520:18` `replace match guard at == 0 with true in check_fetch` → @f68d923 same line
    - `transport channel.rs:566:48` `replace match guard stage == 0 with false in check_fetch_multi` → @f68d923 same line
    - `transport channel.rs:594:58` `replace == with != in check_fetch_multi` → @f68d923 same line
    - `transport relay_queue.rs:256:39` `replace match guard fits(code, &[]) with true in RelayQueueTransport<S>::first_cellr` → @f68d923 `ops.rs:252`
    - `transport relay_queue.rs:391:52` `replace match guard stage == 0 with true in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:326`
    - `transport relay_queue.rs:416:55` `replace == with != in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:349`
  - **Shard 6, timeouts (3):**
    - `client-core scheduler/core/mod.rs:379:62` `replace == with != in World::period_of` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:460:62` `replace == with != in World::start_connect` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1777:47` `replace == with != in Scheduler::find` → @f68d923 same line — caught-by-hang (§Rules)
  - **Shard 7, misses (23):**
    - `transport inv.rs:163:44` `replace | with ^ in base64url_encode` → @f68d923 same line
    - `client-core timing.rs:113:24` `replace ^ with | in TimingRng::next_u64` → @f68d923 same line
    - `client-core scheduler/control.rs:98:39` `replace == with != in ControlOps::kind_of` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:297:5` `replace counters_now -> [u64; 4] with [1; 4]` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:393:43` `replace == with != in World::relay_has_recv` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:521:43` `replace || with && in World::tick` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:802:9` `replace World::begin_work with ()` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:932:44` `replace == with != in World::outcome` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:872:13` `delete match arm TransportError::Auth in World::queue_error` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1160:55` `replace && with || in Scheduler::route_dead` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1295:25` `replace && with || in Scheduler::remove_queue` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1438:35` `replace && with || in Scheduler::change_mode` → @f68d923 same line
    - `client-core scheduler/core/mod.rs:1573:9` `replace Scheduler::control_done with ()` → @f68d923 same line
    - `client-core scheduler/conversation.rs:254:9` `replace Conversation<O, P, S>::set_recv_queue with ()` → @f68d923 same line
    - `client-core scheduler/conversation.rs:322:9` `replace Conversation<O, P, S>::has_pending_real -> bool with true` → @f68d923 same line
    - `client-core scheduler/conversation.rs:324:36` `replace && with || in Conversation<O, P, S>::has_pending_real` → @f68d923 same line
    - `client-core scheduler/conversation.rs:340:9` `replace Conversation<O, P, S>::ts -> u64 with 1` → @f68d923 same line
    - `client-core scheduler/conversation.rs:462:33` `delete ! in Conversation<O, P, S>::restore` → @f68d923 same line
    - `client-core scheduler/conversation.rs:549:9` `replace Conversation<O, P, S>::on_failed with ()` → @f68d923 same line
    - `transport channel.rs:580:51` `replace match guard stage <= 1 with true in check_fetch_multi` → @f68d923 same line
    - `transport channel.rs:599:36` `replace match guard cell_id > floor with true in check_fetch_multi` → @f68d923 same line
    - `transport relay_queue.rs:351:74` `replace > with >= in <impl QueueTransport for RelayQueueTransport<S>>::fetch` → @f68d923 `ops.rs:304`
    - `transport relay_queue.rs:422:62` `replace == with != in <impl QueueTransport for RelayQueueTransport<S>>::fetch_multi` → @f68d923 `ops.rs:355`
  - **Shard 7, timeouts (2):**
    - `client-core timing.rs:47:10` `replace >= with < in sample_with` → @f68d923 same line
    - `client-core scheduler/control.rs:235:9` `replace ControlOps::failed -> Result<(), Unavailable> with Ok(())` → @f68d923 same line

**EXT2-1: design proposal, not implemented (WEISUNG M6-B-2 §1.5).** The goal is for `linux-full` to fail when a delegated
required job (`ct`, `mutants`, `proverif-hx`) is not green.
- **(A) gh-API poll in the delegation step.** `cargo xtask ci-full --delegated X` would poll `gh api
  repos/…/commits/$GITHUB_SHA/check-runs` for job X until it completes, with a timeout, and fail unless it ends in
  `success`.
  - Cons: `linux-full` needs `checks: read` (today the workflow has `contents: read` only); it blocks a runner while it
    waits; the wait is coupled to the other jobs' timing; a re-run of one job does not update an already finished
    verdict.
- **(B) an aggregate verdict job.** A pinned job `ci-verdict` with `needs: [linux-full, ct, mutants, proverif-hx]` and
  `if: always()`. Its single step, `cargo xtask step ci-verdict`, would read `toJSON(needs)` from the environment and fail
  unless every result is `success`. "Skipped" counts as a failure on `pull_request`/`schedule`.
  - Pros: no token scope, no polling, re-runs take effect through GitHub's own `needs` semantics, and the owner makes one
    required check instead of three.
- **Recommendation: (B)**, with a policy test pinning its `needs` list to `expect::DELEGATED_TO`.

## 7. Open risks and known limitations

- **Scheduler core in Phase B:** core changed once in Phase B: EXTB-1 (A)/(A′) @ `cdf2b31`, proofs re-run (client-core Kani 7/7; AI-01…AI-06 sync 64 traces 6/6; AI-01…AI-06 tokio 16 and 64 traces with the extended oracle 6/6; S-* suites 40/40 plus the client-core unit tests 11/11; harness binary 164/164; second mutants run on `core/mod.rs`, see §6).

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
- **P2: how the tokio driver keeps obligations (i)/(vi) with an unchanged core** (`secmp-client-core/src/scheduler/run.rs`,
  module docs).
  - **The constraint.** `Scheduler::work` calls the cell source synchronously, and `poll_due` needs the same `&mut
    Scheduler`. If the expensive cell-source work ran inside `work`, it would block the next due write of every other link.
  - **The design.** `work` sees a non-blocking facade (`Deferred`), and a serial `Worker` runs the cell-source calls off
    the loop.
    - A cell the core asks for comes back as "not ready" until the worker has built it. The core prepares the link again
      at its next pass; that is existing core behaviour.
    - A fetched cell is "not committed" until the worker has committed it, so no acknowledgement is sent (persist before
      ack). The cell is fetched again and found committed then.
    - The notifications are queued to the worker in order.
  - **Consequence to judge: receive throughput.** At most one newly committed cell per `FETCH` / `FETCH_MULTI` response,
    instead of up to F = 4. The core stops at the first uncommitted cell. Each received cell also waits one more fetch
    period before its ack. This affects every cell alike, real or dummy, so it carries no activity information.
  - **Fixing the throughput needs a core API change**, for example a deferred-commit outcome of `deliver`. That touches
    `scheduler/core`, which is a STOP; it is a question in §8.
  - **What still runs on the loop:** the sealing and signing inside `work` (`Channel::prepare`, one frame per slot). It is
    sub-millisecond and independent of activity, and costs 0 virtual time in the tests.
  - **Connect timeout:** `CONNECT_TIMEOUT_MS` = 120 s, for connects and for whole control operations. A provider that
    never answers fails the attempt instead of leaving the link in `Connecting`.
- **P2: tokio feature `test-util`, a dev-dependency of `secmp-testkit` only.** `tokio::time::pause`, which the brief asks
  for, needs it. It is not in the ADR-051 feature table, and no shipped build contains it. Please confirm it or name the
  alternative (a virtual timer of our own) — see §8.
- **P2: AD-09 wording vs. the lock.** TEST-SPEC AD-09 says "no `async-trait` crate in `Cargo.lock`". `async-trait` 0.1.92
  is in the lock through `arti-client` 0.46.0 and its `tor-*` crates. The test asserts instead that no workspace crate
  depends on it, and that every dependent in the lock is a non-`secmp-*` crate.
- **P2: test budget.**
  - The tokio AI repeats run 16 traces for AI-01…03 (the virtual originals run 64). At 64 they would have roughly doubled
    the AI cost in `kat` and `coverage`, and `linux-full` had about 36 min of margin.
  - The local `kat` step grew from 252 s to 320 s.
  - The six repeats are in `MUTANT_HARNESS_SKIP_TESTS` and `docs/mutants-accepted.md` §Skipped with their runtimes
    (25–49 s).
- **P2: two shared refactors.** The commands of the synchronous and asynchronous transports are now one sans-IO
  implementation (`secmp-transport/src/ops.rs`). The harness test binary ran 138/138 unchanged after the refactor.
  Correction (WEISUNG M6-B-5 §3): that was the whole binary at P2 — the 25 M5 harness tests plus the M6 tests of that
  time — not "the M5 harness suite", which is 25 tests.
  `Session::link_kat` and `AsyncSession::link_kat` name `link::Link` fully qualified. The old import was unused without
  feature `harness`.
- **PR run 38724110285 (head `1517781`, P1), read 2026-10-15.**
  - **`kani` failed at compile time** (also on the commit-1 run 38691107733). Under `cfg(kani)`, `zerocopy` 0.8.60
    (`secmp-transport` → `arti-client` → … → `rsa` → `rand` 0.8 → `ppv-lite86` → `zerocopy`) does not build: its own
    `cfg(kani)` code needs the `derive` feature.
    - **Fix (`fix(m6)` commit after P2):** `arti-client` is a `[target.'cfg(not(kani))'.dependencies]` entry of
      `secmp-transport`. `cargo kani` sets `--cfg=kani` in `CARGO_ENCODED_RUSTFLAGS`, so Cargo leaves it out of the Kani
      build only.
    - The dependency set, features, versions and `Cargo.lock` are unchanged; G-04, AD-12, X-03 and `cargo deny` stay
      green.
    - Local `cargo xtask step kani` with the fix: PASS, 40/40 harnesses verified (`secmp-client-core` 7, `secmp-proto` 30,
      `secmp-relay` 3; 3087 s).
  - **`windows-native` was cancelled at its 90-min timeout.** Build and nextest took about 18 min with the Arti closure.
    The `kat` harness suite took 2361 s, almost all of it the Phase A virtual AI tests on the Windows runner (1900–2220 s
    each). I did not change the job's timeout; it is a CI budget decision for you. P2 adds the tokio AI repeats.
  - **NASM:** `windows-latest` ships no NASM. Chocolatey installed `nasm` 3.2.0 ("NASM version 3.02"). The probe step now
    pins `$pin = "3.2.0"` for the fallback install (`ci.yml`, `ci-dispatch.yml`).
  - `linux-fast` passed in 74 min. The mutants shards were still running when I looked (12:35 UTC); their times go here
    when the run ends.
- **Job times of PR run 38724110285** (head `1517781`; all jobs started 11:00:03 UTC; read 14:30 UTC).

  | Job | Result | Time |
  |---|---|---|
  | xwin-cross | success | 6 min |
  | proverif-hx | success | 11 min |
  | kani | failure (zerocopy, fixed in `6c657e0`) | 17 min |
  | proverif-link | success | 19 min |
  | linux-fast | success | 74 min |
  | ct | success | 90 min |
  | windows-native | cancelled at the 90-min timeout | 90 min |
  | linux-full | failure (miri, see below) | 201 min |
  | mutants-shard 0…7 (ADR-047 Am. 4) | all failed, undocumented survivors (§6) | see below |

  Mutants shard times (ADR-047 Am. 4; final, shard 3 from the reviewer, completed 14:37:55 UTC):

  | Shard | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
  |---|---|---|---|---|---|---|---|---|
  | min | 204 | 160 | 200 | 218 | 203 | 192 | 196 | 199 |

  Of each shard, the first run took about 45–50 min and the second (harness) run about 2 h 30 min.
  - **Risk: shard time margin.** Shard 3 left 22 min to the 240-min job budget. Candidates if it shrinks further: fewer
    harness tests per mutant, or 12 shards. No change now (WEISUNG M6-B-4 §0.5).
  - **`linux-full` step times:** kat 3032 s, fuzz 4083 s, coverage 2779 s, nextest 598 s.
  - **The miri failure:** `cargo miri test --target aarch64-unknown-linux-gnu --package secmp-crypto` (portable run)
    fails with `error occurred in cc-rs: failed to find tool "aarch64-linux-gnu-gcc"`.
    - The chain is `secmp-crypto` → dev-dependency `secmp-testkit` → `secmp-transport` → `rustls` → `aws-lc-rs` →
      `aws-lc-sys`, a C build. The testkit's normal dependencies reach it since ADR-051.
    - **Fixed (WEISUNG M6-B-4 §0.1):** `secmp-client-core` and `secmp-transport` are `cfg(not(miri))` dependencies of
      `secmp-testkit`, and its `harness` module is compiled out under Miri (ADR-051 Am. 3 (3)). `cargo miri` honours the
      cfg in Cargo's target tables: `env CARGO_TARGET_DIR=target/miri-portable cargo +nightly-2026-09-21 miri test
      --locked --target aarch64-unknown-linux-gnu -p secmp-crypto --no-run` builds, and the Miri target dir has no
      `aws-lc-sys`, `rustls`, `tor-*`, `arti-*` or `libsqlite3-sys` build. No cross C compiler is installed.
- **`windows-native` with `WINDOWS_SKIP_TESTS` (WEISUNG M6-B-3 §1), expected job time.** In run 38724110285 the steps
  before the harness binary took about 38 min (setup 9 min, clippy 3 min, nextest build and tests 18 min, the `kat` builds).
  The harness binary took 2361 s, almost all of it in the skipped simulations; the longest remaining harness tests take
  about 71 s or less on the runner (`prop_schedule_independent_of_activity`). Expected: about 45–50 min, under the 90-min timeout. The tokio repeats are also
  skipped there.
- **MIRI-01 (Phase B, report only).** Command: `cargo +nightly-2026-09-21 miri test -p secmp-proto -v 2>&1 | grep -oE
  "(-C opt-level=[0-9]|-Zmir-opt-level=[0-9]|-Zmiri[a-z-]*)" | sort -u`. The pinned nightly is needed because Miri is not
  on the stable toolchain. Output:
  ```
  -C opt-level=3
  -Zmiri-backtrace
  ```
  - **(a)** The `test` profile (the workspace sets `opt-level = 3` for `profile.test.package."*"`, `secmp-crypto` and `secmp-proto`) is what Miri builds: the `-v` lines show
    `-C opt-level=3 -C debug-assertions=on`.
  - **(b) Probe M-01 (Phase C1, not committed; `target/fable/ci/miri-probe/`, own `[workspace]`, `[profile.test]
    opt-level = 3`, one test reading `*p.add(len)` of a 4-byte `Vec`).** `cargo +nightly-2026-09-21 miri test -v` runs
    with `-C opt-level=3 -C debug-assertions=on` and reports: `warning: Miri does not support optimizations: the
    opt-level is ignored` and `test tests::reads_past_the_end ... error: Undefined Behavior: memory access failed:
    attempting to access 1 byte, but got alloc39564+0x4 which is at or beyond the end of the allocation of size 4 bytes`.
    Detection survives opt-level 3: Miri interprets MIR and ignores the level, so the profile setting does not weaken it.
- **OPEN-M6-B-3 (HsId re-encode; open → M7).** `tor::onion_host` is a hand-written substitute for Arti's `HsId` (public
  use needs the `experimental-api` feature of `arti-client`). Checksum and version are checked when the `Onion` is
  decoded; there is no Ed25519 point check at this layer, so a non-point 32-byte string gives a host name no service
  answers. Fix in M7. Tests T-01/T-02 (`tor::tests::onion_reencode_*`). Note: production has no onion *text* parser, so
  T-02's text cases (upper-case, 55/57 characters, `.onion` twice) run against a strict test-side decoder, and the
  checksum/version/length cases against `Onion::from_bytes`; the brief's "no RelayRef produced" has no production
  counterpart to assert on.
- **Mutants CI time (ADR-047 Am. 4).** The second run adds 903 mutants: client-core 601, transport 302. The first run has
  2 411. In the local smoke run (32 cores, `-j 3`) each harness mutant took 1–150 s to build and 67–74 s to test. On
  the 4-core runner the time per shard may come close to the 280-min step budget. The per-shard times of the first PR run
  go into §7 (BRIEF §2.7).
- M6-17: cooldown fetch retries transient curl errors (ADR-015 Am. 1) after run 38616364662 `linux-fast` failed on a single connect error.
- The virtual worker is serial and non-blocking; a single-threaded real driver whose preparation blocked its loop would
  delay *other* links' due writes by the preparation of an active link — the cost model cannot show that, the Phase B
  driver must not do it.
- **R-CT-1 (closed): ct run #159 FAIL — target design; fixed in M6-CI-13; product trial-position path clean; residual
  timing of the selected key, entry and message key ≤ 2.2 ns locally, below the 10 ns floor (not monitored by the informative nonce target)**
  (ADR-042 Amendment 5; `docs/reviews/M06-evidence/ct-nonce-M6-CI-13.md`).
  - **Cause.** `tr_decrypt_trial_open_position` (and, in one half, `tr_decrypt_reject_skipped`) failed because their
    classes differed in the public header nonce. CT-DIAG-3 V4 showed the nonce alone shifts §7.4 Decrypt by up to 65
    ticks with either sign.
  - **Product path.** The re-sealed variant, with the same nonce, header plaintext and body and differing only in trial
    position, entry, `hk` and `mk`, stayed ≤ 0.50 ticks in 16/16 halves.
  - **Fix.** `0d89bdf`: both targets hold the nonce, the decoded header contents and the body constant. `6ac385f` adds the
    informative `tr_decrypt_nonce_dependence`.
  - **Acceptance (WEISUNG M6-CI-13b):** every half |Δp90| < 0.5 × floor (20 local ticks = 5 ns) and every rep verdict
    PASS. The 1.0-tick bar of M6-CI-13 §5 was a diagnosis bar and is withdrawn.
  - **Measured** (local repeat mode, Threadripper PRO 5955WX, `q_eff` 40 ticks):

    | Fixture | max \|Δp90\| | Rep verdicts |
    |---|---|---|
    | new | 8.93 ticks = 2.2 ns = 0.22 floor | 6/6 (5a) and 8/8 (5b) PASS |
    | old, local | 28.36 ticks = 7.1 ns | — |
    | old, EPYC | 42 ticks = 17 ns (run #159 FAIL) | — |

  - **Recorded residual** (formerly the §8 question; no question remains open). With the new fixture, 7 of 28 halves
    shifted by more than 1 tick: −1.42 and −1.65 (5a, `reject_skipped`); −8.93 (t −25.22), +3.81 (t 10.93) and −1.27
    (5b, `trial_open_position`); −5.20 (t −12.93) and +1.14 (5b, `reject_skipped`). They come with both signs.
    - This is the timing of the remaining class differences: the selected key/entry/message key (`hk`, `mk` are secret keys) and the header ciphertext that follows; `pn`, `n`, `dh_pk`, `ek_pq`, `ct_pq` are encrypted header contents (spec §7.3), not public fields. `tr_decrypt_nonce_dependence` does not monitor it (key, entry and `mk` fixed): it monitors the nonce / header-ciphertext / body-AD contrast.
    - It is below the floor by a factor of at least 4.
    - The two-receiver control of CT-DIAG-3 (V6c) shifted by up to 7 ticks with nothing differing.
- ct on fine-timer hosts (EPYC 7763, q_eff 1 tick) resolves micro-timing of ≈ 10–20 ns in the nonce and in decoded header contents; targets must
  hold the nonce and the decoded header contents constant across classes unless they name them (ADR-042 Am. 5).
- **OPEN-M6-C1-2 (FINAL4, decided C2 planning → M7 informative target).** The re-sealed position fixture holds the decoded `pn` constant (old classes 0/3,
  new 0/0), so timing that depends on decoded header contents is no longer in the position contrast. Decision: no ct code in M6. A timing
  dependence on decoded encrypted-header contents would be a data dependency on header contents, not a secret-key comparison, and is outside
  `CT_TARGETS` by ADR-042 Am. 5 (no mechanism is asserted: nothing in the tree measures one). A constant-nonce contrast fixture ("header
  contents vary under one nonce") is an **informative** target for M7. Whether the receiver-side timing of skipped-key work needs a docs/01
  entry is the owner's decision (threat model).
- **OPEN-M6-C1-3 (stale auditable binary in `sbom`, decision in the C2 planning).** The `sbom` step must not read back a binary whose embedded dependency list differs from `Cargo.lock` (seen after the `rustls-webpki` bump: `target/release/secmp-relay` was not rebuilt and still listed 0.103.15). Candidate fixes: compare the embedded list with `Cargo.lock` and fail on a mismatch, or build into a target directory owned by the step. No fix now.
- **Kani headroom (item 12, decided WEISUNG M6-C1-3: harnesses unchanged).** Peak `secmp-proto` harness 13.75 GB
  (`kani_commit_accept_atomic`) on a 16 GB runner; seven harnesses exceed 8 GB. The OOM of 14.10. (15.5 GB) came from profile
  overrides, fixed in M6-16. No bound could be lowered without weakening a property. Baseline table:
  `docs/reviews/M06-evidence/kani-rss-d1bcfdc.txt`. No ADR-047 amendment.
- **OPEN-M6-C1-1 (M7).** Split the seven > 8 GB proto harnesses by sub-property, or add an xtask RSS guard
  (`SECMP_RUNNER_TRACE`) that fails the kani job when the peak exceeds 14.5 GB.
- **M7: K-C5 call-through after extraction.** K-C5 mirrors the FETCH-lead and flush-bound expressions; once they are extracted
  into `core/pure.rs` it should call them. K-C6 fixes `max_in_flight` = 2 (a symbolic value cost 14.8 GB under Kani).
- **Infra note for the owner.** The first attempt at K-C4 (a `VecDeque` ledger) ran one `cbmc` to 97 GB RSS; the container has
  no memory limit, and it could not be killed from the session.
- **OPEN-M6-B-1 measured (item 6, R-01 `m6_driver_io::receive_throughput_per_fetch_is_measured`; relabelled after FINAL4 FIN4-6).** Balanced, one recv
  queue, four cells stored before the first `FETCH_MULTI`, 5 ms per received cell: the cells are committed at 11, 21, 31 and 41 s —
  **one cell per response** (10 s apart) — and become ready to be acknowledged at 21, 31, 41 and 51 s — the scheduler's *internal*
  acknowledgement state (`Scheduler::acked`), one period after the commit. The **relay observes** the acknowledgements at 30, 40, 50
  and 60 s (its queue head moves), i.e. with the next `FETCH_MULTI` (`target/m6-evidence/R-01.txt`). The test asserts four values in each
  series before comparing. The fix needs a core API (a deferred-commit outcome of `deliver`): M7 entry.
- **`Scheduler::frame_written` is a trusted-caller contract (item 10, Astra FINAL3 (e)).** A report on an up link with an empty ledger is
  counted (`unmatched_written`, asserted 0 in debug builds by the tokio driver); a duplicate report while the ledger is not empty cannot
  be told from a genuine one — a frame carries no id — and pops the oldest entry. Detecting it needs an API change (a frame id): M7.
- **Kani scope (item 5, M7).** K-C1…K-C6 prove the ledger and reservation functions (`core/pure.rs`) on a symbolic ledger. Not covered, M7:
  the in-flight rule over real transitions, queue generations, the abstract persist contract and paired executions; `Scheduler`
  itself is out of Kani's reach from `secmp-client-core` (an up link needs a `Channel`).
- **Kani times (FINAL4).** `kani_deadline_arithmetic_checked` and `kani_rate_bound_integer_form` are slow (64-bit multiplications): they verified in the container in 687 s and 358 s (`kani-m6c1-ee3c66f.txt`, `Verification Time`; client-core 13/13 in 1 173 s), and in CI the `kani` job of PR run 39110123300 (head `bf7ba1c`, all 46 harnesses, K-C1…K-C6 included) succeeded in 100.5 min (08:05:40 → 09:46:10; run 39080358115 before K-C: 77 min). The reviewer's macOS run was interrupted after 20 min, which is inside these times; they need no change.
- **OPEN-M6-B-3 (item 7).** The onion host re-encode substitutes for Arti's `HsId`; no Ed25519 point check at this layer; fix in M7.

- **M7 (D-C2-1): the handshake through the scheduler.** (1) A `RouteUpdate` sender in `secmp-client-core` (an outbox/plan entry for
  `Content::RouteUpdate`, the first reply of the responder, §6.6 step 4); (2) an input to `IssueParams` for the seeds of a pooled invitation
  queue (§5.2); then the three cells, the responder's accept and `LINK_PUT`/`LINK_GET` run as scheduled ops (the analysis is in §8). Until
  then `two-clients` scripts the handshake on set-up links and carries the inviter's route in the invitation file.
- **`relay_bin()` and `sbom` (input for C2-4.3, not fixed here).** `tests/harness/m6_two_clients.rs` (`relay_bin()`) runs a nested
  `cargo build --locked --offline -p secmp-relay` — in a release test run it rewrites `target/release/secmp-relay`, the very path
  `cargo xtask sbom` reads back with `cargo audit bin`; a stale or foreign binary there is one candidate mechanism for OPEN-M6-C1-3.

- **OPEN-M6-C2-1 (found in C2-2, spec §10.4; accepted by the reviewer as a real protocol gap, WEISUNG M6-C2-4): a `Relayed`,
  unreceipted message is re-sent only on `ERR_NOQUEUE`.** The three code sites: `outbox.rs:177` (`requeue_unreceipted`) ←
  `conversation.rs:571/:748` (`on_lost`) ← `core/mod.rs:941–947` (`Err(NoQueue)` of a `SEND` → `source.queue_lost`). There is no
  time-based re-send, so a sender whose links are down across a relay restart and the recipient's re-creation of the queue never sees
  `ERR_NOQUEUE` and the message stays `Relayed` for ever. Evidence (first SIM-09 draft, relay restart in the flood): the inviter
  received 99/100, message 29 missing; the invitee's outbox ended with 98 delivered + 2 relayed; the queue was re-created 517 s after
  the restart, the sender's links were up again only after the flood (`RouteDead` events: none). No fix, no test change in M6; entered in
  `docs/09-open-questions.md` as OQ-19 (M7 candidate).
- **OPEN-M6-C2-2 (found in C2-2b while re-asserting SIM-02): the tokio driver drains one cell per `FETCH` tick.** The facade
  `Deferred::deliver` (`scheduler/run.rs`) answers "not committed" until the worker finished the job, and the core's `fetched`
  (`core/mod.rs:882–903`) stops at the first uncommitted cell, so of the `F` = 4 cells a `FETCH` returns one is handed to the worker per
  round trip. A recipient therefore drains at the sender's rate (1 cell per `P`), not faster (§10.2 assumes a drain rate above the
  sender's): after the 30-min partition of SIM-02 the queue B → A stays at 128 cells to the end of the 3 h run (`next − head` = 128 in
  every one of the 1 235 store changes after 3.0e6 ms; the baseline without the partition ends with 6 cells), evicting one cell per tick
  and delivering each cell only as it passes the head (messages arrive late and out of order, (E) still holds). Phase A's drain
  measurement MR-02 ran on the virtual driver, which delivers synchronously. Root cause in `scheduler/core` (`fetched`) and the driver
  facade: **not touched, reviewer's**; OQ-20 in `docs/09-open-questions.md`. SIM-02's prediction is taken from the relay's own record
  of evictions and does not depend on the drain.
- **Observation for the owner, not an M6 defect (§10.3 consequence):** Strict `P = 10 s` cannot communicate over a link with RTT >
  20 s (`MAX_IN_FLIGHT · P`): no response is read before `TornDown(InFlight)` (SIM-07).
- **Pool and simulation streams (WEISUNG M6-C2-4 item 8):** the pool streams are strict like the others (a residual at drop is an
  error entry); the streams of the scheduled links in a simulation are lenient at drop (a broken network ends units mid-way on purpose),
  but `Recorder::check()` now runs in simulation runs too and all nine rows pass it.

## 8. Blocked / questions for the reviewer or owner

### Mutants shard time (BRIEF M6-C1 item 9, MU-C2) — decided: ADR-047 Amendment 7 (Accepted, 12 shards)

The per-shard first-run / second-run / job minutes of runs 156 and 160, the cause and the options are in docs/08 (ADR-047 Amendment 7) and
`docs/reviews/M06-evidence/shard-times-c1.txt`; `MUTANT_SHARDS` is 12 since `ci(mutants): ADR-047 Amendment 7 — 12 shards`.

### OPEN-M6-B-5 — memo: `socket2` for keepalive timings and `TCP_USER_TIMEOUT` (BRIEF M6-C1 item 18; memo only, no `Cargo.toml` change)

- **Why.** The direct link's socket (`tls::tcp_socket`, GLMB-1) has keepalive on and Nagle off, but no timings: the kernel's
  defaults (2 h before the first probe) never decide, and a black-holed link is closed only by the driver's own bounds — unanswered
  requests hit the in-flight bound at the third tick (≤ 3 × the slowest period = 240 s), a write that does not drain hits
  `WRITE_STALL_MS` (10 s). Keepalive time/interval/retries and `TCP_USER_TIMEOUT` need `setsockopt`, which tokio does not expose.
  With them a dead direct link would be closed by the kernel after about 60 s (for example `TCP_USER_TIMEOUT` 60 s, keepalive
  30 s / 10 s / 3) instead of up to 240 s. It matters for the direct mode only (testing / own-VPN use, `docs/05` §7); the onion mode
  has the Tor circuit's own liveness.
- **What it would take.** `socket2` 0.6.5 is already in `Cargo.lock` (tokio, tokio-rustls, arti-client and turmoil use it; `cargo tree
  -i socket2` shows its feature `all` enabled by tokio, which is the feature `TcpKeepalive::with_interval`/`with_retries` and
  `Socket::set_tcp_user_timeout` need). The change is a **new direct dependency of `secmp-transport`** (`socket2 = { workspace = true,
  features = ["all"] }`) and nothing new in the lock file: `tokio::net::TcpSocket` → `socket2::SockRef::from(&socket)` → `set_tcp_keepalive`,
  `set_tcp_user_timeout`. No `unsafe` in our crates (socket2's `unsafe` is inside the crate, behind a safe API).
- **Alternatives.** (1) Stay with the 240-s in-flight bound (today; costs up to 4 min of a dead direct link, no dependency). (2) `std` or
  tokio alone: `std::net` and tokio offer keepalive on/off and nodelay only. (3) `libc` in a new `secmp-sys-net` crate with `unsafe`:
  one more audited crate, more code than the safe API of `socket2`. (4) An application-level ping already exists (the scheduler's
  own traffic), so a shorter in-flight bound would change the schedule rules (spec §10.3) — not an option.
- **Maintenance and audit status.** `socket2` lives in the `rust-lang` GitHub organisation, is a dependency of tokio, mio's ecosystem and
  hyper, and is released often; version 0.6.5 is in the lock file and passed the 7-day cooldown. In `supply-chain/config.toml` it is a
  *tracked exemption* (`[[exemptions.socket2]]` 0.6.5, `safe-to-deploy`: "transitive dependency … review at every release"), not an
  audit. As a direct dependency the invariant (CLAUDE.md §1.9) wants an ADR entry and a `cargo vet` record: an `audits` entry for
  0.6.5 by the reviewer after reading its `sys/unix.rs`/`sys/windows.rs` `unsafe` blocks, replacing the exemption.
- **ADR-051 amendment it would need** (text for the reviewer, not applied): "Part 2 (dependencies): `secmp-transport` takes `socket2`
  (feature `all`) as a direct dependency for the direct link's TCP socket: keepalive 30 s / 10 s / 3 probes (all platforms) and
  `TCP_USER_TIMEOUT` 60 s (Linux; the other platforms rely on the keepalive and the driver's bounds). The kernel's probes are
  zero-byte ACKs at a fixed cadence on an otherwise idle connection — a function of the schedule, not of activity; in the direct mode the
  client's IP is exposed to the host anyway (`docs/05` §7)." Work: `cargo vet certify socket2 0.6.5` (or an import), `expect::NORMAL_DEPENDENCY_ALLOW`
  (policy), the amendment in `docs/08`, `tls::tcp_socket` and its test (`direct_tcp_socket_has_keepalive_and_no_delay` also reads the
  timings back), and a Windows run (X-10) since `TCP_USER_TIMEOUT` does not exist there.
- **Recommendation.** Defer to M7 with the other direct-mode work; the status quo (240 s) is within the threat model (a dead direct link
  costs availability, not secrecy).

### BRIEF M6-C1 item 12 (K-12) — BLOCKED 2026-10-18, RESOLVED (WEISUNG M6-C1-3: harnesses kept, risk recorded in §7): seven `secmp-proto` harnesses exceed 8 GB, not one

Measured alone (`docs/reviews/M06-evidence/kani-rss-d1bcfdc.txt`, 30 harnesses, all verified): `kani_commit_accept_atomic` 13 751 MB,
`tr_header_selection` 13 425, `kani_accept_opk_delete_only_on_success` 12 127, `kani_q_frame_plaintext_exact_fit` 11 662,
`request_link_get` 9 304, `response_frame` 8 754, `kani_frame_pad_total` 8 541 (the rest ≤ 7 750). The brief assumed one peak (runner
trace 38616364662: 13.8 GB = `kani_commit_accept_atomic`). A different SAT solver does not change it (`tr_header_selection` with
`--solver cadical`: 13 421 MB). The peak harness is already at the minimum its comments record (M4 report §11.2: no proof with a second
record or a symbolic store finished in 9–30 minutes; its two `kani_commit_on` scenarios are the property). A reduction of any of the seven
by unwind or input size narrows what it proves. Nothing was changed. **Question:** keep the harnesses and the runner's 16 GB (the CI job passes), set
the bound per harness at the measured value, or name which of the seven may be narrowed and how.

### EXTB-1 (WEISUNG M6-B-5 §1) — BLOCKED 2026-10-16, RESOLVED: core change (A)/(A′) approved (WEISUNG M6-B-6), applied @ `cdf2b31`

The text below is the STOP as it was written. The reopened proofs and their results are in §6, "Decisions of WEISUNG
M6-B-6".

- **Why the driver cannot fix it.**
  - In `prepare_link` (`scheduler/core/mod.rs:591–602`), the core seals the FETCH part in the same call in which the
    cell source answered "not ready" for the SEND part. At the tick the SEND part is written first, and `begin_write`
    refuses the counter order.
  - The driver cannot know in advance which send queue the core will ask for. A Balanced link picks it by round robin
    over the relay's send queues; `Scheduler` has no list of them and is not `Clone`. So it cannot have the cell ready,
    or hold the `work` call, before the first "not ready".
  - The core also advances the round-robin position when the chosen cell was not ready (`:633`), so the queue a slot
    serves would depend on the worker's timing — that is, on activity — as soon as the facade defers.
- **Smallest core proposal (two hunks in `prepare_link`/`prepare_send`, +15/−6):**
  `docs/reviews/M06-evidence/extb1-core-proposal.diff`.
  - (A) No FETCH is sealed while the tick's SEND part is still missing: `let send_missing = needs_send &&
    up.send_part.is_none(); if tear.is_none() && !send_missing && …`.
  - (A′) The round-robin position moves only when the chosen queue's cell was obtained, so the same queue is asked
    again at the next pass.
  - With a synchronous cell source nothing changes: it is never "not ready". With `NoCells` the tick overruns as before;
    only the useless FETCH seal is gone.
- **Prototype evidence.** Applied in a throwaway `git worktree` under `target/`, not on the branch, never committed,
  removed afterwards:
  - the probe test is green;
  - `cargo nextest run --workspace` 1125/1125 (AI-01…AI-06 sync and tokio, the S-* / LR-* / prep-log tests, FZ-04
    replay, P-01/P-02);
  - `cargo kani -p secmp-client-core` 7/7.
- **Proofs and evidence it reopens:**
  - Kani K-01…K-07, especially `kani_balanced_rr_selects_due_or_ping` (`rr_select` is unchanged; its caller changes);
  - AI-01…AI-06 sync and tokio, and their 64-trace evidence;
  - S-19…S-25 (prepare/tick split, prep log) and the Balanced S-* rows (round robin);
  - FZ-04 `scheduler_event_sequence`;
  - P-01/P-02;
  - MR-01/MR-02 figures (expected unchanged: sync source);
  - the mutants of `core/mod.rs` (OPEN-M6-B-2 lines shift).
- **Then:** the EXTB-1 test is committed with the fix. The six tokio AI repeats get the extended oracle: (a) no
  `TornDown` other than `Lifetime`, (b) the relay-visible SEND queue sequence identical idle vs active (recorded at the
  `MemRelay` from the store's per-queue `next_cell_id` after each client unit), and (c) frames on every tick. Then
  `ci-full`.
- **On the ack progression of oracle (b):**
  - The acks the client sends for its receive queues follow the peers' activity (`PeerSend` events), so they cannot be
    identical between an idle and an active trace.
  - Proposal: compare the ack progression only in traces without peer activity — AI-01…AI-03 variants with the `PeerSend`
    events removed, as AI-04 removes the `UserSend` ones — and the SEND sequence in all traces.
  - Please confirm the reading.
- **Question:** may I apply (A) and (A′) to `scheduler/core/mod.rs`, with the reopened proofs re-run as listed?

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

### Phase B P2 — questions for the reviewer (no work blocked)

1. **tokio `test-util`.** The paused-clock tests need this feature, and it is not in the ADR-051 table. It is enabled as a
   dev-dependency of `secmp-testkit` only. Accept it as an ADR-051 note, or ask for a virtual timer of our own instead?
2. **Receive throughput of the facade** (§7). Accept at most one newly committed cell per `FETCH`? The alternative is a
   core API change (a deferred-commit `deliver` outcome) in a later phase. That touches `scheduler/core/**`, which the
   brief makes a STOP.
3. **AD-09 wording.** `async-trait` is in `Cargo.lock` through Arti 0.46.0. Is the test as built (no workspace crate
   depends on it) the intended reading?
4. **Trace counts of the tokio AI repeats** (16 / 16 / 16 / 8 / 4 / 8) and the six new entries of
   `MUTANT_HARNESS_SKIP_TESTS`: accept, or raise AI-01…03 to 64?

### TC-03 (b): can the handshake run as scheduled work? (WEISUNG M6-C2-2 §3(b), read-only analysis of `9ba54ac`)

Expressible with the existing public API (checked in the code, not built): `LINK_PUT`, the invitee's consuming `LINK_GET` and the
owner status are `ControlKind::{LinkPut, LinkGetConsume, LinkGetOwner}`, queued with `Scheduler::schedule_control(…, When::Prompt)` and
run by a testkit `ControlRunner` (`TestControl` discards the consumed blob; a wrapper can keep it); the three handshake cells as a testkit
`CellSource` on a send queue to the invitation queue (`add_send_queue`, `SendCap::from_route`; cells that fail to open are ignored by the
responder, §6.5, so random cells are valid dummies); the responder's receive through `CellSource::deliver` and `Responder::accept`; the
pooled queues through `manage_pool` and `take_pool_queue` (done in C2-2 fix-up, see §10).

**Not expressible, with the missing item named:**
1. The responder's first reply carries a `RouteUpdate` that replaces the invitation queue by a pooled queue (§6.6 step 4, §10.6 rule 5).
   `secmp-client-core` has no sender of Content type 0x04: `OutMessage.kind` is an `AppKind` without a route-update kind and
   `Conversation::plan` produces only messages, receipts and dummies. Missing: an outbox/plan entry for `Content::RouteUpdate` (and the
   switch of the contact's send queue to the new route, which `Conversation::set_send_queue` already allows). Without it the invitee cannot
   learn the inviter's queue; the invitation file carries it.
2. `MemoryPrekeyStore::issue_invitation` draws `inv_send_seed` and `invq_recv_seed` itself and `IssueParams` has no field for the seeds of
   a pooled queue (§5.2: "the invitation queue is one of the inviter's pooled recv-queues"). Worked around in testkit code by overwriting
   the public fields `InvitationV1.{inv_sid, inv_send_seed}` and `InvitationRecord.invq_recv_seed` after issuing (the link data does
   not depend on them); a proto API change (an input to `IssueParams`) is M7.

Decision taken, branch **(ii)** of the weisung (item 1 needs a core API change; no core change): the handshake stays scripted outside
the scheduler; deviation D-C2-1 in §5, M7 entry in §7, TC-03 in §3 marked accordingly. The reviewer decides on (ii) when reading the
return block.

- **CLOSED (WEISUNG M6-C2-3, reviewer 2026-10-22): `tokio/test-util` for the `two-clients` binary — no.** ADR-051 Am. 3 stands: the binary's
  `mem` transport runs in real time, the tests drive the engine on a paused runtime (`main_in`). (Asked in §10, C2-1 finding 1.)
- **CLOSED (same weisung): D-C2-1, branch (ii) accepted** — the handshake stays scripted outside the scheduler; the M7 entry in §7 stands.
  No ADR (a test-row deviation, not a spec deviation).

## 9. Checklist before requesting review

- [x] All Phase A rows evidenced above
- [x] Phase C1 closed @ `25625bc` (PR run #165 = 39660191651, all jobs green; local `ci-full` evidence `M06-evidence/ci-full-m6c1-c570d98.txt` at `c570d98`, the later commits `5e1a136`/`25625bc` are covered by run #165): items 1, 3–11, 13 of BRIEF M6-C1 evidenced (§3 rows, §5, §6, §7, §8); item 12 decided (§7); C2 rows are `OPEN — C2` in §3
- [x] `cargo xtask ci-fast --strict` green at `cd828ca` (C-4) and at the C1 head; `ci-full` at `c570d98`: `M06-evidence/ci-full-m6c1-c570d98.txt`
- [x] `cargo xtask ci-fast --strict` green at `7a67339`; Kani 40/40 at `7a67339`; `ci-full` green (§4) at `03cc660`, not rerun
- [x] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [x] Vectors untouched
- [ ] PR run on `linux-fast`, `windows-native`, `xwin-cross`, `linux-full` (after the push by the reviewer)
- [x] Threat model and spec untouched

## 10. Phase C2 log (BRIEF M6-C2; `modell=claude-sonnet-5-5`)

### C2-1 fix (WEISUNG M6-C2-1)

- Git identity, repo-local (`git config --show-origin --get-all user.name|user.email`):
  `file:.git/config	Claude Code` / `file:.git/config	noreply@anthropic.com`.
- Expired exception `rustls@0.23.46` (ADR-015 Am. 2): red before green, `cargo nextest run -p xtask cooldown_covers_m6_lock` after the
  `expect.rs` edit only: `panicked at xtask/src/cooldown.rs:571:9: assertion left == right failed  left: 1` (`assert_eq!(COOLDOWN_EXCEPTIONS.len(), expected.len())`);
  green after the `expected` list dropped the tuple (12/12 `cooldown` tests).
- Gate line: `3 cooldown PASS 90s 561 registry packages (Cargo.lock, fuzz/Cargo.lock), all ≥ 7 days old or excepted (ADR-015 Am. 2); youngest: rustls 0.23.46, 7 days; cooldown: exception rustls-webpki@0.103.16 until 2026-10-27`.
- Commit `56179fb` `deps(cooldown): drop expired ADR-015 Am. 2 exception rustls@0.23.46`; the C2-0 docs commit follows it.
- `rustls-webpki` exception expires 2026-10-27: STOP at the first red `cooldown` then.

### C2-1 `two-clients` (BRIEF M6-C2 §C2-1; rows TC-01…TC-06, TC-09, X-08)

What was built: `secmp-testkit` `[[bin]] two-clients` (`required-features = ["harness"]`, `src/bin/two-clients.rs`, a 10-line `main`) over
the library module `secmp_testkit::two_clients` (`cli`, `run`, `trace`, `rand`): hand-written flags (no argument-parser crate), exit codes
0 ok / 1 run failed / 2 usage / 3 transport unavailable, in-memory profiles (`MemOutbox`, `MemPersist`, ratchet states), the scripted
invitation and handshake (§5.5, §6.4–6.6) on set-up links, then two clients — each a `Scheduler` on the tokio `Driver` — exchanging the
script's messages over constant-rate links; `--trace-out` is JSON lines with exactly the TC-09 keys. Transports: `mem` (in-process relay),
`loopback` (plain TCP to the relay's loopback listener, `TcpProvider`), `tls` (`TlsProvider`, pinned SPKI, scheduler direct mode), `tor`
(`tor::arti::start`, owner-operated); a transport that cannot be used is exit 3 and no other transport is tried (TC-01 checks a decoy
listener sees only a TLS record).

| Row | Test | Command |
|---|---|---|
| TC-01 | `m6_two_clients::two_clients_cli_contract` | `cargo nextest run -p secmp-testkit --features harness --test harness two_clients_cli_contract` |
| TC-02 | `m6_two_clients::two_clients_profiles_are_in_memory` | same, `…two_clients_profiles_are_in_memory` (600 s virtual, 0.5 s wall) |
| TC-03 | `m6_two_clients::two_clients_scripted_invitation_handshake` | same (steps `link_put`, `invitation_queue`, `link_get_consume`, `hx_initiator cells=3`, `hx_responder accepted=true … present=false consumed=true`; two `session=up`; equal 60-digit SAS) |
| TC-04 | `m6_two_clients::two_clients_exchange_script_mem` | same (100 + 100 messages, 1…65 535 B, seed 11; 10.5 s wall; delivered once, in order, bytes equal) |
| TC-05 | `m6_two_clients::two_clients_loopback_tcp` | same (relay binary on 127.0.0.1, Strict and Balanced in parallel; 619 s wall) |
| TC-06 | `m6_two_clients::two_clients_direct_tls_loopback` | same (`DirectRelay`, pinned SPKI; 520 s wall) |
| TC-09 | `m6_two_clients::two_clients_trace_schema` | same |
| X-08 | `policy::tests::two_clients_not_shipped` | `cargo nextest run -p xtask two_clients_not_shipped` |
| TC-07, TC-08 | owner-operated, not run | see §6 (C2-1 owner requests) |

A real failure found on the way: TC-05/TC-06 first ran with 20 messages of 1…65 535 B and did not finish in 1 500 s — a 65 535 B message
is 40 cells, i.e. 400 s at P = 10 s, so 20 of them need ≈ 4 000 s of real time. The rows' scripts use `size_max = 1000` (one cell per
message; 20 cells = 200 s plus link phases up to 180 s); TC-04 (virtual time) keeps 1…65 535 B.

Findings and decisions for the reviewer (none changes the spec; none is a deviation from a row):
1. **Virtual time in the binary.** `tokio::time::pause`/`start_paused` need tokio's `test-util`, which ADR-051 Am. 3 keeps out of every
   build but tests (policy `tokio_test_util_is_dev_only`). The binary's `mem` transport therefore runs in real time (a 600 s run takes
   600 s); the tests drive the same engine in-process on a paused runtime (`two_clients::main_in`, on a 32 MiB-stack thread: the
   handshake and ratchet frames overflow a test thread's 2 MiB in an unoptimised build). Question §8: may `harness` enable
   `tokio/test-util` (a non-default feature of a never-shipped crate) so the binary itself is virtual? Not done — it is outside ADR-051.
2. **The handshake is scripted outside the scheduler.** The invitation, the three cells and the acceptance use one set-up connection per
   step; the first reply's `RouteUpdate` has no sender before M7, so the inviter's reply route travels in the invitation file next to the
   URI (`invitation = …`, `route = …`; testkit-only). Everything after the handshake goes through the scheduler. The script's set-up links are
   not part of `--trace-out`; the pool's links (the scheduler's control and fetch links of C2-1c) are.
3. **CI time.** TC-05/TC-06 are real-time rows with real sockets, 520–619 s each; the `kat` step went from 336 s to 751 s wall on the
   container (they run next to the long simulations), `windows-native` runs them too (the relay binary is built with a nested
   `cargo build --locked --offline -p secmp-relay`). Not changed: no timeout, list or threshold was touched.
4. `interval_s` (script key, default 0) queues message *i* at `t0 + i × interval_s`: needed by MR-04 (latency of a message sent into an
   idle link). The run prints `clock unix_origin=<secs>`, which aligns the `t_ms` of two traces.
5. Groups (b)–(d) of the brief are one commit: they share one test file.

**Owner requests, TC-07 and TC-08 (asked 2026-10-22; not waited for; the rows stay `owner-operated, not run` until the files below exist).**
On both machines, once: `cargo build --locked --release -p secmp-testkit --features harness --bin two-clients`. The same script file
`script-tc07.txt` on both (50 messages each way, one cell each, one every 20 s so each finds an idle link):

```
messages = 50
size_min = 1
size_max = 1000
seed = 7
interval_s = 20
```

`relay.ref` is the test relay's reference file: `relay_ref = <hex RelayRef>` (spec §5.3, with its onion; for TC-08 with the direct
endpoint and the SPKI pin from `secmp-relay spki <cert.der>`) and `access_key = <hex>`; `secmp_testkit::two_clients::run::relay_ref_file`
writes the text.

- **TC-07 (real Tor).** Machine 1: `target/release/two-clients --role inviter --transport tor --mode strict --tor-dir <fresh profile dir>
  --relay-ref relay.ref --invite-out invite.txt --script script-tc07.txt --trace-out inviter.trace.jsonl > inviter.out`. Copy `invite.txt` to
  machine 2 (it is a secret; any private channel). Machine 2: `target/release/two-clients --role invitee --transport tor --tor-dir <fresh
  profile dir> --relay-ref relay.ref --invite-in invite.txt --script script-tc07.txt --trace-out invitee.trace.jsonl > invitee.out`.
- **TC-08 (direct TLS).** The same with `--transport tls` and no `--tor-dir`, files `*-tls.*`.
- **Paste back** into `docs/measurements/M6-evidence/two-clients-<tor|tls>-<date>/`: `inviter.out`, `invitee.out`, both traces, the two
  machine names, the dates, `git rev-parse HEAD`. Expected: `delivered side=inviter 50/50` and `side=invitee 50/50` and `result exact=true`
  within 30 min of `session=up`, the `sas side=…` lines equal on the two machines. The latency file is, per message, the `deliver` time at
  the receiver minus the `enqueue` time at the sender, each plus the `clock unix_origin=` of its own `*.out` (clocks NTP-synchronised);
  MR-04 reads the same files (C2-4).

### C2-1b fix-ups (WEISUNG M6-C2-2; reviewer's diff verification of `9ba54ac`)

Commits: F-1 `4cb8fce`, F-2 `6bdb26c`, TC-03/TC-02 `be2e21e`, this report. `ci-fast --strict` at `be2e21e` (all steps PASS, `kat` 792 s;
output `target/tc/cifast-c21b.txt`; the C2-1 head had `kat` 751 s, `target/tc/cifast-c21.txt` — the figure in the C2-1 return block).

- **F-1 (major), `trace.rs`.** A unit is recorded as it crosses, never re-sliced: a write is a unit at its flush (the driver writes one frame,
  then flushes), a read is the reader's own request (`read_exact` of one frame; a handshake record, read as its two-byte length and its
  body, is one unit of `2 + n` — decided by the length the stream itself carries, not by a constant); a stream that ends inside a unit is an
  error entry (`Recorder::check`), which fails the run (`the trace is not sound`). Tests `two_clients_trace_rejects_partial_unit` and
  `two_clients_trace_unit_lengths_are_observed_not_assumed`; TC-05, TC-06 and TC-09 pass with the real lengths.
- **F-2 (major), `expect::MUTANT_HARNESS_SKIP_TESTS`.** `two_clients_loopback_tcp` (619 s), `two_clients_direct_tls_loopback` (520 s) and
  `two_clients_exchange_script_mem` (10.5 s) are skipped per mutant, comments in the format of the existing entries; the pinning tests
  (`mutants_skip_list_names_existing_tests` and the argument tests) follow the list. Per-mutant harness time after the change, the filter
  of the gate (every skip of the list) on the 32-core container: `cargo nextest run -p secmp-testkit --features harness --test harness
  --no-fail-fast -- --skip activity_independence --skip bandwidth_model_matches_capture … --skip two_clients_loopback_tcp --skip
  two_clients_direct_tls_loopback --skip two_clients_exchange_script_mem` — 235 tests passed, **68.6 s** wall (the slowest, 68.6 s, is the
  existing `timing_draws_independent_of_activity`, AI-05 on the virtual driver, which is not in the list; the new rows in it take ≤ 0.8 s).
- **TC-03 (a).** Each client fills its `QueuePool` through the scheduler (`manage_pool`, `QUEUE_NEW` control operations; the test tool
  shortens the control delay to 2…5 s, nothing else in `Params`); the invitation queue and the inviter's reply queue are two spares
  (`take_pool_queue`), the invitee's reply queue one of its own: `step=invitation_queue source=pool spares_before=2 spares_after=1
  queue_new_commands=0`; the test also checks the engine source has no `.create_queue(` (the only creations are the pool's control
  operations: `queue_new_ops=2` per client). **(b)** analysis in §8, branch (ii), deviation D-C2-1 in §5, M7 in §7, TC-03 marked in §3.
  A probe connection at the start makes an unreachable relay exit 3 at once (the pool control operations would retry for minutes).
- **TC-02.** The binary also runs (30 s real) with cwd, `HOME`, `USERPROFILE`, `TMPDIR`/`TEMP`/`TMP`, the XDG and the Windows data
  directories redirected into one empty sandbox; afterwards the sandbox holds the trace file and nothing else. Redirecting instead of
  listing the real `$HOME`/`/tmp` (which other processes write during the run) keeps the test deterministic: anything the engine wrote
  through those places lands in the sandbox. The in-process 600 s run keeps its listing of the test directory.
- **Red before green, re-quoted from the committed tests** (tests at `be2e21e`; each run against a planted condition of the row's "would
  fail if", sources restored afterwards; text as `cargo nextest` printed it):

  | Row | Planted condition | `m6_two_clients.rs:line` — assertion |
  |---|---|---|
  | TC-01 | `--tor-dir` missing from `--help` | `:135:9` `--help does not list --tor-dir` |
  | TC-02 | the engine writes `profile.bin` into its working directory | `:312:5` `assertion left == right failed: a file besides --trace-out` (left `[…/cwd/profile.bin, …/cwd/trace.jsonl]`, right `[…/cwd/trace.jsonl]`) |
  | TC-03 | the responder sends two of the three handshake cells | `:338:5` `assertion left == right failed: two-clients: failed: no handshake arrived` (left 1, right 0) |
  | TC-04 | the expected payload of message *i* is that of *i + 1* | `:415:5` `assertion left == right failed: two-clients: failed: messages lost, duplicated or altered` (left 1, right 0) |
  | TC-05, TC-06 | every client-to-relay unit one byte longer | `:639:13` `assertion left == right failed: link 0 c2r` (left `[10, 2857]`, right `[9, 2856]`) |
  | TC-09 | a key `id` in every unit line | `:719:13` `assertion left == right failed: unknown keys in {"t_ms":81014,"len":9,"dir":"c2r","link_slot":0,"id":1}` (left `["dir","id","len","link_slot","t_ms"]`) |
  | F-1 partial | the residual error dropped | `:764:31` `called Result::unwrap_err() on an Ok value: ()` |
  | F-1 observed | a write unit clipped at 4 352 | `:808:9` `assertion left == right failed` (left `[(4352, C2R), (4353, R2C), (7, R2C)]`, right `[(4353, C2R), (4353, R2C), (7, R2C)]`) |
  | X-08 | `required-features = ["kat"]` | `xtask/src/policy.rs:1044:9` `assertion left == right failed` (left `["two-clients has required-features [\"kat\"], not [\"harness\"]"]`, right `[]`) |

  (The lines quoted in the first version of this section matched no committed assertion; they came from runs against a stubbed `exec`
  and are withdrawn.)
- **Hygiene.** One number for the C2-1 `kat` step: 751 s (§10 item 3 now says so); `relay_bin()` note in §7. Groups TC-03 and TC-02 are
  one commit (`be2e21e`).

### C2-1c (WEISUNG M6-C2-3; four minors of the reviewer's verification of `ae79352`)

```
PHASE: C2-1c  BRANCH: m06-transport  HEAD: 3fb19db  (code; the report commit follows)  BASE: 6300b653d0f1f176b7a31470910d5214fa87b9cc
ROWS: implemented 8/30 · passing 8 · ⚙ open TC-07,TC-08   CI-LOCAL: ci-fast ok (kat 650 s) · ci-full n/a
```

Commit `3fb19db` `fix(two-clients): recorder residuals on drop, pool traffic traced, runtime counts (C2-1b minors)`; `ci-fast --strict` at it:
all steps PASS, `kat` 650 s (`target/tc/cifast-c21c.txt`).

- **F1-a.** `TracedStream` has a `Drop`: a stream dropped with a non-zero residual (c2r bytes written and not flushed, r2c bytes of a
  request not complete) is an error entry, unless the stream is lenient or the run is sealed (`Recorder::seal`, called when the run's
  loop ends, because the final shutdown drops streams on purpose). Every recorder error is also a message event
  `{"event":"trace_error","msg":<ordinal>,"t_ms":…}` in the JSONL (the keys stay `event`, `msg`, `t_ms`; TC-09 allows the word). Test
  `two_clients_trace_residual_on_drop_fails` (also: after `seal` a drop is not an error).
- **F1-b — chosen: route the pool through the run's recorder** (pool traffic is in the trace like any other link). The pool's control and
  fetch links have the same record and frame lengths, so TC-05's "after HS2 every unit is 4 352 B" holds (TC-05, TC-06 passed in
  `kat`). Two consequences, both in `assert_frames_after_hs2`: a link the run ended during its handshake shows only a prefix of the
  records (the check is a prefix check, then 4 352 B, and the run must show frames somewhere); the pool's streams are lenient on drop
  (the pool driver is shut down on purpose, and the abort drops the streams after the call returns).
- **F3-a.** The script's set-up links are `SetupLink`s that count `QUEUE_NEW` commands (`queue_new_commands`), and the step lines print
  `queue_new_ops_since_fill` (the pool runner's `QueueNew` operations in `material.done` after the pool was full); the test asserts both
  are 0 and the `.create_queue(` source grep is gone.
- **F5-a.** TC-02 now runs both parts with a script of 3 + 3 one-cell messages: in process, 6 `enqueue` and 6 `deliver` events within the 600 s;
  as a process (30 s real, too short for a delivery: links start up to 180 s in), a non-empty trace with 6 `enqueue` events.
- **Red before green** (committed tests at `3fb19db`; planted condition, source restored afterwards):

  | Test | Planted condition | `m6_two_clients.rs:line` — assertion as printed |
  |---|---|---|
  | `two_clients_trace_residual_on_drop_fails` | `Drop` reports nothing | `:836:31` `called Result::unwrap_err() on an Ok value: ()` |
  | `two_clients_scripted_invitation_handshake` | the script sends a `QUEUE_NEW` over its set-up link | `:373:5` `assertion left == right failed` — left has `queue_new_commands=1`, right `queue_new_commands=0` |
  | `two_clients_profiles_are_in_memory` | no `enqueue` events are recorded | `:267:5` `assertion left == right failed` (left 0, right 6) |

- **Decisions of the weisung recorded:** D-C2-1 branch (ii) accepted and the `tokio/test-util` question closed (§8); "xtask doc check" in
  the brief reads as `cargo nextest run -p xtask docs::` (to be noted in §9 at C2-5).

### Resume after the credit stop (WEISUNG M6-C2-3b)

Stock at the resume (`git status --short`, `git log --oneline ae79352..HEAD`, `git diff --stat`, `git stash list` empty): committed `3fb19db`
(C2-1c code) and `d3ef9d4` (C2-1c report); edited and uncommitted: `conversation.rs` (the `kat` accessor `message_key_digests_kat`),
`harness/mem.rs` (`MemRelay::serve`, `new_at`), `two_clients/run.rs` (World/Observer/`resume` hooks), `tests/harness/main.rs`, and the new
`m6_sim.rs`, `m6_sim_restart.rs`. Per item of WEISUNG M6-C2-3: four minors, committed (`3fb19db`); C2-1c block, committed (`d3ef9d4`);
C2-2: edited, not green (SIM-08/03/10 red on my own mistakes: a 10 000-line floor, and a re-creation window of 320 s; no wip commit
was made; both finished to green below, nothing was reverted). Not amended or rebased.

### C2-2 turmoil simulations (BRIEF M6-C2 §C2-2; WEISUNG M6-C2-3)

**Rig** (`tests/harness/m6_sim.rs`, test code only; turmoil stays a dev-dependency): host `relay` = the M5 relay's sans-IO `Connection`
driven by `MemRelay::serve` over simulated sockets (a restart of the host is a fresh store with the same keys); `TurmoilProvider` = a
simulated TCP connect to `relay`; hosts `a` (inviter) and `b` (invitee) run the engine of `two-clients` (pool, scripted handshake, constant-rate
links on the tokio driver) under turmoil's virtual clock; a `clock` client ends the simulation. **(E)** each client reports
`delivered N/N` and `exact=true` (the received ids are the script's, once, with the script's payload; order is reported separately as
`in_order`, because an evicted or lost message is re-sent after later ones). **(K)** SHA-256 of the message key of every cell each sender
sealed under, counted once its new state is durable (H-12 method: `Sealed::message_key_digest_kat`, collected in
`Conversation::message_key_digests_kat`, `secmp-client-core` feature `kat`; the accessor is in `scheduler/conversation.rs`, not in
`scheduler/core`), pairwise distinct, and at least one key per message. `Outcome::assert_e_and_k` asserts both in every row.

| Row | Test (`tests/harness/…`) | Wall | Mutants skip entry |
|---|---|---|---|
| SIM-08 | `m6_sim_restart::sim_replay_deterministic` | 20.5 s | yes (20 s) |
| SIM-03 | `m6_sim_restart::sim_relay_restart_recovery` | 10.4 s | yes (10 s) |
| SIM-10 | `m6_sim_restart::sim_balanced_relay_restart` | 12.4 s | yes (12 s) |
| SIM-06 | `m6_sim_latency::sim_latency_does_not_move_emission` | 19.8 s | yes (19 s) |
| SIM-01 | `m6_sim_faults::sim_loss_breaks_links_eventual_delivery` | 9.3 s | yes (9 s) |
| SIM-02 | `m6_sim_faults::sim_partition_heals` | 59.8 s | yes (60 s) |
| SIM-04 | `m6_sim_faults::sim_both_clients_restart` | 10.0 s | yes (10 s) |
| SIM-05 | `m6_sim_faults::sim_crash_between_persist_and_write` | 10.1 s | yes (10 s) |
| SIM-09 | `m6_sim_faults::sim_hello_flood_backoff_recovery` | 13.7 s | yes (14 s) |
| SIM-07 | not committed — **blocked**, below | — | — |

Nine rows run in 59.8 s wall as a set (nextest, parallel; the longest is SIM-02 at 59.8 s, far from the 900 s per row / 20 min set limits).
Commits: `b827d12` (rig, SIM-08, SIM-03, SIM-10 — one commit: the rig is dead code without them), `b11f2bd` (SIM-06 and engine hooks),
`43dac59` (SIM-01, 02, 04, 05, 09). `ci-fast --strict` at `43dac59`: all steps PASS, `kat` 796 s (`target/tc/cifast-c22.txt`).

How each row is read: SIM-08 compares the full JSON-lines traces (units and message events, > 1 000 lines per client) and reports of two
SIM-03 runs. SIM-03/10 assert the relay holds exactly the conversation's two queues with the `rid`s they had, each first re-created within
the window of the restart (reconnect `U[0,180 s]` + one period ≤ 80 s + `U[10 s, 300 s]` = 560 s; the first version of the window,
320 s, was my error — measured 348 s), and one handshake per client. SIM-06 compares per scheduled link the C2R frame times relative to
the link's first frame between latency 10…2 000 ms and 0 (equal over the common prefix of ≥ 100 frames; every gap is exactly 10 s; no
`InFlight`); the first frame itself moves with the handshake. SIM-01: from 15 min, fail rate 0.01 and repair rate 0.5; ≥ 10 teardowns, and
the next link connect follows each within 180 s (LR-02) / 3 600 s (LR-03, close before `RELAYINFO`). SIM-02: A ↔ relay partitioned
1 800…3 600 s; the ids reported evicted to B equal `[head at partition, head at heal)` of the relay's queue (A fetched nothing, so the
queue's head moved only by eviction; 128 kept). SIM-04: both hosts bounced at 1 h; each client's run resumes (no new invitation).
SIM-05: A is bounced half a period after its latest frame: at the crash it had sealed ≥ 1 cell the relay never stored (the prepared one);
at the end the surplus of sealed over stored is that number plus at most 2; no key reused. SIM-09: flood 8/s for 600 s from 30 min, a
90 s partition of both clients at the flood start forces every honest link to connect again; ≤ 40 attempts per client in the flood and
both scheduled links up by flood end + 3 660 s.

**Red before green** (planted conditions; committed tests at `43dac59`, text as nextest printed it):

| Row | Planted condition | `file:line` — assertion |
|---|---|---|
| SIM-08 | second run with another turmoil seed | `m6_sim_restart.rs:60:9` `assertion left == right failed: client 0: the traces of the two runs differ` |
| SIM-03, SIM-10 | re-creation window narrowed to 100 s | `m6_sim_restart.rs:98:9` `queue [d7, 94, …] re-created 348010 ms after the restart: outside the window …` (SIM-10: 348970 ms) |
| (K) in SIM-03 | the first digest dropped from the set | `m6_sim.rs:400:13` `assertion left == right failed: SIM-03: (K) inviter: a message key was used twice` |
| SIM-06 | latency up to 12 s (round trip above `P`) | `m6_sim_latency.rs:73:9` `assertion left == right failed: client 0: the number of scheduled links` |
| SIM-01 | bound set to 1 s | `m6_sim_faults.rs:71:17` `client 0: InFlight at 964950: the next connect 165475 ms later, bound 180000` |
| SIM-02 | predicted range one id too long | `m6_sim_faults.rs:147:5` `assertion left == right failed: the evicted ids reported to B are not the ids the queue predicts` |
| SIM-04 | client B not restarted | `m6_sim_faults.rs:177:9` `client 1 made a new invitation after the restart` |
| SIM-05 | accepted surplus moved to lost + 3…9 | `m6_sim_faults.rs:280:5` `sealed 1064, stored 1062, lost at the crash 1: surplus 2` |
| SIM-09 | attempts must be 0 | `m6_sim_faults.rs:337:9` `client 0: 7 connection attempts during the flood: no back-off` |

(The first lines of the SIM-03/10 and SIM-08 rows in the earlier run of this session came from older file states and are replaced by
these.) Mutants skip list: each slow test is on `MUTANT_HARNESS_SKIP_TESTS` with its time in the same commit as the test.

**Engine hooks added for the simulations** (testkit only; `two-clients` unchanged on the command line): `MemRelay::serve`/`new_at`;
`World::new` with an `Observer` (recorder, conversations, restart data, evicted ids, connects, scheduler events); `session`/`resume` public;
the duration of an observed run counts from the host's start; `Driver::with_connect_timeout` is reachable (`WorldConfig`).

**BLOCKED — SIM-07 `sim_slow_link_in_flight_teardown` (not committed; draft kept in `target/tc/sim_latency.full`).**
The teardown part works as dictated: with one-way latency 25 s and `P` = 10 s every scheduled link writes exactly its first two ticks
and is `TornDown(InFlight)` 30.0 s after `Up` (assertions passed), the next link is up within `U[0,180 s]` + the handshake. But **(E) cannot
hold**: after 7.6 h virtual `delivered side=inviter 0/3`. Mechanism: a response needs one round trip of 50 s, a link lives 30 s, so no
`FETCH` or `OK_SEND` answer is ever read; the sender never gets `OK_SEND`, the receiver never gets a cell, nothing is acknowledged.
That is a property of §10.3 (two requests in flight, the third tick tears the link down), not an implementation bug, so (E) as written
in the annex header contradicts SIM-07's own input. Two prerequisites of the row are also outside the defaults and were set per row:
the relay's `HELLO`→`HS1` timeout (30 s, OPEN-M5-02) is shorter than a handshake over 25 s one way (75 s), and the driver's connect timeout
(`CONNECT_TIMEOUT_MS` = 120 s) is shorter than TCP connect + handshake (150 s). **Question for the reviewer:** read (E) for SIM-07 as
"no message is delivered twice and none is altered; (K) holds" (the row's own expectation), or give the row another latency/period? I did
not weaken anything and continued with the rows that do not depend on it.

**Finding (spec §10.4, found by a first version of SIM-09 that restarted the relay; not a committed row):** a message that was
`Relayed` (stored by `OK_SEND`) at the moment the relay restarted is lost silently if the sender's links were down until the recipient had
re-created the queue: the sender sees no `ERR_NOQUEUE` (no `RouteDead`), its outbox keeps the message `Relayed` and nothing re-sends it
(invitee outbox after 4 h: 98 delivered, 2 relayed; the inviter received 99/100, message 29 missing; queue re-created 517 s after the
restart, the sender's links up again only after the flood). §10.4 says such messages "are lost and re-sent from the outbox if not yet
receipted", but only an `ERR_NOQUEUE` triggers it. Fix would be in the scheduler core/spec (e.g. re-send a relayed message that is not
receipted after a bound) — **not done, core is the reviewer's**; entered in §7 as an open risk. The committed SIM-09 breaks the links
with a partition instead of a restart.

### C2-2b (WEISUNG M6-C2-4): decisions and fix-ups of the verifier's findings on `3395334`

Commits: `7e8bc99` (items 6, 8), `5d26266` (items 3, 4: SIM-10, SIM-03), `d66808f` (item 1: SIM-07; item 7: SIM-06), `1290576` (item 7:
SIM-01, 02, 05, 09), this report. Decisions: **SIM-07 re-dictated** by the reviewer (no (E): RTT 50 s > `MAX_IN_FLIGHT · P` = 20 s, no
response is read before `TornDown(InFlight)`), the two per-row rig parameters are named in the test's doc comment and here; **§10.4
accepted as a protocol gap** (OPEN-M6-C2-1, §7, OQ-19). The `ci-fast --strict` output is at the end of this section.

- **SIM-07** (`m6_sim_latency::sim_slow_link_in_flight_teardown`, 11.8 s): every `Up` link is `TornDown(InFlight)` 30.0–30.25 s later and
  no other teardown; at most two C2R frames per scheduled link; `responses_read == 0` (R2C frames of 4 352 B after the first `Up`:
  0); reconnect per LR-02 (matched to distinct connects); (K); `exact`. **Rig parameters of this row only** (`Spec`, no default
  changed): relay `hello_timeout_ms` = 300 000 (default 30 000, OPEN-M5-02: the handshake over 25 s one way takes 75 s) and the drivers'
  connect timeout 600 000 ms (`CONNECT_TIMEOUT_MS` default 120 000: TCP connect 50 s + handshake 100 s).
- **SIM-10** (item 3): the field `present == 2` of the `FETCH_MULTI` answers is read inside the client's channel
  (`FetchMultiOutcome.errors` ← `Cellr.present`, `core/mod.rs:967–992`) and reaches neither the driver's host nor the cell source;
  exposing it needs a hook in the core or the driver, which is not done (core is the reviewer's). Asserted instead, what only that answer
  causes and what the spec ties to it: the conversation queues are absent from the relay 2 s after the restart; each recipient's only
  `QUEUE_NEW` after the restart is the re-creation (`Scheduler::queue_error(NoQueue)` is its only trigger); the client kept writing
  frames in the outage; after it the relay holds the pre-restart queues. Reviewer: accept this reading or add the hook.
- **SIM-03** (item 4): the restart waits for the first moment a *real* message sits in the relay's queue (a `Relayed` message whose last
  cell id is still stored; `real_cells_lost ≥ 1`); the re-creation delay is measured per recipient from the first tick after its links
  came up (`Up + P`, the `FETCH` that reads `ERR_NOQUEUE`) to the `QUEUE_NEW` control connection, and must fit `U[10 s, 300 s]` (±250 ms
  driver slack) for one of the client's two links — the events do not say which link fetches the queue; both senders wrote frames in the
  outage; one handshake per client; (E) including the lost messages.
- **SIM-06** (item 7): the full emission series are compared (identical offsets over the whole shorter series; the length difference is at
  most `⌈shift / P⌉` because the run is cut at one absolute time and latency moves the first frame); gaps = `P` in both runs.
- **SIM-01** (item 7): 2 h as written; the loss starts at 15 min (reason: the clients' set-up, the scripted handshake of D-C2-1, runs on
  single links without a retry); the reconnect check matches each teardown to a *distinct* later connect (a `LinkId` names one connection
  and the events do not say which link a connect renews, so a per-link comparison is not possible; the matching never charges one connect
  to two teardowns).
- **SIM-02** (item 7): the full reported set equals the full predicted set; the prediction is derived from the relay's own record of the
  queue B → A (a store raising `next_cell_id` by one and moving the head evicted the cells in between; an acknowledgement moves the head
  alone), not from B. (The first idea, "up to the first acknowledgement", fails because of OPEN-M6-C2-2: the backlog never drains.)
- **SIM-05** (item 7): direct assertion — B's durable ratchet state holds exactly one skipped message key (the position A persisted and
  never sent) and no other; plus the (K) and surplus checks.
- **SIM-09** (item 7): witness that the relay refused honest `HELLO`s (`TornDown(ClosedBeforeRelayInfo)` ≥ 1 per client in the flood);
  both scheduled links are up at flood end + 3 660 s (the set of live link ids is 2); `link_rate: None` has its reason in the code (the
  `HELLO` bucket is what the row tests; the per-link frame rate is off in every simulation of the harness).
- **Item 6**: `Recorder::check()` runs in simulations; items 8: pool streams are strict; all rows pass (§7).
- **Item 5 (TC-02 deliver in the subprocess): STOP, not done.** The subprocess run (`--transport mem`, real time) delivers its first
  message 145.6 s after the start (measured: `enqueue` at 15.4 s, first `deliver` at 145 580 ms; the whole script of 3 + 3 messages by
  146–195 s): the pool fill (control delays 2…5 s, one-shot links) takes ≈ 15 s, the links start at the phases `U[0, 180 s]` of the
  scheduler (deterministic with the `mem` randomness) and the first tick is `P` after `Up`. That is longer than the 90 s limit of the
  weisung, so the test stays as it is (6 `enqueue` events). Option for the reviewer: a subprocess run of 170 s real (≈ 1 test of that
  length, on the `MUTANT_HARNESS_SKIP_TESTS` list) — not done without your word.
- **Red before green** (planted conditions; committed tests at `1290576`, text as nextest printed it):

  | Row | Planted condition | `file:line` — assertion |
  |---|---|---|
  | SIM-07 | one-way latency 5 s (RTT 10 s < 20 s) | `m6_sim_latency.rs:165:9` `client 0: 0 teardowns in 8 h` |
  | SIM-06 | latency up to 12 s | `m6_sim_latency.rs:76:9` `assertion left == right failed: client 0: the number of scheduled links` |
  | SIM-03 | delay window narrowed to 100 s | `m6_sim_restart.rs:208:9` `client 0: re-created at 3947874 ms, links up at [3747980, 3765570] + P: no delay in U[10 s, 300 s]` |
  | SIM-03 | real cells required ≥ 1000 | `m6_sim_restart.rs:154:5` `no real cell was in the store at the restart` |
  | SIM-10 | outage writes required > 100 000 | `m6_sim_restart.rs:232:9` `client 0 wrote no frame during the outage` |
  | SIM-10 | queues required present after the restart | `m6_sim_restart.rs:158:5` `a conversation queue existed 2 s after the restart` |
  | (K) in SIM-03 | the first digest dropped from the set | `m6_sim.rs:401:13` `assertion left == right failed: SIM-03: (K) inviter: a message key was used twice` |
  | SIM-01 | bound set to 1 s | `m6_sim_faults.rs:60:17` `client 0: InFlight at 964950: the reconnect 165475 ms later, bound 1000` |
  | SIM-02 | the first predicted id removed | `m6_sim_faults.rs:162:5` `assertion left == right failed: the evicted ids reported to B are not the ids the queue predicts` |
  | SIM-05 | one skipped position more expected | `m6_sim_faults.rs:311:5` `assertion left == right failed: B skipped positions [4], A lost 1 at the crash` |
  | SIM-09 | 1 000 refusals required | `m6_sim_faults.rs:415:9` `client 0: the relay refused none of its HELLOs during the flood` |

  (SIM-08 and SIM-04 are unchanged from the table of C2-2.) The earlier SIM-01 line "bound 180000" was a quote of a plant that did not
  change the bound; replaced by the row above.

`ci-fast --strict` at the C2-2b head: all steps PASS (fmt, clippy, policy, deny, vet, audit, cooldown, nextest, doctest, hello), `kat` 716 s
(`target/tc/cifast-c22b.txt`).
