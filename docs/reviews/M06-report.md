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
- `crates/secmp-testkit`: `harness::driver` (`VirtualDriver`, `SimClient`, `Gate`, traces), tests `m6_*` under `tests/harness/`.
- `crates/secmp-relay`: `Limits::link_age_ms` (default `LINK_AGE_MAX_MS`, behaviour unchanged) — see §5.
- `crates/secmp-proto`: `RelayKeys::relay_info` signs once, without a placeholder signature (G-09, R-144), counting accessor
  `SIGN_CALLS_KAT`.
- `xtask`: G-03, G-04, G-05, G-06, G-08, G-10, X-05 (new tests and gate wiring), `KAT_PACKAGES` += `secmp-client-core`,
  `PROPERTY_PACKAGES` += `secmp-testkit`, `KANI_*`, `FUZZ_*`, `LINT_ALLOWANCES` += `secmp-client-core/src/clock.rs`.
- `fuzz/`: targets `client_pipeline_responses` (FZ-01), `scheduler_event_sequence` (FZ-04) with committed seeds.
- Root `Cargo.toml`: `[workspace.dependencies]` += `secmp-relay`, `secmp-transport`, `secmp-client-core` (F-10);
  `[profile.dev.package."*"]`/`secmp-crypto`/`secmp-proto` `opt-level = 3` (dev/test only; one virtual hour fell from 21 s to 1.3 s).

## 3. Evidence per acceptance criterion (Phase A rows)

Commands, all at code head `03cc660` (WEISUNG M6-1): `cargo xtask ci-fast --strict` (`M06-evidence/ci-fast-m6a-03cc660.txt`),
`cargo xtask step kani` (`M06-evidence/kani-m6a-03cc660.txt`, with the K-02 negative control), `cargo xtask ci-full --delegated
windows-native --delegated windows-cross --delegated mutants --delegated ct --delegated proverif-link --models tr` as the
`linux-full` job (`M06-evidence/ci-full-m6a-03cc660.txt`). The M6 rows are in the `nextest`/`kat` steps of those runs.

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
| AI-01…AI-06, AI-08, AI-09 | `m6_activity.rs` | pass; max \|Δt\| C2R = R2C = **0 ms** in AI-01/02/03 (`AI-0x.txt`) over 64 traces × 6 h each |
| MR-01 | `m6_measure.rs::bandwidth_model_matches_capture` | pass; model = capture exactly per connection; Strict 3 045.9 B/s while up (spec 3 046.4), Balanced 4 786.3 (4 787.2), Low-bw 1 594.7 (1 595.7) (`MR-01.txt`) |
| MR-02 | `m6_measure.rs::drain_after_offline_virtual` | pass; Strict 232 / 8 512 evicted, drained in 42 recv ticks (≤ 45); Balanced 4×10 s 126 slots (≤ 130); Low-bw 5×40 s 149 slots (≤ 153) (`MR-02.txt`) |
| G-01 | `m6_followups.rs::ok_send_with_implausible_evicted_id_is_rejected` | pass |
| G-02 | `secmp-transport` `caps::tests::caps_have_no_partial_eq` + two `compile_fail,E0369` doctests | pass |
| G-03, G-04, G-05, G-06, G-08, G-10 | xtask tests `ct_guard_sites_use_ct_eq`, `normal_dependencies_match_adr_allowlist`, `fuzz_executor_depth`, `testkit_manifest_and_workflow_texts`, `mutants_report_has_unviable_breakdown`, `no_ignore_without_adr` | pass (`cargo test -p xtask`: 173 passed) |
| G-07 | `secmp-relay` `vectors::v16_checks_unpad`; `m6_followups.rs::h01_identical_queue_new_answers_ok` | pass |
| G-09 | `secmp-proto` `tests/link/vectors.rs::relay_info_without_placeholder_signature` | pass; V-01 bytes unchanged; the counter is `secmp_crypto::SIGN_CALLS_KAT`, incremented inside `Ed25519SigningKey::sign` (VD-2); hand mutation (a placeholder `sign` call re-added): FAIL `sign_calls = 1 per RELAYINFO`, left 2 right 1 (`vd2-g09-hand-mutation.txt`), removed again |
| G-11 | `m6_followups.rs::harness_cap_setters_take_effect`; `cargo mutants --test-tool nextest -p secmp-testkit --features harness -f '**/convo.rs'` | pass; 30 mutants: 25 caught, 0 missed, 5 unviable (`G-11-convo-mutants.txt`) |
| K-01…K-07 | `crates/secmp-client-core/src/kani_proofs.rs` | 7/7 verified (`kani-m6a-03cc660.txt`); negative control K-02 without the in-flight check: `VERIFICATION:- FAILED` (same file, after the marker line) |
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
| `cargo xtask ci-fast --strict` (Linux) | PASS at 03cc660 (`ci-fast-m6a-03cc660.txt`) |
| `cargo xtask ci-full` (as `linux-full`, with the CI delegations) | `ci-full: PASS` at 03cc660 (`ci-full-m6a-03cc660.txt`): fmt, clippy, policy, deny, vet, audit, cooldown, nextest, doctest, kat (239 s), perf, fuzz (3 785 s, 31 targets), coverage, miri, kani (3 071 s, 40/40), proverif, sbom, systemd PASS; ct, mutants, proverif-link, windows-native, windows-cross delegated to the PR run. (An earlier run at `bb9e45d` had failed `fmt` and the Kani cover pins; both were fixed before this one.) |
| Windows VM tests | not applicable in Phase A (no Windows-specific code); `windows-native`/`xwin-cross` run in the PR |
| KATs / differential | PASS (`kat` step, 5 packages incl. `secmp-client-core`) |
| Fuzz smoke | 31 targets × 120 s, PASS; committed seeds of the two new targets: `client_pipeline_responses` 6, `scheduler_event_sequence` 3 (counted by `git diff --name-status 6300b65..HEAD -- fuzz/corpus`). An earlier commit had carried 94 and 620 files: my manual fuzz runs had written libFuzzer's new inputs into the tracked corpus directory; they were removed again and the nine hand-made seeds restored |
| Mutation (`cargo mutants`) | delegated to the `mutants` CI job on the existing scope (crypto, proto, relay); `secmp-client-core`/`secmp-transport` enter the scope in Phase B (ADR-047 Am. 4); the one-off G-11 run above |
| Coverage | secmp-client-core 89.8 %, secmp-transport 87.3 %, secmp-testkit 97.7 %, secmp-crypto 99.4 %, secmp-proto 97.7 %, secmp-relay 98.2 % |
| ProVerif / Kani / Miri | ProVerif PASS (`--models tr`; `proverif-link` delegated); Kani: 40/40 harnesses (client-core 7/7, 0 failures); Miri PASS |
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
11. **mutants: `drain_finished` timeout → caught durch `Fed`-Listener (`FED_DRAIN_CALLS_MAX`), Schranke 100 Accepts (≤ 0,5 s) aus `drain_secs` = 1 bei 100 ms je Uhrablesung (≈ 10 Accepts, Faktor 10)** (WEISUNG M6-5, `M06-evidence/mutants-drain-71f0d93.txt`): Phase A hat `drain_finished` und seine Aufrufer nicht geändert; der Produktcode ist beschränkt (`serve` endet nach `drain_secs`).

## 6. Dependencies added or bumped

None (workspace path crates only: `secmp-client-core` → `secmp-transport`; `secmp-testkit` → `secmp-client-core`).

## 7. Open risks and known limitations

- AI-01…AI-03 take ≈ 1–1.5 min each on a 32-core host (64 traces × 6 h on threads); on a 4-core runner expect several minutes.
- The tick path is "equal" in the virtual driver; the real-time path (tokio driver, Tor) is Phase B/C (AI-07).
- `link_age_ms`/`link_idle` defaults are still the M5 placeholders until G-12.

## 8. Blocked / questions for the reviewer or owner

None for Phase A. Phase B waits for the owner's ADR-051 Part 2 approval and `cargo vet` records.

## 9. Checklist before requesting review

- [x] All Phase A rows evidenced above
- [x] `cargo xtask ci-fast --strict` green; `ci-full` green (§4), at `03cc660`
- [x] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [x] Vectors untouched
- [ ] PR run on `linux-fast`, `windows-native`, `xwin-cross`, `linux-full` (after the push by the reviewer)
- [x] Threat model and spec untouched
