# M6-C1 C-2 proof repeat @ ee3c66f

## Tests (red before green)

| Test | Red on the unchanged code | Green |
|---|---|---|
| C2-01 `frame_written_on_an_empty_ledger_is_counted` | `m6_sched_io.rs:1310` `assertion left == right failed, left: 0 right: 1` (counter present, never incremented) | yes |
| C2-02 `frame_written_for_a_closed_link_is_not_counted` | passes on the stub (a closed link was already ignored); `unmatched_written` did not exist at the pin, so the pin does not compile it | yes |
| C2-03 `driver_reports_no_unmatched_written` | `unmatched_written` did not exist at the pin (compile error); debug assertions on (nextest dev profile), no panic | yes |
| C2-04 `unwritten_ledger_is_bounded_without_completions` | `m6_sched_io.rs:1388` `the fifth tick tears the link down: 200 entries at most`, `left: None right: Some(4)` | yes |
| C2-05 `unwritten_bound_is_not_reached_with_completions` | passes before and after (control) | yes |
| C2-07 `unwritten_bound_teardown_is_activity_independent` | `m6_sched_io.rs:1439` `the ledger bound tore the link down twice at least: links [0]` | yes |

C2-06: `env SECMP_AI_TRACES=64 cargo nextest run -p secmp-testkit --features harness -E 'binary(=harness)'`:
`Summary [1493.754s] 196 tests run: 196 passed (17 slow), 0 skipped` (190 + C2-01…C2-05, C2-07; ai01…ai07 included; the AI
tests assert `max |Δt| = 0`).

## 8 hand mutants of M6-CI-11 (nextest filter `driver_balanced|balanced_round_robin|balanced_rr|driver_rr|driver_stashed|reserv|ai07|frame_written|unwritten`)

Run on 79409c5 (extraction, `VecDeque`) for all eight; the four that live in the extracted code (1, 4, 5, 6) again on ee3c66f
(`Vec`). 8/8 caught each time.

| # | Mutant | Caught by |
|---|---|---|
| 1 | `reserved_rr` ignores the ledger (prepare against `link.rr`) | `balanced_rr_reserves_the_successor_of_an_unwritten_send`, `driver_rr_reservation_does_not_depend_on_worker_timing` |
| 2 | `!send_missing` → `true` | `driver_rr_does_not_advance_for_a_send_never_written`, `driver_balanced_first_tick_sends_and_fetches_in_order`, `driver_rr_reservation_…` |
| 3 | `checked_add` → `checked_sub` (`prepare_link`) | 12 of 13 |
| 4 | committed `n` → `0` | `frame_written_on_an_empty_ledger_is_counted`, `balanced_round_robin_due_rule`, `driver_rr_does_not_advance_…` |
| 5 | commit in `complete_oldest` dropped | the same three |
| 6 | commit at the tick again | `driver_rr_does_not_advance_for_a_send_never_written` |
| 7 | stash drain after the flush wait removed | `driver_stashed_connect_is_anchored_at_its_occurrence`, `ai07_fault_paired_tokio` |
| 8 | occurrence timestamp → now | `driver_stashed_connect_is_anchored_at_its_occurrence` |
| extra | `ledger_admits` `<=` → `<` (item 11) | `unwritten_ledger_is_bounded_without_completions` |

## Item 10b: why the ledger could not be reached through `Scheduler`

An up link holds a `secmp_transport::Channel`. Probe harness (not committed) `Channel::from_link_kat(kani::any())` in
`secmp-client-core` under `cargo kani`:
`error[E0277]: the trait bound secmp_proto::link::Link: kani::Arbitrary is not satisfied` and
`error[E0599]: no associated function or constant named from_link_kat found for struct secmp_transport::Channel`
(feature `kat` is off; `Channel::new` is `pub(crate)`). The ledger and reservation logic was therefore extracted into
`core/pure.rs` (`reserved_rr`, `hand_out`, `complete_oldest`, `ledger_admits`, `unwritten_max`), behaviour-preserving, with the
unchanged regression set green. The ledger became a `Vec`: with a `VecDeque`, K-C1 needed 35.6 GB and failed an unwinding
assertion in `clone`.

## K-C harnesses (max RSS, run alone, `RUSAGE_CHILDREN` method of kani-rss-d1bcfdc.txt)

| Harness | max RSS | wall |
|---|---|---|
| K-C1 `kani_reservation_is_schedule_only` | 2525 MB | 25 s |
| K-C2 `kani_frame_written_commits_fifo` | 2730 MB | 35 s |
| K-C3 `kani_teardown_keeps_the_committed_rr` | 2198 MB | 19 s |
| K-C4 `kani_tick_hands_out_without_commit` | 1272 MB | 11 s |
| K-C5 `kani_deadline_arithmetic_checked` | 212 MB | 687 s |
| K-C6 `kani_unwritten_bound` | 573 MB | 7 s |

`cargo kani -p secmp-client-core` (`kani-m6c1-ee3c66f.txt`): `Complete - 13 successfully verified harnesses, 0 failures, 13
total.`, 1173 s, peak 2994 MB.

Limits of the harnesses (report §7): K-C4 does not cover `last_send` (set inline in `World::tick`); K-C5's `FETCH`-lead and
flush-bound expressions are the same saturating expressions written in the harness, not calls (they live inline in
`prepare_link` and `Driver::flush_wait`, outside the approved extraction); K-C6 fixes `max_in_flight` = 2 (a symbolic value cost
14.8 GB); K-C3 models the teardown as dropping the ledger (`tear` replaces `link.state`; `rr` is a field of the link).
