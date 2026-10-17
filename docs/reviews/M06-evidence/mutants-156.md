# Evidence — PR run #156, mutants-shard survivors in Phase-B code (WEISUNG M6-CI-9), 2026-10-17

Method: each survivor was reproduced with the gate's second-run command restricted by `--file`/`--re` (`cargo mutants
--features harness --package secmp-client-core --package secmp-transport --test-package secmp-client-core
--test-package secmp-transport --test-package secmp-testkit --test-tool nextest --timeout 300 …` with every
`MUTANT_SKIP_TESTS` / `MUTANT_HARNESS_SKIP_TESTS` name as `--skip`, i.e. the CI selection, long AI tests left out) and
killed by a test written against it; relay mutants with the first-run command (`--features kat`, `cargo test`).

Final run on the tree of this commit: `205 mutants tested in 18m: 7 missed, 181 caught, 17 unviable` (all of the below in
`secmp-client-core` / `secmp-transport`); the 7 missed are exactly the documented rows (`docs/mutants-accepted.md`):
`core/mod.rs:1695:21`, `1695:44`, `run.rs:843:34`, `run.rs:1027:54`, `tls.rs:366:13`, `tor/mod.rs:53:26`, `:60:23`.
Relay (`tls.rs`, `conn.rs`, `server.rs`, first-run command): `25 mutants tested in 3m: 1 missed, 23 caught, 1 unviable`
(the missed one, `Deadlined::flush`, documented).

## The two priority analyses

**`core/mod.rs:600:27`, `&&` → `||` in `World::prepare_link`** (`if needs_send && up.send_part.is_none() { prepare_send }`).
With `||` every work pass that finds the link's SEND part already prepared prepares it again: the cell source is asked a
second time for the same tick (another `prepare_cell`, another ratchet step), the sealed part is replaced and the link
counter skips the first part's number — the relay would refuse the frame. For a receive link `prepare_send` returns at once,
so that direction of the mutation changes nothing. No test saw it: the passes between two ticks exist only for links with a
`FETCH` lead (Balanced / receive links), the existing tests assert frames and teardowns of whole runs, none counted the
calls to the cell source per tick, and the AI tests that would see a counter gap are skipped by the gate. Killed by
`m6_sched_io::work_pass_does_not_prepare_a_prepared_send_twice` (a work pass in the middle of the interval asks the source
for nothing). Hand-applied mutant: the test fails; in the gate run the mutant was `caught`.

**`run.rs:836:9`, `flush_wait` → `Ok(())`** (no flush wait). The existing `driver_pending_flush_same_tick`,
`driver_partial_write_is_completed_before_work` (helper `wrote_before_work`) pass without any flush wait: the next pass starts
exactly when the held write's `Written` event arrives, so some later `Work(start, end)` has `start <= done <= end`. They prove
only that some work pass starts at or after the completion, not that the pass that handed the write out waits for it.
`m6_driver_io::flush_wait_ends_at_the_completion_of_the_pass_writes` asserts on the step log that the `Flushed` of that pass
is the completion (t + 100 ms), not the pass's own time and not 250 ms, and that no `Work` starts inside the write;
`flush_wait_does_not_wait_for_an_earlier_pass_write` asserts that the pass at the FETCH lead (no new write) is flushed at
its own time while an older 9.5 s write is still pending, and that the pass that handed it out waited exactly
`FLUSH_WAIT_MS`. Together they kill `Ok(())`, `843:38 && → ||`, `843:34 > → ==/<`, `843:51 == → !=` and `846:21 == → !=`;
`843:34 > → >=` is equivalent (documented).

## Table (shard 2, job 117246088119; first-run relay survivors of shards 1, 2, 4, 6, 7)

| Mutant | Test | Result |
|---|---|---|
| `control.rs:92` `is_empty -> false` | `m6_mut::control_ops_is_empty_follows_the_queue` | caught |
| `control.rs:209:63` `== → !=` in `take_due` | `m6_mut::take_due_records_the_start_under_the_operations_correlation` | caught |
| `core/mod.rs:234` `release_discard -> ()` (Deferred) | `m6_sched_io::balanced_rr_does_not_advance_on_teardown_before_tick` (the discard of the lost tick's cell) | caught |
| `core/mod.rs:217` `release_discard -> ()` (direct `Release for S`, same mutation family) | `m6_sched_io::remove_queue_refuses_unknown_and_ends_the_relay_link_with_its_last_queue` | caught |
| `core/mod.rs:380` `period_of -> Some(1)` (TIMEOUT: other tests loop at 1 ms) | `m6_sched_io::link_period_is_the_queues_or_the_modes_slot` | caught (with Amendment 6) |
| `core/mod.rs:600:27` `&& → \|\|` in `prepare_link` (TIMEOUT in the 300 s run, see the analysis) | `m6_sched_io::work_pass_does_not_prepare_a_prepared_send_twice` | caught (with Amendment 6) |
| `core/mod.rs:971:35` `== → !=` in `outcome` (per-queue FETCH_MULTI error) | `m6_mut::fetch_multi_error_is_attributed_to_its_own_queue` | caught |
| `core/mod.rs:960:52` / `952` `== → !=` in `outcome` (cells of a FETCH_MULTI entry) | `m6_mut::fetch_multi_cells_go_to_their_own_queue` | caught |
| `core/mod.rs:1302:58`, `1303:53`, `1312:52`, `1314:57`, `1315:64` in `remove_queue` | `m6_sched_io::remove_queue_refuses_unknown_and_ends_the_relay_link_with_its_last_queue`, `m6_mut::remove_queue_ends_exactly_the_links_of_the_queue` | caught |
| `core/mod.rs:1611` `control_failed -> Ok(())` (TIMEOUT 900 s) | `m6_mut::control_failed_makes_the_operation_due_again` (one call, one poll) | caught |
| `core/mod.rs:1695:44` (and `:21`) in `work_pass` | none possible: the branch is unreachable (see `docs/mutants-accepted.md`) | documented |
| `conversation.rs:345` `take_seq -> 1` (and `-> 0`) | `m6_sched_io::content_seq_counts_up` | caught |
| `conversation.rs:719` `send_failed -> ()` | `m6_sched_io::send_failed_requeues_the_message` | caught |
| `run.rs:836` `flush_wait -> Ok(())` and the `843`/`846` mutants | `m6_driver_io::flush_wait_ends_at_the_completion_of_the_pass_writes`, `flush_wait_does_not_wait_for_an_earlier_pass_write` | caught; `843:34 > → >=` documented |
| `run.rs:1027:54` `> → <` in `apply` (stalled-write branch) | `m6_driver_io::driver_closes_a_link_whose_write_is_pending_at_its_next_tick` (periods 5 s, shadowed by `close_stalled` with the shipped ≥ 10 s) | caught; `> → >=` documented |
| `run.rs:1263` `stop_tasks -> ()` | `m6_driver_io::driver_shutdown_aborts_pending_control_operations` | caught |
| `timing.rs:47` `sample_with -> None` (TIMEOUT) | `m6_mut::sample_with_accepts_below_and_rejects_at_the_ceiling` | caught (with Amendment 6) |
| `channel.rs:528:48` `&& → \|\|` in `check_fetch` (and `:520`, `:528:20`) | `channel::tests::fetch_batch_has_cells_before_dummies_in_ascending_order`, `fetch_error_frame_is_only_the_first` | caught |
| `ops.rs:188:81` `&& → \|\|` in `Judge::push` (QUEUE_NEW ids) | `ops::tests::queue_new_needs_both_derived_ids` | caught |
| `ops.rs:208:47`, `222:47` match guards `→ true/false` | `ops::tests::fetch_judges_a_first_frame_err` | caught |
| `ops.rs:268:33` `\|\| → &&` in `push_linkr`; `:293`, `:304` in `check_fetch`; `check_fetch_multi` | `ops::tests::link_get_refuses_the_impossible_present_and_consumed`, `check_fetch_judges_errors_and_ascending_cells`, `check_fetch_multi_judges_the_order_and_the_ids`; `channel::tests::fetch_multi_judges_the_order_and_the_ids` | caught |
| `tls.rs:366:13` `\|\| → &&` in `TlsProvider::connect` | none possible (rustls refuses first) | documented |
| `tor/mod.rs:53:26`, `:60:23` in `base32` | none possible (equivalent) | documented |
| `driver/session.rs:209` `is_closed -> true` / `-> false` | `m6_mut::async_link_is_open_after_connect_and_ping`, `async_link_reports_closed_when_the_stream_ends` | caught |
| `server.rs:328:22` `\|\| → &&` in `handle` (relay; TIMEOUT: the trickled-ClientHello test joined a thread that never ended) | `direct_tls::a_trickled_client_hello_ends_at_the_hello_timeout` (bounded) and `server_loop::handle_stops_on_teardown_write_failure_and_refusal` | caught |
| `server.rs:322:32`, `tls.rs:176` (`Deadlined::disarm`), `conn.rs:121`/`138` (`timed_out`, `on_tick`) (relay, shards 1, 2, 4, 6, 7 first run) | the same bounded `direct_tls` tests (they had hung or not been reached) | caught in `out-relay2` |
| `tls.rs:198` `Deadlined::flush -> Ok(())` (relay) | none possible (rustls never calls it) | documented |

## Not handled here: survivors of the other shards (second run), by function

The shard logs 0, 1, 3, 6, 7 finished after the WEISUNG was written and list about 120 more undocumented survivors in
`secmp-client-core` and `secmp-transport` (shard 4's log blob returned 404). Under Amendment 6 a part of them
(the TIMEOUTs of looping mutants: `World::tick`, `Scheduler::find`, `accept_ceiling`, `sample_round`, …) should become
`caught` without a new test; the rest are listed here by function for a follow-up WEISUNG:
`control.rs` `kind_of`, `schedule` (138), `done`, `len`, `failed` (235), `is_empty -> true`; `clock.rs` `SystemClock::mono_ms`,
`ManualClock::set_ms`; `core/mod.rs` `release_failed` (221, 238), `release_discard` (217), `tick` (512, 515), `prepare_fetch`
(731), `set_queue_period` (1367), `queue_error` arms (892, 895), `begin_work` (822), `World::release` (401), `route_dead`
(1180), `reason_of` (1017), `owner_status` (1635), `on_frame` (1934), `find` (1796, 1797), `sync_links` (1408), `link_up`
(1813), `links` (1140), `next_deadline` (1665), `work_pass` (1716), `control_done` (1593), `change_mode` (1458),
`effective_mode` (342); `conversation.rs` `set_send_queue`, `set_send_receipts`, `set_recv_queue`, `bind`, `has_pending_real`,
`ts`, `durable`, `restore`, `on_failed`, `discard`, `pending_real`, `by_send`, `prepare_cell`; `pool.rs` `is_spare`, `missing`;
`outbox.rs` `MemPersist::set_durable`; `timing.rs` `accept_ceiling`, `sample_round`, `Display for Unavailable`; `run.rs`
`Deferred::{discard, send_failed, queue_lost}`, `close_link`, `start_io` (1087), `submit`, `has_link_io`, `release_unused`;
`transport` `channel.rs` `fits`, `prepare` (308, 329), `synced`, `single` (486, 487), `finish` (459), `check_fetch_multi`
(566, 570, 599); `caps.rs:20`; `ops.rs` `fetch_multi_len_ok`; `session.rs` `ensure_open`, `read_exact` (57); `tls.rs`
`is_tls13_hybrid_only` (86, 87); `driver/session.rs` `write_all`, `send`; `driver/relay_queue.rs` `ping`, `is_closed`.
