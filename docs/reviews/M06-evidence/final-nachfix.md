# Evidence — Astra final pass, FIN-1/-2/-3 (WEISUNG M6-CI-10), 2026-10-17

## FIN-3 — dotted / inline exemptions bypass the standalone vet classifier

- Test: `xtask policy::tests::vet_closure_dotted_and_inline_exemptions_are_rejected` — with the real closure member
  `subtle@2.6.1` planted in the real `supply-chain/config.toml`: root dotted assignment, spaced dotted, quoted and
  single-quoted key, inline root table (`exemptions = { subtle = [...] }`), a dotted key inside another table, an indented
  key; positive controls: the real config unchanged, and a comment that mentions `exemptions`.
- Red: before the fix the test failed on the first planted form (no finding; the standalone step reported
  `0 exempted`).
- Fix: `vet_closure_findings` rejects any key line that assigns to `exemptions` (`is_exemptions_key_line`) with `vet config
  uses a non-canonical exemptions form (dotted or inline); only [[exemptions.<name>]] headers are accepted`.
- The structural cross-check "number of strict headers equals the number of `exemptions` keys" was not added: every
  `exemptions` key form is now a finding by itself, and header forms with a quote or escape were already findings (EXTB-5,
  EXT2B-2).
- Containment (reviewer's note, not tested here): the combined gate runs `cargo vet --locked` first, which rejects the
  non-canonical store formatting, so only the standalone policy step was bypassable.
- Green: 220 xtask tests.

## FIN-1 — stashed connection events turn worker cost into relay-visible timing

- Test: `m6_driver_io::driver_stashed_connect_is_anchored_at_its_occurrence` (tokio driver, paused clock, in-memory relay;
  Strict, two contacts, four links, no phase, costs real 20 ms / dummy 1 ms / receive 5 ms; connection 0 stalls on its
  first frame for 5 s, connection 1 completes at 10 100 ms (inside the flush wait of the pass at 10 000), connection 2 is
  healthy, connection 3 never completes), idle against active, for the completing and for the failing connection 1.
- Red at the pin (idle vs active relay-visible `(time, slot, size)`): the late link's frames `(20251, 1, 4352)` idle against
  `(20270, 1, 4352)` active — the 19-ms shift of the Codex probe — on every later frame (`30251`/`30270`, …).
- Fix (`scheduler/run.rs`): the stash holds `(arrival time, event)`; `flush_wait` records the time when it stashes; the stash
  is drained right after the bounded flush, before `work` is called and before any job is dispatched or awaited
  (`drain_stash`); every stashed event is handled at its own arrival time. Every `sched.*(…, now, …)` call fed from the stash
  goes through `on_event(.., at)`: `link_up`, `connect_failed`, `on_closed`, `on_frame`, `control_failed`, `owner_status`,
  `pool_queue_ready`, the job result.
- Green: idle equals active for all variants, and the late link ticks at its occurrence anchor: `(20100, 1, 4352)` is in the
  idle trace (the pin had 20251).
- Why `m6_tokio_ai` could not see it: AI-01…AI-06 run healthy providers (every connect answers at once, every write
  completes in the pass) and `assert_clean` rejects any teardown but a lifetime's end, so no pass has a stalled writer and
  nothing arrives during a flush wait that is not a `Written` event. The fault-paired scenario is now a permanent member
  of the family: `m6_tokio_ai::ai07_fault_paired_tokio` (4 traces, `SECMP_AI_TRACES` overrides; in
  `MUTANT_HARNESS_SKIP_TESTS` and `docs/mutants-accepted.md` §Skipped like the other tokio repeats; the fast
  `driver_stashed_connect_is_anchored_at_its_occurrence` is what the mutation run executes).
- Not reconstructed: the Low-bw second-slot and the Balanced variants of the probe (the probe sources were not available);
  they exercise the same code path — every stashed event is anchored at its arrival — but are not separate tests.

## FIN-2 — A′ commits at the output enqueue, not at the write boundary

- Test: `m6_driver_io::driver_rr_does_not_advance_for_a_send_never_written` — Balanced, three send queues at 10 s, the first
  connection's first frame held at zero bytes (600 s), the driver closes the link at the next tick; the first relay-visible
  SEND of the replacement link equals the first SEND of an unfaulted run; and the normal path: the unfaulted run's first six
  SENDs are three distinct queues, each in turn, then again (the rotation advances exactly once per written SEND).
- Red at the pin: `the rotation moved past a SEND that was never written` — left (the stalled run's first SEND rid)
  `[163, 158, 102, …]`, right (the unfaulted run's) `[239, 176, 167, …]`.
- Fix: `Scheduler::frame_written(link)` (see the diff in the report); `tick` pushes the SEND's `next_rr` on a per-link FIFO
  (`Up::unwritten`) with every frame handed out and commits nothing; `last_send` stays at the tick. The driver reports a
  completed full-frame write from `on_written(.., ok = true)`; the virtual driver after its synchronous write; the scripted
  `Rig` after `write_all`. A link torn down before the completion drops the FIFO with its `Up`: the rotation is unchanged,
  the obtained cell returns through the existing `discard` / `send_failed` path (unchanged).
- Existing tests green: `balanced_rr_does_not_advance_on_teardown_before_tick`, `balanced_round_robin_due_rule`,
  `driver_balanced_first_tick_sends_and_fetches_in_order`.

## Proof repetition (after FIN-1 and FIN-2, at `1eee4f9` + the test pin)

- `env SECMP_AI_TRACES=64 cargo nextest run -p secmp-testkit --features harness -E 'binary(=harness)'`:
  `Summary [1477.365s] 188 tests run: 188 passed (17 slow), 0 skipped` — including the six tokio AI repeats at 64 traces with
  the extended oracle and `ai07_fault_paired_tokio`.
- Mutants (hand-applied in a scratch worktree, tests `driver_balanced|balanced_round_robin|balanced_rr|driver_rr_does|
  driver_stashed|ai07`): 1. `!send_missing` → `true`: `driver_balanced_first_tick_sends_and_fetches_in_order` and
  `driver_rr_does_not_advance_…` FAIL; 2. `checked_add` → `checked_sub`: `balanced_round_robin_due_rule` and
  `driver_rr_does_not_advance_…` FAIL; 3. the committed position `n` → `0` in `frame_written`: both FAIL; 4. (a) the commit in
  `frame_written` dropped: both FAIL; 5. FIN-2 revert (commit at the tick again, besides the completion):
  `driver_rr_does_not_advance_for_a_send_never_written` FAIL; 6. (b) the stash drained after the wait again (the
  drain after the flush removed): `driver_stashed_connect_is_anchored_at_its_occurrence` and `ai07_fault_paired_tokio`
  FAIL; 7. (c) the occurrence timestamp replaced by the current time: `driver_stashed_connect_is_anchored_at_its_occurrence`
  FAIL (`ai07` compares idle with active only and cannot see it; the absolute `(20100, 1, 4352)` assertion does).
- `cargo kani -p secmp-client-core` (after FIN-2): `Complete - 7 successfully verified harnesses, 0 failures, 7 total.`
  (among them `kani_uniform_draw_in_range`, `kani_tick_time_checked`, `kani_in_flight_bound`,
  `kani_balanced_rr_selects_due_or_ping`).

# WEISUNG M6-CI-11 — residuals FIN2-1 and FIN2-2 (Astra FINAL2, GLM EXT5), 2026-10-17

## FIN2-2 — escaped basic-string assignment keys

- Test `xtask policy::tests::vet_closure_escaped_assignment_keys_are_rejected`: `"exempti\U0000006Fns".subtle = [...]`, the `o`
  spelling, an escaped inline root table, an escape in a key inside another table, each with the real `subtle@2.6.1`;
  controls: the real config, a comment, a *value* string with an escape.
- Red (finding disabled): `escaped letter: []`.
- Fix: `is_escaped_assignment_key` — a quoted key with a backslash on the left of an assignment is the finding `vet config uses an
  escaped key in an assignment; only bare keys are accepted`; nothing is decoded.
- The real step, not only the function (the store file temporarily replaced, then restored with `git checkout`):
  `cargo xtask step policy` with `"exempti\U0000006Fns".subtle = [...]` prepended → `FINDING vet-closure: vet config uses an escaped key in
  an assignment; only bare keys are accepted`, `policy FAIL 1 policy finding(s)`; with `exemptions.subtle = [...]` prepended →
  `FINDING vet-closure: vet config uses a non-canonical exemptions form …`, `policy FAIL`; the restored store → `policy PASS`.

## FIN2-1 — the next SEND is chosen against a committed position that lags a write

- Tests: `m6_driver_io::driver_rr_reservation_does_not_depend_on_worker_timing` (tokio, paused clock; Balanced, three send
  queues at 10 s, seed 103, AI costs; first frame held 260 ms after 0 bytes and after 128 bytes, and 200 ms as the control;
  idle against active relay-visible SENDs) and `m6_sched_io::balanced_rr_reserves_the_successor_of_an_unwritten_send`
  (scripted relay, no completion reported: three ticks ask Q0, Q1, Q2; a teardown before any completion → the replacement
  link asks Q0).
- Red at `b06ed10`: idle `[(10260, 239), (20000, 239), (30000, 163), (40000, 185), …]` against active `[(10260, 239), (20000, 163),
  (30000, 185), (40000, 239), …]` (the pin of the Astra table: `20000 Q0` idle, `Q1` active) and `asked: [Q0, Q0, Q0, Q0]` in the Rig.
- Fix: `prepare_link` passes `prepare_send` the successor of the newest unwritten SEND (`Up::unwritten`, newest `Some(n)`), else the
  committed `link.rr`; `last_send` stays at the tick; the reservations die with the `Up`.
- Green: both tests, and `balanced_rr_does_not_advance_on_teardown_before_tick`, `balanced_round_robin_due_rule`,
  `driver_rr_does_not_advance_for_a_send_never_written`, `driver_balanced_first_tick_sends_and_fetches_in_order`.
- Writes in flight on the tokio driver: a second unwritten SEND cannot exist there (a link whose write is pending at its next
  tick is closed), so the two-in-flight chain is tested on the sans-IO core (the Rig) and the driver test covers the
  one-in-flight timing case.

## Proof repetition

- `env SECMP_AI_TRACES=64 cargo nextest run -p secmp-testkit --features harness -E 'binary(=harness)'`:
  `Summary [1533.686s] 190 tests run: 190 passed (18 slow), 0 skipped` (ai01–ai07 included).
- Mutants (scratch worktree of the FIN2-1 head; tests `driver_balanced|balanced_round_robin|balanced_rr|driver_rr|driver_stashed|reserv|ai07`),
  8/8 caught: (d) prepare against `link.rr` while `unwritten` is non-empty — `balanced_rr_reserves_the_successor_of_an_unwritten_send`,
  `driver_rr_reservation_does_not_depend_on_worker_timing`; `!send_missing` → `true` — `driver_rr_does_not_advance_for_a_send_never_written`,
  `driver_balanced_first_tick_sends_and_fetches_in_order`, `driver_rr_reservation_…`; `checked_add` → `checked_sub` —
  `balanced_rr_reserves_…`, `balanced_round_robin_due_rule`, `driver_rr_does_not_advance_…`; committed `n` → `0` —
  `balanced_round_robin_due_rule`, `driver_rr_does_not_advance_…`; commit in `frame_written` dropped — the same two; commit at the
  tick again — `driver_rr_does_not_advance_for_a_send_never_written`; stash drained after the wait again —
  `driver_stashed_connect_is_anchored_at_its_occurrence`, `ai07_fault_paired_tokio`; occurrence timestamp → now —
  `driver_stashed_connect_is_anchored_at_its_occurrence`.
- `cargo kani -p secmp-client-core` (after FIN2-1): `Complete - 7 successfully verified harnesses, 0 failures, 7 total.`
