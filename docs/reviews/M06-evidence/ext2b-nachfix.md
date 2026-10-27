# Evidence — Codex M6B-EXT2 nachfix (WEISUNG M6-CI-2), 2026-10-16

Each finding: the regression test was written first and run red, then the fix.

## EXT2B-1 — relay TLS handshake without an absolute deadline

- Test: `secmp-relay::relay direct_tls::a_trickled_client_hello_ends_at_the_hello_timeout`
  (`cargo nextest run -p secmp-relay --features kat a_trickled`). A TLS record header announcing 1400 bytes, then one byte
  per 300 ms over the in-memory socket; `hello_timeout_ms` = 1500; bound = `hello_timeout` + `READ_POLL` (500 ms) + 300 ms
  slack = 2.3 s; `server::handle` must return (the connection slot is counted out when it does) and the stream must be
  closed.
- Red (before the fix): `EXT2B-1: closed after 12.714695376s, hello_timeout + READ_POLL is 2.3s` (the trickle stops after
  40 bytes, so the run ends instead of lasting the 7 min of the probe).
- Fix: `Deadlined<S>` under rustls's `StreamOwned` in `crates/secmp-relay/src/tls.rs`; `TlsConn::read` sets one absolute
  `Instant` deadline (now + `READ_POLL`) for the whole call; every raw read and write is capped by `deadline -
  now` and fails with `TimedOut` at zero; the connection loop then ticks, so `hello_timeout` is enforced.
- Green: 1.809 s. The whole relay suite: 188 passed (`cargo nextest run -p secmp-relay --features kat`).
- Client side (`secmp-transport/src/tls.rs`): async `tokio-rustls`, no poll-timeout loop, so not the same defect. It also has
  no connect or handshake timeout of its own (`grep timeout(` in `crates/secmp-transport/src` is empty); the bound there
  is the driver's link management (EXTB-4 tasks, in-flight bound). Not changed; reported.

## EXT2B-2 — vet exemption header with a quoted or escaped key

- Test: `xtask policy::tests::vet_closure_header_with_quoted_table_key_is_rejected` — `[["exemptions".const-oid]]`,
  `[['exemptions'.const-oid]]`, `[[ "exemptions" . "const-oid" ]]`, `[["exemptions".const-oid]]`,
  `[["exemptions"."const-oid"]]`; positive controls: the strict form and `[policy."x"]`.
- Red: first run, the headers were flagged only as "not in the strict form" (no finding naming the quoted key); after
  adding that finding, the `i` spelling was red: `an entry is counted: left: 1` (right 2) — the word `exemptions`
  does not occur in it, so it was skipped entirely.
- Fix: `vet_exemptions` takes every `[[` header with a quote and every header with a backslash as an entry with a bad
  header; `vet_closure_findings` adds `vet exemption header with a quoted or escaped key in a table header …`.
- Green: 217 xtask tests passed.

## EXT2B-3 + OPEN-M6-B-4 — G-12 fixture

- Test: `secmp-testkit::harness m6_sched_life::relay_idle_and_age_bounds_from_schedule` (tightened).
- Red (assertion tightened, fixture unchanged): `Strict: client b: [(237303, TornDown(LinkId(1), Overrun))]`.
- Fix: `m6_common::seed_conversation` (one cell of a delivered to b before link-up; `Contact` now carries b's receive queue).
- Green: 26.1 s, Strict and Low-bw (90 000 000 ms): no teardown other than `Lifetime` for a and b, a `Lifetime`
  teardown each. `core/` untouched; OPEN-M6-B-4 closed as a fixture defect.

## GLM2B-1 — Balanced round robin advances at write time (WEISUNG M6-CI-3, approved core change)

- Change (`crates/secmp-client-core/src/scheduler/core/mod.rs`, nothing else in `core/`): `Part` carries `next_rr`; `prepare_send`
  no longer writes the position (it takes it by value); `tick` applies it next to `last_send`. A failed `chan.prepare`, an
  Overrun or InFlight teardown before the tick, and PING slots leave it untouched. Contract text in `scheduler/mod.rs`
  updated.
- Test: `m6_sched_io::balanced_rr_does_not_advance_on_teardown_before_tick` (scripted relay `Rig`, Balanced, three send queues
  due, the cell of tick 1 obtained from q0, its preparation reported finished at 10 001 → Overrun at 10 000, reconnect).
- Red (before the fix): `asked: [QueueId(0), QueueId(1)]` — `left: Some(QueueId(1))`, `right: Some(QueueId(0))`.
- Green after: 1 passed.
- Proof repetition at `50aa71e`, `env SECMP_AI_TRACES=64 cargo nextest run -p secmp-testkit --features harness -E 'binary(=harness)'`:
  `Summary [1585.013s] 165 tests run: 165 passed (16 slow), 0 skipped` — includes `driver_balanced_first_tick_sends_and_fetches_in_order`,
  `balanced_round_robin_due_rule`, AI-01…AI-06 on the virtual driver at 64 traces and the six tokio repeats at 64 traces with the
  extended oracle, the wake-schedule/driver suites. `ci-fast --strict` green. Kani was not re-run in this step (not verified whether any harness reaches the changed code; the
  `kani` job of the PR run covers it).
- Mutants (hand-made, in a scratch worktree, tests `driver_balanced|balanced_round_robin|balanced_rr`): 4/4 caught —
  `!send_missing`→`true`: `driver_balanced_first_tick_sends_and_fetches_in_order` FAIL; `checked_add`→`checked_sub`:
  `balanced_round_robin_due_rule` FAIL; `link.rr = n`→`link.rr = 0`: `balanced_round_robin_due_rule` FAIL; the rr update in `tick`
  dropped: `balanced_round_robin_due_rule` FAIL.
- Mutant gate (GLM §2d): `expect::MUTANT_HARNESS_SKIP_TESTS` skips `ai01…ai06_*_tokio` (and the virtual AI tests) in the
  per-mutant run of the second `cargo mutants` run (`gates::mutants_harness_args`), so `ai02_balanced_tokio` does not run there.
  The pure (A′) revert — the position advancing when the cell is obtained — is exactly the state the new test was red on, so the
  fast suite, which the mutation run does include (`m6_sched_io` is not skipped), now kills it.

## §client-bound — a connect that never completes (WEISUNG M6-CI-4)

- Correction to the EXT2B-1 adapter check above: `secmp-transport` has no timeout of its own, but the driver has one.
  `scheduler/run.rs` wraps provider connect (the direct provider's TCP connect and TLS handshake, the Tor provider's
  `connect_with_prefs`) and the SecMP-LINK handshake of every link in one `tokio::time::timeout(connect_timeout, …)`
  (`CONNECT_TIMEOUT_MS` = 120 000, `Driver::with_connect_timeout`); on expiry the attempt future is dropped, the connect
  resolves as failed (`Conn::Failed`) and the scheduler retries through its back-off. The core has no deadline for a
  `Connecting` link; the driver's timeout is what keeps it from staying there (driver obligation (iii)).
- Probe: `m6_driver_io::driver_never_completing_connect_is_bounded` (real tokio driver, paused clock, one Strict contact at
  P = 10 s, link 0 hung): (a) the provider's connect future never resolves; (b) the peer accepts and never writes a byte
  (`mute_after` 0, the link handshake never gets `RELAYINFO`).
- Observed, both cases: connect of link 0 at t = 0, resolved as failed at t = 120 000 ms (`TornDown(LinkId(0), Closed)`),
  a new link (`LinkId(2)`) connects and comes up at 120 000; the other link (`LinkId(1)`) up at 0 and never torn down; no
  stream task of the hung link remains (`has_link_io` false). 120 000 ms < `link_idle_ms` 240 000 ms; the test pins the
  exact value and `CONNECT_TIMEOUT_MS < link_idle_ms`.
- Result: bounded, no transport change; no `docs/06` default changed (no ADR-047 Amendment 6).
- Not covered by this probe: the real `TlsProvider`/`TcpDialer` over a real socket (the paused-clock harness uses
  `MemProvider`); the timeout wraps the provider future generically, so the provider type does not matter to the bound.

## §GLM2B-1 mutant 5 — the pure (A′) revert under the mutation gate's selection (WEISUNG M6-CI-5)

- Mutant 5 (scratch worktree of `fedf77f`, removed): the position written right after `prepare_cell` succeeds in
  `prepare_send` (`rr: &mut usize`, `*rr = n`), `Part.next_rr` always `None`, so `tick` applies nothing — the pre-GLM2B-1
  behaviour.
- Selection: the harness run of `gates::mutants_harness_args` — packages `secmp-client-core`, `secmp-transport`,
  `secmp-testkit` (`MUTANT_HARNESS_TEST_PACKAGES`), feature `harness`, nextest, with every name of `MUTANT_HARNESS_SKIP_TESTS`
  and `MUTANT_SKIP_TESTS` as `--skip` (so `ai01…ai06_*_tokio` and the virtual AI tests do not run).
- Result: `Summary [67.398s] 200 tests run: 199 passed (1 slow), 1 failed, 16 skipped`; the failure is
  `secmp-testkit::harness m6_sched_io::balanced_rr_does_not_advance_on_teardown_before_tick` — the only test that kills it.
  The skip list stays unchanged (`ai02_balanced_tokio` remains skipped).
- Pin: `gates::tests::rr_write_time_guard_is_not_skipped_by_the_mutation_run` (the guard exists once, no skip entry names it,
  the second run tests `secmp-testkit` with feature `harness`).

## §windows — PR run #155, windows-native (WEISUNG M6-CI-6)

- With measures 1–4 `windows-native` completes in about 55 min (clippy 187 s, nextest 1175 s ≈ 19.6 min, kat 1857 s ≈ 31 min,
  doctest and hello short; #152 was cut at 90 min), instead of 90+.
- The one Windows-only red test of 970: `secmp-transport::tor tor_config_uses_profile_state_dir`
  (`crates\secmp-transport\tests\tor\main.rs:124`). The panic message is the `Debug` of the built `TorClientConfig`, which
  shows `state_dir: CfgPath(Literal(LiteralPath { literal: "D:\\a\\SecMPro\\SecMPro\\target\\tmp\\secmp-tor-tor-01-8700\\tor\\…` —
  backslashes escaped — while the assertion searched for `state.to_str()` with single backslashes; the typed
  `cache_dir` comparison on line 122 passed.
- Fix: the assertion searches for the path's own `Debug` rendering (`format!("{path:?}")` without the quotes), identical on
  every platform; the test's intent (state under `D/tor/state`, no `${ARTI` default) is unchanged. Linux cannot show it red
  (no escaping there); the evidence is the Windows run of the next PR head.
- Sweep (`grep` for `contains(…to_str()/display()/to_string_lossy)` and `format!("{x:?}")` on paths in `crates` and
  `xtask`): one hit, this one. Not hits: `m6_followups.rs:176`, `m6_sched_life.rs:332` (`contains` on file text, `display()` only in the
  message), `xtask/src/policy.rs:494` (extension list), `policy.rs:437` (workspace-relative paths, `policy` is not a
  Windows step); the other `format!("{x:?}")` hits format key types, not paths.
