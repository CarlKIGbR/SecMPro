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
- Fix: `m6_common::seed_conversation` (one cell of a delivered to b before link-up; `Contact` now carries b's queues).
- Green: 26.1 s, Strict and Low-bw (90 000 000 ms): no teardown other than `Lifetime` for a and b, a `Lifetime`
  teardown each. `core/` untouched; OPEN-M6-B-4 closed as a fixture defect.
