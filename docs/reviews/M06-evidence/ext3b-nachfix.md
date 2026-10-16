# Evidence — Codex M6B-EXT3c nachfix (WEISUNG M6-CI-7), 2026-10-16/17

## EXT3B-1 — byte-order mark before an exemption header

- Test: `xtask policy::tests::vet_closure_byte_order_mark_is_rejected` — inputs: `<BOM>[[exemptions.const-oid]]`,
  `<BOM>[["exemptions".const-oid]]`, the full current `supply-chain/config.toml` behind a BOM with the closure exemption
  planted, and a BOM inside a later line; control: the real config without a BOM has no such finding.
- Red (before): `bare: []` — the classifier skipped the header, no finding.
- Fix: `vet_closure_findings` pushes `vet config contains a byte-order mark` when the text contains U+FEFF anywhere (rejected,
  not stripped).
- Green: 219 xtask tests pass.
- Deny/license readers (`deny_duplicate_skips_are_justified`, `licenses_cover_m6_closure`, `audit_ignores_match_deny_toml`):
  they match multi-line needles (`"\nskip-tree = []\n"`, `"\nallow = [\n"`, `split_once("\nskip = [\n")`) and turn a missing
  needle into an assertion failure or an error, so a BOM that hides a list makes them fail closed; they do not classify
  headers. No guard added there. `repo_files_are_read_with_lf_line_endings` now also asserts that `deny.toml`,
  `supply-chain/config.toml` and `audits.toml` contain no U+FEFF. (Argued from the code, not run with BOM inputs.)

## EXT3B-2 — flush wait ignores the next scheduler deadline

- Test: `m6_driver_io::driver_hanging_writer_does_not_shift_staggered_tick` (tokio driver, paused clock; Strict, one contact,
  P = 10 s, no phase; link 1 up at 0 with a tick at 130 000; link 0 connects 119 999 ms late, is up at 119 999, its first
  write at 129 999 hangs for 20 s). The equal-due test is `driver_hanging_writer_does_not_delay_other_links`.
- Red (at the pin): `the healthy link was torn down: [(130249, TornDown(LinkId(1), Overrun))]`.
- Fix (`scheduler/run.rs`, `flush_wait` only): `until = min(now + FLUSH_WAIT_MS, next_deadline − driver_jitter_ms)`; on expiry
  the pass goes on and the stalled write stays pending under `WRITE_STALL_MS`. `FLUSH_WAIT_MS` (250) and every other
  documented driver constant are unchanged (no ADR). `core/` untouched.
- Green: the new test and the 20 other `driver_*` / `m6_tokio::` tests (21 passed); whole harness binary at default trace
  counts: `Summary [293.301s] 167 tests run: 167 passed (16 slow), 0 skipped`, including `driver_balanced_first_tick_sends_and_fetches_in_order`
  and the six tokio repeats `ai01…ai06_*_tokio` (106–165 s each).
