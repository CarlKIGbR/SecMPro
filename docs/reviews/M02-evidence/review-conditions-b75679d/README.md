# Evidence of the code head `b75679d` (M2 review conditions C1–C5; WEISUNG M2-8)

`b75679d` is the fix commit for C1–C5 of `docs/reviews/M02-review.md`; the reviewer's addendum §I records them as
met.

## CI: PR run 36742805570 on `b75679d`

All four required jobs are green: `linux-fast`, `windows-native`, `xwin-cross` and `linux-full` (1 h 32 min).

- `../ci-full-x86_64-linux-pr-run-36742805570-b75679d.txt` — the `linux-full` log, reduced to:
  - the fuzz step's command line per target, with `-max_len` from `expect::FUZZ_MAX_LEN` (C4), and libFuzzer's
    `Done … runs` line for each;
  - Kani's harness verdicts and its summary "Complete - 16 successfully verified harnesses, 0 failures, 16 total."
    (C5);
  - the ci-full step summary: every step PASS, mutants 625 with 1 documented survivor.
- `../ct-report-x86_64-linux-pr-run-36742805570-b75679d.json` — the run's ct report:
  - its `thresholds` echo `samples` 1 000 000 and `sas_samples` 20 000 (C3 (c)), and it has no `secmp_ct_scale`;
  - run verdict PASS on a lattice runner (0.409 ns tick); A/A max |t| 3.20; `min_leak_control` 44.8 floors.
- `../ct-report-x86_64-linux-pr-run-36689454147-b36d252.json` — the ct report of the PR run on `b36d252`. Its A/A
  maximum on Linux is 2.55; the committed Amendment 1 evidence has at most 2.49.

## Local runs (macOS arm64)

The local runs used the working tree that became `b75679d`. After them, only a `#![forbid(unsafe_code)]` header in
`crates/secmp-proto/tests/fuzz_max_len.rs` and one row of `xtask/README.md` changed. The two exceptions:
- the Kani run preceded the last edit of `Writer::reserve`, which changed its growth from twice the capacity to twice
  the length, and one test assertion. Under Kani, `reserve` returns before that line (`cfg!(kani)`), so the verified
  code is the same;
- the mutants runs came after that edit.

- `gate-check-neutralisation.txt` — each new refusal of the gate (C3 (a)–(f), C5 and the C2 policy check)
  neutralised in turn, with the tests that then fail; the baseline has none failing.
- `ct-check-16-reports.txt` — `cargo xtask ct-check` over the 15 committed Amendment 1 reports and the report of
  PR run 36689454147: 16 PASS.
- `ct-check-scaled-run-refused.txt` — a bench run with `SECMP_CT_SCALE=100`, refused by `ct-check` (the
  `secmp_ct_scale` echo and every short sample count).
- `kani-gate-aarch64-apple-darwin.txt` — `cargo xtask step --strict kani`: 16/16 verified in 359 s, with the count
  in the step summary.
- `mutants-4-shards-aarch64-apple-darwin.txt` — the gate's cargo-mutants command in 4 shards: 625 mutants, 1 missed
  (the documented `SecretBytes::drop`), 0 timeouts.

## SHA-256

```
2c5edb46e0fa9bfe77d8f73190369f5c1bd693240daaca43d470817b5bec2df1  docs/reviews/M02-evidence/ci-full-x86_64-linux-pr-run-36742805570-b75679d.txt
0f97eeb0b9a071ffceba5953d9d3996cc3f663b421613ca6104bfce641839ac8  docs/reviews/M02-evidence/ct-report-x86_64-linux-pr-run-36742805570-b75679d.json
224cc13a4e5439aeaa09f46d35a43ef040d47bd64c41436d8d4cdaff9e5424da  docs/reviews/M02-evidence/ct-report-x86_64-linux-pr-run-36689454147-b36d252.json
58b66d10019ceb4117f168037aece8f3708e24d5f4af53f652a507ece721e096  docs/reviews/M02-evidence/review-conditions-b75679d/gate-check-neutralisation.txt
92e01694d50cf7b1acbfb174338d6a2e5ec7f41587d68a72305f5a8ef61c054b  docs/reviews/M02-evidence/review-conditions-b75679d/ct-check-16-reports.txt
b20cabbd92e44bee0b05a79e08871b8585307f6a085ef216d7418cb93b32c510  docs/reviews/M02-evidence/review-conditions-b75679d/ct-check-scaled-run-refused.txt
afd5743a9c59a9f49bbbb6be185023eeae99af1dc1852b58d3b83c944ee85f61  docs/reviews/M02-evidence/review-conditions-b75679d/kani-gate-aarch64-apple-darwin.txt
0f0f0b0074dee7adff396ef4f910e4ee9a7598fe49a0b9632eab03eeb6812d33  docs/reviews/M02-evidence/review-conditions-b75679d/mutants-4-shards-aarch64-apple-darwin.txt
```
