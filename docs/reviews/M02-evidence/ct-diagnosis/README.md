# ct gate diagnosis (WEISUNG M2-2 C) — evidence index and harness reading

Refs (throwaway, not for merge): `diag/ct-head` = `4e582cb` (= `m02-proto` head at the start of the diagnosis: current
harness plus per-class percentiles in the report), `diag/ct-harness-m1` = `5866132` (`crates/secmp-crypto/benches/ct.rs`
exactly as at `bc8d6d5` + the same reporting-only percentile dump; the ct hunks of `xtask/src/{gates,expect}.rs`
reversed to `bc8d6d5`), `diag/ct-aa` = `dbbfd25` (current harness + A/A mode `SECMP_CT_AA=1`: every target except the
control measures class-0 inputs under both random labels; the branch's `linux-ct` job sets the variable),
`diag/ct-aa2` = `2139e38` (A/A′ mode `SECMP_CT_AA=2`: the class-1 source of every target except the control is a
separate copy of its class-0 source — identical contents, another address; added after the reading below named the
source buffer as the remaining class-dependent element), `diag/ct-fix` = `f7b3066` (= the harness fix on `m02-proto`,
C.6; dispatched from this ref so that the reviewer's PR run on `m02-proto` was not cancelled).

Files: `linux-<ref>-<sha>-run<id>.json` (the `ct-report` artefact of each dispatch of the `linux-ct` job),
`macos-arm64-diag-ct-aa-dbbfd25-attempt<n>.json` / `.log` (local A/A runs), `macos-arm64-fix-f7b3066-attempt<n>.json`
/ `.log` (local runs of the fixed harness; attempt 0 has no log), `summary.md` (every verdict, per-class percentiles of
every failing target).

## C.5 — harness reading, M1 (`bc8d6d5`) against the current head (`4e582cb`)

| Question | M1 harness (`bc8d6d5`) | Current harness (`4e582cb`) |
|---|---|---|
| Class sequence per measurement | `measure()` draws `n` class labels up front, `stream.classes(n)`: one byte of the stream per sample, label = low bit; the labels are fixed for the measurement and consumed in order, one per sample | identical (`measure()` unchanged) |
| Which RNG | `Stream`: SHAKE-256 of a 32-byte OS-random seed (`SecretBytes::random`), one stream per bench process, shared by every target and every pass | identical |
| Does warm-up/calibration advance the RNG or the class sequence? | yes, the calibration pass (`target.run(2000, 1)`) draws its own inputs and its own labels from the stream before the measurement; the measurement then draws fresh labels | yes, more of it: the discarded warm-up pass (`target.run(2000, 1)`, F8) + the single-call calibration (`target.run(2000, 1)`) + at most 3 batched rounds (only when k > 1) before the measurement; the measurement draws fresh labels. Consuming more of a SHAKE-256 stream changes which pseudo-random labels come next, not their independence |
| Input preparation | each `target.run` draws its keys and data from the stream and builds one **source buffer per class** (e.g. `[first, last]` for `msg_open_reject`, `sealed`/`tampered` for `caead_open_reject`); every measured input is a fresh copy made by `prepare(c, i)` inside the loop, immediately before the timed window (`Vec` clone for the openers, copy by value for arrays) | identical (targets and `prepare` closures unchanged) |
| Allocation sequence | per sample: `batch.clear()` drops the previous inputs, then `k` fresh copies are allocated; equal sizes for both classes, so the allocator returns the same chunk each time regardless of the class | identical |
| What the warm-up touches | the per-call warm-up inside `measure()`: `op` on the first `n/100` prepared inputs of the measurement's own label sequence | the same per-call warm-up, and in addition (F8) one whole discarded `target.run(2000, 1)` per target before calibration: its own key material, source buffers, 20 warm-up calls and 2000 timed single calls, all dropped before the calibration pass |
| Inside the timed window | `now_ticks()` (`rdtscp` on x86_64), the loop over the `k` prepared inputs calling `op(input)`, `now_ticks()`; nothing else | identical |
| Batches at k = 1 | one input per sample, prepared right before the window | identical; at k = 1 no batched calibration round runs, and the margin, the class-median and the realised-quanta rules only decide `k`/NOT_MEASURABLE, never the t values |
| Report | t on raw + 5 pooled-percentile crops, median, distinct values | the same + per-class percentiles (diagnosis) and the calibration details |

Reading: at k = 1 on x86_64 (every target of the failing Linux run) the measurement code path of M1 and of the current
head is the same; the only difference in the process is the extra discarded warm-up pass per target. No class-dependent
step was found in either version. One class-dependent input remains *by design* in both: the per-class **source
buffer** from which each fresh copy is made — it is read during `prepare` (outside the window) and so leaves a
class-dependent cache footprint (different addresses for class 0 and class 1) at the start of every timed call. The
A/A mode removes this as well (both labels copy from the class-0 source), so an A/A PASS next to an A/B FAIL would not
yet separate "data" from "source address"; an A/A′ mode (identical contents in two separate per-class source buffers)
would.

## Results (C.2, C.3, C.6, C.7) — findings, not decisions

Every verdict and the per-class percentiles of every failing target are in `summary.md`. Counts are gate verdicts
per run (Linux: GitHub-hosted `ubuntu-latest`, three runner types by measured `rdtscp` resolution: 1, 2 or 26 ticks).

| arm | what differs between the classes | Linux | macOS (local) |
|---|---|---|---|
| head `4e582cb` | contents **and** source buffer | FAIL 3/3 | (M2-1 run 1: samekey FAIL) |
| M1 harness `5866132` | contents and source buffer | FAIL 2/3 | — |
| A/A `dbbfd25` | nothing (both labels copy the class-0 source) | PASS 3/3 | PASS 3/3 |
| A/A′ `2139e38` | source buffer only (identical contents) | FAIL 2/3 | — |
| fix `f7b3066` | contents only (one common source, branch-free blend) | FAIL 3/3 | FAIL 3/3 |

1. **F8 refuted.** The M1 harness fails on Linux as well (2/3), so the M2 calibration change (F8) is not the cause.
2. **Harness artefact confirmed and removed.** With identical contents, moving the class-1 source to its own
   allocation is enough to fail the gate (A/A′: `caead_open_reject` 50.1 and 12.8, `msg_open_reject` 13.0), while one
   source for both labels passes every run (A/A). The per-class source buffer read in `prepare` is therefore a
   class-dependent input of the measurement; `f7b3066` removes it (commit message and `ct.rs` targets header).
3. **The gate still fails after the fix**, on Linux (3/3: `caead_open_reject` 47.0/27.4, `caead_derive` 11.4/22.6,
   `caead_aead_reject` 11.6/24.0/13.0, `caead_open_reject_samekey` 52.4/13.9, `msg_open_reject` I→F 9.1/8.8) and on
   macOS (3/3: `caead_derive` I→F each time, `msg_open_reject` 10.6 once). The failing targets include operations
   that are constant-time by construction and whose classes differ only in the contents of one input:
   `caead_derive` (HKDF-SHA-256 over two fixed 32-byte keys that differ in one bit), `caead_aead_reject` (the same
   XChaCha20-Poly1305 reject under two fixed keys), `caead_open_reject_samekey` (same key, tampered at byte 100 vs
   300). Their per-class percentiles agree to the tick at almost every percentile (e.g. fix run 36571079144,
   `caead_derive`: p1…p99 identical in both classes; `caead_open_reject_samekey`: identical except p99); the |t| come
   from shifts smaller than one timer quantum accumulated over 10⁶ samples.
4. **Sign instability.** Several targets show large |t| whose sign flips between the two measurements of one
   process (A/A′ run 36571035269, `msg_open_reject`: p95 t = −5.0, then +48.2; run 36570578827: 7.0, then 165.7) —
   ADR-038 scores these INCONCLUSIVE→PASS (same-sign rule). A data-dependent timing difference of the operation would
   keep its sign.
5. **C.7, macOS run-1 `caead_open_reject_samekey`** (the M2-1 event, per-class source buffers): the macOS A/A runs pass
   it 3/3 (|t| 1.3, 0.7, 1.0) and the fixed harness passes it 3/3 on macOS (2.1, 1.3, 0.9). The event is consistent
   with finding 2 (source-buffer artefact), not with a leak of `Caead::open`.

Open for the reviewer (no threshold, sample count, control or verdict rule was changed): whether the remaining
failures (3) are a property of the fixed-vs-fixed statistic at 10⁶ samples on these runners (sub-quantum,
sign-unstable shifts on code that is constant-time by construction) or need a further harness change; the diagnosis
found no second unambiguous harness defect that can be named with a diff line, so none was fixed.
