# ct verdict-statistic experiment (WEISUNG M2-3 D) — evidence for the ADR proposal

Report only: thresholds, sample counts, control and verdict rules are unchanged (on `m02-proto` and on the
experiment branches). Code on throwaway refs, not merged: `diag/ct-verdict` = `303a784` (`m02-proto` `e230c6e` +
the report extension below), `diag/ct-verdict-fvr` = `96f869a` (`303a784` + `SECMP_CT_ARM=fvr` in the `linux-ct`
job). Two refs so that the two arms' dispatches do not share a concurrency group; each ref's dispatches ran one
after the other.

## What the report adds (`benches/ct.rs` on `303a784`)

- Per target and per crop (`raw`, `p50` … `p99`), for every measurement: n per class, the class means, `delta` =
  mean0 − mean1 in ticks, `delta_res` = delta / reported resolution, the pooled sd, t (`first.crops`,
  `second.crops`).
- Every non-control target is measured twice; `t1_t2` = t of both measurements (sign kept) at the crop of the first
  measurement's maximum. The verdict uses the second measurement exactly as ADR-038 does (only in the 4.5 … 10
  band), so the gate verdicts in the tables are the ADR-038 verdicts.
- Inline A/A negative control: after the targets, one extra pass over the non-control targets with their `k` in
  which both (random) labels get class-0 inputs from the target's common source (`aa_control`).
- Arm `fvr` (`SECMP_CT_ARM=fvr`): class 0 = the default arm's fixed class-0 input, class 1 = a fresh random input of
  the same kind per call (tag / ciphertext bytes / key / `K_enc` / `expected` / tamper position after `COM`); both
  classes draw the random item and select with `blend` (one common source, F9).

**On "fixed-vs-fixed" (D.2):** the default targets already are fixed-vs-fixed — class 0 and class 1 are two constant
inputs A and B, both built through `blend` (`tag_compare`, `msg_open_reject`, `caead_*`); only `sas` is
fixed-vs-random. The default arm is therefore the fixed-vs-fixed arm, and the extra arm run 3× on Linux is its
contrast, fixed-vs-random, which answers the question "does a contents-only difference between two constants fail as
a fixed-vs-random difference does".

## Runs

| arm | where | runs (gate verdict; failing targets) |
|---|---|---|
| default (fixed-vs-fixed) | Linux `linux-ct`, ref `diag/ct-verdict` `303a784` | 36612364236 FAIL (tag, msg_open, caead_open, derive, aead, com, samekey); 36613373270 FAIL (tag, msg_open, caead_open, com); 36614037720 FAIL (tag, msg_open, caead_open, aead, com, samekey) |
| fixed-vs-random | Linux `linux-ct`, ref `diag/ct-verdict-fvr` `96f869a` | 36612369405 FAIL (msg_open, caead_open, derive, com, samekey); 36613376947 FAIL (msg_open, caead_open, derive, aead, com, samekey); 36614043000 FAIL (tag, samekey) |
| default (fixed-vs-fixed) | macOS arm64 local, `303a784` bench code | run 1 FAIL (caead_open, derive, samekey); run 2 FAIL (caead_open, derive, aead); run 3 FAIL (caead_open, derive) |

Files: `linux-default-303a784-run<id>.json`, `linux-fvr-96f869a-run<id>.json`, `macos-arm64-default-303a784-run<n>.json`.

## Findings (facts from the tables below; no decision)

1. **A/A never fires.** The inline A/A control stays at max |t| ≤ 2.69 over all 72 target measurements of the nine
   runs (both arms, both platforms): with the same contents from the same common source the statistic is at noise.
2. **Contents-only differences fire on every platform and in both arms**: default (fixed-vs-fixed) Linux 3/3 and
   macOS 3/3 gate FAIL, fixed-vs-random Linux 3/3 gate FAIL. A difference between two constants fails as a
   fixed-vs-random difference does.
3. **Within a process the effect mostly reproduces; across runs it does not.** Of the 33 first measurements with
   |t1| > 10, 22 have |t2| > 4.5 with the same sign at the same crop, 3 flip sign (`caead_aead_reject` +39.1 / −25.9,
   fvr `caead_open_reject` −28.2 / +13.9, fvr samekey +40.8 / −43.0), 8 fall to ≤ 4.5; of the 9 in the 4.5 … 10
   band, 5 reproduce, 1 flips, 3 fall. Across runs the same target changes size and sometimes sign (Linux default
   `caead_derive` +22.6 / +3.1 / +3.3; samekey +21.8 / +5.8 / −26.0). On macOS `caead_derive` fails 3/3 with the same
   sign (t1 −29.0, −29.0, −36.7) and `caead_open_reject` 3/3 positive.
4. **Size of the shifts** (first measurement, at the crop of the maximum, every failing target): Linux, 0.409
   ns-tick runners (28 failing target measurements): |Δ| = 0.12 … 7.8 ticks = 0.005 … 0.32 of the effective quantum
   (0.05 … 3.2 ns on samples with medians of 1 152 … 28 787 ticks, 0.5 … 11.8 µs), sd 5.9 … 55.5 ticks. Linux res-2
   runner (0.358 ns tick, 2 failing): `tag_compare` −1.5 ticks (0.75 of its 2-tick quantum; sd 20), samekey +43
   ticks at p99 (the tail; sd 557). macOS (8 failing): |Δ| = 0.010 … 0.108 ticks of 41.67 ns (0.4 … 4.5 ns per
   batch of k calls; `caead_derive`, k = 17: ≈ 0.1 ns per call), sd 0.51 … 0.81 ticks.
5. **Reported resolution vs effective quantum.** On 5 of the 6 Linux runs (0.409 ns tick) the reported resolution
   is 1 tick, but the samples lie on a lattice of ≈ 24.5 ticks (≈ 10 ns: percentiles such as 1127, 1151/1152, 1176,
   1200/1201; 15 533, 15 582, 15 631 …); `Δ/res` therefore overstates the shift in quanta by that factor there, and
   the `realised_quanta` figure of ADR-038 (3) uses the reported value. On the res-2 runner and on macOS the reported
   resolution matches the samples.

## Per-run tables

Columns: gate verdict (ADR-038, unchanged), batch `k`, the crop of the first measurement's max |t|, t1 and t2 at that
crop (sign kept; t = (mean0 − mean1)/SE, t < 0: class 0 faster), Δ = mean0 − mean1 at that crop in ticks, in reported
quanta (`Δ/res`) and in the run's effective quantum (`Δ/q_eff`; q_eff = 24.5 ticks on the lattice runners, else the
reported resolution), pooled sd (ticks), n per class after the crop, and the inline A/A control's max |t| (crop).
Generated from the JSON files by `ctv_table.py` (tables verbatim).

**Linux, default arm (fixed-vs-fixed), run 1 of 3 — 36612364236** — `linux-default-303a784-run36612364236.json`; clock tsc/rdtscp, tick 0.409 ns, reported resolution 1 tick(s), q_eff 24.5 ticks; arm default

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 1 | p90 | +60892.09 |  | -4193.154 | -4193.1542 | -171.1492 | 37.89 | 499600 / 305288 | — |
| tag_compare | INCONCLUSIVE→FAIL | 1 | p50 | +6.21 | +8.87 | +0.122 | +0.1221 | +0.0050 | 5.91 | 178788 / 182364 | 0.65 (p99) |
| msg_open_reject | FAIL | 1 | p90 | +25.83 | +20.48 | +1.040 | +1.0396 | +0.0424 | 18.83 | 437024 / 438373 | 1.64 (raw) |
| caead_open_reject | FAIL | 1 | p95 | +78.77 | +70.20 | +7.778 | +7.7778 | +0.3175 | 48.04 | 473530 / 473349 | 1.46 (raw) |
| sas | PASS | 1 | raw | -1.73 | -0.89 | -2388.062 | -2388.0617 | -97.4719 | 97494.82 | 10023 / 9977 | 2.10 (p50) |
| caead_derive | FAIL | 1 | p99 | +22.55 | +16.89 | +0.578 | +0.5779 | +0.0236 | 12.74 | 493928 / 495768 | 0.91 (p99) |
| caead_aead_reject | FAIL | 1 | p95 | +39.09 | -25.86 | +1.972 | +1.9722 | +0.0805 | 24.47 | 469038 / 471582 | 0.91 (p50) |
| caead_com_compare | FAIL | 1 | p90 | +21.05 | +0.10 | +1.172 | +1.1721 | +0.0478 | 26.18 | 445959 / 437837 | 0.61 (p99) |
| caead_open_reject_samekey | FAIL | 1 | p50 | +21.78 | +13.21 | +3.818 | +3.8184 | +0.1559 | 45.01 | 135053 / 129608 | 1.23 (p75) |

**Linux, default arm, run 2 of 3 — 36613373270** — `linux-default-303a784-run36613373270.json`; clock tsc/rdtscp, tick 0.409 ns, reported resolution 1 tick(s), q_eff 24.5 ticks; arm default

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 1 | p50 | +62402.58 |  | -4172.417 | -4172.4169 | -170.3027 | 47.26 | 499695 / 78 | — |
| tag_compare | FAIL | 1 | p75 | -18.36 | -8.06 | -0.592 | -0.5923 | -0.0242 | 13.53 | 358794 / 345382 | 1.29 (p75) |
| msg_open_reject | FAIL | 1 | p95 | +55.50 | +16.42 | +2.241 | +2.2409 | +0.0915 | 19.60 | 470569 / 471519 | 1.95 (p75) |
| caead_open_reject | FAIL | 1 | p50 | +69.69 | +36.09 | +6.976 | +6.9756 | +0.2847 | 34.73 | 232497 / 246696 | 1.37 (p90) |
| sas | PASS | 1 | p99 | +2.42 | -0.01 | +684.784 | +684.7836 | +27.9504 | 19924.54 | 9940 / 9860 | 1.44 (p95) |
| caead_derive | PASS | 1 | p50 | +3.10 | -15.84 | +0.087 | +0.0869 | +0.0035 | 9.88 | 247284 / 247923 | 1.11 (raw) |
| caead_aead_reject | INCONCLUSIVE→PASS | 1 | p95 | -6.10 | +8.58 | -0.320 | -0.3202 | -0.0131 | 25.37 | 466442 / 467148 | 1.47 (p99) |
| caead_com_compare | FAIL | 1 | p90 | +16.84 | +3.79 | +0.935 | +0.9346 | +0.0381 | 26.33 | 453119 / 446556 | 1.49 (p95) |
| caead_open_reject_samekey | INCONCLUSIVE→PASS | 1 | p95 | +5.77 | -1.00 | +2.682 | +2.6822 | +0.1095 | 226.58 | 474759 / 474394 | 1.22 (p99) |

**Linux, default arm, run 3 of 3 — 36614037720** — `linux-default-303a784-run36614037720.json`; clock tsc/rdtscp, tick 0.409 ns, reported resolution 1 tick(s), q_eff 24.5 ticks; arm default

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 1 | p50 | +49219.35 |  | -4170.369 | -4170.3692 | -170.2192 | 59.89 | 499745 / 76 | — |
| tag_compare | INCONCLUSIVE→FAIL | 1 | p75 | +5.20 | +5.81 | +0.185 | +0.1855 | +0.0076 | 14.71 | 338343 / 341911 | 2.04 (p50) |
| msg_open_reject | FAIL | 1 | p95 | +14.94 | +21.30 | +0.595 | +0.5946 | +0.0243 | 19.33 | 471184 / 471749 | 2.13 (p99) |
| caead_open_reject | FAIL | 1 | p95 | +36.94 | +55.49 | +4.168 | +4.1678 | +0.1701 | 54.74 | 469631 / 471757 | 1.41 (p95) |
| sas | PASS | 1 | raw | -1.09 | +0.65 | -536.803 | -536.8031 | -21.9103 | 34657.99 | 10002 / 9998 | 1.10 (p99) |
| caead_derive | PASS | 1 | p90 | +3.34 | +4.82 | +0.045 | +0.0447 | +0.0018 | 6.12 | 417381 / 418068 | 1.32 (raw) |
| caead_aead_reject | FAIL | 1 | p95 | +39.27 | -3.78 | +1.889 | +1.8893 | +0.0771 | 23.36 | 469936 / 473216 | 1.19 (p50) |
| caead_com_compare | FAIL | 1 | p90 | +16.81 | -0.49 | +1.018 | +1.0184 | +0.0416 | 28.64 | 450809 / 443354 | 2.41 (raw) |
| caead_open_reject_samekey | FAIL | 1 | p95 | -26.02 | -30.75 | -2.804 | -2.8042 | -0.1145 | 52.52 | 474339 / 475407 | 1.65 (p99) |

**Linux, fixed-vs-random arm, run 1 of 3 — 36612369405** — `linux-fvr-96f869a-run36612369405.json`; clock tsc/rdtscp, tick 0.409 ns, reported resolution 1 tick(s), q_eff 24.5 ticks; arm fixed-vs-random

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 1 | p75 | +42614.95 |  | -4216.556 | -4216.5558 | -172.1043 | 57.53 | 500095 / 228063 | — |
| tag_compare | PASS | 1 | p50 | -1.07 | -0.69 | -0.025 | -0.0247 | -0.0010 | 6.86 | 175939 / 175325 | 1.75 (p99) |
| msg_open_reject | FAIL | 1 | p90 | +42.86 | +18.76 | +1.515 | +1.5153 | +0.0618 | 16.65 | 442152 / 444855 | 1.55 (p99) |
| caead_open_reject | FAIL | 1 | p95 | -28.21 | +13.95 | -2.645 | -2.6449 | -0.1080 | 45.49 | 471229 / 470162 | 1.90 (raw) |
| sas | PASS | 1 | p90 | -1.33 | +0.77 | -303.075 | -303.0750 | -12.3704 | 15309.52 | 8944 / 9054 | 0.81 (p95) |
| caead_derive | FAIL | 1 | p50 | -79.76 | -77.71 | -2.027 | -2.0269 | -0.0827 | 8.20 | 211080 / 199634 | 1.04 (raw) |
| caead_aead_reject | PASS | 1 | p75 | -3.77 | -7.41 | -0.159 | -0.1585 | -0.0065 | 17.98 | 364381 / 365027 | 1.83 (p75) |
| caead_com_compare | INCONCLUSIVE→FAIL | 1 | p90 | +6.33 | +6.54 | +0.354 | +0.3543 | +0.0145 | 26.47 | 449839 / 444364 | 1.65 (p95) |
| caead_open_reject_samekey | FAIL | 1 | p90 | +40.79 | -42.96 | +4.279 | +4.2792 | +0.1747 | 49.00 | 433888 / 438839 | 0.89 (p50) |

**Linux, fixed-vs-random arm, run 2 of 3 — 36613376947** — `linux-fvr-96f869a-run36613376947.json`; clock tsc/rdtscp, tick 0.409 ns, reported resolution 1 tick(s), q_eff 24.5 ticks; arm fixed-vs-random

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 1 | p75 | +51245.68 |  | -4214.324 | -4214.3240 | -172.0132 | 47.73 | 500047 / 218723 | — |
| tag_compare | PASS | 1 | p50 | +2.27 | -2.42 | +0.044 | +0.0436 | +0.0018 | 5.60 | 169637 / 169199 | 1.46 (p75) |
| msg_open_reject | FAIL | 1 | p75 | +40.63 | +12.83 | +0.994 | +0.9935 | +0.0406 | 9.76 | 313831 / 321862 | 1.61 (p95) |
| caead_open_reject | FAIL | 1 | p90 | +14.54 | +0.53 | +1.714 | +1.7138 | +0.0700 | 55.54 | 444062 / 444341 | 1.62 (p50) |
| sas | PASS | 1 | p75 | +1.86 | -0.13 | +274.483 | +274.4828 | +11.2034 | 9049.15 | 7449 / 7548 | 1.58 (raw) |
| caead_derive | FAIL | 1 | p90 | -70.82 | -86.57 | -1.064 | -1.0636 | -0.0434 | 6.76 | 405683 / 406042 | 1.00 (raw) |
| caead_aead_reject | FAIL | 1 | p95 | +22.30 | +8.40 | +1.102 | +1.1018 | +0.0450 | 23.45 | 449773 / 451283 | 1.01 (p99) |
| caead_com_compare | INCONCLUSIVE→FAIL | 1 | p90 | +9.15 | +10.58 | +0.464 | +0.4642 | +0.0189 | 23.77 | 442914 / 435037 | 1.73 (p90) |
| caead_open_reject_samekey | FAIL | 1 | p90 | +19.19 | -3.96 | +1.841 | +1.8414 | +0.0752 | 45.11 | 441469 / 442678 | 1.31 (p75) |

**Linux, fixed-vs-random arm, run 3 of 3 — 36614043000** — `linux-fvr-96f869a-run36614043000.json`; clock tsc/rdtscp, tick 0.358 ns, reported resolution 2 tick(s), q_eff 2 ticks; arm fixed-vs-random

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 1 | p75 | +94674.04 |  | -6959.175 | -3479.5876 | -3479.5876 | 43.78 | 500178 / 204418 | — |
| tag_compare | FAIL | 1 | p50 | -25.66 | -28.86 | -1.499 | -0.7495 | -0.7496 | 20.16 | 226270 / 243507 | 2.17 (p75) |
| msg_open_reject | PASS | 1 | p50 | -4.21 | -0.06 | -0.449 | -0.2244 | -0.2245 | 37.41 | 246390 / 245655 | 1.28 (p75) |
| caead_open_reject | PASS | 1 | p50 | +2.04 | -1.37 | +0.632 | +0.3161 | +0.3161 | 109.31 | 249140 / 249527 | 0.60 (raw) |
| sas | PASS | 1 | p99 | +1.59 | -2.29 | +301.110 | +150.5548 | +150.5548 | 13336.69 | 9886 / 9914 | 0.79 (raw) |
| caead_derive | PASS | 1 | p75 | +2.22 | +4.63 | +0.073 | +0.0363 | +0.0363 | 14.09 | 372483 / 371427 | 2.31 (p95) |
| caead_aead_reject | PASS | 1 | p50 | +3.19 | -1.51 | +0.449 | +0.2245 | +0.2245 | 49.36 | 246745 / 246771 | 2.39 (p50) |
| caead_com_compare | PASS | 1 | p99 | -3.46 | -1.71 | -3.628 | -1.8139 | -1.8138 | 521.01 | 494610 / 495390 | 1.73 (p50) |
| caead_open_reject_samekey | FAIL | 1 | p99 | +38.56 | +31.87 | +43.175 | +21.5878 | +21.5877 | 556.99 | 495271 / 494729 | 1.21 (p50) |

**macOS arm64 (local), default arm, run 1 of 3** — `macos-arm64-default-303a784-run1.json`; clock n/a/cntvct_el0, tick 41.667 ns, reported resolution 1 tick(s), q_eff 1 ticks; arm default

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 28 | p90 | +104406.53 |  | -1165.338 | -1165.3383 | -1165.3383 | 6.34 | 500043 / 271819 | — |
| tag_compare | PASS | 1 | raw | -1.20 | +1.49 | -0.030 | -0.0303 | -0.0303 | 12.65 | 499780 / 500220 | 0.74 (p90) |
| msg_open_reject | PASS | 2 | raw | +2.11 | -0.08 | +0.036 | +0.0359 | +0.0359 | 8.51 | 499684 / 500316 | 1.52 (raw) |
| caead_open_reject | FAIL | 1 | p90 | +84.00 | +31.09 | +0.108 | +0.1082 | +0.1082 | 0.61 | 443926 / 443503 | 1.45 (p50) |
| sas | PASS | 1 | p95 | +0.77 | +0.05 | +0.799 | +0.7991 | +0.7991 | 71.45 | 9489 / 9511 | 2.50 (raw) |
| caead_derive | FAIL | 17 | p99 | -29.00 | -29.16 | -0.044 | -0.0444 | -0.0444 | 0.76 | 495238 / 494534 | 1.36 (p90) |
| caead_aead_reject | INCONCLUSIVE→PASS | 2 | p95 | +5.29 | +0.98 | +0.007 | +0.0069 | +0.0069 | 0.64 | 474470 / 474774 | 1.31 (p95) |
| caead_com_compare | PASS | 1 | raw | -2.37 | +0.26 | -0.043 | -0.0430 | -0.0430 | 9.08 | 499331 / 500669 | 2.15 (p95) |
| caead_open_reject_samekey | FAIL | 1 | p95 | +30.55 | +45.52 | +0.051 | +0.0511 | +0.0511 | 0.81 | 472611 / 472896 | 1.36 (p95) |

**macOS arm64 (local), default arm, run 2 of 3** — `macos-arm64-default-303a784-run2.json`; clock n/a/cntvct_el0, tick 41.667 ns, reported resolution 1 tick(s), q_eff 1 ticks; arm default

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 28 | p90 | +90295.93 |  | -1181.919 | -1181.9193 | -1181.9193 | 6.94 | 500081 / 386533 | — |
| tag_compare | PASS | 1 | p90 | +0.81 | +0.78 | +0.001 | +0.0007 | +0.0007 | 0.37 | 381490 / 382298 | 1.59 (p75) |
| msg_open_reject | PASS | 2 | p75 | +1.05 | +0.56 | +0.001 | +0.0009 | +0.0009 | 0.38 | 355711 / 355091 | 1.18 (raw) |
| caead_open_reject | FAIL | 1 | p95 | +34.94 | -1.08 | +0.040 | +0.0397 | +0.0397 | 0.55 | 472028 / 473679 | 2.69 (p75) |
| sas | PASS | 1 | p90 | +1.38 | -0.42 | +1.546 | +1.5455 | +1.5455 | 75.36 | 8999 / 8999 | 1.62 (p75) |
| caead_derive | FAIL | 17 | p50 | -29.04 | -7.75 | -0.043 | -0.0426 | -0.0426 | 0.51 | 247573 / 242363 | 1.41 (raw) |
| caead_aead_reject | INCONCLUSIVE→FAIL | 2 | p75 | +8.10 | +9.69 | +0.010 | +0.0103 | +0.0103 | 0.54 | 354300 / 355513 | 1.07 (p90) |
| caead_com_compare | PASS | 1 | p99 | +1.49 | -0.04 | +0.008 | +0.0082 | +0.0082 | 2.73 | 492322 / 492447 | 1.78 (p50) |
| caead_open_reject_samekey | PASS | 1 | p90 | -2.47 | +0.58 | -0.005 | -0.0048 | -0.0048 | 0.89 | 420040 / 419817 | 1.71 (p99) |

**macOS arm64 (local), default arm, run 3 of 3** — `macos-arm64-default-303a784-run3.json`; clock n/a/cntvct_el0, tick 41.667 ns, reported resolution 1 tick(s), q_eff 1 ticks; arm default

| target | verdict | k | crop | t1 | t2 | Δ ticks | Δ/res | Δ/q_eff | sd | n0 / n1 | A/A max \|t\| |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control_variable_time_compare | PASS | 28 | p90 | +65325.79 |  | -1181.363 | -1181.3635 | -1181.3635 | 9.76 | 499300 / 354624 | — |
| tag_compare | PASS | 1 | p90 | -1.36 | -1.27 | -0.006 | -0.0063 | -0.0063 | 2.18 | 443942 / 443404 | 0.82 (raw) |
| msg_open_reject | PASS | 2 | p90 | -1.87 | -0.24 | -0.002 | -0.0017 | -0.0017 | 0.41 | 383205 / 382253 | 1.87 (p50) |
| caead_open_reject | FAIL | 1 | p90 | +28.11 | +1.08 | +0.036 | +0.0362 | +0.0362 | 0.61 | 447635 / 448085 | 0.73 (p95) |
| sas | PASS | 1 | p95 | +1.56 | +1.36 | +6.655 | +6.6553 | +6.6553 | 294.75 | 9453 / 9547 | 1.15 (p90) |
| caead_derive | FAIL | 17 | p95 | -36.70 | -22.42 | -0.055 | -0.0554 | -0.0554 | 0.73 | 464111 / 463411 | 0.79 (raw) |
| caead_aead_reject | INCONCLUSIVE→PASS | 2 | p95 | +6.77 | +0.65 | +0.009 | +0.0093 | +0.0093 | 0.66 | 468136 / 469209 | 1.90 (p50) |
| caead_com_compare | PASS | 1 | p99 | -1.59 | -0.23 | -0.003 | -0.0028 | -0.0028 | 0.88 | 495596 / 493274 | 1.03 (p50) |
| caead_open_reject_samekey | PASS | 1 | p95 | +0.76 | +0.80 | +0.007 | +0.0073 | +0.0073 | 4.60 | 459991 / 459461 | 1.09 (p95) |
