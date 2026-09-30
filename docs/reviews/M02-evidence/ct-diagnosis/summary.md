# ct gate diagnosis — verdicts (WEISUNG M2-2 C.2–C.4, C.6, C.7)

Every Linux run is one dispatch of the `linux-ct` job (`ubuntu-latest`, `cargo xtask step --strict ct`, report artefact copied here as `linux-<ref>-<sha>-run<id>.json`); dispatches on the same ref ran one after the other, refs alternated. Cells: verdict and first-pass max |t| (/ second pass after INCONCLUSIVE); P = PASS, F = FAIL, I = INCONCLUSIVE (4.5 < |t| ≤ 10, re-measured once). `res` = the runner's measured timer resolution in ticks (`rdtscp`, TSC at ~2.4–2.6 GHz). Thresholds, samples, control and verdict rules are unchanged throughout (ADR-038).

## Linux (x86_64, `ubuntu-latest`)

| arm | commit | # | run id | res | gate | control | tag | msg_open | caead_open | sas | derive | aead | com | samekey |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| head (current harness) | `4e582cb` | 1 | 36569276354 | 26 | FAIL | P | P 2.7 | P 3.7 | F 14.8 | P 1.1 | P 1.9 | P 1.5 | P 0.8 | P 2.5 |
| head (current harness) | `4e582cb` | 2 | 36569537981 | 26 | FAIL | P | P 1.2 | P 2.4 | F 83.3 | P 1.0 | F 47.4 | P 2.0 | P 1.4 | F 13.4 |
| head (current harness) | `4e582cb` | 3 | 36569851004 | 26 | FAIL | P | P 1.1 | P 3.6 | F 37.4 | P 2.1 | P 3.5 | P 1.2 | P 3.5 | I→P 5.3/1.6 |
| M1 harness | `5866132` | 1 | 36569280552 | 1 | FAIL | P | P 2.0 | F 47.7 | P 1.8 | P 3.0 | F 35.9 | I→P 4.8/27.3 | P 2.9 | I→F 6.0/5.3 |
| M1 harness | `5866132` | 2 | 36569607551 | 2 | PASS | P | P 0.7 | P 2.0 | P 0.8 | P 1.0 | P 1.7 | P 1.6 | P 1.4 | P 3.2 |
| M1 harness | `5866132` | 3 | 36569911754 | 1 | FAIL | P | P 2.5 | F 10.4 | I→P 8.4/16.2 | P 3.1 | P 1.2 | I→P 5.3/18.5 | P 2.1 | I→P 7.2/46.2 |
| A/A | `dbbfd25` | 1 | 36569285346 | 1 | PASS | P | P 0.3 | P 1.6 | P 0.7 | P 2.1 | P 1.1 | P 1.2 | P 1.4 | P 2.5 |
| A/A | `dbbfd25` | 2 | 36569611898 | 26 | PASS | P | P 1.8 | P 1.2 | P 1.5 | P 1.3 | P 0.4 | P 0.7 | P 1.0 | P 1.8 |
| A/A | `dbbfd25` | 3 | 36569854770 | 1 | PASS | P | P 2.5 | P 0.9 | P 1.1 | P 1.7 | P 2.1 | P 2.3 | P 1.6 | P 1.0 |
| A/A′ | `2139e38` | 1 | 36569831144 | 26 | FAIL | P | P 1.1 | F 13.0 | F 50.1 | P 1.4 | P 1.1 | P 1.2 | P 1.8 | P 2.5 |
| A/A′ | `2139e38` | 2 | 36570578827 | 1 | FAIL | P | P 1.1 | I→P 7.0/165.7 | F 12.8 | P 2.0 | P 1.1 | P 2.3 | P 1.5 | P 2.3 |
| A/A′ | `2139e38` | 3 | 36571035269 | 1 | PASS | P | P 3.2 | I→P 5.0/61.5 | P 3.7 | P 3.0 | P 1.0 | P 1.5 | P 1.8 | P 3.2 |
| fix (common source) | `f7b3066` | 1 | 36571079144 | 1 | FAIL | P | P 3.4 | I→P 5.1/3.5 | F 47.0 | P 0.9 | F 11.4 | F 11.6 | P 3.2 | F 52.4 |
| fix (common source) | `f7b3066` | 2 | 36571807564 | 1 | FAIL | P | I→P 5.0/2.8 | I→F 9.1/8.8 | F 27.4 | P 0.9 | F 22.6 | F 24.0 | P 4.1 | F 13.9 |
| fix (common source) | `f7b3066` | 3 | 36572303711 | 2 | FAIL | P | P 0.9 | P 2.8 | P 1.0 | P 1.2 | P 1.7 | F 13.0 | P 2.4 | P 2.4 |

## macOS (arm64, local, `cntvct_el0` 24 MHz)

| arm | commit | # | file | res | gate | control | tag | msg_open | caead_open | sas | derive | aead | com | samekey |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A/A | `dbbfd25` | 1 | macos-arm64-diag-ct-aa-dbbfd25-attempt1.json | 1 | PASS | P | P 0.7 | P 1.5 | P 1.9 | P 0.9 | P 1.1 | P 1.8 | P 1.7 | P 1.3 |
| A/A | `dbbfd25` | 2 | macos-arm64-diag-ct-aa-dbbfd25-attempt2.json | 1 | PASS | P | P 3.1 | P 2.4 | P 0.7 | P 1.9 | P 1.7 | P 1.6 | P 1.1 | P 0.7 |
| A/A | `dbbfd25` | 3 | macos-arm64-diag-ct-aa-dbbfd25-attempt3.json | 1 | PASS | P | P 1.0 | P 1.3 | P 0.8 | P 1.3 | P 1.7 | P 1.6 | P 1.5 | P 1.0 |
| fix (common source) | `f7b3066` | 0 | macos-arm64-fix-f7b3066-attempt0.json | 1 | FAIL | P | P 0.7 | P 1.1 | P 1.9 | P 1.3 | I→F 9.7/8.4 | P 1.9 | P 1.2 | P 2.1 |
| fix (common source) | `f7b3066` | 1 | macos-arm64-fix-f7b3066-attempt1.json | 1 | FAIL | P | P 1.7 | F 10.6 | P 1.3 | P 1.9 | I→F 9.4/8.4 | P 1.8 | P 1.1 | P 1.3 |
| fix (common source) | `f7b3066` | 2 | macos-arm64-fix-f7b3066-attempt2.json | 1 | FAIL | P | P 0.9 | P 1.8 | P 0.8 | P 1.2 | I→F 9.8/10.6 | P 2.3 | P 1.4 | P 0.9 |

## Per-class sample percentiles of the failing targets (C.4; first measurement, ticks per batch)

- head (current harness) `4e582cb` #1 (run/file 36569276354, res 26): **caead_open_reject** FAIL, k=1, max |t| 14.755 at p99, raw t 1.296
  - class0: n 500080, p1 11206, p5 11206, p10 11232, p25 11258, p50 11284, p75 11284, p90 11310, p95 11336, p99 11388
  - class1: n 499920, p1 11206, p5 11206, p10 11232, p25 11258, p50 11284, p75 11284, p90 11310, p95 11336, p99 11388
- head (current harness) `4e582cb` #2 (run/file 36569537981, res 26): **caead_open_reject** FAIL, k=1, max |t| 83.313 at p95, raw t 0.274
  - class0: n 500379, p1 14144, p5 14144, p10 14170, p25 14196, p50 14222, p75 14274, p90 14300, p95 14326, p99 20826
  - class1: n 499621, p1 14118, p5 14144, p10 14170, p25 14170, p50 14222, p75 14248, p90 14300, p95 14326, p99 20826
- head (current harness) `4e582cb` #2 (run/file 36569537981, res 26): **caead_derive** FAIL, k=3, max |t| 47.424 at p90, raw t 2.618
  - class0: n 499525, p1 3380, p5 3406, p10 3406, p25 3432, p50 3484, p75 3510, p90 3562, p95 3588, p99 3640
  - class1: n 500475, p1 3380, p5 3380, p10 3406, p25 3432, p50 3484, p75 3510, p90 3562, p95 3588, p99 3640
- head (current harness) `4e582cb` #2 (run/file 36569537981, res 26): **caead_open_reject_samekey** FAIL, k=1, max |t| 13.433 at p95, raw t -0.286
  - class0: n 500191, p1 14092, p5 14118, p10 14118, p25 14144, p50 14170, p75 14196, p90 14222, p95 14274, p99 20826
  - class1: n 499809, p1 14092, p5 14118, p10 14118, p25 14144, p50 14170, p75 14196, p90 14248, p95 14274, p99 20800
- head (current harness) `4e582cb` #3 (run/file 36569851004, res 26): **caead_open_reject** FAIL, k=1, max |t| 37.369 at p95, raw t 0.995
  - class0: n 500158, p1 14144, p5 14144, p10 14170, p25 14196, p50 14222, p75 14274, p90 14326, p95 14352, p99 19760
  - class1: n 499842, p1 14144, p5 14144, p10 14170, p25 14196, p50 14222, p75 14274, p90 14300, p95 14352, p99 19942
- M1 harness `5866132` #1 (run/file 36569280552, res 1): **msg_open_reject** FAIL, k=1, max |t| 47.672 at p95, raw t -0.864
  - class0: n 500550, p1 8673, p5 8673, p10 8673, p25 8697, p50 8698, p75 8722, p90 8747, p95 8820, p99 8918
  - class1: n 499450, p1 8673, p5 8673, p10 8673, p25 8697, p50 8698, p75 8722, p90 8747, p95 8820, p99 8918
- M1 harness `5866132` #1 (run/file 36569280552, res 1): **caead_derive** FAIL, k=1, max |t| 35.931 at p99, raw t -2.701
  - class0: n 500941, p1 1176, p5 1176, p10 1176, p25 1176, p50 1176, p75 1200, p90 1201, p95 1201, p99 1298
  - class1: n 499059, p1 1176, p5 1176, p10 1176, p25 1176, p50 1176, p75 1200, p90 1201, p95 1201, p99 1298
- M1 harness `5866132` #1 (run/file 36569280552, res 1): **caead_open_reject_samekey** INCONCLUSIVE→FAIL, k=1, max |t| 6.018 at p90, raw t -1.619
  - class0: n 500166, p1 15386, p5 15435, p10 15435, p25 15460, p50 15484, p75 15509, p90 15557, p95 15582, p99 17395
  - class1: n 499834, p1 15386, p5 15435, p10 15435, p25 15460, p50 15484, p75 15509, p90 15557, p95 15582, p99 17419
- M1 harness `5866132` #3 (run/file 36569911754, res 1): **msg_open_reject** FAIL, k=1, max |t| 10.416 at p95, raw t 0.028
  - class0: n 500583, p1 8673, p5 8673, p10 8673, p25 8697, p50 8698, p75 8746, p90 8771, p95 8820, p99 8942
  - class1: n 499417, p1 8673, p5 8673, p10 8673, p25 8697, p50 8698, p75 8746, p90 8771, p95 8820, p99 8918
- A/A′ `2139e38` #1 (run/file 36569831144, res 26): **msg_open_reject** FAIL, k=1, max |t| 13.043 at p99, raw t 0.126
  - class0: n 500474, p1 8190, p5 8216, p10 8216, p25 8242, p50 8268, p75 8294, p90 8294, p95 8320, p99 8372
  - class1: n 499526, p1 8190, p5 8216, p10 8216, p25 8242, p50 8268, p75 8294, p90 8294, p95 8320, p99 8372
- A/A′ `2139e38` #1 (run/file 36569831144, res 26): **caead_open_reject** FAIL, k=1, max |t| 50.087 at p95, raw t 2.844
  - class0: n 500319, p1 14092, p5 14118, p10 14144, p25 14170, p50 14196, p75 14222, p90 14274, p95 14300, p99 19422
  - class1: n 499681, p1 14092, p5 14118, p10 14144, p25 14144, p50 14196, p75 14222, p90 14248, p95 14274, p99 19396
- A/A′ `2139e38` #2 (run/file 36570578827, res 1): **caead_open_reject** FAIL, k=1, max |t| 12.848 at p90, raw t 0.618
  - class0: n 499613, p1 15484, p5 15508, p10 15509, p25 15533, p50 15557, p75 15582, p90 15631, p95 15705, p99 25014
  - class1: n 500387, p1 15484, p5 15508, p10 15509, p25 15533, p50 15557, p75 15582, p90 15631, p95 15705, p99 25063
- fix (common source) `f7b3066` #1 (run/file 36571079144, res 1): **caead_open_reject** FAIL, k=1, max |t| 47.034 at p95, raw t -0.437
  - class0: n 499602, p1 15337, p5 15361, p10 15361, p25 15386, p50 15410, p75 15459, p90 15509, p95 15558, p99 22662
  - class1: n 500398, p1 15337, p5 15361, p10 15361, p25 15386, p50 15411, p75 15460, p90 15533, p95 15582, p99 22442
- fix (common source) `f7b3066` #1 (run/file 36571079144, res 1): **caead_derive** FAIL, k=1, max |t| 11.403 at p99, raw t 0.363
  - class0: n 500641, p1 1127, p5 1151, p10 1151, p25 1151, p50 1152, p75 1152, p90 1176, p95 1176, p99 1250
  - class1: n 499359, p1 1127, p5 1151, p10 1151, p25 1151, p50 1152, p75 1152, p90 1176, p95 1176, p99 1250
- fix (common source) `f7b3066` #1 (run/file 36571079144, res 1): **caead_aead_reject** FAIL, k=1, max |t| 11.603 at p50, raw t 0.112
  - class0: n 499849, p1 7693, p5 7693, p10 7717, p25 7717, p50 7742, p75 7742, p90 7767, p95 7791, p99 9408
  - class1: n 500151, p1 7693, p5 7693, p10 7717, p25 7717, p50 7742, p75 7742, p90 7767, p95 7791, p99 9555
- fix (common source) `f7b3066` #1 (run/file 36571079144, res 1): **caead_open_reject_samekey** FAIL, k=1, max |t| 52.445 at p90, raw t 0.049
  - class0: n 500373, p1 15288, p5 15288, p10 15312, p25 15313, p50 15337, p75 15362, p90 15410, p95 15484, p99 22687
  - class1: n 499627, p1 15288, p5 15288, p10 15312, p25 15313, p50 15337, p75 15362, p90 15410, p95 15484, p99 22932
- fix (common source) `f7b3066` #2 (run/file 36571807564, res 1): **msg_open_reject** INCONCLUSIVE→FAIL, k=1, max |t| 9.146 at p95, raw t 1.387
  - class0: n 499472, p1 8698, p5 8722, p10 8722, p25 8746, p50 8747, p75 8771, p90 8771, p95 8869, p99 8918
  - class1: n 500528, p1 8698, p5 8722, p10 8722, p25 8746, p50 8747, p75 8747, p90 8771, p95 8869, p99 8918
- fix (common source) `f7b3066` #2 (run/file 36571807564, res 1): **caead_open_reject** FAIL, k=1, max |t| 27.36 at p75, raw t 0.541
  - class0: n 500089, p1 15386, p5 15410, p10 15435, p25 15459, p50 15484, p75 15509, p90 15557, p95 15607, p99 23814
  - class1: n 499911, p1 15386, p5 15410, p10 15435, p25 15459, p50 15484, p75 15509, p90 15558, p95 15607, p99 23275
- fix (common source) `f7b3066` #2 (run/file 36571807564, res 1): **caead_derive** FAIL, k=1, max |t| 22.579 at p95, raw t -1.402
  - class0: n 500053, p1 1127, p5 1151, p10 1151, p25 1151, p50 1152, p75 1152, p90 1176, p95 1225, p99 1568
  - class1: n 499947, p1 1127, p5 1151, p10 1151, p25 1151, p50 1152, p75 1152, p90 1176, p95 1225, p99 1568
- fix (common source) `f7b3066` #2 (run/file 36571807564, res 1): **caead_aead_reject** FAIL, k=1, max |t| 24.015 at p95, raw t -0.874
  - class0: n 499869, p1 7742, p5 7766, p10 7767, p25 7791, p50 7815, p75 7840, p90 7864, p95 7865, p99 8012
  - class1: n 500131, p1 7742, p5 7766, p10 7767, p25 7791, p50 7815, p75 7840, p90 7840, p95 7865, p99 8012
- fix (common source) `f7b3066` #2 (run/file 36571807564, res 1): **caead_open_reject_samekey** FAIL, k=1, max |t| 13.941 at p75, raw t 0.707
  - class0: n 500418, p1 15361, p5 15362, p10 15386, p25 15410, p50 15435, p75 15460, p90 15533, p95 15606, p99 17321
  - class1: n 499582, p1 15361, p5 15362, p10 15386, p25 15410, p50 15435, p75 15460, p90 15533, p95 15606, p99 17321
- fix (common source) `f7b3066` #3 (run/file 36572303711, res 2): **caead_aead_reject** FAIL, k=1, max |t| 12.966 at p95, raw t -0.417
  - class0: n 499953, p1 5786, p5 5804, p10 5810, p25 5822, p50 5836, p75 5852, p90 5868, p95 5878, p99 5914
  - class1: n 500047, p1 5788, p5 5804, p10 5812, p25 5822, p50 5836, p75 5852, p90 5868, p95 5878, p99 5918
- fix (common source) (macOS) `f7b3066` #0 (run/file macos-arm64-fix-f7b3066-attempt0.json, res 1): **caead_derive** INCONCLUSIVE→FAIL, k=17, max |t| 9.679 at p75, raw t 1.001
  - class0: n 500204, p1 111, p5 112, p10 113, p25 114, p50 115, p75 118, p90 120, p95 122, p99 126
  - class1: n 499796, p1 111, p5 112, p10 113, p25 114, p50 115, p75 118, p90 120, p95 122, p99 126
- fix (common source) (macOS) `f7b3066` #1 (run/file macos-arm64-fix-f7b3066-attempt1.json, res 1): **msg_open_reject** FAIL, k=2, max |t| 10.606 at p75, raw t 2.561
  - class0: n 500896, p1 117, p5 117, p10 118, p25 120, p50 121, p75 124, p90 126, p95 127, p99 133
  - class1: n 499104, p1 116, p5 117, p10 118, p25 120, p50 121, p75 124, p90 126, p95 127, p99 133
- fix (common source) (macOS) `f7b3066` #1 (run/file macos-arm64-fix-f7b3066-attempt1.json, res 1): **caead_derive** INCONCLUSIVE→FAIL, k=16, max |t| 9.443 at p75, raw t 0.015
  - class0: n 500642, p1 104, p5 105, p10 106, p25 107, p50 108, p75 110, p90 113, p95 115, p99 119
  - class1: n 499358, p1 104, p5 105, p10 106, p25 107, p50 108, p75 110, p90 113, p95 114, p99 119
- fix (common source) (macOS) `f7b3066` #2 (run/file macos-arm64-fix-f7b3066-attempt2.json, res 1): **caead_derive** INCONCLUSIVE→FAIL, k=17, max |t| 9.82 at p99, raw t 2.78
  - class0: n 499169, p1 110, p5 111, p10 111, p25 113, p50 115, p75 118, p90 121, p95 123, p99 127
  - class1: n 500831, p1 110, p5 110, p10 111, p25 113, p50 115, p75 118, p90 121, p95 123, p99 127
