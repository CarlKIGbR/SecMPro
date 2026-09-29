# ct gate under ADR-041 — evidence (WEISUNG M2-4 C)

Head `b8a7915` (`bdf10db` ADR-041 implementation + `b8a7915` re-batching fix), run on the throwaway ref
`diag/ct-adr041` (deleted afterwards; the commits are on `m02-proto`). Linux: `linux-ct` dispatches, one after
the other; macOS arm64: `cargo xtask step ct` locally. Thresholds, samples, positive control and batching rule
unchanged; ADR-041 verdict (`docs/08`).

Cells: verdict (`SQS` = `SUB_QUANTUM_SHIFT`, informative, passes); for non-control targets the crop, t of the
two measurements and Δ of the cropped class means in effective quanta (`q`) of each, at the deciding crop (else
at the first measurement's maximum); for the positive control its max |t|. `re-batched`: targets whose samples
showed a coarser lattice than the clock's quantum and were batched again with it.

## Runs on `b8a7915` (the evidence)

| run | run verdict | A/A max \|t\| | reported res / clock q_eff (ticks) | re-batched | control | tag | msg_open | caead_open | sas | derive | aead | com | samekey |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Linux run 1 — 36621138939 | PASS | 1.96 | 26 / 26 | 0 | PASS (\|t\| 25223) | SQS p95: -47.1/-33.7, Δ -0.07/-0.05 q | SQS p99: -7.1/-11.0, Δ -0.02/-0.03 q | PASS p75: +1.2/-25.9, Δ +0.00/-0.08 q | PASS p90: +1.3/-0.6, Δ +7.09/-3.16 q | PASS p99: -42.7/+10.0, Δ -0.19/+0.05 q | PASS p50: +2.0/-0.6, Δ +0.00/-0.00 q | PASS p95: +1.6/+0.8, Δ +0.00/+0.00 q | SQS p90: -65.9/-50.5, Δ -0.29/-0.22 q |
| Linux run 2 — 36621645926 | PASS | 2.80 | 1 / 1 | 7 | PASS (\|t\| 59399) | SQS p50: +8.7/+8.8, Δ +0.18/+0.18 q | PASS p95: +16.4/-108.3, Δ +0.02/-0.30 q | SQS p90: +20.8/+17.6, Δ +0.10/+0.08 q | PASS p90: -1.2/+0.2, Δ -20.19/+3.07 q | SQS p99: -31.6/-14.0, Δ -0.10/-0.04 q | SQS p75: -4.9/-11.6, Δ -0.01/-0.02 q | PASS p90: -6.9/-1.9, Δ -0.02/-0.01 q | PASS p90: +3.9/+3.0, Δ +0.01/+0.01 q |
| Linux run 3 — 36622240073 | PASS | 2.39 | 26 / 26 | 0 | PASS (\|t\| 25906) | SQS p95: -59.2/-32.1, Δ -0.09/-0.04 q | PASS p50: +4.4/+3.5, Δ +0.01/+0.01 q | PASS p90: -1.8/-2.9, Δ -0.01/-0.02 q | PASS p50: +1.4/+0.2, Δ +12.80/+2.09 q | SQS p50: -10.4/-16.9, Δ -0.04/-0.06 q | PASS p50: +8.7/-4.9, Δ +0.02/-0.02 q | PASS p75: -6.3/-0.1, Δ -0.01/-0.00 q | PASS p90: -11.3/+2.5, Δ -0.06/+0.01 q |
| macOS run 1 (local) | PASS | 2.01 | 1 / 1 | 0 | PASS (\|t\| 42127) | PASS p99: +1.6/+0.5, Δ +0.01/+0.01 q | PASS p50: +2.1/+0.3, Δ +0.00/+0.00 q | PASS p99: +1.9/-0.9, Δ +0.02/-0.01 q | PASS p95: +2.0/-0.9, Δ +11.19/-6.01 q | SQS p50: +7.2/+6.7, Δ +0.02/+0.02 q | PASS p50: +3.2/+2.2, Δ +0.01/+0.01 q | PASS p99: +1.9/-0.8, Δ +0.02/-0.01 q | PASS p95: -2.8/-2.3, Δ -0.02/-0.02 q |
| macOS run 2 (local) | PASS | 1.96 | 1 / 1 | 0 | PASS (\|t\| 68004) | PASS p99: -2.3/-1.1, Δ -0.01/-0.01 q | PASS p75: +2.5/+1.0, Δ +0.00/+0.00 q | PASS p90: -1.0/+0.4, Δ -0.01/+0.00 q | PASS raw: +2.9/+1.9, Δ +29.49/+30.51 q | PASS p50: +4.3/+4.8, Δ +0.01/+0.01 q | PASS p99: +1.8/-0.5, Δ +0.01/-0.00 q | PASS raw: -1.7/+0.3, Δ -0.47/+0.26 q | PASS p75: -2.3/-1.5, Δ -0.01/-0.01 q |
| macOS run 3 (local) | PASS | 2.29 | 1 / 1 | 0 | PASS (\|t\| 43899) | PASS p50: +0.9/+0.2, Δ +0.00/+0.00 q | PASS p50: +6.0/+4.2, Δ +0.01/+0.00 q | PASS p50: +4.4/+3.3, Δ +0.01/+0.00 q | PASS p75: +2.3/+0.2, Δ +9.40/+0.69 q | PASS p99: +4.8/+2.8, Δ +0.03/+0.02 q | PASS p99: +3.4/-1.8, Δ +0.03/-0.01 q | PASS p99: +1.9/+1.2, Δ +0.01/+0.01 q | PASS p99: +1.6/-0.2, Δ +0.01/-0.00 q |

Result: 6/6 runs PASS, the positive control detected in every run, every A/A control ≤ 4.5, every reproduced
shift below one effective quantum (`SUB_QUANTUM_SHIFT`); no target FAILs under ADR-041.

## Superseded runs on `bdf10db` (before the re-batching fix)

Linux run 36620324956 ran on a runner whose samples lie on the ≈ 24.5-tick lattice while the counter reports a
1-tick resolution; the clock's workload probe did not recognise the lattice, so the calibration kept k = 1 and
the positive control (26 quanta) and `caead_derive` (50) were NOT MEASURABLE against the samples' effective
quantum. No target failed. `b8a7915` batches such a target again with its samples' quantum (Linux run 2 above:
seven targets re-batched, `caead_derive` k = 3, 140 quanta).

| run | run verdict | A/A max \|t\| | reported res / clock q_eff (ticks) | re-batched | control | tag | msg_open | caead_open | sas | derive | aead | com | samekey |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Linux run 36619823491 | PASS | 3.18 | 26 / 26 | 0 | PASS (\|t\| 27901) | PASS p90: -2.1/-2.6, Δ -0.00/-0.00 q | SQS p75: +10.8/+10.5, Δ +0.01/+0.01 q | SQS p99: +17.0/+35.6, Δ +0.08/+0.44 q | PASS raw: +1.2/+0.3, Δ +27.32/+16.71 q | PASS p90: +22.2/+0.1, Δ +0.07/+0.00 q | PASS p99: +4.4/+0.2, Δ +0.01/+0.00 q | PASS raw: +1.9/+2.0, Δ +0.66/+0.43 q | SQS p95: -59.0/-54.6, Δ -0.23/-0.18 q |
| Linux run 36620324956 | FAIL | 2.87 | 1 / 1 | 0 | **NM** (\|t\| 44175) | PASS p75: +3.3/+4.6, Δ +0.10/+0.14 q | PASS p90: -16.9/+12.6, Δ -0.02/+0.02 q | SQS p95: +283.6/+217.2, Δ +0.81/+0.63 q | PASS p95: -0.9/+0.7, Δ -24.63/+17.98 q | **NM** | SQS p95: -40.8/-32.0, Δ -0.07/-0.06 q | PASS p95: +1.9/-1.2, Δ +0.01/-0.00 q | SQS p50: +143.6/+104.5, Δ +0.36/+0.24 q |
| macOS run 1 | PASS | 2.20 | 1 / 1 | 0 | PASS (\|t\| 35650) | PASS p75: +0.9/-1.3, Δ +0.00/-0.00 q | SQS p75: +13.1/+11.8, Δ +0.02/+0.01 q | PASS p50: +1.3/-1.4, Δ +0.00/-0.00 q | PASS p75: +1.8/+0.1, Δ +7.05/+0.58 q | SQS p75: +13.2/+7.3, Δ +0.03/+0.02 q | PASS p50: -2.2/+0.7, Δ -0.00/+0.00 q | PASS p75: -1.5/-1.3, Δ -0.01/-0.00 q | PASS p95: -0.9/-0.9, Δ -0.01/-0.00 q |
| macOS run 2 | PASS | 3.52 | 1 / 1 | 0 | PASS (\|t\| 43745) | PASS raw: +1.4/-0.5, Δ +0.11/-0.02 q | SQS p75: +12.1/+10.6, Δ +0.01/+0.02 q | PASS p75: +0.9/+0.1, Δ +0.01/+0.00 q | PASS p50: +1.3/-1.8, Δ +2.11/-2.15 q | SQS p75: +18.1/+13.7, Δ +0.03/+0.03 q | SQS p75: +5.8/+6.3, Δ +0.01/+0.01 q | PASS raw: -2.0/-1.0, Δ -0.14/-0.19 q | PASS p75: -1.9/-0.4, Δ -0.00/-0.00 q |
