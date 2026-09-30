# ct key-swap experiment and sensitivity control (WEISUNG M2-5 A, B; report only)

Throwaway branch `diag/ct-keyswap`, commit `a2095a9` = `m02-proto` `355d641` plus the bench changes below. It
changes no threshold, floor, rule or verdict, and it is not for merge. The gate's targets, samples, controls and
ADR-041 verdict run unchanged. The additions are:

- `caead_open_reject_keyswap`: `caead_open_reject` with the two key constants exchanged. The message is sealed
  under `other` (= `k` with byte 0 ⊕ 1). Class 0 opens with `k` as the wrong key (COM and tag fail). Class 1 opens
  with `other` as the right key on the ciphertext tampered at byte 100 (COM ok, tag fails).
- `caead_open_reject_wrongkey_only`: both classes are wrong-key rejects of the same untampered ciphertext, which is
  sealed under `k`. Class 0 uses `k` with byte 0 ⊕ 1 and class 1 uses `k` with byte 0 ⊕ 2. The classes differ in
  key contents only, not in semantics.
- `min_leak_control` (the report's top-level `sensitivity_control`, which is outside every verdict): a 32-byte
  comparison with a byte-wise early exit, reading each byte through `black_box`. Class 0 differs in byte 31 (32
  byte steps) and class 1 in byte 30 (it exits one byte step early). Each call makes 256 comparisons, as
  `tag_compare` does. It uses `tag_compare`'s calibrated `k` and `N`, is measured once after the targets and is
  analysed like a target.

Runs: macOS arm64 (local, `cargo xtask step ct`) 3×. Linux x86_64 `linux-ct` dispatched 6× on the branch
(`gh workflow run ci.yml --ref diag/ct-keyswap -f suite=ct`): 36660962382, 36661346822, 36661863996, 36662314808,
36662991110 and 36663462640. Each report is stored unmodified as `<platform>-a2095a9-run<id>.json`.

## Runners

| run | runner timer | CAEAD call median | run verdict (gate targets, ADR-041) |
|---|---|---|---|
| macOS-1/2/3 | cntvct_el0, tick 41.667 ns, res 1, q_eff 1 tick (41.67 ns) | 7.7 µs | PASS / PASS / PASS |
| 36660962382 | tsc/rdtscp, tick 0.385 ns, res 2, q_eff 2 ticks (0.77 ns): **fine timer** | 4.3 µs | FAIL (`tag_compare` only: p75, −1.08 / −1.42 q_eff, −0.83 / −1.09 ns) |
| 36661346822 | tsc/rdtscp, tick 0.385 ns, res 26, q_eff 26 ticks (10.02 ns) | 8.5 µs | PASS |
| 36661863996 | tsc/rdtscp, tick 0.409 ns, res 1, samples' lattice ≈ 24.5 ticks (10.0 ns) | 7.6 µs | PASS |
| 36662314808 | as above | 7.6 µs | PASS |
| 36662991110 | as above | 7.6 µs | PASS |
| 36663462640 | as above | 7.6 µs | PASS |

None of the six dispatches ran on the 0.358 ns-tick runner type of PR run 36651079069. One ran on a fine-timer
runner (36660962382), which has the same resolution of 2 ticks and lattice gap of 2 but a different TSC frequency
(2.60 vs 2.79 GHz). On that runner `caead_open_reject` shifted by +0.19 / +0.11 ns (0.25 / 0.15 q_eff), not by the
+5 ns of the PR run.

## A. Key swap

t = (mean class 0 − mean class 1) / SE, so + means class 0 is slower. Δ is in ns and in the target's q_eff. The crop
is the target's decisive crop. "reproduced sign" means both measurements have |t| > 4.5 with the same sign.

| run | target | q_eff (ticks / ns) | verdict | crop | t1 / t2 | Δ1 / Δ2 (ns) | Δ1 / Δ2 (q_eff) | reproduced sign |
|---|---|---|---|---|---|---|---|---|
| macOS-1 | open_reject | 1 / 41.67 | PASS | p95 | −3.1 / −1.3 | −0.48 / −0.20 | −0.01 / −0.00 | — |
| | keyswap | 1 / 41.67 | PASS | p50 | −2.5 / −2.4 | −0.12 / −0.12 | −0.00 / −0.00 | — |
| | wrongkey_only | 1 / 41.67 | PASS | p90 | +4.4 / −1.3 | +1.15 / −0.32 | +0.03 / −0.01 | — |
| macOS-2 | open_reject | 1 / 41.67 | PASS | raw | −1.6 / −1.2 | −1.33 / −0.91 | −0.03 / −0.02 | — |
| | keyswap | 1 / 41.67 | PASS | p75 | +1.1 / −0.0 | +0.20 / −0.00 | +0.00 / −0.00 | — |
| | wrongkey_only | 1 / 41.67 | PASS | p95 | −2.0 / +1.2 | −0.53 / +0.35 | −0.01 / +0.01 | — |
| macOS-3 | open_reject | 1 / 41.67 | PASS | p90 | +27.3 / +1.4 | +1.43 / +0.14 | +0.03 / +0.00 | — |
| | keyswap | 1 / 41.67 | PASS | p50 | +0.6 / +0.4 | +0.03 / +0.03 | +0.00 / +0.00 | — |
| | wrongkey_only | 1 / 41.67 | PASS | p75 | −3.4 / +0.1 | −0.26 / +0.00 | −0.01 / +0.00 | — |
| 36660962382 (fine) | open_reject | 2 / 0.77 | SUB_QUANTUM_SHIFT | p50 | +10.4 / +6.3 | +0.19 / +0.11 | +0.25 / +0.15 | + |
| | keyswap | 2 / 0.77 | PASS | p50 | −2.3 / −1.7 | −0.05 / −0.03 | −0.06 / −0.04 | — |
| | wrongkey_only | 2 / 0.77 | SUB_QUANTUM_SHIFT | p75 | −7.4 / −10.1 | −0.14 / −0.25 | −0.18 / −0.33 | − |
| 36661346822 | open_reject | 26 / 10.02 | SUB_QUANTUM_SHIFT | p95 | +21.5 / +33.3 | +1.27 / +1.94 | +0.13 / +0.19 | + |
| | keyswap | 26 / 10.02 | SUB_QUANTUM_SHIFT | p95 | −74.3 / −8.1 | −4.57 / −0.42 | −0.46 / −0.04 | − |
| | wrongkey_only | 26 / 10.02 | SUB_QUANTUM_SHIFT | p75 | +5.2 / +8.0 | +0.20 / +0.32 | +0.02 / +0.03 | + |
| 36661863996 | open_reject | 24.571 / 10.05 | PASS | p90 | −8.4 / +83.0 | −0.16 / +1.73 | −0.02 / +0.17 | — (flip) |
| | keyswap | 24.5 / 10.02 | SUB_QUANTUM_SHIFT | p75 | −50.8 / −37.7 | −1.06 / −0.80 | −0.11 / −0.08 | − |
| | wrongkey_only | 24.5 / 10.02 | PASS | p90 | −11.5 / +8.4 | −0.25 / +0.19 | −0.03 / +0.02 | — (flip) |
| 36662314808 | open_reject | 24.375 / 9.97 | SUB_QUANTUM_SHIFT | p95 | +49.4 / +34.8 | +1.39 / +0.94 | +0.14 / +0.09 | + |
| | keyswap | 24.571 / 10.05 | PASS | p95 | +86.4 / −82.8 | +2.31 / −2.40 | +0.23 / −0.24 | — (flip) |
| | wrongkey_only | 24.5 / 10.02 | SUB_QUANTUM_SHIFT | p95 | +6.2 / +33.9 | +0.20 / +0.97 | +0.02 / +0.10 | + |
| 36662991110 | open_reject | 24.444 / 10.00 | SUB_QUANTUM_SHIFT | p50 | −5.9 / −31.4 | −0.33 / −1.84 | −0.03 / −0.18 | − |
| | keyswap | 24.571 / 10.05 | PASS | p90 | +33.0 / −12.3 | +0.94 / −0.65 | +0.09 / −0.07 | — (flip) |
| | wrongkey_only | 24.556 / 10.04 | SUB_QUANTUM_SHIFT | p95 | +14.9 / +19.9 | +0.70 / +0.86 | +0.07 / +0.09 | + |
| 36663462640 | open_reject | 24.571 / 10.05 | SUB_QUANTUM_SHIFT | p75 | +49.2 / +10.1 | +1.03 / +0.24 | +0.10 / +0.02 | + |
| | keyswap | 24.429 / 9.99 | SUB_QUANTUM_SHIFT | p90 | +8.0 / +45.9 | +0.24 / +1.71 | +0.02 / +0.17 | + |
| | wrongkey_only | 24.444 / 10.00 | SUB_QUANTUM_SHIFT | p95 | −25.5 / −42.4 | −1.24 / −1.16 | −0.12 / −0.12 | − |

Pooled over the 12 Linux measurements per target (6 runs × first/second), the counts are measurements with
t > 4.5 (+) or t < −4.5 (−) at a fixed crop:

| crop | open_reject + / − | keyswap + / − | wrongkey_only + / − |
|---|---|---|---|
| p50 | 8 / 3 | 2 / 6 | 3 / 4 |
| p75 | 9 / 2 | 2 / 8 | 5 / 5 |
| p90 | 8 / 2 | 4 / 7 | 6 / 4 |
| p95 | 8 / 3 | 4 / 6 | 6 / 4 |

macOS has 2 measurements out of 18 (three targets × 3 runs × 2) with any crop |t| > 4.5. Both are `open_reject`:
run 2 second at p50, −7.9 (its first is −1.6), and run 3 first at p75–p99, up to +27.3 (its second is +1.4).
Neither reproduces.

## B. Sensitivity control `min_leak_control`

Δ = mean(class 0) − mean(class 1), so + is expected because class 0 takes one more byte step. The per-comparison
value is derived as raw Δ / 256; it was not measured on its own.

| run | runner timer | k | N | q_eff (ticks / ns) | max \|t\| (crop) | raw t | Δ at max crop (ns / q_eff) | raw Δ (ns / q_eff) | per comparison (ns / q_eff) |
|---|---|---|---|---|---|---|---|---|---|
| macOS-1 | cntvct_el0, 41.667 ns | 1 | 10⁶ | 1 / 41.67 | 814 (p99) | 341 | +151.3 / +3.63 | +156.5 / +3.76 | +0.61 / +0.015 |
| macOS-2 | cntvct_el0, 41.667 ns | 1 | 10⁶ | 1 / 41.67 | 723 (p99) | 274 | +150.6 / +3.61 | +156.3 / +3.75 | +0.61 / +0.015 |
| macOS-3 | cntvct_el0, 41.667 ns | 1 | 10⁶ | 1 / 41.67 | 1488 (p90) | 368 | +134.2 / +3.22 | +151.6 / +3.64 | +0.59 / +0.014 |
| 36660962382 | rdtscp 0.385 ns, res 2 (fine) | 1 | 10⁶ | 2 / 0.77 | 691 (p50) | 111 | −117.5 / −152.7 | +132.8 / +172.7 | +0.52 / +0.675 |
| 36661346822 | rdtscp 0.385 ns, res 26 | 1 | 10⁶ | 26 / 10.02 | 4437 (p75) | 178 | +244.7 / +24.4 | +279.0 / +27.9 | +1.09 / +0.109 |
| 36661863996 | rdtscp 0.409 ns, lattice 24.5 | 1 | 10⁶ | 24.5 / 10.02 | 1706 (p50) | 203 | +343.1 / +34.2 | +454.6 / +45.4 | +1.78 / +0.177 |
| 36662314808 | rdtscp 0.409 ns, lattice 24.5 | 1 | 10⁶ | 24.5 / 10.02 | 1470 (p50) | 190 | +336.5 / +33.6 | +459.8 / +45.9 | +1.80 / +0.179 |
| 36662991110 | rdtscp 0.409 ns, lattice 24.5 | 1 | 10⁶ | 24.5 / 10.02 | 1689 (p50) | 144 | +341.8 / +34.1 | +457.6 / +45.7 | +1.79 / +0.178 |
| 36663462640 | rdtscp 0.409 ns, lattice 24.5 | 1 | 10⁶ | 24.5 / 10.02 | 1850 (p50) | 195 | +348.7 / +34.8 | +453.0 / +45.2 | +1.77 / +0.177 |

On the fine runner, the p50-cropped Δ is negative while the raw Δ is positive. The cropped statistic compares
only the samples below the pooled median, and on that runner the control's two classes barely overlap. The raw Δ
is the effect.

## Reading (for the reviewer; no verdict or rule change)

1. **The sign does not follow the semantics.** `open_reject` and `keyswap` have the same semantics: class 0 is
   the wrong key, and class 1 is the right key on a tampered ciphertext. On Linux their significant measurements
   lean in opposite directions (p75: 9+/2− vs 2+/8−). Each has runs where the two measurements are significant with
   opposite signs: 36661863996 `open_reject` −8.4/+83.0, 36662314808 `keyswap` +86.4/−82.8 and 36662991110
   `keyswap` +33.0/−12.3.
   `open_reject` reproduced with class 0 *faster* in 36662991110 (−5.9/−31.4). This contradicts observation (3) in
   the M2 report §8, where every significant run had class 0 slower. `wrongkey_only` has no semantic difference
   between its classes. It shows reproduced shifts in 5 of 6 Linux runs, with both signs and the same magnitude
   (|Δ| ≤ 1.24 ns), and |t| up to 42.
2. **The swap is a relabelling in this bench.** The bench draws a fresh random seed per run (`Stream::new`,
   `benches/ct.rs:567–572`). Every measurement draws `k`, the plaintext and the nonce again (`evaluate` calls
   `target.run` for each measurement, `benches/ct.rs:1001–1003`). `keyswap` with `k' = other` is therefore
   `open_reject` with `k'` in the role of `k`: the two targets have the same input distribution. The key-swap
   cannot test fixed key contents. It gives a replication with a different code instance (separate monomorphised
   `measure`/closures) and position in the run. The opposite leanings of two targets with the same semantics and
   the same input distribution point to an incidental factor: the drawn contents, the code instance or the run
   position. Class semantics would give both targets the same sign. Pinning the key contents would need a fixed
   `k` shared across targets or across runs. That is a bench change I have not made.
3. **Magnitude.** On the ≈ 10 ns runners every shift is ≤ 0.46 q_eff (≤ 4.6 ns). On the fine runner the three
   targets stay ≤ 0.33 q_eff (≤ 0.25 ns). On macOS nothing reproduces.
4. **Sensitivity.** The control is detected on every runner, with max |t| 691–4437 and raw Δ 28–173 q_eff per
   sample. Divided by the 256 comparisons per call, one byte step of early exit costs 0.52–1.80 ns. That is
   0.015–0.18 q_eff on macOS and the ≈ 10 ns runners, and 0.67 q_eff on the fine runner. So a single one-byte
   early exit in one comparison per call is below the ADR-041 effect floor of 1 q_eff on every runner seen. It
   becomes ≥ 1 q_eff only when repeated, as the 256-fold loop of the compare targets does. This is derived
   (Δ / 256), not measured separately.
5. **Code.** Neither `Caead::open` nor the AEAD crate has a class-dependent software path; see the M2 report §8.
   The harness is class-symmetric: `blend` builds its mask arithmetically (`benches/ct.rs:1112`). `measure`
   prepares, allocates and times both classes identically (`benches/ct.rs:593–626`).
