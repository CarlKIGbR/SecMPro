# ct gate under ADR-041 Amendment 1 (WEISUNG M2-6 C)

Head `6b9da3b` on `m02-proto`:

- `ae2ac52`: the amendment text.
- `31d13de`: the implementation — `CT_EFFECT_FLOOR_NS = 10.0`, floor `max(1 q_eff, 10 ns)`, `SUB_FLOOR_SHIFT`,
  and the mandatory `min_leak_control`.
- `6b9da3b`: the gate's recheck of the sensitivity control made exact to the report's rounding (below).

Thresholds, sample counts, the positive control, the inline A/A control and batching are unchanged. Every report
in this directory is stored as written by the bench (`target/ct-report.json`).

## Runs

- **Linux, `linux-ct`:** dispatched on `m02-proto` (`gh workflow run ci.yml --ref m02-proto -f suite=ct`), one at a
  time, 8 dispatches (the WEISUNG's maximum). Since M2 review C2 the dispatch lives in its own workflow and the job
  is `dispatch-ct`: `gh workflow run ci-dispatch.yml --ref <branch> -f suite=ct` (dispatchable once the file is on
  `main`); `ci.yml` no longer has a dispatch trigger.
  - 3 on `31d13de`: 36677648129, 36678360108, 36678826377;
  - 5 on `6b9da3b`: 36679955738, 36680376550, 36680797237, 36681396211, 36681989835.
- **macOS arm64, local `cargo xtask step ct`:** 3 on `31d13de` and 3 on `6b9da3b`. The second of the `6b9da3b`
  runs is the ct step of the local ci-full.

**No dispatch landed on a fine-timer runner** (tick ≤ 0.4 ns with a resolution of 1–2 ticks). The runners were:

| runner | runs | effective quantum |
|---|---|---|
| tick 0.385 ns, resolution 26 | 36677648129, 36679955738, 36680376550, 36680797237, 36681396211 | 10.0 ns |
| tick 0.409 ns, resolution 1 | 36678360108, 36678826377, 36681989835 | the samples lie on a ≈ 24.5-tick lattice (10.0 ns) |

For the fine-timer case, the section "Fine-timer case" below recomputes the verdict from the recorded samples of the
two earlier fine-timer reports. That is a recomputation, not a new measurement.

**Gate defect found by this evidence, and fixed in `6b9da3b`.** Run 36678826377 on `31d13de` wrote run verdict PASS
with `min_leak_control` raw Δ 450.0 ns against a floor of 10.02 ns. The gate refused the report: "run verdict PASS
although the sensitivity control did not reach the floor". The cause was the gate's recheck:

- It compared `floor_ns` (rounded to 4 decimals) with `q_eff_ticks` (rounded to 3 decimals) × the tick length, with
  1 ppm of slack.
- On the lattice runners the floor is exactly one q_eff (24.4928 ticks, printed next to a q_eff of 24.493), so the
  rounding alone made "floor ≥ q_eff" false.

`6b9da3b` rechecks in ticks and allows exactly half a unit of each printed place. The regression test uses this
run's numbers. The bench and the verdict did not change, so the three `31d13de` reports are kept as evidence;
36678826377 counts as a PASS report whose gate step failed on that defect.

## Summary

- Run verdict PASS in all 14 reports, and every gate step on `6b9da3b` passed (5 Linux, 3 macOS).
- No target has a reproduced Δ ≥ floor anywhere (no FAIL, no STOP). The largest sub-floor shifts:
  - `msg_open_reject`: 0.53 floors (p95, 36678826377, second measurement; the first was 0.01);
  - `caead_open_reject_samekey`: 0.49 floors (p99, 36680797237).
- Inline A/A control: max |t| ≤ 3.16 in every run (threshold 4.5).
- `min_leak_control` reached the floor in every run:
  - macOS: raw Δ ≈ 154 ns on a 41.67 ns floor (3.7–3.8 floors);
  - resolution-26 runners: 218–282 ns (21.8–28.1 floors);
  - lattice runners: ≈ 451 ns (44.9–45.1 floors).

### Per run

| run | runner timer | targets' q_eff (ticks / ns) | floor used (ns) | A/A max \|t\| | min_leak raw Δ (ns) | min_leak Δ / floor | run verdict | non-PASS targets (verdict at crop: Δ1 / Δ2 in floors) |
|---|---|---|---|---|---|---|---|---|
| 36677648129 (31d13de) | tsc/rdtscp, tick 0.385 ns, res 26, clock q_eff 26 | 26.0 / 10.01 | 10.02 | 2.27 | +221.2 (floor 10.01) | 22.1 (reached) | PASS | tag_compare SUB_FLOOR_SHIFT at p95: -0.07 / -0.11; caead_derive SUB_FLOOR_SHIFT at p75: -0.04 / -0.10; caead_aead_reject SUB_FLOOR_SHIFT at p75: +0.01 / +0.01; caead_open_reject_samekey SUB_FLOOR_SHIFT at p99: -0.35 / -0.28 |
| 36678360108 (31d13de) | tsc/rdtscp, tick 0.409 ns, res 1, clock q_eff 1 | 1.0–24.6 / 0.41–10.05 | 10.00–10.05 | 2.02 | +451.5 (floor 10.02) | 45.1 (reached) | PASS | msg_open_reject SUB_FLOOR_SHIFT at p95: -0.03 / -0.18; caead_open_reject SUB_FLOOR_SHIFT at p95: +0.09 / +0.02; caead_aead_reject SUB_FLOOR_SHIFT at p90: +0.03 / +0.01; caead_open_reject_samekey SUB_FLOOR_SHIFT at p90: +0.09 / +0.03 |
| 36678826377 (31d13de) | tsc/rdtscp, tick 0.409 ns, res 1, clock q_eff 1 | 1.0–24.6 / 0.41–10.06 | 10.00–10.06 | 1.79 | +450.0 (floor 10.02) | 44.9 (reached) | PASS | tag_compare SUB_FLOOR_SHIFT at p50: -0.01 / -0.00; msg_open_reject SUB_FLOOR_SHIFT at p95: -0.01 / -0.53; caead_derive SUB_FLOOR_SHIFT at p95: +0.09 / +0.02; caead_open_reject_samekey SUB_FLOOR_SHIFT at p75: -0.07 / -0.05 |
| 36679955738 | tsc/rdtscp, tick 0.385 ns, res 26, clock q_eff 26 | 26.0 / 10.01 | 10.02 | 2.11 | +218.3 (floor 10.01) | 21.8 (reached) | PASS | tag_compare SUB_FLOOR_SHIFT at p95: -0.07 / -0.05; msg_open_reject SUB_FLOOR_SHIFT at p99: -0.02 / -0.02; caead_open_reject SUB_FLOOR_SHIFT at p95: -0.06 / -0.06; caead_derive SUB_FLOOR_SHIFT at p50: -0.04 / -0.04; caead_aead_reject SUB_FLOOR_SHIFT at p95: +0.01 / +0.01; caead_com_compare SUB_FLOOR_SHIFT at p90: +0.01 / +0.01; caead_open_reject_samekey SUB_FLOOR_SHIFT at p95: -0.24 / -0.27 |
| 36680376550 | tsc/rdtscp, tick 0.385 ns, res 26, clock q_eff 26 | 26.0 / 10.02 | 10.02 | 2.05 | +218.0 (floor 10.02) | 21.8 (reached) | PASS | tag_compare SUB_FLOOR_SHIFT at p95: -0.07 / -0.06; caead_open_reject SUB_FLOOR_SHIFT at p90: +0.03 / +0.08; caead_open_reject_samekey SUB_FLOOR_SHIFT at p95: -0.33 / -0.21 |
| 36680797237 | tsc/rdtscp, tick 0.385 ns, res 26, clock q_eff 26 | 26.0 / 10.02 | 10.02 | 2.49 | +267.6 (floor 10.02) | 26.7 (reached) | PASS | msg_open_reject SUB_FLOOR_SHIFT at p99: +0.07 / +0.05; caead_open_reject SUB_FLOOR_SHIFT at p50: +0.26 / +0.04; caead_derive SUB_FLOOR_SHIFT at p50: +0.02 / +0.01; caead_open_reject_samekey SUB_FLOOR_SHIFT at p99: -0.49 / -0.40 |
| 36681396211 | tsc/rdtscp, tick 0.385 ns, res 26, clock q_eff 26 | 26.0 / 10.01 | 10.02 | 2.06 | +281.5 (floor 10.02) | 28.1 (reached) | PASS | tag_compare SUB_FLOOR_SHIFT at p95: -0.08 / -0.06; msg_open_reject SUB_FLOOR_SHIFT at p50: -0.09 / -0.01; caead_open_reject SUB_FLOOR_SHIFT at p95: +0.34 / +0.15; caead_com_compare SUB_FLOOR_SHIFT at p95: +0.01 / +0.01; caead_open_reject_samekey SUB_FLOOR_SHIFT at p75: -0.17 / -0.15 |
| 36681989835 | tsc/rdtscp, tick 0.409 ns, res 1, clock q_eff 1 | 1.0–24.5 / 0.41–10.02 | 10.00–10.02 | 2.33 | +451.6 (floor 10.02) | 45.1 (reached) | PASS | tag_compare SUB_FLOOR_SHIFT at p75: +0.01 / +0.01; caead_open_reject SUB_FLOOR_SHIFT at p75: -0.09 / -0.07; caead_derive SUB_FLOOR_SHIFT at p95: +0.02 / +0.03; caead_aead_reject SUB_FLOOR_SHIFT at p90: -0.06 / -0.01; caead_open_reject_samekey SUB_FLOOR_SHIFT at p90: +0.05 / +0.03 |
| macOS-1 (31d13de) | cntvct_el0, tick 41.667 ns, res 1, clock q_eff 1 | 1.0 / 41.67 | 41.67 | 3.16 | +153.7 (floor 41.67) | 3.7 (reached) | PASS | caead_derive SUB_FLOOR_SHIFT at p95: +0.02 / +0.02 |
| macOS-2 (31d13de) | cntvct_el0, tick 41.667 ns, res 1, clock q_eff 1 | 1.0 / 41.67 | 41.67 | 2.51 | +153.8 (floor 41.67) | 3.7 (reached) | PASS | — |
| macOS-3 (31d13de) | cntvct_el0, tick 41.667 ns, res 1, clock q_eff 1 | 1.0 / 41.67 | 41.67 | 2.28 | +156.8 (floor 41.67) | 3.8 (reached) | PASS | caead_derive SUB_FLOOR_SHIFT at p75: +0.03 / +0.04 |
| macOS-1 | cntvct_el0, tick 41.667 ns, res 1, clock q_eff 1 | 1.0 / 41.67 | 41.67 | 2.38 | +153.3 (floor 41.67) | 3.7 (reached) | PASS | caead_derive SUB_FLOOR_SHIFT at p90: +0.03 / +0.02 |
| macOS-2 | cntvct_el0, tick 41.667 ns, res 1, clock q_eff 1 | 1.0 / 41.67 | 41.67 | 2.92 | +157.0 (floor 41.67) | 3.8 (reached) | PASS | caead_derive SUB_FLOOR_SHIFT at p75: +0.02 / +0.02 |
| macOS-3 | cntvct_el0, tick 41.667 ns, res 1, clock q_eff 1 | 1.0 / 41.67 | 41.67 | 2.58 | +154.2 (floor 41.67) | 3.7 (reached) | PASS | caead_derive SUB_FLOOR_SHIFT at p75: +0.02 / +0.03 |

### Per target (P = PASS, S = SUB_FLOOR_SHIFT with max |Δ| of both measurements at the deciding crop in floors, F = FAIL)

| target | 36677648129 (31d13de) | 36678360108 (31d13de) | 36678826377 (31d13de) | 36679955738 | 36680376550 | 36680797237 | 36681396211 | 36681989835 | macOS-1 (31d13de) | macOS-2 (31d13de) | macOS-3 (31d13de) | macOS-1 | macOS-2 | macOS-3 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `control_variable_time_compare` | P | P | P | P | P | P | P | P | P | P | P | P | P | P |
| `tag_compare` | S 0.11 | P | S 0.01 | S 0.07 | S 0.07 | P | S 0.08 | S 0.01 | P | P | P | P | P | P |
| `msg_open_reject` | P | S 0.18 | S 0.53 | S 0.02 | P | S 0.07 | S 0.09 | P | P | P | P | P | P | P |
| `caead_open_reject` | P | S 0.09 | P | S 0.06 | S 0.08 | S 0.26 | S 0.34 | S 0.09 | P | P | P | P | P | P |
| `sas` | P | P | P | P | P | P | P | P | P | P | P | P | P | P |
| `caead_derive` | S 0.10 | P | S 0.09 | S 0.04 | P | S 0.02 | P | S 0.03 | S 0.02 | P | S 0.04 | S 0.03 | S 0.02 | S 0.03 |
| `caead_aead_reject` | S 0.01 | S 0.03 | P | S 0.01 | P | P | P | S 0.06 | P | P | P | P | P | P |
| `caead_com_compare` | P | P | P | S 0.01 | P | P | S 0.01 | P | P | P | P | P | P | P |
| `caead_open_reject_samekey` | S 0.35 | S 0.09 | S 0.07 | S 0.27 | S 0.33 | S 0.49 | S 0.17 | S 0.05 | P | P | P | P | P | P |

Column notes:

- "floor used" is `max(1 q_eff, 10 ns)` per measurement, as a range over the run's targets. On macOS the floor is
  one quantum (41.67 ns); on the Linux runners seen it is ≈ 10 ns.
- The per-run table lists non-PASS targets with Δ at the deciding crop in floors (first / second measurement).
- The per-target table gives, for a sub-floor shift, the larger |Δ| of the two measurements in floors.

## Fine-timer case (recomputed from recorded samples)

The verdict of Amendment 1 is applied to the per-crop class statistics already recorded in two fine-timer reports:

- PR run 36651079069 (`0804f60`; tick 0.358 ns, q_eff 2 ticks = 0.72 ns), whose five FAILs stopped M2;
- `linux-ct` 36660962382 (`a2095a9`, the key-swap branch; tick 0.385 ns, q_eff 2 ticks = 0.77 ns), which failed
  on `tag_compare`.

The rule is the one `decide` applies: a crop is reproduced if |t| > 4.5 in both measurements with the same sign, and
relevant if |Δ| ≥ `max(1 q_eff, 10 ns)` in both. The numbers below are the reports' own `crops` values.

| report | target | ADR-041 verdict (recorded) | Amendment 1 verdict (recomputed) | crop | Δ1 / Δ2 (ns) | floor (ns) | Δ1 / Δ2 (floors) |
|---|---|---|---|---|---|---|---|
| PR 36651079069 (0804f60) | `tag_compare` | FAIL | SUB_FLOOR_SHIFT | p50 | -1.16 / -1.14 | 10.00 / 10.00 | -0.116 / -0.114 |
| PR 36651079069 (0804f60) | `msg_open_reject` | FAIL | SUB_FLOOR_SHIFT | p99 | -0.99 / -0.97 | 10.00 / 10.00 | -0.099 / -0.097 |
| PR 36651079069 (0804f60) | `caead_open_reject` | FAIL | SUB_FLOOR_SHIFT | p50 | +4.97 / +4.71 | 10.00 / 10.00 | +0.497 / +0.471 |
| PR 36651079069 (0804f60) | `sas` | PASS | PASS | — | — | — | — |
| PR 36651079069 (0804f60) | `caead_derive` | SUB_QUANTUM_SHIFT | SUB_FLOOR_SHIFT | p75 | -0.07 / -0.07 | 10.00 / 10.00 | -0.007 / -0.007 |
| PR 36651079069 (0804f60) | `caead_aead_reject` | SUB_QUANTUM_SHIFT | SUB_FLOOR_SHIFT | p99 | +0.45 / +0.50 | 10.00 / 10.00 | +0.045 / +0.050 |
| PR 36651079069 (0804f60) | `caead_com_compare` | FAIL | SUB_FLOOR_SHIFT | p50 | -1.67 / -2.03 | 10.00 / 10.00 | -0.167 / -0.203 |
| PR 36651079069 (0804f60) | `caead_open_reject_samekey` | FAIL | SUB_FLOOR_SHIFT | p99 | +7.70 / +2.20 | 10.00 / 10.00 | +0.770 / +0.220 |
| linux-ct 36660962382 (a2095a9) | `tag_compare` | FAIL | SUB_FLOOR_SHIFT | p75 | -0.83 / -1.09 | 10.00 / 10.00 | -0.083 / -0.109 |
| linux-ct 36660962382 (a2095a9) | `msg_open_reject` | SUB_QUANTUM_SHIFT | SUB_FLOOR_SHIFT | p75 | +0.29 / +1.24 | 10.00 / 10.00 | +0.029 / +0.124 |
| linux-ct 36660962382 (a2095a9) | `caead_open_reject` | SUB_QUANTUM_SHIFT | SUB_FLOOR_SHIFT | p50 | +0.19 / +0.11 | 10.00 / 10.00 | +0.019 / +0.011 |
| linux-ct 36660962382 (a2095a9) | `sas` | PASS | PASS | — | — | — | — |
| linux-ct 36660962382 (a2095a9) | `caead_derive` | SUB_QUANTUM_SHIFT | SUB_FLOOR_SHIFT | p75 | +0.07 / +0.06 | 10.00 / 10.00 | +0.007 / +0.006 |
| linux-ct 36660962382 (a2095a9) | `caead_aead_reject` | PASS | PASS | — | — | — | — |
| linux-ct 36660962382 (a2095a9) | `caead_com_compare` | PASS | PASS | — | — | — | — |
| linux-ct 36660962382 (a2095a9) | `caead_open_reject_samekey` | PASS | PASS | — | — | — | — |
| linux-ct 36660962382 (a2095a9) | `min_leak_control` | (report only) | reached | raw | +132.84 | 10.00 | +13.28 |

Every target that failed under ADR-041 on the fine timer is a `SUB_FLOOR_SHIFT` under Amendment 1, as the WEISUNG
expected. The largest are `caead_open_reject_samekey` at 0.77 / 0.22 floors (p99) and `caead_open_reject` at
0.50 / 0.47 floors. On the fine runner the sensitivity control's raw Δ was 13.3 floors.
