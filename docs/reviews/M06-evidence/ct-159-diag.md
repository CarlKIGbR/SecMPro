# CT-DIAG — red `ct` gate on PR run 39040543318 (head 62d8e59): `tr_decrypt_trial_open_position` (WEISUNG M6-CI-12)

Session `M6-CT`, 2026-10-17. Branch `m06-ct-diag` from `62d8e59441e494404f6ad9f8284b2d985923ccdf`. Facts only, no verdict.
No product code changed; no threshold, crop, floor or sample count changed; no `#[ignore]`.

## 0 · Inputs

`git diff --stat 2934cd7..62d8e59` (last green `ct` head → failing head):

```
 crates/secmp-client-core/src/scheduler/core/mod.rs |  47 +++++-
 crates/secmp-client-core/src/scheduler/mod.rs      |  10 +-
 crates/secmp-client-core/src/scheduler/run.rs      |  31 +++-
 crates/secmp-testkit/src/harness/driver.rs         |   2 +
 crates/secmp-testkit/tests/harness/m6_driver_io.rs | 181 ++++++++++++++++++++-
 crates/secmp-testkit/tests/harness/m6_sched_io.rs  |  57 +++++++
 crates/secmp-testkit/tests/harness/m6_tokio_ai.rs  |  19 +++
 docs/06-engineering-standards.md                   |   2 +
 docs/08-decisions.md                               |   2 +
 docs/mutants-accepted.md                           |   1 +
 docs/reviews/M06-evidence/final-nachfix.md         | 123 ++++++++++++++
 docs/reviews/M06-report.md                         |   1 +
 xtask/src/expect.rs                                |   4 +
 xtask/src/policy.rs                                | 181 +++++++++++++++++++++
 14 files changed, 641 insertions(+), 20 deletions(-)
```

`git diff --stat 2934cd7..62d8e59 -- crates/secmp-crypto crates/secmp-proto` is empty. `crates/secmp-testkit/benches/ct.rs` is
unchanged between the two heads too (not in the list). The `secmp-client-core` changes are linked into the bench binary
only through `secmp-testkit`'s dependencies; the bench does not call the scheduler.

The failing run's report (`target/fable/ci/ct159/ct-report.json`, extracted with a throwaway script that prints the report's
fields; "c0−c1" is class 0 minus class 1 at each recorded quantile of `shape`):

```
clock: timer rdtscp tick_ns 0.4089 q_eff_ticks 1.0 resolution_ticks 1 median_delta_ticks 49 lattice_probe {"median_gap": 25, "regular": 1.0, "runs": 2} clocksource tsc
host: {"cpu_model": "AMD EPYC 7763 64-Core Processor", "microcode": "0xffffffff"}
run_verdict: FAIL
== tr_decrypt_trial_open_position  verdict FAIL  crop p90  k 1  aa_passed True  site body MAC
  first: q_eff 1.0 (clock) floor 24.45 ticks, median 130242 ticks, max|t| 62.35 at p90
    delta ticks: raw +11.43 (t 0.69)  p50 +18.34 (t 42.19)  p75 +30.43 (t 60.84)  p90 +42.74 (t 62.35)  p95 +34.26 (t 8.97)  p99 +39.43 (t 4.31)
    c0-c1  p1=+24 p5=+48 p10=+25 p25=+49 p50=+49 p75=+49 p90=+49 p95=+24 p99=+0
  second: q_eff 1.0 (clock) floor 24.45 ticks, median 130193 ticks, max|t| 69.44 at p90
    delta ticks: raw +39.91 (t 2.73)  p50 +19.05 (t 44.92)  p75 +29.27 (t 60.91)  p90 +42.37 (t 69.44)  p95 +23.46 (t 5.89)  p99 +40.54 (t 4.41)
    c0-c1  p1=+25 p5=+49 p10=+49 p25=+49 p50=+49 p75=+25 p90=+48 p95=+25 p99=-73
  aa_control: q_eff 1.0 (clock) floor 24.45 ticks, median 130242 ticks, max|t| 1.63 at p50
== tr_decrypt_reject_skipped  verdict PASS  crop None  k 1  aa_passed True  site body MAC
  first: q_eff 1.0 (clock) floor 24.45 ticks, median 162068 ticks, max|t| 3.29 at p75
    delta ticks: raw +12.50 (t 0.81)  p50 +1.12 (t 2.80)  p75 +1.54 (t 3.29)  p90 +1.91 (t 2.85)  p95 -9.12 (t -1.43)  p99 -5.15 (t -0.49)
    c0-c1  p1=+0 p5=+0 p10=+0 p25=+0 p50=+0 p75=+0 p90=-24 p95=+0 p99=+123
  second: q_eff 1.0 (clock) floor 24.45 ticks, median 161969 ticks, max|t| 96.97 at p90
    delta ticks: raw +26.60 (t 1.58)  p50 +30.87 (t 74.31)  p75 +45.06 (t 95.09)  p90 +64.67 (t 96.97)  p95 +15.16 (t 2.39)  p99 +55.28 (t 5.28)
    c0-c1  p1=+49 p5=+73 p10=+73 p25=+73 p50=+73 p75=+73 p90=+0 p95=+49 p99=-171
  aa_control: q_eff 24.501 (samples) floor 24.50 ticks, median 162116 ticks, max|t| 1.51 at p95
== same_content_control  verdict PASS  crop None  k 1  aa_passed True  site body MAC
  first:  max|t| 1.14 at p90 (q_eff 24.494 samples);  second: max|t| 1.74 at p99 (q_eff 24.5 samples)
```

Other facts I noted from the same report:

- The sample values sit on a lattice of ≈ 24.5 ticks (`lattice_probe.median_gap` 25; the recorded quantiles differ by
  multiples of 24/25 ticks). The class-0 shift is +49 ticks (2 lattice steps) in `tr_decrypt_trial_open_position` and
  +73 ticks (3 steps) in the second measurement of `tr_decrypt_reject_skipped`. `clock.median_delta_ticks`, the median
  delta of two back-to-back timer reads, is also 49.
- For both TR targets the first and second measurements took `q_eff` 1.0 from `clock`, while `same_content_control`,
  and the A/A control of `tr_decrypt_reject_skipped`, took `q_eff` ≈ 24.5 from `samples`. The floor is 24.45 ticks
  (10 ns) either way.

## 1 · Q1 — code path (§7.4 Decrypt on the skipped path, as the bench calls it), lines @62d8e59

What I inspected (no file on this path changed between 62d8e59 and `m06-ct-diag`):

- `crates/secmp-proto/src/tr/ratchet.rs`
  - `decrypt_with` 732–738 → `decrypt_within` 754–787: on `Err` it returns at 762 via `Refused::new` 169–174 (one
    `Box::new(state)` for every rejection).
  - `open` 807–863:
    - length check 815;
    - splits 825–828;
    - `header_ad` / `body_ad` 829–830 (fixed-length `concat`);
    - `dummy` 831;
    - `distinct_skipped_keys` 792–803 (depends on the state only);
    - the trials 834–842: `distinct.iter().map(open_header)` over all distinct skipped keys, then `hk_r`, then `nhk_r`.
      No `break` and no `find`: the iterator is collected in full.
  - `open_header` 368–384: one `Zeroizing<Vec>` of `HEADER_LEN`, then `Aead::open_ct_constant_flow`; the key comes from
    `unwrap_or(dummy)` on `Some` (the same for every skipped key).
  - `select_header` 444–505:
    - `first_opened_cell` (458–469) runs over every trial, with `CellChoice::assign` (masked) for the plaintext, `hk`
      and `n`;
    - `header_n` 417–424 runs on every trial's plaintext (fixed offset);
    - `lookup_skipped` 391–408 runs over every entry: `ct_eq` on `hk` and `n`, masked assign of `found_at` and of all 32
      `mk` bytes per entry, no early exit;
    - `select::path` (the one branch) gives `Path::Skipped` for both classes;
    - then `HeaderV1::decode(&selected)` at 493 and `SecretBytes::from_slice(&*mk)` at 494.
  - The `Selected::Skipped` arm 844–848: `MsgEncrypt::open(&mk, &body_ad, body)?`. It fails at the tag compare for both
    classes; `at` (0 vs 2) is never used on this path.
- `crates/secmp-proto/src/tr/select.rs`:
  - `first_opened` 45–56 (`Choice` arithmetic over every element);
  - `decide` 68–87 (`conditional_assign`, one `match` on the code);
  - `CellChoice::assign` 98–100 (`conditional_assign`);
  - `first_opened_cell` 116–122;
  - `path` 125–134.
- `crates/secmp-crypto/src/aead.rs` `open_ct_constant_flow` 132–166:
  - two `encrypt_inout_detached` passes, one `Zeroizing` heap copy (`again`);
  - `ct_eq` on the tags;
  - masked zeroing of `out`.
  - The early returns at 141/144/157 depend on lengths and on the AEAD's 2^38 bound only.
- `crates/secmp-crypto/src/msg.rs` `MsgEncrypt::open` 106–121: length check, then `MsgKeys::derive` (HKDF, fixed
  length), then `tag` (HMAC over a fixed-length `ad ‖ c`), then `ct_eq`, then return `Err`. The same instructions for
  both classes, up to the key value.
- `crates/secmp-proto/src/wire/cell.rs` `HeaderV1::decode_from` 143–154.

**Answer for trial position: B — none found.** I found no instruction on this path whose execution depends on *which*
trial opened. I checked for each of the following and found none:

- early `break` / `continue`;
- `Option` short-circuit on a trial result;
- a copy made only on success (every trial's `out` is written by the same masked loop; `selected`, `skipped_hk` and `n`
  are written by masked assigns for every trial);
- a `found` flag that changes later iterations;
- a class-dependent allocation (the allocations are the same in number and size for both classes);
- a `subtle` select that is not a select.

**Class-dependent inputs I did find (they depend on the content, not on the trial position).** Facts, no assessment:

- The header that `HeaderV1::decode` at `ratchet.rs:493` decodes is a different public header per class: class 0
  carries A's chain-1 header, class 1 its chain-2 header. They differ in `dh_pk`, `pn`, `ek_pq` and `ct_pq`; both have
  `n = 0`. The decode runs:
  - `X25519Pk::decode_from` → `X25519Public::from_bytes_checked` (`crates/secmp-crypto/src/x25519.rs:140–150`), whose
    `LOW_ORDER_MASKED.contains(&masked)` at 146 compares `[u8; 32]` arrays with `==`, an early-exit compare per table
    entry, over the public `dh_pk`;
  - `MlKem768Ek::decode_from` → `MlKem768Ek::from_bytes` (`crates/secmp-crypto/src/mlkem.rs:123–130`, libcrux
    `validate_public_key`) over the public `ek_pq`;
  - `r.boxed()` for `ct_pq`.
- `mk` is a different 32-byte value per class. It feeds a fixed-length HKDF and HMAC (`msg.rs:42`, `msg.rs:68`).
- In `tr_decrypt_reject_skipped` both classes are chain-1 cells, `n = 0` and `n = 4`, under the same `hk_1`. Their
  headers share `dh_pk`, `ek_pq`, `ct_pq` and `pn` and differ in `n` (and in the per-cell nonce and ciphertext).

## 2 · Diagnosis targets (test-only, `crates/secmp-testkit/benches/ct.rs`, `SECMP_CT_DIAG=trial_open`)

With `SECMP_CT_DIAG=trial_open` the bench measures, in this order:

1. `tr_decrypt_trial_open_position` (production, unchanged);
2. `diag_trial_open_position_swapped`;
3. `diag_trial_open_position_interleaved`;
4. `diag_trial_open_position_same_content`.

Then the inline A/A control runs on these four. The report carries `"secmp_ct_diag":"trial_open"`, and the gate refuses
it because the target set differs from `expect::CT_TARGETS`. Unset or empty, the target set and the run are the
production ones. Any other non-empty value aborts the bench with a reason.

A diagnosis run measures no `tag_compare`, so the sensitivity control is never measured. Only in a diagnosis run, its
"not measured" reason is left out of `run_reason`, so that it does not override the four verdicts. The A/A,
placement and same-content rules are unchanged; the last two find no target of theirs in a diagnosis run.

- **Q2 `diag_trial_open_position_swapped`:** the same fixture construction (`tr_skipped_session_with(.., &[2, 2])`), the
  same receiver and the same `tr_measure` as production, with class 0 = the `hk_2` cell (trial 1, entry 2) and class 1
  = the `hk_1` cell (trial 0, entry 0). Class 1, the `blend` base, is now the `hk_1` cell.
- **Q3 `diag_trial_open_position_interleaved`:** the production classes and cells (`blend`, class 1 the base). The
  pre-check is the one `tr_measure` does, on the receiver. The receiver is then serialised once and restored into an
  arena:
  - the arena is one `Vec<RefCell<Option<RatchetState>>>` of 2 × 8 slots, laid out class 0, class 1, class 0, …;
  - every slot has the same type, size and alignment;
  - the slots are restored with `RatchetState::from_bytes` in slot order, so the two classes' heap parts are allocated
    alternately;
  - sample `i` of class `c` decrypts on slot `2·(i mod 8) + c`.

  How I read the brief: there is no "arena" helper in the bench (ADR-042 Am. 3 is the HX same-content control). The
  only long-lived fixture object in the production target is the one receiver both classes share; the cells are already
  built with no class-selected address (`blend`, ADR-042 Am. 4). So this variant gives each class its own receiver
  copies, interleaved. If the reviewer meant a different layout (for example a fresh clone per sample, or the cells in
  an arena), it is a small change.
- **Q4 `diag_trial_open_position_same_content`:** the production fixture and `tr_measure`, with the `hk_1` cell
  (production class 0) in both classes. `blend` runs with an all-zero delta under the per-class mask (the
  `same_content_control` pattern).

Every diagnosis target has its own claim (site "body MAC", `SiteCheck::Tagged`), and its pre-check passed in both
local runs. `claim_json` also looks the targets up in `DIAG_CLAIMS`, so the report records their site and pre-check.

## 3 · Q5 — local timer, and local Q2–Q4 smoke

Container host: `AMD Ryzen Threadripper PRO 5955WX 16-Cores`, microcode `0xa00820f`.
`clock`: `timer rdtscp`, `tick_ns 0.2500`, `q_eff_ticks 40.0` (`resolution_ticks 40`, `lattice_probe.median_gap 40`),
`median_delta_ticks 80`, clocksource `tsc`.

- Local `q_eff` = 40 ticks = 10.0 ns. In ticks that is above the brief's 24-tick mark, so the runs below count only as
  a smoke.
- In nanoseconds, 20 ns = 80 ticks = 2 local quanta, and the local floor is 40 ticks = 10 ns, the same 10 ns as the CI
  floor.

Command (both runs; this is the executable the gate runs, called the way the gate calls it):

```
cargo bench --locked -p secmp-testkit --features kat --bench ct --no-run
env SECMP_CT_DIAG=trial_open target/release/deps/ct-faacae40b4f5ca2f --bench
```

Full sample counts (1 000 000 per measurement), `k` 1, about 7.5 min per run.

- **Run 1** (`ct-159-diag-local-run1.json`, bench sha256 `f2cb79c4…`): measured before the sensitivity reason was left
  out of diagnosis runs, so every verdict there reads CONTROL_FAIL ("sensitivity control min_leak_control not
  measured"). Measurements:

```
tr_decrypt_trial_open_position         first  p50 -3.85 (t -13.16) p75 -8.51 (t -27.83) p90 -14.56 (t -42.82)   second p50 +1.84 (t 6.43) p75 +6.59 (t 21.81) p90 +15.72 (t 46.59) p95 +28.43 (t 48.22)   A/A max|t| 2.42 raw
diag_trial_open_position_swapped       first  p50 +5.33 (t 17.89) p75 +9.20 (t 30.08) p90 +16.54 (t 47.75)    second max|t| 0.89 at p90                                                          A/A max|t| 1.69 p99
diag_trial_open_position_interleaved   first  p50 +4.85 (t 17.25) p75 +5.29 (t 17.52) p90 +2.19 (t 6.29)      second p50 -4.80 (t -17.01) p75 -10.63 (t -35.20) p90 +21.93 (t 44.19) p95 +137.95 (t 143.52)  A/A max|t| 1.24 p90  decisive_crop p90
diag_trial_open_position_same_content  first  max|t| 2.70 at p99                                             second max|t| 1.69 at p50                                                          A/A max|t| 1.00 p90
```

- **Run 2** (`ct-159-diag-local-run2.json`, bench sha256 `ba76ed14…`, the committed bench): `run_verdict PASS`,
  `run_reason null`.

```
== tr_decrypt_trial_open_position  verdict PASS  crop None  k 1  aa_passed True  site body MAC
  first: q_eff 40.0 (samples) floor 40.00 ticks, median 143680 ticks, max|t| 4.77 at p95
    delta ticks: raw +0.20 (t 0.01)  p50 -0.77 (t -2.81)  p75 -1.24 (t -4.42)  p90 -1.24 (t -4.06)  p95 -2.54 (t -4.77)  p99 +1.68 (t 0.33)
  second: q_eff 40.0 (samples) floor 40.00 ticks, median 143760 ticks, max|t| 22.50 at p90
    delta ticks: raw +35.76 (t 1.89)  p50 +2.94 (t 10.27)  p75 +4.19 (t 14.10)  p90 +7.46 (t 22.50)  p95 +9.64 (t 16.99)  p99 +9.18 (t 1.78)
  aa_control: max|t| 1.04 at p99
== diag_trial_open_position_swapped  verdict PASS  crop None  k 1  aa_passed True  site body MAC
  first: q_eff 40.0 (samples) floor 40.00 ticks, median 144320 ticks, max|t| 6.68 at p50
    delta ticks: raw -0.30 (t -0.02)  p50 +2.00 (t 6.68)  p75 +1.76 (t 5.75)  p90 +1.63 (t 4.81)  p95 +1.67 (t 3.41)  p99 -6.72 (t -1.28)
  second: q_eff 40.0 (samples) floor 40.00 ticks, median 143840 ticks, max|t| 9.33 at p90
    delta ticks: raw -11.43 (t -0.69)  p50 -1.47 (t -5.45)  p75 -1.98 (t -6.95)  p90 -2.99 (t -9.33)  p95 -2.79 (t -4.96)  p99 -13.97 (t -2.70)
  aa_control: max|t| 0.94 at raw
== diag_trial_open_position_interleaved  verdict PASS  crop None  k 1  aa_passed True  site body MAC
  first: q_eff 40.0 (samples) floor 40.00 ticks, median 143720 ticks, max|t| 42.13 at p90
    delta ticks: raw -16.17 (t -0.86)  p50 -5.77 (t -20.71)  p75 -8.62 (t -29.92)  p90 -13.53 (t -42.13)  p95 -16.11 (t -29.23)  p99 -15.56 (t -3.07)
  second: q_eff 40.0 (samples) floor 40.00 ticks, median 143880 ticks, max|t| 29.41 at p90
    delta ticks: raw +46.06 (t 2.42)  p50 +3.39 (t 11.99)  p75 +5.44 (t 18.97)  p90 +9.36 (t 29.41)  p95 +11.39 (t 19.83)  p99 +11.22 (t 2.16)
  aa_control: max|t| 2.08 at p75
== diag_trial_open_position_same_content  verdict PASS  crop None  k 1  aa_passed True  site body MAC
  first: q_eff 40.0 (samples) floor 40.00 ticks, median 143640 ticks, max|t| 1.35 at p99
    delta ticks: raw -3.62 (t -0.18)  p50 -0.00 (t -0.02)  p75 +0.22 (t 0.75)  p90 +0.29 (t 0.87)  p95 +0.53 (t 0.89)  p99 -7.01 (t -1.35)
  second: q_eff 40.0 (samples) floor 40.00 ticks, median 143600 ticks, max|t| 1.28 at p50
    delta ticks: raw +9.69 (t 0.65)  p50 +0.36 (t 1.28)  p75 -0.06 (t -0.21)  p90 +0.28 (t 0.84)  p95 +0.39 (t 0.71)  p99 +0.60 (t 0.12)
  aa_control: max|t| 1.90 at p75
```

Locally, no target shows a shift that reproduces with the same sign in both measurements and reaches the 40-tick floor.
The production target's p90 Δ is −14.56 / +15.72 ticks in run 1 and −1.24 / +7.46 in run 2: the sign changes between
the halves in both runs. The local runs were taken on a different CPU (Zen 3 Threadripper, a 10 ns timer quantum) from
the CI runner (EPYC 7763 VM, a 24.5-tick lattice at 0.409 ns).

## 4 · CI dispatch

`ci-dispatch.yml` had no environment input. Change on `m06-ct-diag`:

- a `workflow_dispatch` input `ct_env` (`type: string`, `default: ""`);
- the `dispatch-ct` job's gate step gets `env: SECMP_CT_DIAG: ${{ inputs.ct_env }}`.

The value reaches the bench as an environment value, never through the shell line. The gate run line
(`cargo xtask step --strict ct`) is unchanged, so `dispatch_full_runs_the_linux_full_line` and the policy workflow
checks stay green (`cargo xtask ci-fast --strict`: PASS). The gate builds the bench and runs it with the caller's
environment; it removes only `SECMP_CT_SCALE`. The report, the progress file and the bench log are uploaded `if:
always()`, also when the gate refuses the diagnosis report.

```
gh workflow run ci-dispatch.yml --ref m06-ct-diag -f suite=ct -f ct_env=trial_open
```

The `ct` step is expected to end red: the gate refuses the report because its target set differs from
`expect::CT_TARGETS`. The data is in the artifact `ct-report-Linux-X64-<sha>-<run_id>-<attempt>` (`ct-report.json`),
and the log line `ct report: {...}` carries the whole report too.

Result of dispatch 39063440795, as reported by the reviewer: all four targets PASS on EPYC 7763 (q_eff 1.0). The
production Δ is ≤ 2.5 ticks in both halves; swapped, interleaved and same_content are ≤ 6 ticks.

## 5 · Repeat mode with fixture-address logging (WEISUNG M6-CT-3)

### 5.1 · What the mode does

`SECMP_CT_DIAG=trial_open_repeat` runs `DIAG_REPEATS` = 8 independent `evaluate`s for each of three targets:

1. `tr_decrypt_trial_open_position` (production function);
2. `tr_decrypt_reject_skipped` (production function);
3. `diag_trial_open_position_resealed`: the M6-CT-2 Q3 variant. Class 1 is class 0's header plaintext re-sealed under
   `hk_2` with the same nonce, followed by the same body. The cells differ only in `hdr_ct`, and the public header
   content is the same.

Each `evaluate` is the production calibration plus the production pair. Each half is a fresh fixture, as in the gate.
There is no A/A pass and no other target; `run_verdict` is `"DIAG"`. Per half, the mode writes one entry into the
report array `diag_repeat` and one line into the progress file. The gate echoes these lines as
`ct progress ct diag_repeat: …`.

### 5.2 · Fields per half (`diag_repeat[]`)

- Identity: `target`, `rep` (0–7), `half` (1, 2).
- The rep's `verdict` and `decisive_crop` (`decide` on its two halves).
- `k`, `q_eff_ticks`, `q_eff_source`, `n0`, `n1` (raw crop).
- `p50` / `p75` / `p90`, each `{delta_ticks (class 0 − class 1), t, n0, n1}`.
- `shape`: per-class percentiles.
- `input[c]`: the per-class measured input buffer, as `{ptr, mod4096, mod64, other_addresses}`. `other_addresses` is
  the number of the class's inputs whose address differed from the first.
- `input_d4096`, `input_d64`: (addr0 − addr1) mod 4096 and mod 64.
- The `blend` sources, each as `{ptr, mod4096, mod64}`:
  - `class0_cell` (not read during the measurement);
  - `class1_cell_base` (read by both classes);
  - `delta` (read by both classes).
- The receiver: `receiver_state` (the state inside the slot), `hk_r`, `nhk_r` (their heap boxes), as above.
- `headers[c]`: the decoded public header of each class's cell — `chain`, `dh_pk` (hex), `pn`, `n`, and the first 8
  bytes of SHA-256 of `ek_pq` and of `ct_pq`.

Not logged: the skipped-entry boxes (`SkippedKey.hk` and `.mk`, the table the lookup reads) and the per-call heap
buffers inside `decrypt_with`. Their addresses have no accessor outside `secmp-proto`, and adding one is a product
change.

The progress line has this form:

```
ct diag_repeat: <target> rep <r> half <h> Δp50/Δp75/Δp90 <a>/<b>/<c> t90 <t> addr0 <hex> addr1 <hex> d4096 <n> d64 <n> verdict <v>
```

`addr0` and `addr1` are the per-class input buffers.

### 5.3 · Harness changes on the diag branch (production paths touched, untimed)

- `TrSkipped` keeps `chain_keys`.
- `tr_decrypt_trial_open_position` and `tr_decrypt_reject_skipped` call `diag_note_headers`.
- `tr_measure` calls `diag_note_measure` before `measure`, and wraps `prepare` with `diag_note_input`.

All three are no-ops (one thread-local check) unless the repeat mode records. All of this runs outside the timed
window; it applies to every TR target on this branch.

### 5.4 · Local run

- Host: Threadripper PRO 5955WX, `q_eff` 40 ticks = 10 ns.
- Settings: 1M samples, `k` 1; 1963 s in total.
- Command: `env SECMP_CT_DIAG=trial_open_repeat target/release/deps/ct-faacae40b4f5ca2f --bench`.
- Report: `ct-159-diag-repeat-local.json` (bench sha256 `e93640c1…`). The 48 progress lines are verbatim in
  `ct-159-diag-repeat-local.txt`.

Excerpt, per half (Δp90 in ticks, t90, and the address fields mod 4096):

```
target rep half dp90 t90 | input0%4096 | c0cell%4096 c1base%4096 delta%4096 | state%4096 hk_r%4096 nhk_r%4096 | hdr0 chain/pn hdr1 chain/pn same_dh same_ek
tr_decrypt_trial_open_position         0 1   -1.03   -2.98 | 3472 | 2064 2832 1136 |  392  976  944 | 1/0 2/3 False False
tr_decrypt_trial_open_position         0 2  -28.36  -84.76 | 1056 | 3904 1152 1040 |  392  624  112 | 1/0 2/3 False False
tr_decrypt_trial_open_position         1 1  -25.82  -72.29 | 3616 | 3200 1840 3104 |  392 1328  736 | 1/0 2/3 False False
tr_decrypt_trial_open_position         1 2  -11.40  -32.22 | 1808 |  976 3216 1840 |  392  896 2896 | 1/0 2/3 False False
tr_decrypt_trial_open_position         2 1  +24.14   70.47 |  992 | 2592  128 2112 |  392 3904 2480 | 1/0 2/3 False False
tr_decrypt_trial_open_position         2 2  +19.66   53.77 |  976 |  544 2112 3120 |  392 3904 2560 | 1/0 2/3 False False
tr_decrypt_trial_open_position         3 1   +8.64   25.83 | 1312 |    0 1440 1296 |  392 2560 1904 | 1/0 2/3 False False
tr_decrypt_trial_open_position         3 2  +11.95   32.95 |    0 | 1136 1424 1296 |  392 1936 3840 | 1/0 2/3 False False
tr_decrypt_trial_open_position         4 1  +26.20   70.59 |  352 |  400  416  336 |  392  416  720 | 1/0 2/3 False False
tr_decrypt_trial_open_position         4 2   -9.56  -26.72 | 1920 |  400 2960 2976 |  392 1664  416 | 1/0 2/3 False False
tr_decrypt_trial_open_position         5 1  -13.60  -38.63 | 3344 | 2960 1552 2016 |  392 2352  576 | 1/0 2/3 False False
tr_decrypt_trial_open_position         5 2   +0.11    0.33 | 1296 | 2016 2160 2176 |  392 3792  288 | 1/0 2/3 False False
tr_decrypt_trial_open_position         6 1  -10.21  -30.09 | 1536 |  736 2928 1520 |  392 2608 3792 | 1/0 2/3 False False
tr_decrypt_trial_open_position         6 2   +0.16    0.49 | 1168 |  736  752 1152 |  392 3040  656 | 1/0 2/3 False False
tr_decrypt_trial_open_position         7 1   -0.58   -1.62 | 3952 |  976 2832 3936 |  392 1712 1664 | 1/0 2/3 False False
tr_decrypt_trial_open_position         7 2   +5.66   14.76 | 3840 | 1632 3936 3824 |  392  144  304 | 1/0 2/3 False False
tr_decrypt_reject_skipped              0 1  +15.45   41.55 |  592 | 2256 1088 3712 |  392 3280 3328 | 1/0 1/0 True True
tr_decrypt_reject_skipped              0 2  -26.88  -69.13 | 3424 | 3920 3456 1408 |  392 1136  928 | 1/0 1/0 True True
tr_decrypt_reject_skipped              1 1  +11.69   30.68 | 3600 | 3968 1088 3584 |  392 2992 3472 | 1/0 1/0 True True
tr_decrypt_reject_skipped              1 2   +0.09    0.24 | 2320 |  464 1760 1776 |  392  672 1520 | 1/0 1/0 True True
tr_decrypt_reject_skipped              2 1   -0.67   -1.86 |  944 |  304 1920  928 |  392 3072 2432 | 1/0 1/0 True True
tr_decrypt_reject_skipped              2 2  +11.88   32.56 | 1552 | 2720 3408 3424 |  392  784 3264 | 1/0 1/0 True True
tr_decrypt_reject_skipped              3 1   +7.42   18.95 | 1728 | 1152 1568 1712 |  392 1696 1664 | 1/0 1/0 True True
tr_decrypt_reject_skipped              3 2  +19.96   53.53 | 3440 |  464 2768 2160 |  392  112   64 | 1/0 1/0 True True
tr_decrypt_reject_skipped              4 1  -15.09  -38.53 | 2800 |  464  416 2784 |  392 2128 1520 | 1/0 1/0 True True
tr_decrypt_reject_skipped              4 2   +1.85    4.92 | 3872 | 1520 2736 3776 |  392  256 1424 | 1/0 1/0 True True
tr_decrypt_reject_skipped              5 1  -25.50  -65.43 | 1536 | 3168 2800 2848 |  392 4064 1328 | 1/0 1/0 True True
tr_decrypt_reject_skipped              5 2   +9.32   23.94 | 2128 | 1776 1456 2736 |  392 1648 3488 | 1/0 1/0 True True
tr_decrypt_reject_skipped              6 1  +12.09   33.41 | 3520 |  416 2000 3504 |  392 1760 1424 | 1/0 1/0 True True
tr_decrypt_reject_skipped              6 2  +27.46   77.87 |  512 |    0 2784 2000 |  392 1328 2768 | 1/0 1/0 True True
tr_decrypt_reject_skipped              7 1   +0.93    2.57 |  304 |  352 1536 2080 |  392   96 4000 | 1/0 1/0 True True
tr_decrypt_reject_skipped              7 2  +22.73   61.48 |  368 | 2304 2112  352 |  392 1648 3440 | 1/0 1/0 True True
diag_trial_open_position_resealed      0 1   +0.17    0.53 |  400 | 3856 3872 3840 |  232 1344 3744 | 1/0 2/0 True True
diag_trial_open_position_resealed      0 2   +0.24    0.71 | 2976 | 3248 3264 2016 |  232 3280 1104 | 1/0 2/0 True True
diag_trial_open_position_resealed      1 1   +0.01    0.03 | 3456 | 1648 1664  480 |  232 2704  976 | 1/0 2/0 True True
diag_trial_open_position_resealed      1 2   -0.02   -0.06 | 1664 | 1136 1648 2256 |  232 3376 2208 | 1/0 2/0 True True
diag_trial_open_position_resealed      2 1   -0.50   -1.53 | 1840 | 1856 1872 3344 |  232 4000 2048 | 1/0 2/0 True True
diag_trial_open_position_resealed      2 2   -0.47   -1.48 | 1872 | 3056 1856 1840 |  232 1760 3008 | 1/0 2/0 True True
diag_trial_open_position_resealed      3 1   +0.03    0.08 | 3584 | 1280 3536 2448 |  232  752 1296 | 1/0 2/0 True True
diag_trial_open_position_resealed      3 2   +0.30    0.87 | 3680 | 2448 3536 1280 |  232 3024 1696 | 1/0 2/0 True True
diag_trial_open_position_resealed      4 1   -0.06   -0.18 | 2624 | 4080 2208  640 |  232 1328 1520 | 1/0 2/0 True True
diag_trial_open_position_resealed      4 2   -0.24   -0.74 | 2208 |    0 2624 1120 |  232 2816 2480 | 1/0 2/0 True True
diag_trial_open_position_resealed      5 1   -0.24   -0.67 | 1408 |   80 3328 2080 |  232 1968 1472 | 1/0 2/0 True True
diag_trial_open_position_resealed      5 2   +0.11    0.34 | 2976 | 1408  480 2704 |  232   16 1632 | 1/0 2/0 True True
diag_trial_open_position_resealed      6 1   -0.46   -1.37 | 3440 | 2912 3424  608 |  232 1744 2912 | 1/0 2/0 True True
diag_trial_open_position_resealed      6 2   -0.30   -0.89 | 3440 | 2816 2608 1808 |  232 1344 1792 | 1/0 2/0 True True
diag_trial_open_position_resealed      7 1   +0.12    0.33 | 4048 | 2208 4032 2192 |  232  176 2448 | 1/0 2/0 True True
diag_trial_open_position_resealed      7 2   -0.13   -0.39 | 3536 | 2992 3008 1712 |  232 3376 1680 | 1/0 2/0 True True
```

The resealed rows show class 1 as `2/0`: its header opens under `hk_2` (chain 2) and carries `pn 0`, because it is
class 0's header.

### 5.5 · Facts from the local run (no verdict)

- **Input addresses:** in every half of every target, both classes' measured inputs have the same address (`d4096 0`,
  `d64 0`, `other_addresses 0` in all 48 halves). The per-class input buffer does not differ in placement between the
  classes.
- **Receiver state:** the receiver state's offset mod 4096 is constant per target: 392 for the production targets, 232
  for the resealed one. It sits in the stack frame of `tr_measure`.
- **Shifts in the production targets** (each half is a fresh fixture):

  | Target | Halves with \|t90\| > 4.5 | \|Δp90\| range | Signs |
  |---|---|---|---|
  | `tr_decrypt_trial_open_position` | 12 of 16 | 5.7 … 28.4 ticks (1.4 … 7.1 ns) | both |
  | `tr_decrypt_reject_skipped` | 13 of 16 | up to 27.5 ticks | both |

  Rep verdicts:
  - `tr_decrypt_trial_open_position`: SUB_FLOOR_SHIFT in reps 1, 2, 3; PASS otherwise.
  - `tr_decrypt_reject_skipped`: SUB_FLOOR_SHIFT in reps 3 and 6; PASS otherwise.
  - No rep reached the 40-tick floor in both halves.
- **Shifts in `diag_trial_open_position_resealed`:** |Δp90| ≤ 0.50 ticks and |t90| ≤ 1.53 in all 16 halves. Every rep
  verdict is PASS.
- **Which inputs differ between the classes:**

  | Target | Differs between classes | Same in both classes |
  |---|---|---|
  | `tr_decrypt_trial_open_position` | header nonce; header plaintext (`dh_pk`, `ek_pq`, `ct_pq`, `pn`); `hdr_ct`; body ciphertext; header key and entry (trial 0 / entry 0 vs trial 1 / entry 2) | — |
  | `tr_decrypt_reject_skipped` | header nonce; `n` (0 vs 4); `hdr_ct`; body ciphertext; entry (0 vs 4) | `dh_pk`, `ek_pq`, `ct_pq`, `pn`; header key `hk_1` (both trial 0) |
  | `diag_trial_open_position_resealed` | `hdr_ct`; header key and entry (trial 0 / entry 0 vs trial 1 / entry 2) | header nonce, header plaintext, body |

- None of the logged address fields (input, the `blend` sources, `hk_r`, `nhk_r`, all mod 4096) takes the same value in
  the halves with large |Δ| and differs in the others. The logged offsets vary from half to half in all three targets.

### 5.6 · CI dispatch

```
gh workflow run ci-dispatch.yml --ref m06-ct-diag -f suite=ct -f ct_env=trial_open_repeat
```

- Expected duration: ≈ 33 min locally at 37 µs per call. Scaled by the CI per-call durations (`tr_decrypt_*` 53–66 µs
  on the EPYC 7763), that is ≈ 48 min.
- The step ends red: the gate refuses the report (its target set). The data is in the `ct-report-…` artifact
  (`diag_repeat`) and in the `ct progress ct diag_repeat:` log lines.
