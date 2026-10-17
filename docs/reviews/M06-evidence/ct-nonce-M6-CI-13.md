# ct run #159 — TR target design fix (WEISUNG M6-CI-13, ADR-042 Amendment 5)

Branch `m06-transport`; fix commits `0d89bdf` (fixture rule) and `6ac385f` (informative nonce target). Raw data of the
diagnosis: diag branch `m06-ct-diag` at `4239879a142795edd5fbdd9af1130bca8d71db6a`, `docs/reviews/M06-evidence/ct-159-diag.md`
(§5, §6) with its JSON and TXT files. That branch is not merged.

## 1 · Diagnosis, condensed (from `ct-159-diag.md` §5, §6)

All local: Threadripper PRO 5955WX, `q_eff` 40 ticks = 10 ns, 1M samples per half, every half a fresh fixture.

**Repeat mode** (§5, 8 evaluations = 16 halves per target):

| Target | max \|Δp90\| ticks | Halves with \|t90\| > 4.5 |
|---|---|---|
| `tr_decrypt_trial_open_position`, old fixture | 28.36 | 12/16 |
| `tr_decrypt_reject_skipped`, old fixture | 27.46 | 13/16 |
| `diag_trial_open_position_resealed`: class 1 = class 0's header re-sealed under `hk_2`, same nonce, plaintext and body — the new `tr_decrypt_trial_open_position` construction | 0.50 | 0/16 |

Input addresses were identical for both classes in all 48 halves.

**Bisection** (§6, 4 evaluations = 8 halves per variant; class 1 = class 0 with one component changed):

| Variant | max \|Δp90\| ticks | Halves with \|t90\| > 4.5 |
|---|---|---|
| V1 `pn` | 0.45 | 0 |
| V2 `dh_pk` | 0.88 | 0 |
| V3 `ek_pq` / `ct_pq` | 0.89 | 0 |
| V4 header nonce | 65.38 | 5 |
| V5 body ciphertext | 0.52 | 0 |
| V6 `mk` (two receivers) | 10.95 | 5 |
| V6c two receivers, same `mk` | 6.98 | 6 |

Dispatch 39063440795 (EPYC 7763, the diagnosis set, one evaluation each): all PASS. Production Δ ≤ 2.5 ticks;
swapped, interleaved and same_content ≤ 6 ticks.

**Old fixture under the repeat mode** — the red baseline for 5b, verbatim from `ct-159-diag.md` §5.4 (`ct-159-diag-repeat-local.txt`
on the diag branch), the halves with the largest shift:

```
ct diag_repeat: tr_decrypt_trial_open_position rep 0 half 2 Δp50/Δp75/Δp90 -7.13/-13.78/-28.36 t90 -84.76 addr0 0x60cf88bbd420 addr1 0x60cf88bbd420 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 2 half 1 Δp50/Δp75/Δp90 +6.55/+14.06/+24.14 t90 70.47 addr0 0x60cf88bd63e0 addr1 0x60cf88bd63e0 d4096 0 d64 0 verdict SUB_FLOOR_SHIFT
ct diag_repeat: tr_decrypt_reject_skipped rep 0 half 2 Δp50/Δp75/Δp90 -6.65/-13.97/-26.88 t90 -69.13 addr0 0x60cf88c18d60 addr1 0x60cf88c18d60 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 6 half 2 Δp50/Δp75/Δp90 +7.25/+15.55/+27.46 t90 77.87 addr0 0x60cf88c4b200 addr1 0x60cf88c4b200 d4096 0 d64 0 verdict SUB_FLOOR_SHIFT
```

## 2 · Local verification of the fix

### 2.1 · How it was run

The production bench has no per-target filter, and a full production run measures every target. So the verification
used the diag branch's repeat mode, with each half run exactly as in the gate (`evaluate`: production calibration and
pair, a fresh fixture per half).

- A scratch worktree at `6ac385f` (this branch with both fix commits): `target/wt-ct13`, detached and gitignored, left
  in place. It is the source of §2.2 and §2.3; its reports are under `target/wt-ct13/target/verify_5a/` and `verify_5b/`.
- The three diag commits were cherry-picked onto it as `bf5106c`, `cf45a0f` and `d889bbe`. The one conflict was the
  report's format string; the other merges were textual.
- Two scratch modes, never committed: `verify_5a` and `verify_5b`.
- The measured target functions are this branch's production functions, `tr_decrypt_trial_open_position` and
  `tr_decrypt_reject_skipped` with the Amendment 5 fixtures, and `tr_decrypt_nonce_dependence`. The repeat mode adds
  only the untimed recording hooks of §5.3 of the diag evidence.

Setup:

- Host: Threadripper PRO 5955WX, `q_eff` 40 ticks, 1M samples per half.
- Bench sha256: `97fc338c784cb3c7…` (scratch build).
- Commands:
  - `env SECMP_CT_DIAG=verify_5a <scratch>/target/release/deps/ct-2ad4057bbea631e6 --bench` (3 evaluations of each of
    the three targets);
  - the same with `verify_5b` (4 evaluations of each fixed target).
- Reports: `ct-nonce-M6-CI-13-verify-5a.json` / `-5b.json`; verbatim progress lines in `ct-nonce-M6-CI-13-verify-5a.txt`
  / `-5b.txt`.

### 2.2 · 5a — 3 evaluations (6 halves) per target

```
ct diag_repeat: tr_decrypt_trial_open_position rep 0 half 1 Δp50/Δp75/Δp90 +0.68/+0.69/+0.89 t90 2.55 addr0 0x5c95bc294040 addr1 0x5c95bc294040 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 0 half 2 Δp50/Δp75/Δp90 -0.67/-0.33/-0.51 t90 -1.51 addr0 0x5c95bc2a71f0 addr1 0x5c95bc2a71f0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 1 half 1 Δp50/Δp75/Δp90 +0.46/+0.76/+0.91 t90 2.58 addr0 0x5c95bc2a6600 addr1 0x5c95bc2a6600 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 1 half 2 Δp50/Δp75/Δp90 +0.47/+0.55/+0.65 t90 1.84 addr0 0x5c95bc2afcc0 addr1 0x5c95bc2afcc0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 2 half 1 Δp50/Δp75/Δp90 +0.08/+0.01/-0.13 t90 -0.38 addr0 0x5c95bc2b67b0 addr1 0x5c95bc2b67b0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 2 half 2 Δp50/Δp75/Δp90 -0.06/+0.27/+0.05 t90 0.15 addr0 0x5c95bc2b77c0 addr1 0x5c95bc2b77c0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 0 half 1 Δp50/Δp75/Δp90 -0.21/-1.27/-1.42 t90 -3.83 addr0 0x5c95bc2c8210 addr1 0x5c95bc2c8210 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 0 half 2 Δp50/Δp75/Δp90 +0.28/+0.18/+0.33 t90 0.83 addr0 0x5c95bc2c4210 addr1 0x5c95bc2c4210 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 1 half 1 Δp50/Δp75/Δp90 +0.04/-0.17/-0.12 t90 -0.31 addr0 0x5c95bc2ce460 addr1 0x5c95bc2ce460 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 1 half 2 Δp50/Δp75/Δp90 +0.24/-0.07/-0.53 t90 -1.31 addr0 0x5c95bc2ce270 addr1 0x5c95bc2ce270 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 2 half 1 Δp50/Δp75/Δp90 -0.12/-0.50/-0.75 t90 -1.79 addr0 0x5c95bc2d99c0 addr1 0x5c95bc2d99c0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 2 half 2 Δp50/Δp75/Δp90 -0.78/-0.89/-1.65 t90 -4.18 addr0 0x5c95bc2ce7c0 addr1 0x5c95bc2ce7c0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_nonce_dependence rep 0 half 1 Δp50/Δp75/Δp90 +15.63/+24.09/+32.40 t90 91.01 addr0 0x5c95bc2dcec0 addr1 0x5c95bc2dcec0 d4096 0 d64 0 verdict SUB_FLOOR_SHIFT
ct diag_repeat: tr_decrypt_nonce_dependence rep 0 half 2 Δp50/Δp75/Δp90 +9.23/+14.21/+19.92 t90 57.01 addr0 0x5c95bc2dcc20 addr1 0x5c95bc2dcc20 d4096 0 d64 0 verdict SUB_FLOOR_SHIFT
ct diag_repeat: tr_decrypt_nonce_dependence rep 1 half 1 Δp50/Δp75/Δp90 +15.87/+22.91/+34.47 t90 97.92 addr0 0x5c95bc2e3760 addr1 0x5c95bc2e3760 d4096 0 d64 0 verdict FAIL
ct diag_repeat: tr_decrypt_nonce_dependence rep 1 half 2 Δp50/Δp75/Δp90 +31.14/+49.92/+70.46 t90 207.99 addr0 0x5c95bc2e2e70 addr1 0x5c95bc2e2e70 d4096 0 d64 0 verdict FAIL
ct diag_repeat: tr_decrypt_nonce_dependence rep 2 half 1 Δp50/Δp75/Δp90 +18.83/+28.48/+37.98 t90 116.64 addr0 0x5c95bc2ebf10 addr1 0x5c95bc2ebf10 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_nonce_dependence rep 2 half 2 Δp50/Δp75/Δp90 -7.03/-11.41/-18.33 t90 -55.77 addr0 0x5c95bc2eaca0 addr1 0x5c95bc2eaca0 d4096 0 d64 0 verdict PASS
```

The `verdict` column is the repeat mode's `decide` on each evaluation's two halves. For the informative target it is
diagnosis only: the production bench gives that target no verdict.

### 2.3 · 5b — 4 evaluations (8 halves) per fixed target

```
ct diag_repeat: tr_decrypt_trial_open_position rep 0 half 1 Δp50/Δp75/Δp90 -4.21/-6.23/-8.93 t90 -25.22 addr0 0x56c928de74a0 addr1 0x56c928de74a0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 0 half 2 Δp50/Δp75/Δp90 +0.20/+0.11/+0.46 t90 1.25 addr0 0x56c928de8de0 addr1 0x56c928de8de0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 1 half 1 Δp50/Δp75/Δp90 -0.08/-0.19/+0.17 t90 0.46 addr0 0x56c928de6850 addr1 0x56c928de6850 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 1 half 2 Δp50/Δp75/Δp90 +2.43/+3.41/+3.81 t90 10.93 addr0 0x56c928df24d0 addr1 0x56c928df24d0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 2 half 1 Δp50/Δp75/Δp90 -1.05/-1.12/-1.27 t90 -3.51 addr0 0x56c928de86a0 addr1 0x56c928de86a0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 2 half 2 Δp50/Δp75/Δp90 +0.57/+0.88/+0.27 t90 0.72 addr0 0x56c928dea8f0 addr1 0x56c928dea8f0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 3 half 1 Δp50/Δp75/Δp90 -0.00/-0.10/-0.04 t90 -0.12 addr0 0x56c928e04d40 addr1 0x56c928e04d40 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_trial_open_position rep 3 half 2 Δp50/Δp75/Δp90 +0.22/+0.26/+0.12 t90 0.37 addr0 0x56c928e041f0 addr1 0x56c928e041f0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 0 half 1 Δp50/Δp75/Δp90 -1.98/-3.67/-5.20 t90 -12.93 addr0 0x56c928e11850 addr1 0x56c928e11850 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 0 half 2 Δp50/Δp75/Δp90 +0.02/-0.36/+0.00 t90 0.01 addr0 0x56c928e13ac0 addr1 0x56c928e13ac0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 1 half 1 Δp50/Δp75/Δp90 -0.24/+0.31/+0.50 t90 1.23 addr0 0x56c928e08260 addr1 0x56c928e08260 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 1 half 2 Δp50/Δp75/Δp90 +0.24/+0.41/+0.10 t90 0.24 addr0 0x56c928e1ca80 addr1 0x56c928e1ca80 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 2 half 1 Δp50/Δp75/Δp90 +0.77/+0.97/+1.14 t90 2.81 addr0 0x56c928e22f10 addr1 0x56c928e22f10 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 2 half 2 Δp50/Δp75/Δp90 +0.76/+0.42/+0.28 t90 0.69 addr0 0x56c928e261f0 addr1 0x56c928e261f0 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 3 half 1 Δp50/Δp75/Δp90 -0.02/-0.39/-0.37 t90 -0.89 addr0 0x56c928e15740 addr1 0x56c928e15740 d4096 0 d64 0 verdict PASS
ct diag_repeat: tr_decrypt_reject_skipped rep 3 half 2 Δp50/Δp75/Δp90 +0.38/+0.33/-0.27 t90 -0.65 addr0 0x56c928e14280 addr1 0x56c928e14280 d4096 0 d64 0 verdict PASS
```

### 2.4 · Against the criterion of WEISUNG M6-CI-13 §5 (|Δp90| ≤ 1.0 tick and |t| < 4.5 in every half)

| Run | Target | Halves | Halves meeting \|Δp90\| ≤ 1.0 | Halves with \|t90\| < 4.5 | Rep verdicts |
|---|---|---|---|---|---|
| 5a | `tr_decrypt_trial_open_position` | 6 | **6** (max 0.91) | 6 (max 2.58) | PASS ×3 |
| 5a | `tr_decrypt_reject_skipped` | 6 | **4** (rep 0 h1 −1.42, rep 2 h2 −1.65) | 6 (max 4.18) | PASS ×3 |
| 5b | `tr_decrypt_trial_open_position` | 8 | **5** (rep 0 h1 −8.93, rep 1 h2 +3.81, rep 2 h1 −1.27) | 6 (rep 0 h1 −25.22, rep 1 h2 10.93) | PASS ×4 |
| 5b | `tr_decrypt_reject_skipped` | 8 | **6** (rep 0 h1 −5.20, rep 2 h1 +1.14) | 7 (rep 0 h1 −12.93) | PASS ×4 |

- **The 1-tick bar** (withdrawn, see the decision below) fails in 7 of 28 fixed-target halves. All 7 are below the
  40-tick local floor (largest 8.93 ticks = 2.2 ns = 0.22 floor), and every rep verdict of both fixed targets is PASS.
- **The accepted criterion** (|Δp90| < 0.5 × floor = 20 local ticks in every half, every rep verdict PASS) is met in
  28 of 28 halves, 14 of 14 rep verdicts.
- **Old fixture, for comparison:** max 28.36 / 27.46 ticks, and 25 of 32 halves with |t90| > 4.5.
- **The new fixture of `tr_decrypt_trial_open_position`** is the construction of `diag_trial_open_position_resealed`.
  That gave ≤ 0.50 ticks in 16/16 halves in §5; here 3 of its 14 halves exceed 1 tick.
- **`tr_decrypt_nonce_dependence`** (informative): Δp90 +32.40 / +19.92 / +34.47 / +70.46 / +37.98 / −18.33 ticks,
  |t90| 56–208.
- Input addresses were identical for both classes in all 34 halves.

**Reviewer decision (WEISUNG M6-CI-13b, verbatim):**

> Decision (Fable, 2026-10-17 23:50 UTC): the fix is **accepted**. The 1.0-tick bar in M6-CI-13 §5 was mis-specified by the reviewer: one local tick is 0.25 ns, far below any resolution the gate claims (floor 10 ns, ADR-041 Am. 1). The acceptance criterion for the fixture fix is the gate's own rule plus a margin: every half |Δp90| < 0.5 × floor (= 20 local ticks / 5 ns) and every rep verdict PASS. Measured: max |Δp90| 8.93 ticks = 2.2 ns (0.22 floor), 16/16 and 6/6 rep verdicts PASS, against the old fixture's 28 ticks = 7 ns locally and 42 ticks = 17 ns on the EPYC (FAIL). The residual (≤ 2.2 ns, both signs, |t| up to 25 on 1M samples) is a public-content micro-timing of the remaining class differences (`hdr_ct`, key/entry, `mk`); it is below the floor by a factor ≥ 4 and is monitored by `tr_decrypt_nonce_dependence`. No further diagnosis before the PR run.

## 3 · Status

- The fixture rule and the informative target are implemented, and the fix is accepted (WEISUNG M6-CI-13b).
- R-CT-1 is closed in `M06-report.md` §7. No rerun was made to obtain a passing set.
