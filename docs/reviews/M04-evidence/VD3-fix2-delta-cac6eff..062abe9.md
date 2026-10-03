# VD3: delta verifier (second instance), M4 FIX-2, `cac6eff..062abe9`

Inputs: `/mnt/user-data/uploads/SecMPro/target/fable/m4/` (WEISUNG_M4-FIX-2, REPORT-FIX-2, fix2-delta.diff, diffstat, commits, tests, full files at 062abe9 of responder.rs, inv.rs, gates.rs, accept_ok.rs).
Not in the inputs, so not verified: `kani_proofs.rs`, `benches/ct.rs` (full), `expect.rs` (full), `ci.yml`, `scenario.rs` (`Lib::assert_rejected`, `outer_variant`), the two raw external reports (excluded from the diff), the kat log, the scale-1000 ct output, and per-commit diffs.
Diff completeness: the added and removed line counts per file match `fix2-diffstat.txt` for all 15 diffed files. Together with the two excluded raw reports that makes 17 files, matching the diffstat.

---

## Q1: Item 1 (R-94), portable kat rerun includes `hx`. **met-with-note**

- `gates.rs:153-156` (062abe9): the new `KAT_PORTABLE_RERUN` reads `secmp-proto → ["tr_vectors", "hx"]`. The loop at `:188` (`for &(package, tests) in KAT_PORTABLE_RERUN`) is the only consumer and builds `nextest run --locked --package P --features kat --test T…` with `LIBCRUX_DISABLE_SIMD128/256=1` and `CARGO_TARGET_DIR=target/kat-portable`.
- Features: the native run (`:168-178`) uses `--package p --features kat`. The portable run uses the same `--features kat`, so the features are identical.
- Comment `:180-186` and Pass text `:210` are corrected and now name `hx`.
- Test `kat_portable_rerun_includes_the_hx_suite` (`gates.rs:5332`) asserts that the constant's `secmp-proto` list contains `hx` and `tr_vectors`. It also asserts that `crates/secmp-proto/Cargo.toml` contains `name = "<t>"` for each listed target.
  - Removing `hx` from the constant makes it fail.
  - It does **not** inspect the generated arguments or the kat log. The binding from constant to command is structural only (a single use at `:188`). A future edit that bypasses the constant inside `kat()`, or drops the `--test` push, would not be caught.
  - The manifest check is a substring match (any `name = "hx"` in the file would satisfy it). This is a nit.
- Silent-skip analysis:
  - **required-features.** `hx` needs `kat` (per external EXT-6, "Miri filters hx out (required-features)"). `--features kat` is passed. An explicitly selected `--test hx` with unmet required-features is a hard cargo error, not a skip.
  - **Target dir.** The separate `target/kat-portable` only prevents a stale SIMD build. It does not affect target selection.
  - **Filter.** No `-E`/filter string and no `--no-tests` flag are passed.
  - **Residual.** A repository nextest profile or default-filter is not in the inputs and cannot be excluded. The reported kat-log figure (131 passed = 129 hx + 2 tr_vectors) is consistent but not in the inputs.

## Q2: Item 2 (VD2-1), cap 50. **met-with-note**

**Self-consistency at 062abe9:**
- `responder.rs:49`: `MAX_PROCESSED_GROUPS = 50`.
- `:50`: `const _: () = assert!(MAX_PROCESSED_GROUPS >= (128 + 24) / 3)`, and (128+24)/3 = 50.
- `:262`: `Processed<K, MAX_PROCESSED_GROUPS>`.
- `:237-240`: `is_full` = `len >= R`.
- `:288`: `if !processed.push(group.init_id) || processed.is_full() { return Err(Rejected) }`.
- Docs at `:45-48`, `:251-252`, `:285-286` and `:306-309` all state one reading: at most 50 complete groups per call; the 50th processed group being rejected stops the call; 49 rejected followed by a good group is accepted.
- `Processed` records only rejected ids, and an accepted group returns at once. So "processed groups" = rejected + at most 1, which is consistent.

**Window coverage:**
- Every complete group consumes ≥ 3 distinct cells. Chunks of an already processed `init_id` are dropped (`:265`), and duplicates or evicted partials consume cells without forming groups.
- So 152 cells (128 fetched + 24 retained) hold at most ⌊152/3⌋ = 50 complete groups, plus 2 spare cells.
- Under the implemented reading the 50th group is still processed (and accepted if honest). No honest group inside the RT-1 window can be cut off.
- The Weisung's alternative reading ("up to 50 *rejected*, then still process") differs only for a 51st group, which needs ≥ 153 cells and so lies outside the window. Rejecting there is the fail-closed choice.
- Deviation 1 is therefore sound and should be ratified.
- The `>=` in the assert is the right direction (it needs R ≥ max groups in the window).

**Fail-closed:**
- The stop is an immediate `return Err(Error::Rejected)` before any `commit_accept`. `process` only gets `&*store`.
- `Groups`/`Processed` are locals, so there is no partial state and no accept after the stop.
- The store is only mutated by `commit_accept` (`:281`).

**Boundary tests:**
- `drive_does_not_re_form_a_rejected_init_id` (`responder.rs:584-599`):
  - ids 0..49 (50 rejected) + good 200 ⇒ `Rejected`, `seen.len() == 50` (the good group is never processed), `commits == 0`.
  - ids 1..49 (49 rejected) + good ⇒ `Ok(200)`, which implies a commit.
  - Both sides are covered.
- `fifty_rejected_groups_then_an_honest_group_still_accepts` (`accept_ok.rs:360-378`):
  - 49 groups with Outer ver 0x02 (147 cells) + honest = 150 cells ⇒ `accepted_ok` (Ok and OPK deleted).
  - 50 rejected + honest = 153 cells ⇒ `lib.assert_rejected`.
  - Guard: the honest `init_id` ∉ {[1;16]…[50;16]}.
  - The only reason the 50-case can reject is the cap, since the same honest group accepts after 49. Both sides are proven end-to-end.
  - "Store unchanged, OPK kept" relies on `Lib::assert_rejected` (scenario.rs, not in the inputs).
- **Name nit.** This test's name (dictated) says "fifty rejected … still accepts", while its 50-case asserts `Rejected`.
- `rejected_init_id_does_not_re_form_within_one_accept` is unchanged in the diff (hunk context only). It is a regression rerun.

**Kani risk (K2a `kani_accept_opk_delete_only_on_success`):**
- `drive` hard-codes `Processed<K, 50>`, so the harness runs the production cap. With ≤ 6 chunks there are ≤ 2 complete groups, so `processed.len ≤ 2`. `is_full` is never true, and `push` never fails. The cap is unreachable in the harness.
- The obligations are unchanged apart from the array length and one extra `len >= R` comparison, whose true branch is unreachable and mirrors the old push-failure return:
  - `Processed::new` is an array repeat (`[const { None }; R]`), with no loop.
  - `contains` is bounded by `take(len)`.
  - `push` indexes at `len`.
- Any loop over all R slots would already have exceeded unwind 10 at R = 42. The size change therefore cannot add an unwinding obligation.
- The harness bounds are taken from the brief, since `kani_proofs.rs` is not in the inputs.
- **Verdict.** The proof risk is negligible. The evidence risk is real: the committed Kani log `kani-xtask-step-0a5d2b6.txt` no longer covers head code. Close it with a Kani run on ≥ 797528f (the PR run's Kani step, if linux-full runs it, which is not verifiable from the inputs, or one local K2a run of about 515 s).
- **Side note.** `!processed.push(..)` at `:288` is now unreachable, because the call returns as soon as `len == R`. It is redundant but harmless. The obvious mutants (`||→&&`, `!` deleted, `is_full→true/false`, `>=→<`) are each killed by the drive test or the integration test.
- **Nit.** The assert uses the literals 128 and 24 instead of `3 * MAX_PARTIAL_GROUPS` and the queue-capacity constant. It would not follow a change of either.

## Q3: Item 3 (VD2-2, R-46), reject sites. **met-with-note**

**`first_msg_with_nonzero_n_rejects_before_any_chain_step`** (`accept_ok.rs:1192ff`):
- It resets `tr::DECRYPT_SITE_KAT` (and `SKIP_STEPS_KAT = u32::MAX`) before each call.
- For n ∈ {1, 7, 2^20} it asserts `Rejected`, `SKIP_STEPS_KAT == 0`, `DECRYPT_SITE_KAT == Some("counter rule")`, store digest unchanged, and OPK kept.
- This pins the site mechanically: the TR tag plus a chain-step counter of 0.

**`accept_counter_rules_reject_n_before_and_pn_after_the_mac`** (renamed, `:1144`):
- It resets the TR tag and returns `(DECRYPT_SITE_KAT, ACCEPT_SITE_KAT)`.
- n ∈ {1, 7} ⇒ `(counter rule, first_msg decrypt)` and `remaining == full` (no draw).
- pn = 5 ⇒ `(body MAC, first_msg checks)` and `remaining == 0` (the DH step drew after the MAC verified).
- Control (0, 0) accepts.
- The name now matches what the test proves. Both sides are pinned by site tags and the entropy counter.

**Deviation 2** (also pins the pn ≠ 0 sites): harmless.
- It pins `kat`-only instrumentation, not the spec. After a successful decrypt the TR tag names the last TR step that began ("body MAC"), and the HX tag names the post-decrypt checks (`responder.rs:451-456`).
- The only coupling: a future TR step that sets a tag after the MAC would require editing the test. No spec property is over-constrained.

**Deviation 3** (`benches/ct.rs`, 15 lines added, 2 removed, all inside `fn hx_accept_reject`, about lines 3085-3120):
- `tr_site = Some("body MAC")` iff `claim.target == CLAIM_HX_FIRST_MSG.target`.
- `DECRYPT_SITE_KAT.set(None)` at the start of `accept_once`.
- `observed` gets `", tr site …"` appended for that target only, and `expected` gets the same suffix.
- `accept_once` feeds only `observed = [accept_once(&class0), accept_once(&class1)]` → `precheck(...)`.
- No other hunk exists in ct.rs: the measured loop, samples, crops, floors and controls are untouched.
- The pre-check is deterministic (`FixedEntropy`, fixed fixtures), so a scale-1000 run executes it exactly as a full run would.
- The same-content control (ADR-042 Am. 3) changes only if its claim had the first_msg target string. Even then its identical-content classes would both show "body MAC". No change to its semantics or to the C-2 judgment.
- The full ct file and the scale-1000 output are not in the inputs.
- The Weisung's reference to ≈1920-1928 was not touched; the requirement is met entirely in the pre-check.

## Q4: Item 4 (VD1-2, VD1-4). **met**

**Timeout:**
- `ci-dispatch.yml`: `dispatch-ct` `timeout-minutes: 300 → 330`. The comment states it matches the `ct` job of ci.yml.
- `expect.rs:96-98` comment: 290 min = `CT_STEP_TIMEOUT_SECONDS` 17 400 (unchanged), "40 min below the 330 min" of both.
- This matches the Weisung's 330 min.
- Note: no test pins the timeouts against the budget. `dispatch_full_runs_the_linux_full_line` compares gate lines only, so a regression to ≤ 290 min would not fail a test.

**Flow-style `jobs:` line:**
- `gates.rs:3024-3029`, new finding: `l.col == 0 && dash none && key == "jobs" && value non-empty`.
- Before this change the only flow-style rule required `l.job.is_some()` (`:3017`). `yaml_lines` gives the col-0 `jobs:` line `job = None` (`:3239-3242`).
- So `jobs: {a: {...uses: evil/action@sha}}`, `jobs: {a: {if: false, runs-on: x}}`, `"jobs": {...}` (the quoted key is unquoted by `yaml_key_value`, `:3180-3187`) and `jobs: [a]` all produced 0 findings before.
- The test asserts exactly 1 finding, "on the `jobs:` line", so it fails without the new rule. It is a genuine regression test.
- Negative controls (`jobs:`, `jobs: # the jobs`, `"jobs":`) give 0 findings.

**Widening:** none. The change is one added `out.push`; nothing was removed or relaxed.
- A flow mapping on the line after `jobs:` was already caught by `:3017` (its key starts with `{` and its job is Some).
- A fully flow-style document (`{on: …, jobs: …}`) remains outside this reader. That is accident-guard scope, not VD1-4.

## Q5: Item 5 (VD1-5, VD1-6). **met**

**`expect::KANI_COVERS`:**
- `[(kani_proofs::kani_accept_opk_delete_only_on_success, 1), (kani_proofs::kani_commit_accept_atomic, 1)]`, i.e. 2 harnesses × 1 cover.
- Gate `gates.rs:1764-1770` bails on any `kani_cover_pin_findings`: a missing pinned summary, an unpinned one, or a duplicate harness line (`:1838-1857`).

**Parser `:1811-1827`:**
- `strip_suffix` became `split_once`, and any suffix such as " (1 unreachable)" now fails.
- Before, such a line was skipped silently, which was the VD1-5 hole.

**`kani_cover_count_is_pinned` (`:5791`):**
- `kani::cover!(` count in `kani_proofs.rs` == Σ pinned (2), so a cover added or removed in source fails at test time.
- Each pinned harness is in `KANI_HARNESSES`.
- The committed log `kani-xtask-step-0a5d2b6.txt` gives 0 findings.
- One summary deleted ⇒ 1 finding.
- "2 of 2" ⇒ 2 findings (missing + not pinned).
- "1 of 2 …(1 unreachable)" and "1 of 1 …(1 unreachable)" ⇒ `Err` naming the suffix.
- Note: the source count is textual (`kani::cover!(`), so a cover spelled as an imported `cover!(` escapes the unit test but not the gate pin.
- Note: the comment "no cover at all is no failure" at `:5782` (unchanged test) is now true for the parser only; the gate fails it through the pin. This is a nit.

**docs/06:82:** docs only.
- "with a 6-hour timeout per package" matches `gates.rs:1529-1530` (one job per package, own 6-hour limit).
- The listed `MIRI_FEATURE_GATED` targets (`hx`, `tr_generator`, `tr_properties`, `tr_vectors`) are not verifiable from the inputs (expect.rs is excerpt only). The gate `:1539-1562` enforces that list against the manifests.

## Q6: Item 6 (VD2-3…7). **met**

**Tests:**
- `base64url_decode_rejects_invalid_and_dirty_alike` (`inv.rs` tests, `:455ff`):
  - "*A": len 2, invalid in sextet 0. 'A' = 0 fills bits 12-17, and the unused mask 0xFFFF sees 0. So `invalid < 0`, `dirty == 0`: invalid only.
  - "AAA*": len 4, mask 0, so invalid only.
  - "AB": 'B' = 1 ⇒ `group & 0xFFFF = 0x1000`, so dirty only.
  - Dropping either operand of `inv.rs:220` fails the test. The old "A*" was both invalid and dirty, which let a mutant survive.
- `accept_every_rejecting_row_counts_no_delete_and_no_draw` (`tests/hx/accept.rs:≈767`): `left == step.len() || left == 0` became `assert_eq!(remaining(), step.len())`. This is strictly stronger.
- `invitee_bad_ed25519_identity_rejects` (`tests/hx/inv.rs:553ff`): uses `rejects_at_as(…, name, "linkdata decode")`. The per-case label is restored and the site assertion is kept (now with a message). `rejects_at` delegates with `what = site`, so its behaviour is identical.
- `start_persist_error_is_returned_and_nothing_sent`: only the V-6 doc comment moved from `PersistError` to the test; the body is unchanged.

**Every non-test hunk in product code:**

| # | Location | Item | Kind |
|---|---|---|---|
| 1 | `responder.rs` module doc `:23-25` | VD2-7 | doc |
| 2 | `responder.rs:45-50` | 2 | behaviour (const 42→50) + doc + assert formula |
| 3 | `responder.rs:237-240` `is_full` (new private const fn) | 2 | behaviour |
| 4 | `responder.rs:251-252` `drive` doc | 2 | doc |
| 5 | `responder.rs:285-288` comment + `\|\| processed.is_full()` | 2 | behaviour |
| 6 | `responder.rs:306-309, 315-316` `accept` doc | 2, VD2-7 | doc |
| 7 | `inv.rs` | — | none (its only hunk is inside `#[cfg(test)] mod tests`, `:430`) |

- No renames in product code, and no behaviour change beyond item 2.
- Nit: the VD2-7 sentence appears twice with different wording. The module doc says "spent after `Ok` (or `Rejected`)"; the `accept` doc says "spent after `Ok`". The Weisung asked for one sentence.

## Q7: Item 7 (docs). **met-with-note**

- `docs/reviews/M04-external.md`: present, 110 lines. Its internal arithmetic checks out:
  - 4+1+3+1+1+89 = 99.
  - 7/37/23/26/3 = 96; internal-only 5/34/23/24/3 = 89.
  - FP 1/6 = 16.7 %, 1/8 = 12.5 %.
  - Recall 3/44 = 6.8 %, 5/44 = 11.4 %.
- The two raw reports are listed in the diffstat (299 + 67 lines) but excluded from the diff, so their "verbatim" status is not checked.
- `docs/04:45`: residual sentence present. It names `link_key` in zeroizing heap `SecretBytes`, not locked memory, ≤ 30 days, until M7, R-37 / Codex EXT-3 / GLM EXT-5.
- `M04-report.md`:
  - §5 VD2-1 deviation row present.
  - Erratum "four M4 ct targets + respecified M3 `tr_decrypt_reject_skipped`" at both "five" sites (§7.1 :197, §12.3 :474).
  - VD2-8 Kani row: K2a 514.6 s, K3 348.0 s. These values are not verifiable against the log here.
  - New FIX-2 section with errata: C-10 row superseded (42 → 50); C-1 row (300 → 330).
- `M04-review.md`:
  - §C R-94 row present: minor, CONFIRMED, fixed in `72d4c90`.
  - §E row "D-20…D-26 (CLAIMS editorial errata, L7-10) ratified as reviewer amendments 2026-10-03" present, verbatim.
- Open: Weisung item 7 "report §5 rows … for R-90 if missing". No R-90 row was added, and REPORT-FIX-2 does not say whether one already existed. The register R-90 row says "Documented deviation in report §5". This is unverifiable here.
- Frozen paths: none of docs/03, docs/01, vectors/ or formal/ appears in the diffstat. Edits there: none.
- No xtask test reads the docs changed in 062abe9 (grep of gates.rs). The test run at 33e7405 therefore stays valid for 062abe9.

## Q8: Weakening scan. **none**

- `#[ignore]`, `continue-on-error`, `allow(…)`, skip lists, thresholds, floors, sample counts, mutants floor/caught ≥ 1, ct floor/budget, ProVerif hashes, `MIRI_*` lists: no hunk touches any of them (grep of ± lines).
- Changed expectations:
  - The drive-test boundary moved 51→50 groups and `seen` 51→50. This follows the cap reading, with both sides still asserted.
  - `"A*"` was replaced by the stronger `"*A"`/`"AAA*"`.
  - `|| left == 0` was removed (stronger).
  - The renamed test has its dictated replacement.
- Timeout 300→330 on `dispatch-ct` is a dictated CI job limit, not a gate criterion. The step budget 17 400 s is unchanged.
- The cap 42→50 raises the work bound per call by about 19 %. This was the reviewer's decision, not a gate.

## Q9: Completeness. **met-with-note**

| File | Item(s) |
|---|---|
| ci-dispatch.yml | 4 |
| responder.rs | 2, 6 |
| inv.rs | 6 |
| tests/hx/accept.rs | 6 |
| tests/hx/accept_ok.rs | 2, 3, 6 |
| tests/hx/inv.rs | 6 |
| benches/ct.rs | 3 |
| docs/04 | 7 |
| docs/06 | 5 |
| fix2-tests-33e7405.txt | 7 (evidence) |
| two raw reports | 7 |
| M04-external.md | 7 |
| M04-report.md | 2 (§5 row), 7 |
| M04-review.md | 7 |
| expect.rs | 4 (comment), 5 |
| gates.rs | 1, 4, 5 |

- All 17 files are accounted for.
- Tests: all 13 names exist at 062abe9.
  - 4 new: `kat_portable_rerun…`, `fifty_rejected…`, `policy_refuses_flow_style_jobs_line`, `kani_cover_count_is_pinned`. This is consistent with 560 + 4 = 564.
  - 7 changed.
  - 2 are unchanged reruns: `rejected_init_id_does_not_re_form_within_one_accept`, `kani_gate_fails_on_an_unsatisfiable_cover`.
- Commit titles match the Weisung's dictated messages verbatim, with tags. Commit bodies and the per-commit file split are not in the inputs.

---

## Findings

- **VD3-1 (minor):** `responder.rs:262,288`. K2a covers `drive`, whose cap and `is_full` changed, but the only Kani evidence is at 0a5d2b6. The proof impact is nil (the cap is unreachable with ≤ 6 chunks, and no new loop exists), but a Kani run on ≥ 797528f is needed before claiming 25/25 for the head.
- **VD3-2 (nit):** `accept_ok.rs:360`. The dictated name `fifty_rejected_groups_then_an_honest_group_still_accepts` contradicts its 50-case (`Rejected`). Ratify deviation 1 and either keep the name as dictated or rename it later.
- **VD3-3 (nit):** `responder.rs:50`. The assert uses the literals `(128 + 24) / 3`, not `3 * MAX_PARTIAL_GROUPS` or the queue-capacity constant, so it does not follow a change of either.
- **VD3-4 (note):** `gates.rs:5332`. `kat_portable_rerun_includes_the_hx_suite` checks the constant and the manifest, not the generated `--test` arguments or the log. The binding is structural (`:188`). This is acceptable as dictated.
- **VD3-5 (note):** `responder.rs:288`. `!processed.push(..)` is now unreachable, because the call returns at `len == R`. It is redundant and harmless.
- **VD3-6 (note):** `ci-dispatch.yml:152`/`expect.rs:96`. No test pins the `ct`/`dispatch-ct` timeout-minutes above `CT_STEP_TIMEOUT_SECONDS`; the 40-min slack is in comments only.
- **VD3-7 (note):** `M04-report.md` §5. Weisung item 7 "R-90 row if missing" is neither done nor reported as already present, and it is unverifiable from the inputs.
- **VD3-8 (nit):** `responder.rs:23-25` vs `:315-316`. The VD2-7 sentence appears twice with different wording ("(or `Rejected`)" only in the module doc).
- **VD3-9 (nit):** `gates.rs:5782`. The comment "no cover at all is no failure" holds for the parser only; the gate now fails it through `KANI_COVERS`.

## Recommended next step

Ready for push after run 37127247911 is adjudicated. No FIX-3 is needed. The reviewer should ratify deviations 1-4. VD3-1 is closed by the PR run's Kani step on 062abe9 (or one local K2a run), and deviation 3 by the PR run's ct job, both before the evidence commit.
