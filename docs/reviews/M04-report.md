# Milestone report — M04 SecMP-HX handshake + SecMP-INV (sans-IO) + ProVerif model

Branch: `m04-hx` · Base: `main` at `836a94e4f8abec27d877740291ecbe9957c10177` (M3 squash merge) · Author: Claude Code (Sonnet 5.5) · Date: 2026-10-01 –

Status: **Phase A in progress** (INV, HX, prekey store, tests, vectors, xtask, ADR-045, M3 follow-ups except F5/F34/F2).
Phase B (`formal/hx.pv`, F5, F34, F2 ct target) is a separate conversation on Opus; `formal/hx.pv` is not part of Phase A.
**Phase B (BRIEF M4-PV, 2026-10-01): STOP at B1** — `formal/hx.pv` (e42c854) gives no RESULT within 30 min, nor
does its O-7 bounded variant (§3.1, §8.1). B2–B4 not started; B5–B8 prepared on two worktree branches, not on
`m04-hx` (§1.2).
**WEISUNG M4-5 (2026-10-02, §13):** `formal/hx.pvl` + 14 session files (O-13…O-19): 5 files finish with every
verdict as expected, 9 files STOP at the 30-min cap (§13.7); `tr.pv` F5 + T13 done (46 lines as expected); gate F7,
CI job `proverif-hx`, ADR-046 done.
**WEISUNG M4-7 (2026-10-02, §13.11):** O-20…O-23 applied (O-23 in all five auth files): 14 session files pass the
gate (82 / 82 lines as expected, hBoth 1043.5 s the longest); the 5 `-auth` files (H5, H5, H8, H9, H9b) STOP at the
30-min cap (§13.11.5) — the stall also occurs without the attacker as inviter (§13.11.4).
**WEISUNG M4-8 (2026-10-02, §11.2):** K2 option (c) (`prop_outer_unpad_total_12018`); `secmp-sys-mem` `cfg(kani)`
backend (the Miri file); K4b on the real store VERIFIED for two one-record stores — the M4-3 bound (≤ 2 records)
STOPs (§11.3); K4a keeps its store model (real store > 30 min). Kani gate 25/25, 1422 s.

Inputs: `docs/07` §M4; spec `docs/03` §5, §6 (+ §7.2–7.4, §7.6 for `first_msg`), App. A/B/D; `CLAUDE.md`; `docs/06` §8;
`docs/08` ADR-043, ADR-044 (proposed), ADR-045; `docs/reviews/M04-planning/TEST-SPEC-M4.md` (115 dictated rows),
`CLAIMS-HX.md`; `docs/reviews/ref-spec-questions-M4.md`; `docs/reviews/M03-review.md` §C (F1–F23, F34);
`vectors/SCHEMA-4.10-hx.md`; `vectors/ref/hx.json` (sha256 `a33cf162e36969dc4bd70114a7c1b0ae3a97e09a187cd210c47dc374f436e7d2`, 30 cases).

## 1. Plan (written before implementation, updated during)

Scope: `secmp-proto::inv`, `secmp-proto::hx`, the prekey store trait + in-memory impl, the `hx` vector suite
(Rust generator byte-identical to `vectors/ref/hx.json`), the dictated tests (TEST-SPEC-M4 rows under their exact
names; extras named in §2), proptests P1–P11, fuzz targets F1–F7, Kani K1–K5, ct targets, xtask changes
(ADR-045 job summary, the M3 follow-ups). Not in scope: LINK/Q/relay (M5/M6), client store/CLI (M7), SAS UI,
`formal/hx.pv` (Phase B), F-M11, EXT-2, binding of LinkDataV1 profile/created, DIT ADR.
`secmp-proto` stays sans-IO; every cryptographic operation goes through `secmp-crypto` types. ADR-043 (f)/(g)/(h)
are enforced only after ratification (default 2026-10-02 ~02:45 UTC): they land in the commit after that time.
ADR-044 (b)–(f) are enforced in this milestone.

### 1.1 Steps (Phase A)

| Step | What | Test rows / F-ids closed | Status |
|---|---|---|---|
| 1 | Commit 1: plan, CLAIMS §HX, ADR-044 (proposed) and ADR-045, test spec, ref HX/INV files, `docs/07` status + API line, M3 final-run evidence | — | done |
| 2 | `inv`: InvitationV1 create/parse, URI/QR text, blob seal/open, `K_ld`/`K_inv`, invitee checks §5.5 steps 1,3,4 (ADR-043 (h): no inviter bounds) | (a) `inv_uri_roundtrip`, `inv_qr_text_equals_uri`, `inv_blob_len_and_keys`; N-1…N-23; P10, P11; F1, F2 fuzz | open |
| 3 | `hx` core: transcript, `K_id`, `K_inv`, `Initiator::start`, envelope/cells (3 chunks), `Responder::accept` (grouping per ADR-044 (c), steps 1–3, OPK delete after step 4, uniform `Rejected`), reflection / first_msg constraints (ADR-044 (e)(f)) | (a) HX roundtrip, garbage, retry, group tests; N-24…N-57, N-66…N-71; (e) review-focus assertions; P1–P9 | open |
| 4 | Prekey store trait + in-memory impl (SPK generations by `spk_id`, retention §6.1, OPK single use, RPK), invitation records and lifecycle | N-61…N-65, N-72, N-59, N-60 | open |
| 5 | `hx` vector generator (`xtask vectors`), `vectors/hx.json` byte-identical to `vectors/ref/hx.json`; `hx_vectors` test | (a) `hx_vectors` (30 cases) | open |
| 6 | Fuzz targets F1–F7 (structured seeds), Kani K1–K5 | (d) | open |
| 7 | ct targets `inv_fingerprint_compare`, `x25519_zero_check`, `hx_accept_reject_inner`, `hx_accept_reject_first_msg` | (f) | open |
| 8 | xtask: ADR-045 job-summary table for every gate step | ADR-045 | open |
| 9 | M3 follow-ups F1, F3, F4, F6–F14, F16 (after ratification), F17–F23, ctreport `class_median` refusal, ADR-041 Amendment 2 status line, M03-report §8 Q-1 text | F-ids | open |
| 10 | Report evidence, push, PR | Phase-A closing message | open |

### 1.2 Steps (Phase B, BRIEF M4-PV; head before: 2e5953e)

| Item | What | State |
|---|---|---|
| B1 | `formal/hx.pv` (CLAIMS §HX) | committed `e42c854`; **STOP** (§8.1); replaced by `formal/hx.pvl` + `formal/hx/*.pv` (`79f4705`, WEISUNG M4-5): 9 of 14 files **STOP** (§13.7); WEISUNG M4-7 (`4f5562d`): 14 session files pass, 5 `-auth` files **STOP** (§13.11.5) |
| B2 | `tr.pv` F5 (M3 R-12) | done `ea071c3` (§13.4) |
| B3 | `tr.pv` F34 / CLAIMS T13 | done `ea071c3` (T13 false ×7) |
| B4 | ProVerif gate F7 | done `5bf47a1`, CI `6599d49` (§13.5) |
| B5 | ct `tr_decrypt_reject_skipped` (F2) | on `m04-hx` as `5005399` (WEISUNG M4-4); respecified in `8077590` (§12) |
| B6 | ct `inv_fingerprint_compare`, `x25519_zero_check`, `hx_accept_reject_inner`, `hx_accept_reject_first_msg` | on `m04-hx` as `67dc5cb` |
| B7 | F19 pre-checks + reject sites | on `m04-hx` as `260b4bd`; TR/INV site tags added in `db6d085`, pre-checks assert them in `8077590` (§12) |
| B8 | F1 branch-free `any_skipped` | on `m04-hx` as `e48a99d`; deviation (§5.2) accepted by WEISUNG M4-4 |

The two worktree branches were deleted after the cherry-picks (WEISUNG M4-4 Part A, §12).

## 2. What was built (Phase A, WEISUNG M4-1 applied; local HEAD see §9)

- `secmp-proto::inv`: URI/QR text with constant-time, `Zeroizing` base64url (V-5), blob seal/open, `K_ld`/`K_inv`, `invitee_check` → `InviteeAccepted` (private fields, accessors; V-12), `IssueError` bounds.
- `secmp-proto::hx`: `transcript`, `session_key`, `k_id`; `Initiator::start(&InviteeAccepted, &InitiatorKeys, routes, profile, now, entropy)`; `HandshakeCells::release(persist(cells, state))` and `PersistedCells` for retry (V-6); `Responder::accept` over the array-based `Groups`/`drive` (ADR-044 (c)) with one `commit_accept` (OPK deleted and record consumed, V-7).
- `secmp-proto::prekeys`: `IdentityKeys`, `PrekeyStore` (+`commit_accept`), `MemoryPrekeyStore` (SPK generations by id with retention, OPK single use, RPK, records, `consume_record`, `issue_invitation`, `retire_expired`); bundle signing now uses `PrekeyBundle::signed_fields` (V-11).
- `tr`: `Opened::header_counters` (V-10: no fail-open default), entropy extensions, `encrypt_padded_kat`.
- Vectors: `vectors/hx.json` frozen (sha256 `a33cf162…`), generator and replay as before.
- Tests: `tests/hx/` 109 tests + 16 lib unit tests in `inv`/`hx`/`prekeys`; proptest-style properties P1–P11; fuzz F1–F7; Kani K1–K5.

## 3. Evidence (docs/reviews/M04-evidence/)
`ci-fast-aarch64-apple-darwin-local.txt` (PASS), `vectors-xtask.txt` (11 suites identical), `kani-xtask-step.txt` (`cargo xtask step --strict kani`: 24/24 harnesses verified, 847 s, Kani 0.68.0), `kani-k5-first-run-harness-overflow.txt` (first K5 run: failing check `kani_cell_plaintext_decode_total.assertion.1` = `attempt to add with overflow` at `len + 1` in the HARNESS' own assumption, not the decoder; fixed by `len >= PT_LEN - 1`; V-3 decoder unit tests `cell_plaintext_decode_rejects_i_ge_total` / `_total_ne_3` pass, the M2 decoder already rejects both), `fuzz-m4-local-120s.txt` (7 targets × 120 s, no findings).
Kani bounds (before WEISUNG M4-3): K1 none; K2 `unpad` stubbed (any proper prefix or rejection); K3 `Groups<u8,u8,2>`, ≤ 4 chunks over 3 init_ids, unwind 6 (44 s); K4 production bound 8 slots, ≤ 4 chunks over 3 init_ids, unwind 10 (250 s); K5 unwind 4010 (50 s). Current bounds and uncovered regions of K2–K4: §11.

### 3.1 ProVerif — `formal/hx.pv` (Phase B, B1)

Model `formal/hx.pv` @ `e42c854`, 938 lines, sha256 `88054ef35a5d6cc45d4193c48158c513553e5efb4e40cb12186335551f9168a9`;
`formal/tr.pv` unchanged (sha256 `e1c3f488…5a4d`; baseline run on 2e5953e: 39 RESULT lines as `expect::PROVERIF_EXPECTED`,
66 s, 390 "secrecy assumption verified" lines). 98 queries in one declaration, CLAIMS order: H1 2 · H2 2 · H3 2 · H4 1 ·
H5 2 (hClean, hKEM) · H6a 13 · H6b 1 · H7a–H7d 2 each · H8 1 · H9 1 · H9b 1 · H9c 1 · H10 1 · H11 56 (4 × 14
sessions) · H12 2 · H12b 2 · H12c 2. ProVerif 2.05, this Mac (M1 Pro), runs in parallel with other ProVerif runs.

| Run | Wall time | Result |
|---|---|---|
| replicated `formal/hx.pv` (byte-identical copy), cap 1800 s | 1800.8 s (killed) | no RESULT line; last: `138600 rules inserted. Base: 55688 rules (578 with conclusion selected). Queue: 276175 rules.` (`M04-evidence/proverif-hx-e42c854.txt`) |
| O-7 bounded variant (`M04-evidence/proverif-hx-bounded-e42c854.pv`, sha256 `6ee50fe8…6f8`), cap 1800 s | 1801.0 s (killed) | no RESULT line; last: `329200 rules inserted. Base: 73650 rules (519 with conclusion selected). Queue: 295274 rules.` (`M04-evidence/proverif-hx-bounded-e42c854.txt`) |

Bounded: yes (attempted, per O-7) — neither attempt finished. Per-ID verdict table (CLAIMS ID | verdict | session |
wall time): every row H1 … H12c "not reached" (no RESULT line), sessions as `hx.pv` header §3, wall time — (both
runs killed at 1800 s). Diagnostics (single session, devices, honest-flow sanity, clause profile):
`M04-evidence/proverif-hx-diagnostics-e42c854.txt`; the honest flow of the fixed model is reachable (all four H11
lines of hClean "is false." in the unreplicated reduced instance, 5.8 s).

## 4. Verifier findings
V-1 done (`accept_counter_rules_reject_after_a_valid_mac`: MAC verifies, `remaining()==0`, store/OPK unchanged, control 0/0 accepts; `first_msg_with_counters` advances `ck_s`). V-3 done (two named decoder tests). V-5 done (arithmetic base64, `Zeroizing`). V-6 done (`start_persist_error_is_returned_and_nothing_sent`). V-7 done (`accept_success_consumes_record_and_opk`). V-8 done (docs; `hx_secrets_are_zeroizing_types` type ascription). V-9 done (hard assertions, `low_order()` extended to 8 values, moved to `hx/tests.rs`). V-10 done. V-11 done. V-12 done (`docs/07` API line updated).

## 5. M3 follow-ups (Part E)
F3 done (dependency-free YAML-aware reader, `required_job_bypasses_are_findings`) · F6 not done: formal (`tr.pv`) — Phase B · F8 done · F9 done (bound check before `apply`; the post-apply error arm is provably unreachable) · F10 partly (`Profile.name` is `Zeroizing<String>`; hosts/msg_ids unchanged) · F11 done · F12 partly (type-pin test in `tr/ratchet.rs`; no heap-probe pattern in testkit) · F14 done · F18 done · F20 done (ADR-042 consequence sentence + non-kat nextest in step 4) · F21 done · F22 done (`miri-full.yml` one job per package; required jobs unchanged) · F23 done · ctreport `class_median` refusal done (Amendment-2 format reports only) · ADR-041 Amendment 2 status line, M03-report Q-1 text done. F16 waits for ADR-043 ratification (after 2026-10-02 02:45 UTC). F4, F17 skipped (optional).

### 5.1 Model coverage — `formal/hx.pv` (Phase B)

Paths covered and excluded: exactly the CLAIMS §HX text "Paths the model covers / excludes" (`formal/CLAIMS.md`
§HX, referenced, not copied); `hx.pv` header §1 maps each covered path to its process line. Bounded: **no** — the
committed model is the replicated one; the O-7 bounded variant (2 invitations × 2 initiator sessions per invitation
source (from R, and in non-hId sessions from c) × 3 acceptance attempts per invitation) exists only as evidence
(`M04-evidence/proverif-hx-bounded-e42c854.pv`), because it did not terminate either (§3.1).
Choices inside the CLAIMS text (header §3, §5, queries): hKCIi also has LeakInv phase 0 (its row names none; H9c is
H1 (i), whose assumptions include it); InvitationV1 is modelled as (ld_id, link_key, inviter_fp) (inv_sid,
inv_send_seed carry no HX key material); H6a is one line per session without RevealLT(R) before IStart (13 lines);
the H11 IStart/RAccept/IConfirm lines name the honest identities of the session; the TR reply of R (H6b) carries a
fresh name as content. Devices (header §7): `new n[]`, the OPK cell read with `(=osk, =odk)`, `eph()` indices with
123 secrecy assumptions, `selFun = Term`, two `nounif` declarations.

### 5.2 Deviation from the letter — B8 / F1 (prepared commit `2a93d6c`, not on `m04-hx`)

The brief says "decode only on `Path::Skipped`". Taken literally this changes one input class: a header ciphertext
that opens under a skipped key whose plaintext does not decode, with its raw `(hk, n)` not in `skipped`, and that
also opens under `hk_r`/`nhk_r` (only a contact holding both keys can build it: the header AEAD is not
key-committing) — today rejected (ADR-043 (b): `Open` includes decoding), under the letter accepted on the
chain/step path. `2a93d6c` keeps today's behaviour: after `decide`, the first skipped key's header is decoded on
every accepting path (used on Skipped; decoded and dropped on Chain/Step), selected without a branch on
`any_skipped`. Test `undecodable_skipped_header_rejects_on_every_path` pins the class (fails under the letter with
`Some(("chain", 8))`); `any_skipped_single_conversion` pins one conversion up to and including `decide`.

## 6. ADR-045
`xtask/src/summary.rs`; every step of `ci-full`/`ci-fast` appends a table (`status`, one row per verdict line; for `ct` the run verdict, runner timer, every target/control row from the gate's reading; for `proverif` the sha256 of the models) to `$GITHUB_STEP_SUMMARY`, else stdout. Test `summary::tests::the_ct_table_comes_from_a_recorded_report` (run 36840478213 report: 18 rows). A run page with the table is the next push's PR run.

## 7. Test counts per spec section (implemented / passing / extra)
(a) positives + vectors: 8 listed + `hx_vectors`, generator, flow, builder controls → all pass; extras: `builders_reproduce_an_accepted_envelope`, `accept_counter_rules_reject_after_a_valid_mac`, `accept_success_consumes_record_and_opk`, `hx_secrets_are_zeroizing_types`, `start_persist_error_is_returned_and_nothing_sent`. (b) negatives N-1…N-72 (N-58 withdrawn): all rows named, all pass. (c) P1–P11 pass. (d) F1–F7 implemented, 120 s each, K1–K5 verified (K1 is a check of the chunking constants and their tiling, not of the split or the join; M4 review C-15, E-12). (e) all named assertions pass. (f) ct targets: Phase B (not started). (g) F10–F12 per §5.

### 7.1 ct targets (Phase B; prepared on `worktree-agent-a77420be221171832` `4d92ec2`, not on `m04-hx`)

Local run of that commit's bench, release, `SECMP_CT_SCALE=6` (166 666 samples per target, 537 s; a shortened run,
refused by the gate's reader by design; the full local gate needs ≈ 50 min > the 10-min foreground cap):
`M04-evidence/ct-local-4d92ec2-scale6.txt`. Clock `cntvct_el0`, 1 tick = 41.667 ns = effect floor, k = 1 for all five.

| Target | Pre-check (REACH) | Verdict | Max reproduced shift | Reject site, both classes |
|---|---|---|---|---|
| `tr_decrypt_reject_skipped` | yes | **FAIL** | p50: t −12.88 / −15.29, Δ −1.41 / −1.42 floors (class 0 faster; median 27 917 ns); A/A max \|t\| 1.06 | Err(Rejected); site tag n/a (TR, §8.1) |
| `inv_fingerprint_compare` | yes (+ unmodified invitation Ok) | PASS | none (max \|t\| 2.83 / 1.72) | Err(Rejected); site tag n/a (`inv.rs`, §8.1) |
| `x25519_zero_check` | yes (Ok; output non-zero only in byte 0 resp. 31) | PASS | none (1.79 / 0.42) | not a reject target |
| `hx_accept_reject_inner` | yes (+ honest envelope Ok) | PASS | none (1.74 / 2.96) | "inner open" |
| `hx_accept_reject_first_msg` | yes (+ honest envelope Ok) | PASS | none (1.89 / 1.54) | "first_msg decrypt" |

Controls: positive control PASS (max \|t\| 15 731); A/A′ placement PASS (0.98 / 1.48); same-content PASS (1.05 /
1.61); `min_leak_control` reached 3.05 floors. Run verdict FAIL (from `tr_decrypt_reject_skipped` only); nothing was
tuned. `x25519_zero_check` measures `secmp_crypto::X25519Secret::diffie_hellman` (the helper behind `dh_checked`,
which `start`/`accept` call; no existing target measured it); class inputs computed offline in Python (RFC 7748
§5.2 and 487 Wycheproof cases reproduced): class 0 output u = 9, class 1 output u = 49·2^248. HX site tag: kat-only
thread-local `hx::ACCEPT_SITE_KAT` (`responder.rs:55`), set at the start of each §6.6 step (8 kat-only writes per
`accept`, identical in both classes). xtask tests 100 → 104 (`the_ct_reader_accepts_site_and_precheck`,
`ct_sites_go_on_the_verdict_row`, `ct_sites_need_a_passed_precheck`, `a_failed_precheck_fails_the_gate`).
B8 (`2a93d6c`): `cargo nextest run -p secmp-proto` 125 → 128, `--features kat` 242 → 245, all pass; new tests
`any_skipped_single_conversion`, `undecodable_skipped_header_rejects_on_every_path`, `header_n_reads_bytes_38_to_42`;
`vectors/tr.json` sha256 `01a6d161…a837` before and after (`cargo xtask vectors`: 11 suites agree, no file changed).

The FAIL above is diagnosed (reviewer, WEISUNG M4-4) as the position of the opening trial (trial 0 vs trial 2 of 5)
— R-59, accepted under R-15 — plus a secret-indexed `mk` load (R-58, fixed); the target is respecified and re-run:
§12.3.

## 8. Open / Phase B
ct targets (f), `formal/hx.pv`, F1, F2, F5, F6, F7, F19, F34, F16 (after ratification), F10 hosts/msg_ids, F12 heap probe.

### 8.1 Blocked — Phase B STOP (BRIEF M4-PV §7)

1. **STOP — ProVerif > 30 min after the bounded fallback.** `formal/hx.pv` (`e42c854`) and its O-7 bounded variant
   each ran 1800 s without a RESULT line (§3.1). B2–B8 were not continued on `m04-hx` (brief §1).
2. **Injectivity cannot come from the OPK cell in ProVerif (evidence, independent of termination).** H5 (hClean,
   hKEM), H9b (hKCIlt) and H10 (hClean) are inj-event correspondences whose injectivity rests on the single-use OPK
   cell (`hx.pv:761` `in(ocell, (=osk, =odk))`, `:779` and `:808` `out(ocell, (osk, odk))`). ProVerif's clause
   abstraction keeps a private-channel message after it is received. Probe
   `M04-evidence/proverif-hx-probe-opk-cell.pv` (the same cell: one output per invitation, replicated attempts,
   equality read, re-output on failure only) gives for both injective shapes "cannot be proved" ("but … is true"
   for the non-injective form); derivation (`proverif-hx-probe-opk-cell.txt` l.95-128): step 2 I sends
   senc((ek, o), kinv); step 3 `mess(cell_2, o_3)` (one output of the cell, l.101); steps 4 and 6 attempts @sid_3
   and @sid_2 both receive the same envelope and the same cell message → RAccept twice; "Could not find a trace
   corresponding to this derivation." The same with `set preciseActions = true`
   (`proverif-hx-probe-opk-cell-precise.pv`/`.txt`). A terminating
   `hx.pv` would therefore give H5, H9b, H10 "cannot be proved" — opposite to the gate rule (true).
3. **F19 TR reject-site tag:** needs `crates/secmp-proto/src/tr/ratchet.rs` (the §7.4 reject sites are there; no
   tag exists) — outside §0 (ratchet.rs is F1-only). The TR targets are pre-checked for `Err(Rejected)` only.
   **INV:** `inv_fingerprint_compare` has no site tag (`crates/secmp-proto/src/inv.rs` outside §0); pre-check is
   `Err(Rejected)` plus the unmodified invitation accepted. — *Resolved by WEISUNG M4-4 Part E (§12.4).*
4. **Pre-push check fails on the unchanged Phase-A head `2e5953e`:** `cargo clippy --workspace --all-targets -- -D
   warnings` → `error: missing documentation for the crate` at `crates/secmp-testkit/tests/differential.rs:2`
   (built without `kat`; outside §0). The gate's form (`--all-features --locked`) passes. — *Resolved by WEISUNG
   M4-4 Part F (§12.5).*

Question: how is `formal/hx.pv` to be run within the gate's time (scope or bound of the sessions/attacker roles),
and how is the injectivity of H5/H9b/H10 to be obtained, given item 2?

## 9. Push state
PR run 36885710027 (head 50cfca3) was still running at the end of this session: the 4 later commits are NOT pushed.
Phase B (BRIEF M4-PV): run 36885710027 was `in_progress` at the start (Part 0) and at 2026-10-01 20:23 CEST; no push window
(after B4 / after B8) was reached because of the B1 STOP — nothing pushed. Unpushed on `m04-hx`: 8455f93, b552682,
98b6b22, 268bb1d, 2e5953e (Phase A), e42c854 (B1), and the Phase-B report commit.

## 10. WEISUNG M4-2 (Phase A closure items)
§1 state at start: head `3a02557`; `git log origin/m04-hx..HEAD` = 7 commits; status: only untracked `.claude/`.
- A (V-6): `HandshakeCells::to_bytes` is `pub(crate)`; doc-test `compile_fail` on `HandshakeCells` (`hx/mod.rs`, named `handshake_cells_expose_no_cells_before_release` in its text); the external test that read the cell bytes now captures them through `release`.
- B (V-8): module doc matches `initiator.rs:31-32, 192-193`; `hx_store_and_persisted_bytes_are_zeroizing_types` (crate-private pins: SPK_dh/SPK_kem/RPK_kem/OPK_dh/OPK_kem, `to_bytes`, `state_bytes`) next to `hx_secrets_are_zeroizing_types`.
- C (F9): `decrypt_with` builds `next` (round trip `to_bytes`/`from_bytes`, since `RatchetState` has no `Clone`), serialises it, then replaces; tests `receive_persist_bytes_equal_state_after_swap`, `receive_error_leaves_state_unchanged`. Removed: the pre-check `after = skipped.len() - remove + added; if after.saturating_sub(select::evicted(after)) > MAX_SKIPPED` (dead).
- D (F10): `Accepted.routes: Zeroizing<Vec<RouteDescriptor>>`, `InviteeAccepted.invitation: Zeroizing<InvitationV1>`, `Host` holds `Zeroizing<Vec<u8>>`; `Zeroize` impls for `RelayRef`/`RelayQueue`/`RouteDescriptor`/`InvitationV1` (host, onion, akc, relay_fp, sid, ld_id, inv_sid); `secmp-crypto` re-exports `Zeroize` (no new dependency). msg-id fields are not held by `Accepted`/`InviteeAccepted`: nothing to wrap there.
- E: `delete_opk` hits remaining: the method itself and its impls (`prekeys.rs:330,721,724`) and the Kani stub (`kani_proofs.rs:487`).
- Unpushed: PR run 36885710027 `in_progress`.

## 11. WEISUNG M4-3 (Kani K2, K3, K4 strengthened)
§1 state at start: head `69d1320`; `git log origin/m04-hx..HEAD` = 11 commits; status: only untracked `.claude/`.
Commits: `e1630b1` (harnesses, xtask list), `648bd3f` (K2 back to the stubbed scan after K2a gave no verdict in 2 h),
then this report. Evidence: `M04-evidence/kani-m4-3-attempts.txt` (every single-harness attempt with its time, and the
K2a source), `kani-k4-store-probe.txt` (the K4b STOP), `kani-xtask-step-648bd3f.txt` (the gate run). The single runs
shared the CPU with 1–3 other CBMC runs.

| Harness | Result | Bound used | Not covered |
|---|---|---|---|
| K2 `kani_outer_unpad_total` | unchanged (STOP §11.1) | as before: `unpad` stubbed (any proper prefix or rejection); every input of 0…12019 bytes | the real ISO/IEC 7816-4 scan at 12018 bytes, and the assertion that an accepted input's field string is the 9362-byte `Outer` (the scan itself is proven by `padding` for sizes ≤ 32) |
| K2 full buffer | no verdict, 2 attempts | real `unpad`, 12018 symbolic bytes, unwind 12020 | — |
| K2a (last 2700 bytes symbolic) | no verdict in 2 h | real `unpad`, fixed valid field prefix + 2700 symbolic bytes, unwind 2702 | — |
| K2b | not added | — | each case scans ≥ 2656 bytes, concrete or not |
| K3 `kani_hx_grouping` | VERIFIED, 275 s in the gate (529 s alone, shared CPU) | **fallback** N = 3 slots, 4 distinct symbolic ids, ≤ 6 inserts `(init_id, i ≤ 2, symbolic u8 tag)`; independent model (arrival order, first-seen tag per `i`); a completed group removed by `Groups::remove` as `drive` does; unwind 7 | N = 4…8, more ids or inserts; the 4006-byte chunk type (u8 stand-in) |
| K4a `kani_accept_opk_delete_only_on_success` | VERIFIED, 293 s in the gate (651 s alone, shared CPU) | `drive` with the production 8 slots; ≤ 6 chunks of 3 init_ids (two complete groups); 4 nondeterministic step outcomes per group; symbolic `opk_id`, `ld_id` and store state (OPK present, record present, commit durable); commit ⇔ a processed group passed every step, no processing after it; the store untouched at every processing; `Ok` ⇔ the commit succeeded, then OPK and record gone; `Err` ⇒ store as before; cover "a rejected complete group, then a group of another init_id commits" SATISFIED; unwind 10 | the real `MemoryPrekeyStore` (§11.1); > 6 chunks |
| K4b `kani_commit_accept_atomic` | not added — STOP §11.1 | — | `MemoryPrekeyStore::commit_accept` (concrete tests: `accept_success_deletes_exactly_that_opk`, `accept_success_consumes_record_and_opk`) |

Harness count 24 → 24 (K3 and K4a changed in place; K2 unchanged). Times of the attempts that did not finish
(`kani-m4-3-attempts.txt`): K2 full buffer — 1900 s cap at unwinding iteration 1720 of 12018 (first form, symbolic
length), 1830 s cap at iteration 2138 of 12018 (exactly as the brief: fixed 12018 bytes, one scan); K2a — 7200 s cap,
the scan unwound by 22:13 (54 min), then no verdict; K2b — ≈ 18 min for 2370 of the all-zero buffer's 12018 scan
iterations; K3 at N = 8, 9 ids, 10 inserts — 1900 s cap (symex 1716 s, 40153 VCCs left) and, with the corrected
model, 1830 s cap still in symex. Kani's symbolic execution of the `unpad` scan (`iter().rposition`) costs time
roughly quadratic in the scanned length, for symbolic and concrete bytes alike (600 symbolic bytes: 273 s), and every
accepted input needs a scan of 2656 bytes (from byte 12017 down to the marker at 9362).

Deviations from the brief:
1. `crates/secmp-proto/src/hx/responder.rs` (outside the file list): `#[cfg(kani)] Groups::remove_completed`, which
   calls the private `Groups::remove` — the function `drive` removes a completed group with, which the brief requires
   K3 to call. Compiled only under Kani, like the existing `#[cfg(kani)] Groups::get`; no product build changes.
2. K3's model removes entries with an element loop: with `copy_within` (a `ptr::copy` over a symbolic count) Kani
   reported a counterexample (`now[k] == expected`) whose inputs pass natively and under Kani with the same values
   concrete — a spurious result in the harness's model, not in `insert`/`remove` (attempts file, K3 2–3).
3. K4a compares the 16-byte `ld_id` at one symbolic index (`same_bytes`, as the M2 harnesses do): a `==` on the
   array is a `memcmp` loop that needs unwind 17, and unwind 17 made `Groups::remove`'s loop unroll to 16 (> 40 min).

### 11.1 Blocked — WEISUNG M4-3 (STOP)
1. **K2: the real scan at 12018 bytes does not finish in time.** Harness: K2 `kani_outer_unpad_total` (full buffer)
   and its fallback K2a. Failing check: none — no verdict (full buffer: > 30 min twice; K2a: > 2 h, symbolic execution
   unfinished). Property: not contradicted, not proven. K2b is not feasible either (above). K2 stays as in `69d1320`.
   Options: (a) a one-off K2a run outside the gate with a longer limit, if the evidence may come from outside CI;
   (b) a hand-written marker scan in `codec::unpad` with a Kani loop contract (`-Z loop-contracts`), proven once
   for all sizes — a product-code change; (c) accept `padding` (the size-generic `pad`/`unpad` for every size ≤ 32)
   plus the stubbed K2 as the coverage.
2. **K4b and the real store of K4a.** Harness: K4b `kani_commit_accept_atomic`, and K4a's "the store in the harness
   is the real `MemoryPrekeyStore`". Failing check: `secmp_sys_mem::secret_page::os::Mapping::new.unsupported_construct.1`
   — "call to foreign "C" function `mmap` is not currently supported by Kani" (probe
   `MemoryPrekeyStore::starting_at(1, 1).issue_opk(&mut OsEntropy)`); harness-file stubs of the libc calls are not
   applied by Kani to foreign functions; with `-Z c-ffi`: "Function `mmap` with missing definition is unreachable"
   (`kani-k4-store-probe.txt`). Property: not contradicted — the store cannot be built under Kani: every OPK, SPK
   generation and record comes through the sealed `Entropy` (only `OsEntropy` without `kat`) into `LockedSecret` =
   `secmp_sys_mem::SecretPage` (mmap + mlock; on Linux first the variadic `syscall(memfd_secret)`), all with private
   fields, so no stub in `secmp-proto` can construct them. What would unblock it (a product change, not made): a
   `cfg(kani)` heap backend in `secmp-sys-mem` beside its `cfg(miri)` one (`secret_page/heap.rs`), or `cfg(kani)`
   constructors of `OpkSecrets`/`SpkGeneration`. K4a was strengthened with a store model that keeps
   `commit_accept`'s contract instead.

Questions: K2 — which of (a)–(c)? K4 — may `secmp-sys-mem` get a `cfg(kani)` heap backend (as for Miri) so that K4b
and K4a run on the real `MemoryPrekeyStore`, or are K4a's contract model plus the two concrete `commit_accept` tests
the accepted coverage?

Gate: `cargo xtask step --strict kani` on `648bd3f`: PASS, 24/24 harnesses verified, 1084 s (step), peak RSS 6.64 GiB,
no other CBMC run in parallel; K2 46 s, K3 275 s, K4a 293 s, K5 41 s (`kani-xtask-step-648bd3f.txt`).
Push: `gh run list --branch m04-hx --limit 3` at 23:43 CEST showed no run `in_progress`/`queued` (36885710027 and
36862814521 completed): pushed with this commit.

### 11.2 WEISUNG M4-8 (K2 option (c); `cfg(kani)` backend; K4b and K4a on the real store)
§1 state at start: head `8434372`; `git log origin/m04-hx..HEAD` = 3 commits (`4f5562d`, `7c235d2`, `8434372`);
status clean. Commits: `13640ac` (sys-mem backend), `15b7b3b` (K4b, K4a doc, harness list), `80f1f5b` (property
test), then this report. Evidence: `M04-evidence/kani-m4-8-attempts.txt` (every attempt with time and memory; the
backend-absence proof), `kani-xtask-step-80f1f5b.txt` (the gate run).

**K2 — option (c).** Not proven by Kani: the scan at full size; covered by `padding` (≤ 32 B) and
`prop_outer_unpad_total_12018`. `kani_outer_unpad_total` stays the stubbed K2 of `69d1320`.
`prop_outer_unpad_total_12018` (`tests/hx/props.rs`, seeded like M3: `DEFAULT_SEED`, or `SECMP_PROPTEST_SEED`,
which CI sets to the run id): 450 buffers of 12018 bytes, 64 each with the 0x80 marker at 9362 (valid), 0, 1, 9361,
9363 and 12017 (random bytes before it, zeros after it, half of them with version byte 1), the all-zero and the
all-0x80 buffer, and 64 fully random buffers. Invariant: never panics; `unpad` returns exactly the bytes before the
last non-zero byte if that byte is 0x80 (reference: a forward scan), else `Rejected`; `Outer::decode` returns `Ok`
exactly when the marker is at 9362, `ver` = 1 and `ek_I` passes the X25519 key check, and then the field string is
9362 bytes, `buf[9362]` = 0x80, `buf[9363..]` all zero and the `Outer` re-encodes to `buf`; otherwise
`Err(Rejected)`; at least 8 valid buffers accepted. PASS in 0.30 s with the default seed and with
`SECMP_PROPTEST_SEED=36885710027`.

**Backend.** `secret_page.rs` selects `secret_page/heap.rs` under `cfg(any(miri, kani))` and the unix/windows
backends under `not(any(miri, kani))`: the Kani backend is the Miri backend file (a `Box` of one 4096-byte page,
zeroised by `SecretPage::drop`, no `mmap`/`mlock`), no new `unsafe`; crate root documents it as "the verification
backend (Kani), like the Miri one". Miri: same code under `cfg(miri)`, only doc comments changed. Absent from
non-Kani builds: no `--cfg kani`/`--cfg miri` in any `secmp_sys_mem` rustc invocation of `cargo build --release` and
`cargo test --no-run`; `nm -u` of the native test binary shows the unix backend's `_mmap _mlock _mprotect _munlock
_munmap`; the new test `heap_backend_only_under_miri_or_kani` (backend is `Heap` ⇔ `cfg!(any(miri, kani))`) passes.

| Harness | Result | Bound used | Not covered |
|---|---|---|---|
| K4b `kani_commit_accept_atomic` | VERIFIED, 304.3 s in the gate | real `MemoryPrekeyStore`; two stores: SPK 1, OPKs 1 and 2, record `[1; 16]` naming OPK 1 — or naming OPK 2, then OPK 2 deleted; arbitrary `created`/`expires`; every `(opk_id, ld_id)`; one arbitrary probe id per kind; unwind 3 | the WEISUNG M4-3 bound: every store of ≤ 2 OPKs and ≤ 2 records with arbitrary ids (STOP §11.3); a second record |
| K4a `kani_accept_opk_delete_only_on_success` | VERIFIED, 306.1 s in the gate | unchanged: the store model (`ContractStore`), ≤ 6 chunks, 3 init_ids, 8 slots, unwind 10 | the real store: no verdict in 30 min (below) |
| K2 `kani_outer_unpad_total` | VERIFIED, 58.6 s | unchanged (stubbed scan) | the full-size scan → `prop_outer_unpad_total_12018` |

K4b checks: no panic; `Ok` ⇔ the OPK `opk_id` and the record `ld_id` are both held, and then both are gone;
otherwise `Err(Rejected)`; each other OPK, the record (if not consumed) and the SPK generation keep their tag (fields
and the first secret byte, which names the key: the RNG stub makes draw *d* the byte *d* repeated); the probe ids:
present after exactly as before unless removed, same tag — nothing else removed, changed or added; cover "a
commit" satisfied. Stubs (in `kani_proofs.rs`, K4b only, none in the store's logic): `secmp_crypto::rng::fill`
(Kani executes no `getentropy`), `zeroize::optimization_barrier` (inline `asm!`), zeroize's `[Z; N]` wipe as one
assignment of zeros, and `[u8; 16] ==` (Kani's `memcmp` model) without a loop — the last two are loops of 64 and
16 steps, and `#[kani::unwind]` bounds every loop of a harness: with them CBMC unrolled each loop over the store's
vectors 64 or 16 times (no verdict in 30 min).

K4a on the real store: no (kept the model, as the WEISUNG allows). `drive` on `MemoryPrekeyStore` with the K4a
bound gave no verdict in 30 min three times: unwind 65 without stubs (1811 s, CBMC timed out), unwind 17 with the
wipe stub (stopped at ~27 min, symex unfinished), unwind 10 with both stubs (1803 s, CBMC timed out).

Harness count 24 → 25. Gate: `cargo xtask step --strict kani` on `80f1f5b`: PASS, 25/25 verified, 1422 s (step),
wall 1423 s, peak RSS 6.33 GiB, nothing else running; K4b 304.3 s, K4a 306.1 s, K3 279.0 s, K2 58.6 s.
Other checks: `cargo nextest run -p secmp-proto --all-features` 257/257 PASS (81.5 s); `cargo xtask step --strict
fmt clippy policy` PASS; `cargo clippy -p secmp-proto -p secmp-sys-mem --all-targets -D warnings` clean (no `kat`);
`cargo nextest run -p xtask kani` 2/2 PASS (harness list test now 25).

Deviations from the brief:
1. K4b's bound is two concrete stores with one record, not every store of ≤ 2 OPKs and ≤ 2 records (STOP §11.3).
2. The four stubs above, and the RNG stub's concrete secrets (the store never reads them; symbolic secrets only
   added solver time).
3. Files beyond "the `cfg(kani)` backend only" in `secmp-sys-mem/src`: the absence test and the
   `cfg(not(any(miri, kani)))` on the OS-view test (`secret_page.rs`), and the backend's doc comments.
4. `kani_proofs.rs` imports `core::cmp::PartialEq` explicitly: Kani resolves the stub path neither through the
   prelude nor through `core::cmp::PartialEq` (the derive macro).

### 11.3 Blocked — WEISUNG M4-8 (STOP)
1. **K4b at the WEISUNG M4-3 bound.** Harness: `kani_commit_accept_atomic` with a symbolic store (arbitrary first
   ids, optional SPK, ≤ 2 OPKs, ≤ 2 records with arbitrary `ld_id`/`spk_id`/`opk_id`, optional `delete_opk` of an
   arbitrary id), and also as 28 concrete store shapes. Failing check: none — no verdict. Best runs: with all four
   stubs, unwind 3: symex 47 s (337 518 steps, 8 794 VCCs), then "CBMC appears to have run out of memory" in the
   propositional reduction (1194 s, 3.06 GiB; again alone with concrete secrets: 800 s, 3.00 GiB); without the
   `==` stub (unwind 17): CBMC timed out at 30 min. Property: not contradicted, not proven. Bisection on concrete
   stores (presence checks only): 1 OPK + 1 record 13.1 s, 2 OPKs + 1 record 39–46 s, **any store with a second
   record: no verdict in 9–20 min** (2 OPKs + 2 records with the full checks: 20-min cap, 5.30 GiB) — a second
   record makes `consume_record` a `Vec::remove` of an `InvitationRecord` at a symbolic index. A symbolic store
   with ≤ 2 OPKs and ≤ 1 record did not finish in 9 min either (3 runs at once). Options: (a) accept K4b as committed (two
   concrete one-record stores) plus the concrete tests of two records (`accept_success_deletes_exactly_that_opk`,
   `accept_success_consumes_record_and_opk`); (b) a one-off run of one two-record store outside the gate with a
   longer limit (not tried beyond 20 min; memory grew to 5.3 GiB of 16); (c) leave K4b at the model level (K4a).
   Question: which of (a)–(c)?

Push: `gh run list --branch m04-hx --limit 4` at 2026-10-02 17:17 CEST showed no run `in_progress`/`queued` (last PR
run 36983733373, head `2c23c0f`, completed `failure`): pushed with this commit (`13640ac`…this commit, together with
the earlier unpushed `4f5562d`, `7c235d2`, `8434372`).

## 12. WEISUNG M4-4 (B5–B8 landed, R-58, F2 respecified, F19 site tags)

§1 state at start: head `812e1bd`; `git log origin/m04-hx..HEAD` = 0 commits; status: only untracked `.claude/`;
`worktree-agent-a4a02fcd8ae0c8aac` (`2a93d6c`) and `worktree-agent-a77420be221171832` (`4d92ec2`), each checked out in
its worktree under `.claude/worktrees/`. WEISUNG M4-3 had committed and pushed (`812e1bd`).

Commits: `5005399`, `67dc5cb`, `260b4bd`, `e48a99d` (Part A), `db6d085` (Parts B, D, E: product and unit tests),
`8077590` (Parts C, E: bench), `2b6373d` (Part F.3), `14e55da` (mutation-gate exclusion, §12.3), and this report.

### 12.1 Part A — the prepared commits
`32005b0` → `5005399`, `1f3e113` → `67dc5cb`, `4d92ec2` → `260b4bd`, `2a93d6c` → `e48a99d`, in that order; **no
conflicts** (git auto-merged `xtask/src/expect.rs`, `hx/mod.rs`, `hx/responder.rs`, `tr/ratchet.rs`). F9 is intact
(`decrypt_with`, `ratchet.rs:721-753`: the post-step state is built and serialised before it replaces `self`), F10
untouched (other files). The F1 deviation (§5.2) is kept with `undecodable_skipped_header_rejects_on_every_path`
(passes). `git branch -D` refuses a branch checked out in a worktree, so both worktrees (no uncommitted changes) were
removed with `git worktree remove` first; then both branches were deleted. Nothing else was deleted.

### 12.2 Part B — R-58: `mk` selected by masks
The entry scan is `lookup_skipped` (`ratchet.rs:372-395`, called at `:460`): for every entry, `hit` =
`ct_eq(hk) & ct_eq(n)`; `found |= hit`; `hit.assign(found_at, j)`; and (new, `:386-388`) each byte of the entry's
`mk` is `conditional_assign`ed under `hit` into a `Zeroizing<[u8; 32]>` (all-zero on a miss). `Selected::Skipped`
carries that key; the `Path::Skipped` arm (`:801-805`) passes it to `MsgEncrypt::open` and no longer calls
`self.skipped.get(at)`; `found_at` is used only by `Update { remove: Some(at) }`, applied after the MAC verified.
Doc comment as dictated ("mk selected by masks over every entry (R-58): no secret-indexed load before the body MAC").
Test `skipped_mk_is_selected_without_indexing` (`:1341`): seven entries over three keys, matches at index 0, 2, 3
(middle) and 6 (last) give `found`, the index and the entry's key; four misses and an empty `skipped` give the
all-zero key and index 0. A hook on `VecDeque::get` is not possible (std), so the brief's fallback applies: this test,
the visit counter of Part D (every entry, every call) and the mutants run. `vectors/tr.json` sha256
`01a6d161138508af8fedd27df0fe5c62d473dbbf27530accbe6cde293201a837` before and after (`cargo xtask vectors`: 11 suites
agree with ref, every frozen file unchanged).

### 12.3 Parts C and D — `tr_decrypt_reject_skipped` respecified; the early-exit detector as a count

**R-58 / R-59 (reviewer's diagnosis, binding).** The M3-dictated classes (first vs last distinct skipped key) differ
in the trial at which the one header open succeeds (trial 0 vs 2 of 5); the position of the single succeeding
tag-check branch of the AEAD library among five shifts branch prediction — the −1.41 / −1.42-floor (≈ −59 ns) shift of
§7.1, reproduced on two fixtures. That is the position leak M3 accepted under R-15 (R-59: accepted; hardening =
branch-free trial opens, F-M5, not M4), and not the early exit F2 was for (whole AEAD opens, ≈ µs). The second,
unaccepted dependence — `entry.mk` loaded by the secret-derived index (R-58) — is fixed (§12.2).

**Fixture and classes (Part C).** Chain 1 with 5 skipped keys (n = 0…4), chains 2 and 3 with 2 each: 9 entries,
3 distinct header keys, 5 candidates (`hk_1`, `hk_2`, `hk_3`, `hk_r`, `nhk_r`); chain 4 is B's current chain; the
fixture checks the four header keys pairwise distinct, `hk_r`/`nhk_r` not a skipped chain's key, and that all nine
undelivered cells open on a copy of B. Class 0 = A's cell `(hk_1, n = 0)` (entry 0), class 1 = `(hk_1, n = 4)`
(entry 4); both open at trial 0; both with the body tag wrong in byte 0; claimed site "body MAC". The target's doc
comment carries the dictated sentence verbatim.

**Local run at the gate's scale** (`M04-evidence/ct-local-14e55da.txt`): `cargo xtask step ct` (full sample counts,
`SECMP_CT_SCALE` removed by the step) on this Mac, background run with no build or test in parallel: **run verdict
PASS**, step 2677 s (≤ 60 min, so the gate scale, not scale 6). Clock `cntvct_el0`, 1 tick = 41.667 ns = effect
floor, k = 1 for all five, 1 000 000 samples each; Δ = class 0 − class 1 at the decisive or largest-|t| crop.

| Target | Verdict | First: max \|t\| (crop, Δ floors) | Second | A/A max \|t\| | Pre-check (site) |
|---|---|---|---|---|---|
| `tr_decrypt_reject_skipped` | **PASS** | 1.00 (p99, −0.023) | 2.31 (raw, +0.099) | 2.11 | both Err(Rejected), "body MAC" |
| `inv_fingerprint_compare` | PASS | 2.40 (p75, −0.013) | 0.93 (p75, −0.005) | 1.96 | both "fingerprint"; twin Ok |
| `x25519_zero_check` | PASS | 2.15 (p90, +0.018) | 2.28 (p75, −0.010) | 2.28 | Ok, bytes [0] / [31] |
| `hx_accept_reject_inner` | SUB_FLOOR_SHIFT | 44.48 (p50, +0.354) | 40.10 (p50, +0.324) | 2.19 | both "inner open"; twin Ok |
| `hx_accept_reject_first_msg` | SUB_FLOOR_SHIFT | 6.32 (p50, −0.512) | 7.62 (p50, −0.598) | 2.25 | both "first_msg decrypt"; twin Ok |

`tr_decrypt_reject_skipped` before → after: FAIL, Δ −1.41 / −1.42 floors (old classes, scale 6, §7.1) → PASS,
|Δ| ≤ 0.10 floors (new classes, full scale), median 30 083 ns. Controls: positive control PASS (max |t| 105 938);
`min_leak_control` REACHED (raw Δ 2.86 floors); A/A′ placement PASS (1.53 / 0.99); same-content control
SUB_FLOOR_SHIFT (31.56 / 29.84 at p75 / p50, Δ +0.079 / +0.059 floors — identical inputs in both classes; it is a
control only for FAIL); other TR targets: `_hdr_key` SUB_FLOOR_SHIFT (Δ +0.107 / +0.042), `_body_tag` PASS, `_ct_pq`
SUB_FLOOR_SHIFT (Δ +0.059 / +0.046); every M1–M3 target PASS. The two HX sub-floor shifts (+0.35 and −0.51 / −0.60
floors, reproduced) were PASS in the scale-6 run of §7.1; nothing was tuned.

**Counting test (Part D).** `TRIAL_COUNTS_KAT` (thread-local, `#[cfg(any(test, feature = "kat"))]`): header trial
decryptions (`open_header`) and entries visited by `lookup_skipped`, reset when a 4096-byte cell's processing begins.
`trial_opens_every_candidate_every_call` (`ratchet.rs:1454`): receivers with 1, 3 and 6 distinct skipped keys (2
entries each); for each, cells opening at the first, the middle (`distinct / 2`) and the last skipped candidate
(accepted), the last one with its body tag flipped (rejected at the MAC), under `hk_r`, under `nhk_r` (accepted) and
under no key (rejected) — after every `decrypt` the counters are `(distinct + 2, 2 · distinct)`: (3, 2), (5, 6), (8, 12).
Hand mutants, applied, run, reverted: (1) the skipped trials as a loop that `break`s after the first trial that opened
→ 119 of 120 lib tests pass, `trial_opens_every_candidate_every_call` fails (`3 keys, first skipped candidate`: left
(3, 6), right (5, 6)); (2) `lookup_skipped` `break`s at the first hit → the same single failure (`1 keys, first
skipped candidate`: left (3, 1), right (3, 2)). No other test catches either.

Deviation from the letter: the counter is `cfg(any(test, feature = "kat"))`, not `kat` alone, and the test is a
unit test (`#[cfg(test)]`): the mutation gate builds `secmp-proto` without `kat`, so a `kat`-only test would not run
there; under `kat` the counter exists too (exported as `tr::TRIAL_COUNTS_KAT`).

**Mutants** (`M04-evidence/mutants-tr-2b6373d.txt`): `cargo mutants` with the gate's flags (`--features
secmp-crypto/kat`, the gate's `--exclude-re` list) restricted to `-f tr/ratchet.rs -f tr/select.rs`, three shards:
107 mutants — **53 caught, 1 missed, 53 unviable, 0 timeouts**. Missed: `ratchet.rs:631:9 replace
RatchetState::encrypt_padded_kat -> … with Ok(Default::default())` — a `kat`-only function (since `c6a80ca`), not built
by the gate, in neither `MUTANT_EXCLUDE_RE` nor `docs/mutants-accepted.md`, so the CI mutants gate would report it as
undocumented: added to `MUTANT_EXCLUDE_RE` with the other `kat`-only `RatchetState` accessors (`14e55da`; the hx
generator exercises it under the `kat` step). Every mutant of `lookup_skipped`, `open_header`, `first_opened`,
`decide` is caught or unviable. (A `kat`-only helper `select::reject_site_kat` was replaced by an inline `kat`
statement after the listing showed it would add two unkillable mutants to the gate.)

### 12.4 Part E — F19 reject-site tags
Mechanism of `hx::ACCEPT_SITE_KAT`: a `kat`-only thread-local set when a step begins; every added non-test line is a
`#[cfg(feature = "kat")]` statement or item, so the build without `kat` is unchanged.

- `tr::DECRYPT_SITE_KAT` (`tr/ratchet.rs`): `"cell length"`, `"header: no key opened"`, `"skipped: (hk, n) not
  stored"`, `"header decode"`, `"kem constancy"`, `"counter rule"`, `"dh_pk"`, `"body MAC"`, `"body decode"` (set by
  `Plaintext::content`). The `Path::Reject` site (no key vs a skipped key opened without `(hk, n)` stored) is
  selected with a mask on `any_skipped` — no `kat` branch on it.
- `inv::INVITEE_SITE_KAT` (`inv.rs`; set also by the `InvitationV1` and `PrekeyBundle` decoders in `wire/inv.rs`):
  `"uri"`, `"invitation decode"`, `"expired"`, `"blob open"`, `"linkdata decode"`, `"opk_present"`, `"fingerprint"`,
  `"bundle signature"`, `"bundle expired"`.
- Unit evidence, one input per site: `tr::tests::reject_sites_are_tagged` (all nine TR sites; body MAC on the step,
  chain and skipped paths) and `hx inv::invitee_reject_sites_are_tagged` (all nine INV sites, plus the control).
- Pre-checks now assert the site (`SiteCheck::Untagged` removed): `tr_decrypt_reject_hdr_key` → "header: no key
  opened"; `tr_decrypt_reject_body_tag` → "body MAC"; `tr_decrypt_reject_ct_pq` → "kem constancy";
  `tr_decrypt_reject_skipped` → "body MAC"; `same_content_control` → "body MAC"; `inv_fingerprint_compare` →
  "fingerprint" (twin: the unmodified invitation `Ok`); HX unchanged ("inner open", "first_msg decrypt").

### 12.5 Part F — docs and hygiene
1. `docs/01-threat-model.md` §7: the dictated "Opening-trial position (R-59, M4)" paragraph, verbatim, below the
   register table (the table's severity column has no dictated value).
2. This section and §7.1.
3. `crates/secmp-testkit/tests/differential.rs`: the `//!` crate documentation now precedes `#![cfg(feature =
   "kat")]`, so it survives without `kat`. Also `crates/secmp-proto/src/prekeys.rs`: the `sha256` import, used only by
   `digest_kat`, is gated like it — `cargo clippy -p secmp-proto --all-targets -- -D warnings` (no `kat`) failed on it
   as an unused import. Both forms clean: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo clippy
   --workspace --all-targets --all-features --locked -- -D warnings`; also the package form without `kat`
   (`-p secmp-proto`; the workspace form unifies `secmp-proto/kat` on through `secmp-testkit`).

### 12.6 Checks
`cargo fmt --all --check` clean; both clippy forms clean (and `-p secmp-proto` without `kat`).
`cargo nextest run -p secmp-proto --all-features`: 253 passed of 253 (`#[test]` items 246 at `812e1bd` → 253: +3 from
`e48a99d` — `any_skipped_single_conversion`, `undecodable_skipped_header_rejects_on_every_path`,
`header_n_reads_bytes_38_to_42` — and +4 here — `skipped_mk_is_selected_without_indexing`,
`trial_opens_every_candidate_every_call`, `reject_sites_are_tagged`, `invitee_reject_sites_are_tagged`); without
`kat` 134 of 134; `cargo nextest run -p xtask` 104 of 104 (the four `ct_site*`/pre-check tests came with `260b4bd`).
`cargo xtask vectors`: 11 suites agree with ref, no frozen file changed.

### 12.7 Push
`gh run list --branch m04-hx --limit 3` at 2026-10-02 00:53 CEST: PR run 36930469555 (head `812e1bd`) `in_progress`
(`linux-full` running since 23:42 CEST; linux-fast, windows-native, xwin-cross succeeded): **not pushed**, so no
`ci-dispatch.yml -f suite=ct` was started (it would have measured `812e1bd`). Unpushed on `m04-hx`: `5005399`,
`67dc5cb`, `260b4bd`, `e48a99d`, `db6d085`, `8077590`, `2b6373d`, `14e55da` and this report commit.

STOP: none.

## 13. WEISUNG M4-5 (Phase B resumed: per-session HX models, tr.pv F5/T13, gate F7, ADR-046)

Start: HEAD `c1c1b1f`, 9 commits not on `origin/m04-hx` (`git log origin/m04-hx..HEAD`). Diagnosis read in full
(`DIAG-hx-termination.md`, `hx-1s-V9b.pv`, `hx-proto.pv`, `toy-seq.pv`; copied to `target/tmp/m4-5/`, not committed).

### 13.1 What was built
- `formal/hx.pv` removed; `formal/hx.pvl` (library: types, constructors, equations, events, letfuns, macros
  `Accept23`/`AcceptP`/`AcceptS`, `ProcIP`/`ProcIS`, compromise macros without phases) and `formal/hx/<session>.pv`
  × 14 (tag, oracles, secrecy assumptions, grouped queries, the session's `Invitation` with its compromise tail and
  phases, `process`) — O-13…O-19 applied as dictated (`79f4705`). CLAIMS §HX amended: O-13…O-19 verbatim under
  "Reviewer decisions" (O-7 marked replaced); Model, abstraction block, events, H5/H6a/H10/H11 rows, gate rule, paths.
- Reading of O-17 for `hIdThief` (Q-1 below): plaintext layers (its invitations are leaked in phase 0), but I keeps
  taking invitations from `pinv(hIdThief)`. O-17's "I takes the invitation from the public channel" is the dropdup
  step (every trace of I on `pinv` is one of I on `c`), which holds only where I already runs on `c`; in hId* CLAIMS
  excludes the attacker as inviter (H7). Measured: with I on `c`, H7b is false ×2 (diagnostics §E).
- Two devices (library header 7.), forced by O-17 together with `new n[]`: I's names carry the invitation
  (`new e[ld, lk]`, also r1, r2, r3, routes) and `set unifyDerivation = false`. Without them hClean's H11 honest-pair
  and IConfirm lines "cannot be proved" (no trace reconstructed: ProVerif decomposes the plaintext Outer tuple and
  takes its components from different runs of one merged I copy); matrix in diagnostics §A. Neither changes the
  process semantics; every "false" comes with a trace ProVerif executed.

### 13.2 Runs (ProVerif 2.05, `timeout 1800 proverif -lib formal/hx.pvl formal/hx/<s>.pv`, 4 in parallel, this Mac)

| file | lines | wall | RESULT | finished | last progress line (if not) |
|---|---|---|---|---|---|
| `tr.pv` (gate, `--models tr`) | 983 | 87.4 s | 46 / 46 | yes | — |
| `hx/hClean.pv` | 96 | 1801.7 s | 7 / 10 | no | `11800 rules inserted. Base: 7259 rules (108 with conclusion selected). Queue: 50455 rules.` |
| `hx/hDH.pv` | 80 | 1802.6 s | 6 / 7 | no | `11800 rules inserted. Base: 7299 rules (128 with conclusion selected). Queue: 50635 rules.` |
| `hx/hKEM.pv` | 82 | 1802.2 s | 6 / 7 | no | `11800 rules inserted. Base: 7267 rules (111 with conclusion selected). Queue: 50453 rules.` |
| `hx/hBoth.pv` | 76 | 1802.9 s | 0 / 5 | no | `318400 rules inserted. Base: 72756 rules (4192 with conclusion selected). Queue: 21436 rules.` |
| `hx/hId.pv` | 74 | 2.0 s | 7 / 7 | yes | — |
| `hx/hIdThief.pv` | 68 | 4.0 s | 6 / 6 | yes | — |
| `hx/hIdLater.pv` | 76 | 2.0 s | 6 / 6 | yes | — |
| `hx/hIdLaterOPK.pv` | 75 | 2.0 s | 6 / 6 | yes | — |
| `hx/hKCI.pv` | 69 | 1802.4 s | 4 / 5 | no | `11800 rules inserted. Base: 7262 rules (110 with conclusion selected). Queue: 50455 rules.` |
| `hx/hKCIlt.pv` | 70 | 1803.0 s | 4 / 5 | no | `11800 rules inserted. Base: 7260 rules (109 with conclusion selected). Queue: 50455 rules.` |
| `hx/hKCIi.pv` | 65 | 26.1 s | 5 / 5 | yes | — |
| `hx/hFS.pv` | 74 | 1803.0 s | 0 / 6 | no | `23400 rules inserted. Base: 10053 rules (1144 with conclusion selected). Queue: 1949 rules.` |
| `hx/hFSOPK.pv` | 73 | 1801.1 s | 0 / 6 | no | `24600 rules inserted. Base: 10309 rules (1163 with conclusion selected). Queue: 2201 rules.` |
| `hx/hFSDH.pv` | 80 | 1800.5 s | 0 / 6 | no | `28000 rules inserted. Base: 10784 rules (1160 with conclusion selected). Queue: 3080 rules.` |

`formal/hx.pvl`: 430 lines. Every verdict obtained (57 of the 87 HX lines) is the one the gate rule expects; 30 were
not reached. Per file: `M04-evidence/proverif-hx-<session>-6599d49.txt` (query, ID, expected, verdict, last 20
progress lines); sha256 of the 16 model files: `M04-evidence/proverif-6599d49.sha256`; tr gate:
`M04-evidence/proverif-tr-6599d49.txt`. Wall times of the HX files are with 4 ProVerif processes in parallel and
other runs alongside.

### 13.3 Verdicts (no mismatch; session of every false trace = the file's: one session per file, no other tag in any log)
hClean: H1 (i) true · H1 (ii) true · H11 false ×4 · H6a true · H5, H6b, H10 not reached. hDH: H2 (i), (ii) true ·
H11 false ×4 · H8 not reached. hKEM: H3 (i), (ii) true · H11 false ×4 · H5 not reached. hBoth: H4, H11 ×4 not
reached. hId: H7a true ×2 · H11 false ×4 · H6a true. hIdThief: H7b true ×2 · H11 false ×4. hIdLater: H7c true ×2 ·
H11 false ×4. hIdLaterOPK: H7d false ×2 · H11 false ×4. hKCI: H11 false ×4 · H9 not reached. hKCIlt: H11 false ×4 ·
H9b not reached. hKCIi: H9c true · H11 false ×4. hFS, hFSOPK, hFSDH: nothing reached.

### 13.4 tr.pv — F5 and T13 (`ea071c3`)
F5 as dictated, in `ProcA5`/`ProcB5` for sClean and the four mPCS sessions (header 1a.); sFS/sHFS keep `ProcA`/`ProcB`
(T3/T9 in order). The first F5 version changed three of the 39 verdicts (T2 line 1 "cannot be proved", its
non-injective form true; T7 ×2 "cannot be proved"); both were ProVerif imprecision, not attacks, fixed without touching
a query: `set preciseActions = true` (the in-order and other-first branches of one input are exclusive; T2's
derivation paired the Recv of (1,0) at the step and at the skipped key, "We have @occ141_1 ≠ @occ294_1", no trace)
and the private healing-round delivery offered in parallel (a blocking private output fixed the order, so T7's
other-first derivation had no trace). Final: 46 RESULT lines, the 39 previous verdicts unchanged, T13 false ×7 (one
per honest session: sClean, sFS, sPCS, sPCSdh, sPCSkem, sPCSboth, sHFS), 87.4 s. `tr.pv` at `ea071c3`: +290 / −23
lines (306 changed lines incl. the header); CLAIMS: T13 row, gate rule, F5 note. Settings matrix: diagnostics §B.

### 13.5 Gate F7, CI, ADR-046
`cargo xtask step proverif [--models tr|hx|all] [--jobs N]` (`5bf47a1`): pool of ≤ 4 processes, 1800 s each, a
timeout fails naming the file and its last progress line; `expect::PROVERIF_EXPECTED` = tr runs + T13 (46 lines);
`expect::PROVERIF_EXPECTED_HX` = 87 rows (63 equal a printed RESULT line; the 24 of unreached declarations derived by
the same display rules, stated above the table); evidence `target/proverif/summary.txt` and `results.tsv`, ADR-045
table in `summary.rs`. Tests (`cargo nextest run -p xtask` 109/109): `proverif_verdicts_against_the_claims_table`,
`proverif_gate_rejects_reordered_result_lines`, `proverif_gate_rejects_missing_hx_line`,
`proverif_gate_timeout_is_a_fail`, plus the HX table checked against CLAIMS. Gate runs: `--models tr` PASS
(`proverif-tr-6599d49.txt`); `--models hx` replayed over the recorded logs through a `SECMP_PROVERIF` wrapper
(labelled, `proverif-hx-gate-replay-6599d49.txt`): the 5 finished files pass the check, the 9 capped files fail. CI
(`6599d49`): job `proverif-hx` added; `linux-full` runs `ci-full … --models tr`; `cargo xtask step policy` passes.
ADR-046 in `docs/08` verbatim. Not changed (outside the allowed files): `ci-dispatch.yml` still runs `ci-full` without
`--models` (default all: all 14 HX files in that job); `xtask/README.md` does not list `--models`/`--jobs`.

### 13.6 Diagnostics (`M04-evidence/proverif-m4-5-diagnostics-6599d49.txt`; scratch variants, nothing applied)
- hClean's begin-IStart declaration, profile: the rules carry b-inj-event(IStart) for I on an attacker invitation;
  each DH field of the attacker's bundle (`attacker(exp(g, ·))`) is resolved against every public key; ≈ 40 rules/s up
  to 11800, then a few per minute; the same stall point in hClean, hKEM, hDH, hKCI, hKCIlt. H6b alone: true (14.4 s);
  H10 alone: true (22.5 s); H5 with iR bound to IKSPublic_R: the same stall (600 s).
- hFS without I on `c`: H11 false ×4, H12 true ×2 in 0.7 s. hBoth with I on `pinv(hBoth)`: H4 false, H11 false ×3,
  IConfirm "cannot be proved", 290 s.

### 13.7 Blocked — STOP (WEISUNG M4-5 §7: a file > 30 min after the §1 structure)
- STOP hClean: begin-IStart declaration (H5) > 1800 s; last `11800 rules inserted. Base: 7259 rules (108 with
  conclusion selected). Queue: 50455 rules.`; H5, H6b, H10 not reached (H6b and H10 alone: true).
- STOP hKEM: begin-IStart (H5) > 1800 s; last `11800 rules inserted. Base: 7267 rules (111 with conclusion
  selected). Queue: 50453 rules.`
- STOP hDH: begin-IStart (H8) > 1800 s; last `11800 rules inserted. Base: 7299 rules (128 with conclusion selected).
  Queue: 50635 rules.`
- STOP hKCI: begin-IStart (H9) > 1800 s; last `11800 rules inserted. Base: 7262 rules (110 with conclusion selected).
  Queue: 50455 rules.`
- STOP hKCIlt: begin-IStart (H9b) > 1800 s; last `11800 rules inserted. Base: 7260 rules (109 with conclusion
  selected). Queue: 50455 rules.`
- STOP hBoth: no-begin declaration (H4, H11) > 1800 s; last `318400 rules inserted. Base: 72756 rules (4192 with
  conclusion selected). Queue: 21436 rules.`
- STOP hFS / hFSOPK / hFSDH: no-begin declaration (H11, H12 / H12b / H12c) > 1800 s; last `23400 rules inserted.
  Base: 10053 rules (1144 …). Queue: 1949 rules.` / `24600 … Base: 10309 rules (1163 …). Queue: 2201 rules.` /
  `28000 … Base: 10784 rules (1160 …). Queue: 3080 rules.`
- Abstractions that would be needed (named, not applied): for hFS, hFSOPK, hFSDH and hBoth, I only on R's invitations
  (no attacker as inviter; DIAG §5: H12/H4 use it only as an extra oracle) — measured in §13.6. For the begin-IStart
  declarations (H5, H8, H9, H9b) none found inside §1: H5 needs the attacker as inviter (DIAG §5) and binding iR does
  not help; candidates: DIAG 9 (c) (non-injective agreement + uniqueness lemma), or a reviewer decision on the
  attacker-as-inviter's bundle fields.

### 13.8 Questions
- Q-1: O-17's "I takes the invitation from the public channel" for hIdThief — confirm the reading of §13.1 (I on
  `pinv`, plaintext layers), or the literal reading (then H7b is false, as measured).
- Q-2: the dictated declaration order puts begin-IStart before RAccept/InvIssued; in hClean, H6b and H10 are proved
  alone but not reached in the file because H5 runs first. Keep the order (gate FAIL by timeout) or reorder?

### 13.9 Deviations
None from the spec. From the letter of the WEISUNG: the two HX devices of §13.1, `tr.pv`'s `preciseActions` and its
parallel private delivery (precision / trace reconstruction only; no query, oracle or compromise touched), and the
hIdThief reading (Q-1).

### 13.10 Push
`gh run list --branch m04-hx --limit 3` at 2026-10-02 02:46 CEST: PR run 36930469555 (head `812e1bd`) `in_progress` —
**not pushed** (WEISUNG M4-5 §6). Unpushed on `m04-hx`: `5005399`, `67dc5cb`, `260b4bd`, `e48a99d`, `db6d085`,
`8077590`, `2b6373d`, `14e55da`, `c1c1b1f`, `79f4705`, `ea071c3`, `5bf47a1`, `6599d49` and this report commit.

### 13.11 WEISUNG M4-7 — formal round 2: the 9 capped files (reviewer decisions O-20…O-23)

Start: HEAD `2c23c0f`, 0 commits not on `origin/m04-hx`, working tree clean; PR run 36983733373 (head `2c23c0f`)
`in_progress`. Adjudication of M4-5 (WEISUNG §0) recorded: Q-1 clause added to O-17, the two devices in the
`hx.pvl` header and in CLAIMS §HX "Model devices" (one line each).

#### 13.11.1 What was built (`4f5562d` formal, `7c235d2` xtask)
- **O-20:** hBoth and hKCIi: R's invitation also goes to I on `pinv(s)`, I runs only there (plaintext layers kept,
  as hIdThief); hFS, hFSOPK, hFSDH: `! ProcIS(s, c)` removed.
- **O-21/O-22:** hClean, hKEM, hDH, hKCI, hKCIlt are split. Base file `<s>.pv`: I only on `pinv(s)`, no
  attacker-as-inviter process, declarations ordered no-begin, H6b, H10, H6a (only hClean has the last three).
  Auth file `<s>-auth.pv`: the same session and processes plus `! ProcIPA(s, c)` (the attacker as inviter: every
  invitation on `c`, the attacker's own and R's leaked ones), which emits `IStartA` (new event in the library, in
  no query); only the begin-IStart declaration (H5, H5, H8, H9, H9b).
- **O-23 applied, all five auth files:** with O-20–O-22 alone every auth file reached the 1800 s cap (diagnostics A
  below), so `ProcIPA` additionally requires `hverify(vk(iksig(s, pR)), lbl_bundle, (b, ikdhR), sig) = true`
  after the protocol's own check.
- **Device (not dictated, for the reviewer):** I's names carry the verified bundle as well, `new e[ld, lk, b]`
  (also r1, r2, r3, routes; ProcIP, ProcIS, ProcIPA). With I only on R's invitations two H11 IConfirm lines came out
  "cannot be proved" under the M4-5 index `[ld, lk]`: hKCIlt (RevealLT(R) in phase 0; the derivation joins I runs of
  one invitation that took different bundles signed with R's revealed key) and hBoth (R's bundle of another invitation
  under this invitation's plaintext `ld_id`); with `[ld, lk, b]` both are false with a trace (diagnostics E;
  `[ld, lk, opkid]` does not suffice for hKCIlt). Same kind as the accepted device: a name's arguments never change
  the process; ProVerif's default `new e` carries every message received before it. Recorded in the `hx.pvl` header
  (7.) and as a third line under CLAIMS "Model devices", marked M4-7.
- `xtask`: `expect::PROVERIF_EXPECTED_HX` = 19 files, 87 rows (82 session-file rows equal the printed RESULT lines of
  this round; the 5 auth rows equal the `-- Query` line ProVerif prints before solving, which carries the RESULT
  text: `ld_6`, `b_3`, `tr_3`, `rt_3`, `sk_3`). The HX verdict test pinned 14 files (`gates.rs:3041`), now 19 — a
  one-line change outside the WEISUNG's file list (§13.11.7). `cargo nextest run -p xtask` 109/109, `cargo fmt --all
  --check` and `cargo clippy -p xtask --all-targets -- -D warnings` clean.
- `ci-dispatch.yml` has no ProVerif file list: its `full` suite runs `ci-full --strict` (default `--models all`) and
  the files are discovered from `formal/hx/*.pv` and checked against the table (`hx_set_check`) — unchanged. Same for
  `ci.yml`'s `proverif-hx` job. `xtask/README.md` already documents `--models`/`--jobs` and lists no files —
  unchanged. `formal/README.md` names the auth files.
- CLAIMS §HX (`docs` commit): O-20…O-23 verbatim under "Reviewer decisions" (new amendments block), the Q-1 clause in
  O-17, "Model devices", the old grouping bullet marked "replaced by O-22", the gate-rule paragraph (19 files) and the
  Model paragraph (attacker as inviter only in the auth files).

#### 13.11.2 Runs (gate run `cargo xtask step --strict proverif --models hx --jobs 4` at `7c235d2`, 1800 s cap per
file, nothing else running; tr: `--models tr`)

| file | wall | RESULT | finished | O-23 | last progress line (if capped) |
|---|---|---|---|---|---|
| `tr.pv` (`--models tr`) | 91.6 s | 46 / 46 | yes | n/a | — |
| `hx/hClean.pv` | 33.1 s | 9 / 9 | yes | n/a | — |
| `hx/hClean-auth.pv` | 1800.7 s | 0 / 1 | no | yes | `26000 rules inserted. Base: 19482 rules (146 with conclusion selected). Queue: 68188 rules.` |
| `hx/hDH.pv` | 28.7 s | 6 / 6 | yes | n/a | — |
| `hx/hDH-auth.pv` | 1800.8 s | 0 / 1 | no | yes | `25400 rules inserted. Base: 18594 rules (190 with conclusion selected). Queue: 68166 rules.` |
| `hx/hKEM.pv` | 21.7 s | 6 / 6 | yes | n/a | — |
| `hx/hKEM-auth.pv` | 1801.3 s | 0 / 1 | no | yes | `34400 rules inserted. Base: 27742 rules (176 with conclusion selected). Queue: 99810 rules.` |
| `hx/hBoth.pv` | 1043.5 s | 5 / 5 | yes | n/a | — |
| `hx/hId.pv` | 0.6 s | 7 / 7 | yes | n/a | — |
| `hx/hIdThief.pv` | 6.0 s | 6 / 6 | yes | n/a | — |
| `hx/hIdLater.pv` | 0.5 s | 6 / 6 | yes | n/a | — |
| `hx/hIdLaterOPK.pv` | 0.7 s | 6 / 6 | yes | n/a | — |
| `hx/hKCI.pv` | 18.4 s | 4 / 4 | yes | n/a | — |
| `hx/hKCI-auth.pv` | 1800.9 s | 0 / 1 | no | yes | `25200 rules inserted. Base: 18521 rules (147 with conclusion selected). Queue: 66843 rules.` |
| `hx/hKCIlt.pv` | 48.6 s | 4 / 4 | yes | n/a | — |
| `hx/hKCIlt-auth.pv` | 1801.4 s | 0 / 1 | no | yes | `59200 rules inserted. Base: 31244 rules (276 with conclusion selected). Queue: 89292 rules.` |
| `hx/hKCIi.pv` | 14.5 s | 5 / 5 | yes | n/a | — |
| `hx/hFS.pv` | 1.0 s | 6 / 6 | yes | n/a | — |
| `hx/hFSOPK.pv` | 1.9 s | 6 / 6 | yes | n/a | — |
| `hx/hFSDH.pv` | 1.1 s | 6 / 6 | yes | n/a | — |

Total wall time of the `--jobs 4` gate: 3624 s (step line), FAIL: "5 of 19 ProVerif files failed" (the five auth
files, timeout). 14 of 19 files pass with 82 of 82 lines as expected; tr 46 / 46. Per file:
`M04-evidence/proverif-hx-<file>-7c235d2.txt` (query, ID, expected, verdict, last 20 progress lines; no other session
tag in any log); gate output `proverif-hx-gate-7c235d2.txt` (incl. the ADR-045 table and the sha256 of every model
file), `proverif-tr-7c235d2.txt`; sha256 list `proverif-7c235d2.sha256`; diagnostics
`proverif-m4-7-diagnostics-7c235d2.txt`.

Measured effect of each decision:
- O-20: hFS 1.0 s, hFSOPK 1.9 s, hFSDH 1.1 s (M4-5: capped, 0 of 6 each); hBoth 1043.5 s, 5 / 5 (M4-5: capped,
  0 / 5; with the M4-5 name index `[ld, lk]` 471.0 s but IConfirm "cannot be proved"); hKCIi 14.5 s (M4-5: 26.1 s).
- O-21/O-22, base files: hClean 33.1 s, 9 / 9 (M4-5: capped at 7 / 10); hKEM 21.7 s, hDH 28.7 s, hKCI 18.4 s,
  hKCIlt 48.6 s, all lines (M4-5: capped). The capped auth files no longer hide any base verdict.
- O-21/O-22, auth files without O-23 (diagnostics A, 3 in parallel): all five capped at 1800 s; last lines
  `40400 … Queue: 58657` (hClean-auth), `40400 … Queue: 58686` (hKEM-auth), `41400 … Queue: 57368` (hDH-auth),
  `40800 … Queue: 59169` (hKCI-auth), `58800 … Queue: 16407` (hKCIlt-auth).
- O-23 (applied in all five, named here): all five still capped (table above; diagnostics B for the earlier O-23 runs).

#### 13.11.3 Verdicts (no mismatch; every false trace is in the file's own session — one session per file)

| file | ID | verdict | expected |
|---|---|---|---|
| `hClean-auth` | H5 | not reached (cap) | true |
| `hKEM-auth` | H5 | not reached (cap) | true |
| `hDH-auth` | H8 | not reached (cap) | false |
| `hKCI-auth` | H9 | not reached (cap) | false |
| `hKCIlt-auth` | H9b | not reached (cap) | true |
| `hClean` | H1 (i), H1 (ii), H6b, H10, H6a | true ×5 | true |
| `hClean`, `hDH`, `hKEM`, `hBoth`, `hId`, `hIdThief`, `hIdLater`, `hIdLaterOPK`, `hKCI`, `hKCIlt`, `hKCIi`, `hFS`, `hFSOPK`, `hFSDH` | H11 | false ×4 each (56) | false |
| `hDH` | H2 (i), (ii) | true ×2 | true |
| `hKEM` | H3 (i), (ii) | true ×2 | true |
| `hBoth` | H4 | false | false |
| `hId` | H7a ×2, H6a | true ×3 | true |
| `hIdThief` | H7b ×2 | true | true |
| `hIdLater` | H7c ×2 | true | true |
| `hIdLaterOPK` | H7d ×2 | false | false |
| `hKCIi` | H9c | true | true |
| `hFS` | H12 (i), (ii) | true | true |
| `hFSOPK` | H12b (i), (ii) | false | false |
| `hFSDH` | H12c (i), (ii) | true | true |

Every false verdict (H11 ×56, H4, H7d ×2, H12b ×2) comes with a trace in its own file's session.

#### 13.11.4 Diagnostics (`proverif-m4-7-diagnostics-7c235d2.txt`; scratch files, nothing applied unless stated)
- C — the stall is in the begin-IStart declaration itself, not in the attacker as inviter: hClean-auth **without**
  `ProcIPA` (I only on R's invitations, i.e. the base file's processes plus H5) gives no RESULT in 590 s (`17200
  rules inserted. Base: 11003 rules (141 …). Queue: 37156 rules.`); the non-injective H5 likewise (`18800 … Queue:
  44403`); with ProcIPA fed only R's own invitations likewise; a `nounif` on the bundle signature and a proved lemma
  "IStart names IKSPublic_R and a BundleSigned bundle" do not change it (580 s, `32600 … Queue: 41828`). Profile
  (verboseRules, 240 s): 2564 of the last 3000 rules carry the begin-IStart hypothesis; the selected facts are I's
  `pinv` input and the bundle signature/DH fields while the signer is still a variable. No restriction of the
  attacker-as-inviter process (O-20, O-21, O-23) can therefore bring H5/H8/H9/H9b under the cap.
- D — O-21 and R's own leaked invitation: `ProcIPA` reads every invitation on `c`, including R's own (LeakInv in
  phase 0 publishes them). Scratch reachability (12.7 s, trace): LeakInv(ld_9) → ProcIPA takes (ld_9, lk_5,
  fp(R)) and R's blob → IStartA → Outer → R's AcceptP → RAccept(R, I, ld_9, …) with the same tr, rt, sk. Under O-21
  this RAccept has no IStart, so H5 (hClean, hKEM) and H9b (hKCIlt) have a counterexample that is a modelling
  artefact (the honest I on R's genuine invitation), i.e. they would come out false — opposite to the gate rule —
  once a run saturates; H8/H9 would be false for this reason as well, not only for the claimed attacks. Not observed
  in an auth file (none saturated); stated as analysis plus the scratch trace.
- E — the bundle index of I's names (§13.11.1): `[ld, lk]` hKCIlt IConfirm "cannot be proved" (16.1 s), hBoth
  IConfirm "cannot be proved" (471.0 s); `[ld, lk, opkid]` hKCIlt still "cannot be proved"; `[ld, lk, b]` both
  false with a trace (31.6 s / 1072.5 s in the development runs; 48.6 s / 1043.5 s in the gate run).

#### 13.11.5 Blocked — STOP (WEISUNG M4-7 §4: an auth file > 30 min even with O-23)
- STOP `formal/hx/hClean-auth.pv`: declaration H5 `inj-event(RAccept(hClean,iR,iks_I,ld,oid,tr,rt,sk)) ==>
  inj-event(IStart(hClean,iks_I,iR,b,tr,rt,sk))`; last `26000 rules inserted. Base: 19482 rules (146 with conclusion
  selected). Queue: 68188 rules.`
- STOP `formal/hx/hKEM-auth.pv`: H5 (same declaration, tag hKEM); last `34400 rules inserted. Base: 27742 rules (176
  with conclusion selected). Queue: 99810 rules.`
- STOP `formal/hx/hDH-auth.pv`: H8 (same correspondence, tag hDH); last `25400 rules inserted. Base: 18594 rules
  (190 with conclusion selected). Queue: 68166 rules.`
- STOP `formal/hx/hKCI-auth.pv`: H9 (tag hKCI); last `25200 rules inserted. Base: 18521 rules (147 with conclusion
  selected). Queue: 66843 rules.`
- STOP `formal/hx/hKCIlt-auth.pv`: H9b (tag hKCIlt); last `59200 rules inserted. Base: 31244 rules (276 with
  conclusion selected). Queue: 89292 rules.`
- Not applied (beyond §1 of the WEISUNG), for the reviewer: (1) per diagnostics C the cost sits in the begin-IStart
  hypotheses of I's own (pinv) run, so a decision must act on H5/H8/H9/H9b's declaration or on I's run, not on the
  attacker as inviter; (2) per diagnostics D, O-21 needs `ProcIPA` to exclude R's own invitations (e.g. R's link keys
  as tagged names checked by a private `otherwise` destructor, R's invitations reaching I only on `pinv`), or IStart
  for runs on R's own invitation — otherwise the auth files' verdicts, once reached, are not those of the claims.

#### 13.11.6 Questions
- Q-3: the begin-IStart declarations (H5, H8, H9, H9b) do not finish in 30 min even with I only on R's invitations
  (diagnostics C). Which change of the declaration or model do you want measured next?
- Q-4: O-21's IStartA also covers I's runs on R's own leaked invitations (diagnostics D). Exclude R's own invitations
  from the attacker-as-inviter process, or emit IStart there?

#### 13.11.7 Deviations
None from the spec. From the letter of the WEISUNG: the name index `new e[ld, lk, b]` (precision device, §13.11.1,
needed for two H11 lines once O-20 holds); the one-line test change `gates.rs:3041` (14 → 19 files), outside the
listed files but forced by the dictated 19-file table; `ci-dispatch.yml` not changed (it has no ProVerif file list).

#### 13.11.8 Push
`gh run list --branch m04-hx --limit 3` at 2026-10-02 12:59 CEST: PR run 36983733373 (head `2c23c0f`) `in_progress`
— **not pushed** (WEISUNG M4-7). Unpushed on `m04-hx`: `4f5562d`, `7c235d2` and this report commit.

### 13.12 WEISUNG M4-11 — formal round 3: O-21 withdrawn, O-24 search devices; all 19 hx files terminate

Start: HEAD `4a0960e`, 0 commits not on `origin/m04-hx`, working tree clean; PR run 37038178041 (head `4a0960e`)
`in_progress`. Adjudication of M4-7 (WEISUNG §0) recorded: 14 session files with 82/82 lines accepted; the device
`new e[ld, lk, b]` and the `gates.rs:3041` count fix accepted (CLAIMS "Model devices" now says so); Q-3/Q-4 answered
by the reviewer's measurements; O-21 withdrawn.

#### 13.12.1 What was changed (`744d3cd` formal, `569c2e2` xtask, the docs commit)
- `formal/hx.pvl`: the event `IStartA` is removed; `ProcIPA` (the attacker as inviter) emits `IStart`. The O-20 scope
  (only in the five auth files) and the O-23 check stay as they were. Header 3. and 7. and the `ProcIPA` comment are
  updated to match.
- The five auth files: the three O-24 lines verbatim, plus the fourth in `hDH-auth.pv`. The auth files have no `set`
  line: the two `set` lines are in `hx.pvl`. So the lines go where the reviewer's measured files (`T-*.pv`,
  `S*-*.pv`) put them: directly after `const <tag>: tagt.`, before the oracle and secrecy declarations and the process.
  Where a declaration sits does not change what it means to ProVerif. The row comment "with event IStartA (…, O-21)"
  now reads "with event IStart (…; O-21 withdrawn) … ; search devices (O-24)". No query, process or secrecy assumption
  changed: `git diff 4a0960e 744d3cd -- formal/hx/` shows only that comment and the inserted lines.
- `expect::PROVERIF_EXPECTED_HX` is unchanged: 19 files, 87 rows. The query texts of the five auth rows (`ld_6`,
  `b_3`, `tr_3`, `rt_3`, `sk_3`) equal the RESULT lines of the gate run, so the O-24 declarations do not shift
  ProVerif's variable renaming.
- **Gate parser** (`xtask/src/gates.rs`, outside the WEISUNG's file list, see §13.12.6). H8 and H9 are now decided for
  the first time. Under a false injective query whose non-injective version is false too, ProVerif 2.05 prints an
  extra remark line, `RESULT (even event(…) ==> event(…) is false.)`. `proverif_result_lines` skipped only the
  `RESULT (but …)` form. It counted the `(even …)` remark as an extra, unreadable line, so it failed hDH-auth and
  hKCI-auth although their verdicts were right. The first gate run at `744d3cd` shows this:
  `M04-evidence/proverif-hx-gate-744d3cd-run1.txt`, "2 of 20 ProVerif files failed … extra RESULT line 2 (no such
  query in the table), unreadable: (even …)"; every other file passed there.
  - Fix: both remark forms are skipped.
  - Tests: `gates::tests::proverif_verdicts` checks that both forms are skipped. In
    `gates::tests::proverif_verdicts_against_the_claims_table`, the hx output fixture now emits `(even …)` under a
    false injective query and `(but …)` under an undecided one.
  - Checks: `cargo nextest run -p xtask` 109/109; `cargo fmt --all --check` and `cargo clippy -p xtask --all-targets
    -- -D warnings` clean.
- `formal/CLAIMS.md` §HX:
  - "O-21 withdrawn" and O-24 are added verbatim under "Reviewer decisions", in a new amendments block (WEISUNG M4-11).
  - The O-21 bullet is marked "Withdrawn 2026-10-02".
  - "Model devices": the M4-7 device line now says "accepted by the reviewer, M4-11 §0", and a fourth line names O-24.

#### 13.12.2 Runs (gate run `cargo xtask step --strict proverif --models all --jobs 4` at `569c2e2`, whose models are those of `744d3cd`; 1800 s cap per file; 4 files in parallel; nothing else running)

| file | wall | RESULT | finished | M4-7 (`7c235d2`) |
|---|---|---|---|---|
| `tr.pv` | 169.6 s | 46 / 46 | yes | 91.6 s (`--models tr`, alone) |
| `hx/hClean.pv` | 37.5 s | 9 / 9 | yes | 33.1 s |
| `hx/hClean-auth.pv` | 2.5 s | 1 / 1 | yes | capped (0 / 1) |
| `hx/hDH.pv` | 33.7 s | 6 / 6 | yes | 28.7 s |
| `hx/hDH-auth.pv` | 10.4 s | 1 / 1 | yes | capped (0 / 1) |
| `hx/hKEM.pv` | 22.7 s | 6 / 6 | yes | 21.7 s |
| `hx/hKEM-auth.pv` | 4.8 s | 1 / 1 | yes | capped (0 / 1) |
| `hx/hBoth.pv` | 474.9 s | 5 / 5 | yes | 1043.5 s |
| `hx/hId.pv` | 0.7 s | 7 / 7 | yes | 0.6 s |
| `hx/hIdThief.pv` | 6.5 s | 6 / 6 | yes | 6.0 s |
| `hx/hIdLater.pv` | 0.5 s | 6 / 6 | yes | 0.5 s |
| `hx/hIdLaterOPK.pv` | 0.8 s | 6 / 6 | yes | 0.7 s |
| `hx/hKCI.pv` | 20.3 s | 4 / 4 | yes | 18.4 s |
| `hx/hKCI-auth.pv` | 6.5 s | 1 / 1 | yes | capped (0 / 1) |
| `hx/hKCIlt.pv` | 44.3 s | 4 / 4 | yes | 48.6 s |
| `hx/hKCIlt-auth.pv` | 307.5 s | 1 / 1 | yes | capped (0 / 1) |
| `hx/hKCIi.pv` | 12.7 s | 5 / 5 | yes | 14.5 s |
| `hx/hFS.pv` | 1.1 s | 6 / 6 | yes | 1.0 s |
| `hx/hFSOPK.pv` | 1.9 s | 6 / 6 | yes | 1.9 s |
| `hx/hFSDH.pv` | 1.0 s | 6 / 6 | yes | 1.1 s |

The gate's step line reads `10 proverif PASS 475s`, `step: PASS`: 20 of 20 files, hx 87 / 87 lines as expected
(82 session-file lines + 5 auth lines), tr 46 / 46.
- hBoth.pv is byte-identical to M4-7 (same sha256). `hx.pvl` changed only in `ProcIPA`/`IStartA`, which hBoth does not
  use. In the M4-7 run the capped auth files ran alongside it for 30 min each. These are measurements; I give no
  further cause.
- hKCIlt-auth: 307.5 s here. The reviewer measured 506.7 s in its container with both `nounif` lines *without*
  `[ignoreAFewTimes]` (S0); S5 on hKCIlt was unmeasured there. This run uses the dictated O-24 lines, with the option.

Evidence (all in `M04-evidence/`):
- per file, `proverif-hx-<file>-569c2e2.txt`: query, ID, expected and actual verdict; for each false verdict whether a
  trace was found, the session tags and the events of the trace; the RESULT lines; the last 20 progress lines.
- `proverif-tr-569c2e2.txt`.
- the gate output `proverif-hx-gate-569c2e2.txt`, incl. the ADR-045 table and the sha256 of every model file.
- the sha256 list `proverif-569c2e2.sha256`. Against `proverif-7c235d2.sha256` only `hx.pvl` and the five auth files
  differ.

#### 13.12.3 Verdicts (no mismatch)

| file | ID | verdict | expected | wall |
|---|---|---|---|---|
| `hClean-auth` | H5 | true | true | 2.5 s |
| `hKEM-auth` | H5 | true | true | 4.8 s |
| `hDH-auth` | H8 | false, with a trace | false | 10.4 s |
| `hKCI-auth` | H9 | false, with a trace | false | 6.5 s |
| `hKCIlt-auth` | H9b | true | true | 307.5 s |

The 14 session files give the verdicts of §13.11.3 again (82 / 82).

There are 63 false verdicts: H11 ×56 (four in each of the 14 session files), H4 (hBoth), H7d ×2 (hIdLaterOPK), H8
(hDH-auth), H9 (hKCI-auth) and H12b (i)/(ii) (hFSOPK). For each, ProVerif reports "A trace has been found.", and every
event in the trace carries the file's own session tag. Source: `target/tmp/m411_evidence.py` over the gate logs; one
column per verdict in the per-file evidence.
- **H8 trace (hDH-auth, session hDH):**
  1. PubIKS(hDH, pI); R issues its invitations; LeakInv(hDH, ld_10).
  2. The attacker sends R, on ld_10, an Outer built from its own EK (= g), its own encapsulations ct_spk and ct_opk
     (coins a_4, a_5) and its own ct1 (a_6), inner IKS_I, with DH1 = dh_break(IK_dh_I, SPK_dh_R) (the DH oracle).
  3. RAccept(hDH, IKS_R, IKS_I, ld_10, opkid_9, …).

  The trace contains no IStart. This is the CLAIMS H8 attack: with a classical break, I's authentication to R rests
  on the PQ part alone, and that part does not authenticate I.
- **H9 trace (hKCI-auth, session hKCI):**
  1. RevealSPK(hKCI, pR) puts the secrets of SPK_dh, SPK_kem and RPK_kem on c; PubIKS(hKCI, pI); LeakInv(hKCI, ld_12).
  2. R reaches RAccept(hKCI, IKS_R, IKS_I, ld_12, opkid_10, …) on an Outer that has:
     - the attacker's own EK (= g), its own ct_opk (a_10) and its own ct1 (a_11);
     - DH1 = X25519(IK_dh_I, the revealed SPK_dh secret);
     - a ct_spk the attacker took from I's init cell in an attacker-as-inviter run and decapsulated with the revealed
       SPK_kem. That run is IStart(hKCI, IKS_I, IKS_R, …) on the attacker's own invitation a_5 with R's genuine bundle
       of opkid_12 (O-23). Its tr contains ld_id a_5 ≠ ld_12, so it does not match the RAccept.

  The trace has no event of another session. It differs from the reviewer's trace in one point: ct_spk is replayed
  from I's run instead of being the attacker's own encapsulation. The attacker could have made its own, since
  SPK_kem is public.

#### 13.12.4 Gate
PASS: 20 / 20 files, 475 s wall time for the `--jobs 4` step; hx 87 lines as expected (82 + 5), tr 46.

#### 13.12.5 Blocked
STOP: none.

#### 13.12.6 Deviations
None from the spec. From the letter of the WEISUNG:
- the gate parser fix in `xtask/src/gates.rs` (§13.12.1), outside the listed files. It was forced by the dictated
  "19/19 pass, 87 hx lines": without it the gate fails on correct verdicts. It is a third commit, `569c2e2`.
- where the O-24 lines sit: the auth files have no `set` line, so the lines are placed as in the reviewer's measured
  files.
- the row comment in each auth file, which named the removed `IStartA`.

#### 13.12.7 Push
`gh run list --branch m04-hx --limit 2` at 2026-10-02 19:27 CEST: PR run 37038178041 (head `4a0960e`) `in_progress`
— **not pushed** (window rule). Unpushed on `m04-hx`: `744d3cd`, `569c2e2` and the docs commit.

## M4-12 — WEISUNG M4-12 (R-60 closed, R-61, R-63, R-64, mutants-job runtime)

Start (§1 record): head `67bce1a` (`docs(m4): report M4-9`), 0 commits unpushed (`origin/m04-hx` = HEAD), tree clean,
2026-10-02. Commits (head `d176e95` before this report commit): `51f05f4` R-64, `b1a6a51` R-61, `357fde8` R-60 tests,
`d176e95` R-63 + `-j 3`.

### A. The 22 missed HX mutants (`M04-evidence/mutants-hx-bc17190.txt`)

| # | Mutant(s) | Closed by |
|---|---|---|
| 1 | `prekeys.rs:36` ×5 | `store::spk_rotation_is_seven_days` (`SPK_ROTATION_S == 604_800`) |
| 2 | `prekeys.rs:184` `created` | `store::spk_generation_created_is_the_issue_time`. The store has no retention path that reads `created` (`retire_expired` keeps by current generation and record references; `rotate_if_due` reads the field directly), so the accessor test stands alone, as the WEISUNG allows. |
| 3 | `prekeys.rs:497-498` | `store::add_record_rejects_unknown_spk_alone`, `…_unknown_opk_alone`, `…_duplicate_ld_id_alone` (each: `Err(Rejected)`, digest unchanged, then the valid add succeeds) |
| 4 | `prekeys.rs:590` | `store::issue_invitation_failure_removes_only_that_opk`. Names differ from the WEISUNG's {1, 2}: the first issuance (OPK 1) stays; the second takes OPK 2, and `FixedEntropy` replays the same stream so that its `ld_id` collides with the recorded one. Result: OPK 1 present, OPK 2 (the failed issuance's) absent. |
| 5 | `prekeys.rs:717` + R-64 | `commit_accept` now: record of `ld_id` must exist, `record.opk_id == opk_id`, and the OPK must be held, else `Err(Rejected)` with the store unchanged. Tests `store::commit_accept_rejects_missing_opk_alone`, `…_missing_record_alone`, `…_mismatched_opk`. K4b `kani_commit_accept_atomic`: `ok == (held(opk_id) && ld_id == [1; 16] && opk_id == named)`; both stores of the harness now include a mismatch case. `cargo xtask step --strict kani`: PASS, 25/25 harnesses, 1585 s; **K4b 424.1 s** (304.3 s in M4-8). Evidence `kani-m4-12.log`. |
| 6 | `responder.rs:108`, `:114` | `MUTANT_EXCLUDE_RE` gets `Groups<.*>::(get\|remove_completed) ` with the comment "cfg(kani)-only helpers (M4-12)". The literal pattern `Groups::get\|Groups::remove_completed` would not match cargo-mutants' names (`Groups<K, C, N>::get`), so the type parameters are matched. |
| 7 | `responder.rs:131` | `hx::responder::tests::groups_remove_shifts_later_slots_in_order` (N ∈ {1, 3, 8}, every slot; order, `len`, freed slots at the end, chunk of each survivor), `groups_remove_on_empty_store_is_none` (unit tests in `responder.rs`: `Groups::remove` is private) |
| 8 | `responder.rs:290` | `accept::accept_wrong_spk_id_rejects_at_the_id_check`, `accept_wrong_opk_id_rejects_at_the_id_check`. The site tag of §6.6 step 1 is `"outer"`; with only `Rejected` asserted the `&&` mutant also ends at `"outer"` when the wrong id names no key, so the store also holds SPK 8 and OPK 43: with `&&` the check passes and the group dies at `"inner open"`. Both tests fail with the mutation applied by hand (checked), pass without. |
| 9 | `inv.rs:81` | `MUTANT_EXCLUDE_RE`: `impl (core::fmt::)?Display for \w+Error>::fmt` ("error text, no logic (M4-12)") |
| 10 | `inv.rs:161` ×2, `:198` | Equivalent: operands are disjoint. `(b0 << 16) \| (b1 << 8) \| b2`: bits 16..24, 8..16, 0..8 (bytes ≤ 0xff). `(group << 6) \| (v & 0x3f)`: bits 0..6 clear vs bits 0..6 set. Masks stated in a comment at each line; two rows in `docs/mutants-accepted.md` (path + description, as the gate matches them). |

**Re-run** (the M4-10 command, `-j 3`, plus the two new exclusions; `M04-evidence/mutants-hx-m4-12.txt`, head `d176e95`):
331 mutants tested in 67 min: **235 caught, 3 missed, 93 unviable, 0 timeouts.** The 3 missed are exactly the documented
equivalents of item 10 (`inv.rs:163:44`, `:163:32` `base64url_encode`; `:202:34` `base64url_decode`; lines moved by the
two comment lines). A second run on the new `Drop`/`Zeroize`/`wipe_seed` code of `wire/inv.rs` and `wire/cell.rs`
(`--re 'Drop for|wipe_seed|Zeroize for'`, which the HX command does not cover): 10 mutants, 10 caught, 5 min.

### B. R-61 — wipe on drop

`RelayRef`, `RelayQueue`, `RouteDescriptor`, `InvitationV1` have a `Drop` calling their `Zeroize` (hand-written, not
`ZeroizeOnDrop`: `secmp-proto` has no direct `zeroize` dependency). `SecretBytes` has no in-place wipe, so `zeroize()` of
`InvitationV1` and `RelayQueue` replaces `link_key`, `inv_send_seed`, `send_seed` with a zero value (`wipe_seed`); the
old allocation is wiped by `SecretBytes::drop`. A test in `wire/cell.rs` that moved a field out of a `RouteDescriptor`
now borrows it. Tests (`wire::cell::wipe_tests`): `zeroize_clears_every_byte_field` (relay_fp, onion, akc, host,
spki, sid, ld_id, link_key, inviter_fp, inv_sid, inv_send_seed, send_seed, `Unknown.blob`/`kind`, `expires`: all zero),
`dropped_invitation_is_wiped`. No testkit pattern for a runtime drop-wipe exists (only type pins, e.g.
`hx_secrets_are_zeroizing_types`), and reading freed memory needs `unsafe`, so the second test observes **that** the
`Drop` ran: a `cfg(test)` log of the type names (`wire::wipe_log`), asserted for a plain drop, for `invitee_check`
on an expired invitation (the rejection path) and for each route variant. Vectors unchanged (`cargo xtask vectors`:
11 suites identical).

### C. R-63 — known ct sites

`expect::KNOWN_SITES` (TR 8, INV 9, HX 8 names and the Output claim of `x25519_zero_check`); `ct_site_lines` reports
`ct: <target> claims the unknown reject site "<site>" …` as a problem, which fails the gate. `gates::tests::ct_gate_rejects_unknown_site`
(an unknown site fails and names target and site; every listed site passes). The `M3_SITES` fixtures of the existing
tests now use real site names (they were "site one"…); the summary row keeps `— site <site>`.

### D. mutants job

`cargo mutants -j 3` in the step, `timeout-minutes: 240` on the `mutants` job, ADR-047 Consequences: "`-j 3`; budget 240 min".
**Local time of the full two-crate step: not measured.** `cargo mutants --list` with the gate's flags gives 1281
mutants; the HX subset (331) alone took 67 min at `-j 3`, so the step is well over the 90-minute limit and was not
started locally. If cost scaled with the count the step would need about 4 h at `-j 3`, i.e. the 240-min budget
could be tight; crypto's tests are faster than the proto suite, so this is an upper estimate. The CI run measures it.

### E. Checks

`cargo fmt --check` ok; `cargo clippy --workspace --all-targets -- -D warnings`, `-p secmp-proto --all-targets`, and
`--all-features`: clean; `cargo nextest run -p secmp-proto --all-features`: 280 passed (before R-63; xtask 110
passed after); `cargo xtask vectors`: 11 suites identical; `cargo xtask step --strict policy`: PASS; Kani: above.

### Open / deviations
No deviation from the spec. From the letter of the WEISUNG: item 6's pattern (type parameters added, see table); item 4's
OPK numbering; `MUTANT_EXCLUDE_RE` additions sit in the same file as `KNOWN_SITES` (`expect.rs`), committed with
`xtask(m4): known ct sites (R-63), mutants -j3`. Risk: the full mutants step runtime (D). Totals: 22 missed → 3 missed
(documented equivalents); unviable 93 (was 93); caught 220 → 235 (the mutant set changed with the exclusions and new code).

### Push
At the end of the session PR run 37041956810 (head `67bce1a`, `linux-full` and `mutants` in progress since 17:37 UTC)
was still running: **not pushed** (window rule; a push cancels the run). Unpushed on `m04-hx`: `51f05f4`, `b1a6a51`,
`357fde8`, `d176e95` and the report commit.

## M4-10 — R-60 (mutants gate builds secmp-proto with kat)

The mutants step now passes `--features secmp-crypto/kat,secmp-proto/kat`, so the HX integration suite counts. Measured on bc17190 (HX files; command and full list in `M04-evidence/mutants-hx-bc17190.txt`): 335 mutants, 220 caught, 22 missed, 93 unviable, 0 timeouts; 67 min with -j3 (serial estimate ~3 h). Baseline test run is now ~130 s per mutant build: the full two-crate gate must be re-timed against the 180-min job budget. The 22 survivors are not fixed or excluded; the reviewer decides per mutant.

## M4-9 — WEISUNG M4-9 (ADR-043 ratified → rev 2.4, F16, ADR-044 → rev 2.5, O-10)

Start (§1 record): head `b204a8b`, 3 commits unpushed (`ahead 3`), tree clean, 2026-10-02 17:27 UTC (≥ 11:00 UTC: Part D due).
End: head `2af7924`.

- **A.** ADR-043 Status → Accepted (owner ratification by default 2026-10-02 02:45 UTC). `docs/03` rev 2.4, items (a)–(k)
  (k = `CLAUDE.md` §5, already in place since the M3 docs commit).
- **B.** `tr/content.rs`: `chunk_total`, `split_chunks` (the encoder shape), `canonical_shape` checked when a group completes;
  4 existing content tests rewritten to canonical chunking; 6 new tests in `tr/tests.rs`. Empty last chunk and over-long last
  chunk are already refused earlier (Fragment decoder `chunk ≥ 1`; the cell geometry limits a chunk to 1669 B), so those two tests do
  not depend on the new check; the other four fail without it (checked by disabling the check). `vectors/tr.json` unchanged.
- **C.** (g) `accept_handshake_caps_nonzero_rejects_and_keeps_opk` added (N-55: caps 1 and 0x80). (j) `dummy_carries_seq_zero_ts_zero`
  added (`content::dummy()` exists).
- **D.** ADR-044 Status → Accepted (11:00 UTC default). `docs/03` rev 2.5, items (a)–(f). Existing tests: (b) `initiator_start_output_and_state_contain_no_ek_secret`;
  (c) `group_rejected_then_other_init_id_accepts`, `group_duplicate_chunk_differing_first_seen_wins`, `group_duplicate_chunk_identical_ignored`,
  `group_partial_store_bound_8_evicts_oldest`; (d) `expired_invitation_record_is_not_offered_to_accept`; (e) `accept_first_msg_n_nonzero_rejects_and_keeps_opk`,
  `accept_first_msg_pn_nonzero_rejects_and_keeps_opk`, `accept_handshake_without_known_route_rejects_and_keeps_opk`; (f) `accept_reflected_own_iks_rejects_and_keeps_opk`.
- **E.** `docs/01` §7 row RR-15 (O-10).
