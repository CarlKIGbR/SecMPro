# Milestone report — M04 SecMP-HX handshake + SecMP-INV (sans-IO) + ProVerif model

Branch: `m04-hx` · Base: `main` at `836a94e4f8abec27d877740291ecbe9957c10177` (M3 squash merge) · Author: Claude Code (Sonnet 5.5) · Date: 2026-10-01 –

Status: **Phase A in progress** (INV, HX, prekey store, tests, vectors, xtask, ADR-045, M3 follow-ups except F5/F34/F2).
Phase B (`formal/hx.pv`, F5, F34, F2 ct target) is a separate conversation on Opus; `formal/hx.pv` is not part of Phase A.
**Phase B (BRIEF M4-PV, 2026-10-01): STOP at B1** — `formal/hx.pv` (e42c854) gives no RESULT within 30 min, nor
does its O-7 bounded variant (§3.1, §8.1). B2–B4 not started; B5–B8 prepared on two worktree branches, not on
`m04-hx` (§1.2).

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
| B1 | `formal/hx.pv` (CLAIMS §HX) | committed `e42c854`; **STOP** (§8.1) |
| B2 | `tr.pv` F5 (M3 R-12) | not started (brief §1: no B2 after a B1 STOP) |
| B3 | `tr.pv` F34 / CLAIMS T13 | not started |
| B4 | ProVerif gate F7 | not started |
| B5 | ct `tr_decrypt_reject_skipped` (F2) | prepared: branch `worktree-agent-a77420be221171832` `32005b0`; not on `m04-hx` |
| B6 | ct `inv_fingerprint_compare`, `x25519_zero_check`, `hx_accept_reject_inner`, `hx_accept_reject_first_msg` | prepared: same branch `1f3e113`; not on `m04-hx` |
| B7 | F19 pre-checks + reject sites | prepared: same branch `4d92ec2`; not on `m04-hx`; TR/INV site tags blocked (§8.1) |
| B8 | F1 branch-free `any_skipped` | prepared: branch `worktree-agent-a4a02fcd8ae0c8aac` `2a93d6c`; not on `m04-hx`; deviation (§5.2) |

Both branches are based on `2e5953e` (worktrees `.claude/worktrees/agent-a77420be221171832`, `…/agent-a4a02fcd8ae0c8aac`).

## 2. What was built (Phase A, WEISUNG M4-1 applied; local HEAD see §9)

- `secmp-proto::inv`: URI/QR text with constant-time, `Zeroizing` base64url (V-5), blob seal/open, `K_ld`/`K_inv`, `invitee_check` → `InviteeAccepted` (private fields, accessors; V-12), `IssueError` bounds.
- `secmp-proto::hx`: `transcript`, `session_key`, `k_id`; `Initiator::start(&InviteeAccepted, &InitiatorKeys, routes, profile, now, entropy)`; `HandshakeCells::release(persist(cells, state))` and `PersistedCells` for retry (V-6); `Responder::accept` over the array-based `Groups`/`drive` (ADR-044 (c)) with one `commit_accept` (OPK deleted and record consumed, V-7).
- `secmp-proto::prekeys`: `IdentityKeys`, `PrekeyStore` (+`commit_accept`), `MemoryPrekeyStore` (SPK generations by id with retention, OPK single use, RPK, records, `consume_record`, `issue_invitation`, `retire_expired`); bundle signing now uses `PrekeyBundle::signed_fields` (V-11).
- `tr`: `Opened::header_counters` (V-10: no fail-open default), entropy extensions, `encrypt_padded_kat`.
- Vectors: `vectors/hx.json` frozen (sha256 `a33cf162…`), generator and replay as before.
- Tests: `tests/hx/` 109 tests + 16 lib unit tests in `inv`/`hx`/`prekeys`; proptest-style properties P1–P11; fuzz F1–F7; Kani K1–K5.

## 3. Evidence (docs/reviews/M04-evidence/)
`ci-fast-aarch64-apple-darwin-local.txt` (PASS), `vectors-xtask.txt` (11 suites identical), `kani-xtask-step.txt` (`cargo xtask step --strict kani`: 24/24 harnesses verified, 847 s, Kani 0.68.0), `kani-k5-first-run-harness-overflow.txt` (first K5 run: failing check `kani_cell_plaintext_decode_total.assertion.1` = `attempt to add with overflow` at `len + 1` in the HARNESS' own assumption, not the decoder; fixed by `len >= PT_LEN - 1`; V-3 decoder unit tests `cell_plaintext_decode_rejects_i_ge_total` / `_total_ne_3` pass, the M2 decoder already rejects both), `fuzz-m4-local-120s.txt` (7 targets × 120 s, no findings).
Kani bounds: K1 none; K2 `unpad` stubbed (any proper prefix or rejection); K3 `Groups<u8,u8,2>`, ≤ 4 chunks over 3 init_ids, unwind 6 (44 s); K4 production bound 8 slots, ≤ 4 chunks over 3 init_ids, unwind 10 (250 s); K5 unwind 4010 (50 s).

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
(a) positives + vectors: 8 listed + `hx_vectors`, generator, flow, builder controls → all pass; extras: `builders_reproduce_an_accepted_envelope`, `accept_counter_rules_reject_after_a_valid_mac`, `accept_success_consumes_record_and_opk`, `hx_secrets_are_zeroizing_types`, `start_persist_error_is_returned_and_nothing_sent`. (b) negatives N-1…N-72 (N-58 withdrawn): all rows named, all pass. (c) P1–P11 pass. (d) F1–F7 implemented, 120 s each, K1–K5 verified. (e) all named assertions pass. (f) ct targets: Phase B (not started). (g) F10–F12 per §5.

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
   `Err(Rejected)` plus the unmodified invitation accepted.
4. **Pre-push check fails on the unchanged Phase-A head `2e5953e`:** `cargo clippy --workspace --all-targets -- -D
   warnings` → `error: missing documentation for the crate` at `crates/secmp-testkit/tests/differential.rs:2`
   (built without `kat`; outside §0). The gate's form (`--all-features --locked`) passes.

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
