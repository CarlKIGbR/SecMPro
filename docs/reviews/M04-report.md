# Milestone report — M04 SecMP-HX handshake + SecMP-INV (sans-IO) + ProVerif model

Branch: `m04-hx` · Base: `main` at `836a94e4f8abec27d877740291ecbe9957c10177` (M3 squash merge) · Author: Claude Code (Sonnet 5.5) · Date: 2026-10-01 –

Status: **Phase A in progress** (INV, HX, prekey store, tests, vectors, xtask, ADR-045, M3 follow-ups except F5/F34/F2).
Phase B (`formal/hx.pv`, F5, F34, F2 ct target) is a separate conversation on Opus; `formal/hx.pv` is not part of Phase A.

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

## 4. Verifier findings
V-1 done (`accept_counter_rules_reject_after_a_valid_mac`: MAC verifies, `remaining()==0`, store/OPK unchanged, control 0/0 accepts; `first_msg_with_counters` advances `ck_s`). V-3 done (two named decoder tests). V-5 done (arithmetic base64, `Zeroizing`). V-6 done (`start_persist_error_is_returned_and_nothing_sent`). V-7 done (`accept_success_consumes_record_and_opk`). V-8 done (docs; `hx_secrets_are_zeroizing_types` type ascription). V-9 done (hard assertions, `low_order()` extended to 8 values, moved to `hx/tests.rs`). V-10 done. V-11 done. V-12 done (`docs/07` API line updated).

## 5. M3 follow-ups (Part E)
F3 done (dependency-free YAML-aware reader, `required_job_bypasses_are_findings`) · F6 not done: formal (`tr.pv`) — Phase B · F8 done · F9 done (bound check before `apply`; the post-apply error arm is provably unreachable) · F10 partly (`Profile.name` is `Zeroizing<String>`; hosts/msg_ids unchanged) · F11 done · F12 partly (type-pin test in `tr/ratchet.rs`; no heap-probe pattern in testkit) · F14 done · F18 done · F20 done (ADR-042 consequence sentence + non-kat nextest in step 4) · F21 done · F22 done (`miri-full.yml` one job per package; required jobs unchanged) · F23 done · ctreport `class_median` refusal done (Amendment-2 format reports only) · ADR-041 Amendment 2 status line, M03-report Q-1 text done. F16 waits for ADR-043 ratification (after 2026-10-02 02:45 UTC). F4, F17 skipped (optional).

## 6. ADR-045
`xtask/src/summary.rs`; every step of `ci-full`/`ci-fast` appends a table (`status`, one row per verdict line; for `ct` the run verdict, runner timer, every target/control row from the gate's reading; for `proverif` the sha256 of the models) to `$GITHUB_STEP_SUMMARY`, else stdout. Test `summary::tests::the_ct_table_comes_from_a_recorded_report` (run 36840478213 report: 18 rows). A run page with the table is the next push's PR run.

## 7. Test counts per spec section (implemented / passing / extra)
(a) positives + vectors: 8 listed + `hx_vectors`, generator, flow, builder controls → all pass; extras: `builders_reproduce_an_accepted_envelope`, `accept_counter_rules_reject_after_a_valid_mac`, `accept_success_consumes_record_and_opk`, `hx_secrets_are_zeroizing_types`, `start_persist_error_is_returned_and_nothing_sent`. (b) negatives N-1…N-72 (N-58 withdrawn): all rows named, all pass. (c) P1–P11 pass. (d) F1–F7 implemented, 120 s each, K1–K5 verified. (e) all named assertions pass. (f) ct targets: Phase B (not started). (g) F10–F12 per §5.

## 8. Open / Phase B
ct targets (f), `formal/hx.pv`, F1, F2, F5, F6, F7, F19, F34, F16 (after ratification), F10 hosts/msg_ids, F12 heap probe.

## 9. Push state
PR run 36885710027 (head 50cfca3) was still running at the end of this session: the 4 later commits are NOT pushed.
