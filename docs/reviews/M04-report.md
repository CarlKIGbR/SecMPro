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

## 2. What was built
(filled in as the steps complete)

## 3. Evidence per acceptance criterion
(filled in as the steps complete)

## 4. Gates
(filled in per push; evidence under `docs/reviews/M04-evidence/`)

## 5. Deviations from the spec
None so far.

## 6. Open risks
None recorded.

## 7. Questions
None.

## 8. Blocked
Nothing.
