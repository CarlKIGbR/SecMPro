# Milestone report — M5 SecMP-LINK + SecMP-Q + relay core + in-process harness

Branch: `m05-link` · Base: `a229dbfc9dfe57dd0957359044389eb3b6654b32` · Author: Claude Code · Date: 2026-10-07
Phase A: `modell=claude-sonnet-5-5` (sub-agents for test code: `claude-sonnet-5-5` ×5, `claude-opus-5-5` ×1 for the spec-text application)
Phase B: `modell=claude-opus-5-5` (sub-agents: `claude-opus-5-5` ×9)

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M05-planning/` (`BRIEF_M5.md`, `TEST-SPEC-M5.md`, `ADR-048-proposed.md`, `CLAIMS-LINK.md`,
`OPEN-M5-decided.md`). ADR-048 and the owner-class items (o), (p) were ratified by default on 2026-10-04 20:45 UTC (brief
§11 (1)); optional (q) is not adopted (reading A). The [SQ-n], [O-1], [O-2], [O-6] rows are therefore in scope from the start.

Phases and handover: A (Sonnet) → B (Opus) → C (Sonnet). **Phase A closed @ `8738ae170a083a1323f14eeb21183bb567e693f5`**
(PR run `37719235451` green on linux-fast, windows-native, xwin-cross, linux-full, ct, mutants, proverif-hx; rows of steps 1–10).
Phase B: `modell=claude-opus-5-5`, binding inputs additionally `BRIEF_M5-B` (reviewer, 2026-10-08).

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 1 | A | Commit 1: planning files, ADR-048, CLAIMS §LINK, reference files, SCHEMA rev-6 delta, this plan, M2 coverage table | — | done (`7bb2f39`) |
| 2 | A | `secmp-proto::link`: constants, derived ids (rid/sid/akc), access token; `secmp-crypto::{hkdf_extract, hmac_sha256(+verify), Nonce24::from_link_counter}`; `Entropy::hybrid_encaps{768,1024}` | P-05 | done |
| 3 | A | Link handshake, client and relay (sans-IO): HELLO/RELAYINFO/HS1/HS2 | C-01…C-22, RH-01…RH-15, P-01 | done |
| 4 | A | Frame layer `Link::{seal, open_unit, commit, open, open_request, open_response}`, counters, `LINK_MAX_FRAMES`, CONT assembly | F-01…F-10, F-12, P-02…P-04 | done |
| 5 | A | Rust replay of link-0001…0005, 0052…0074; file shape | V-01…V-05, V-17…V-19, V-21 | done |
| 6 | A | R-55, R-56 | G-03, P-12 | done |
| 7 | A | Kani harnesses | K-01…K-04, K-08 | done (30/30 harnesses, local `step kani`) |
| 8 | A | Fuzz targets (+ committed seeds) incl. `hx_accept_structured` mode 3 | FZ-01…FZ-06, FZ-09 | done (local 120 s each) |
| 9 | A | docs/03 rev 2.6 (ADR-048), errata, re-anchoring | — | done (`ca3a304`) |
| 10 | A | `cargo xtask ci-fast`, push, PR, PR run; handover | — | ci-fast done locally; PR run: see §4 |
| B1 | B | Commit 1 (docs): ADR-047 Am. 3 in `docs/08`, CLAIMS §TR row T14 (+ gate rule), this Phase B plan | — | done (`6665c78`, run `37737873733`) |
| B2 | B | `crates/secmp-relay`: executor, `QueueStore`, `LinkDataStore`, `MemoryBudget`; link-A replay (oracle); Rust generator of `vectors/link.json`, step 12a with 12 suites | Q-01…Q-60, P-06…P-11, K-05…K-07, FZ-07, V-06…V-16, V-20, V-22, X-01 | done (`2d2fa09`, `e6d8f17`, `96a61f0`, `ae0d67e`, `85f4c01`) |
| B3 | B | Relay connection task, sweeper, rate limits, drain, `keygen`/`rotate-static`, config, tracing test, zeroization | RL-01…RL-23, F-11, FZ-08 | done (`e6d8f17`, `96a61f0`, `d4eef33`) |
| B4 | B | Gates: ct targets; counting accessors (R-42/R-59) + docs/01 RR-17 line; `formal/link.pvl` + `formal/link/*.pv`, `tr.pv` T14, CLAIMS O-15 sentence, `proverif-link` job; mutants scope (`docs/06` §4); PR-run CI seed for properties | CT-01…CT-06, X-03, G-01, G-02, PV-01…PV-03, X-04, X-05, X-02, X-07 (opt: X-06, X-08) | done; PV-01 after WEISUNG M5-B-2 (LO-5, LO-6: the breaks of `lDH`, `lBoth` as reveals; 9/9 files PASS at `5d7d45b`) |
| B5 | B | Evidence under `M05-evidence/` per push; Phase B report; closing push; row "Phase B closed @ `<sha>`" | — | done — **Phase B closed @ `dc34d93`** (`dc34d93d696b4d4699aa3939e9af428de2e7bdd6`; run 37817187858 red: windows-native, coverage, mutants; fixed in M5-B-3; §4B, §5B; one docs/evidence-only commit on top). Earlier close @ `6483344` |
| C1 | C | Commit 1: carry-over test `keys::tests::rotation_boundary_new_generation_may_expire_with_the_newest` (+ the gate's mutants command restricted to `keys.rs` `rotate`: 7 caught); ADR-042 consequence line accepted; hx re-freeze: `vectors/ref/hx.json` (sha256 `2bf05e69…a0e8d`, 1 432 784 B, checked), `vectors/SCHEMA.md` rev 7, `vectors/SCHEMA-4.10-hx.md`; `InvitationRecord` (owner and invitation-queue recipient seeds), `issue_invitation` (derived `inv_sid`), `RelayQueue::derived`; generator cases hx-0003, hx-0031…0037; `vectors/hx.json` re-frozen by `cargo xtask vectors` | V-23, V-24, V-25, G-04, G-05 | done |
| C2 | C | `secmp-transport`: `Session` (SecMP-LINK client over `std::io` streams), `RelayQueueTransport`, `RecvCap`/`SendCap` | T-01…T-09, T-11 | in progress |
| C3 | C | `secmp-testkit::harness` (feature `kat`): `Harness`, virtual `Clock`, `EntropyPool`, `HarnessStream`/`Capture`/`Split`, `Side`; scenarios | H-01…H-06, H-08…H-13, G-06 | in progress |
| C4 | C | Local gates (`ci-fast --strict`, `step --strict vectors kat`, Kani, nextest per touched crate), evidence under `M05-evidence/` | — | open |
| C5 | C | Closing push = this report complete; PR run green on all jobs | — | open |

### M2 coverage of D.1 records and D.2 requests/responses (decides K-08 and P-13)

| Item | Existing M2 artefact | Decodes | Covers |
|---|---|---|---|
| property | `crates/secmp-proto/tests/canonical.rs::records` | `Hello`, `RelayInfoV1`, `RelayInfoRecord`, `Hs1`, `Hs2` (D.1) | decode(encode(x)) = x; mutants canonical |
| property | `crates/secmp-proto/tests/canonical.rs::frames` | every `Request` / `Response` (D.2 incl. `CONT`, all `CELLR` contexts) | same, incl. `check_bytes` and `mutants_are_canonical` |
| Kani | `request_queue_new`, `request_skey`, `request_send`, `request_fetch`, `request_queue_del`, `request_link_put`, `request_link_get`, `request_ping`, `request_cont`, `request_fetch_multi` | request decoder, plaintext length 4335/4336/4337 per opcode | total, exact-fit |
| Kani | `response_frame` | response decoder, both `CELLR` contexts, lengths 4335/4336/4337 | total, exact-fit, opcode preserved |
| Kani | — | no harness runs the request and the response decoder in one proof | — |

Decision: **P-13 not dictated** (`canonical.rs::records` and `::frames` cover all four D.1 records and every D.2 request and
response). **K-08 dictated** (the condition "no M2 harness runs both decoders" holds literally) and implemented as
`kani_q_frame_plaintext_exact_fit`.

## 2. What was built

- `crates/secmp-crypto`: `mac.rs` (`hkdf_extract`, `hmac_sha256`, `hmac_sha256_verify`, `MAC_LEN`; RFC 5869 A.1/A.3 and RFC 4231
  1/2 vectors), `Nonce24::from_link_counter` (spec §8.4 nonce). No new dependency (`hmac`, `hkdf` were already direct).
- `crates/secmp-proto/src/link/` (spec §8, §9.1–9.2, §9.6, D.1, D.2): `client.rs` (typestate `start → AwaitRelayInfo →
  AwaitHs2 → Link`), `relay.rs` (`RelayKeys`, `accept → AwaitHello → AwaitHs1 → (HS2, Link)`), `handshake.rs` (the key schedule of
  §8.3), `frame.rs` (`Link`: seal / `open_unit` / `commit`, strict `+1` counters with `checked_add`, `LINK_MAX_FRAMES` on the
  client, uniform `Error::Rejected`, kat trace), `cont.rs` (the pure continuation decision `step`, `LinkPutAssembler`,
  `LinkrAssembler`, `split_blob`), `ids.rs` (`relay_fp`, `akc`, `rid`, `sid`, `token`, `token_verify`).
- `tr::Entropy` gains `hybrid_encaps768` / `hybrid_encaps1024` (draw order `sk_e`, then `m`, reading OPEN-1).
- Tests: `crates/secmp-proto/tests/link/` (one test crate: `fixture`, `vectors`, `client`, `relay_hs`, `frames`), unit tests in
  `link/cont.rs`, `link/mod.rs`, `secmp-crypto` `mac::tests`, `nonce::tests`; G-03 in `tests/tr_vectors.rs`; P-12 in `tests/hx/props.rs`.
- Kani: `kani_proofs.rs` (5 harnesses), `#[cfg(kani)]` AEAD stand-in in `link/frame.rs`.
- Fuzz: 6 new targets + mode 3 of `hx_accept_structured` (`fuzz/`), seeds under `fuzz/corpus/`.
- Gates: `xtask/src/expect.rs` (`KANI_HARNESSES` 25 → 30, `KANI_COVERS`, `FUZZ_TARGETS` 21 → 27, `FUZZ_MAX_LEN`, `FUZZ_TRACKED_ONLY`,
  `VECTOR_REF_PENDING = [link]`, `MIRI_FEATURE_GATED`), `gates.rs` (portable-backend rerun of `link`).
- Docs: `docs/03` rev 2.6 (ADR-048 (a)–(d), (f)–(p), E-1, E-2, E-8), errata E-3…E-5, E-7, re-anchoring of `formal/CLAIMS.md` and
  `docs/08` ADR-044 (E-6), `vectors/SCHEMA.md` rev 6 + `SCHEMA-4.11-link.md`, `vectors/ref/link.json`, `ref/` LINK files.

## 3. Evidence per acceptance criterion (Phase A rows)

Reference-file check (commit 1): `shasum -a 256 vectors/ref/link.json` = `dd77bb7c96d298f9cc188d4eadbd950605ccca2a250169708cdc573a73264c77`,
`stat -f %z` = 2 818 910. `vectors/SCHEMA.md` vs `target/fable/m5/ref/SCHEMA.md`: only the revision-7 header line and the §4.10
pointer differ (Phase C); `docs/reviews/M05-evidence/schema-diff.txt`.

| Section | Rows | Test names (integration crate `link`, in `crates/secmp-proto/tests/link/`, unless noted) |
|---|---|---|
| (a) vectors | V-01…V-05, V-17…V-19, V-21 | `vectors::link_vectors_relay_keys`, `…_relayinfo_accept`, `…_hs1`, `…_hs2`, `…_hs2_accept`, `…_relayinfo_reject`, `…_hs1_reject`, `…_hs2_reject`, `…_file_shape` |
| (b1) client | C-01…C-22 | `client::client_hello_record_bytes` … `client::client_rejection_leaves_no_link` (names as in the TEST-SPEC) |
| (b2) relay | RH-01…RH-15 | `relay_hs::relay_hello_shape_tears_down` … `relay_hs::relay_handshake_rejection_keeps_no_state` |
| (b3) frames | F-01…F-10, F-12 | `frames::link_frame_seal_matches_independent_aead` … `frames::link_client_response_value_rules_reject` (F-11 is Phase B) |
| (b7) F-M5 | G-03 | `tr_vectors::tr_vectors_f14_new_iks_equals_vector_iks` |
| (d) properties | P-01…P-05, P-12 | `frames::prop_*` (5), `hx::props::prop_k_id_independent_of_iks_i_dh1_dh2` |
| (e) Kani | K-01…K-04, K-08 | `kani_proofs::{kani_frame_pad_total, kani_link_counter_strict_plus_one, kani_link_counter_checked_add, kani_cont_assembly, kani_q_frame_plaintext_exact_fit}` |
| (f) fuzz | FZ-01…FZ-06, FZ-09 | `link_records`, `link_client_handshake`, `link_relay_handshake`, `link_frame_open`, `q_request_decode`, `q_response_decode`, `hx_accept_structured` (mode 3) |

Counts (implemented / passing / extra): vectors 9 / 9 / 1 · client 22 / 22 / 0 · relay 15 / 15 / 1 · frames 11 / 11 / 0 · F-M5 unit 1 / 1 / 0 ·
properties 6 / 6 / 0 · Kani 5 / 5 / 0 · fuzz 7 / 7 / 0 → 76 rows (75 dictated + K-08). Listing: `docs/reviews/M05-evidence/kat-listing-phase-a.txt`.

Extra tests (named): `vectors::link_vectors_derived_ids_and_token_of_case_6`, `relay_hs::relay_keys_report_their_kid`;
unit: `link::cont::tests::{step_follows_the_table, blob_offsets_and_cont_indices, link_put_assembles_in_order, link_put_rejects_every_other_order,
linkr_assembles_in_order_and_rejects_the_rest, split_blob_cuts_at_the_offsets}`, `link::tests::{display_names_each_condition_without_detail,
errors_convert_keeping_their_kind, limits_are_the_spec_values}`, `secmp-crypto` `mac::tests::{extract_matches_rfc5869_a1,
extract_matches_rfc5869_a3_and_empty_salt_is_zero_salt, hmac_matches_rfc4231, labelled_mac_is_hmac_over_label_then_context_unframed,
verify_accepts_only_the_tag}`, `nonce::tests::link_counter_nonce_is_zero_prefix_then_u64_be`.

F-M5 lines of Phase A: R-44 → FZ-09 (done) · R-55 → G-03 (done) · R-56 → P-12 (done; function-level: the end-to-end variant
through the `Initiator` was not built) · R-42/R-59, R-41, R-47, R-66, R-67, R-70, R-90, R-92, R-93 → Phases B/C.

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci-fast --strict` (local, `fd86ca2`) | PASS; log `docs/reviews/M05-evidence/ci-fast-local-fd86ca2.txt` |
| `cargo xtask step --strict kani` (local, `ae10972`) | 30/30 harnesses verified, 3215 s; covers 1/1, 2/2, 1/1, 1/1; log `kani-xtask-step-ae10972.txt` |
| Fuzz (local, 120 s per target, scratch corpus) | `link_records` cov 677 ft 1604; `link_client_handshake` 3197/6506; `link_relay_handshake` 2908/5183; `link_frame_open` 3881/4467; `q_request_decode` 559/1485; `q_response_decode` 237/341; `hx_accept_structured` 6111/9468; no crash; `fuzz-phase-a-local-e243648.log` |
| Mutation pre-check (local, `cargo mutants -f 'link/*.rs'`, link tests only) | first run 160 mutants: 76 caught, 44 unviable, 40 missed → tests added (§2); second run (`e243648`): 156 mutants, 112 caught, 44 unviable, 0 missed (`mutants-link-second-run.txt`); `secmp-crypto` `mac.rs` + `nonce.rs`: 22 mutants, 9 caught, 13 unviable, 0 missed (`mutants-crypto-mac-nonce.txt`) |
| PR run (`linux-fast`, `windows-native`, `xwin-cross`, `linux-full`, `ct`, `mutants`, `proverif-hx`) | pending — run IDs in the closing message |

## 5. Deviations from spec / plan

- Reference files copied by the reviewer (WEISUNG M5-1), `<SECMPROREF>` = `target/fable/m5/ref/`.
- R-104: `e243648` left `kani_stubs` importing `AEAD_TAG_LEN` from `super` after the `use crate::sizes` line lost it; the Kani
  gate evidence (30/30, 3215 s) predates that commit; fixed in `cc6d8c8`, codegen at the fixed head exit 0
  (`M05-evidence/kani-codegen-m5a-cc6d8c8.txt`), full gate = CI `linux-full` of the run on the pushed head.
- `docs/01:48` (E-4): the literal substitution of ADR-048 Part 5 breaks the sentence; applied as "identical handshake cells
  (App. D `HandshakeCell`) are indistinguishable from other cells".
- K-01 `kani_frame_pad_total` is bounded: the symbolic `unpad` scan of a 4336-byte buffer did not finish in about 30 minutes, so
  `unpad` is proven total / inverting `pad` for buffers whose last 32 bytes are not all zero (`SCAN_WINDOW`); the longer all-zero tail rests
  on the existing `padding` harness (size-generic code, sizes up to 32). K-08's request side stubs `RequestCmd::decode_fields` (as
  `request_frame` does); the per-opcode `request_*` harnesses cover the field decoders.
- Fuzz seeding: `xtask::expect::FUZZ_TRACKED_ONLY` lists the six link/Q targets, which rely on their tracked corpus until Phase B freezes
  the `link` suite (the unit test `the_rules_name_listed_targets_and_frozen_suites` fails if a listed target also has a seeding rule).
- Test layout: one test crate `link` (the policy gate refuses a `dead_code` allow, so the shared fixture must be used by something
  in every build); F-08 is exercised on the relay link (the client's `LINK_MAX_FRAMES` check precedes the overflow check).
- The nightly fuzz campaign now gets 14 400 / 27 = 533 s per target (README updated).

## 6. Dependencies added or bumped

None.

## 7. Open risks and known limitations

- The `step kani` gate takes 3215 s locally (M4: 1791 s for 25 harnesses); K-01 and K-08 are the long ones (712 s, 472 s alone).
- P-12 is checked at function level (independent key agreement of §6.4 with the real `hx::k_id`), not through a full `Initiator`/`Responder` run.
- `tr::Entropy` is sealed and now has two more methods; any Phase B/C counting wrapper must live in `secmp-proto` (`kat`).

## 8. Blocked / questions for the reviewer or owner

None.

## Phase B (BRIEF_M5-B, WEISUNG M5-B-0, WEISUNG M5-B-2, BRIEF M5-B-3; `modell=claude-opus-5-5`)

Commits `6665c78`, `b5e156d`…`85f4c01`, `3dfc55d`, `c3a684b` (STOP report), `5d7d45b`, `0ca55bb`, `6483344` (WEISUNG M5-B-2),
`d349053`, `109b280`, `dc34d93` (BRIEF M5-B-3) (+ this report). Phase B closed @ `6483344` (the PV-01 STOP resolved by the
reviewer decisions LO-5…LO-7, §5B, §8B); its PR run 37817187858 was red in windows-native, linux-full (coverage) and mutants;
**closed @ `dc34d93`** after the M5-B-3 fixes.

### 2B. What was built

- `crates/secmp-relay` (new; spec §8.2–§8.5, §9, D.1, D.2, D.6): `conn` (records, handshake rate, `HELLO`→`HS1` timeout, kid
  validity, one link per connection), `executor` (open, decode, `SKEY`, CONT assembly, frame rate, `cmd_seq` admission
  `admit`/`answer`, render and seal), `exec` (the eight commands under one lock, OPEN-M5-04 order), `plan` (D.2 counts,
  OPEN-7/OPEN-8/SQ-28 layouts), `relay` (state, sweeper, drain, kat snapshot/digest), `queue`, `linkdata`, `cells`, `budget`
  (two pools, worst-case reservations), `buf` (wipe on drop, kat live count), `cmdseq`, `rate`, `keys` (key file, `keygen`,
  `rotate-static`, `KeyRing`), `config` (TOML subset), `event` (closed set), `clock` (hour buckets; the one `SystemTime::now`),
  `server` (generic `serve`/`handle` over `Listener`/`Stream`/`Time`; `std::net`), `error`, `main` (CLI), `kani_proofs`.
- `secmp-proto`: §4.2 constants, `relay::accept_ring`, `Cell::into_boxed`, `signed::link_put_hashed`, `RelayKeys: ZeroizeOnDrop`;
  TR header trial through the constant-flow open, `SkippedKey::mk()` counting accessor; `tests/common/seed.rs`.
- `secmp-crypto`: `Aead::open_ct_constant_flow` (R-59; used only by the TR header trial); `ZeroizeOnDrop` re-export and markers.
- `secmp-testkit`: ct targets CT-01…CT-06. `fuzz`: `relay_executor`, `relay_link_session` (+3 seeds each).
- `formal`: `link.pvl` + `link/*.pv` (9 sessions; in `lDH` and `lBoth` the breaks as phase-0 reveals through the variants
  `RelayR`/`RConnR`/`ClientR`/`CLinkR`/`CTailR`, LO-5, LO-6), `tr.pv` T14, CLAIMS O-15 sentence, CLAIMS §LINK "Reviewer
  decisions (2026-10-08)". `vectors/link.json` frozen.
- `xtask`/CI: gate tables (vectors 12 suites, fuzz seeding, Kani 33, ct 26, mutants +relay, kat +relay, link models), `testscan`
  (CI run seed, compile_fail scan), job `proverif-link`, `linux-full --delegated proverif-link`.
- Docs: ADR-047 Am. 3, ADR-049 (accepted by the reviewer 2026-10-08), CLAIMS T14, `docs/06` §4 Mutation and §2 logging line
  (the relay's closed event set meets CLAUDE.md §4), `docs/01` RR-17 status line, `docs/mutants-accepted.md` (2 rows).

### 3B. Evidence per TEST-SPEC row (Phase B)

| Section | Rows | Tests (crate `secmp-relay` test `relay` unless noted) | Result |
|---|---|---|---|
| (a) vectors | V-06…V-16, V-20 | `vectors::link_vectors_{queue_new, send, ping, fetch, fetch_multi, send_fill, queue_del, link_put, link_get, skey, indist, frame_reject}` | 12 PASS (every link-A case byte-identical: req, req_frames, resp, resp_frames, link_post, store_post, draws consumed) |
| (a) vectors | V-22 | `generator::link_generator_reproduces_ref_file` | PASS; `cargo xtask vectors`: 12 suites identical, `link` frozen (sha256 `dd77bb7c…4c77`, 2 818 910 B) |
| (b3) | F-11 | `rl_conn::relay_unknown_request_opcode_tears_down` | PASS |
| (b4) | Q-01…Q-60 | `q_queue::*`, `q_send_fetch::*`, `q_linkdata::*`, `q_seq::*`, `q_auth::*`, `q_shape::*` (names as TEST-SPEC) | 60 PASS |
| (b5) | RL-01…RL-23 | `rl_store::*`, `rl_conn::*`, `rl_process::*` (names as TEST-SPEC) | 23 PASS |
| (b7) | G-01, G-02 | `secmp-proto` test `tr_trial_counts`: `tr_header_trial_open_tries_every_key`, `tr_skipped_lookup_touches_every_entry` | PASS |
| (d) | P-06…P-11 | `props::prop_*` (names as TEST-SPEC) | 6 PASS (DEFAULT_SEED; CI seed pass in the kat step) |
| (e) | K-05…K-07 | `kani_proofs::{kani_cmd_seq_monotone, kani_queue_eviction_bounds, kani_executor_response_count}` | VERIFIED 2.9 s / 52.2 s / 113.7 s; K-06 negative control FAILED, 3/3 covers |
| (f) | FZ-07, FZ-08 | `relay_executor`, `relay_link_session` | 120 s each, no crash; cov 5727 / 5280, ft 20652 / 12238 |
| (g) | CT-01…CT-06 | `link_hs1_reject_mac1`, `link_hs2_reject_mac2`, `link_frame_open_reject`, `q_queue_new_reject_token`, `tr_decrypt_trial_open_position`, `link_same_content_control` | local `SECMP_CT_SCALE=10`: PASS each, run PASS (evidence only); CI `ct`: run below |
| (h) | PV-01 | `formal/link/*.pv`, xtask `proverif_link_matches_claims` | PASS: gate 9/9 files, 55 RESULT lines as expected, models `5d7d45b` (`M05-evidence/proverif-link-local-2.txt`); `lDH` L3a true ×2, L8 false ×3, L1a true, L4 true ×2 (59.0 s); `lBoth` L3c false ×2, L8 false ×3, L1c false (655.2 s); test PASS. Traces of the false lines: below |
| (h) | PV-02 | `tr.pv` T14; xtask `proverif_tr_t14_second_receive` | T14 true; T1–T13 unchanged (46 lines); probe with the entry kept: false |
| (h) | PV-03 | CLAIMS O-15 sentence | done |
| (i) | X-01…X-08 | `vectors::tests::vectors_step_12a_covers_twelve_suites`, `gates::tests::mutants_scope_includes_relay`, `ctreport::tests::ct_targets_list_names_m5_targets`, `gates::tests::proverif_link_table_covers_every_claims_row`, `gates::tests::proverif_link_model_hashes_are_pinned`, `…doctest_compile_fail_blocks_name_an_error_code` (opt), `…pr_ci_runs_props_with_ci_run_seed`, `gates::tests::ct_target_sites_bind_each_target_to_its_site` (opt) | 8 PASS (both optional rows done) |

Counts implemented / passing / extra: vectors 13 / 13 / 1 · unit 86 / 86 / 53 · property 6 / 6 / 0 · Kani 3 / 3 / 0 · fuzz 2 / 2 / 0 ·
ct 6 / 6 local (CI pending) / 0 · formal 3 / 3 / 0 · xtask 8 / 8 / 6 → 127 rows, 127 evidenced.

PV-01, the false lines of `lDH` and `lBoth`, one line per trace (`target/proverif/link-<s>.log`, "A trace has been found." each):
- `lDH` L8 ×3, `lBoth` L8 ×3: honest runs — CStart after R's RELAYINFO; the honest pair (R answers C's HS1, C verifies mac2);
  R executes C's QUEUE_NEW.
- `lBoth` L1c: R never receives the HS1; the attacker computes ss1 from the revealed exponents (relay_dh, the HybridKEM-1024
  ephemeral) and the revealed coins r1 and answers HS2 itself (its own e_r and ML-KEM-768 encapsulation to ek_c, ck2, mac2):
  CAccept without RAccept (the non-injective companion line too).
- `lBoth` L3c (c2r): honest handshake; ss1 and ss2 from the reveals (relay_dh, e1, e_r, coins r1, r2) give k_c2r; the attacker
  opens C's FETCH frame (counter 1).
- `lBoth` L3c (r2c): honest handshake; under k_c2r from the reveals the attacker sends R its own QUEUE_NEW on the honest link, R
  executes it and its OK_QUEUE_NEW is opened under k_r2c; C accepts the HS2.

Extra tests (named): `vectors::link_vectors_ok_queue_new_carries_the_derived_ids`; `conn_stream::{connection_answers_each_record_when_complete_at_any_split, connection_takes_coalesced_records_and_frames}`;
`rate_cont::{a_link_put_with_one_frame_over_the_rate_is_err_7, a_stale_link_put_over_the_rate_is_err_6}`; `server_loop::{serve_retries_and_exits_after_the_drain, serve_fails_on_a_listener_error, serve_closes_connections_while_draining, serve_hands_each_connection_to_its_thread, handle_answers_and_closes_at_eof, handle_ticks_retries_and_stops_on_an_error, handle_stops_on_teardown_write_failure_and_refusal}`;
test `cli`: `cli_{prints_the_banner, keygen_writes_a_key_file_and_prints_relay_fp, keygen_takes_the_validity_in_days, rotate_static_adds_the_next_generation, refuses_incomplete_and_unknown_arguments, config_errors_refuse_the_start}`;
relay unit tests (33): `budget::tests::{reservations_are_the_worst_case, a_reservation_fails_exactly_when_it_would_exceed, an_unlimited_pool_refuses_only_overflow}`, `buf::tests::{buffers_keep_their_bytes, the_live_count_follows_the_buffers}`, `cells::tests::{ids_start_at_one_and_eviction_reports_the_oldest, ack_deletes_exactly_the_ids_up_to_it, expiry_follows_the_arrival_bucket, an_exhausted_id_space_changes_nothing}`, `clock::tests::{buckets_are_hours_since_the_epoch, expiry_is_strictly_after_the_ttl, now_has_its_bucket}`, `cmdseq::tests::only_a_greater_cmd_seq_is_fresh`, `config::tests::{every_value_is_taken, absent_limits_are_the_defaults, every_malformed_text_is_refused, values_and_comments_follow_the_subset, a_hash_inside_a_string_is_not_a_comment, the_vector_limits_are_unlimited_rates}`, `error::tests::messages_name_the_condition_only`, `event::tests::names_and_lines`, `keys::tests::{a_generated_file_round_trips, the_decoder_refuses_every_rule_violation, the_decoder_bounds_and_orders_the_generations, rotation_adds_the_next_kid_and_keeps_the_identity}`, `plan::tests::{fetch_pads_with_dummies_and_puts_an_error_first, fetch_multi_errors_first_then_cells_then_dummies, frame_counts_follow_d2}`, `queue::tests::{ids_index_the_queue_until_it_is_removed, arrivals_count_from_one}`, `rate::tests::{a_burst_then_the_refill_rate, the_hello_default_and_a_backwards_clock}`, `server::tests::the_sweeper_ticks_once_a_second`;
`secmp-crypto`: `aead::tests::constant_flow_rejects_like_open_ct`, `kat_symmetric::{wycheproof_xchacha20_poly1305_constant_flow_equals_open_ct, constant_flow_equals_open_ct_randomized}`;
xtask: `gates::tests::{relay_trace_allow_equals_the_event_names, mutants_floor_refuses_unattributable_outcomes, ci_full_accepts_the_proverif_link_delegation}`, `testscan::scan::tests::{the_seed_scan_flags_each_rule, the_seed_scanner_reads_items_and_calls}`, `fuzzseed::tests::link_seeds_follow_the_target_layouts`.

Tests touched by M5-B-3 (extra tests; no TEST-SPEC row changes, counts unchanged): `cli::cli_config_errors_refuse_the_start` (config
path with `/`), `cli::cli_rotate_static_adds_the_next_generation` (+ `--valid-days x`), `gates::tests::relay_trace_allow_equals_the_event_names`
(source through `lf`), `gates::tests::coverage_ignores_test_files` (+ `--features secmp-relay/kat`), `secmp-proto`
`wire::cell::tests::cell_parts` (+ `into_boxed` content), `server_loop::*` (the scripted listener fails after `ACCEPT_CALLS_MAX` = 100
accept calls; it waits for the connection's close once). All PASS at `dc34d93` (`M05-evidence/m5b3-checks-local-dc34d93.txt`).

F-M5 lines: R-41 → PV-02 T14 true (`33a55ea`) · R-42/R-59 → G-01, G-02 PASS; constant-flow AEAD open of the TR header trial (`b5e156d`); CT-05 local PASS, CI below; `docs/01:192` status line · R-47 → X-08 done · R-70 → PV-03 done · R-92 → X-06 done (stable rustdoc does not check the code; the test is a source scan) · R-93 → X-07 done (CI seed = `GITHUB_RUN_ID`, pass in the `kat` step for `secmp-proto` and `secmp-relay`).

### 4B. Gates (local, Apple M1 Pro; heads named)

| Gate | Head | Result |
|---|---|---|
| `step --strict fmt clippy policy` (WEISUNG M5-B-0 §2) | working tree on `6665c78` | PASS after `cargo fmt --all` and one `too_many_lines` fix (`target/fable/m5b0-fast.txt`) |
| `nextest -p secmp-relay -p secmp-proto` (§2) | same | 402 / 402 PASS (`target/fable/m5b0-nextest.txt`); relay with `kat` 138 / 138 |
| `ci-fast --strict` | `85f4c01` | fmt, clippy, policy, deny, vet, audit, cooldown, doctest, hello, kat PASS; nextest FAIL: only `proverif_link_matches_claims` (PV-01 STOP); `M05-evidence/ci-fast-local-85f4c01.txt` |
| `step --strict kani` | `ae0d67e` | PASS, 33/33 harnesses, 5291 s (load from ProVerif and cargo-mutants), every cover satisfied; codegen `-Z stubbing --only-codegen` exit 0 after the last `#[cfg(kani)]` change |
| Kani per harness (relay) | `ae0d67e` | K-05 2.9 s, K-06 52.2 s, K-07 113.7 s; negative control 40.2 s FAILED (1 of 791), 3/3 covers; `M05-evidence/kani-m5b-*.txt` |
| Fuzz 120 s | `6665c78` + tree | `relay_executor` 752 runs cov 5727 ft 20652; `relay_link_session` 7465 runs cov 5280 ft 12238; no crash (`fuzz-m5b-local.log`) |
| Mutation pre-check `secmp-relay` (`-j 2`) | `ae0d67e` | 438 tested: 296 caught (67.6 %), 121 unviable (27.6 %), 21 missed (`mutants-relay-local-ae0d67e.txt`) → 19 killed by `d4eef33`/`9378b71` (targeted rerun of `server.rs` + `queue.rs`: 66 tested, 38 caught, 25 unviable, 3 missed; then `serve` 6/6 caught), 2 documented (`docs/mutants-accepted.md`, the `TcpStream` shim) |
| ProVerif `link` gate | `d4eef33` | FAIL: 7/9 PASS (lClean 83 s, lKEM 172 s, lSig 292 s, lFS 39 s, lFSDH 30 s, lFSEph 47 s, lQKey 50 s), lDH and lBoth killed at 1800 s (`proverif-link-local.txt`) — superseded by the next row |
| ProVerif `link` gate (WEISUNG M5-B-2) | models `5d7d45b` | `step --strict proverif --models link --jobs 1` PASS, 9/9 files, every RESULT line as expected, 1072 s: lBoth 655.2 s, lClean 38.7 s, lDH 59.0 s, lFS 15.7 s, lFSDH 16.3 s, lFSEph 23.5 s, lKEM 95.5 s, lQKey 24.8 s, lSig 138.9 s; one process at a time; load average 41–72 (system processes, §5B); the seven untouched files: expanded processes byte-identical and RESULT `diff` empty against the first run (`proverif-link-local-2.txt`) |
| `nextest -p xtask` | tree = `6483344` | 162 / 162 PASS (PV-01 `proverif_link_matches_claims`, X-04, X-05 included) |
| `ci-fast --strict` (WEISUNG M5-B-2) | tree = `6483344` | PASS: fmt, clippy, policy, deny, vet, audit, cooldown, nextest (111 s; workspace 712, xtask 162, relay 155, …), doctest, hello, kat (449 s) (`M05-evidence/ci-fast-local-6483344.txt`) |
| `step --strict kani` (R-104, before the closing push) | `6483344` | PASS, 33/33 harnesses (secmp-proto, secmp-relay; = `expect::KANI_HARNESSES`), 33 `VERIFICATION:- SUCCESSFUL`, 0 failed, 2370 s, load average 36–75 (`M05-evidence/kani-xtask-step-6483344.txt`) |
| ProVerif `tr` (T14) | `85f4c01` | `step --strict proverif --models tr` PASS, 47 RESULT lines as expected (T14 true ×1), 129.6 s on the idle machine (1307.7 s under load earlier); `proverif-tr-gate-local-85f4c01.txt` |
| ct `SECMP_CT_SCALE=10` | `6665c78` + bench | run PASS, six new targets PASS (evidence only) |
| vectors / step 12a | tree on `6665c78` | 12 suites identical; 12a PASS, 962 cases |
| PR run 37817187858 (BRIEF M5-B-3 findings, checked against the logs) | `7742e38` | windows-native FAIL (nextest 710/712, kat: `cli_config_errors_refuse_the_start`, `relay_trace_allow_equals_the_event_names`); linux-full FAIL only in step 7 (`secmp-relay` 1235/2098 = 58.9 %, min 80 %), 221 of 240 min; mutants FAIL (5 undocumented: 2 missed, 3 timeout); the rest green (`M05-evidence/m5b3-run-37817187858-red.txt`) |
| `step --strict coverage`, before | `7742e38` | FAIL, `secmp-relay` 1235/2098 = 58.9 % (= CI), 86 s; `conn.rs`, `exec.rs`, `executor.rs`, `linkdata.rs`, `relay.rs` 0 % (`M05-evidence/coverage-local-m5b3.txt`) |
| `step --strict coverage`, after | `dc34d93` | PASS, `secmp-relay` 2161/2218 = 97.4 % (min 80 %), 92 s, 828 tests (712 before); `secmp-crypto` 2523/2539 and `secmp-testkit` 172/172 unchanged, `secmp-proto` 6548/6706 = 97.6 % (6526/6705 before); 54 uncovered relay lines listed (20 in `server.rs`: the `std::net` shims and `bind`) |
| Mutants pre-check, the five survivors (gate command line + `--file`/`--re`) | `109b280` code | 9 mutants in 5 min: 8 caught, 1 unviable (`relay.rs:166` `&&`→`\|\|`); `into_boxed` ×2 caught (1–2 s test), `start_drain`→`()`, `draining`→`true`, `drain_finished`→`false` caught in 49–56 s (were TIMEOUT 1733 s); also `draining`→`false`, `drain_finished`→`true`, `>=`→`<` caught (`M05-evidence/mutants-m5b3-local.txt`) |
| `ci-fast --strict` | `dc34d93` | PASS: fmt, clippy, policy, deny, vet, audit, cooldown, nextest (119 s), doctest, hello, kat (459 s) (`M05-evidence/ci-fast-local-dc34d93.txt`) |
| `nextest -p secmp-relay -p secmp-proto -p xtask` | `dc34d93` | 570 / 570 PASS; with `--features secmp-relay/kat` 686 / 686 PASS |
| `step --strict windows-cross` | `dc34d93` | PASS (`cargo xwin build --all-targets`, x86_64-pc-windows-msvc) |

### 5B. Deviations

- Interrupted by the Mac reboot at `6665c78` (step B1 pushed; B2–B4 uncommitted in the tree) and once more at ≈12:20 UTC (after
  `a8fb992`), resumed with WEISUNG M5-B-0; recovered files: 88 (all), reverted files: none.
- Commit 1 pushed alone (brief §2.1): run `37737873733` linux-fast, windows-native and linux-full FAIL (xwin-cross, ct, mutants, proverif-hx
  PASS) on `proverif_table_follows_the_claims` and
  `proverif_table_covers_every_claims_row` (CLAIMS T14 row before its model); closed by `33a55ea`
  (`M05-evidence/linux-fast-37737873733-claims-t14.txt`).
- No `tokio`/`tracing` (outside the vetted closure): sans-IO relay, `std::net` server, closed event set (ADR-049, accepted by the
  reviewer 2026-10-08); CLAUDE.md §4 "tracing with a redaction layer" met by a construction without a logging crate (`docs/06` §2
  line).
- RL-03 runs an H-03-equivalent relay scenario (1000 cells each way) through `Connection` (the Phase C harness does not exist); RL-02
  runs the scenario in a child process of the test binary with cwd/TMPDIR/HOME in an empty directory.
- The binary has no drain trigger (no signal handling without `unsafe` in `secmp-sys-*`; M10); drain is `Relay::start_drain` + `serve`.
- Readings in the relay (engineering): a `LINK_PUT` one of whose three frames finds the rate bucket empty is ERR 7; a stale `cmd_seq`
  takes precedence over the rate (ERR 6); the HELLO limit is per listener (OPEN-M5-02) where §9.7 item 7 says "per-connection"; the
  `HELLO`→`HS1` timeout fires at ≥ 30 s and bounds accept→`HELLO` too; an identical `QUEUE_NEW` while draining answers `OK_QUEUE_NEW`.
- R-59: the leak was inside the AEAD open (`chacha20poly1305` decrypts only on a matching tag); fixed with a separate constant-flow
  open for the TR header trial only (two XChaCha20-Poly1305 passes per candidate; isolated cost 10.5 µs vs 4.5/2.7 µs per 2314-B
  header; `step perf` PASS on an idle run, FAIL under load 3 of 4 runs, A/B under the same load shows no difference).
- CT-05 classes: "the last candidate" read as the last of the 2 distinct skipped header keys (both classes on the skipped path); CT-06
  mirrors the 4352-B frame target; LINK targets use a positive-twin pre-check (no LINK site tag exists).
- Kani K-06 and K-07 run fixed patterns with symbolic values (K-06: 3 SENDs / ack / SEND / ack; K-07: FETCH 5 and FETCH_MULTI 8 outcome
  shapes): the free search gave no verdict in 25–30 min; bounds documented in `kani_proofs.rs`.
- `relay_executor`, `relay_link_session` are in `FUZZ_TRACKED_ONLY` (command-script inputs; no vector layout); the six link/Q targets
  moved to vector seeding. Nightly fuzz: 14 400 / 29 = 496 s per target.
- PV-01 model readings (CLAIMS §LINK, for confirmation): L4 not split (LO-3), the premise adds `event(RAccept(…))`; L3/L5 "CAccept names
  R's fp" as a premise conjunct; L7 as `CAccept ⇒ RInfo(s, kid, fp, h(akc label, ak))`; L8 RExec with an honest queue key; RevealEph
  on one designated link; bounds two c2r / three r2c frames. Devices: `formal/link.pvl` header 7., 8. (not copied into CLAIMS).
- `PROVERIF_EXPECTED_LINK`: every row is now the RESULT text of a completed run (`proverif-link-local-2.txt`); the lDH and lBoth
  rows, written earlier from the `-- Query` text, matched the completed runs character for character (no table edit).
- The §5B readings above are confirmed by the reviewer (WEISUNG M5-B-2 item 5).
- **LO-5** (reviewer, 2026-10-08): in `lDH` and `lBoth` `dh_break` is removed; the session outputs in phase 0 `dhsk(s, kRdh)`
  (session process) and `dhsk(s, iC(e))`, `dhsk(s, iE(e1))`, `dhsk(s, iR(er))` right after their `new` (macros `CLinkR`,
  `CTailR`, `RConnR`; `iD(e)` exists only in lFSEph); the `dhsk` assumptions of both files and the lazy-DH `select` line are
  removed; justification in `formal/link.pvl` 4. and CLAIMS §LINK "Reviewer decisions". Applied as written.
- **LO-6** (reviewer, 2026-10-08): in `lBoth` `kem_break1024/768` are removed; `kemr(s, r1)` (CTailR) and `kemr(s, r2)` (RConnR)
  are output in phase 0; `not attacker(kemr(lBoth, x))` dropped in lBoth only; lKEM untouched. Reading: the variants' flag `rk`
  gates the two `kemr` outputs (`false` in lDH, `true` in lBoth), so each sits in a parallel branch right after its `new`
  (`new r1[]; ((if rk then out(c, kemr(s, r1))) | …)`) instead of a sequential output; the output is available from the same
  point and the rest of the process is not duplicated.
- **LO-7** (reviewer, 2026-10-08): fallback split of `lDH` — not needed (lDH 59.0 s); the CLAIMS file list and
  `PROVERIF_EXPECTED_LINK` are unchanged (nine files).
- The other seven session files and their expanded ProVerif processes are byte-identical before/after; the library gained only
  the reveal variants and comment text (`proverif-link-local-2.txt`).
- Machine not idle during the WEISUNG M5-B-2 gate (load average 41–72 sampled from 18:21 to 18:37 CEST, from system processes —
  Spotlight workers — outside this session; no cargo/Kani/mutants/other ProVerif process of the session ran); one ProVerif process
  at a time as instructed.
- **M5-B-3 windows-native** (`d349053`, test-only): `cli_config_errors_refuse_the_start` wrote the Windows temp path (`C:\…`) into
  `key_file = "…"`, which the configuration's TOML subset refuses (`config.rs:123`, "strings take no quotes or escapes"); the test
  writes the path with `/`. `relay_trace_allow_equals_the_event_names` applied `\n`-anchored edits to the CRLF checkout of `event.rs`
  (no edit → 0 findings, expected 1); it reads the file through `lf` (M4 review R-100). No product change.
- **M5-B-3 coverage** (`dc34d93`, gate scope): the relay's `relay` suite is `required-features = ["kat"]` and no workspace crate turns
  on `secmp-relay/kat` by unification, so the coverage run built none of it (`conn`, `exec`, `executor`, `linkdata`, `relay` at 0 %);
  `coverage_args` adds `--features secmp-relay/kat` (`gates::COVERAGE_FEATURES`). Thresholds, ignore regex and the exclusion
  mechanism unchanged; `main.rs` is covered by the `cli` child processes (80/88 → 81/88 with `rotate-static --valid-days x`), no
  exclusion used. Recorded as an ADR-042 consequence line, proposed (engineering class), §8B. A variant with `kat` of every
  `expect::KAT_PACKAGES` crate was measured and dropped: it adds `secmp-testkit`'s differential suites (151–289 s each) and no
  relay line.
- **M5-B-3 mutants** (`109b280`, test-only): `cell_parts` checks the content of `Cell::into_boxed`; the `server_loop` listener fails
  after `ACCEPT_CALLS_MAX` = 100 accept calls (a passing test makes ≈ 10), so a drain that never starts or never finishes ends
  `serve` with `Error::Io` and fails the `Ok(())` assertion instead of hanging; it waits for the connection's close once (taken
  `Receiver`). No entry in `docs/mutants-accepted.md`.

### 6B. Dependencies added or bumped

None (no new crate in `Cargo.lock` or `fuzz/Cargo.lock`; `secmp-relay` gains workspace crates and the dev-dependencies `serde_json`,
`rand`; ADR-049 accepted).

### 7B. Open risks and known limitations

- Mutation shards now include 446 relay mutants (local per-mutant test run ≈ 40–70 s; Q-42's 1000 iterations dominate); shard times on CI: closing message.
- `tr.pv` grew to 47 lines (129.6 s idle); `linux-full` runs it.
- `lBoth` takes 655.2 s of its 1800 s cap here under load ≈ 50 (margin ≈ 2.7×); its log is 1.4 GB (attack traces with large
  terms); the `proverif-link` job's runner time comes with the CI run.
- Kani bounds of K-06/K-07 (§5B); `server` is thread-per-connection (M10 load test).
- `linux-full` budget (run 37817187858): 221 of 240 min (`timeout-minutes: 240`, `ci.yml:155`); step times nextest 350 s, kat
  1580 s, perf 24 s, fuzz 3579 s, coverage 334 s, miri 2898 s, kani 4190 s, proverif 201 s, sbom 30 s. M5-B-3 adds test time in step
  7 only: the relay suite (116 tests, 150 s of summed test time, longest 38 s) — locally 86 s → 92 s; the CI step time comes with
  the new run. Pins: fuzz has `expect::FUZZ_SMOKE_SECONDS` = 120 per target (29 targets = 3480 s); Kani has no time pin in
  `expect.rs` (33 harnesses). No change.

### 8B. Blocked / questions for the reviewer or owner

- M5-B-3: the coverage gate's feature scope (`--features secmp-relay/kat`) is a measurement-scope change of a gate — ADR-042
  consequence line in `docs/08` marked proposed (engineering class), for the reviewer's acceptance. Blocked: none.

- **STOP closed (WEISUNG M5-B-2, LO-5…LO-7):** with the breaks as reveals `lDH` completes in 59.0 s and `lBoth` in 655.2 s; every
  RESULT line as expected (L1a true, L3a true ×2, L4 true ×2, L8 false ×3; L1c false, L3c false ×2, L8 false ×3), no "cannot be
  proved", no split, no RESULT line of an untouched file changed. Open questions: none. The original STOP, for the record:
- ~~STOP (BRIEF_M5-B §3, "a ProVerif file over 30 min"): PV-01.~~ `formal/link/lDH.pv` does not finish its L1a declaration within
  1800 s (first declaration complete: L3a true ×2, L8 false ×3), `formal/link/lBoth.pv` not its first declaration; tried: a DH `select`
  line (kept), the HX lazy-DH `nounif` (rejected: two L8 lines "cannot be proved"), selecting the DH shared secrets / derived link keys /
  HKDF extract last, the lClean `nounif` set, `redundancyElim = no`, `nounifIgnoreNtimes`, `selFun = Term`, re-indexing R's names
  (`target/tmp/pvlink-status.md`, `M05-evidence/proverif-link-local.txt`). No query gave the opposite verdict; no true query came out
  "cannot be proved" in a completed run. Consequence: `proverif_link_matches_claims` fails (linux-fast, windows-native, linux-full
  nextest) and the `proverif-link` job will fail on the two timeouts. Question: which search devices or file layout for lDH and lBoth.
- ~~The PV-01 readings and devices of §5B for confirmation; ADR-049 (proposed) for acceptance.~~ Confirmed / accepted (WEISUNG
  M5-B-2 item 5).

## 9. Checklist before requesting review

Not yet applicable (Phase A of three).
