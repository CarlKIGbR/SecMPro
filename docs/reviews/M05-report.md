# Milestone report — M5 SecMP-LINK + SecMP-Q + relay core + in-process harness

Branch: `m05-link` · Base: `a229dbfc9dfe57dd0957359044389eb3b6654b32` · Author: Claude Code · Date: 2026-10-07
Phase A: `modell=claude-sonnet-5-5` (sub-agents for test code: `claude-sonnet-5-5` ×5, `claude-opus-5-5` ×1 for the spec-text application)

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M05-planning/` (`BRIEF_M5.md`, `TEST-SPEC-M5.md`, `ADR-048-proposed.md`, `CLAIMS-LINK.md`,
`OPEN-M5-decided.md`). ADR-048 and the owner-class items (o), (p) were ratified by default on 2026-10-04 20:45 UTC (brief
§11 (1)); optional (q) is not adopted (reading A). The [SQ-n], [O-1], [O-2], [O-6] rows are therefore in scope from the start.

Phases and handover: A (Sonnet) → B (Opus) → C (Sonnet). Handover row: "Phase A closed @ `<sha>`" (set when the PR run is green).

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
| B | B | relay crate, link-A vector groups (V-06…V-16, V-20, V-22), Q-*, RL-*, G-01, G-02, ct, K-05…K-07, FZ-07, FZ-08, formal, xtask | see brief §5 | not started |
| C | C | transport, harness, hx re-freeze rows | see brief §5 | not started |

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

## 9. Checklist before requesting review

Not yet applicable (Phase A of three).
