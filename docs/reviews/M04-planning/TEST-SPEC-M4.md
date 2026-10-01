# TEST-MATRIX-M4 — `secmp-proto::inv` and `secmp-proto::hx` (v2: planning cell draft of 2026-10-01 with the reviewer's decisions of 2026-10-01 applied)

For the reviewer to dictate to the implementer. Sources: `docs/03-protocol-spec.md` rev 2.3 (`docs/03:line`),
`docs/07-milestones.md` §M4 (`docs/07:84-95`), `ref/secmp_ref/hx.py`, `inv.py`, `SPEC-QUESTIONS.md` (REF-M4
readings 1–15 confirmed, SQ-25 reading A, Weisung REF-M4-1), `docs/reviews/M03-review.md` (carry-overs),
`crates/secmp-testkit/benches/ct.rs` (existing ct targets).
**Fill-in from SCHEMA-4.10:** `vectors/SCHEMA-4.10-hx.md` was **not** among the inputs: the vector case table below is reconstructed only as far as SPEC-QUESTIONS.md names cases.

## Conventions (apply to every row)

- **Uniform error.** Every rejection of untrusted input returns the single `Reject` (one variant, no payload; the
  reject site is observable only through the `kat` diagnostic tag, M3 F19). Each negative test asserts
  `Err(Reject)` and, via the aggregate row N-60, that all reject sites produce an identical error value.
- **"…_and_keeps_opk"** (responder): after the call the prekey store (SPK, RPK, every OPK: ids and bytes), the
  invitation record and the contact list have the same digest as before; no `RatchetState`, `peer_iks`, routes or
  profile is returned; the tracing capture holds no identifying field (§6.6 step 3 `docs/03:348` "discard
  everything, keep the OPK, log nothing identifying"); no RNG draw before §6.6 step 3 (draws of the step-3
  DHRatchet working copy are allowed and discarded, ref reading 11).
- **"…_and_sends_nothing"** (invitee): no `Start`, no cells, nothing persisted, no RNG draw after the reject site.
  There is no OPK on the invitee side: the docs/07 negatives "wrong fingerprint", "expired bundle", "bad signature"
  and "missing OPK" are invitee checks (§5.5), not `accept` checks.
- **Vector column**: the `vectors/hx.json` case where SPEC-QUESTIONS.md names it; "SCHEMA-4.10" where a case
  probably exists but its id is not in the inputs; "test" = Rust-only test from the spec.
- **API (reviewer decision O-12, 2026-10-01).** The API follows §6.4–§6.6 (`docs/03:313-320`, `:328`, `:346`), not the
  `docs/07:88` sketch:
  ```
  Initiator::start(invitation: &InvitationV1, link_data: &LinkDataV1 /* verified per §5.5 */, own_iks: &IdentityKeys, reply_routes, profile, entropy) -> Result<(HandshakeCells /* 3 */, RatchetState), Error>
  Responder::accept(cells, record: &InvitationRecord, store: &mut impl PrekeyStore, own_iks: &IdentityKeys, entropy) -> Result<(RatchetState, IKSPublic /* peer */, Routes, Profile), Error>
  ```
  The `docs/07` §M4 deliverable line is amended in the M4 plan commit to these signatures.
- **IDs.** The N-n of the draft keep their numbers; rows added in v2 take N-66 onward and sit in their matching
  section; N-58 is withdrawn (ADR-044 (d)) and its number is not reused.

## (a) Positive vector tests — `vectors/hx.json` (frozen)

Facts (SPEC-QUESTIONS.md state "Weisung REF-M4-1"): `"schema": 5`; **30 cases = 8 positive + 9 `invitee-reject`
(V1–V9) + 13 `respond-reject` (R1–R13)**; SHA-256 `a33cf162e36969dc4bd70114a7c1b0ae3a97e09a187cd210c47dc374f436e7d2`;
`hx-0001`…`hx-0028` byte-identical to the REF-M4 file; `hx-0029` = V9 `ld-bad-sig-ed`; `hx-0030` = R13
`first-msg-not-handshake`. The positive run is "restructured" (reading confirmation) and the responder cases run
"R after cases 1–4" with "case 6's cells"; **Fill-in from SCHEMA-4.10:** the exact list of the 8 positives (not provided).

Vectors are unchanged by the reviewer's decisions of 2026-10-01. The retained-SPK positive has no vector; SQ-28 (for the
ref): add a retained-SPK positive case at the next vector freeze.

Test `hx_vectors` (one assertion message per case id) compares, byte for byte, every output the ref emits:

| op (ref function) | Fields compared |
|---|---|
| bundle sign (`hx.sign_bundle`) | signed message (4434 B = bundle fields before `sig` ‖ signer's `ik_dh`, reading 2), `sig` (3373 B); hedge `rnd` 32 drawn first |
| invitee (`inv.invitee_accept`) | `uri` (exact ASCII), decoded InvitationV1, opened and decoded LinkDataV1, `K_ld`, `K_inv` |
| start (`hx.start`) | `EK_I` (pk), DH1, DH2, DH3, DH4, `ct_spk`, `ss_spk`, `ct_opk`, `ss_opk`, `transcript`, `SK`, `K_id`, `K_inv`, TR initiator state digest (StateDigestV1, SCHEMA §4.9) |
| envelope (`hx.envelope`) | `first_msg` (4096), Inner (6113), `inner_ct` (6185), Outer unpadded (9362), `init_id`, `cells[0..3]` (4096 each) |
| respond (`hx.respond`) | `init_id`, `transcript`, `SK`, `K_id`, `peer_iks` (2017), Handshake Content unpadded (Profile, caps, routes), `routes`, `profile`, TR responder state digest, `opks_post` |
| `invitee-reject` | `expect = reject` (no outputs) |
| `respond-reject` | `expect = reject`, `opks_post` (e.g. `[42]`: the OPK is kept) |

Cross-side equalities asserted in the same test: I.SK = R.SK; I.transcript = R.transcript = I.sb = R.sb; I.K_id =
R.K_id (Appendix C `docs/03:784` "both sides derive identical `SK`, `transcript`, `K_id`").
RNG order the `kat` RNG must reproduce (`hx.py:21-27`): sign_bundle `rnd` 32 · start `EK_I` 32, Encaps m (SPK) 32,
Encaps m (OPK) 32, TR init `dh_s` 32, `kem_s` seed 64, m 32 · envelope `hdr_nonce` 24, N2 24, `init_id` 16, N_0 24,
N_1 24, N_2 24 · respond DHRatchet `dh_s` 32, `kem_s` seed 64, m 32.
Case ids named in SPEC-QUESTIONS.md: V1 `expires` = now − 1; V5 bad bundle signature (manipulation per
SCHEMA-4.10); V6 `spk_expiry` = now − 1; V7 `opk_present` = 0, signed; V8 `K_ld` from `link_key` with bit 0
flipped; V9 (`hx-0029`) Ed25519 R bit 0 flipped (ML-DSA half verifies); R1 `spk_id` mismatch; R2 `opk_id`
mismatch; R3 OPK already used; R4 `ek_I` = 0 (Outer decoder); R6, R11, R12 "no complete group"; R8 first_msg body
MAC fails after DHRatchet; R9 Content decoder fails; R13 (`hx-0030`) first_msg Content is a Batch. **Fill-in from SCHEMA-4.10:** V2–V4, R5, R7,
R10.

Rust-only positive tests (no vector):

| Test | Spec | What |
|---|---|---|
| `hx_roundtrip_os_rng` | §6.4–§6.6 | fresh randomness; both sides equal as above |
| `accept_garbage_interleaved_succeeds` | §6.5 `docs/03:340` | random cells before, between and after the three chunks; also a complete foreign group of an invitation holder placed **after** the honest group ⇒ honest group accepted |
| `initiator_retry_resends_identical_cells` | §6.5 `docs/03:340` | the persisted cells are re-sent byte-identical; no re-seal, no RNG draw |
| `group_rejected_then_other_init_id_accepts` | §6.6 `docs/03:348`; ADR-044 (c) | a rejected complete group is discarded and the OPK kept; a later group with another init_id (the honest one) is processed ⇒ Ok |
| `accept_with_retained_previous_spk_succeeds` | §6.1 `docs/03:271` | the prekey store keeps SPK generations keyed by spk_id; invitation referencing a rotated-but-retained, unexpired SPK ⇒ Ok (no vector: the ref holds one SPK, `hx.py:362`; SQ-28) |
| `inv_uri_roundtrip`, `inv_qr_text_equals_uri` | §5.2 `docs/03:209` | URI = `secmp://i/` + base64url without padding; QR text is the same string |
| `inv_blob_len_and_keys` | §5.4 `docs/03:243-245` | blob = 12360 B; `K_ld`, `K_inv` equal an independent HKDF computation |

## (b) Negative tests

### INV — invitee (§5.5 `docs/03:250-257`); assertion: `_and_sends_nothing`

| # | Test | Spec | Input mutation | Expected | Vector |
|---|---|---|---|---|---|
| N-1 | `invitee_uri_wrong_prefix_rejects` | §5.2 `:209`; reading 4 | `secmp://I/…`, `secmp:/i/…`, leading space | Reject | test |
| N-2 | `invitee_uri_noncanonical_base64_rejects` | reading 4 | `=` padding; `+`/`/`; length ≡ 1 (mod 4); non-zero unused low bits | Reject | test |
| N-3 | `invitee_invitation_wrong_ver_rejects` | §5.5 `:252`, §4.1 `:150` | `ver` 0x02 | Reject | encodings + test |
| N-4 | `invitee_invitation_kind_not_one_time_rejects` | §5.2 `:197` | `kind` 0x02 (reserved), 0x00, 0x03 | Reject | encodings + test |
| N-5 | `invitee_invitation_bad_period_rejects` | §5.2 `:204` | `inv_period_s` ∉ PERIODS | Reject | encodings |
| N-6 | `invitee_expired_invitation_rejects` | §5.5 `:252`; reading 3 | `now` = `expires` (boundary) and `now` = `expires` + 1; control `now` = `expires` − 1 accepts | Reject | V1 (now − 1); boundary test |
| N-7 | `invitee_blob_wrong_link_key_rejects` | §5.4 `:243` | `K_ld` from `link_key` with bit 0 flipped | Reject | V8 |
| N-8 | `invitee_blob_wrong_ld_id_ad_rejects` | §5.4 `:244` | blob sealed with AD `"SecMP-INV/1 blob"` ‖ other `ld_id` | Reject | test |
| N-9 | `invitee_blob_tampered_rejects` | §3.4 `:126` | flip COM byte 0 / 31, a ct byte, the tag; length 12359 and 12361 | Reject | test |
| N-10 | `invitee_linkdata_bad_padding_rejects` | §4.1 `:149` | correctly sealed, padding without 0x80 or with a non-zero byte after it | Reject | test |
| N-11 | `invitee_wrong_fingerprint_rejects_and_sends_nothing` | §5.5 `:254` | `inviter_fp` ≠ fingerprint(`inviter_iks`), flipped in byte 0 and byte 31 | Reject | SCHEMA-4.10 (docs/07 "wrong fingerprint") |
| N-12 | `invitee_substituted_inviter_iks_rejects` | §5.5 `:254`, §6.6 `:352` | link data with another valid IKS and a bundle validly signed by it; invitation keeps the original `inviter_fp` | Reject | test |
| N-13 | `invitee_bundle_bad_sig_ed25519_rejects` | §3.5 `:137`, §5.5 `:255` | Ed25519 R bit 0 flipped | Reject | V9 `hx-0029` |
| N-14 | `invitee_bundle_bad_sig_mldsa_rejects` | §3.5 `:137` | a byte of the ML-DSA half flipped | Reject | V5? (SCHEMA-4.10) |
| N-15 | `invitee_bundle_field_tampered_rejects` | §6.3 `:296` | after signing flip a bit of `spk_kem`, `rpk_kem`, `opk_dh`, `spk_expiry`, `opk_id` (re-sealed blob) | Reject | test |
| N-16 | `invitee_bundle_signed_over_other_ik_dh_rejects` | §6.3 `:296` "‖ ik_dh" | signature over the fields ‖ a different `ik_dh` | Reject | test |
| N-17 | `invitee_bundle_wrong_label_rejects` | §3.5 `:140` | signed with `"SecMP-TR/1 keychange"` | Reject | test |
| N-18 | `invitee_bundle_expired_rejects` | §5.5 `:255`; reading 3 | `spk_expiry` = now − 1 and = now (boundary rejects); control now + 1 accepts | Reject | V6 (now − 1); boundary test (docs/07 "expired bundle") |
| N-19 | `invitee_bundle_without_opk_rejects` | §6.3 `:292`, §5.5 `:255` | `opk_present` = 0, validly signed | Reject (decoder) | V7 (docs/07 "missing OPK") |
| N-20 | `invitee_low_order_x25519_rejects` | §4.1 (a) `:152`, §6.4 `:311` | `spk_dh`, `opk_dh`, `ik_dh` ∈ {0, 1, p − 1, both order-8 u} and the encodings u + p | Reject (decoder) | encodings + test (docs/07 "zero DH") |
| N-21 | `invitee_kem_modulus_rejects` | §4.1 (c) `:152` | `spk_kem`, `rpk_kem`, `opk_kem` failing the FIPS 203 modulus check | Reject | encodings + test |
| N-22 | `invitee_bad_ed25519_identity_rejects` | §4.1 (b) `:152` | `ik_ed25519` small-order / y ≥ p | Reject | encodings + test |
| N-23 | `invitee_does_not_check_inviter_bounds` | SQ-25 (A) | `expires` > `created` + 30 d; `spk_expiry` < `expires` (but > now) | **accepted** (pins reading A) | test |

### HX — initiator (§6.4–§6.5)

| # | Test | Spec | Input mutation | Expected | Vector |
|---|---|---|---|---|---|
| N-24 | `start_zero_dh_rejects_and_sends_nothing` | §6.4 `:311`, §3 `:69` | the DH-with-check helper called (internal/`kat`) with each low-order peer value, bypassing the decoder | Reject | test (reading 7: "needs no vector") |
| N-25 | `inviter_create_enforces_own_bounds` | §5.2 `:205`, §6.3 `:291` | inviter asked for `expires` > creation + 30 d, or a bundle whose `spk_expiry` < `expires` | local error (not `Reject`), nothing issued | test |

### HX — responder grouping (§6.5 `docs/03:340`); assertion: `_and_keeps_opk`

| # | Test | Spec | Input mutation | Expected | Vector |
|---|---|---|---|---|---|
| N-26 | `accept_two_of_three_chunks_rejects_and_keeps_opk` | §6.5 | cells 0 and 1 only (each pair) | Reject | R6/R11/R12 (one of) |
| N-27 | `accept_garbage_only_rejects_and_keeps_opk` | §6.5 | 3 and 12 random 4096-byte cells | Reject | test |
| N-28 | `accept_tampered_chunk_rejects_and_keeps_opk` | §3.4, §6.5 | one byte of cell i (i = 0, 1, 2) flipped in N, COM, ct, tag | flipped cell ignored ⇒ no complete group ⇒ Reject | SCHEMA-4.10 (docs/07 "tampered chunk") |
| N-29 | `accept_mixed_init_id_chunks_rejects_and_keeps_opk` | §6.5 | chunks 0, 1 of envelope A + chunk 2 of envelope B (same invitation) | Reject | test |
| N-30 | `accept_spliced_chunk_same_init_id_rejects_and_keeps_opk` | §6.5 | chunk 2 of B re-sealed under A's `init_id` | Reject (Outer/inner fails) | test |
| N-31 | `accept_bad_total_or_index_cell_ignored` | D.4 `:854`; readings 5, 11 | `total` ≠ 3, `i` = 3 (re-sealed) next to an honest group | ignored; honest group ⇒ Ok | test |
| N-32 | `accept_cell_of_other_invitation_ignored` | §6.5 `:335` AD ‖ ld_id | cell under another invitation's `K_inv`, or AD with another `ld_id` | ignored | test |
| N-33 | `group_duplicate_chunk_differing_first_seen_wins` | reading 5; ADR-044 (c) | a second (init_id, i) with differing bytes before / after the honest one | the later one is discarded (first-seen wins) | test |
| N-66 | `group_duplicate_chunk_identical_ignored` | ADR-044 (c) | a second (init_id, i) with identical bytes next to the honest group | ignored; honest group ⇒ Ok | test |
| N-67 | `group_partial_store_bound_8_evicts_oldest` | ADR-044 (c) | partial groups (cells 0 and 1) of 9 distinct init_ids, then the missing cell of the oldest | at most 8 partial groups stored, the oldest evicted; the evicted group does not complete ⇒ Reject | test |

### HX — responder §6.6 steps 1–3 (resealed under `K_inv` / `K_id` by the test); assertion: `_and_keeps_opk`

| # | Test | Spec | Input mutation | Expected | Vector |
|---|---|---|---|---|---|
| N-34 | `accept_outer_bad_padding_rejects_and_keeps_opk` | §4.1 `:149`, §6.5 `:333` | Padded without 0x80 / non-zero after it | Reject | test |
| N-35 | `accept_outer_wrong_ver_rejects_and_keeps_opk` | §4.1 `:150` | Outer `ver` 0x02 | Reject | test |
| N-36 | `accept_wrong_spk_id_rejects_and_keeps_opk` | §6.6 `:346` | `spk_id` ≠ recorded | Reject | R1 |
| N-37 | `accept_wrong_opk_id_rejects_and_keeps_opk` | §6.6 `:346` | `opk_id` of another live OPK; an unknown id | Reject; the other OPK untouched | R2 |
| N-38 | `accept_used_opk_rejects` | §6.6 `:346`, `:354` | envelope for an invitation whose OPK was consumed | Reject; store unchanged | R3 (docs/07 "used OPK") |
| N-39 | `accept_replayed_envelope_rejects_after_success` | §6.6 `:354` | after Ok, the same three cells (and the retransmitted copies) again | Reject; store unchanged; first session unaffected | test (docs/07 "replayed envelope") |
| N-40 | `accept_low_order_ek_i_rejects_and_keeps_opk` | §4.1 (a), §6.4 `:311` | `ek_I` ∈ low-order set incl. 0 | Reject (Outer decoder, before any DH) | R4 (`ek_I` = 0) (docs/07 "zero DH") |
| N-41 | `accept_zero_dh_rejects_and_keeps_opk` | §6.4 `:311` | DH1–DH4 helper with low-order input, decoder bypassed (internal) | Reject | test (reading 7) |
| N-42 | `accept_tampered_ek_i_rejects_and_keeps_opk` | §6.4 | another valid `ek_I` | `K_id` differs ⇒ inner open fails ⇒ Reject | test |
| N-43 | `accept_tampered_ct_spk_rejects_and_keeps_opk` | §3.2 `:100`, §6.6 `:347` | flip a byte of `ct_spk` | implicit-rejection `ss_spk` ⇒ `K_id` differs ⇒ Reject | test |
| N-44 | `accept_tampered_ct_opk_rejects_and_keeps_opk` | as N-43 | flip a byte of `ct_opk` | Reject | test |
| N-45 | `accept_inner_wrong_k_id_rejects_and_keeps_opk` | §6.5 `:331` | `inner_ct` under the `K_id` of another `link_key`, or AD ‖ other `ld_id` | Reject | test |
| N-46 | `accept_inner_tampered_rejects_and_keeps_opk` | §3.4 | flip COM, a ct byte, the tag of `inner_ct` | Reject | test |
| N-47 | `accept_inner_iks_low_order_ik_dh_rejects_and_keeps_opk` | §6.6 `:347` | `IKSPublic_I.ik_dh` low-order (re-sealed under the right `K_id`) | Reject | test |
| N-48 | `accept_inner_iks_bad_ed25519_rejects_and_keeps_opk` | §4.1 (b); reading 7 | `ik_ed25519` small-order; IKS `ver` 0x02 | Reject | test |
| N-49 | `accept_substituted_initiator_identity_rejects_and_keeps_opk` | §6.6 `:352` (I authenticated by DH1), CLAIMS H5 | another valid IKSPublic in Inner, re-sealed under the right `K_id`, `first_msg` unchanged | transcript and DH1 change ⇒ SK differs ⇒ first_msg fails ⇒ Reject | test |
| N-50 | `accept_first_msg_bad_header_rejects_and_keeps_opk` | §7.4 `:438-440` | header sealed under a key ≠ HK_A | Reject | test |
| N-51 | `accept_first_msg_bad_body_mac_rejects_and_keeps_opk` | §7.4 `:448`, §3.3 | body tag flipped | Reject | R8 |
| N-52 | `accept_first_msg_wrong_sb_rejects_and_keeps_opk` | §7.3 `:421-422` | first_msg encrypted with AD ‖ a different `sb` | Reject | test |
| N-53 | `accept_first_msg_content_undecodable_rejects_and_keeps_opk` | §7.6, §4.1 | bad Content padding / `ver` | Reject | R9 |
| N-54 | `accept_first_msg_not_handshake_rejects_and_keeps_opk` | §6.5 `:330` | Content type Batch; type Dummy | Reject | R13 `hx-0030` |
| N-55 | `accept_first_msg_caps_nonzero_rejects_and_keeps_opk` | §7.6 `:495` | `caps` = 1 | Reject | test |
| N-56 | `accept_first_msg_zero_routes_rejects_and_keeps_opk` | §7.6, D.5; SQ-17 | route count 0 | Reject | test |
| N-57 | `accept_reflected_own_iks_rejects_and_keeps_opk` | §6.6 `:347`; ADR-044 (f) | `IKSPublic_I` = `IKSPublic_R` (reflection) | Reject | test |
| N-68 | `accept_first_msg_n_nonzero_rejects_and_keeps_opk` | §6.5 `:330`; ADR-044 (e) | first_msg header n ≠ 0, everything else valid | Reject | test |
| N-69 | `accept_first_msg_pn_nonzero_rejects_and_keeps_opk` | §6.5 `:330`; ADR-044 (e) | first_msg header pn ≠ 0, everything else valid | Reject | test |
| N-70 | `accept_handshake_without_known_route_rejects_and_keeps_opk` | §6.5 `:330`, §9.8 `:640`; ADR-044 (e) | Handshake content with routes, none of a known kind (route count 0 is N-56) | Reject | test |
| N-71 | `accept_with_rotated_out_spk_rejects_and_keeps_opk` | §6.1 `:271`, §6.6 `:346` | `spk_id` of a generation that was rotated out and is no longer retained | Reject | test |

### HX — after success, prekey store, aggregate

| # | Test | Spec | Input / action | Expected | Vector |
|---|---|---|---|---|---|
| N-59 | `retransmitted_handshake_cells_after_success_are_tr_rejects` | §6.6 `:349`, §10.6 `:688-689` | after Ok, the three handshake cells arrive on the retiring invitation queue and go to TR decrypt | TR `Reject`; session state unchanged | test |
| N-60 | `accept_reject_is_uniform_and_transactional` | §6.6 `:348`, §1.1 goal 6 | every `accept` row N-26…N-57 and N-66…N-71 | identical error value; store digest unchanged; no identifying log field | aggregate |
| N-61 | `prekey_store_opk_consume_twice_fails` | §6.1 `:273` | consume the same OPK twice | second fails; no side effect | test |
| N-62 | `prekey_store_spk_rotates_weekly` | §6.1 `:271` | clock + 7 d | new SPK (and its RPK) current | test |
| N-63 | `prekey_store_retains_spk_while_referenced` | §6.1 `:271` | rotation while an unexpired invitation references the old SPK | old SPK and its RPK retained until that invitation expires, then deleted (and zeroized) | test |
| N-64 | `prekey_store_rpk_follows_its_spk` | §6.1 `:272` | rotation / expiry | RPK lifetime = its SPK's | test |
| N-65 | `prekey_store_one_opk_per_invitation` | §6.1 `:273` | issue two invitations | distinct OPKs; each invitation record names its own opk_id | test |
| N-72 | `expired_invitation_record_is_not_offered_to_accept` | §5.2 `:211`, §6.6 `:346-349`; ADR-044 (d) | store/record level: invitation record whose `expires` has passed (`accept` has no clock parameter) | the record is not offered to `accept`; its queue is retired | test |

docs/07 negatives checklist (`docs/07:90`): wrong fingerprint N-11/N-12 · expired bundle N-18 (V6) · bad signature
N-13–N-17 (V5, V9) · missing OPK N-19 (V7) · used OPK N-38 (R3) · zero DH N-20, N-24, N-40 (R4), N-41 · tampered
chunk N-28, N-30, N-34…N-46 · garbage cells interleaved `accept_garbage_interleaved_succeeds`, N-27, P3 · replayed
envelope N-39 (and H10).

## (c) Property tests (proptest; default seed + CI-run seed, as M3)

| # | Name | Randomised invariant |
|---|---|---|
| P1 | `prop_handshake_complementary_states` | random identities, prekeys, routes, profile ⇒ Ok; SK, transcript, K_id equal; the states are **complementary, not identical** (§7.2 `:394-408`, §7.4 DHRatchet): R.sb = I.sb = transcript; R.hk_r = I.hk_s = HK_A; R.ck_r = I.ck_s; R.n_r = I.n_s = 1; R.dh_r = I.dh_s.pk; R.kem_r = I.kem_s.ek; R.last_ct_r = I.ct_s; R.hk_s = I.nhk_r = NHK_B; R.nhk_r = I.nhk_s; then R → I and a second I → R message decrypt |
| P2 | `prop_opk_consumed_exactly_once` | random schedule of ≤ 12 cells per call over repeated `accept` calls, drawn from honest cells (duplicated, reordered), retransmissions, another envelope of the same invitation, resealed-tampered cells, random cells ⇒ at most one Ok per OPK; the store loses exactly {opk_id} iff Ok; Ok ⇔ an untampered complete honest group was delivered |
| P3 | `prop_garbage_never_changes_outcome_or_state` | inserting any number of random cells at any positions never changes the outcome or the returned state digest; with no honest group ⇒ Reject, store unchanged |
| P4 | `prop_cell_byte_flip_rejects_or_is_ignored` | any single-byte flip in any of the three cells ⇒ Reject, store unchanged |
| P5 | `prop_resealed_padded_flip_rejects` | with `K_inv`: any single-byte flip in Padded[0..12018] (fields and padding) ⇒ Reject, store unchanged |
| P6 | `prop_reject_is_transactional` | for every Reject in P2–P5 the digest of prekey store + invitation records + contacts is unchanged |
| P7 | `prop_stored_routes_equal_sent_routes` | random RouteDescriptor lists (1..=255, incl. unknown kinds, at least one of a known kind: ADR-044 (e)) ⇒ R's stored routes and profile are byte-identical to the ones in I's first_msg |
| P8 | `prop_transcript_component_sensitivity` | changing any one of the 13 transcript components (§6.4 `:313-316`) changes the transcript and SK |
| P9 | `prop_k_id_input_set` | K_id changes with each of ld_id, link_key, DH3, ss_spk, DH4, ss_opk and does **not** change with IKSPublic_I / DH1 / DH2 (§6.4 `:320`, `:323`) |
| P10 | `prop_inv_hx_canonical` | decode(encode(x)) = x and encode(decode(b)) = b for InvitationV1, URI, LinkDataV1 (padded), Outer (padded), Inner, HandshakeCellPlaintext (§4.1 `:154`) |
| P11 | `prop_blob_flip_rejects` | any single-byte flip in the 12360-byte blob ⇒ invitee Reject |

## (d) Kani and fuzz targets

Fuzz (2 min each without findings, as M2/M3 acceptance; seeds = vector cases + structured fixtures — random cells
never open under `K_inv`, so a structured target is mandatory, M3 R-43):

| # | Target | Input → invariant |
|---|---|---|
| F1 | `inv_uri` | arbitrary str → `uri_decode` + InvitationV1 decode; no panic; Ok ⇒ re-encode = input |
| F2 | `inv_linkdata` | arbitrary 12288 B as the opened plaintext → LinkDataV1 decode; arbitrary blob → `invitee_accept` with a fixed invitation; no panic, Reject or Ok only |
| F3 | `hx_outer` | arbitrary 12018 B → Outer unpad + decode; total |
| F4 | `hx_inner` | arbitrary 6113 B → Inner (IKSPublic ‖ Cell) decode; total |
| F5 | `hx_cell_plaintext` | arbitrary 4024 B → HandshakeCellPlaintext decode; total |
| F6 | `hx_accept_raw` | arbitrary list (≤ 12) of 4096-byte cells, with the fixture's honest cells at fuzzer-chosen positions → `accept`; no panic; store changes iff Ok; Ok only with the complete untampered honest group |
| F7 | `hx_accept_structured` | fuzzer mutates Padded and/or Inner; the harness re-seals with the fixture's `K_inv` (and `K_id`) → reaches the step 1–3 rejects; invariants as F6 |

Kani:

| # | Harness | Property |
|---|---|---|
| K1 | `kani_hx_chunk_bounds` | for i < 3: i·4006 + 4006 ≤ 12018, no overflow; split/join of Padded is the identity on indices |
| K2 | `kani_outer_unpad_total` | ISO/IEC 7816-4 unpad of any 12018-byte buffer returns the 9362-byte Outer or Reject; never panics |
| K3 | `kani_hx_grouping` | over a bounded sequence of (init_id, i): ≤ 3 chunks per init_id, first-seen wins, completion iff {0,1,2} present, at most 8 partial groups stored, oldest evicted; stored state bounded by the input length (ADR-044 (c)) |
| K4 | `kani_accept_opk_delete_only_on_success` | crypto stubbed with nondeterministic per-step success: the OPK delete is reached iff every step succeeds; every Err path leaves the store untouched |
| K5 | `kani_cell_plaintext_decode_total` | HandshakeCellPlaintext decoder total, `total` = 3 and `i` ≤ 2 enforced |

## (e) Review-focus checks as assertions (`docs/07:95`)

| Focus | Assertions |
|---|---|
| Transcript completeness (§6.4 `:313-316`) | `transcript_matches_independent_concatenation` (test code computes SHA-256("SecMP-HX/1 transcript" ‖ encode(IKS_R) ‖ u32be(spk_id) ‖ SPK_dh ‖ H(SPK_kem) ‖ H(RPK_kem) ‖ u32be(opk_id) ‖ OPK_dh ‖ H(OPK_kem) ‖ encode(IKS_I) ‖ EK_I ‖ H(ct_spk) ‖ H(ct_opk) ‖ ld_id) without the implementation's helper; reading 1); `transcript_each_component_changes_sk` (13 mutations, P8); `transcript_iks_encoded_2017_bytes` |
| `K_id` inputs (§6.4 `:320`) | `k_id_matches_spec_hkdf` (salt ld_id; IKM link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk; info "SecMP-HX/1 idkey"; L 32); `k_id_derived_before_initiator_identity` (R opens inner_ct before parsing IKSPublic_I; P9); `k_inv_k_ld_k_id_distinct` (labels "initkey", "linkdata", "idkey") |
| OPK deleted only on success (§6.6 `:348-349`) | every responder negative asserts the store digest unchanged; `accept_success_deletes_exactly_that_opk` (store = before − {opk_id}; SPK, RPK, other OPKs, other records unchanged); a counting store mock: 1 delete on Ok, 0 on every Err; K4 |
| No signature by I (§6.6 `:352`) | `initiator_takes_no_signing_key` (the `Initiator::start` signature has no IK_sig secret parameter; type-level); `envelope_has_no_signature` (Inner is exactly IKSPublic ‖ Cell, 2017 + 4096; Outer exactly the §6.5 fields); `hybridsign_not_called_by_initiator` (counting hook on the HybridSign wrapper: 0 calls during start/envelope) |
| `first_msg` route = stored route (§6.5 `:342`, §6.6 `:349`) | `accept_stored_routes_equal_first_msg_routes` (byte-identical RouteDescriptors and Profile; no other source); P7 |
| Garbage ignored, not fatal (§6.5 `:340`) | `accept_garbage_interleaved_succeeds`; N-27; N-31/N-32 (ignored, not fatal); P3 |
| M3 carry-over F13 (R-27) | `initiator_cells_persisted_with_state`: the three cells and the post-first_msg RatchetState are durably persisted before any cell is handed out; retry re-sends the persisted bytes |
| FS of the returned state (CLAIMS H12) | `accept_state_holds_no_prekey_secret`: R's returned RatchetState holds neither the SPK_dh secret, the RPK seed nor the OPK (§7.2 `:406` starts R with SPK/RPK; DHRatchet replaces them) |
| EK_I discarded (CLAIMS H7c, H12; ADR-044 (b)) | `initiator_start_output_and_state_contain_no_ek_secret`: structural — the types returned by `Initiator::start` have no EK field; the serialised initiator state bytes do not contain the EK_I scalar; zeroize-on-drop check via the existing testkit pattern |
| Uniform error, no identifying log | N-60 |

## (f) Constant-time targets

Existing (`benches/ct.rs`): `control_variable_time_compare`, `tag_compare`, `msg_open_reject`, `caead_open_reject`,
`sas`, `caead_derive`, `caead_aead_reject`, `caead_com_compare`, `caead_open_reject_samekey`, `aa_prime_control`,
`tr_decrypt_reject_hdr_key`, `tr_decrypt_reject_body_tag`, `tr_decrypt_reject_ct_pq`. HX/INV adds these
secret-dependent comparisons:

| Target | Where | Classes |
|---|---|---|
| `inv_fingerprint_compare` | §5.5 step 3 `docs/03:254` (`inv.py:125` uses `ct_equal`): `inviter_fp` from the secret invitation vs the fingerprint of the K_ld-decrypted IKS | "fp differs in byte 0", "fp differs in byte 31" |
| `x25519_zero_check` | §3 `docs/03:69`, §6.4 `docs/03:311`: the all-zero test of a secret DH output (DH1–DH4, both sides) | "output non-zero in byte 0", "output non-zero only in byte 31" (if the secmp-crypto wrapper is already measured, cite that target instead) |
| `hx_accept_reject_inner` | §6.6 step 2: CAEAD.Open of inner_ct under K_id after the real DH/KEM work | "wrong K_id (COM fails)", "right K_id, tag fails" (confirms HX uses CAEAD unchanged) |
| `hx_accept_reject_first_msg` | §6.6 step 3: first_msg on R's step path from a fresh responder state (empty `skipped`) | as `tr_decrypt_reject_body_tag` ("body tag wrong in byte 0" / "in byte 31") |

Not targets (reason): spk_id/opk_id comparison and the OPK lookup (ids are in the bundle, not secret); transcript and
SK (never compared); bundle signature verification (public inputs). Recorded, not a target: the reject sites
differ in cost by design (K_inv open ≪ K_id open ≪ TR decrypt), so the reject step leaks through processing time,
the same class as M3 R-15 (conditionally accepted; ack timing).

## (g) Hygiene carried over from M3 that touches HX

F10 (R-23): Profile.name and routes from a decrypted Handshake in `Zeroizing` types. F11 (R-24): no derived
`PartialEq`/`Eq` on HX secret types outside tests. F12 (R-25): type-ascription test pinning zeroizing types for
`SK`, `K_id`, `K_inv`, `K_ld`, `EK_I`, `ss_spk`, `ss_opk`, OPK/SPK/RPK secrets and the persisted envelope.

## Changes against the draft (reviewer decisions of 2026-10-01)

| Draft | v2 | Decision |
|---|---|---|
| (a) `accept_retained_old_spk_accepts` | (a) `accept_with_retained_previous_spk_succeeds` | O-3 |
| — | N-71 `accept_with_rotated_out_spk_rejects_and_keeps_opk` | O-3 |
| (a) `accept_after_rejected_group_valid_group_succeeds` | (a) `group_rejected_then_other_init_id_accepts` | O-4, ADR-044 (c) |
| N-33 `accept_duplicate_chunk_first_seen_wins` | N-33 `group_duplicate_chunk_differing_first_seen_wins` | O-4, ADR-044 (c) |
| — | N-66 `group_duplicate_chunk_identical_ignored`, N-67 `group_partial_store_bound_8_evicts_oldest` | O-4, ADR-044 (c) |
| K3 (O-4) | K3: at most 8 partial groups, oldest evicted | O-4, ADR-044 (c) |
| N-57 `accept_reflected_identity` | N-57 `accept_reflected_own_iks_rejects_and_keeps_opk` | O-11, ADR-044 (f) |
| N-58 `accept_after_expiry` | withdrawn; N-72 `expired_invitation_record_is_not_offered_to_accept` | O-5, ADR-044 (d) |
| — | N-68, N-69, N-70 (first_msg n, pn; Handshake without a known route) | O-6, ADR-044 (e) |
| P7 | at least one route of a known kind per list | O-6, ADR-044 (e) |
| — | (e) `initiator_start_output_and_state_contain_no_ek_secret` | O-2, ADR-044 (b) |
| N-60 range N-26…N-58 | N-26…N-57 and N-66…N-71 | follows the rows above |
| Conventions: API note of the draft | the two signatures; ID rule | O-12 |
