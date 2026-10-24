# TEST-SPEC-M5 — SecMP-LINK, SecMP-Q, relay core, in-process harness (v2, 2026-10-03: reviewer decisions on OPEN-M5 and PRUEF-M5 applied)

For the implementer, dictated by the reviewer (attachment of BRIEF_M5, all phases). Sources:
`docs/03-protocol-spec.md` rev 2.5 as delivered (`docs/03:<line>` = line of that file), `docs/07-milestones.md` §M5 and
its F-M5 paragraph (`docs/07:101-113`), `docs/06` §2/§4/§8/§9, `docs/02` §3/§5, brief REF-M5 (readings OPEN-1…OPEN-13
and (a)–(g): binding), `vectors/SCHEMA-4.11-link.md` (86 cases, `vectors/link.json` sha256
`dd77bb7c96d298f9cc188d4eadbd950605ccca2a250169708cdc573a73264c77`, 2 818 910 B), `ref/SPEC-QUESTIONS.md` (SQ-26…SQ-28,
"Readings adopted without a question — REF-M5" items 1–13), `docs/reviews/M04-review.md` §C/§E (F-M5 rows),
`TEST-SPEC-M4.md` (form). Companion files: `ADR-048-draft.md`, `OPEN-M5-decided.md`, `CLAIMS-LINK-draft.md`.

## Counts

| Category | Rows | Phase A (Sonnet) | Phase B (Opus) | Phase C (Sonnet) |
|---|---|---|---|---|
| vector (one test per op group + file/generator checks) | 25 | 9 | 13 | 3 |
| unit (client, relay, frames, Q executor, relay obligations, transport, F-M5) | 148 | 49 | 86 | 13 |
| integration (harness) | 12 | 0 | 0 | 12 |
| property | 12 | 6 | 6 | 0 |
| Kani | 7 | 4 | 3 | 0 |
| fuzz | 9 | 7 | 2 | 0 |
| ct (5 targets + 1 control) | 6 | 0 | 6 | 0 |
| ProVerif obligation (PV-03: docs, no test) | 3 | 0 | 3 | 0 |
| xtask / gate | 8 | 0 | 8 | 0 |
| **total** | **230** | **75** | **127** | **28** |

Conditional rows, not counted: K-08 and P-13 (Phase A), dictated only if Phase A's first step finds that no M2 harness /
property covers them (notes under (d) and (e)). Withdrawn, numbers not reused: T-10 → H-11 (no network in unit tests,
`docs/06:93`), H-07 → H-12 (re-sending lost cells is the M6 outbox).

Marked rows: **[SQ-26]/[SQ-27]/[SQ-28]** = depends on the SQ part of ADR-048 (f)/(j) (proposed, owner default +24 h);
lands in the first commit after ratification; **[O-n]** = governed by OPEN-M5-n as decided in `OPEN-M5-decided.md`;
the owner-class ones ([O-1], [O-2], [O-6] = ADR-048 (q), (p), (o)) land after ratification like [SQ-n];
**[R5-n]** = pins REF-M5 reading n, confirmed by the reviewer (OPEN-M5-13); **[HX-RF]** = needs the re-frozen
`vectors/ref/hx.json` (R-66/R-90, WEISUNG_REF M5-2); **(opt)** = optional per the M4 review.
Labels without a hyphen (P1–P27, E1–E23, X1, I1–I8, H1, S1–S10, T1–T4, F1–F12) are SCHEMA-4.11 case labels, not row ids.

## Conventions (apply to every row)

- **Client uniform error.** Every LINK failure at the client (RelayInfo, HS2, frame, response decode) returns the
  single `link::Error::Rejected` (one variant, no payload; the site is observable only through the `kat` tag, M3 F19).
  The handshake state is consumed: no `Link`, no key, nothing emitted after the reject (reading OPEN-2).
- **Relay teardown ("…_tears_down").** The relay emits no further byte for that connection and closes it; its frame
  counters, its recorded `cmd_seq` (`last`), the store digest and the relay keys equal the values before the unit; no
  RNG draw after the reject site; for HS1: no HS2 draw before `mac1` verifies (OPEN-2).
- **Local errors** (`CounterOverflow`, `PayloadTooLong`, `NewLinkRequired`) are not `Rejected` and never reach the wire.
- **"store unchanged".** `QueueStore::digest_kat()` ‖ `LinkDataStore::digest_kat()` ‖ budget counters (kat-only
  accessors: every queue's rid, sid, recv_pk, send_pk, cell ids, cells, next_cell_id, buckets; every link-data entry,
  marker and bucket) are byte-equal before and after.
- **D.2 response shape** (`assert_d2_shape`): exact frame count, every frame 4352 B, opens under `k_r2c` at consecutive
  counters, plaintext 4336 B ISO/IEC 7816-4 padded (`docs/03:149`), `cmd_seq` echoed (`docs/03:827`), emitted right after
  the command's last request frame (`docs/03:839`, `:631`).

  | Request (op) | req frames · payload B | Response frames · payload B |
  |---|---|---|
  | QUEUE_NEW 0x01 | 1 · 165 | 1 · OK_QUEUE_NEW 37 / ERR 6 |
  | SKEY 0x02 | 1 · 5 | 1 · ERR 6 (code 6) |
  | SEND 0x03 | 1 · 4181 | 1 · OK_SEND 22 / ERR 6 |
  | FETCH 0x04 | 1 · 93 | `F` = 4 · CELLR 4126 each |
  | FETCH_MULTI 0x05 | 1 · 6 + 88·count (count 1..=32) | `F_M` = 8 · CELLR 4126 each |
  | QUEUE_DEL 0x06 | 1 · 85 | 1 · OK 5 / ERR 6 |
  | LINK_PUT 0x07 | 3 · 4314, 4106, 4106 | 1 · OK 5 / ERR 6, after frame 3 |
  | LINK_GET 0x08 | 1 · 86 | 3 · LINKR 4167, CONT 4106, CONT 4106 |
  | PING 0x09 | 1 · 5 | 1 · OK 5 |

  Exceptions (ADR-048 (f), (p)): a stale `cmd_seq` ⇒ exactly one ERR 6 frame for every command [SQ-26]; a request over
  the per-link rate ⇒ exactly one ERR 7 frame, not executed, `cmd_seq` recorded [O-2]; for LINK_PUT both come after its
  third frame. The largest payload a frame carries is 4335 B (`docs/03:163`).
- **Draws.** A counting `Entropy` (kat, from M4) asserts draw counts and order (SCHEMA §2; OPEN-1).
- **Low-order set** (X25519, `docs/03:152` (a)): u ∈ {0, 1, p − 1, the two order-8 u (`e0eb7a7c…b800` and its
  partner)}, plus u + p where u + p < 2^255 (u ∈ {0, 1}), each also with bit 255 set.
- **API sketch (proposal; the reviewer fixes it as in M4 O-12; names may change, test names may not):**
  `link::client::start(pinned_relay_fp, access_key: Option<&AccessKey>, now, entropy) -> (HelloRecord, AwaitRelayInfo)`;
  `AwaitRelayInfo::on_relayinfo(self, rec) -> Result<(Hs1Record, AwaitHs2), Rejected>`;
  `AwaitHs2::on_hs2(self, rec) -> Result<Link, Rejected>`; `link::relay::Responder::new(&RelayKeys)`,
  `on_hello(&mut self, rec) -> Result<RelayInfoRecord, Teardown>`, `on_hs1(self, rec, entropy) -> Result<(Hs2Record,
  Link), Teardown>`; `Link::seal(&mut self, payload) -> Result<[u8; 4352], LocalError>`, `Link::open(&mut self, unit)
  -> Result<Plaintext, Rejected>`; `secmp_relay::Executor::on_unit(&mut self, link, unit, now_bucket, entropy) ->
  Outcome { Respond(Vec<[u8; 4352]>), Pending, Teardown }`.
- **IDs.** V = vector, C = client handshake, RH = relay handshake, F = frames, Q = executor, RL = relay obligations and
  relay crate, T = client transport, G = F-M5 rows, H = harness, P = property, K = Kani, FZ = fuzz, CT = ct, PV = formal,
  X = xtask. "Ph" = phase.

## (a) Vector tests — `vectors/ref/link.json` (frozen after the Rust/ref match)

One test per op group; each row of the file is one assertion message (case id). Link-A cases are replayed in event
order from `link-0001` (state by `from`); a shared replay (`OnceLock`) may serve all group tests. Every link-A case
also asserts: client and relay counters agree, `link_post` equal, `store_post` equal (kat snapshot in the SCHEMA shape),
every frame 4352 B. Secret intermediates (`ss1`, `ck1`, `k_c2r`, …) are compared through `kat` accessors.

| # | Test | Cases | Fields compared byte-exactly | Ph |
|---|---|---|---|---|
| V-01 | `link_vectors_relay_keys` | 0001 | `relay_sig_pk`, `relay_fp`, `relay_dh_pk`, `relay_kem_ek` (1568), `akc`, `relayinfo` (1741), `rec_relayinfo` (1744) | A |
| V-02 | `link_vectors_relayinfo_accept` | 0002, 0059 | `rec_hello` = `0007015345434d5001`, `accept` = true (0059: `valid_until − now` = 5 184 000) | A |
| V-03 | `link_vectors_hs1` | 0003 | `e_c`, `ek_c` (1184), `pk_e1`, `ct_kem` (1568), `ss1`, `h0`, `ck1`, `mac1`, `hs1` (2853), `rec_hs1` (2856); draws `e_c_sk` 32, `ek_c_seed` 64, `sk_e1` 32, `m1` 32 in this order | A |
| V-04 | `link_vectors_hs2` | 0004 | `ss1`, `h0`, `ck1` (= 0003, asserted), `e_r`, `ct_c` (1088), `ss2`, `h1`, `ck2`, `mac2`, `hs2` (1153), `rec_hs2` (1156), `k_c2r`, `k_r2c`, `sess_id`, `link_post` {0,0,0}; draws `sk_er`, `m2` only after `mac1` | A |
| V-05 | `link_vectors_hs2_accept` | 0005 | `ss2`, `h1`, `ck2`, `k_c2r`, `k_r2c`, `sess_id` (= 0004, asserted), `link_post` | A |
| V-06 | `link_vectors_queue_new` | 0006, 0009, 0015, 0016, 0030–0034 | `req`, `req_frames`, `resp`, `resp_frames`, `rid`/`sid` (first QUEUE_NEW of a queue), `token`, `sig`, `link_post`, `store_post` | B |
| V-07 | `link_vectors_send` | 0007, 0010, 0011, 0017, 0018, 0021, 0035–0037 | as V-06; `sig` | B |
| V-08 | `link_vectors_ping` | 0008, 0023, 0050 | as V-06 (0050: two PINGs 172, 172 → OK, ERR 6) | B |
| V-09 | `link_vectors_fetch` | 0012–0014, 0022, 0038–0041 | as V-06; 0013's present-1 (`cell_id`, `cell`) = 0012's (asserted) | B |
| V-10 | `link_vectors_fetch_multi` | 0019, 0042 | as V-06; `sig_0`, `sig_1` in entry order | B |
| V-11 | `link_vectors_send_fill` | 0020 | `frames_sha256` over the 254 wire frames in event order, `resp_last` (OK_SEND {128,0,0}), `link_post` {141,157,141}, `store_post` | B |
| V-12 | `link_vectors_queue_del` | 0024, 0043 | as V-06 | B |
| V-13 | `link_vectors_link_put` | 0025, 0026, 0044, 0045 | as V-06; `req` sizes [4314, 4106, 4106], one response after frame 3 | B |
| V-14 | `link_vectors_link_get` | 0027–0029, 0046, 0047, 0049 | as V-06; `resp` sizes [4167, 4106, 4106] | B |
| V-15 | `link_vectors_skey` | 0048 | as V-06 (ERR 6) | B |
| V-16 | `link_vectors_indist` | 0051 | `resp_counts` [[1,1,1],[4,4,4],[8,8],[1,1,1,1],[1,1,1],[3,3,3,3,3,3],[1,1]], `frame_len` 4352; for every link-A case: response position right after the last request frame, every frame 4352 B, every plaintext 4336 B ISO-padded (`docs/03:610`) | B |
| V-17 | `link_vectors_relayinfo_reject` | 0052–0058 | client `Rejected`; nothing emitted; no state | A |
| V-18 | `link_vectors_hs1_reject` | 0060–0070 | relay teardown, no draw; 0070 (S10): new `rec_hs2`, `sess_id` `009c442d…` ≠ 0004's, then P6's request frame fails | A |
| V-19 | `link_vectors_hs2_reject` | 0071–0074 | client `Rejected` | A |
| V-20 | `link_vectors_frame_reject` | 0075–0086 | receiver rejects (C) / tears down (R); `link_post` {3,3,3}; store unchanged | B |
| V-21 | `link_vectors_file_shape` | file | sha256 `dd77bb7c…`, 2 818 910 B, `"schema": 6`, `"suite": "link"`, 86 ids contiguous, op and party counts as `ref-link-cases-index.txt` (R 23, C 17, CR 46) | A |
| V-22 | `link_generator_reproduces_ref_file` | file | the Rust generator writes `vectors/link.json`; it equals `vectors/ref/link.json` as xtask step 12a compares it | B |
| V-23 | `hx_vectors` (existing name, re-frozen file) [HX-RF][O-14] | all hx cases | as TEST-SPEC-M4 (a), against the re-frozen file (sha recorded at the freeze) | C |
| V-24 | `hx_vectors_rev25_cases` [HX-RF][O-14][O-15] | the R-66 cases | later group after a rejected group accepted; rejected `init_id` does not re-form; `n` ≠ 0; `pn` ≠ 0; reflection; Handshake without a known route; retained-SPK positive (RF-1, OPEN-M5-15) — reject rows: `expect` reject + `opks_post` | C |
| V-25 | `hx_generator_reproduces_ref_file` [HX-RF][O-14] | file | the Rust generator writes `vectors/hx.json`; it equals the re-frozen `vectors/ref/hx.json` as xtask step 12a compares it | C |

## (b) Unit tests

### b1 · Client handshake (§8.2–8.3, D.1) — assertion: `Rejected`, nothing emitted

| # | Test | Spec | Input / mutation | Expected | Ph |
|---|---|---|---|---|---|
| C-01 | `client_hello_record_bytes` | D.1 `:801`, `:798` | `client::start` | `00 07 01 53 45 43 4d 50 01` (9 B) | A |
| C-02 | `client_relayinfo_record_shape_rejects` | D.1 `:798`, `:802`; REF-M2 r.2 | `len` 1741, 1743; type 0x01, 0x03, 0x04; body ±1 byte | Rejected | A |
| C-03 | `client_relayinfo_ver_rejects` | D.1 `:805`, §4.1 `:150` | `ver` 0x00, 0x02 (I5), 0xFF, re-signed | Rejected | A |
| C-04 | `client_relayinfo_bad_sig_pk_rejects` | §4.1 (b) `:152` | `relay_sig_pk`: the 8 small-order encodings, y ≥ p, not on the curve | Rejected (decoder) | A |
| C-05 | `client_relayinfo_bad_sig_encoding_rejects` | §3.5 `:140`, §4.1 (b) | `sig` S := S + L; R small-order; R with y ≥ p | Rejected (decoder) | A |
| C-06 | `client_relayinfo_low_order_dh_rejects` | §4.1 (a) | `relay_dh_pk` := each low-order value, re-signed (I6 = one) | Rejected | A |
| C-07 | `client_relayinfo_kem_ek_modulus_rejects` | §4.1 (c) | `relay_kem_ek` bytes 0–2 := `ff ff ff`, re-signed | Rejected | A |
| C-08 | `client_relayinfo_signature_binds_every_field` | §8.2 `:536`, App. A `:760` | flip a byte of `kid`, `relay_dh_pk`, `relay_kem_ek`, `akc`, `valid_until` after signing; sig over the 1677 bytes without the label; with label `"SecMP-LINK/1 relay-fp"`; flip(`sig`, 32) (I1) | Rejected | A |
| C-09 | `client_relayinfo_fp_mismatch_rejects` | §8.2 `:532`, `:539` | pinned fp flipped (I2); a RelayInfo validly signed by another `relay_sig` key | Rejected | A |
| C-10 | `client_relayinfo_validity_boundaries` | §8.2 `:539`; OPEN-4 | `valid_until` = now; now − 1 (I3); now + 5 184 000 (I8); now + 5 184 001; now + 61 d (I7); u64::MAX | accept; reject; accept; reject; reject; reject (no overflow) | A |
| C-11 | `client_relayinfo_akc_with_access_key` | §8.2 `:539`, §5.3 `:222`, `:229` | holding key k: `akc` = SHA-256("SecMP-Q/1 akc" ‖ k); flip byte 0 and 31 (I4) | accept; Rejected | A |
| C-12 | `client_relayinfo_akc_without_access_key_not_checked` [O-1] | §8.2 `:539` "if it holds an access key"; ADR-048 (q) | no key; `akc` arbitrary | accept (if the owner adopts optional (q): reject unless `akc` = the pinned `RelayRef.akc`; the row is then re-dictated) | A |
| C-13 | `client_relayinfo_not_cached_across_links` | §8.2 `:539` | two handshakes; the second RELAYINFO carries kid 2 and new static keys | second HS1 has kid 2 and encapsulates to the new keys; no API takes a stored RelayInfo | A |
| C-14 | `client_unexpected_record_type_rejects` | D.1; OPEN-2 | awaiting RELAYINFO: HELLO, HS1, HS2 records; awaiting HS2: RELAYINFO, HS1 | Rejected | A |
| C-15 | `client_takes_no_long_term_secret` | §8.3 `:541`, `:560` (client anonymous) | type-level: `client::start` parameters; draw counter over one handshake | no DH/signing key parameter; draws exactly 32 + 64 + 32 + 32 B | A |
| C-16 | `client_hs1_matches_independent_derivation` | §8.3 `:546`, `:549-552`, §3.2 | test recomputes h0 (preimage 180 B: label 15 ‖ ver ‖ u32be kid ‖ relay_fp ‖ e_c ‖ H(ek_c) ‖ pk_e1 ‖ H(ct_kem)), ck1 = HKDF-Extract(h0, ss1), mac1 with secmp-crypto primitives | equal; HS1 offsets ver 0, kid 1, e_c 5, ek_c 37, pk_e1 1221, ct_kem 1253, mac1 2821, end 2853 | A |
| C-17 | `client_hs2_mac2_flip_rejects` | §8.3 `:556` | flip `mac2` bytes 0 (T1), 15, 31 | Rejected | A |
| C-18 | `client_hs2_tampered_field_rejects` | §8.3 `:554` | `e_r` := another valid point; `ct_c` flipped at 0 (T2) and 1087 | Rejected (h1/ss2 differ) | A |
| C-19 | `client_hs2_low_order_e_r_rejects` | §4.1 (a) | `e_r` := each low-order value (T3 = one) | Rejected (decoder) | A |
| C-20 | `client_hs2_record_shape_rejects` | D.1 `:804` | `len` 1153, 1155; type ≠ 0x04; `ver` 0x02 (T4) | Rejected | A |
| C-21 | `client_hs2_of_other_handshake_rejects` | §8.3 `:554` | honest HS2 of a second handshake (other `e_c`) | Rejected | A |
| C-22 | `client_rejection_leaves_no_link` | OPEN-2 | after each reject of C-02…C-21 | state consumed; no `Link`, no key material returned | A |

### b2 · Relay handshake (§8.2–8.3, D.1) — assertion: teardown, no draw

| # | Test | Spec | Input / mutation | Expected | Ph |
|---|---|---|---|---|---|
| RH-01 | `relay_hello_shape_tears_down` | D.1 `:801`; OPEN-2 | `len` ≠ 7; magic "RECMP" (H1), "SECMQ", "secmp"; `ver` 0x00, 0x02; type 0x02 | teardown, no RELAYINFO | A |
| RH-02 | `relay_answers_every_hello_with_current_relayinfo` | §8.2 `:539` | HELLO on three connections | each gets `rec_relayinfo` (1744 B) of the current kid, verifying under `relay_sig` | A |
| RH-03 | `relay_hs1_before_hello_tears_down` | D.1, §8.3 `:544` | HS1 as the first record | teardown | A |
| RH-04 | `relay_second_hello_tears_down` | §9.7 (7) `:632` | after RELAYINFO a HELLO instead of HS1 | teardown | A |
| RH-05 | `relay_hs1_record_shape_tears_down` | D.1 `:803` | `len` 2853 (S9), 2855; type ≠ 0x03; `ver` 0x02 (S8) | teardown | A |
| RH-06 | `relay_hs1_low_order_points_tear_down` | §4.1 (a) | `e_c`, `pk_e1` := each low-order value (S5, S6) | teardown | A |
| RH-07 | `relay_hs1_ek_c_modulus_tears_down` | §4.1 (c) | `ek_c` bytes 0–2 := `ff ff ff` (S7) | teardown | A |
| RH-08 | `relay_hs1_mac1_flip_tears_down_without_draw` | §8.3 `:552`; OPEN-2 | flip `mac1` bytes 0 (S1), 15, 31 | teardown; draw counter 0; nothing emitted | A |
| RH-09 | `relay_hs1_field_tamper_tears_down` | §8.3 `:549` | `e_c`, `ek_c`, `pk_e1` := other valid values; `ct_kem` flipped at 0 (S2) and 1567 | teardown (h0/ss1 differ, implicit rejection) | A |
| RH-10 | `relay_hs1_unknown_kid_tears_down` | §8.2 `:532`, `:560` | `kid` 0, 2 (S3), u32::MAX | teardown | A |
| RH-11 | `relay_hs1_wrong_static_key_tears_down` | §8.3 `:560` | honest HS1 to another static pair (S4) | teardown | A |
| RH-12 | `relay_hs1_replay_answers_new_handshake` | OPEN-3 | the same `rec_hs1` on a second connection (S10) | fresh HS2, `sess_id` differs; the first link's frame 0 fails on the new link | A |
| RH-13 | `relay_hs2_matches_independent_derivation` | §8.3 `:553-557` | test recomputes ss2, h1 (preimage 128 B), ck2 = HKDF-Extract(h1, ck1 ‖ ss2), mac2, HKDF-Expand(ck2, "SecMP-LINK/1 keys", 80) | equal; split 32/32/16; HS2 offsets ver 0, e_r 1, ct_c 33, mac2 1121, end 1153 | A |
| RH-14 | `relay_bytes_after_hs2_are_frames` | D.1 `:808` | after HS2 a 2856-byte HS1 record, then a 4352-byte unit of zeros | read as 4352-B units; open fails ⇒ teardown | A |
| RH-15 | `relay_handshake_rejection_keeps_no_state` | OPEN-2 | after each teardown of RH-01…RH-14 | relay keys unchanged; no store entry; no `Link` | A |

### b3 · Frames (§8.4)

| # | Test | Spec | Input / mutation | Expected | Ph |
|---|---|---|---|---|---|
| F-01 | `link_frame_seal_matches_independent_aead` | §8.4 `:567` | payloads 0, 5, 4314, 4335 B, both directions | equals XChaCha20-Poly1305.Seal(k_dir, 0^16 ‖ u64be(ctr), "SecMP-LINK/1 frame" ‖ sess_id, pad(p, 4336)) computed in the test | A |
| F-02 | `link_frame_unit_length_rejected_before_aead` | §8.4 `:570`, D.1 `:808` | units of 0, 1, 4335, 4351 (F4), 4353 (F5), 8704 B | Rejected; AEAD-open counter (kat) 0 | A |
| F-03 | `link_frame_counter_strict_plus_one` | §8.4 `:570` | c2r skip (F1), replay (F2); r2c skip (F8), replay | Rejected; the expected frame then opens | A |
| F-04 | `link_frame_flip_rejects` | §8.4 | flip ct byte 0, 4335; tag byte 0, 15; both directions (F3, F9) | Rejected | A |
| F-05 | `link_frame_direction_and_link_binding` | §8.3 `:557`, §8.4 | reflected frame both ways (F6); AD with flip(sess_id, 0) (F7); frame of another link, same counter | Rejected | A |
| F-06 | `link_frame_failed_open_changes_nothing` | OPEN-2 | after each failure of F-02…F-05 | counters unchanged; next honest frame opens | A |
| F-07 | `link_frame_padding_rules` | §4.1 `:149`; OPEN-6 | seal of 4335 B ok, 4336 B ⇒ `PayloadTooLong`; open: no 0x80 (F11), a non-zero byte after 0x80, all-zero plaintext | local error; Rejected | A |
| F-08 | `link_frame_counter_overflow_aborts` | §8.4 `:570`; [R5-9] | counter set (kat) to 2^64 − 1 | that frame seals/opens; the next is `CounterOverflow`, nothing sealed/opened | A |
| F-09 | `link_client_refuses_seal_beyond_link_max_frames` [O-3] | §4.2 `:179`, §8.4 `:570` | counter (kat) c2r at 2^20 − 1; r2c at 2^20 − 1 | c2r: that frame seals, the next seal is `NewLinkRequired`; r2c: that frame opens, the next seal is `NewLinkRequired` | A |
| F-10 | `link_client_response_decode_failure_rejects` | D.2 `:830-836`; REF-M2 r.6; OPEN-2 | r2c plaintext with op 0x01, 0x00, 0x85; bad padding | Rejected | A |
| F-11 | `relay_unknown_request_opcode_tears_down` | D.2 `:812-824`; OPEN-6 | ops 0x0A (F12), 0x00, 0x80, 0xFF; 0x7F with nothing pending (F10); control: 0x02 | teardown; 0x02 ⇒ one ERR 6 (E21) | B |
| F-12 | `link_client_response_value_rules_reject` | D.2 `:832-836`; REF-M2 r.5, r.9; OPEN-2 | OK_SEND `evicted_present` 0 with `evicted_id` ≠ 0; CELLR `present` 5; `present` 0 with `rid` or `cell_id` ≠ 0; FETCH `present` 1 with `rid` ≠ 0; `present` 2–4 with `cell_id` ≠ 0; LINKR `present` or `consumed` 2; response CONT `idx` 0, 3 | Rejected (client response decoder) | A |

### b4 · SecMP-Q executor (§9.1–9.6, D.2, D.6) — every row also asserts `assert_d2_shape`; error rows: store unchanged

| # | Test | Spec | Input / mutation | Expected | Ph |
|---|---|---|---|---|---|
| Q-01 | `q_queue_new_creates_queue_with_derived_ids` | §9.1 `:581-582` | QUEUE_NEW fresh keys (P6) | OK_QUEUE_NEW {rid, sid} = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16], SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]; queue empty, next_cell_id 1 | B |
| Q-02 | `q_queue_new_identical_is_idempotent` | §9.7 (8) `:633`; (c) | identical keys, fresh token and sig (P9) | OK_QUEUE_NEW, same ids; store unchanged | B |
| Q-03 | `q_queue_new_known_recv_pk_other_send_pk_is_auth` | §9.7 (8) | B's recv key + fresh send key (E6) | ERR 4 | B |
| Q-04 | `q_queue_new_token_binding` | §9.6 `:622`; (b) | flip(token, 0) (E3); token of cmd_seq 1 (E4); over flip(sess_id, 0) (E5); under another access key | ERR 1 each | B |
| Q-05 | `q_queue_new_bad_signature_is_auth` | D.2 `:815`, D.6; OPEN-9 | signed by the send key (E7), by an unrelated key, with label "SecMP-Q/1 SEND", over another cmd_seq, over flip(sess_id, 0) | ERR 4 each | B |
| Q-06 | `q_queue_new_budget_exceeded_is_full` | §9.7 (4) `:629`; OPEN-12 | third queue with the vector budget (E1) | ERR 2 | B |
| Q-07 | `q_queue_new_identical_at_budget_is_ok` [O-4] | §9.7 (4), (8) | identical QUEUE_NEW of an existing queue at the limit | OK_QUEUE_NEW | B |
| Q-08 | `q_send_cell_ids_from_one` | §9.1 `:587` | SENDs to a fresh queue (P7, P10, P11) | OK_SEND {1,0,0}, {2,0,0}, {3,0,0} | B |
| Q-09 | `q_send_unknown_sid_is_noqueue` | §9.3 `:600` | sid never created; sid deleted (E10) | ERR 3 | B |
| Q-10 | `q_send_bad_signature_is_auth` | §9.3 `:600`, D.6 | wrong signer (E8); over flip(sess_id, 0) (E9); over another cmd_seq; label "SecMP-Q/1 FETCH" | ERR 4 each | B |
| Q-11 | `q_send_at_capacity_evicts_oldest` | §9.5 `:618`; (e) | 128 cells, then 3 SENDs | {129,1,1}, {130,1,2}, {131,1,3}; queue = 4…131; `evicted_id` 0 iff `evicted_present` 0 | B |
| Q-12 | `q_send_accepted_when_budget_exhausted` [O-7] | §9.7 (4) | queue pool and link-data pool full (O-7 A) | SEND OK_SEND | B |
| Q-13 | `q_fetch_oldest_f_then_dummies` | §9.3 `:601`, `:608`; OPEN-7 | 3 cells, `ack` 0 (P12) | present-1 cells 1, 2, 3 ascending, rid 0, then 1 dummy {0, rid 0, cell_id 0} | B |
| Q-14 | `q_fetch_same_ack_is_idempotent` | §9.3 `:608` | repeat with the same `ack` (P13) | identical (cell_id, cell) pairs | B |
| Q-15 | `q_fetch_cumulative_ack` | §9.3 `:608` | `ack` 2 (P14); `ack` 0 deletes nothing | cells ≤ ack deleted before selection | B |
| Q-16 | `q_fetch_ack_bounds` | §9.1 `:589`; OPEN-7 | `ack` = next_cell_id − 1; = next_cell_id (E14); = u64::MAX | all deleted, `F` dummies; present 4, nothing deleted; present 4 | B |
| Q-17 | `q_fetch_unknown_rid_is_present_2` | §9.3 `:601` | deleted rid (E11) | frame 1 present 2 | B |
| Q-18 | `q_fetch_bad_signature_is_present_3` | §9.3 `:601`, D.6 | send-key signer (E12); flip(sess_id, 0) (E13); other cmd_seq; label MFETCH | present 3 | B |
| Q-19 | `q_fetch_error_frame_layout` | OPEN-7; D.2 `:833` | each error of Q-16…Q-18 | frame 1: rid = requested rid, cell_id 0, cell 4096 random; frames 2…4 present 0, rid 0, cell_id 0 | B |
| Q-20 | `q_fetch_after_recreate_old_ack_is_present_4` | §9.1 `:589` | queue deleted and re-created (same keys), FETCH with the old committed ack | present 4, nothing deleted | B |
| Q-21 | `q_fetch_multi_oldest_first_by_arrival` | §9.3 `:602`; OPEN-8 | entries [B ack 0, A ack 2], arrival A3 < B1 < A4 (P18) | {1,A,3}, {1,B,1}, {1,A,4}, 5 dummies; present-1 frames carry their rid | B |
| Q-22 | `q_fetch_multi_error_frames_first_in_request_order` | §9.3 `:602` | [A deleted, B] (E15); [B bad sig, A deleted, C ok] | error frames first in request order, then cells | B |
| Q-23 | `q_fetch_multi_per_entry_ack_semantics` | OPEN-8 | entry ack deletes before selection; entry ack ≥ next_cell_id | deleted; that entry present 4, others served | B |
| Q-24 | `q_fetch_multi_signature_label_is_mfetch` | D.2 `:819`, D.6 `:886`; REF-M2 r.13 | entry signed with label "SecMP-Q/1 FETCH"; one entry dropped and `count` reduced | present 3; remaining entries still verify (count not signed) | B |
| Q-25 | `q_fetch_multi_more_errors_than_f_m` [SQ-28] | §9.3 `:602` | 9 entries, all in error | exactly 8 frames: the first 8 errors in request order | B |
| Q-26 | `q_fetch_multi_repeated_rid` [SQ-28] | §9.3 `:602` | rid listed twice, acks 1 then 2 | acks applied in request order; no cell returned twice | B |
| Q-27 | `q_fetch_multi_count_bounds_tear_down` | D.2 `:819`; OPEN-6 | `count` 0 and 33 | teardown | B |
| Q-28 | `q_queue_del_removes_queue` | §9.3 `:603` | QUEUE_DEL (P23); then SEND, FETCH | OK; ERR 3; present 2 | B |
| Q-29 | `q_queue_del_unknown_rid_is_noqueue` | OPEN-9 | rid never created | ERR 3 | B |
| Q-30 | `q_queue_del_bad_signature_is_auth` | OPEN-9 | send-key signer (E16); label "SecMP-Q/1 FETCH" | ERR 4 | B |
| Q-31 | `q_queue_del_then_recreate_is_fresh` | §9.1 `:585` | QUEUE_NEW with the same keys | same rid/sid, next_cell_id 1, no cells | B |
| Q-32 | `q_link_put_three_frames_one_response` | D.2 `:821`, `:824`; (d) | P24 | nothing emitted after frames 1 and 2; OK after frame 3; entry {one_time 1, expires_bucket, present 1, consumed 0} | B |
| Q-33 | `q_link_put_errors_answered_after_third_frame` [O-7] | D.2 `:824`; (d); OPEN-9 | token flip (E17); wrong signer (E18); existing ld_id (E2); link-data pool full (O-7 A; the vector budget never refuses link data) | ERR 1; ERR 4; ERR 5; ERR 2 — each one frame after frame 3 | B |
| Q-34 | `q_link_put_signature_covers_blob_hash` | D.6 `:886`, D.2 `:821` | flip a byte of CONT idx 2 data after signing | ERR 4 | B |
| Q-35 | `q_link_put_cont_violations_tear_down` [SQ-27] | §9.2 `:593`, D.2 `:824` | CONT with another cmd_seq; idx 2 first; idx 1 twice; idx 0, 3; PING between; SKEY between; data 4099/4101 B; EOF after frame 2 | teardown; nothing stored; nothing emitted | B |
| Q-36 | `q_link_put_on_consumed_marker_is_exists` [R5-5] | §9.4 `:614` | LINK_PUT on a consumed one-time ld_id before its expiry | ERR 5 | B |
| Q-37 | `q_link_get_consume_one_time_returns_and_deletes` | §9.4 `:614`; (f); OPEN-11 | consume (P26) | LINKR {1,0} + CONT + CONT; parts 4160/4100/4100 = the stored blob; entry {0,1} | B |
| Q-38 | `q_link_get_consume_again_is_0_1` | §9.4 | second consume (E19) | LINKR {0,1}, dummy blob | B |
| Q-39 | `q_link_get_unknown_is_0_0_with_fresh_dummy` | §9.3 `:605`; OPEN-11 | ld_id never stored (E20), twice | {0,0}; 12360-B dummies differ between calls | B |
| Q-40 | `q_link_get_owner_status_does_not_consume` | §9.4; (f) | owner status (P25), consume, owner status (P27) | {1,0}; {1,0}+blob; {0,1}; entry consumed only by the consume | B |
| Q-41 | `q_link_get_owner_status_bad_signature_is_0_0` | OPEN-10 | wrong signer (E22); unknown ld_id; sig over another cmd_seq | LINKR {0,0}, dummy, CONT, CONT; store unchanged | B |
| Q-42 | `q_link_get_consume_is_atomic_single_winner` | §9.4 "atomically"; (f) | 4 links consume one ld_id concurrently, 1000 iterations | exactly one {1,0,blob}, the others {0,1} | B |
| Q-43 | `q_link_get_mode_rules_tear_down` | D.2 `:822`; REF-M2 r.10 | `mode` 2; `mode` 0 with a non-zero `sig` | teardown | B |
| Q-44 | `q_link_get_not_one_time_is_kept` [R5-6] | §9.4 | `one_time` 0, consume twice | {1,0,blob} twice; entry kept | B |
| Q-45 | `q_ping_is_ok` | §9.3 `:606` | PING (P8) | OK, 5 B | B |
| Q-46 | `q_skey_is_err_6` [R5-2] | D.2 `:816`; OPEN-6 | `0x02 ‖ cmd_seq` (E21); with non-zero bytes before the padding | ERR 6; cmd_seq recorded | B |
| Q-47 | `q_cmd_seq_gap_is_accepted` | §9.2 `:593`; (a) | cmd_seq 143 → 145 (P22) | OK | B |
| Q-48 | `q_cmd_seq_not_increasing_is_err_6` | §9.2; OPEN-5 | equal (E23); lower; 0 as the first request (`last` = 0) | one ERR 6; nothing executed; store unchanged | B |
| Q-49 | `q_cmd_seq_recorded_whatever_the_outcome` | OPEN-5 | SEND with ERR 4 at cmd_seq 7, then PING 7 | ERR 4; ERR 6 | B |
| Q-50 | `q_cmd_seq_stale_multi_frame_commands` [SQ-26] | §9.2; D.2 `:839` | stale FETCH, FETCH_MULTI, LINK_GET; stale LINK_PUT with its two CONTs | one ERR 6 each; LINK_PUT: one ERR 6 after frame 3 | B |
| Q-51 | `q_cmd_seq_u32_max` | §9.2; OPEN-5 | cmd_seq 2^32 − 1, then any request | executed; ERR 6 | B |
| Q-52 | `q_response_echoes_cmd_seq` | D.2 `:827`, `:839` | every response kind, multi-frame ones included | every frame echoes the request's cmd_seq | B |
| Q-53 | `q_token_matches_spec_hmac` | §9.6 `:622` | test computes HMAC-SHA-256(key, "SecMP-Q/1 token" ‖ sess_id ‖ u32be(cmd_seq)) (35-B input) | equals the client's token; only it is accepted | B |
| Q-54 | `q_signed_bytes_match_d6` | §9.2 `:593`, D.6 `:886` | the 7 signed commands | signed message = independent concatenation: QUEUE_NEW 135 B, SEND 4146, FETCH 59, MFETCH entry 60, QUEUE_DEL 55, LINK_PUT 155 (SHA-256 of the 12360-B blob), LINK_GET 55 | B |
| Q-55 | `q_every_signed_command_is_bound_to_sess_id` [O-4] | §8.3 `:560`, §9.2 `:593`, §9.6 `:622` | each signed command replayed byte-identically on a second link whose `last` is below the replayed `cmd_seq` | ERR 1 (QUEUE_NEW; LINK_PUT after frame 3 — the `sess_id`-bound token fails before the signature) · ERR 4 (SEND, QUEUE_DEL) · `present` 3 (FETCH, each FETCH_MULTI entry) · LINKR {0,0} (owner status) | B |
| Q-56 | `q_strict_ed25519_on_requests_tears_down` | §4.1 (b) `:152`; (g); OPEN-6; [R5-3] | `sig` S + L, R small-order, R y ≥ p; `recv_pk`/`send_pk`/`owner_pk` small-order or y ≥ p | teardown (decoder) | B |
| Q-57 | `q_every_response_is_d2_count_of_4352_byte_frames` [SQ-26] | §9.3 `:610`, D.2 `:839`, §9.7 (6) | every command × every reachable outcome (success, ERR 1–6, present 0–4, LINKR {0,0}/{0,1}/{1,0}) | D.2 count per command, stale `cmd_seq` and ERR 7 excepted (Conventions); every frame 4352 B; position right after the last request frame | B |
| Q-58 | `q_responses_in_request_order_when_pipelined` | D.2 `:839`, §9.7 (6), §10.3 `:674` | FETCH, SEND back-to-back; LINK_PUT ×3 then FETCH | responses in request order | B |
| Q-59 | `q_response_field_rules` | D.2 `:832-834` | every response built by the relay | CELLR present 0: rid 0, cell_id 0; present 2–4: rid set, cell_id 0; FETCH present 1: rid 0; LINKR flags ∈ {0,1} | B |
| Q-60 | `q_request_decoder_rules_tear_down` | §4.1 `:149`; §9.7 (7) `:632`; REF-M2 r.5; OPEN-6 | LINK_PUT `one_time` 2 and 0xFF; QUEUE_NEW, SEND, FETCH, QUEUE_DEL, LINK_GET and PING payloads with one extra non-zero byte after the last field (then 0x80 and zeros) | teardown (decoder: boolean rule, consistency rule) | B |

### b5 · Relay obligations (§9.7) and the relay crate (`docs/07:105`)

| # | Test | Spec | Input / action | Expected | Ph |
|---|---|---|---|---|---|
| RL-01 | `relay_restart_loses_all_state` | §9.7 (1) `:626` | new relay instance from the same key file | store empty; FETCH present 2; SEND ERR 3; owner status {0,0} | B |
| RL-02 | `relay_writes_no_file_after_start` | §9.7 (1); `docs/02` §5.1 | harness scenario with cwd/TMPDIR/HOME in an empty temp dir | no file created or modified after key load | B |
| RL-03 | `relay_tracing_emits_no_per_request_field` [O-8] | §9.7 (2) `:627`; `docs/07:105` | TRACE capture over the H-03 scenario | no event outside `expect::RELAY_TRACE_ALLOW`; no rid, sid, ld_id, key, token, sess_id, cmd_seq, cell_id, address (raw, hex, base64, decimal) | B |
| RL-04 | `relay_sweeper_cell_ttl` [O-5] | §9.7 (3) `:628`, §4.2 `:171` | virtual clock: arrival bucket b; buckets b + 168, b + 169 | retained; expired | B |
| RL-05 | `relay_sweeper_queue_idle_ttl` [O-5][R5-8] | §4.2 `:172`, §9.1 `:587` | no non-error FETCH since bucket b; b + 720, b + 721; a FETCH at b + 700 | retained; expired; refreshed | B |
| RL-06 | `relay_sweeper_link_data_expiry_and_marker` [O-5] | §9.4 `:614`, §4.2 `:173` | entry and consumed marker at `expires_bucket` e; buckets e, e + 1; LINK_PUT same ld_id after | present; gone ({0,0}); OK | B |
| RL-07 | `relay_link_put_expires_bucket_range` [O-6] | §9.3 `:604`, §4.2 `:173`; ADR-048 (o) | `expires_bucket` = now_bucket − 1, now_bucket, now_bucket + 720, now_bucket + 721 | ERR 6; OK; OK; ERR 6 — each one frame after frame 3; nothing stored on ERR 6 | B |
| RL-08 | `relay_memory_budget_accounting` [O-7] | §9.7 (4) | allocations to the limit; QUEUE_DEL, consume, expiry release | ERR 2 exactly when the next reservation exceeds; released reservations reusable; SEND never ERR 2 | B |
| RL-09 | `relay_storage_types_zeroize_on_drop` | §9.7 (5) `:630`; M4 §E (E9) | type-level `assert_zod::<T: ZeroizeOnDrop>()` | stored cell, stored blob, dummy buffers, `RelayKeys` secrets, access key | B |
| RL-10 | `relay_every_delete_path_drops_the_buffer` | §9.7 (5) | ack, eviction, QUEUE_DEL, cell TTL, idle TTL, consume, link-data expiry | kat live-buffer counter −1 per buffer; 0 after the store drops | B |
| RL-11 | `relay_store_holds_hour_buckets_only` | §9.1 `:587`; `docs/07:111`; `docs/06` §2 | type-level + policy grep | every store time field is `HourBucket(u32)`; `SystemTime::now` in `secmp-relay` only in the bucket function | B |
| RL-12 | `relay_one_link_per_connection` | §9.7 (7) | HELLO after an established link | teardown | B |
| RL-13 | `relay_frame_rate_limit` [O-2] | §9.7 (7), D.2 `:835`, `:839`; ADR-048 (p) | PING, FETCH and LINK_PUT above the configured per-link rate | one ERR 7 frame each, not executed, `cmd_seq` recorded; the LINK_PUT's ERR 7 after its third frame | B |
| RL-14 | `relay_handshake_rate_limit` [O-2] | §9.7 (7) | HELLOs above the configured rate | connection closed before RELAYINFO | B |
| RL-15 | `relay_graceful_drain` [O-9] | `docs/02` §5.1 | drain started; QUEUE_NEW, LINK_PUT, SEND, FETCH on an open link; new connection | ERR 2; ERR 2; served; served; refused; exit after `drain_secs` | B |
| RL-16 | `relay_keygen_then_load_same_identity` | §8.2 `:532`, `:539`; OPEN-4 | `keygen`, then load | same relay_sig_pk/relay_fp/kid keys; RelayInfo verifies; `valid_until − now` ≤ 5 184 000 | B |
| RL-17 | `relay_rotate_static_overlap` [O-10] | §8.2 `:539` | `rotate-static` | RELAYINFO announces kid + 1; HS1 with the old kid accepted until its `valid_until`, teardown after | B |
| RL-18 | `relay_hash_maps_use_random_state` | `docs/06` §2 `:40` | type-level assertion | maps keyed by client-chosen rid/sid/ld_id use `std` `RandomState`; maps keyed by relay-generated ids may use another hasher | B |
| RL-19 | `relay_akc_matches_access_key` | §8.2, §5.3 `:222`, §9.6 | configured access key | RelayInfo `akc` = SHA-256("SecMP-Q/1 akc" ‖ key) | B |
| RL-20 | `relay_dummies_are_fresh_randomness` [R5-7] | §9.3 `:601`, `:605` | two FETCHes with dummies; two absent LINK_GETs | dummies differ; kat draw order per R5-7 | B |
| RL-21 | `relay_restart_identical_link_put_is_accepted` | §9.7 (1) `:626` | LINK_PUT L; relay restart; owner status; the identical LINK_PUT (same `ld_id`, blob, `owner_pk`, `one_time`, `expires_bucket`; fresh token and signature) | {0,0}; OK; a consume then returns the blob | B |
| RL-22 | `relay_hello_to_hs1_timeout` [O-2] | §9.7 (7); OPEN-M5-02 values | HELLO answered, no complete HS1 within 30 s (virtual clock); control: HS1 complete at 29 s | connection closed, nothing emitted; control completes | B |
| RL-23 | `relay_config_controls_start_and_limits` | `docs/07:105` "config" | missing key file; unreadable config; a valid config with budget, rate limits, HELLO→HS1 timeout, `drain_secs` | start refused before any listener binds (error, no panic); the values in effect (kat accessor) equal the configured ones | B |

### b6 · Client transport `secmp-transport::RelayQueueTransport` (§12.1)

| # | Test | Spec | Input / action | Expected | Ph |
|---|---|---|---|---|---|
| T-01 | `transport_create_queue_idempotent` | §12.1 `:730` | create twice | same (RecvCap, SendCap) | C |
| T-02 | `transport_send_outcome_mapping` | §12.1 `:731` | OK_SEND with and without eviction; ERR 3; ERR 4 | `Ok{cell_id, evicted}`; `NoQueue`; `Auth` | C |
| T-03 | `transport_fetch_returns_real_cells_only` | §12.1 `:732` | 0–4 stored cells; present 2/3/4 | ≤ `F` real cells ascending, dummies filtered; errors mapped | C |
| T-04 | `transport_fetch_multi_maps_queue_refs` | §12.1 `:733` | two queues, one in error | cells with their `QueueRef`; per-queue error | C |
| T-05 | `transport_delete_queue` | §12.1 `:734` | delete, then fetch | Ok; `NoQueue` | C |
| T-06 | `transport_put_and_get_link_data` | §12.1 `:735-736` | put (3 frames); get consume, owner status | `{present, consumed, blob}`; no blob returned when present 0 | C |
| T-07 | `transport_cmd_seq_starts_at_1_strictly_increasing` | §9.2; OPEN-5 | first commands of a link | 1, 2, 3, …; CONT repeats | C |
| T-08 | `transport_token_per_command` | §9.6 | QUEUE_NEW, LINK_PUT | token over this link's sess_id and the command's own cmd_seq | C |
| T-09 | `transport_rejects_bad_response_shape` [O-11] | D.2 `:839` | wrong count, order, op, cmd_seq echo; OK_QUEUE_NEW ids ≠ derived | link Rejected and closed | C |
| T-10 | withdrawn → H-11 (no network in unit tests, `docs/06:93`) | — | — | — | — |
| T-11 | `transport_caps_are_opaque_and_roundtrip` | §12.1 `:740` | serialise and restore RecvCap/SendCap | equal; usable after restore | C |

### b7 · F-M5 follow-ups with unit tests (M04-review §C, `docs/07:113`)

| # | Test | Source | Input / action | Expected | Ph |
|---|---|---|---|---|---|
| G-01 | `tr_header_trial_open_tries_every_key` | R-42, campaign R-59, docs/01 RR-17; §7.4 `:440` | decrypts where the header opens under the first skipped hk, the last skipped hk, hk_r, nhk_r, none (states with `hk_r` and `nhk_r` set; an absent key costs one dummy open) | kat counting accessor: AEAD-open attempts = \|distinct skipped hks\| + 2 in every case | B |
| G-02 | `tr_skipped_lookup_touches_every_entry` | R-42, campaign R-58 | match at the first, middle, last entry; no match | lookup reads all \|skipped\| entries in every case | B |
| G-03 | `tr_vectors_f14_new_iks_equals_vector_iks` | R-55 | F14 block of `tests/tr_vectors.rs` | delivered `new_iks` byte-equal to the vector's IKSPublic | A |
| G-04 | `invitation_record_holds_owner_and_invq_recv_keys` [HX-RF][O-14] | R-67, §5.2 `:211` | issue, serialise, restore a record | link-data owner key and invitation-queue recv key present, zeroizing types, equal after restore | C |
| G-05 | `issue_invitation_derives_inv_sid` [HX-RF][O-14] | R-90, §9.1 `:581-582`, ADR-048 (m) | issue an invitation | `inv_sid` = SHA-256("SecMP-Q/1 sid" ‖ invq_recv_pk ‖ Ed25519.pk(inv_send_seed))[0..16]; kat draw order = the re-frozen case: the 16 B formerly drawn for `inv_sid` drawn and discarded (zeroized), `invq_recv_seed` 32 and `owner_seed` 32 after the case's last draw | C |
| G-06 | `route_relay_queue_sid_is_derived` | §9.8 `:639`, §9.1 | RelayQueue route built by the new constructor for a pool queue | `sid` = derived sid of (recv_pk, pk(send_seed)); a SEND with that route reaches the queue. Not [HX-RF]: the hx, tr and encodings generators keep their stream-drawn route `sid`s (opaque to every decoder) and do not call the constructor | C |

## (c) Integration — `secmp-testkit::Harness` (relay + N clients, virtual clock, scenario DSL; `docs/07:106`, `:109`)

| # | Test | Acceptance (`docs/07:109`) / spec | Scenario | Expected | Ph |
|---|---|---|---|---|---|
| H-01 | `harness_clients_create_pool_queues` | "create queues (pool)"; §10.6 (3) `:691` | two clients, ≥ 2 pool queues each | OK_QUEUE_NEW, derived ids | C |
| H-02 | `harness_invitation_and_handshake_over_relay` [HX-RF] (needs G-04, G-05) | §5.5, §6.4–6.6, §9.4 | A: LINK_PUT + pooled invitation queue; B: LINK_GET consume, `invitee_check`, `Initiator::start`, 3 SENDs to `inv_sid`; A: FETCH, `Responder::accept`; owner status | Ok both sides; owner status {0,1} | C |
| H-03 | `harness_exchange_1000_cells_each_way` | "exchange 1 000 cells each way"; §9.3 `:608` | TR session pair initialised from one shared SK (M3 `init_initiator`/`init_responder`; no HX, hence no [HX-RF]); queues from H-01; 1000 real cells each way; FETCH with cumulative ack, dedup by cell_id | all 1000 decrypt in order, each once; every delivered cell acked; queues end empty | C |
| H-04 | `harness_eviction_reports_ids_newest_128_decrypt` | "relay evicts at capacity and reports ids"; §9.5 | recipient offline; sender sends 200 cells | evicted ids 1…72 in order; recipient gets the newest 128; TR fast-forward decrypts them | C |
| H-05 | `harness_sweeper_expires_by_bucket` [O-5] | "sweeper expires by bucket" | virtual clock across CELL_TTL, QUEUE_IDLE_TTL, link-data expiry | as RL-04…RL-06 end to end | C |
| H-06 | `harness_memory_budget_refuses_new_queue_at_limit` [O-7] | "memory budget refuses new queues at the limit" | configured budget | QUEUE_NEW ERR 2 at the limit; SEND accepted | C |
| H-07 | withdrawn → H-12 (re-sending lost cells is the M6 outbox) | — | — | — | — |
| H-08 | `harness_all_bytes_after_hs2_are_4352_byte_frames` | "all responses FRAME_SIZE"; D.1 `:808` | byte capture of every connection in H-01, H-03…H-06, H-12, H-13 (not H-02: [HX-RF]) | after HS2 every stream length ≡ 0 mod 4352; every unit opens | C |
| H-09 | `harness_scenario_api_is_public_for_two_clients` [HX-RF] | M6 `two-clients` dependency (`docs/07:122`) | H-02 + H-03 written in `crates/secmp-testkit/tests/` against `pub` items only | compiles and passes | C |
| H-10 | `harness_replay_is_deterministic` | `docs/06` §4 (no wall clock in tests) | H-03 twice with kat entropy and the virtual clock | byte-identical frame captures | C |
| H-11 | `harness_transport_runs_over_in_process_streams` | `docs/07:106` "over an abstract byte stream"; `docs/06:93` | H-03 over `tokio::io::duplex` and over an in-process stream that splits every write into chunks of 1…4352 B | identical outcomes; no socket opened | C |
| H-12 | `harness_relay_restart_queues_recreated_conversation_continues` | "relay restart → ERR_NOQUEUE → identical queues re-created → conversation continues without a new invitation"; §9.1 `:585-589` | restart mid-conversation (H-03 sessions) | sender: ERR 3, keeps sending, ~~drops its cell_id map~~ (struck, M05 review R-115/§E: no outbox in M5, the map is M6); recipient: present 2, re-creates the identical queue after U[10 s, 5 min] (virtual), resets committed_ack and its dedup set; cells sent after the re-creation decrypt (TR fast-forward over the lost positions); no new invitation; no mk reused; lost cells are not re-sent (M6 outbox) | C |
| H-13 | `harness_undecryptable_cell_is_acknowledged` | §9.3 `:608` "every delivered cell is acknowledged, whether or not it decrypted" | a harness hook SENDs a random 4096-B cell with the sender's key between two real cells | the random cell fails to decrypt, is discarded and acknowledged (the next FETCH's ack covers it); both real cells decrypt | C |

## (d) Property tests (proptest; default seed + CI-run seed, R-93)

| # | Name | Invariant | Ph |
|---|---|---|---|
| P-01 | `prop_link_handshake_agrees` | random relay keys and entropy ⇒ both sides derive equal ss1, ck1, ss2, ck2, k_c2r, k_r2c, sess_id; k_c2r ≠ k_r2c | A |
| P-02 | `prop_frame_roundtrip_any_payload` | payload 0..=4335 B ⇒ open(seal(p)) = p, unit 4352 B, counters +1 | A |
| P-03 | `prop_frame_single_byte_flip_rejects` | any one-byte flip of a sealed frame ⇒ Rejected, counter unchanged | A |
| P-04 | `prop_frame_sequence_tampering_rejects` | any drop, duplicate or swap in a sealed sequence ⇒ the first out-of-place unit is Rejected | A |
| P-05 | `prop_q_ids_are_derived` | random recv_pk/send_pk ⇒ rid, sid equal the independent SHA-256 recomputation | A |
| P-06 | `prop_executor_response_shape_matches_d2` [SQ-26] | random request sequences (honestly signed over random fields, plus random faults) ⇒ `assert_d2_shape` per request | B |
| P-07 | `prop_queue_store_matches_model` | random QUEUE_NEW/SEND/FETCH/FETCH_MULTI/QUEUE_DEL ⇒ same responses and states as a plain model (VecDeque ≤ 128, ids from 1, oldest evicted, cumulative ack, arrival order) | B |
| P-08 | `prop_rejection_leaves_link_and_store_unchanged` | random mutation of a valid unit or record that is rejected ⇒ counters, `last`, store digest unchanged, nothing emitted | B |
| P-09 | `prop_response_count_independent_of_outcome` | per command, frame count and lengths depend only on the op (exceptions of the shape table) | B |
| P-10 | `prop_one_time_link_data_single_winner` | random interleavings of consume/owner-status from several links ⇒ exactly one consume returns the blob | B |
| P-11 | `prop_cmd_seq_executes_iff_greater_than_last` | random cmd_seq sequences ⇒ executed iff > last; last = max recorded | B |
| P-12 | `prop_k_id_independent_of_iks_i_dh1_dh2` (opt) | R-56: K_id recomputed with IKSPublic_I/DH1/DH2 varied is unchanged; with each of its six inputs varied it changes | A |

Cited from M2 (no new row): the canonicality properties over every App. D structure (`docs/07:58`, `:60`), D.1 records and
D.2 request/response payloads included. Phase A's first step names the M2 property that covers them; **P-13
`prop_link_wire_canonical`** (conditional, A: decode(encode(x)) = x and encode(decode(b)) = b for the four D.1 records and
every D.2 request and response payload) is dictated only if none does.

## (e) Kani

| # | Harness | Property | Ph |
|---|---|---|---|
| K-01 | `kani_frame_pad_total` | pad of any payload ≤ 4335 B gives 4336 B; unpad of any 4336-B buffer is total and inverts pad | A |
| K-02 | `kani_link_counter_strict_plus_one` | AEAD stubbed (open ok iff nonce counter = sealed counter): over bounded open sequences the receive counter moves +1 per success and never on failure | A |
| K-03 | `kani_link_counter_checked_add` | counters at 2^64 − 1 abort without wrap; `LINK_MAX_FRAMES` check total [O-3] | A |
| K-04 | `kani_cont_assembly` [SQ-27] | over bounded frame sequences (LINK_PUT, CONT idx 0..=3, other op; cmd_seq ∈ {1,2}) the assembler completes exactly LINK_PUT(s), CONT(s,1), CONT(s,2) and rejects every other order; blob offsets 0/4160/8260, total 12360 | A |
| K-05 | `kani_cmd_seq_monotone` | `last` never decreases; stale ⇒ ERR 6 and nothing executed; CONT exempt | B |
| K-06 | `kani_queue_eviction_bounds` | store logic at a const capacity of 3: length ≤ capacity after any SEND; oldest evicted and reported; next_cell_id strictly increasing; ack deletes exactly ids ≤ ack | B |
| K-07 | `kani_executor_response_count` [SQ-26] | for every decoded request and store outcome the executor returns the D.2 count (stores and crypto stubbed) | B |

Cited from M2 (no new row): the frame-plaintext Kani harnesses of `kani_proofs` (`docs/07:58`, e.g. `request_*`,
`response_frame`). Phase A's first step names them and what they decode; **K-08 `kani_q_frame_plaintext_exact_fit`**
(conditional, A: the request and the response decoder over an arbitrary 4336-B plaintext are total and exact-fit, Ok ⇒
consistent with D.2) is dictated only if no M2 harness runs both decoders.

Negative control (M4 C-15): one committed K-06 run with the eviction removed, expected `VERIFICATION:- FAILED`; every `cover!` SATISFIED.

## (f) Fuzz targets (2 min each per PR; ≥ 1 committed seed per target, M4 C-6)

| # | Target | Input → invariant | Ph |
|---|---|---|---|
| FZ-01 | `link_records` | arbitrary bytes → HELLO/RELAYINFO/HS1/HS2 decoders; total; Ok ⇒ re-encode = input | A |
| FZ-02 | `link_client_handshake` | raw and structured (fuzzer mutates HS2 fields, harness re-MACs with the fixture relay) → client; no panic; Ok only on consistent records | A |
| FZ-03 | `link_relay_handshake` | raw and structured (fuzzer mutates HS1 fields, harness re-encapsulates and re-MACs) → relay responder; no panic; teardown or HS2 | A |
| FZ-04 | `link_frame_open` | arbitrary units of any length → `Link::open`; total; failure ⇒ counter unchanged | A |
| FZ-05 | `q_request_decode` | arbitrary 4336 B → request decoder; total; Ok ⇒ encode = input | A |
| FZ-06 | `q_response_decode` | arbitrary 4336 B with a request context → response decoder; total; canonical | A |
| FZ-07 | `relay_executor` [SQ-26] | structured: fuzzer picks commands and fields, harness signs, tokens and seals → executor; D.2 shape; store invariants (≤ 128, ids monotone, ids derived); no panic (`docs/07:109`) | B |
| FZ-08 | `relay_link_session` [SQ-27] | arbitrary plaintexts sealed honestly in fuzzer order (CONT/LINK_PUT interleavings included) → relay connection; teardown leaves the store unchanged; no panic | B |
| FZ-09 | `hx_accept_structured` mode 3 (existing target) | R-44: fuzzer bytes as a padded Content, encrypted from the fixture's post-init TR state; reaches the step-3 rejects (n/pn, type, caps, known route) | A |

## (g) Constant time (`benches/ct.rs`, docs/06 §4 rules, ADR-041 Am. 1–3, ADR-042 Am. 2–3)

| # | Target | Where | Classes | Ph |
|---|---|---|---|---|
| CT-01 | `link_hs1_reject_mac1` | relay `mac1` compare after Decaps (§8.3 `:552`; §3 MAC row) — composed, floor-only | "mac1 differs in byte 0" / "in byte 31" | B |
| CT-02 | `link_hs2_reject_mac2` | client `mac2` compare (§8.3 `:556`) — composed | as CT-01 | B |
| CT-03 | `link_frame_open_reject` | `Link::open` of a 4352-B frame (§8.4) — composed | "tag differs in byte 0" / "in byte 15" | B |
| CT-04 | `q_queue_new_reject_token` | relay token compare (§9.6), through the secmp-crypto HMAC verify whose primitive is `tag_compare` — composed | "token differs in byte 0" / "in byte 31" | B |
| CT-05 | `tr_decrypt_trial_open_position` | R-42/R-59: §7.4 header trial opens with 2 distinct skipped hks — composed | "header opens under the first candidate key" / "under the last" | B |
| CT-06 | `link_same_content_control` | control for the new 2856-B record / 4352-B frame preparation path (ADR-042 Am. 2 rule: a new artefact class gets its control) | identical content through both class paths; FAIL ⇒ `CONTROL_FAIL` | B |

CT-01…04 are floor-only; G-03 pins the comparison primitive (TEST-SPEC-M6 G-03, `ct_guard_sites_use_ct_eq`, M5 review F-6, R-124).

Not targets (reason): `akc` and `relay_fp` compares (public values, §5.3); Ed25519 verification of RelayInfo and
commands (public inputs); `cmd_seq` (known to both ends, its outcome is answered on the wire); frame counters (the
counter is the nonce, nothing is compared); rid/sid/ld_id lookups (ids are not secret to the requester; M4 R-85).
Recorded, not targets: owner-status time may differ between an absent and a present entry, and FETCH time between
dummy generation and stored cells (µs against Tor latency; the M3 R-15 class).

## (h) Formal obligations (`docs/03:711`, `docs/07:107`, `:113`)

| # | Obligation | Expected | Ph |
|---|---|---|---|
| PV-01 | `proverif_link_matches_claims` [O-16] — LINK model per CLAIMS §LINK (query set fixed by the reviewer before modelling, §11.2): `formal/link.pvl` + `formal/link/<session>.pv`, `expect::PROVERIF_EXPECTED` rows, model sha256 pinned (ADR-046 Am. 1), 30-min cap per file | every M5 row with its CLAIMS verdict | B |
| PV-02 | `proverif_tr_t14_second_receive` — R-41 (M3 F6): `tr.pv` second receive attempt after a skipped-path acceptance on the F5 branch; CLAIMS row T14 (proposal: injective agreement for a cell re-delivered after its skipped-path acceptance; expected true; the reviewer fixes the text before modelling) | T14 true; T13 reachability per session unchanged | B |
| PV-03 | docs, no test — R-70: one sentence under CLAIMS O-15 (D-18): FS of TR step-1 content after a store compromise rests on H12/H12c | docs only | B |

## (i) xtask / gate tests; mutation scope

| # | Test | Purpose | Ph |
|---|---|---|---|
| X-01 | `vectors_step_12a_covers_twelve_suites` | step 12a compares 12 suites incl. `link` | B |
| X-02 | `mutants_scope_includes_relay` [O-12] | `secmp-relay` (executor, stores, link server) in the 8-shard gate with the ADR-047 Am. 2 floor | B |
| X-03 | `ct_targets_list_names_m5_targets` | `expect::CT_TARGETS` holds CT-01…CT-06; CT-06 judged as a control | B |
| X-04 | `proverif_link_table_covers_every_claims_row` [O-16] | CLAIMS §LINK rows ⇔ `PROVERIF_EXPECTED` link rows, both directions (C-7 pattern) | B |
| X-05 | `proverif_link_model_hashes_are_pinned` [O-16] | `expect::PROVERIF_MODEL_SHA256` holds every link file | B |
| X-06 | `doctest_compile_fail_blocks_name_an_error_code` (opt) | R-92: every `compile_fail` fence names an error code | B |
| X-07 | `pr_ci_runs_props_with_ci_run_seed` [O-17] | R-93: PR runs execute every property with `DEFAULT_SEED` and a run-derived seed; `prop_outer_unpad_total_12018` gains the classes "no 0x80 in the tail" and "0x80 as the last byte" (OPEN-M5-17, decided 2026-10-03) | B |
| X-08 | `ct_target_sites_bind_each_target_to_its_site` (opt) | R-47: `CT_TARGET_SITES` (target, site) checked by `ct_site_lines` | B |

Mutation scope: `secmp-proto` (new `link` and Q modules; automatic), `secmp-crypto` (unchanged), `secmp-relay` [O-12].
Survivors only as documented equivalents in `docs/mutants-accepted.md` with `:line` (R-74).

## (j) Maps

**Acceptance (`docs/07:109`).** pool queues H-01 · 1 000 cells each way H-03 · eviction + ids Q-11, H-04 · sweeper RL-04…RL-06,
H-05 · budget Q-06, RL-08, H-06 · restart H-12, RL-01, RL-21, Q-20, Q-31 · config RL-23 · FRAME_SIZE Q-57, H-08, V-16 · indistinguishability V-16,
Q-57, P-09 · executor fuzz FZ-07 · unit test per command Q-01…Q-46 · FETCH idempotence + cumulative ack Q-14, Q-15, V-09.

**Review focus (`docs/07:111`).** strict counters F-03, F-06, K-02, P-04 · `sess_id` in command signatures Q-55, Q-10, Q-18 ·
one-time consumption atomic Q-42, P-10 · owner status non-consuming Q-40 · eviction reporting Q-11 · zeroize on delete
RL-09, RL-10 · hour buckets only RL-11 · RelayInfo never cached C-13.

**Appendix C (`docs/03:790`)** "LINK handshake + first three frames each direction": V-03…V-08 (QUEUE_NEW, SEND, PING; OPEN-13).

**F-M5 (M04-review §C).** R-41 PV-02 · R-42/campaign R-59 G-01, G-02, CT-05 · R-44 FZ-09 · R-47 X-08 · R-55 G-03 ·
R-56 P-12 · R-66 V-23, V-24 · R-67 G-04 · R-70 PV-03 · R-90 G-05, V-23…V-25 · R-92 X-06 · R-93 X-07 · F15 ref (WEISUNG_REF).
