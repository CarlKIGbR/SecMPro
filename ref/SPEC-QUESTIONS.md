# SPEC-QUESTIONS — open issues found while writing `ref/` from the spec alone

Sources: `docs/03-protocol-spec.md` (rev 2.1, 2026-09-25 → answers refer to **rev 2.2**, 2026-09-28) and `vectors/SCHEMA.md` (rev 1 → **rev 2**, 2026-09-28).
Each entry gives the place, the quoted text, the possible readings, the reading `ref/` would choose
and why, and the suites it blocks. A blocked suite is not written until the answer comes back
(`BLOCKED_BY` in `ref/gen_vectors.py`). Answers go under **Answer:**. Please keep the IDs stable.

| ID | Topic | Blocks | Status |
|---|---|---|---|
| SQ-01 | How case inputs are derived from `seed_i` | **all M1 suites** | answered 2026-09-28 |
| SQ-02 | Suite tags in case ids | **all M1 suites** | answered 2026-09-28 |
| SQ-03 | JSON form of values that are not byte strings | hkdf-labels, hybridsign, sas | answered 2026-09-28 |
| SQ-04 | Inputs and construction of negative cases | negatives of msgencrypt, caead, hybridkem-* | answered 2026-09-28 |
| SQ-05 | "Flipped ciphertext ⇒ reject" vs ML-KEM implicit rejection | hybridkem-768, hybridkem-1024 | answered 2026-09-28 |
| SQ-06 | `verify_strict` is not a specification | hybridsign negatives (if any) | answered 2026-09-28 |
| SQ-07 | Appendix A is not prefix-free; `label ‖ data` has no framing | hybridsign | answered 2026-09-28 |
| SQ-08 | ML-DSA-65 in HybridSign: pure ML-DSA.Sign (confirmation) | — (confirmation only) | answered 2026-09-28 |
| SQ-09 | Where "wrong padding" is tested; MsgEncrypt length checks | msgencrypt negatives | answered 2026-09-28 |
| SQ-10 | What the `fingerprint` input `iks` is | fingerprint | answered 2026-09-28 |
| SQ-11 | X25519 public-key input handling beyond the all-zero check | negatives with crafted X25519 keys (if any) | answered 2026-09-28 |
| SQ-12 | Which key and signature checks belong to decoding | `encodings`: 4 rows (written since REF-M2-1) | answered 2026-09-29 |
| SQ-13 | `RelayRef.onion`: what the decoder checks | `encodings`: 2 rows (written since REF-M2-1) | answered 2026-09-29 |
| SQ-14 | `RelayRef.direct`: host and port constraints | `encodings`: 4 rows (written since REF-M2-1) | answered 2026-09-29 |
| SQ-15 | `HandshakeBody.caps` "(= 0)": reject or ignore other values | `encodings`: 2 rows (written since REF-M2-1) | answered 2026-09-29 |
| SQ-16 | Body layouts given in §7.6 but missing from App. D | — (generated from §7.6) | answered 2026-09-29 |
| SQ-17 | Lists with count 0 (Batch, RouteUpdate, Handshake routes, Receipt) | `encodings`: 4 rows (written since REF-M2-1) | answered 2026-09-29 |
| SQ-18 | Fragment: `idx` base, `total`/`chunk` minimum, reassembled inner types | `encodings`: 6 rows (written since REF-M2-1) | answered 2026-09-29 |
| SQ-19 | AppMessage payloads and Control arguments have no layout | — (no row depends on it) | answered 2026-09-29 |
| SQ-20 | Weisung addition 1 ("top-level" `ver`) vs App. D: `RouteDescriptor.ver`, frames, Cell, records | — (written per App. D; the 50 rows stand) | answered 2026-09-29 |
| SQ-21 | Content of the `op`/`mode` JSON strings inside `value` (correction 1) | — (representation only; bytes unaffected) | answered 2026-09-29 |

**State 2026-09-28 (brief REF-M1):** all answers applied; `BLOCKED_BY` is empty; the eight M1 files are written to `vectors/`. No new question was raised by the rev 2.2 spec or SCHEMA rev 2. The readings applied to the new SCHEMA §4 tables are listed at the end ("Readings adopted without a question — SCHEMA rev 2 §4") for the reviewer to veto.

**State 2026-09-29 (brief REF-M2):** `vectors/encodings.json` is written from the case-table proposal `SCHEMA-4.8-encodings.md` (71 positive, 517 negative rows). SQ-12 … SQ-19 are new. None blocks the suite, so `BLOCKED_BY` stays empty. Every row whose outcome depends on an answer is **withheld**: 22 rows, listed in SCHEMA-4.8 with their outcome under the proposed reading. Every written row holds under every reading: the generator decodes each row twice, once with the proposed readings and once with the most permissive reading of every open question, and requires the same result both times. The M2 readings adopted without a question are listed at the end ("Readings adopted without a question — REF-M2").

**State 2026-09-29 (Weisung REF-M2-1):** every answer to SQ-12 … SQ-19 and every SCHEMA-4.8 correction is applied (see "Applied: Weisung REF-M2-1" at the end). The file is renumbered and re-seeded once: 85 positive and 547 negative rows, `"schema": 3`. No row is withheld any more, and the generator's lenient mode is gone. Applying the Weisung raised two questions. Neither blocks a row, because the file follows App. D and SCHEMA §1 literally where they apply: SQ-20 (addition 1 against App. D) and SQ-21 (the content of the `op`/`mode` strings).

---

## SQ-01 — How case inputs are derived from `seed_i` (blocks all M1 suites)

**Where:** `vectors/SCHEMA.md`, "Suites and their keys".
**Quote:** "Each suite has ≥ 8 positive cases from fixed seeds (`seed_i = SHA-256("SecMP-vectors/1" ‖ suite ‖ i)` expanded with SHAKE-256 to the required randomness, so both sides derive identical inputs)".

**Problem.** The Rust and Python files are compared byte for byte, *inputs included*, so both sides must turn `seed_i` into identical inputs. The text leaves open:

1. the encoding of `suite` (suite name `"hkdf-labels"`, or the tag `"hkdf"`?) and of `i` (u8? u32 BE? ASCII decimal?), and whether `i` starts at 0 or at 1 (ids are `…-0001`);
2. how the SHAKE-256 output is consumed: one stream per case, and in which field order? A separate XOF call per field?
3. the lengths of variable-length inputs (`salt`, `ikm`, `extra_info`, `ad`, `p` content, `msg`), the value of `len`, and which Appendix A `label` a case uses. Are these drawn from the stream (how exactly?), or fixed by a table?
4. hkdf-labels: which labels are in scope. Appendix A mixes HKDF infos with hash prefixes, AD prefixes and signature prefixes. Two HKDF labels are used with HKDF-Expand only (`"SecMP-commit/1"` §3.4, `"SecMP-LINK/1 keys"` §8.3). `"SecMP-STORE/1 <table>"` names tables that are defined only in `02-architecture.md` §4.2, which this session does not have.
5. For fingerprint and hybridsign: whether keys are derived from seeds or taken as raw bytes (see SQ-10).

**Reading A (proposed, implemented in `ref/secmp_ref/vectorfile.py`, not yet used to write any file):**

```
seed_i   = SHA-256( "SecMP-vectors/1" ‖ ASCII(suite name) ‖ u32be(i) )    ; i = 1, 2, … = the number in the case id
stream_i = SHAKE-256(seed_i), consumed front to back
input fields are taken from stream_i in the order of the SCHEMA "inputs" column; a field of fixed size n takes n bytes
lengths, `len`, and `label` come from a per-suite shape table fixed in SCHEMA.md (not from the stream)
```

Worked example (hkdf-labels, case 1):
`preimage = 5365634d502d766563746f72732f31686b64662d6c6162656c7300000001`,
`seed_1 = cf66f30f0fe1f5798c9c3f1e8e4034fbd3ef99ca2dcf68bf3d533caa15a33d23`,
first 16 stream bytes (= `salt`) `66a224dde82f65dff9bc79b22f39a9ad`, next 32 (= `ikm`) `30c09b030215e20d5de63ff06946dfb6aa044c903b7709cd7c9c3d80e8326007`.

Proposed shape table for hkdf-labels: one case per labelled HKDF call site of the spec, using that call site's lengths, plus three edge cases. There are no negative cases, because Appendix C lists none for HKDF.

| i | label | salt | ikm | extra_info | len | call site |
|---|---|---|---|---|---|---|
| 1 | `SecMP-INV/1 linkdata` | 16 | 32 | 0 | 32 | §5.4 `K_ld` |
| 2 | `SecMP-HX/1 sk` | 32 | 224 | 32 | 32 | §6.4 `SK` (extra = transcript) |
| 3 | `SecMP-HX/1 idkey` | 16 | 160 | 0 | 32 | §6.4 `K_id` |
| 4 | `SecMP-HX/1 initkey` | 16 | 32 | 0 | 32 | §6.5 `K_inv` |
| 5 | `SecMP-TR/1 init` | 32 | 32 | 0 | 96 | §7.2 |
| 6 | `SecMP-TR/1 rk` | 32 | 64 | 0 | 96 | §7.2 `KDF_RK` |
| 7 | `SecMP-TR/1 msgkeys` | 32 | 32 | 0 | 76 | §3.3 |
| 8 | `SecMP-commit/1` | 32 | 32 | 24 | 64 | §3.4 label, via full HKDF here |
| 9 | `SecMP-LINK/1 keys` | 32 | 32 | 0 | 80 | §8.3 label, via full HKDF here |
| 10 | `SecMP-TR/1 msgkeys` | 0 | 32 | 0 | 76 | edge: empty salt (RFC 5869 ≡ 0^32) |
| 11 | `SecMP-HX/1 sk` | 32 | 32 | 100 | 8160 | edge: maximum L |
| 12 | `SecMP-TR/1 rk` | 32 | 0 | 0 | 1 | edge: empty IKM, L = 1 |

**Reading B:** lengths and labels are also drawn from the stream (e.g. `u16be mod (max+1)`, `u8 mod |labels|`). **Reading C:** only `cargo xtask` derives inputs and hands the same inputs to both implementations. The README ("runs it and the Rust implementation over the same inputs") could mean this.

**Choice: A.** A u32 BE index matches the spec's own integer encoding (§4.1). A shape table guarantees coverage of every call site and every edge case, whereas random lengths would cover whatever the seeds happen to produce. Reading C would make the seed rule unnecessary on the Rust side, and SCHEMA says "both sides derive identical inputs".
**Please also answer:** is `SecMP-STORE/1 <table>` in scope for hkdf-labels? If yes, the table names are needed.
**Blocks:** every M1 suite, hkdf-labels included. hkdf-labels needs only this table; the other suites need their own shape tables. I will propose each one when I reach that suite, unless the reviewer prefers to write them into SCHEMA.md directly.
**Answer (reviewer, 2026-09-28): Reading A, adopted verbatim and now normative in `SCHEMA.md` rev 2 §2.** `seed_i = SHA-256(ASCII("SecMP-vectors/1") ‖ ASCII(<suite name>) ‖ u32be(i))`, `i` from 1 = the id number; one SHAKE-256 stream per case consumed front to back in the order of the suite's input list; lengths, labels, `len`, `mode`, `op` and manipulations come from the case tables, never from the stream. Your worked example is confirmed as the check value. Your 12-row hkdf-labels table is adopted with one refinement: rows 8 and 9 carry `mode = "expand"` (HKDF-Expand with PRK = `ikm`, empty `salt`), all other rows `mode = "extract-expand"`; see `SCHEMA.md` §4.1. `SecMP-STORE/1 *` is out of scope for vectors (local storage, M7); spec rev 2.2 App. A now lists the nine table names anyway so the spec is self-contained. The reviewer wrote the case tables for all six M1 suites into `SCHEMA.md` §4, so no further suite is blocked on shapes.

## SQ-02 — Suite tags in case ids (blocks all M1 suites)

**Where:** SCHEMA "Rules". **Quote:** "`id` is `<suite-tag>-<4-digit index>`". The only tag given is `hk768` (in the example).
**Readings:** (A) tags `hkdf`, `caead`, `msgenc`, `hk768`, `hk1024`, `hsig`, `fp`, `sas`; (B) the full suite name (`hkdf-labels-0001`).
**Choice: A.** It matches the one example given. Also: does the index start at 0001 (as proposed in SQ-01), and are negative cases numbered after the positive cases in the same sequence?
**Answer: Reading A.** Tags `hkdf`, `caead`, `msgenc`, `hk768`, `hk1024`, `hsig`, `fp`, `sas` (`SCHEMA.md` §3). Index starts at `0001`; negative cases continue the same sequence after the positives.

## SQ-03 — JSON form of values that are not byte strings

**Where:** SCHEMA. **Quotes:** "every byte string is lowercase hex; integers are JSON numbers"; hybridsign `label` "(ASCII, from Appendix A)"; hkdf-labels `label` "(from Appendix A)" but `extra_info` "(hex appended to the label)"; sas `half_a` "(30 digits)"; hybridsign `verify` = `true`; the comparison normalises "lowercase hex".
**Readings for `label`:** (A) a JSON string holding the ASCII label, e.g. `"SecMP-TR/1 rk"`; (B) the hex of its ASCII bytes. For SAS digits: (A) a JSON string of decimal digits (leading zeros kept); (B) hex of the ASCII digits. `verify`: a JSON boolean.
**Choice: A for both.** The hybridsign row says "ASCII", and the hkdf-labels row contrasts `label` with the hex `extra_info`. A 30- or 60-digit value cannot be a JSON number. **Consequence:** the normaliser's "lowercase hex" step must not lowercase these strings (`"SecMP-…"` would become `"secmp-…"`). `ref/` writes files that are already canonical: sorted keys, `separators=(",", ":")`, ASCII only, no trailing newline. The SHA-256 values reported are over those bytes.
**Answer: Reading A for both.** Labels are JSON strings holding the ASCII label; SAS halves and the safety number are JSON strings of decimal digits with leading zeros; `verify` is a JSON boolean; `mode`/`op` are JSON strings. The comparison is **structural** (parse both files, drop `generator`, compare values) with no case-folding at all; a validator checks that byte-string fields match `^([0-9a-f]{2})*$`. Your canonical writer (sorted keys, `(",", ":")`, ASCII, no trailing newline) is the normative writer (`SCHEMA.md` §1).

## SQ-04 — Inputs and construction of negative cases

**Where:** SCHEMA. **Quote:** "Negative cases carry `"expect": "reject"` instead of `outputs` … non-contributory X25519 (all-zero shared secret), malformed ML-KEM encapsulation key, truncated/flipped ciphertext, wrong MAC, wrong `COM`, wrong padding."
**Problem.** The input columns hold seeds and plaintexts, the inputs of the *sealing* direction. A reject case needs the object under test as an input: the tampered `c_tag` (msgencrypt), `com`/`c` (caead), a low-order `pk_dh` or a malformed `ek_kem` (hybridkem Encaps side), a low-order `pk_e` or a truncated `ct_kem` (Decaps side). No key names exist for these, and nothing says which operation a case exercises. Nor is it said how the tampering is chosen (which byte and bit, how much truncation, which low-order point) so that both sides produce identical files.
**Reading A (proposed):** negative cases list the opening-direction inputs, e.g. msgencrypt `{mk, ad, c_tag}`, caead `{k, n, ad, com, c}`, hybridkem Decaps `{dk_seed, sk_dh, pk_e, ct_kem}`, hybridkem Encaps `{ek_kem, pk_dh, m, sk_e}` (with an `op` field, or separate key sets per operation). The valid object comes from the case's own seed stream, and the per-suite shape table names the manipulation, e.g. "flip bit 0 of byte 0 of `c_tag`", "drop the last byte", "`pk_e` = u-coordinate 0 / 1 / the order-8 point".
**Reading B:** negative cases carry the positive inputs plus a `tamper` descriptor that each side applies itself.
**Choice: A.** The file then shows the exact rejected bytes, and neither side has to interpret a descriptor.
**Answer: Reading A.** Negative cases list the opening-direction inputs and carry an `op` field (`"open"`, `"decaps"`, `"encaps-to"`, `"verify"`; positives carry `"seal"`, `"encaps"`, `"sign"`, `"derive"`, `"fp"`, `"sas"`). The valid object is derived from the referenced positive row's stream and the manipulation is fixed by the table (`flip(field, k)`, `drop-last`, `append-zero`, `prefix`, or an explicit constant); the file shows the exact rejected bytes. Tables in `SCHEMA.md` §4.2–4.5.

## SQ-05 — "Flipped ciphertext ⇒ reject" contradicts ML-KEM implicit rejection (§3.2)

**Where:** SCHEMA negative list ("truncated/flipped ciphertext"), Appendix C, §3.2 "`ss_kem = ML-KEM.Decaps(dk_kem, ct_kem) ; implicit rejection per FIPS 203`".
**Problem.** A flipped `ct_kem` of the right length is not rejected. FIPS 203 decapsulation returns `K̄ = J(z ‖ c)`, and the combiner then produces a well-formed `ss` that differs from the encapsulator's. A flipped `pk_e` likewise gives a different, non-zero `ss_dh` (unless it lands on a low-order point). For HybridKEM only a length error (truncated `ct_kem`/`pk_e`) or an all-zero X25519 output rejects.
**Readings:** (A) hybridkem "flipped ciphertext" cases are *positive* Decaps vectors whose output `ss` is the implicit-rejection value. This checks that the Rust side implements implicit rejection rather than returning an error or the honest key. "Truncated" cases are `expect: reject`. (B) hybridkem has no flipped-ciphertext cases at all.
**Choice: A.** It is the only way to test implicit rejection end to end, and the ACVP decapsulation vectors in `ref/tests` already confirm the library does it.
**Answer: Reading A — you are right, and the spec was wrong.** A bit-flipped `ct_kem` of correct length is a **positive** decapsulation case whose `ss` is the hybrid secret computed with the implicit-rejection KEM secret; a flipped non-low-order `pk_e` is likewise positive with a recomputed `ss`. Only length errors and all-zero X25519 outputs reject. Spec rev 2.2 Appendix C is corrected accordingly; `SCHEMA.md` §4.4 rows 10–12 (positive), 13–16 (reject).

## SQ-06 — `verify_strict` is not a specification (§3.5)

**Where:** §3 table "Ed25519 (`verify_strict`)"; §3.5 "both components MUST verify (verify_strict for Ed25519)".
**Problem.** `verify_strict` is the name of a function in the ed25519-dalek crate. Its exact acceptance set is defined by that crate's code, not by RFC 8032. Libraries disagree on edge cases such as non-canonical encodings of `A` or `R`, small-order and mixed-order points, and cofactored versus cofactorless checks (see Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs", 2020). A reference written from the spec cannot reproduce one crate's behaviour. `ref/` uses libsodium's `crypto_sign_verify_detached` via PyNaCl.
**Readings:** (A) the spec states the rule itself, e.g. "RFC 8032 §5.1.7 with: reject `S ≥ L`; reject non-canonical encodings of `A` and `R`; reject small-order `A` and `R`; cofactorless equation `[S]B = R + [k]A`". Both sides then test against that rule. (B) "whatever ed25519-dalek `verify_strict` does", in which case no Ed25519 edge-case vectors can come from `ref/`.
**Choice: A.** This only matters for negative hybridsign vectors with crafted keys or signatures. Positive vectors from honest keys agree under every reading. SCHEMA lists no hybridsign negatives, so hybridsign positives are not blocked by this.
**Answer: Reading A — the spec now states the rule itself (rev 2.2 §3.5):** RFC 8032 §5.1.7 with the cofactorless equation `[S]B = R + [k]A`; reject `S ≥ L`; reject non-canonical encodings of `A` or `R` (y ≥ p); reject small-order `A` or `R` (order dividing 8, incl. the identity). Implementations whose library does less must add the checks on the encoded bytes — that applies to `ref/` (add byte-level pre-checks in the wrapper if libsodium does not already reject a case) and to the Rust side alike. Negative hybridsign vectors for `S + L`, the identity as `A`, and a non-canonical `A` are in `SCHEMA.md` §4.5 rows 14–16.

## SQ-07 — Appendix A is not prefix-free, and `label ‖ data` has no framing

**Where:** Appendix A; §3.5 `m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)`; §3 table "Every `info` begins with a label"; SCHEMA hybridsign `label` "(ASCII, from Appendix A)".
**Observation.** Several labels are prefixes of others: `"SecMP-INV/1"` ⊂ `"SecMP-INV/1 linkdata"`, `"SecMP-HX/1 init"` ⊂ `"SecMP-HX/1 initkey"`, `"SecMP-Q/1 FETCH"` ⊂ `"SecMP-Q/1 FETCH_MULTI"`. The spec concatenates labels with the following bytes without a separator or length prefix. So `(label, M) = ("SecMP-HX/1 init", "key…")` and `("SecMP-HX/1 initkey", "…")` hash to the same `m`. For HybridSign, the ML-DSA half binds the label separately through `ctx`, but the Ed25519 half does not. I found no actual collision in the protocol: HybridSign is only used with `"SecMP-HX/1 bundle"` and `"SecMP-TR/1 keychange"`, and each prefix pair is used in different primitive roles. `ref/tests/test_hkdf_labels.py::test_label_and_extra_info_split_is_not_unique` records the property.
**Question 1 (blocks hybridsign):** which labels may a hybridsign vector use? (A) only the two HybridSign labels of the spec; (B) any Appendix A label. **Choice: A.** The other labels are never HybridSign contexts, and an implementation may reasonably refuse them.
**Question 2 (design, non-blocking):** should the spec state the rule "labels of one primitive role are prefix-free", or frame labels with a length?
**Answer.** Q1: (A) — only `"SecMP-HX/1 bundle"` and `"SecMP-TR/1 keychange"`; implementations MUST refuse any other label (rev 2.2 §3.5). Q2: a real finding, fixed in rev 2.2 (ADR-035): the label set is now **prefix-free by rule**, with three renames — `"SecMP-INV/1"` → `"SecMP-INV/1 blob"`, `"SecMP-HX/1 init"` → `"SecMP-HX/1 initcell"`, and the `FETCH_MULTI` signature label is `"SecMP-Q/1 MFETCH"`. Appendix A carries the rule and both implementations carry a unit test that re-reads Appendix A and checks prefix-freeness (`ref/tests/test_labels_sizes.py` is the natural home). Your `labels.py` must be regenerated from the rev 2.2 spec.

## SQ-08 — ML-DSA-65 in HybridSign (§3.5), confirmation only

**Quote:** "`ML-DSA-65.Sign(sk_mldsa, m, ctx = label)`", §3 table "ML-DSA-65 (hedged)", SCHEMA `mldsa_seed` (32 B ξ), `rnd` (32 B hedge).
**Reading used by `ref/`:** pure ML-DSA, not HashML-DSA and not external-μ. It is FIPS 204 Alg. 2 with `M' = 0x00 ‖ |ctx| ‖ ctx ‖ m`, where `ctx` is the label's ASCII bytes and `m` is the 32-byte SHA-256 digest, followed by `ML-DSA.Sign_internal(sk, M', rnd)` with the supplied `rnd`. Keys come from `ML-DSA.KeyGen_internal(ξ)` of the final FIPS 204, which appends `k` and `l` to ξ. Checked against the ACVP "external / pure / hedged" vectors.
**Alternative:** HashML-DSA with SHA-256 (Alg. 4), because `m` is already a digest. I consider it excluded, since the spec would have to say "HashML-DSA". Please confirm.
**Answer: confirmed exactly as you read it.** Pure ML-DSA (FIPS 204 Alg. 2/3), `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ m` with `ctx` = the label's ASCII bytes and `m` the 32-byte SHA-256 digest, `Sign_internal(sk, M', rnd)` with the supplied `rnd`, keys from `KeyGen_internal(ξ)`. Not HashML-DSA. Rev 2.2 §3.5 now says so explicitly.

## SQ-09 — Where "wrong padding" is tested; MsgEncrypt length checks (§3.3)

**Quote:** SCHEMA negative list "wrong padding"; §3.3 "plaintext `P` (already padded to the fixed body length)"; §4.1 "padding … MUST be verified on decode".
**Problem.** MsgEncrypt never removes padding, so no msgencrypt input can fail because of padding. Padding is checked by the decoders (`Content` in §7.6 / D.5, `LinkDataV1`, the handshake `Outer`, frame plaintexts).
**Readings:** (A) wrong-padding cases belong to the `encodings` suite (M2) and to `tr`/`hx`, not to msgencrypt; (B) MsgDecrypt must also unpad and reject bad padding.
**Choice: A.** Reading B is not in §3.3.
**Related:** must MsgEncrypt/MsgDecrypt reject `|P| ≠ BODY_LEN` or `|C ‖ TAG| ≠ BODY_LEN + 32`? `ref/` would reject a wrong `C ‖ TAG` length, uniformly. A truncated input is rejected under either reading, so the vector outcome is the same.
**Answer: Reading A.** Wrong-padding cases belong to `encodings` (M2) and later `hx`/`tr`; removed from the M1 negative list. Rev 2.2 §3.3 adds: `MsgEncrypt` MUST reject `|P| ≠ BODY_LEN`, `MsgDecrypt` MUST reject `|C ‖ TAG| ≠ BODY_LEN + 32`, both with the uniform error. `SCHEMA.md` §4.3 rows 11, 12, 15, 16 cover these.

## SQ-10 — What the `fingerprint` input `iks` is (§6.2)

**Quote:** SCHEMA fingerprint "`iks` (2017 B encoded `IKSPublic`)"; §6.2 `fingerprint(iks) = SHA-256("SecMP-FP/1" ‖ encode(iks))`; §6.6 "well-formedness: decodable, `ik_dh` not low-order".
**Readings:** (A) `iks` is a well-formed `IKSPublic` built from real keys. `ver = 0x01`, the Ed25519 public key comes from an `ed_seed`, the ML-DSA-65 key from ξ, and `ik_dh` from an X25519 secret, all taken from the case stream. A Rust `fingerprint` that takes a typed, validated `IKSPublic` can then run every case. (B) `iks` is 2017 arbitrary bytes. Roughly half of all random 32-byte strings are not valid Ed25519 points, so a typed decoder would refuse such cases.
**Choice: A**, positive cases only. Does `fingerprint` also have negative cases (wrong `ver`, wrong length, low-order `ik_dh`), or do those belong to `encodings`?
**Answer: Reading A, positive cases only.** Inputs `ed_seed`, `mldsa_seed`, `dh_seed` (32 B each); outputs the encoded `iks` (2017 B) and `fp`. Negatives (wrong `ver`, wrong length, low-order `ik_dh`) belong to `encodings` (M2). `SCHEMA.md` §4.6.

## SQ-11 — X25519 public-key input handling beyond the all-zero check (§3, §3.2)

**Quote:** §3 table "X25519 (RFC 7748) | All-zero output MUST be rejected."
**Problem.** The spec does not say how inputs are handled when the top bit is set or the u-coordinate is non-canonical (u ≥ 2^255 − 19). RFC 7748 §5 says the top bit MUST be masked and non-canonical values accepted. Some libraries reject such inputs instead.
**Readings:** (A) RFC 7748 behaviour: mask, accept non-canonical u, reject only an all-zero output (which covers every low-order point after clamping); (B) reject non-canonical or top-bit-set inputs.
**Choice: A** (this is what `ref/` does, and RFC 7748 §5.2 vector #2, with the top bit set, passes). Note that the HybridKEM combiner hashes `pk_dh`/`pk_e` as transmitted bytes, so under reading A two encodings of one point give different `ss`. This only matters if SQ-04 adds vectors with crafted X25519 keys.
**Answer: Reading A — RFC 7748 behaviour**, now stated in the rev 2.2 §3 table: mask the top bit, accept non-canonical u, reject only the all-zero output (which covers every low-order input); public keys are hashed and transmitted as the received bytes. No M1 vectors use non-canonical X25519 inputs; low-order inputs are `SCHEMA.md` §4.4 rows 14–16 (reject).

## SQ-12 — Which key and signature checks belong to decoding (§3, §3.5, §6.6, App. D)

**Where:** §6.6 step 2 "`IKSPublic_I` (well-formedness: decodable, `ik_dh` not low-order)"; §3 X25519 row "the all-zero output MUST be rejected — this covers every low-order input"; §3.5 strict Ed25519; brief REF-M2 families "low-order X25519 points in `ik_dh`/`pk` fields" and "non-canonical or small-order Ed25519 points where a signature or verifying key is embedded".
**Problem.** The spec puts exactly one key check into decoding: `ik_dh` of `IKSPublic_I`. Every other key check happens when the key is used: the X25519 output, strict verification, the FIPS 203 Encaps input check. A negative `encodings` row is valid only if *every* conforming decoder rejects it, so the set of decode-time checks must be fixed. The brief names two families. Three neighbouring checks are not mentioned.
**Reading used for the written rows (SCHEMA-4.8 D-9, D-10):**
1. Every X25519 public-key field (`relay_dh_pk`, `e_c`, `pk_e1`, `e_r`, `ik_dh`, `spk_dh`, `opk_dh`, `ek_I`, `dh_pk`) rejects a low-order value and accepts anything else as received. Low-order means u after RFC 7748 decoding ∈ {0, 1, p − 1, the two order-8 values}. That is 14 byte strings, each checked against libsodium in `ref/tests/test_encodings.py`.
2. Every Ed25519 key field (`relay_sig_pk`, `ik_ed25519`, `recv_pk`, `send_pk`, `owner_pk`) rejects y ≥ p and the five small-order y. Every Ed25519 signature field, and the first 64 bytes of a HybridSig, rejects an R that fails the same rules and S ≥ L.

These are the §3.5 byte rules, which need no message. Any key that fails them is rejected at use anyway, so moving the check into decoding changes no end-to-end outcome.
**Open, rows withheld:** (a) an Ed25519 key or R whose y is canonical but not on the curve (RFC 8032 §5.1.3 decoding fails), e.g. y = 2; (b) an ML-KEM encapsulation key that fails the FIPS 203 §7.2 modulus check (`relay_kem_ek`, `ek_c`, `spk_kem`, `rpk_kem`, `opk_kem`, `ek_pq`); (c) an ML-DSA half of a HybridSig that fails FIPS 204 sigDecode (malformed hint).
**Proposed:** 1 and 2 as used. (a) Yes: a decoder that parses the key into a point, as most libraries do, rejects it anyway. (b) Yes, by the same argument as for X25519. (c) No: sigDecode is part of ML-DSA.Verify (FIPS 204 Alg. 8), libraries rarely expose it, and the signature is verified before use.
**Blocks:** 4 withheld rows: `ik_ed25519` with y = 2, RelayInfoV1 R with y = 2, and `spk_kem` and `ek_pq` each with a coefficient ≥ q. If the answer narrows 1 or 2 to fewer fields, the written X25519/ED25519 rows on the dropped fields are removed.
**Answer** (reviewer, 2026-09-29): **Adopted in full.** Decoders MUST reject low-order points in every X25519 field (`relay_dh_pk`, `e_c`, `pk_e1`, `e_r`, `ik_dh`, `spk_dh`, `opk_dh`, `ek_I`, `dh_pk`). Decoders MUST apply the §3.5 byte rules (canonical y < p, no small-order point, S < L) to every Ed25519 key (`relay_sig_pk`, `ik_ed25519`, `recv_pk`, `send_pk`, `owner_pk`) and to every Ed25519 signature (R, S), including the first 64 bytes of a HybridSig. (a) Yes: Ed25519 keys and R that are not on the curve reject. (b) Yes: every ML-KEM encapsulation key (`relay_kem_ek`, `ek_c`, `spk_kem`, `rpk_kem`, `opk_kem`, `ek_pq`) passes the FIPS 203 §7.2 modulus check at decode. (c) No: decoders MUST NOT run ML-DSA sigDecode at decode. All 84 written rows stand; the 4 withheld rows become rejects (`IKSPublic` `ik_ed25519` y = 2; `RelayInfoV1` sig R y = 2; `PrekeyBundle` `spk_kem` and `HeaderV1` `ek_pq`, each with a coefficient ≥ q). Spec evidence: §6.6 step 2 ("well-formedness: decodable, `ik_dh` not low-order") is the only key check the spec places at decode. Every other check named here is message-independent and already mandatory at use: §3 ("the all-zero output MUST be rejected — this covers every low-order input"), §3.5 ("Implementations whose library does less MUST add the missing checks on the encoded bytes before verifying"), §7.4 DHRatchet (`ML-KEM-768.Encaps(kem_r)` runs on receipt, so a bad `ek_pq` is already rejected in the receive path) and SCHEMA §4.4 row 17. Moving them to decode therefore changes no end-to-end outcome and fails earlier; the brief and SCHEMA §5 ("low-order `ik_dh`") already ask for it. ML-DSA sigDecode stays at use because it is part of ML-DSA.Verify (FIPS 204 Alg. 8) and the signature is verified before use. Spec: new "decoder obligations" bullet in §4.1 (ADR-039); without it a Rust decoder that accepted all of these rows would still be conforming.

## SQ-13 — `RelayRef.onion`: what the decoder checks (§5.3, D.3)

**Quote:** "`onion: [u8; 35] ; v3 onion service identity (decoded 56-char address) — REQUIRED`".
**Problem.** The 35 bytes are the base32-decoded v3 address. Tor defines it as `PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1]`, with `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[0..2]` and `VERSION = 0x03` (rend-spec-v3 §6). The spec does not say whether a decoder checks them.
**Readings:** (A) 35 opaque bytes; (B) decoding checks VERSION = 0x03 and the CHECKSUM; (C) B, plus PUBKEY must pass the D-10 Ed25519 key rules.
**Choice: B.** An `onion` that is not a v3 address can never be connected to, so it is malformed, and checking it at decode fails early like the other rules. C would additionally reject keys that Tor itself may accept, which I cannot verify from this spec. The positives build `onion` from a real Ed25519 key with a correct checksum and version, so they are valid under A, B and C. The checksum formula is checked in `ref/tests` against three published v3 addresses.
**Blocks:** 2 withheld rows (VERSION := 0x02; CHECKSUM byte flipped). No written row depends on this.
**Answer** (reviewer, 2026-09-29): **Reading B.** A decoder checks that the VERSION byte is 0x03 and that the CHECKSUM is valid (rend-spec-v3 §6, onion-address encoding: `PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1]`, `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[0..2]`). There is no Ed25519 rule on PUBKEY. Both withheld rows reject (`onion[34]` := 0x02; `onion[32]` ^= 0x01). Spec evidence: §5.3 already calls the field a "v3 onion service identity (decoded 56-char address)", an onion with a bad version or checksum can never be connected to, and §5.5 step 1 says "reject if … malformed". Reading C (the D-10 Ed25519 rules on PUBKEY) is not adopted: it would depend on Tor's own key-validation rules, which nobody has checked here. Spec: §5.3 cites rend-spec-v3 (ADR-039).

## SQ-14 — `RelayRef.direct`: host and port (§5.3, §8.1, D.3)

**Quote:** "`direct: Option<{ host_len: u16, host: [u8; host_len], port: u16, spki_sha256: [u8; 32] }>`"; §8.1 direct mode is TLS 1.3/TCP with rustls.
**Problem.** `host` has no character set and no bounds (0 bytes? up to 65535?), and nothing is said about port 0. rustls needs a DNS name or an IP address as the server name.
**Readings:** (A) opaque `host` of any length 0 … 65535, any port; (B) `host` is 1 … 253 bytes of printable ASCII (0x21–0x7E: a DNS name or an IP literal), port ≠ 0.
**Choice: B.** The exact host grammar could be tightened further to DNS or IP syntax.
**Blocks:** 4 withheld rows (host empty; 254 bytes; containing a space; port 0). The positives use host `relay.example.org` and port 443, valid under both readings. The written rows that change `host_len` are rejected under both readings; the generator checks this.
**Answer** (reviewer, 2026-09-29): **Reading B.** `RelayRef.direct.host` is 1..=253 bytes, each in 0x21..=0x7E, and `port` ≠ 0. All four withheld rows reject (host empty; host 254 × `a`; `host[5]` := 0x20; port := 0). Spec evidence: D.3 (`direct_present u8 ‖ [host_len u16 ‖ host ‖ port u16 ‖ spki_sha256[32]]`) and §8.1 (direct mode is TLS 1.3/TCP with rustls, certificate pinned by `RelayRef.direct.spki_sha256`) give widths only and say nothing about the host grammar, its bounds or the port. The rule is an exact byte rule that rejects only values that can never be connected to: rustls needs a DNS name or an IP address as the server name, and TCP port 0 is not usable. A full DNS/IP grammar may follow by ADR and would only turn more rows into rejects. Spec: D.3 states the host/port rule for `RelayRef.direct` (ADR-039).

## SQ-15 — `HandshakeBody.caps` "(= 0)" (§7.6, D.5)

**Quote:** §7.6 "**Handshake** (first message only): `Profile ‖ caps: u32 (= 0) ‖ routes: u8 count ‖ RouteDescriptor[]`".
**Readings:** (A) `caps` MUST be 0 in v1 and any other value rejects, like `HeaderV1.flags` (§7.5); (B) v1 senders write 0 and receivers ignore unknown bits, i.e. a capability field for v1.1.
**Choice: A:** §1.1 goal 4 ("no negotiation"), the `flags` precedent, and failing closed. A field named `caps` does suggest that B was intended, though.
**Blocks:** 2 withheld rows (`caps` := 1; := 0x80000000). The positives have `caps` = 0.
**Answer** (reviewer, 2026-09-29): **Reading A.** `caps` MUST be 0 in v1; any other value rejects, and D.5 writes `caps u32 (0)`. Both withheld rows reject (`caps` := 0x00000001 and := 0x80000000). Spec evidence: §7.6 fixes the value ("`caps: u32 (= 0)`"); D.5 dropped the "(= 0)"; §7.5 ("`flags` MUST be zero in v1 (reserved)") is the precedent; and §1.1 goals 4 ("No negotiation") and 6 ("Fail closed") exclude an ignored capability field. Spec: D.5 `caps u32 (0)` (ADR-039).

## SQ-16 — Body layouts given in §7.6 but missing from App. D (§4.1, §7.6, D.5)

**Quote:** §4.1 "All byte layouts are in Appendix D; a structure not listed there does not exist on the wire." §7.6 "**Batch**: `count: u8 ‖ AppMessage[]`", "**RouteUpdate**: `count: u8 ‖ RouteDescriptor[]`", "reassembled bytes are `inner_type: u8 ‖ inner_body`", "**Dummy**: empty body". D.5 lists the Handshake, KeyChange, Receipt and Control bodies, AppMessage and Fragment, but not these four.
**Reading used:** the §7.6 layouts are normative. The suite has `BatchBody`, `RouteUpdateBody`, `FragmentPayload`, and a Dummy Content with `body_len` = 0 (SCHEMA-4.8 D-7). One consequence is stated in D-6: a KeyChange body (5390 B) never fits a Content body (≤ 1689 B). A Content of type 0x05 therefore always rejects, and a KeyChange exists only inside a FragmentPayload.
**Question:** please add the four layouts to D.5 (or state that §7.6 governs), and confirm the consequence for type 0x05.
**Blocks:** nothing. The layouts themselves are unambiguous and generated under this reading.
**Answer** (reviewer, 2026-09-29): **§7.6 is normative.** ADR-039 adds the Batch (`count u8 ‖ AppMessage[]`), RouteUpdate (`count u8 ‖ RouteDescriptor[]`), reassembled-Fragment (`inner_type u8 ‖ inner_body`) and Dummy (empty body) layouts to D.5, with `count u8 (1..=255)` as in SQ-17, and states that Content type 0x05 (KeyChange) never appears unfragmented: an unfragmented 0x05 rejects. Spec evidence: §4.1 closes the wire format to App. D ("All byte layouts are in Appendix D; a structure not listed there does not exist on the wire"), so the four §7.6 layouts must be listed there; §7.6 already says that KeyChange is "always fragmented" (5390 B against a Content body of at most 1689 B), so the consequence for type 0x05 follows from the text. No withheld rows depend on this; the written Batch, RouteUpdate, FragmentPayload and Content rows built on it stand.

## SQ-17 — Lists with count 0 (§7.6, D.5)

**Where:** Batch `count`, RouteUpdate `count`, Handshake `route_count`, Receipt `count`.
**Problem.** The spec bounds FETCH_MULTI (`1..=32`) but gives no minimum for these four counts. A Handshake without a reply route leaves R unable to answer, a RouteUpdate without routes removes every route, and an empty Batch or Receipt carries nothing.
**Readings:** (A) at least 1 for all four; (B) 0 allowed.
**Choice: A.** I propose no minimum for `name_len`, `payload_len` or `arg_len`, because an empty display name, text or argument is plausible. No written row depends on those either.
**Blocks:** 4 withheld rows (each list emptied, count 0). The written rows "count := 0 (… kept)" reject under both readings (under B the kept elements become trailing bytes); the generator checks this.
**Answer** (reviewer, 2026-09-29): **Reading A.** Each of the four lists (Batch, RouteUpdate, Handshake routes, Receipt) has at least 1 element; D.5 and §7.6 write `count u8 (1..=255)`, and the Handshake `route_count` is likewise ≥ 1. All four withheld rows reject (BatchBody `messages` := []; RouteUpdateBody `routes` := []; HandshakeBody `routes` := []; ReceiptBody `msg_ids` := []). Spec evidence: an empty Handshake route list leaves R unable to answer, which contradicts §6.6 step 4 ("start sending to I's reply route"); an empty RouteUpdate strands the peer, and contact removal has its own Control code 1; an empty Batch or Receipt carries nothing, and cover traffic is Dummy's job; D.2 sets the precedent with `0x05 FETCH_MULTI  count u8 (1..=32)`.

## SQ-18 — Fragment fields and the reassembled payload (§7.6, D.5)

**Quote:** "**Fragment**: `msg_id [16] ‖ idx: u16 ‖ total: u16 (≤ 64) ‖ chunk`; reassembled bytes are `inner_type: u8 ‖ inner_body` and are processed as a Content of that type (so large `KeyChange`/`RouteUpdate`/`Batch` contents are fragmented like anything else)."
**Problems.** (1) Is `idx` counted from 0 (`idx < total`) or from 1 (`1 ≤ idx ≤ total`)? (2) Is the minimum `total` 1 or 2? (3) May `chunk` be empty? (4) Which `inner_type` values may a reassembled payload carry? In particular: a Dummy, a Handshake ("first message only"), or another Fragment?
**Choice:** (1) from 0, like the CONT `idx` (frame 1 is the command itself) and the handshake cells' `i`; (2) 1 ≤ `total` ≤ 64; (3) `chunk` ≥ 1 byte; (4) Batch, RouteUpdate, KeyChange, Receipt, Control.
**Blocks:** 6 withheld rows: `idx` = `total`; `idx` = 0 and (`total` = 1, `idx` = 0), both accepted under the proposal but rejected if counted from 1; empty `chunk`; inner types 0x03 and 0x00. The positives use `idx` 1 with `total` 2 or 3, and inner type KeyChange, which are valid under every reading. The written rows use `total` 0, 65 and 0xFFFF, and `idx` > `total`.
**Answer** (reviewer, 2026-09-29): (1) `idx` counts from 0, and `idx` < `total`. (2) 2 ≤ `total` ≤ 64: `total` = 1 is a second encoding of an unfragmented Content and violates canonicality (§4.1, "exactly one byte string per value"), so it rejects. This departs from the ref's 1 ≤ `total` ≤ 64; the withheld row "`total` = 1, `idx` = 0" becomes a reject. (3) `chunk` ≥ 1 byte. (4) `inner_type` ∈ {0x02, 0x04, 0x05, 0x06, 0x07}; 0x00, 0x01 and 0x03 reject, and the missing withheld row `FragmentPayload` `inner_type` 0x01 is added as a reject. Chunk sizing and cross-fragment consistency (`msg_id`, `total`) are reassembly rules (M3/M7), not encoding rules. Spec evidence: (1) the only other chunk index in the spec, §6.5 `cell_i` (i = 0, 1, 2), counts from 0; (2) an honest sender fragments only bodies over 1689 B, and those always need at least 2 chunks of at most 1669 B; (4) 0x01 is excluded because a Handshake is a single-cell `first_msg` (§6.5), 0x03 because nesting would make reassembly recursive, and 0x00 because a Dummy carries nothing. Of the 6 withheld rows, `idx` = `total`, `total` = 1 with `idx` = 0, empty `chunk`, `inner_type` 0x03 and `inner_type` 0x00 reject; `idx` = 0 with `total` = 2 is valid under (1) and becomes an accepted case (see the SCHEMA-4.8 corrections).

## SQ-19 — AppMessage payloads and Control arguments have no layout (§7.6)

**Quote:** "`AppMessage { msg_id [16], kind: u8 (1 text, 2 attachment-inline, 3 view-once-text, 4 reaction, 5 edit, 6 delete), expire_after: u32, payload_len: u16, payload }`. Text ≤ 16 KiB UTF-8; inline attachments ≤ `MAX_MSG_BYTES`." and "**Control**: `code: u8 ‖ arg_len: u16 ‖ arg` — codes: 1 contact-removed, 2 session-reset-request."
**Problem.** Kinds 2 and 4–6 have no payload layout: which message does a reaction, edit or delete refer to, and what metadata does an inline attachment carry? The two control codes have no argument layout. It is also unclear whether "Text ≤ 16 KiB UTF-8" is a decode check.
**Reading used:** at the encoding layer, `payload` and `arg` are opaque length-prefixed bytes (SCHEMA-4.8 D-12). The positives are chosen to stay valid under any later layout: text kinds 1 and 3 with ASCII text, and Control with `arg_len` 0.
**Blocks:** nothing in `encodings`; the application layer needs the layouts. Kinds 2, 4, 5 and 6 get positive rows once their payloads have a layout.
**Answer** (reviewer, 2026-09-29): **Opaque in `encodings`.** `AppMessage.payload` and `ControlBody.arg` are opaque length-prefixed bytes (`payload_len u16 ‖ payload`, `arg_len u16 ‖ arg`). Their layouts, and the UTF-8 and 16 KiB checks for text, come in an application-layer ADR before M7. The asymmetry to `Profile.name` (strict UTF-8, checked at decode) is accepted explicitly. Spec evidence: §7.6 defines no layout for the payloads of kinds 2 and 4–6 or for the Control `arg`, and states "Text ≤ 16 KiB UTF-8" without saying that it is a decode check; nothing on the wire depends on the layouts, and the written positives (text kinds 1 and 3 with ASCII text) stay valid under any later layout. No withheld rows depend on this.

## SQ-20 — Weisung REF-M2-1 addition 1 ("top-level structure") against App. D (§4.1, D.1, D.2, D.5, §9.8)

**Quote (addition 1):** "a top-level structure is one that is the first thing parsed from a transport unit — the D.1 records, the D.2 frame plaintext, the D.3 invitation / relay reference / link data, the D.4 handshake envelope and the D.5 cell. Nested bodies (Content bodies, RouteDescriptor, AppMessage, Fragment payload, …) carry no `ver`; their version is the enclosing structure's."
**Problem.** Read as a layout rule, this contradicts App. D, which says "Structures are listed with their exact field order; nothing else is on the wire", in three places:
1. `RouteDescriptor` is listed as a nested body without `ver`, but D.5 (`RouteDescriptor = ver ‖ kind u8 ‖ len u16 ‖ blob`) and §9.8 (`RouteDescriptor { ver, kind: u8, len: u16, blob }`) give it one.
2. The D.2 frame plaintext (`op ‖ cmd_seq ‖ fields ‖ pad`) and the D.5 Cell (`hdr_nonce ‖ hdr_ct ‖ body_ct ‖ tag`) are listed as top-level, but neither has a `ver`. The D.1 records start with `len ‖ type`; HELLO's `ver` is its last byte.
3. Conversely, `IKSPublic`, `PrekeyBundle`, `RelayRef`, `HeaderV1` and `Content` carry their own `ver` in App. D also where they are nested (in LinkDataV1, Inner, KeyChange, InvitationV1, RelayQueue, the cell).

**Reading used:** point 2 cannot be a layout change (frames would need a new byte, and nothing else suggests one), so addition 1 is read as a description of §4.1, not as a change to App. D. Every layout stays exactly as App. D rev 2.2 has it; this is REF-M2 reading 3, which the reviewer confirmed. `RouteDescriptor` keeps its `ver`, and the written rows `RouteDescriptor ver := 0x00` / `:= 0x02` and `routes[…].ver := …` stand.
**Question:** please confirm that App. D governs, and word §4.1 in rev 2.3 so that it matches App. D (for example: "every structure that App. D gives a `ver` field checks it; …").
**Blocks:** nothing is withheld. If `RouteDescriptor.ver` is really meant to go, these rows change (bytes, and some rows disappear): positives 53, 56, 67–69, 71–72, and negatives 513–514, 554–570, 579–602 (50 rows: the RouteDescriptor, RouteUpdateBody and HandshakeBody rows and the Content rows built on them).

**Answer** (reviewer, 2026-09-29, Weisung REF-M2-2): **App. D governs.** Addition 1 was a description of §4.1, not a layout rule, and its wording was wrong on two points (RouteDescriptor; frame plaintext and Cell as "top-level"). Every layout stays exactly as App. D rev 2.2 lists it: `RouteDescriptor` keeps its `ver`; the D.2 frame plaintext and the D.5 Cell carry no `ver`; `IKSPublic`, `PrekeyBundle`, `RelayRef`, `HeaderV1` and `Content` carry theirs also where nested. §4.1 in rev 2.3 will read: "Every structure that App. D gives a `ver` field checks it on decode (reject on any other value); a structure without a `ver` field in App. D takes its version from the enclosing structure or the transport unit." The 50 rows stand unchanged.

## SQ-21 — The content of the `op` and `mode` strings inside `value` (SCHEMA §1; correction 1)

**Quote (correction 1):** "`op` and `mode` are JSON strings (SCHEMA §1), everywhere they occur in `encodings.json`: the case-level fields and also `value.op` (the frame opcode) and `value.mode` (LINK_GET), which the proposal wrote as JSON numbers."
**Problem.** The correction fixes the JSON type but not the string. Possible choices: the D.2 name (`"QUEUE_NEW"`), the byte in hex (`"01"`), or the decimal (`"1"`).
**Reading used:** names, as with the M1 `op`/`mode` values, which are names (`"encaps"`, `"extract-expand"`). `value.op` is the D.2 command name (`"QUEUE_NEW"` … `"PING"`, `"OK"` … `"ERR"`; `"CONT"` in both directions, the structure name says which). `value.mode` is `"consume"` (0) or `"owner-status"` (1), in the style of the hkdf `mode` values and §9.4's "Owner-status mode". SCHEMA §4.8 ("Value representation") and SCHEMA §1 now state this.
**Blocks:** nothing. Only the JSON representation of 25 positive rows depends on it (the 24 frame rows and `Signed/LINK_GET`); the bytes do not. Another spelling is a mechanical change.

**Answer** (reviewer, 2026-09-29, Weisung REF-M2-2): **Keep the names used.** `op` holds the D.2 command name exactly as App. D spells it (e.g. `"QUEUE_NEW"`, `"OK_SEND"`, `"CELLR"`); `mode` holds `"consume"` / `"owner-status"`. SCHEMA §1 records this as the normative spelling. No row's JSON representation changes beyond what REF-M2-1 already wrote, and no byte changes.

---

## Readings adopted without a question (for the reviewer to veto)

**Reviewer: all readings in this section are confirmed.** (ML-KEM `d ‖ z`; combiner `V` raw ASCII; SHA3-256 inner hashes; MsgEncrypt key split and counter 0; CAEAD split, `COM ‖ C` without `N`, COM compared before the AEAD, one uniform error; pure Ed25519 over `m`; `sig_ed ‖ sig_mldsa`; empty salt ≡ `0^32`; `info = label ‖ context`; SAS exactly as described.)

These seemed unambiguous. They are listed because an identical wrong reading on both sides would pass the byte-for-byte comparison.

- **§3 table, ML-KEM seeds:** the 64-byte seed is `d ‖ z` (d first), fed to `ML-KEM.KeyGen_internal(d, z)` (FIPS 203 Alg. 16). Encaps is `ML-KEM.Encaps_internal(ek, m)` (Alg. 17) after the §7.2 type and modulus checks.
- **§3.2 HybridKEM:** `V` is appended as raw ASCII with no length. Both inner hashes are SHA3-256. `pk_dh` is the recipient's static X25519 key and `pk_e` the ephemeral one, both as transmitted bytes. The X25519 secrets are 32 raw bytes, clamped inside X25519 (RFC 7748 §5).
- **§3.3 MsgEncrypt:** `K_enc = okm[0:32]`, `K_mac = okm[32:64]`, `IV = okm[64:76]`. The ChaCha20 block counter starts at **0** (not 1 as in the RFC 8439 AEAD). `TAG = HMAC(K_mac, AD ‖ C)` with no length encoding. The output is `C ‖ TAG`.
- **§3.4 CAEAD:** `K_enc = okm[0:32]`, `COM = okm[32:64]` from HKDF-Expand with `PRK = K` directly (no Extract). The output is `COM ‖ C` and does not include `N`. Open compares `COM` in constant time before calling the AEAD, and both failures raise the same error.
- **§3.5 HybridSign:** Ed25519 is pure RFC 8032 Ed25519 over the 32-byte `m` (not Ed25519ph/ctx). `sig = sig_ed (64) ‖ sig_mldsa (3309)`.
- **§3 table HKDF:** an empty salt equals `0^32` (RFC 5869 §2.2); `info = label ‖ context` with no separator.
- **§6.7 SAS:** `iter` applies SHA-256 exactly 5200 times, starting from `h = fp`, and every round hashes `"SecMP-SAS/1" ‖ h ‖ fp`. `0..6` and `[5k..5k+5]` are half-open, so the six groups use bytes 0–29 of the 32-byte result. `int_be` is big-endian. Each group is zero-padded to 5 digits. "sorted_lexicographically" is ascending, and for equal-length digit strings this equals numeric order. `half_a = half(fp_a)`, `half_b = half(fp_b)`. The cross-checks 6 × 5 = 30 digits, 2 × 30 = 60 = `SAS_DIGITS`, and 12 display groups of 5 are consistent.

## Readings adopted without a question — SCHEMA rev 2 §4 (for the reviewer to veto)

None of these blocks a suite. Item 1 is the one where a different reading changes bytes; if the Rust side differs, the comparison will show it exactly in the rows named there.

**Reviewer (2026-09-28): all seven readings are confirmed as the intended meaning of SCHEMA rev 2 §4.** In particular (1): a derived negative case always draws from its *own* stream and takes only the referenced row's shape (lengths, label); the honest object is computed from that stream and then manipulated. (3): the decapsulator hashes its own recomputed `ek_kem`/`pk_dh` and the received (manipulated) `pk_e`/`ct_kem` bytes. (7): the Rust side is bound to the same four byte-level rules (`S < L`, canonical `A` and `R`, no small-order `A` or `R`) independently of what its library checks. These readings bind the Rust implementation; no schema change is needed.

1. **Stream of a negative row "derived from row r".** The §4 preamble says "Manipulations apply to the honest value derived from the case's **own** stream". So case *i* always draws from its own `stream_i`, and row *r* supplies only the shape (lengths, label). The stream is consumed exactly as row *r* would consume it, the honest object is computed, and then the manipulation is applied. Consequences:
   - caead rows 9–17 consume `k, n, ad, p`.
   - msgencrypt rows 9–15 consume `mk, ad, p`; row 16 consumes `mk`, `ad` (0), `p` (1709).
   - hybridkem decaps rows 9–16 and encaps-to rows 17–19 consume `dk_seed, sk_dh, m, sk_e` ("stream as the referenced row"), although decaps rows list only `dk_seed, sk_dh, pk_e, ct_kem` and encaps-to rows list `ek_kem, pk_dh, m, sk_e`. So row 9's honest `ss` is the `ss` of its own encapsulation, not row 1's.
   - hybridsign rows 9–17 consume `ed_seed, mldsa_seed, rnd, msg (32)` and sign with row 3's label.
   - The only row that reuses another row's *values* is sas row 10, because its table text says so ("swapped relative to row 1", "same safety_number as row 1").
2. **sas row 9:** `fp_a` = the first 32 bytes of `stream_9`, and `fp_b := fp_a`. No further bytes are drawn.
3. **hybridkem decaps, combiner inputs:** `ek_kem` and `pk_dh` in the combiner are the decapsulator's own public keys, recomputed from `dk_seed` and `sk_dh`. `pk_e` and `ct_kem` are hashed as the (manipulated) bytes received.
4. **hybridsign `verify`:** this is the result of `HybridVerify` over the row's own `pk_ed`, `pk_mldsa`, `label`, `msg` and `sig`, i.e. always `true`. Negative rows list `label` as a JSON string like the positives.
5. **hkdf-labels rows 8/9:** these list `"salt": ""`. HKDF-Expand additionally requires `|PRK| ≥ 32` (RFC 5869 §2.3). No vector is affected.
6. **Uniform errors:** HybridVerify refuses a non-HybridSign label with the same `Reject` as a failed signature (row 12). HybridSign refuses one as a caller error. MsgEncrypt rejects `|P| ≠ BODY_LEN` with the uniform `Reject` (row 16).
7. **Strict Ed25519 (§3.5), libsodium 1.0.20-stable in PyNaCl 1.6.2:** every rule that can be isolated is enforced by `crypto_sign_open` itself: `S < L`, `A` not of small order (all eight torsion points, their `y + p` encodings, and the x-sign-bit variants), `R` not of small order, and `A`/`R` canonical. Each probe satisfies the cofactorless equation under an independent pure-Python model, so it isolates a single rule (`ref/tools/probe_ed25519_strict.py`, `ref/tests/test_hybridsign.py`). A non-canonical encoding of a point outside the torsion subgroup cannot be isolated, because that needs a point with y < 19 and a known discrete logarithm; both layers still reject it. The wrapper nevertheless carries all four rules as byte-level pre-checks (`primitives.ed25519_strict_precheck`). That keeps `ref/` independent of libsodium build options: an `ED25519_COMPAT` build checks only the top bits of S.

## Noted for later milestones (not blocking M1)

- **L-1 (D.2 vs §9.2/D.6) — fixed in rev 2.2:** D.2 comments now carry the `"SecMP-Q/1 "` prefix; D.6 governs.
- *(original note)* **L-1 (D.2 vs §9.2/D.6):** the D.2 comments write the signed data as `"QUEUE_NEW"‖sess_id‖…` without the `"SecMP-Q/1 "` prefix, while §9.2, D.6 ("always") and Appendix A include it. I read D.6 as governing. The D.2 comments could be aligned.
- **L-2 — fixed in rev 2.2:** Appendix A lists the nine `SecMP-STORE/1 <table>` labels explicitly.
- *(original note)* **L-2 (Appendix A, `SecMP-STORE/1 <table>`):** the table names are defined outside this document (`02-architecture.md` §4.2). No STORE label can be written from this spec alone.
- **Arithmetic check:** every size in Appendix B, and the frame, cell and handshake layouts they come from, were added up again from their field lists. All of them agree (`ref/tests/test_labels_sizes.py::test_composite_sizes_add_up`), as do the §10.2 bandwidth figures and the §7.4 "≈ 121 days" figure.
- **L-3 (§9.1 vs §9.3 / D.2, for M5):** §9.1 says "The relay MUST answer a `FETCH` whose `ack ≥ next_cell_id` with `ERR_MALFORMED`". But §9.3 answers a FETCH with "exactly `F` `CELLR` frames; errors are signalled in `CELLR.present` (… 4 = MALFORMED)", and D.2 says "A relay MUST answer every request with the exact number of frames the table specifies". Is a stale ack answered with one ERR frame or with F CELLR frames with `present` = 4? This does not affect `encodings`.
- **L-4 (§4.2 "PERIODS … tunable … finalised in M6", ADR-018):** the `encodings` rows that use period values (`inv_period_s` := 30, the positives with 10/20/40/80, …) are frozen with PERIODS = {10, 20, 40, 80}. If M6 changes PERIODS, these rows change with it.
- **L-5 (D.2):** a LINKR with `present` = 1 and `consumed` = 1 has no stated meaning (a consumed one-time blob is deleted), and a CELLR with `present` = 1 and `cell_id` = 0 contradicts "cell_id … monotonically increasing from 1" (§9.1). Decoders accept both, since D-5 and D-7 check each field on its own. No vector uses either.

## Readings adopted without a question — REF-M2 (for the reviewer to veto)

These concern the `encodings` suite and its proposal `SCHEMA-4.8-encodings.md`, whose "decoding contract" D-1 … D-12 states them in full. An identical wrong reading on both sides would pass the comparison, so the ones that decide a row's outcome are listed here.

1. **Decode = structural validation of exactly one encoding.** Leftover or missing bytes reject. Signatures, MACs, AEAD tags, fingerprints, timestamps and `cmd_seq` order are not checked (D-1, D-12).
2. **D.1 `Record = len ‖ body`:** `len` = |body| including the type byte. Each record decoder expects its own type, and `len` must be that type's fixed body size (HELLO 7, RELAYINFO 1742, HS1 2854, HS2 1154).
3. **`ver` exactly where App. D lists it.** HELLO: after the magic; HS1/HS2: after the type byte. Frames, Profile, AppMessage, Fragment and the Content bodies have none. §4.1's "every top-level structure starts with `ver`" is read as describing App. D, which governs.
4. **Padding** is ISO/IEC 7816-4 (at least the 0x80 marker, then only zeros) for frames (§8.4), Content, LinkDataV1 and Outer. Every payload length here is determined by the fields, so parsing forward and checking the pad at the end is equivalent to unpadding first.
5. **Boolean u8 fields** (`one_time`, LINKR `present`/`consumed`) accept only 0x00 and 0x01, like Option presence bytes. §4.1's canonical-encoding rule (decode-then-encode reproduces the input) requires this.
6. **Enumerations are closed** (Record type, `op` per direction, `InvitationV1.kind`, `Content.type`, `AppMessage.kind`, Receipt `kind`, Control `code`, ERR `code`, `inner_type`), except `RouteDescriptor.kind` (§9.8 "MUST ignore unknown kinds"). An unknown-kind descriptor is accepted and kept with its opaque blob, so re-encoding is canonical; its `ver` is still checked. The v1.1 kinds 0x02/0x03 are not used by any row, because a v1 decoder may or may not validate their layout.
7. **Content decoding includes the typed body.** A Dummy's body must be empty; Content type 0x05 always rejects (SQ-16).
8. **CONT (0x7F and 0xFF):** `idx` ∈ {1, 2} and `data` exactly 4100 B. LINK_PUT and LINKR are v1's only multi-frame messages (D.2).
9. **CELLR is decoded with its request as context.** D.2's "For FETCH, rid is zero on present 0/1" needs to know the request. With FETCH_MULTI, the `rid` of `present` = 1 is not checked.
10. **LINK_GET:** `mode` ∈ {0, 1}; `mode` = 0 requires `sig` = 0^64 ("zeros when mode = 0"; canonicality). A zero `sig` with `mode` = 1 fails D-10 (R = 0 has small order).
11. **HandshakeCellPlaintext:** `total` = 3 ("total u8 (=3)"), `i` ∈ {0, 1, 2}.
12. **`Profile.name`:** `name_len` counts bytes (a u8 cannot count 64 four-byte characters), and the name must be strict UTF-8 (RFC 3629).
13. **D.6:** each FETCH_MULTI entry signs `"SecMP-Q/1 MFETCH" ‖ sess_id ‖ cmd_seq ‖ rid ‖ ack` (D.2's comment; the entry count is not signed). LINK_PUT signs SHA-256 of the whole 12360-byte blob. `cmd_seq` is a u32 BE, as in the frame. D.6 rows are encode-only.
14. **Opaque structures** (`Cell`, `HandshakeCell`, `LinkBlob`, `inner_ct`) check their length only. `ik_mldsa65` has no invalid encodings (every 10-bit `t1` coefficient is in range), and neither has an ML-KEM ciphertext.
15. **Vector-file shape** (SCHEMA-4.8 "Value representation"). The only departures from SCHEMA §1 are nested objects and arrays inside `value` and the ASCII fields `structure` and `context`. `ref/secmp_ref/vectorfile.py` was extended for them; the M1 files regenerate byte for byte.
16. **Stream derivation** (SCHEMA-4.8 "Input derivation"). Keys and signatures are derived from seeds. Ciphertexts, MACs, hashes, ids and tokens are raw stream bytes. Free integers are big-endian stream bytes. Constrained values come from the table. Text is the lowercase hex of stream bytes, because random bytes are not valid UTF-8. A signed frame's `sess_id` and the signer seed are drawn after the frame's fields.

## SCHEMA-4.8 corrections (reviewer, 2026-09-29)

**Answer** (reviewer, 2026-09-29): the case table `SCHEMA-4.8-encodings.md` is adopted as SCHEMA §4.8 (ADR-039) with the corrections below, which `ref/` applies before `vectors/encodings.json` is frozen. All eight answers above are settled, so the file is renumbered and re-seeded once, now.

1. **`op` and `mode` are JSON strings** (SCHEMA §1), everywhere they occur in `encodings.json`: the case-level fields and also `value.op` (the frame opcode) and `value.mode` (LINK_GET), which the proposal wrote as JSON numbers.
2. **`"schema": 3`.** The file header becomes `"schema": 3` because of the new JSON shapes (nested objects and arrays inside `inputs.value`; the ASCII strings `structure` and `context`), and SCHEMA §1 records this.
3. **The 22 withheld rows are written:** 21 as rejects (the 4 of SQ-12, the 2 of SQ-13, the 4 of SQ-14, the 2 of SQ-15, the 4 of SQ-17, and `idx` = `total`, `total` = 1 with `idx` = 0, empty `chunk`, `inner_type` 0x03 and 0x00 of SQ-18) and one as an accepted case: `Fragment` with `idx` = 0 and `total` = 2 is valid under SQ-18 (1). SCHEMA §1 has no accepting `decode` shape, so that row is written as a positive `encode` row.
4. **Rows to add** (rejects unless stated):
   - `FragmentPayload` `inner_type` 0x01 (Handshake), the missing withheld row of SQ-18 (4);
   - LINK_GET, mode 1: the R rules of the signature, one row for R with y ≥ p and one for R with a small-order y (until now only S + L was tested);
   - a `ControlBody` positive with a non-empty `arg`, and with it the LEN negatives that the single positive with `arg_len` 0 made impossible (`arg_len` − 1; `arg_len` := 0 with the argument kept);
   - positives with counters and lengths at their maximum values (this confirms the ref's reading of the brief's "counter overflow" family as a field at its maximum value): exact u32 and u64 big-endian round trips, e.g. `cmd_seq`, `ack`/`cell_id`, HeaderV1 `pn`/`n`, Content `seq`, and length fields at their maxima.
5. **Renumber and re-seed once.** Ids are contiguous with the negatives after the positives (SCHEMA §1) and `seed_i` follows from the new index (SCHEMA §2). Row numbers quoted in the proposal, in the ref's questions and in earlier notes refer to the proposal before this renumbering.

## Applied: Weisung REF-M2-1 (ref/, 2026-09-29)

- **Answers SQ-12 … SQ-19** are implemented as plain decoder rules (SCHEMA §4.8 D-1 … D-13). The lenient mode and the `sqNN-` check names are gone. SQ-18 (2), `total` ≥ 2, replaces the proposal's `total` ≥ 1.
- **Correction 1:** `value.op` and `value.mode` are names. The spelling is recorded as SQ-21.
- **Correction 2:** `encodings.json` has `"schema": 3` (`vectorfile.SUITE_SCHEMA`); the M1 files keep 2.
- **Correction 3:** the 22 withheld rows are written: 21 rejects, and `Fragment` `idx` 0 / `total` 2 as a positive.
- **Correction 4 adds:**
  - `FragmentPayload` `inner_type` 0x01;
  - two LINK_GET mode-1 R rows (y = p + 3; order 8);
  - a `ControlBody` positive with `arg_len` 16, and from it `arg_len` − 1 and `arg_len` := 0 (arg kept);
  - positives at the maximum values: `cmd_seq`, `ack`, `cell_id`, `evicted_id`, `pn`, `n`, `seq`, `ts`, `kid`, `valid_until`, `expires`, `expire_after`, `host_len` 253 with port 65535, `payload_len`, `arg_len`, RouteDescriptor `len` 65535, Receipt `count` 255, and Fragment `idx` 63 / `total` 64.
- **Correction 5:** renumbered and re-seeded once.
- **Addition 1** is read against App. D; see SQ-20.
- **Addition 2:** modulus-check rows for `relay_kem_ek`, `ek_c`, `rpk_kem` and `opk_kem`. With `spk_kem` and `ek_pq` from the withheld rows, every ML-KEM encapsulation-key field now has one.
- **Addition 3:** `SCHEMA.md` is rev 3. §1 records `"schema": 3`, the `op`/`mode` strings and boolean `u8` fields as 0/1; §3 lists the tag `enc`; §4.8 points to `SCHEMA-4.8-encodings.md`.
- **Result:** 85 positive + 547 negative = 632 rows. `vectors/encodings.json` SHA-256 is `9abd63d7ea5c35c0a9731f91ab7584de57890de728f8799ad3dae30f380131b8`. It was written twice, from fresh processes, byte-identical. The M1 files are unchanged.
- **Rows whose outcome changed:** only the 22 formerly withheld rows, now written. One of them differs from the proposal's reading: `Fragment` `total` := 1, `idx` := 0 was proposed as accept and now rejects (SQ-18 (2)). Every case of the proposal's file (`f2166aa9…`) was decoded again under the answered rules, and none changed outcome.
