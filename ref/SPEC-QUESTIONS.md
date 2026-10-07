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
| SQ-22 | m05 "Batch L=1689" does not fit one cell | `tr`: 2 cases (written with L = 1665) | answered 2026-09-30 |
| SQ-23 | N9 "sealed under the sender's `nhk_s`" | `tr`: 1 case (written under the m16 key) | answered 2026-09-30 |
| SQ-24 | The state-digest label is not in App. A | — (confirmation) | answered 2026-09-30 |
| SQ-25 | Does the invitee check the inviter's expiry bounds (`expires` ≤ creation + 30 d, `spk_expiry` ≥ `expires`)? | — (no `hx` case depends on it) | answered 2026-09-30 |
| SQ-26 | A request with `cmd_seq` ≤ `last`: frame count and timing for FETCH, FETCH_MULTI, LINK_GET, LINK_PUT | — (no `link` case depends on it) | answered 2026-10-07 |
| SQ-27 | Frames that arrive while a LINK_PUT waits for its CONT frames | — (no `link` case depends on it) | answered 2026-10-07 |
| SQ-28 | FETCH_MULTI with more entries in error than `F_M`, and a repeated `rid` | — (no `link` case depends on it) | answered 2026-10-07 |
| SQ-29 | What "a route of a known kind" means for a Handshake content (§6.5 rev 2.5, §9.8) | — (R18 uses kind 0x7F) | open (2026-10-07) |

**State 2026-09-28 (brief REF-M1):** all answers applied; `BLOCKED_BY` is empty; the eight M1 files are written to `vectors/`. No new question was raised by the rev 2.2 spec or SCHEMA rev 2. The readings applied to the new SCHEMA §4 tables are listed at the end ("Readings adopted without a question — SCHEMA rev 2 §4") for the reviewer to veto.

**State 2026-09-29 (brief REF-M2):** `vectors/encodings.json` is written from the case-table proposal `SCHEMA-4.8-encodings.md` (71 positive, 517 negative rows). SQ-12 … SQ-19 are new. None blocks the suite, so `BLOCKED_BY` stays empty. Every row whose outcome depends on an answer is **withheld**: 22 rows, listed in SCHEMA-4.8 with their outcome under the proposed reading. Every written row holds under every reading: the generator decodes each row twice, once with the proposed readings and once with the most permissive reading of every open question, and requires the same result both times. The M2 readings adopted without a question are listed at the end ("Readings adopted without a question — REF-M2").

**State 2026-09-29 (Weisung REF-M2-1):** every answer to SQ-12 … SQ-19 and every SCHEMA-4.8 correction is applied (see "Applied: Weisung REF-M2-1" at the end). The file is renumbered and re-seeded once: 85 positive and 547 negative rows, `"schema": 3`. No row is withheld any more, and the generator's lenient mode is gone. Applying the Weisung raised two questions. Neither blocks a row, because the file follows App. D and SCHEMA §1 literally where they apply: SQ-20 (addition 1 against App. D) and SQ-21 (the content of the `op`/`mode` strings).

**State 2026-09-30 (brief REF-M3):** spec rev 2.3; SCHEMA is rev 4, with the §4.9 proposal `SCHEMA-4.9-tr.md`. `vectors/tr.json` is written: 96 cases (1 init, 40 send, 40 recv, 2 advance, 13 recv-reject). There are three new questions, and none blocks the suite, so `BLOCKED_BY` stays empty. SQ-22 (the length of m05) touches 2 cases and SQ-23 (the key of N9) touches 1; their bytes follow the pinned reading, and no state digest depends on either. SQ-24 is a confirmation. The readings adopted without a question are listed at the end ("Readings adopted without a question — REF-M3"). The M1 and M2 files are unchanged.

**State 2026-09-30 (brief REF-M4):** spec rev 2.3, unchanged; SCHEMA is rev 5, with the §4.10 proposal `SCHEMA-4.10-hx.md`. `vectors/hx.json` is written: 28 cases (8 positive, 8 `invitee-reject`, 12 `respond-reject`), `"schema": 5`. There is one new question, SQ-25, and it blocks nothing: no case depends on it, so `BLOCKED_BY` stays empty. The readings adopted without a question are listed at the end ("Readings adopted without a question — REF-M4"). The ten earlier files are unchanged.

**State 2026-09-30 (Weisung REF-M4-1):** readings 1–15 are confirmed and SQ-25 is answered (reading A). V9 (`hx-0029`, `ld-bad-sig-ed`) and R13 (`hx-0030`, `first-msg-not-handshake`) are appended after R12, so no earlier index or seed moves: 30 cases (8 positive, 9 `invitee-reject`, 13 `respond-reject`). Cases `hx-0001` … `hx-0028` are byte-identical to the REF-M4 file. No open questions.

**State 2026-10-02 (brief REF-M5):** spec rev 2.3, unchanged here; SCHEMA is rev 6, with §4.11 `SCHEMA-4.11-link.md` (the reviewer's table, regenerated from `ref/secmp_ref/link_cases.py`). `vectors/link.json` is written: 86 cases (27 positive, 23 command-error, X1, 8 RelayInfo, 11 `hs1-reject`, 4 `hs2-reject`, 12 `frame-reject`), `"schema": 6`. The reviewer's readings OPEN-1 … OPEN-13 and (a)–(g) are implemented as given; they answer the ref-log notes L-3 (OPEN-7) and L-5 (OPEN-11). There are three new questions, SQ-26 … SQ-28. None blocks a case: each concerns a relay behaviour that no case exercises, so `BLOCKED_BY` stays empty. The readings adopted without a question are listed at the end ("Readings adopted without a question — REF-M5"). The eleven earlier files are unchanged.

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

## SQ-22 — m05 "Batch L=1689" does not fit one cell (brief REF-M3; §7.6, D.5)

**Quote (brief):** "2. B→A m04 Batch L=100, m05 Batch L=1689, m06 Dummy" and "*Batch* = `count = 1 ‖ AppMessage{ msg_id (16, stream), kind = 1, expire_after = 0, payload_len = L, payload (L, stream) }`". **§7.6:** "Content (padded to 1710) { ver: u8, type: u8, seq: u64, ts: u64, body_len: u16, body } ; body ≤ 1689 B".
**Problem.** A Batch body with one AppMessage is 1 + 16 + 1 + 4 + 2 + L = 24 + L bytes. With L = 1689 the body is 1713 B, which is more than 1689. The Content cannot be encoded: its 20-byte header plus the body plus at least the 0x80 marker exceed `BODY_LEN`. The possible readings are (A) L = 1665, the largest payload of a one-cell Batch (`body_len` = 1689, so the brief meant a maximal body); (B) `body_len` = 1689, which is the same bytes as (A); (C) m05 is fragmented. (C) contradicts the transcript, in which m05 is one message and one cell: fragmenting would add messages and shift m06 … m40.
**Reading used:** (A)/(B): **L = 1665**. The Content is then exactly 1709 B, so the padding is the 0x80 marker alone.
**Blocks:** nothing is withheld. Only tr-0013 (send m05: `payload`, the stream position of `hdr_nonce`, `content`, `cell`) and tr-0017 (recv m05: `content`) depend on it. No state digest does, because the Content bytes never enter the state.
**Answer** (reviewer, 2026-09-30, Weisung REF-M3-1): the brief's "L = 1689" was the reviewer's slip (1689 is the Content body limit, not the payload); L = 1665 (body filled exactly: 24 + 1665) is the reading, as the §4.9 table says.

## SQ-23 — N9 "sealed under the sender's `nhk_s`" (brief REF-M3; §7.4)

**Quote (brief):** "N9 `step-without-new-dh`: before A's `recv m16` — a header sealed under the sender's `nhk_s` carrying `dh_pk = A.dh_r` (the old key), `pn`/`n` as m16, `ek_pq`/`ct_pq` as m16; rejected before any KDF."
**Problem.** At that point B has already stepped (on m14). B's `hk_s` is the header key of the chain m16–m17, which A holds as `nhk_r`. B's `nhk_s` is the key of B's *next* chain, and A does not hold it yet. Sealed under the literal B `nhk_s`, the header opens under none of A's keys (the skipped hks, `hk_r`, `nhk_r`). N9 would then test "no header key opens", like N8 and N13, and would never reach the §7.4 check `header.dh_pk == dh_r` that its name describes.
**Reading used:** the key m16 is sealed under: B's `hk_s` at m16, which is A's `nhk_r` and was B's `nhk_s` until B's step on m14 (so "the sender's `nhk_s`" is read as of the sender's previous chain). The header opens under A's `nhk_r`, the step branch is taken, and `dh_pk == dh_r` rejects before `skip_message_keys`, DHRatchet or any KDF. The generator asserts that m16's key equals A's `nhk_r` and that this check is the one that fires.
**Blocks:** nothing is withheld. Only the `cell` of tr-0044 depends on it. Under either reading the case is a rejection with the state unchanged.
**Answer** (reviewer, 2026-09-30, Weisung REF-M3-1): the ref's reading is the intended one: the N9 header is sealed under the key m16 is sealed under (B's current `hk_s` = A's `nhk_r`), so A opens it via `nhk_r` and the `dh_pk == dh_r` check rejects; the §4.9 row now reads "under the sender's current `hk_s` (the key the receiver opens with `nhk_r`)".

## SQ-24 — The state-digest label is not in App. A (SCHEMA §4.9; App. A)

**Quote (App. A):** "Domain-separation labels (exhaustive)" … "`"SecMP-vectors/1"` (test-vector seed derivation only, vectors/SCHEMA.md)" … "Any new label requires a spec change and an ADR." **Brief:** "`StateDigestV1 = SHA-256( "SecMP-TR/1 state-digest" ‖ sb ‖ …`".
**Problem.** The digest label lies in the protocol namespace `"SecMP-TR/1 "`, but App. A does not list it. So neither implementation's App. A unit test sees it, and a later protocol label such as `"SecMP-TR/1 state"` could break prefix-freeness unnoticed. Today the set stays prefix-free: no App. A label is a prefix of it, and it is a prefix of none (`ref/tests/test_tr.py`). A rename into the vectors namespace (`"SecMP-vectors/1 …"`) is not an option, because `"SecMP-vectors/1"` would then be a prefix of it.
**Question:** should App. A list `"SecMP-TR/1 state-digest"` beside `"SecMP-vectors/1"`, with a note such as "(test-vector state digest only, vectors/SCHEMA.md §4.9)"?
**Reading used:** the label as the brief gives it. **Blocks:** nothing (confirmation only); listing it changes no byte.
**Answer** (reviewer, 2026-09-30, Weisung REF-M3-1): yes. `"SecMP-TR/1 state-digest"` is a test-construct label like `"SecMP-vectors/1"`; it is recorded in SCHEMA §4.9 now and will be listed in App. A with the next spec revision (reviewer's ADR); the ref's prefix-freedom test is the guard until then.

## SQ-25 — Does the invitee enforce the inviter's two expiry bounds? (§5.2, §6.3, §5.5)

**Quote:** §5.2 "`expires: u64 ; Unix seconds; MUST be ≤ creation + 30 days`"; §6.3 "`spk_expiry: u64 ; MUST be ≥ the expiry of every invitation referencing it`"; §5.5 step 1 "reject if expired, wrong version/kind, malformed", step 4 "reject expired bundles"; brief REF-M4: step 1 checks "version, kind, expiry, well-formedness", step 4 "bundle signature under `IK_sig_R`, `spk_expiry > now`, `opk_present`".
**Problem.** Both MUSTs bind the inviter. §5.5 does not say whether the invitee checks them. InvitationV1 carries no creation time, so step 1 could only check `expires − now ≤ 30 days`; after step 2 the invitee could check `expires ≤ LinkDataV1.created + 30 days` (`created` has no other use in §5) and, in step 4, `spk_expiry ≥ InvitationV1.expires`. A violation hurts only the invitee (a handshake the inviter can no longer answer, or an invitation that outlives its SPK), so these would be consistency checks, not security checks.
**Readings:** (A) the invitee checks neither (the brief's lists for steps 1 and 4); (B) it checks both, `expires ≤ created + 30 days` against LinkDataV1 and `spk_expiry ≥ expires`; (C) as B, but the first bound as `expires − now ≤ 30 days` in step 1.
**Reading used: A.** No case depends on it: the positive run has `expires` = `created` + 30 days exactly (and `expires − now` < 30 days) and `spk_expiry` = `expires`, so it is valid under A, B and C; V1 (`expires` = `now` − 1) and V6 (`spk_expiry` = `now` − 1) reject under every reading.
**Blocks:** nothing. Under B or C, two `invitee-reject` cases could be added (`expires` one second over the bound; `spk_expiry` = `expires` − 1 with `spk_expiry` > `now`).
**Answer** (reviewer, 2026-09-30, Weisung REF-M4-1): reading A is correct. §5.2 and §6.3 bind the inviter; the invitee checks exactly §5.5 steps 1, 3 and 4 as listed in the brief. No case is added. A spec clarification will say so; nothing changes for `ref/`.

## SQ-26 — A request with `cmd_seq` ≤ `last`: frame count and timing for FETCH, FETCH_MULTI, LINK_GET and LINK_PUT (§9.2, §9.3, D.2; reading OPEN-5)

**Quote:** reading OPEN-5: "`cmd_seq ≤ last` is answered with one ERR 6 (MALFORMED), and nothing is executed. CONT stays exempt." §9.3: FETCH "exactly `F` `CELLR` frames; errors are signalled in `CELLR.present` (… 4 = MALFORMED)", FETCH_MULTI "exactly `F_M` `CELLR` frames", LINK_GET "3 `LINKR` frames"; D.2: "LINK_PUT receives ONE response frame after its third frame", "A relay MUST answer every request with the exact number of frames the table specifies, in request order"; §9.3: "success and error frames are indistinguishable on the wire".
**Problem.** For PING, SKEY, SEND, QUEUE_NEW and QUEUE_DEL one ERR frame is the D.2 count anyway. For FETCH (`F`), FETCH_MULTI (`F_M`) and LINK_GET (3), "one ERR 6" differs from the D.2 count, and FETCH and FETCH_MULTI have their own MALFORMED channel (`present` 4, reading OPEN-7). For LINK_PUT, the stale `cmd_seq` is in frame 1: if the relay answers at once, the two CONT frames that follow are orphans and tear the link down (reading OPEN-6); if it waits, the answer comes after the third frame like every LINK_PUT answer (reading R-e).
**Readings:** (A) one ERR 6 frame for every command, sent after the command's last request frame (for LINK_PUT, after the third); (B) the command's own D.2 shape: FETCH `F` CELLR with frame 1 `present` 4, FETCH_MULTI `F_M` CELLR with one `present` 4 frame per entry, LINK_GET LINKR {0, 0, dummy} and two CONT (it has no MALFORMED signal), LINK_PUT one ERR 6 after the third frame; (C) as A, but LINK_PUT answered at its first frame, so its CONTs tear the link down.
**Reading used: A** (reading OPEN-5 as written, with the LINK_PUT timing of D.2). A stale `cmd_seq` comes only from a faulty client (frames are authenticated and counted), so A's frame count reveals nothing about the store. B keeps the D.2 counts exact.
**Answer** (reviewer, ADR-048 (f), ratified by default 2026-10-04 20:45 UTC; Weisung REF-M5-2): reading A. Nothing changes for `ref/`.
**Blocks:** nothing. The only case with a stale `cmd_seq`, E23 (`link-0050`), is a PING, for which A, B and C give the same single ERR 6. `ref/tests/test_link.py` pins A for LINK_PUT and FETCH.

## SQ-27 — Frames that arrive while a LINK_PUT waits for its CONT frames (§9.2, D.2; reading OPEN-6)

**Quote:** D.2: "`0x7F CONT idx u8 ‖ data` ; continuation of the previous multi-frame command with the same cmd_seq (LINK_PUT: idx 1,2 carry 4100 B each …); LINK_PUT receives ONE response frame after its third frame"; §9.2: "`CONT` frames repeat the continued command's `cmd_seq` and are exempt from the increase check"; reading OPEN-6: a CONT "with no multi-frame command pending" is a LINK-level rejection.
**Problem.** OPEN-6 covers a CONT with nothing pending. After a LINK_PUT's first frame, the spec does not say what the relay does with (a) a CONT with another `cmd_seq`, (b) a CONT with `idx` 2 first or `idx` 1 twice, or (c) any other request, SKEY included, before both CONTs have arrived.
**Readings:** (A) a LINK-level rejection, as for the orphan CONT: teardown, nothing emitted, state unchanged; (B) the pending LINK_PUT is dropped silently and the new frame is processed; (C) the LINK_PUT is answered with ERR 6 and the new frame is processed.
**Reading used: A** (reference check `cont-expected`). B and C break "one response after the third frame" (B answers nothing, C answers before the third frame), and a client that interleaves is faulty.
**Answer** (reviewer, ADR-048 (j), ratified by default 2026-10-04 20:45 UTC; Weisung REF-M5-2): reading A. Nothing changes for `ref/`.
**Blocks:** nothing; no case sends such a frame. `ref/tests/test_link.py` pins A.

## SQ-28 — FETCH_MULTI with more entries in error than `F_M`, and a repeated `rid` (§9.3, §4.2, D.2)

**Quote:** D.2: "`0x05 FETCH_MULTI count u8 (1..=32)`"; §9.3: "exactly `F_M` `CELLR` frames: first one `CELLR` with `present ∈ {2,3,4}` for each listed queue in error, then cells from the remaining queues oldest-first by `arrival`, then dummies"; §4.2: `F_M` = 8.
**Problem.** `count` may exceed `F_M`. With more than `F_M` entries in error, "one CELLR for each listed queue in error" and "exactly `F_M` frames" cannot both hold. A `rid` listed twice (possibly with two `ack`s) is not addressed either: one error frame per entry or per queue, and can a cell come back twice?
**Readings, over-full:** (A) the first `F_M` error frames, in request order, and no others; (B) one frame per error, more than `F_M` frames; (C) `count` ≤ `F_M` is a decoder rule. **Repeated `rid`:** (A) each entry is checked and its `ack` applied in request order, an error frame per erroneous entry, and the queue's cells are selected once; (B) a repeated `rid` makes the request MALFORMED.
**Reading used: A and A.** B breaks D.2's exact count; C would change the decoder (the `encodings` suite accepts `count` up to 32).
**Answer** (reviewer, ADR-048 (j), ratified by default 2026-10-04 20:45 UTC; Weisung REF-M5-2): A and A. Nothing changes for `ref/`.
**Blocks:** nothing. P18 and E15 list two distinct queues with at most one in error. `ref/tests/test_link.py` pins the over-full reading.

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
- **L-3 — answered by reading OPEN-7 (brief REF-M5):** a stale ack is answered with `F` CELLR frames, frame 1 with `present` 4.
- *(original note)* **L-3 (§9.1 vs §9.3 / D.2, for M5):** §9.1 says "The relay MUST answer a `FETCH` whose `ack ≥ next_cell_id` with `ERR_MALFORMED`". But §9.3 answers a FETCH with "exactly `F` `CELLR` frames; errors are signalled in `CELLR.present` (… 4 = MALFORMED)", and D.2 says "A relay MUST answer every request with the exact number of frames the table specifies". Is a stale ack answered with one ERR frame or with F CELLR frames with `present` = 4? This does not affect `encodings`.
- **L-4 (§4.2 "PERIODS … tunable … finalised in M6", ADR-018):** the `encodings` rows that use period values (`inv_period_s` := 30, the positives with 10/20/40/80, …) are frozen with PERIODS = {10, 20, 40, 80}. If M6 changes PERIODS, these rows change with it.
- **L-5 — answered by reading OPEN-11 (brief REF-M5):** the consuming LINK_GET answers `present` 1, `consumed` 0; the dummy blob is 12360 random bytes. The CELLR half (`present` 1 with `cell_id` 0) does not occur, since `cell_id` counts from 1.
- *(original note)* **L-5 (D.2):** a LINKR with `present` = 1 and `consumed` = 1 has no stated meaning (a consumed one-time blob is deleted), and a CELLR with `present` = 1 and `cell_id` = 0 contradicts "cell_id … monotonically increasing from 1" (§9.1). Decoders accept both, since D-5 and D-7 check each field on its own. No vector uses either.

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

## Readings adopted without a question — REF-M3 (for the reviewer to veto)

These concern `ref/secmp_ref/tr.py` (spec §7) and the `tr` suite (`SCHEMA-4.9-tr.md`). An identical wrong reading on both sides would pass the comparison. Items 1–8 are about the ratchet, and items 9–14 about the vector file.

1. **KDF splits (§7.2).** `(RK ‖ HK_A ‖ NHK_B)` and `KDF_RK → (rk', ck, nhk)` are bytes 0–31, 32–63 and 64–95 of the HKDF output. `KDF_CK` is HMAC-SHA-256 keyed with `ck`, over the one byte 0x02 (the next chain key) or 0x01 (the message key). The `KDF_RK` input is `X25519(dh_s, dh_r) ‖ ss_pq`, with the DH output first.
2. **ADs (§7.3).** The header AD is `"SecMP-TR/1 hdr" ‖ sb`. The body AD is `"SecMP-TR/1 body" ‖ sb ‖ hdr_nonce ‖ hdr_ct`, where `hdr_ct` includes its 16-byte tag (2330 B). Decrypt uses the same body AD in both paths.
3. **Randomness order.** Encrypt draws only `hdr_nonce`, after `KDF_CK`. The initiator's init and DHRatchet draw the dh secret 32, the ML-KEM seed `d ‖ z` 64 and the Encaps `m` 32, in the order of the §7.2/§7.4 lines (keygen, keygen, Encaps). The decapsulation in DHRatchet draws nothing.
4. **Open() includes HeaderV1 decoding** (App. D, §4.1 decoder obligations, `flags` = 0 by §7.5). A header that authenticates under a key but does not decode rejects the cell at once (N11). Treating it as "did not open" and trying the next key gives the same outcome, because the AEAD opens under at most one key.
5. **The §7.4 step-1 path** (skipped keys) is followed as written. It tries the distinct `hk` in order of first insertion (which order is used cannot change the outcome), and it checks neither KEM constancy nor `dh_pk`. The entry is removed only after the MAC has verified, so a MAC failure leaves it in place (tested). Once a header opens under a skipped `hk` without a matching `(hk, n)`, step 2 follows.
6. **The transaction ends at MsgDecrypt.** Decrypt returns the padded Content; decoding the Content (and checking its ISO/IEC 7816-4 padding) comes after it and is not part of the transaction. No case depends on this.
7. **Counters.** Encrypt aborts (a local error, not the uniform Reject) when `n_s` = 2^32 − 1, before any state change. Decrypt rejects when `n_r` would pass 2^32 − 1 (`n_r` is a u32, §7.1). No case reaches either.
8. **Transactional decrypt** works on a copy of the state and commits every field at once after the MAC. The test compares the full digest preimage, which holds every §7.1 field, before and after each rejection.
9. **Interleaving** (SCHEMA-4.9 "Transcript"). Within a phase the `send` events come first, in send order, then the deliveries; phases 5 and 9 follow the brief's order. The case indices, and so the streams, follow from this.
10. **Re-sealed headers** (N1–N3, N8–N11) keep the base cell's `hdr_nonce` and body, and are sealed with the sender's header key of the base message.
11. **`advance` Dummy Content:** `ver` 1, `type` 0x00, `seq` 0, `ts` 0, empty body. The cells are discarded, so no byte of the file depends on it. The nonces are listed as `hdr_nonces` (24 × `count` bytes), because SCHEMA §2 lists every stream-derived value.
12. **N1 lists `dh_sk`, `kem_seed`, `m`:** it is rejected by the body MAC after DHRatchet has run on the working copy, so it draws DHRatchet's randomness like a `recv`. No other negative draws anything, except N2's `ek_pq_seed`.
13. **Case shape:** `party` = `"AB"` for `init`; a `recv-reject` also carries `msg` and `from` (the base message and its `send` case); digests are in `outputs`, and so is the pair of a `recv-reject` next to `expect`. The Batch `payload` is L raw stream bytes (opaque, SQ-19), not the hex text of the §4.8 text rows. The RouteUpdate descriptor is the §4.8 row `rd_relayqueue`.
14. **"No `mk` used twice"** is checked as follows: across the whole run, no message key encrypts twice and none decrypts twice, and each decryption uses the key that encrypted that same message. The run has 10 340 encryptions (40 messages + 10 300 advance cells) and 40 decryptions, so 10 340 distinct keys are tracked.

## Readings adopted without a question — REF-M4 (for the reviewer to veto)

**Reviewer (2026-09-30, Weisung REF-M4-1): readings 1–15 are all confirmed**, including 7 (the §4.1(a) decoder rejects a low-order `ek_I`/`spk_dh`/`opk_dh`/`ik_dh` before any DH; the §6.4 non-zero check stays as defence in depth and needs no vector), 8, 12 and 13. The restructured positive run and the added V3, V8, R11 and R12 are accepted as the case table.

These concern `ref/secmp_ref/inv.py` (spec §5), `ref/secmp_ref/hx.py` (spec §6) and the `hx` suite (`SCHEMA-4.10-hx.md`). An identical wrong reading on both sides would pass the comparison. Items 1–10 are about the protocol, and items 11–15 about the vector file. The REF-M3 readings for `tr` stand; `tr.py` is used unchanged.

1. **Transcript integers (§6.4).** `spk_id` and `opk_id` are u32 big-endian (4 bytes), as in the bundle (§4.1, D.3). `encode(IKSPublic_*)` is the 2017-byte encoding, and `SHA-256(SPK_kem_R)` and the others hash the encapsulation keys as encoded. The initiator takes `IKSPublic_R` and the bundle fields from the decoded LinkDataV1; the responder takes them from its own keys. Both give the same bytes.
2. **Bundle signature (§6.3).** The signed message is the encoded bundle fields before `sig`, as they stand, followed by the signer's `ik_dh` (the `inviter_iks` of the same LinkDataV1): 4434 B, as SCHEMA §4.5 row 7. V7 signs the fields with `opk_present` = 0 and the OPK bytes kept.
3. **Invitee (§5.5): order and checks.** Step 1 is the URI (item 4), the InvitationV1 decoder (`ver`, `kind` = 0x01, the RelayRef with the onion checksum, `inv_period_s` ∈ PERIODS) and `expires` > `now`: an invitation is expired iff `now` ≥ `expires` (no case sits on the boundary). Then come CAEAD.Open of the blob with `K_ld` (the part of step 2 that is not the relay's) and the LinkDataV1 decoder (padding, the §4.1 decoder obligations, `opk_present` = 1). Step 3 compares the fingerprint in constant time. Step 4 runs HybridVerify first, then `spk_expiry` > `now`. Neither of the inviter's bounds of SQ-25 is checked. The UI text of step 3 ("invitation does not match link data") is outside the vectors: every invitee rejection is the one uniform error there.
4. **The URI (§5.2).** The exact prefix `secmp://i/` (case-sensitive), then canonical base64url without padding (RFC 4648 §5): only `A–Z a–z 0–9 - _`, no `=`, length ≢ 1 (mod 4), and the text re-encodes to itself (the unused low bits are zero). Anything else is a malformed invitation. No case depends on this strictness; `ref/tests/test_hx.py` tests it.
5. **Responder grouping (§6.5, §6.6 step 1).** The fetched cells are trial-opened in fetch order. A cell that does not open, or whose plaintext is not a valid HandshakeCellPlaintext (`total` = 3, `i` ∈ {0, 1, 2}), is ignored, and so is a later chunk with an (`init_id`, `i`) already seen (first seen wins). The first `init_id` whose chunks 0, 1 and 2 have all arrived is processed, and one `respond` call processes one group. "No complete group" is the op's uniform rejection (R6, R11, R12); a client would keep the chunks and wait for more cells, which is outside the suite. What a client does with a second complete group after a rejected one is outside the suite too: the OPK is kept, so a later valid group can still succeed.
6. **Responder step 1.** `spk_id` must equal the recorded (and current) `spk_id` and `opk_id` the recorded `opk_id` (R1, R2); then the OPK must still be unused (R3). Each failure is the uniform rejection.
7. **Checks at decode on R's side.** Outer and Inner go through the M2 decoders, so the §4.1 decoder obligations apply. R4's `ek_I` = 0 is rejected by the Outer decoder before any DH (the all-zero checks of §6.4 would reject it otherwise), and IKSPublic_I gets every IKSPublic check (the Ed25519 key rules too), not only "`ik_dh` not low-order".
8. **The first message.** After Decrypt, R decodes the Content (padding, `caps` = 0) and requires type 0x01 (§6.5: "Content type Handshake"). It checks neither `seq` nor `ts`, nor the header's `pn`/`n`.
9. **No time at R.** §6.6 steps 1–4 take no `now`; the invitation record exists until the invitation is consumed or expires (§5.2).
10. **What R keeps.** R's state in the suite is its keys, the list of unused OPKs and the invitation record. A rejection changes none of it, and success deletes only the OPK. Retiring the invitation queue and the record (§6.6 step 4, §10.6) is outside the suite.
11. **R8 and R9 list R's DH-step draws** (`dh_sk`, `kem_seed`, `m`) after the construction draws, like tr's N1: R's Decrypt runs DHRatchet on its working copy before the body MAC (R8) or the Content decoder (R9) fails. No output depends on them.
12. **R9** encrypts from I's post-init TR state, as the brief says, so its `first_msg` uses the message key of case 6's (n = 0) for another plaintext. Only a vector may do that.
13. **The two `onion`s.** The invitation's RelayRef takes `onion_pubkey` (32 raw stream bytes) as PUBKEY (brief; §5.3 checks no key, SQ-13). The Handshake route's RelayRef takes the Ed25519 public key of `onion_seed`, as the §4.8 row `rd_relayqueue` and tr's RouteUpdate do.
14. **V8** reads "the `K_ld` of `link_key` with bit 0 flipped" as `flip(link_key, 0)` (byte 0 XOR 0x01, SCHEMA §4).
15. **Vector-file shape** (SCHEMA §1 `"schema": 5`, SCHEMA-4.10). `uri` is an ASCII string, `accept` a boolean, `opks_post` an ascending array of numbers, `fetched` and `routes` arrays of byte strings. `profile` is the encoded Profile and `routes` the encoded RouteDescriptors of the Handshake body; `content` is unpadded. `fetched` is listed in every responder case, also where it repeats case 6's cells. An `invitee-reject` case has no `outputs`, and the suite's constants are not repeated in `inputs`.

## Applied: Weisung REF-M4-1 (ref/, 2026-09-30)

- **V9 `ld-bad-sig-ed`** (`hx-0029`, invitee-reject): as V5, but bit 0 of byte 0 of `bundle.sig` is flipped (the Ed25519 R), sealed with `n` 24 from the stream. The flipped R is still a valid curve point, so the LinkDataV1 decoder (§4.1 (b)) accepts it, and HybridVerify rejects: the ML-DSA half verifies and the Ed25519 half fails (tested). Ref check `bundle-sig`.
- **R13 `first-msg-not-handshake`** (`hx-0030`, respond-reject, R after cases 1–4): a Batch Content (type 0x02, `ver` 1, `seq` 1, `ts` 1 700 000 001, `count` 1 ‖ AppMessage{`msg_id` 16, kind 1, `expire_after` 0, `payload_len` 8, `payload` 8}) encrypted from a fresh copy of I's post-init TR state. Stream order: `msg_id`, `payload`, `hdr_nonce`, `inner_nonce`, `init_id`, `cell_nonce_0..2`, then R's `dh_sk`, `kem_seed`, `m`. Inner and outer are re-sealed. TR decrypt succeeds, and the Handshake type check (reading 8) rejects: ref check `not-handshake`; `opks_post` = [42].
- Both are appended after R12, so no earlier case index or seed moves. `hx-0001` … `hx-0028` were compared with the REF-M4 file (`e5f82bae…`) case by case and are byte-identical. `vectors/hx.json` is still `"schema": 5`, written twice from fresh processes, byte-identical: SHA-256 `a33cf162e36969dc4bd70114a7c1b0ae3a97e09a187cd210c47dc374f436e7d2`. `SCHEMA-4.10-hx.md` is re-rendered (30 cases: 8 / 9 / 13). `SCHEMA.md` and the ten earlier files are unchanged.

## Readings adopted without a question — REF-M5 (for the reviewer to veto)

**Reviewer (Weisung REF-M5-2, 2026-10-07): readings 1–13 are confirmed** (reading 1 as the relay's check order, OPEN-M5-04). SQ-26 (A), SQ-27 (A) and SQ-28 (A, A) are answered as ADR-048 (f), (j); an owner override would mean one more re-freeze.

These concern `ref/secmp_ref/link.py` (spec §8), `ref/secmp_ref/relay.py` (spec §9) and the `link` suite (`SCHEMA-4.11-link.md`). The reviewer's readings OPEN-1 … OPEN-13 and (a)–(g) are implemented as given and are not repeated here. Items 1–10 are about the protocol, and items 11–13 about the vector file. No byte of `vectors/link.json` depends on items 1–9: every case has one fault, and no case reaches the behaviours they pin.

1. **Order of checks inside a command.** §9 gives none, so each row of the table has exactly one fault. `ref/` checks: QUEUE_NEW token, signature, known `recv_pk` (identical: OK_QUEUE_NEW; other `send_pk`: ERR 4), budget; SEND `sid`, signature; FETCH and each FETCH_MULTI entry `rid`, signature, `ack`; QUEUE_DEL `rid`, signature; LINK_PUT token, signature, `ld_id` known; owner-status LINK_GET entry and signature together (either failing gives {0, 0}, reading OPEN-10). The budget comes after the idempotency check, so an identical QUEUE_NEW at the limit is answered OK_QUEUE_NEW (reading OPEN-12: no case sends one).
2. **SKEY** (reading OPEN-6). The relay reads `op` and `cmd_seq` and parses nothing else (SKEY has no v1 fields); the padding is verified when the frame opens (item 3). Its `cmd_seq` is recorded under reading OPEN-5 like any request.
3. **Padding first, then the D.2 decoder.** `Link.open` returns the payload after the ISO/IEC 7816-4 check, and the relay then decodes it with the M2 request decoder (which re-pads and checks the fields, so the two together are the decoder of REF-M2 reading 4). Either failure is the LINK-level rejection of reading OPEN-6 (reference check `pt-decode`). A request that fails the §4.1 decoder obligations (a low-order key, a bad signature encoding) is such a rejection too.
4. **RelayInfo.** The checks run in the order decode, `sig`, `relay_fp`, `valid_until ≥ now`, `valid_until − now ≤ 60 days`, `akc`. `akc` is compared only when the client holds an access key (§8.2 "if it holds an access key"); in the suite it always does. HS1's `h0` takes `relay_fp` computed from the accepted RelayInfoV1's `relay_sig_pk`, which equals the pinned value.
5. **Consumed one-time link data.** The blob is dropped and a marker keeps `one_time`, `expires_bucket` and `owner_pk`; owner status reports {0, 1}; a LINK_PUT on the marker's `ld_id` is ERR 5 until the marker expires (the reviewer lists this outside the suite).
6. **Link data that is not one-time** (`one_time` = 0): a consume-mode LINK_GET returns it ({1, 0}) and keeps it.
7. **Draws.** An owner-status LINK_GET draws its dummy blob whether or not the entry exists and the signature verifies; a consume-mode LINK_GET draws one only when it returns no blob. FETCH draws its error frame's cell before the dummies; FETCH_MULTI draws one cell per error frame in request order, then the dummies (response-frame order, as the brief says).
8. **Store internals.** `arrival` starts at 1 and increases by one per stored cell; a FETCH or FETCH_MULTI entry that is not in error sets `last_fetch_bucket`; buckets are hours since epoch; nothing expires within the suite.
9. **Counters.** `checked_add` is a local abort (`CounterOverflow`, not the uniform Reject) when a counter would pass 2^64 − 1, after the frame with counter 2^64 − 1 has been sealed or opened. A frame that does not open leaves the counter where it was. Not reachable in a vector.
10. **The client's checks of a response** (generator self-checks, not spec rules): the D.2 frame count, the position after the command's last request frame, and the `cmd_seq` echo.
11. **`from`.** `link-0001` starts from no state and has no `from`; X1 has `cases` instead.
12. **Outputs.** A command-error case lists `req`, `req_frames`, `resp`, `resp_frames`, `link_post` and `store_post` (its manipulated token or signature is visible in `req`). The derived outputs of a positive case are `token` and `sig` (QUEUE_NEW, plus `rid` and `sid` on a queue's first QUEUE_NEW), `sig` (SEND, FETCH, QUEUE_DEL, owner-status LINK_GET), `sig_0`/`sig_1` in entry order (FETCH_MULTI) and `token`, `sig` (LINK_PUT); a consume-mode LINK_GET (`sig` = 0^64) and PING have none. Every link-A case, PING included, has `store_post`.
13. **JSON shapes** (SCHEMA §1 `"schema": 6`): `frame_len` (X1) is a JSON number; everything else is as the brief lists it.

## SQ-29 — What "a route of a known kind" means for a Handshake content (§6.5 rev 2.5, §9.8)

**Quote:** §6.5 (rev 2.5): "the Handshake content MUST contain at least one route of a known kind, else R rejects (uniform error, OPK kept)"; §9.8: "kind 0x01 RelayQueue … ; v1", "kind 0x02 OnionEndpoint … ; v1.1", "kind 0x03 Mailbox … ; v1.1", "v1 clients MUST ignore unknown kinds"; D.5: RouteDescriptor.
**Problem.** "Known" can mean the kinds listed in §9.8 (0x01, 0x02, 0x03) or the kinds a v1 client implements (0x01 only). A Handshake whose only route is kind 0x02 or 0x03 is rejected under the second reading and accepted under the first, though a v1 client could not use it.
**Readings:** (A) known = 0x01, the v1 kind; (B) known = 0x01, 0x02 and 0x03.
**Reading used: A.** R18 (`hx-0036`) uses kind 0x7F, which both readings reject; no case uses 0x02 or 0x03.
**Blocks:** nothing.

## Applied: Weisung REF-M5-2 (ref/, 2026-10-07)

- **RF-1** is the name of the retained-SPK request ("SQ-28 (ref)" in the earlier announcement; SQ-28 is the FETCH_MULTI question above). Case A2 (`hx-0037`).
- **`inv_sid` derived** (ADR-048 (m), M4 review R-90), draw-and-discard (OPEN-M5-14 B): `hx-0003` lists `inv_sid_discarded` at the old position, then `invq_recv_seed` and `owner_seed` after the last draw; outputs add `inv_sid`, `invq_recv_pk`, `owner_pk`. The invitation and URI bytes change, so do `hx-0009` … `hx-0011` (their invitation and URI inputs); every other old case is unchanged.
- **Appended after `hx-0030`:** `hx-0031` A1 `respond-later-group`, `hx-0032` R14 `no-reform`, `hx-0033` R15 `first-msg-n`, `hx-0034` R16 `first-msg-pn`, `hx-0035` R17 `reflection`, `hx-0036` R18 `no-known-route`, `hx-0037` A2 `respond-retained-spk`. `vectors/hx.json` names spec rev 2.6 in its header (all cases: only the header differs for the unchanged ones).
- **`hx.py`:** groups are processed in completion order and a rejected group is discarded (a closed group cannot re-form), at most 8 partial groups, the first_msg header must have `n` = `pn` = 0, `IKSPublic_I` ≠ `IKSPublic_R`, at least one route of kind 0x01, and the Outer's `spk_id` may name a retained SPK generation (`Prekeys.retained`).
- **ADR-048 (o)** in `relay.py`: LINK_PUT checks token, signature, `now_bucket ≤ expires_bucket ≤ now_bucket + 720`, then `ld_id`; outside the range: ERR 6 after the third frame, nothing stored. `vectors/link.json` is unchanged (its `expires_bucket` is `now_bucket` + 168).
- **F15:** in this directory the four renderers (`ref/tools/render_schema_4_{8,9,10,11}.py`) already write `SCHEMA-4.<n>-….md` in the directory root, next to `SCHEMA.md`, not under `vectors/`; the main repository's copy (the one that wrote under `vectors/`) is not visible here. The 4.8, 4.9 and 4.11 tables re-render byte-identically; 4.10 is re-rendered.
- **`tests/test_tr.py`:** the SQ-24 test asserted that the label `SecMP-TR/1 state-digest` is absent from the spec. Rev 2.4's App. A now names it once, as a test-only label outside the set; the test checks exactly that.

## Readings adopted without a question — REF-M5-2 (for the reviewer to veto)

1. **Grouping (§6.5 rev 2.5).** A group that has completed is closed whether it is accepted or rejected: later chunks of its `init_id` are ignored. A duplicate (`init_id`, `i`) is ignored whatever its bytes (first-seen wins). Eviction: when a ninth `init_id` would be stored, the oldest partial group is dropped first.
2. **Rejection result with several groups.** If no group is accepted, the reference check is that of the last rejected group; `no-complete-envelope` only if no group completed. A rejected group's DH-step draws are consumed (they are listed, as R8's).
3. **Order of the new checks.** `reflection` right after the Inner decoder (before any DH1/DH2); `first-msg-header` after Decrypt succeeds and before the Content decoder; `no-known-route` after the Handshake type check. The header is read with the responder's next header key, before the DH step.
4. **A1's rejected group** is R8's construction (last byte of `first_msg` flipped) under a fresh `init_id`; its cells and the honest cells follow in that order.
5. **R15** builds `n` = 1 by encrypting one message from I's post-init state and discarding it; **R16** sets `pn` = 1 on that state. Both therefore decrypt, and only the header rule rejects.
6. **R17** uses case 6's `first_msg` unchanged under `IKSPublic_I` := `IKSPublic_R`.
7. **A2**: R's current SPK is a new generation `spk_id` 8 (keys from the case's stream, `spk_expiry` unchanged); SPK 7 is retained with its RPK. The outputs equal case 7's `transcript`, `sk`, `k_id`, `peer_iks`, `content`; `state_post_R` differs (other step draws).
8. **JSON shapes and names (proposal).** New ops `respond-later-group` and `respond-retained-spk` (positive, party R, outputs as `respond`); `invite` outputs add `inv_sid`, `invq_recv_pk`, `owner_pk`. `SCHEMA.md` §1's hx bullet (op list, outputs) was not touched, as instructed, and lists neither new op nor the three outputs.
9. **ADR-048 (o) boundaries.** Both bounds are inclusive, as quoted; `expires_bucket` is compared as the u32 it is on the wire.
