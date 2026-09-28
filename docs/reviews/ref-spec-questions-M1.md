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

## Noted for later milestones (not blocking M1)

- **L-1 (D.2 vs §9.2/D.6) — fixed in rev 2.2:** D.2 comments now carry the `"SecMP-Q/1 "` prefix; D.6 governs.
- *(original note)* **L-1 (D.2 vs §9.2/D.6):** the D.2 comments write the signed data as `"QUEUE_NEW"‖sess_id‖…` without the `"SecMP-Q/1 "` prefix, while §9.2, D.6 ("always") and Appendix A include it. I read D.6 as governing. The D.2 comments could be aligned.
- **L-2 — fixed in rev 2.2:** Appendix A lists the nine `SecMP-STORE/1 <table>` labels explicitly.
- *(original note)* **L-2 (Appendix A, `SecMP-STORE/1 <table>`):** the table names are defined outside this document (`02-architecture.md` §4.2). No STORE label can be written from this spec alone.
- **Arithmetic check:** every size in Appendix B, and the frame, cell and handshake layouts they come from, were added up again from their field lists. All of them agree (`ref/tests/test_labels_sizes.py::test_composite_sizes_add_up`), as do the §10.2 bandwidth figures and the §7.4 "≈ 121 days" figure.
