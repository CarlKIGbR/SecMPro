# Test-vector schema — revision 2 (normative for `ref/` and for `secmp-crypto`/`secmp-proto`)

Revision 2 (2026-09-28) answers the reference implementation's questions SQ-01–SQ-11 (`docs/reviews/ref-spec-questions-M1.md`) and applies to spec **revision 2.2**. Defined by the reviewer so that neither implementation invents the format. Both the Python reference implementation (`ref/`, ADR-026) and the Rust implementation generate vectors in exactly this shape; `cargo xtask vectors` compares them and freezes the agreed files under `vectors/<suite>.json`.

## 1. File shape and comparison

```json
{
  "schema": 2,
  "suite": "hybridkem-768",
  "spec": "SecMP/1 rev 2.2",
  "generator": "ref-python" | "secmp-rust",
  "cases": [
    { "id": "hk768-0001", "op": "encaps", "inputs": { "...": "<hex>" }, "outputs": { "...": "<hex>" } },
    { "id": "hk768-0013", "op": "decaps", "inputs": { "...": "<hex>" }, "expect": "reject" }
  ]
}
```

- **Byte strings** are lowercase hex JSON strings. **Integers** are JSON numbers. **Labels** are JSON strings holding the ASCII label (e.g. `"SecMP-TR/1 rk"`). **Digit strings** (SAS) are JSON strings, leading zeros kept. **Booleans** are JSON booleans. `mode`/`op` are JSON strings.
- Every case has `id`, `op`, `inputs`, and either `outputs` or `"expect": "reject"`. Cases are ordered by `id`; the index starts at `0001`; negative cases continue the same sequence after the positive ones.
- Files are written canonically: keys sorted by code point at every level, `separators=(",", ":")`, ASCII only, no trailing newline. **Comparison is structural**: both files are parsed, `generator` is removed, and the resulting JSON values must be equal. No case-folding of any string. A validator additionally checks that every byte-string field matches `^([0-9a-f]{2})*$`.
- Rejected cases MUST be rejected with the implementation's single uniform error for that construction.

## 2. Input derivation from seeds (SQ-01)

```
seed_i   = SHA-256( ASCII("SecMP-vectors/1") ‖ ASCII(<suite name>) ‖ u32be(i) )       ; i = the case index (1, 2, …), <suite name> e.g. "hkdf-labels"
stream_i = SHAKE-256(seed_i), one XOF stream per case, consumed front to back
```

Every **stream-derived** input takes its bytes from `stream_i` in the order of the suite's input list below; fixed-size fields take their size, variable-size fields take the byte length given in the case table. Lengths, labels, `len`, `mode`, `op` and manipulations are **never** drawn from the stream; they come from the case tables in §4. Fields marked *derived* are computed from other inputs (e.g. an honest ciphertext that is then manipulated) and are listed in `inputs` so that the file shows the exact bytes under test. Worked check (hkdf-labels case 1): preimage `5365634d502d766563746f72732f31686b64662d6c6162656c7300000001`, `seed_1 = cf66f30f0fe1f5798c9c3f1e8e4034fbd3ef99ca2dcf68bf3d533caa15a33d23`, first 16 stream bytes (`salt`) `66a224dde82f65dff9bc79b22f39a9ad`, next 32 (`ikm`) `30c09b030215e20d5de63ff06946dfb6aa044c903b7709cd7c9c3d80e8326007`.

Key material derived from the stream: an X25519 secret is 32 raw stream bytes (clamped inside X25519); an Ed25519 seed is 32 bytes; an ML-KEM seed is 64 bytes `d ‖ z` for `KeyGen_internal(d, z)`; ML-KEM encapsulation randomness `m` is 32 bytes for `Encaps_internal(ek, m)`; an ML-DSA seed ξ is 32 bytes for `KeyGen_internal(ξ)`; ML-DSA hedge randomness `rnd` is 32 bytes for `Sign_internal(sk, M', rnd)`.

## 3. Suite tags (SQ-02)

| Suite name | tag |
|---|---|
| `hkdf-labels` | `hkdf` |
| `caead` | `caead` |
| `msgencrypt` | `msgenc` |
| `hybridkem-768` / `hybridkem-1024` | `hk768` / `hk1024` |
| `hybridsign` | `hsig` |
| `fingerprint` | `fp` |
| `sas` | `sas` |

## 4. M1 suites — inputs, outputs and case tables

Manipulations used below: **flip(field, k)** = XOR byte `k` of the field with `0x01` (negative `k` counts from the end: `-1` is the last byte); **drop-last(field)** = remove the last byte; **append-zero(field)** = append one `0x00` byte; **prefix(field, n)** = keep the first `n` bytes. Manipulations apply to the honest value derived from the case's own stream; the manipulated value is what the file lists.

### 4.1 `hkdf-labels` — HKDF-SHA-256 with the label discipline (spec §3, App. A)

inputs (stream order): `salt` (len per table), `ikm` (len per table), `extra_info` (len per table); table-fixed: `mode` (`"extract-expand"` = HKDF(salt, IKM, info, L) with an empty salt meaning `0^32` per RFC 5869; `"expand"` = HKDF-Expand(PRK = `ikm`, info, L), `salt` MUST be the empty string), `label`, `len`. `info = ASCII(label) ‖ extra_info`. outputs: `okm`. `op` = `"derive"`.

| i | mode | label | salt | ikm | extra_info | len | note |
|---|---|---|---|---|---|---|---|
| 1 | extract-expand | `SecMP-INV/1 linkdata` | 16 | 32 | 0 | 32 | §5.4 `K_ld` |
| 2 | extract-expand | `SecMP-HX/1 sk` | 32 | 224 | 32 | 32 | §6.4 `SK` (extra = transcript) |
| 3 | extract-expand | `SecMP-HX/1 idkey` | 16 | 160 | 0 | 32 | §6.4 `K_id` |
| 4 | extract-expand | `SecMP-HX/1 initkey` | 16 | 32 | 0 | 32 | §6.5 `K_inv` |
| 5 | extract-expand | `SecMP-TR/1 init` | 32 | 32 | 0 | 96 | §7.2 |
| 6 | extract-expand | `SecMP-TR/1 rk` | 32 | 64 | 0 | 96 | §7.2 `KDF_RK` |
| 7 | extract-expand | `SecMP-TR/1 msgkeys` | 32 | 32 | 0 | 76 | §3.3 |
| 8 | expand | `SecMP-commit/1` | 0 | 32 | 24 | 64 | §3.4 (PRK = K, info = label ‖ N) |
| 9 | expand | `SecMP-LINK/1 keys` | 0 | 32 | 0 | 80 | §8.3 (PRK = ck2) |
| 10 | extract-expand | `SecMP-TR/1 msgkeys` | 0 | 32 | 0 | 76 | edge: empty salt ≡ `0^32` |
| 11 | extract-expand | `SecMP-HX/1 sk` | 32 | 32 | 100 | 8160 | edge: maximum L |
| 12 | extract-expand | `SecMP-TR/1 rk` | 32 | 0 | 0 | 1 | edge: empty IKM, L = 1 |

No negative cases. `SecMP-STORE/1 *` labels are out of scope for vectors (local storage, tested in M7).

### 4.2 `caead` — committing AEAD wrapper (spec §3.4)

Positive cases (`op` = `"seal"`): inputs (stream order) `k` (32), `n` (24), `ad` (len), `p` (len); outputs `com` (32), `c` (|p| + 16).

| i | ad | p |
|---|---|---|
| 1 | 0 | 0 |
| 2 | 16 | 1 |
| 3 | 21 | 16 |
| 4 | 32 | 255 |
| 5 | 64 | 256 |
| 6 | 128 | 1024 |
| 7 | 256 | 4006 |
| 8 | 1024 | 12288 |

Negative cases (`op` = `"open"`, `expect: reject`): inputs `k`, `n`, `ad` (stream, lengths as the referenced positive row), then the *derived* `com`, `c` from an honest seal of `p` (stream, length as the row) with the manipulation applied.

| i | derived from row | manipulation |
|---|---|---|
| 9 | 3 | flip(`c`, 0) |
| 10 | 3 | flip(`c`, -1) (tag) |
| 11 | 3 | flip(`com`, 0) |
| 12 | 3 | drop-last(`c`) |
| 13 | 3 | prefix(`c`, 15) (shorter than a tag) |
| 14 | 3 | flip(`ad`, 0) |
| 15 | 3 | flip(`n`, 0) |
| 16 | 3 | flip(`k`, 0) |
| 17 | 1 | flip(`c`, 0) (empty plaintext: only the tag exists) |

### 4.3 `msgencrypt` — Encrypt-then-MAC (spec §3.3)

Positive cases (`op` = `"seal"`): inputs (stream order) `mk` (32), `ad` (len), `p` (1710 = `BODY_LEN`, arbitrary bytes — padding is not interpreted here); outputs `k_enc` (32), `k_mac` (32), `iv` (12), `c_tag` (1742).

| i | ad |
|---|---|
| 1 | 0 |
| 2 | 1 |
| 3 | 32 |
| 4 | 64 |
| 5 | 128 |
| 6 | 1024 |
| 7 | 2401 (= the real body AD length: 15 + 32 + 24 + 2330) |
| 8 | 4096 |

Negative cases (`op` = `"open"`, `expect: reject`): inputs `mk`, `ad` (stream, lengths as the referenced row) and the *derived* `c_tag` with the manipulation.

| i | derived from row | manipulation |
|---|---|---|
| 9 | 3 | flip(`c_tag`, 0) |
| 10 | 3 | flip(`c_tag`, -1) |
| 11 | 3 | drop-last(`c_tag`) |
| 12 | 3 | append-zero(`c_tag`) |
| 13 | 3 | flip(`ad`, 0) |
| 14 | 3 | flip(`mk`, 0) |
| 15 | 3 | `c_tag` = empty |
| 16 | 1 | `p` of length 1709 on the seal side → `op` = `"seal"`, `expect: reject` (inputs `mk`, `ad`, `p`) |

### 4.4 `hybridkem-768` and `hybridkem-1024` (spec §3.2)

Positive round-trip cases (`op` = `"encaps"`): inputs (stream order) `dk_seed` (64), `sk_dh` (32), `m` (32), `sk_e` (32); outputs `ek_kem`, `pk_dh`, `ct_kem`, `pk_e`, `ss` (32). The Rust side additionally checks that `Decaps` of its own outputs returns `ss`.

Rows 1–8: eight round trips.

Decapsulation cases (`op` = `"decaps"`): inputs `dk_seed`, `sk_dh` (stream as the referenced row), then *derived* `pk_e`, `ct_kem` (from the honest encapsulation of that row) with the manipulation; outputs `ss` — **or** `expect: reject`.

| i | from row | manipulation | result |
|---|---|---|---|
| 9 | 1 | none (honest) | `ss` = honest |
| 10 | 1 | flip(`ct_kem`, 0) | `ss` = hybrid secret computed with the **implicit-rejection** KEM secret (FIPS 203 `Decaps` returns `J(z ‖ c)`); positive |
| 11 | 1 | flip(`ct_kem`, -1) | positive, implicit-rejection secret |
| 12 | 2 | flip(`pk_e`, 0) | positive, `ss` recomputed with the modified `pk_e` bytes (they are hashed into the combiner and used as the X25519 input) |
| 13 | 1 | drop-last(`ct_kem`) | reject |
| 14 | 1 | `pk_e` = `00…00` (u = 0) | reject (all-zero X25519 output) |
| 15 | 1 | `pk_e` = `01 00…00` (u = 1) | reject |
| 16 | 1 | `pk_e` = `e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800` (order-8 point) | reject |

Encapsulation-side negatives (`op` = `"encaps-to"`, `expect: reject`): inputs `ek_kem`, `pk_dh` (derived from the referenced row's keys, then manipulated), `m`, `sk_e` (stream).

| i | from row | manipulation |
|---|---|---|
| 17 | 1 | `ek_kem` with bytes 0–2 set to `ff ff ff` (a packed coefficient ≥ q → fails the FIPS 203 modulus check) |
| 18 | 1 | drop-last(`ek_kem`) |
| 19 | 1 | `pk_dh` = `00…00` |

### 4.5 `hybridsign` (spec §3.5)

Positive cases (`op` = `"sign"`): inputs (stream order) `ed_seed` (32), `mldsa_seed` (32), `rnd` (32), `msg` (len); table-fixed `label`; outputs `pk_ed` (32), `pk_mldsa` (1952), `sig` (3373), `verify` = `true`.

| i | label | msg |
|---|---|---|
| 1 | `SecMP-HX/1 bundle` | 0 |
| 2 | `SecMP-TR/1 keychange` | 1 |
| 3 | `SecMP-HX/1 bundle` | 32 |
| 4 | `SecMP-TR/1 keychange` | 32 |
| 5 | `SecMP-HX/1 bundle` | 100 |
| 6 | `SecMP-TR/1 keychange` | 1024 |
| 7 | `SecMP-HX/1 bundle` | 4434 (= `PrekeyBundle` fields before `sig` (4402) + `ik_dh` (32)) |
| 8 | `SecMP-TR/1 keychange` | 4096 |

Negative cases (`op` = `"verify"`, `expect: reject`): inputs `pk_ed`, `pk_mldsa`, `label`, `msg`, `sig` — derived from the referenced positive row and then manipulated.

| i | from row | manipulation |
|---|---|---|
| 9 | 3 | flip(`sig`, 0) (Ed25519 R) |
| 10 | 3 | flip(`sig`, 64) (ML-DSA part) |
| 11 | 3 | `label` = `SecMP-TR/1 keychange` (the other HybridSign label) |
| 12 | 3 | `label` = `SecMP-TR/1 rk` (not a HybridSign label → refused) |
| 13 | 3 | drop-last(`sig`) |
| 14 | 3 | Ed25519 `S` replaced by `S + L` (bytes 32–63 of `sig`, little-endian; `L = 2^252 + 27742317777372353535851937790883648493`) |
| 15 | 3 | `pk_ed` = `01 00…00` (the identity, small order) |
| 16 | 3 | `pk_ed` = `eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (non-canonical encoding of y = 1) |
| 17 | 3 | flip(`msg`, 0) (msg length 32) |

### 4.6 `fingerprint` (spec §6.2)

`op` = `"fp"`: inputs (stream order) `ed_seed` (32), `mldsa_seed` (32), `dh_seed` (32); outputs `iks` (2017, the encoded `IKSPublic` with `ver = 0x01`, `ik_ed25519` from `ed_seed`, `ik_mldsa65` from ξ, `ik_dh` = X25519 public key of `dh_seed`) and `fp` (32). Rows 1–8. No negatives (malformed `IKSPublic` belongs to the `encodings` suite in M2).

### 4.7 `sas` (spec §6.7)

`op` = `"sas"`: inputs (stream order) `fp_a` (32), `fp_b` (32); outputs `half_a`, `half_b` (30-digit strings), `safety_number` (60-digit string). Rows 1–8 from the stream; row 9: `fp_b` := `fp_a` (equal fingerprints); row 10: `fp_a`, `fp_b` swapped relative to row 1 (must give the same `safety_number` as row 1).

## 5. Later suites (M2–M5)

`encodings` (one case per structure in App. D, positive and ≥ 200 negatives incl. wrong padding, wrong `ver`, low-order `ik_dh`), `hx` (full run with fixed seeds; outputs `sk`, `transcript`, `k_id`, the three handshake cells), `tr` (40-message transcript; each case = one message with SHA-256 of the serialised pre/post state), `link` (HS1/HS2 and the first three frames each direction). Their case tables are added to this file by the reviewer before the milestone starts.

## 6. Library independence

The reference implementation MUST NOT contain code derived from this repository's Rust crates. It MAY use independent, well-known libraries for primitives (recommended: `kyber-py` for ML-KEM, `dilithium-py` for ML-DSA, PyNaCl for X25519/Ed25519/XChaCha20-Poly1305, `cryptography` for ChaCha20/HMAC/HKDF, `hashlib` for SHA-2/SHA-3/SHAKE), after checking each library once against the official NIST ACVP / RFC vectors in the reference's own test-suite. The constructions (combiner, EtM, CAEAD, HybridSign, SAS, encodings, handshake, ratchet, link) are written by hand from the spec. Where a library's checks are weaker than the spec's rules (e.g. strict Ed25519 verification, spec §3.5), the wrapper adds the missing checks on the encoded bytes.
