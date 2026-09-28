# Test-vector schema (normative for `ref/` and for `secmp-crypto`/`secmp-proto`)

Defined by the reviewer (2026-09-28) so that neither implementation invents the format. Both the Python reference implementation (`ref/`, ADR-026) and the Rust implementation generate vectors in exactly this shape; `cargo xtask vectors` compares them byte-for-byte after canonical JSON normalisation (sorted keys, no whitespace, lowercase hex) and freezes the agreed files under `vectors/<suite>.json`.

## File shape

```json
{
  "schema": 1,
  "suite": "hybridkem-768",
  "spec": "SecMP/1 rev 2.1",
  "generator": "ref-python" | "secmp-rust",
  "cases": [
    { "id": "hk768-0001", "inputs": { "...": "<hex>" }, "outputs": { "...": "<hex>" } }
  ]
}
```

Rules: every byte string is lowercase hex; integers are JSON numbers; there are no optional keys — a case that has no value for a key omits the key only if the suite definition says so; `id` is `<suite-tag>-<4-digit index>`; cases are ordered by `id`; `generator` is the only field that may differ between the two files and is excluded from the comparison. Negative cases carry `"expect": "reject"` instead of `outputs` and MUST be rejected with a uniform error.

## Suites and their keys (M1)

| Suite | inputs | outputs |
|---|---|---|
| `hybridkem-768`, `hybridkem-1024` | `dk_seed` (64 B = d‖z for ML-KEM `KeyGen_internal`), `sk_dh` (32 B X25519 secret), `m` (32 B ML-KEM encaps randomness), `sk_e` (32 B ephemeral X25519 secret) | `ek_kem`, `pk_dh`, `ct_kem`, `pk_e`, `ss` (32 B) |
| `hybridsign` | `ed_seed` (32), `mldsa_seed` (32 B ξ), `rnd` (32 B hedge), `label` (ASCII, from Appendix A), `msg` (hex) | `pk_ed`, `pk_mldsa`, `sig` (3373 B), and `verify` = `true` |
| `msgencrypt` | `mk` (32), `ad` (hex), `p` (hex, already padded to `BODY_LEN`) | `k_enc`, `k_mac`, `iv`, `c_tag` (= C ‖ TAG) |
| `caead` | `k` (32), `n` (24), `ad`, `p` | `com` (32), `c` (ciphertext incl. 16-byte tag) |
| `hkdf-labels` | `salt`, `ikm`, `label` (from Appendix A), `extra_info` (hex appended to the label), `len` | `okm` |
| `fingerprint` | `iks` (2017 B encoded `IKSPublic`) | `fp` (32) |
| `sas` | `fp_a`, `fp_b` | `half_a` (30 digits), `half_b`, `safety_number` (60 digits) |

Each suite has ≥ 8 positive cases from fixed seeds (`seed_i = SHA-256("SecMP-vectors/1" ‖ suite ‖ i)` expanded with SHAKE-256 to the required randomness, so both sides derive identical inputs) and the negative cases listed in the spec (Appendix C): non-contributory X25519 (all-zero shared secret), malformed ML-KEM encapsulation key, truncated/flipped ciphertext, wrong MAC, wrong `COM`, wrong padding.

Later suites (M2–M5) follow the same shape: `encodings` (one case per structure, positive and negative), `hx` (full run with fixed seeds; outputs `sk`, `transcript`, `k_id`, the three handshake cells), `tr` (40-message transcript; each case = one message with the full pre/post state hashes), `link` (HS1/HS2 and the first three frames each direction). Their key lists are added to this file by the reviewer before the milestone starts.

## Library independence

The reference implementation MUST NOT contain any code derived from this repository's Rust crates. It MAY use independent, well-known libraries for primitives (recommended: `kyber-py` for ML-KEM, `dilithium-py` for ML-DSA, PyNaCl for X25519/Ed25519/XChaCha20-Poly1305, `cryptography` for ChaCha20/HMAC/HKDF, `hashlib` for SHA-2/SHA-3/SHAKE), after checking each library once against the official NIST ACVP / RFC vectors in the reference's own test-suite. The constructions (combiner, EtM, CAEAD, HybridSign, SAS, encodings, handshake, ratchet, link) are written by hand from the spec.
