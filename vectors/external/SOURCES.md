# External known-answer vectors — provenance

Vendored test data for `secmp-crypto`'s known-answer tests (feature `kat`, docs/06 §4–5, spec Appendix C). Data
only; nothing here is executed. Fetched 2026-09-28. Every file is checked by the KAT tests on every target
(`cargo xtask step kat`); a changed file is a reviewed change of this list.

## Wycheproof — `C2SP/wycheproof` @ `3fa63dd0344abb611f1fb1d77e119938603ea230` (2026-09-02)

Source: `https://raw.githubusercontent.com/C2SP/wycheproof/<commit>/testvectors_v1/<file>`, unmodified.
Licence: Apache-2.0.

| File | SHA-256 | Exercised through |
|---|---|---|
| `wycheproof/x25519_test.json` | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` | `X25519Secret::diffie_hellman` |
| `wycheproof/ed25519_test.json` | `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536` | `Ed25519VerifyingKey` (strict, spec §3.5) |
| `wycheproof/xchacha20_poly1305_test.json` | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` | `chacha20poly1305::XChaCha20Poly1305` (the AEAD inside `Caead`) |
| `wycheproof/chacha20_poly1305_test.json` | `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d` | `chacha20::ChaCha20` (the stream inside `MsgEncrypt`: AEAD ciphertext = plaintext ⊕ keystream from block 1) |
| `wycheproof/hkdf_sha256_test.json` | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` | `hkdf::Hkdf<Sha256>` (under `hkdf`/`hkdf_expand`) |
| `wycheproof/hmac_sha256_test.json` | `2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f` | `hmac::Hmac<Sha256>` (the MAC inside `MsgEncrypt`) |
| `wycheproof/mlkem_768_test.json` | `c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90` | `MlKem768Dk::from_seed`, `decapsulate` |
| `wycheproof/mlkem_1024_test.json` | `17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a` | `MlKem1024Dk::from_seed`, `decapsulate` |
| `wycheproof/mlkem_768_encaps_test.json` | `9d4381f94c40853bba430245b94968b7390d9175aacd9f1ae4e250a71c78b713` | `MlKem768Ek::from_bytes`, `encapsulate_kat` |
| `wycheproof/mlkem_1024_encaps_test.json` | `da41e8daf57e40a6b334a722e3f56067817352f5583fdb2434da1a2cd611358e` | `MlKem1024Ek::from_bytes`, `encapsulate_kat` |
| `wycheproof/mlkem_768_keygen_seed_test.json` | `fde5abe284396f4cb3c4610b90d680f0b57782e94c3365c97aee59e24881ebe4` | `MlKem768Dk::from_seed` (ek), `libcrux-ml-kem` (expanded dk) |
| `wycheproof/mlkem_1024_keygen_seed_test.json` | `cd9241bf5d65a78e005866ea2c660615c17f50caa9afc2b96fd1573cc65617b5` | `MlKem1024Dk::from_seed` (ek), `libcrux-ml-kem` (expanded dk) |
| `wycheproof/mlkem_768_semi_expanded_decaps_test.json` | `e4438ab7d4dd7b6ace7165e45aeed4403082f981f86300c8369f69d3d071060a` | `libcrux-ml-kem` directly (expanded keys; SecMP stores only seeds) |
| `wycheproof/mlkem_1024_semi_expanded_decaps_test.json` | `a4a7c88152df3d8d4b3f33aad584167dfaff67195cfde08aac4b981030b4d05c` | `libcrux-ml-kem` directly (expanded keys) |
| `wycheproof/mldsa_65_sign_seed_test.json` | `d72e9c2f514c9f7490c33785ae0027d942ba2c45a9b8ebfc8fb1802b4913bf38` | `MlDsa65SigningKey::from_seed`, `sign_kat` (cases of the `Internal` interface — μ given, no message — do not apply to pure ML-DSA and are counted as skipped) |
| `wycheproof/mldsa_65_verify_test.json` | `49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02` | `MlDsa65VerifyingKey::from_bytes`, `verify` |

Not vendored: `mldsa_65_sign_noseed_test.json` (expanded ML-DSA private keys; SecMP keys are seeds, spec §3.5,
and the same signatures are covered by `sign_seed`).

## NIST ACVP — `usnistgov/ACVP-Server` @ `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12)

Source: `https://raw.githubusercontent.com/usnistgov/ACVP-Server/<commit>/gen-val/json-files/<dir>/internalProjection.json`,
**filtered** with `jq -c` to the parameter sets SecMP uses (the filter only removes test groups). Licence: work of
the U.S. Government (NIST), not subject to copyright in the United States (17 U.S.C. §105); the repository has no
licence file at this commit.

| File | Upstream SHA-256 (unfiltered) | Filter (`.testGroups \|= map(select(…)))`) | Filtered SHA-256 | Exercised through |
|---|---|---|---|---|
| `acvp/ML-KEM-keyGen-FIPS203.json` | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` | `.parameterSet=="ML-KEM-768" or .parameterSet=="ML-KEM-1024"` | `6247ea334cb42900e4b4a4b9422a2f42b8575b85ab34d521a4da88f761fdd639` | `MlKem*Dk::from_seed(d ‖ z)` (ek), `libcrux-ml-kem` (expanded dk) |
| `acvp/ML-KEM-encapDecap-FIPS203.json` | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` | same | `b417bf729def5834877652519de33fd443f2bf5a4bfca73bf006c3331fb4a252` | encapsulation and `encapsulationKeyCheck`: `MlKem*Ek`; decapsulation and `decapsulationKeyCheck` (expanded dk): `libcrux-ml-kem` directly |
| `acvp/ML-DSA-keyGen-FIPS204.json` | `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` | `.parameterSet=="ML-DSA-65"` | `e35f1a5091671662ce15aa8b881fe8e4c823ee8a2efcca457f5593b286b1242f` | `MlDsa65SigningKey::from_seed` (pk) |
| `acvp/ML-DSA-sigVer-FIPS204.json` | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` | same | `fd61a76d44d18fb8517cccf2164ce3e846e397798fdef79343d33c8cd293c8a4` | `MlDsa65VerifyingKey::verify` |

Not vendored: ACVP `ML-DSA-sigGen-FIPS204` — it provides only expanded private keys, whose import in `ml-dsa` 0.1.1
(`ExpandedSigningKey::from_expanded`) is `#[deprecated]` and would need an unsanctioned lint allowance; SecMP signs
only from seeds, and pure hedged/deterministic signing with contexts is covered by Wycheproof `mldsa_65_sign_seed`
through the wrapper. The expanded `sk` of ACVP keyGen is not compared for the same reason (`to_expanded` is deprecated).

## RFC vectors (inline in the tests)

RFC 7748 §5.2 and §6.1 (X25519, incl. 1 000 iterations), RFC 8032 §7.1 (Ed25519 tests 1–3), RFC 5869 A.1–A.3
(HKDF-SHA-256), RFC 4231 test cases 1–4 and 6–7 (HMAC-SHA-256), RFC 8439 A.1 block 0 of the all-zero key and nonce
(ChaCha20 from block counter 0, as `MsgEncrypt` uses it).
