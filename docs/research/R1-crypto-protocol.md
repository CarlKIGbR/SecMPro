---
title: "R1 — Cryptographic protocol state of the art (research brief)"
date: 2026-09-25
status: research input (not normative; the normative documents are docs/03-protocol-spec.md and docs/08-decisions.md)
---

# SecMPro: cryptography architecture research brief (state as of 2026-09-25)

**How this was checked.** I checked the claims against primary sources on the live web:
- signal.org specs and blog
- libsignal and SPQR source on GitHub `main`
- IETF datatracker
- NIST CSRC and SP PDFs
- the crates.io API (queried 2026-09-25)
- RustSec
- eprint
- BSI TR-02102-1

Anything I could not confirm from a primary source is marked **UNVERIFIED**.

## 0. Key takeaways
- **Signal's stack today** is PQXDH (X25519 plus Kyber-1024) followed by the Triple Ratchet (the Double Ratchet running alongside SPQR, which uses ML-KEM-768).
  - SPQR is mandatory for all sessions since libsignal v0.100.0 (2026-08-07).
  - All the specs are public domain, so they can be re-implemented freely.
- **libsignal** is AGPL-3.0-only, is not on crates.io, and its README says "Use outside of Signal is unsupported." SecMPro should re-implement from the specs and not depend on it.
- **Recommended baseline for SecMPro:**
  - Handshake: hybrid X25519 + ML-KEM (in X-Wing format).
  - Ratchet: Double Ratchet plus a KEM ratchet, with the two message keys mixed through a KDF for every message.
  - Identity keys: Ed25519 and ML-DSA-65 concatenated, used only to sign keys.
  - No version or algorithm negotiation at all (you can do this because the protocol is new).
- **The 2025–26 incidents were almost all in implementation "glue", not in the math:**
  - all-zero Diffie-Hellman outputs accepted (vodozemac, hpke-rs)
  - a counter that wraps around and reuses nonces (hpke-rs)
  - downgrade attacks (vodozemac)
  - platform-specific bugs in the "formally verified" libcrux library, one of which broke real Signal decryptions
  - timing leaks (RustCrypto ml-dsa, KyberSlash)
- **Key transparency is overkill for 1 server + 2 clients.** Use mandatory out-of-band verification, trust-on-first-use with hard key pinning, and a signed append-only key log whose signed tree heads the clients gossip to each other.

## 1. Signal protocol stack

**PQXDH**
- **Spec:** Revision 3 (2023-05-24, last updated 2024-01-23), by Kret and Schmidt, public domain.
  - Its parameters are generic: curve25519/448, SHA-256/512, and "pqkem, e.g. Crystals-Kyber-1024".
  - It gives post-quantum forward secrecy only. The spec says authentication "still relies on the hardness of the discrete log problem" and that PQXDH is "not designed to provide protection against active quantum attackers."
- **Revision 2 fixes:** Cryspen's ProVerif analysis (2023-10-20) found a key-encoding confusion and a KEM re-encapsulation attack. Revision 2 fixed both by requiring distinguishable encodings and by binding the KEM public key into the associated data or KDF.
- **Proofs and analyses:**
  - USENIX Security 2024 (Bhargavan et al.).
  - eprint 2024/702 (Fiedler/Günther).
  - The BAKE paper (eprint 2025/040, USENIX Security 2025) shows X3DH and PQXDH do not reach "optimal security" and proposes RingXKEM.
- **What libsignal actually does** (my reading of the `main` source, workspace 0.103.1; Signal has not announced this):
  - The shared key is `HKDF-SHA256(IKM = 0xFF×32 ‖ DH1..DH4 ‖ SS, info "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024")`.
  - That KDF outputs a root key, a chain key and a 32-byte SPQR authentication key.
  - The KEM key type 0x08 "Kyber1024" calls libcrux `kyber1024`, which is **Round-3 Kyber, not FIPS 203 ML-KEM**.
  - A FIPS 203 ML-KEM-1024 key type (0x0A) exists but sits behind a `mlkem1024` feature that is not enabled by default.

**SPQR / Triple Ratchet**
- **Documents:**
  - Announced 2025-10-02 (Connell, Schmidt).
  - ML-KEM Braid spec Rev 1 (2025-09-26).
  - Double Ratchet spec Rev 4 (2025-11-04), which adds §5 "Sparse PQ Ratchet" and §6 "Triple Ratchet".
- **How it works:**
  - It is a "sparse continuous key agreement" protocol built on ML-KEM's incremental interface. The spec allows ML-KEM-512/768/1024; Signal uses 768.
  - The encapsulation-key header is 64 bytes: a 32-byte seed plus a SHA3-256 hash of the key. That header alone is enough to compute the first ciphertext part, ct1 (960 B). So ct1 and the key's vector part (1152 B) are sent in parallel; the second ciphertext part, ct2, is 128 B.
  - Messages are split into chunks with Reed–Solomon erasure codes over GF(2^16), roughly 100-byte chunks. Of the 37 chunks per epoch, 35 can travel while both sides are sending.
  - It has an internal authenticator: a ratcheting HMAC-SHA256 keyed from the PQXDH output.
- **How keys are mixed (libsignal):**
  - Message keys = `HKDF-SHA256(salt = SPQR message key, IKM = Double Ratchet chain seed, "WhisperMessageKeys")`.
  - That feeds AES-256-CBC + HMAC-SHA256.
- **Rollout:**
  - The upgrade was MAC-protected against downgrade and locked after the first exchange.
  - From libsignal v0.100.0 it is required: the code now reads `min_version: V1 // Require that all clients speak SPQR`.
- **Code:** crate `spqr` v1.6.0, AGPL-3.0-only, depends on libcrux-ml-kem 0.0.10 (`incremental`, `mlkem768`) and hax-lib 0.3.7.
- **Verification:**
  - ProVerif models of about a dozen candidate designs; the Braid spec says correctness, forward secrecy, post-compromise security and mutual authentication are proven in the Dolev-Yao model.
  - hax/F* proofs of panic-freedom and "some correctness goals" run in CI. This is **not** a full proof of the implementation.
  - Academic basis: Triple Ratchet paper (Eurocrypt 2025, eprint 2025/078; its "Katana" KEM variant is not deployed) and Auerbach et al. (USENIX Security 2025).
- **Incident:** a byte-order mismatch between libcrux's portable and SIMD back ends in the incremental ML-KEM API caused real SPQR decryption failures.
  - Affected: libsignal v0.76.3–v0.86.9.
  - Fixed in v0.86.12 (2026-01-15).
  - Source: eprint 2026/192.

**Recommendations for SecMPro**
- Adopt the same shape: hybrid handshake, then Double Ratchet running alongside a KEM ratchet, with a per-message KDF mix.
- Use FIPS 203 ML-KEM from day one, not Round-3 Kyber.
- Make PQ mandatory with no negotiation path.
- v1 is desktop-only and not bandwidth-bound. A simpler, non-chunked KEM ratchet in the style of Apple's PQ3 (full encapsulation key and ciphertext per epoch) is acceptable. Chunking is worth it only if you need small messages or have MTU limits in the v1.1 P2P transport.
- Bind every public key, KEM ciphertext and protocol version into the KDF transcript.

## 2. libsignal and alternatives
- **libsignal:**
  - Latest release v0.102.3 (Sep 15); `main` is at 0.103.1; minimum Rust version 1.93.1.
  - AGPL-3.0-only (confirmed).
  - README: "Use outside of Signal is unsupported." The shipped products are the Java/Swift/TypeScript wrappers; the Rust APIs are versioned "best-effort".
  - Not published on crates.io. The crates.io crate named `libsignal-protocol` (0.1.0, 2019) is unrelated. So it can only be a git dependency.
  - It uses Signal-specific wire formats: message versions, Sesame, sealed sender.
  - **Verdict:** usable in law only if SecMPro is AGPL-compatible. Not advisable in any case: no support, frequent breaking changes, heavy dependency tree (BoringSSL, tonic).
- **vodozemac** (Matrix): 0.11.0 (2026-09-11), Apache-2.0.
  - One audit (Least Authority, 2022).
  - Advisories RUSTSEC-2024-0354 (non-constant-time base64) and RUSTSEC-2024-0342 (zeroization).
  - Soatok (2026-02-17) reported that Olm accepts all-zero Diffie-Hellman outputs and allows a V2→V1 downgrade by truncating the MAC. Matrix disputes the practical impact.
  - No PQ support. Not a suitable base.
- **OpenMLS** 0.9.0 (MIT) and **mls-rs** 0.56.0 (Apache/MIT; README says "not yet received a full security audit") are covered in §3.
- **"ratchetx":** no maintained crate found (UNVERIFIED).
- **libsignal-dezire** 0.2.0: 362 downloads, hobby-level. Avoid.

**Recommendation for SecMPro:** a lean in-house Rust implementation from Signal's public-domain specs, built on audited primitives. Use libsignal only as a reference, and only as a test oracle if the licence allows it.

## 3. MLS
- **Standards status:**
  - RFC 9420 is the protocol; RFC 9750 (Apr 2025) is the architecture.
  - draft-ietf-mls-extensions-10 (2026-07-06): issues raised in last call, not an RFC.
  - draft-ietf-mls-pq-ciphersuites-06 (2026-07-21, Mahy/Barnes): 11 suites (ML-KEM-768 hybrid with X25519 or P-256, pure ML-KEM, ML-KEM-1024+P-384, ML-DSA suites). State: "Waiting for WG Chair Go-Ahead", so no final code points yet.
- **OpenMLS** 0.9.0 (Phoenix R&D + CE Labs):
  - The README lists only 3 classical suites.
  - An experimental X-Wing suite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D, no IANA code point) runs through libcrux.
  - Size cost: KeyPackage 299 → 2669 B, Welcome 716 → 5457 B.
- **mls-rs** 0.56.0: claims 100% RFC 9420 conformance; providers OpenSSL, AWS-LC and RustCrypto. PQ suites: UNVERIFIED.
- **Formal verification:** MLS\* (Inria, F\*) verifies TreeSync (USENIX Security 2023) and TreeKEM (eprint 2025/410), but not TreeDEM, and not OpenMLS itself.
- **Metadata:** per RFC 9750, the delivery service sees group_id, epoch and content type.
  - If handshake messages are sent as PublicMessage, it also sees credentials and public group state.
  - The RFC recommends encrypted (PrivateMessage) handshakes.
  - KeyPackage fetches and message fan-out still leak membership.
- **Fit for SecMPro:**
  - MLS needs a globally ordered commit sequence, which is awkward for serverless P2P (v1.1).
  - Every MLS message is signed, so it is non-deniable.
  - For 1:1 chats the Triple-Ratchet design is simpler.

**Recommendation for SecMPro:** keep MLS off the v1 critical path. For later groups, use MLS with a hybrid PQ suite once code points exist. For small P2P groups, pairwise ratchets.

## 4. NIST, IETF and Apple PQ3

**NIST**
- FIPS 203/204/205 final on 2024-08-13.
- SP 800-227 final on 2025-09-18.
  - Its §4.6 covers composite/hybrid KEMs.
  - Approved key combiners are the SP 800-56C key-derivation methods and the SP 800-133 methods.
  - It cites X-Wing as an example.
- **HQC:** selected 2025-03-11 (IR 8545). No draft standard appears in the NIST news feed (UNVERIFIED that none exists).
- **FIPS 206 (FN-DSA/Falcon):**
  - On 2025-08-28 NIST said the draft was "essentially completed… submitted… for approval."
  - The CSRC page for the initial public draft (`/pubs/fips/206/ipd`) returns 404, so it is **not verifiably published**.
  - Floating-point constant-time concerns make it a poor fit for SecMPro in any case.
- IR 8610 (2026-05-14): nine additional signature schemes advance to Round 3.
- SP 800-230 initial public draft (2026-04-13): additional SLH-DSA parameter sets.
- IR 8547: initial public draft (Nov 2024) deprecates quantum-vulnerable algorithms by 2030 and disallows them by 2035. Final status UNVERIFIED.

**BSI TR-02102-1, version 2026-01 (2026-01-23)** — relevant for a German project:
- PQ key agreement only in hybrid form.
- Recommended KEMs: ML-KEM-768/1024, FrodoKEM-976/1344, Classic McEliece.
- Combiners: CatKDF (with HKDF/KMAC) or KeyCombine.
- Signatures: ML-DSA-65/87 and SLH-DSA, "hedged" variants. Hybrid signatures by concatenation. Classical signatures alone only until the end of 2035.
- It lists Brainpool/NIST curves; **X25519 is not listed**.

**IETF**
- draft-ietf-tls-ecdhe-mlkem-05: approved, in the RFC Editor queue. Code points X25519MLKEM768 0x11EC, SecP256r1MLKEM768 0x11EB, SecP384r1MLKEM1024 0x11ED.
- draft-connolly-cfrg-xwing-kem-11 (2026-09-23): individual/Independent-stream, Informational.
  - Combiner: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label).
  - Sizes: public key 1216 B, ciphertext 1120 B, secret key a 32-byte seed.
  - The changelog shows no combiner change since -07.
- draft-irtf-cfrg-hybrid-kems-12: defines UG/UK/CG/CK frameworks; X-Wing is the CG case.
- draft-ietf-hpke-pq-05: ML-KEM IDs 0x0040–0x0042, and MLKEM768-X25519 as 0x647a with the same sizes as X-Wing.
- draft-ietf-tls-mldsa-06 and draft-ietf-lamps-pq-composite-sigs-19 (includes ML-DSA-65+Ed25519): both in the RFC Editor queue.

**Apple PQ3** (2024-02-21, "Level 3")
- Kyber-1024 for the initial key agreement, Kyber-768 for rekeying.
- P-256 ECDH, and ECDSA P-256 for authentication.
- PQ rekey about every 50 messages and at least every 7 days.
- Keys chained with HKDF-SHA384; Padmé padding.
- Verified with Tamarin (Linker/Sasse/Basin, USENIX Security 2025) and a game-based proof by Stebila.

**Recommendations for SecMPro**
- Use X-Wing (X25519 + ML-KEM-768) for ephemeral and ratchet KEMs.
- Use ML-KEM-1024 hybrid for long-lived prekeys, as Signal and Apple do.
- If BSI conformance is a goal, make the curve and combiner configurable (P-256/P-384 with CatKDF).
- Use TLS 1.3 with X25519MLKEM768 plus a pinned server key as transport defence-in-depth only.

## 5. Rust crates (versions from crates.io API, 2026-09-25)

| Crate | Version (date) | Assurance / issues | Verdict |
|---|---|---|---|
| ml-kem (RustCrypto) | 0.3.2 (2026-05-10) | README: "never been independently audited"; pure Rust; RustSec's recommended replacement for pqc_kyber | Candidate |
| libcrux-ml-kem (CE Labs, a Cryspen spin-off since 2026-06-25) | 0.0.10 (2026-07-15) | hax/F\*-verified portable and AVX2 code, including secret independence. NEON and incremental API only partly verified. RUSTSEC-2025-0133 (aarch64 SHA-3); byte-order bug (Jan 2026); spec-level proof bugs (eprint 2026/192, vendor disputes some). Used by Signal and Google | Candidate; pin it and run known-answer tests on every platform |
| aws-lc-rs | 1.18.1 (2026-09-01) | ML-KEM-512/768/1024 and ML-DSA-44/65/87 stable; FIPS mode through AWS-LC-FIPS 4.x. AWS-LC FIPS 3.0 was the first FIPS 140-3 module with ML-KEM (Dec 2024, "in process" at the time). Needs a C/asm build | Pick if FIPS matters |
| x-wing (RustCrypto) | 0.1.0 (2026-07-09) | Unaudited; tracks draft-06 | Use, or write the ~20-line combiner yourself; check test vectors against -11 |
| pqcrypto-mlkem / pqc_kyber | 0.1.1 / 0.7.1 | Unmaintained (RUSTSEC-2026-0161; PQClean archived July 2026) / KyberSlash, unpatched (RUSTSEC-2023-0079) | **Avoid** |
| ml-dsa (RustCrypto) | 0.1.1 (2026-06-05) | Unaudited; RUSTSEC-2025-0144 / CVE-2026-22705 timing leak (hardware division), fixed | Use with caution, or use aws-lc-rs |
| libcrux-ml-dsa | 0.0.10 | RUSTSEC-2026-0076/0077/0125/0126 (FIPS 204 verifier violations and more) | Caution |
| x25519-dalek / ed25519-dalek / curve25519-dalek | 3.0.0 / 3.0.0 / 5.0.0 (2026-07-06) | 280 functions formally verified with Verus (as of v4.1.3); fiat-crypto back end available; RUSTSEC-2024-0344 fixed | Use; always call `was_contributory()` and `verify_strict` |
| chacha20poly1305 / aes-gcm | 0.11.0 / 0.11.1 | NCC Group audit, no significant findings; constant-time design | Use, with a commitment layer (§9) |
| hkdf / hmac / sha2 / sha3 | 0.13 / 0.13 / 0.11 / 0.12 | Mature RustCrypto | Use |
| argon2 | 0.6.0 | — | Argon2id for the local keystore |
| zeroize / secrecy | 1.9.0 / 0.10.3 (last release 2024-10) | — | Use zeroize |
| hpke (rozbb) / hpke-rs (CE Labs) | 0.14.1 / 0.7.0 | hpke: no paid audit (Cloudflare reviewed v0.8). hpke-rs: RUSTSEC-2026-0069/0070/0071 (nonce reuse, CVSS 9.3) | Prefer hpke or aws-lc-rs |
| snow / clatter (PQ Noise) | 0.10.0 / 2.3.0 | Neither audited; snow had RUSTSEC-2024-0011 (fixed) | Transport only |
| ring | 0.17.14 (2025-03-11) | Last release March 2025; no ML-KEM (UNVERIFIED) | Prefer aws-lc-rs |
| blake3 | 1.8.7 | — | Not needed; stay with SHA-2/SHA-3 |

**Which ML-KEM is constant-time and audited?** I could not verify a published third-party audit for any pure-Rust ML-KEM crate. The strongest evidence is:
- libcrux: formal secret-independence proofs plus large-scale deployment.
- aws-lc: FIPS validation. CMVP testing is functional testing, not a side-channel audit.

## 6. Key transparency
- **Signal** (launched 2026-08-11):
  - Structure: a log tree plus prefix trees.
  - Privacy: identifiers are hidden behind a verifiable random function (VRF) and values behind a keyed hash.
  - It maps phone number or username to the ACI identity key.
  - Based on draft-ietf-keytrans-protocol, now -05 (2026-07-06, McMillion/Linker). The draft defines contact-monitoring, third-party-management and third-party-auditing modes.
  - Auditors: Cloudflare and Trail of Bits. Clients need signed tree heads from Signal plus both auditors, each no older than 7 days.
  - Server: signalapp/key-transparency-server (Go, AGPL). Client verifier: `libsignal-keytrans` (Rust, AGPL).
  - Limits: needs the phone number, and cannot tell a legitimate re-registration from a server attack.
- **WhatsApp (2023) and Messenger (2025-11-20):**
  - Meta's Auditable Key Directory (AKD), based on the SEEMless/Parakeet papers, with Cloudflare as auditor.
  - About 2 minutes per publish, hundreds of thousands of keys per epoch.
  - Crate akd 0.13.0 (2026-08-13), MIT/Apache; NCC audited v0.9.0 in 2023.
- **Apple Contact Key Verification** (Oct 2023):
  - A CONIKS-style verifiable log-backed map, indexed by VRF output.
  - An account signing key synced through iCloud Keychain.
  - Signed mutation timestamps with a 48-hour maximum merge delay.
  - Log hashes are gossiped inside a small percentage of messages.
  - Manual verification by short comparison codes (Vaudenay SAS).

**Recommendations for SecMPro (self-hosted)**

Transparency only works with many independent observers; with one server and two clients, a malicious server can show each side a different view.
1. Require out-of-band verification before a contact counts as "verified": a QR code or SAS over the full hybrid identity fingerprint, at least 256 bits.
2. Trust on first use with hard pinning. A changed key blocks the conversation until re-verified; it is not just a banner.
3. The server keeps an append-only Merkle log (RFC 9162 style) of all key and device events. Clients embed the signed tree head inside E2E messages and check consistency proofs, the way Apple gossips log hashes.
4. Consider `akd` only if the user base grows.
5. v1.1 P2P: the identity *is* the key; pairing is by QR code; there is no directory.

## 7. Deniability and authentication
- **What the PQXDH spec says:**
  - It aims for X3DH-style offline deniability.
  - Adding a PQ identity key that signs PQ prekeys would protect against a malicious server, but "does not provide mutual authentication."
  - NIST's schemes offer no PQ *deniable* mutual authentication; that would need PQ ring signatures or designated-verifier signatures ("We urge the community…").
- **SPQR** authenticates with a symmetric HMAC, which is compatible with deniability. But its authentication is only as strong as PQXDH's classical authentication.
- **Research:**
  - K-Waay (USENIX Security 2024; split-KEMs, no ring signatures).
  - Sparrow-KEM (ASIACCS 2025): 5.1× less communication, 40× faster.
  - RingXKEM (USENIX Security 2025).
  - None is standardized and none has audited Rust code.
  - An unreviewed ProVerif repository (JakeGinesin/signal-proofs) claims responder deniability fails for PQXDH + Double Ratchet (UNVERIFIED).
- **Deployed practice:** Signal and Apple still authenticate classically. Harvest-now-decrypt-later threatens confidentiality today; authentication is only threatened once a quantum computer exists.

**Recommendations for SecMPro**
- Identity key = Ed25519 ‖ ML-DSA-65, and both signatures must verify. This matches BSI's concatenation hybrid and the IETF composite ML-DSA-65+Ed25519.
- Sign only prekeys, device certificates and log entries, never messages. That keeps transcripts X3DH-deniable. ML-DSA-65 is 1952 B per public key and 3309 B per signature, which is fine on desktop.
- Authenticate sessions with DH/KEM plus MAC.
- Decide explicitly whether deniability is a requirement at all.
- Track split-KEM designs for v2.

## 8. Formal verification tooling
- **ProVerif 2.05** (latest on opam): unbounded analysis; used for PQXDH and for SPQR in CI. The most practical choice.
- **Tamarin 1.12** (2026-03-08): won the 2026 Levchin Prize; Springer book published 2025; used for PQ3 and TLS 1.3. More expressive than ProVerif, steeper to learn.
- **Verifpal 1.0** (2026-08-15):
  - Rewritten engine with KEM primitives and a soundness theorem.
  - Limits: bounded sessions only, and no observational equivalence, so it cannot prove deniability.
  - Good for quick design iteration.
- **hax:**
  - v0.4.0 release candidate (Sept 2026), with F\* and Lean (via aeneas) back ends.
  - Its lead developer left in Jan 2026.
  - eprint 2026/192 ("Verification Theatre", Kobeissi, disputed by the vendor) shows admitted proofs and specification errors inside libcrux.
  - Lesson: what is verified, and what is not, must be written down explicitly.

**Recommendation for SecMPro:**
- Maintain ProVerif models of the handshake, ratchet and key log from the design phase, in CI.
- Use Tamarin for the multi-device state machine if you have the capacity.
- Commission an external computational proof and a code audit before 1.0.
- Add cargo-fuzz, Wycheproof and known-answer tests, and differential tests across implementations.

## 9. Attacks and lessons (2023–2026)
1. **vodozemac (Feb 2026):** all-zero DH accepted; V2→V1 downgrade.
   - Reject non-contributory DH results; allow no negotiation.
2. **hpke-rs:** 32-bit sequence number wraps → nonce reuse (RUSTSEC-2026-0071, CVSS 9.3); missing X25519 zero check.
   - Use 64-bit `checked_add` counters and a hard rekey limit.
3. **libcrux:** RUSTSEC-2025-0133 (aarch64); incremental ML-KEM byte-order bug (Signal outage); libcrux-sha3 SHAKE wrong output on repeated squeezes (RUSTSEC-2026-0074/0207, July 2026).
   - Run known-answer tests in CI on every target (x86_64 Linux/Windows, aarch64); pin versions; use cargo-vet and cargo-deny.
4. **Timing leaks:** KyberSlash; RustCrypto ml-dsa division; curve25519-dalek compiler-introduced branch.
5. **Signal message injection** (Truong/Terzo/Paterson, USENIX Security 2026):
   - A sealed-sender bug on Android had allowed undetectable message injection since 2018, caused by missing key checks and lost context across components. A separate username-resolution flaw was also fixed.
   - Patched within 2 and 8 days.
   - Lesson: bind the sender identity inside the AEAD and verify in exactly one place.
6. **Session** (eprint 2026/1247, WOOT '26): no mutual public-key authentication and no binding of sequence counters.
   - Consequences: impersonation, timestamp forgery, replay.
   - Lesson: put counters and timestamps in the AEAD associated data.
7. **Prekey Pogo** (WOOT '25): targeted one-time-prekey depletion. **Careless Whisper:** tracking users through silent delivery receipts.
   - Rate-limit prekey bundle fetches; send no receipts to unaccepted contacts.
8. **KEM binding:** PQXDH re-encapsulation attack (2023); ML-KEM is not MAL-BIND-K-CT when keys are stored in expanded form (Schmieg, 2024).
   - Store seed-only decapsulation keys; hash the public key and ciphertext into the transcript.
9. **AEAD key commitment:** RFC 9771 (May 2025) confirms AES-GCM and ChaCha20-Poly1305 are not committing.
   - Add a commitment, e.g. HMAC encrypt-then-MAC or a commitment tag. This matters most for attachments, multi-device, groups and abuse reporting.
10. **Older lessons:** Threema's "Three Lessons" (USENIX Security 2023) led to the Ibex protocol, proven in 2023. Telegram's key exchange (Eurocrypt 2025) could only be proven under non-standard assumptions.

## Open questions and uncertainties
- Whether Signal plans to move PQXDH from Round-3 Kyber-1024 to ML-KEM-1024. The code has it behind a feature flag; no announcement found.
- FIPS 206 initial draft, HQC draft and final NIST IR 8547: none verifiable as published.
- Whether the RustCrypto x-wing crate (draft-06) is byte-compatible with -11. The changelog suggests it is; confirm with test vectors.
- Whether mls-rs has PQ suites, and whether ring has an ML-KEM API.
- Whether AWS-LC's ML-KEM has formal verification or side-channel audits (it may derive from mlkem-native).
- How complete libcrux's fixes are for the eprint 2026/192 findings; the claims are contested.
- The deniability status of PQXDH + Double Ratchet (the unreviewed ProVerif claim).
- The BSI stance on X25519 in hybrids; a German deployment should check TR-02102-2/-3.

## Sources
- https://signal.org/blog/spqr/
- https://signal.org/docs/specifications/pqxdh/
- https://signal.org/docs/specifications/mlkembraid/
- https://signal.org/docs/specifications/doubleratchet/
- https://signal.org/blog/automatic-key-verification/
- https://github.com/signalapp/libsignal
- https://github.com/signalapp/libsignal/releases
- https://raw.githubusercontent.com/signalapp/libsignal/main/rust/protocol/src/kem.rs
- https://raw.githubusercontent.com/signalapp/libsignal/main/rust/protocol/src/pqxdh.rs
- https://raw.githubusercontent.com/signalapp/libsignal/main/rust/protocol/src/ratchet.rs
- https://raw.githubusercontent.com/signalapp/libsignal/main/Cargo.toml
- https://github.com/signalapp/SparsePostQuantumRatchet
- https://github.com/signalapp/key-transparency-server
- https://cryspen.com/post/signal-spqr-verification/
- https://cryspen.com/post/pqxdh/
- https://cryspen.com/post/announcing-ce-labs/
- https://eprint.iacr.org/2025/078
- https://www.usenix.org/conference/usenixsecurity25/presentation/auerbach
- https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf
- https://eprint.iacr.org/2024/702.pdf
- https://eprint.iacr.org/2025/040
- https://eprint.iacr.org/2026/192.pdf
- https://github.com/JakeGinesin/signal-proofs
- https://datatracker.ietf.org/doc/draft-ietf-mls-extensions/
- https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/
- https://www.rfc-editor.org/rfc/rfc9750.html
- https://github.com/openmls/openmls
- https://blog.openmls.tech/posts/2024-04-11-pq-openmls/
- https://github.com/awslabs/mls-rs
- https://github.com/Inria-Prosecco/mls-star
- https://csrc.nist.gov/Projects/post-quantum-cryptography/news
- https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/CsWPP35LJWw/m/7pOF01tIAgAJ
- https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist
- https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption
- https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf
- https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html
- https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/
- https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
- https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt
- https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/
- https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
- https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/
- https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-properties/ (RFC 9771)
- https://security.apple.com/blog/imessage-pq3/
- https://eprint.iacr.org/2024/1395
- https://security.apple.com/blog/imessage-contact-key-verification/
- https://blog.trailofbits.com/2026/08/11/how-trail-of-bits-helps-verify-the-integrity-of-your-signal-chats
- https://github.com/facebook/akd
- https://engineering.fb.com/2025/11/20/security/key-transparency-comes-to-messenger/
- https://blog.cloudflare.com/key-transparency/
- https://crates.io/api/v1/crates/ (per-crate queries)
- https://docs.rs/aws-lc-rs/latest/aws_lc_rs/kem/index.html
- https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation
- https://rustsec.org/advisories/RUSTSEC-2023-0079.html
- https://rustsec.org/advisories/RUSTSEC-2025-0144.html
- https://rustsec.org/advisories/RUSTSEC-2025-0133.html
- https://rustsec.org/advisories/RUSTSEC-2026-0071.html
- https://rustsec.org/advisories/RUSTSEC-2026-0161.html
- https://rustsec.org/advisories/RUSTSEC-2026-0207.html
- https://rustsec.org/packages/libcrux-ml-dsa.html
- https://rustsec.org/packages/hpke-rs.html
- https://soatok.blog/2026/02/17/cryptographic-issues-in-matrixs-rust-library-vodozemac/
- https://matrix.org/blog/2024/08/libolm-deprecation/
- https://www.flyingpenguin.com/rustsec-integrity-breach-hides-dangerous-crypto-flaw/
- https://eprint.iacr.org/2024/120
- https://eprint.iacr.org/2025/853
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/8cNYhg23B9k
- https://eprint.iacr.org/2026/484
- https://eprint.iacr.org/2026/1247
- https://arxiv.org/abs/2504.07323
- https://eprint.iacr.org/2025/451
- https://www.usenix.org/system/files/usenixsecurity23-paterson.pdf
- https://threema.com/en/blog/security-proof-ibex
- https://tamarin-prover.com/news.html
- https://symbolic.software/blog/2026-08-15-verifpal-1-0/
- https://hax.cryspen.com/blog/archive/2026/
- https://bblanche.gitlabpages.inria.fr/proverif/
