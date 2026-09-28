# Kickoff prompt — the independent reference implementation (`ref/`, ADR-026)

**Owner set-up before starting the session.** Create a directory that contains **nothing but** these files, copied from the main repository (the session must never see the Rust code):

```
~/coding/claude_code/SecMPro-ref/
├── docs/03-protocol-spec.md        (revision 2.1)
├── vectors/SCHEMA.md
└── ref/README.md
```

Start a fresh Claude Code session **in that directory** and paste everything below the line. When the session reports that a suite is done, copy its `ref/` directory and the generated `vectors/*.json` into the main repository (`SecMPro/ref/`, `SecMPro/vectors/ref/`) so that `cargo xtask vectors` can cross-check them. Never copy anything from the main repository into the ref directory except the three files above (and, later, updated spec revisions or `SCHEMA.md`).

---

You are writing the **independent reference implementation** of the SecMP/1 protocol for the SecMPro project, in Python. Its only purpose is to generate test vectors from the specification alone, so that the project's Rust implementation — which you will never see — can be checked against an implementation that shares no code, no author session and no assumptions with it. Your work product is correctness, not performance or polish.

## 1. The rule that defines this session

You work **only** from `docs/03-protocol-spec.md` (the normative protocol specification) and `vectors/SCHEMA.md` (the vector format). You have no access to the Rust implementation and you must not try to obtain it (no fetching of the GitHub repository, no asking for it). If the specification is ambiguous, under-specified or arithmetically wrong, you **do not guess**: you write the issue into `ref/SPEC-QUESTIONS.md` (section, quote, the two possible readings, which one you would choose and why) and stop the affected suite until the owner brings back the reviewer's answer. Ambiguities you discover are the most valuable output of this session — they would otherwise be resolved silently and identically wrong on both sides.

## 2. What to build (in this order; one suite at a time, each finished with generated vectors and tests)

Milestone M1 suites (see `vectors/SCHEMA.md` for exact input/output keys):

1. `hkdf-labels` — HKDF-SHA-256 with the label discipline of spec §3 and Appendix A.
2. `caead` — the committing AEAD wrapper of spec §3.4.
3. `msgencrypt` — the Encrypt-then-MAC construction of spec §3.3.
4. `hybridkem-768` and `hybridkem-1024` — spec §3.2, with deterministic ML-KEM key generation (`KeyGen_internal(d, z)`) and encapsulation (`Encaps_internal(ek, m)`) so that vectors are reproducible.
5. `hybridsign` — spec §3.5, Ed25519 (deterministic) ‖ ML-DSA-65 hedged with the supplied `rnd`, context string = label.
6. `fingerprint` and `sas` — spec §6.2 and §6.7 (note the exact iteration definition in §6.7).

Later milestones (you will be told when): `encodings` (Appendix D), `hx` (§5–6), `tr` (§7), `link` (§8).

## 3. Engineering rules for `ref/`

- Python ≥ 3.12, a single package `ref/secmp_ref/` with one module per construction, plus `ref/gen_vectors.py` (writes `vectors/<suite>.json` in the schema) and `ref/tests/` (pytest).
- Primitives come from independent, well-known libraries — recommended: `kyber-py` (ML-KEM), `dilithium-py` (ML-DSA), PyNaCl (X25519, Ed25519, XChaCha20-Poly1305), `cryptography` (ChaCha20, HMAC, HKDF), `hashlib` (SHA-2, SHA-3, SHAKE). Pin exact versions in `ref/requirements.txt`. **Before using a library, add a test that checks it against official vectors** (NIST ACVP or FIPS 203/204 known-answer tests for ML-KEM/ML-DSA; RFC 7748 §6.1, RFC 8032 §7.1, RFC 8439 §2.8.2, RFC 5869 A.1 and the XChaCha20-Poly1305 draft vectors). If a library cannot do deterministic ML-KEM key generation from (d, z) or deterministic ML-DSA hedged signing with a supplied `rnd`, say so in `ref/SPEC-QUESTIONS.md` and pick another library — do not weaken the vectors by using non-deterministic APIs.
- The constructions themselves (combiner, EtM, CAEAD, HybridSign, fingerprint, SAS, and later the encodings, handshake, ratchet and link) are written by hand, straight from the spec text, with a comment citing the spec section on every step. Byte-string concatenation order and every label must be copied literally from the spec.
- Every construction has: positive tests, the negative cases listed in `vectors/SCHEMA.md` and spec Appendix C (uniform rejection), and a size assertion for every fixed-size object against spec Appendix B.
- Seeds: derive all randomness for case *i* of a suite exactly as `SCHEMA.md` prescribes (`SHA-256("SecMP-vectors/1" ‖ suite ‖ i)` expanded with SHAKE-256), so that the Rust side derives the same inputs.
- No network access is needed after installing the libraries. No secrets, no real keys, nothing outside `ref/` and `vectors/`.
- Plain, readable code beats clever code. Readability is a review property here.

## 4. Reporting

For each finished suite, end your turn with: the suite name, the number of positive and negative cases, the library versions used and which official vectors they were checked against, any entry you added to `ref/SPEC-QUESTIONS.md`, and the SHA-256 of the generated `vectors/<suite>.json`. The owner relays questions to the reviewer and brings answers back; do not proceed past an open question that affects the suite you are on.

## 5. First message back

Before writing any code, reply with (1) a ≤ 10-line summary of the six M1 constructions in your own words with their spec sections, (2) any ambiguity you already see in §3, §6.2 or §6.7 of the spec, (3) the library versions you intend to pin. Then proceed with suite 1.
