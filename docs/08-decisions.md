# SecMPro — Architecture Decision Records

Format: MADR-style, one entry per decision, numbered, never deleted (superseded entries are marked). New entries are appended by the implementer and require reviewer approval before the affected code merges. Each entry: Context · Decision · Alternatives considered · Consequences · Status.

---

### ADR-001 — Implementation language: Rust, single workspace
**Context.** Memory safety, mature crypto ecosystem (RustCrypto, dalek, libcrux, aws-lc-rs, rustls, arti), one binary for Linux and Windows.
**Decision.** Everything (relay, clients, protocol) in Rust, stable pinned toolchain, `forbid(unsafe_code)` except the two `secmp-sys-*` crates.
**Alternatives.** Go (weaker constant-time story, no Arti), C++ (memory safety), mixed Rust core + C#/.NET UI (extra a11y/IPC surface; WDA still needs native hooks anyway).
**Consequences.** Slint or egui for UI; cross-compilation with cargo-xwin; C dependencies limited to SQLCipher and AWS-LC.
**Status.** Accepted (owner confirmed 2026-09-25).

### ADR-002 — Own protocol implementation from public specs; no libsignal/vodozemac/OpenMLS
**Context.** libsignal is AGPL-3.0, "unsupported outside Signal", not on crates.io, Signal-specific wire formats, uses Round-3 Kyber in PQXDH by default; vodozemac has no PQ and 2026 findings (zero-DH, downgrade); OpenMLS is non-deniable and needs ordered commits (bad for v1.1 P2P).
**Decision.** Implement SecMP/1 (PQXDH-shaped handshake, Double-Ratchet-with-header-encryption + hybrid KEM step) from the public-domain Signal specifications on audited/verified primitives; use libsignal only as a reading reference.
**Consequences.** More code to write and verify (hence ProVerif models and mutation gates); freedom in licensing and wire format; no third-party protocol bugs inherited.
**Status.** Accepted.

### ADR-003 — Single ciphersuite, no negotiation
**Decision.** Exactly one suite (spec §3): X25519 + ML-KEM-768/1024 hybrids, Ed25519 ‖ ML-DSA-65 hybrid signatures, HKDF/HMAC-SHA-256, SHA3-256 in the KEM combiner, ChaCha20 EtM for E2E bodies, XChaCha20-Poly1305 elsewhere, Argon2id locally. A protocol version byte exists; mismatch is a hard failure.
**Alternatives.** Negotiable suites (downgrade surface; vodozemac lesson), pure PQ (no hedging against ML-KEM implementation bugs), NIST-curve variants for BSI conformance (deferred; could be a separate version).
**Consequences.** Future changes are new protocol versions, not runtime negotiation.
**Status.** Accepted.

### ADR-004 — Hybrid ratchet as "KEM at every DH step, KEM material in every message", not SPQR
**Context.** Signal's SPQR spreads ML-KEM material over many messages with erasure coding to save bandwidth on mobile. SecMPro v1 is desktop-only with 4 KiB cells. The plan review showed that carrying KEM material only in the first message of a chain makes the session unrecoverable when that cell is evicted (routine with constant-rate dummies).
**Decision.** Every DH ratchet step (both halves, per the Double Ratchet header-encryption variant) mixes an ML-KEM-768 secret into the root KDF; **every message of a chain carries the chain's encapsulation key and ciphertext**, so the header has one fixed length (2330 B) and any message of a chain can trigger the step (spec §7). The responder's bundle carries an ML-KEM-768 ratchet prekey so that the first step has the same size as all others.
**Alternatives.** SPQR port (complex, AGPL code); KEM material only in the first message of a chain (fragile, three header lengths); PQ only in the handshake (no PQ post-compromise security).
**Consequences.** Content capacity per cell is 1710 B (fragmentation for larger messages); PQ post-compromise security at every step; single header length simplifies trial decryption; simple to model.
**Status.** Accepted (rev. 2).

### ADR-005 — Header encryption and fixed-size cells
**Decision.** The Double Ratchet header (ratchet public key, counters, KEM material) is encrypted with header keys; every E2E unit is a 4096-byte cell; every link unit is a 4352-byte frame in both directions.
**Consequences.** Trial decryption over header keys only (one header length); relay and network learn nothing from sizes or headers; multi-cell fragmentation for large messages.
**Status.** Accepted.

### ADR-006 — TCP streams in v1, no QUIC
**Context.** Onion services carry TCP only; a constant-rate protocol needs no multiplexing; quinn's default ring provider has no ML-KEM.
**Decision.** SecMP-LINK runs over Tor onion streams (default) or TLS 1.3/TCP (direct, optional). QUIC is deferred to v1.x for direct mode only.
**Status.** Accepted.

### ADR-007 — Tor: Arti client in the app, C tor for hosting the relay's onion service
**Context.** Arti 2.6.0 (`arti-client` 0.46.x) onion-service *client* support is stable (vanguards, restricted discovery); *hosting* is still documented as experimental; the PoW client is experimental (see ADR-024).
**Decision.** Clients embed `arti-client` (pinned, features `onion-service-client` + `rustls`, with a CI upgrade job). The relay's onion service is hosted with C tor ≥ 0.4.9.11 as a sidecar. v1.1 introduces a `TorProvider` trait so both can be swapped.
**Status.** Accepted; revisit when Arti removes the hosting warning.

### ADR-008 — No identifiers; unidirectional capability queues (SimpleX-shaped)
**Decision.** Users have no server-side identity. Each contact pair uses two unidirectional queues with independent random ids and per-queue Ed25519 capabilities; queues are created by their recipient; identity keys never reach the relay.
**Alternatives.** Sealed sender with accounts (still identifies recipients and needs certificates), MLS delivery service (membership visible), enclave-based discovery (no Hetzner support; broken threat model).
**Status.** Accepted.

### ADR-009 — Constant-rate scheduler with three modes, recipient-chosen periods, and lifecycle blurring
**Decision.** Traffic is emitted in fixed slots independent of activity; Strict (per-queue isolated circuits), Balanced (single link, round-robin `SEND` + `FETCH_MULTI`), Low-bandwidth. Each queue's send period is chosen by its recipient (`PERIODS`) so that the recipient's drain rate always exceeds inbound rates. Dummies are ratchet messages. Frames are pre-built before the tick so persistence cost cannot shift timing. Link phases/lifetimes are randomised, control operations run on delayed one-shot links, queues are pooled, rotations overlap (spec §10.6) to blur lifecycle correlation. Parameters are finalised in M6 (ADR-018).
**Alternatives.** Push-based delivery (timing leaks), Poisson/mixnet timing (needs many users; possible later via a Nym transport), no cover traffic (relay sees activity), sender-chosen rates (Balanced recipients could not drain).
**Status.** Accepted (rev. 2).

### ADR-010 — Two-layer handshake envelope (invitation key outside, ephemeral-derived key inside)
**Context.** The initiator's identity public keys must not be visible to the relay, and must stay hidden even if the invitation leaks later and the relay recorded the cells.
**Decision.** The envelope is sealed under `K_inv` (from the invitation) and, inside, the identity and first message are sealed under `K_id` derived from `link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk` — computable by the responder before it knows the initiator, forward-secret once the OPK is deleted. Cells use random nonces, carry chunk ids inside the ciphertext, are persisted and re-sent byte-identical, and the responder ignores cells that fail to open (spec §6.5).
**Alternatives.** Single `K_inv` layer (identity exposed on later invitation leak); HPKE to the responder's prekey (second construction to model).
**Status.** Accepted (rev. 2).

### ADR-011 — Relay eviction: FIFO with sender notification; ratchet fast-forward
**Context.** Dummies are indistinguishable from real cells, so a full queue would otherwise block real messages while the recipient is offline; and constant-rate chains grow by ~8 640 positions per day, far beyond a classic `MAX_SKIP`.
**Decision.** On a full queue the relay evicts the oldest cell and returns its id; the sender re-encrypts and re-sends evicted real messages at the next slot. Capacity 128 cells. The receiving ratchet fast-forwards chains by up to `MAX_FF = 2^20` positions and stores skipped keys only for the last `SKIP_WINDOW = 256` positions (older cells cannot arrive any more). Recipient-chosen periods guarantee that an online recipient drains faster than senders fill (spec §10.2), so eviction only happens while the recipient is offline.
**Alternatives.** Relay-visible dummy flag (activity leak), reject-new-on-full (real messages starve behind dummies), sender-side pausing (pattern change), unbounded skipped-key storage.
**Consequences.** Slightly more outbox logic; bounded fast-forward CPU (≤ 2^20 HMACs).
**Status.** Accepted (rev. 2).

### ADR-012 — No Tor restricted discovery (client authorisation) on the relay onion
**Context.** A shared client-auth key would let the relay link every circuit of one client.
**Decision.** Relay onion is public; DoS defence via Tor PoW and intro DoS defence; queue creation gated by tokens.
**Status.** Accepted. (Per-contact restricted discovery *is* used in v1.1 on peer-hosted endpoints, where linkage is inherent anyway.)

### ADR-013 — UI framework: Slint (winit backend), egui as fallback
**Context.** Need native Wayland, DPI-aware Windows, AccessKit, GPU rendering, control of the native window handle for `WDA_EXCLUDEFROMCAPTURE`; webview stacks widen the scraping/JIT surface and have known content-protection regressions.
**Decision.** Slint ≥ 1.18 with the winit backend; go/no-go spike at the start of M8 (including WDA-before-first-paint and KWin exclusion from the app); egui/eframe as fallback.
**License note.** Slint is GPLv3 / royalty-free / commercial — compatible with the likely project license (OQ-1).
**Status.** Accepted pending spike.

### ADR-014 — Single process in v1; UI/core split in v1.x (M14)
**Decision.** v1 runs UI and core in one process with a channel-based `Api` boundary designed for later IPC. Mitigations incompatible with single-process GUI (ACG, Win32k lockdown, AppContainer) are deferred to M14.
**Status.** Accepted.

### ADR-015 — Dependency and license policy
**Decision.** Allowlisted crates only (cargo-deny), vetted (cargo-vet with imports), 7-day cooldown, exact pins for crypto crates, no git deps, no build scripts in our crates. Licenses: permissive set plus Slint and SQLCipher exceptions. Final project license: OQ-1.
**Status.** Accepted.

### ADR-016 — Update security: signed manifests now, TUF later
**Decision.** v1 ships minisign-signed release manifests with version monotonicity; TUF via `tough` in v1.x.
**Status.** Accepted.

### ADR-017 — No key-transparency server in v1
**Context.** KT needs many independent observers; one operator with two users can equivocate freely.
**Decision.** Mandatory out-of-band verification (safety number/QR), hard pinning, signed key succession; reconsider `akd`/keytrans when the user base is large.
**Status.** Accepted.

### ADR-018 — Traffic parameters (`PERIODS`, `T_BALANCED`, `T_LOWBW`, `F`, `F_M`)
**Decision.** Provisional values in spec §4.2; finalised after M6 measurements. Constraint: any value must keep the activity-independence invariant and ≤ ~300 MB/day per contact in Strict mode.
**Status.** Proposed (owner decides after M6).

### ADR-019 — Committing Encrypt-then-MAC for E2E bodies
**Context.** RFC 9771: AES-GCM/ChaCha20-Poly1305 are not key-committing; deniability requires no signatures on messages.
**Decision.** ChaCha20 + HMAC-SHA-256 EtM with per-message derived keys; XChaCha20-Poly1305 (+ HMAC commitment where keys could be substituted) elsewhere.
**Status.** Accepted.

### ADR-020 — Local store: SQLCipher via rusqlite, per-record sealing, Argon2id master-key wrapping
**Alternatives.** Own AEAD over sqlx (more code, less battle-tested), plaintext SQLite in an encrypted container (leaks structure via WAL/temp files).
**Status.** Accepted.

### ADR-021 — Classical authentication accepted; PQ signatures only on bundles
**Context.** No standardised, audited PQ deniable AKE exists; Signal and Apple also authenticate classically.
**Decision.** As in spec §6.6; hybrid IKS enables later PQ-authenticated bundles without key changes; tracked as RR-4.
**Status.** Accepted.

### ADR-022 — Relay keeps nothing on disk
**Decision.** RAM only; restart loses queues by design; clients recover via outbox/`RouteUpdate`. No encrypted spool.
**Alternatives.** Encrypted at-rest spool (metadata on disk: which queues exist and when; unattended-reboot key is a seizure key).
**Status.** Accepted.

### ADR-024 — Tor proof-of-work defence off in v1; Arti without `hs-pow-full`
**Context.** Arti's onion-service PoW *client* (`hs-pow-full`) is marked experimental and pulls LGPL dependencies (incompatible with ADR-015). A relay with PoW enabled would starve exactly those clients when the defence engages.
**Decision.** v1 relay: `HiddenServicePoWDefensesEnabled 0`, intro-DoS defence on, relay rate limits. Clients build Arti without `hs-pow-full`. Revisit when the PoW client is stable and the license question (OQ-16) is settled.
**Consequences.** Weaker DoS resistance of the onion service in v1 (RR to be tracked in the threat model at M10).
**Status.** Accepted.

### ADR-025 — Deterministic, re-creatable queue identifiers
**Context.** With one RAM-only relay, every restart (kernel updates, crashes) would otherwise destroy every session, since no queue would survive to carry a `RouteUpdate`.
**Decision.** `rid`/`sid` are derived from the queue's keys (spec §9.1); `QUEUE_NEW` is signed by the recipient key and idempotent; after `ERR_NOQUEUE` recipients re-create identical queues at a random delay and senders keep sending. No persistence on the relay.
**Alternatives.** Encrypted at-rest spool (metadata on disk; ADR-022); random ids + `RouteUpdate` (fails when the only relay restarts).
**Status.** Accepted.

### ADR-026 — Independent reference implementation for test vectors
**Context.** Vectors generated by the implementation under test only guard against regressions.
**Decision.** `ref/` contains a Python implementation of HybridKEM, HybridSign, MsgEncrypt, CAEAD, SAS, encodings, HX, TR and LINK written from the spec alone in a separate agent session (no access to the Rust code). Vectors are cross-generated and must match byte-for-byte before being frozen. Formal-model queries (`formal/CLAIMS.md`) are fixed by the reviewer before modelling, including queries expected to be false.
**Status.** Accepted.

### ADR-027 — Local store: SQLCipher primary, sealed-column SQLite fallback
**Context.** SQLCipher needs an OpenSSL backend; cross-compiling it to `x86_64-pc-windows-msvc` with cargo-xwin is unproven for this project.
**Decision.** M0 spikes the SQLCipher build. If it fails or cannot be made reproducible, the store uses plain SQLite (bundled) with **every** column sealed by `CAEAD` under per-table keys (CS-3.3), fixed-size dummy padding of rows, and no plaintext metadata beyond table names and row counts; the decision is recorded here at M0.
**Status.** Proposed (resolved at M0).

### ADR-028 — Relay identity distribution: `RelayInfo` per link, access-key commitment
**Context.** A relay that could hand each client a different static key or access key would link all of that client's links or identify it by token.
**Decision.** `RelayInfo` is returned on every `HELLO`, used only for that link, never cached; `akc = SHA-256("SecMP-Q/1 akc" ‖ relay_access_key)` is included in the signed `RelayInfo` and pinned in every `RelayRef`; clients refuse mismatches.
**Status.** Accepted.

### ADR-023 — Provisional crate choices for PQ primitives
**Decision.** ML-KEM: `libcrux-ml-kem` (hax/F*-verified, used by Signal/Google) with differential tests against RustCrypto `ml-kem` and `aws-lc-rs`; ML-DSA: RustCrypto `ml-dsa` (≥ version fixing RUSTSEC-2025-0144) with differential tests against `aws-lc-rs`; KATs on every target. Pinned exactly; bumps require KAT re-runs. Revisit at M11 with audit status.
**Status.** Accepted (implementer verifies exact versions at M1 and records them here).

---

*Template for new entries:*

### ADR-0NN — Title
**Context.** … **Decision.** … **Alternatives.** … **Consequences.** … **Status.** Proposed / Accepted / Superseded by ADR-0MM.
