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
**Update 2026-09-28 (owner decision OQ-1).** The project license is **AGPL-3.0-or-later** for all crates (`LICENSE` holds the AGPL-3.0 text; `license = "AGPL-3.0-or-later"` in `[workspace.package]`). SPDX policy: every first-party source file starts with `SPDX-License-Identifier: AGPL-3.0-or-later` in the file type's comment syntax, enforced by `cargo xtask policy`. `deny.toml` applies the dependency allowlist of `06` §3 (our own unpublished crates are exempt from it via `[licenses.private] ignore = true`); Slint's GPL-3.0-only branch is the single copyleft exception (compatible with AGPL-3.0, section 13).
**Update 2026-09-28 (M0 review).** Publisher trust: `cargo vet trust` for dtolnay and BurntSushi (`safe-to-deploy`, end 2027-09-28), justified by their trust in ≥ 2 imported audit sets; rule in `06` §3.
**Status.** Accepted; license decided 2026-09-28.

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
**Update 2026-09-28 (owner decision OQ-17).** The owner starts the separate `ref/` session before M1; the reviewer supplies its brief. In M0 `ref/` contains only a README stating this rule; the implementer never writes `ref/` code.
**Status.** Accepted.

### ADR-027 — Local store: SQLCipher primary, sealed-column SQLite fallback
**Context.** SQLCipher needs an OpenSSL backend; cross-compiling it to `x86_64-pc-windows-msvc` with cargo-xwin is unproven for this project.
**Decision.** M0 spikes the SQLCipher build. If it fails or cannot be made reproducible, the store uses plain SQLite (bundled) with **every** column sealed by `CAEAD` under per-table keys (CS-3.3), fixed-size dummy padding of rows, and no plaintext metadata beyond table names and row counts; the decision is recorded here at M0.
**M0 outcome 2026-09-28 (spike (a), `docs/reviews/M0-spikes.md`; rule of Amendment A1 §4: fallback only if the native Windows build fails).** `rusqlite` 0.40.2 `bundled-sqlcipher-vendored-openssl` (SQLCipher 4.14.0, OpenSSL 3.6.3) builds and runs natively on `windows-latest`, Linux and macOS → **SQLCipher remains primary; the fallback is not triggered.** The cargo-xwin cross-build to `x86_64-pc-windows-msvc` fails (OpenSSL's `VC-WIN64A` configuration requires a Windows perl and `nmake`), so the Windows release-build route and its reproducibility are open questions for M11 (options listed in the spike record).
**Status.** **Accepted** (M0 review, 2026-09-28): SQLCipher stays primary; the Windows build route is settled by ADR-034 (native Windows builds).

### ADR-028 — Relay identity distribution: `RelayInfo` per link, access-key commitment
**Context.** A relay that could hand each client a different static key or access key would link all of that client's links or identify it by token.
**Decision.** `RelayInfo` is returned on every `HELLO`, used only for that link, never cached; `akc = SHA-256("SecMP-Q/1 akc" ‖ relay_access_key)` is included in the signed `RelayInfo` and pinned in every `RelayRef`; clients refuse mismatches.
**Status.** Accepted.

### ADR-023 — Provisional crate choices for PQ primitives
**Decision.** ML-KEM: `libcrux-ml-kem` (hax/F*-verified, used by Signal/Google) with differential tests against RustCrypto `ml-kem` and `aws-lc-rs`; ML-DSA: RustCrypto `ml-dsa` (≥ version fixing RUSTSEC-2025-0144) with differential tests against `aws-lc-rs`; KATs on every target. Pinned exactly; bumps require KAT re-runs. Revisit at M11 with audit status.
**Versions (M1, live-checked on crates.io 2026-09-28; approved by the reviewer in the M1 brief; all ≥ 7 days old, at or above the patched version of every RustSec advisory for the crate).** `libcrux-ml-kem =0.0.10` (`default-features = false`, features `mlkem768`, `mlkem1024`; its build scripts add the NEON backend on aarch64 and the run-time-selected AVX2 backend on x86_64, see ADR-037); `ml-dsa =0.1.1` (fixes RUSTSEC-2025-0144; `default-features = false`, `zeroize`); `x25519-dalek =3.0.0`, `ed25519-dalek =3.0.0` (`curve25519-dalek 5.0.0` transitively; RUSTSEC-2024-0344 and RUSTSEC-2022-0093 fixed); `chacha20 =0.10.2`; `chacha20poly1305 =0.11.0`; `hmac =0.13.0`; `hkdf =0.13.0`; `sha2 =0.11.0`; `sha3 =0.11.0` (not 0.12.0: `ml-kem 0.3.2` depends on 0.11 and `deny.toml` bans duplicate versions); `subtle =2.6.1`; `zeroize =1.9.0`; `getrandom =0.4.3`; `rand_core 0.10.1` (transitive only, see ADR-037). Differential partners (dev-dependencies of `secmp-testkit` only): `ml-kem =0.3.2`, `aws-lc-rs =1.18.1` (`aws-lc-sys 0.45.0`, RUSTSEC-2026-0044…0048 fixed). The full M1 dependency set, its vetting and the feature choices are in ADR-037.
**Status.** Accepted; versions recorded 2026-09-28.

### ADR-029 — Development host, repository hosting and CI topology
**Context.** OQ-3 and Amendment A1 (2026-09-28): the development host is macOS on Apple Silicon, not Linux; the libvirt Windows 11 VM does not exist yet; the repository is hosted on GitHub.
**Decision.**
- *Development host*: macOS `aarch64-apple-darwin` (development only — v1 ships for Linux and Windows). The full test suite and every KAT run natively on it; `aarch64-apple-darwin` is a pinned toolchain target and a first-class KAT target. Linux-target builds from macOS use `cargo-zigbuild`; Linux-only code is not run locally.
- *Hosting*: private GitHub repository `CarlKIGbR/SecMPro`; `main` advances only through reviewed pull requests (squash merge); nobody pushes to `main` directly.
- *CI for M0–M8*: GitHub-hosted `ubuntu-latest` runs the full Linux pipeline (`ci-fast` on every push/PR plus steps 13–14; `ci-full --strict` nightly and on demand); GitHub-hosted `windows-latest` is the Windows gate (native MSVC build + tests, `cargo xtask win-test --backend github`); a `cargo-xwin` cross-build job records the cross-build outcome (`continue-on-error` allowed in M0 only).
- *From M9*: an ephemeral self-hosted libvirt Windows 11 VM runner (overlay reverted per run, no secrets, never runs pull requests) behind `cargo xtask win-test --backend libvirt`; required for the screen-capture tests of `04` §7.
- *M11*: Linux release builders (GitHub-hosted plus a second, independent builder) for the two-builder reproducibility check.
**Alternatives.** Self-hosted Forgejo/Gitea with own runners (more operations work, no benefit for M0–M8); the libvirt VM from M0 (does not exist yet); a Linux development host (not the owner's machine).
**Consequences.** Windows evidence for M0–M8 comes from GitHub-hosted `windows-latest`, not from the VM; this is an owner decision, not a gap. The VM gate becomes mandatory at M9. Branch protection and rulesets are not available for private repositories on GitHub's free plan (API: HTTP 403), so "no direct pushes to `main`" is enforced by process until the owner upgrades the plan or makes the repository public.
**Status.** Accepted (owner, 2026-09-28; OQ-3 and Amendment A1).

### ADR-030 — Product and protocol naming
**Decision.** Product name **SecMPro**; protocol name **SecMP/1**; URI scheme **`secmp://`**; crate prefix **`secmp-`**.
**Consequences.** The invitation URI format frozen in the M3/M4 vectors uses `secmp://`.
**Status.** Accepted (owner, 2026-09-28; OQ-2).

### ADR-031 — xtask dependencies and external tools
**Context.** `xtask` must read `cargo metadata`, `cargo llvm-cov` exports, crates.io sparse-index lines and `gh` output, all JSON.
**Decision.** One direct dependency: `serde_json` `=1.0.151` (`default-features = false`, `std`), used only by `xtask`. HTTP is done by invoking `curl`; GitHub by `gh`; everything else by invoking the pinned tools (`xtask/src/tools.rs`: cargo-nextest 0.9.145, cargo-deny 0.20.2, cargo-vet 0.10.2, cargo-audit 0.22.2, cargo-auditable 0.7.6, cargo-cyclonedx 0.5.9, cargo-fuzz 0.13.2, cargo-mutants 27.1.0, cargo-llvm-cov 0.9.1, cargo-xwin 0.23.1, cargo-zigbuild 0.23.4, kani-verifier 0.68.0, nightly-2026-09-21 for Miri/fuzz, ProVerif 2.05, zig 0.16.0). Tools are not Cargo dependencies; their pins follow the 7-day cooldown.
**Alternatives.** A hand-written JSON parser (more first-party parsing code in the gate that checks everything else); `cargo_metadata` (adds `serde` derive, `semver`, `camino`, `cargo-platform`); an HTTP client crate (a TLS stack inside build tooling).
**Maintenance / audit status.** `serde_json` is maintained by David Tolnay and ubiquitous. At 1.0.151 neither it nor its transitive crates are covered by the imported cargo-vet audits (the importers trust the publisher instead), so they are tracked exemptions (`supply-chain/README.md`); none is in the `secmp-crypto`/`secmp-proto` closure.
**Status.** Accepted (M0 review, 2026-09-28).

### ADR-032 — Release path remapping injected by xtask
**Context.** `06` §6 asks for `--remap-path-prefix` of `$CARGO_HOME` and the workspace to be fixed in `.cargo/config.toml`. Cargo 1.98.1 does not expand variables in config values, and `trim-paths` is still unstable (`-Z trim-paths`).
**Decision.** `.cargo/config.toml` holds the static flags (`-C target-cpu=x86-64-v2` for both x86_64 targets, `-C control-flow-guard` for `x86_64-pc-windows-msvc`). For release builds `cargo xtask` adds `--config target.<triple>.rustflags=["--remap-path-prefix=<workspace>=/secmpro","--remap-path-prefix=<CARGO_HOME>=/cargo"]`; Cargo merges config arrays, so the static flags stay. Replaced by `trim-paths` once stable.
**Alternatives.** Literal paths in `.cargo/config.toml` (valid only inside a fixed build container — may be combined with this in M11); `RUSTFLAGS` (replaces rather than merges the config flags).
**Consequences.** Target rustflags in `.cargo/config.toml` apply to every profile of those targets, not only to release builds; a plain `cargo build --release` without xtask is not path-remapped — therefore `cargo xtask release` (M11) is the only sanctioned release path (`06` §6).
**Status.** Accepted (M0 review, 2026-09-28).

### ADR-033 — `secmp-ui`: `deny(unsafe_code)` with Slint-generated `allow` tolerated
**Context.** M0 spike (c): `slint::slint!` expands to code carrying `#[allow(unsafe_code)]`, which rustc rejects under a crate-level `forbid` (E0453). `slint-build` would need a build script, which CLAUDE.md §1.9 bans.
**Decision.** `secmp-ui` declares `#![deny(unsafe_code)]` (not `forbid`). The only tolerated `allow(unsafe_code)` is the one generated inside `slint!` expansions. The `policy` step verifies that `secmp-ui`'s own source files contain neither the token `unsafe` nor a hand-written `allow(unsafe_code)`/`expect(unsafe_code)`. Build scripts remain banned. The M8 spike may evaluate `slint-interpreter` as an alternative; egui remains the fallback (ADR-013).
**Alternatives.** `slint-interpreter` (runtime loading of `.slint`; different attack surface and a11y questions); an ADR exception for a one-line `build.rs` (rejected: keeps the build-script ban absolute); egui now (premature — Slint's a11y/text stack is the reason for ADR-013).
**Status.** Accepted (M0 review, 2026-09-28).

### ADR-034 — Windows release artefacts are built natively on Windows
**Context.** M0 spike (a): `rusqlite` with `bundled-sqlcipher-vendored-openssl` builds and runs natively on Windows, Linux and macOS, but OpenSSL's `VC-WIN64A` configuration cannot be cross-built with cargo-xwin (needs a Windows perl and `nmake`). `02` §7 and `06` §5–6 had planned Linux cross-builds for Windows.
**Decision.** Windows test and release builds run natively on Windows: GitHub `windows-latest` and, from M9, the owner's ephemeral libvirt Windows 11 VM. The two-builder reproducibility check for Windows uses two independent Windows builders. `cargo-xwin` cross-builds stay as a compile-compatibility CI check (with NASM), never as a release path.
**Alternatives.** Prebuilt OpenSSL via `OPENSSL_DIR` (rejected: an unvetted binary supply-chain input); the ADR-027 sealed-column fallback (rejected: SQLCipher works natively); another SQLCipher crypto provider (not exposed by `libsqlite3-sys`).
**Consequences.** Reproducibility of native MSVC builds must be measured in M11 (pinned MSVC/SDK versions on the runner image and in the VM); `02` §7 and `06` §5/§6 updated.
**Status.** Accepted (M0 review, 2026-09-28).

### ADR-035 — Prefix-free label set; three label renames (spec rev 2.2)
**Context.** The reference implementation (ADR-026) found that Appendix A was not prefix-free (`"SecMP-INV/1"` ⊂ `"SecMP-INV/1 linkdata"`, `"SecMP-HX/1 init"` ⊂ `"SecMP-HX/1 initkey"`, `"SecMP-Q/1 FETCH"` ⊂ `"SecMP-Q/1 FETCH_MULTI"`) while labels are concatenated with data without framing, so `(label, data)` pairs are not uniquely parseable. No exploitable collision exists in v1 (the pairs are used in different primitive roles), but the property should hold by construction.
**Decision.** Appendix A gains the rule "the label set is prefix-free; labels are raw ASCII with no framing", enforced by a unit test in both implementations that re-reads Appendix A. Renames: `"SecMP-INV/1"` → `"SecMP-INV/1 blob"`; `"SecMP-HX/1 init"` → `"SecMP-HX/1 initcell"`; the `FETCH_MULTI` signature label is `"SecMP-Q/1 MFETCH"`. `HybridSign` accepts only its two labels. Appendix A also lists the nine `SecMP-STORE/1` table labels so the spec is self-contained.
**Alternatives.** Length-framing every label (touches every construction for no additional benefit once the set is prefix-free); a `0x00` terminator (same).
**Consequences.** Spec rev 2.2; nothing was implemented under the old names. Also in rev 2.2 (same review round): strict Ed25519 verification defined in the spec (§3.5), pure ML-DSA stated explicitly, MsgEncrypt/MsgDecrypt length checks (§3.3), X25519 input handling per RFC 7748 (§3 table), Appendix C corrected (a flipped KEM ciphertext is a positive implicit-rejection case), D.2 comments aligned with D.6.
**Status.** Accepted (reviewer, 2026-09-28).

### ADR-036 — Vetting policy for the cryptographic dependency closure
**Context.** M1 vet probe (`docs/reviews/M01-evidence/vet-probe-2026-09-28.txt`): none of the nine public cargo-vet audit sets covers `libcrux-ml-kem`, `ml-kem`, `ml-dsa`, the dalek crates, `hkdf`, `chacha20poly1305` or `aws-lc-rs` at any version; the unaudited backlog is ≈ 0.69 M lines without the test-only crates. The `06` §3 rule (imported audit or named human audit; zero exemptions in the `secmp-crypto`/`secmp-proto` closure) is therefore unsatisfiable as written.
**Decision.** For the **normal (shipped) dependency closure** of `secmp-crypto` and `secmp-proto` (`cargo tree -e normal`), every crate MUST be covered by one of: (1) an imported audit; (2) **publisher trust** for the crates.io accounts that actually publish the chosen primitive crates (RustCrypto, dalek-cryptography, Cryspen/CE Labs for libcrux, AWS for aws-lc — recorded per account with `cargo vet trust`, an `end` date ≤ 12 months, and a note naming the crate family it is trusted for), or (3) a **delta audit** (`cargo vet diff`) against an audited or trusted version, with the full diff attached under `docs/reviews/Mxx-evidence/vet-deltas/`, written by the implementer, read by the reviewer, and approved by the owner, whose name goes into the audit note. **Compensating controls are mandatory** regardless of coverage: official KATs on every target, three-way differential tests, fuzzing of every parser, mutation gate. Dev-dependencies (test-only crates such as `ml-kem` and `aws-lc-rs` used for differential tests) and build-dependencies outside the normal closure MAY be tracked exemptions. The zero-exemption rule now reads: *zero exemptions in the normal closure*.
**Alternatives.** Named human audits of ≈ 0.69 M lines (not credible); dropping vet for crypto crates (loses the change-tracking benefit); trusting whole organisations by name (over-broad — accounts, not organisations, are trusted).
**Consequences.** `06` §3 amended; `supply-chain/audits.toml` gains trust entries and delta audits; the residual crates named in the probe (`rand_core`, `keccak`, `hax-lib`, `hax-lib-macros`, `typenum`) are covered by trust or delta audits in M1.
**Status.** Accepted (reviewer, 2026-09-28).

### ADR-037 — M1 dependency set: primitive crates, OS bindings, test-only crates
**Context.** M1 brings the first third-party code into the shipped graph (`secmp-crypto`, `secmp-sys-mem`) and the test-only crates for KATs, differential tests and vector generation. `docs/06` §3 requires an ADR line per direct dependency (why, alternatives, maintenance, audit status); ADR-036 defines the vetting; ADR-023 records the primitive versions.
**Decision.** Direct dependencies, all pinned with `=` in `[workspace.dependencies]`, default features off:

| Crate | Where | Why / features | Alternatives | Maintenance | Vet coverage (ADR-036) |
|---|---|---|---|---|---|
| `libcrux-ml-kem 0.0.10` | `secmp-crypto` | ML-KEM-768/1024 (ADR-023). `mlkem768`, `mlkem1024`, no default features. **Correction (M1, found by Miri):** the build scripts of `libcrux-ml-kem`, `libcrux-sha3` and `libcrux-intrinsics` enable the NEON backend on every aarch64 build and compile the AVX2 backend on every x86_64 build (chosen at run time by CPUID, portable otherwise), independent of Cargo features unless `LIBCRUX_DISABLE_SIMD128/256=1` is set. The `kat` step therefore runs the ML-KEM KATs and frozen vectors twice per target (the host's backend, and the portable one with SIMD disabled); Miri interprets the portable backend | `ml-kem`, `aws-lc-rs` (kept as differential partners) | Cryspen, active; hax/F*-verified | trust `jschneider-bensch`; `hax-lib`, `hax-lib-macros`(`-types`): trust `maximebuyse` (Cryspen hax co-owner), crate-scoped |
| `ml-dsa 0.1.1` | `secmp-crypto` | ML-DSA-65, pure, hedged (spec §3.5). `zeroize` | `aws-lc-rs` (C; differential partner) | RustCrypto, active | trust `github:RustCrypto/signatures`, `tarcieri` |
| `x25519-dalek 3.0.0` | `secmp-crypto` | X25519 (RFC 7748). `static_secrets`, `zeroize`, `precomputed-tables` | `aws-lc-rs` | dalek-cryptography, active | trust `rozbb` |
| `ed25519-dalek 3.0.0` | `secmp-crypto` | Ed25519 signing; strict verification completed by byte-level checks (spec §3.5). `fast`, `zeroize` | `aws-lc-rs` | dalek-cryptography | trust `rozbb` |
| `chacha20 0.10.2`, `chacha20poly1305 0.11.0`, `hmac 0.13.0`, `hkdf 0.13.0`, `sha2 0.11.0`, `sha3 0.11.0` | `secmp-crypto` | ChaCha20 (§3.3), XChaCha20-Poly1305 (§3.4), HMAC/HKDF-SHA-256, SHA-256, SHA3-256; `zeroize` where offered | `aws-lc-rs` (no XChaCha20-Poly1305) | RustCrypto, active | trust RustCrypto accounts (`tarcieri`, `github:RustCrypto/*`) |
| `subtle 2.6.1` | `secmp-crypto` | constant-time comparison and selection | — | dalek-cryptography | imported audit |
| `zeroize 1.9.0` | `secmp-crypto`, `secmp-sys-mem` | zeroisation of secrets | — | RustCrypto | trust `github:RustCrypto/utils`, `tarcieri` |
| `getrandom 0.4.3` | `secmp-crypto` | OS CSPRNG, the only randomness source (spec §3) | `rand` (adds a userspace RNG) | rust-random | trust `github:rust-random/getrandom`, crate-scoped |
| `libc 0.2.189` | `secmp-sys-mem` (unix) | `mmap`, `mprotect`, `mlock`, `madvise`, `memfd_secret` for `SecretPage` | `rustix`, `nix` (more code; `secmp-sys-mem` is the one place for such bindings) | rust-lang | trust `rust-lang-owner` (M0 rule) |
| `windows-sys 0.61.2` | `secmp-sys-mem` (windows) | `VirtualAlloc`/`VirtualProtect`/`VirtualLock`/working-set adjustment. `Win32_Foundation`, `Win32_System_Memory`, `Win32_System_SystemInformation`, `Win32_System_Threading` | `windows` (heavier) | Microsoft | trust `kennykerr` (M0 rule) |
| `ml-kem 0.3.2` | dev (`secmp-testkit`) | ML-KEM differential partner | — | RustCrypto | trust |
| `aws-lc-rs 1.18.1` | dev (`secmp-testkit`) | differential partner for ML-KEM, ML-DSA (stable `signature` API), Ed25519. `aws-lc-sys`, `alloc` | — | AWS | trust `justsmth` |
| `serde_json 1.0.151` | `secmp-testkit`; dev (`secmp-crypto`) | JSON of the external KAT files and the vector files (canonical writer: sorted keys, compact) | hand-written parser (ADR-031 reasoning) | dtolnay | trust `dtolnay` (ADR-031) |
| `libfuzzer-sys 0.4.13` (+ `arbitrary 1.4.2`) | `fuzz/` only (separate workspace and `Cargo.lock`, seeded from the workspace lock) | cargo-fuzz harness (docs/06 §4) | — (cargo-fuzz's standard harness) | rust-fuzz | outside the vetted workspace graph (never built into a shipped artefact); cooldown checked by `cargo xtask cooldown` on `fuzz/Cargo.lock` |

`rand_core` (0.10.1) is not a direct dependency: no randomised API of the chosen crates is used (ML-DSA hedging passes OS randomness to `sign_internal`, the dalek keys come from seeds); it stays in the closure through `libcrux-traits`/`rand` and is covered by a delta audit. The SHAKE-256 streams of the vector seed rule (`vectors/SCHEMA.md` §2), the differential tests and the constant-time harness use `sha3::Shake256`; `shake 0.1.0` is not a direct dependency but stays in the closure as a normal dependency of `ml-dsa` (trust `github:RustCrypto/XOFs`). The normal closure of `secmp-crypto`/`secmp-proto` on the three targets is 52 crates, each covered by an imported audit, publisher trust or one of the two delta audits (`rand_core`, `rand`; diffs in `docs/reviews/M01-evidence/vet-deltas/`); the 25 tracked exemptions are all outside it (build-only, dev-only, wasm32/UEFI-only or `cfg(hax)`/`cfg(valgrind_ct_test)`-only crates). Cooldown: the newest `cc` (1.5.x), `find-msvc-tools` 0.1.14, `wasm-bindgen` 0.2.129 and `js-sys` 0.3.106 were younger than 7 days, so `Cargo.lock` pins 1.4.7, 0.1.13, 0.2.128 and 0.3.105. **Advisory triage:** RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained) is ignored by `cargo audit` (`xtask/src/expect.rs` `AUDIT_IGNORES`): the crate is in `Cargo.lock` only as a `cfg(hax)` dependency of `hax-lib-macros` and is never compiled for any target; `cargo deny` (per-target graph) does not report it.
**Alternatives.** `aws-lc-rs` for all primitives (one C library; but no XChaCha20-Poly1305, and ADR-023 keeps it as an independent differential partner); `libcrux` for every primitive (its non-ML-KEM crates are younger).
**Consequences.** Every bump of a crate above re-runs the KATs, differential tests and frozen vectors (`docs/06` §3); trust entries end 2027-09-28 and are reviewed at every release; `rand_core`/`rand` delta audits await the owner's approval (note in `supply-chain/audits.toml`).
**Status.** Proposed (implementer, M1); dependency pins approved in the M1 brief, 2026-09-28.

---

*Template for new entries:*

### ADR-0NN — Title
**Context.** … **Decision.** … **Alternatives.** … **Consequences.** … **Status.** Proposed / Accepted / Superseded by ADR-0MM.
