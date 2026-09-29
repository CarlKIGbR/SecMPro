# SecMPro — Milestone Plan (v1 and v1.1)

Status: baseline, revision 2 (2026-09-25, after adversarial review). This is the execution plan for the implementing agent (Claude Code / Opus) and the reviewer (Fable). Milestones are strictly sequential; the next one starts only after the previous one's review is recorded in `docs/reviews/`. Sizes are relative (S ≈ one focused session, M ≈ 2–4, L ≈ 5–8, XL ≈ 8+).

Every milestone ends with a **Milestone Report** (`docs/templates/milestone-report.md`) and a **Review** (`docs/templates/review-checklist.md`). The Definition of Done in `06-engineering-standards.md` §8 applies to all.

**Owner-operated gates** (marked ⚙) need infrastructure only the owner runs: the Windows 11 VM runner, the Hetzner relay host, a KDE ≥ 6.7 machine, the offline signing key, long fuzz campaigns. When such a gate is unavailable the implementer completes everything else, states the gap in the report, and the milestone stays open — evidence is never faked.

```
v1  : M0 → M1 → M2 → M3 → M4 → M5 → M6 → M7 → M8 → M9 → M10 → M11 → M12 (release)
v1.x: M13 (anonymous tokens), M14 (process split + sandbox), M15 (blob channel)
v1.1: M16 → M17 → M18 → M19 → M20 (release)
```

---

## v1 — "two clients and a relay, with every security function on"

### M0 — Repository bootstrap and engineering baseline (M)

**Goal.** A workspace in which every later milestone can be built, tested and gated without further infrastructure work; the two build risks (SQLCipher on Windows, aws-lc-rs cross-compilation) spiked.

**Deliverables.**
- Cargo workspace per `02-architecture.md` §3 with empty crates (each `lib.rs` documents responsibility and allowed dependencies); every crate except `secmp-sys-mem`/`secmp-sys-desktop` carries `#![forbid(unsafe_code)]`.
- `rust-toolchain.toml`, `[workspace.lints]` per `06` §2 (with `priority = -1` on groups), `clippy.toml`, `deny.toml`, `supply-chain/` initialised with `cargo vet init` and audit imports; tracked-exemption procedure documented.
- `xtask`: `ci-fast`, `ci-full`, `vectors` (stub), `repro-check` (stub), `sbom`, `win-test --backend github|libvirt` (`github` = runs/inspects the `windows-latest` workflow, real in M0; `libvirt` = QEMU guest agent or SSH into the owner's VM with snapshot revert per run — mechanism documented in M0, activated when the VM exists, required from M9), `ops-check` (stub), plus the `forbid(unsafe_code)` grep check.
- CI workflows (GitHub Actions): `06` §5 steps 1–5, 13, 14 on `ubuntu-latest`; native Windows build + tests on `windows-latest`; a `cargo-xwin` cross-build job from Linux (may be allowed to fail in M0 with the outcome recorded); no `pull_request_target`; SHA-pinned actions.
- **Spikes** with written outcome in `docs/reviews/M0-spikes.md`: (a) `rusqlite` + `bundled-sqlcipher-vendored-openssl` built and executed natively on `windows-latest` *and* cross-built with `cargo-xwin` (from macOS with Homebrew LLVM, or from the Linux runner); (b) `aws-lc-rs` the same way; (c) hello-world Slint compiled for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`, opened natively on macOS (opening on Linux/Windows desktops is the M8 spike). A native-works/cross-fails outcome is recorded, not a blocker; fallback decisions per ADR-027 only if (a) fails natively.
- `SECURITY.md`, `CHANGELOG.md`, `docs/reviews/`, `README.md` build instructions.

**Acceptance.** `cargo xtask ci-full` green on the empty workspace (macOS natively and `ubuntu-latest`); `cargo deny check` and `cargo vet` pass with zero exemptions in the `secmp-crypto`/`secmp-proto` closure; a test crate containing `unwrap()` and one containing `unsafe` outside `secmp-sys-*` both fail CI (demonstrated, then removed); Windows hello-world and the (empty) test suite run on `windows-latest` via `cargo xtask win-test --backend github`; the `libvirt` backend is documented and stubbed (⚙ activation deferred until the VM exists, required by M9); spike outcomes recorded.

**Review focus.** Lint set actually enforced; cooldown check works; nothing in CI can be skipped silently.

---

### M1 — `secmp-crypto`: typed primitives and constructions (M)

**Status (2026-09-29).** Merged as `bc8d6d5` (2026-09-29, PR #2, reviewer GO) — `docs/reviews/M01-review.md`: approved; conditions met. Follow-ups F1, F3, §E 5.7 and F8 are carried into the first M2 commits.

**Deliverables.**
- Types: `X25519{Secret,Public}`, `MlKem{768,1024}{Dk,Ek,Ct}`, `HybridKem{768,1024}` (spec §3.2), `Ed25519`, `MlDsa65`, `HybridSigningKey/VerifyingKey/Signature` (§3.5), `MsgEncrypt` (§3.3), `Caead` (§3.4), HKDF helpers with the label enum from Appendix A, `Sas` (§6.7), `Fingerprint`, `SecretBytes<N>` (zeroizing, no Debug/PartialEq/Clone), `Nonce24`/`Counter64` (consumed by value).
- `secmp-sys-mem::SecretPage` (memfd_secret / mlock / VirtualLock) used for long-lived secrets; Miri on the crate.
- KAT loaders (Wycheproof, ACVP) under feature `kat`; differential tests (libcrux vs RustCrypto `ml-kem` vs `aws-lc-rs`; `ml-dsa` vs `aws-lc-rs`; dalek vs `aws-lc-rs`).
- `ref/` (Python, ADR-026) implementations of HybridKEM, HybridSign, MsgEncrypt, CAEAD, SAS, written **in a separate session from the spec alone**; `cargo xtask vectors` cross-checks the Rust-generated files (`vectors/rust/<suite>.json`, gitignored) against the committed reference files (`vectors/ref/<suite>.json`, generated on the owner's machine by the `ref/` session — CI never runs the Python generator) and, on byte-for-byte agreement, freezes `vectors/<suite>.json`.
- Fuzz targets for key/ciphertext/signature parsers; mutation run.

**Acceptance.** All KATs pass on Linux and ⚙ in the Windows VM; differential tests pass 10 000 iterations; constant-time test (dudect-style) for tag comparison shows no leak; mutation survivors zero or documented; coverage ≥ 90 %; Rust and `ref/` vectors identical.

**Review focus.** Combiner label/variant and input order byte-for-byte; all-zero DH rejection; `verify_strict`; dk as seed; no `Clone` on secrets; no primitive implemented locally; `ref/` really independent (no shared code, different author session).

---

### M2 — `secmp-proto`: encodings, cells, frames, command types (M)

**Status (2026-09-29).** Started on branch `m02-proto` from `main` at `bc8d6d559795cf515bcf08f63fcfe0b9eb3058d9`; spec rev 2.3 (ADR-039) and the `encodings` reference file are committed first.

**Deliverables.** `Encode`/`Decode` for every structure in Appendix D; padding helpers; size constants with compile-time assertions; property tests (canonicality), ≥ 200 negative vectors, Kani harnesses for `Cell`/`Frame`/`HeaderV1`/frame-plaintext parsing, fuzz targets for every decoder; `ref/` encoders for cross-generated positive vectors.

**Acceptance.** `decode(encode(x)) == x` and `encode(decode(b)) == b` for all structures; every negative vector rejected with the uniform error; Kani proofs pass; fuzzers run 2 min without findings; Rust and `ref/` encodings identical.

**Review focus.** Consistency rule; `Option` strictness; no unchecked `usize` arithmetic; sizes match Appendix B; opcode table complete.

---

### M3 — SecMP-TR hybrid ratchet (sans-IO) + ProVerif model (L)

**Goal.** The Double Ratchet (header-encryption variant) with hybrid KEM steps, robust to loss, reordering, huge gaps and restarts, initialised from a supplied `SK` (HX comes in M4).

**Deliverables.**
- `secmp-proto::tr`: `RatchetState` (serialisable, zeroizing, incremental-persistence API), `init_initiator/init_responder` (§7.2), `encrypt`, `decrypt` (transactional), `DHRatchet` with KEM in both halves, `skip_message_keys` with `SKIP_WINDOW`/`MAX_FF`, dummy generation, fragment/batch/`KeyChange`/`RouteUpdate` content handling.
- `ref/` TR implementation; frozen vectors: 40-message bidirectional transcript with two full round trips, out-of-order delivery, dropped first-message-of-chain, 10 000-message gap; negative vectors (bad KEM ct, replay, truncated body, wrong `sb`, KEM material changed mid-chain).
- Property tests: random interleavings with drops/dups/reorders/gaps never reuse a message key (all keys tracked) or panic; state round-trips through serialisation at every step.
- `formal/CLAIMS.md` (queries fixed by the reviewer before modelling) and `formal/tr.pv` (bounded 3 steps): secrecy, FS, PCS with and without a DH oracle, header confidentiality.

**Acceptance.** Vectors and properties pass; ProVerif green on the fixed query set; encrypt+decrypt of a message < 3 ms.

**Review focus.** Header-key rotation exactly per §7.2–7.4; KEM material constant within a chain and rejected otherwise; persist-before-send/ack possible with the API; fast-forward bounds; transactional decrypt.

---

### M4 — SecMP-HX handshake + SecMP-INV (sans-IO) + ProVerif model (M/L)

**Deliverables.**
- `secmp-proto::inv`: invitation create/parse, `LinkDataV1` sealing/opening, `K_ld`/`K_inv` derivation, QR/URI text.
- `secmp-proto::hx`: `Initiator::start(bundle, own_iks, reply_routes, profile) -> (three HandshakeCells, RatchetState)` and `Responder::accept(cells, own_keys) -> (RatchetState, peer_iks, routes, profile)` per §6.4–6.6 (outer/inner layers, `K_id`, OPK bookkeeping).
- Prekey store trait with in-memory implementation (SPK weekly, retention rule, OPK single use, RPK).
- `ref/` HX; frozen vectors for a full run with fixed randomness (identical `SK`, `transcript`, `K_id`, cells); negative tests: wrong fingerprint, expired bundle, bad signature, missing/used OPK, zero DH, tampered chunk, garbage cells interleaved, replayed envelope.
- `formal/hx.pv`: SK secrecy (classical and with the DH oracle broken), injective agreement on the transcript, identity confidentiality of I under `K_id`, plus the reviewer's expected-false queries (PQ authentication, KCI).

**Acceptance.** Vectors pass; negative tests rejected with uniform errors; ProVerif matches `CLAIMS.md`.

**Review focus.** Transcript completeness (§6.4); `K_id` inputs; OPK deleted only on success; no signature by I; `first_msg` route equals the stored route; garbage cells ignored, not fatal.

---

### M5 — SecMP-LINK + SecMP-Q + relay core + in-process harness (L)

**Deliverables.**
- `secmp-proto::link`: sans-IO handshake state machines (client/relay) and frame codec (§8), multi-frame continuation.
- `secmp-relay` (library + binary): connection task, executor for the eight commands, `QueueStore` with derived ids and idempotent creation, `LinkDataStore` with owner-status mode, `MemoryBudget`, sweeper, `RelayInfo` per HELLO, tokens/`akc`, rate limits, graceful drain, `keygen`/`rotate-static`, config; a `tracing` test that fails on any per-request field.
- `secmp-transport::RelayQueueTransport` over an abstract byte stream; `secmp-testkit::Harness` (relay + N clients, virtual clock, scenario DSL).
- `ref/` LINK; frozen vectors (HS1/HS2, first three frames each way, every command/response layout); `formal/link.pv`.

**Acceptance.** Harness: two clients create queues (pool), exchange 1 000 cells each way, relay evicts at capacity and reports ids, sweeper expires by bucket, memory budget refuses new queues at the limit; **relay restart → `ERR_NOQUEUE` → identical queues re-created → conversation continues without a new invitation**; all responses `FRAME_SIZE`; byte-level test proves error and success frames are indistinguishable; fuzz target for the executor; relay unit tests for every command; `FETCH` idempotence and cumulative ack verified.

**Review focus.** Strict counters; `sess_id` in command signatures; one-time consumption atomic; owner-status non-consuming; eviction reporting; zeroize on delete; hour buckets only; `RelayInfo` never cached by the client.

---

### M6 — Transport providers, constant-rate scheduler, measurements (L)

**Deliverables.**
- `secmp-transport::tor` (Arti 2.6.x / `arti-client` 0.46.x, `onion-service-client`, `rustls` feature, per-link isolation, bootstrap events, state dir) and `::tls` (rustls/aws-lc-rs, `X25519MLKEM768` only, SPKI pinning, no tickets/0-RTT).
- `secmp-client-core::scheduler`: `LinkTask` with pre-built frames, modes (Strict/Balanced/Low-bw), periods per queue, random phases and lifetimes, in-flight bounds, reconnect jitter; `ControlOps` one-shot links with delays; `QueuePool`; `outbox` (in-memory behind a trait; store integration in M7).
- `secmp-testkit` binary `two-clients` (in-memory profiles, scripted invitation/handshake using M3–M5 code) so that this milestone's network tests do not depend on M7.
- `turmoil` simulations: loss, partition, relay restart, both clients restarting.
- **Activity-independence test**: for random user-activity traces, the (time, size, direction) sequence of emitted frames equals the idle trace within 5 ms under the virtual clock; on real hardware a KS test over 1 h idle vs 1 h active shows no significant difference.
- Measurement report `docs/measurements/M6-traffic.md`: bandwidth per mode (incl. Tor overhead), latency over real Tor, CPU, drain behaviour after 1 h and 24 h offline; recommendation for `PERIODS`/`T_*`/`F`/`F_M` → ADR-018.

**Acceptance.** Two `two-clients` instances on two machines exchange messages through the relay over real Tor (⚙ test relay with C tor) and over direct TLS; activity-independence test passes; simulations pass; ⚙ Arti bootstraps and the transport KATs pass in the Windows VM.

**Review focus.** No code path where activity influences timing (grep `Instant::now`, conditionals on outbox state outside `prepare`); isolation tokens per link; exactly one TLS KX group; Tor never bypassed silently.

---

### M7 — Client core: identity, contacts, store, invitations, sessions, CLI (L)

**Deliverables.**
- `secmp-store` (SQLCipher or ADR-027 fallback; schema per `02` §4.2; master-key wrapping per `04` §3; incremental ratchet persistence; migrations; secure delete; backup export/import per CS-3.5 — no ratchet state).
- `secmp-client-core`: `Profile`, `Contacts`, `Invitations`, `Sessions` (HX/TR orchestration, `RouteUpdate`, rotation with overlap, `KeyChange`, verification state), `Api` (async request/response + events), `clock`, settings, "what the relay can see" model.
- `secmp-cli`: `profile new/open`, `invite create/accept`, `contacts list/verify`, `send`, `tail`, `status`, `export/import`; JSON-lines output.
- E2E test: two CLI profiles + relay over loopback TCP and ⚙ over Tor; invitation via URI; safety numbers match; 500 messages both directions with client restarts mid-way; queue rotation with overlap; key-change flow blocks sending until re-verified; **recipient offline 24 h while the peer keeps sending, then returns and receives every real message** (fast-forward + eviction path).

**Acceptance.** E2E green locally and in CI (loopback), nightly ⚙ over Tor; forensic test: `strings`/hexdump of the profile directory shows no plaintext message, key, contact name or fingerprint; wrong passphrase takes constant time; the crash-between-persist-and-send test shows no key reuse on restart.

**Review focus.** Persist-before-send/ack enforced by construction; OPK deletion; unverified contacts cannot receive view-once messages; no identifiers reach `secmp-transport`; backup contains no ratchet material.

---

### M8 — Desktop UI (Slint) (L)

**Deliverables.**
- Spike (first session): Slint 1.18 + winit backend on both OSes — text rendering, IME, AccessKit tree, DPI, GPU renderer, **`WDA_EXCLUDEFROMCAPTURE` applied before first paint on the Slint window**, **KWin `excludeFromCapture` set from the app** — go/no-go in `docs/reviews/M8-spike.md` (fallback: egui).
- Screens: onboarding (profile + passphrase + mode with "what the relay can see"), contacts (verification state), invitation create/accept (QR + URI), conversation (batching, fragments, view-once placeholder, receipts), safety number (digits + QR), settings (mode, retention, receipts, screen security, accessibility mode), Tor status, security status indicator (CS-1.18) driven by a stub.
- Locale table (en, de). No content in window titles or notifications. UI tests via the core API and a nested-compositor screenshot harness on Linux.

**Acceptance.** ⚙ A non-developer completes profile creation, invitation exchange, verification, chat and rotation on Linux and Windows using only the UI (recorded walkthrough); AccessKit tree present for structural UI; Windows build with a test certificate runs in the VM.

**Review focus.** UI holds no keys or store handles; no blocking of the scheduler by the UI thread; no telemetry.

---

### M9 — Screen-capture resistance and client hardening (L)

**Deliverables.** Every `CS-*` in `04-client-security.md`: `secmp-sys-desktop` (Windows: WDA apply/verify/watchdog, `DISPLAY_ONLY`, DACL with OWNER RIGHTS ACE, mitigation policies, WER exclusion, remote-session detection, Recall input scope, clipboard formats; Linux: session/compositor detection, KWin/Hyprland/niri exclusion install + 2 s verification + lock-on-loss, PipeWire heuristic; keystores), `secmp-sys-mem` in the client (SecretPage, dumpable, Landlock + seccomp); UI behaviours (locked mode by default on every unprotected path, blur-on-unfocus, view-once hold-to-reveal, watermark, real security indicator, a11y gating, clipboard policy); Flatpak (Wayland-only) and tarball; Windows installer with WER exclusion; the verification matrix of `04` §7 as automated tests plus a manual protocol for GNOME/X11.

**Acceptance.** All matrix tests pass (⚙ Windows VM; ⚙ KDE ≥ 6.7 machine or nested KWin); a screen recording of the Windows VM shows the client window absent from Snipping Tool, Game Bar and a WGC recorder while visible on the monitor; the injected-thread test triggers the alarm; XWayland and GNOME sessions start locked; clearing the KWin property locks content within 2 s; process memory (test build) contains the master key only inside the locked page.

**Review focus.** Locked mode cannot be disabled permanently; watchdogs not configurable off; a11y gating; every `unsafe` block has a SAFETY comment and a test.

---

### M10 — Relay hardening, deployment and operations (M)

**Deliverables.** `deploy/` (systemd unit per `05` §4 as corrected, torrc with PoW off/intro-DoS on, nftables incl. `notrack`, sysctl/journald/sshd configs, installer for Debian 13 / Ubuntu 26.04, `check-hardening.sh`, key generation and credential encryption, `docs/ops-runbook.md`); in-process sandboxing in the relay via `secmp-sys-mem` with integration tests; `secmp-relay ping`; optional telemetry socket; `cargo xtask ops-check` (runs `check-hardening.sh` against a host over SSH/WireGuard); `systemd-analyze security` gate in CI.

**Acceptance.** ⚙ `ops-check` passes on the production host; exposure ≤ 2.0; 1-hour load test with 200 simulated Strict-mode clients over loopback within memory budget; graceful drain; no file grows on disk during operation (`inotify` watch); onion reachable; a relay restart during the load test leads to full recovery of all simulated sessions.

---

### M11 — Security verification, audit preparation and release engineering (M/L)

**Deliverables.** ⚙ 24 h fuzz campaign (corpora committed); mutation and coverage reports; `formal/` finalised with `CLAIMS.md` results; reproducible release builds for Linux and Windows on two builders with matching hashes (`xtask repro-check` real); SLSA L3 provenance; ⚙ offline minisign signing procedure executed; SBOMs; `docs/audit-package.md`; disclosure texts; `security.txt`; the M12 acceptance protocol scripted where possible (`xtask acceptance`).

**Acceptance.** Two builders → identical hashes; all gates green; audit package reviewed; an adversarial review of the implementation (Fable directorate-style; independent of the author sessions) with all blockers/majors closed or ADR'd.

---

### M12 — v1 acceptance and release 1.0.0 (M)

**Definition of v1:** "client and server can communicate with all security functions — one server and two clients".

**Acceptance protocol (executed and recorded with evidence in `docs/reviews/M12-acceptance.md`):**
1. ⚙ Relay on Hetzner per M10 (`ops-check` passes), onion service up.
2. ⚙ Client A on Linux (KDE ≥ 6.7 or Hyprland), Client B on Windows 11 (VM or physical).
3. A creates a one-time invitation (QR); B scans it; handshake completes over Tor in Strict mode; safety numbers match and are verified.
4. Functional: 200 messages each direction incl. fragments (a 60 KB inline attachment), view-once messages, receipts; queue rotation with overlap; both clients restarted mid-conversation; **the relay restarted once — conversation continues without a new invitation**; **B offline for 2 h while A keeps sending 20 real messages — all 20 arrive after B returns**; Balanced mode exercised for 30 minutes.
5. Fail-closed: Tor stopped → client emits no network traffic and shows the state; a tampered and a replayed cell injected via a test hook are dropped and counted; a `KeyChange` with a bad signature freezes the session; a deliberate SAS mismatch leaves the contact unverified.
6. PQ evidence: scheduler/protocol counters show every link handshake used `HybridKEM-1024` + `HybridKEM-768` and every ratchet step carried ML-KEM-768 material; the TLS listener (test relay only) negotiated `X25519MLKEM768`.
7. Screen capture per `04` §7 on both machines (Windows: Snipping Tool/Game Bar/WGC recorder show no window; KDE: portal screencast and screenshot show no window; XWayland session starts locked).
8. Relay host inspection during and after the test: no per-request logs, no files changed, RAM-only confirmed (`ops-check`, `inotify`, journald volatile).
9. Traffic: the scheduler's internal (time, size) log for a 1 h idle window and a 1 h active window are statistically indistinguishable (KS test), and a packet capture at the relay's loopback shows only 4352-byte frame boundaries after the handshake (byte counts modulo 4352).
10. Store forensics on both real machines (no plaintext, keys or names on disk).
11. Release artefacts reproducible, signed, SBOM attached; `CHANGELOG.md`; tag `v1.0.0`.

---

## v1.x — hardening increments (may be scheduled between v1 and v1.1)

### M13 — Anonymous queue-creation tokens (M)
VOPRF-based tokens (Privacy Pass RFC 9578 type 1, P-384): operator issues N blind tokens per invited user; `QUEUE_NEW`/`LINK_PUT` redeem one; double-spend tracking in RAM with epoch rotation; `akc` replaced by the issuer public key. ADR + spec §9.6 update + vectors + model.

### M14 — Process split and sandboxing (L)
`secmp-core` as a separate process (Unix socket / named pipe, capability-based API); core under Landlock + seccomp (Linux) / AppContainer + LPAC + ACG + Win32k lockdown (Windows); UI holds no keys.

### M15 — Blob channel for attachments (M/L)
XFTP-shaped: fixed-size encrypted chunks (64 KiB / 1 MiB classes, Padmé on total size) under random ids; keys and ids in a `Content`; constant-rate fetch on a separate link. Spec section + vectors.

Also in v1.x: Arti onion-service hosting for the relay behind `TorProvider`; Tor PoW once Arti's client is stable (ADR-024 revisit); pluggable transports via Arti `pt-client`; TUF updates (`tough`); panic wipe; signed relay-rotation notices.

---

## v1.1 — "peer-to-peer, serverless"

Design basis: research R4. Two online peers exchange messages directly over per-contact Tor onion endpoints; an optional personal mailbox (the relay binary run by the user) covers offline delivery. Nothing above `QueueTransport` changes.

### M16 — Transport-neutrality audit and `TorProvider` abstraction (M)
Tests that nothing above `secmp-transport` depends on relay semantics; `TorProvider` trait (`bootstrap`, `connect`, `launch_onion_service(keys, auth_clients)`, incoming streams) with Arti (`onion-service-service`, restricted discovery, full vanguards) and C-tor-control-port implementations; measurements (`docs/measurements/M16-onion.md`): publish time, connect latency, cost of N per-contact services.

### M17 — Per-contact onion endpoints and P2P sessions (L)
Per-contact endpoint onion services with per-contact restricted-discovery keys and capabilities, epoch rotation (pairwise-secret-derived); `OnionEndpointTransport` running SecMP-LINK with **mutual** authentication (peer static keys from the session) and the same cell/constant-rate semantics; invitations carrying a route of kind `OnionEndpoint` (a one-time invitation onion + auth key), endpoint exchange inside the first messages, invitation onion destroyed; "mailbox-only" mode to hide online presence.

### M18 — Personal mailbox and multi-route delivery (M/L)
`secmp-relay --mailbox` (owner-run onion service, restricted-discovery keys per contact); `MailboxTransport`; route list per contact (direct → mailbox → transition-only v1 relay); idempotent delivery; v1 clients ignore unknown route kinds.

### M19 — DoS, introductions and hardening for P2P (M)
Per-contact quotas; capability tokens MAC'd with the pairwise key; contact-issued Privacy Pass tokens for friend-of-friend introductions; PoW on invitation onions when available; `formal/link-mutual.pv`; fuzzing of the new transports; turmoil simulations with churn.

### M20 — v1.1 acceptance and release 1.1.0 (S/M)
Two clients (Linux + Windows) exchange messages directly over onion endpoints with the relay switched off; one goes offline, the other's messages land in the first's mailbox and are delivered on return; all v1 security functions hold (constant rate, screen security, PQ). Evidence as in M12.

---

## v1.2 and beyond (outline, not scheduled)

Small groups (sender keys over pairwise sessions + causal DAG + admin-signed membership log; later MLS with a group-owner sequencer once PQ ciphersuites have code points); multi-device (device certificates, signed hash-chained device log gossiped to contacts); PQ deniable authentication (K-Waay / RingXKEM-style) once standardised and audited; mobile clients with an honest push story.

## Dependency graph

```
M0 → M1 → M2 → M3 (TR) → M4 (HX/INV) → M5 → M6 → M7 → M8 → M9 → M10 → M11 → M12
                                          └────────────────────────────► M13, M14, M15 (any order after M12)
M12 → M16 → M17 → M18 → M19 → M20
```
