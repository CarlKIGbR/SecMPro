# SecMPro — System Architecture

Status: v1 architecture baseline (2026-09-25). Normative where it says MUST; otherwise explanatory. Protocol details live in `03-protocol-spec.md`; client hardening in `04-client-security.md`; relay operations in `05-relay-ops.md`.

## 1. One-paragraph summary

SecMPro is a desktop messenger (Linux + Windows) with its own post-quantum end-to-end protocol (SecMP/1) and a deliberately dumb relay (eight commands). Users have no identifiers; contacts are made only through out-of-band invitations; every message travels as a fixed-size cell, emitted at a constant rate, through an anonymous capability-authenticated queue on a relay reached over Tor. The relay holds ciphertext in RAM and nothing else. The client is a single Rust binary built around a sans-IO protocol core, an encrypted local store, an embedded Tor client, and a native GPU-rendered UI hardened against screen capture. v1.1 replaces the relay with peer-hosted onion endpoints and personal mailboxes without changing anything above the transport trait.

## 2. Component overview

```
┌────────────────────────────── Client (one process in v1) ──────────────────────────────┐
│                                                                                         │
│  ┌──────────────┐   commands/events    ┌─────────────────────────────────────────────┐  │
│  │  secmp-ui    │◄────────────────────►│  secmp-client-core                          │  │
│  │  (Slint)     │   (async channel)    │  contacts · sessions · invitations · outbox │  │
│  │  screen-sec  │                      │  scheduler (constant rate) · settings       │  │
│  └──────┬───────┘                      └───────┬───────────────────┬─────────────────┘  │
│         │ platform hooks                       │                   │                    │
│  ┌──────▼────────────┐                 ┌───────▼────────┐  ┌───────▼────────┐           │
│  │ secmp-sys-desktop │                 │ secmp-store    │  │ secmp-transport│           │
│  │ (unsafe: WDA,     │                 │ SQLCipher, key │  │ QueueTransport │           │
│  │  DACL, Wayland,   │                 │ wrapping       │  │ SecMP-LINK/Q   │           │
│  │  keystores)       │                 └────────────────┘  │ Tor (arti) /   │           │
│  └───────────────────┘                                     │ TLS direct     │           │
│                       ┌────────────────┐  ┌─────────────┐  └───────┬────────┘           │
│                       │  secmp-proto   │  │ secmp-crypto│          │                    │
│                       │  sans-IO: HX,  │◄─┤ typed prims │          │                    │
│                       │  TR, encoding  │  │ (only crate │          │                    │
│                       └────────────────┘  │ w/ SecMP    │          │                    │
│                                           │ crypto deps)│          │                    │
│                                           └──────┬──────┘          │                    │
│                                           ┌──────▼──────┐                               │
│                                           │secmp-sys-mem│ (unsafe: SecretPage, mlock,   │
│                                           │             │  dumpable, Landlock, seccomp) │
│                                           └─────────────┘                               │
└────────────────────────────────────────────────────────────────────┼────────────────────┘
                                                                     │ Tor circuit(s) / TLS
                                                                     ▼
┌──────────────────────────────── Relay host (Linux, Hetzner) ───────────────────────────┐
│  C tor (onion service, intro-DoS defence) ► 127.0.0.1:7443 ► secmp-relay (Rust, RAM only) │
│  optional: 0.0.0.0:443 TLS 1.3 (X25519MLKEM768, pinned cert) ──► same binary           │
│  systemd sandbox · Landlock · seccomp · no swap · no logs · nftables notrack            │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## 3. Cargo workspace layout

```
secmpro/
├── Cargo.toml                 # [workspace], [workspace.dependencies], [workspace.lints]
├── rust-toolchain.toml        # exact pinned toolchain
├── deny.toml                  # cargo-deny: licenses, bans, sources, advisories
├── supply-chain/              # cargo-vet config + audits + imports
├── CLAUDE.md                  # working rules for the implementing agent
├── docs/                      # this documentation set (00–09, research/, templates/, decisions/)
├── formal/                    # ProVerif (and optional Tamarin) models + CI runner script
├── vectors/                   # frozen test vectors (JSON), incl. negative vectors
├── crates/
│   ├── secmp-crypto/          # ONLY crate using crypto crates for SecMP constructions. Typed keys/nonces, HybridKEM, HybridSign, MsgEncrypt, CAEAD, HKDF helpers, SAS
│   ├── secmp-proto/           # sans-IO: encodings (App. D), SecMP-INV/HX/TR state machines, cell/frame layouts, Q command types
│   ├── secmp-transport/       # QueueTransport trait; SecMP-LINK client; relay-queue transport; Tor (arti) + TLS stream providers (rustls/aws-lc-rs used here for TLS only)
│   ├── secmp-store/           # encrypted profile store (rusqlite + SQLCipher), key wrapping, migrations, outbox tables, incremental ratchet persistence
│   ├── secmp-client-core/     # contacts, sessions, invitations, scheduler, outbox, queue pool, settings; exposes an async API used by UIs
│   ├── secmp-relay/           # the server binary: SecMP-LINK server, SecMP-Q executor, RAM queue store, listeners, in-process sandboxing (via secmp-sys-mem)
│   ├── secmp-cli/             # headless client (scriptable) for integration/E2E tests and ops
│   ├── secmp-ui/              # Slint desktop UI binary (Linux/Windows)
│   ├── secmp-sys-mem/         # unsafe, portable: SecretPage (memfd_secret/mlock/VirtualLock), dumpable/core-dump control, Landlock, seccomp, mlockall
│   ├── secmp-sys-desktop/     # unsafe, desktop only: WDA/DISPLAY_ONLY, process DACL + mitigation policies, WER exclusion, Recall input scope, Wayland/compositor probes and exclusion requests, OS keystores (DPAPI/CNG/TPM, Secret Service/TPM2), clipboard formats
│   └── secmp-testkit/         # in-process harness (relay + N clients), KAT loaders, turmoil simulations, fault injection, `two-clients` binary
├── ref/                       # independent Python reference implementation (vectors only; written from the spec in a separate session, ADR-026)
├── fuzz/                      # cargo-fuzz targets for every decoder and state machine input
├── xtask/                     # `cargo xtask ci-fast | ci-full | vectors | repro-check | sbom | release | win-test | ops-check`
└── deploy/                    # systemd units, tor config, nftables, install scripts, hardening checks
```

Dependency direction (enforced by review and by `cargo-deny` bans where possible):
`secmp-sys-mem` ← `secmp-crypto` ← `secmp-proto` ← `secmp-transport` / `secmp-store` ← `secmp-client-core` ← `secmp-cli` / `secmp-ui`; `secmp-sys-desktop` is used only by `secmp-ui`, `secmp-store` (keystores) and `secmp-client-core`; `secmp-relay` depends on `secmp-crypto`, `secmp-proto`, `secmp-sys-mem` only — never on desktop code. `secmp-proto` and `secmp-crypto` MUST NOT depend on tokio or any I/O crate (sans-IO). The two `secmp-sys-*` crates are the only crates that may contain `unsafe`.

## 4. Client architecture

### 4.1 Process model

v1 is a single process with three long-lived async domains on one tokio runtime: UI (Slint event loop on the main thread), core (sessions, scheduler, store), transport (Arti + link tasks). The core exposes an `Api` (request/response over `tokio::sync` channels plus an event stream) so that a later split into a UI process and a sandboxed core process (Win32k lockdown, ACG, seccomp/Landlock) is a mechanical change (planned v1.x, ADR-014).

### 4.2 Data model (encrypted store)

Tables (SQLCipher, one database per profile):

| Table | Content |
|---|---|
| `identity` | IKS secret material (wrapped), fingerprint, creation time |
| `prekeys` | SPK/OPK secret material (wrapped), ids, expiry, used flag |
| `relays` | `RelayRef`, access key (`RelayInfo` is never stored — spec §8.2) |
| `contacts` | peer `IKSPublic`, fingerprint, display name, verified flag, routes (ordered `RouteDescriptor`s), our queues for this contact (`rid`, recv key), state |
| `sessions` | serialised `RatchetState` per contact (persist-before-send) |
| `outbox` | queued/relayed/delivered `AppMessage`s with cell-id mapping for eviction handling |
| `messages` | conversation history (content, direction, ts, expiry, view-once state) |
| `invitations` | issued invitations: `ld_id`, `link_key`, link-data owner key, `spk_id`/`opk_id`, invitation-queue recipient key, `inv_period_s`, `expires`, status (pending/consumed/expired) |
| `settings` | mode (Strict/Balanced/Low-bw), screen-security options, retention defaults |

All secret columns are additionally wrapped with a per-profile master key (`04-client-security.md` §3). Nothing in the store is ever written unencrypted; temp files are forbidden (`PRAGMA temp_store = MEMORY`, `journal_mode = WAL` inside the encrypted file). Ratchet persistence is incremental (chain keys/counters per slot; skipped keys row-by-row), because constant-rate dummies update every session every slot.

Concurrency: a session is owned by one `SessionActor` task; the send-link and recv-link tasks of a contact send it messages (`prepare_next_cell`, `receive_cell`) and never touch the ratchet directly. Each actor operation runs in one store transaction (`persist-before-send`, `persist-before-ack`).

### 4.3 Session lifecycle

```
[Invitation created] ──LINK_PUT──► relay      (inviter, responder)
[Invitation scanned] ──LINK_GET──► relay      (invitee, initiator)
  initiator: create own recv-queue → HandshakeInit (3 cells over invitation queue)
  responder: process → take a pooled recv-queue → first reply (RouteUpdate) over initiator's queue; invitation queue retired with overlap
  both: show safety number; contact = unverified until confirmed
[Steady state] each contact = 2 queues; constant-rate SEND/FETCH per §10 of the spec
[Rotation] recipient takes a pooled queue → RouteUpdate → sender switches → old queue kept alive with dummies U[1 h, 24 h] → deleted (every 30 days or on demand)
[Relay restart] recv-queues: ERR_NOQUEUE → re-create identical queues (derived ids) after a random delay, reset committed_ack and dedup set; send-queues: keep sending, discard cell_id→outbox map; outbox re-sends unreceipted messages
[Key change / reset] per spec §7.7 / §7.8
```

### 4.4 Scheduler

One `LinkTask` per link. Each holds its own monotonic timer with a randomised phase and lifetime (spec §10.6), a bounded in-flight counter, and a pre-built frame for the next tick (prepared — including ratchet update and persistence — off the tick path). The scheduler MUST NOT read UI/focus state. Mode changes (Strict ↔ Balanced) tear down and recreate all links. Control operations (`QUEUE_NEW`, `QUEUE_DEL`, `LINK_PUT`, owner-status `LINK_GET`) run on one-shot links scheduled by a `ControlOps` task with the delays of spec §10.6; a `QueuePool` keeps ≥ 2 spare recv-queues per relay.

### 4.5 UI

Slint (winit backend) with a strict separation: the UI never touches key material and never receives the store handle; it receives already-decrypted view models from the core API. Screen-security behaviours (exclude-from-capture, blur on focus loss, view-once reveal, watermark overlay, clipboard policy, accessibility mode) are implemented in `secmp-ui` + `secmp-sys-desktop` (see `04-client-security.md`).

## 5. Relay architecture

### 5.1 Structure

```
listeners (tor loopback TCP, optional TLS)  →  per-connection task: SecMP-LINK server (HS, frame codec, rate limit)
   →  command decoder (exact-fit) → Executor → QueueStore (sharded RwLock<HashMap<qid, Queue>>, 4×cores shards)
                                              → LinkDataStore (sharded)
                                              → MemoryBudget (atomic counter) → Sweeper (hour-bucket expiry)
```

- `Queue` = bounded `VecDeque<Cell>` (capacity 128), Ed25519 keys, buckets. Zeroize on drop.
- No database, no files, no log lines with per-request data. The binary can run with a read-only root filesystem.
- Aggregate metrics (optional, off by default) exposed only on a Unix socket for the operator.
- Graceful shutdown: stop accepting `QUEUE_NEW`, keep serving `FETCH` for `drain_secs` (default 60), then exit. Everything is then gone.

### 5.2 Scale-out model

The unit of scale is an *independent relay*. Queue addresses include the relay reference, so a user's queues can live on any relay and different contacts can be served by different relays. Relays never talk to each other. Within one relay, sharded in-memory stores scale to the NIC limit long before the CPU (see research R5 §2). No clustering, no shared state, no load balancer in v1.

## 6. Trust boundaries and data flow

| Boundary | What crosses it | Protection |
|---|---|---|
| UI ↔ core | Plaintext view models, user input | In-process in v1; designed as a channel API so it can become an IPC boundary |
| Core ↔ store | Serialised state, messages | SQLCipher + per-record wrapping; master key never leaves `secmp-crypto` typed wrappers |
| Core ↔ transport | Cells (opaque), capabilities | Cells are already E2E encrypted; transport sees no plaintext ever |
| Transport ↔ network | Frames inside Tor stream / TLS | SecMP-LINK (PQ hybrid) inside Tor (classical) or TLS (PQ hybrid) |
| Relay ↔ world | Frames | Relay validates every byte; RAM only; sandboxed process |

## 7. Key technology decisions (summary; full ADRs in `08-decisions.md`)

| Area | Decision |
|---|---|
| Language | Rust, stable, pinned toolchain, `forbid(unsafe_code)` outside the two `secmp-sys-*` crates |
| Crypto crates | `libcrux-ml-kem` (verified) primary for ML-KEM with differential tests against RustCrypto `ml-kem`; `ml-dsa` (RustCrypto, patched ≥ timing fix) with differential tests against `aws-lc-rs`; `x25519-dalek`/`ed25519-dalek` v3 (Verus-verified core); RustCrypto `chacha20`, `chacha20poly1305`, `hmac`, `hkdf`, `sha2`, `sha3`, `argon2`; `zeroize`, `subtle` |
| Protocol libraries | None (libsignal is AGPL, unsupported outside Signal, and Signal-specific; vodozemac has no PQ). SecMP/1 is implemented from public-domain specs with our own code |
| Transport | v1: TCP streams (Tor onion via `arti-client`; direct via rustls/aws-lc-rs TLS 1.3 with X25519MLKEM768). No QUIC in v1 (ADR-006) |
| Server onion hosting | C tor sidecar (mature hosting; intro-DoS defence; PoW defence off in v1 because Arti's PoW client is experimental/LGPL — ADR-024) — Arti hosting still marked experimental for services |
| UI | Slint 1.18+ (winit backend, AccessKit); egui as fallback if the M8 spike fails the a11y/text bar |
| Local storage | rusqlite + bundled SQLCipher; master key from Argon2id passphrase, optionally also OS keystore (DPAPI/TPM, Secret Service/TPM2) |
| Formal verification | ProVerif models in CI for HX, LINK, TR; Tamarin optional later |
| Build & supply chain | cargo-deny + cargo-vet + cargo-audit + cargo-auditable; 7-day dependency cooldown; reproducible builds checked on two builders; SLSA L3 provenance + offline minisign signature; SBOM |
| Windows builds | cross-compiled from Linux with `cargo-xwin` (msvc target); tests executed on the owner's ephemeral libvirt Windows 11 VM |

## 8. What v1.1 changes (and what it does not)

Unchanged: `secmp-crypto`, `secmp-proto`, `secmp-store`, the session model, the UI.
Changed/added: `secmp-transport` gains `OnionEndpointTransport` (per-contact onion services hosted by the client via a `TorProvider` trait — Arti or C tor) and `MailboxTransport` (the relay binary run by the user as a personal onion service); `secmp-client-core` gains multi-route delivery (direct → mailbox → relay) and route management; invitations gain kind 0x02 routes. Details in `07-milestones.md` (M14–M18) and research R4.

## 9. Explicitly rejected alternatives

- **Using libsignal / vodozemac / OpenMLS as the E2E core** — licensing (AGPL), unsupported external use, Signal-specific wire formats, no PQ (vodozemac), or MLS's non-deniability and ordering needs (see research R1 §2–3).
- **A TEE (SGX/SEV-SNP) for contact discovery** — Hetzner offers none; 2025 attacks (RMPocalypse, Heracles, TEE.fail) break the relevant threat model; the design avoids needing discovery at all (research R5 §3).
- **Push notifications** — unavoidable third-party metadata; desktop clients keep long-lived circuits instead.
- **Public DHT for discovery** — Kademlia lookups leak target keys and IPs (research R4).
- **QUIC in v1** — onion services carry TCP only; a constant-rate protocol gains little from QUIC; quinn's default `ring` provider has no ML-KEM (research R5 §1). Revisit for direct mode in v1.x.
- **Key transparency server in v1** — meaningless with one operator and two clients; replaced by mandatory out-of-band verification, hard pinning and signed key succession (research R1 §6).
